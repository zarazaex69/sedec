// package structuring — property 1: bug condition exploration test.
//
// CRITICAL: this test MUST FAIL on unfixed code.
// failure confirms that the structuring engine duplicates basic block IR
// instructions: blocks that are inlined into if-then-else branches are also
// emitted again as top-level statements by the pre-order traversal in
// collapseRegions, because collapseConditional does not mark branch-target
// blocks as collapsed before the pre-order pass runs.
//
// observed counterexample (diamond cfg entry->A->C, entry->B->C):
//   - bb1 (then_var = 1) appears inside the if-statement AND as a top-level stmt
//   - bb2 (else_var = 2) appears inside the if-statement AND as a top-level stmt
//   - bb3 (convergence_sentinel = 99) appears once (correct)
//
// the property asserts: for any diamond cfg, every block's sentinel instruction
// appears exactly once in the full structured ast output.
package structuring

import (
	"fmt"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
	"pgregory.net/rapid"
)

// ============================================================================
// diamond cfg construction helpers
// ============================================================================

// diamondCFGSpec describes a parameterised diamond cfg:
//
//	entry (id=0) -> thenBlock (id=1) -> convergence (id=3)
//	entry (id=0) -> elseBlock (id=2) -> convergence (id=3)
//
// extraBlocks is the number of additional linear blocks inserted between
// thenBlock and convergence (ids 4..4+extraBlocks-1).
type diamondCFGSpec struct {
	extraBlocks int // 0..6 extra blocks on the then-arm before convergence
}

// sentinelVarName returns the unique sentinel variable name for a given block id.
// each block gets a distinct name so occurrences are independently countable.
func sentinelVarName(id cfg.BlockID) string {
	return fmt.Sprintf("sentinel_bb%d", id)
}

// buildDiamondCFG constructs a diamond-shaped cfg and its ir block map.
// block ids: 0=entry, 1=then, 2=else, 3=convergence, 4..=extra then-arm blocks.
// each block has exactly one ir.Assign whose destination name is sentinelVarName(id).
func buildDiamondCFG(spec diamondCFGSpec) (*cfg.CFG, IRBlockMap, []cfg.BlockID) {
	const (
		entryID       cfg.BlockID = 0
		thenID        cfg.BlockID = 1
		elseID        cfg.BlockID = 2
		convergenceID cfg.BlockID = 3
	)

	g := cfg.NewCFG()
	g.Entry = entryID

	irBlocks := make(IRBlockMap)

	// helper: add a block with a unique sentinel assign instruction
	addBlock := func(id cfg.BlockID) {
		g.AddBlock(&cfg.BasicBlock{ID: id})
		irBlocks[id] = []ir.IRInstruction{
			ir.Assign{
				Dest: ir.Variable{
					Name: sentinelVarName(id),
					Type: ir.IntType{Width: ir.Size8},
				},
				Source: ir.ConstantExpr{
					Value: ir.IntConstant{
						//nolint:gosec // G115: id is bounded by cfg size
						Value: int64(id),
						Width: ir.Size8,
					},
				},
			},
		}
	}

	addBlock(entryID)
	addBlock(thenID)
	addBlock(elseID)
	addBlock(convergenceID)

	// entry branches to then and else
	g.AddEdge(entryID, thenID, cfg.EdgeTypeConditional)
	g.AddEdge(entryID, elseID, cfg.EdgeTypeConditional)

	// track all block ids for the emit-count check
	allBlocks := []cfg.BlockID{entryID, thenID, elseID, convergenceID}

	if spec.extraBlocks == 0 {
		// simple diamond: then -> convergence, else -> convergence
		g.AddEdge(thenID, convergenceID, cfg.EdgeTypeFallthrough)
		g.AddEdge(elseID, convergenceID, cfg.EdgeTypeFallthrough)
	} else {
		// extended then-arm: thenID -> extra0 -> ... -> convergence
		prevID := thenID
		for i := 0; i < spec.extraBlocks; i++ {
			//nolint:gosec // G115: i bounded by extraBlocks <= 6
			extraID := cfg.BlockID(4 + i)
			addBlock(extraID)
			allBlocks = append(allBlocks, extraID)
			g.AddEdge(prevID, extraID, cfg.EdgeTypeFallthrough)
			prevID = extraID
		}
		g.AddEdge(prevID, convergenceID, cfg.EdgeTypeFallthrough)
		g.AddEdge(elseID, convergenceID, cfg.EdgeTypeFallthrough)
	}

	g.Exits = []cfg.BlockID{convergenceID}

	return g, irBlocks, allBlocks
}

// buildEngineForDiamond constructs a fully initialised structuring Engine
// for the given diamond cfg spec. returns nil on any infrastructure error.
func buildEngineForDiamond(t *testing.T, spec diamondCFGSpec) (*Engine, []cfg.BlockID) {
	t.Helper()

	g, irBlocks, allBlocks := buildDiamondCFG(spec)

	dt, err := cfg.ComputeDominatorsForCFG(g)
	if err != nil {
		t.Logf("compute dominators failed: %v", err)
		return nil, nil
	}

	li := cfg.NewLoopInfo(g, dt)

	engine, err := New(g, dt, li, irBlocks)
	if err != nil {
		t.Logf("new engine failed: %v", err)
		return nil, nil
	}

	return engine, allBlocks
}

// ============================================================================
// ast walking helpers
// ============================================================================

// countSentinel walks the full structured ast and counts how many times
// the sentinel instruction for the given block id appears in the output.
// the sentinel is identified by the destination variable name sentinelVarName(id).
func countSentinel(stmt Statement, id cfg.BlockID) int {
	if stmt == nil {
		return 0
	}

	target := sentinelVarName(id)

	switch s := stmt.(type) {
	case IRBlock:
		count := 0
		for _, instr := range s.Instructions {
			if assign, ok := instr.(ir.Assign); ok {
				if assign.Dest.Name == target {
					count++
				}
			}
		}
		return count

	case Block:
		total := 0
		for _, child := range s.Stmts {
			total += countSentinel(child, id)
		}
		return total

	case IfStatement:
		return countSentinel(s.Then, id) + countSentinel(s.Else, id)

	case WhileStatement:
		return countSentinel(s.Body, id)

	case DoWhileStatement:
		return countSentinel(s.Body, id)

	case ForStatement:
		return countSentinel(s.Body, id)

	default:
		return 0
	}
}

// ============================================================================
// property 1: bug condition exploration test
// ============================================================================

// TestProperty1_BugCondition_CFGStructuringBlockDuplication is the bug condition
// exploration test for defect 1.
//
// CRITICAL: this test MUST FAIL on unfixed code.
//
// the property asserts: for any diamond cfg, every block's sentinel instruction
// appears exactly once in the full structured ast output.
//
// on unfixed code this assertion fails because collapseConditional inlines
// branch-target blocks (bb1, bb2) into the if-statement but does NOT mark them
// as collapsed. the subsequent pre-order traversal in collapseRegions then emits
// them again as top-level statements, producing duplicate ir output.
//
// documented counterexample (simple diamond, extraBlocks=0):
//   - bb1 sentinel (then_var) emitted 2 times: once inside if-then, once top-level
//   - bb2 sentinel (else_var) emitted 2 times: once inside if-else, once top-level
//   - bb3 sentinel (convergence) emitted 1 time: correct (not duplicated)
func TestProperty1_BugCondition_CFGStructuringBlockDuplication(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	params.MaxSize = 6

	properties := gopter.NewProperties(params)

	// property 1a: concrete simple diamond (no extra blocks)
	// this is the canonical bug trigger: entry->A->C, entry->B->C
	// bb1 and bb2 are duplicated by the unfixed collapseConditional
	properties.Property(
		"every block emitted exactly once in simple diamond cfg",
		prop.ForAll(
			func(_ bool) bool {
				return checkAllBlocksEmitCountOnce(t, diamondCFGSpec{extraBlocks: 0})
			},
			gopter.Gen(func(params *gopter.GenParameters) *gopter.GenResult {
				return gopter.NewGenResult(true, gopter.NoShrinker)
			}),
		),
	)

	// property 1b: extended diamond with 1-6 extra blocks on the then-arm
	// exercises deeper cfg traversal; the bug manifests for any extraBlocks value
	// because collapseConditional always fails to mark branch targets as collapsed
	properties.Property(
		"every block emitted exactly once in extended diamond cfg",
		prop.ForAll(
			func(spec diamondCFGSpec) bool {
				return checkAllBlocksEmitCountOnce(t, spec)
			},
			genDiamondCFGSpec(),
		),
	)

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// checkAllBlocksEmitCountOnce runs the structuring engine on a diamond cfg
// and asserts that every block's sentinel instruction appears exactly once.
// returns true if all assertions hold (expected behavior after fix),
// false if any block is duplicated (bug condition confirmed).
func checkAllBlocksEmitCountOnce(t *testing.T, spec diamondCFGSpec) bool {
	t.Helper()

	engine, allBlocks := buildEngineForDiamond(t, spec)
	if engine == nil {
		// infrastructure failure: skip this sample
		return true
	}

	ast, err := engine.Structure()
	if err != nil {
		t.Logf("structure failed (extraBlocks=%d): %v", spec.extraBlocks, err)
		// structuring error is not the bug we are testing — skip
		return true
	}

	allCorrect := true
	for _, blockID := range allBlocks {
		emitCount := countSentinel(ast.Body, blockID)
		if emitCount != 1 {
			t.Logf(
				"BUG CONFIRMED (extraBlocks=%d): bb%d sentinel emitted %d times, expected 1",
				spec.extraBlocks,
				blockID,
				emitCount,
			)
			allCorrect = false
		}
	}

	if !allCorrect {
		t.Logf("structured ast (extraBlocks=%d):\n%s", spec.extraBlocks, ast.Body.String())
	}

	// assert every block emitted exactly once — MUST FAIL on unfixed code
	return allCorrect
}

// ============================================================================
// gopter generator for diamond cfg specs
// ============================================================================

// genDiamondCFGSpec generates random diamondCFGSpec values with extraBlocks in [0, 6].
func genDiamondCFGSpec() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		// extraBlocks: 0..6 (7 possible values)
		extraBlocks := int(params.NextUint64() % 7)
		spec := diamondCFGSpec{extraBlocks: extraBlocks}
		return gopter.NewGenResult(spec, gopter.NoShrinker)
	}
}

// ============================================================================
// preservation 1: linear cfgs (no shared blocks) emit each block exactly once
// ============================================================================

// TestPreservation1_LinearCFGEmitsEachBlockOnce verifies that for any cfg where
// every block has exactly one predecessor (no shared convergence blocks), the
// structuring engine emits each block's ir instructions exactly once.
//
// **Validates: Requirements 3.1, 3.2**
//
// this is the preservation guarantee for fix 1: the fix must not break the
// baseline behavior for cfgs that do not trigger the duplication bug.
// a linear cfg (chain: entry -> b1 -> b2 -> ... -> exit) has no shared blocks
// and must always produce exactly one emission per block.
//
// EXPECTED OUTCOME: PASS on both unfixed and fixed code.
// linear cfgs never trigger the collapseConditional duplication path.
func TestPreservation1_LinearCFGEmitsEachBlockOnce(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// generate a linear chain of 2–8 blocks: entry -> b1 -> b2 -> ... -> exit
		chainLen := rapid.IntRange(2, 8).Draw(rt, "chainLen")

		g := cfg.NewCFG()
		g.Entry = 0
		irBlocks := make(IRBlockMap)

		// add all blocks with unique sentinel assigns
		for i := 0; i < chainLen; i++ {
			id := cfg.BlockID(i)
			g.AddBlock(&cfg.BasicBlock{ID: id})
			irBlocks[id] = []ir.IRInstruction{
				ir.Assign{
					Dest: ir.Variable{
						Name: sentinelVarName(id),
						Type: ir.IntType{Width: ir.Size8},
					},
					Source: ir.ConstantExpr{
						Value: ir.IntConstant{
							//nolint:gosec // G115: id bounded by chainLen <= 8
							Value: int64(id),
							Width: ir.Size8,
						},
					},
				},
			}
		}

		// connect blocks in a linear chain
		for i := 0; i < chainLen-1; i++ {
			g.AddEdge(cfg.BlockID(i), cfg.BlockID(i+1), cfg.EdgeTypeFallthrough)
		}
		g.Exits = []cfg.BlockID{cfg.BlockID(chainLen - 1)}

		dt, err := cfg.ComputeDominatorsForCFG(g)
		if err != nil {
			// infrastructure failure: skip this sample
			return
		}

		li := cfg.NewLoopInfo(g, dt)
		engine, err := New(g, dt, li, irBlocks)
		if err != nil {
			return
		}

		ast, err := engine.Structure()
		if err != nil {
			return
		}

		// preservation property: every block emitted exactly once
		for i := 0; i < chainLen; i++ {
			id := cfg.BlockID(i)
			emitCount := countSentinel(ast.Body, id)
			if emitCount != 1 {
				rt.Errorf(
					"preservation violated: linear cfg (chainLen=%d), bb%d emitted %d times, expected 1",
					chainLen, id, emitCount,
				)
			}
		}
	})
}
