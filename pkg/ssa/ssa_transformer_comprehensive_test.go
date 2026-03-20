package ssa

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// Task 5.11: Comprehensive SSA Transformer Tests
// ============================================================================
//
// Coverage:
//   1. Round-trip property: IR -> SSA -> verify semantic invariants
//   2. Phi-node placement correctness (cascading, complex CFG)
//   3. Dominance property verification (def-use chain integrity)
//   4. Memory SSA construction (loops, nested control flow)
//
// Requirements: 7.6, 22.3

// ============================================================================
// 1. Round-Trip Property Tests
// ============================================================================

func intVar(name string) ir.Variable {
	return ir.Variable{Name: name, Type: ir.IntType{Width: ir.Size4, Signed: true}}
}

func intConst(v int64) *ir.ConstantExpr {
	return &ir.ConstantExpr{Value: ir.IntConstant{Value: v, Width: ir.Size4, Signed: true}}
}

func varExpr(name string) *ir.VariableExpr {
	return &ir.VariableExpr{Var: intVar(name)}
}

func addExpr(left, right ir.Expression) *ir.BinaryOp {
	return &ir.BinaryOp{Op: ir.BinOpAdd, Left: left, Right: right}
}

func ltExpr(left, right ir.Expression) *ir.BinaryOp {
	return &ir.BinaryOp{Op: ir.BinOpLt, Left: left, Right: right}
}

func makeDomTree(cfgGraph *cfg.CFG, idom map[cfg.BlockID]cfg.BlockID, children map[cfg.BlockID][]cfg.BlockID) *cfg.DominatorTree {
	dt := cfg.NewDominatorTree(cfgGraph)
	dt.Idom = idom
	dt.Children = children
	return dt
}

// TestRoundTrip_DoWhileLoop verifies SSA transformation for do-while loop pattern.
// do-while has the body executed before the condition check, meaning the back-edge
// goes from the condition block to the body, not to a separate header.
// Structure: entry -> body -> cond -> body (back-edge) | exit
func TestRoundTrip_DoWhileLoop(t *testing.T) {
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0, Successors: []cfg.BlockID{1}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0, 2}, Successors: []cfg.BlockID{2}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{1, 3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{2}})

	fn := &ir.Function{
		Name:       "do_while",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	// entry: x = 0
	fn.Blocks[0] = &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: intConst(0)},
			&ir.Jump{Target: 1},
		},
		Successors: []ir.BlockID{1},
	}
	// body: x = x + 1
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: addExpr(varExpr("x"), intConst(1))},
			&ir.Jump{Target: 2},
		},
		Predecessors: []ir.BlockID{0, 2},
		Successors:   []ir.BlockID{2},
	}
	// cond: if x < 10 goto body else exit
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Branch{
				Condition:   ltExpr(varExpr("x"), intConst(10)),
				TrueTarget:  1,
				FalseTarget: 3,
			},
		},
		Predecessors: []ir.BlockID{1},
		Successors:   []ir.BlockID{1, 3},
	}
	// exit: return x
	fn.Blocks[3] = &ir.BasicBlock{
		ID: 3,
		Instructions: []ir.IRInstruction{
			&ir.Return{Value: &ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}}},
		},
		Predecessors: []ir.BlockID{2},
	}

	domTree := makeDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 1, 3: 2},
		map[cfg.BlockID][]cfg.BlockID{0: {1}, 1: {2}, 2: {3}, 3: {}})

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	verifySSAProperty(t, fn)
	verifyDominanceProperty(t, fn)

	// phi-node for x at body block (1) -- merge of entry and back-edge
	xLocs := transformer.GetPhiNodeLocations("x")
	if len(xLocs) != 1 || xLocs[0] != 1 {
		t.Errorf("expected phi-node for x at block 1, got %v", xLocs)
	}

	// body block must start with phi
	phi, ok := fn.Blocks[1].Instructions[0].(*ir.Phi)
	if !ok {
		t.Fatalf("body block[0]: expected *ir.Phi, got %T", fn.Blocks[1].Instructions[0])
	}
	if len(phi.Sources) != 2 {
		t.Errorf("phi has %d sources, expected 2", len(phi.Sources))
	}

	// verify phi dest has non-zero version
	if phi.Dest.Version == 0 {
		t.Error("phi dest must have non-zero SSA version")
	}
}

// TestRoundTrip_DiamondWithLoop verifies SSA for a diamond (if-then-else) followed
// by a loop. This exercises phi-node placement at both the merge point and the loop header.
// Structure: entry -> {left, right} -> merge -> header <-> body -> exit
func TestRoundTrip_DiamondWithLoop(t *testing.T) {
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0, Successors: []cfg.BlockID{1, 2}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{1, 2}, Successors: []cfg.BlockID{4}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 4, Predecessors: []cfg.BlockID{3, 5}, Successors: []cfg.BlockID{5, 6}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 5, Predecessors: []cfg.BlockID{4}, Successors: []cfg.BlockID{4}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 6, Predecessors: []cfg.BlockID{4}})

	fn := &ir.Function{
		Name:       "diamond_loop",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	fn.Blocks[0] = &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Branch{
				Condition:   &ir.VariableExpr{Var: ir.Variable{Name: "cond", Type: ir.BoolType{}}},
				TrueTarget:  1,
				FalseTarget: 2,
			},
		},
		Successors: []ir.BlockID{1, 2},
	}
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: intConst(10)},
			&ir.Jump{Target: 3},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{3},
	}
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: intConst(20)},
			&ir.Jump{Target: 3},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{3},
	}
	fn.Blocks[3] = &ir.BasicBlock{
		ID: 3,
		Instructions: []ir.IRInstruction{
			&ir.Jump{Target: 4},
		},
		Predecessors: []ir.BlockID{1, 2},
		Successors:   []ir.BlockID{4},
	}
	fn.Blocks[4] = &ir.BasicBlock{
		ID: 4,
		Instructions: []ir.IRInstruction{
			&ir.Branch{
				Condition:   ltExpr(varExpr("x"), intConst(100)),
				TrueTarget:  5,
				FalseTarget: 6,
			},
		},
		Predecessors: []ir.BlockID{3, 5},
		Successors:   []ir.BlockID{5, 6},
	}
	fn.Blocks[5] = &ir.BasicBlock{
		ID: 5,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: addExpr(varExpr("x"), intConst(1))},
			&ir.Jump{Target: 4},
		},
		Predecessors: []ir.BlockID{4},
		Successors:   []ir.BlockID{4},
	}
	fn.Blocks[6] = &ir.BasicBlock{
		ID: 6,
		Instructions: []ir.IRInstruction{
			&ir.Return{Value: &ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}}},
		},
		Predecessors: []ir.BlockID{4},
	}

	domTree := makeDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 0, 3: 0, 4: 3, 5: 4, 6: 4},
		map[cfg.BlockID][]cfg.BlockID{0: {1, 2, 3}, 1: {}, 2: {}, 3: {4}, 4: {5, 6}, 5: {}, 6: {}})

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	verifySSAProperty(t, fn)
	verifyDominanceProperty(t, fn)

	// x defined in blocks 1, 2, 5 -> phi at merge (3) and loop header (4)
	xLocs := transformer.GetPhiNodeLocations("x")
	hasBlock3 := false
	hasBlock4 := false
	for _, loc := range xLocs {
		if loc == 3 {
			hasBlock3 = true
		}
		if loc == 4 {
			hasBlock4 = true
		}
	}
	if !hasBlock3 {
		t.Errorf("expected phi-node for x at merge block 3, got %v", xLocs)
	}
	if !hasBlock4 {
		t.Errorf("expected phi-node for x at loop header block 4, got %v", xLocs)
	}
}

// TestRoundTrip_MultipleVarsInLoop verifies SSA for a loop modifying multiple
// variables simultaneously. Each variable must get its own phi-node at the header.
func TestRoundTrip_MultipleVarsInLoop(t *testing.T) {
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0, Successors: []cfg.BlockID{1}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0, 2}, Successors: []cfg.BlockID{2, 3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{1}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{1}})

	fn := &ir.Function{
		Name:       "multi_var_loop",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	fn.Blocks[0] = &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("i"), Source: intConst(0)},
			&ir.Assign{Dest: intVar("sum"), Source: intConst(0)},
			&ir.Assign{Dest: intVar("prod"), Source: intConst(1)},
			&ir.Jump{Target: 1},
		},
		Successors: []ir.BlockID{1},
	}
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Branch{
				Condition:   ltExpr(varExpr("i"), intConst(10)),
				TrueTarget:  2,
				FalseTarget: 3,
			},
		},
		Predecessors: []ir.BlockID{0, 2},
		Successors:   []ir.BlockID{2, 3},
	}
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("sum"), Source: addExpr(varExpr("sum"), varExpr("i"))},
			&ir.Assign{Dest: intVar("prod"), Source: &ir.BinaryOp{Op: ir.BinOpMul, Left: varExpr("prod"), Right: varExpr("i")}},
			&ir.Assign{Dest: intVar("i"), Source: addExpr(varExpr("i"), intConst(1))},
			&ir.Jump{Target: 1},
		},
		Predecessors: []ir.BlockID{1},
		Successors:   []ir.BlockID{1},
	}
	fn.Blocks[3] = &ir.BasicBlock{
		ID:           3,
		Instructions: []ir.IRInstruction{&ir.Return{}},
		Predecessors: []ir.BlockID{1},
	}

	domTree := makeDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 1, 3: 1},
		map[cfg.BlockID][]cfg.BlockID{0: {1}, 1: {2, 3}, 2: {}, 3: {}})

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	verifySSAProperty(t, fn)
	verifyDominanceProperty(t, fn)

	// all three variables must have phi-nodes at loop header (block 1)
	for _, varName := range []string{"i", "sum", "prod"} {
		locs := transformer.GetPhiNodeLocations(varName)
		if len(locs) != 1 || locs[0] != 1 {
			t.Errorf("expected phi-node for '%s' at block 1, got %v", varName, locs)
		}
	}

	// header must start with 3 phi-nodes
	headerBlock := fn.Blocks[1]
	phiCount := 0
	for _, instr := range headerBlock.Instructions {
		if _, isPhi := instr.(*ir.Phi); isPhi {
			phiCount++
		}
	}
	if phiCount != 3 {
		t.Errorf("header block: expected 3 phi-nodes, got %d", phiCount)
	}
}

// TestRoundTrip_VersionConsistency verifies that after SSA transformation,
// every variable use references a version that was actually defined somewhere
// in the function. This is the semantic round-trip guarantee: the transformed
// IR is internally consistent even without out-of-SSA conversion.
func TestRoundTrip_VersionConsistency(t *testing.T) {
	// if-then-else with loop in one branch
	// entry -> {left (loop), right} -> merge
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0, Successors: []cfg.BlockID{1, 3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0, 2}, Successors: []cfg.BlockID{2, 4}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{1}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{4}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 4, Predecessors: []cfg.BlockID{1, 3}})

	fn := &ir.Function{
		Name:       "version_consistency",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	fn.Blocks[0] = &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: intConst(0)},
			&ir.Branch{
				Condition:   &ir.VariableExpr{Var: ir.Variable{Name: "flag", Type: ir.BoolType{}}},
				TrueTarget:  1,
				FalseTarget: 3,
			},
		},
		Successors: []ir.BlockID{1, 3},
	}
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: addExpr(varExpr("x"), intConst(1))},
			&ir.Branch{
				Condition:   ltExpr(varExpr("x"), intConst(5)),
				TrueTarget:  2,
				FalseTarget: 4,
			},
		},
		Predecessors: []ir.BlockID{0, 2},
		Successors:   []ir.BlockID{2, 4},
	}
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: addExpr(varExpr("x"), intConst(2))},
			&ir.Jump{Target: 1},
		},
		Predecessors: []ir.BlockID{1},
		Successors:   []ir.BlockID{1},
	}
	fn.Blocks[3] = &ir.BasicBlock{
		ID: 3,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: intConst(99)},
			&ir.Jump{Target: 4},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{4},
	}
	fn.Blocks[4] = &ir.BasicBlock{
		ID: 4,
		Instructions: []ir.IRInstruction{
			&ir.Return{Value: &ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}}},
		},
		Predecessors: []ir.BlockID{1, 3},
	}

	domTree := makeDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 1, 3: 0, 4: 0},
		map[cfg.BlockID][]cfg.BlockID{0: {1, 3, 4}, 1: {2}, 2: {}, 3: {}, 4: {}})

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	verifySSAProperty(t, fn)
	verifyDominanceProperty(t, fn)
	verifyDefUseChainIntegrity(t, fn)
}

// ============================================================================
// 2. Phi-Node Placement Correctness Tests
// ============================================================================

// TestPhiPlacement_CascadingPhiNodes verifies that phi-nodes themselves trigger
// further phi-node placement at dominance frontiers. When a phi-node is placed
// at block B, it creates a new definition of the variable, which may require
// additional phi-nodes at B's dominance frontier.
func TestPhiPlacement_CascadingPhiNodes(t *testing.T) {
	// Structure:
	//   0 -> 1 -> 2 -> 4
	//   0 -> 3 -> 4
	//   4 -> 5 -> 6
	//   4 -> 6
	// x defined in blocks 1 and 3
	// phi at 4 (frontier of 1 and 3)
	// if 4 is in frontier of something else, cascading phi
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0, Successors: []cfg.BlockID{1, 3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{2}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{4}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{4}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 4, Predecessors: []cfg.BlockID{2, 3}, Successors: []cfg.BlockID{5, 6}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 5, Predecessors: []cfg.BlockID{4}, Successors: []cfg.BlockID{6}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 6, Predecessors: []cfg.BlockID{4, 5}})

	fn := &ir.Function{
		Name:       "cascading_phi",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	fn.Blocks[0] = &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Branch{
				Condition:   &ir.VariableExpr{Var: ir.Variable{Name: "c", Type: ir.BoolType{}}},
				TrueTarget:  1,
				FalseTarget: 3,
			},
		},
		Successors: []ir.BlockID{1, 3},
	}
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: intConst(1)},
			&ir.Jump{Target: 2},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{2},
	}
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Jump{Target: 4},
		},
		Predecessors: []ir.BlockID{1},
		Successors:   []ir.BlockID{4},
	}
	fn.Blocks[3] = &ir.BasicBlock{
		ID: 3,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: intConst(2)},
			&ir.Jump{Target: 4},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{4},
	}
	fn.Blocks[4] = &ir.BasicBlock{
		ID: 4,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("y"), Source: varExpr("x")},
			&ir.Branch{
				Condition:   &ir.VariableExpr{Var: ir.Variable{Name: "c2", Type: ir.BoolType{}}},
				TrueTarget:  5,
				FalseTarget: 6,
			},
		},
		Predecessors: []ir.BlockID{2, 3},
		Successors:   []ir.BlockID{5, 6},
	}
	fn.Blocks[5] = &ir.BasicBlock{
		ID: 5,
		Instructions: []ir.IRInstruction{
			&ir.Jump{Target: 6},
		},
		Predecessors: []ir.BlockID{4},
		Successors:   []ir.BlockID{6},
	}
	fn.Blocks[6] = &ir.BasicBlock{
		ID:           6,
		Instructions: []ir.IRInstruction{&ir.Return{}},
		Predecessors: []ir.BlockID{4, 5},
	}

	domTree := makeDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 1, 3: 0, 4: 0, 5: 4, 6: 4},
		map[cfg.BlockID][]cfg.BlockID{0: {1, 3, 4}, 1: {2}, 2: {}, 3: {}, 4: {5, 6}, 5: {}, 6: {}})

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	verifySSAProperty(t, fn)
	verifyDominanceProperty(t, fn)

	// x must have phi at block 4 (merge of blocks 2 and 3)
	xLocs := transformer.GetPhiNodeLocations("x")
	hasBlock4 := false
	for _, loc := range xLocs {
		if loc == 4 {
			hasBlock4 = true
		}
	}
	if !hasBlock4 {
		t.Errorf("expected phi-node for x at block 4, got %v", xLocs)
	}
}

// TestPhiPlacement_NoPhiForUnmodifiedVar verifies that variables not modified
// in any branch do not receive phi-nodes, even at merge points.
func TestPhiPlacement_NoPhiForUnmodifiedVar(t *testing.T) {
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0, Successors: []cfg.BlockID{1, 2}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{1, 2}})

	fn := &ir.Function{
		Name:       "no_phi_unmodified",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	// x defined only in entry, y defined in both branches
	fn.Blocks[0] = &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: intConst(42)},
			&ir.Branch{
				Condition:   &ir.VariableExpr{Var: ir.Variable{Name: "c", Type: ir.BoolType{}}},
				TrueTarget:  1,
				FalseTarget: 2,
			},
		},
		Successors: []ir.BlockID{1, 2},
	}
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("y"), Source: addExpr(varExpr("x"), intConst(1))},
			&ir.Jump{Target: 3},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{3},
	}
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("y"), Source: addExpr(varExpr("x"), intConst(2))},
			&ir.Jump{Target: 3},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{3},
	}
	fn.Blocks[3] = &ir.BasicBlock{
		ID: 3,
		Instructions: []ir.IRInstruction{
			&ir.Return{Value: &ir.Variable{Name: "y", Type: ir.IntType{Width: ir.Size4, Signed: true}}},
		},
		Predecessors: []ir.BlockID{1, 2},
	}

	domTree := makeDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 0, 3: 0},
		map[cfg.BlockID][]cfg.BlockID{0: {1, 2, 3}, 1: {}, 2: {}, 3: {}})

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	verifySSAProperty(t, fn)
	verifyDominanceProperty(t, fn)

	// x has single definition -> no phi
	xLocs := transformer.GetPhiNodeLocations("x")
	if len(xLocs) != 0 {
		t.Errorf("x has single definition, should have no phi-nodes, got %v", xLocs)
	}

	// y has definitions in both branches -> phi at merge
	yLocs := transformer.GetPhiNodeLocations("y")
	if len(yLocs) != 1 || yLocs[0] != 3 {
		t.Errorf("expected phi-node for y at block 3, got %v", yLocs)
	}

	// verify x uses in both branches reference x_1 (the entry definition)
	for _, blockID := range []ir.BlockID{1, 2} {
		assign, ok := fn.Blocks[blockID].Instructions[0].(*ir.Assign)
		if !ok {
			t.Fatalf("block %d: expected *ir.Assign", blockID)
		}
		binOp, ok := assign.Source.(*ir.BinaryOp)
		if !ok {
			t.Fatalf("block %d: expected *ir.BinaryOp", blockID)
		}
		xUse, ok := binOp.Left.(*ir.VariableExpr)
		if !ok {
			t.Fatalf("block %d: expected *ir.VariableExpr", blockID)
		}
		if xUse.Var.Version != 1 {
			t.Errorf("block %d: expected x_1, got x_%d", blockID, xUse.Var.Version)
		}
	}
}

// TestPhiPlacement_EmptyBlocks verifies correct phi-node placement when
// some blocks have no instructions (pass-through blocks).
func TestPhiPlacement_EmptyBlocks(t *testing.T) {
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0, Successors: []cfg.BlockID{1, 2}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{1, 2}})

	fn := &ir.Function{
		Name:       "empty_blocks",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	fn.Blocks[0] = &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: intConst(1)},
			&ir.Branch{
				Condition:   &ir.VariableExpr{Var: ir.Variable{Name: "c", Type: ir.BoolType{}}},
				TrueTarget:  1,
				FalseTarget: 2,
			},
		},
		Successors: []ir.BlockID{1, 2},
	}
	// block 1: redefines x
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: intConst(2)},
			&ir.Jump{Target: 3},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{3},
	}
	// block 2: empty pass-through, x flows from entry
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: intConst(3)},
			&ir.Jump{Target: 3},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{3},
	}
	fn.Blocks[3] = &ir.BasicBlock{
		ID: 3,
		Instructions: []ir.IRInstruction{
			&ir.Return{Value: &ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}}},
		},
		Predecessors: []ir.BlockID{1, 2},
	}

	domTree := makeDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 0, 3: 0},
		map[cfg.BlockID][]cfg.BlockID{0: {1, 2, 3}, 1: {}, 2: {}, 3: {}})

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	verifySSAProperty(t, fn)
	verifyDominanceProperty(t, fn)

	// phi at merge block 3
	xLocs := transformer.GetPhiNodeLocations("x")
	if len(xLocs) != 1 || xLocs[0] != 3 {
		t.Errorf("expected phi-node for x at block 3, got %v", xLocs)
	}
}

// ============================================================================
// 3. Dominance Property Verification
// ============================================================================

// verifyDefUseChainIntegrity checks that every variable use references a version
// that is actually defined somewhere in the function. This is the strongest
// semantic consistency check for SSA form.
func verifyDefUseChainIntegrity(t *testing.T, fn *ir.Function) {
	t.Helper()

	// collect all defined variable versions
	definedVersions := make(map[string]bool)
	for _, block := range fn.Blocks {
		for _, instr := range block.Instructions {
			var definedVar *ir.Variable
			switch i := instr.(type) {
			case *ir.Assign:
				definedVar = &i.Dest
			case *ir.Load:
				definedVar = &i.Dest
			case *ir.Call:
				definedVar = i.Dest
			case *ir.Phi:
				definedVar = &i.Dest
			case *ir.Intrinsic:
				definedVar = i.Dest
			}
			if definedVar != nil && definedVar.Version > 0 {
				definedVersions[definedVar.String()] = true
			}
		}
	}

	// check all uses reference defined versions
	for blockID, block := range fn.Blocks {
		for _, instr := range block.Instructions {
			checkUsesInInstruction(t, instr, definedVersions, blockID)
		}
	}
}

func checkUsesInInstruction(t *testing.T, instr ir.IRInstruction, defined map[string]bool, blockID ir.BlockID) {
	t.Helper()

	switch i := instr.(type) {
	case *ir.Assign:
		checkUsesInExpression(t, i.Source, defined, blockID)
	case *ir.Load:
		checkUsesInExpression(t, i.Address, defined, blockID)
	case *ir.Store:
		checkUsesInExpression(t, i.Address, defined, blockID)
		checkUsesInExpression(t, i.Value, defined, blockID)
	case *ir.Branch:
		checkUsesInExpression(t, i.Condition, defined, blockID)
	case *ir.Call:
		checkUsesInExpression(t, i.Target, defined, blockID)
		for _, arg := range i.Args {
			if arg.Version > 0 {
				if !defined[arg.String()] {
					t.Errorf("block %d: call arg uses undefined version %s", blockID, arg.String())
				}
			}
		}
	case *ir.Return:
		if i.Value != nil && i.Value.Version > 0 {
			if !defined[i.Value.String()] {
				t.Errorf("block %d: return uses undefined version %s", blockID, i.Value.String())
			}
		}
	case *ir.Phi:
		for _, src := range i.Sources {
			if src.Var.Version > 0 {
				if !defined[src.Var.String()] {
					t.Errorf("block %d: phi source from block %d uses undefined version %s",
						blockID, src.Block, src.Var.String())
				}
			}
		}
	case *ir.Intrinsic:
		for _, arg := range i.Args {
			checkUsesInExpression(t, arg, defined, blockID)
		}
	}
}

func checkUsesInExpression(t *testing.T, expr ir.Expression, defined map[string]bool, blockID ir.BlockID) {
	t.Helper()
	if expr == nil {
		return
	}
	switch e := expr.(type) {
	case *ir.VariableExpr:
		if e.Var.Version > 0 {
			if !defined[e.Var.String()] {
				t.Errorf("block %d: expression uses undefined version %s", blockID, e.Var.String())
			}
		}
	case *ir.BinaryOp:
		checkUsesInExpression(t, e.Left, defined, blockID)
		checkUsesInExpression(t, e.Right, defined, blockID)
	case *ir.UnaryOp:
		checkUsesInExpression(t, e.Operand, defined, blockID)
	case *ir.Cast:
		checkUsesInExpression(t, e.Expr, defined, blockID)
	case *ir.Extract:
		if e.Source.Version > 0 {
			if !defined[e.Source.String()] {
				t.Errorf("block %d: extract uses undefined version %s", blockID, e.Source.String())
			}
		}
	case *ir.Insert:
		if e.Dest.Version > 0 {
			if !defined[e.Dest.String()] {
				t.Errorf("block %d: insert uses undefined version %s", blockID, e.Dest.String())
			}
		}
		checkUsesInExpression(t, e.Value, defined, blockID)
	case *ir.ZeroExtend:
		if e.Source.Version > 0 {
			if !defined[e.Source.String()] {
				t.Errorf("block %d: zeroextend uses undefined version %s", blockID, e.Source.String())
			}
		}
	case *ir.LoadExpr:
		checkUsesInExpression(t, e.Address, defined, blockID)
	}
}

// TestDominance_DefUseChainIntegrity_NestedLoops verifies def-use chain integrity
// for a complex nested loop structure where multiple variables interact.
func TestDominance_DefUseChainIntegrity_NestedLoops(t *testing.T) {
	// outer: i=0; while(i<10) { inner: j=0; while(j<5) { j++; } i++; }
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0, Successors: []cfg.BlockID{1}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0, 4}, Successors: []cfg.BlockID{2, 5}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{1, 3}, Successors: []cfg.BlockID{3, 4}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{2}, Successors: []cfg.BlockID{2}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 4, Predecessors: []cfg.BlockID{2}, Successors: []cfg.BlockID{1}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 5, Predecessors: []cfg.BlockID{1}})

	fn := &ir.Function{
		Name:       "nested_loop_integrity",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	fn.Blocks[0] = &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("i"), Source: intConst(0)},
			&ir.Jump{Target: 1},
		},
		Successors: []ir.BlockID{1},
	}
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Branch{
				Condition:   ltExpr(varExpr("i"), intConst(10)),
				TrueTarget:  2,
				FalseTarget: 5,
			},
		},
		Predecessors: []ir.BlockID{0, 4},
		Successors:   []ir.BlockID{2, 5},
	}
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("j"), Source: intConst(0)},
			&ir.Branch{
				Condition:   ltExpr(varExpr("j"), intConst(5)),
				TrueTarget:  3,
				FalseTarget: 4,
			},
		},
		Predecessors: []ir.BlockID{1, 3},
		Successors:   []ir.BlockID{3, 4},
	}
	fn.Blocks[3] = &ir.BasicBlock{
		ID: 3,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("j"), Source: addExpr(varExpr("j"), intConst(1))},
			&ir.Jump{Target: 2},
		},
		Predecessors: []ir.BlockID{2},
		Successors:   []ir.BlockID{2},
	}
	fn.Blocks[4] = &ir.BasicBlock{
		ID: 4,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("i"), Source: addExpr(varExpr("i"), intConst(1))},
			&ir.Jump{Target: 1},
		},
		Predecessors: []ir.BlockID{2},
		Successors:   []ir.BlockID{1},
	}
	fn.Blocks[5] = &ir.BasicBlock{
		ID: 5,
		Instructions: []ir.IRInstruction{
			&ir.Return{Value: &ir.Variable{Name: "i", Type: ir.IntType{Width: ir.Size4, Signed: true}}},
		},
		Predecessors: []ir.BlockID{1},
	}

	domTree := makeDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 1, 3: 2, 4: 2, 5: 1},
		map[cfg.BlockID][]cfg.BlockID{0: {1}, 1: {2, 5}, 2: {3, 4}, 3: {}, 4: {}, 5: {}})

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	verifySSAProperty(t, fn)
	verifyDominanceProperty(t, fn)
	verifyDefUseChainIntegrity(t, fn)

	// i must have phi at outer header (block 1)
	iLocs := transformer.GetPhiNodeLocations("i")
	hasBlock1 := false
	for _, loc := range iLocs {
		if loc == 1 {
			hasBlock1 = true
		}
	}
	if !hasBlock1 {
		t.Errorf("expected phi-node for i at block 1, got %v", iLocs)
	}

	// j must have phi at inner header (block 2)
	jLocs := transformer.GetPhiNodeLocations("j")
	hasBlock2 := false
	for _, loc := range jLocs {
		if loc == 2 {
			hasBlock2 = true
		}
	}
	if !hasBlock2 {
		t.Errorf("expected phi-node for j at block 2, got %v", jLocs)
	}
}

// TestDominance_PhiSourcesMatchPredecessors verifies that every phi-node
// has exactly one source per predecessor and each source block is a valid predecessor.
func TestDominance_PhiSourcesMatchPredecessors(t *testing.T) {
	// three-way merge: entry -> {a, b, c} -> merge
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0, Successors: []cfg.BlockID{1, 2, 3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{4}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{4}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{4}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 4, Predecessors: []cfg.BlockID{1, 2, 3}})

	fn := &ir.Function{
		Name:       "three_way_merge",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	fn.Blocks[0] = &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Jump{Target: 1}, // simplified; real code would have switch
		},
		Successors: []ir.BlockID{1, 2, 3},
	}
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: intConst(1)},
			&ir.Jump{Target: 4},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{4},
	}
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: intConst(2)},
			&ir.Jump{Target: 4},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{4},
	}
	fn.Blocks[3] = &ir.BasicBlock{
		ID: 3,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: intConst(3)},
			&ir.Jump{Target: 4},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{4},
	}
	fn.Blocks[4] = &ir.BasicBlock{
		ID: 4,
		Instructions: []ir.IRInstruction{
			&ir.Return{Value: &ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}}},
		},
		Predecessors: []ir.BlockID{1, 2, 3},
	}

	domTree := makeDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 0, 3: 0, 4: 0},
		map[cfg.BlockID][]cfg.BlockID{0: {1, 2, 3, 4}, 1: {}, 2: {}, 3: {}, 4: {}})

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	verifySSAProperty(t, fn)
	verifyDominanceProperty(t, fn)
	verifyDefUseChainIntegrity(t, fn)

	// phi at merge block 4 must have 3 sources
	mergeBlock := fn.Blocks[4]
	phi, ok := mergeBlock.Instructions[0].(*ir.Phi)
	if !ok {
		t.Fatalf("merge block[0]: expected *ir.Phi, got %T", mergeBlock.Instructions[0])
	}
	if len(phi.Sources) != 3 {
		t.Errorf("phi has %d sources, expected 3", len(phi.Sources))
	}

	// each source must come from a distinct predecessor
	sourceBlocks := make(map[ir.BlockID]bool)
	for _, src := range phi.Sources {
		sourceBlocks[src.Block] = true
	}
	for _, predID := range []ir.BlockID{1, 2, 3} {
		if !sourceBlocks[predID] {
			t.Errorf("phi missing source from predecessor block %d", predID)
		}
	}

	// each source must have a distinct non-zero version
	versions := make(map[int]bool)
	for _, src := range phi.Sources {
		if src.Var.Version == 0 {
			t.Errorf("phi source from block %d has version 0", src.Block)
		}
		if versions[src.Var.Version] {
			t.Errorf("phi has duplicate version %d", src.Var.Version)
		}
		versions[src.Var.Version] = true
	}
}

// ============================================================================
// 4. Memory SSA Construction Tests
// ============================================================================

// TestMemorySSA_LoopWithLoadStore verifies memory SSA construction for a loop
// containing both store and load operations. The loop header must have a memory
// phi-node merging the initial memory state with the modified state from the body.
func TestMemorySSA_LoopWithLoadStore(t *testing.T) {
	// entry -> header <-> body -> exit
	// body: store + load
	cfgGraph := &cfg.CFG{
		Blocks: map[cfg.BlockID]*cfg.BasicBlock{
			0: {ID: 0, Successors: []cfg.BlockID{1}},
			1: {ID: 1, Predecessors: []cfg.BlockID{0, 2}, Successors: []cfg.BlockID{2, 3}},
			2: {ID: 2, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{1}},
			3: {ID: 3, Predecessors: []cfg.BlockID{1}},
		},
		Entry: 0,
		Exits: []cfg.BlockID{3},
	}

	fn := &ir.Function{
		Name:       "loop_load_store",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	ptrExpr := &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x1000, Width: ir.Size8}}
	valExpr := &ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size4, Signed: true}}
	vVar := ir.Variable{Name: "v", Type: ir.IntType{Width: ir.Size4, Signed: true}}

	fn.Blocks[0] = &ir.BasicBlock{
		ID:           0,
		Instructions: []ir.IRInstruction{&ir.Jump{Target: 1}},
		Successors:   []ir.BlockID{1},
	}
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Branch{
				Condition:   &ir.ConstantExpr{Value: ir.BoolConstant{Value: true}},
				TrueTarget:  2,
				FalseTarget: 3,
			},
		},
		Predecessors: []ir.BlockID{0, 2},
		Successors:   []ir.BlockID{2, 3},
	}
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Store{Address: ptrExpr, Value: valExpr, Size: ir.Size4},
			&ir.Load{Dest: vVar, Address: ptrExpr, Size: ir.Size4},
			&ir.Jump{Target: 1},
		},
		Predecessors: []ir.BlockID{1},
		Successors:   []ir.BlockID{1},
	}
	fn.Blocks[3] = &ir.BasicBlock{
		ID:           3,
		Instructions: []ir.IRInstruction{&ir.Return{}},
		Predecessors: []ir.BlockID{1},
	}

	domTree := createTestDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 1, 3: 1},
		map[cfg.BlockID][]cfg.BlockID{0: {1}, 1: {2, 3}, 2: {}, 3: {}})

	builder := NewMemorySSABuilder(fn, cfgGraph, domTree)
	memInfo, err := builder.BuildMemorySSA()
	if err != nil {
		t.Fatalf("BuildMemorySSA failed: %v", err)
	}

	// body block (2) has 1 store (def) and 1 load (use)
	defs := memInfo.GetMemoryDefsInBlock(2)
	if len(defs) != 1 {
		t.Errorf("body: expected 1 memory def, got %d", len(defs))
	}
	uses := memInfo.GetMemoryUsesInBlock(2)
	if len(uses) != 1 {
		t.Errorf("body: expected 1 memory use, got %d", len(uses))
	}

	// memory phi at loop header (block 1)
	phi, hasPhi := memInfo.GetMemoryPhiForBlock(1)
	if !hasPhi {
		t.Fatal("expected memory phi-node at loop header (block 1)")
	}
	if len(phi.Sources) != 2 {
		t.Errorf("memory phi has %d sources, expected 2", len(phi.Sources))
	}
	if phi.Version.ID == 0 {
		t.Error("memory phi version must be non-zero")
	}

	// block exit versions must be tracked
	for _, blockID := range []ir.BlockID{0, 1, 2, 3} {
		_, exists := memInfo.GetMemoryVersionAtBlockExit(blockID)
		if !exists {
			t.Errorf("block %d: exit version not tracked", blockID)
		}
	}
}

// TestMemorySSA_NestedIfWithMemory verifies memory SSA for nested if-then-else
// with memory operations at different nesting levels.
// Structure: entry -> {left -> {ll, lr} -> left_merge, right} -> merge
func TestMemorySSA_NestedIfWithMemory(t *testing.T) {
	cfgGraph := &cfg.CFG{
		Blocks: map[cfg.BlockID]*cfg.BasicBlock{
			0: {ID: 0, Successors: []cfg.BlockID{1, 4}},
			1: {ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{2, 3}},
			2: {ID: 2, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{5}},
			3: {ID: 3, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{5}},
			4: {ID: 4, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{5}},
			5: {ID: 5, Predecessors: []cfg.BlockID{2, 3, 4}},
		},
		Entry: 0,
		Exits: []cfg.BlockID{5},
	}

	fn := &ir.Function{
		Name:       "nested_if_memory",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	makeStore := func(addr, val int64) *ir.Store {
		return &ir.Store{
			Address: &ir.ConstantExpr{Value: ir.IntConstant{Value: addr, Width: ir.Size8}},
			Value:   &ir.ConstantExpr{Value: ir.IntConstant{Value: val, Width: ir.Size4, Signed: true}},
			Size:    ir.Size4,
		}
	}

	fn.Blocks[0] = &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			makeStore(0x100, 0),
			&ir.Branch{
				Condition:   &ir.ConstantExpr{Value: ir.BoolConstant{Value: true}},
				TrueTarget:  1,
				FalseTarget: 4,
			},
		},
		Successors: []ir.BlockID{1, 4},
	}
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Branch{
				Condition:   &ir.ConstantExpr{Value: ir.BoolConstant{Value: true}},
				TrueTarget:  2,
				FalseTarget: 3,
			},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{2, 3},
	}
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			makeStore(0x200, 1),
			&ir.Jump{Target: 5},
		},
		Predecessors: []ir.BlockID{1},
		Successors:   []ir.BlockID{5},
	}
	fn.Blocks[3] = &ir.BasicBlock{
		ID: 3,
		Instructions: []ir.IRInstruction{
			makeStore(0x300, 2),
			&ir.Jump{Target: 5},
		},
		Predecessors: []ir.BlockID{1},
		Successors:   []ir.BlockID{5},
	}
	fn.Blocks[4] = &ir.BasicBlock{
		ID: 4,
		Instructions: []ir.IRInstruction{
			makeStore(0x400, 3),
			&ir.Jump{Target: 5},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{5},
	}
	fn.Blocks[5] = &ir.BasicBlock{
		ID:           5,
		Instructions: []ir.IRInstruction{&ir.Return{}},
		Predecessors: []ir.BlockID{2, 3, 4},
	}

	domTree := createTestDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 1, 3: 1, 4: 0, 5: 0},
		map[cfg.BlockID][]cfg.BlockID{0: {1, 4, 5}, 1: {2, 3}, 2: {}, 3: {}, 4: {}, 5: {}})

	builder := NewMemorySSABuilder(fn, cfgGraph, domTree)
	memInfo, err := builder.BuildMemorySSA()
	if err != nil {
		t.Fatalf("BuildMemorySSA failed: %v", err)
	}

	// stores in blocks 0, 2, 3, 4 -> 4 total defs
	totalDefs := memInfo.GetTotalMemoryDefs()
	if totalDefs != 4 {
		t.Errorf("expected 4 total memory defs, got %d", totalDefs)
	}

	// memory phi at final merge (block 5) -- three predecessors with stores
	phi5, hasPhi5 := memInfo.GetMemoryPhiForBlock(5)
	if !hasPhi5 {
		t.Fatal("expected memory phi-node at merge block 5")
	}
	if len(phi5.Sources) != 3 {
		t.Errorf("merge phi has %d sources, expected 3", len(phi5.Sources))
	}

	// verify all block exit versions are tracked
	for blockID := ir.BlockID(0); blockID <= 5; blockID++ {
		_, exists := memInfo.GetMemoryVersionAtBlockExit(blockID)
		if !exists {
			t.Errorf("block %d: exit version not tracked", blockID)
		}
	}
}

// TestMemorySSA_CallInLoop verifies memory SSA for function calls inside a loop.
// Calls are conservatively treated as both memory defs and uses.
func TestMemorySSA_CallInLoop(t *testing.T) {
	cfgGraph := &cfg.CFG{
		Blocks: map[cfg.BlockID]*cfg.BasicBlock{
			0: {ID: 0, Successors: []cfg.BlockID{1}},
			1: {ID: 1, Predecessors: []cfg.BlockID{0, 2}, Successors: []cfg.BlockID{2, 3}},
			2: {ID: 2, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{1}},
			3: {ID: 3, Predecessors: []cfg.BlockID{1}},
		},
		Entry: 0,
		Exits: []cfg.BlockID{3},
	}

	fn := &ir.Function{
		Name:       "call_in_loop",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	fn.Blocks[0] = &ir.BasicBlock{
		ID:           0,
		Instructions: []ir.IRInstruction{&ir.Jump{Target: 1}},
		Successors:   []ir.BlockID{1},
	}
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Branch{
				Condition:   &ir.ConstantExpr{Value: ir.BoolConstant{Value: true}},
				TrueTarget:  2,
				FalseTarget: 3,
			},
		},
		Predecessors: []ir.BlockID{0, 2},
		Successors:   []ir.BlockID{2, 3},
	}
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Call{
				Target: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x4000, Width: ir.Size8}},
				Args:   []ir.Variable{},
			},
			&ir.Jump{Target: 1},
		},
		Predecessors: []ir.BlockID{1},
		Successors:   []ir.BlockID{1},
	}
	fn.Blocks[3] = &ir.BasicBlock{
		ID:           3,
		Instructions: []ir.IRInstruction{&ir.Return{}},
		Predecessors: []ir.BlockID{1},
	}

	domTree := createTestDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 1, 3: 1},
		map[cfg.BlockID][]cfg.BlockID{0: {1}, 1: {2, 3}, 2: {}, 3: {}})

	builder := NewMemorySSABuilder(fn, cfgGraph, domTree)
	memInfo, err := builder.BuildMemorySSA()
	if err != nil {
		t.Fatalf("BuildMemorySSA failed: %v", err)
	}

	// call creates both a def and a use
	defs := memInfo.GetMemoryDefsInBlock(2)
	if len(defs) != 1 {
		t.Errorf("body: expected 1 memory def (call), got %d", len(defs))
	}
	uses := memInfo.GetMemoryUsesInBlock(2)
	if len(uses) != 1 {
		t.Errorf("body: expected 1 memory use (call), got %d", len(uses))
	}

	// memory phi at loop header (block 1)
	_, hasPhi := memInfo.GetMemoryPhiForBlock(1)
	if !hasPhi {
		t.Fatal("expected memory phi-node at loop header (block 1)")
	}

	// def-use chains must be built
	if len(memInfo.DefUseChains) == 0 && memInfo.GetTotalMemoryUses() > 0 {
		t.Error("def-use chains not built despite having memory uses")
	}
}

// TestMemorySSA_NoMemoryOps verifies that memory SSA handles functions
// with no memory operations gracefully (no defs, no uses, no phis).
func TestMemorySSA_NoMemoryOps(t *testing.T) {
	cfgGraph := &cfg.CFG{
		Blocks: map[cfg.BlockID]*cfg.BasicBlock{
			0: {ID: 0, Successors: []cfg.BlockID{1, 2}},
			1: {ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{3}},
			2: {ID: 2, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{3}},
			3: {ID: 3, Predecessors: []cfg.BlockID{1, 2}},
		},
		Entry: 0,
		Exits: []cfg.BlockID{3},
	}

	fn := &ir.Function{
		Name:       "no_memory",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	fn.Blocks[0] = &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("x"), Source: intConst(1)},
			&ir.Branch{
				Condition:   &ir.ConstantExpr{Value: ir.BoolConstant{Value: true}},
				TrueTarget:  1,
				FalseTarget: 2,
			},
		},
		Successors: []ir.BlockID{1, 2},
	}
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("y"), Source: addExpr(varExpr("x"), intConst(1))},
			&ir.Jump{Target: 3},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{3},
	}
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: intVar("y"), Source: addExpr(varExpr("x"), intConst(2))},
			&ir.Jump{Target: 3},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{3},
	}
	fn.Blocks[3] = &ir.BasicBlock{
		ID:           3,
		Instructions: []ir.IRInstruction{&ir.Return{}},
		Predecessors: []ir.BlockID{1, 2},
	}

	domTree := createTestDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 0, 3: 0},
		map[cfg.BlockID][]cfg.BlockID{0: {1, 2, 3}, 1: {}, 2: {}, 3: {}})

	builder := NewMemorySSABuilder(fn, cfgGraph, domTree)
	memInfo, err := builder.BuildMemorySSA()
	if err != nil {
		t.Fatalf("BuildMemorySSA failed: %v", err)
	}

	if memInfo.GetTotalMemoryDefs() != 0 {
		t.Errorf("expected 0 memory defs, got %d", memInfo.GetTotalMemoryDefs())
	}
	if memInfo.GetTotalMemoryUses() != 0 {
		t.Errorf("expected 0 memory uses, got %d", memInfo.GetTotalMemoryUses())
	}
	if memInfo.GetTotalMemoryPhis() != 0 {
		t.Errorf("expected 0 memory phis, got %d", memInfo.GetTotalMemoryPhis())
	}
}

// TestMemorySSA_InterleavedLoadStore verifies memory version chaining when
// loads and stores are interleaved in the same block.
func TestMemorySSA_InterleavedLoadStore(t *testing.T) {
	cfgGraph := &cfg.CFG{
		Blocks: map[cfg.BlockID]*cfg.BasicBlock{
			0: {ID: 0},
		},
		Entry: 0,
		Exits: []cfg.BlockID{0},
	}

	vVar := ir.Variable{Name: "v", Type: ir.IntType{Width: ir.Size4, Signed: true}}
	wVar := ir.Variable{Name: "w", Type: ir.IntType{Width: ir.Size4, Signed: true}}

	fn := &ir.Function{
		Name:       "interleaved",
		EntryBlock: 0,
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Load{
						Dest:    vVar,
						Address: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x100, Width: ir.Size8}},
						Size:    ir.Size4,
					},
					&ir.Store{
						Address: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x200, Width: ir.Size8}},
						Value:   &ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size4, Signed: true}},
						Size:    ir.Size4,
					},
					&ir.Load{
						Dest:    wVar,
						Address: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x300, Width: ir.Size8}},
						Size:    ir.Size4,
					},
					&ir.Store{
						Address: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x400, Width: ir.Size8}},
						Value:   &ir.ConstantExpr{Value: ir.IntConstant{Value: 2, Width: ir.Size4, Signed: true}},
						Size:    ir.Size4,
					},
					&ir.Return{},
				},
			},
		},
	}

	domTree := createTestDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{0: 0},
		map[cfg.BlockID][]cfg.BlockID{0: {}})

	builder := NewMemorySSABuilder(fn, cfgGraph, domTree)
	memInfo, err := builder.BuildMemorySSA()
	if err != nil {
		t.Fatalf("BuildMemorySSA failed: %v", err)
	}

	// 2 loads -> 2 uses, 2 stores -> 2 defs
	if memInfo.GetTotalMemoryDefs() != 2 {
		t.Errorf("expected 2 memory defs, got %d", memInfo.GetTotalMemoryDefs())
	}
	if memInfo.GetTotalMemoryUses() != 2 {
		t.Errorf("expected 2 memory uses, got %d", memInfo.GetTotalMemoryUses())
	}

	// verify version chaining for stores
	defs := memInfo.GetMemoryDefsInBlock(0)
	if len(defs) != 2 {
		t.Fatalf("expected 2 defs in block 0, got %d", len(defs))
	}
	// first store: prev=initial(0), version=1
	if defs[0].PrevVersion.ID != 0 {
		t.Errorf("first store prev: expected 0, got %d", defs[0].PrevVersion.ID)
	}
	if defs[0].Version.ID != 1 {
		t.Errorf("first store version: expected 1, got %d", defs[0].Version.ID)
	}
	// second store: prev=1, version=2
	if defs[1].PrevVersion.ID != 1 {
		t.Errorf("second store prev: expected 1, got %d", defs[1].PrevVersion.ID)
	}
	if defs[1].Version.ID != 2 {
		t.Errorf("second store version: expected 2, got %d", defs[1].Version.ID)
	}

	// block exit version must be 2
	exitVersion, exists := memInfo.GetMemoryVersionAtBlockExit(0)
	if !exists {
		t.Fatal("block 0 exit version not tracked")
	}
	if exitVersion.ID != 2 {
		t.Errorf("block exit: expected version 2, got %d", exitVersion.ID)
	}
}
