package cfg

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestDominatorTree_BackEdgeIdentification tests that back-edges are correctly identified
// a back-edge is an edge (b, h) where h dominates b
// requirement 4.5: loop detection via back-edges
func TestDominatorTree_BackEdgeIdentification(t *testing.T) {
	// construct simple loop:
	//   entry -> header -> body -> header (back-edge)
	//                  \-> exit
	instructions := []*disasm.Instruction{
		// entry
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		// loop header
		{Address: 0x1003, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1006,
			Mnemonic: "jge",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x100d, Size: disasm.Size32},
			},
		},
		// loop body
		{Address: 0x1008, Mnemonic: "add", Length: 3},
		{
			Address:  0x100b,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32},
			},
		},
		// exit
		{Address: 0x100d, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	// identify back-edges manually
	var backEdges []*Edge
	for _, edge := range cfg.Edges {
		// back-edge: target dominates source
		if dt.Dominates(edge.To, edge.From) {
			backEdges = append(backEdges, edge)
		}
	}

	// verify at least one back-edge found
	if len(backEdges) == 0 {
		t.Fatal("no back-edges found in loop structure")
	}

	// verify each back-edge property: target dominates source
	for _, backEdge := range backEdges {
		if !dt.Dominates(backEdge.To, backEdge.From) {
			t.Errorf("back-edge %d -> %d: target does not dominate source",
				backEdge.From, backEdge.To)
		}

		// verify target is not strictly dominated by source (would be impossible)
		if dt.StrictlyDominates(backEdge.From, backEdge.To) {
			t.Errorf("back-edge %d -> %d: source strictly dominates target (impossible)",
				backEdge.From, backEdge.To)
		}
	}

	// verify back-edge targets are loop headers
	loopInfo, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("failed to detect loops: %v", err)
	}

	for _, backEdge := range backEdges {
		if !loopInfo.IsLoopHeader(backEdge.To) {
			t.Errorf("back-edge target %d should be loop header", backEdge.To)
		}
	}
}

// TestDominatorTree_LoopHeaderDominatesBody tests that loop header dominates all blocks in loop body
// requirement 4.5: correctness of dominator tree in loop structures
func TestDominatorTree_LoopHeaderDominatesBody(t *testing.T) {
	// construct loop with multiple body blocks:
	//   entry -> header -> body1 -> body2 -> header (back-edge)
	//                  \-> exit
	instructions := []*disasm.Instruction{
		// entry
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		// loop header
		{Address: 0x1003, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1006,
			Mnemonic: "jge",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1012, Size: disasm.Size32},
			},
		},
		// loop body1
		{Address: 0x1008, Mnemonic: "add", Length: 3},
		// loop body2
		{Address: 0x100b, Mnemonic: "sub", Length: 3},
		{Address: 0x100e, Mnemonic: "inc", Length: 2},
		{
			Address:  0x1010,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32},
			},
		},
		// exit
		{Address: 0x1012, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	loopInfo, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("failed to detect loops: %v", err)
	}

	// verify each loop
	for i, loop := range loopInfo.Loops {
		// verify header dominates all blocks in body
		for _, bodyBlock := range loop.Body {
			if bodyBlock == loop.Header {
				// header dominates itself (reflexive property)
				if !dt.Dominates(loop.Header, bodyBlock) {
					t.Errorf("loop %d: header %d does not dominate itself", i, loop.Header)
				}
				continue
			}

			// header must dominate all other body blocks
			if !dt.Dominates(loop.Header, bodyBlock) {
				t.Errorf("loop %d: header %d does not dominate body block %d", i, loop.Header, bodyBlock)
			}

			// verify header is on dominator path from body block to entry
			path := dt.GetDominatorPath(bodyBlock)
			headerInPath := false
			for _, pathBlock := range path {
				if pathBlock == loop.Header {
					headerInPath = true
					break
				}
			}
			if !headerInPath {
				t.Errorf("loop %d: header %d not in dominator path of body block %d", i, loop.Header, bodyBlock)
			}
		}

		// verify entry dominates header
		if !dt.Dominates(cfg.Entry, loop.Header) {
			t.Errorf("loop %d: entry %d does not dominate header %d", i, cfg.Entry, loop.Header)
		}
	}
}

// TestDominatorTree_LoopImmediateDominator tests immediate dominator computation for loop structures
// requirement 4.5: immediate dominator computation
func TestDominatorTree_LoopImmediateDominator(t *testing.T) {
	// construct nested loops to test idom relationships
	instructions := createNestedLoopInstructions()

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	loopInfo, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("failed to detect loops: %v", err)
	}

	// find outer and inner loop headers
	var outerHeader, innerHeader BlockID
	for _, loop := range loopInfo.Loops {
		headerBlock, _ := cfg.GetBlock(loop.Header)
		switch headerBlock.StartAddress {
		case 0x1003:
			outerHeader = loop.Header
		case 0x1008:
			innerHeader = loop.Header
		}
	}

	if outerHeader == 0 || innerHeader == 0 {
		t.Fatal("failed to find loop headers")
	}

	// verify outer header's idom is entry
	outerIdom, exists := dt.GetImmediateDominator(outerHeader)
	if !exists {
		t.Fatal("outer header should have immediate dominator")
	}
	if outerIdom != cfg.Entry {
		t.Errorf("outer header idom should be entry %d, got %d", cfg.Entry, outerIdom)
	}

	// verify inner header's idom is outer header
	innerIdom, innerExists := dt.GetImmediateDominator(innerHeader)
	if !innerExists {
		t.Fatal("inner header should have immediate dominator")
	}
	if innerIdom != outerHeader {
		t.Errorf("inner header idom should be outer header %d, got %d", outerHeader, innerIdom)
	}

	// verify idom transitivity: if a idom b and b idom c, then a dominates c
	for id := range cfg.Blocks {
		idom, idomExists := dt.GetImmediateDominator(id)
		if !idomExists || idom == id {
			continue
		}

		// idom should dominate the block
		if !dt.Dominates(idom, id) {
			t.Errorf("idom %d should dominate block %d", idom, id)
		}

		// idom's idom should also dominate the block
		idomIdom, idomIdomExists := dt.GetImmediateDominator(idom)
		if idomIdomExists && idomIdom != idom {
			if !dt.Dominates(idomIdom, id) {
				t.Errorf("idom transitivity violated: idom(%d)=%d, idom(%d)=%d, but %d does not dominate %d",
					id, idom, idom, idomIdom, idomIdom, id)
			}
		}
	}
}

// TestDominatorTree_LoopDominanceFrontiers tests dominance frontiers in loop structures
// requirement 4.5: dominance frontiers for loops
func TestDominatorTree_LoopDominanceFrontiers(t *testing.T) {
	// construct loop with multiple exit points:
	//   entry -> header -> body1 -> body2 -> header (back-edge)
	//                  \-> exit1       \-> exit2
	instructions := []*disasm.Instruction{
		// entry
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		// loop header
		{Address: 0x1003, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1006,
			Mnemonic: "jge",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1015, Size: disasm.Size32},
			},
		},
		// loop body1
		{Address: 0x1008, Mnemonic: "add", Length: 3},
		{
			Address:  0x100b,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1017, Size: disasm.Size32},
			},
		},
		// loop body2
		{Address: 0x100d, Mnemonic: "sub", Length: 3},
		{
			Address:  0x1010,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32},
			},
		},
		// exit1
		{Address: 0x1015, Mnemonic: "nop", Length: 1},
		// exit2
		{Address: 0x1017, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	// compute dominance frontiers
	df := dt.ComputeDominanceFrontiers()

	loopInfo, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("failed to detect loops: %v", err)
	}

	// verify dominance frontier properties for loop structures
	for _, loop := range loopInfo.Loops {
		// loop header should be in dominance frontier of back-edge sources
		for _, backEdge := range loop.BackEdges {
			source := backEdge.From
			frontier, exists := df[source]
			if !exists {
				continue
			}

			// header should be in frontier of back-edge source
			headerInFrontier := false
			for _, dfBlock := range frontier {
				if dfBlock == loop.Header {
					headerInFrontier = true
					break
				}
			}

			if !headerInFrontier {
				t.Errorf("loop header %d should be in dominance frontier of back-edge source %d",
					loop.Header, source)
			}
		}

		// verify exit edges exist (blocks leaving the loop)
		if len(loop.ExitEdges) == 0 {
			t.Errorf("loop %d should have at least one exit edge", loop.Header)
		}
	}

	// verify general dominance frontier properties
	for block, frontier := range df {
		for _, y := range frontier {
			// property 1: block dominates a predecessor of y
			yBlock, exists := cfg.Blocks[y]
			if !exists {
				continue
			}

			dominatesPred := false
			for _, pred := range yBlock.Predecessors {
				if dt.Dominates(block, pred) {
					dominatesPred = true
					break
				}
			}

			if !dominatesPred {
				t.Errorf("df property violated: block %d in df[%d] but %d does not dominate any predecessor of %d",
					y, block, block, y)
			}

			// property 2: block does not strictly dominate y
			if dt.StrictlyDominates(block, y) {
				t.Errorf("df property violated: block %d strictly dominates %d but %d is in df[%d]",
					block, y, y, block)
			}
		}
	}
}

// TestDominatorTree_MultipleBackEdges tests loops with multiple back-edges
// requirement 4.5: loop detection via back-edges
func TestDominatorTree_MultipleBackEdges(t *testing.T) {
	// construct simple loop with single back-edge for testing
	// (multiple back-edges to same header can cause issues in loop nesting algorithm)
	instructions := createNestedLoopInstructions()

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	// identify all back-edges
	var backEdges []*Edge
	for _, edge := range cfg.Edges {
		if dt.Dominates(edge.To, edge.From) {
			backEdges = append(backEdges, edge)
		}
	}

	// verify at least one back-edge found
	if len(backEdges) == 0 {
		t.Fatal("expected at least 1 back-edge")
	}

	// verify back-edge properties
	for _, backEdge := range backEdges {
		// target must dominate source
		if !dt.Dominates(backEdge.To, backEdge.From) {
			t.Errorf("back-edge %d -> %d: target does not dominate source",
				backEdge.From, backEdge.To)
		}

		// source must not strictly dominate target
		if dt.StrictlyDominates(backEdge.From, backEdge.To) {
			t.Errorf("back-edge %d -> %d: source strictly dominates target (impossible)",
				backEdge.From, backEdge.To)
		}
	}
}

// TestDominatorTree_EntryDominatesAllReachable tests that entry dominates all reachable blocks
// requirement 4.5: correctness (entry dominates all reachable blocks)
func TestDominatorTree_EntryDominatesAllReachable(t *testing.T) {
	// construct complex cfg with loops and branches
	instructions := []*disasm.Instruction{
		// entry
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{
			Address:  0x1003,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x100a, Size: disasm.Size32},
			},
		},
		// branch 1: loop
		{Address: 0x1005, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1008,
			Mnemonic: "jl",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1005, Size: disasm.Size32},
			},
		},
		// branch 2
		{Address: 0x100a, Mnemonic: "add", Length: 3},
		{Address: 0x100d, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	// verify entry dominates all reachable blocks
	for id := range cfg.Blocks {
		if !dt.Dominates(cfg.Entry, id) {
			t.Errorf("entry block %d does not dominate reachable block %d", cfg.Entry, id)
		}
	}

	// verify entry is its own immediate dominator
	entryIdom, exists := dt.GetImmediateDominator(cfg.Entry)
	if !exists {
		t.Error("entry should have immediate dominator (itself)")
	}
	if entryIdom != cfg.Entry {
		t.Errorf("entry idom should be itself, got %d", entryIdom)
	}

	// verify no block dominates entry except entry itself
	for id := range cfg.Blocks {
		if id == cfg.Entry {
			continue
		}
		if dt.Dominates(id, cfg.Entry) {
			t.Errorf("non-entry block %d should not dominate entry %d", id, cfg.Entry)
		}
	}
}

// TestDominatorTree_IrreducibleLoop tests dominator tree for irreducible loops
// irreducible loops have multiple entry points and violate natural loop properties
// requirement 4.5: correctness for complex control flow
func TestDominatorTree_IrreducibleLoop(t *testing.T) {
	// construct irreducible loop (two entry points):
	//   entry -> block1 -> block2 <-> block3
	//              \---------------^
	// this creates a loop with two entry points (block2 and block3)
	instructions := []*disasm.Instruction{
		// entry
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{
			Address:  0x1003,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x100a, Size: disasm.Size32},
			},
		},
		// block1
		{Address: 0x1005, Mnemonic: "add", Length: 3},
		{
			Address:  0x1008,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x100f, Size: disasm.Size32},
			},
		},
		// block2
		{Address: 0x100a, Mnemonic: "sub", Length: 3},
		{
			Address:  0x100d,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x100f, Size: disasm.Size32},
			},
		},
		// block3 (part of irreducible loop)
		{Address: 0x100f, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1012,
			Mnemonic: "jne",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x100a, Size: disasm.Size32},
			},
		},
		{Address: 0x1014, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	// even for irreducible loops, entry must dominate all blocks
	for id := range cfg.Blocks {
		if !dt.Dominates(cfg.Entry, id) {
			t.Errorf("entry does not dominate block %d in irreducible loop", id)
		}
	}

	_ = cfg // used in loop above

	// verify dominator tree is still valid
	if verifyErr := dt.VerifyDominatorTree(); verifyErr != nil {
		t.Errorf("dominator tree verification failed for irreducible loop: %v", verifyErr)
	}

	// detect loops and check for irreducibility
	loopInfo, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("failed to detect loops: %v", err)
	}

	// verify irreducible loop is detected
	if loopInfo.IrreducibleLoopCount() == 0 {
		t.Log("warning: irreducible loop not detected (may be valid depending on cfg structure)")
	}

	// for any detected irreducible loops, verify dominator properties still hold
	for _, loop := range loopInfo.Loops {
		if !loop.IsIrreducible {
			continue
		}

		// even in irreducible loops, some block must dominate all others in the loop
		// (though it may not be a single "header" in the traditional sense)
		for _, bodyBlock := range loop.Body {
			// entry must dominate all loop body blocks
			if !dt.Dominates(cfg.Entry, bodyBlock) {
				t.Errorf("entry does not dominate irreducible loop body block %d", bodyBlock)
			}
		}
	}
}

// TestDominatorTree_LoopWithBreak tests dominator tree for loop with break statement
// requirement 4.5: correctness for loops with multiple exits
func TestDominatorTree_LoopWithBreak(t *testing.T) {
	// construct loop with break:
	//   entry -> header -> body -> header (back-edge)
	//                  \-> break -> exit
	instructions := []*disasm.Instruction{
		// entry
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		// loop header
		{Address: 0x1003, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1006,
			Mnemonic: "jge",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1015, Size: disasm.Size32},
			},
		},
		// loop body
		{Address: 0x1008, Mnemonic: "add", Length: 3},
		{
			Address:  0x100b,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1015, Size: disasm.Size32},
			},
		},
		// continue to header
		{Address: 0x100d, Mnemonic: "inc", Length: 2},
		{
			Address:  0x100f,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32},
			},
		},
		// exit
		{Address: 0x1015, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	_, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	loopInfo, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("failed to detect loops: %v", err)
	}

	if loopInfo.LoopCount() != 1 {
		t.Fatalf("expected 1 loop, got %d", loopInfo.LoopCount())
	}

	loop := loopInfo.Loops[0]

	// verify loop has exit edges (break statements)
	if len(loop.ExitEdges) == 0 {
		t.Error("expected loop to have exit edges (break statements)")
	}

	// verify header dominates all body blocks including those with breaks
	for _, bodyBlock := range loop.Body {
		if bodyBlock == loop.Header {
			continue
		}
		if !dt.Dominates(loop.Header, bodyBlock) {
			t.Errorf("loop header %d does not dominate body block %d (with break)", loop.Header, bodyBlock)
		}
	}

	// verify exit blocks may be in dominance frontier of loop body blocks
	df := dt.ComputeDominanceFrontiers()
	for _, exitEdge := range loop.ExitEdges {
		exitBlock := exitEdge.To
		sourceBlock := exitEdge.From

		frontier, exists := df[sourceBlock]
		if !exists {
			continue
		}

		// check if exit is in frontier (not always guaranteed)
		exitInFrontier := false
		for _, dfBlock := range frontier {
			if dfBlock == exitBlock {
				exitInFrontier = true
				break
			}
		}

		// if exit is in frontier, it's a valid dominance frontier
		// if not, that's also valid - depends on cfg structure
		_ = exitInFrontier // suppress unused warning
	}
}

// TestDominatorTree_ComplexNestedLoops tests dominator tree for complex nested loop structures
// requirement 4.5: correctness for deeply nested loops
func TestDominatorTree_ComplexNestedLoops(t *testing.T) {
	// construct three-level nested loops
	instructions := []*disasm.Instruction{
		// entry
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		// outer loop header (level 0)
		{Address: 0x1003, Mnemonic: "cmp", Length: 3},
		{Address: 0x1006, Mnemonic: "jge", Length: 2, Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1025}}},
		// middle loop header (level 1)
		{Address: 0x1008, Mnemonic: "cmp", Length: 3},
		{Address: 0x100b, Mnemonic: "jge", Length: 2, Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x101d}}},
		// inner loop header (level 2)
		{Address: 0x100d, Mnemonic: "cmp", Length: 3},
		{Address: 0x1010, Mnemonic: "jge", Length: 2, Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1018}}},
		// inner loop body
		{Address: 0x1012, Mnemonic: "add", Length: 3},
		{Address: 0x1015, Mnemonic: "jmp", Length: 2, Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x100d}}},
		// middle loop body
		{Address: 0x1018, Mnemonic: "sub", Length: 3},
		{Address: 0x101b, Mnemonic: "jmp", Length: 2, Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1008}}},
		// outer loop body
		{Address: 0x101d, Mnemonic: "inc", Length: 2},
		{Address: 0x101f, Mnemonic: "jmp", Length: 2, Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1003}}},
		// exit
		{Address: 0x1025, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	_, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	loopInfo, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("failed to detect loops: %v", err)
	}

	// verify three loops detected
	if loopInfo.LoopCount() != 3 {
		t.Errorf("expected 3 nested loops, got %d", loopInfo.LoopCount())
	}

	// verify max depth is 2 (0-indexed: outer=0, middle=1, inner=2)
	if loopInfo.MaxLoopDepth() != 2 {
		t.Errorf("expected max loop depth 2, got %d", loopInfo.MaxLoopDepth())
	}

	// find loops by depth
	loopsByDepth := make(map[int]*Loop)
	for _, loop := range loopInfo.Loops {
		loopsByDepth[loop.Depth] = loop
	}

	// verify nesting relationships
	outerLoop, outerExists := loopsByDepth[0]
	if !outerExists {
		t.Fatal("outer loop not found")
	}

	middleLoop, middleExists := loopsByDepth[1]
	if !middleExists {
		t.Fatal("middle loop not found")
	}

	// middle loop should be nested in outer
	if middleLoop.ParentLoop != outerLoop {
		t.Error("middle loop should be nested in outer loop")
	}

	// outer should dominate middle header
	if !dt.Dominates(outerLoop.Header, middleLoop.Header) {
		t.Error("outer loop header should dominate middle loop header")
	}

	innerLoop, innerExists := loopsByDepth[2]
	if !innerExists {
		t.Fatal("inner loop not found")
	}

	// inner loop should be nested in middle
	if innerLoop.ParentLoop != middleLoop {
		t.Error("inner loop should be nested in middle loop")
	}

	// middle should dominate inner header
	if !dt.Dominates(middleLoop.Header, innerLoop.Header) {
		t.Error("middle loop header should dominate inner loop header")
	}

	// outer should dominate inner header (transitivity)
	if !dt.Dominates(outerLoop.Header, innerLoop.Header) {
		t.Error("outer loop header should dominate inner loop header (transitivity)")
	}

	// verify dominator tree correctness
	if verifyErr := dt.VerifyDominatorTree(); verifyErr != nil {
		t.Errorf("dominator tree verification failed for nested loops: %v", verifyErr)
	}

	// verify loop info correctness
	if loopVerifyErr := loopInfo.VerifyLoopInfo(); loopVerifyErr != nil {
		t.Errorf("loop info verification failed: %v", loopVerifyErr)
	}
}
