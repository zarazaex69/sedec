package analysis

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// buildDCECFG creates a cfg.CFG from block connectivity for dce tests.
func buildDCECFG(entry cfg.BlockID, blocks map[cfg.BlockID][]cfg.BlockID) *cfg.CFG {
	return buildLiveCFG(entry, blocks)
}

// countInstructions returns the total number of instructions across all blocks.
func countInstructions(fn *ir.Function) int {
	total := 0
	for _, block := range fn.Blocks {
		total += len(block.Instructions)
	}
	return total
}

// TestDCE_RemovesDeadAssignment verifies that a dead assignment is removed.
// bb0: dead_1 = 99; x_1 = 1; return x_1
// dead_1 is never used, so it must be eliminated.
func TestDCE_RemovesDeadAssignment(t *testing.T) {
	cfgGraph := buildDCECFG(0, map[cfg.BlockID][]cfg.BlockID{0: {}})

	fn := &ir.Function{
		Name: "dead_assign",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("dead", 1), Source: intConst(99)},
					&ir.Assign{Dest: ssaVar("x", 1), Source: intConst(1)},
					&ir.Return{Value: &ir.Variable{Name: "x", Type: intType(), Version: 1}},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateDeadCode(fn, cfgGraph, nil)
	if err != nil {
		t.Fatalf("EliminateDeadCode failed: %v", err)
	}

	if result.RemovedInstructions != 1 {
		t.Errorf("expected 1 removed instruction, got %d", result.RemovedInstructions)
	}

	block := fn.Blocks[0]
	if len(block.Instructions) != 2 {
		t.Errorf("expected 2 instructions remaining, got %d", len(block.Instructions))
	}

	// verify dead_1 assignment is gone
	for _, instr := range block.Instructions {
		if a, ok := instr.(*ir.Assign); ok {
			if a.Dest.Name == "dead" {
				t.Error("dead_1 assignment should have been removed")
			}
		}
	}
}

// TestDCE_PreservesStore verifies that stores are never removed even if
// the stored value is not used elsewhere.
// bb0: x_1 = 42; store *0x1000, x_1; return
func TestDCE_PreservesStore(t *testing.T) {
	cfgGraph := buildDCECFG(0, map[cfg.BlockID][]cfg.BlockID{0: {}})

	fn := &ir.Function{
		Name: "preserve_store",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("x", 1), Source: intConst(42)},
					&ir.Store{
						Address: intConst(0x1000),
						Value:   varExpr("x", 1),
						Size:    ir.Size8,
					},
					&ir.Return{},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateDeadCode(fn, cfgGraph, nil)
	if err != nil {
		t.Fatalf("EliminateDeadCode failed: %v", err)
	}

	// x_1 is used by the store, so it must be preserved
	// the store itself must be preserved (side effect)
	if result.RemovedInstructions != 0 {
		t.Errorf("expected 0 removed instructions, got %d", result.RemovedInstructions)
	}
	if len(fn.Blocks[0].Instructions) != 3 {
		t.Errorf("expected 3 instructions, got %d", len(fn.Blocks[0].Instructions))
	}
}

// TestDCE_PreservesCall verifies that calls are never removed.
// bb0: call foo(); return
func TestDCE_PreservesCall(t *testing.T) {
	cfgGraph := buildDCECFG(0, map[cfg.BlockID][]cfg.BlockID{0: {}})

	fn := &ir.Function{
		Name: "preserve_call",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Call{
						Target: ir.VariableExpr{Var: ir.Variable{Name: "foo", Type: ir.FunctionType{}}},
					},
					&ir.Return{},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateDeadCode(fn, cfgGraph, nil)
	if err != nil {
		t.Fatalf("EliminateDeadCode failed: %v", err)
	}

	if result.RemovedInstructions != 0 {
		t.Errorf("expected 0 removed instructions, got %d", result.RemovedInstructions)
	}
}

// TestDCE_RemovesDeadLoad verifies that a load whose result is never used is removed.
// bb0: x_1 = load *0x1000; return
// x_1 is never used after the load.
func TestDCE_RemovesDeadLoad(t *testing.T) {
	cfgGraph := buildDCECFG(0, map[cfg.BlockID][]cfg.BlockID{0: {}})

	fn := &ir.Function{
		Name: "dead_load",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Load{
						Dest:    ssaVar("x", 1),
						Address: intConst(0x1000),
						Size:    ir.Size8,
					},
					&ir.Return{},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateDeadCode(fn, cfgGraph, nil)
	if err != nil {
		t.Fatalf("EliminateDeadCode failed: %v", err)
	}

	if result.RemovedInstructions != 1 {
		t.Errorf("expected 1 removed instruction, got %d", result.RemovedInstructions)
	}
}

// TestDCE_RemovesUnreachableBlock verifies that unreachable blocks are removed.
// bb0: jump bb2
// bb1: x_1 = 1; return x_1   (unreachable)
// bb2: return
func TestDCE_RemovesUnreachableBlock(t *testing.T) {
	cfgGraph := buildDCECFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {2},
		1: {},
		2: {},
	})

	fn := &ir.Function{
		Name: "unreachable_block",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID:           0,
				Instructions: []ir.IRInstruction{&ir.Jump{Target: 2}},
				Successors:   []ir.BlockID{2},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("x", 1), Source: intConst(1)},
					&ir.Return{Value: &ir.Variable{Name: "x", Type: intType(), Version: 1}},
				},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{&ir.Return{}},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateDeadCode(fn, cfgGraph, nil)
	if err != nil {
		t.Fatalf("EliminateDeadCode failed: %v", err)
	}

	if result.RemovedBlocks != 1 {
		t.Errorf("expected 1 removed block, got %d", result.RemovedBlocks)
	}

	if _, exists := fn.Blocks[1]; exists {
		t.Error("unreachable block bb1 should have been removed")
	}
	if _, exists := fn.Blocks[0]; !exists {
		t.Error("reachable block bb0 should be preserved")
	}
	if _, exists := fn.Blocks[2]; !exists {
		t.Error("reachable block bb2 should be preserved")
	}
}

// TestDCE_ChainedDeadCode verifies that removing one dead instruction exposes
// another dead instruction in subsequent iterations.
// bb0: a_1 = 1; b_1 = a_1 + 2; return
// b_1 is dead → removed. then a_1 is dead (b_1 was its only use) → removed.
func TestDCE_ChainedDeadCode(t *testing.T) {
	cfgGraph := buildDCECFG(0, map[cfg.BlockID][]cfg.BlockID{0: {}})

	fn := &ir.Function{
		Name: "chained_dead",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("a", 1), Source: intConst(1)},
					&ir.Assign{
						Dest:   ssaVar("b", 1),
						Source: ir.BinaryOp{Op: ir.BinOpAdd, Left: varExpr("a", 1), Right: intConst(2)},
					},
					&ir.Return{},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateDeadCode(fn, cfgGraph, nil)
	if err != nil {
		t.Fatalf("EliminateDeadCode failed: %v", err)
	}

	if result.RemovedInstructions != 2 {
		t.Errorf("expected 2 removed instructions (chained), got %d", result.RemovedInstructions)
	}

	block := fn.Blocks[0]
	if len(block.Instructions) != 1 {
		t.Errorf("expected 1 instruction remaining (return), got %d", len(block.Instructions))
	}
}

// TestDCE_PreservesLiveCode verifies that live code is not removed.
// bb0: x_1 = 1; y_1 = x_1 + 2; return y_1
// all instructions are live.
func TestDCE_PreservesLiveCode(t *testing.T) {
	cfgGraph := buildDCECFG(0, map[cfg.BlockID][]cfg.BlockID{0: {}})

	fn := &ir.Function{
		Name: "all_live",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("x", 1), Source: intConst(1)},
					&ir.Assign{
						Dest:   ssaVar("y", 1),
						Source: ir.BinaryOp{Op: ir.BinOpAdd, Left: varExpr("x", 1), Right: intConst(2)},
					},
					&ir.Return{Value: &ir.Variable{Name: "y", Type: intType(), Version: 1}},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateDeadCode(fn, cfgGraph, nil)
	if err != nil {
		t.Fatalf("EliminateDeadCode failed: %v", err)
	}

	if result.RemovedInstructions != 0 {
		t.Errorf("expected 0 removed instructions, got %d", result.RemovedInstructions)
	}
	if len(fn.Blocks[0].Instructions) != 3 {
		t.Errorf("expected 3 instructions, got %d", len(fn.Blocks[0].Instructions))
	}
}

// TestDCE_DeadPhiNode verifies that a dead phi-node is removed.
// bb0: jump bb2
// bb1: jump bb2  (unreachable)
// bb2: x_3 = phi(x_1 from bb0, x_2 from bb1); return
// after removing bb1, the phi has one source and x_3 is dead.
func TestDCE_DeadPhiNode(t *testing.T) {
	cfgGraph := buildDCECFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {2},
		1: {2},
		2: {},
	})

	fn := &ir.Function{
		Name: "dead_phi",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID:           0,
				Instructions: []ir.IRInstruction{&ir.Jump{Target: 2}},
				Successors:   []ir.BlockID{2},
			},
			1: {
				ID:           1,
				Instructions: []ir.IRInstruction{&ir.Jump{Target: 2}},
				Successors:   []ir.BlockID{2},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Phi{
						Dest: ssaVar("x", 3),
						Sources: []ir.PhiSource{
							{Block: 0, Var: ssaVar("x", 1)},
							{Block: 1, Var: ssaVar("x", 2)},
						},
					},
					&ir.Return{},
				},
				Predecessors: []ir.BlockID{0, 1},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateDeadCode(fn, cfgGraph, nil)
	if err != nil {
		t.Fatalf("EliminateDeadCode failed: %v", err)
	}

	// bb1 is unreachable → removed
	if _, exists := fn.Blocks[1]; exists {
		t.Error("unreachable block bb1 should have been removed")
	}
	if result.RemovedBlocks < 1 {
		t.Errorf("expected at least 1 removed block, got %d", result.RemovedBlocks)
	}

	// x_3 is not used by return → phi should be removed
	block2 := fn.Blocks[2]
	for _, instr := range block2.Instructions {
		if phi, ok := instr.(*ir.Phi); ok {
			if phi.Dest.Name == "x" {
				t.Error("dead phi for x_3 should have been removed")
			}
		}
	}
}

// TestDCE_NilFunction tests error handling for nil function.
func TestDCE_NilFunction(t *testing.T) {
	_, err := EliminateDeadCode(nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil function")
	}
}

// TestDCE_EmptyFunction tests error handling for function with no blocks.
func TestDCE_EmptyFunction(t *testing.T) {
	fn := &ir.Function{
		Name:   "empty",
		Blocks: map[ir.BlockID]*ir.BasicBlock{},
	}
	_, err := EliminateDeadCode(fn, nil, nil)
	if err == nil {
		t.Fatal("expected error for empty function")
	}
}

// TestDCE_IfThenElse verifies DCE across a diamond CFG with mixed live/dead code.
// bb0: cond_1 = 1; dead_0 = 99; branch cond_1 → bb1/bb2
// bb1: x_1 = 10; jump bb3
// bb2: x_2 = 20; jump bb3
// bb3: x_3 = phi(x_1, x_2); return x_3
// dead_0 is never used → removed.
func TestDCE_IfThenElse(t *testing.T) {
	cfgGraph := buildDCECFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {1, 2},
		1: {3},
		2: {3},
		3: {},
	})

	fn := &ir.Function{
		Name: "dce_if_then_else",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("cond", 1), Source: intConst(1)},
					&ir.Assign{Dest: ssaVar("dead", 0), Source: intConst(99)},
					&ir.Branch{Condition: varExpr("cond", 1), TrueTarget: 1, FalseTarget: 2},
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("x", 1), Source: intConst(10)},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("x", 2), Source: intConst(20)},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			3: {
				ID: 3,
				Instructions: []ir.IRInstruction{
					&ir.Phi{
						Dest: ssaVar("x", 3),
						Sources: []ir.PhiSource{
							{Block: 1, Var: ssaVar("x", 1)},
							{Block: 2, Var: ssaVar("x", 2)},
						},
					},
					&ir.Return{Value: &ir.Variable{Name: "x", Type: intType(), Version: 3}},
				},
				Predecessors: []ir.BlockID{1, 2},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateDeadCode(fn, cfgGraph, nil)
	if err != nil {
		t.Fatalf("EliminateDeadCode failed: %v", err)
	}

	if result.RemovedInstructions != 1 {
		t.Errorf("expected 1 removed instruction (dead_0), got %d", result.RemovedInstructions)
	}

	// verify dead_0 is gone from bb0
	for _, instr := range fn.Blocks[0].Instructions {
		if a, ok := instr.(*ir.Assign); ok && a.Dest.Name == "dead" {
			t.Error("dead_0 should have been removed from bb0")
		}
	}

	// verify all blocks still present
	for _, id := range []ir.BlockID{0, 1, 2, 3} {
		if _, exists := fn.Blocks[id]; !exists {
			t.Errorf("block bb%d should be preserved", id)
		}
	}
}

// TestDCE_MultipleUnreachableBlocks verifies removal of a chain of unreachable blocks.
// bb0: return
// bb1: jump bb2   (unreachable)
// bb2: return     (unreachable, only reachable from bb1)
func TestDCE_MultipleUnreachableBlocks(t *testing.T) {
	cfgGraph := buildDCECFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {},
		1: {2},
		2: {},
	})

	fn := &ir.Function{
		Name: "multi_unreachable",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID:           0,
				Instructions: []ir.IRInstruction{&ir.Return{}},
			},
			1: {
				ID:           1,
				Instructions: []ir.IRInstruction{&ir.Jump{Target: 2}},
				Successors:   []ir.BlockID{2},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{&ir.Return{}},
				Predecessors: []ir.BlockID{1},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateDeadCode(fn, cfgGraph, nil)
	if err != nil {
		t.Fatalf("EliminateDeadCode failed: %v", err)
	}

	if result.RemovedBlocks != 2 {
		t.Errorf("expected 2 removed blocks, got %d", result.RemovedBlocks)
	}

	if len(fn.Blocks) != 1 {
		t.Errorf("expected 1 block remaining, got %d", len(fn.Blocks))
	}
	if _, exists := fn.Blocks[0]; !exists {
		t.Error("entry block bb0 must be preserved")
	}
}

// TestDCE_IterationsConverge verifies that the fixed-point iteration terminates
// and that the iteration count is reasonable.
func TestDCE_IterationsConverge(t *testing.T) {
	cfgGraph := buildDCECFG(0, map[cfg.BlockID][]cfg.BlockID{0: {}})

	fn := &ir.Function{
		Name: "converge",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("a", 1), Source: intConst(1)},
					&ir.Assign{
						Dest:   ssaVar("b", 1),
						Source: ir.BinaryOp{Op: ir.BinOpAdd, Left: varExpr("a", 1), Right: intConst(2)},
					},
					&ir.Assign{
						Dest:   ssaVar("c", 1),
						Source: ir.BinaryOp{Op: ir.BinOpMul, Left: varExpr("b", 1), Right: intConst(3)},
					},
					&ir.Return{},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateDeadCode(fn, cfgGraph, nil)
	if err != nil {
		t.Fatalf("EliminateDeadCode failed: %v", err)
	}

	// all 3 assigns are dead (return is void)
	if result.RemovedInstructions != 3 {
		t.Errorf("expected 3 removed instructions, got %d", result.RemovedInstructions)
	}

	// must converge in a bounded number of iterations
	if result.Iterations > 10 {
		t.Errorf("expected convergence within 10 iterations, took %d", result.Iterations)
	}
}
