package analysis

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// buildLiveCFG is a helper that creates a cfg.CFG from block connectivity.
// reuses the same pattern as buildCFGAndDomTree in reaching_defs_test.go.
func buildLiveCFG(entry cfg.BlockID, blocks map[cfg.BlockID][]cfg.BlockID) *cfg.CFG { //nolint:unparam // entry is always 0 but kept for API symmetry
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = entry

	preds := make(map[cfg.BlockID][]cfg.BlockID)
	for id := range blocks {
		preds[id] = nil
	}
	for id, succs := range blocks {
		for _, s := range succs {
			preds[s] = append(preds[s], id)
		}
	}

	for id, succs := range blocks {
		b := &cfg.BasicBlock{
			ID:           id,
			Predecessors: preds[id],
			Successors:   succs,
		}
		cfgGraph.AddBlock(b)
	}
	return cfgGraph
}

// TestLiveVars_LinearCode tests liveness for straight-line code.
// bb0: x_1 = 1; y_1 = x_1 + 2
// bb1: return y_1
// expected: x_1 is live after bb0:0 (used by bb0:1), dead after bb0:1.
// y_1 is live after bb0:1 (used by bb1:0), dead after bb1:0.
func TestLiveVars_LinearCode(t *testing.T) {
	cfgGraph := buildLiveCFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {1},
		1: {},
	})

	function := &ir.Function{
		Name: "linear",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("x", 1), Source: intConst(1)},
					&ir.Assign{
						Dest:   ssaVar("y", 1),
						Source: ir.BinaryOp{Op: ir.BinOpAdd, Left: varExpr("x", 1), Right: intConst(2)},
					},
				},
				Successors: []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Return{Value: &ir.Variable{Name: "y", Type: intType(), Version: 1}},
				},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewLiveVarsAnalyzer(function, cfgGraph, nil)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// after bb0:0 (x_1 = 1): x_1 is live (used by next instruction)
	liveOut00 := result.GetLiveOutAt(ProgramPoint{BlockID: 0, InstrIdx: 0})
	if !liveOut00.Contains(ssaVar("x", 1)) {
		t.Error("expected x_1 live after bb0:0")
	}

	// after bb0:1 (y_1 = x_1+2): y_1 is live, x_1 is dead
	liveOut01 := result.GetLiveOutAt(ProgramPoint{BlockID: 0, InstrIdx: 1})
	if !liveOut01.Contains(ssaVar("y", 1)) {
		t.Error("expected y_1 live after bb0:1")
	}
	if liveOut01.Contains(ssaVar("x", 1)) {
		t.Error("expected x_1 dead after bb0:1")
	}

	// before bb1:0 (return y_1): y_1 is live
	liveIn10 := result.GetLiveInAt(ProgramPoint{BlockID: 1, InstrIdx: 0})
	if !liveIn10.Contains(ssaVar("y", 1)) {
		t.Error("expected y_1 live before bb1:0")
	}

	// after bb1:0 (return): nothing is live
	liveOut10 := result.GetLiveOutAt(ProgramPoint{BlockID: 1, InstrIdx: 0})
	if liveOut10.Len() != 0 {
		t.Errorf("expected nothing live after return, got %v", liveOut10.Slice())
	}
}

// TestLiveVars_IfThenElse tests liveness across a diamond CFG.
// bb0: cond_1 = 1; branch cond_1 → bb1/bb2
// bb1: x_1 = 10; jump bb3
// bb2: x_2 = 20; jump bb3
// bb3: x_3 = phi(x_1, x_2); return x_3
func TestLiveVars_IfThenElse(t *testing.T) {
	cfgGraph := buildLiveCFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {1, 2},
		1: {3},
		2: {3},
		3: {},
	})

	function := makeIfThenElseFunction()

	analyzer := NewLiveVarsAnalyzer(function, cfgGraph, nil)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// at exit of bb1 (after jump): x_1 must be live (used by phi in bb3)
	liveOutBB1 := result.GetBlockLiveOut(1)
	if !liveOutBB1.Contains(ssaVar("x", 1)) {
		t.Error("expected x_1 live at exit of bb1")
	}

	// at exit of bb2 (after jump): x_2 must be live (used by phi in bb3)
	liveOutBB2 := result.GetBlockLiveOut(2)
	if !liveOutBB2.Contains(ssaVar("x", 2)) {
		t.Error("expected x_2 live at exit of bb2")
	}

	// at entry of bb3 (before phi): x_1 and x_2 are live (phi sources)
	liveInBB3 := result.GetBlockLiveIn(3)
	if !liveInBB3.Contains(ssaVar("x", 1)) {
		t.Error("expected x_1 live at entry of bb3")
	}
	if !liveInBB3.Contains(ssaVar("x", 2)) {
		t.Error("expected x_2 live at entry of bb3")
	}

	// cond_1 is live after bb0:0 (used by branch at bb0:1)
	liveOut00 := result.GetLiveOutAt(ProgramPoint{BlockID: 0, InstrIdx: 0})
	if !liveOut00.Contains(ssaVar("cond", 1)) {
		t.Error("expected cond_1 live after bb0:0")
	}

	// cond_1 is dead after bb0:1 (branch consumes it, no further use)
	liveOutBB0 := result.GetBlockLiveOut(0)
	if liveOutBB0.Contains(ssaVar("cond", 1)) {
		t.Error("expected cond_1 dead at exit of bb0")
	}
}

// TestLiveVars_WhileLoop tests liveness in a loop.
// bb0: i_1 = 0
// bb1: i_2 = phi(i_1, i_3); branch i_2 < 10 → bb2/bb3
// bb2: i_3 = i_2 + 1; jump bb1
// bb3: return i_2
func TestLiveVars_WhileLoop(t *testing.T) {
	cfgGraph := buildLiveCFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {1},
		1: {2, 3},
		2: {1},
		3: {},
	})

	function := makeWhileLoopFunction()

	analyzer := NewLiveVarsAnalyzer(function, cfgGraph, nil)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// i_1 must be live at exit of bb0 (used by phi in bb1)
	liveOutBB0 := result.GetBlockLiveOut(0)
	if !liveOutBB0.Contains(ssaVar("i", 1)) {
		t.Error("expected i_1 live at exit of bb0")
	}

	// i_3 must be live at exit of bb2 (used by phi in bb1 back-edge)
	liveOutBB2 := result.GetBlockLiveOut(2)
	if !liveOutBB2.Contains(ssaVar("i", 3)) {
		t.Error("expected i_3 live at exit of bb2")
	}

	// i_2 must be live at entry of bb2 (used in i_3 = i_2 + 1)
	liveInBB2 := result.GetBlockLiveIn(2)
	if !liveInBB2.Contains(ssaVar("i", 2)) {
		t.Error("expected i_2 live at entry of bb2")
	}

	// i_2 must be live at entry of bb3 (used by return)
	liveInBB3 := result.GetBlockLiveIn(3)
	if !liveInBB3.Contains(ssaVar("i", 2)) {
		t.Error("expected i_2 live at entry of bb3")
	}

	// i_2 must be live at entry of bb1 (phi defines it, but sources i_1 and i_3 are live)
	liveInBB1 := result.GetBlockLiveIn(1)
	if !liveInBB1.Contains(ssaVar("i", 1)) {
		t.Error("expected i_1 live at entry of bb1 (phi source)")
	}
	if !liveInBB1.Contains(ssaVar("i", 3)) {
		t.Error("expected i_3 live at entry of bb1 (phi source from back-edge)")
	}
}

// TestLiveVars_LiveAcrossMultipleBlocks tests variables live across several blocks.
// bb0: a_1 = 1; b_1 = 2
// bb1: c_1 = a_1 + b_1
// bb2: return c_1
// a_1 and b_1 must be live across bb0→bb1 boundary.
func TestLiveVars_LiveAcrossMultipleBlocks(t *testing.T) {
	cfgGraph := buildLiveCFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {1},
		1: {2},
		2: {},
	})

	function := &ir.Function{
		Name: "live_across",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("a", 1), Source: intConst(1)},
					&ir.Assign{Dest: ssaVar("b", 1), Source: intConst(2)},
				},
				Successors: []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   ssaVar("c", 1),
						Source: ir.BinaryOp{Op: ir.BinOpAdd, Left: varExpr("a", 1), Right: varExpr("b", 1)},
					},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{2},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Return{Value: &ir.Variable{Name: "c", Type: intType(), Version: 1}},
				},
				Predecessors: []ir.BlockID{1},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewLiveVarsAnalyzer(function, cfgGraph, nil)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// a_1 and b_1 must be live at exit of bb0
	liveOutBB0 := result.GetBlockLiveOut(0)
	if !liveOutBB0.Contains(ssaVar("a", 1)) {
		t.Error("expected a_1 live at exit of bb0")
	}
	if !liveOutBB0.Contains(ssaVar("b", 1)) {
		t.Error("expected b_1 live at exit of bb0")
	}

	// a_1 and b_1 must be live at entry of bb1
	liveInBB1 := result.GetBlockLiveIn(1)
	if !liveInBB1.Contains(ssaVar("a", 1)) {
		t.Error("expected a_1 live at entry of bb1")
	}
	if !liveInBB1.Contains(ssaVar("b", 1)) {
		t.Error("expected b_1 live at entry of bb1")
	}

	// c_1 must be live at exit of bb1
	liveOutBB1 := result.GetBlockLiveOut(1)
	if !liveOutBB1.Contains(ssaVar("c", 1)) {
		t.Error("expected c_1 live at exit of bb1")
	}

	// a_1 and b_1 must be dead at exit of bb1 (consumed by c_1 = a_1 + b_1)
	if liveOutBB1.Contains(ssaVar("a", 1)) {
		t.Error("expected a_1 dead at exit of bb1")
	}
	if liveOutBB1.Contains(ssaVar("b", 1)) {
		t.Error("expected b_1 dead at exit of bb1")
	}
}

// TestLiveVars_DeadVariable tests that a variable defined but never used is dead.
// bb0: dead_1 = 99; x_1 = 1; return x_1
// dead_1 should never appear in any live set.
func TestLiveVars_DeadVariable(t *testing.T) {
	cfgGraph := buildLiveCFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {},
	})

	function := &ir.Function{
		Name: "dead_var",
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

	analyzer := NewLiveVarsAnalyzer(function, cfgGraph, nil)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// dead_1 should not appear in any live-out set
	for i := 0; i < 3; i++ {
		point := ProgramPoint{BlockID: 0, InstrIdx: i}
		liveOut := result.GetLiveOutAt(point)
		if liveOut.Contains(ssaVar("dead", 1)) {
			t.Errorf("dead_1 should not be live after bb0:%d", i)
		}
		liveIn := result.GetLiveInAt(point)
		if liveIn.Contains(ssaVar("dead", 1)) {
			t.Errorf("dead_1 should not be live before bb0:%d", i)
		}
	}

	// x_1 must be live before the return (bb0:2)
	liveIn02 := result.GetLiveInAt(ProgramPoint{BlockID: 0, InstrIdx: 2})
	if !liveIn02.Contains(ssaVar("x", 1)) {
		t.Error("expected x_1 live before return")
	}
}

// TestLiveVars_MultipleDeadVars tests several dead variables in sequence.
// bb0: a_1 = 1; b_1 = 2; c_1 = 3; return intConst(0)
// none of a_1, b_1, c_1 are used.
func TestLiveVars_MultipleDeadVars(t *testing.T) {
	cfgGraph := buildLiveCFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {},
	})

	function := &ir.Function{
		Name: "multi_dead",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("a", 1), Source: intConst(1)},
					&ir.Assign{Dest: ssaVar("b", 1), Source: intConst(2)},
					&ir.Assign{Dest: ssaVar("c", 1), Source: intConst(3)},
					&ir.Return{},
				},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewLiveVarsAnalyzer(function, cfgGraph, nil)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// no variable should ever be live
	for i := 0; i < 4; i++ {
		point := ProgramPoint{BlockID: 0, InstrIdx: i}
		for _, v := range []ir.Variable{ssaVar("a", 1), ssaVar("b", 1), ssaVar("c", 1)} {
			if result.GetLiveOutAt(point).Contains(v) {
				t.Errorf("%s should not be live after bb0:%d", v.String(), i)
			}
		}
	}
}

// TestLiveVars_NilFunction tests error handling for nil function.
func TestLiveVars_NilFunction(t *testing.T) {
	analyzer := NewLiveVarsAnalyzer(nil, nil, nil)
	_, err := analyzer.Compute()
	if err == nil {
		t.Fatal("expected error for nil function")
	}
}

// TestLiveVars_EmptyFunction tests error handling for function with no blocks.
func TestLiveVars_EmptyFunction(t *testing.T) {
	function := &ir.Function{
		Name:   "empty",
		Blocks: map[ir.BlockID]*ir.BasicBlock{},
	}
	analyzer := NewLiveVarsAnalyzer(function, nil, nil)
	_, err := analyzer.Compute()
	if err == nil {
		t.Fatal("expected error for empty function")
	}
}

// TestLiveVars_StoreDoesNotDefineVar tests that a store instruction does not
// create a definition (stores write to memory, not to a variable).
// bb0: store *addr, x_1; return x_1
// x_1 must be live before the store (it is used as the value to store).
func TestLiveVars_StoreDoesNotDefineVar(t *testing.T) {
	cfgGraph := buildLiveCFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {},
	})

	function := &ir.Function{
		Name: "store_test",
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
					&ir.Return{Value: &ir.Variable{Name: "x", Type: intType(), Version: 1}},
				},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewLiveVarsAnalyzer(function, cfgGraph, nil)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// x_1 must be live after bb0:0 (used by store and return)
	liveOut00 := result.GetLiveOutAt(ProgramPoint{BlockID: 0, InstrIdx: 0})
	if !liveOut00.Contains(ssaVar("x", 1)) {
		t.Error("expected x_1 live after bb0:0 (used by store)")
	}

	// x_1 must be live after bb0:1 (store uses it, but return also uses it)
	liveOut01 := result.GetLiveOutAt(ProgramPoint{BlockID: 0, InstrIdx: 1})
	if !liveOut01.Contains(ssaVar("x", 1)) {
		t.Error("expected x_1 live after bb0:1 (used by return)")
	}
}

// TestLiveVars_LoadDefinesVar tests that a load instruction defines a variable.
// bb0: x_1 = load *addr; return x_1
// x_1 must be live after the load.
func TestLiveVars_LoadDefinesVar(t *testing.T) {
	cfgGraph := buildLiveCFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {},
	})

	function := &ir.Function{
		Name: "load_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Load{
						Dest:    ssaVar("x", 1),
						Address: intConst(0x1000),
						Size:    ir.Size8,
					},
					&ir.Return{Value: &ir.Variable{Name: "x", Type: intType(), Version: 1}},
				},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewLiveVarsAnalyzer(function, cfgGraph, nil)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// x_1 must be live after load (used by return)
	liveOut00 := result.GetLiveOutAt(ProgramPoint{BlockID: 0, InstrIdx: 0})
	if !liveOut00.Contains(ssaVar("x", 1)) {
		t.Error("expected x_1 live after load")
	}

	// x_1 must be dead after return
	liveOut01 := result.GetLiveOutAt(ProgramPoint{BlockID: 0, InstrIdx: 1})
	if liveOut01.Contains(ssaVar("x", 1)) {
		t.Error("expected x_1 dead after return")
	}
}

// TestLiveVars_CallWithReturnValue tests liveness with a call that returns a value.
// bb0: result_1 = call foo(x_1); return result_1
func TestLiveVars_CallWithReturnValue(t *testing.T) {
	cfgGraph := buildLiveCFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {},
	})

	resultVar := ssaVar("result", 1)
	function := &ir.Function{
		Name: "call_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("x", 1), Source: intConst(5)},
					&ir.Call{
						Dest:   &resultVar,
						Target: ir.VariableExpr{Var: ir.Variable{Name: "foo", Type: ir.FunctionType{}}},
						Args:   []ir.Variable{ssaVar("x", 1)},
					},
					&ir.Return{Value: &ir.Variable{Name: "result", Type: intType(), Version: 1}},
				},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewLiveVarsAnalyzer(function, cfgGraph, nil)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// x_1 must be live after bb0:0 (used as call argument)
	liveOut00 := result.GetLiveOutAt(ProgramPoint{BlockID: 0, InstrIdx: 0})
	if !liveOut00.Contains(ssaVar("x", 1)) {
		t.Error("expected x_1 live after bb0:0 (call argument)")
	}

	// result_1 must be live after call (used by return)
	liveOut01 := result.GetLiveOutAt(ProgramPoint{BlockID: 0, InstrIdx: 1})
	if !liveOut01.Contains(ssaVar("result", 1)) {
		t.Error("expected result_1 live after call")
	}

	// x_1 must be dead after call (no further use)
	if liveOut01.Contains(ssaVar("x", 1)) {
		t.Error("expected x_1 dead after call")
	}
}

// TestVarSet_Operations tests the VarSet data structure.
func TestVarSet_Operations(t *testing.T) {
	v1 := ssaVar("a", 1)
	v2 := ssaVar("b", 1)
	v3 := ssaVar("c", 1)

	t.Run("add and contains", func(t *testing.T) {
		vs := NewVarSet()
		vs.Add(v1)
		vs.Add(v2)
		if !vs.Contains(v1) {
			t.Error("expected v1 in set")
		}
		if !vs.Contains(v2) {
			t.Error("expected v2 in set")
		}
		if vs.Contains(v3) {
			t.Error("expected v3 not in set")
		}
		if vs.Len() != 2 {
			t.Errorf("expected len 2, got %d", vs.Len())
		}
	})

	t.Run("duplicate add", func(t *testing.T) {
		vs := NewVarSet()
		vs.Add(v1)
		vs.Add(v1)
		if vs.Len() != 1 {
			t.Errorf("expected len 1 after duplicate add, got %d", vs.Len())
		}
	})

	t.Run("remove", func(t *testing.T) {
		vs := NewVarSet()
		vs.Add(v1)
		vs.Add(v2)
		vs.Remove(v1)
		if vs.Contains(v1) {
			t.Error("expected v1 removed")
		}
		if vs.Len() != 1 {
			t.Errorf("expected len 1, got %d", vs.Len())
		}
	})

	t.Run("union", func(t *testing.T) {
		vs1 := NewVarSet()
		vs1.Add(v1)
		vs1.Add(v2)
		vs2 := NewVarSet()
		vs2.Add(v2)
		vs2.Add(v3)
		u := vs1.Union(vs2)
		if u.Len() != 3 {
			t.Errorf("expected union len 3, got %d", u.Len())
		}
	})

	t.Run("difference", func(t *testing.T) {
		vs1 := NewVarSet()
		vs1.Add(v1)
		vs1.Add(v2)
		vs1.Add(v3)
		vs2 := NewVarSet()
		vs2.Add(v2)
		diff := vs1.Difference(vs2)
		if diff.Len() != 2 {
			t.Errorf("expected diff len 2, got %d", diff.Len())
		}
		if diff.Contains(v2) {
			t.Error("expected v2 not in difference")
		}
		if !diff.Contains(v1) || !diff.Contains(v3) {
			t.Error("expected v1 and v3 in difference")
		}
	})

	t.Run("equal", func(t *testing.T) {
		vs1 := NewVarSet()
		vs1.Add(v1)
		vs1.Add(v2)
		vs2 := NewVarSet()
		vs2.Add(v2)
		vs2.Add(v1)
		if !vs1.Equal(vs2) {
			t.Error("expected equal sets")
		}
		vs3 := NewVarSet()
		vs3.Add(v1)
		if vs1.Equal(vs3) {
			t.Error("expected unequal sets")
		}
	})

	t.Run("clone independence", func(t *testing.T) {
		vs := NewVarSet()
		vs.Add(v1)
		clone := vs.Clone()
		clone.Add(v2)
		if vs.Len() != 1 {
			t.Error("mutating clone should not affect original")
		}
	})

	t.Run("new from slice", func(t *testing.T) {
		vs := NewVarSetFrom([]ir.Variable{v3, v1, v2})
		if vs.Len() != 3 {
			t.Errorf("expected len 3, got %d", vs.Len())
		}
		// verify sorted order
		slice := vs.Slice()
		for i := 1; i < len(slice); i++ {
			if !varLess(slice[i-1], slice[i]) {
				t.Errorf("slice not sorted at index %d", i)
			}
		}
	})
}

// TestLiveVars_BlockLiveInOut verifies block-level live sets are consistent
// with per-instruction sets.
// bb0: x_1 = 1; y_1 = 2
// bb1: z_1 = x_1 + y_1; return z_1
func TestLiveVars_BlockLiveInOut(t *testing.T) {
	cfgGraph := buildLiveCFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {1},
		1: {},
	})

	function := makeMultiVarFunction()
	function.Name = "block_live"

	analyzer := NewLiveVarsAnalyzer(function, cfgGraph, nil)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// block live-out of bb0 must equal live-in of first instruction of bb1
	blockLiveOut0 := result.GetBlockLiveOut(0)
	instrLiveIn10 := result.GetLiveInAt(ProgramPoint{BlockID: 1, InstrIdx: 0})
	if !blockLiveOut0.Equal(instrLiveIn10) {
		t.Errorf("block live-out of bb0 (%v) != live-in of bb1:0 (%v)",
			blockLiveOut0.Slice(), instrLiveIn10.Slice())
	}

	// block live-in of bb1 must equal live-in of first instruction of bb1
	blockLiveIn1 := result.GetBlockLiveIn(1)
	if !blockLiveIn1.Equal(instrLiveIn10) {
		t.Errorf("block live-in of bb1 (%v) != live-in of bb1:0 (%v)",
			blockLiveIn1.Slice(), instrLiveIn10.Slice())
	}

	// x_1 and y_1 must be live at entry of bb1
	if !blockLiveIn1.Contains(ssaVar("x", 1)) {
		t.Error("expected x_1 live at entry of bb1")
	}
	if !blockLiveIn1.Contains(ssaVar("y", 1)) {
		t.Error("expected y_1 live at entry of bb1")
	}

	// nothing should be live at entry of bb0 (no predecessors, no upward-exposed uses)
	blockLiveIn0 := result.GetBlockLiveIn(0)
	if blockLiveIn0.Len() != 0 {
		t.Errorf("expected nothing live at entry of bb0, got %v", blockLiveIn0.Slice())
	}
}

// TestLiveVars_IsLiveAt tests the IsLiveAt and IsLiveAfter convenience methods.
func TestLiveVars_IsLiveAt(t *testing.T) {
	cfgGraph := buildLiveCFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {},
	})

	function := &ir.Function{
		Name: "is_live_at",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("x", 1), Source: intConst(1)},
					&ir.Return{Value: &ir.Variable{Name: "x", Type: intType(), Version: 1}},
				},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewLiveVarsAnalyzer(function, cfgGraph, nil)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	p00 := ProgramPoint{BlockID: 0, InstrIdx: 0}
	p01 := ProgramPoint{BlockID: 0, InstrIdx: 1}

	// x_1 is not live before bb0:0 (not yet defined, no upward-exposed use)
	if result.IsLiveAt(p00, ssaVar("x", 1)) {
		t.Error("x_1 should not be live before bb0:0")
	}

	// x_1 is live after bb0:0 (used by return)
	if !result.IsLiveAfter(p00, ssaVar("x", 1)) {
		t.Error("x_1 should be live after bb0:0")
	}

	// x_1 is live before bb0:1 (return uses it)
	if !result.IsLiveAt(p01, ssaVar("x", 1)) {
		t.Error("x_1 should be live before bb0:1")
	}

	// x_1 is dead after bb0:1 (return consumes it)
	if result.IsLiveAfter(p01, ssaVar("x", 1)) {
		t.Error("x_1 should be dead after bb0:1")
	}
}

func TestLiveVars_UnaryOpExpression(t *testing.T) {
	cfgGraph := buildLiveCFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {},
	})

	function := &ir.Function{
		Name: "unary_op",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("x", 1), Source: intConst(42)},
					&ir.Assign{
						Dest:   ssaVar("y", 1),
						Source: &ir.UnaryOp{Op: ir.UnOpNeg, Operand: varExpr("x", 1)},
					},
					&ir.Return{Value: &ir.Variable{Name: "y", Type: intType(), Version: 1}},
				},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewLiveVarsAnalyzer(function, cfgGraph, nil)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	liveOut00 := result.GetLiveOutAt(ProgramPoint{BlockID: 0, InstrIdx: 0})
	if !liveOut00.Contains(ssaVar("x", 1)) {
		t.Error("expected x_1 live after bb0:0 (used by unary op)")
	}

	liveOut01 := result.GetLiveOutAt(ProgramPoint{BlockID: 0, InstrIdx: 1})
	if !liveOut01.Contains(ssaVar("y", 1)) {
		t.Error("expected y_1 live after bb0:1")
	}
	if liveOut01.Contains(ssaVar("x", 1)) {
		t.Error("expected x_1 dead after bb0:1")
	}
}

func TestLiveVars_CastExpression(t *testing.T) {
	cfgGraph := buildLiveCFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {},
	})

	function := &ir.Function{
		Name: "cast_expr",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("x", 1), Source: intConst(42)},
					&ir.Assign{
						Dest: ssaVar("y", 1),
						Source: &ir.Cast{
							Expr:       varExpr("x", 1),
							TargetType: ir.IntType{Width: ir.Size8, Signed: false},
						},
					},
					&ir.Return{Value: &ir.Variable{Name: "y", Type: intType(), Version: 1}},
				},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewLiveVarsAnalyzer(function, cfgGraph, nil)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	liveOut00 := result.GetLiveOutAt(ProgramPoint{BlockID: 0, InstrIdx: 0})
	if !liveOut00.Contains(ssaVar("x", 1)) {
		t.Error("expected x_1 live after bb0:0 (used by cast)")
	}

	liveOut01 := result.GetLiveOutAt(ProgramPoint{BlockID: 0, InstrIdx: 1})
	if liveOut01.Contains(ssaVar("x", 1)) {
		t.Error("expected x_1 dead after bb0:1")
	}
}

func TestLiveVars_PointerTypeExpressions(t *testing.T) {
	cfgGraph := buildLiveCFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {},
	})

	function := &ir.Function{
		Name: "ptr_expr",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("a", 1), Source: intConst(1)},
					&ir.Assign{Dest: ssaVar("b", 1), Source: intConst(2)},
					&ir.Assign{
						Dest: ssaVar("c", 1),
						Source: &ir.BinaryOp{
							Op:    ir.BinOpAdd,
							Left:  &ir.VariableExpr{Var: ssaVar("a", 1)},
							Right: &ir.VariableExpr{Var: ssaVar("b", 1)},
						},
					},
					&ir.Return{Value: &ir.Variable{Name: "c", Type: intType(), Version: 1}},
				},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewLiveVarsAnalyzer(function, cfgGraph, nil)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	liveOut01 := result.GetLiveOutAt(ProgramPoint{BlockID: 0, InstrIdx: 1})
	if !liveOut01.Contains(ssaVar("a", 1)) {
		t.Error("expected a_1 live after bb0:1 (used by pointer-type BinaryOp)")
	}
	if !liveOut01.Contains(ssaVar("b", 1)) {
		t.Error("expected b_1 live after bb0:1 (used by pointer-type BinaryOp)")
	}
}

func TestLiveVars_NonexistentProgramPoint(t *testing.T) {
	cfgGraph := buildLiveCFG(0, map[cfg.BlockID][]cfg.BlockID{
		0: {},
	})

	function := &ir.Function{
		Name: "nonexistent",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Return{},
				},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewLiveVarsAnalyzer(function, cfgGraph, nil)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	bogus := ProgramPoint{BlockID: 99, InstrIdx: 0}
	if result.IsLiveAt(bogus, ssaVar("x", 1)) {
		t.Error("expected false for nonexistent program point")
	}
	if result.IsLiveAfter(bogus, ssaVar("x", 1)) {
		t.Error("expected false for nonexistent program point")
	}
	if result.GetLiveInAt(bogus).Len() != 0 {
		t.Error("expected empty set for nonexistent program point")
	}
	if result.GetLiveOutAt(bogus).Len() != 0 {
		t.Error("expected empty set for nonexistent program point")
	}
	if result.GetBlockLiveIn(99).Len() != 0 {
		t.Error("expected empty set for nonexistent block")
	}
	if result.GetBlockLiveOut(99).Len() != 0 {
		t.Error("expected empty set for nonexistent block")
	}
}

func TestLiveVars_RemoveNonexistent(t *testing.T) {
	vs := NewVarSet()
	vs.Add(ssaVar("a", 1))
	vs.Remove(ssaVar("z", 99))
	if vs.Len() != 1 {
		t.Error("removing nonexistent variable should not change set")
	}
}
