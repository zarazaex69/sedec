package analysis

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// helper to create a simple int type used across tests
func intType() ir.Type {
	return ir.IntType{Width: ir.Size8, Signed: true}
}

// helper to create a variable with ssa version
func ssaVar(name string, version int) ir.Variable {
	return ir.Variable{Name: name, Type: intType(), Version: version}
}

// helper to create a constant expression
func intConst(val int64) ir.Expression {
	return ir.ConstantExpr{Value: ir.IntConstant{Value: val, Width: ir.Size8, Signed: true}}
}

// helper to create a variable expression
func varExpr(name string, version int) ir.Expression {
	return ir.VariableExpr{Var: ssaVar(name, version)}
}

// buildCFGAndDomTree creates a cfg.CFG and dominator tree from block connectivity.
// blocks is a map of block id to list of successor block ids.
// entry is the entry block id.
func buildCFGAndDomTree(entry cfg.BlockID, blocks map[cfg.BlockID][]cfg.BlockID, idom map[cfg.BlockID]cfg.BlockID) (*cfg.CFG, *cfg.DominatorTree) {
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = entry

	// compute predecessors
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

	for id, succs := range blocks {
		for _, s := range succs {
			cfgGraph.AddEdge(id, s, cfg.EdgeTypeFallthrough)
		}
	}

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = idom

	// build children from idom
	children := make(map[cfg.BlockID][]cfg.BlockID)
	for id := range blocks {
		children[id] = nil
	}
	for block, dom := range idom {
		if block != dom {
			children[dom] = append(children[dom], block)
		}
	}
	domTree.Children = children

	return cfgGraph, domTree
}

// TestReachingDefs_LinearCode tests reaching definitions for straight-line ssa code.
// cfg: bb0 -> bb1 -> bb2
// bb0: x_1 = 1
// bb1: x_2 = x_1 + 1
// bb2: return x_2
func TestReachingDefs_LinearCode(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{
			0: {1},
			1: {2},
			2: {},
		},
		map[cfg.BlockID]cfg.BlockID{
			0: 0,
			1: 0,
			2: 1,
		},
	)

	function := &ir.Function{
		Name: "linear",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("x", 1), Source: intConst(1)},
				},
				Successors: []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest: ssaVar("x", 2),
						Source: ir.BinaryOp{
							Op:    ir.BinOpAdd,
							Left:  varExpr("x", 1),
							Right: intConst(1),
						},
					},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{2},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Return{Value: &ir.Variable{Name: "x", Type: intType(), Version: 2}},
				},
				Predecessors: []ir.BlockID{1},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewReachingDefsAnalyzer(function, cfgGraph, domTree)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// at bb0:0 (x_1 = 1), reach-in should be empty (entry point)
	reachIn00 := result.GetReachingDefsAt(ProgramPoint{BlockID: 0, InstrIdx: 0})
	if reachIn00.Len() != 0 {
		t.Errorf("expected 0 reaching defs at bb0:0, got %d", reachIn00.Len())
	}

	// after bb0:0, x_1 should be defined
	reachOut00 := result.GetDefinitionsAfter(ProgramPoint{BlockID: 0, InstrIdx: 0})
	if reachOut00.Len() != 1 {
		t.Errorf("expected 1 definition after bb0:0, got %d", reachOut00.Len())
	}

	// at bb1:0 (x_2 = x_1 + 1), reach-in should contain x_1
	reachIn10 := result.GetReachingDefsAt(ProgramPoint{BlockID: 1, InstrIdx: 0})
	if reachIn10.Len() != 1 {
		t.Errorf("expected 1 reaching def at bb1:0, got %d", reachIn10.Len())
	}
	defs := result.GetReachingDefsForVariable(ProgramPoint{BlockID: 1, InstrIdx: 0}, "x")
	if len(defs) != 1 || defs[0].Variable.Version != 1 {
		t.Errorf("expected x_1 reaching bb1:0, got %v", defs)
	}

	// at bb2:0 (return x_2), reach-in should contain x_1 and x_2
	reachIn20 := result.GetReachingDefsAt(ProgramPoint{BlockID: 2, InstrIdx: 0})
	if reachIn20.Len() != 2 {
		t.Errorf("expected 2 reaching defs at bb2:0, got %d", reachIn20.Len())
	}

	// verify def sites
	site, ok := result.GetDefinitionSite(ssaVar("x", 1))
	if !ok {
		t.Fatal("expected definition site for x_1")
	}
	if site.BlockID != 0 || site.InstrIdx != 0 {
		t.Errorf("expected x_1 defined at bb0:0, got %s", site.String())
	}

	site, ok = result.GetDefinitionSite(ssaVar("x", 2))
	if !ok {
		t.Fatal("expected definition site for x_2")
	}
	if site.BlockID != 1 || site.InstrIdx != 0 {
		t.Errorf("expected x_2 defined at bb1:0, got %s", site.String())
	}
}

// TestReachingDefs_IfThenElse tests reaching definitions with a diamond cfg pattern.
// cfg:
//
//	bb0 (entry)
//	 / \
//	bb1  bb2
//	 \ /
//	bb3 (merge)
//
// bb0: cond_1 = ...
// bb1: x_1 = 10
// bb2: x_2 = 20
// bb3: x_3 = phi(x_1, x_2); return x_3
func TestReachingDefs_IfThenElse(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{
			0: {1, 2},
			1: {3},
			2: {3},
			3: {},
		},
		map[cfg.BlockID]cfg.BlockID{
			0: 0,
			1: 0,
			2: 0,
			3: 0,
		},
	)

	function := &ir.Function{
		Name: "if_then_else",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("cond", 1), Source: intConst(1)},
					&ir.Branch{
						Condition:   varExpr("cond", 1),
						TrueTarget:  1,
						FalseTarget: 2,
					},
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

	analyzer := NewReachingDefsAnalyzer(function, cfgGraph, domTree)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// at bb3:0 (phi node), reach-in should contain cond_1, x_1, x_2
	// (cond_1 from bb0, x_1 from bb1, x_2 from bb2)
	reachIn30 := result.GetReachingDefsAt(ProgramPoint{BlockID: 3, InstrIdx: 0})
	if reachIn30.Len() != 3 {
		t.Errorf("expected 3 reaching defs at bb3:0, got %d: %v", reachIn30.Len(), reachIn30.Slice())
	}

	// after phi (bb3:0), x_3 should also be in the set
	reachOut30 := result.GetDefinitionsAfter(ProgramPoint{BlockID: 3, InstrIdx: 0})
	if reachOut30.Len() != 4 {
		t.Errorf("expected 4 definitions after bb3:0, got %d: %v", reachOut30.Len(), reachOut30.Slice())
	}

	// x definitions reaching bb3:0 should be x_1 and x_2
	xDefs := result.GetReachingDefsForVariable(ProgramPoint{BlockID: 3, InstrIdx: 0}, "x")
	if len(xDefs) != 2 {
		t.Errorf("expected 2 x-definitions reaching bb3:0, got %d", len(xDefs))
	}
}

// TestReachingDefs_WhileLoop tests reaching definitions with a loop.
// cfg:
//
//	bb0 (entry)
//	  |
//	bb1 (loop header) <--+
//	  |                   |
//	bb2 (loop body) ------+
//	  |
//	bb3 (exit)
//
// bb0: i_1 = 0
// bb1: i_2 = phi(i_1, i_3); branch i_2 < 10
// bb2: i_3 = i_2 + 1; jump bb1
// bb3: return i_2
func TestReachingDefs_WhileLoop(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{
			0: {1},
			1: {2, 3},
			2: {1},
			3: {},
		},
		map[cfg.BlockID]cfg.BlockID{
			0: 0,
			1: 0,
			2: 1,
			3: 1,
		},
	)

	function := &ir.Function{
		Name: "while_loop",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("i", 1), Source: intConst(0)},
				},
				Successors: []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Phi{
						Dest: ssaVar("i", 2),
						Sources: []ir.PhiSource{
							{Block: 0, Var: ssaVar("i", 1)},
							{Block: 2, Var: ssaVar("i", 3)},
						},
					},
					&ir.Branch{
						Condition: ir.BinaryOp{
							Op:    ir.BinOpLt,
							Left:  varExpr("i", 2),
							Right: intConst(10),
						},
						TrueTarget:  2,
						FalseTarget: 3,
					},
				},
				Predecessors: []ir.BlockID{0, 2},
				Successors:   []ir.BlockID{2, 3},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest: ssaVar("i", 3),
						Source: ir.BinaryOp{
							Op:    ir.BinOpAdd,
							Left:  varExpr("i", 2),
							Right: intConst(1),
						},
					},
					&ir.Jump{Target: 1},
				},
				Predecessors: []ir.BlockID{1},
				Successors:   []ir.BlockID{1},
			},
			3: {
				ID: 3,
				Instructions: []ir.IRInstruction{
					&ir.Return{Value: &ir.Variable{Name: "i", Type: intType(), Version: 2}},
				},
				Predecessors: []ir.BlockID{1},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewReachingDefsAnalyzer(function, cfgGraph, domTree)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// at bb1:0 (phi node), reach-in is union of bb0-out and bb2-out.
	// bb0-out = {i_1}; bb2-out = {i_1, i_2, i_3} (after fixed-point).
	// so reach-in bb1:0 = {i_1, i_2, i_3} at fixed-point.
	iDefs := result.GetReachingDefsForVariable(ProgramPoint{BlockID: 1, InstrIdx: 0}, "i")
	if len(iDefs) < 2 {
		t.Errorf("expected at least 2 i-definitions reaching bb1:0, got %d: %v", len(iDefs), iDefs)
	}

	// after phi at bb1:0, i_2 is also defined -- all three i versions present
	reachOut10 := result.GetDefinitionsAfter(ProgramPoint{BlockID: 1, InstrIdx: 0})
	iDefsAfter := make([]Definition, 0)
	for _, d := range reachOut10.Slice() {
		if d.Variable.Name == "i" {
			iDefsAfter = append(iDefsAfter, d)
		}
	}
	if len(iDefsAfter) < 2 {
		t.Errorf("expected at least 2 i-definitions after bb1:0, got %d: %v", len(iDefsAfter), iDefsAfter)
	}

	// verify fixed-point convergence: bb1 reach-in must include i_3 from back-edge
	blockReachIn1 := result.GetBlockReachIn(1)
	hasI3 := false
	for _, d := range blockReachIn1.Slice() {
		if d.Variable.Name == "i" && d.Variable.Version == 3 {
			hasI3 = true
			break
		}
	}
	if !hasI3 {
		t.Error("expected i_3 in block 1 reach-in (from back-edge), but not found")
	}

	// verify i_1 also reaches bb1 from the entry path
	hasI1 := false
	for _, d := range blockReachIn1.Slice() {
		if d.Variable.Name == "i" && d.Variable.Version == 1 {
			hasI1 = true
			break
		}
	}
	if !hasI1 {
		t.Error("expected i_1 in block 1 reach-in (from entry), but not found")
	}

	// at bb3:0 (return), all three i versions should reach
	reachIn30 := result.GetReachingDefsAt(ProgramPoint{BlockID: 3, InstrIdx: 0})
	if reachIn30.Len() < 3 {
		t.Errorf("expected at least 3 reaching defs at bb3:0, got %d: %v", reachIn30.Len(), reachIn30.Slice())
	}
}

// TestReachingDefs_MultipleVariables tests reaching definitions with multiple independent variables.
// cfg: bb0 -> bb1
// bb0: x_1 = 1; y_1 = 2
// bb1: z_1 = x_1 + y_1; return z_1
func TestReachingDefs_MultipleVariables(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{
			0: {1},
			1: {},
		},
		map[cfg.BlockID]cfg.BlockID{
			0: 0,
			1: 0,
		},
	)

	function := &ir.Function{
		Name: "multi_var",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("x", 1), Source: intConst(1)},
					&ir.Assign{Dest: ssaVar("y", 1), Source: intConst(2)},
				},
				Successors: []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest: ssaVar("z", 1),
						Source: ir.BinaryOp{
							Op:    ir.BinOpAdd,
							Left:  varExpr("x", 1),
							Right: varExpr("y", 1),
						},
					},
					&ir.Return{Value: &ir.Variable{Name: "z", Type: intType(), Version: 1}},
				},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewReachingDefsAnalyzer(function, cfgGraph, domTree)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// at bb1:0, both x_1 and y_1 should reach
	reachIn10 := result.GetReachingDefsAt(ProgramPoint{BlockID: 1, InstrIdx: 0})
	if reachIn10.Len() != 2 {
		t.Errorf("expected 2 reaching defs at bb1:0, got %d: %v", reachIn10.Len(), reachIn10.Slice())
	}

	// at bb1:1 (return), x_1, y_1, z_1 should all reach
	reachIn11 := result.GetReachingDefsAt(ProgramPoint{BlockID: 1, InstrIdx: 1})
	if reachIn11.Len() != 3 {
		t.Errorf("expected 3 reaching defs at bb1:1, got %d: %v", reachIn11.Len(), reachIn11.Slice())
	}

	// verify def sites for all three variables
	for _, v := range []ir.Variable{ssaVar("x", 1), ssaVar("y", 1), ssaVar("z", 1)} {
		if _, ok := result.GetDefinitionSite(v); !ok {
			t.Errorf("expected definition site for %s", v.String())
		}
	}
}

// TestReachingDefs_LoadStore tests reaching definitions with memory operations.
// cfg: bb0 -> bb1
// bb0: store *addr, val; x_1 = load *addr
// bb1: return x_1
func TestReachingDefs_LoadStore(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{
			0: {1},
			1: {},
		},
		map[cfg.BlockID]cfg.BlockID{
			0: 0,
			1: 0,
		},
	)

	function := &ir.Function{
		Name: "load_store",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Store{
						Address: intConst(0x1000),
						Value:   intConst(42),
						Size:    ir.Size8,
					},
					&ir.Load{
						Dest:    ssaVar("x", 1),
						Address: intConst(0x1000),
						Size:    ir.Size8,
					},
				},
				Successors: []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Return{Value: &ir.Variable{Name: "x", Type: intType(), Version: 1}},
				},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewReachingDefsAnalyzer(function, cfgGraph, domTree)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// store does not define a variable, so after bb0:0 there are 0 defs
	reachOut00 := result.GetDefinitionsAfter(ProgramPoint{BlockID: 0, InstrIdx: 0})
	if reachOut00.Len() != 0 {
		t.Errorf("expected 0 definitions after store at bb0:0, got %d", reachOut00.Len())
	}

	// load defines x_1, so after bb0:1 there is 1 def
	reachOut01 := result.GetDefinitionsAfter(ProgramPoint{BlockID: 0, InstrIdx: 1})
	if reachOut01.Len() != 1 {
		t.Errorf("expected 1 definition after load at bb0:1, got %d", reachOut01.Len())
	}

	// at bb1:0, x_1 should reach
	reachIn10 := result.GetReachingDefsAt(ProgramPoint{BlockID: 1, InstrIdx: 0})
	if reachIn10.Len() != 1 {
		t.Errorf("expected 1 reaching def at bb1:0, got %d", reachIn10.Len())
	}
}

// TestReachingDefs_CallWithReturn tests reaching definitions with function calls.
// cfg: bb0
// bb0: result_1 = call foo(x_1); return result_1
func TestReachingDefs_CallWithReturn(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{
			0: {},
		},
		map[cfg.BlockID]cfg.BlockID{
			0: 0,
		},
	)

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

	analyzer := NewReachingDefsAnalyzer(function, cfgGraph, domTree)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// after call (bb0:1), both x_1 and result_1 should be defined
	reachOut01 := result.GetDefinitionsAfter(ProgramPoint{BlockID: 0, InstrIdx: 1})
	if reachOut01.Len() != 2 {
		t.Errorf("expected 2 definitions after call at bb0:1, got %d: %v", reachOut01.Len(), reachOut01.Slice())
	}

	// verify result_1 has a def site
	site, ok := result.GetDefinitionSite(ssaVar("result", 1))
	if !ok {
		t.Fatal("expected definition site for result_1")
	}
	if site.BlockID != 0 || site.InstrIdx != 1 {
		t.Errorf("expected result_1 defined at bb0:1, got %s", site.String())
	}
}

// TestReachingDefs_VoidCall tests that void calls (no return value) don't create definitions.
func TestReachingDefs_VoidCall(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{
			0: {},
		},
		map[cfg.BlockID]cfg.BlockID{
			0: 0,
		},
	)

	function := &ir.Function{
		Name: "void_call",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Call{
						Dest:   nil, // void call
						Target: ir.VariableExpr{Var: ir.Variable{Name: "bar", Type: ir.FunctionType{}}},
					},
					&ir.Return{},
				},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewReachingDefsAnalyzer(function, cfgGraph, domTree)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// void call should not create any definitions
	reachOut00 := result.GetDefinitionsAfter(ProgramPoint{BlockID: 0, InstrIdx: 0})
	if reachOut00.Len() != 0 {
		t.Errorf("expected 0 definitions after void call, got %d", reachOut00.Len())
	}
}

// TestReachingDefs_NilFunction tests error handling for nil function.
func TestReachingDefs_NilFunction(t *testing.T) {
	analyzer := NewReachingDefsAnalyzer(nil, nil, nil)
	_, err := analyzer.Compute()
	if err == nil {
		t.Fatal("expected error for nil function")
	}
}

// TestReachingDefs_EmptyFunction tests error handling for function with no blocks.
func TestReachingDefs_EmptyFunction(t *testing.T) {
	function := &ir.Function{
		Name:   "empty",
		Blocks: map[ir.BlockID]*ir.BasicBlock{},
	}
	analyzer := NewReachingDefsAnalyzer(function, nil, nil)
	_, err := analyzer.Compute()
	if err == nil {
		t.Fatal("expected error for empty function")
	}
}

// TestReachingDefs_PreSSA tests reaching definitions for non-ssa code (version 0).
// in pre-ssa form, redefinitions kill previous definitions of the same variable.
// cfg: bb0
// bb0: x = 1; x = 2; return x
func TestReachingDefs_PreSSA(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{
			0: {},
		},
		map[cfg.BlockID]cfg.BlockID{
			0: 0,
		},
	)

	function := &ir.Function{
		Name: "pre_ssa",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ir.Variable{Name: "x", Type: intType()}, Source: intConst(1)},
					&ir.Assign{Dest: ir.Variable{Name: "x", Type: intType()}, Source: intConst(2)},
					&ir.Return{Value: &ir.Variable{Name: "x", Type: intType()}},
				},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewReachingDefsAnalyzer(function, cfgGraph, domTree)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// after first assignment (bb0:0), x (version 0) at bb0:0 should be defined
	reachOut00 := result.GetDefinitionsAfter(ProgramPoint{BlockID: 0, InstrIdx: 0})
	if reachOut00.Len() != 1 {
		t.Errorf("expected 1 definition after bb0:0, got %d", reachOut00.Len())
	}

	// after second assignment (bb0:1), the first x should be killed, only x at bb0:1 remains
	reachOut01 := result.GetDefinitionsAfter(ProgramPoint{BlockID: 0, InstrIdx: 1})
	if reachOut01.Len() != 1 {
		t.Errorf("expected 1 definition after bb0:1 (kill of first x), got %d: %v", reachOut01.Len(), reachOut01.Slice())
	}
	defs := reachOut01.Slice()
	if len(defs) == 1 && defs[0].Point.InstrIdx != 1 {
		t.Errorf("expected surviving definition at bb0:1, got %s", defs[0].Point.String())
	}

	// at return (bb0:2), only the second x definition should reach
	reachIn02 := result.GetReachingDefsAt(ProgramPoint{BlockID: 0, InstrIdx: 2})
	if reachIn02.Len() != 1 {
		t.Errorf("expected 1 reaching def at bb0:2, got %d", reachIn02.Len())
	}
}

// TestDefinitionSet_Operations tests the DefinitionSet data structure operations.
func TestDefinitionSet_Operations(t *testing.T) {
	d1 := Definition{Point: ProgramPoint{BlockID: 0, InstrIdx: 0}, Variable: ssaVar("x", 1)}
	d2 := Definition{Point: ProgramPoint{BlockID: 1, InstrIdx: 0}, Variable: ssaVar("y", 1)}
	d3 := Definition{Point: ProgramPoint{BlockID: 2, InstrIdx: 0}, Variable: ssaVar("z", 1)}

	t.Run("add and contains", func(t *testing.T) {
		ds := NewDefinitionSet()
		ds.Add(d1)
		ds.Add(d2)

		if !ds.Contains(d1) {
			t.Error("expected set to contain d1")
		}
		if !ds.Contains(d2) {
			t.Error("expected set to contain d2")
		}
		if ds.Contains(d3) {
			t.Error("expected set to not contain d3")
		}
		if ds.Len() != 2 {
			t.Errorf("expected len 2, got %d", ds.Len())
		}
	})

	t.Run("duplicate add", func(t *testing.T) {
		ds := NewDefinitionSet()
		ds.Add(d1)
		ds.Add(d1) // duplicate
		if ds.Len() != 1 {
			t.Errorf("expected len 1 after duplicate add, got %d", ds.Len())
		}
	})

	t.Run("remove", func(t *testing.T) {
		ds := NewDefinitionSet()
		ds.Add(d1)
		ds.Add(d2)
		ds.Remove(d1)
		if ds.Contains(d1) {
			t.Error("expected d1 removed")
		}
		if ds.Len() != 1 {
			t.Errorf("expected len 1 after remove, got %d", ds.Len())
		}
	})

	t.Run("union", func(t *testing.T) {
		ds1 := NewDefinitionSet()
		ds1.Add(d1)
		ds1.Add(d2)

		ds2 := NewDefinitionSet()
		ds2.Add(d2)
		ds2.Add(d3)

		union := ds1.Union(ds2)
		if union.Len() != 3 {
			t.Errorf("expected union len 3, got %d", union.Len())
		}
		if !union.Contains(d1) || !union.Contains(d2) || !union.Contains(d3) {
			t.Error("union missing elements")
		}
	})

	t.Run("equal", func(t *testing.T) {
		ds1 := NewDefinitionSet()
		ds1.Add(d1)
		ds1.Add(d2)

		ds2 := NewDefinitionSet()
		ds2.Add(d2)
		ds2.Add(d1) // different insertion order

		if !ds1.Equal(ds2) {
			t.Error("expected equal sets")
		}

		ds3 := NewDefinitionSet()
		ds3.Add(d1)
		if ds1.Equal(ds3) {
			t.Error("expected unequal sets")
		}
	})

	t.Run("clone", func(t *testing.T) {
		ds := NewDefinitionSet()
		ds.Add(d1)
		ds.Add(d2)

		clone := ds.Clone()
		if !ds.Equal(clone) {
			t.Error("clone should equal original")
		}

		// mutating clone should not affect original
		clone.Add(d3)
		if ds.Equal(clone) {
			t.Error("mutating clone should not affect original")
		}
	})

	t.Run("new from slice", func(t *testing.T) {
		ds := NewDefinitionSetFrom([]Definition{d3, d1, d2})
		if ds.Len() != 3 {
			t.Errorf("expected len 3, got %d", ds.Len())
		}
		// verify sorted order
		slice := ds.Slice()
		for i := 1; i < len(slice); i++ {
			if !defLess(slice[i-1], slice[i]) {
				t.Errorf("slice not sorted at index %d", i)
			}
		}
	})
}

// TestReachingDefs_NestedLoops tests reaching definitions with nested loop structure.
// cfg:
//
//	bb0 (entry)
//	  |
//	bb1 (outer header) <--------+
//	  |                          |
//	bb2 (inner header) <--+     |
//	  |                    |     |
//	bb3 (inner body) -----+     |
//	  |                          |
//	bb4 (outer latch) ----------+
//	  |
//	bb5 (exit)
func TestReachingDefs_NestedLoops(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{
			0: {1},
			1: {2, 5},
			2: {3, 4},
			3: {2},
			4: {1},
			5: {},
		},
		map[cfg.BlockID]cfg.BlockID{
			0: 0,
			1: 0,
			2: 1,
			3: 2,
			4: 2,
			5: 1,
		},
	)

	function := &ir.Function{
		Name: "nested_loops",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("i", 1), Source: intConst(0)},
					&ir.Assign{Dest: ssaVar("sum", 1), Source: intConst(0)},
				},
				Successors: []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Phi{
						Dest: ssaVar("i", 2),
						Sources: []ir.PhiSource{
							{Block: 0, Var: ssaVar("i", 1)},
							{Block: 4, Var: ssaVar("i", 3)},
						},
					},
					&ir.Phi{
						Dest: ssaVar("sum", 2),
						Sources: []ir.PhiSource{
							{Block: 0, Var: ssaVar("sum", 1)},
							{Block: 4, Var: ssaVar("sum", 4)},
						},
					},
					&ir.Branch{
						Condition:   varExpr("i", 2),
						TrueTarget:  2,
						FalseTarget: 5,
					},
				},
				Predecessors: []ir.BlockID{0, 4},
				Successors:   []ir.BlockID{2, 5},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Phi{
						Dest: ssaVar("sum", 3),
						Sources: []ir.PhiSource{
							{Block: 1, Var: ssaVar("sum", 2)},
							{Block: 3, Var: ssaVar("sum", 5)},
						},
					},
					&ir.Branch{
						Condition:   intConst(1),
						TrueTarget:  3,
						FalseTarget: 4,
					},
				},
				Predecessors: []ir.BlockID{1, 3},
				Successors:   []ir.BlockID{3, 4},
			},
			3: {
				ID: 3,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest: ssaVar("sum", 5),
						Source: ir.BinaryOp{
							Op:    ir.BinOpAdd,
							Left:  varExpr("sum", 3),
							Right: intConst(1),
						},
					},
					&ir.Jump{Target: 2},
				},
				Predecessors: []ir.BlockID{2},
				Successors:   []ir.BlockID{2},
			},
			4: {
				ID: 4,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest: ssaVar("i", 3),
						Source: ir.BinaryOp{
							Op:    ir.BinOpAdd,
							Left:  varExpr("i", 2),
							Right: intConst(1),
						},
					},
					&ir.Assign{
						Dest:   ssaVar("sum", 4),
						Source: varExpr("sum", 3),
					},
					&ir.Jump{Target: 1},
				},
				Predecessors: []ir.BlockID{2},
				Successors:   []ir.BlockID{1},
			},
			5: {
				ID: 5,
				Instructions: []ir.IRInstruction{
					&ir.Return{Value: &ir.Variable{Name: "sum", Type: intType(), Version: 2}},
				},
				Predecessors: []ir.BlockID{1},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewReachingDefsAnalyzer(function, cfgGraph, domTree)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// verify that all definition sites are recorded
	expectedDefs := []ir.Variable{
		ssaVar("i", 1), ssaVar("i", 2), ssaVar("i", 3),
		ssaVar("sum", 1), ssaVar("sum", 2), ssaVar("sum", 3),
		ssaVar("sum", 4), ssaVar("sum", 5),
	}
	for _, v := range expectedDefs {
		if _, ok := result.GetDefinitionSite(v); !ok {
			t.Errorf("missing definition site for %s", v.String())
		}
	}

	// at exit block (bb5), all definitions should be reachable through the loop
	reachIn50 := result.GetReachingDefsAt(ProgramPoint{BlockID: 5, InstrIdx: 0})
	if reachIn50.Len() < 5 {
		t.Errorf("expected at least 5 reaching defs at exit, got %d", reachIn50.Len())
	}

	// inner loop header (bb2) should have sum definitions from both outer and inner loops
	sumDefs := result.GetReachingDefsForVariable(ProgramPoint{BlockID: 2, InstrIdx: 0}, "sum")
	if len(sumDefs) < 2 {
		t.Errorf("expected at least 2 sum-definitions reaching bb2:0, got %d", len(sumDefs))
	}
}

// TestProgramPoint_String tests the string representation of ProgramPoint.
func TestProgramPoint_String(t *testing.T) {
	pp := ProgramPoint{BlockID: 3, InstrIdx: 7}
	expected := "bb3:7"
	if pp.String() != expected {
		t.Errorf("expected %q, got %q", expected, pp.String())
	}
}

// TestDefinition_String tests the string representation of Definition.
func TestDefinition_String(t *testing.T) {
	d := Definition{
		Point:    ProgramPoint{BlockID: 1, InstrIdx: 2},
		Variable: ssaVar("x", 3),
	}
	expected := "x_3@bb1:2"
	if d.String() != expected {
		t.Errorf("expected %q, got %q", expected, d.String())
	}
}
