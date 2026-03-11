package ssa

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// Round-Trip Property Tests: IR → SSA → verify SSA invariants
// ============================================================================

// verifySSAProperty checks the fundamental ssa invariant:
// every variable has exactly one definition in the entire function.
// this is the core correctness property of ssa form.
func verifySSAProperty(t *testing.T, fn *ir.Function) {
	t.Helper()

	// map from variable name+version to definition count
	defCount := make(map[string]int)

	for blockID, block := range fn.Blocks {
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
			}

			if definedVar == nil || definedVar.Version == 0 {
				continue
			}

			key := definedVar.String()
			defCount[key]++

			if defCount[key] > 1 {
				t.Errorf("ssa violation: variable %s defined more than once (block %d)", key, blockID)
			}
		}
	}
}

// verifyDominanceProperty checks that phi-nodes only appear at the beginning of blocks
// and that each phi-node has exactly one source per predecessor block.
func verifyDominanceProperty(t *testing.T, fn *ir.Function) {
	t.Helper()

	for blockID, block := range fn.Blocks {
		seenNonPhi := false

		for _, instr := range block.Instructions {
			phi, isPhi := instr.(*ir.Phi)

			if isPhi {
				// phi-nodes must appear before all non-phi instructions
				if seenNonPhi {
					t.Errorf("dominance violation: phi-node after non-phi instruction in block %d", blockID)
				}

				// phi-node must have exactly one source per predecessor
				if len(phi.Sources) != len(block.Predecessors) {
					t.Errorf("phi-node in block %d has %d sources but block has %d predecessors",
						blockID, len(phi.Sources), len(block.Predecessors))
				}

				// each source must reference a valid predecessor block
				predSet := make(map[ir.BlockID]bool)
				for _, pred := range block.Predecessors {
					predSet[pred] = true
				}
				for _, src := range phi.Sources {
					if !predSet[src.Block] {
						t.Errorf("phi-node in block %d has source from non-predecessor block %d",
							blockID, src.Block)
					}
				}
			} else {
				seenNonPhi = true
			}
		}
	}
}

// buildIfThenElseFunction creates a canonical if-then-else ir function for testing
func buildIfThenElseFunction() (*ir.Function, *cfg.CFG, *cfg.DominatorTree) {
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0

	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0, Predecessors: []cfg.BlockID{}, Successors: []cfg.BlockID{1, 2}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{1, 2}, Successors: []cfg.BlockID{}})

	fn := &ir.Function{
		Name:       "if_then_else",
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
		Predecessors: []ir.BlockID{},
		Successors:   []ir.BlockID{1, 2},
	}
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 10, Width: ir.Size4, Signed: true}},
			},
			&ir.Jump{Target: 3},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{3},
	}
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 20, Width: ir.Size4, Signed: true}},
			},
			&ir.Jump{Target: 3},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{3},
	}
	fn.Blocks[3] = &ir.BasicBlock{
		ID: 3,
		Instructions: []ir.IRInstruction{
			&ir.Return{
				Value: &ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
			},
		},
		Predecessors: []ir.BlockID{1, 2},
		Successors:   []ir.BlockID{},
	}

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 0, 3: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {1, 2, 3}, 1: {}, 2: {}, 3: {}}

	return fn, cfgGraph, domTree
}

// TestSSAProperty_SingleDefinition verifies that after ssa transformation
// every versioned variable has exactly one definition (core ssa invariant).
func TestSSAProperty_SingleDefinition(t *testing.T) {
	fn, cfgGraph, domTree := buildIfThenElseFunction()

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	verifySSAProperty(t, fn)
}

// TestSSAProperty_PhiNodePlacement verifies dominance property:
// phi-nodes appear only at the beginning of blocks and have correct sources.
func TestSSAProperty_PhiNodePlacement(t *testing.T) {
	fn, cfgGraph, domTree := buildIfThenElseFunction()

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	verifyDominanceProperty(t, fn)
}

// TestSSAProperty_VersionMonotonicity verifies that version numbers are monotonically
// increasing along any path through the dominator tree.
// this ensures the renaming algorithm correctly tracks definition order.
func TestSSAProperty_VersionMonotonicity(t *testing.T) {
	// create linear chain: bb0 → bb1 → bb2 → bb3
	// each block redefines x, so versions must increase: x_1, x_2, x_3, x_4
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0, Successors: []cfg.BlockID{1}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{2}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{2}})

	fn := &ir.Function{
		Name:       "version_monotonicity",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	for i := ir.BlockID(0); i < 4; i++ {
		fn.Blocks[i] = &ir.BasicBlock{
			ID: i,
			Instructions: []ir.IRInstruction{
				&ir.Assign{
					Dest:   ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
					Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: int64(i), Width: ir.Size4, Signed: true}},
				},
			},
		}
	}
	fn.Blocks[0].Successors = []ir.BlockID{1}
	fn.Blocks[1].Predecessors = []ir.BlockID{0}
	fn.Blocks[1].Successors = []ir.BlockID{2}
	fn.Blocks[2].Predecessors = []ir.BlockID{1}
	fn.Blocks[2].Successors = []ir.BlockID{3}
	fn.Blocks[3].Predecessors = []ir.BlockID{2}

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 1, 3: 2}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {1}, 1: {2}, 2: {3}, 3: {}}

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	// verify versions are 1, 2, 3, 4 in order
	for i := ir.BlockID(0); i < 4; i++ {
		assign, ok := fn.Blocks[i].Instructions[0].(*ir.Assign)
		if !ok {
			t.Fatalf("block %d: expected *ir.Assign", i)
		}
		expectedVersion := int(i) + 1
		if assign.Dest.Version != expectedVersion {
			t.Errorf("block %d: expected x_%d, got x_%d", i, expectedVersion, assign.Dest.Version)
		}
	}

	verifySSAProperty(t, fn)
}

// ============================================================================
// Round-Trip Tests: IR → SSA → verify semantic equivalence
// ============================================================================

// TestRoundTrip_StoreAndLoad tests ssa transformation with store/load instructions
// verifies that renameUsesInInstruction handles Store and Load correctly
func TestRoundTrip_StoreAndLoad(t *testing.T) {
	// bb0:
	//   ptr = 0x1000
	//   store.4 ptr, 42
	//   v = load.4 ptr
	//   return v

	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0})

	fn := &ir.Function{
		Name:       "store_load",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	ptrVar := ir.Variable{Name: "ptr", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: true}}}
	vVar := ir.Variable{Name: "v", Type: ir.IntType{Width: ir.Size4, Signed: true}}

	fn.Blocks[0] = &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			// ptr = 0x1000
			&ir.Assign{
				Dest:   ptrVar,
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x1000, Width: ir.Size8, Signed: false}},
			},
			// store.4 ptr, 42
			&ir.Store{
				Address: &ir.VariableExpr{Var: ptrVar},
				Value:   &ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size4, Signed: true}},
				Size:    ir.Size4,
			},
			// v = load.4 ptr
			&ir.Load{
				Dest:    vVar,
				Address: &ir.VariableExpr{Var: ptrVar},
				Size:    ir.Size4,
			},
			// return v
			&ir.Return{Value: &vVar},
		},
	}

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	verifySSAProperty(t, fn)

	block := fn.Blocks[0]

	// ptr_1 = 0x1000
	assign, ok := block.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("instr 0: expected *ir.Assign, got %T", block.Instructions[0])
	}
	if assign.Dest.Version != 1 {
		t.Errorf("ptr definition: expected ptr_1, got ptr_%d", assign.Dest.Version)
	}

	// store.4 ptr_1, 42 — address must use ptr_1
	store, ok := block.Instructions[1].(*ir.Store)
	if !ok {
		t.Fatalf("instr 1: expected *ir.Store, got %T", block.Instructions[1])
	}
	addrExpr, ok := store.Address.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("store address: expected *ir.VariableExpr, got %T", store.Address)
	}
	if addrExpr.Var.Version != 1 {
		t.Errorf("store address: expected ptr_1, got ptr_%d", addrExpr.Var.Version)
	}

	// v_1 = load.4 ptr_1 — address must use ptr_1
	load, ok := block.Instructions[2].(*ir.Load)
	if !ok {
		t.Fatalf("instr 2: expected *ir.Load, got %T", block.Instructions[2])
	}
	loadAddrExpr, ok := load.Address.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("load address: expected *ir.VariableExpr, got %T", load.Address)
	}
	if loadAddrExpr.Var.Version != 1 {
		t.Errorf("load address: expected ptr_1, got ptr_%d", loadAddrExpr.Var.Version)
	}
	if load.Dest.Version != 1 {
		t.Errorf("load dest: expected v_1, got v_%d", load.Dest.Version)
	}

	// return v_1
	ret, ok := block.Instructions[3].(*ir.Return)
	if !ok {
		t.Fatalf("instr 3: expected *ir.Return, got %T", block.Instructions[3])
	}
	if ret.Value.Version != 1 {
		t.Errorf("return: expected v_1, got v_%d", ret.Value.Version)
	}
}

// TestRoundTrip_CallInstruction tests ssa transformation with call instructions
// verifies that renameUsesInInstruction handles Call (args, dest) correctly
func TestRoundTrip_CallInstruction(t *testing.T) {
	// bb0:
	//   a = 1
	//   b = 2
	//   result = call foo(a, b)
	//   return result

	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0})

	fn := &ir.Function{
		Name:       "call_test",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	aVar := ir.Variable{Name: "a", Type: ir.IntType{Width: ir.Size4, Signed: true}}
	bVar := ir.Variable{Name: "b", Type: ir.IntType{Width: ir.Size4, Signed: true}}
	resultVar := ir.Variable{Name: "result", Type: ir.IntType{Width: ir.Size4, Signed: true}}

	fn.Blocks[0] = &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   aVar,
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size4, Signed: true}},
			},
			&ir.Assign{
				Dest:   bVar,
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 2, Width: ir.Size4, Signed: true}},
			},
			&ir.Call{
				Dest:   &resultVar,
				Target: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x4000, Width: ir.Size8, Signed: false}},
				Args:   []ir.Variable{aVar, bVar},
			},
			&ir.Return{Value: &resultVar},
		},
	}

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	verifySSAProperty(t, fn)

	block := fn.Blocks[0]

	// a_1 = 1
	assignA, ok := block.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("instr 0: expected *ir.Assign")
	}
	if assignA.Dest.Version != 1 {
		t.Errorf("a definition: expected a_1, got a_%d", assignA.Dest.Version)
	}

	// b_1 = 2
	assignB, ok := block.Instructions[1].(*ir.Assign)
	if !ok {
		t.Fatalf("instr 1: expected *ir.Assign")
	}
	if assignB.Dest.Version != 1 {
		t.Errorf("b definition: expected b_1, got b_%d", assignB.Dest.Version)
	}

	// result_1 = call foo(a_1, b_1)
	call, ok := block.Instructions[2].(*ir.Call)
	if !ok {
		t.Fatalf("instr 2: expected *ir.Call, got %T", block.Instructions[2])
	}
	if call.Dest == nil {
		t.Fatal("call dest is nil")
	}
	if call.Dest.Version != 1 {
		t.Errorf("call dest: expected result_1, got result_%d", call.Dest.Version)
	}
	if len(call.Args) != 2 {
		t.Fatalf("call args: expected 2, got %d", len(call.Args))
	}
	if call.Args[0].Version != 1 {
		t.Errorf("call arg[0]: expected a_1, got a_%d", call.Args[0].Version)
	}
	if call.Args[1].Version != 1 {
		t.Errorf("call arg[1]: expected b_1, got b_%d", call.Args[1].Version)
	}

	// return result_1
	ret, ok := block.Instructions[3].(*ir.Return)
	if !ok {
		t.Fatalf("instr 3: expected *ir.Return")
	}
	if ret.Value.Version != 1 {
		t.Errorf("return: expected result_1, got result_%d", ret.Value.Version)
	}
}

// TestRoundTrip_UnaryAndCastExpressions tests ssa renaming through unary ops and casts
// verifies renameUsesInExpression handles UnaryOp and Cast correctly
func TestRoundTrip_UnaryAndCastExpressions(t *testing.T) {
	// bb0:
	//   x = 42
	//   y = -x
	//   z = (i64)y
	//   return z

	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0})

	fn := &ir.Function{
		Name:       "unary_cast",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	xVar := ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}}
	yVar := ir.Variable{Name: "y", Type: ir.IntType{Width: ir.Size4, Signed: true}}
	zVar := ir.Variable{Name: "z", Type: ir.IntType{Width: ir.Size8, Signed: true}}

	fn.Blocks[0] = &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			// x = 42
			&ir.Assign{
				Dest:   xVar,
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size4, Signed: true}},
			},
			// y = -x
			&ir.Assign{
				Dest: yVar,
				Source: &ir.UnaryOp{
					Op:      ir.UnOpNeg,
					Operand: &ir.VariableExpr{Var: xVar},
				},
			},
			// z = (i64)y
			&ir.Assign{
				Dest: zVar,
				Source: &ir.Cast{
					Expr:       &ir.VariableExpr{Var: yVar},
					TargetType: ir.IntType{Width: ir.Size8, Signed: true},
				},
			},
			&ir.Return{Value: &zVar},
		},
	}

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	verifySSAProperty(t, fn)

	block := fn.Blocks[0]

	// y = -x_1 → unary operand must be x_1
	assignY, ok := block.Instructions[1].(*ir.Assign)
	if !ok {
		t.Fatalf("instr 1: expected *ir.Assign")
	}
	unary, ok := assignY.Source.(*ir.UnaryOp)
	if !ok {
		t.Fatalf("y source: expected *ir.UnaryOp, got %T", assignY.Source)
	}
	unaryVar, ok := unary.Operand.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("unary operand: expected *ir.VariableExpr, got %T", unary.Operand)
	}
	if unaryVar.Var.Version != 1 {
		t.Errorf("unary operand: expected x_1, got x_%d", unaryVar.Var.Version)
	}

	// z = (i64)y_1 → cast expr must be y_1
	assignZ, ok := block.Instructions[2].(*ir.Assign)
	if !ok {
		t.Fatalf("instr 2: expected *ir.Assign")
	}
	cast, ok := assignZ.Source.(*ir.Cast)
	if !ok {
		t.Fatalf("z source: expected *ir.Cast, got %T", assignZ.Source)
	}
	castVar, ok := cast.Expr.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("cast expr: expected *ir.VariableExpr, got %T", cast.Expr)
	}
	if castVar.Var.Version != 1 {
		t.Errorf("cast expr: expected y_1, got y_%d", castVar.Var.Version)
	}
}
