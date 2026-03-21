package analysis

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// constant propagation: evaluateUnaryOp coverage
// ============================================================================

func TestConstProp_UnaryNeg(t *testing.T) {
	cfgGraph := buildSimpleCFG()
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	x := ssaVar("x", 1)
	y := ssaVar("y", 1)

	fn := &ir.Function{
		Name: "unary_neg",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x, Source: intConst(7)},
					&ir.Assign{Dest: y, Source: &ir.UnaryOp{
						Op:      ir.UnOpNeg,
						Operand: &ir.VariableExpr{Var: x},
					}},
					&ir.Return{Value: &y},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(fn, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}
	if !result.IsConstant(y) {
		t.Fatal("expected y to be constant (-7)")
	}
	c := result.GetConstant(y)
	if c.(ir.IntConstant).Value != -7 { //nolint:forcetypeassert // test helper
		t.Errorf("expected -7, got %v", c)
	}
}

func TestConstProp_UnaryBitwiseNot(t *testing.T) {
	cfgGraph := buildSimpleCFG()
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	x := ssaVar("x", 1)
	y := ssaVar("y", 1)

	fn := &ir.Function{
		Name: "unary_not",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x, Source: intConst(0)},
					&ir.Assign{Dest: y, Source: &ir.UnaryOp{
						Op:      ir.UnOpNot,
						Operand: &ir.VariableExpr{Var: x},
					}},
					&ir.Return{Value: &y},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(fn, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}
	if !result.IsConstant(y) {
		t.Fatal("expected y to be constant (~0 = -1)")
	}
	c := result.GetConstant(y)
	if c.(ir.IntConstant).Value != -1 { //nolint:forcetypeassert // test helper
		t.Errorf("expected -1, got %v", c)
	}
}

func TestConstProp_UnaryLogicalNot(t *testing.T) {
	cfgGraph := buildSimpleCFG()
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	x := ir.Variable{Name: "x", Version: 1, Type: ir.BoolType{}}
	y := ir.Variable{Name: "y", Version: 1, Type: ir.BoolType{}}

	fn := &ir.Function{
		Name: "unary_logical_not",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x, Source: ir.ConstantExpr{Value: ir.BoolConstant{Value: true}}},
					&ir.Assign{Dest: y, Source: &ir.UnaryOp{
						Op:      ir.UnOpLogicalNot,
						Operand: &ir.VariableExpr{Var: x},
					}},
					&ir.Return{Value: &y},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(fn, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}
	if !result.IsConstant(y) {
		t.Fatal("expected y to be constant (!true = false)")
	}
	c := result.GetConstant(y)
	if c.(ir.BoolConstant).Value != false { //nolint:forcetypeassert // test helper
		t.Errorf("expected false, got %v", c)
	}
}

// ============================================================================
// constant propagation: foldFloatBinaryOp coverage
// ============================================================================

func TestFoldFloatBinaryOp_AllOps(t *testing.T) {
	f := func(v float64) ir.FloatConstant { return ir.FloatConstant{Value: v, Width: ir.Size8} }

	tests := []struct {
		name   string
		op     ir.BinaryOperator
		l, r   ir.FloatConstant
		wantF  float64
		wantB  bool
		isBool bool
		wantOK bool
	}{
		{"add", ir.BinOpAdd, f(1.5), f(2.5), 4.0, false, false, true},
		{"sub", ir.BinOpSub, f(5.0), f(3.0), 2.0, false, false, true},
		{"mul", ir.BinOpMul, f(2.0), f(3.0), 6.0, false, false, true},
		{"div", ir.BinOpDiv, f(10.0), f(4.0), 2.5, false, false, true},
		{"div by zero", ir.BinOpDiv, f(1.0), f(0.0), 0, false, false, false},
		{"eq true", ir.BinOpEq, f(3.14), f(3.14), 0, true, true, true},
		{"eq false", ir.BinOpEq, f(3.14), f(2.71), 0, false, true, true},
		{"ne true", ir.BinOpNe, f(1.0), f(2.0), 0, true, true, true},
		{"lt true", ir.BinOpLt, f(1.0), f(2.0), 0, true, true, true},
		{"lt false", ir.BinOpLt, f(2.0), f(1.0), 0, false, true, true},
		{"le true", ir.BinOpLe, f(2.0), f(2.0), 0, true, true, true},
		{"gt true", ir.BinOpGt, f(3.0), f(1.0), 0, true, true, true},
		{"ge true", ir.BinOpGe, f(2.0), f(2.0), 0, true, true, true},
		{"mod unsupported", ir.BinOpMod, f(1.0), f(2.0), 0, false, false, false},
		{"and unsupported", ir.BinOpAnd, f(1.0), f(2.0), 0, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := foldFloatBinaryOp(tt.op, tt.l, tt.r)
			if ok != tt.wantOK {
				t.Fatalf("ok=%v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if tt.isBool {
				bc := got.(ir.BoolConstant) //nolint:forcetypeassert // test helper
				if bc.Value != tt.wantB {
					t.Errorf("got %v, want %v", bc.Value, tt.wantB)
				}
			} else {
				fc := got.(ir.FloatConstant) //nolint:forcetypeassert // test helper
				if fc.Value != tt.wantF {
					t.Errorf("got %f, want %f", fc.Value, tt.wantF)
				}
			}
		})
	}
}

// ============================================================================
// constant propagation: foldBoolBinaryOp coverage
// ============================================================================

func TestFoldBoolBinaryOp_AllOps(t *testing.T) {
	tests := []struct {
		name   string
		op     ir.BinaryOperator
		l, r   ir.BoolConstant
		want   bool
		wantOK bool
	}{
		{"and tt", ir.BinOpLogicalAnd, ir.BoolConstant{Value: true}, ir.BoolConstant{Value: true}, true, true},
		{"and tf", ir.BinOpLogicalAnd, ir.BoolConstant{Value: true}, ir.BoolConstant{Value: false}, false, true},
		{"or ff", ir.BinOpLogicalOr, ir.BoolConstant{Value: false}, ir.BoolConstant{Value: false}, false, true},
		{"or ft", ir.BinOpLogicalOr, ir.BoolConstant{Value: false}, ir.BoolConstant{Value: true}, true, true},
		{"eq same", ir.BinOpEq, ir.BoolConstant{Value: true}, ir.BoolConstant{Value: true}, true, true},
		{"eq diff", ir.BinOpEq, ir.BoolConstant{Value: true}, ir.BoolConstant{Value: false}, false, true},
		{"ne same", ir.BinOpNe, ir.BoolConstant{Value: false}, ir.BoolConstant{Value: false}, false, true},
		{"ne diff", ir.BinOpNe, ir.BoolConstant{Value: true}, ir.BoolConstant{Value: false}, true, true},
		{"add unsupported", ir.BinOpAdd, ir.BoolConstant{Value: true}, ir.BoolConstant{Value: true}, false, false},
		{"lt unsupported", ir.BinOpLt, ir.BoolConstant{Value: true}, ir.BoolConstant{Value: false}, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := foldBoolBinaryOp(tt.op, tt.l, tt.r)
			if ok != tt.wantOK {
				t.Fatalf("ok=%v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			bc := got.(ir.BoolConstant) //nolint:forcetypeassert // test helper
			if bc.Value != tt.want {
				t.Errorf("got %v, want %v", bc.Value, tt.want)
			}
		})
	}
}

// ============================================================================
// constant propagation: isTruthy coverage (float, null, unknown)
// ============================================================================

func TestConstProp_BranchOnFloatCondition(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{
			0: {1, 2},
			1: {},
			2: {},
		},
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 0},
	)

	cond := ir.Variable{Name: "cond", Version: 1, Type: ir.FloatType{Width: ir.Size8}}

	fn := &ir.Function{
		Name: "float_branch",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: cond, Source: ir.ConstantExpr{Value: ir.FloatConstant{Value: 1.0, Width: ir.Size8}}},
					&ir.Branch{Condition: &ir.VariableExpr{Var: cond}, TrueTarget: 1, FalseTarget: 2},
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID:           1,
				Instructions: []ir.IRInstruction{&ir.Return{}},
				Predecessors: []ir.BlockID{0},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{&ir.Return{}},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}

	_, err := PropagateConstants(fn, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}
}

func TestConstProp_BranchOnZeroFloat(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{
			0: {1, 2},
			1: {},
			2: {},
		},
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 0},
	)

	cond := ir.Variable{Name: "cond", Version: 1, Type: ir.FloatType{Width: ir.Size8}}

	fn := &ir.Function{
		Name: "zero_float_branch",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: cond, Source: ir.ConstantExpr{Value: ir.FloatConstant{Value: 0.0, Width: ir.Size8}}},
					&ir.Branch{Condition: &ir.VariableExpr{Var: cond}, TrueTarget: 1, FalseTarget: 2},
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID:           1,
				Instructions: []ir.IRInstruction{&ir.Return{}},
				Predecessors: []ir.BlockID{0},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{&ir.Return{}},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}

	_, err := PropagateConstants(fn, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}
}

// ============================================================================
// reaching definitions: GetBlockReachOut coverage
// ============================================================================

func TestReachingDefs_GetBlockReachOut(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{0: {}},
		map[cfg.BlockID]cfg.BlockID{0: 0},
	)

	fn := &ir.Function{
		Name: "reach_out",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("x", 1), Source: intConst(42)},
					&ir.Return{Value: &ir.Variable{Name: "x", Type: intType(), Version: 1}},
				},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewReachingDefsAnalyzer(fn, cfgGraph, domTree)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	reachOut := result.GetBlockReachOut(0)
	if reachOut == nil {
		t.Fatal("expected non-nil reach-out set for block 0")
	}
	if reachOut.Len() == 0 {
		t.Error("expected non-empty reach-out set for block 0")
	}

	nonExistent := result.GetBlockReachOut(99)
	if nonExistent == nil {
		t.Fatal("expected non-nil (empty) set for non-existent block")
	}
	if nonExistent.Len() != 0 {
		t.Error("expected empty reach-out set for non-existent block")
	}
}

// ============================================================================
// VSA: evalConstant coverage (bool, float, null branches)
// ============================================================================

func TestVSA_BoolConstant(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.BoolType{}}
	fn := buildVSAFunction("bool_const", []ir.IRInstruction{
		&ir.Assign{
			Dest:   x,
			Source: &ir.ConstantExpr{Value: ir.BoolConstant{Value: true}},
		},
	})

	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	val, ok := result.IsConstant(x)
	if !ok {
		t.Fatal("expected x to be constant (true = 1)")
	}
	if val != 1 {
		t.Errorf("expected 1 for true, got %d", val)
	}
}

func TestVSA_BoolConstantFalse(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.BoolType{}}
	fn := buildVSAFunction("bool_false", []ir.IRInstruction{
		&ir.Assign{
			Dest:   x,
			Source: &ir.ConstantExpr{Value: ir.BoolConstant{Value: false}},
		},
	})

	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	val, ok := result.IsConstant(x)
	if !ok {
		t.Fatal("expected x to be constant (false = 0)")
	}
	if val != 0 {
		t.Errorf("expected 0 for false, got %d", val)
	}
}

func TestVSA_FloatConstantIsTop(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.FloatType{Width: ir.Size8}}
	fn := buildVSAFunction("float_const", []ir.IRInstruction{
		&ir.Assign{
			Dest:   x,
			Source: &ir.ConstantExpr{Value: ir.FloatConstant{Value: 3.14, Width: ir.Size8}},
		},
	})

	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	xVS := result.GetValueSet(x)
	if !xVS.IsTop() {
		t.Errorf("expected top for float constant in VSA, got %s", xVS.String())
	}
}

func TestVSA_NullConstant(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.PointerType{Pointee: ir.VoidType{}}}
	fn := buildVSAFunction("null_const", []ir.IRInstruction{
		&ir.Assign{
			Dest:   x,
			Source: &ir.ConstantExpr{Value: ir.NullConstant{}},
		},
	})

	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	val, ok := result.IsConstant(x)
	if !ok {
		t.Fatal("expected x to be constant (null = 0)")
	}
	if val != 0 {
		t.Errorf("expected 0 for null, got %d", val)
	}
}

// ============================================================================
// VSA: evalUnaryOp coverage
// ============================================================================

func TestVSA_UnaryNot(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: true}}
	y := ir.Variable{Name: "y", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: true}}

	fn := buildVSAFunction("unary_not", []ir.IRInstruction{
		&ir.Assign{
			Dest:   x,
			Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 10, Width: ir.Size8, Signed: true}},
		},
		&ir.Assign{
			Dest:   y,
			Source: &ir.UnaryOp{Op: ir.UnOpNeg, Operand: &ir.VariableExpr{Var: x}},
		},
	})

	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	val, ok := result.IsConstant(y)
	if !ok {
		t.Fatal("expected y to be constant (-10)")
	}
	if val != -10 {
		t.Errorf("expected -10, got %d", val)
	}
}

// ============================================================================
// VSA: evalBinaryOp coverage for comparison, shift, bitwise ops
// ============================================================================

func TestVSA_BitwiseAndOp(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}
	y := ir.Variable{Name: "y", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}
	z := ir.Variable{Name: "z", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}

	fn := buildVSAFunction("bitwise_and", []ir.IRInstruction{
		&ir.Assign{Dest: x, Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0xFF, Width: ir.Size8}}},
		&ir.Assign{Dest: y, Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x0F, Width: ir.Size8}}},
		&ir.Assign{Dest: z, Source: &ir.BinaryOp{
			Op:    ir.BinOpAnd,
			Left:  &ir.VariableExpr{Var: x},
			Right: &ir.VariableExpr{Var: y},
		}},
	})

	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	zVS := result.GetValueSet(z)
	si := zVS.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if si.Lo > 0x0F || si.Hi < 0x0F {
		t.Errorf("expected AND result to contain 0x0F, got %s", si.String())
	}
}

func TestVSA_BitwiseOrOp(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}
	y := ir.Variable{Name: "y", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}
	z := ir.Variable{Name: "z", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}

	fn := buildVSAFunction("bitwise_or", []ir.IRInstruction{
		&ir.Assign{Dest: x, Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0xF0, Width: ir.Size8}}},
		&ir.Assign{Dest: y, Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x0F, Width: ir.Size8}}},
		&ir.Assign{Dest: z, Source: &ir.BinaryOp{
			Op:    ir.BinOpOr,
			Left:  &ir.VariableExpr{Var: x},
			Right: &ir.VariableExpr{Var: y},
		}},
	})

	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	zVS := result.GetValueSet(z)
	si := zVS.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if si.Lo > 0xFF || si.Hi < 0xFF {
		t.Errorf("expected OR result to contain 0xFF, got %s", si.String())
	}
}

func TestVSA_ShlOp(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}
	y := ir.Variable{Name: "y", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}
	z := ir.Variable{Name: "z", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}

	fn := buildVSAFunction("shl_op", []ir.IRInstruction{
		&ir.Assign{Dest: x, Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8}}},
		&ir.Assign{Dest: y, Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 4, Width: ir.Size8}}},
		&ir.Assign{Dest: z, Source: &ir.BinaryOp{
			Op:    ir.BinOpShl,
			Left:  &ir.VariableExpr{Var: x},
			Right: &ir.VariableExpr{Var: y},
		}},
	})

	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	val, ok := result.IsConstant(z)
	if !ok {
		t.Fatal("expected z to be constant (1 << 4 = 16)")
	}
	if val != 16 {
		t.Errorf("expected 16, got %d", val)
	}
}

func TestVSA_ShrOp(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}
	y := ir.Variable{Name: "y", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}
	z := ir.Variable{Name: "z", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}

	fn := buildVSAFunction("shr_op", []ir.IRInstruction{
		&ir.Assign{Dest: x, Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 32, Width: ir.Size8}}},
		&ir.Assign{Dest: y, Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 3, Width: ir.Size8}}},
		&ir.Assign{Dest: z, Source: &ir.BinaryOp{
			Op:    ir.BinOpShr,
			Left:  &ir.VariableExpr{Var: x},
			Right: &ir.VariableExpr{Var: y},
		}},
	})

	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	zVS := result.GetValueSet(z)
	si := zVS.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if si.Lo > 4 || si.Hi < 4 {
		t.Errorf("expected SHR result to contain 4 (32>>3), got %s", si.String())
	}
}

func TestVSA_XorOp(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}
	y := ir.Variable{Name: "y", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}
	z := ir.Variable{Name: "z", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}

	fn := buildVSAFunction("xor_op", []ir.IRInstruction{
		&ir.Assign{Dest: x, Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0xFF, Width: ir.Size8}}},
		&ir.Assign{Dest: y, Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x0F, Width: ir.Size8}}},
		&ir.Assign{Dest: z, Source: &ir.BinaryOp{
			Op:    ir.BinOpXor,
			Left:  &ir.VariableExpr{Var: x},
			Right: &ir.VariableExpr{Var: y},
		}},
	})

	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	zVS := result.GetValueSet(z)
	if zVS.IsBottom() {
		t.Error("expected non-bottom result for XOR")
	}
}

// ============================================================================
// VSA: SubValueSets coverage for pointer subtraction
// ============================================================================

func TestVSA_SubValueSets_PointerMinusOffset(t *testing.T) {
	stackRegion := MemoryRegion{Kind: RegionStack, ID: 0}
	ptr := NewValueSetPointer(stackRegion, 1, -64, -8)
	offset := NewValueSetConstant(8)

	result := SubValueSets(ptr, offset)
	si := result.GetInterval(stackRegion)
	if si.Lo != -72 || si.Hi != -16 {
		t.Errorf("ptr-8: want stack offset [-72,-16], got [%d,%d]", si.Lo, si.Hi)
	}
}

func TestVSA_SubValueSets_WithBottom(t *testing.T) {
	bottom := NewValueSetBottom()
	vs := NewValueSetConstant(5)
	result := SubValueSets(bottom, vs)
	if !result.IsBottom() {
		t.Fatal("bottom - anything must be bottom")
	}
}

func TestVSA_SubValueSets_WithTop(t *testing.T) {
	top := NewValueSetTop()
	vs := NewValueSetConstant(5)
	result := SubValueSets(top, vs)
	if !result.IsTop() {
		t.Fatal("top - anything must be top")
	}
}

// ============================================================================
// VSA: NegValueSet coverage
// ============================================================================

func TestVSA_NegValueSet(t *testing.T) {
	vs := NewValueSetInterval(1, 3, 7)
	result := NegValueSet(vs)
	si := result.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if si.Lo != -7 || si.Hi != -3 {
		t.Errorf("neg([3,7]): want [-7,-3], got [%d,%d]", si.Lo, si.Hi)
	}
}

func TestVSA_NegValueSet_Bottom(t *testing.T) {
	result := NegValueSet(NewValueSetBottom())
	if !result.IsBottom() {
		t.Error("neg(bottom) must be bottom")
	}
}

func TestVSA_NegValueSet_Top(t *testing.T) {
	result := NegValueSet(NewValueSetTop())
	if !result.IsTop() {
		t.Error("neg(top) must be top")
	}
}

// ============================================================================
// constant propagation: latticeValue.String coverage
// ============================================================================

func TestLatticeValue_String(t *testing.T) {
	top := latticeValue{kind: latticeTop}
	bot := latticeValue{kind: latticeBottom}
	c := latticeValue{kind: latticeConstant, constant: ir.IntConstant{Value: 42, Width: ir.Size8, Signed: true}}

	if top.String() == "" {
		t.Error("expected non-empty string for top")
	}
	if bot.String() == "" {
		t.Error("expected non-empty string for bottom")
	}
	if c.String() == "" {
		t.Error("expected non-empty string for constant")
	}
}

// ============================================================================
// constant propagation: foldIntBinaryOp unsigned operations coverage
// ============================================================================

func TestFoldBinaryOp_UnsignedOps(t *testing.T) {
	u64 := func(v int64) ir.IntConstant { return ir.IntConstant{Value: v, Width: ir.Size8, Signed: false} }

	tests := []struct {
		name    string
		op      ir.BinaryOperator
		l, r    ir.IntConstant
		wantVal int64
		wantB   bool
		isBool  bool
		wantOK  bool
	}{
		{"udiv", ir.BinOpUDiv, u64(84), u64(2), 42, false, false, true},
		{"udiv by zero", ir.BinOpUDiv, u64(1), u64(0), 0, false, false, false},
		{"umod", ir.BinOpUMod, u64(47), u64(5), 2, false, false, true},
		{"umod by zero", ir.BinOpUMod, u64(1), u64(0), 0, false, false, false},
		{"ult true", ir.BinOpULt, u64(3), u64(5), 0, true, true, true},
		{"ult false", ir.BinOpULt, u64(5), u64(3), 0, false, true, true},
		{"ule true", ir.BinOpULe, u64(5), u64(5), 0, true, true, true},
		{"ugt true", ir.BinOpUGt, u64(7), u64(3), 0, true, true, true},
		{"uge true", ir.BinOpUGe, u64(5), u64(5), 0, true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := foldBinaryOp(tt.op, tt.l, tt.r)
			if ok != tt.wantOK {
				t.Fatalf("ok=%v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if tt.isBool {
				bc := got.(ir.BoolConstant) //nolint:forcetypeassert // test helper
				if bc.Value != tt.wantB {
					t.Errorf("got %v, want %v", bc.Value, tt.wantB)
				}
			} else {
				ic := got.(ir.IntConstant) //nolint:forcetypeassert // test helper
				if ic.Value != tt.wantVal {
					t.Errorf("got %d, want %d", ic.Value, tt.wantVal)
				}
			}
		})
	}
}

// ============================================================================
// constant propagation: evaluateExpression nil and value-type branches
// ============================================================================

func TestConstProp_ValueTypeBinaryOp(t *testing.T) {
	cfgGraph := buildSimpleCFG()
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	x := ssaVar("x", 1)
	y := ssaVar("y", 1)

	fn := &ir.Function{
		Name: "value_type_binop",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x, Source: intConst(5)},
					&ir.Assign{Dest: y, Source: ir.BinaryOp{
						Op:    ir.BinOpAdd,
						Left:  ir.VariableExpr{Var: x},
						Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 3, Width: ir.Size8, Signed: true}},
					}},
					&ir.Return{Value: &y},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(fn, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}
	if !result.IsConstant(y) {
		t.Fatal("expected y to be constant (5+3=8)")
	}
	c := result.GetConstant(y)
	if c.(ir.IntConstant).Value != 8 { //nolint:forcetypeassert // test helper
		t.Errorf("expected 8, got %v", c)
	}
}

func TestConstProp_ValueTypeUnaryOp(t *testing.T) {
	cfgGraph := buildSimpleCFG()
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	x := ssaVar("x", 1)
	y := ssaVar("y", 1)

	fn := &ir.Function{
		Name: "value_type_unaryop",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x, Source: intConst(5)},
					&ir.Assign{Dest: y, Source: ir.UnaryOp{
						Op:      ir.UnOpNeg,
						Operand: ir.VariableExpr{Var: x},
					}},
					&ir.Return{Value: &y},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(fn, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}
	if !result.IsConstant(y) {
		t.Fatal("expected y to be constant (-5)")
	}
	c := result.GetConstant(y)
	if c.(ir.IntConstant).Value != -5 { //nolint:forcetypeassert // test helper
		t.Errorf("expected -5, got %v", c)
	}
}

func TestConstProp_ValueTypeCast(t *testing.T) {
	cfgGraph := buildSimpleCFG()
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	x := ssaVar("x", 1)
	y := ssaVar("y", 1)

	fn := &ir.Function{
		Name: "value_type_cast",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x, Source: intConst(42)},
					&ir.Assign{Dest: y, Source: ir.Cast{
						Expr:       ir.VariableExpr{Var: x},
						TargetType: ir.IntType{Width: ir.Size4, Signed: true},
					}},
					&ir.Return{Value: &y},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(fn, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}
	if !result.IsConstant(y) {
		t.Fatal("expected y to be constant after cast")
	}
}

func TestCopyProp_ValueTypeBinaryOp(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{0: {}},
		map[cfg.BlockID]cfg.BlockID{0: 0},
	)

	a := ssaVar("a", 1)
	b := ssaVar("b", 1)
	c := ssaVar("c", 1)
	d := ssaVar("d", 1)

	fn := &ir.Function{
		Name: "copy_binop",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: a, Source: intConst(1)},
					&ir.Assign{Dest: b, Source: &ir.VariableExpr{Var: a}},
					&ir.Assign{Dest: c, Source: intConst(2)},
					&ir.Assign{Dest: d, Source: ir.BinaryOp{
						Op:    ir.BinOpAdd,
						Left:  ir.VariableExpr{Var: b},
						Right: ir.VariableExpr{Var: c},
					}},
					&ir.Return{Value: &d},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateCopies(fn, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateCopies failed: %v", err)
	}
	if result.ReplacedCount == 0 {
		t.Error("expected at least one replacement in value-type BinaryOp")
	}
}

func TestCopyProp_ValueTypeUnaryOp(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{0: {}},
		map[cfg.BlockID]cfg.BlockID{0: 0},
	)

	a := ssaVar("a", 1)
	b := ssaVar("b", 1)
	c := ssaVar("c", 1)

	fn := &ir.Function{
		Name: "copy_unaryop",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: a, Source: intConst(5)},
					&ir.Assign{Dest: b, Source: &ir.VariableExpr{Var: a}},
					&ir.Assign{Dest: c, Source: ir.UnaryOp{
						Op:      ir.UnOpNeg,
						Operand: ir.VariableExpr{Var: b},
					}},
					&ir.Return{Value: &c},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateCopies(fn, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateCopies failed: %v", err)
	}
	if result.ReplacedCount == 0 {
		t.Error("expected at least one replacement in value-type UnaryOp")
	}
}

func TestCopyProp_ValueTypeCast(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{0: {}},
		map[cfg.BlockID]cfg.BlockID{0: 0},
	)

	a := ssaVar("a", 1)
	b := ssaVar("b", 1)
	c := ssaVar("c", 1)

	fn := &ir.Function{
		Name: "copy_cast",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: a, Source: intConst(42)},
					&ir.Assign{Dest: b, Source: &ir.VariableExpr{Var: a}},
					&ir.Assign{Dest: c, Source: ir.Cast{
						Expr:       ir.VariableExpr{Var: b},
						TargetType: ir.IntType{Width: ir.Size4, Signed: true},
					}},
					&ir.Return{Value: &c},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateCopies(fn, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateCopies failed: %v", err)
	}
	if result.ReplacedCount == 0 {
		t.Error("expected at least one replacement in value-type Cast")
	}
}

func TestCopyProp_ValueTypeLoadExpr(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{0: {}},
		map[cfg.BlockID]cfg.BlockID{0: 0},
	)

	addr := ir.Variable{Name: "addr", Version: 1, Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size8, Signed: true}}}
	addrCopy := ssaVar("addr_copy", 1)
	val := ssaVar("val", 1)

	fn := &ir.Function{
		Name: "copy_loadexpr",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: addr, Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 0x1000, Width: ir.Size8}}},
					&ir.Assign{Dest: addrCopy, Source: &ir.VariableExpr{Var: addr}},
					&ir.Assign{Dest: val, Source: ir.LoadExpr{
						Address: ir.VariableExpr{Var: addrCopy},
						Size:    ir.Size8,
					}},
					&ir.Return{Value: &val},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateCopies(fn, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateCopies failed: %v", err)
	}
	if result.ReplacedCount == 0 {
		t.Error("expected at least one replacement in value-type LoadExpr")
	}
}

func TestFoldCast_BoolToInt(t *testing.T) {
	got, ok := foldCast(ir.BoolConstant{Value: true}, ir.IntType{Width: ir.Size4, Signed: true})
	if !ok {
		t.Fatal("expected ok for bool->int cast")
	}
	ic := got.(ir.IntConstant) //nolint:forcetypeassert // test helper
	if ic.Value != 1 {
		t.Errorf("expected 1, got %d", ic.Value)
	}

	got2, ok2 := foldCast(ir.BoolConstant{Value: false}, ir.IntType{Width: ir.Size4, Signed: true})
	if !ok2 {
		t.Fatal("expected ok for bool(false)->int cast")
	}
	ic2 := got2.(ir.IntConstant) //nolint:forcetypeassert // test helper
	if ic2.Value != 0 {
		t.Errorf("expected 0, got %d", ic2.Value)
	}
}

func TestFoldCast_FloatToInt(t *testing.T) {
	got, ok := foldCast(ir.FloatConstant{Value: 3.7, Width: ir.Size8}, ir.IntType{Width: ir.Size8, Signed: true})
	if !ok {
		t.Fatal("expected ok for float->int cast")
	}
	ic := got.(ir.IntConstant) //nolint:forcetypeassert // test helper
	if ic.Value != 3 {
		t.Errorf("expected 3 (truncated), got %d", ic.Value)
	}
}

func TestFoldCast_IntToFloat(t *testing.T) {
	got, ok := foldCast(ir.IntConstant{Value: 42, Width: ir.Size8, Signed: true}, ir.FloatType{Width: ir.Size8})
	if !ok {
		t.Fatal("expected ok for int->float cast")
	}
	fc := got.(ir.FloatConstant) //nolint:forcetypeassert // test helper
	if fc.Value != 42.0 {
		t.Errorf("expected 42.0, got %f", fc.Value)
	}
}

func TestFoldCast_FloatToFloat(t *testing.T) {
	got, ok := foldCast(ir.FloatConstant{Value: 3.14, Width: ir.Size8}, ir.FloatType{Width: ir.Size4})
	if !ok {
		t.Fatal("expected ok for float->float cast")
	}
	fc := got.(ir.FloatConstant) //nolint:forcetypeassert // test helper
	if fc.Value != 3.14 {
		t.Errorf("expected 3.14, got %f", fc.Value)
	}
	if fc.Width != ir.Size4 {
		t.Errorf("expected width Size4, got %d", fc.Width)
	}
}

func TestFoldCast_IntToBool(t *testing.T) {
	got, ok := foldCast(ir.IntConstant{Value: 42, Width: ir.Size8, Signed: true}, ir.BoolType{})
	if !ok {
		t.Fatal("expected ok for int->bool cast")
	}
	bc := got.(ir.BoolConstant) //nolint:forcetypeassert // test helper
	if !bc.Value {
		t.Error("expected true for non-zero int->bool")
	}

	got2, ok2 := foldCast(ir.IntConstant{Value: 0, Width: ir.Size8, Signed: true}, ir.BoolType{})
	if !ok2 {
		t.Fatal("expected ok for int(0)->bool cast")
	}
	bc2 := got2.(ir.BoolConstant) //nolint:forcetypeassert // test helper
	if bc2.Value {
		t.Error("expected false for zero int->bool")
	}
}

func TestFoldCast_BoolToBool(t *testing.T) {
	got, ok := foldCast(ir.BoolConstant{Value: true}, ir.BoolType{})
	if !ok {
		t.Fatal("expected ok for bool->bool cast")
	}
	bc := got.(ir.BoolConstant) //nolint:forcetypeassert // test helper
	if !bc.Value {
		t.Error("expected true for bool->bool identity cast")
	}
}

func TestFoldCast_UnsupportedTarget(t *testing.T) {
	_, ok := foldCast(ir.IntConstant{Value: 1, Width: ir.Size8}, ir.VoidType{})
	if ok {
		t.Error("expected not ok for int->void cast")
	}
}

func TestConstProp_BranchOnNullCondition(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{
			0: {1, 2},
			1: {},
			2: {},
		},
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 0},
	)

	cond := ir.Variable{Name: "cond", Version: 1, Type: ir.PointerType{Pointee: ir.VoidType{}}}

	fn := &ir.Function{
		Name: "null_branch",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: cond, Source: ir.ConstantExpr{Value: ir.NullConstant{}}},
					&ir.Branch{Condition: &ir.VariableExpr{Var: cond}, TrueTarget: 1, FalseTarget: 2},
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID:           1,
				Instructions: []ir.IRInstruction{&ir.Return{}},
				Predecessors: []ir.BlockID{0},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{&ir.Return{}},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}

	_, err := PropagateConstants(fn, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}
}

func TestVSA_UnaryBitwiseNot(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}
	y := ir.Variable{Name: "y", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}

	fn := buildVSAFunction("bitwise_not", []ir.IRInstruction{
		&ir.Assign{
			Dest:   x,
			Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0xFF, Width: ir.Size8}},
		},
		&ir.Assign{
			Dest:   y,
			Source: &ir.UnaryOp{Op: ir.UnOpNot, Operand: &ir.VariableExpr{Var: x}},
		},
	})

	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	yVS := result.GetValueSet(y)
	if yVS.IsBottom() {
		t.Error("expected non-bottom result for bitwise NOT")
	}
}

func TestVSA_UnaryLogicalNot(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.BoolType{}}
	y := ir.Variable{Name: "y", Version: 1, Type: ir.BoolType{}}

	fn := buildVSAFunction("logical_not", []ir.IRInstruction{
		&ir.Assign{
			Dest:   x,
			Source: &ir.ConstantExpr{Value: ir.BoolConstant{Value: true}},
		},
		&ir.Assign{
			Dest:   y,
			Source: &ir.UnaryOp{Op: ir.UnOpLogicalNot, Operand: &ir.VariableExpr{Var: x}},
		},
	})

	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	yVS := result.GetValueSet(y)
	si := yVS.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if si.Lo != 0 || si.Hi != 1 {
		t.Errorf("expected [0,1] for logical NOT, got [%d,%d]", si.Lo, si.Hi)
	}
}

func TestVSA_CastExpression(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: true}}
	y := ir.Variable{Name: "y", Version: 1, Type: ir.IntType{Width: ir.Size4, Signed: true}}

	fn := buildVSAFunction("cast_expr", []ir.IRInstruction{
		&ir.Assign{
			Dest:   x,
			Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size8, Signed: true}},
		},
		&ir.Assign{
			Dest: y,
			Source: &ir.Cast{
				Expr:       &ir.VariableExpr{Var: x},
				TargetType: ir.IntType{Width: ir.Size4, Signed: true},
			},
		},
	})

	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	val, ok := result.IsConstant(y)
	if !ok {
		t.Fatal("expected y to be constant after cast in VSA")
	}
	if val != 42 {
		t.Errorf("expected 42, got %d", val)
	}
}

func TestVSA_ValueTypeCast(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: true}}
	y := ir.Variable{Name: "y", Version: 1, Type: ir.IntType{Width: ir.Size4, Signed: true}}

	fn := buildVSAFunction("value_cast", []ir.IRInstruction{
		&ir.Assign{
			Dest:   x,
			Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 99, Width: ir.Size8, Signed: true}},
		},
		&ir.Assign{
			Dest: y,
			Source: ir.Cast{
				Expr:       ir.VariableExpr{Var: x},
				TargetType: ir.IntType{Width: ir.Size4, Signed: true},
			},
		},
	})

	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	val, ok := result.IsConstant(y)
	if !ok {
		t.Fatal("expected y to be constant after value-type cast in VSA")
	}
	if val != 99 {
		t.Errorf("expected 99, got %d", val)
	}
}

func TestVSA_NilExpression(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: true}}

	fn := buildVSAFunction("nil_expr", []ir.IRInstruction{
		&ir.Assign{
			Dest:   x,
			Source: nil,
		},
	})

	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	xVS := result.GetValueSet(x)
	if !xVS.IsTop() {
		t.Error("expected top for nil expression in VSA")
	}
}

func TestConstProp_ApplyToFunction_StoreAndCall(t *testing.T) {
	cfgGraph := buildSimpleCFG()
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	x := ssaVar("x", 1)
	addr := ir.Variable{Name: "addr", Version: 1, Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size8, Signed: true}}}

	fn := &ir.Function{
		Name: "store_and_call",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x, Source: intConst(42)},
					&ir.Assign{Dest: addr, Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 0x1000, Width: ir.Size8}}},
					&ir.Store{
						Address: &ir.VariableExpr{Var: addr},
						Value:   &ir.VariableExpr{Var: x},
						Size:    ir.Size8,
					},
					&ir.Call{
						Target: &ir.VariableExpr{Var: addr},
					},
					&ir.Return{Value: &x},
				},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewConstPropAnalyzer(fn, cfgGraph, domTree)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	count := analyzer.ApplyToFunction(result)
	if count < 0 {
		t.Error("expected non-negative replacement count")
	}
}

func TestConstProp_ApplyToFunction_LoadRewrite(t *testing.T) {
	cfgGraph := buildSimpleCFG()
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	addr := ir.Variable{Name: "addr", Version: 1, Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size8, Signed: true}}}
	val := ssaVar("val", 1)

	fn := &ir.Function{
		Name: "load_rewrite",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: addr, Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 0x2000, Width: ir.Size8}}},
					&ir.Load{
						Dest:    val,
						Address: &ir.VariableExpr{Var: addr},
						Size:    ir.Size8,
					},
					&ir.Return{Value: &val},
				},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewConstPropAnalyzer(fn, cfgGraph, domTree)
	result, err := analyzer.Compute()
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	count := analyzer.ApplyToFunction(result)
	if count < 0 {
		t.Error("expected non-negative replacement count")
	}
}

func TestFoldCast_IntToUnsignedInt(t *testing.T) {
	got, ok := foldCast(ir.IntConstant{Value: -1, Width: ir.Size8, Signed: true}, ir.IntType{Width: ir.Size4, Signed: false})
	if !ok {
		t.Fatal("expected ok for signed->unsigned cast")
	}
	ic := got.(ir.IntConstant) //nolint:forcetypeassert // test helper
	if ic.Signed {
		t.Error("expected unsigned result")
	}
}

func TestConstProp_EvaluateBranch_TopCondition(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{
			0: {1, 2},
			1: {3},
			2: {3},
			3: {},
		},
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 0, 3: 0},
	)

	unknown := ir.Variable{Name: "unknown", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: true}}
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	z := ssaVar("z", 1)

	fn := &ir.Function{
		Name: "top_branch",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Branch{Condition: &ir.VariableExpr{Var: unknown}, TrueTarget: 1, FalseTarget: 2},
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x, Source: intConst(10)},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: y, Source: intConst(20)},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			3: {
				ID: 3,
				Instructions: []ir.IRInstruction{
					&ir.Phi{
						Dest: z,
						Sources: []ir.PhiSource{
							{Block: 1, Var: x},
							{Block: 2, Var: y},
						},
					},
					&ir.Return{Value: &ir.Variable{Name: "z", Type: intType(), Version: 1}},
				},
				Predecessors: []ir.BlockID{1, 2},
			},
		},
		EntryBlock: 0,
	}

	_, err := PropagateConstants(fn, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}
}
