package analysis

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// helpers
// ============================================================================

// boolConst creates a boolean constant expression.
func boolConst(v bool) ir.Expression {
	return ir.ConstantExpr{Value: ir.BoolConstant{Value: v}}
}

// floatConst creates a float64 constant expression.
func floatConst(v float64) ir.Expression {
	return ir.ConstantExpr{Value: ir.FloatConstant{Value: v, Width: ir.Size8}}
}

// buildSimpleCFG creates a minimal cfg.CFG for single-block functions.
func buildSimpleCFG() *cfg.CFG {
	entry := cfg.BlockID(0)
	g := cfg.NewCFG()
	g.Entry = entry
	g.AddBlock(&cfg.BasicBlock{ID: entry})
	return g
}

// ============================================================================
// lattice unit tests
// ============================================================================

// TestLattice_Meet verifies the meet operation on the three-valued lattice.
func TestLattice_Meet(t *testing.T) {
	top := latticeValue{kind: latticeTop}
	bot := latticeValue{kind: latticeBottom}
	c42 := latticeValue{kind: latticeConstant, constant: ir.IntConstant{Value: 42, Width: ir.Size8, Signed: true}}
	c99 := latticeValue{kind: latticeConstant, constant: ir.IntConstant{Value: 99, Width: ir.Size8, Signed: true}}

	tests := []struct {
		name string
		a, b latticeValue
		want latticeKind
	}{
		{"top meet top", top, top, latticeTop},
		{"top meet const", top, c42, latticeConstant},
		{"const meet top", c42, top, latticeConstant},
		{"const meet same const", c42, c42, latticeConstant},
		{"const meet diff const", c42, c99, latticeBottom},
		{"bottom meet top", bot, top, latticeBottom},
		{"top meet bottom", top, bot, latticeBottom},
		{"bottom meet const", bot, c42, latticeBottom},
		{"const meet bottom", c42, bot, latticeBottom},
		{"bottom meet bottom", bot, bot, latticeBottom},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := meet(tt.a, tt.b)
			if got.kind != tt.want {
				t.Errorf("meet(%s, %s) = %s, want kind %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// ============================================================================
// constant folding unit tests
// ============================================================================

// TestFoldBinaryOp_IntArithmetic verifies integer arithmetic folding.
func TestFoldBinaryOp_IntArithmetic(t *testing.T) {
	i64 := func(v int64) ir.IntConstant { return ir.IntConstant{Value: v, Width: ir.Size8, Signed: true} }

	tests := []struct {
		name    string
		op      ir.BinaryOperator
		l, r    ir.IntConstant
		wantVal int64
		wantOK  bool
	}{
		{"add", ir.BinOpAdd, i64(10), i64(32), 42, true},
		{"sub", ir.BinOpSub, i64(50), i64(8), 42, true},
		{"mul", ir.BinOpMul, i64(6), i64(7), 42, true},
		{"div", ir.BinOpDiv, i64(84), i64(2), 42, true},
		{"div by zero", ir.BinOpDiv, i64(1), i64(0), 0, false},
		{"mod", ir.BinOpMod, i64(47), i64(5), 2, true},
		{"and", ir.BinOpAnd, i64(0xFF), i64(0x0F), 0x0F, true},
		{"or", ir.BinOpOr, i64(0xF0), i64(0x0F), 0xFF, true},
		{"xor", ir.BinOpXor, i64(0xFF), i64(0x0F), 0xF0, true},
		{"shl", ir.BinOpShl, i64(1), i64(3), 8, true},
		{"shr", ir.BinOpShr, i64(16), i64(2), 4, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := foldBinaryOp(tt.op, tt.l, tt.r)
			if ok != tt.wantOK {
				t.Fatalf("foldBinaryOp ok=%v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			ic, isInt := got.(ir.IntConstant)
			if !isInt {
				t.Fatalf("expected IntConstant, got %T", got)
			}
			if ic.Value != tt.wantVal {
				t.Errorf("got %d, want %d", ic.Value, tt.wantVal)
			}
		})
	}
}

// TestFoldBinaryOp_IntComparisons verifies integer comparison folding.
func TestFoldBinaryOp_IntComparisons(t *testing.T) {
	i64 := func(v int64) ir.IntConstant { return ir.IntConstant{Value: v, Width: ir.Size8, Signed: true} }

	tests := []struct {
		name string
		op   ir.BinaryOperator
		l, r ir.IntConstant
		want bool
	}{
		{"eq true", ir.BinOpEq, i64(5), i64(5), true},
		{"eq false", ir.BinOpEq, i64(5), i64(6), false},
		{"ne true", ir.BinOpNe, i64(5), i64(6), true},
		{"lt true", ir.BinOpLt, i64(3), i64(5), true},
		{"lt false", ir.BinOpLt, i64(5), i64(3), false},
		{"le equal", ir.BinOpLe, i64(5), i64(5), true},
		{"gt true", ir.BinOpGt, i64(7), i64(3), true},
		{"ge equal", ir.BinOpGe, i64(5), i64(5), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := foldBinaryOp(tt.op, tt.l, tt.r)
			if !ok {
				t.Fatal("expected fold to succeed")
			}
			bc, isBool := got.(ir.BoolConstant)
			if !isBool {
				t.Fatalf("expected BoolConstant, got %T", got)
			}
			if bc.Value != tt.want {
				t.Errorf("got %v, want %v", bc.Value, tt.want)
			}
		})
	}
}

// TestFoldBinaryOp_OverflowWrapping verifies that integer overflow wraps correctly.
func TestFoldBinaryOp_OverflowWrapping(t *testing.T) {
	// 8-bit unsigned: 255 + 1 = 0 (wraps)
	u8max := ir.IntConstant{Value: 255, Width: ir.Size1, Signed: false}
	one := ir.IntConstant{Value: 1, Width: ir.Size1, Signed: false}

	got, ok := foldBinaryOp(ir.BinOpAdd, u8max, one)
	if !ok {
		t.Fatal("expected fold to succeed")
	}
	ic := got.(ir.IntConstant) //nolint:forcetypeassert // test: value is always IntConstant here
	if ic.Value != 0 {
		t.Errorf("expected 0 (overflow wrap), got %d", ic.Value)
	}
}

// TestFoldUnaryOp verifies unary operation folding.
func TestFoldUnaryOp(t *testing.T) {
	i64 := func(v int64) ir.IntConstant { return ir.IntConstant{Value: v, Width: ir.Size8, Signed: true} }

	t.Run("neg int", func(t *testing.T) {
		got, ok := foldUnaryOp(ir.UnOpNeg, i64(42))
		if !ok {
			t.Fatal("expected success")
		}
		if got.(ir.IntConstant).Value != -42 { //nolint:forcetypeassert // test: value is always IntConstant here
			t.Errorf("expected -42, got %v", got)
		}
	})

	t.Run("bitwise not", func(t *testing.T) {
		// ~0 for 8-byte signed = -1
		got, ok := foldUnaryOp(ir.UnOpNot, i64(0))
		if !ok {
			t.Fatal("expected success")
		}
		if got.(ir.IntConstant).Value != -1 { //nolint:forcetypeassert // test: value is always IntConstant here
			t.Errorf("expected -1, got %v", got)
		}
	})

	t.Run("logical not true", func(t *testing.T) {
		got, ok := foldUnaryOp(ir.UnOpLogicalNot, ir.BoolConstant{Value: true})
		if !ok {
			t.Fatal("expected success")
		}
		if got.(ir.BoolConstant).Value != false { //nolint:forcetypeassert // test: value is always BoolConstant here
			t.Error("expected false")
		}
	})

	t.Run("logical not zero int", func(t *testing.T) {
		got, ok := foldUnaryOp(ir.UnOpLogicalNot, i64(0))
		if !ok {
			t.Fatal("expected success")
		}
		if got.(ir.BoolConstant).Value != true { //nolint:forcetypeassert // test: value is always BoolConstant here
			t.Error("expected true for !0")
		}
	})
}

// TestFoldCast verifies type cast folding.
func TestFoldCast(t *testing.T) {
	t.Run("int to narrower int truncates", func(t *testing.T) {
		// 0x1FF cast to u8 = 0xFF
		c := ir.IntConstant{Value: 0x1FF, Width: ir.Size8, Signed: false}
		got, ok := foldCast(c, ir.IntType{Width: ir.Size1, Signed: false})
		if !ok {
			t.Fatal("expected success")
		}
		if got.(ir.IntConstant).Value != 0xFF { //nolint:forcetypeassert // test: value is always IntConstant here
			t.Errorf("expected 0xFF, got %v", got)
		}
	})

	t.Run("int to float", func(t *testing.T) {
		c := ir.IntConstant{Value: 42, Width: ir.Size8, Signed: true}
		got, ok := foldCast(c, ir.FloatType{Width: ir.Size8})
		if !ok {
			t.Fatal("expected success")
		}
		if got.(ir.FloatConstant).Value != 42.0 { //nolint:forcetypeassert // test: value type is known at this point
			t.Errorf("expected 42.0, got %v", got)
		}
	})

	t.Run("bool to int", func(t *testing.T) {
		got, ok := foldCast(ir.BoolConstant{Value: true}, ir.IntType{Width: ir.Size8, Signed: false})
		if !ok {
			t.Fatal("expected success")
		}
		if got.(ir.IntConstant).Value != 1 { //nolint:forcetypeassert // test: value type is known at this point
			t.Errorf("expected 1, got %v", got)
		}
	})
}

// ============================================================================
// SCCP integration tests
// ============================================================================

// TestConstProp_LinearCode verifies propagation through straight-line code.
// bb0: x_1 = 10; y_1 = 32; z_1 = x_1 + y_1; return z_1
// expected: z_1 = 42 (constant)
func TestConstProp_LinearCode(t *testing.T) {
	cfgGraph := buildSimpleCFG()
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	x1 := ssaVar("x", 1)
	y1 := ssaVar("y", 1)
	z1 := ssaVar("z", 1)

	function := &ir.Function{
		Name: "linear",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x1, Source: intConst(10)},
					&ir.Assign{Dest: y1, Source: intConst(32)},
					&ir.Assign{
						Dest: z1,
						Source: &ir.BinaryOp{
							Op:    ir.BinOpAdd,
							Left:  &ir.VariableExpr{Var: x1},
							Right: &ir.VariableExpr{Var: y1},
						},
					},
					&ir.Return{Value: &z1},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(function, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}

	if !result.IsConstant(x1) {
		t.Error("expected x_1 to be constant")
	}
	if !result.IsConstant(y1) {
		t.Error("expected y_1 to be constant")
	}
	if !result.IsConstant(z1) {
		t.Error("expected z_1 to be constant (10+32=42)")
	}

	c := result.GetConstant(z1)
	if c == nil {
		t.Fatal("expected non-nil constant for z_1")
	}
	ic, ok := c.(ir.IntConstant)
	if !ok || ic.Value != 42 {
		t.Errorf("expected z_1 = 42, got %v", c)
	}
}

// TestConstProp_PhiAllSameConstant verifies that a phi-node with all identical
// constant inputs is itself resolved to that constant.
// cfg: bb0 -> bb1, bb0 -> bb2, bb1 -> bb3, bb2 -> bb3
// bb0: branch true -> bb1, false -> bb2
// bb1: x_1 = 42; jump bb3
// bb2: x_2 = 42; jump bb3
// bb3: x_3 = phi(x_1, x_2); return x_3
// expected: x_3 = 42
//
//nolint:dupl // similar test setup
func TestConstProp_PhiAllSameConstant(t *testing.T) {
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

	x1 := ssaVar("x", 1)
	x2 := ssaVar("x", 2)
	x3 := ssaVar("x", 3)

	function := &ir.Function{
		Name: "phi_same",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Branch{
						Condition:   boolConst(true),
						TrueTarget:  1,
						FalseTarget: 2,
					},
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x1, Source: intConst(42)},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x2, Source: intConst(42)},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			3: {
				ID: 3,
				Instructions: []ir.IRInstruction{
					&ir.Phi{
						Dest: x3,
						Sources: []ir.PhiSource{
							{Block: 1, Var: x1},
							{Block: 2, Var: x2},
						},
					},
					&ir.Return{Value: &x3},
				},
				Predecessors: []ir.BlockID{1, 2},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(function, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}

	if !result.IsConstant(x3) {
		t.Error("expected x_3 to be constant (phi of 42, 42 = 42)")
	}
	c := result.GetConstant(x3)
	if c == nil {
		t.Fatal("expected non-nil constant for x_3")
	}
	if c.(ir.IntConstant).Value != 42 { //nolint:forcetypeassert // test: value type is known at this point
		t.Errorf("expected 42, got %v", c)
	}
}

// TestConstProp_PhiDifferentConstants verifies that a phi-node with different
// constant inputs is resolved to bottom (overdefined).
// bb1: x_1 = 10; bb2: x_2 = 20; bb3: x_3 = phi(x_1, x_2)
// expected: x_3 is NOT constant
func TestConstProp_PhiDifferentConstants(t *testing.T) {
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

	x1 := ssaVar("x", 1)
	x2 := ssaVar("x", 2)
	x3 := ssaVar("x", 3)

	function := &ir.Function{
		Name: "phi_diff",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Branch{
						Condition:   &ir.VariableExpr{Var: ssaVar("cond", 1)},
						TrueTarget:  1,
						FalseTarget: 2,
					},
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x1, Source: intConst(10)},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x2, Source: intConst(20)},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			3: {
				ID: 3,
				Instructions: []ir.IRInstruction{
					&ir.Phi{
						Dest: x3,
						Sources: []ir.PhiSource{
							{Block: 1, Var: x1},
							{Block: 2, Var: x2},
						},
					},
					&ir.Return{Value: &x3},
				},
				Predecessors: []ir.BlockID{1, 2},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(function, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}

	if result.IsConstant(x3) {
		t.Error("expected x_3 to be overdefined (phi of 10, 20)")
	}
}

// TestConstProp_ConditionalConstantBranch verifies that when a branch condition
// is a known constant, only the taken path is marked executable.
// bb0: branch true -> bb1, false -> bb2
// bb1: x_1 = 42; jump bb3
// bb2: x_2 = 99; jump bb3  (unreachable)
// bb3: x_3 = phi(x_1, x_2)
// expected: x_3 = 42 (only bb1 is reachable)
//
//nolint:dupl // similar test setup
func TestConstProp_ConditionalConstantBranch(t *testing.T) {
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

	x1 := ssaVar("x", 1)
	x2 := ssaVar("x", 2)
	x3 := ssaVar("x", 3)

	function := &ir.Function{
		Name: "const_branch",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Branch{
						Condition:   boolConst(true), // always true
						TrueTarget:  1,
						FalseTarget: 2,
					},
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x1, Source: intConst(42)},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x2, Source: intConst(99)},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			3: {
				ID: 3,
				Instructions: []ir.IRInstruction{
					&ir.Phi{
						Dest: x3,
						Sources: []ir.PhiSource{
							{Block: 1, Var: x1},
							{Block: 2, Var: x2},
						},
					},
					&ir.Return{Value: &x3},
				},
				Predecessors: []ir.BlockID{1, 2},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(function, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}

	// x_3 should be 42 because only the true branch (bb1) is executable
	if !result.IsConstant(x3) {
		t.Error("expected x_3 to be constant (only true branch reachable)")
	}
	c := result.GetConstant(x3)
	if c != nil && c.(ir.IntConstant).Value != 42 { //nolint:forcetypeassert // test: value type is known at this point
		t.Errorf("expected x_3 = 42, got %v", c)
	}
}

// TestConstProp_WhileLoopInvariant verifies that a loop-invariant constant
// is correctly identified even with back-edges.
// bb0: i_1 = 0; limit_1 = 10
// bb1: i_2 = phi(i_1, i_3); branch i_2 < limit_1 -> bb2, bb3
// bb2: i_3 = i_2 + 1; jump bb1
// bb3: return i_2
// expected: limit_1 = 10 (constant), i_2 is NOT constant (changes each iteration)
func TestConstProp_WhileLoopInvariant(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{
			0: {1},
			1: {2, 3},
			2: {1},
			3: {},
		},
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 1, 3: 1},
	)

	i1 := ssaVar("i", 1)
	i2 := ssaVar("i", 2)
	i3 := ssaVar("i", 3)
	limit1 := ssaVar("limit", 1)

	function := &ir.Function{
		Name: "while_loop",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: i1, Source: intConst(0)},
					&ir.Assign{Dest: limit1, Source: intConst(10)},
				},
				Successors: []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Phi{
						Dest: i2,
						Sources: []ir.PhiSource{
							{Block: 0, Var: i1},
							{Block: 2, Var: i3},
						},
					},
					&ir.Branch{
						Condition: &ir.BinaryOp{
							Op:    ir.BinOpLt,
							Left:  &ir.VariableExpr{Var: i2},
							Right: &ir.VariableExpr{Var: limit1},
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
						Dest: i3,
						Source: &ir.BinaryOp{
							Op:    ir.BinOpAdd,
							Left:  &ir.VariableExpr{Var: i2},
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
					&ir.Return{Value: &i2},
				},
				Predecessors: []ir.BlockID{1},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(function, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}

	// limit_1 is a loop-invariant constant
	if !result.IsConstant(limit1) {
		t.Error("expected limit_1 to be constant (10)")
	}

	// i_2 is a loop variable: phi(0, i_2+1) -> overdefined
	if result.IsConstant(i2) {
		t.Error("expected i_2 to be overdefined (loop variable)")
	}
}

// TestConstProp_ChainedPropagation verifies multi-level constant propagation.
// a = 2; b = a * 3; c = b + 4; d = c - 2
// expected: a=2, b=6, c=10, d=8
func TestConstProp_ChainedPropagation(t *testing.T) {
	cfgGraph := buildSimpleCFG()
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	a := ssaVar("a", 1)
	b := ssaVar("b", 1)
	c := ssaVar("c", 1)
	d := ssaVar("d", 1)

	function := &ir.Function{
		Name: "chain",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: a, Source: intConst(2)},
					&ir.Assign{Dest: b, Source: &ir.BinaryOp{
						Op:    ir.BinOpMul,
						Left:  &ir.VariableExpr{Var: a},
						Right: intConst(3),
					}},
					&ir.Assign{Dest: c, Source: &ir.BinaryOp{
						Op:    ir.BinOpAdd,
						Left:  &ir.VariableExpr{Var: b},
						Right: intConst(4),
					}},
					&ir.Assign{Dest: d, Source: &ir.BinaryOp{
						Op:    ir.BinOpSub,
						Left:  &ir.VariableExpr{Var: c},
						Right: intConst(2),
					}},
					&ir.Return{Value: &d},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(function, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}

	expected := map[ir.Variable]int64{a: 2, b: 6, c: 10, d: 8}
	for v, want := range expected {
		if !result.IsConstant(v) {
			t.Errorf("expected %s to be constant", v)
			continue
		}
		got := result.GetConstant(v).(ir.IntConstant).Value //nolint:forcetypeassert // test: value type is known at this point
		if got != want {
			t.Errorf("%s: expected %d, got %d", v, want, got)
		}
	}
}

// TestConstProp_LoadIsBottom verifies that load results are always overdefined.
// loads may read from memory that changes at runtime.
func TestConstProp_LoadIsBottom(t *testing.T) {
	cfgGraph := buildSimpleCFG()
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	x1 := ssaVar("x", 1)

	function := &ir.Function{
		Name: "load_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Load{
						Dest:    x1,
						Address: intConst(0x1000),
						Size:    ir.Size8,
					},
					&ir.Return{Value: &x1},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(function, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}

	if result.IsConstant(x1) {
		t.Error("expected load result to be overdefined (not constant)")
	}
}

// TestConstProp_NilFunction verifies error handling for nil function.
func TestConstProp_NilFunction(t *testing.T) {
	_, err := PropagateConstants(nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil function")
	}
}

// TestConstProp_EmptyFunction verifies error handling for function with no blocks.
func TestConstProp_EmptyFunction(t *testing.T) {
	function := &ir.Function{
		Name:   "empty",
		Blocks: map[ir.BlockID]*ir.BasicBlock{},
	}
	_, err := PropagateConstants(function, nil, nil)
	if err == nil {
		t.Fatal("expected error for empty function")
	}
}

// TestConstProp_ReplacedCount verifies that ApplyToFunction correctly counts replacements.
func TestConstProp_ReplacedCount(t *testing.T) {
	cfgGraph := buildSimpleCFG()
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	x1 := ssaVar("x", 1)
	y1 := ssaVar("y", 1)

	function := &ir.Function{
		Name: "replace_count",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x1, Source: intConst(5)},
					// y_1 = x_1 + x_1: two uses of x_1 should be replaced
					&ir.Assign{Dest: y1, Source: &ir.BinaryOp{
						Op:    ir.BinOpAdd,
						Left:  &ir.VariableExpr{Var: x1},
						Right: &ir.VariableExpr{Var: x1},
					}},
					&ir.Return{Value: &y1},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(function, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}

	// two uses of x_1 in the binary op should have been replaced
	if result.ReplacedCount < 2 {
		t.Errorf("expected at least 2 replacements, got %d", result.ReplacedCount)
	}
}

// TestConstProp_FloatArithmetic verifies constant propagation for float operations.
func TestConstProp_FloatArithmetic(t *testing.T) {
	cfgGraph := buildSimpleCFG()
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	pi := ssaVar("pi", 1)
	r := ssaVar("r", 1)
	area := ssaVar("area", 1)

	function := &ir.Function{
		Name: "float_arith",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: pi, Source: floatConst(3.14)},
					&ir.Assign{Dest: r, Source: floatConst(2.0)},
					// area = pi * r * r
					&ir.Assign{Dest: area, Source: &ir.BinaryOp{
						Op: ir.BinOpMul,
						Left: &ir.BinaryOp{
							Op:    ir.BinOpMul,
							Left:  &ir.VariableExpr{Var: pi},
							Right: &ir.VariableExpr{Var: r},
						},
						Right: &ir.VariableExpr{Var: r},
					}},
					&ir.Return{Value: &area},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(function, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}

	if !result.IsConstant(area) {
		t.Error("expected area to be constant (3.14 * 2.0 * 2.0)")
	}
	c := result.GetConstant(area)
	fc, ok := c.(ir.FloatConstant)
	if !ok {
		t.Fatalf("expected FloatConstant, got %T", c)
	}
	expected := 3.14 * 2.0 * 2.0
	if fc.Value != expected {
		t.Errorf("expected %f, got %f", expected, fc.Value)
	}
}

// TestConstProp_ArithmeticRightShift verifies sign-preserving arithmetic shift.
// sar(-8, 1) = -4 (sign bit preserved)
func TestConstProp_ArithmeticRightShift(t *testing.T) {
	l := ir.IntConstant{Value: -8, Width: ir.Size8, Signed: true}
	r := ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}

	got, ok := foldBinaryOp(ir.BinOpSar, l, r)
	if !ok {
		t.Fatal("expected fold to succeed")
	}
	ic := got.(ir.IntConstant) //nolint:forcetypeassert // test: value type is known at this point
	if ic.Value != -4 {
		t.Errorf("expected -4 (arithmetic right shift), got %d", ic.Value)
	}
}

// ============================================================================
// additional constant propagation correctness tests (task 7.9)
// ============================================================================

// TestConstProp_SSAChainThroughPhi verifies that constants propagate correctly
// through an ssa chain that passes through a phi-node with identical inputs.
// this is the canonical "phi-of-same-constant" pattern from real decompiled code.
//
// cfg: bb0 -> bb1, bb0 -> bb2, bb1 -> bb3, bb2 -> bb3
// bb0: branch (always true) -> bb1, bb2
// bb1: a_1 = 5; b_1 = a_1 * 2; jump bb3
// bb2: a_2 = 5; b_2 = a_2 * 2; jump bb3
// bb3: b_3 = phi(b_1, b_2); c_1 = b_3 + 1; return c_1
// expected: b_3 = 10, c_1 = 11
func TestConstProp_SSAChainThroughPhi(t *testing.T) {
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

	a1 := ssaVar("a", 1)
	a2 := ssaVar("a", 2)
	b1 := ssaVar("b", 1)
	b2 := ssaVar("b", 2)
	b3 := ssaVar("b", 3)
	c1 := ssaVar("c", 1)

	function := &ir.Function{
		Name: "ssa_chain_phi",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Branch{Condition: boolConst(true), TrueTarget: 1, FalseTarget: 2},
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: a1, Source: intConst(5)},
					&ir.Assign{Dest: b1, Source: &ir.BinaryOp{
						Op:    ir.BinOpMul,
						Left:  &ir.VariableExpr{Var: a1},
						Right: intConst(2),
					}},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: a2, Source: intConst(5)},
					&ir.Assign{Dest: b2, Source: &ir.BinaryOp{
						Op:    ir.BinOpMul,
						Left:  &ir.VariableExpr{Var: a2},
						Right: intConst(2),
					}},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			3: {
				ID: 3,
				Instructions: []ir.IRInstruction{
					&ir.Phi{
						Dest: b3,
						Sources: []ir.PhiSource{
							{Block: 1, Var: b1},
							{Block: 2, Var: b2},
						},
					},
					&ir.Assign{Dest: c1, Source: &ir.BinaryOp{
						Op:    ir.BinOpAdd,
						Left:  &ir.VariableExpr{Var: b3},
						Right: intConst(1),
					}},
					&ir.Return{Value: &c1},
				},
				Predecessors: []ir.BlockID{1, 2},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(function, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}

	// b_3 = phi(10, 10) = 10
	if !result.IsConstant(b3) {
		t.Error("expected b_3 to be constant (phi of 10, 10)")
	}
	if c := result.GetConstant(b3); c != nil {
		if c.(ir.IntConstant).Value != 10 { //nolint:forcetypeassert // test: value type is known at this point
			t.Errorf("expected b_3 = 10, got %v", c)
		}
	}

	// c_1 = b_3 + 1 = 11
	if !result.IsConstant(c1) {
		t.Error("expected c_1 to be constant (10 + 1 = 11)")
	}
	if c := result.GetConstant(c1); c != nil {
		if c.(ir.IntConstant).Value != 11 { //nolint:forcetypeassert // test: value type is known at this point
			t.Errorf("expected c_1 = 11, got %v", c)
		}
	}
}

// TestConstProp_CastPropagation verifies that constants propagate correctly
// through cast expressions in ssa chains.
// bb0: x_1 = 255 (u8); y_1 = (i64)(x_1); z_1 = y_1 + 1
// expected: y_1 = 255, z_1 = 256
func TestConstProp_CastPropagation(t *testing.T) {
	cfgGraph := buildSimpleCFG()
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	x1 := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size1, Signed: false}}
	y1 := ssaVar("y", 1)
	z1 := ssaVar("z", 1)

	function := &ir.Function{
		Name: "cast_prop",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x1, Source: ir.ConstantExpr{
						Value: ir.IntConstant{Value: 255, Width: ir.Size1, Signed: false},
					}},
					&ir.Assign{Dest: y1, Source: &ir.Cast{
						Expr:       &ir.VariableExpr{Var: x1},
						TargetType: ir.IntType{Width: ir.Size8, Signed: true},
					}},
					&ir.Assign{Dest: z1, Source: &ir.BinaryOp{
						Op:    ir.BinOpAdd,
						Left:  &ir.VariableExpr{Var: y1},
						Right: intConst(1),
					}},
					&ir.Return{Value: &z1},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(function, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}

	// y_1 = (i64)(255) = 255
	if !result.IsConstant(y1) {
		t.Error("expected y_1 to be constant after cast propagation")
	}

	// z_1 = 255 + 1 = 256
	if !result.IsConstant(z1) {
		t.Error("expected z_1 to be constant (255 + 1 = 256)")
	}
	if c := result.GetConstant(z1); c != nil {
		if c.(ir.IntConstant).Value != 256 { //nolint:forcetypeassert // test: value type is known at this point
			t.Errorf("expected z_1 = 256, got %v", c)
		}
	}
}

// TestConstProp_UnreachablePhiSource verifies that phi-nodes with unreachable
// sources are resolved correctly: only the reachable source contributes.
// cfg: bb0 (branch always-false) -> bb1 (unreachable), bb2 (reachable)
// bb1: x_1 = 99 (unreachable)
// bb2: x_2 = 42 (reachable)
// bb3: x_3 = phi(x_1, x_2)
// expected: x_3 = 42 (only bb2 is reachable)
//
//nolint:dupl // similar test setup
func TestConstProp_UnreachablePhiSource(t *testing.T) {
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

	x1 := ssaVar("x", 1)
	x2 := ssaVar("x", 2)
	x3 := ssaVar("x", 3)

	function := &ir.Function{
		Name: "unreachable_phi_source",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					// branch false: only bb2 is reachable
					&ir.Branch{Condition: boolConst(false), TrueTarget: 1, FalseTarget: 2},
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x1, Source: intConst(99)},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x2, Source: intConst(42)},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			3: {
				ID: 3,
				Instructions: []ir.IRInstruction{
					&ir.Phi{
						Dest: x3,
						Sources: []ir.PhiSource{
							{Block: 1, Var: x1},
							{Block: 2, Var: x2},
						},
					},
					&ir.Return{Value: &x3},
				},
				Predecessors: []ir.BlockID{1, 2},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(function, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}

	// x_3 should be 42 because only the false branch (bb2) is executable
	if !result.IsConstant(x3) {
		t.Error("expected x_3 to be constant (only false branch reachable, x_2=42)")
	}
	if c := result.GetConstant(x3); c != nil {
		if c.(ir.IntConstant).Value != 42 { //nolint:forcetypeassert // test: value type is known at this point
			t.Errorf("expected x_3 = 42, got %v", c)
		}
	}
}

// TestConstProp_BooleanShortCircuit verifies that boolean constant propagation
// correctly handles logical operations in branch conditions.
// bb0: a_1 = true; b_1 = false; c_1 = a_1 && b_1; branch c_1 -> bb1, bb2
// expected: c_1 = false, only bb2 is reachable
func TestConstProp_BooleanShortCircuit(t *testing.T) {
	cfgGraph, domTree := buildCFGAndDomTree(
		0,
		map[cfg.BlockID][]cfg.BlockID{
			0: {1, 2},
			1: {},
			2: {},
		},
		map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 0},
	)

	a1 := ir.Variable{Name: "a", Version: 1, Type: ir.BoolType{}}
	b1 := ir.Variable{Name: "b", Version: 1, Type: ir.BoolType{}}
	c1 := ir.Variable{Name: "c", Version: 1, Type: ir.BoolType{}}

	function := &ir.Function{
		Name: "bool_short_circuit",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: a1, Source: ir.ConstantExpr{Value: ir.BoolConstant{Value: true}}},
					&ir.Assign{Dest: b1, Source: ir.ConstantExpr{Value: ir.BoolConstant{Value: false}}},
					&ir.Assign{Dest: c1, Source: &ir.BinaryOp{
						Op:    ir.BinOpLogicalAnd,
						Left:  &ir.VariableExpr{Var: a1},
						Right: &ir.VariableExpr{Var: b1},
					}},
					&ir.Branch{Condition: &ir.VariableExpr{Var: c1}, TrueTarget: 1, FalseTarget: 2},
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

	result, err := PropagateConstants(function, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}

	// c_1 = true && false = false
	if !result.IsConstant(c1) {
		t.Error("expected c_1 to be constant (true && false = false)")
	}
	if c := result.GetConstant(c1); c != nil {
		if c.(ir.BoolConstant).Value != false { //nolint:forcetypeassert // test: value type is known at this point
			t.Errorf("expected c_1 = false, got %v", c)
		}
	}
}

// TestConstProp_MultiLevelSSAChain verifies propagation through a deep ssa chain.
// a_1 = 1; b_1 = a_1 + 1; c_1 = b_1 * 2; d_1 = c_1 - 1; e_1 = d_1 / 3
// expected: a=1, b=2, c=4, d=3, e=1
func TestConstProp_MultiLevelSSAChain(t *testing.T) {
	cfgGraph := buildSimpleCFG()
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	a := ssaVar("a", 1)
	b := ssaVar("b", 1)
	c := ssaVar("c", 1)
	d := ssaVar("d", 1)
	e := ssaVar("e", 1)

	function := &ir.Function{
		Name: "deep_ssa_chain",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: a, Source: intConst(1)},
					&ir.Assign{Dest: b, Source: &ir.BinaryOp{
						Op: ir.BinOpAdd, Left: &ir.VariableExpr{Var: a}, Right: intConst(1),
					}},
					&ir.Assign{Dest: c, Source: &ir.BinaryOp{
						Op: ir.BinOpMul, Left: &ir.VariableExpr{Var: b}, Right: intConst(2),
					}},
					&ir.Assign{Dest: d, Source: &ir.BinaryOp{
						Op: ir.BinOpSub, Left: &ir.VariableExpr{Var: c}, Right: intConst(1),
					}},
					&ir.Assign{Dest: e, Source: &ir.BinaryOp{
						Op: ir.BinOpDiv, Left: &ir.VariableExpr{Var: d}, Right: intConst(3),
					}},
					&ir.Return{Value: &e},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateConstants(function, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("PropagateConstants failed: %v", err)
	}

	expected := map[ir.Variable]int64{a: 1, b: 2, c: 4, d: 3, e: 1}
	for v, want := range expected {
		if !result.IsConstant(v) {
			t.Errorf("expected %s to be constant", v.String())
			continue
		}
		got := result.GetConstant(v).(ir.IntConstant).Value //nolint:forcetypeassert // test: value type is known at this point
		if got != want {
			t.Errorf("%s: expected %d, got %d", v.String(), want, got)
		}
	}
}
