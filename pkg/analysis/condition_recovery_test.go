package analysis

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

func cmpSub(left, right ir.Expression) ir.BinaryOp {
	return ir.BinaryOp{Op: ir.BinOpSub, Left: left, Right: right}
}

func zfExpr(left, right ir.Expression) ir.Expression {
	return ir.BinaryOp{
		Op:    ir.BinOpEq,
		Left:  cmpSub(left, right),
		Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 0}},
	}
}

func notZfExpr(left, right ir.Expression) ir.Expression {
	return ir.BinaryOp{
		Op:    ir.BinOpNe,
		Left:  cmpSub(left, right),
		Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 0}},
	}
}

func signBitMask64() ir.Expression {
	return ir.ConstantExpr{Value: ir.IntConstant{Value: 0x80000000, Width: ir.Size4}}
}

func sfExprReal(left, right ir.Expression) ir.Expression {
	return ir.BinaryOp{
		Op: ir.BinOpNe,
		Left: ir.BinaryOp{
			Op:    ir.BinOpAnd,
			Left:  cmpSub(left, right),
			Right: signBitMask64(),
		},
		Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 0}},
	}
}

func cfExpr(left, right ir.Expression) ir.Expression {
	return ir.BinaryOp{
		Op:    ir.BinOpULt,
		Left:  left,
		Right: right,
	}
}

func TestRecoverConditions_NilFunction(t *testing.T) {
	RecoverConditions(nil)
}

func TestRecoverConditions_EmptyFunction(t *testing.T) {
	fn := &ir.Function{
		Name:       "empty",
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: {ID: 0}},
		EntryBlock: 0,
	}
	RecoverConditions(fn)
}

func TestRecoverConditions_JE_ZeroFlag(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	cond := zfExpr(a, b)

	fn := &ir.Function{
		Name: "je_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Branch{Condition: cond, TrueTarget: 1},
				},
			},
		},
		EntryBlock: 0,
	}

	RecoverConditions(fn)

	branch, ok := fn.Blocks[0].Instructions[0].(*ir.Branch)
	if !ok {
		t.Fatal("expected Branch instruction")
	}
	binOp, ok := branch.Condition.(ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp condition, got %T", branch.Condition)
	}
	if binOp.Op != ir.BinOpEq {
		t.Errorf("expected BinOpEq, got %v", binOp.Op)
	}
}

func TestRecoverConditions_JNE_NotZeroFlag(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	cond := notZfExpr(a, b)

	fn := &ir.Function{
		Name: "jne_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Branch{Condition: cond, TrueTarget: 1},
				},
			},
		},
		EntryBlock: 0,
	}

	RecoverConditions(fn)

	branch, ok := fn.Blocks[0].Instructions[0].(*ir.Branch)
	if !ok {
		t.Fatal("expected Branch instruction")
	}
	binOp, ok := branch.Condition.(ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp condition, got %T", branch.Condition)
	}
	if binOp.Op != ir.BinOpNe {
		t.Errorf("expected BinOpNe, got %v", binOp.Op)
	}
}

func TestIsZeroConstant(t *testing.T) {
	tests := []struct {
		name string
		expr ir.Expression
		want bool
	}{
		{"int_zero", ir.ConstantExpr{Value: ir.IntConstant{Value: 0}}, true},
		{"int_nonzero", ir.ConstantExpr{Value: ir.IntConstant{Value: 1}}, false},
		{"variable", ir.VariableExpr{Var: ir.Variable{Name: "x"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isZeroConstant(tt.expr); got != tt.want {
				t.Errorf("isZeroConstant() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsFalseConstant(t *testing.T) {
	tests := []struct {
		name string
		expr ir.Expression
		want bool
	}{
		{"bool_false", ir.ConstantExpr{Value: ir.BoolConstant{Value: false}}, true},
		{"bool_true", ir.ConstantExpr{Value: ir.BoolConstant{Value: true}}, false},
		{"int_zero_not_false", ir.ConstantExpr{Value: ir.IntConstant{Value: 0}}, false},
		{"variable", ir.VariableExpr{Var: ir.Variable{Name: "x"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isFalseConstant(tt.expr); got != tt.want {
				t.Errorf("isFalseConstant() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsSignBitMask(t *testing.T) {
	tests := []struct {
		name string
		expr ir.Expression
		want bool
	}{
		{"0x80", ir.ConstantExpr{Value: ir.IntConstant{Value: 0x80}}, true},
		{"0x8000", ir.ConstantExpr{Value: ir.IntConstant{Value: 0x8000}}, true},
		{"0x80000000", ir.ConstantExpr{Value: ir.IntConstant{Value: 0x80000000}}, true},
		{"width_based_size1", ir.ConstantExpr{Value: ir.IntConstant{Value: 0x80, Width: ir.Size1}}, true},
		{"width_based_size4", ir.ConstantExpr{Value: ir.IntConstant{Value: 0x80000000, Width: ir.Size4}}, true},
		{"zero", ir.ConstantExpr{Value: ir.IntConstant{Value: 0}}, false},
		{"one", ir.ConstantExpr{Value: ir.IntConstant{Value: 1}}, false},
		{"variable", ir.VariableExpr{Var: ir.Variable{Name: "x"}}, false},
		{"float", ir.ConstantExpr{Value: ir.FloatConstant{Value: 1.0}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSignBitMask(tt.expr); got != tt.want {
				t.Errorf("isSignBitMask() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSameOperands(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}
	c := ir.VariableExpr{Var: ir.Variable{Name: "c"}}

	if !sameOperands(cmpOperands{left: a, right: b}, cmpOperands{left: a, right: b}) {
		t.Error("expected same operands to match")
	}
	if sameOperands(cmpOperands{left: a, right: b}, cmpOperands{left: a, right: c}) {
		t.Error("expected different operands to not match")
	}
}

func TestExprEqual(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a", Version: 1}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "a", Version: 1}}
	c := ir.VariableExpr{Var: ir.Variable{Name: "b", Version: 1}}

	if !exprEqual(a, b) {
		t.Error("expected equal variables to be equal")
	}
	if exprEqual(a, c) {
		t.Error("expected different variables to not be equal")
	}
	if !exprEqual(nil, nil) {
		t.Error("expected nil == nil")
	}
	if exprEqual(a, nil) {
		t.Error("expected non-nil != nil")
	}

	binA := ir.BinaryOp{Op: ir.BinOpAdd, Left: a, Right: c}
	binB := ir.BinaryOp{Op: ir.BinOpAdd, Left: a, Right: c}
	binC := ir.BinaryOp{Op: ir.BinOpSub, Left: a, Right: c}
	if !exprEqual(binA, binB) {
		t.Error("expected equal BinaryOps")
	}
	if exprEqual(binA, binC) {
		t.Error("expected different BinaryOps")
	}

	unA := ir.UnaryOp{Op: ir.UnOpNeg, Operand: a}
	unB := ir.UnaryOp{Op: ir.UnOpNeg, Operand: a}
	unC := ir.UnaryOp{Op: ir.UnOpNot, Operand: a}
	if !exprEqual(unA, unB) {
		t.Error("expected equal UnaryOps")
	}
	if exprEqual(unA, unC) {
		t.Error("expected different UnaryOps")
	}

	cA := ir.ConstantExpr{Value: ir.IntConstant{Value: 42}}
	cB := ir.ConstantExpr{Value: ir.IntConstant{Value: 42}}
	cC := ir.ConstantExpr{Value: ir.IntConstant{Value: 43}}
	if !exprEqual(cA, cB) {
		t.Error("expected equal ConstantExprs")
	}
	if exprEqual(cA, cC) {
		t.Error("expected different ConstantExprs")
	}
}

func TestConstantEqual(t *testing.T) {
	if !constantEqual(ir.IntConstant{Value: 42}, ir.IntConstant{Value: 42}) {
		t.Error("expected equal int constants")
	}
	if constantEqual(ir.IntConstant{Value: 42}, ir.IntConstant{Value: 43}) {
		t.Error("expected different int constants")
	}
	if !constantEqual(ir.BoolConstant{Value: true}, ir.BoolConstant{Value: true}) {
		t.Error("expected equal bool constants")
	}
	if !constantEqual(ir.FloatConstant{Value: 1.5}, ir.FloatConstant{Value: 1.5}) {
		t.Error("expected equal float constants")
	}
	if constantEqual(ir.IntConstant{Value: 1}, ir.BoolConstant{Value: true}) {
		t.Error("expected different types to not be equal")
	}
}

func TestRecoverExpr_NonBinaryOp(t *testing.T) {
	expr := ir.VariableExpr{Var: ir.Variable{Name: "x"}}
	result := recoverExpr(expr)
	if _, ok := result.(ir.VariableExpr); !ok {
		t.Error("non-BinaryOp should pass through unchanged")
	}
}

func TestRecoverExpr_UnrelatedBinaryOp(t *testing.T) {
	expr := ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  ir.VariableExpr{Var: ir.Variable{Name: "x"}},
		Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 1}},
	}
	result := recoverExpr(expr)
	binOp, ok := result.(ir.BinaryOp)
	if !ok {
		t.Fatal("expected BinaryOp")
	}
	if binOp.Op != ir.BinOpAdd {
		t.Error("unrelated BinaryOp should pass through unchanged")
	}
}

func TestRecoverConditions_JL_SFneFalse(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	sf := sfExprReal(a, b)
	cond := ir.BinaryOp{
		Op:    ir.BinOpNe,
		Left:  sf,
		Right: ir.ConstantExpr{Value: ir.BoolConstant{Value: false}},
	}

	fn := &ir.Function{
		Name: "jl_sf_ne_false",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Branch{Condition: cond, TrueTarget: 1},
				},
			},
		},
		EntryBlock: 0,
	}

	RecoverConditions(fn)

	branch, ok := fn.Blocks[0].Instructions[0].(*ir.Branch) //nolint:forcetypeassert
	if !ok {
		t.Fatal("expected Branch instruction")
	}
	binOp, ok := branch.Condition.(ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp, got %T", branch.Condition)
	}
	if binOp.Op != ir.BinOpLt {
		t.Errorf("expected BinOpLt, got %v", binOp.Op)
	}
}

func TestRecoverConditions_JB_UnsignedLessThan(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	cond := cfExpr(a, b)

	fn := &ir.Function{
		Name: "jb_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Branch{Condition: cond, TrueTarget: 1},
				},
			},
		},
		EntryBlock: 0,
	}

	RecoverConditions(fn)
}

func TestRecoverConditions_NonBranchInstruction(t *testing.T) {
	fn := &ir.Function{
		Name: "non_branch",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   ir.Variable{Name: "x"},
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 1}},
					},
					&ir.Return{},
				},
			},
		},
		EntryBlock: 0,
	}

	RecoverConditions(fn)
}

func TestExtractCmpEqZero(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	ops, ok := extractCmpEqZero(zfExpr(a, b))
	if !ok {
		t.Fatal("expected extractCmpEqZero to succeed")
	}
	if ops.right == nil {
		t.Error("expected non-nil operands")
	}

	_, ok = extractCmpEqZero(ir.VariableExpr{Var: ir.Variable{Name: "x"}})
	if ok {
		t.Error("expected extractCmpEqZero to fail on non-pattern")
	}
}

func TestExtractSignFlag(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	_, ok := extractSignFlag(sfExprReal(a, b))
	if !ok {
		t.Error("expected extractSignFlag to succeed on valid pattern")
	}

	_, ok = extractSignFlag(ir.VariableExpr{Var: ir.Variable{Name: "x"}})
	if ok {
		t.Error("expected extractSignFlag to fail on non-pattern")
	}
}

func TestSameBinaryOp(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	op1 := ir.BinaryOp{Op: ir.BinOpSub, Left: a, Right: b}
	op2 := ir.BinaryOp{Op: ir.BinOpSub, Left: a, Right: b}
	op3 := ir.BinaryOp{Op: ir.BinOpAdd, Left: a, Right: b}

	if !sameBinaryOp(op1, op2) {
		t.Error("expected same BinaryOps to match")
	}
	if sameBinaryOp(op1, op3) {
		t.Error("expected different BinaryOps to not match")
	}
}

func TestRecoverConditions_JLE_ZfOrSfNeOf(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	zf := zfExpr(a, b)
	sfNeOf := ir.BinaryOp{
		Op:    ir.BinOpNe,
		Left:  sfExprReal(a, b),
		Right: ir.ConstantExpr{Value: ir.BoolConstant{Value: false}},
	}
	cond := ir.BinaryOp{Op: ir.BinOpLogicalOr, Left: zf, Right: sfNeOf}

	fn := &ir.Function{
		Name: "jle_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Branch{Condition: cond, TrueTarget: 1},
				},
			},
		},
		EntryBlock: 0,
	}

	RecoverConditions(fn)

	branch, ok := fn.Blocks[0].Instructions[0].(*ir.Branch) //nolint:forcetypeassert
	if !ok {
		t.Fatal("expected Branch instruction")
	}
	binOp, ok := branch.Condition.(ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp, got %T", branch.Condition)
	}
	if binOp.Op != ir.BinOpLogicalOr {
		t.Errorf("expected BinOpLogicalOr (sub-patterns simplified individually), got %v", binOp.Op)
	}
	lhs, lok := binOp.Left.(ir.BinaryOp)
	if lok && lhs.Op != ir.BinOpEq {
		t.Errorf("expected left to be BinOpEq (zf simplified), got %v", lhs.Op)
	}
	rhs, rok := binOp.Right.(ir.BinaryOp)
	if rok && rhs.Op != ir.BinOpLt {
		t.Errorf("expected right to be BinOpLt (sf!=of simplified), got %v", rhs.Op)
	}
}

func TestRecoverConditions_JGE_SfEqFalse(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	cond := ir.BinaryOp{
		Op:    ir.BinOpEq,
		Left:  sfExprReal(a, b),
		Right: ir.ConstantExpr{Value: ir.BoolConstant{Value: false}},
	}

	fn := &ir.Function{
		Name: "jge_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Branch{Condition: cond, TrueTarget: 1},
				},
			},
		},
		EntryBlock: 0,
	}

	RecoverConditions(fn)

	branch, ok := fn.Blocks[0].Instructions[0].(*ir.Branch) //nolint:forcetypeassert
	if !ok {
		t.Fatal("expected Branch instruction")
	}
	binOp, ok := branch.Condition.(ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp, got %T", branch.Condition)
	}
	if binOp.Op != ir.BinOpGe {
		t.Errorf("expected BinOpGe, got %v", binOp.Op)
	}
}

func TestRecoverConditions_JBE_CfOrZf(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	cf := cfExpr(a, b)
	zf := zfExpr(a, b)
	cond := ir.BinaryOp{Op: ir.BinOpLogicalOr, Left: cf, Right: zf}

	fn := &ir.Function{
		Name: "jbe_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Branch{Condition: cond, TrueTarget: 1},
				},
			},
		},
		EntryBlock: 0,
	}

	RecoverConditions(fn)

	branch, ok := fn.Blocks[0].Instructions[0].(*ir.Branch) //nolint:forcetypeassert
	if !ok {
		t.Fatal("expected Branch instruction")
	}
	binOp, ok := branch.Condition.(ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp, got %T", branch.Condition)
	}
	if binOp.Op != ir.BinOpULe {
		t.Errorf("expected BinOpULe, got %v", binOp.Op)
	}
}

func TestRecoverConditions_JA_NotCfAndNotZf(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	notCf := ir.UnaryOp{Op: ir.UnOpLogicalNot, Operand: cfExpr(a, b)}
	notZf := ir.UnaryOp{Op: ir.UnOpLogicalNot, Operand: zfExpr(a, b)}
	cond := ir.BinaryOp{Op: ir.BinOpLogicalAnd, Left: notCf, Right: notZf}

	fn := &ir.Function{
		Name: "ja_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Branch{Condition: cond, TrueTarget: 1},
				},
			},
		},
		EntryBlock: 0,
	}

	RecoverConditions(fn)

	branch, ok := fn.Blocks[0].Instructions[0].(*ir.Branch) //nolint:forcetypeassert
	if !ok {
		t.Fatal("expected Branch instruction")
	}
	binOp, ok := branch.Condition.(ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp, got %T", branch.Condition)
	}
	if binOp.Op != ir.BinOpLogicalAnd {
		t.Errorf("expected BinOpLogicalAnd (sub-patterns simplified individually), got %v", binOp.Op)
	}
}

func TestRecoverExpr_NilExpr(t *testing.T) {
	result := recoverExpr(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestRecoverExpr_UnaryNotZf(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	notZf := ir.UnaryOp{Op: ir.UnOpLogicalNot, Operand: zfExpr(a, b)}
	result := recoverExpr(notZf)

	binOp, ok := result.(ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp, got %T", result)
	}
	if binOp.Op != ir.BinOpNe {
		t.Errorf("expected BinOpNe, got %v", binOp.Op)
	}
}

func TestExtractCFPattern(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	ops, ok := extractCFPattern(cfExpr(a, b))
	if !ok {
		t.Fatal("expected extractCFPattern to succeed")
	}
	if ops.left == nil || ops.right == nil {
		t.Error("expected non-nil operands")
	}

	_, ok = extractCFPattern(ir.VariableExpr{Var: ir.Variable{Name: "x"}})
	if ok {
		t.Error("expected extractCFPattern to fail on non-pattern")
	}
}

func TestExtractNotCF(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	notCf := ir.UnaryOp{Op: ir.UnOpLogicalNot, Operand: cfExpr(a, b)}
	ops, ok := extractNotCF(notCf)
	if !ok {
		t.Fatal("expected extractNotCF to succeed")
	}
	if ops.left == nil {
		t.Error("expected non-nil operands")
	}

	_, ok = extractNotCF(ir.VariableExpr{Var: ir.Variable{Name: "x"}})
	if ok {
		t.Error("expected extractNotCF to fail on non-UnaryOp")
	}
}

func TestExtractNotCmpEqZero(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	notZf := ir.UnaryOp{Op: ir.UnOpLogicalNot, Operand: zfExpr(a, b)}
	ops, ok := extractNotCmpEqZero(notZf)
	if !ok {
		t.Fatal("expected extractNotCmpEqZero to succeed")
	}
	if ops.left == nil {
		t.Error("expected non-nil operands")
	}

	_, ok = extractNotCmpEqZero(ir.VariableExpr{Var: ir.Variable{Name: "x"}})
	if ok {
		t.Error("expected extractNotCmpEqZero to fail on non-UnaryOp")
	}
}

func TestRecoverConditions_AssignRecovery(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	fn := &ir.Function{
		Name: "assign_recovery",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   ir.Variable{Name: "cond"},
						Source: zfExpr(a, b),
					},
				},
			},
		},
		EntryBlock: 0,
	}

	RecoverConditions(fn)

	assign, ok := fn.Blocks[0].Instructions[0].(*ir.Assign) //nolint:forcetypeassert
	if !ok {
		t.Fatal("expected Assign instruction")
	}
	binOp, ok := assign.Source.(ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp, got %T", assign.Source)
	}
	if binOp.Op != ir.BinOpEq {
		t.Errorf("expected BinOpEq, got %v", binOp.Op)
	}
}
