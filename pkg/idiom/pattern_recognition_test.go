package idiom

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

func mkVar(name string, version int) ir.Variable {
	return ir.Variable{Name: name, Version: version, Type: ir.IntType{Width: ir.Size8, Signed: true}}
}

func mkUVar(name string, version int) ir.Variable {
	return ir.Variable{Name: name, Version: version, Type: ir.IntType{Width: ir.Size8, Signed: false}}
}

func mkConst(v int64) ir.Expression {
	return &ir.ConstantExpr{Value: ir.IntConstant{Value: v, Width: ir.Size8, Signed: true}}
}

func mkUConst(v uint64) ir.Expression {
	return &ir.ConstantExpr{Value: ir.IntConstant{Value: int64(v), Width: ir.Size8, Signed: false}}
}

func vExpr(v ir.Variable) ir.Expression {
	return &ir.VariableExpr{Var: v}
}

func assign(dest ir.Variable, src ir.Expression) ir.IRInstruction {
	return &ir.Assign{Dest: dest, Source: src}
}

func binop(op ir.BinaryOperator, left, right ir.Expression) ir.Expression {
	return &ir.BinaryOp{Op: op, Left: left, Right: right}
}

func unaryop(op ir.UnaryOperator, operand ir.Expression) ir.Expression {
	return &ir.UnaryOp{Op: op, Operand: operand}
}

func castExpr(expr ir.Expression, t ir.Type) ir.Expression {
	return &ir.Cast{Expr: expr, TargetType: t}
}

// ---------------------------------------------------------------------------
// Magic Divisor: edge cases and low-coverage paths
// ---------------------------------------------------------------------------

func TestMagicDivisor_Unsigned_Div2(t *testing.T) {
	x := u32Var("x", 1)
	block := buildMagicBlock(x, 0xCCCCCCCD, 2, ir.BinOpShr)
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Divisor != 5 {
		t.Errorf("expected divisor 5, got %d", matches[0].Divisor)
	}
}

func TestMagicDivisor_EmptyBlock(t *testing.T) {
	block := &ir.BasicBlock{ID: 0, Instructions: nil}
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty block, got %d", len(matches))
	}
}

func TestMagicDivisor_ShiftWithoutMul(t *testing.T) {
	x := mkVar("x", 1)
	y := mkVar("y", 1)
	result := mkVar("result", 1)
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(y, vExpr(x)),
			assign(result, binop(ir.BinOpShr, vExpr(y), mkConst(3))),
		},
	}
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestMagicDivisor_ShiftAmountTooLarge(t *testing.T) {
	x := mkUVar("x", 1)
	t1 := mkUVar("t", 1)
	result := mkUVar("result", 1)
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(t1, binop(ir.BinOpMul, vExpr(x), mkUConst(0xAAAAAAAAAAAAAAAB))),
			assign(result, binop(ir.BinOpShr, vExpr(t1), mkConst(64))),
		},
	}
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for shift > 63, got %d", len(matches))
	}
}

func TestMagicDivisor_MulWithNonConstant(t *testing.T) {
	x := mkUVar("x", 1)
	y := mkUVar("y", 1)
	t1 := mkUVar("t", 1)
	result := mkUVar("result", 1)
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(t1, binop(ir.BinOpMul, vExpr(x), vExpr(y))),
			assign(result, binop(ir.BinOpShr, vExpr(t1), mkConst(3))),
		},
	}
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for non-constant mul, got %d", len(matches))
	}
}

func TestMagicDivisor_ShiftedValueNotVariable(t *testing.T) {
	result := mkUVar("result", 1)
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(result, binop(ir.BinOpShr, mkConst(42), mkConst(3))),
		},
	}
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestMagicDivisor_NonAssignInstruction(t *testing.T) {
	x := mkUVar("x", 1)
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Store{Address: vExpr(x), Value: mkConst(0), Size: ir.Size8},
		},
	}
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestMagicDivisor_MulDefIsNotAssign(t *testing.T) {
	t1 := mkUVar("t", 1)
	result := mkUVar("result", 1)
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Load{Dest: t1, Address: mkConst(0x1000), Size: ir.Size8},
			assign(result, binop(ir.BinOpShr, vExpr(t1), mkConst(3))),
		},
	}
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestMagicDivisor_MulDefIsNotMul(t *testing.T) {
	x := mkUVar("x", 1)
	t1 := mkUVar("t", 1)
	result := mkUVar("result", 1)
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(t1, binop(ir.BinOpAdd, vExpr(x), mkConst(42))),
			assign(result, binop(ir.BinOpShr, vExpr(t1), mkConst(3))),
		},
	}
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestMagicDivisor_MagicOnLeftSide(t *testing.T) {
	x := u32Var("x", 1)
	t1 := u32Var("t", 1)
	result := u32Var("result", 1)
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(t1, binop(ir.BinOpMul, u32Const(0xAAAAAAAB), varExpr(x))),
			assign(result, binop(ir.BinOpShr, varExpr(t1), u32Const(1))),
		},
	}
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Divisor != 3 {
		t.Errorf("expected divisor 3, got %d", matches[0].Divisor)
	}
}

func TestMagicDivisor_ShiftNonIntConstant(t *testing.T) {
	x := mkUVar("x", 1)
	t1 := mkUVar("t", 1)
	result := mkUVar("result", 1)
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(t1, binop(ir.BinOpMul, vExpr(x), mkUConst(0xAAAAAAAAAAAAAAAB))),
			assign(result, binop(ir.BinOpShr, vExpr(t1),
				&ir.ConstantExpr{Value: ir.BoolConstant{Value: true}})),
		},
	}
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for non-int shift constant, got %d", len(matches))
	}
}

// ---------------------------------------------------------------------------
// Compiler Idiom: Inlined Calls - min pattern coverage
// ---------------------------------------------------------------------------

func buildMinBlockDistinct(a, b ir.Variable) *ir.BasicBlock {
	t1 := ir.Variable{Name: "t", Version: 10, Type: a.Type}
	t2 := ir.Variable{Name: "t", Version: 11, Type: a.Type}
	t3 := ir.Variable{Name: "t", Version: 12, Type: a.Type}
	result := ir.Variable{Name: "min_result", Version: 1, Type: a.Type}

	return &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(t1, binop(ir.BinOpSub, vExpr(b), vExpr(a))),
			assign(t2, binop(ir.BinOpSar, vExpr(t1), mkConst(63))),
			assign(t3, binop(ir.BinOpAnd, vExpr(t1), vExpr(t2))),
			assign(result, binop(ir.BinOpAdd, vExpr(a), vExpr(t3))),
		},
	}
}

func TestInlinedCalls_MinDetected(t *testing.T) {
	a := mkVar("alpha", 1)
	b := mkVar("beta", 1)
	block := buildMinBlockDistinct(a, b)

	matches, err := DetectInlinedCalls(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Kind != InlinedCallMin && matches[0].Kind != InlinedCallMax {
		t.Errorf("expected min or max, got %v", matches[0].Kind)
	}
}

func TestInlinedCalls_MinReversedAddOperands(t *testing.T) {
	a := mkVar("alpha", 1)
	b := mkVar("beta", 1)
	t1 := ir.Variable{Name: "t", Version: 10, Type: a.Type}
	t2 := ir.Variable{Name: "t", Version: 11, Type: a.Type}
	t3 := ir.Variable{Name: "t", Version: 12, Type: a.Type}
	result := ir.Variable{Name: "min_result", Version: 1, Type: a.Type}

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(t1, binop(ir.BinOpSub, vExpr(b), vExpr(a))),
			assign(t2, binop(ir.BinOpSar, vExpr(t1), mkConst(63))),
			assign(t3, binop(ir.BinOpAnd, vExpr(t2), vExpr(t1))),
			assign(result, binop(ir.BinOpAdd, vExpr(t3), vExpr(a))),
		},
	}

	matches, err := DetectInlinedCalls(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
}

func TestInlinedCalls_NotEnoughInstructions(t *testing.T) {
	a := mkVar("a", 1)
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(a, mkConst(42)),
		},
	}
	matches, err := DetectInlinedCalls(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestInlinedCalls_SubWithNonVariableOperands(t *testing.T) {
	t1 := mkVar("t", 1)
	t2 := mkVar("t", 2)
	t3 := mkVar("t", 3)
	result := mkVar("result", 1)

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(t1, binop(ir.BinOpSub, mkConst(10), mkConst(5))),
			assign(t2, binop(ir.BinOpSar, vExpr(t1), mkConst(63))),
			assign(t3, binop(ir.BinOpAnd, vExpr(t1), vExpr(t2))),
			assign(result, binop(ir.BinOpAdd, mkConst(5), vExpr(t3))),
		},
	}
	matches, err := DetectInlinedCalls(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for constant sub operands, got %d", len(matches))
	}
}

func TestInlinedCalls_WrongShiftAmount(t *testing.T) {
	a := mkVar("a", 1)
	b := mkVar("b", 1)
	t1 := mkVar("t", 1)
	t2 := mkVar("t", 2)
	t3 := mkVar("t", 3)
	result := mkVar("result", 1)

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(t1, binop(ir.BinOpSub, vExpr(b), vExpr(a))),
			assign(t2, binop(ir.BinOpSar, vExpr(t1), mkConst(31))),
			assign(t3, binop(ir.BinOpAnd, vExpr(t1), vExpr(t2))),
			assign(result, binop(ir.BinOpAdd, vExpr(a), vExpr(t3))),
		},
	}
	matches, err := DetectInlinedCalls(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for wrong shift amount, got %d", len(matches))
	}
}

func TestInlinedCalls_AndWithWrongOperands(t *testing.T) {
	a := mkVar("a", 1)
	b := mkVar("b", 1)
	t1 := mkVar("t", 1)
	t2 := mkVar("t", 2)
	t3 := mkVar("t", 3)
	result := mkVar("result", 1)
	other := mkVar("other", 1)

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(t1, binop(ir.BinOpSub, vExpr(b), vExpr(a))),
			assign(t2, binop(ir.BinOpSar, vExpr(t1), mkConst(63))),
			assign(t3, binop(ir.BinOpAnd, vExpr(other), vExpr(t2))),
			assign(result, binop(ir.BinOpAdd, vExpr(a), vExpr(t3))),
		},
	}
	matches, err := DetectInlinedCalls(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for wrong and operands, got %d", len(matches))
	}
}

func TestInlinedCalls_FinalAddNotAdd(t *testing.T) {
	a := mkVar("a", 1)
	b := mkVar("b", 1)
	t1 := mkVar("t", 1)
	t2 := mkVar("t", 2)
	t3 := mkVar("t", 3)
	result := mkVar("result", 1)

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(t1, binop(ir.BinOpSub, vExpr(b), vExpr(a))),
			assign(t2, binop(ir.BinOpSar, vExpr(t1), mkConst(63))),
			assign(t3, binop(ir.BinOpAnd, vExpr(t1), vExpr(t2))),
			assign(result, binop(ir.BinOpSub, vExpr(a), vExpr(t3))),
		},
	}
	matches, err := DetectInlinedCalls(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for sub instead of add, got %d", len(matches))
	}
}

func TestInlinedCalls_SecondInstrNotAssign(t *testing.T) {
	a := mkVar("a", 1)
	b := mkVar("b", 1)
	t1 := mkVar("t", 1)
	t3 := mkVar("t", 3)
	result := mkVar("result", 1)

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(t1, binop(ir.BinOpSub, vExpr(b), vExpr(a))),
			&ir.Store{Address: vExpr(t1), Value: mkConst(0), Size: ir.Size8},
			assign(t3, binop(ir.BinOpAnd, vExpr(t1), mkConst(0))),
			assign(result, binop(ir.BinOpAdd, vExpr(a), vExpr(t3))),
		},
	}
	matches, err := DetectInlinedCalls(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

// ---------------------------------------------------------------------------
// Compiler Idiom: Loop Unrolling - low-coverage paths
// ---------------------------------------------------------------------------

func TestLoopUnrolling_FindVarPlusConstAnywhere_NestedBinop(t *testing.T) {
	idx := mkVar("idx", 1)
	arr := mkVar("arr", 1)
	dst := mkVar("dst", 1)

	addr := binop(ir.BinOpAdd, vExpr(arr),
		binop(ir.BinOpAdd, vExpr(dst),
			binop(ir.BinOpAdd, vExpr(idx), mkConst(16))))

	t1 := mkVar("t", 1)
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Load{Dest: t1, Address: addr, Size: ir.Size8},
			&ir.Store{Address: addr, Value: vExpr(t1), Size: ir.Size8},
			&ir.Load{Dest: mkVar("t", 2), Address: binop(ir.BinOpAdd, vExpr(arr),
				binop(ir.BinOpAdd, vExpr(dst),
					binop(ir.BinOpAdd, vExpr(idx), mkConst(24)))), Size: ir.Size8},
			&ir.Store{Address: binop(ir.BinOpAdd, vExpr(arr),
				binop(ir.BinOpAdd, vExpr(dst),
					binop(ir.BinOpAdd, vExpr(idx), mkConst(24)))),
				Value: vExpr(mkVar("t", 2)), Size: ir.Size8},
		},
	}

	matches, err := DetectLoopUnrolling(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = matches
}

func TestLoopUnrolling_InstructionsStructurallyEquivalent_AssignVsLoad(t *testing.T) {
	x := mkVar("x", 1)
	a := assign(x, mkConst(42))
	b := &ir.Load{Dest: x, Address: mkConst(0x1000), Size: ir.Size8}

	result := instructionsStructurallyEquivalent(a, b, "idx")
	if result {
		t.Error("assign and load should not be structurally equivalent")
	}
}

func TestLoopUnrolling_InstructionsStructurallyEquivalent_StoreVsStore(t *testing.T) {
	idx := mkVar("idx", 1)
	arr := mkVar("arr", 1)

	a := &ir.Store{
		Address: binop(ir.BinOpAdd, vExpr(arr), vExpr(idx)),
		Value:   mkConst(0),
		Size:    ir.Size8,
	}
	b := &ir.Store{
		Address: binop(ir.BinOpAdd, vExpr(arr), vExpr(idx)),
		Value:   mkConst(0),
		Size:    ir.Size8,
	}

	result := instructionsStructurallyEquivalent(a, b, "idx")
	if !result {
		t.Error("identical stores should be structurally equivalent")
	}
}

func TestLoopUnrolling_InstructionsStructurallyEquivalent_DifferentSizes(t *testing.T) {
	idx := mkVar("idx", 1)
	arr := mkVar("arr", 1)

	a := &ir.Store{
		Address: binop(ir.BinOpAdd, vExpr(arr), vExpr(idx)),
		Value:   mkConst(0),
		Size:    ir.Size8,
	}
	b := &ir.Store{
		Address: binop(ir.BinOpAdd, vExpr(arr), vExpr(idx)),
		Value:   mkConst(0),
		Size:    ir.Size4,
	}

	result := instructionsStructurallyEquivalent(a, b, "idx")
	if result {
		t.Error("stores with different sizes should not be structurally equivalent")
	}
}

func TestLoopUnrolling_InstructionsStructurallyEquivalent_LoadVsLoad(t *testing.T) {
	idx := mkVar("idx", 1)
	arr := mkVar("arr", 1)

	a := &ir.Load{
		Dest:    mkVar("t", 1),
		Address: binop(ir.BinOpAdd, vExpr(arr), vExpr(idx)),
		Size:    ir.Size8,
	}
	b := &ir.Load{
		Dest:    mkVar("t", 2),
		Address: binop(ir.BinOpAdd, vExpr(arr), vExpr(idx)),
		Size:    ir.Size8,
	}

	result := instructionsStructurallyEquivalent(a, b, "idx")
	if !result {
		t.Error("loads with same address pattern should be structurally equivalent")
	}
}

func TestLoopUnrolling_InstructionsStructurallyEquivalent_LoadDifferentSize(t *testing.T) {
	idx := mkVar("idx", 1)
	arr := mkVar("arr", 1)

	a := &ir.Load{
		Dest:    mkVar("t", 1),
		Address: binop(ir.BinOpAdd, vExpr(arr), vExpr(idx)),
		Size:    ir.Size8,
	}
	b := &ir.Load{
		Dest:    mkVar("t", 2),
		Address: binop(ir.BinOpAdd, vExpr(arr), vExpr(idx)),
		Size:    ir.Size4,
	}

	result := instructionsStructurallyEquivalent(a, b, "idx")
	if result {
		t.Error("loads with different sizes should not be structurally equivalent")
	}
}

func TestLoopUnrolling_InstructionsStructurallyEquivalent_UnknownTypes(t *testing.T) {
	a := &ir.Jump{Target: 1}
	b := &ir.Jump{Target: 2}

	result := instructionsStructurallyEquivalent(a, b, "idx")
	if !result {
		t.Error("same-type unknown instructions should be structurally equivalent")
	}
}

func TestLoopUnrolling_InstructionsStructurallyEquivalent_DifferentUnknownTypes(t *testing.T) {
	a := &ir.Jump{Target: 1}
	b := &ir.Return{}

	result := instructionsStructurallyEquivalent(a, b, "idx")
	if result {
		t.Error("different-type instructions should not be structurally equivalent")
	}
}

// ---------------------------------------------------------------------------
// Compiler Idiom: Expressions structurally equivalent - low-coverage paths
// ---------------------------------------------------------------------------

func TestExpressionsStructurallyEquivalent_BinaryOpDifferentOps(t *testing.T) {
	x := mkVar("x", 1)
	a := binop(ir.BinOpAdd, vExpr(x), mkConst(8))
	b := binop(ir.BinOpSub, vExpr(x), mkConst(8))

	result := expressionsStructurallyEquivalent(a, b, "idx")
	if result {
		t.Error("different binary ops should not be equivalent")
	}
}

func TestExpressionsStructurallyEquivalent_BinaryOpVsVariable(t *testing.T) {
	x := mkVar("x", 1)
	a := binop(ir.BinOpAdd, vExpr(x), mkConst(8))
	b := vExpr(x)

	result := expressionsStructurallyEquivalent(a, b, "idx")
	if result {
		t.Error("binary op and variable should not be equivalent")
	}
}

func TestExpressionsStructurallyEquivalent_VariableVsBinaryOp(t *testing.T) {
	x := mkVar("x", 1)
	a := vExpr(x)
	b := binop(ir.BinOpAdd, vExpr(x), mkConst(8))

	result := expressionsStructurallyEquivalent(a, b, "idx")
	if result {
		t.Error("variable and binary op should not be equivalent")
	}
}

func TestExpressionsStructurallyEquivalent_ConstantVsVariable(t *testing.T) {
	a := mkConst(42)
	b := vExpr(mkVar("x", 1))

	result := expressionsStructurallyEquivalent(a, b, "idx")
	if result {
		t.Error("constant and variable should not be equivalent")
	}
}

func TestExpressionsStructurallyEquivalent_ConstantVsConstant(t *testing.T) {
	a := mkConst(42)
	b := mkConst(99)

	result := expressionsStructurallyEquivalent(a, b, "idx")
	if !result {
		t.Error("two int constants should be structurally equivalent (values ignored)")
	}
}

func TestExpressionsStructurallyEquivalent_BoolConstantVsIntConstant(t *testing.T) {
	a := &ir.ConstantExpr{Value: ir.BoolConstant{Value: true}}
	b := mkConst(1)

	result := expressionsStructurallyEquivalent(a, b, "idx")
	if result {
		t.Error("bool constant and int constant should not be equivalent")
	}
}

func TestExpressionsStructurallyEquivalent_UnaryOps(t *testing.T) {
	idx := mkVar("idx", 1)
	a := unaryop(ir.UnOpNeg, vExpr(idx))
	b := unaryop(ir.UnOpNeg, vExpr(idx))

	result := expressionsStructurallyEquivalent(a, b, "idx")
	if !result {
		t.Error("identical unary ops should be equivalent")
	}
}

func TestExpressionsStructurallyEquivalent_UnaryOpDifferentOps(t *testing.T) {
	idx := mkVar("idx", 1)
	a := unaryop(ir.UnOpNeg, vExpr(idx))
	b := unaryop(ir.UnOpNot, vExpr(idx))

	result := expressionsStructurallyEquivalent(a, b, "idx")
	if result {
		t.Error("different unary ops should not be equivalent")
	}
}

func TestExpressionsStructurallyEquivalent_UnaryVsBinary(t *testing.T) {
	idx := mkVar("idx", 1)
	a := unaryop(ir.UnOpNeg, vExpr(idx))
	b := binop(ir.BinOpAdd, vExpr(idx), mkConst(1))

	result := expressionsStructurallyEquivalent(a, b, "idx")
	if result {
		t.Error("unary and binary should not be equivalent")
	}
}

func TestExpressionsStructurallyEquivalent_CastVsCast(t *testing.T) {
	idx := mkVar("idx", 1)
	targetType := ir.IntType{Width: ir.Size4, Signed: true}
	a := castExpr(vExpr(idx), targetType)
	b := castExpr(vExpr(idx), targetType)

	result := expressionsStructurallyEquivalent(a, b, "idx")
	if !result {
		t.Error("identical casts should be equivalent")
	}
}

func TestExpressionsStructurallyEquivalent_CastVsNonCast(t *testing.T) {
	idx := mkVar("idx", 1)
	targetType := ir.IntType{Width: ir.Size4, Signed: true}
	a := castExpr(vExpr(idx), targetType)
	b := vExpr(idx)

	result := expressionsStructurallyEquivalent(a, b, "idx")
	if result {
		t.Error("cast and variable should not be equivalent")
	}
}

func TestExpressionsStructurallyEquivalent_InductionVars(t *testing.T) {
	idx1 := ir.Variable{Name: "idx", Version: 1, Type: ir.IntType{Width: ir.Size8}}
	idx2 := ir.Variable{Name: "idx", Version: 2, Type: ir.IntType{Width: ir.Size8}}

	a := vExpr(idx1)
	b := vExpr(idx2)

	result := expressionsStructurallyEquivalent(a, b, "idx")
	if !result {
		t.Error("induction variables with different versions should be equivalent")
	}
}

func TestExpressionsStructurallyEquivalent_NonInductionDifferentNames(t *testing.T) {
	x := mkVar("x", 1)
	y := mkVar("y", 1)

	result := expressionsStructurallyEquivalent(vExpr(x), vExpr(y), "idx")
	if result {
		t.Error("different non-induction variables should not be equivalent")
	}
}

func TestExpressionsStructurallyEquivalent_DefaultCase(t *testing.T) {
	a := &ir.LoadExpr{Address: mkConst(0x1000), Size: ir.Size8}
	b := &ir.LoadExpr{Address: mkConst(0x2000), Size: ir.Size8}

	result := expressionsStructurallyEquivalent(a, b, "idx")
	if !result {
		t.Error("same-type unknown expressions should be equivalent")
	}
}

func TestExpressionsStructurallyEquivalent_DefaultCaseDifferentTypes(t *testing.T) {
	a := &ir.LoadExpr{Address: mkConst(0x1000), Size: ir.Size8}
	b := mkConst(42)

	result := expressionsStructurallyEquivalent(a, b, "idx")
	if result {
		t.Error("different-type expressions should not be equivalent")
	}
}

// ---------------------------------------------------------------------------
// Compiler Idiom: Strength Reduction - additional edge cases
// ---------------------------------------------------------------------------

func TestStrengthReduction_3x_ReversedOperands(t *testing.T) {
	x := mkVar("x", 1)
	t1 := ir.Variable{Name: "t", Version: 1, Type: x.Type}
	t2 := ir.Variable{Name: "t", Version: 2, Type: x.Type}

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(t1, binop(ir.BinOpAdd, vExpr(x), vExpr(x))),
			assign(t2, binop(ir.BinOpAdd, vExpr(x), vExpr(t1))),
		},
	}

	matches, err := RecognizeStrengthReduction(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Multiplier != 3 {
		t.Errorf("expected multiplier 3, got %d", matches[0].Multiplier)
	}
}

func TestStrengthReduction_NonAddChain(t *testing.T) {
	x := mkVar("x", 1)
	t1 := ir.Variable{Name: "t", Version: 1, Type: x.Type}
	t2 := ir.Variable{Name: "t", Version: 2, Type: x.Type}

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(t1, binop(ir.BinOpMul, vExpr(x), mkConst(2))),
			assign(t2, binop(ir.BinOpAdd, vExpr(t1), vExpr(x))),
		},
	}

	matches, err := RecognizeStrengthReduction(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for non-add chain, got %d", len(matches))
	}
}

func TestStrengthReduction_AddWithConstant(t *testing.T) {
	x := mkVar("x", 1)
	t1 := ir.Variable{Name: "t", Version: 1, Type: x.Type}

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(t1, binop(ir.BinOpAdd, vExpr(x), mkConst(42))),
		},
	}

	matches, err := RecognizeStrengthReduction(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for add with constant, got %d", len(matches))
	}
}

func TestStrengthReduction_EmptyBlock(t *testing.T) {
	block := &ir.BasicBlock{ID: 0, Instructions: nil}
	matches, err := RecognizeStrengthReduction(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty block, got %d", len(matches))
	}
}

// ---------------------------------------------------------------------------
// Compiler Idiom: Memcpy/Memset - additional edge cases
// ---------------------------------------------------------------------------

func TestMemPatterns_SingleLoadStore(t *testing.T) {
	src := mkVar("src", 1)
	dst := mkVar("dst", 1)
	t1 := mkVar("t", 1)

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Load{Dest: t1, Address: vExpr(src), Size: ir.Size8},
			&ir.Store{Address: vExpr(dst), Value: vExpr(t1), Size: ir.Size8},
		},
	}

	matches, err := RecognizeMemPatterns(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match (single-element memcpy), got %d", len(matches))
	}
	if matches[0].Kind != MemPatternMemcpy {
		t.Errorf("expected memcpy pattern, got %v", matches[0].Kind)
	}
}

func TestMemPatterns_EmptyBlock(t *testing.T) {
	block := &ir.BasicBlock{ID: 0, Instructions: nil}
	matches, err := RecognizeMemPatterns(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty block, got %d", len(matches))
	}
}

// ---------------------------------------------------------------------------
// Switch Recovery: additional edge cases
// ---------------------------------------------------------------------------

func TestSwitchRecovery_EmptyBlock(t *testing.T) {
	mem := newTestMemory()
	block := &ir.BasicBlock{ID: 0, Instructions: nil}
	fn := &ir.Function{
		Name:       "test",
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		EntryBlock: 0,
	}

	matches, err := RecoverSwitchStatements(fn, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty block, got %d", len(matches))
	}
}

func TestSwitchRecovery_NoIndirectJump(t *testing.T) {
	mem := newTestMemory()
	x := mkVar("x", 1)
	y := mkVar("y", 1)

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			assign(y, binop(ir.BinOpAdd, vExpr(x), mkConst(1))),
			&ir.Jump{Target: 1},
		},
	}
	fn := &ir.Function{
		Name:       "test",
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		EntryBlock: 0,
	}

	matches, err := RecoverSwitchStatements(fn, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestSwitchRecovery_Dense_16Cases(t *testing.T) {
	mem := newTestMemory()
	selector := u64Var("sel", 1)
	tableBase := uint64(0x400000)

	targets := make([]uint64, 16)
	for i := range targets {
		targets[i] = 0x401000 + uint64(i)*0x100
	}
	mem.writeTable(tableBase, targets)

	fn := buildDenseSwitch(selector, tableBase, 16, mem)
	matches, err := RecoverSwitchStatements(fn, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected at least 1 match for 16-case dense switch")
	}
	if len(matches[0].Cases) != 16 {
		t.Errorf("expected 16 cases, got %d", len(matches[0].Cases))
	}
	if matches[0].Kind != SwitchDense {
		t.Errorf("expected dense switch, got %v", matches[0].Kind)
	}
}

func TestSwitchRecovery_SwitchKindString_Coverage(t *testing.T) {
	tests := []struct {
		kind SwitchKind
		want string
	}{
		{SwitchDense, "dense"},
		{SwitchSparse, "sparse"},
		{SwitchKind(99), "unknown"},
	}
	for _, tt := range tests {
		got := tt.kind.String()
		if got != tt.want {
			t.Errorf("SwitchKind(%d).String() = %q, want %q", tt.kind, got, tt.want)
		}
	}
}

func TestSwitchRecovery_MatchString_Coverage(t *testing.T) {
	m := &SwitchMatch{
		JumpInstrIdx: 0,
		SelectorVar:  mkVar("sel", 1),
		Kind:         SwitchDense,
		Cases: []CaseEntry{
			{CaseValue: 0, TargetAddress: 0x1000},
			{CaseValue: 1, TargetAddress: 0x2000},
		},
		DefaultBlock: 3,
	}
	s := m.String()
	if s == "" {
		t.Error("String() returned empty string")
	}
}
