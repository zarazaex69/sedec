package analysis

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// helpers shared across folding tests
// ============================================================================

// intConst creates an i64 constant expression (reuses the helper from cp tests).
// defined in constant_propagation_test.go as intConst; redeclared here would
// cause a duplicate — we rely on the package-level helper already present.

// vExpr wraps a variable in a VariableExpr pointer.
func vExpr(v ir.Variable) ir.Expression {
	return &ir.VariableExpr{Var: v}
}

// binOp builds a BinaryOp expression.
func binOp(op ir.BinaryOperator, l, r ir.Expression) ir.Expression {
	return &ir.BinaryOp{Op: op, Left: l, Right: r}
}

// unOp builds a UnaryOp expression.
func unOp(op ir.UnaryOperator, operand ir.Expression) ir.Expression {
	return &ir.UnaryOp{Op: op, Operand: operand}
}

// castExpr builds a Cast expression.
func castExpr(expr ir.Expression, t ir.Type) ir.Expression {
	return &ir.Cast{Expr: expr, TargetType: t}
}

// i64c creates an i64 IntConstant (value helper).
func i64c(v int64) ir.Constant {
	return ir.IntConstant{Value: v, Width: ir.Size8, Signed: true}
}

// u8c creates a u8 IntConstant.
func u8c(v int64) ir.Constant {
	return ir.IntConstant{Value: v, Width: ir.Size1, Signed: false}
}

// constExpr wraps a Constant in a ConstantExpr pointer.
func constExpr(c ir.Constant) ir.Expression {
	return &ir.ConstantExpr{Value: c}
}

// ============================================================================
// FoldConstants — nil / empty guard
// ============================================================================

func TestFoldConstants_NilFunction(t *testing.T) {
	result, err := FoldConstants(nil)
	if err == nil {
		t.Fatal("expected error for nil function")
	}
	if result != nil {
		t.Fatal("expected nil result for nil function")
	}
}

func TestFoldConstants_EmptyFunction(t *testing.T) {
	fn := &ir.Function{
		Name:   "empty",
		Blocks: map[ir.BlockID]*ir.BasicBlock{},
	}
	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for empty function")
	}
	if result.FoldedCount != 0 || result.SimplifiedCount != 0 {
		t.Errorf("expected 0 folds/simplifications, got %+v", result)
	}
}

// ============================================================================
// constant evaluation (both operands known at compile time)
// ============================================================================

func TestFoldConstants_BothOperandsConst(t *testing.T) {
	// assign x = 3 + 4  =>  assign x = 7
	x := ssaVar("x", 1)
	fn := singleBlockFn(x,
		binOp(ir.BinOpAdd, constExpr(i64c(3)), constExpr(i64c(4))),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FoldedCount != 1 {
		t.Errorf("expected 1 fold, got %d", result.FoldedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test: type is known
	ce, ok := src.(*ir.ConstantExpr)
	if !ok {
		t.Fatalf("expected ConstantExpr after fold, got %T", src)
	}
	if ce.Value.(ir.IntConstant).Value != 7 { //nolint:forcetypeassert // test: type is known
		t.Errorf("expected 7, got %v", ce.Value)
	}
}

func TestFoldConstants_NestedConstExpr(t *testing.T) {
	// assign x = (2 * 3) + (10 - 4)  =>  assign x = 12
	x := ssaVar("x", 1)
	expr := binOp(ir.BinOpAdd,
		binOp(ir.BinOpMul, constExpr(i64c(2)), constExpr(i64c(3))),
		binOp(ir.BinOpSub, constExpr(i64c(10)), constExpr(i64c(4))),
	)
	fn := singleBlockFn(x, expr)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// two inner folds + one outer fold = 3
	if result.FoldedCount < 3 {
		t.Errorf("expected >= 3 folds, got %d", result.FoldedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test: type is known
	ce, ok := src.(*ir.ConstantExpr)
	if !ok {
		t.Fatalf("expected ConstantExpr, got %T", src)
	}
	if ce.Value.(ir.IntConstant).Value != 12 { //nolint:forcetypeassert // test: type is known
		t.Errorf("expected 12, got %v", ce.Value)
	}
}

// ============================================================================
// overflow semantics preservation
// ============================================================================

func TestFoldConstants_OverflowWraps_U8(t *testing.T) {
	// u8: 255 + 1 = 0 (wraps)
	x := ssaVar("x", 1)
	fn := singleBlockFn(x,
		binOp(ir.BinOpAdd, constExpr(u8c(255)), constExpr(u8c(1))),
	)

	_, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test: type is known
	ce := src.(*ir.ConstantExpr)                            //nolint:forcetypeassert // test: type is known
	if ce.Value.(ir.IntConstant).Value != 0 {               //nolint:forcetypeassert // test: type is known
		t.Errorf("expected 0 (u8 overflow wrap), got %v", ce.Value)
	}
}

func TestFoldConstants_SignedOverflow_I8(t *testing.T) {
	// i8: 127 + 1 = -128 (two's complement wrap)
	i8max := ir.IntConstant{Value: 127, Width: ir.Size1, Signed: true}
	one := ir.IntConstant{Value: 1, Width: ir.Size1, Signed: true}
	x := ssaVar("x", 1)
	fn := singleBlockFn(x,
		binOp(ir.BinOpAdd, constExpr(i8max), constExpr(one)),
	)

	_, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test: type is known
	ce := src.(*ir.ConstantExpr)                            //nolint:forcetypeassert // test: type is known
	if ce.Value.(ir.IntConstant).Value != -128 {            //nolint:forcetypeassert // test: type is known
		t.Errorf("expected -128 (i8 overflow wrap), got %v", ce.Value)
	}
}

// ============================================================================
// algebraic identity: additive identity (x + 0 = x, 0 + x = x)
// ============================================================================

func TestFoldConstants_AddZeroRight(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpAdd, vExpr(x), constExpr(i64c(0))),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification, got %d", result.SimplifiedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	ve, ok := src.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("expected VariableExpr after x+0 simplification, got %T", src)
	}
	if ve.Var.Name != "x" {
		t.Errorf("expected x, got %s", ve.Var.Name)
	}
}

func TestFoldConstants_AddZeroLeft(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpAdd, constExpr(i64c(0)), vExpr(x)),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification, got %d", result.SimplifiedCount)
	}
}

// ============================================================================
// algebraic identity: multiplicative identity (x * 1 = x, 1 * x = x)
// ============================================================================

func TestFoldConstants_MulOneRight(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpMul, vExpr(x), constExpr(i64c(1))),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification, got %d", result.SimplifiedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if _, ok := src.(*ir.VariableExpr); !ok {
		t.Fatalf("expected VariableExpr after x*1, got %T", src)
	}
}

func TestFoldConstants_MulOneLeft(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpMul, constExpr(i64c(1)), vExpr(x)),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification, got %d", result.SimplifiedCount)
	}
}

// ============================================================================
// algebraic identity: absorbing element (x * 0 = 0, x & 0 = 0)
// ============================================================================

func TestFoldConstants_MulZeroRight(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpMul, vExpr(x), constExpr(i64c(0))),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification, got %d", result.SimplifiedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	ce, ok := src.(*ir.ConstantExpr)
	if !ok {
		t.Fatalf("expected ConstantExpr (zero) after x*0, got %T", src)
	}
	if ce.Value.(ir.IntConstant).Value != 0 { //nolint:forcetypeassert // test: value is always IntConstant here
		t.Errorf("expected 0, got %v", ce.Value)
	}
}

func TestFoldConstants_AndZero(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpAnd, vExpr(x), constExpr(i64c(0))),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification, got %d", result.SimplifiedCount)
	}
}

// ============================================================================
// algebraic identity: x - x = 0, x ^ x = 0, x & x = x, x | x = x
// ============================================================================

func TestFoldConstants_SubSelf(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpSub, vExpr(x), vExpr(x)),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification, got %d", result.SimplifiedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	ce, ok := src.(*ir.ConstantExpr)
	if !ok {
		t.Fatalf("expected ConstantExpr (zero) after x-x, got %T", src)
	}
	if ce.Value.(ir.IntConstant).Value != 0 { //nolint:forcetypeassert // test: value is always IntConstant here
		t.Errorf("expected 0, got %v", ce.Value)
	}
}

func TestFoldConstants_XorSelf(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpXor, vExpr(x), vExpr(x)),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification, got %d", result.SimplifiedCount)
	}
}

func TestFoldConstants_AndSelf(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpAnd, vExpr(x), vExpr(x)),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification, got %d", result.SimplifiedCount)
	}

	// result should be x itself
	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if _, ok := src.(*ir.VariableExpr); !ok {
		t.Fatalf("expected VariableExpr after x&x, got %T", src)
	}
}

// ============================================================================
// algebraic identity: double negation elimination
// ============================================================================

func TestFoldConstants_DoubleNeg(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	// y = -(-x)  =>  y = x
	fn := singleBlockFn(y,
		unOp(ir.UnOpNeg, unOp(ir.UnOpNeg, vExpr(x))),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification, got %d", result.SimplifiedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if _, ok := src.(*ir.VariableExpr); !ok {
		t.Fatalf("expected VariableExpr after -(-x), got %T", src)
	}
}

func TestFoldConstants_DoubleBitwiseNot(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	// y = ~~x  =>  y = x
	fn := singleBlockFn(y,
		unOp(ir.UnOpNot, unOp(ir.UnOpNot, vExpr(x))),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification, got %d", result.SimplifiedCount)
	}
}

func TestFoldConstants_DoubleLogicalNot(t *testing.T) {
	b := ssaVar("b", 1)
	c := ssaVar("c", 1)
	// c = !!b  =>  c = b
	fn := singleBlockFn(c,
		unOp(ir.UnOpLogicalNot, unOp(ir.UnOpLogicalNot, vExpr(b))),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification, got %d", result.SimplifiedCount)
	}
}

// ============================================================================
// unary constant folding
// ============================================================================

func TestFoldConstants_UnaryNegConst(t *testing.T) {
	x := ssaVar("x", 1)
	fn := singleBlockFn(x, unOp(ir.UnOpNeg, constExpr(i64c(42))))

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FoldedCount != 1 {
		t.Errorf("expected 1 fold, got %d", result.FoldedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	ce := src.(*ir.ConstantExpr)                            //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if ce.Value.(ir.IntConstant).Value != -42 {             //nolint:forcetypeassert // test: value is always IntConstant here
		t.Errorf("expected -42, got %v", ce.Value)
	}
}

func TestFoldConstants_UnaryNotConst(t *testing.T) {
	// ~0 for i64 = -1
	x := ssaVar("x", 1)
	fn := singleBlockFn(x, unOp(ir.UnOpNot, constExpr(i64c(0))))

	_, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	ce := src.(*ir.ConstantExpr)                            //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if ce.Value.(ir.IntConstant).Value != -1 {              //nolint:forcetypeassert // test: value is always IntConstant here
		t.Errorf("expected -1, got %v", ce.Value)
	}
}

// ============================================================================
// cast folding
// ============================================================================

func TestFoldConstants_CastConstTruncates(t *testing.T) {
	// (u8)(0x1FF) = 0xFF
	x := ssaVar("x", 1)
	fn := singleBlockFn(x,
		castExpr(constExpr(ir.IntConstant{Value: 0x1FF, Width: ir.Size8, Signed: false}),
			ir.IntType{Width: ir.Size1, Signed: false}),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FoldedCount != 1 {
		t.Errorf("expected 1 fold, got %d", result.FoldedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	ce := src.(*ir.ConstantExpr)                            //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if ce.Value.(ir.IntConstant).Value != 0xFF {            //nolint:forcetypeassert // test: value is always IntConstant here
		t.Errorf("expected 0xFF, got %v", ce.Value)
	}
}

func TestFoldConstants_IdentityCast(t *testing.T) {
	// (i64)(x) where x is already i64 => x
	x := ssaVar("x", 1)
	x.Type = ir.IntType{Width: ir.Size8, Signed: true}
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		castExpr(vExpr(x), ir.IntType{Width: ir.Size8, Signed: true}),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for identity cast, got %d", result.SimplifiedCount)
	}
}

// ============================================================================
// shift identities
// ============================================================================

func TestFoldConstants_ShiftByZero(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpShl, vExpr(x), constExpr(i64c(0))),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for x<<0, got %d", result.SimplifiedCount)
	}
}

func TestFoldConstants_ZeroShiftedLeft(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpShl, constExpr(i64c(0)), vExpr(x)),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for 0<<x, got %d", result.SimplifiedCount)
	}
}

// ============================================================================
// logical short-circuit identities
// ============================================================================

func TestFoldConstants_LogicalAndFalse(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	// y = x && false  =>  y = false
	fn := singleBlockFn(y,
		binOp(ir.BinOpLogicalAnd, vExpr(x), constExpr(ir.BoolConstant{Value: false})),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification, got %d", result.SimplifiedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	ce, ok := src.(*ir.ConstantExpr)
	if !ok {
		t.Fatalf("expected ConstantExpr, got %T", src)
	}
	if ce.Value.(ir.BoolConstant).Value != false { //nolint:forcetypeassert // test: value is always BoolConstant here
		t.Error("expected false")
	}
}

func TestFoldConstants_LogicalOrTrue(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	// y = x || true  =>  y = true
	fn := singleBlockFn(y,
		binOp(ir.BinOpLogicalOr, vExpr(x), constExpr(ir.BoolConstant{Value: true})),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification, got %d", result.SimplifiedCount)
	}
}

// ============================================================================
// idempotency: running twice produces same result
// ============================================================================

func TestFoldConstants_Idempotent(t *testing.T) {
	y := ssaVar("y", 1)
	// y = (3 + 4) * 2
	fn := singleBlockFn(y,
		binOp(ir.BinOpMul,
			binOp(ir.BinOpAdd, constExpr(i64c(3)), constExpr(i64c(4))),
			constExpr(i64c(2)),
		),
	)

	r1, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("first fold failed: %v", err)
	}
	r2, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("second fold failed: %v", err)
	}

	// second pass should find nothing new to fold
	if r2.FoldedCount != 0 {
		t.Errorf("second pass should fold 0, got %d (first pass folded %d)", r2.FoldedCount, r1.FoldedCount)
	}
}

// ============================================================================
// division by zero: must not fold, must not panic
// ============================================================================

func TestFoldConstants_DivByZeroNotFolded(t *testing.T) {
	x := ssaVar("x", 1)
	fn := singleBlockFn(x,
		binOp(ir.BinOpDiv, constExpr(i64c(10)), constExpr(i64c(0))),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// division by zero must NOT be folded (undefined behavior)
	if result.FoldedCount != 0 {
		t.Errorf("expected 0 folds for div-by-zero, got %d", result.FoldedCount)
	}

	// expression must remain a BinaryOp, not a ConstantExpr
	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if _, ok := src.(*ir.ConstantExpr); ok {
		t.Fatal("div-by-zero must not be folded to a constant")
	}
}

// ============================================================================
// store and branch instructions are also folded
// ============================================================================

func TestFoldConstants_StoreAddressAndValue(t *testing.T) {
	// store.8 (1000 + 8), (2 * 3)
	fn := &ir.Function{
		Name: "store_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Store{
						Address: binOp(ir.BinOpAdd, constExpr(i64c(1000)), constExpr(i64c(8))),
						Value:   binOp(ir.BinOpMul, constExpr(i64c(2)), constExpr(i64c(3))),
						Size:    ir.Size8,
					},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FoldedCount != 2 {
		t.Errorf("expected 2 folds (address + value), got %d", result.FoldedCount)
	}

	store := fn.Blocks[0].Instructions[0].(*ir.Store) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	addrCE, ok := store.Address.(*ir.ConstantExpr)
	if !ok {
		t.Fatalf("expected ConstantExpr for address, got %T", store.Address)
	}
	if addrCE.Value.(ir.IntConstant).Value != 1008 { //nolint:forcetypeassert // test: value is always IntConstant here
		t.Errorf("expected address 1008, got %v", addrCE.Value)
	}
	valCE, ok := store.Value.(*ir.ConstantExpr)
	if !ok {
		t.Fatalf("expected ConstantExpr for value, got %T", store.Value)
	}
	if valCE.Value.(ir.IntConstant).Value != 6 { //nolint:forcetypeassert // test: value is always IntConstant here
		t.Errorf("expected value 6, got %v", valCE.Value)
	}
}

func TestFoldConstants_BranchCondition(t *testing.T) {
	// branch (3 == 3) -> bb1, bb2  =>  branch true -> bb1, bb2
	fn := &ir.Function{
		Name: "branch_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Branch{
						Condition:   binOp(ir.BinOpEq, constExpr(i64c(3)), constExpr(i64c(3))),
						TrueTarget:  1,
						FalseTarget: 2,
					},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FoldedCount != 1 {
		t.Errorf("expected 1 fold, got %d", result.FoldedCount)
	}

	branch := fn.Blocks[0].Instructions[0].(*ir.Branch) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	ce, ok := branch.Condition.(*ir.ConstantExpr)
	if !ok {
		t.Fatalf("expected ConstantExpr for condition, got %T", branch.Condition)
	}
	if ce.Value.(ir.BoolConstant).Value != true { //nolint:forcetypeassert // test: value is always BoolConstant here
		t.Error("expected true condition after 3==3 fold")
	}
}

// ============================================================================
// test helper: build a single-block function with one assign instruction
// ============================================================================

// singleBlockFn creates a minimal function with one block containing
// a single assign instruction: dest = expr.
func singleBlockFn(dest ir.Variable, expr ir.Expression) *ir.Function {
	return &ir.Function{
		Name: "test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: dest, Source: expr},
				},
			},
		},
		EntryBlock: 0,
	}
}

func TestFoldConstants_CallTargetFolded(t *testing.T) {
	fn := &ir.Function{
		Name: "call_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Call{
						Target: binOp(ir.BinOpAdd, constExpr(i64c(100)), constExpr(i64c(200))),
					},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FoldedCount != 1 {
		t.Errorf("expected 1 fold for call target, got %d", result.FoldedCount)
	}

	call, ok := fn.Blocks[0].Instructions[0].(*ir.Call)
	if !ok {
		t.Fatalf("expected *ir.Call, got %T", fn.Blocks[0].Instructions[0])
	}
	ce, ok := call.Target.(*ir.ConstantExpr)
	if !ok {
		t.Fatalf("expected ConstantExpr for call target, got %T", call.Target)
	}
	ic, ok := ce.Value.(ir.IntConstant)
	if !ok {
		t.Fatalf("expected IntConstant, got %T", ce.Value)
	}
	if ic.Value != 300 {
		t.Errorf("expected 300, got %v", ce.Value)
	}
}

func TestFoldConstants_LoadAddressFolded(t *testing.T) {
	x := ssaVar("x", 1)
	fn := &ir.Function{
		Name: "load_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Load{
						Dest:    x,
						Address: binOp(ir.BinOpAdd, constExpr(i64c(500)), constExpr(i64c(8))),
						Size:    ir.Size8,
					},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FoldedCount != 1 {
		t.Errorf("expected 1 fold for load address, got %d", result.FoldedCount)
	}

	load, ok := fn.Blocks[0].Instructions[0].(*ir.Load)
	if !ok {
		t.Fatalf("expected *ir.Load, got %T", fn.Blocks[0].Instructions[0])
	}
	ce, ok := load.Address.(*ir.ConstantExpr)
	if !ok {
		t.Fatalf("expected ConstantExpr for load address, got %T", load.Address)
	}
	ic, ok := ce.Value.(ir.IntConstant)
	if !ok {
		t.Fatalf("expected IntConstant, got %T", ce.Value)
	}
	if ic.Value != 508 {
		t.Errorf("expected 508, got %v", ce.Value)
	}
}

func TestFoldConstants_AndAllOnes(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	allOnes := ir.IntConstant{Value: -1, Width: ir.Size8, Signed: true}
	fn := singleBlockFn(y,
		binOp(ir.BinOpAnd, vExpr(x), constExpr(allOnes)),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for x & ~0, got %d", result.SimplifiedCount)
	}

	assign, ok := fn.Blocks[0].Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", fn.Blocks[0].Instructions[0])
	}
	src := assign.Source
	if _, ok := src.(*ir.VariableExpr); !ok {
		t.Fatalf("expected VariableExpr after x & ~0, got %T", src)
	}
}

func TestFoldConstants_OrAllOnes(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	allOnes := ir.IntConstant{Value: -1, Width: ir.Size8, Signed: true}
	fn := singleBlockFn(y,
		binOp(ir.BinOpOr, vExpr(x), constExpr(allOnes)),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for x | ~0, got %d", result.SimplifiedCount)
	}

	assign2, ok := fn.Blocks[0].Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", fn.Blocks[0].Instructions[0])
	}
	src2 := assign2.Source
	ce, ok := src2.(*ir.ConstantExpr)
	if !ok {
		t.Fatalf("expected ConstantExpr (~0) after x | ~0, got %T", src2)
	}
	ic, ok := ce.Value.(ir.IntConstant)
	if !ok {
		t.Fatalf("expected IntConstant, got %T", ce.Value)
	}
	if ic.Value != -1 {
		t.Errorf("expected -1, got %v", ce.Value)
	}
}

func TestFoldConstants_OrSelf(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpOr, vExpr(x), vExpr(x)),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for x|x, got %d", result.SimplifiedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test helper
	if _, ok := src.(*ir.VariableExpr); !ok {
		t.Fatalf("expected VariableExpr after x|x, got %T", src)
	}
}

func TestFoldConstants_DivByOne(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpDiv, vExpr(x), constExpr(i64c(1))),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for x/1, got %d", result.SimplifiedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test helper
	if _, ok := src.(*ir.VariableExpr); !ok {
		t.Fatalf("expected VariableExpr after x/1, got %T", src)
	}
}

func TestFoldConstants_XorZero(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpXor, vExpr(x), constExpr(i64c(0))),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for x^0, got %d", result.SimplifiedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test helper
	if _, ok := src.(*ir.VariableExpr); !ok {
		t.Fatalf("expected VariableExpr after x^0, got %T", src)
	}
}

func TestFoldConstants_OrZero(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpOr, vExpr(x), constExpr(i64c(0))),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for x|0, got %d", result.SimplifiedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test helper
	if _, ok := src.(*ir.VariableExpr); !ok {
		t.Fatalf("expected VariableExpr after x|0, got %T", src)
	}
}

func TestFoldConstants_SubZero(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpSub, vExpr(x), constExpr(i64c(0))),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for x-0, got %d", result.SimplifiedCount)
	}
}

func TestFoldConstants_ShrByZero(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpShr, vExpr(x), constExpr(i64c(0))),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for x>>0, got %d", result.SimplifiedCount)
	}
}

func TestFoldConstants_SarByZero(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpSar, vExpr(x), constExpr(i64c(0))),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for x>>>0, got %d", result.SimplifiedCount)
	}
}

func TestFoldConstants_LogicalNotConst(t *testing.T) {
	x := ssaVar("x", 1)
	fn := singleBlockFn(x,
		unOp(ir.UnOpLogicalNot, constExpr(ir.BoolConstant{Value: true})),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FoldedCount != 1 {
		t.Errorf("expected 1 fold, got %d", result.FoldedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test helper
	ce := src.(*ir.ConstantExpr)                            //nolint:forcetypeassert // test helper
	if ce.Value.(ir.BoolConstant).Value != false {          //nolint:forcetypeassert // test helper
		t.Error("expected false after !true")
	}
}

func TestFoldConstants_MulZeroLeft(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpMul, constExpr(i64c(0)), vExpr(x)),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for 0*x, got %d", result.SimplifiedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test helper
	ce, ok := src.(*ir.ConstantExpr)
	if !ok {
		t.Fatalf("expected ConstantExpr after 0*x, got %T", src)
	}
	if ce.Value.(ir.IntConstant).Value != 0 { //nolint:forcetypeassert // test helper
		t.Errorf("expected 0, got %v", ce.Value)
	}
}

func TestFoldConstants_AndZeroLeft(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpAnd, constExpr(i64c(0)), vExpr(x)),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for 0&x, got %d", result.SimplifiedCount)
	}
}

func TestFoldConstants_UDivByOne(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpUDiv, vExpr(x), constExpr(ir.IntConstant{Value: 1, Width: ir.Size8, Signed: false})),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for x udiv 1, got %d", result.SimplifiedCount)
	}
}

func TestFoldConstants_LogicalAndTrue(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpLogicalAnd, constExpr(ir.BoolConstant{Value: true}), vExpr(x)),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for true&&x, got %d", result.SimplifiedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test helper
	if _, ok := src.(*ir.VariableExpr); !ok {
		t.Fatalf("expected VariableExpr after true&&x, got %T", src)
	}
}

func TestFoldConstants_LogicalOrFalse(t *testing.T) {
	x := ssaVar("x", 1)
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpLogicalOr, constExpr(ir.BoolConstant{Value: false}), vExpr(x)),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for false||x, got %d", result.SimplifiedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test helper
	if _, ok := src.(*ir.VariableExpr); !ok {
		t.Fatalf("expected VariableExpr after false||x, got %T", src)
	}
}

func TestFoldConstants_ValueTypeBinaryOp(t *testing.T) {
	x := ssaVar("x", 1)
	fn := &ir.Function{
		Name: "value_type_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   x,
						Source: ir.BinaryOp{Op: ir.BinOpAdd, Left: constExpr(i64c(5)), Right: constExpr(i64c(3))},
					},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FoldedCount != 1 {
		t.Errorf("expected 1 fold for value-type BinaryOp, got %d", result.FoldedCount)
	}
}

func TestFoldConstants_ValueTypeUnaryOp(t *testing.T) {
	x := ssaVar("x", 1)
	fn := &ir.Function{
		Name: "value_type_unary_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   x,
						Source: ir.UnaryOp{Op: ir.UnOpNeg, Operand: constExpr(i64c(7))},
					},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FoldedCount != 1 {
		t.Errorf("expected 1 fold for value-type UnaryOp, got %d", result.FoldedCount)
	}
}

func TestFoldConstants_ValueTypeCast(t *testing.T) {
	x := ssaVar("x", 1)
	fn := &ir.Function{
		Name: "value_type_cast_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest: x,
						Source: ir.Cast{
							Expr:       constExpr(i64c(300)),
							TargetType: ir.IntType{Width: ir.Size1, Signed: false},
						},
					},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FoldedCount != 1 {
		t.Errorf("expected 1 fold for value-type Cast, got %d", result.FoldedCount)
	}
}

func TestFoldConstants_JumpNotModified(t *testing.T) {
	fn := &ir.Function{
		Name: "jump_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Jump{Target: 1},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FoldedCount != 0 && result.SimplifiedCount != 0 {
		t.Errorf("expected no changes for jump, got folds=%d simplifications=%d",
			result.FoldedCount, result.SimplifiedCount)
	}
}

func TestFoldConstants_ReturnNotModified(t *testing.T) {
	fn := &ir.Function{
		Name: "return_test",
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

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FoldedCount != 0 && result.SimplifiedCount != 0 {
		t.Errorf("expected no changes for return, got folds=%d simplifications=%d",
			result.FoldedCount, result.SimplifiedCount)
	}
}

func TestFoldConstants_PhiNotModified(t *testing.T) {
	x := ssaVar("x", 1)
	fn := &ir.Function{
		Name: "phi_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Phi{
						Dest: x,
						Sources: []ir.PhiSource{
							{Block: 1, Var: ssaVar("a", 1)},
							{Block: 2, Var: ssaVar("b", 1)},
						},
					},
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FoldedCount != 0 && result.SimplifiedCount != 0 {
		t.Errorf("expected no changes for phi, got folds=%d simplifications=%d",
			result.FoldedCount, result.SimplifiedCount)
	}
}

func TestFoldConstants_SubSelfFloat(t *testing.T) {
	x := ir.Variable{Name: "x", Type: ir.FloatType{Width: ir.Size8}, Version: 1}
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpSub, vExpr(x), vExpr(x)),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for float x-x, got %d", result.SimplifiedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test helper
	ce, ok := src.(*ir.ConstantExpr)
	if !ok {
		t.Fatalf("expected ConstantExpr (zero) after float x-x, got %T", src)
	}
	fc, ok := ce.Value.(ir.FloatConstant)
	if !ok {
		t.Fatalf("expected FloatConstant, got %T", ce.Value)
	}
	if fc.Value != 0.0 {
		t.Errorf("expected 0.0, got %v", fc.Value)
	}
}

func TestFoldConstants_XorSelfBool(t *testing.T) {
	x := ir.Variable{Name: "x", Type: ir.BoolType{}, Version: 1}
	y := ssaVar("y", 1)
	fn := singleBlockFn(y,
		binOp(ir.BinOpXor, vExpr(x), vExpr(x)),
	)

	result, err := FoldConstants(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SimplifiedCount != 1 {
		t.Errorf("expected 1 simplification for bool x^x, got %d", result.SimplifiedCount)
	}

	src := fn.Blocks[0].Instructions[0].(*ir.Assign).Source //nolint:forcetypeassert // test helper
	ce, ok := src.(*ir.ConstantExpr)
	if !ok {
		t.Fatalf("expected ConstantExpr after bool x^x, got %T", src)
	}
	bc, ok := ce.Value.(ir.BoolConstant)
	if !ok {
		t.Fatalf("expected BoolConstant, got %T", ce.Value)
	}
	if bc.Value != false {
		t.Errorf("expected false, got %v", bc.Value)
	}
}
