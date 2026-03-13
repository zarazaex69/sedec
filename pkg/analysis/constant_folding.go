package analysis

import (
	"github.com/zarazaex69/sedec/pkg/ir"
)

// FoldingResult holds statistics from a constant folding pass.
type FoldingResult struct {
	// FoldedCount is the number of expressions reduced to constants.
	FoldedCount int
	// SimplifiedCount is the number of algebraic simplifications applied
	// (identity elements, absorbing elements, etc.).
	SimplifiedCount int
}

// FoldConstants performs a single-pass constant folding and algebraic
// simplification over all instructions in a function.
//
// this pass is purely structural: it rewrites expressions bottom-up without
// any data-flow lattice. it is complementary to SCCP (PropagateConstants):
//   - SCCP propagates constants through def-use chains across blocks
//   - FoldConstants simplifies constant sub-expressions and algebraic identities
//     within individual expressions, regardless of variable values
//
// the pass is idempotent: running it twice produces the same result.
// it should be run after PropagateConstants to collapse newly-introduced
// constant sub-expressions.
//
// algebraic identities applied (preserving exact overflow semantics):
//
//	x + 0  = x          x - 0  = x
//	x * 1  = x          x / 1  = x
//	x * 0  = 0          x & 0  = 0
//	x | 0  = x          x ^ 0  = x
//	x & x  = x          x | x  = x
//	x ^ x  = 0          x - x  = 0
//	x << 0 = x          x >> 0 = x
//	0 << x = 0          0 >> x = 0
//	!!b    = b          ~~x    = x
//	-(-x)  = x
func FoldConstants(function *ir.Function) (*FoldingResult, error) {
	if function == nil {
		return nil, nil
	}

	result := &FoldingResult{}
	folder := &constantFolder{result: result}

	for _, block := range function.Blocks {
		for i, instr := range block.Instructions {
			block.Instructions[i] = folder.foldInstruction(instr)
		}
	}

	return result, nil
}

// constantFolder carries folding state across the recursive expression walk.
type constantFolder struct {
	result *FoldingResult
}

// foldInstruction rewrites a single instruction, folding its expressions.
func (f *constantFolder) foldInstruction(instr ir.IRInstruction) ir.IRInstruction {
	switch i := instr.(type) {
	case *ir.Assign:
		i.Source = f.foldExpr(i.Source)
		return i
	case *ir.Load:
		i.Address = f.foldExpr(i.Address)
		return i
	case *ir.Store:
		i.Address = f.foldExpr(i.Address)
		i.Value = f.foldExpr(i.Value)
		return i
	case *ir.Branch:
		i.Condition = f.foldExpr(i.Condition)
		return i
	case *ir.Call:
		i.Target = f.foldExpr(i.Target)
		return i
	default:
		// phi, jump, return: no foldable sub-expressions
		return instr
	}
}

// foldExpr recursively folds an expression bottom-up.
// returns the (possibly new) expression after folding.
func (f *constantFolder) foldExpr(expr ir.Expression) ir.Expression {
	if expr == nil {
		return nil
	}

	switch e := expr.(type) {
	case *ir.BinaryOp:
		return f.foldBinaryOp(e)
	case ir.BinaryOp:
		ep := e
		return f.foldBinaryOp(&ep)

	case *ir.UnaryOp:
		return f.foldUnaryOp(e)
	case ir.UnaryOp:
		ep := e
		return f.foldUnaryOp(&ep)

	case *ir.Cast:
		return f.foldCastExpr(e)
	case ir.Cast:
		ep := e
		return f.foldCastExpr(&ep)

	default:
		// ConstantExpr, VariableExpr: already in normal form
		return expr
	}
}

// foldBinaryOp folds a binary operation after recursively folding its operands.
// applies constant evaluation first, then algebraic simplifications.
func (f *constantFolder) foldBinaryOp(e *ir.BinaryOp) ir.Expression {
	// fold operands first (bottom-up)
	e.Left = f.foldExpr(e.Left)
	e.Right = f.foldExpr(e.Right)

	lc, lIsConst := extractConstant(e.Left)
	rc, rIsConst := extractConstant(e.Right)

	// case 1: both operands are constants — evaluate at compile time
	if lIsConst && rIsConst {
		if folded, ok := foldBinaryOp(e.Op, lc, rc); ok {
			f.result.FoldedCount++
			return &ir.ConstantExpr{Value: folded}
		}
	}

	// case 2: one operand is constant — apply algebraic identities
	if simplified, ok := f.applyAlgebraicIdentity(e.Op, e.Left, e.Right, lc, rc, lIsConst, rIsConst); ok {
		f.result.SimplifiedCount++
		return simplified
	}

	// case 3: same variable on both sides — x op x identities
	if simplified, ok := f.applySameOperandIdentity(e.Op, e.Left, e.Right); ok {
		f.result.SimplifiedCount++
		return simplified
	}

	return e
}

// foldUnaryOp folds a unary operation after folding its operand.
// also eliminates double negation/not patterns.
func (f *constantFolder) foldUnaryOp(e *ir.UnaryOp) ir.Expression {
	e.Operand = f.foldExpr(e.Operand)

	// case 1: operand is a constant — evaluate at compile time
	if c, ok := extractConstant(e.Operand); ok {
		if folded, ok := foldUnaryOp(e.Op, c); ok {
			f.result.FoldedCount++
			return &ir.ConstantExpr{Value: folded}
		}
	}

	// case 2: double negation elimination
	// -(-x) = x,  ~~x = x,  !!b = b
	if inner, ok := e.Operand.(*ir.UnaryOp); ok {
		if inner.Op == e.Op && (e.Op == ir.UnOpNeg || e.Op == ir.UnOpNot || e.Op == ir.UnOpLogicalNot) {
			f.result.SimplifiedCount++
			return inner.Operand
		}
	}

	return e
}

// foldCastExpr folds a cast expression after folding its operand.
func (f *constantFolder) foldCastExpr(e *ir.Cast) ir.Expression {
	e.Expr = f.foldExpr(e.Expr)

	// evaluate cast on constant operand
	if c, ok := extractConstant(e.Expr); ok {
		if folded, ok := foldCast(c, e.TargetType); ok {
			f.result.FoldedCount++
			return &ir.ConstantExpr{Value: folded}
		}
	}

	// identity cast: cast to same type is a no-op
	if typesEqual(e.Expr.Type(), e.TargetType) {
		f.result.SimplifiedCount++
		return e.Expr
	}

	return e
}

// applyAlgebraicIdentity applies single-operand algebraic simplifications.
// returns (simplified, true) if a simplification was applied.
//
// identities applied:
//
//	x + 0 = x,  0 + x = x
//	x - 0 = x
//	x * 1 = x,  1 * x = x
//	x * 0 = 0,  0 * x = 0
//	x / 1 = x
//	x & 0 = 0,  0 & x = 0
//	x | 0 = x,  0 | x = x
//	x ^ 0 = x,  0 ^ x = x
//	x << 0 = x, x >> 0 = x, x >>> 0 = x
//	0 << x = 0, 0 >> x = 0, 0 >>> x = 0
//	false && x = false, x && false = false
//	true  || x = true,  x || true  = true
//	true  && x = x,     x && true  = x
//	false || x = x,     x || false = x
func (f *constantFolder) applyAlgebraicIdentity(
	op ir.BinaryOperator,
	left, right ir.Expression,
	lc, rc ir.Constant,
	lIsConst, rIsConst bool,
) (ir.Expression, bool) {
	switch op {
	case ir.BinOpAdd:
		if rIsConst && isIntZero(rc) {
			return left, true // x + 0 = x
		}
		if lIsConst && isIntZero(lc) {
			return right, true // 0 + x = x
		}

	case ir.BinOpSub:
		if rIsConst && isIntZero(rc) {
			return left, true // x - 0 = x
		}

	case ir.BinOpMul:
		if rIsConst && isIntOne(rc) {
			return left, true // x * 1 = x
		}
		if lIsConst && isIntOne(lc) {
			return right, true // 1 * x = x
		}
		if rIsConst && isIntZero(rc) {
			return right, true // x * 0 = 0 (return the zero constant)
		}
		if lIsConst && isIntZero(lc) {
			return left, true // 0 * x = 0
		}

	case ir.BinOpDiv, ir.BinOpUDiv:
		if rIsConst && isIntOne(rc) {
			return left, true // x / 1 = x
		}

	case ir.BinOpAnd:
		if rIsConst && isIntZero(rc) {
			return right, true // x & 0 = 0
		}
		if lIsConst && isIntZero(lc) {
			return left, true // 0 & x = 0
		}
		if rIsConst && isIntAllOnes(rc) {
			return left, true // x & ~0 = x
		}
		if lIsConst && isIntAllOnes(lc) {
			return right, true // ~0 & x = x
		}

	case ir.BinOpOr:
		if rIsConst && isIntZero(rc) {
			return left, true // x | 0 = x
		}
		if lIsConst && isIntZero(lc) {
			return right, true // 0 | x = x
		}
		if rIsConst && isIntAllOnes(rc) {
			return right, true // x | ~0 = ~0
		}
		if lIsConst && isIntAllOnes(lc) {
			return left, true // ~0 | x = ~0
		}

	case ir.BinOpXor:
		if rIsConst && isIntZero(rc) {
			return left, true // x ^ 0 = x
		}
		if lIsConst && isIntZero(lc) {
			return right, true // 0 ^ x = x
		}

	case ir.BinOpShl, ir.BinOpShr, ir.BinOpSar:
		if rIsConst && isIntZero(rc) {
			return left, true // x << 0 = x
		}
		if lIsConst && isIntZero(lc) {
			return left, true // 0 << x = 0
		}

	case ir.BinOpLogicalAnd:
		if rIsConst {
			if b, ok := rc.(ir.BoolConstant); ok {
				if !b.Value {
					return right, true // x && false = false
				}
				return left, true // x && true = x
			}
		}
		if lIsConst {
			if b, ok := lc.(ir.BoolConstant); ok {
				if !b.Value {
					return left, true // false && x = false
				}
				return right, true // true && x = x
			}
		}

	case ir.BinOpLogicalOr:
		if rIsConst {
			if b, ok := rc.(ir.BoolConstant); ok {
				if b.Value {
					return right, true // x || true = true
				}
				return left, true // x || false = x
			}
		}
		if lIsConst {
			if b, ok := lc.(ir.BoolConstant); ok {
				if b.Value {
					return left, true // true || x = true
				}
				return right, true // false || x = x
			}
		}
	}

	return nil, false
}

// applySameOperandIdentity handles x op x patterns.
// returns (simplified, true) if a simplification was applied.
//
// identities:
//
//	x - x = 0
//	x ^ x = 0
//	x & x = x
//	x | x = x
func (f *constantFolder) applySameOperandIdentity(
	op ir.BinaryOperator,
	left, right ir.Expression,
) (ir.Expression, bool) {
	if !expressionsEqual(left, right) {
		return nil, false
	}

	switch op {
	case ir.BinOpSub:
		// x - x = 0; preserve width from left operand type
		if zero := makeZeroForType(left.Type()); zero != nil {
			return &ir.ConstantExpr{Value: zero}, true
		}

	case ir.BinOpXor:
		// x ^ x = 0
		if zero := makeZeroForType(left.Type()); zero != nil {
			return &ir.ConstantExpr{Value: zero}, true
		}

	case ir.BinOpAnd, ir.BinOpOr:
		// x & x = x,  x | x = x
		return left, true
	}

	return nil, false
}

// ============================================================================
// helpers
// ============================================================================

// extractConstant returns the constant value from a ConstantExpr, or (nil, false).
func extractConstant(expr ir.Expression) (ir.Constant, bool) {
	switch e := expr.(type) {
	case *ir.ConstantExpr:
		return e.Value, true
	case ir.ConstantExpr:
		return e.Value, true
	}
	return nil, false
}

// isIntZero reports whether a constant is an integer or bool zero.
func isIntZero(c ir.Constant) bool {
	switch cv := c.(type) {
	case ir.IntConstant:
		return cv.Value == 0
	case ir.BoolConstant:
		return !cv.Value
	case ir.FloatConstant:
		return cv.Value == 0.0
	}
	return false
}

// isIntOne reports whether a constant is an integer one.
func isIntOne(c ir.Constant) bool {
	switch cv := c.(type) {
	case ir.IntConstant:
		return cv.Value == 1
	case ir.FloatConstant:
		return cv.Value == 1.0
	}
	return false
}

// isIntAllOnes reports whether a constant is the all-ones bitmask for its width.
// e.g., 0xFF for u8, 0xFFFFFFFF for u32, -1 for signed integers.
func isIntAllOnes(c ir.Constant) bool {
	ic, ok := c.(ir.IntConstant)
	if !ok {
		return false
	}
	mask := widthMask(ic.Width)
	return uint64(ic.Value)&mask == mask
}

// expressionsEqual performs structural equality on two expressions.
// only handles the common case of two VariableExpr references.
// complex expressions (BinaryOp, etc.) are conservatively considered unequal
// to avoid incorrect elimination of side-effecting sub-expressions.
func expressionsEqual(a, b ir.Expression) bool {
	av, aOK := toVarExpr(a)
	bv, bOK := toVarExpr(b)
	if aOK && bOK {
		return av.Name == bv.Name && av.Version == bv.Version
	}
	// conservative: do not assume equality for complex expressions
	return false
}

// toVarExpr extracts the Variable from a VariableExpr (pointer or value).
func toVarExpr(expr ir.Expression) (ir.Variable, bool) {
	switch e := expr.(type) {
	case *ir.VariableExpr:
		return e.Var, true
	case ir.VariableExpr:
		return e.Var, true
	}
	return ir.Variable{}, false
}

// makeZeroForType creates a zero constant appropriate for the given type.
// returns nil for types where zero is not well-defined (void, function, etc.).
func makeZeroForType(t ir.Type) ir.Constant {
	switch tt := t.(type) {
	case ir.IntType:
		return ir.IntConstant{Value: 0, Width: tt.Width, Signed: tt.Signed}
	case ir.FloatType:
		return ir.FloatConstant{Value: 0.0, Width: tt.Width}
	case ir.BoolType:
		return ir.BoolConstant{Value: false}
	}
	return nil
}

// typesEqual performs structural equality on two ir.Type values.
func typesEqual(a, b ir.Type) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	switch ta := a.(type) {
	case ir.IntType:
		tb, ok := b.(ir.IntType)
		return ok && ta.Width == tb.Width && ta.Signed == tb.Signed
	case ir.FloatType:
		tb, ok := b.(ir.FloatType)
		return ok && ta.Width == tb.Width
	case ir.BoolType:
		_, ok := b.(ir.BoolType)
		return ok
	case ir.VoidType:
		_, ok := b.(ir.VoidType)
		return ok
	case ir.PointerType:
		tb, ok := b.(ir.PointerType)
		return ok && typesEqual(ta.Pointee, tb.Pointee)
	}
	return false
}
