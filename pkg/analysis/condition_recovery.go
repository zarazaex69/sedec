package analysis

import (
	"github.com/zarazaex69/sedec/pkg/ir"
)

// RecoverConditions walks all expressions in the ir function and replaces
// flag-based comparison patterns with high-level relational operators.
//
// the x86-64 lifter materializes conditional jumps as boolean combinations of
// cpu flags (zf, sf, of, cf). for example, jle after cmp a, b becomes:
//
//	(a - b == 0) || ((a - b & 0x80000000) != 0) != ((overflow expr) != 0)
//
// this pass recognizes these canonical patterns and collapses them into
// direct comparisons: a <= b, a > b, a < b, etc.
//
// supported patterns (after cmp a, b which produces result = a - b):
//
//	zf                          -> a == b
//	!zf                         -> a != b
//	sf != of                    -> a < b   (signed)
//	zf || (sf != of)            -> a <= b  (signed)
//	!zf && (sf == of)           -> a > b   (signed)
//	sf == of                    -> a >= b  (signed)
//	cf                          -> a < b   (unsigned)
//	cf || zf                    -> a <= b  (unsigned)
//	!cf && !zf                  -> a > b   (unsigned)
//	!cf                         -> a >= b  (unsigned)
func RecoverConditions(fn *ir.Function) {
	if fn == nil {
		return
	}
	for _, block := range fn.Blocks {
		for i, instr := range block.Instructions {
			block.Instructions[i] = recoverInstrConditions(instr)
		}
	}
}

// recoverInstrConditions applies condition recovery to a single ir instruction.
func recoverInstrConditions(instr ir.IRInstruction) ir.IRInstruction {
	switch typed := instr.(type) {
	case *ir.Branch:
		typed.Condition = recoverExpr(typed.Condition)
		return typed
	case ir.Branch:
		typed.Condition = recoverExpr(typed.Condition)
		return typed
	case *ir.Assign:
		typed.Source = recoverExpr(typed.Source)
		return typed
	case ir.Assign:
		typed.Source = recoverExpr(typed.Source)
		return typed
	}
	return instr
}

// recoverExpr recursively walks an expression tree and replaces flag-based
// comparison patterns with high-level relational operators.
func recoverExpr(expr ir.Expression) ir.Expression {
	if expr == nil {
		return nil
	}

	switch e := expr.(type) {
	case ir.BinaryOp:
		// recurse first so nested patterns are simplified bottom-up
		left := recoverExpr(e.Left)
		right := recoverExpr(e.Right)
		recovered := ir.BinaryOp{Op: e.Op, Left: left, Right: right}

		// try to match signed comparison patterns
		if result := matchSignedPattern(recovered); result != nil {
			return result
		}
		// try to match unsigned comparison patterns
		if result := matchUnsignedPattern(recovered); result != nil {
			return result
		}
		return recovered

	case ir.UnaryOp:
		operand := recoverExpr(e.Operand)
		recovered := ir.UnaryOp{Op: e.Op, Operand: operand}

		// !zf -> a != b (when zf is a == 0 pattern from cmp)
		if e.Op == ir.UnOpLogicalNot {
			if cmp, ok := extractCmpEqZero(operand); ok {
				return ir.BinaryOp{Op: ir.BinOpNe, Left: cmp.left, Right: cmp.right}
			}
		}
		return recovered

	default:
		// zf alone as a condition: (a - b) == 0 -> a == b
		if cmp, ok := extractCmpEqZero(expr); ok {
			return ir.BinaryOp{Op: ir.BinOpEq, Left: cmp.left, Right: cmp.right}
		}
		return expr
	}
}

// cmpOperands holds the original left and right operands extracted from a cmp result.
type cmpOperands struct {
	left  ir.Expression
	right ir.Expression
}

// extractCmpEqZero checks if expr is (X - Y) == 0 and returns the operands.
// this is the materialized form of ZF after cmp X, Y.
func extractCmpEqZero(expr ir.Expression) (cmpOperands, bool) {
	binOp, ok := expr.(ir.BinaryOp)
	if !ok || binOp.Op != ir.BinOpEq {
		return cmpOperands{}, false
	}
	if !isZeroConstant(binOp.Right) {
		return cmpOperands{}, false
	}
	// left should be (X - Y)
	sub, ok := binOp.Left.(ir.BinaryOp)
	if !ok || sub.Op != ir.BinOpSub {
		return cmpOperands{}, false
	}
	return cmpOperands{left: sub.Left, right: sub.Right}, true
}

// extractSignFlag checks if expr matches the SF materialization pattern:
// ((X - Y) & signbit) != 0
// returns the sub-expression (X - Y) if matched.
func extractSignFlag(expr ir.Expression) (ir.BinaryOp, bool) {
	// pattern: ((result) & signbit) != 0
	neq, ok := expr.(ir.BinaryOp)
	if !ok || neq.Op != ir.BinOpNe {
		return ir.BinaryOp{}, false
	}
	if !isZeroConstant(neq.Right) {
		return ir.BinaryOp{}, false
	}
	andOp, ok := neq.Left.(ir.BinaryOp)
	if !ok || andOp.Op != ir.BinOpAnd {
		return ir.BinaryOp{}, false
	}
	if !isSignBitMask(andOp.Right) {
		return ir.BinaryOp{}, false
	}
	sub, ok := andOp.Left.(ir.BinaryOp)
	if !ok || sub.Op != ir.BinOpSub {
		return ir.BinaryOp{}, false
	}
	return sub, true
}

// extractOverflowFlag checks if expr matches the OF materialization pattern for sub:
// ((left & signbit) != (right & signbit)) && (((left - right) & signbit) != (left & signbit))
// for cmp (sub), OF is true when operand signs differ and result sign differs from left.
// when comparing against immediate 0, OF is always false, so we handle that case too.
func extractOverflowFlag(expr ir.Expression) (ir.BinaryOp, bool) {
	// of for sub: (sign(left) != sign(right)) && (sign(result) != sign(left))
	andOp, ok := expr.(ir.BinaryOp)
	if !ok || andOp.Op != ir.BinOpLogicalAnd {
		return ir.BinaryOp{}, false
	}

	// left side: sign(left) != sign(right)
	signsDiff, ok := andOp.Left.(ir.BinaryOp)
	if !ok || signsDiff.Op != ir.BinOpNe {
		return ir.BinaryOp{}, false
	}

	// extract left operand from (left & signbit)
	leftSignAnd, ok := signsDiff.Left.(ir.BinaryOp)
	if !ok || leftSignAnd.Op != ir.BinOpAnd || !isSignBitMask(leftSignAnd.Right) {
		return ir.BinaryOp{}, false
	}

	// extract right operand from (right & signbit)
	rightSignAnd, ok := signsDiff.Right.(ir.BinaryOp)
	if !ok || rightSignAnd.Op != ir.BinOpAnd || !isSignBitMask(rightSignAnd.Right) {
		return ir.BinaryOp{}, false
	}

	// right side: sign(result) != sign(left)
	resultDiff, ok := andOp.Right.(ir.BinaryOp)
	if !ok || resultDiff.Op != ir.BinOpNe {
		return ir.BinaryOp{}, false
	}

	// extract result from (result & signbit)
	resultSignAnd, ok := resultDiff.Left.(ir.BinaryOp)
	if !ok || resultSignAnd.Op != ir.BinOpAnd || !isSignBitMask(resultSignAnd.Right) {
		return ir.BinaryOp{}, false
	}

	// result should be (left - right)
	sub, ok := resultSignAnd.Left.(ir.BinaryOp)
	if !ok || sub.Op != ir.BinOpSub {
		return ir.BinaryOp{}, false
	}

	return sub, true
}

// matchSignedPattern matches signed comparison patterns from jle/jl/jg/jge.
func matchSignedPattern(expr ir.BinaryOp) ir.Expression {
	switch expr.Op { //nolint:exhaustive // only logical/comparison ops are relevant for signed flag patterns
	case ir.BinOpLogicalOr:
		zfCmp, zfOk := extractCmpEqZero(expr.Left)
		if !zfOk {
			return nil
		}
		sfNeOf := matchSFneOF(expr.Right)
		if sfNeOf == nil {
			return nil
		}
		// verify both patterns reference the same cmp operands
		if !sameOperands(zfCmp, *sfNeOf) {
			return nil
		}
		return ir.BinaryOp{Op: ir.BinOpLe, Left: zfCmp.left, Right: zfCmp.right}

	case ir.BinOpLogicalAnd:
		// jg: !zf && (sf == of) -> a > b
		notZf, nzOk := extractNotCmpEqZero(expr.Left)
		if !nzOk {
			return nil
		}
		sfEqOf := matchSFeqOF(expr.Right)
		if sfEqOf == nil {
			return nil
		}
		if !sameOperands(notZf, *sfEqOf) {
			return nil
		}
		return ir.BinaryOp{Op: ir.BinOpGt, Left: notZf.left, Right: notZf.right}

	case ir.BinOpNe:
		// jl: sf != of -> a < b
		// both sides should be sf and of materialized from the same cmp
		sfSub, sfOk := extractSignFlag(expr.Left)
		if !sfOk {
			return nil
		}
		// of can be a complex expression or a constant false (when comparing against 0)
		if isFalseConstant(expr.Right) {
			// sf != false -> sf -> sign bit set -> a < b (when cmp a, 0 and no overflow)
			return ir.BinaryOp{Op: ir.BinOpLt, Left: sfSub.Left, Right: sfSub.Right}
		}
		ofSub, ofOk := extractOverflowFlag(expr.Right)
		if !ofOk {
			// try the other direction: of on left, sf on right
			ofSub2, ofOk2 := extractOverflowFlag(expr.Left)
			sfSub2, sfOk2 := extractSignFlag(expr.Right)
			if ofOk2 && sfOk2 && sameBinaryOp(ofSub2, sfSub2) {
				return ir.BinaryOp{Op: ir.BinOpLt, Left: sfSub2.Left, Right: sfSub2.Right}
			}
			return nil
		}
		if sameBinaryOp(sfSub, ofSub) {
			return ir.BinaryOp{Op: ir.BinOpLt, Left: sfSub.Left, Right: sfSub.Right}
		}
		return nil

	case ir.BinOpEq:
		// jge: sf == of -> a >= b
		sfSub, sfOk := extractSignFlag(expr.Left)
		if !sfOk {
			return nil
		}
		if isFalseConstant(expr.Right) {
			// sf == false -> !sf -> sign bit not set -> a >= b (when cmp a, 0 and no overflow)
			return ir.BinaryOp{Op: ir.BinOpGe, Left: sfSub.Left, Right: sfSub.Right}
		}
		ofSub, ofOk := extractOverflowFlag(expr.Right)
		if !ofOk {
			ofSub2, ofOk2 := extractOverflowFlag(expr.Left)
			sfSub2, sfOk2 := extractSignFlag(expr.Right)
			if ofOk2 && sfOk2 && sameBinaryOp(ofSub2, sfSub2) {
				return ir.BinaryOp{Op: ir.BinOpGe, Left: sfSub2.Left, Right: sfSub2.Right}
			}
			return nil
		}
		if sameBinaryOp(sfSub, ofSub) {
			return ir.BinaryOp{Op: ir.BinOpGe, Left: sfSub.Left, Right: sfSub.Right}
		}
		return nil
	}
	return nil
}

// matchUnsignedPattern matches unsigned comparison patterns from jb/jbe/ja/jae.
func matchUnsignedPattern(expr ir.BinaryOp) ir.Expression {
	switch expr.Op { //nolint:exhaustive // only logical ops are relevant for unsigned flag patterns
	case ir.BinOpLogicalOr:
		cfCmp, cfOk := extractCFPattern(expr.Left)
		if cfOk {
			zfCmp, zfOk := extractCmpEqZero(expr.Right)
			if zfOk && sameOperands(cfCmp, zfCmp) {
				return ir.BinaryOp{Op: ir.BinOpULe, Left: cfCmp.left, Right: cfCmp.right}
			}
		}
		// try reversed: zf || cf
		zfCmp, zfOk := extractCmpEqZero(expr.Left)
		if zfOk {
			cfCmp2, cfOk2 := extractCFPattern(expr.Right)
			if cfOk2 && sameOperands(zfCmp, cfCmp2) {
				return ir.BinaryOp{Op: ir.BinOpULe, Left: zfCmp.left, Right: zfCmp.right}
			}
		}

	case ir.BinOpLogicalAnd:
		// ja: !cf && !zf -> a > b (unsigned)
		notCf, ncfOk := extractNotCF(expr.Left)
		if ncfOk {
			notZf, nzfOk := extractNotCmpEqZero(expr.Right)
			if nzfOk && sameOperands(notCf, notZf) {
				return ir.BinaryOp{Op: ir.BinOpUGt, Left: notCf.left, Right: notCf.right}
			}
		}
	}
	return nil
}

// matchSFneOF matches the pattern sf != of, returning the cmp operands if found.
// sf is materialized as ((result & signbit) != 0)
// of is materialized as the overflow expression or constant false.
func matchSFneOF(expr ir.Expression) *cmpOperands {
	neq, ok := expr.(ir.BinaryOp)
	if !ok || neq.Op != ir.BinOpNe {
		return nil
	}
	sfSub, sfOk := extractSignFlag(neq.Left)
	if !sfOk {
		return nil
	}
	// of can be false (no overflow possible, e.g., cmp x, 0)
	if isFalseConstant(neq.Right) {
		return &cmpOperands{left: sfSub.Left, right: sfSub.Right}
	}
	ofSub, ofOk := extractOverflowFlag(neq.Right)
	if ofOk && sameBinaryOp(sfSub, ofSub) {
		return &cmpOperands{left: sfSub.Left, right: sfSub.Right}
	}
	return nil
}

// matchSFeqOF matches the pattern sf == of, returning the cmp operands if found.
func matchSFeqOF(expr ir.Expression) *cmpOperands {
	eq, ok := expr.(ir.BinaryOp)
	if !ok || eq.Op != ir.BinOpEq {
		return nil
	}
	sfSub, sfOk := extractSignFlag(eq.Left)
	if !sfOk {
		return nil
	}
	if isFalseConstant(eq.Right) {
		return &cmpOperands{left: sfSub.Left, right: sfSub.Right}
	}
	ofSub, ofOk := extractOverflowFlag(eq.Right)
	if ofOk && sameBinaryOp(sfSub, ofSub) {
		return &cmpOperands{left: sfSub.Left, right: sfSub.Right}
	}
	return nil
}

// extractNotCmpEqZero matches !(result == 0) and returns the cmp operands.
func extractNotCmpEqZero(expr ir.Expression) (cmpOperands, bool) {
	not, ok := expr.(ir.UnaryOp)
	if !ok || not.Op != ir.UnOpLogicalNot {
		return cmpOperands{}, false
	}
	return extractCmpEqZero(not.Operand)
}

// extractCFPattern matches the CF materialization: (left < right) unsigned
// where left and right come from a cmp instruction.
func extractCFPattern(expr ir.Expression) (cmpOperands, bool) {
	ult, ok := expr.(ir.BinaryOp)
	if !ok || ult.Op != ir.BinOpULt {
		return cmpOperands{}, false
	}
	return cmpOperands{left: ult.Left, right: ult.Right}, true
}

// extractNotCF matches !cf -> !(left < right) unsigned.
func extractNotCF(expr ir.Expression) (cmpOperands, bool) {
	not, ok := expr.(ir.UnaryOp)
	if !ok || not.Op != ir.UnOpLogicalNot {
		return cmpOperands{}, false
	}
	return extractCFPattern(not.Operand)
}

// isZeroConstant checks if expr is an integer constant with value 0.
func isZeroConstant(expr ir.Expression) bool {
	c, ok := expr.(ir.ConstantExpr)
	if !ok {
		return false
	}
	ic, ok := c.Value.(ir.IntConstant)
	if !ok {
		return false
	}
	return ic.Value == 0
}

// isFalseConstant checks if expr is a boolean constant false.
func isFalseConstant(expr ir.Expression) bool {
	c, ok := expr.(ir.ConstantExpr)
	if !ok {
		return false
	}
	bc, ok := c.Value.(ir.BoolConstant)
	if !ok {
		return false
	}
	return !bc.Value
}

// isSignBitMask checks if expr is a constant with value equal to a sign bit mask
// (0x80, 0x8000, 0x80000000, or 0x8000000000000000).
func isSignBitMask(expr ir.Expression) bool {
	c, ok := expr.(ir.ConstantExpr)
	if !ok {
		return false
	}
	ic, ok := c.Value.(ir.IntConstant)
	if !ok {
		return false
	}
	switch ic.Value {
	case 0x80, 0x8000, 0x80000000, 0x800000000000000:
		return true
	}
	// also check via width: 1 << (width*8 - 1)
	if ic.Width > 0 {
		expected := int64(1) << (int64(ic.Width)*8 - 1)
		return ic.Value == expected
	}
	return false
}

// sameOperands checks if two cmpOperands reference the same left and right expressions.
func sameOperands(a, b cmpOperands) bool {
	return exprEqual(a.left, b.left) && exprEqual(a.right, b.right)
}

// sameBinaryOp checks if two BinaryOp have the same operator and operands.
func sameBinaryOp(a, b ir.BinaryOp) bool {
	return a.Op == b.Op && exprEqual(a.Left, b.Left) && exprEqual(a.Right, b.Right)
}

// exprEqual performs structural equality comparison on ir expressions.
func exprEqual(a, b ir.Expression) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	switch av := a.(type) {
	case ir.VariableExpr:
		bv, ok := b.(ir.VariableExpr)
		return ok && av.Var.Name == bv.Var.Name && av.Var.Version == bv.Var.Version
	case ir.ConstantExpr:
		bc, ok := b.(ir.ConstantExpr)
		if !ok {
			return false
		}
		return constantEqual(av.Value, bc.Value)
	case ir.BinaryOp:
		bb, ok := b.(ir.BinaryOp)
		return ok && av.Op == bb.Op && exprEqual(av.Left, bb.Left) && exprEqual(av.Right, bb.Right)
	case ir.UnaryOp:
		bu, ok := b.(ir.UnaryOp)
		return ok && av.Op == bu.Op && exprEqual(av.Operand, bu.Operand)
	case ir.Cast:
		bc, ok := b.(ir.Cast)
		return ok && exprEqual(av.Expr, bc.Expr)
	case ir.LoadExpr:
		bl, ok := b.(ir.LoadExpr)
		return ok && av.Size == bl.Size && exprEqual(av.Address, bl.Address)
	default:
		return a.String() == b.String()
	}
}

// constantEqual compares two ir.Constant values for equality.
func constantEqual(a, b ir.Constant) bool {
	switch av := a.(type) {
	case ir.IntConstant:
		bv, ok := b.(ir.IntConstant)
		return ok && av.Value == bv.Value
	case ir.BoolConstant:
		bv, ok := b.(ir.BoolConstant)
		return ok && av.Value == bv.Value
	case ir.FloatConstant:
		bv, ok := b.(ir.FloatConstant)
		return ok && av.Value == bv.Value
	default:
		return false
	}
}
