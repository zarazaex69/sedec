// Package idiom implements compiler idiom recognition for the sedec decompiler.
// it detects and reverses compiler optimizations that obscure source-level intent.
package idiom

import (
	"errors"
	"fmt"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// sentinel errors for nil-input guards.
var (
	ErrNilBlock    = errors.New("magic divisor recognition: nil block")
	ErrNilFunction = errors.New("magic divisor recognition: nil function")
)

// MagicDivKind distinguishes signed from unsigned magic division patterns.
type MagicDivKind int

const (
	// MagicDivUnsigned represents an unsigned division pattern (logical right shift).
	MagicDivUnsigned MagicDivKind = iota
	// MagicDivSigned represents a signed division pattern (arithmetic right shift).
	MagicDivSigned
)

// MagicDivisorMatch describes a recognized magic divisor pattern in the IR.
type MagicDivisorMatch struct {
	// MulInstrIdx is the index of the multiply instruction in the block.
	MulInstrIdx int
	// ShiftInstrIdx is the index of the shift instruction in the block.
	ShiftInstrIdx int
	// Dividend is the variable being divided.
	Dividend ir.Variable
	// MagicConstant is the magic multiplier M extracted from the pattern.
	MagicConstant uint64
	// ShiftAmount is the shift amount S extracted from the pattern.
	ShiftAmount uint8
	// Divisor is the recovered original divisor D.
	Divisor uint64
	// Kind indicates whether this is a signed or unsigned division.
	Kind MagicDivKind
	// ResultVar is the variable that holds the division result.
	ResultVar ir.Variable
}

// String returns a human-readable description of the match.
func (m *MagicDivisorMatch) String() string {
	op := "/u"
	if m.Kind == MagicDivSigned {
		op = "/"
	}
	return fmt.Sprintf("%s = %s %s %d  [magic: M=0x%x, S=%d]",
		m.ResultVar.String(), m.Dividend.String(), op, m.Divisor,
		m.MagicConstant, m.ShiftAmount)
}

// RecognizeMagicDivisors scans a basic block for magic divisor patterns and
// replaces them with explicit division instructions.
//
// the compiler transforms x / D into:
//
//	t1 = x * M          (high-multiply by magic constant)
//	t2 = t1 >> S        (logical or arithmetic right shift)
//
// for unsigned division: M = ceil(2^(N+S) / D), shift is logical (BinOpShr)
// for signed division:   M is chosen so that arithmetic shift (BinOpSar) works
//
// the function modifies block.Instructions in place, replacing the two-instruction
// pattern with a single division instruction. it returns all matches found.
func RecognizeMagicDivisors(block *ir.BasicBlock) ([]*MagicDivisorMatch, error) {
	if block == nil {
		return nil, ErrNilBlock
	}

	var matches []*MagicDivisorMatch

	// build a map from variable name+version to the instruction index that defines it.
	// this allows O(1) lookup when we find a shift and need to trace back to the multiply.
	defIndex := buildDefIndex(block.Instructions)

	// scan forward for shift instructions; each shift is the tail of the pattern.
	for shiftIdx, instr := range block.Instructions {
		assign, ok := instr.(*ir.Assign)
		if !ok {
			continue
		}

		// check if this instruction is a right shift (logical or arithmetic)
		shiftOp, shiftLeft, shiftRight, isShift := extractShift(assign.Source)
		if !isShift {
			continue
		}

		// the shift amount must be a compile-time constant
		shiftConst, ok := shiftRight.(*ir.ConstantExpr)
		if !ok {
			continue
		}
		shiftIC, ok := shiftConst.Value.(ir.IntConstant)
		if !ok {
			continue
		}
		// shift amount must be in [1, 63] to be meaningful
		//nolint:gosec // shift amount is bounded by the check below
		shiftAmt := uint8(shiftIC.Value)
		if shiftAmt == 0 || shiftAmt > 63 {
			continue
		}

		// the shifted value must be a variable (result of the multiply)
		shiftedVar, ok := extractVar(shiftLeft)
		if !ok {
			continue
		}

		// look up the instruction that defines the shifted variable
		mulIdx, defined := defIndex[varKey{name: shiftedVar.Name, version: shiftedVar.Version}]
		if !defined {
			continue
		}

		mulAssign, ok := block.Instructions[mulIdx].(*ir.Assign)
		if !ok {
			continue
		}

		// the defining instruction must be a multiply
		_, mulLeft, mulRight, isMul := extractMul(mulAssign.Source)
		if !isMul {
			continue
		}

		// one operand of the multiply must be a compile-time constant (the magic number)
		// the other operand is the dividend
		magicConst, dividend, ok := extractMagicAndDividend(mulLeft, mulRight)
		if !ok {
			continue
		}

		// determine kind from shift operator
		kind := MagicDivUnsigned
		if shiftOp == ir.BinOpSar {
			kind = MagicDivSigned
		}

		// reverse-engineer the original divisor from (M, S)
		divisor, ok := recoverDivisor(magicConst, shiftAmt, kind)
		if !ok {
			continue
		}

		matches = append(matches, &MagicDivisorMatch{
			MulInstrIdx:   mulIdx,
			ShiftInstrIdx: shiftIdx,
			Dividend:      dividend,
			MagicConstant: magicConst,
			ShiftAmount:   shiftAmt,
			Divisor:       divisor,
			Kind:          kind,
			ResultVar:     assign.Dest,
		})
	}

	if len(matches) == 0 {
		return nil, nil
	}

	// apply replacements in reverse order so indices remain valid
	applyReplacements(block, matches)

	return matches, nil
}

// RecognizeMagicDivisorsInFunction applies magic divisor recognition to every
// basic block in a function. returns all matches found across all blocks.
func RecognizeMagicDivisorsInFunction(fn *ir.Function) ([]*MagicDivisorMatch, error) {
	if fn == nil {
		return nil, ErrNilFunction
	}

	var allMatches []*MagicDivisorMatch
	for _, block := range fn.Blocks {
		matches, err := RecognizeMagicDivisors(block)
		if err != nil {
			return nil, fmt.Errorf("magic divisor recognition: block %d: %w", block.ID, err)
		}
		allMatches = append(allMatches, matches...)
	}
	return allMatches, nil
}

// ============================================================================
// divisor recovery
// ============================================================================

// recoverDivisor brute-forces the original divisor D from magic constant M and
// shift amount S by checking all candidates in [2, 2^31].
//
// for unsigned division (logical shift):
//
//	floor(x / D) == (x * M) >> S  for all x in [0, 2^32)
//
// we verify the candidate D by checking the magic constant formula:
//
//	M = ceil(2^(32+S) / D)  (for 32-bit operands)
//
// for signed division (arithmetic shift), the formula is more complex due to
// sign extension and the correction step compilers sometimes add. we verify
// by checking a representative set of values.
func recoverDivisor(magic uint64, shift uint8, kind MagicDivKind) (uint64, bool) {
	// try all divisors from 2 to 2^31
	for d := uint64(2); d <= (1 << 31); d++ {
		if verifyMagicDivisor(magic, shift, d, kind) {
			return d, true
		}
	}
	return 0, false
}

// verifyMagicDivisor checks whether (magic, shift) correctly implements division by d.
//
// for unsigned 32-bit division:
//   - the compiler computes M = ceil(2^(32+S) / D) and uses the high 32 bits of x*M
//   - equivalently: floor(x / D) == (x * M) >> (32 + S) for all x in [0, 2^32)
//   - we check a representative sample of values for efficiency
//
// for signed 32-bit division:
//   - the compiler uses arithmetic shift and may add a correction term
//   - we verify using the arithmetic shift formula
func verifyMagicDivisor(magic uint64, shift uint8, d uint64, kind MagicDivKind) bool {
	if d == 0 {
		return false
	}

	switch kind {
	case MagicDivUnsigned:
		return verifyUnsigned(magic, shift, d)
	case MagicDivSigned:
		return verifySigned(magic, shift, d)
	default:
		return false
	}
}

// verifyUnsigned checks the unsigned magic divisor formula.
//
// gcc/clang generate: result = (x * M) >> S
// where M is a 33-bit magic constant stored in a 64-bit register.
// the multiply produces a 64-bit result; the shift discards the low 32 bits.
//
// two common forms:
//  1. post-shift only:  result = mulhi(x, M) >> S  (M fits in 32 bits)
//  2. with correction:  result = (mulhi(x, M) + x) >> S  (M has bit 32 set)
//
// we check both forms against a representative sample.
func verifyUnsigned(magic uint64, shift uint8, d uint64) bool {
	// check the mathematical relationship: M ≈ 2^(32+S) / D
	// with tolerance for rounding
	expected := (uint64(1) << (32 + uint(shift))) / d
	if magic != expected && magic != expected+1 {
		return false
	}

	// verify with a sample of values to confirm correctness
	testValues := []uint64{0, 1, d - 1, d, d + 1, 2*d - 1, 2 * d, 100, 1000, 0xFFFF, 0xFFFFFFFF}
	for _, x := range testValues {
		x32 := x & 0xFFFFFFFF
		expected32 := x32 / d
		// form 1: (x * M) >> (32 + S)
		got := (x32 * magic) >> (32 + uint(shift))
		if got == expected32 {
			continue
		}
		// form 2: ((x * M) >> 32 + x) >> S  (correction variant)
		hiMul := (x32 * magic) >> 32
		got2 := (hiMul + x32) >> uint(shift)
		if got2 != expected32 {
			return false
		}
	}
	return true
}

// verifySigned checks the signed magic divisor formula.
//
// for signed division, the compiler uses arithmetic right shift (SAR).
// the formula (Hacker's Delight, Warren 2002):
//
//	result = (mulhi(x, M) >> S) + (x < 0 ? 1 : 0)
//
// where mulhi(x, M) = high 32 bits of the 64-bit signed product x * M.
// the correction (+1 for negative x) implements C truncation-toward-zero semantics.
//
// the magic constant M is computed as:
//
//	M = floor(2^(p+N-1) / D)  where p = ceil(log2(D)), N = 32
//
// we verify by checking that the formula holds for a representative sample
// using C truncation semantics (not floor division).
func verifySigned(magic uint64, shift uint8, d uint64) bool {
	if d == 0 || d > (1<<31) {
		return false
	}

	// compute the expected magic range using Hacker's Delight formula
	// M ≈ 2^(p+31) / D where p = ceil(log2(D)), p in [1..31]
	// the upper bound is 2^(31+31)/2 = 2^61, but we cap at 2^34/D+2
	// to cover all practical compiler-generated magic constants
	lo := (uint64(1) << 31) / d
	hi := (uint64(1)<<34)/d + 2
	if magic < lo || magic > hi {
		return false
	}

	// verify with a representative sample using C truncation semantics
	testValues := []int64{0, 1, -1, int64(d) - 1, int64(d), -int64(d), 100, -100, 1000, -1000}
	for _, x := range testValues {
		// c truncation division (toward zero)
		expectedC := truncDiv(x, int64(d))

		// mulhi: high 32 bits of 64-bit signed product
		//nolint:gosec // intentional signed/unsigned conversion for magic number arithmetic
		product := int64(uint64(x) * magic)
		hi32 := product >> 32
		got := hi32 >> uint(shift)
		// correction for negative dividend
		if x < 0 {
			got++
		}
		if got != expectedC {
			return false
		}
	}
	return true
}

// truncDiv performs C-style truncation division (toward zero).
func truncDiv(a, b int64) int64 {
	if b == 0 {
		return 0
	}
	// go integer division already truncates toward zero for int64
	return a / b
}

// ============================================================================
// IR pattern extraction helpers
// ============================================================================

// extractShift checks if an expression is a right shift (logical or arithmetic).
// returns (op, left, right, true) if it is, or (0, nil, nil, false) otherwise.
func extractShift(expr ir.Expression) (ir.BinaryOperator, ir.Expression, ir.Expression, bool) {
	switch e := expr.(type) {
	case *ir.BinaryOp:
		if e.Op == ir.BinOpShr || e.Op == ir.BinOpSar {
			return e.Op, e.Left, e.Right, true
		}
	case ir.BinaryOp:
		if e.Op == ir.BinOpShr || e.Op == ir.BinOpSar {
			return e.Op, e.Left, e.Right, true
		}
	}
	return 0, nil, nil, false
}

// extractMul checks if an expression is a multiplication.
// returns (op, left, right, true) if it is, or (0, nil, nil, false) otherwise.
func extractMul(expr ir.Expression) (ir.BinaryOperator, ir.Expression, ir.Expression, bool) {
	switch e := expr.(type) {
	case *ir.BinaryOp:
		if e.Op == ir.BinOpMul {
			return e.Op, e.Left, e.Right, true
		}
	case ir.BinaryOp:
		if e.Op == ir.BinOpMul {
			return e.Op, e.Left, e.Right, true
		}
	}
	return 0, nil, nil, false
}

// extractVar extracts the variable from a VariableExpr.
func extractVar(expr ir.Expression) (ir.Variable, bool) {
	switch e := expr.(type) {
	case *ir.VariableExpr:
		return e.Var, true
	case ir.VariableExpr:
		return e.Var, true
	}
	return ir.Variable{}, false
}

// extractMagicAndDividend identifies which operand of a multiply is the magic
// constant and which is the dividend variable.
// returns (magic, dividend, true) or (0, zero, false).
func extractMagicAndDividend(left, right ir.Expression) (uint64, ir.Variable, bool) {
	// try: left is constant, right is variable
	if lc, ok := extractIntConst(left); ok {
		if rv, ok := extractVar(right); ok {
			return lc, rv, true
		}
	}
	// try: right is constant, left is variable
	if rc, ok := extractIntConst(right); ok {
		if lv, ok := extractVar(left); ok {
			return rc, lv, true
		}
	}
	return 0, ir.Variable{}, false
}

// extractIntConst extracts an unsigned integer value from a ConstantExpr.
func extractIntConst(expr ir.Expression) (uint64, bool) {
	switch e := expr.(type) {
	case *ir.ConstantExpr:
		if ic, ok := e.Value.(ir.IntConstant); ok {
			//nolint:gosec // intentional signed->unsigned for magic constant extraction
			return uint64(ic.Value), true
		}
	case ir.ConstantExpr:
		if ic, ok := e.Value.(ir.IntConstant); ok {
			//nolint:gosec // intentional signed->unsigned for magic constant extraction
			return uint64(ic.Value), true
		}
	}
	return 0, false
}

// ============================================================================
// def-index and replacement
// ============================================================================

// varKey is a canonical key for a variable (name + version).
type varKey struct {
	name    string
	version int
}

// buildDefIndex builds a map from variable key to the instruction index that defines it.
func buildDefIndex(instrs []ir.IRInstruction) map[varKey]int {
	idx := make(map[varKey]int, len(instrs))
	for i, instr := range instrs {
		if assign, ok := instr.(*ir.Assign); ok {
			idx[varKey{name: assign.Dest.Name, version: assign.Dest.Version}] = i
		}
	}
	return idx
}

// applyReplacements rewrites the block's instruction list by replacing each
// matched (mul, shift) pair with a single division instruction.
//
// the multiply instruction is replaced with a no-op (removed by marking as nil
// and compacting), and the shift instruction is replaced with the division.
// we process matches in reverse order of ShiftInstrIdx to keep indices stable.
func applyReplacements(block *ir.BasicBlock, matches []*MagicDivisorMatch) {
	// sort matches by shift index descending so earlier indices are not invalidated
	sortMatchesDesc(matches)

	// mark multiply instructions for removal
	removeSet := make(map[int]bool, len(matches))
	for _, m := range matches {
		removeSet[m.MulInstrIdx] = true
	}

	// replace shift instructions with division
	for _, m := range matches {
		divOp := ir.BinOpUDiv
		if m.Kind == MagicDivSigned {
			divOp = ir.BinOpDiv
		}

		// determine the type for the divisor constant; fall back to i32/u32
		if m.Dividend.Type == nil {
			m.Dividend.Type = ir.IntType{Width: ir.Size4, Signed: m.Kind == MagicDivSigned}
		}
		signed := m.Kind == MagicDivSigned

		block.Instructions[m.ShiftInstrIdx] = &ir.Assign{
			Dest: m.ResultVar,
			Source: &ir.BinaryOp{
				Op:   divOp,
				Left: &ir.VariableExpr{Var: m.Dividend},
				Right: &ir.ConstantExpr{Value: ir.IntConstant{
					//nolint:gosec // divisor is bounded to [2, 2^31] by recoverDivisor
					Value:  int64(m.Divisor),
					Width:  ir.Size4,
					Signed: signed,
				}},
			},
		}
	}

	// compact: remove multiply instructions
	kept := block.Instructions[:0]
	for i, instr := range block.Instructions {
		if !removeSet[i] {
			kept = append(kept, instr)
		}
	}
	block.Instructions = kept
}

// sortMatchesDesc sorts matches by ShiftInstrIdx in descending order.
// insertion sort is sufficient for the small number of matches per block.
func sortMatchesDesc(matches []*MagicDivisorMatch) {
	for i := 1; i < len(matches); i++ {
		key := matches[i]
		j := i - 1
		for j >= 0 && matches[j].ShiftInstrIdx < key.ShiftInstrIdx {
			matches[j+1] = matches[j]
			j--
		}
		matches[j+1] = key
	}
}
