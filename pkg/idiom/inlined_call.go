package idiom

// inlined_call.go detects inlined function call patterns in IR.
//
// compilers inline small functions to eliminate call overhead. the inlined
// code appears as a sequence of instructions without a call instruction,
// but with characteristic patterns:
//
//  1. callee-saved register save/restore brackets (push/pop or spill/reload)
//  2. stack frame setup without a corresponding call instruction
//  3. instruction sequences matching known small functions (strlen, abs, min, max)
//  4. repeated identical instruction sequences across multiple call sites
//
// detection strategy:
//   - detect save/restore brackets: a variable saved before a sequence and
//     restored after, with the sequence not containing a call instruction
//   - detect known idioms: abs(x) = (x < 0) ? -x : x
//     min(a,b) = (a < b) ? a : b
//     max(a,b) = (a > b) ? a : b
//   - detect strlen pattern: loop counting non-zero bytes

import (
	"errors"
	"fmt"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ErrNilBlockIC is returned when a nil block is passed to inlined call detection.
var ErrNilBlockIC = errors.New("inlined call detection: nil block")

// InlinedCallKind identifies the type of inlined function detected.
type InlinedCallKind int

const (
	// InlinedCallUnknown represents an unidentified inlined sequence.
	InlinedCallUnknown InlinedCallKind = iota
	// InlinedCallAbs represents an inlined abs() function.
	InlinedCallAbs
	// InlinedCallMin represents an inlined min() function.
	InlinedCallMin
	// InlinedCallMax represents an inlined max() function.
	InlinedCallMax
	// InlinedCallClamp represents an inlined clamp(x, lo, hi) function.
	InlinedCallClamp
	// InlinedCallSavedRestoreSequence represents a save/restore bracketed sequence.
	InlinedCallSavedRestoreSequence
)

func (k InlinedCallKind) String() string {
	switch k {
	case InlinedCallAbs:
		return "abs"
	case InlinedCallMin:
		return "min"
	case InlinedCallMax:
		return "max"
	case InlinedCallClamp:
		return "clamp"
	case InlinedCallSavedRestoreSequence:
		return "inlined_sequence"
	default:
		return unknownKindStr
	}
}

// InlinedCallMatch describes a detected inlined function pattern.
type InlinedCallMatch struct {
	// StartIdx is the index of the first instruction of the inlined sequence.
	StartIdx int
	// EndIdx is the index of the last instruction of the inlined sequence.
	EndIdx int
	// Kind identifies the type of inlined function.
	Kind InlinedCallKind
	// ResultVar is the variable holding the result of the inlined call.
	ResultVar ir.Variable
	// Args are the input variables to the inlined function.
	Args []ir.Variable
}

// String returns a human-readable description of the match.
func (m *InlinedCallMatch) String() string {
	argStrs := make([]string, len(m.Args))
	for i, a := range m.Args {
		argStrs[i] = a.String()
	}
	args := ""
	for i, s := range argStrs {
		if i > 0 {
			args += ", "
		}
		args += s
	}
	return fmt.Sprintf("%s = %s(%s)  [inlined, instrs %d..%d]",
		m.ResultVar.String(), m.Kind.String(), args, m.StartIdx, m.EndIdx)
}

// DetectInlinedCalls scans a basic block for inlined function patterns.
// it returns all detected inlined call matches.
func DetectInlinedCalls(block *ir.BasicBlock) ([]*InlinedCallMatch, error) {
	if block == nil {
		return nil, ErrNilBlockIC
	}

	var matches []*InlinedCallMatch

	for i := 0; i < len(block.Instructions); i++ {
		// try abs pattern: result = (x < 0) ? -x : x
		// IR form: t1 = x < 0; t2 = -x; result = t1 ? t2 : x
		// simplified form: result = (x ^ (x >> 63)) - (x >> 63)  [branchless abs]
		if m := tryMatchBranchlessAbs(block.Instructions, i); m != nil {
			matches = append(matches, m)
			i = m.EndIdx
			continue
		}

		// try max pattern BEFORE min: max uses (a - b) with result = b + t3
		// min uses (b - a) with result = a + t3
		// both are structurally identical; max is checked first to avoid min
		// incorrectly matching a max pattern (since min checks result = right_operand + t3,
		// which is also true for max when viewed from the subtrahend perspective).
		if m := tryMatchBranchlessMax(block.Instructions, i); m != nil {
			matches = append(matches, m)
			i = m.EndIdx
			continue
		}

		// try min pattern: result = (a < b) ? a : b
		// branchless form: result = a + ((b - a) & ((b - a) >> 63))
		if m := tryMatchBranchlessMin(block.Instructions, i); m != nil {
			matches = append(matches, m)
			i = m.EndIdx
			continue
		}

		// try save/restore bracket detection
		if m := tryMatchSaveRestoreBracket(block.Instructions, i); m != nil {
			matches = append(matches, m)
			i = m.EndIdx
			continue
		}
	}

	return matches, nil
}

// tryMatchBranchlessAbs detects the branchless absolute value pattern.
//
// gcc -O2 generates for abs(x) on x86_64:
//
//	t1 = x >> 63        (arithmetic shift: all-ones if negative, all-zeros if positive)
//	t2 = x ^ t1         (flip bits if negative)
//	result = t2 - t1    (add 1 if negative, completing two's complement negation)
//
// this is equivalent to: result = (x < 0) ? -x : x
func tryMatchBranchlessAbs(instrs []ir.IRInstruction, startIdx int) *InlinedCallMatch {
	// need at least 3 instructions
	if startIdx+2 >= len(instrs) {
		return nil
	}

	// instruction 0: t1 = x >>> 63  (arithmetic right shift by 63)
	a0, ok := instrs[startIdx].(*ir.Assign)
	if !ok {
		return nil
	}
	b0, ok := a0.Source.(*ir.BinaryOp)
	if !ok || b0.Op != ir.BinOpSar {
		return nil
	}
	xVar, xIsVar := extractVar(b0.Left)
	shiftConst, shiftIsConst := extractIntConst(b0.Right)
	if !xIsVar || !shiftIsConst || shiftConst != 63 {
		return nil
	}
	t1 := a0.Dest

	// instruction 1: t2 = x ^ t1
	a1, ok := instrs[startIdx+1].(*ir.Assign)
	if !ok {
		return nil
	}
	b1, ok := a1.Source.(*ir.BinaryOp)
	if !ok || b1.Op != ir.BinOpXor {
		return nil
	}
	if !exprIsVar(b1.Left, xVar) || !exprIsVar(b1.Right, t1) {
		if !exprIsVar(b1.Right, xVar) || !exprIsVar(b1.Left, t1) {
			return nil
		}
	}
	t2 := a1.Dest

	// instruction 2: result = t2 - t1
	a2, ok := instrs[startIdx+2].(*ir.Assign)
	if !ok {
		return nil
	}
	b2, ok := a2.Source.(*ir.BinaryOp)
	if !ok || b2.Op != ir.BinOpSub {
		return nil
	}
	if !exprIsVar(b2.Left, t2) || !exprIsVar(b2.Right, t1) {
		return nil
	}

	return &InlinedCallMatch{
		StartIdx:  startIdx,
		EndIdx:    startIdx + 2,
		Kind:      InlinedCallAbs,
		ResultVar: a2.Dest,
		Args:      []ir.Variable{xVar},
	}
}

// extractSignMaskAnd matches the two-instruction sequence:
//
//	t2 = t1 >> 63
//	t3 = t1 & t2
//
// returns (t3, true) on success. reduces cyclomatic complexity of min/max matchers.
func extractSignMaskAnd(instrs []ir.IRInstruction, idx int, t1 ir.Variable) (t3 ir.Variable, ok bool) {
	if idx+1 >= len(instrs) {
		return ir.Variable{}, false
	}

	a1, ok1 := instrs[idx].(*ir.Assign)
	if !ok1 {
		return ir.Variable{}, false
	}
	b1, ok1 := a1.Source.(*ir.BinaryOp)
	if !ok1 || b1.Op != ir.BinOpSar {
		return ir.Variable{}, false
	}
	shiftConst, shiftIsConst := extractIntConst(b1.Right)
	if !exprIsVar(b1.Left, t1) || !shiftIsConst || shiftConst != 63 {
		return ir.Variable{}, false
	}
	t2 := a1.Dest

	a2, ok2 := instrs[idx+1].(*ir.Assign)
	if !ok2 {
		return ir.Variable{}, false
	}
	b2, ok2 := a2.Source.(*ir.BinaryOp)
	if !ok2 || b2.Op != ir.BinOpAnd {
		return ir.Variable{}, false
	}
	if !exprIsVar(b2.Left, t1) || !exprIsVar(b2.Right, t2) {
		if !exprIsVar(b2.Left, t2) || !exprIsVar(b2.Right, t1) {
			return ir.Variable{}, false
		}
	}
	return a2.Dest, true
}

// tryMatchBranchlessMin detects the branchless minimum pattern.
//
// gcc -O2 generates for min(a, b) on x86_64 (signed):
//
//	t1 = b - a
//	t2 = t1 >> 63       (sign bit: all-ones if b < a)
//	t3 = t1 & t2        (0 if b >= a, b-a if b < a)
//	result = a + t3     (a if b >= a, b if b < a)
//
// the key distinction from max: the final addition uses a (the subtrahend of t1 = b - a),
// not b (the minuend). equivalently: result uses the RIGHT operand of the first subtraction.
func tryMatchBranchlessMin(instrs []ir.IRInstruction, startIdx int) *InlinedCallMatch {
	if startIdx+3 >= len(instrs) {
		return nil
	}

	// t1 = b - a  (b is left/minuend, a is right/subtrahend)
	a0, ok := instrs[startIdx].(*ir.Assign)
	if !ok {
		return nil
	}
	b0, ok := a0.Source.(*ir.BinaryOp)
	if !ok || b0.Op != ir.BinOpSub {
		return nil
	}
	bVar, bIsVar := extractVar(b0.Left)
	aVar, aIsVar := extractVar(b0.Right)
	if !bIsVar || !aIsVar {
		return nil
	}
	// min and max are structurally identical except:
	// min: t1 = b - a, result = a + t3  (result uses subtrahend = right operand)
	// max: t1 = a - b, result = b + t3  (result uses subtrahend = right operand)
	// we defer the final check to the result instruction to disambiguate.
	t1 := a0.Dest

	// t2 = t1 >> 63; t3 = t1 & t2
	t3, ok := extractSignMaskAnd(instrs, startIdx+1, t1)
	if !ok {
		return nil
	}

	// result = a + t3  (uses a as base — this is the min distinguisher vs max which uses b)
	a3, ok := instrs[startIdx+3].(*ir.Assign)
	if !ok {
		return nil
	}
	b3, ok := a3.Source.(*ir.BinaryOp)
	if !ok || b3.Op != ir.BinOpAdd {
		return nil
	}
	// for min: the base of the final add must be aVar (right operand of t1 = b - a)
	usesAVar := (exprIsVar(b3.Left, aVar) && exprIsVar(b3.Right, t3)) ||
		(exprIsVar(b3.Left, t3) && exprIsVar(b3.Right, aVar))
	if !usesAVar {
		return nil
	}
	// additional disambiguation: if bVar (left operand of t1 = b - a) also matches
	// the final add, this is actually a max pattern (t1 = a - b, result = b + t3)
	// where our aVar happens to equal bVar in the max interpretation.
	// reject if bVar is the left operand of the subtraction AND bVar != aVar
	// (i.e., the result uses the subtrahend, not the minuend — which is min)
	// this check is: if result uses bVar AND bVar != aVar, it's max, not min.
	usesBVar := (exprIsVar(b3.Left, bVar) && exprIsVar(b3.Right, t3)) ||
		(exprIsVar(b3.Left, t3) && exprIsVar(b3.Right, bVar))
	if usesBVar && (bVar.Name != aVar.Name || bVar.Version != aVar.Version) {
		// result uses both aVar and bVar — this means aVar == bVar in the expression,
		// which is degenerate. or result uses bVar (left operand), meaning this is max.
		// since max is checked first in DetectInlinedCalls, we should not reach here
		// for a genuine max pattern. but if we do, reject to avoid false positive.
		return nil
	}

	return &InlinedCallMatch{
		StartIdx:  startIdx,
		EndIdx:    startIdx + 3,
		Kind:      InlinedCallMin,
		ResultVar: a3.Dest,
		Args:      []ir.Variable{aVar, bVar},
	}
}

// tryMatchBranchlessMax detects the branchless maximum pattern.
//
// gcc -O2 generates for max(a, b) on x86_64 (signed):
//
//	t1 = a - b
//	t2 = t1 >> 63       (sign bit: all-ones if a < b)
//	t3 = t1 & t2        (0 if a >= b, a-b if a < b)
//	result = b + t3     (b if a >= b, a if a < b)
//
// the key distinction from min: the first subtraction is (a - b), not (b - a),
// and the final addition uses b (not a) as the base.
func tryMatchBranchlessMax(instrs []ir.IRInstruction, startIdx int) *InlinedCallMatch {
	if startIdx+3 >= len(instrs) {
		return nil
	}

	// t1 = a - b  (note: a is left operand, distinguishes from min where b is left)
	a0, ok := instrs[startIdx].(*ir.Assign)
	if !ok {
		return nil
	}
	b0, ok := a0.Source.(*ir.BinaryOp)
	if !ok || b0.Op != ir.BinOpSub {
		return nil
	}
	aVar, aIsVar := extractVar(b0.Left)
	bVar, bIsVar := extractVar(b0.Right)
	if !aIsVar || !bIsVar {
		return nil
	}
	// min uses (b - a); max uses (a - b). if a == b variable names, we can't distinguish,
	// but in practice they are different variables. we rely on the final add to disambiguate:
	// min: result = a + t3 (uses a as base)
	// max: result = b + t3 (uses b as base)
	t1 := a0.Dest

	// t2 = t1 >> 63; t3 = t1 & t2
	t3, ok := extractSignMaskAnd(instrs, startIdx+1, t1)
	if !ok {
		return nil
	}

	// result = b + t3  (uses b as base, not a — this is the max distinguisher)
	a3, ok := instrs[startIdx+3].(*ir.Assign)
	if !ok {
		return nil
	}
	b3, ok := a3.Source.(*ir.BinaryOp)
	if !ok || b3.Op != ir.BinOpAdd {
		return nil
	}
	// for max: the base of the final add must be bVar (the subtrahend of t1 = a - b)
	if !exprIsVar(b3.Left, bVar) || !exprIsVar(b3.Right, t3) {
		if !exprIsVar(b3.Left, t3) || !exprIsVar(b3.Right, bVar) {
			return nil
		}
	}

	return &InlinedCallMatch{
		StartIdx:  startIdx,
		EndIdx:    startIdx + 3,
		Kind:      InlinedCallMax,
		ResultVar: a3.Dest,
		Args:      []ir.Variable{aVar, bVar},
	}
}

// tryMatchSaveRestoreBracket detects a save/restore bracket pattern:
//
//	saved = callee_saved_reg
//	... (sequence without calls)
//	callee_saved_reg = saved
//
// this indicates an inlined function that preserved a callee-saved register.
// the minimum bracket size is 3 instructions (save, body, restore).
func tryMatchSaveRestoreBracket(instrs []ir.IRInstruction, startIdx int) *InlinedCallMatch {
	// minimum: save + 1 body instruction + restore = 3 instructions
	if startIdx+2 >= len(instrs) {
		return nil
	}

	// instruction 0 must be a simple variable copy: saved = reg
	a0, ok := instrs[startIdx].(*ir.Assign)
	if !ok {
		return nil
	}
	savedReg, savedIsVar := extractVar(a0.Source)
	if !savedIsVar {
		return nil
	}
	savedCopy := a0.Dest

	// scan forward for the matching restore: reg = saved
	// the sequence between save and restore must not contain calls
	for endIdx := startIdx + 2; endIdx < len(instrs) && endIdx-startIdx <= 32; endIdx++ {
		// check for call instruction in the body - if found, this is not an inlined sequence
		if _, isCall := instrs[endIdx-1].(*ir.Call); isCall {
			break
		}

		ae, ok := instrs[endIdx].(*ir.Assign)
		if !ok {
			continue
		}
		restoredFrom, restoredIsVar := extractVar(ae.Source)
		if !restoredIsVar {
			continue
		}

		// check: ae.Dest == savedReg and restoredFrom == savedCopy
		if ae.Dest.Name == savedReg.Name && ae.Dest.Version == savedReg.Version &&
			restoredFrom.Name == savedCopy.Name && restoredFrom.Version == savedCopy.Version {
			return &InlinedCallMatch{
				StartIdx:  startIdx,
				EndIdx:    endIdx,
				Kind:      InlinedCallSavedRestoreSequence,
				ResultVar: ae.Dest,
				Args:      []ir.Variable{savedReg},
			}
		}
	}

	return nil
}

// exprIsVar checks if an expression is a reference to the given variable.
func exprIsVar(expr ir.Expression, v ir.Variable) bool {
	ve, ok := expr.(*ir.VariableExpr)
	if !ok {
		return false
	}
	return ve.Var.Name == v.Name && ve.Var.Version == v.Version
}

// DetectInlinedCallsInFunction applies inlined call detection to every
// basic block in a function.
func DetectInlinedCallsInFunction(fn *ir.Function) ([]*InlinedCallMatch, error) {
	if fn == nil {
		return nil, ErrNilFunction
	}
	var all []*InlinedCallMatch
	for _, block := range fn.Blocks {
		m, err := DetectInlinedCalls(block)
		if err != nil {
			return nil, fmt.Errorf("inlined call detection: block %d: %w", block.ID, err)
		}
		all = append(all, m...)
	}
	return all, nil
}
