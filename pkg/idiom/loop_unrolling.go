package idiom

// loop_unrolling.go detects loop unrolling patterns in IR basic blocks.
//
// compilers unroll loops to reduce branch overhead and enable instruction-level
// parallelism. the unrolled form repeats the loop body N times with adjusted
// induction variables, followed by a remainder loop for non-multiple counts.
//
// detection strategy:
//  1. identify sequences of structurally identical instruction groups
//  2. verify that induction variable offsets differ by a constant stride
//  3. confirm the stride equals the number of repeated groups (unroll factor)

import (
	"errors"
	"fmt"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ErrNilBlockLU is returned when a nil block is passed to loop unrolling detection.
var ErrNilBlockLU = errors.New("loop unrolling detection: nil block")

// UnrollMatch describes a detected loop unrolling pattern.
type UnrollMatch struct {
	// UnrollFactor is the number of times the loop body was replicated.
	UnrollFactor int
	// BodySize is the number of instructions in a single loop body copy.
	BodySize int
	// StartIdx is the index of the first instruction of the first body copy.
	StartIdx int
	// InductionVar is the induction variable being incremented.
	InductionVar ir.Variable
	// Stride is the increment per unrolled iteration.
	Stride int64
}

// String returns a human-readable description of the match.
func (m *UnrollMatch) String() string {
	return fmt.Sprintf("loop unrolled x%d: body_size=%d, induction=%s, stride=%d",
		m.UnrollFactor, m.BodySize, m.InductionVar.String(), m.Stride)
}

// minUnrollFactor is the minimum unroll factor we consider meaningful.
const minUnrollFactor = 2

// maxBodySize is the maximum instruction count per body copy we scan.
const maxBodySize = 64

// DetectLoopUnrolling scans a basic block for repeated instruction patterns
// that indicate loop unrolling. it returns all detected unroll matches.
func DetectLoopUnrolling(block *ir.BasicBlock) ([]*UnrollMatch, error) {
	if block == nil {
		return nil, ErrNilBlockLU
	}

	n := len(block.Instructions)
	if n < minUnrollFactor*2 {
		// need at least 4 instructions for a 2x unroll of a 2-instruction body
		return nil, nil
	}

	var matches []*UnrollMatch
	covered := make(map[int]bool)

	for bodySize := 1; bodySize <= maxBodySize && bodySize*minUnrollFactor <= n; bodySize++ {
		for startIdx := 0; startIdx+bodySize*minUnrollFactor <= n; startIdx++ {
			if covered[startIdx] {
				continue
			}

			factor, stride, inductionVar, ok := countUnrolledGroups(
				block.Instructions, startIdx, bodySize,
			)
			if !ok || factor < minUnrollFactor {
				continue
			}

			for i := startIdx; i < startIdx+factor*bodySize; i++ {
				covered[i] = true
			}

			matches = append(matches, &UnrollMatch{
				UnrollFactor: factor,
				BodySize:     bodySize,
				StartIdx:     startIdx,
				InductionVar: inductionVar,
				Stride:       stride,
			})
			break
		}
	}

	return matches, nil
}

// countUnrolledGroups counts how many consecutive groups of size bodySize
// starting at startIdx are structurally equivalent with a constant induction
// variable stride.
func countUnrolledGroups(
	instrs []ir.IRInstruction,
	startIdx, bodySize int,
) (factor int, stride int64, inductionVar ir.Variable, ok bool) {
	n := len(instrs)
	if startIdx+bodySize > n {
		return 0, 0, ir.Variable{}, false
	}

	template := instrs[startIdx : startIdx+bodySize]

	templateOffset, templateVar, hasInduction := extractInductionOffset(template)
	if !hasInduction {
		return 0, 0, ir.Variable{}, false
	}

	factor = 1
	prevOffset := templateOffset

	for nextStart := startIdx + bodySize; nextStart+bodySize <= n; nextStart += bodySize {
		group := instrs[nextStart : nextStart+bodySize]

		groupOffset, groupVar, groupHasInduction := extractInductionOffset(group)
		if !groupHasInduction {
			break
		}

		if groupVar.Name != templateVar.Name {
			break
		}

		groupStride := groupOffset - prevOffset
		if factor == 1 {
			stride = groupStride
		} else if groupStride != stride {
			break
		}

		if stride <= 0 {
			break
		}

		if !groupsStructurallyEquivalent(template, group, templateVar.Name) {
			break
		}

		factor++
		prevOffset = groupOffset
	}

	if factor < minUnrollFactor {
		return 0, 0, ir.Variable{}, false
	}

	return factor, stride, templateVar, true
}

// extractInductionOffset finds the induction variable and its constant offset
// within an instruction group.
//
// address patterns handled:
//
//	base + (idx + offset)  -> returns (offset, idx)
//	base + idx             -> returns (0, idx)
//	idx + offset           -> returns (offset, idx)
//	idx                    -> returns (0, idx)
func extractInductionOffset(group []ir.IRInstruction) (offset int64, inductionVar ir.Variable, ok bool) {
	for _, instr := range group {
		switch inst := instr.(type) {
		case *ir.Load:
			if off, v, found := findInductionInAddress(inst.Address); found {
				return off, v, true
			}
		case *ir.Store:
			if off, v, found := findInductionInAddress(inst.Address); found {
				return off, v, true
			}
		case *ir.Assign:
			if off, v, found := findVarPlusConstAnywhere(inst.Source); found {
				return off, v, true
			}
		}
	}
	return 0, ir.Variable{}, false
}

// findInductionInAddress extracts the induction variable from a memory address.
// handles the canonical compiler pattern: base + idx  or  base + (idx + offset).
// the key insight: in `base + rhs`, rhs is the index; we extract from rhs, not base.
func findInductionInAddress(addr ir.Expression) (int64, ir.Variable, bool) {
	binop, ok := addr.(*ir.BinaryOp)
	if !ok {
		// plain variable: treat as induction var with offset 0
		if v, found := extractVar(addr); found {
			return 0, v, true
		}
		return 0, ir.Variable{}, false
	}

	if binop.Op != ir.BinOpAdd {
		return 0, ir.Variable{}, false
	}

	// try: left is base (plain variable), right is index expression
	if _, leftIsVar := extractVar(binop.Left); leftIsVar {
		if off, v, found := extractVarPlusConst(binop.Right); found {
			return off, v, true
		}
		if v, found := extractVar(binop.Right); found {
			return 0, v, true
		}
	}

	// try: right is base (plain variable), left is index expression
	if _, rightIsVar := extractVar(binop.Right); rightIsVar {
		if off, v, found := extractVarPlusConst(binop.Left); found {
			return off, v, true
		}
		if v, found := extractVar(binop.Left); found {
			return 0, v, true
		}
	}

	// fallback: recurse into both sides
	if off, v, found := findInductionInAddress(binop.Left); found {
		return off, v, true
	}
	return findInductionInAddress(binop.Right)
}

// findVarPlusConstAnywhere recursively searches an expression tree for a
// (var + const) or (const + var) sub-expression.
func findVarPlusConstAnywhere(expr ir.Expression) (int64, ir.Variable, bool) {
	if off, v, ok := extractVarPlusConst(expr); ok {
		return off, v, true
	}
	binop, isBinop := expr.(*ir.BinaryOp)
	if !isBinop {
		return 0, ir.Variable{}, false
	}
	if off, v, ok := findVarPlusConstAnywhere(binop.Left); ok {
		return off, v, true
	}
	if off, v, ok := findVarPlusConstAnywhere(binop.Right); ok {
		return off, v, true
	}
	return 0, ir.Variable{}, false
}

// extractVarPlusConst checks if an expression has the form (var + const) or (const + var).
func extractVarPlusConst(expr ir.Expression) (int64, ir.Variable, bool) {
	binop, ok := expr.(*ir.BinaryOp)
	if !ok {
		return 0, ir.Variable{}, false
	}
	if binop.Op != ir.BinOpAdd && binop.Op != ir.BinOpSub {
		return 0, ir.Variable{}, false
	}
	leftVar, leftIsVar := extractVar(binop.Left)
	rightConst, rightIsConst := extractIntConst(binop.Right)
	if leftIsVar && rightIsConst {
		if binop.Op == ir.BinOpSub {
			return -int64(rightConst), leftVar, true //nolint:gosec // safe: uint64->int64 constant cast
		}
		return int64(rightConst), leftVar, true //nolint:gosec // safe: uint64->int64 constant cast
	}
	rightVar, rightIsVar := extractVar(binop.Right)
	leftConst, leftIsConst := extractIntConst(binop.Left)
	if rightIsVar && leftIsConst {
		return int64(leftConst), rightVar, true //nolint:gosec // safe: uint64->int64 constant cast
	}
	_ = rightVar
	_ = leftIsConst
	return 0, ir.Variable{}, false
}

// groupsStructurallyEquivalent checks if two instruction groups have the same
// structure, ignoring constant offsets applied to the named induction variable.
func groupsStructurallyEquivalent(a, b []ir.IRInstruction, inductionVarName string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !instructionsStructurallyEquivalent(a[i], b[i], inductionVarName) {
			return false
		}
	}
	return true
}

// instructionsStructurallyEquivalent checks if two instructions have the same
// type and operator structure, ignoring induction variable offsets.
func instructionsStructurallyEquivalent(a, b ir.IRInstruction, inductionVarName string) bool {
	switch ia := a.(type) {
	case *ir.Assign:
		ib, ok := b.(*ir.Assign)
		if !ok {
			return false
		}
		return expressionsStructurallyEquivalent(ia.Source, ib.Source, inductionVarName)
	case *ir.Load:
		ib, ok := b.(*ir.Load)
		if !ok {
			return false
		}
		return ia.Size == ib.Size &&
			expressionsStructurallyEquivalent(ia.Address, ib.Address, inductionVarName)
	case *ir.Store:
		ib, ok := b.(*ir.Store)
		if !ok {
			return false
		}
		return ia.Size == ib.Size &&
			expressionsStructurallyEquivalent(ia.Address, ib.Address, inductionVarName)
	default:
		return fmt.Sprintf("%T", a) == fmt.Sprintf("%T", b)
	}
}

// expressionsStructurallyEquivalent checks if two expressions have the same
// operator structure, treating induction variable offsets as wildcards.
func expressionsStructurallyEquivalent(a, b ir.Expression, inductionVarName string) bool {
	aIsInd := isInductionRef(a, inductionVarName)
	bIsInd := isInductionRef(b, inductionVarName)
	if aIsInd && bIsInd {
		return true
	}
	switch ea := a.(type) {
	case *ir.BinaryOp:
		eb, ok := b.(*ir.BinaryOp)
		if !ok {
			return false
		}
		if ea.Op != eb.Op {
			return false
		}
		return expressionsStructurallyEquivalent(ea.Left, eb.Left, inductionVarName) &&
			expressionsStructurallyEquivalent(ea.Right, eb.Right, inductionVarName)
	case *ir.VariableExpr:
		eb, ok := b.(*ir.VariableExpr)
		if !ok {
			return false
		}
		if ea.Var.Name == inductionVarName {
			return eb.Var.Name == inductionVarName
		}
		return ea.Var.Name == eb.Var.Name
	case *ir.ConstantExpr:
		_, aIsInt := ea.Value.(ir.IntConstant)
		if eb, ok := b.(*ir.ConstantExpr); ok {
			_, bIsInt := eb.Value.(ir.IntConstant)
			return aIsInt && bIsInt
		}
		return false
	case *ir.UnaryOp:
		eb, ok := b.(*ir.UnaryOp)
		if !ok {
			return false
		}
		return ea.Op == eb.Op &&
			expressionsStructurallyEquivalent(ea.Operand, eb.Operand, inductionVarName)
	case *ir.Cast:
		eb, ok := b.(*ir.Cast)
		if !ok {
			return false
		}
		return expressionsStructurallyEquivalent(ea.Expr, eb.Expr, inductionVarName)
	default:
		return fmt.Sprintf("%T", a) == fmt.Sprintf("%T", b)
	}
}

// isInductionRef returns true if expr is a reference to the induction variable,
// either directly (var) or with a constant offset (var + const or const + var).
func isInductionRef(expr ir.Expression, inductionVarName string) bool {
	switch e := expr.(type) {
	case *ir.VariableExpr:
		return e.Var.Name == inductionVarName
	case *ir.BinaryOp:
		if e.Op != ir.BinOpAdd && e.Op != ir.BinOpSub {
			return false
		}
		if lv, ok := e.Left.(*ir.VariableExpr); ok {
			if lv.Var.Name == inductionVarName {
				_, isConst := e.Right.(*ir.ConstantExpr)
				return isConst
			}
		}
		if rv, ok := e.Right.(*ir.VariableExpr); ok {
			if rv.Var.Name == inductionVarName {
				_, isConst := e.Left.(*ir.ConstantExpr)
				return isConst
			}
		}
	}
	return false
}

// DetectLoopUnrollingInFunction applies loop unrolling detection to every
// basic block in a function.
func DetectLoopUnrollingInFunction(fn *ir.Function) ([]*UnrollMatch, error) {
	if fn == nil {
		return nil, ErrNilFunction
	}
	var all []*UnrollMatch
	for _, block := range fn.Blocks {
		m, err := DetectLoopUnrolling(block)
		if err != nil {
			return nil, fmt.Errorf("loop unrolling detection: block %d: %w", block.ID, err)
		}
		all = append(all, m...)
	}
	return all, nil
}
