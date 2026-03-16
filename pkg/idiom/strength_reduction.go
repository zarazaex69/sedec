package idiom

// strength_reduction.go detects strength reduction patterns in loops:
// compilers replace x * C with repeated addition sequences when C is small.
// this pass reverses that transformation, restoring the multiplication.
//
// canonical pattern (gcc -O2 for small constant multipliers):
//
//	entry:
//	  acc = 0
//	loop:
//	  acc = acc + x   ; repeated C times (unrolled) or via induction
//	  ...
//	exit:
//	  result = acc    ; equivalent to result = x * C
//
// we detect the simpler induction-variable form:
//
//	t0 = x
//	t1 = t0 + x   ; t1 = 2*x
//	t2 = t1 + x   ; t2 = 3*x
//	...
//	tN = t(N-1) + x  ; tN = (N+1)*x

import (
	"errors"
	"fmt"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ErrNilBlockSR is returned when a nil block is passed to strength reduction.
var ErrNilBlockSR = errors.New("strength reduction: nil block")

// StrengthReductionMatch describes a recognized addition-chain → multiplication pattern.
type StrengthReductionMatch struct {
	// ChainStart is the index of the first add instruction in the chain.
	ChainStart int
	// ChainEnd is the index of the last add instruction in the chain.
	ChainEnd int
	// Multiplier is the recovered constant multiplier C.
	Multiplier int64
	// Operand is the variable being multiplied.
	Operand ir.Variable
	// ResultVar is the variable holding the final product.
	ResultVar ir.Variable
}

// String returns a human-readable description of the match.
func (m *StrengthReductionMatch) String() string {
	return fmt.Sprintf("%s = %s * %d  [strength-reduced from %d additions]",
		m.ResultVar.String(), m.Operand.String(), m.Multiplier,
		int(m.Multiplier)-1)
}

// RecognizeStrengthReduction scans a basic block for addition-chain patterns
// that represent strength-reduced multiplications and replaces them with
// explicit multiply instructions.
//
// the algorithm:
//  1. build a def-index mapping variable → defining instruction index
//  2. for each add instruction, trace the addition chain backward
//  3. if the chain has a single base operand repeated N times, it is x * (N+1)
//  4. replace the chain with a single multiply instruction
func RecognizeStrengthReduction(block *ir.BasicBlock) ([]*StrengthReductionMatch, error) {
	if block == nil {
		return nil, ErrNilBlockSR
	}

	defIdx := buildDefIndex(block.Instructions)
	var matches []*StrengthReductionMatch

	// track which instruction indices are already consumed by a match
	consumed := make(map[int]bool)

	for i := len(block.Instructions) - 1; i >= 0; i-- {
		if consumed[i] {
			continue
		}
		assign, ok := block.Instructions[i].(*ir.Assign)
		if !ok {
			continue
		}

		// check if this is an add instruction
		binop, ok := assign.Source.(*ir.BinaryOp)
		if !ok {
			continue
		}
		if binop.Op != ir.BinOpAdd {
			continue
		}

		// trace the addition chain rooted at this instruction
		chain, base, count := traceAdditionChain(i, block.Instructions, defIdx)
		if count < 2 {
			// need at least x + x = 2*x to be meaningful
			continue
		}

		// verify none of the chain members are already consumed
		alreadyUsed := false
		for _, idx := range chain {
			if consumed[idx] {
				alreadyUsed = true
				break
			}
		}
		if alreadyUsed {
			continue
		}

		matches = append(matches, &StrengthReductionMatch{
			ChainStart: chain[len(chain)-1],
			ChainEnd:   i,
			Multiplier: count,
			Operand:    base,
			ResultVar:  assign.Dest,
		})

		for _, idx := range chain {
			consumed[idx] = true
		}
	}

	if len(matches) == 0 {
		return nil, nil
	}

	applyStrengthReductionReplacements(block, matches, consumed)
	return matches, nil
}

// traceAdditionChain follows an addition chain backward from instruction at idx.
// it returns the list of instruction indices in the chain (from deepest to idx),
// the base variable being added, and the total count (multiplier).
//
// example chain for 4*x:
//
//	t1 = x + x      (count=2)
//	t2 = t1 + x     (count=3)
//	t3 = t2 + x     (count=4)  ← starting point
//
// returns ([idx_t1, idx_t2, idx_t3], x, 4)
func traceAdditionChain(
	startIdx int,
	instrs []ir.IRInstruction,
	defIdx map[varKey]int,
) (chain []int, base ir.Variable, count int64) {
	chain = []int{startIdx}

	assign, ok := instrs[startIdx].(*ir.Assign)
	if !ok {
		return nil, ir.Variable{}, 0
	}
	binop, ok := assign.Source.(*ir.BinaryOp)
	if !ok || binop.Op != ir.BinOpAdd {
		return nil, ir.Variable{}, 0
	}

	// identify the "accumulator" side and the "base" side.
	// the accumulator is the variable defined by a previous add in the chain;
	// the base is the variable being repeatedly added.
	leftVar, leftIsVar := extractVar(binop.Left)
	rightVar, rightIsVar := extractVar(binop.Right)

	if !leftIsVar || !rightIsVar {
		return nil, ir.Variable{}, 0
	}

	// determine which side is the accumulator (defined by another add)
	// and which is the base operand
	var accumVar, baseVar ir.Variable
	leftDefIdx, leftDefined := defIdx[varKey{name: leftVar.Name, version: leftVar.Version}]
	rightDefIdx, rightDefined := defIdx[varKey{name: rightVar.Name, version: rightVar.Version}]

	switch {
	case leftDefined && isAddInstruction(instrs[leftDefIdx]):
		accumVar = leftVar
		baseVar = rightVar
		_ = rightDefIdx
	case rightDefined && isAddInstruction(instrs[rightDefIdx]):
		accumVar = rightVar
		baseVar = leftVar
		_ = leftDefIdx
	case leftVar.Name == rightVar.Name && leftVar.Version == rightVar.Version:
		// x + x = 2*x: base case
		base = leftVar
		count = 2
		return chain, base, count
	default:
		return nil, ir.Variable{}, 0
	}

	base = baseVar
	count = 2 // current instruction adds 1 more

	// walk backward through the accumulator chain
	current := accumVar
	for {
		cidx, defined := defIdx[varKey{name: current.Name, version: current.Version}]
		if !defined {
			break
		}
		ca, ok := instrs[cidx].(*ir.Assign)
		if !ok {
			break
		}
		cb, ok := ca.Source.(*ir.BinaryOp)
		if !ok || cb.Op != ir.BinOpAdd {
			break
		}

		clv, clIsVar := extractVar(cb.Left)
		crv, crIsVar := extractVar(cb.Right)
		if !clIsVar || !crIsVar {
			break
		}

		// one side must be the base variable, the other is the next accumulator
		var nextAccum ir.Variable
		done := false

		switch {
		case clv.Name == base.Name && clv.Version == base.Version:
			nextAccum = crv
		case crv.Name == base.Name && crv.Version == base.Version:
			nextAccum = clv
		case clv.Name == crv.Name && clv.Version == crv.Version &&
			clv.Name == base.Name && clv.Version == base.Version:
			// x + x at the bottom of the chain
			chain = append(chain, cidx)
			count++
			done = true
		default:
			done = true
		}

		if done || nextAccum.Name == "" {
			break
		}

		chain = append(chain, cidx)
		count++
		current = nextAccum
	}

	return chain, base, count
}

// isAddInstruction returns true if the instruction at idx is an add assignment.
func isAddInstruction(instr ir.IRInstruction) bool {
	a, ok := instr.(*ir.Assign)
	if !ok {
		return false
	}
	b, ok := a.Source.(*ir.BinaryOp)
	return ok && b.Op == ir.BinOpAdd
}

// applyStrengthReductionReplacements rewrites the block by replacing addition
// chains with single multiply instructions and removing intermediate adds.
func applyStrengthReductionReplacements(
	block *ir.BasicBlock,
	matches []*StrengthReductionMatch,
	consumed map[int]bool,
) {
	// replace the final instruction of each chain with a multiply
	for _, m := range matches {
		signed := m.Operand.Type != nil
		if it, ok := m.Operand.Type.(ir.IntType); ok {
			signed = it.Signed
		}

		block.Instructions[m.ChainEnd] = &ir.Assign{
			Dest: m.ResultVar,
			Source: &ir.BinaryOp{
				Op:   ir.BinOpMul,
				Left: &ir.VariableExpr{Var: m.Operand},
				Right: &ir.ConstantExpr{Value: ir.IntConstant{
					Value:  m.Multiplier,
					Width:  ir.Size8,
					Signed: signed,
				}},
			},
		}
	}

	// remove all intermediate chain instructions (not the final one)
	removeSet := make(map[int]bool)
	for idx := range consumed {
		removeSet[idx] = true
	}
	// un-mark the final instructions (they were replaced, not removed)
	for _, m := range matches {
		delete(removeSet, m.ChainEnd)
	}

	kept := block.Instructions[:0]
	for i, instr := range block.Instructions {
		if !removeSet[i] {
			kept = append(kept, instr)
		}
	}
	block.Instructions = kept
}

// RecognizeStrengthReductionInFunction applies strength reduction recognition
// to every basic block in a function.
func RecognizeStrengthReductionInFunction(fn *ir.Function) ([]*StrengthReductionMatch, error) {
	if fn == nil {
		return nil, ErrNilFunction
	}
	var all []*StrengthReductionMatch
	for _, block := range fn.Blocks {
		m, err := RecognizeStrengthReduction(block)
		if err != nil {
			return nil, fmt.Errorf("strength reduction: block %d: %w", block.ID, err)
		}
		all = append(all, m...)
	}
	return all, nil
}
