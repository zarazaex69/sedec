package analysis

import (
	"strings"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// PropagateReturnValues traces the value assigned to the return register (rax/eax)
// and substitutes it into Return instructions. this replaces bare "return rax;"
// (which after renaming becomes "return var_N;") with the actual expression that
// was last assigned to the return register.
//
// algorithm:
//  1. for each block ending with a Return that has a Value (return register variable),
//     scan backwards through the block's instructions to find the last Assign or Load
//     whose destination is the same variable (or a sub-register alias).
//  2. if found, follow the assignment chain to find the ultimate source.
//  3. replace Return.Value with the resolved variable.
func PropagateReturnValues(fn *ir.Function) {
	for _, block := range fn.Blocks {
		propagateBlockReturn(block)
	}
}

// propagateBlockReturn scans a single block for return value propagation.
func propagateBlockReturn(block *ir.BasicBlock) {
	// find the return instruction (if any) in this block
	retIdx := -1
	for i, instr := range block.Instructions {
		if _, ok := ir.AsReturn(instr); ok {
			retIdx = i
			break
		}
	}
	if retIdx < 0 {
		return
	}

	ret, ok := ir.AsReturn(block.Instructions[retIdx])
	if !ok || ret.Value == nil {
		return
	}

	retVarName := strings.ToLower(ret.Value.Name)

	// scan backwards from the return to find the last assignment to the return variable.
	// then follow the chain: if the source is also a single-use temp, follow it.
	resolvedExpr := resolveAssignChain(block, retIdx, retVarName)
	if resolvedExpr != nil {
		patched := ret
		if varExpr, ok := resolvedExpr.(ir.VariableExpr); ok {
			v := varExpr.Var
			patched.Value = &v
			block.Instructions[retIdx] = &patched
		}
	}
}

// canonicalReturnReg maps sub-register aliases to their canonical 64-bit name
// for return value matching. eax, ax, al all map to rax.
func canonicalReturnReg(name string) string {
	switch name {
	case "rax", "eax", "ax", "al", "ah":
		return "rax"
	case "rdx", "edx", "dx", "dl", "dh":
		return "rdx"
	case "xmm0":
		return "xmm0"
	case "xmm1":
		return "xmm1"
	default:
		return name
	}
}

// resolveAssignChain follows a chain of assignments backwards from beforeIdx
// to find the ultimate source expression for a variable.
func resolveAssignChain(block *ir.BasicBlock, beforeIdx int, varName string) ir.Expression {
	// canonicalize the target name for register alias matching
	canonicalTarget := canonicalReturnReg(varName)

	for i := beforeIdx - 1; i >= 0; i-- {
		instr := block.Instructions[i]
		if instr.Location().IsFrameArtifact {
			continue
		}

		if assign, ok := ir.AsAssign(instr); ok {
			destName := strings.ToLower(assign.Dest.Name)
			// match by exact name or by canonical register alias
			if destName == varName || canonicalReturnReg(destName) == canonicalTarget {
				// found the assignment: check if source is another variable we can follow
				if srcVar, ok := assign.Source.(ir.VariableExpr); ok {
					deeper := resolveAssignChain(block, i, strings.ToLower(srcVar.Var.Name))
					if deeper != nil {
						return deeper
					}
				}
				return assign.Source
			}
		}

		if load, ok := ir.AsLoad(instr); ok {
			destName := strings.ToLower(load.Dest.Name)
			if destName == varName || canonicalReturnReg(destName) == canonicalTarget {
				return ir.VariableExpr{Var: load.Dest}
			}
		}
	}
	return nil
}
