// package structuring - loop structure recovery
// this file implements loop kind classification (while/do-while/for) and
// induction variable analysis for recovering for-loop patterns from SSA IR.
package structuring

import (
	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// loopClassifier analyses a cfg.Loop and its IR to determine the loop kind
// and extract induction variables and bounds.
type loopClassifier struct {
	cfgraph  *cfg.CFG
	dt       *cfg.DominatorTree
	loopInfo *cfg.LoopInfo
	irBlocks IRBlockMap
}

// newLoopClassifier creates a loop classifier backed by the given analysis data.
func newLoopClassifier(
	cfgraph *cfg.CFG,
	dt *cfg.DominatorTree,
	loopInfo *cfg.LoopInfo,
	irBlocks IRBlockMap,
) *loopClassifier {
	return &loopClassifier{
		cfgraph:  cfgraph,
		dt:       dt,
		loopInfo: loopInfo,
		irBlocks: irBlocks,
	}
}

// classifyLoop determines the LoopKind for the given loop and returns
// the exit condition expression and whether the condition is at the header.
//
// classification rules:
//   - infinite loop: no exit edges → LoopKindInfinite
//   - for loop: has a canonical induction variable with constant step → LoopKindFor
//   - while loop: exit edge originates from header → LoopKindWhile
//   - do-while loop: exit edge originates from a non-header tail block → LoopKindDoWhile
func (lc *loopClassifier) classifyLoop(loop *cfg.Loop) (LoopKind, ir.Expression, bool) {
	if len(loop.ExitEdges) == 0 {
		// infinite loop: no way out
		return LoopKindInfinite, ir.ConstantExpr{Value: ir.BoolConstant{Value: true}}, true
	}

	// check for canonical induction variable → for loop
	iv := lc.findInductionVariable(loop)
	if iv != nil {
		cond := lc.extractExitCondition(loop)
		return LoopKindFor, cond, true
	}

	// determine while vs do-while by exit edge location
	for _, exitEdge := range loop.ExitEdges {
		if exitEdge.From == loop.Header {
			// condition checked at header → while loop
			cond := lc.extractBlockCondition(loop.Header)
			return LoopKindWhile, cond, true
		}
	}

	// condition at tail block → do-while loop
	exitFrom := loop.ExitEdges[0].From
	cond := lc.extractBlockCondition(exitFrom)
	return LoopKindDoWhile, cond, false
}

// findInductionVariable searches for a canonical induction variable in the loop.
// a canonical IV has the form: iv = phi(init, iv + step) where step is a constant.
// it scans phi-nodes in the loop header block.
func (lc *loopClassifier) findInductionVariable(loop *cfg.Loop) *InductionVariable {
	instrs, ok := lc.irBlocks[loop.Header]
	if !ok {
		return nil
	}

	// find the pre-header block: the predecessor of the header that is outside the loop
	preHeader, hasPreHeader := lc.findPreHeader(loop)

	for _, instr := range instrs {
		phi, ok := ir.AsPhi(instr)
		if !ok {
			continue
		}

		// look for phi(init_from_preheader, update_from_backedge)
		iv := lc.analyzePhiAsInductionVar(phi, loop, preHeader, hasPreHeader)
		if iv != nil {
			return iv
		}
	}

	return nil
}

// analyzePhiAsInductionVar checks whether a phi-node represents a canonical
// induction variable. returns nil if the phi is not an IV.
func (lc *loopClassifier) analyzePhiAsInductionVar(
	phi ir.Phi,
	loop *cfg.Loop,
	preHeader cfg.BlockID,
	hasPreHeader bool,
) *InductionVariable {
	if len(phi.Sources) != 2 {
		// canonical IV has exactly two phi sources: init and back-edge update
		return nil
	}

	var initExpr ir.Expression
	var updateBlock cfg.BlockID
	var updateVar ir.Variable

	for _, src := range phi.Sources {
		//nolint:gosec // ir.BlockID and cfg.BlockID are both uint64
		srcBlock := cfg.BlockID(src.Block)

		isFromPreHeader := hasPreHeader && srcBlock == preHeader
		if isFromPreHeader || !lc.blockInLoop(srcBlock, loop) {
			// this source comes from outside the loop: it is the initial value
			initExpr = ir.VariableExpr{Var: src.Var}
		} else {
			// this source comes from inside the loop: it is the back-edge update
			updateBlock = srcBlock
			updateVar = src.Var
		}
	}

	if initExpr == nil {
		return nil
	}

	// find the step: look for an assignment updateVar = phi.Dest + constant
	// in the update block or any block in the loop body
	stepExpr, isCanonical := lc.findStep(phi.Dest, updateVar, loop)
	if stepExpr == nil {
		return nil
	}

	return &InductionVariable{
		Var:         phi.Dest,
		InitExpr:    initExpr,
		StepExpr:    stepExpr,
		UpdateBlock: updateBlock,
		IsCanonical: isCanonical,
	}
}

// findStep searches for the step expression of an induction variable.
// it looks for an assignment of the form: updateVar = iv + step or iv - step
// where step is a constant. returns (stepExpr, isCanonical).
func (lc *loopClassifier) findStep(
	iv ir.Variable,
	updateVar ir.Variable,
	loop *cfg.Loop,
) (ir.Expression, bool) {
	for _, blockID := range loop.Body {
		instrs, ok := lc.irBlocks[blockID]
		if !ok {
			continue
		}

		for _, instr := range instrs {
			assign, ok := ir.AsAssign(instr)
			if !ok {
				continue
			}

			// check if this assignment defines updateVar
			if assign.Dest.Name != updateVar.Name {
				continue
			}

			// check if source is iv +/- constant
			binop, ok := assign.Source.(ir.BinaryOp)
			if !ok {
				continue
			}

			if binop.Op != ir.BinOpAdd && binop.Op != ir.BinOpSub {
				continue
			}

			// check left operand is the induction variable
			leftVar, ok := binop.Left.(ir.VariableExpr)
			if !ok || leftVar.Var.Name != iv.Name {
				continue
			}

			// check right operand is a constant
			_, isConst := binop.Right.(ir.ConstantExpr)
			if isConst {
				return binop.Right, true
			}

			// non-constant step: still an IV, just not canonical
			return binop.Right, false
		}
	}

	return nil, false
}

// findPreHeader returns the pre-header block of the loop: the unique predecessor
// of the loop header that is outside the loop body.
// returns (0, false) if no unique pre-header exists.
func (lc *loopClassifier) findPreHeader(loop *cfg.Loop) (cfg.BlockID, bool) {
	headerBlock, exists := lc.cfgraph.Blocks[loop.Header]
	if !exists {
		return 0, false
	}

	var preHeader cfg.BlockID
	count := 0

	for _, pred := range headerBlock.Predecessors {
		if !lc.blockInLoop(pred, loop) {
			preHeader = pred
			count++
		}
	}

	if count == 1 {
		return preHeader, true
	}

	return 0, false
}

// blockInLoop checks whether blockID is in the loop body.
func (lc *loopClassifier) blockInLoop(blockID cfg.BlockID, loop *cfg.Loop) bool {
	for _, b := range loop.Body {
		if b == blockID {
			return true
		}
	}
	return false
}

// extractExitCondition extracts the loop exit condition expression.
// it prefers the condition at the loop header; falls back to the first exit block.
func (lc *loopClassifier) extractExitCondition(loop *cfg.Loop) ir.Expression {
	// prefer header condition
	if cond := lc.extractBlockCondition(loop.Header); cond != nil {
		return cond
	}

	// fall back to first exit block
	if len(loop.ExitEdges) > 0 {
		return lc.extractBlockCondition(loop.ExitEdges[0].From)
	}

	return ir.ConstantExpr{Value: ir.BoolConstant{Value: true}}
}

// extractBlockCondition extracts the branch condition from the last IR instruction
// of the given block. returns nil if the block has no branch terminator.
func (lc *loopClassifier) extractBlockCondition(blockID cfg.BlockID) ir.Expression {
	instrs, ok := lc.irBlocks[blockID]
	if !ok || len(instrs) == 0 {
		return ir.ConstantExpr{Value: ir.BoolConstant{Value: true}}
	}

	last := instrs[len(instrs)-1]
	if branch, ok := ir.AsBranch(last); ok {
		return branch.Condition
	}

	return ir.ConstantExpr{Value: ir.BoolConstant{Value: true}}
}

// extractLoopBounds extracts the statically-recoverable bounds of a loop
// given its induction variable and exit condition.
//
// it looks for a comparison of the form: iv < limit, iv <= limit, iv != limit, etc.
// in the exit condition expression.
func extractLoopBounds(iv *InductionVariable, exitCond ir.Expression) *LoopBounds {
	if iv == nil || exitCond == nil {
		return nil
	}

	binop, ok := exitCond.(ir.BinaryOp)
	if !ok {
		return nil
	}

	// check if this is a comparison involving the induction variable
	switch binop.Op {
	case ir.BinOpLt, ir.BinOpLe, ir.BinOpGt, ir.BinOpGe,
		ir.BinOpEq, ir.BinOpNe, ir.BinOpULt, ir.BinOpULe, ir.BinOpUGt, ir.BinOpUGe:
		// valid comparison operator
	default:
		return nil
	}

	// check left operand is the induction variable
	leftVar, ok := binop.Left.(ir.VariableExpr)
	if !ok || leftVar.Var.Name != iv.Var.Name {
		return nil
	}

	return &LoopBounds{
		InitValue:  iv.InitExpr,
		LimitValue: binop.Right,
		StepValue:  iv.StepExpr,
		LimitOp:    binop.Op,
	}
}

// buildForStatement constructs a ForStatement from a loop with a known
// induction variable. the init statement is an assignment of the IV to its
// initial value; the post statement is the IV update expression.
func buildForStatement(
	iv *InductionVariable,
	condition ir.Expression,
	body Statement,
) ForStatement {
	// init: iv = initExpr
	initStmt := IRBlock{
		BlockID: iv.UpdateBlock,
		Instructions: []ir.IRInstruction{
			ir.Assign{
				Dest:   iv.Var,
				Source: iv.InitExpr,
			},
		},
	}

	// post: iv = iv + step (reconstruct the update assignment)
	postExpr := ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  ir.VariableExpr{Var: iv.Var},
		Right: iv.StepExpr,
	}
	postStmt := IRBlock{
		BlockID: iv.UpdateBlock,
		Instructions: []ir.IRInstruction{
			ir.Assign{
				Dest:   iv.Var,
				Source: postExpr,
			},
		},
	}

	return ForStatement{
		Init:      initStmt,
		Condition: condition,
		Post:      postStmt,
		Body:      body,
	}
}
