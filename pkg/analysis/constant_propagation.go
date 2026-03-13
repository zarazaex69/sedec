// Package analysis provides data flow analysis algorithms for the sedec decompiler.
package analysis

import (
	"fmt"
	"math/bits"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// latticeValue represents an element in the constant propagation lattice.
// the lattice has three levels:
//
//	top (undefined) > constant(c) > bottom (overdefined/non-constant)
//
// this is the standard three-valued lattice used in sccp.
type latticeValue struct {
	kind     latticeKind
	constant ir.Constant // valid only when kind == latticeConstant
}

// latticeKind identifies the level in the constant propagation lattice.
type latticeKind int

const (
	// latticeTop means the variable has not yet been assigned a value (undefined).
	// all variables start at top.
	latticeTop latticeKind = iota

	// latticeConstant means the variable is known to hold a specific constant.
	latticeConstant

	// latticeBottom means the variable may hold different values at runtime (overdefined).
	latticeBottom
)

// String returns a human-readable representation of the lattice value.
func (lv latticeValue) String() string {
	switch lv.kind {
	case latticeTop:
		return "top"
	case latticeConstant:
		return fmt.Sprintf("const(%s)", lv.constant.String())
	case latticeBottom:
		return "bottom"
	default:
		return "unknown"
	}
}

// meet computes the greatest lower bound of two lattice values.
// the meet operation follows the lattice ordering:
//
//	meet(top, x)      = x
//	meet(x, top)      = x
//	meet(c, c)        = c        (same constant)
//	meet(c1, c2)      = bottom   (different constants)
//	meet(bottom, x)   = bottom
//	meet(x, bottom)   = bottom
func meet(a, b latticeValue) latticeValue {
	if a.kind == latticeTop {
		return b
	}
	if b.kind == latticeTop {
		return a
	}
	if a.kind == latticeBottom || b.kind == latticeBottom {
		return latticeValue{kind: latticeBottom}
	}
	// both are constants: equal constants meet to the same constant, different to bottom
	if constantsEqual(a.constant, b.constant) {
		return a
	}
	return latticeValue{kind: latticeBottom}
}

// constantsEqual checks structural equality of two ir.Constant values.
func constantsEqual(a, b ir.Constant) bool {
	switch ca := a.(type) {
	case ir.IntConstant:
		cb, ok := b.(ir.IntConstant)
		return ok && ca.Value == cb.Value && ca.Width == cb.Width && ca.Signed == cb.Signed
	case ir.FloatConstant:
		cb, ok := b.(ir.FloatConstant)
		return ok && ca.Value == cb.Value && ca.Width == cb.Width
	case ir.BoolConstant:
		cb, ok := b.(ir.BoolConstant)
		return ok && ca.Value == cb.Value
	case ir.NullConstant:
		_, ok := b.(ir.NullConstant)
		return ok
	default:
		return false
	}
}

// ConstPropResult holds the output of constant propagation analysis.
type ConstPropResult struct {
	// Lattice maps each ssa variable key (name_version) to its lattice value.
	Lattice map[string]latticeValue

	// ReplacedCount is the number of variable uses replaced with constants.
	ReplacedCount int
}

// IsConstant reports whether the given variable was determined to be a constant.
func (r *ConstPropResult) IsConstant(v ir.Variable) bool {
	lv, ok := r.Lattice[v.String()]
	return ok && lv.kind == latticeConstant
}

// GetConstant returns the constant value for a variable, or nil if not constant.
func (r *ConstPropResult) GetConstant(v ir.Variable) ir.Constant {
	lv, ok := r.Lattice[v.String()]
	if ok && lv.kind == latticeConstant {
		return lv.constant
	}
	return nil
}

// ConstPropAnalyzer implements Sparse Conditional Constant Propagation (SCCP)
// over an ssa-form ir function.
//
// algorithm overview (Wegman & Zadeck, 1991):
//  1. initialize all variables to top (undefined).
//  2. seed the entry block as executable.
//  3. maintain two worklists:
//     - cfgWorklist: basic block edges to process (executable flow edges)
//     - ssaWorklist: ssa def-use edges to re-evaluate when a value changes
//  4. for each executable block, evaluate each instruction:
//     - if the result changes lattice value, add all uses to ssaWorklist
//  5. for phi-nodes: meet over all incoming values from executable predecessors only
//  6. for branches: if condition is constant, mark only the taken edge executable
//  7. terminate when both worklists are empty (fixed point)
//  8. replace all uses of constant variables with their constant values
type ConstPropAnalyzer struct {
	function *ir.Function
	cfgGraph *cfg.CFG
	domTree  *cfg.DominatorTree

	// lattice maps variable key -> lattice value
	lattice map[string]latticeValue

	// executableEdges tracks which cfg edges have been determined executable
	executableEdges map[cfgEdge]bool

	// executableBlocks tracks which blocks have been visited at least once
	executableBlocks map[ir.BlockID]bool

	// defUseChains maps variable key -> list of program points that use the variable
	defUseChains map[string][]ProgramPoint

	// defSites maps variable key -> program point where it is defined
	defSites map[string]ProgramPoint

	// cfgWorklist contains block edges to process
	cfgWorklist []cfgEdge

	// ssaWorklist contains program points to re-evaluate
	ssaWorklist []ProgramPoint
}

// cfgEdge represents a directed edge in the cfg.
type cfgEdge struct {
	from ir.BlockID
	to   ir.BlockID
}

// NewConstPropAnalyzer creates a new constant propagation analyzer.
func NewConstPropAnalyzer(
	function *ir.Function,
	cfgGraph *cfg.CFG,
	domTree *cfg.DominatorTree,
) *ConstPropAnalyzer {
	return &ConstPropAnalyzer{
		function:         function,
		cfgGraph:         cfgGraph,
		domTree:          domTree,
		lattice:          make(map[string]latticeValue),
		executableEdges:  make(map[cfgEdge]bool),
		executableBlocks: make(map[ir.BlockID]bool),
		defUseChains:     make(map[string][]ProgramPoint),
		defSites:         make(map[string]ProgramPoint),
		cfgWorklist:      make([]cfgEdge, 0, 16),
		ssaWorklist:      make([]ProgramPoint, 0, 64),
	}
}

// Compute performs SCCP analysis and returns the result.
// the function ir is NOT modified; call ApplyToFunction to rewrite constants.
func (a *ConstPropAnalyzer) Compute() (*ConstPropResult, error) {
	if a.function == nil {
		return nil, fmt.Errorf("constant propagation: function is nil")
	}
	if len(a.function.Blocks) == 0 {
		return nil, fmt.Errorf("constant propagation: function %q has no blocks", a.function.Name)
	}

	// phase 1: build def-use chains and initialize lattice to top
	a.buildDefUseChains()

	// phase 2: seed entry block
	entryID := a.function.EntryBlock
	a.cfgWorklist = append(a.cfgWorklist, cfgEdge{from: entryID, to: entryID})

	// phase 3: fixed-point iteration
	for len(a.cfgWorklist) > 0 || len(a.ssaWorklist) > 0 {
		// drain cfg worklist first
		for len(a.cfgWorklist) > 0 {
			edge := a.cfgWorklist[0]
			a.cfgWorklist = a.cfgWorklist[1:]
			a.visitEdge(edge)
		}

		// drain ssa worklist
		for len(a.ssaWorklist) > 0 {
			point := a.ssaWorklist[0]
			a.ssaWorklist = a.ssaWorklist[1:]
			a.visitInstruction(point)
		}
	}

	return &ConstPropResult{Lattice: a.lattice}, nil
}

// buildDefUseChains scans all instructions to populate:
//   - a.defSites: where each variable is defined
//   - a.defUseChains: which program points use each variable
//   - a.lattice: initialized to top for all variables
func (a *ConstPropAnalyzer) buildDefUseChains() {
	for blockID, block := range a.function.Blocks {
		for instrIdx, instr := range block.Instructions {
			point := ProgramPoint{BlockID: blockID, InstrIdx: instrIdx}

			// record definition site and initialize lattice
			if v := extractDefinedVariable(instr); v != nil {
				key := v.String()
				a.defSites[key] = point
				a.lattice[key] = latticeValue{kind: latticeTop}
			}

			// record uses for def-use chains
			for _, usedVar := range extractUsedVariables(instr) {
				key := usedVar.String()
				a.defUseChains[key] = append(a.defUseChains[key], point)
			}
		}
	}
}

// visitEdge processes a cfg edge, marking the target block executable
// and evaluating its phi-nodes and instructions.
func (a *ConstPropAnalyzer) visitEdge(edge cfgEdge) {
	targetID := edge.to

	// mark edge as executable
	a.executableEdges[edge] = true

	// if block already fully visited, only re-evaluate phi-nodes
	// (new executable predecessor may change phi results)
	alreadyVisited := a.executableBlocks[targetID]
	a.executableBlocks[targetID] = true

	block, exists := a.function.Blocks[targetID]
	if !exists {
		return
	}

	for instrIdx, instr := range block.Instructions {
		point := ProgramPoint{BlockID: targetID, InstrIdx: instrIdx}

		phi, isPhi := instr.(*ir.Phi)
		if isPhi {
			// always re-evaluate phi-nodes when a new predecessor becomes executable
			a.evaluatePhi(phi, point)
			continue
		}

		// for non-phi instructions, only evaluate on first visit
		if !alreadyVisited {
			a.visitInstruction(point)
		}
	}
}

// visitInstruction re-evaluates a single instruction and propagates changes.
func (a *ConstPropAnalyzer) visitInstruction(point ProgramPoint) {
	block, exists := a.function.Blocks[point.BlockID]
	if !exists {
		return
	}
	if point.InstrIdx >= len(block.Instructions) {
		return
	}
	// only evaluate instructions in executable blocks
	if !a.executableBlocks[point.BlockID] {
		return
	}

	instr := block.Instructions[point.InstrIdx]

	switch i := instr.(type) {
	case *ir.Phi:
		a.evaluatePhi(i, point)
	case *ir.Assign:
		a.evaluateAssign(i, point)
	case *ir.Branch:
		a.evaluateBranch(i, point)
	case *ir.Jump:
		a.evaluateJump(i, point)
	case *ir.Load, *ir.Store, *ir.Call, *ir.Return:
		// loads, stores, calls, returns: result is always bottom
		// (memory aliasing and side effects prevent constant folding here)
		if v := extractDefinedVariable(instr); v != nil {
			a.updateLattice(v.String(), latticeValue{kind: latticeBottom})
		}
	}
}

// evaluatePhi computes the meet of all incoming values from executable predecessors.
func (a *ConstPropAnalyzer) evaluatePhi(phi *ir.Phi, point ProgramPoint) {
	result := latticeValue{kind: latticeTop}

	for _, src := range phi.Sources {
		// only consider sources from executable predecessors
		edge := cfgEdge{from: src.Block, to: point.BlockID}
		if !a.executableEdges[edge] && src.Block != point.BlockID {
			// check if this is the entry self-edge
			if !(src.Block == a.function.EntryBlock && point.BlockID == a.function.EntryBlock) {
				continue
			}
		}

		srcLV := a.getLattice(src.Var)
		result = meet(result, srcLV)

		// short-circuit: bottom is the lowest element
		if result.kind == latticeBottom {
			break
		}
	}

	a.updateLattice(phi.Dest.String(), result)
}

// evaluateAssign evaluates an assignment instruction.
func (a *ConstPropAnalyzer) evaluateAssign(assign *ir.Assign, point ProgramPoint) {
	lv := a.evaluateExpression(assign.Source)
	a.updateLattice(assign.Dest.String(), lv)
}

// evaluateBranch evaluates a conditional branch and marks reachable edges.
func (a *ConstPropAnalyzer) evaluateBranch(branch *ir.Branch, point ProgramPoint) {
	condLV := a.evaluateExpression(branch.Condition)

	switch condLV.kind {
	case latticeTop:
		// condition not yet determined: do nothing (wait for more info)

	case latticeConstant:
		// condition is a known constant: only one edge is executable
		taken := a.isTruthy(condLV.constant)
		if taken {
			a.addCFGEdge(cfgEdge{from: point.BlockID, to: branch.TrueTarget})
		} else {
			a.addCFGEdge(cfgEdge{from: point.BlockID, to: branch.FalseTarget})
		}

	case latticeBottom:
		// condition is overdefined: both edges are executable
		a.addCFGEdge(cfgEdge{from: point.BlockID, to: branch.TrueTarget})
		a.addCFGEdge(cfgEdge{from: point.BlockID, to: branch.FalseTarget})
	}
}

// evaluateJump marks the unconditional jump target as executable.
func (a *ConstPropAnalyzer) evaluateJump(jump *ir.Jump, point ProgramPoint) {
	a.addCFGEdge(cfgEdge{from: point.BlockID, to: jump.Target})
}

// addCFGEdge adds an edge to the cfg worklist if not already executable.
func (a *ConstPropAnalyzer) addCFGEdge(edge cfgEdge) {
	if !a.executableEdges[edge] {
		a.cfgWorklist = append(a.cfgWorklist, edge)
	}
}

// updateLattice updates the lattice value for a variable key.
// if the value changes, all uses of the variable are added to the ssa worklist.
func (a *ConstPropAnalyzer) updateLattice(key string, newLV latticeValue) {
	current := a.lattice[key]

	// lattice values can only move downward: top -> constant -> bottom
	// if the new value is not strictly lower, ignore the update
	if !latticeStrictlyLower(current, newLV) {
		return
	}

	a.lattice[key] = newLV

	// propagate change to all uses via ssa def-use chains
	for _, usePoint := range a.defUseChains[key] {
		a.ssaWorklist = append(a.ssaWorklist, usePoint)
	}
}

// latticeStrictlyLower reports whether b is strictly lower than a in the lattice.
// top > constant > bottom
func latticeStrictlyLower(current, newLV latticeValue) bool {
	if current.kind == newLV.kind {
		// same level: only a change in constant value counts as lower
		if current.kind == latticeConstant {
			return !constantsEqual(current.constant, newLV.constant)
		}
		return false
	}
	// top(0) < constant(1) < bottom(2): strictly lower means higher numeric kind
	return newLV.kind > current.kind
}

// getLattice returns the current lattice value for a variable.
// variables not yet seen are treated as top.
func (a *ConstPropAnalyzer) getLattice(v ir.Variable) latticeValue {
	if lv, ok := a.lattice[v.String()]; ok {
		return lv
	}
	return latticeValue{kind: latticeTop}
}

// evaluateExpression computes the lattice value of an expression.
// returns top if any operand is top, bottom if any operand is bottom,
// and a constant if all operands are constants and the operation can be folded.
func (a *ConstPropAnalyzer) evaluateExpression(expr ir.Expression) latticeValue {
	if expr == nil {
		return latticeValue{kind: latticeBottom}
	}

	switch e := expr.(type) {
	case *ir.ConstantExpr:
		return latticeValue{kind: latticeConstant, constant: e.Value}
	case ir.ConstantExpr:
		return latticeValue{kind: latticeConstant, constant: e.Value}

	case *ir.VariableExpr:
		return a.getLattice(e.Var)
	case ir.VariableExpr:
		return a.getLattice(e.Var)

	case *ir.BinaryOp:
		return a.evaluateBinaryOp(e.Op, e.Left, e.Right)
	case ir.BinaryOp:
		return a.evaluateBinaryOp(e.Op, e.Left, e.Right)

	case *ir.UnaryOp:
		return a.evaluateUnaryOp(e.Op, e.Operand)
	case ir.UnaryOp:
		return a.evaluateUnaryOp(e.Op, e.Operand)

	case *ir.Cast:
		return a.evaluateCast(e.Expr, e.TargetType)
	case ir.Cast:
		return a.evaluateCast(e.Expr, e.TargetType)

	default:
		return latticeValue{kind: latticeBottom}
	}
}

// evaluateBinaryOp folds a binary operation if both operands are constants.
func (a *ConstPropAnalyzer) evaluateBinaryOp(op ir.BinaryOperator, left, right ir.Expression) latticeValue {
	lv := a.evaluateExpression(left)
	rv := a.evaluateExpression(right)

	// propagate top: if either operand is top, result is top
	if lv.kind == latticeTop || rv.kind == latticeTop {
		return latticeValue{kind: latticeTop}
	}
	// propagate bottom: if either operand is bottom, result is bottom
	if lv.kind == latticeBottom || rv.kind == latticeBottom {
		return latticeValue{kind: latticeBottom}
	}

	// both operands are constants: attempt constant folding
	folded, ok := foldBinaryOp(op, lv.constant, rv.constant)
	if !ok {
		return latticeValue{kind: latticeBottom}
	}
	return latticeValue{kind: latticeConstant, constant: folded}
}

// evaluateUnaryOp folds a unary operation if the operand is a constant.
func (a *ConstPropAnalyzer) evaluateUnaryOp(op ir.UnaryOperator, operand ir.Expression) latticeValue {
	lv := a.evaluateExpression(operand)
	if lv.kind != latticeConstant {
		return lv // propagate top or bottom
	}

	folded, ok := foldUnaryOp(op, lv.constant)
	if !ok {
		return latticeValue{kind: latticeBottom}
	}
	return latticeValue{kind: latticeConstant, constant: folded}
}

// evaluateCast folds a cast if the operand is a constant.
func (a *ConstPropAnalyzer) evaluateCast(expr ir.Expression, targetType ir.Type) latticeValue {
	lv := a.evaluateExpression(expr)
	if lv.kind != latticeConstant {
		return lv
	}

	folded, ok := foldCast(lv.constant, targetType)
	if !ok {
		return latticeValue{kind: latticeBottom}
	}
	return latticeValue{kind: latticeConstant, constant: folded}
}

// isTruthy determines whether a constant is considered true for branch evaluation.
func (a *ConstPropAnalyzer) isTruthy(c ir.Constant) bool {
	switch cv := c.(type) {
	case ir.IntConstant:
		return cv.Value != 0
	case ir.BoolConstant:
		return cv.Value
	case ir.FloatConstant:
		return cv.Value != 0.0
	case ir.NullConstant:
		return false
	default:
		return false
	}
}

// ApplyToFunction rewrites the function ir by replacing variable uses with
// their constant values wherever the lattice determined a constant.
// returns the number of replacements made.
func (a *ConstPropAnalyzer) ApplyToFunction(result *ConstPropResult) int {
	count := 0
	for _, block := range a.function.Blocks {
		for i, instr := range block.Instructions {
			block.Instructions[i], count = a.rewriteInstruction(instr, result, count)
		}
	}
	result.ReplacedCount = count
	return count
}

// rewriteInstruction replaces variable uses with constants in a single instruction.
func (a *ConstPropAnalyzer) rewriteInstruction(
	instr ir.IRInstruction,
	result *ConstPropResult,
	count int,
) (ir.IRInstruction, int) {
	switch i := instr.(type) {
	case *ir.Assign:
		newSrc, n := a.rewriteExpression(i.Source, result)
		i.Source = newSrc
		return i, count + n

	case *ir.Load:
		newAddr, n := a.rewriteExpression(i.Address, result)
		i.Address = newAddr
		return i, count + n

	case *ir.Store:
		newAddr, n1 := a.rewriteExpression(i.Address, result)
		newVal, n2 := a.rewriteExpression(i.Value, result)
		i.Address = newAddr
		i.Value = newVal
		return i, count + n1 + n2

	case *ir.Branch:
		newCond, n := a.rewriteExpression(i.Condition, result)
		i.Condition = newCond
		return i, count + n

	case *ir.Call:
		newTarget, n := a.rewriteExpression(i.Target, result)
		i.Target = newTarget
		return i, count + n

	case *ir.Return:
		if i.Value != nil {
			if c := result.GetConstant(*i.Value); c != nil {
				i.Value = nil // void return after constant folding is not applicable
				// keep the variable reference; only expressions are rewritten
			}
		}
		return i, count

	case *ir.Phi:
		// phi-nodes are not rewritten here; they are handled by dead code elimination
		return i, count

	default:
		return instr, count
	}
}

// rewriteExpression replaces variable references with constants in an expression.
// returns the (possibly new) expression and the number of replacements.
func (a *ConstPropAnalyzer) rewriteExpression(
	expr ir.Expression,
	result *ConstPropResult,
) (ir.Expression, int) {
	if expr == nil {
		return expr, 0
	}

	switch e := expr.(type) {
	case *ir.VariableExpr:
		if c := result.GetConstant(e.Var); c != nil {
			return &ir.ConstantExpr{Value: c}, 1
		}
		return e, 0

	case ir.VariableExpr:
		if c := result.GetConstant(e.Var); c != nil {
			return &ir.ConstantExpr{Value: c}, 1
		}
		return &e, 0

	case *ir.BinaryOp:
		newLeft, n1 := a.rewriteExpression(e.Left, result)
		newRight, n2 := a.rewriteExpression(e.Right, result)
		e.Left = newLeft
		e.Right = newRight
		return e, n1 + n2

	case ir.BinaryOp:
		newLeft, n1 := a.rewriteExpression(e.Left, result)
		newRight, n2 := a.rewriteExpression(e.Right, result)
		e.Left = newLeft
		e.Right = newRight
		return &e, n1 + n2

	case *ir.UnaryOp:
		newOperand, n := a.rewriteExpression(e.Operand, result)
		e.Operand = newOperand
		return e, n

	case ir.UnaryOp:
		newOperand, n := a.rewriteExpression(e.Operand, result)
		e.Operand = newOperand
		return &e, n

	case *ir.Cast:
		newExpr, n := a.rewriteExpression(e.Expr, result)
		e.Expr = newExpr
		return e, n

	case ir.Cast:
		newExpr, n := a.rewriteExpression(e.Expr, result)
		e.Expr = newExpr
		return &e, n

	default:
		return expr, 0
	}
}

// ============================================================================
// Constant Folding Arithmetic
// ============================================================================

// foldBinaryOp evaluates a binary operation on two constants.
// preserves exact integer overflow semantics (wrapping arithmetic).
// returns (result, true) on success, (nil, false) if the operation cannot be folded
// (e.g., division by zero, unsupported operand types).
func foldBinaryOp(op ir.BinaryOperator, left, right ir.Constant) (ir.Constant, bool) {
	// integer × integer
	li, liOK := left.(ir.IntConstant)
	ri, riOK := right.(ir.IntConstant)
	if liOK && riOK {
		return foldIntBinaryOp(op, li, ri)
	}

	// float × float
	lf, lfOK := left.(ir.FloatConstant)
	rf, rfOK := right.(ir.FloatConstant)
	if lfOK && rfOK {
		return foldFloatBinaryOp(op, lf, rf)
	}

	// bool × bool (logical ops)
	lb, lbOK := left.(ir.BoolConstant)
	rb, rbOK := right.(ir.BoolConstant)
	if lbOK && rbOK {
		return foldBoolBinaryOp(op, lb, rb)
	}

	return nil, false
}

// foldIntBinaryOp folds integer binary operations with correct overflow semantics.
func foldIntBinaryOp(op ir.BinaryOperator, l, r ir.IntConstant) (ir.Constant, bool) {
	// use unsigned arithmetic for overflow-correct wrapping
	lu := uint64(l.Value)
	ru := uint64(r.Value)

	// mask to the actual bit width to simulate hardware truncation
	mask := widthMask(l.Width)

	var result uint64
	isBool := false
	boolResult := false

	switch op {
	case ir.BinOpAdd:
		result = (lu + ru) & mask
	case ir.BinOpSub:
		result = (lu - ru) & mask
	case ir.BinOpMul:
		result = (lu * ru) & mask
	case ir.BinOpDiv:
		if r.Value == 0 {
			return nil, false // division by zero
		}
		if l.Signed {
			result = uint64(l.Value/r.Value) & mask
		} else {
			result = (lu / ru) & mask
		}
	case ir.BinOpMod:
		if r.Value == 0 {
			return nil, false
		}
		if l.Signed {
			result = uint64(l.Value%r.Value) & mask
		} else {
			result = (lu % ru) & mask
		}
	case ir.BinOpUDiv:
		if ru == 0 {
			return nil, false
		}
		result = (lu / ru) & mask
	case ir.BinOpUMod:
		if ru == 0 {
			return nil, false
		}
		result = (lu % ru) & mask
	case ir.BinOpAnd:
		result = (lu & ru) & mask
	case ir.BinOpOr:
		result = (lu | ru) & mask
	case ir.BinOpXor:
		result = (lu ^ ru) & mask
	case ir.BinOpShl:
		shift := ru & 63
		result = (lu << shift) & mask
	case ir.BinOpShr:
		shift := ru & 63
		result = (lu >> shift) & mask
	case ir.BinOpSar:
		// arithmetic right shift: sign-extend then shift
		shift := ru & 63
		signedVal := signExtend(lu, l.Width)
		result = uint64(signedVal>>shift) & mask
	// comparison operators return bool
	case ir.BinOpEq:
		isBool, boolResult = true, l.Value == r.Value
	case ir.BinOpNe:
		isBool, boolResult = true, l.Value != r.Value
	case ir.BinOpLt:
		isBool, boolResult = true, l.Value < r.Value
	case ir.BinOpLe:
		isBool, boolResult = true, l.Value <= r.Value
	case ir.BinOpGt:
		isBool, boolResult = true, l.Value > r.Value
	case ir.BinOpGe:
		isBool, boolResult = true, l.Value >= r.Value
	case ir.BinOpULt:
		isBool, boolResult = true, lu < ru
	case ir.BinOpULe:
		isBool, boolResult = true, lu <= ru
	case ir.BinOpUGt:
		isBool, boolResult = true, lu > ru
	case ir.BinOpUGe:
		isBool, boolResult = true, lu >= ru
	default:
		return nil, false
	}

	if isBool {
		return ir.BoolConstant{Value: boolResult}, true
	}

	// sign-extend result back to int64 if signed
	if l.Signed {
		return ir.IntConstant{
			Value:  signExtend(result, l.Width),
			Width:  l.Width,
			Signed: true,
		}, true
	}
	return ir.IntConstant{
		Value:  int64(result),
		Width:  l.Width,
		Signed: false,
	}, true
}

// foldFloatBinaryOp folds floating-point binary operations.
func foldFloatBinaryOp(op ir.BinaryOperator, l, r ir.FloatConstant) (ir.Constant, bool) {
	switch op {
	case ir.BinOpAdd:
		return ir.FloatConstant{Value: l.Value + r.Value, Width: l.Width}, true
	case ir.BinOpSub:
		return ir.FloatConstant{Value: l.Value - r.Value, Width: l.Width}, true
	case ir.BinOpMul:
		return ir.FloatConstant{Value: l.Value * r.Value, Width: l.Width}, true
	case ir.BinOpDiv:
		if r.Value == 0.0 {
			return nil, false
		}
		return ir.FloatConstant{Value: l.Value / r.Value, Width: l.Width}, true
	case ir.BinOpEq:
		return ir.BoolConstant{Value: l.Value == r.Value}, true
	case ir.BinOpNe:
		return ir.BoolConstant{Value: l.Value != r.Value}, true
	case ir.BinOpLt:
		return ir.BoolConstant{Value: l.Value < r.Value}, true
	case ir.BinOpLe:
		return ir.BoolConstant{Value: l.Value <= r.Value}, true
	case ir.BinOpGt:
		return ir.BoolConstant{Value: l.Value > r.Value}, true
	case ir.BinOpGe:
		return ir.BoolConstant{Value: l.Value >= r.Value}, true
	default:
		return nil, false
	}
}

// foldBoolBinaryOp folds boolean logical operations.
func foldBoolBinaryOp(op ir.BinaryOperator, l, r ir.BoolConstant) (ir.Constant, bool) {
	switch op {
	case ir.BinOpLogicalAnd:
		return ir.BoolConstant{Value: l.Value && r.Value}, true
	case ir.BinOpLogicalOr:
		return ir.BoolConstant{Value: l.Value || r.Value}, true
	case ir.BinOpEq:
		return ir.BoolConstant{Value: l.Value == r.Value}, true
	case ir.BinOpNe:
		return ir.BoolConstant{Value: l.Value != r.Value}, true
	default:
		return nil, false
	}
}

// foldUnaryOp evaluates a unary operation on a constant.
func foldUnaryOp(op ir.UnaryOperator, operand ir.Constant) (ir.Constant, bool) {
	switch op {
	case ir.UnOpNeg:
		switch c := operand.(type) {
		case ir.IntConstant:
			mask := widthMask(c.Width)
			result := (^uint64(c.Value) + 1) & mask
			if c.Signed {
				return ir.IntConstant{Value: signExtend(result, c.Width), Width: c.Width, Signed: true}, true
			}
			return ir.IntConstant{Value: int64(result), Width: c.Width, Signed: false}, true
		case ir.FloatConstant:
			return ir.FloatConstant{Value: -c.Value, Width: c.Width}, true
		}
	case ir.UnOpNot:
		if c, ok := operand.(ir.IntConstant); ok {
			mask := widthMask(c.Width)
			result := (^uint64(c.Value)) & mask
			if c.Signed {
				return ir.IntConstant{Value: signExtend(result, c.Width), Width: c.Width, Signed: true}, true
			}
			return ir.IntConstant{Value: int64(result), Width: c.Width, Signed: false}, true
		}
	case ir.UnOpLogicalNot:
		switch c := operand.(type) {
		case ir.BoolConstant:
			return ir.BoolConstant{Value: !c.Value}, true
		case ir.IntConstant:
			return ir.BoolConstant{Value: c.Value == 0}, true
		}
	}
	return nil, false
}

// foldCast evaluates a type cast on a constant.
func foldCast(operand ir.Constant, targetType ir.Type) (ir.Constant, bool) {
	switch tt := targetType.(type) {
	case ir.IntType:
		switch c := operand.(type) {
		case ir.IntConstant:
			mask := widthMask(tt.Width)
			result := uint64(c.Value) & mask
			if tt.Signed {
				return ir.IntConstant{Value: signExtend(result, tt.Width), Width: tt.Width, Signed: true}, true
			}
			return ir.IntConstant{Value: int64(result), Width: tt.Width, Signed: false}, true
		case ir.BoolConstant:
			val := int64(0)
			if c.Value {
				val = 1
			}
			return ir.IntConstant{Value: val, Width: tt.Width, Signed: tt.Signed}, true
		case ir.FloatConstant:
			return ir.IntConstant{Value: int64(c.Value), Width: tt.Width, Signed: tt.Signed}, true
		}
	case ir.FloatType:
		switch c := operand.(type) {
		case ir.IntConstant:
			return ir.FloatConstant{Value: float64(c.Value), Width: tt.Width}, true
		case ir.FloatConstant:
			return ir.FloatConstant{Value: c.Value, Width: tt.Width}, true
		}
	case ir.BoolType:
		switch c := operand.(type) {
		case ir.IntConstant:
			return ir.BoolConstant{Value: c.Value != 0}, true
		case ir.BoolConstant:
			return c, true
		}
	}
	return nil, false
}

// widthMask returns a bitmask for the given integer width.
// e.g., Size1 (1 byte = 8 bits) -> 0xFF
func widthMask(width ir.Size) uint64 {
	if width >= 8 {
		return ^uint64(0) // 64-bit: no masking needed
	}
	return (uint64(1) << (uint(width) * 8)) - 1
}

// signExtend sign-extends a value of the given width to int64.
func signExtend(value uint64, width ir.Size) int64 {
	bits64 := uint(width) * 8
	if bits64 == 0 || bits64 >= 64 {
		return int64(value)
	}
	// check sign bit
	signBit := uint64(1) << (bits64 - 1)
	if value&signBit != 0 {
		// sign bit set: fill upper bits with 1s
		return int64(value | (^uint64(0) << bits64))
	}
	return int64(value)
}

// PropagateConstants is the top-level entry point for constant propagation.
// it runs SCCP analysis and rewrites the function ir in place.
// returns the analysis result and the number of replacements made.
func PropagateConstants(
	function *ir.Function,
	cfgGraph *cfg.CFG,
	domTree *cfg.DominatorTree,
) (*ConstPropResult, error) {
	analyzer := NewConstPropAnalyzer(function, cfgGraph, domTree)

	result, err := analyzer.Compute()
	if err != nil {
		return nil, err
	}

	analyzer.ApplyToFunction(result)
	return result, nil
}

// countLeadingZeros is used to verify bit width computations in tests.
// exported for use in property tests.
func countLeadingZeros(v uint64) int {
	return bits.LeadingZeros64(v)
}
