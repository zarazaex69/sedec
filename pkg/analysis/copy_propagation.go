package analysis

import (
	"fmt"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// CopyPropResult holds statistics from a copy propagation pass.
type CopyPropResult struct {
	// ReplacedCount is the number of variable uses replaced.
	ReplacedCount int
	// CopiesFound is the number of copy instructions identified.
	CopiesFound int
}

// CopyPropagator performs copy propagation on ssa-form ir.
//
// in ssa form a copy is an Assign instruction whose source is a single
// VariableExpr: x = y. the propagator builds a copy map, computes its
// transitive closure, then rewrites all uses of copied variables.
//
// safety rules:
//   - phi-node inputs are NOT treated as copies (phi merges values from
//     multiple predecessors; the phi result may itself be a copy if the
//     phi has a single live source, but that is handled by dce, not here)
//   - only Assign instructions with a bare VariableExpr source qualify
//   - the copy map is computed once over the whole function; ssa guarantees
//     each variable has exactly one definition, so the map is acyclic
type CopyPropagator struct {
	function *ir.Function
	cfgGraph *cfg.CFG
	domTree  *cfg.DominatorTree
}

// NewCopyPropagator creates a new copy propagation pass.
func NewCopyPropagator(
	function *ir.Function,
	cfgGraph *cfg.CFG,
	domTree *cfg.DominatorTree,
) *CopyPropagator {
	return &CopyPropagator{
		function: function,
		cfgGraph: cfgGraph,
		domTree:  domTree,
	}
}

// Propagate runs copy propagation and rewrites the function ir in place.
func (p *CopyPropagator) Propagate() (*CopyPropResult, error) {
	if p.function == nil {
		return nil, fmt.Errorf("copy propagation: %w", ErrNilFunction)
	}
	if len(p.function.Blocks) == 0 {
		return nil, fmt.Errorf("copy propagation: function %q: %w", p.function.Name, ErrNoBlocks)
	}

	// phase 1: collect all copy instructions and build the raw copy map.
	// copyMap[x] = y means there exists an instruction x = y (a copy).
	copyMap := p.buildCopyMap()

	result := &CopyPropResult{CopiesFound: len(copyMap)}
	if len(copyMap) == 0 {
		return result, nil
	}

	// phase 2: compute transitive closure.
	// if x = y and y = z then x -> z.
	resolved := p.transitiveClosure(copyMap)

	// phase 3: rewrite all uses of copied variables throughout the function.
	result.ReplacedCount = p.rewriteUses(resolved)

	return result, nil
}

// buildCopyMap scans all blocks and collects copy instructions.
// a copy is an *ir.Assign whose Source is a *ir.VariableExpr or ir.VariableExpr.
// phi-node sources are explicitly excluded: a phi result is a copy only if
// the phi has exactly one source (degenerate phi), but we do not treat phi
// inputs as copies per the safety rules.
func (p *CopyPropagator) buildCopyMap() map[VarKey]VarKey {
	copyMap := make(map[VarKey]VarKey)

	for _, block := range p.function.Blocks {
		for _, instr := range block.Instructions {
			assign, ok := instr.(*ir.Assign)
			if !ok {
				continue
			}

			// extract the source variable if the source is a bare variable reference
			srcVar, isCopy := extractSingleVar(assign.Source)
			if !isCopy {
				continue
			}

			destKey := varKeyOf(assign.Dest)
			srcKey := varKeyOf(srcVar)

			// avoid trivial self-copies (x = x) which can appear after renaming
			if destKey == srcKey {
				continue
			}

			copyMap[destKey] = srcKey
		}
	}

	return copyMap
}

// extractSingleVar returns the variable from a bare VariableExpr, or false.
// only pointer and value forms of VariableExpr qualify; any other expression
// (BinaryOp, UnaryOp, Cast, ConstantExpr, etc.) returns false.
func extractSingleVar(expr ir.Expression) (ir.Variable, bool) {
	switch e := expr.(type) {
	case *ir.VariableExpr:
		return e.Var, true
	case ir.VariableExpr:
		return e.Var, true
	default:
		return ir.Variable{}, false
	}
}

// transitiveClosure computes the transitive closure of the copy map.
// given copyMap[x] = y and copyMap[y] = z, the result maps x -> z.
// the ssa property guarantees no cycles (each variable defined once),
// so the closure always terminates.
func (p *CopyPropagator) transitiveClosure(copyMap map[VarKey]VarKey) map[VarKey]VarKey {
	resolved := make(map[VarKey]VarKey, len(copyMap))

	// memoized resolution: follow the chain until we reach a variable
	// that is not itself a copy.
	var resolve func(k VarKey) VarKey
	resolve = func(k VarKey) VarKey {
		// already resolved
		if r, ok := resolved[k]; ok {
			return r
		}
		// not a copy at all
		next, ok := copyMap[k]
		if !ok {
			return k
		}
		// follow the chain
		ultimate := resolve(next)
		resolved[k] = ultimate
		return ultimate
	}

	for k := range copyMap {
		resolve(k)
	}

	return resolved
}

// rewriteUses replaces all uses of copied variables with their ultimate sources.
// returns the total number of replacements made.
func (p *CopyPropagator) rewriteUses(resolved map[VarKey]VarKey) int {
	count := 0
	for _, block := range p.function.Blocks {
		for _, instr := range block.Instructions {
			count += p.rewriteInstruction(instr, resolved)
		}
	}
	return count
}

// rewriteInstruction rewrites variable uses in a single instruction.
// the instruction is modified in place via pointer receivers.
func (p *CopyPropagator) rewriteInstruction(instr ir.IRInstruction, resolved map[VarKey]VarKey) int {
	count := 0
	switch i := instr.(type) {
	case *ir.Assign:
		// rewrite source expression; do NOT rewrite the destination
		newSrc, n := rewriteExpr(i.Source, resolved)
		i.Source = newSrc
		count += n

	case *ir.Load:
		newAddr, n := rewriteExpr(i.Address, resolved)
		i.Address = newAddr
		count += n

	case *ir.Store:
		newAddr, n1 := rewriteExpr(i.Address, resolved)
		newVal, n2 := rewriteExpr(i.Value, resolved)
		i.Address = newAddr
		i.Value = newVal
		count += n1 + n2

	case *ir.Branch:
		newCond, n := rewriteExpr(i.Condition, resolved)
		i.Condition = newCond
		count += n

	case *ir.Call:
		newTarget, n := rewriteExpr(i.Target, resolved)
		i.Target = newTarget
		count += n
		// rewrite call arguments (Variables, not Expressions)
		for j, arg := range i.Args {
			if rep, ok := resolveVar(arg, resolved); ok {
				i.Args[j] = rep
				count++
			}
		}

	case *ir.Return:
		if i.Value != nil {
			if rep, ok := resolveVar(*i.Value, resolved); ok {
				*i.Value = rep
				count++
			}
		}

	case *ir.Phi:
		// rewrite phi sources: each source variable may be a copy.
		// note: we rewrite the phi SOURCE variables (the uses), not the
		// phi destination. this is safe because we are replacing uses of
		// copied variables with their ultimate originals.
		for j, src := range i.Sources {
			if rep, ok := resolveVar(src.Var, resolved); ok {
				i.Sources[j].Var = rep
				count++
			}
		}

	case *ir.Intrinsic:
		for j, arg := range i.Args {
			newArg, n := rewriteExpr(arg, resolved)
			i.Args[j] = newArg
			count += n
		}

	case *ir.Jump:
		// no variable uses in unconditional jumps
	}
	return count
}

// rewriteExpr recursively rewrites variable references in an expression.
// returns the (possibly new) expression and the replacement count.
func rewriteExpr(expr ir.Expression, resolved map[VarKey]VarKey) (ir.Expression, int) {
	if expr == nil {
		return expr, 0
	}

	switch e := expr.(type) {
	case *ir.VariableExpr:
		if rep, ok := resolveVar(e.Var, resolved); ok {
			return &ir.VariableExpr{Var: rep}, 1
		}
		return e, 0

	case ir.VariableExpr:
		if rep, ok := resolveVar(e.Var, resolved); ok {
			return &ir.VariableExpr{Var: rep}, 1
		}
		return &e, 0

	case *ir.BinaryOp:
		newLeft, n1 := rewriteExpr(e.Left, resolved)
		newRight, n2 := rewriteExpr(e.Right, resolved)
		e.Left = newLeft
		e.Right = newRight
		return e, n1 + n2

	case ir.BinaryOp:
		newLeft, n1 := rewriteExpr(e.Left, resolved)
		newRight, n2 := rewriteExpr(e.Right, resolved)
		e.Left = newLeft
		e.Right = newRight
		return &e, n1 + n2

	case *ir.UnaryOp:
		newOperand, n := rewriteExpr(e.Operand, resolved)
		e.Operand = newOperand
		return e, n

	case ir.UnaryOp:
		newOperand, n := rewriteExpr(e.Operand, resolved)
		e.Operand = newOperand
		return &e, n

	case *ir.Cast:
		newExpr, n := rewriteExpr(e.Expr, resolved)
		e.Expr = newExpr
		return e, n

	case ir.Cast:
		newExpr, n := rewriteExpr(e.Expr, resolved)
		e.Expr = newExpr
		return &e, n

	default:
		// ConstantExpr and other non-variable expressions: no rewrite needed
		return expr, 0

	case *ir.LoadExpr:
		newAddr, n := rewriteExpr(e.Address, resolved)
		e.Address = newAddr
		return e, n

	case ir.LoadExpr:
		newAddr, n := rewriteExpr(e.Address, resolved)
		e.Address = newAddr
		return &e, n
	}
}

// resolveVar looks up a variable in the resolved copy map.
// returns the replacement variable and true if a replacement exists,
// or the original variable and false otherwise.
func resolveVar(v ir.Variable, resolved map[VarKey]VarKey) (ir.Variable, bool) {
	k := varKeyOf(v)
	repKey, ok := resolved[k]
	if !ok {
		return v, false
	}
	// preserve the type from the original variable; the name and version
	// come from the resolved copy source.
	rep := ir.Variable{
		Name:    repKey.Name,
		Version: repKey.Version,
		Type:    v.Type,
	}
	return rep, true
}

// PropagateCopies is the top-level entry point for copy propagation.
// it creates a CopyPropagator and runs it on the given function.
func PropagateCopies(
	function *ir.Function,
	cfgGraph *cfg.CFG,
	domTree *cfg.DominatorTree,
) (*CopyPropResult, error) {
	propagator := NewCopyPropagator(function, cfgGraph, domTree)
	return propagator.Propagate()
}
