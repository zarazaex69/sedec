package typeinfer

import (
	"fmt"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// maxFixedPointIterations caps the worklist loop to prevent infinite iteration
// on pathological inputs (e.g., mutually recursive functions with widening types).
const maxFixedPointIterations = 100

// systemVIntParamRegs lists the integer/pointer parameter registers for
// the System V AMD64 ABI in argument order.
var systemVIntParamRegs = []string{"rdi", "rsi", "rdx", "rcx", "r8", "r9"}

// systemVFloatParamRegs lists the floating-point parameter registers for
// the System V AMD64 ABI in argument order.
var systemVFloatParamRegs = []string{"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"}

// msX64IntParamRegs lists the integer/pointer parameter registers for
// the Microsoft x64 ABI in argument order.
var msX64IntParamRegs = []string{"rcx", "rdx", "r8", "r9"}

// msX64FloatParamRegs lists the floating-point parameter registers for
// the Microsoft x64 ABI in argument order.
var msX64FloatParamRegs = []string{"xmm0", "xmm1", "xmm2", "xmm3"}

// FunctionSummary holds the interprocedurally inferred type information
// for a single function. it is updated iteratively during fixed-point propagation.
type FunctionSummary struct {
	// FuncID is the canonical identifier of the function.
	FuncID FunctionID

	// ParamTypes holds the inferred type for each parameter position.
	// nil entries mean the type is not yet constrained.
	ParamTypes []ir.Type

	// ReturnType is the inferred return type. nil means not yet constrained.
	ReturnType ir.Type

	// Convention is the calling convention used by this function.
	Convention CallingConvention

	// ExtraConstraints holds additional constraints derived from call sites
	// that could not be expressed as simple parameter/return types.
	ExtraConstraints []TypeConstraint
}

// InterproceduralPropagator propagates type information across function call
// boundaries using a worklist-based fixed-point algorithm.
//
// the propagation direction is bottom-up: callee summaries are computed first,
// then propagated to callers. for recursive SCCs, the group is iterated until
// convergence.
//
// Requirements: 11.14, 11.16
type InterproceduralPropagator struct {
	// callGraph is the program-wide call graph.
	callGraph *CallGraph

	// solutions maps each function to its per-function type solution
	// produced by intraprocedural HM unification.
	solutions map[FunctionID]*TypeSolution

	// summaries holds the interprocedurally computed summary for each function.
	summaries map[FunctionID]*FunctionSummary
}

// NewInterproceduralPropagator creates a propagator for the given call graph
// and per-function type solutions.
func NewInterproceduralPropagator(
	cg *CallGraph,
	solutions map[FunctionID]*TypeSolution,
) *InterproceduralPropagator {
	return &InterproceduralPropagator{
		callGraph: cg,
		solutions: solutions,
		summaries: make(map[FunctionID]*FunctionSummary, len(cg.nodes)),
	}
}

// Propagate is the main entry point for interprocedural type propagation.
//
// algorithm:
//  1. seed initial summaries from per-function solutions and calling conventions.
//  2. compute SCCs via Tarjan's algorithm for correct recursive handling.
//  3. process SCCs in reverse topological order (bottom-up).
//  4. within each SCC, iterate until fixed point or maxFixedPointIterations.
//  5. after convergence, merge propagated constraints back into solutions.
//
// Requirements: 11.14, 11.16
func (p *InterproceduralPropagator) Propagate(
	callGraph *CallGraph,
	solutions map[FunctionID]*TypeSolution,
) error {
	// update internal state from arguments (allows reuse of the struct)
	p.callGraph = callGraph
	p.solutions = solutions

	// step 1: initialize summaries for all functions
	for _, id := range callGraph.Functions() {
		p.initSummary(id)
	}

	// step 2: seed from calling conventions
	for _, id := range callGraph.Functions() {
		p.seedFromCallingConvention(id)
	}

	// step 3: compute SCCs (Tarjan) for bottom-up ordering
	sccs := callGraph.SCCs()

	// step 4: process each SCC with fixed-point iteration
	for _, scc := range sccs {
		if err := p.processSCC(scc); err != nil {
			return err
		}
	}

	return nil
}

// initSummary creates an initial FunctionSummary for a function by reading
// its node descriptor from the call graph and its intraprocedural solution.
func (p *InterproceduralPropagator) initSummary(id FunctionID) {
	node := p.callGraph.Node(id)
	if node == nil {
		p.summaries[id] = &FunctionSummary{FuncID: id}
		return
	}

	// copy parameter types from the node (may be nil if not yet known)
	params := make([]ir.Type, len(node.Params))
	copy(params, node.Params)

	p.summaries[id] = &FunctionSummary{
		FuncID:     id,
		ParamTypes: params,
		ReturnType: node.ReturnType,
		Convention: node.Convention,
	}
}

// processSCC runs fixed-point iteration over a single strongly connected component.
// for non-recursive SCCs (single node, no self-edge), one pass suffices.
func (p *InterproceduralPropagator) processSCC(scc []FunctionID) error {
	for iter := 0; iter < maxFixedPointIterations; iter++ {
		changed := false

		for _, id := range scc {
			if p.propagateCallerToCallee(id) {
				changed = true
			}
			if p.propagateCalleeToCallerReturn(id) {
				changed = true
			}
			if p.propagateCalleeParamToCallerArg(id) {
				changed = true
			}
		}

		if !changed {
			// fixed point reached
			return nil
		}
	}

	// reached iteration limit - not an error, just conservative
	return nil
}

// propagateCallerToCallee seeds the callee's parameter types from the argument
// types observed at each call site where this function is the callee.
// returns true if any summary was updated.
func (p *InterproceduralPropagator) propagateCallerToCallee(calleeID FunctionID) bool {
	callerEdges := p.callGraph.Callers(calleeID)
	if len(callerEdges) == 0 {
		return false
	}

	calleeSummary := p.summaries[calleeID]
	if calleeSummary == nil {
		return false
	}

	changed := false

	for _, edge := range callerEdges {
		callerSol := p.solutions[edge.CallerID]

		for argIdx, argExpr := range edge.Site.ArgExprs {
			// resolve the argument type from the caller's solution
			argType := p.resolveExprType(argExpr, callerSol)
			if argType == nil {
				continue
			}

			// extend param slice if needed
			for len(calleeSummary.ParamTypes) <= argIdx {
				calleeSummary.ParamTypes = append(calleeSummary.ParamTypes, nil)
			}

			// merge the argument type into the callee's parameter type
			merged := p.mergeTypes(calleeSummary.ParamTypes[argIdx], argType)
			if !typesEqual(merged, calleeSummary.ParamTypes[argIdx]) {
				calleeSummary.ParamTypes[argIdx] = merged
				changed = true
			}
		}
	}

	return changed
}

// propagateCalleeToCallerReturn propagates the callee's return type back to
// the variable that receives the return value in each caller.
// it also attempts to refine the callee's return type from its intraprocedural
// solution if the summary does not yet have one.
// returns true if any solution was updated.
func (p *InterproceduralPropagator) propagateCalleeToCallerReturn(calleeID FunctionID) bool {
	calleeSummary := p.summaries[calleeID]
	if calleeSummary == nil {
		return false
	}

	changed := false

	if calleeSummary.ReturnType == nil {
		calleeSol := p.solutions[calleeID]
		if calleeSol != nil {
			retKey := fmt.Sprintf("$ret_%s", calleeID)
			if t, ok := calleeSol.Types[retKey]; ok && t != nil {
				calleeSummary.ReturnType = t
				changed = true
			}
		}
	}

	if calleeSummary.ReturnType == nil {
		return changed
	}

	callerEdges := p.callGraph.Callers(calleeID)

	for _, edge := range callerEdges {
		if edge.Site.ReturnVar == nil {
			continue
		}

		callerSol := p.solutions[edge.CallerID]
		if callerSol == nil {
			continue
		}

		varKey := edge.Site.ReturnVar.String()
		existing := callerSol.Types[varKey]
		merged := p.mergeTypes(existing, calleeSummary.ReturnType)

		if !typesEqual(merged, existing) {
			callerSol.Types[varKey] = merged
			changed = true
		}
	}

	return changed
}

// propagateCalleeParamToCallerArg propagates the callee's inferred parameter
// types back to the caller's argument variables. this is the reverse direction
// of propagateCallerToCallee: when a callee's parameter type is known (e.g.,
// from its own body analysis or from other callers), that type information
// flows back to constrain the argument expression in each caller.
// returns true if any caller solution was updated.
func (p *InterproceduralPropagator) propagateCalleeParamToCallerArg(calleeID FunctionID) bool {
	calleeSummary := p.summaries[calleeID]
	if calleeSummary == nil {
		return false
	}

	callerEdges := p.callGraph.Callers(calleeID)
	changed := false

	for _, edge := range callerEdges {
		callerSol := p.solutions[edge.CallerID]
		if callerSol == nil {
			continue
		}

		for argIdx, argExpr := range edge.Site.ArgExprs {
			if argIdx >= len(calleeSummary.ParamTypes) {
				break
			}
			paramType := calleeSummary.ParamTypes[argIdx]
			if paramType == nil {
				continue
			}

			varExpr, ok := argExpr.(ir.VariableExpr)
			if !ok {
				continue
			}

			varKey := varExpr.Var.String()
			existing := callerSol.Types[varKey]
			merged := p.mergeTypes(existing, paramType)
			if !typesEqual(merged, existing) {
				callerSol.Types[varKey] = merged
				changed = true
			}
		}
	}

	return changed
}

// mergeConstraints merges type constraints from multiple callers using the
// type lattice join operation. this is used when a callee has multiple callers
// with potentially different argument types for the same parameter.
func (p *InterproceduralPropagator) mergeConstraints(existing []TypeConstraint, incoming []TypeConstraint) []TypeConstraint {
	// build a map from constraint key to existing constraint for deduplication
	type constraintKey struct {
		kind       ConstraintKind
		leftName   string
		rightName  string
		fieldOff   int64
		paramIndex int
	}

	keyOf := func(c TypeConstraint) constraintKey {
		return constraintKey{
			kind:       c.Kind,
			leftName:   c.Left.Name,
			rightName:  c.Right.Name,
			fieldOff:   c.FieldOffset,
			paramIndex: c.ParamIndex,
		}
	}

	seen := make(map[constraintKey]int, len(existing))
	result := make([]TypeConstraint, 0, len(existing)+len(incoming))
	result = append(result, existing...)

	for i, c := range result {
		seen[keyOf(c)] = i
	}

	for _, c := range incoming {
		k := keyOf(c)
		if idx, ok := seen[k]; ok {
			// merge confidence: take the maximum (most informative)
			if c.Confidence > result[idx].Confidence {
				result[idx].Confidence = c.Confidence
			}
		} else {
			seen[k] = len(result)
			result = append(result, c)
		}
	}

	return result
}

// seedFromCallingConvention seeds initial parameter types for a function based
// on its calling convention. this provides high-confidence type axioms for
// register-passed parameters before any call-site evidence is available.
//
// Requirements: 11.16
func (p *InterproceduralPropagator) seedFromCallingConvention(id FunctionID) {
	node := p.callGraph.Node(id)
	if node == nil {
		return
	}

	summary := p.summaries[id]
	if summary == nil {
		return
	}

	sol := p.solutions[id]
	if sol == nil {
		return
	}

	switch node.Convention {
	case CallingConventionUnknown:
		// no register-based seeding for unknown convention
	case CallingConventionSystemVAMD64:
		p.seedSystemVParams(summary, sol)
	case CallingConventionMicrosoftX64:
		p.seedMicrosoftX64Params(summary, sol)
	}
}

// seedParamsFromRegisters is a shared helper that seeds parameter types from
// ABI register names into the function summary. it iterates over the integer
// and float register lists, looking up each register in the solution.
func (p *InterproceduralPropagator) seedParamsFromRegisters(
	summary *FunctionSummary,
	sol *TypeSolution,
	intRegs []string,
	floatRegs []string,
) {
	for i, reg := range intRegs {
		if i >= len(summary.ParamTypes) {
			break
		}
		if summary.ParamTypes[i] != nil {
			continue
		}
		if t, ok := sol.Types[reg]; ok && t != nil {
			summary.ParamTypes[i] = t
		}
	}

	for i, reg := range floatRegs {
		if i >= len(summary.ParamTypes) {
			break
		}
		if summary.ParamTypes[i] != nil {
			continue
		}
		if t, ok := sol.Types[reg]; ok && t != nil {
			summary.ParamTypes[i] = t
		}
	}

	if summary.ReturnType == nil {
		if t, ok := sol.Types["rax"]; ok && t != nil {
			summary.ReturnType = t
		}
	}
	if summary.ReturnType == nil {
		if t, ok := sol.Types["xmm0"]; ok && t != nil {
			if _, isFloat := t.(ir.FloatType); isFloat {
				summary.ReturnType = t
			}
		}
	}
}

// seedSystemVParams seeds parameter types from System V AMD64 ABI register names.
// integer/pointer params: RDI, RSI, RDX, RCX, R8, R9
// float params: XMM0-XMM7
// return value: RAX (integer), XMM0 (float)
func (p *InterproceduralPropagator) seedSystemVParams(summary *FunctionSummary, sol *TypeSolution) {
	p.seedParamsFromRegisters(summary, sol, systemVIntParamRegs, systemVFloatParamRegs)
}

// seedMicrosoftX64Params seeds parameter types from Microsoft x64 ABI register names.
// integer/pointer params: RCX, RDX, R8, R9
// float params: XMM0-XMM3
// return value: RAX (integer), XMM0 (float)
func (p *InterproceduralPropagator) seedMicrosoftX64Params(summary *FunctionSummary, sol *TypeSolution) {
	p.seedParamsFromRegisters(summary, sol, msX64IntParamRegs, msX64FloatParamRegs)
}

// resolveExprType extracts the ir.Type for an expression from a TypeSolution.
// for VariableExpr it looks up the variable name in the solution.
// for ConstantExpr it returns the constant's type directly.
// for compound expressions it returns nil (type not directly resolvable).
func (p *InterproceduralPropagator) resolveExprType(expr ir.Expression, sol *TypeSolution) ir.Type {
	if expr == nil {
		return nil
	}

	switch e := expr.(type) {
	case ir.VariableExpr:
		if sol != nil {
			if t, ok := sol.Types[e.Var.String()]; ok {
				return t
			}
		}
		// fall back to the variable's declared type
		return e.Var.Type

	case ir.ConstantExpr:
		return e.Value.Type()

	default:
		return nil
	}
}

// mergeTypes computes the join of two types in the type lattice.
//
// lattice rules:
//   - bottom (nil) join T = T
//   - T join T = T
//   - Int(n) join Int(m) = Int(max(n,m)) with widening
//   - Pointer(T) join Pointer(U) = Pointer(T join U)
//   - Array(T,n) join Array(U,n) = Array(T join U, n) when lengths match
//   - Struct join Struct = Struct when field-compatible
//   - Function join Function = Function when arity matches
//   - T join U where no widening rule applies = nil (conservative unknown)
func (p *InterproceduralPropagator) mergeTypes(a, b ir.Type) ir.Type {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if typesEqual(a, b) {
		return a
	}

	// integer widening: Int(n) join Int(m) = Int(max(n,m))
	ai, aIsInt := a.(ir.IntType)
	bi, bIsInt := b.(ir.IntType)
	if aIsInt && bIsInt {
		width := ai.Width
		if bi.Width > width {
			width = bi.Width
		}
		signed := ai.Signed || bi.Signed
		return ir.IntType{Width: width, Signed: signed}
	}

	// float widening: Float(n) join Float(m) = Float(max(n,m))
	af, aIsFloat := a.(ir.FloatType)
	bf, bIsFloat := b.(ir.FloatType)
	if aIsFloat && bIsFloat {
		width := af.Width
		if bf.Width > width {
			width = bf.Width
		}
		return ir.FloatType{Width: width}
	}

	// pointer covariance: Pointer(T) join Pointer(U) = Pointer(T join U)
	ap, aIsPtr := a.(ir.PointerType)
	bp, bIsPtr := b.(ir.PointerType)
	if aIsPtr && bIsPtr {
		merged := p.mergeTypes(ap.Pointee, bp.Pointee)
		if merged == nil {
			return ir.PointerType{Pointee: ir.VoidType{}}
		}
		return ir.PointerType{Pointee: merged}
	}

	// array covariance: Array(T,n) join Array(U,n) = Array(T join U, n)
	aa, aIsArr := a.(ir.ArrayType)
	ba, bIsArr := b.(ir.ArrayType)
	if aIsArr && bIsArr && aa.Length == ba.Length {
		merged := p.mergeTypes(aa.Element, ba.Element)
		if merged == nil {
			return nil
		}
		return ir.ArrayType{Element: merged, Length: aa.Length}
	}

	// struct merge: compatible when same number of fields at same offsets
	as, aIsStruct := a.(ir.StructType)
	bs, bIsStruct := b.(ir.StructType)
	if aIsStruct && bIsStruct {
		return p.mergeStructTypes(as, bs)
	}

	// function merge: compatible when same arity
	afn, aIsFn := a.(ir.FunctionType)
	bfn, bIsFn := b.(ir.FunctionType)
	if aIsFn && bIsFn {
		return p.mergeFunctionTypes(afn, bfn)
	}

	// int/float conflict: use the wider/more general type
	if aIsInt && bIsFloat {
		return b
	}
	if aIsFloat && bIsInt {
		return a
	}

	// all other combinations: conservative unknown
	return nil
}

// mergeStructTypes merges two struct types field-by-field.
// returns nil if the structs are incompatible (different field count or offsets).
func (p *InterproceduralPropagator) mergeStructTypes(a, b ir.StructType) ir.Type {
	if len(a.Fields) != len(b.Fields) {
		return nil
	}
	mergedFields := make([]ir.StructField, len(a.Fields))
	for i := range a.Fields {
		if a.Fields[i].Offset != b.Fields[i].Offset {
			return nil
		}
		ft := p.mergeTypes(a.Fields[i].Type, b.Fields[i].Type)
		if ft == nil {
			return nil
		}
		name := a.Fields[i].Name
		if name == "" {
			name = b.Fields[i].Name
		}
		mergedFields[i] = ir.StructField{
			Name:   name,
			Type:   ft,
			Offset: a.Fields[i].Offset,
		}
	}
	name := a.Name
	if name == "" {
		name = b.Name
	}
	return ir.StructType{Name: name, Fields: mergedFields}
}

// mergeFunctionTypes merges two function types by merging parameters and return types.
// returns nil if the functions have different arity.
func (p *InterproceduralPropagator) mergeFunctionTypes(a, b ir.FunctionType) ir.Type {
	if len(a.Parameters) != len(b.Parameters) {
		return nil
	}
	retMerged := p.mergeTypes(a.ReturnType, b.ReturnType)
	mergedParams := make([]ir.Type, len(a.Parameters))
	for i := range a.Parameters {
		pm := p.mergeTypes(a.Parameters[i], b.Parameters[i])
		if pm == nil {
			return nil
		}
		mergedParams[i] = pm
	}
	return ir.FunctionType{
		ReturnType: retMerged,
		Parameters: mergedParams,
		Variadic:   a.Variadic || b.Variadic,
	}
}

// Summary returns the computed FunctionSummary for the given function,
// or nil if the function was not processed.
func (p *InterproceduralPropagator) Summary(id FunctionID) *FunctionSummary {
	return p.summaries[id]
}

// Summaries returns all computed function summaries keyed by FunctionID.
func (p *InterproceduralPropagator) Summaries() map[FunctionID]*FunctionSummary {
	return p.summaries
}

// ApplySummaries writes the propagated parameter and return types back into
// the per-function TypeSolutions as high-confidence constraints.
// this allows the intraprocedural unifier to benefit from interprocedural info.
func (p *InterproceduralPropagator) ApplySummaries() {
	for id, summary := range p.summaries {
		sol := p.solutions[id]
		if sol == nil {
			continue
		}

		// write parameter types into the solution under canonical names
		for i, paramType := range summary.ParamTypes {
			if paramType == nil {
				continue
			}
			key := fmt.Sprintf("$param_%s_%d", id, i)
			sol.Types[key] = paramType
		}

		// write return type into the solution
		if summary.ReturnType != nil {
			key := fmt.Sprintf("$ret_%s", id)
			sol.Types[key] = summary.ReturnType
		}
	}
}
