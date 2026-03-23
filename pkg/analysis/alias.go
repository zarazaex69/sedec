// Package analysis provides data flow analysis algorithms for the sedec decompiler.
package analysis

// ============================================================================
// Alias Analysis
//
// flow-sensitive alias analysis computing may-alias and must-alias relationships
// for pointer variables in SSA IR. the analysis integrates three complementary
// techniques:
//
//  1. region-based non-aliasing: two pointers into disjoint memory regions
//     (stack vs heap vs global vs code) cannot alias. derived from VSA results.
//
//  2. type-based non-aliasing: two pointers with incompatible pointee types
//     cannot alias (strict aliasing rules, analogous to TBAA in LLVM).
//
//  3. points-to set intersection: two pointers may-alias iff their points-to
//     sets (from Andersen/Steensgaard analysis) intersect. must-alias iff
//     they are the same SSA variable or their points-to sets are identical
//     singletons pointing to the same abstract location.
//
// the analysis is flow-sensitive: alias information is computed per program
// point using the Memory SSA def-use chains to track pointer values through
// stores and loads.
//
// requirements: 25.1, 25.2, 25.3, 25.4, 25.6
// ============================================================================

import (
	"fmt"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
	"github.com/zarazaex69/sedec/pkg/ssa"
	typeinfer "github.com/zarazaex69/sedec/pkg/types"
)

// AliasKind classifies the alias relationship between two pointer expressions.
type AliasKind int

const (
	// AliasNo means the two pointers definitely cannot point to the same location.
	// this is a definite result: the analysis has proven non-aliasing.
	AliasNo AliasKind = iota

	// AliasMay means the two pointers might point to the same location.
	// this is the conservative default when the analysis cannot prove otherwise.
	AliasMay

	// AliasMust means the two pointers definitely point to the same location
	// at the given program point. this is a definite result.
	AliasMust
)

// String returns a human-readable name for the alias kind.
func (k AliasKind) String() string {
	switch k {
	case AliasNo:
		return "no-alias"
	case AliasMay:
		return "may-alias"
	case AliasMust:
		return "must-alias"
	default:
		return fmt.Sprintf("alias(%d)", int(k))
	}
}

// AliasQuery represents a query about the alias relationship between two pointers
// at a specific program point.
type AliasQuery struct {
	// A and B are the two pointer variables being queried.
	A ir.Variable
	B ir.Variable
	// Point is the program point at which the query is evaluated.
	// if Point is the zero value, the query is flow-insensitive.
	Point ProgramPoint
}

// AliasResult holds the result of a single alias query.
type AliasResult struct {
	Query  AliasQuery
	Kind   AliasKind
	Reason string // human-readable explanation for the result
}

// AliasSet stores all alias pairs for a function, indexed by variable pair.
// the key is a canonical pair (smaller name first) to avoid duplicates.
type AliasSet struct {
	// pairs maps canonical variable pair keys to their alias kind.
	pairs map[aliasPairKey]AliasKind
}

// aliasPairKey is a canonical key for an unordered pair of SSA variables.
type aliasPairKey struct {
	nameA    string
	versionA int
	nameB    string
	versionB int
}

// newAliasPairKey creates a canonical (sorted) key for a variable pair.
func newAliasPairKey(a, b ir.Variable) aliasPairKey {
	// canonical order: sort by name then version to avoid (a,b) vs (b,a) duplicates
	if a.Name < b.Name || (a.Name == b.Name && a.Version < b.Version) {
		return aliasPairKey{a.Name, a.Version, b.Name, b.Version}
	}
	return aliasPairKey{b.Name, b.Version, a.Name, a.Version}
}

// NewAliasSet creates an empty alias set.
func NewAliasSet() *AliasSet {
	return &AliasSet{pairs: make(map[aliasPairKey]AliasKind)}
}

// Set records the alias kind for a variable pair.
func (as *AliasSet) Set(a, b ir.Variable, kind AliasKind) {
	as.pairs[newAliasPairKey(a, b)] = kind
}

// Get returns the alias kind for a variable pair.
// returns AliasMust if both variables are the same SSA variable.
// returns AliasMay if the pair has not been explicitly recorded.
func (as *AliasSet) Get(a, b ir.Variable) AliasKind {
	// same SSA variable always must-aliases itself
	if a.Name == b.Name && a.Version == b.Version {
		return AliasMust
	}
	if kind, ok := as.pairs[newAliasPairKey(a, b)]; ok {
		return kind
	}
	return AliasMay
}

// MayAlias reports whether two variables may alias.
func (as *AliasSet) MayAlias(a, b ir.Variable) bool {
	return as.Get(a, b) != AliasNo
}

// MustAlias reports whether two variables must alias.
func (as *AliasSet) MustAlias(a, b ir.Variable) bool {
	return as.Get(a, b) == AliasMust
}

// NoAlias reports whether two variables definitely do not alias.
func (as *AliasSet) NoAlias(a, b ir.Variable) bool {
	return as.Get(a, b) == AliasNo
}

// Len returns the number of recorded alias pairs.
func (as *AliasSet) Len() int {
	return len(as.pairs)
}

// AliasAnalysisResult holds the complete alias analysis results for a function.
type AliasAnalysisResult struct {
	// GlobalAliases stores flow-insensitive alias pairs (conservative).
	GlobalAliases *AliasSet

	// PointAliases stores flow-sensitive alias pairs per program point.
	// keyed by program point, each entry contains the alias set valid at that point.
	PointAliases map[ProgramPoint]*AliasSet

	// PointerVars is the set of all pointer-typed variables in the function.
	PointerVars []ir.Variable

	// AliasSets groups variables into equivalence classes of must-alias sets.
	// variables in the same class must alias each other at all program points.
	MustAliasSets [][]ir.Variable
}

// MayAliasAt reports whether two variables may alias at a specific program point.
// falls back to global (flow-insensitive) result if no point-specific data exists.
func (r *AliasAnalysisResult) MayAliasAt(point ProgramPoint, a, b ir.Variable) bool {
	if pointSet, ok := r.PointAliases[point]; ok {
		return pointSet.MayAlias(a, b)
	}
	return r.GlobalAliases.MayAlias(a, b)
}

// MustAliasAt reports whether two variables must alias at a specific program point.
func (r *AliasAnalysisResult) MustAliasAt(point ProgramPoint, a, b ir.Variable) bool {
	if pointSet, ok := r.PointAliases[point]; ok {
		return pointSet.MustAlias(a, b)
	}
	return r.GlobalAliases.MustAlias(a, b)
}

// NoAliasAt reports whether two variables definitely do not alias at a program point.
func (r *AliasAnalysisResult) NoAliasAt(point ProgramPoint, a, b ir.Variable) bool {
	if pointSet, ok := r.PointAliases[point]; ok {
		return pointSet.NoAlias(a, b)
	}
	return r.GlobalAliases.NoAlias(a, b)
}

// AliasAnalyzer computes alias relationships for pointer variables in a function.
//
// the analysis pipeline:
//  1. collect all pointer-typed variables from the IR
//  2. run Andersen's points-to analysis to get precise points-to sets
//  3. run VSA to get memory region information for each variable
//  4. for each pair of pointer variables, determine alias kind:
//     a. same SSA variable → must-alias
//     b. disjoint memory regions (from VSA) → no-alias
//     c. type-incompatible pointees → no-alias
//     d. points-to sets intersect → may-alias
//     e. points-to sets are identical singletons → must-alias
//     f. otherwise → may-alias (conservative)
//  5. integrate with Memory SSA for flow-sensitive refinement
type AliasAnalyzer struct {
	function *ir.Function
	cfgGraph *cfg.CFG
	domTree  *cfg.DominatorTree
	memSSA   *ssa.MemorySSAInfo

	// vsaResult provides memory region information for region-based non-aliasing
	vsaResult *VSAResult

	// andersenPTS provides precise points-to sets for intersection-based aliasing
	andersenPTS typeinfer.AndersenPointsToSet
}

// NewAliasAnalyzer creates a new alias analyzer.
// vsaResult and memSSA may be nil; the analysis degrades gracefully without them.
func NewAliasAnalyzer(
	function *ir.Function,
	cfgGraph *cfg.CFG,
	domTree *cfg.DominatorTree,
	vsaResult *VSAResult,
	memSSA *ssa.MemorySSAInfo,
) *AliasAnalyzer {
	return &AliasAnalyzer{
		function:  function,
		cfgGraph:  cfgGraph,
		domTree:   domTree,
		memSSA:    memSSA,
		vsaResult: vsaResult,
	}
}

// ComputeAliasSets is the main entry point for alias analysis.
// it computes may-alias and must-alias relationships for all pointer pairs
// in the function and returns the complete AliasAnalysisResult.
//
// requirements: 25.1, 25.2, 25.3, 25.4, 25.6
func (a *AliasAnalyzer) ComputeAliasSets() (*AliasAnalysisResult, error) {
	if a.function == nil {
		return nil, fmt.Errorf("alias analysis: %w", ErrNilFunction)
	}
	if len(a.function.Blocks) == 0 {
		return nil, fmt.Errorf("alias analysis: function %q: %w", a.function.Name, ErrNoBlocks)
	}

	result := &AliasAnalysisResult{
		GlobalAliases: NewAliasSet(),
		PointAliases:  make(map[ProgramPoint]*AliasSet),
	}

	// step 1: collect all pointer-typed variables
	result.PointerVars = a.collectPointerVariables()

	// step 2: run Andersen's points-to analysis for precise intersection checks
	andersenAnalyzer := typeinfer.NewAndersenAnalyzer()
	a.andersenPTS = andersenAnalyzer.Analyze(a.function)

	// step 3: compute flow-insensitive global alias pairs
	a.computeGlobalAliases(result)

	// step 4: compute flow-sensitive per-point alias refinements
	a.computeFlowSensitiveAliases(result)

	// step 5: build must-alias equivalence classes
	result.MustAliasSets = a.buildMustAliasSets(result.PointerVars, result.GlobalAliases)

	return result, nil
}

// collectPointerVariables scans all instructions and collects pointer-typed variables.
// a variable is considered a pointer if its type is ir.PointerType or if it is
// used as an address in a load/store instruction.
func (a *AliasAnalyzer) collectPointerVariables() []ir.Variable {
	seen := make(map[string]ir.Variable)

	for _, block := range a.function.Blocks {
		for _, instr := range block.Instructions {
			// collect defined variables with pointer types
			if defVar := extractDefinedVariable(instr); defVar != nil {
				if isPointerType(defVar.Type) {
					seen[defVar.String()] = *defVar
				}
			}

			// collect variables used as addresses in loads/stores
			switch i := instr.(type) {
			case *ir.Load:
				for _, v := range extractVarsFromExpression(i.Address) {
					seen[v.String()] = v
				}
			case *ir.Store:
				for _, v := range extractVarsFromExpression(i.Address) {
					seen[v.String()] = v
				}
			case *ir.Call:
				// function pointer targets are pointer variables
				for _, v := range extractVarsFromExpression(i.Target) {
					seen[v.String()] = v
				}
			}
		}
	}

	result := make([]ir.Variable, 0, len(seen))
	for _, v := range seen {
		result = append(result, v)
	}
	return result
}

// isPointerType reports whether a type is a pointer type.
func isPointerType(t ir.Type) bool {
	if t == nil {
		return false
	}
	switch t.(type) {
	case ir.PointerType:
		return true
	default:
		return false
	}
}

// computeGlobalAliases computes flow-insensitive alias pairs for all pointer variable pairs.
// this is the conservative baseline: may-alias unless proven otherwise.
func (a *AliasAnalyzer) computeGlobalAliases(result *AliasAnalysisResult) {
	vars := result.PointerVars
	n := len(vars)

	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			varA := vars[i]
			varB := vars[j]

			kind := a.queryAliasKind(varA, varB)
			if kind != AliasMay {
				// only record non-default results to save memory
				result.GlobalAliases.Set(varA, varB, kind)
			}
		}
	}
}

// queryAliasKind determines the alias relationship between two pointer variables
// using all available analysis information.
func (a *AliasAnalyzer) queryAliasKind(varA, varB ir.Variable) AliasKind {
	// rule 1: same SSA variable → must-alias
	if varA.Name == varB.Name && varA.Version == varB.Version {
		return AliasMust
	}

	// rule 2: type-based non-aliasing (TBAA)
	// two pointers with incompatible pointee types cannot alias
	if a.typeIncompatible(varA, varB) {
		return AliasNo
	}

	// rule 3: region-based non-aliasing from VSA
	// two pointers into disjoint memory regions cannot alias
	if a.vsaResult != nil {
		if a.regionsDisjoint(varA, varB) {
			return AliasNo
		}
	}

	// rule 4: points-to set analysis
	// use Andersen's precise points-to sets for intersection check
	ptsA := a.andersenPTS[varA.String()]
	ptsB := a.andersenPTS[varB.String()]

	if len(ptsA) > 0 && len(ptsB) > 0 {
		// check if points-to sets intersect
		if !pointsToSetsIntersect(ptsA, ptsB) {
			return AliasNo
		}

		// check for must-alias: both point to the same single abstract location
		if len(ptsA) == 1 && len(ptsB) == 1 && ptsA[0] == ptsB[0] {
			return AliasMust
		}
	}

	// conservative default: may-alias
	return AliasMay
}

// typeIncompatible reports whether two pointer variables have incompatible pointee types.
// two pointers are type-incompatible if their pointee types are concrete and different
// (e.g., *int32 vs *float64). this implements strict aliasing rules.
func (a *AliasAnalyzer) typeIncompatible(varA, varB ir.Variable) bool {
	typeA := varA.Type
	typeB := varB.Type

	if typeA == nil || typeB == nil {
		return false // unknown types: conservative
	}

	ptrA, isPtrA := typeA.(ir.PointerType)
	ptrB, isPtrB := typeB.(ir.PointerType)

	if !isPtrA || !isPtrB {
		return false // not both pointers: not applicable
	}

	// void pointers can alias anything
	if isVoidType(ptrA.Pointee) || isVoidType(ptrB.Pointee) {
		return false
	}

	// check pointee type compatibility
	return !typesCompatible(ptrA.Pointee, ptrB.Pointee)
}

// isVoidType reports whether a type is void.
func isVoidType(t ir.Type) bool {
	if t == nil {
		return true
	}
	_, isVoid := t.(ir.VoidType)
	return isVoid
}

// typesCompatible reports whether two types are compatible for aliasing purposes.
// two types are compatible if they are the same type or if one is a subtype of the other.
// this is a conservative check: when in doubt, return true (compatible).
func typesCompatible(a, b ir.Type) bool {
	if a == nil || b == nil {
		return true
	}

	// void is compatible with everything
	if isVoidType(a) || isVoidType(b) {
		return true
	}

	// same type string → compatible
	if a.String() == b.String() {
		return true
	}

	// integer types of different widths are incompatible
	intA, isIntA := a.(ir.IntType)
	intB, isIntB := b.(ir.IntType)
	if isIntA && isIntB {
		// different widths or signedness: incompatible for strict aliasing
		return intA.Width == intB.Width
	}

	// float types of different widths are incompatible
	floatA, isFloatA := a.(ir.FloatType)
	floatB, isFloatB := b.(ir.FloatType)
	if isFloatA && isFloatB {
		return floatA.Width == floatB.Width
	}

	// int and float are incompatible
	if (isIntA && isFloatB) || (isFloatA && isIntB) {
		return false
	}

	// pointer types: compatible if pointees are compatible
	ptrA, isPtrA := a.(ir.PointerType)
	ptrB, isPtrB := b.(ir.PointerType)
	if isPtrA && isPtrB {
		return typesCompatible(ptrA.Pointee, ptrB.Pointee)
	}

	// struct types: compatible only if same name
	structA, isStructA := a.(ir.StructType)
	structB, isStructB := b.(ir.StructType)
	if isStructA && isStructB {
		if structA.Name != "" && structB.Name != "" {
			return structA.Name == structB.Name
		}
		return true // anonymous structs: conservative
	}

	// mixed categories (e.g., int vs struct): incompatible
	if (isIntA || isFloatA) && (isStructA || isStructB) {
		return false
	}

	// conservative: assume compatible
	return true
}

// regionsDisjoint reports whether two pointer variables point into disjoint memory regions.
// uses VSA results to determine the memory regions each pointer can point into.
// two pointers are disjoint if all their possible regions are different.
func (a *AliasAnalyzer) regionsDisjoint(varA, varB ir.Variable) bool {
	if a.vsaResult == nil {
		return false
	}

	vsA := a.vsaResult.GetValueSet(varA)
	vsB := a.vsaResult.GetValueSet(varB)

	if vsA.IsTop() || vsB.IsTop() || vsA.IsBottom() || vsB.IsBottom() {
		return false // unknown regions: conservative
	}

	regionsA := vsA.Regions()
	regionsB := vsB.Regions()

	if len(regionsA) == 0 || len(regionsB) == 0 {
		return false
	}

	// check if any region from A overlaps with any region from B
	for _, rA := range regionsA {
		for _, rB := range regionsB {
			if regionsOverlap(rA, rB, vsA, vsB) {
				return false // found overlap: not disjoint
			}
		}
	}

	return true // all region pairs are disjoint
}

// regionsOverlap reports whether two memory regions can overlap.
// two regions overlap if they are the same kind and their offset intervals intersect.
func regionsOverlap(rA, rB MemoryRegion, vsA, vsB *ValueSet) bool {
	// different region kinds are always disjoint
	// (stack vs heap vs global vs code cannot overlap)
	if rA.Kind != rB.Kind {
		return false
	}

	// unknown regions may overlap with anything
	if rA.Kind == RegionUnknown || rB.Kind == RegionUnknown {
		return true
	}

	// same kind but different IDs: disjoint (different stack frames, heap allocations)
	if rA.ID != rB.ID {
		return false
	}

	// same region: check if offset intervals intersect
	siA := vsA.GetInterval(rA)
	siB := vsB.GetInterval(rB)

	if siA.IsEmpty() || siB.IsEmpty() {
		return false
	}

	// intervals overlap if they share at least one value
	intersection := siA.Meet(siB)
	return !intersection.IsEmpty()
}

// pointsToSetsIntersect reports whether two points-to sets share any abstract location.
func pointsToSetsIntersect(ptsA, ptsB []string) bool {
	if len(ptsA) == 0 || len(ptsB) == 0 {
		return false
	}

	// build a set from the smaller slice for O(min(|A|,|B|)) intersection check
	if len(ptsA) > len(ptsB) {
		ptsA, ptsB = ptsB, ptsA
	}

	setA := make(map[string]bool, len(ptsA))
	for _, loc := range ptsA {
		setA[loc] = true
	}

	for _, loc := range ptsB {
		if setA[loc] {
			return true
		}
	}
	return false
}

// computeFlowSensitiveAliases refines alias information at specific program points
// by tracking pointer assignments through SSA def-use chains. Memory SSA is used
// for additional store/load dependency refinement when available, but the core
// pointer assignment tracking works directly on IR instructions.
func (a *AliasAnalyzer) computeFlowSensitiveAliases(result *AliasAnalysisResult) {
	rpo := a.reversePostOrder()

	for _, blockID := range rpo {
		block, exists := a.function.Blocks[blockID]
		if !exists {
			continue
		}

		for instrIdx, instr := range block.Instructions {
			point := ProgramPoint{BlockID: blockID, InstrIdx: instrIdx}

			switch typed := instr.(type) {
			case *ir.Assign:
				a.refineAliasAtAssign(typed, point, result)
			case ir.Assign:
				a.refineAliasAtAssign(&typed, point, result)
			}

			switch typed := instr.(type) {
			case *ir.Phi:
				a.refineAliasAtPhi(typed, point, result)
			case ir.Phi:
				a.refineAliasAtPhi(&typed, point, result)
			}
		}
	}

	// Memory SSA refinement: use def-use chains to identify loads that
	// read from the same memory version as a store, establishing must-alias
	// between the store address and load address at those program points.
	a.refineWithMemorySSA(result)
}

// refineWithMemorySSA uses Memory SSA def-use chains to refine alias information.
// when a MemoryDef (store) has MemoryUse (load) consumers reading the same version,
// and no intervening MemoryDef exists, the store and load addresses must-alias
// if they access the same memory version without any clobbering def in between.
func (a *AliasAnalyzer) refineWithMemorySSA(result *AliasAnalysisResult) {
	if a.memSSA == nil {
		return
	}

	for defVersion, uses := range a.memSSA.DefUseChains {
		var defInstr ir.IRInstruction
		for _, defs := range a.memSSA.Defs {
			for _, d := range defs {
				if d.Version == defVersion {
					defInstr = d.Instruction
					break
				}
			}
			if defInstr != nil {
				break
			}
		}
		if defInstr == nil {
			continue
		}

		storeAddr := extractMemoryAddress(defInstr)
		if storeAddr == nil {
			continue
		}
		storeVars := extractVarsFromExpression(storeAddr)
		if len(storeVars) == 0 {
			continue
		}

		for _, use := range uses {
			loadAddr := extractMemoryAddress(use.Instruction)
			if loadAddr == nil {
				continue
			}
			loadVars := extractVarsFromExpression(loadAddr)
			if len(loadVars) == 0 {
				continue
			}

			// find the instruction index for this use in its block
			useBlock, exists := a.function.Blocks[use.Block]
			if !exists {
				continue
			}
			useIdx := -1
			for idx, bi := range useBlock.Instructions {
				if bi == use.Instruction {
					useIdx = idx
					break
				}
			}
			if useIdx < 0 {
				continue
			}

			usePoint := ProgramPoint{BlockID: use.Block, InstrIdx: useIdx}

			// the load reads from the exact memory version produced by the store.
			// if both use the same single address variable, they must-alias at this point.
			for _, sv := range storeVars {
				for _, lv := range loadVars {
					if sv.Name == lv.Name && sv.Version == lv.Version {
						pointSet := a.getOrCreatePointSet(usePoint, result)
						pointSet.Set(sv, lv, AliasMust)
					}
				}
			}
		}
	}
}

// refineAliasAtAssign refines alias information at an assignment instruction.
// if the source is a variable, the destination must-aliases the source at this point.
func (a *AliasAnalyzer) refineAliasAtAssign(
	assign *ir.Assign,
	point ProgramPoint,
	result *AliasAnalysisResult,
) {
	if !isPointerType(assign.Dest.Type) {
		return
	}

	// handle both *ir.VariableExpr and ir.VariableExpr source forms
	var srcVar *ir.Variable
	switch src := assign.Source.(type) {
	case *ir.VariableExpr:
		srcVar = &src.Var
	case ir.VariableExpr:
		v := src.Var
		srcVar = &v
	}

	if srcVar != nil && isPointerType(srcVar.Type) {
		pointSet := a.getOrCreatePointSet(point, result)
		pointSet.Set(assign.Dest, *srcVar, AliasMust)
	}
}

// refineAliasAtPhi refines alias information at a phi-node.
// the phi destination may-aliases all source variables.
func (a *AliasAnalyzer) refineAliasAtPhi(
	phi *ir.Phi,
	point ProgramPoint,
	result *AliasAnalysisResult,
) {
	if !isPointerType(phi.Dest.Type) {
		return
	}

	pointSet := a.getOrCreatePointSet(point, result)
	for _, src := range phi.Sources {
		if isPointerType(src.Var.Type) {
			// phi destination may-aliases each source (conservative)
			// only record if not already no-alias from global analysis
			globalKind := result.GlobalAliases.Get(phi.Dest, src.Var)
			if globalKind != AliasNo {
				pointSet.Set(phi.Dest, src.Var, AliasMay)
			}
		}
	}
}

// getOrCreatePointSet returns the alias set for a program point, creating it if absent.
func (a *AliasAnalyzer) getOrCreatePointSet(
	point ProgramPoint,
	result *AliasAnalysisResult,
) *AliasSet {
	if set, ok := result.PointAliases[point]; ok {
		return set
	}
	set := NewAliasSet()
	result.PointAliases[point] = set
	return set
}

// buildMustAliasSets groups variables into must-alias equivalence classes.
// uses union-find to efficiently compute transitive must-alias closure.
func (a *AliasAnalyzer) buildMustAliasSets(
	vars []ir.Variable,
	aliases *AliasSet,
) [][]ir.Variable {
	// union-find for must-alias equivalence classes
	parent := make(map[string]string, len(vars))
	for _, v := range vars {
		parent[v.String()] = v.String()
	}

	var findRoot func(string) string
	findRoot = func(name string) string {
		if parent[name] != name {
			parent[name] = findRoot(parent[name]) // path compression
		}
		return parent[name]
	}

	union := func(a, b string) {
		ra, rb := findRoot(a), findRoot(b)
		if ra != rb {
			parent[ra] = rb
		}
	}

	// union all must-alias pairs
	n := len(vars)
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if aliases.MustAlias(vars[i], vars[j]) {
				union(vars[i].String(), vars[j].String())
			}
		}
	}

	// collect equivalence classes
	classes := make(map[string][]ir.Variable)
	for _, v := range vars {
		root := findRoot(v.String())
		classes[root] = append(classes[root], v)
	}

	result := make([][]ir.Variable, 0, len(classes))
	for _, class := range classes {
		if len(class) > 1 {
			result = append(result, class)
		}
	}
	return result
}

// reversePostOrder computes a reverse postorder traversal of the cfg.
//
//nolint:dupl // similar to other analyzers
func (a *AliasAnalyzer) reversePostOrder() []ir.BlockID {
	visited := make(map[ir.BlockID]bool)
	postOrder := make([]ir.BlockID, 0, len(a.function.Blocks))

	var dfs func(ir.BlockID)
	dfs = func(blockID ir.BlockID) {
		if visited[blockID] {
			return
		}
		visited[blockID] = true

		block, exists := a.function.Blocks[blockID]
		if !exists {
			return
		}

		for _, succID := range block.Successors {
			dfs(succID)
		}

		postOrder = append(postOrder, blockID)
	}

	dfs(a.function.EntryBlock)

	for blockID := range a.function.Blocks {
		if !visited[blockID] {
			dfs(blockID)
		}
	}

	rpo := make([]ir.BlockID, len(postOrder))
	for i, id := range postOrder {
		rpo[len(postOrder)-1-i] = id
	}
	return rpo
}

// ============================================================================
// Memory SSA integration: alias-aware memory dependency queries
// ============================================================================

// MemoryDependencyKind classifies the dependency between two memory operations.
type MemoryDependencyKind int

const (
	// MemDepNone means the two memory operations are independent (no dependency).
	MemDepNone MemoryDependencyKind = iota
	// MemDepMay means the two operations may access the same memory location.
	MemDepMay
	// MemDepMust means the two operations definitely access the same memory location.
	MemDepMust
)

// String returns a human-readable name for the memory dependency kind.
func (k MemoryDependencyKind) String() string {
	switch k {
	case MemDepNone:
		return "no-dep"
	case MemDepMay:
		return "may-dep"
	case MemDepMust:
		return "must-dep"
	default:
		return fmt.Sprintf("dep(%d)", int(k))
	}
}

// QueryMemoryDependency determines whether two memory operations (load/store)
// have a dependency based on alias analysis results.
//
// a load-store dependency exists if the load may read from the same location
// that the store writes to. a store-store dependency exists if both stores
// may write to the same location.
//
// requirements: 25.6
func QueryMemoryDependency(
	instrA, instrB ir.IRInstruction,
	pointA, pointB ProgramPoint,
	aliasResult *AliasAnalysisResult,
) MemoryDependencyKind {
	addrA := extractMemoryAddress(instrA)
	addrB := extractMemoryAddress(instrB)

	if addrA == nil || addrB == nil {
		return MemDepNone // not memory operations
	}

	// extract pointer variables from address expressions
	varsA := extractVarsFromExpression(addrA)
	varsB := extractVarsFromExpression(addrB)

	if len(varsA) == 0 || len(varsB) == 0 {
		// constant addresses: check if they are equal
		constA := extractConstantAddress(addrA)
		constB := extractConstantAddress(addrB)
		if constA != nil && constB != nil {
			if *constA == *constB {
				return MemDepMust
			}
			return MemDepNone
		}
		return MemDepMay // conservative
	}

	// check alias relationship between all pairs of address variables
	worstCase := MemDepNone
	for _, vA := range varsA {
		for _, vB := range varsB {
			mayA := aliasResult.MayAliasAt(pointA, vA, vB)
			mayB := aliasResult.MayAliasAt(pointB, vA, vB)
			if mayA || mayB {
				mustA := aliasResult.MustAliasAt(pointA, vA, vB)
				mustB := aliasResult.MustAliasAt(pointB, vA, vB)
				if mustA || mustB {
					return MemDepMust
				}
				worstCase = MemDepMay
			}
		}
	}

	return worstCase
}

// extractMemoryAddress extracts the address expression from a load or store instruction.
// returns nil if the instruction is not a memory operation.
func extractMemoryAddress(instr ir.IRInstruction) ir.Expression {
	switch i := instr.(type) {
	case *ir.Load:
		return i.Address
	case *ir.Store:
		return i.Address
	default:
		return nil
	}
}

// extractConstantAddress extracts a constant integer address from an expression.
// returns nil if the expression is not a constant integer.
func extractConstantAddress(expr ir.Expression) *int64 {
	switch e := expr.(type) {
	case *ir.ConstantExpr:
		if ic, ok := e.Value.(ir.IntConstant); ok {
			return &ic.Value
		}
	case ir.ConstantExpr:
		if ic, ok := e.Value.(ir.IntConstant); ok {
			return &ic.Value
		}
	}
	return nil
}

// ============================================================================
// Top-level entry point
// ============================================================================

// PerformAliasAnalysis runs the complete alias analysis pipeline for a function.
// vsaResult and memSSA are optional; pass nil to skip those refinements.
//
// requirements: 25.1, 25.2, 25.3, 25.4, 25.6
func PerformAliasAnalysis(
	function *ir.Function,
	cfgGraph *cfg.CFG,
	domTree *cfg.DominatorTree,
	vsaResult *VSAResult,
	memSSA *ssa.MemorySSAInfo,
) (*AliasAnalysisResult, error) {
	analyzer := NewAliasAnalyzer(function, cfgGraph, domTree, vsaResult, memSSA)
	return analyzer.ComputeAliasSets()
}
