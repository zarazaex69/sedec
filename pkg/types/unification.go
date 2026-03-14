package typeinfer

import (
	"fmt"
	"strings"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// Type Terms - the internal representation used during unification
// ============================================================================

// termKind classifies the shape of a type term in the unification lattice.
type termKind int

const (
	termVar      termKind = iota // unresolved type variable (free)
	termConcrete                 // known concrete ir.Type (ground term)
	termPointer                  // pointer constructor: *T
	termArray                    // array constructor: [N]T
	termStruct                   // struct constructor: {f0:T0, f1:T1, ...}
	termFunction                 // function constructor: func(T0,...) R
)

// term is a node in the type term graph.
// during unification, terms are linked via the union-find parent pointer.
type term struct {
	kind termKind

	// for termConcrete: the resolved ir.Type
	concrete ir.Type

	// for termPointer: index of the pointee term in Unifier.terms
	pointee int

	// for termArray: element term index and length
	arrayElem int
	arrayLen  uint64

	// for termStruct: ordered list of field descriptors
	structFields []termField

	// for termFunction: parameter term indices and return term index
	funcParams []int
	funcReturn int

	// union-find bookkeeping
	parent int // index of parent term; self-loop means root
	rank   int // union-by-rank heuristic
}

// termField describes a single field in a struct term.
type termField struct {
	offset uint64
	termID int
}

// ============================================================================
// TypeSolution - the result of successful unification
// ============================================================================

// TypeSolution maps each TypeVar name to its inferred ir.Type.
// variables that remain free after solving are mapped to nil.
type TypeSolution struct {
	// Types maps TypeVar.Name → resolved ir.Type (nil = still polymorphic)
	Types map[string]ir.Type

	// Conflicts records constraints that could not be satisfied.
	// populated only when unification partially fails (soft constraints).
	Conflicts []ConflictRecord
}

// ConflictRecord describes a single unification failure.
type ConflictRecord struct {
	Constraint TypeConstraint
	Reason     string
}

// String returns a human-readable summary of the solution.
func (s *TypeSolution) String() string {
	var sb strings.Builder
	sb.WriteString("TypeSolution{\n")
	for name, t := range s.Types {
		if t != nil {
			sb.WriteString(fmt.Sprintf("  %s => %s\n", name, t.String()))
		} else {
			sb.WriteString(fmt.Sprintf("  %s => <free>\n", name))
		}
	}
	if len(s.Conflicts) > 0 {
		sb.WriteString(fmt.Sprintf("  conflicts: %d\n", len(s.Conflicts)))
	}
	sb.WriteString("}")
	return sb.String()
}

// ============================================================================
// Unifier - the core Hindley-Milner unification engine
// ============================================================================

// Unifier implements Hindley-Milner unification over the TypeConstraint set.
// it uses a union-find (disjoint-set) data structure with:
//   - path compression (find with halving)
//   - union by rank
//   - occurs check to prevent infinite types
//
// Requirements: 11.3, 11.4, 11.15
type Unifier struct {
	// terms is the flat array of all type terms.
	// indices into this slice are stable identifiers.
	terms []term

	// varIndex maps TypeVar.Name → term index.
	// every TypeVar encountered during constraint processing gets an entry.
	varIndex map[string]int

	// conflicts accumulates soft-constraint failures (low-confidence constraints
	// that could not be satisfied without breaking higher-confidence ones).
	conflicts []ConflictRecord
}

// NewUnifier creates an empty Unifier ready to process constraints.
func NewUnifier() *Unifier {
	return &Unifier{
		terms:    make([]term, 0, 64),
		varIndex: make(map[string]int, 64),
	}
}

// ============================================================================
// Union-Find primitives
// ============================================================================

// newTerm allocates a fresh self-rooted term and returns its index.
func (u *Unifier) newTerm(k termKind) int {
	idx := len(u.terms)
	u.terms = append(u.terms, term{
		kind:   k,
		parent: idx, // self-loop = root
		rank:   0,
	})
	return idx
}

// find returns the canonical root index for term i, applying path compression
// via the "path halving" variant (every other node on the path is updated).
// path halving achieves the same amortised O(α(n)) complexity as full compression
// but requires only a single pass and no recursion, avoiding stack overflow on
// deep chains produced by large constraint sets.
func (u *Unifier) find(i int) int {
	for u.terms[i].parent != i {
		// path halving: point i to its grandparent
		grandparent := u.terms[u.terms[i].parent].parent
		u.terms[i].parent = grandparent
		i = grandparent
	}
	return i
}

// union merges the equivalence classes of terms a and b using union-by-rank.
// returns the index of the new root.
// the caller is responsible for ensuring the merge is type-safe before calling.
func (u *Unifier) union(a, b int) int {
	ra, rb := u.find(a), u.find(b)
	if ra == rb {
		return ra
	}
	// union by rank: attach smaller tree under larger tree
	switch {
	case u.terms[ra].rank < u.terms[rb].rank:
		u.terms[ra].parent = rb
		return rb
	case u.terms[ra].rank > u.terms[rb].rank:
		u.terms[rb].parent = ra
		return ra
	default:
		// equal rank: arbitrary choice, increment winner's rank
		u.terms[rb].parent = ra
		u.terms[ra].rank++
		return ra
	}
}

// ============================================================================
// Term allocation helpers
// ============================================================================

// termForVar returns the term index for a TypeVar, creating a fresh free
// variable term if this is the first time the name is seen.
// if the TypeVar carries a Concrete type, the term is immediately grounded.
func (u *Unifier) termForVar(tv TypeVar) int {
	if idx, ok := u.varIndex[tv.Name]; ok {
		return idx
	}
	idx := u.newTerm(termVar)
	u.varIndex[tv.Name] = idx
	if tv.Concrete != nil {
		// ground the term immediately from the known concrete type
		concreteIdx := u.termForConcreteType(tv.Concrete)
		// merge: the var term becomes an alias for the concrete term
		u.terms[idx].parent = concreteIdx
	}
	return idx
}

// termForConcreteType converts an ir.Type into a term, recursively building
// constructor terms for compound types (pointer, array, struct, function).
func (u *Unifier) termForConcreteType(t ir.Type) int {
	if t == nil {
		return u.newTerm(termVar) // treat nil as free variable
	}
	switch ct := t.(type) {
	case ir.VoidType, ir.BoolType, ir.IntType, ir.FloatType:
		// ground scalar types: allocate a concrete term
		idx := u.newTerm(termConcrete)
		u.terms[idx].concrete = ct
		return idx

	case ir.PointerType:
		idx := u.newTerm(termPointer)
		pointeeIdx := u.termForConcreteType(ct.Pointee)
		u.terms[idx].pointee = pointeeIdx
		return idx

	case ir.ArrayType:
		idx := u.newTerm(termArray)
		elemIdx := u.termForConcreteType(ct.Element)
		u.terms[idx].arrayElem = elemIdx
		u.terms[idx].arrayLen = ct.Length
		return idx

	case ir.StructType:
		idx := u.newTerm(termStruct)
		fields := make([]termField, len(ct.Fields))
		for i, f := range ct.Fields {
			fields[i] = termField{
				offset: f.Offset,
				termID: u.termForConcreteType(f.Type),
			}
		}
		u.terms[idx].structFields = fields
		return idx

	case ir.FunctionType:
		idx := u.newTerm(termFunction)
		params := make([]int, len(ct.Parameters))
		for i, p := range ct.Parameters {
			params[i] = u.termForConcreteType(p)
		}
		u.terms[idx].funcParams = params
		u.terms[idx].funcReturn = u.termForConcreteType(ct.ReturnType)
		return idx

	default:
		// unknown type: treat as free variable
		return u.newTerm(termVar)
	}
}

// ============================================================================
// Occurs check
// ============================================================================

// occursIn returns true if term needle appears anywhere in the type tree rooted
// at term haystack. this prevents the creation of infinite recursive types
// (e.g., T = *T) which would cause unification to loop forever.
// the visited set prevents re-traversal of shared sub-terms.
func (u *Unifier) occursIn(needle, haystack int, visited map[int]bool) bool {
	haystack = u.find(haystack)
	needle = u.find(needle)

	if needle == haystack {
		return true
	}
	if visited[haystack] {
		return false
	}
	visited[haystack] = true

	kind := u.terms[haystack].kind
	switch kind {
	case termVar, termConcrete:
		return false

	case termPointer:
		pointee := u.terms[haystack].pointee
		return u.occursIn(needle, pointee, visited)

	case termArray:
		elem := u.terms[haystack].arrayElem
		return u.occursIn(needle, elem, visited)

	case termStruct:
		fields := make([]termField, len(u.terms[haystack].structFields))
		copy(fields, u.terms[haystack].structFields)
		for _, f := range fields {
			if u.occursIn(needle, f.termID, visited) {
				return true
			}
		}
		return false

	case termFunction:
		params := make([]int, len(u.terms[haystack].funcParams))
		copy(params, u.terms[haystack].funcParams)
		ret := u.terms[haystack].funcReturn
		for _, p := range params {
			if u.occursIn(needle, p, visited) {
				return true
			}
		}
		return u.occursIn(needle, ret, visited)
	}
	return false
}

// ============================================================================
// Core unification algorithm
// ============================================================================

// unifyTerms attempts to unify terms a and b, returning an error if they are
// incompatible. this is the structural unification step of Hindley-Milner.
//
// IMPORTANT: we never hold a pointer (*term) across recursive calls because
// recursive calls may invoke newTerm which appends to u.terms and can
// reallocate the backing array, invalidating any previously taken pointer.
// all term fields are read into local variables before any recursive call.
func (u *Unifier) unifyTerms(a, b int) error {
	ra, rb := u.find(a), u.find(b)
	if ra == rb {
		return nil // already in the same equivalence class
	}

	// snapshot kinds before any call that may grow u.terms
	kindA := u.terms[ra].kind
	kindB := u.terms[rb].kind

	// case 1: left is a free variable - bind it to right
	if kindA == termVar {
		if u.occursIn(ra, rb, make(map[int]bool)) {
			return fmt.Errorf("occurs check failed: circular type %d in %d", ra, rb)
		}
		u.terms[ra].parent = rb
		return nil
	}

	// case 2: right is a free variable - bind it to left
	if kindB == termVar {
		if u.occursIn(rb, ra, make(map[int]bool)) {
			return fmt.Errorf("occurs check failed: circular type %d in %d", rb, ra)
		}
		u.terms[rb].parent = ra
		return nil
	}

	// case 3: both concrete - structural equality check
	if kindA == termConcrete && kindB == termConcrete {
		ca, cb := u.terms[ra].concrete, u.terms[rb].concrete
		if !typesEqual(ca, cb) {
			return fmt.Errorf("type clash: %s vs %s", ca.String(), cb.String())
		}
		u.terms[ra].parent = rb
		return nil
	}

	// case 4: both pointer constructors - unify pointees
	if kindA == termPointer && kindB == termPointer {
		pA, pB := u.terms[ra].pointee, u.terms[rb].pointee
		u.terms[ra].parent = rb
		return u.unifyTerms(pA, pB)
	}

	// case 5: both array constructors - unify element types
	if kindA == termArray && kindB == termArray {
		lA, lB := u.terms[ra].arrayLen, u.terms[rb].arrayLen
		if lA != 0 && lB != 0 && lA != lB {
			return fmt.Errorf("array length mismatch: %d vs %d", lA, lB)
		}
		eA, eB := u.terms[ra].arrayElem, u.terms[rb].arrayElem
		u.terms[ra].parent = rb
		return u.unifyTerms(eA, eB)
	}

	// case 6: both struct constructors - merge fields
	if kindA == termStruct && kindB == termStruct {
		fA := make([]termField, len(u.terms[ra].structFields))
		copy(fA, u.terms[ra].structFields)
		fB := make([]termField, len(u.terms[rb].structFields))
		copy(fB, u.terms[rb].structFields)
		u.terms[ra].parent = rb
		return u.unifyStructFields(fA, fB)
	}

	// case 7: both function constructors - unify params and return
	if kindA == termFunction && kindB == termFunction {
		pA := make([]int, len(u.terms[ra].funcParams))
		copy(pA, u.terms[ra].funcParams)
		pB := make([]int, len(u.terms[rb].funcParams))
		copy(pB, u.terms[rb].funcParams)
		rA, rB := u.terms[ra].funcReturn, u.terms[rb].funcReturn
		if len(pA) != len(pB) {
			return fmt.Errorf("function arity mismatch: %d vs %d", len(pA), len(pB))
		}
		u.terms[ra].parent = rb
		for i := range pA {
			if err := u.unifyTerms(pA[i], pB[i]); err != nil {
				return fmt.Errorf("function param %d: %w", i, err)
			}
		}
		return u.unifyTerms(rA, rB)
	}

	// case 8: concrete vs constructor - ground the constructor
	if kindA == termConcrete {
		ca := u.terms[ra].concrete
		return u.unifyConcreteWithConstructor(ca, rb)
	}
	if kindB == termConcrete {
		cb := u.terms[rb].concrete
		return u.unifyConcreteWithConstructor(cb, ra)
	}

	return fmt.Errorf("incompatible type constructors: kind %d vs kind %d", kindA, kindB)
}

// unifyStructFields merges two sets of struct fields by matching on byte offset.
// fields present in only one struct are carried over to the merged result.
func (u *Unifier) unifyStructFields(fa, fb []termField) error {
	// build offset → termID map for fb
	bMap := make(map[uint64]int, len(fb))
	for _, f := range fb {
		bMap[f.offset] = f.termID
	}
	for _, f := range fa {
		if bTermID, ok := bMap[f.offset]; ok {
			if err := u.unifyTerms(f.termID, bTermID); err != nil {
				return fmt.Errorf("struct field at offset %d: %w", f.offset, err)
			}
		}
		// fields only in fa are fine - they extend the merged struct
	}
	return nil
}

// unifyConcreteWithConstructor attempts to unify a concrete ir.Type with a
// constructor term. this handles cases like unifying ir.PointerType with a
// termPointer constructor, or ir.FunctionType with a termFunction constructor.
func (u *Unifier) unifyConcreteWithConstructor(concrete ir.Type, constructorIdx int) error {
	root := u.find(constructorIdx)
	switch ct := concrete.(type) {
	case ir.PointerType:
		if u.terms[root].kind != termPointer {
			return fmt.Errorf("type clash: pointer vs kind %d", u.terms[root].kind)
		}
		pointeeConstructor := u.terms[root].pointee
		pointeeIdx := u.termForConcreteType(ct.Pointee)
		return u.unifyTerms(pointeeConstructor, pointeeIdx)

	case ir.ArrayType:
		if u.terms[root].kind != termArray {
			return fmt.Errorf("type clash: array vs kind %d", u.terms[root].kind)
		}
		elemConstructor := u.terms[root].arrayElem
		elemIdx := u.termForConcreteType(ct.Element)
		return u.unifyTerms(elemConstructor, elemIdx)

	case ir.FunctionType:
		if u.terms[root].kind != termFunction {
			return fmt.Errorf("type clash: function vs kind %d", u.terms[root].kind)
		}
		existingParams := make([]int, len(u.terms[root].funcParams))
		copy(existingParams, u.terms[root].funcParams)
		existingRet := u.terms[root].funcReturn
		if len(ct.Parameters) != len(existingParams) {
			return fmt.Errorf("function arity mismatch: %d vs %d",
				len(ct.Parameters), len(existingParams))
		}
		for i, p := range ct.Parameters {
			paramIdx := u.termForConcreteType(p)
			if err := u.unifyTerms(existingParams[i], paramIdx); err != nil {
				return fmt.Errorf("function param %d: %w", i, err)
			}
		}
		retIdx := u.termForConcreteType(ct.ReturnType)
		return u.unifyTerms(existingRet, retIdx)

	default:
		return fmt.Errorf("cannot unify concrete %s with constructor term", concrete.String())
	}
}

// ============================================================================
// Constraint processing
// ============================================================================

// processConstraint dispatches a single TypeConstraint to the appropriate
// unification strategy based on its ConstraintKind.
// soft constraints (confidence < 0.5) that fail are recorded as conflicts
// rather than propagating the error.
func (u *Unifier) processConstraint(c TypeConstraint) {
	var err error

	switch c.Kind {
	case ConstraintEquality:
		// direct unification: left ≡ right
		la := u.termForVar(c.Left)
		rb := u.termForVar(c.Right)
		err = u.unifyTerms(la, rb)

	case ConstraintSubtype:
		// for decompilation purposes, subtype is treated as equality
		// (we do not have a full subtype lattice; widening is handled by casts)
		la := u.termForVar(c.Left)
		rb := u.termForVar(c.Right)
		err = u.unifyTerms(la, rb)

	case ConstraintPointerTo:
		// left must be a pointer to right: left ≡ *right
		la := u.termForVar(c.Left)
		rb := u.termForVar(c.Right)
		// create a pointer constructor term wrapping rb
		ptrIdx := u.newTerm(termPointer)
		u.terms[ptrIdx].pointee = rb
		err = u.unifyTerms(la, ptrIdx)

	case ConstraintFieldAccess:
		// left must be a struct with a field at FieldOffset of type right
		la := u.termForVar(c.Left)
		rb := u.termForVar(c.Right)
		err = u.processFieldConstraint(la, rb, uint64(c.FieldOffset))

	case ConstraintArrayElement:
		// left must be an array with element type right
		la := u.termForVar(c.Left)
		rb := u.termForVar(c.Right)
		arrIdx := u.newTerm(termArray)
		u.terms[arrIdx].arrayElem = rb
		u.terms[arrIdx].arrayLen = 0 // unknown length
		err = u.unifyTerms(la, arrIdx)

	case ConstraintReturnType:
		// left must be a function whose return type is right
		la := u.termForVar(c.Left)
		rb := u.termForVar(c.Right)
		err = u.processReturnTypeConstraint(la, rb)

	case ConstraintParamType:
		// left must be a function whose param[ParamIndex] type is right
		la := u.termForVar(c.Left)
		rb := u.termForVar(c.Right)
		err = u.processParamTypeConstraint(la, rb, c.ParamIndex)
	}

	if err != nil {
		u.conflicts = append(u.conflicts, ConflictRecord{
			Constraint: c,
			Reason:     err.Error(),
		})
	}
}

// processFieldConstraint ensures that term structTerm is a struct containing
// a field at the given byte offset with type fieldTerm.
// if structTerm is already a struct, the field is merged; otherwise a new
// struct constructor is created and unified with structTerm.
func (u *Unifier) processFieldConstraint(structTerm, fieldTerm int, offset uint64) error {
	root := u.find(structTerm)

	if u.terms[root].kind == termVar {
		// promote free variable to a struct constructor with this single field
		u.terms[root].kind = termStruct
		u.terms[root].structFields = []termField{{offset: offset, termID: fieldTerm}}
		return nil
	}

	if u.terms[root].kind == termStruct {
		// check if a field at this offset already exists
		for i, f := range u.terms[root].structFields {
			if f.offset == offset {
				return u.unifyTerms(f.termID, fieldTerm)
			}
			// insert in sorted order for deterministic output
			if f.offset > offset {
				newFields := make([]termField, len(u.terms[root].structFields)+1)
				copy(newFields, u.terms[root].structFields[:i])
				newFields[i] = termField{offset: offset, termID: fieldTerm}
				copy(newFields[i+1:], u.terms[root].structFields[i:])
				u.terms[root].structFields = newFields
				return nil
			}
		}
		// append at end (largest offset)
		u.terms[root].structFields = append(u.terms[root].structFields,
			termField{offset: offset, termID: fieldTerm})
		return nil
	}

	return fmt.Errorf("field constraint on non-struct term (kind=%d)", u.terms[root].kind)
}

// processReturnTypeConstraint ensures that funcTerm is a function constructor
// whose return type unifies with retTerm.
func (u *Unifier) processReturnTypeConstraint(funcTerm, retTerm int) error {
	root := u.find(funcTerm)

	if u.terms[root].kind == termVar {
		// promote to function constructor with unknown params and known return
		u.terms[root].kind = termFunction
		u.terms[root].funcParams = nil
		u.terms[root].funcReturn = retTerm
		return nil
	}

	if u.terms[root].kind == termFunction {
		return u.unifyTerms(u.terms[root].funcReturn, retTerm)
	}

	return fmt.Errorf("return type constraint on non-function term (kind=%d)", u.terms[root].kind)
}

// processParamTypeConstraint ensures that funcTerm is a function constructor
// whose parameter at paramIdx unifies with paramTerm.
// the params slice is extended with free variables if paramIdx exceeds current length.
func (u *Unifier) processParamTypeConstraint(funcTerm, paramTerm, paramIdx int) error {
	root := u.find(funcTerm)

	if u.terms[root].kind == termVar {
		// promote to function constructor
		u.terms[root].kind = termFunction
		u.terms[root].funcReturn = u.newTerm(termVar) // unknown return type
		u.terms[root].funcParams = nil
	}

	if u.terms[root].kind != termFunction {
		return fmt.Errorf("param type constraint on non-function term (kind=%d)", u.terms[root].kind)
	}

	// extend params slice with free variables up to paramIdx
	for len(u.terms[root].funcParams) <= paramIdx {
		u.terms[root].funcParams = append(u.terms[root].funcParams, u.newTerm(termVar))
	}

	return u.unifyTerms(u.terms[root].funcParams[paramIdx], paramTerm)
}

// ============================================================================
// Solution extraction
// ============================================================================

// Solve processes all constraints in priority order (highest confidence first)
// and returns the most general unifier (MGU) as a TypeSolution.
//
// the algorithm:
//  1. sort constraints by confidence descending (hard constraints first)
//  2. process each constraint via processConstraint
//  3. extract the resolved type for each TypeVar from the union-find structure
//
// Requirements: 11.3, 11.4, 11.15
func (u *Unifier) Solve(constraints []TypeConstraint) *TypeSolution {
	// sort by confidence descending so high-confidence axioms are processed first
	// and establish ground truth before lower-confidence inferences can conflict
	sorted := make([]TypeConstraint, len(constraints))
	copy(sorted, constraints)
	sortConstraintsByConfidence(sorted)

	for _, c := range sorted {
		u.processConstraint(c)
	}

	return u.extractSolution()
}

// extractSolution walks every registered TypeVar and resolves its canonical type
// by reading the root term of its equivalence class.
func (u *Unifier) extractSolution() *TypeSolution {
	sol := &TypeSolution{
		Types:     make(map[string]ir.Type, len(u.varIndex)),
		Conflicts: u.conflicts,
	}

	for name, termIdx := range u.varIndex {
		sol.Types[name] = u.resolveTermToType(u.find(termIdx), make(map[int]bool))
	}

	return sol
}

// resolveTermToType converts a term back into an ir.Type.
// free variables (termVar) resolve to nil (polymorphic / unknown).
// the visited map prevents infinite recursion on cyclic terms that slipped
// through the occurs check (defensive programming).
func (u *Unifier) resolveTermToType(termIdx int, visited map[int]bool) ir.Type {
	root := u.find(termIdx)
	if visited[root] {
		return nil // cycle detected - return unknown rather than looping
	}
	visited[root] = true

	kind := u.terms[root].kind
	switch kind {
	case termVar:
		return nil // still polymorphic

	case termConcrete:
		return u.terms[root].concrete

	case termPointer:
		pointee := u.terms[root].pointee
		pt := u.resolveTermToType(pointee, visited)
		if pt == nil {
			pt = ir.VoidType{} // *void for unresolved pointee
		}
		return ir.PointerType{Pointee: pt}

	case termArray:
		elem := u.terms[root].arrayElem
		length := u.terms[root].arrayLen
		et := u.resolveTermToType(elem, visited)
		if et == nil {
			et = ir.VoidType{}
		}
		return ir.ArrayType{Element: et, Length: length}

	case termStruct:
		fields := make([]termField, len(u.terms[root].structFields))
		copy(fields, u.terms[root].structFields)
		irFields := make([]ir.StructField, len(fields))
		for i, f := range fields {
			ft := u.resolveTermToType(f.termID, visited)
			if ft == nil {
				ft = ir.VoidType{}
			}
			irFields[i] = ir.StructField{
				Name:   fmt.Sprintf("field_%d", f.offset),
				Type:   ft,
				Offset: f.offset,
			}
		}
		return ir.StructType{Fields: irFields}

	case termFunction:
		params := make([]int, len(u.terms[root].funcParams))
		copy(params, u.terms[root].funcParams)
		ret := u.terms[root].funcReturn
		irParams := make([]ir.Type, len(params))
		for i, p := range params {
			pt := u.resolveTermToType(p, visited)
			if pt == nil {
				pt = ir.VoidType{}
			}
			irParams[i] = pt
		}
		rt := u.resolveTermToType(ret, visited)
		if rt == nil {
			rt = ir.VoidType{}
		}
		return ir.FunctionType{ReturnType: rt, Parameters: irParams}
	}

	return nil
}

// ============================================================================
// Utility functions
// ============================================================================

// typesEqual performs structural equality comparison between two ir.Type values.
// this is used when both sides of a unification are concrete ground types.
func typesEqual(a, b ir.Type) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	// use string representation as a canonical form for structural equality.
	// this is correct because ir.Type.String() is injective for all concrete types.
	return a.String() == b.String()
}

// sortConstraintsByConfidence sorts constraints in descending confidence order
// using insertion sort (stable, O(n^2) but n is typically small for a single function).
func sortConstraintsByConfidence(cs []TypeConstraint) {
	for i := 1; i < len(cs); i++ {
		key := cs[i]
		j := i - 1
		for j >= 0 && cs[j].Confidence < key.Confidence {
			cs[j+1] = cs[j]
			j--
		}
		cs[j+1] = key
	}
}

// Unify is the top-level entry point for Hindley-Milner unification.
// it creates a fresh Unifier, processes all constraints, and returns the MGU.
// this function is the primary API consumed by the Type_Inferencer pipeline.
//
// Requirements: 11.3, 11.4, 11.15
func Unify(constraints []TypeConstraint) *TypeSolution {
	u := NewUnifier()
	return u.Solve(constraints)
}
