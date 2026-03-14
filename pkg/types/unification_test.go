package typeinfer

import (
	"fmt"
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// helpers
// ============================================================================

// tv creates a TypeVar with no concrete type (free variable).
func tv(name string) TypeVar {
	return TypeVar{Name: name}
}

// tvConcrete creates a TypeVar with a known concrete type.
func tvConcrete(name string, t ir.Type) TypeVar {
	return TypeVar{Name: name, Concrete: t}
}

// eqConstraint builds a high-confidence equality constraint.
func eqConstraint(left, right TypeVar) TypeConstraint {
	return TypeConstraint{
		Kind:       ConstraintEquality,
		Left:       left,
		Right:      right,
		Confidence: 1.0,
		Origin:     "test",
	}
}

// ptrConstraint builds a pointer-to constraint: left ≡ *right.
func ptrConstraint(left, right TypeVar) TypeConstraint {
	return TypeConstraint{
		Kind:       ConstraintPointerTo,
		Left:       left,
		Right:      right,
		Confidence: 1.0,
		Origin:     "test",
	}
}

// fieldConstraint builds a field-access constraint.
func fieldConstraint(structVar, fieldVar TypeVar, offset int64) TypeConstraint {
	return TypeConstraint{
		Kind:        ConstraintFieldAccess,
		Left:        structVar,
		Right:       fieldVar,
		FieldOffset: offset,
		Confidence:  1.0,
		Origin:      "test",
	}
}

// ============================================================================
// basic unification tests
// ============================================================================

// TestUnify_FreeVarBindsToFreeVar verifies that two free variables unify
// and subsequently resolve to the same type when one is later grounded.
func TestUnify_FreeVarBindsToFreeVar(t *testing.T) {
	// x ≡ y, then y ≡ i64 → x must also be i64
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	cs := []TypeConstraint{
		eqConstraint(tv("x"), tv("y")),
		eqConstraint(tv("y"), tvConcrete("c_i64", i64)),
	}
	sol := Unify(cs)
	if sol.Types["x"] == nil {
		t.Fatal("expected x to resolve to i64, got nil")
	}
	if sol.Types["x"].String() != i64.String() {
		t.Errorf("expected x=i64, got %s", sol.Types["x"].String())
	}
}

// TestUnify_ConcreteEquality verifies that two identical concrete types unify.
func TestUnify_ConcreteEquality(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	cs := []TypeConstraint{
		eqConstraint(tvConcrete("a", i32), tvConcrete("b", i32)),
	}
	sol := Unify(cs)
	if len(sol.Conflicts) != 0 {
		t.Errorf("expected no conflicts for identical types, got: %v", sol.Conflicts)
	}
}

// TestUnify_ConcreteClash verifies that conflicting concrete types produce a conflict record.
func TestUnify_ConcreteClash(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	cs := []TypeConstraint{
		eqConstraint(tvConcrete("a", i32), tvConcrete("b", i64)),
	}
	sol := Unify(cs)
	if len(sol.Conflicts) == 0 {
		t.Error("expected a conflict for i32 vs i64, got none")
	}
}

// TestUnify_FreeVarBindsToConcrete verifies that a free variable binds to a concrete type.
func TestUnify_FreeVarBindsToConcrete(t *testing.T) {
	u64 := ir.IntType{Width: ir.Size8, Signed: false}
	cs := []TypeConstraint{
		eqConstraint(tv("v"), tvConcrete("c", u64)),
	}
	sol := Unify(cs)
	if sol.Types["v"] == nil {
		t.Fatal("expected v to resolve to u64, got nil")
	}
	if sol.Types["v"].String() != u64.String() {
		t.Errorf("expected v=u64, got %s", sol.Types["v"].String())
	}
}

// ============================================================================
// pointer unification tests
// ============================================================================

// TestUnify_PointerTo verifies that a pointer constraint creates *T.
func TestUnify_PointerTo(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	// p ≡ *v, v ≡ i64 → p must be *i64
	cs := []TypeConstraint{
		ptrConstraint(tv("p"), tv("v")),
		eqConstraint(tv("v"), tvConcrete("c", i64)),
	}
	sol := Unify(cs)
	pt, ok := sol.Types["p"].(ir.PointerType)
	if !ok {
		t.Fatalf("expected p to be PointerType, got %T (%v)", sol.Types["p"], sol.Types["p"])
	}
	if pt.Pointee.String() != i64.String() {
		t.Errorf("expected *i64, got *%s", pt.Pointee.String())
	}
}

// TestUnify_PointerChain verifies multi-level pointer unification: p ≡ *q, q ≡ *r, r ≡ i32.
func TestUnify_PointerChain(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	cs := []TypeConstraint{
		ptrConstraint(tv("p"), tv("q")),
		ptrConstraint(tv("q"), tv("r")),
		eqConstraint(tv("r"), tvConcrete("c", i32)),
	}
	sol := Unify(cs)

	// p must be **i32
	pt, ok := sol.Types["p"].(ir.PointerType)
	if !ok {
		t.Fatalf("expected p=**i32, got %T", sol.Types["p"])
	}
	inner, ok := pt.Pointee.(ir.PointerType)
	if !ok {
		t.Fatalf("expected p pointee to be *i32, got %T", pt.Pointee)
	}
	if inner.Pointee.String() != i32.String() {
		t.Errorf("expected **i32, got **%s", inner.Pointee.String())
	}
}

// TestUnify_PointerClash verifies that *i32 and *i64 produce a conflict.
func TestUnify_PointerClash(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	cs := []TypeConstraint{
		ptrConstraint(tv("p"), tvConcrete("c32", i32)),
		ptrConstraint(tv("p"), tvConcrete("c64", i64)),
	}
	sol := Unify(cs)
	if len(sol.Conflicts) == 0 {
		t.Error("expected conflict for *i32 vs *i64, got none")
	}
}

// ============================================================================
// struct / field access tests
// ============================================================================

// TestUnify_FieldAccess verifies that field constraints build a struct type.
func TestUnify_FieldAccess(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	// s.field[0] ≡ i32, s.field[8] ≡ i64
	cs := []TypeConstraint{
		fieldConstraint(tv("s"), tvConcrete("f0", i32), 0),
		fieldConstraint(tv("s"), tvConcrete("f8", i64), 8),
	}
	sol := Unify(cs)
	st, ok := sol.Types["s"].(ir.StructType)
	if !ok {
		t.Fatalf("expected s to be StructType, got %T", sol.Types["s"])
	}
	if len(st.Fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(st.Fields))
	}
	if st.Fields[0].Offset != 0 || st.Fields[0].Type.String() != i32.String() {
		t.Errorf("field[0] mismatch: offset=%d type=%v", st.Fields[0].Offset, st.Fields[0].Type)
	}
	if st.Fields[1].Offset != 8 || st.Fields[1].Type.String() != i64.String() {
		t.Errorf("field[8] mismatch: offset=%d type=%v", st.Fields[1].Offset, st.Fields[1].Type)
	}
}

// TestUnify_FieldMerge verifies that two struct constraints on the same variable merge fields.
func TestUnify_FieldMerge(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	// two separate constraints both adding field at offset 0 with same type - no conflict
	cs := []TypeConstraint{
		fieldConstraint(tv("s"), tvConcrete("f0a", i32), 0),
		fieldConstraint(tv("s"), tvConcrete("f0b", i32), 0),
	}
	sol := Unify(cs)
	if len(sol.Conflicts) != 0 {
		t.Errorf("expected no conflict for identical field types, got: %v", sol.Conflicts)
	}
	st, ok := sol.Types["s"].(ir.StructType)
	if !ok {
		t.Fatalf("expected StructType, got %T", sol.Types["s"])
	}
	if len(st.Fields) != 1 {
		t.Errorf("expected 1 merged field, got %d", len(st.Fields))
	}
}

// ============================================================================
// function type tests
// ============================================================================

// TestUnify_ReturnType verifies that a return type constraint builds a function type.
func TestUnify_ReturnType(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	cs := []TypeConstraint{
		{
			Kind:       ConstraintReturnType,
			Left:       tv("fn"),
			Right:      tvConcrete("ret", i64),
			Confidence: 1.0,
			Origin:     "test",
		},
	}
	sol := Unify(cs)
	ft, ok := sol.Types["fn"].(ir.FunctionType)
	if !ok {
		t.Fatalf("expected fn to be FunctionType, got %T", sol.Types["fn"])
	}
	if ft.ReturnType.String() != i64.String() {
		t.Errorf("expected return type i64, got %s", ft.ReturnType.String())
	}
}

// TestUnify_ParamType verifies that param type constraints build function parameter list.
func TestUnify_ParamType(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	cs := []TypeConstraint{
		{
			Kind:       ConstraintParamType,
			Left:       tv("fn"),
			Right:      tvConcrete("p0", i32),
			ParamIndex: 0,
			Confidence: 1.0,
			Origin:     "test",
		},
		{
			Kind:       ConstraintParamType,
			Left:       tv("fn"),
			Right:      tvConcrete("p1", i64),
			ParamIndex: 1,
			Confidence: 1.0,
			Origin:     "test",
		},
	}
	sol := Unify(cs)
	ft, ok := sol.Types["fn"].(ir.FunctionType)
	if !ok {
		t.Fatalf("expected fn to be FunctionType, got %T", sol.Types["fn"])
	}
	if len(ft.Parameters) < 2 {
		t.Fatalf("expected at least 2 params, got %d", len(ft.Parameters))
	}
	if ft.Parameters[0].String() != i32.String() {
		t.Errorf("param[0]: expected i32, got %s", ft.Parameters[0].String())
	}
	if ft.Parameters[1].String() != i64.String() {
		t.Errorf("param[1]: expected i64, got %s", ft.Parameters[1].String())
	}
}

// ============================================================================
// occurs check tests
// ============================================================================

// TestUnify_OccursCheck verifies that a circular constraint (T = *T) is rejected.
func TestUnify_OccursCheck(t *testing.T) {
	// x ≡ *x would create an infinite type; the occurs check must catch this.
	cs := []TypeConstraint{
		ptrConstraint(tv("x"), tv("x")),
	}
	sol := Unify(cs)
	if len(sol.Conflicts) == 0 {
		t.Error("expected occurs check to produce a conflict for T = *T, got none")
	}
}

// ============================================================================
// confidence ordering tests
// ============================================================================

// TestUnify_HighConfidenceWins verifies that a high-confidence constraint
// establishes the type before a conflicting low-confidence one is processed.
// the low-confidence constraint should be recorded as a conflict, not override.
func TestUnify_HighConfidenceWins(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	cs := []TypeConstraint{
		{
			Kind:       ConstraintEquality,
			Left:       tv("v"),
			Right:      tvConcrete("c_i64", i64),
			Confidence: 1.0, // relocation-derived axiom
			Origin:     "relocation",
		},
		{
			Kind:       ConstraintEquality,
			Left:       tv("v"),
			Right:      tvConcrete("c_i32", i32),
			Confidence: 0.3, // heuristic
			Origin:     "heuristic",
		},
	}
	sol := Unify(cs)
	// the high-confidence constraint must win
	if sol.Types["v"] == nil {
		t.Fatal("expected v to be resolved, got nil")
	}
	if sol.Types["v"].String() != i64.String() {
		t.Errorf("expected v=i64 (high confidence), got %s", sol.Types["v"].String())
	}
	// the low-confidence conflict must be recorded
	if len(sol.Conflicts) == 0 {
		t.Error("expected conflict record for low-confidence clash, got none")
	}
}

// ============================================================================
// path compression and union-by-rank tests
// ============================================================================

// TestUnify_LongChainPathCompression verifies that a long chain of equality
// constraints resolves correctly and that find() terminates in O(α(n)) time.
func TestUnify_LongChainPathCompression(t *testing.T) {
	const chainLen = 200
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cs := make([]TypeConstraint, 0, chainLen)
	// build chain: v0 ≡ v1 ≡ v2 ≡ ... ≡ v(chainLen-1) ≡ i64
	for i := 0; i < chainLen-1; i++ {
		cs = append(cs, eqConstraint(
			tv(fmt.Sprintf("v%d", i)),
			tv(fmt.Sprintf("v%d", i+1)),
		))
	}
	cs = append(cs, eqConstraint(
		tv(fmt.Sprintf("v%d", chainLen-1)),
		tvConcrete("c", i64),
	))

	sol := Unify(cs)
	if len(sol.Conflicts) != 0 {
		t.Errorf("unexpected conflicts in chain: %v", sol.Conflicts)
	}
	// every variable in the chain must resolve to i64
	for i := 0; i < chainLen; i++ {
		name := fmt.Sprintf("v%d", i)
		if sol.Types[name] == nil {
			t.Errorf("v%d: expected i64, got nil", i)
			continue
		}
		if sol.Types[name].String() != i64.String() {
			t.Errorf("v%d: expected i64, got %s", i, sol.Types[name].String())
		}
	}
}

// ============================================================================
// array element tests
// ============================================================================

// TestUnify_ArrayElement verifies that an array element constraint builds [N]T.
func TestUnify_ArrayElement(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	cs := []TypeConstraint{
		{
			Kind:       ConstraintArrayElement,
			Left:       tv("arr"),
			Right:      tvConcrete("elem", i32),
			Confidence: 1.0,
			Origin:     "test",
		},
	}
	sol := Unify(cs)
	at, ok := sol.Types["arr"].(ir.ArrayType)
	if !ok {
		t.Fatalf("expected arr to be ArrayType, got %T", sol.Types["arr"])
	}
	if at.Element.String() != i32.String() {
		t.Errorf("expected element type i32, got %s", at.Element.String())
	}
}

// ============================================================================
// empty and edge case tests
// ============================================================================

// TestUnify_Empty verifies that an empty constraint set produces an empty solution.
func TestUnify_Empty(t *testing.T) {
	sol := Unify(nil)
	if len(sol.Types) != 0 {
		t.Errorf("expected empty solution for nil constraints, got %d entries", len(sol.Types))
	}
	if len(sol.Conflicts) != 0 {
		t.Errorf("expected no conflicts for nil constraints, got %d", len(sol.Conflicts))
	}
}

// TestUnify_FreeVarRemainsNil verifies that an unconstrained variable stays nil.
func TestUnify_FreeVarRemainsNil(t *testing.T) {
	cs := []TypeConstraint{
		eqConstraint(tv("x"), tv("y")), // both free, no concrete type
	}
	sol := Unify(cs)
	// both x and y should be nil (polymorphic)
	if sol.Types["x"] != nil {
		t.Errorf("expected x=nil (free), got %s", sol.Types["x"].String())
	}
	if sol.Types["y"] != nil {
		t.Errorf("expected y=nil (free), got %s", sol.Types["y"].String())
	}
}

// TestUnify_BoolType verifies that bool type constraints unify correctly.
func TestUnify_BoolType(t *testing.T) {
	cs := []TypeConstraint{
		eqConstraint(tv("cond"), tvConcrete("b", ir.BoolType{})),
	}
	sol := Unify(cs)
	if sol.Types["cond"] == nil {
		t.Fatal("expected cond=bool, got nil")
	}
	if _, ok := sol.Types["cond"].(ir.BoolType); !ok {
		t.Errorf("expected BoolType, got %T", sol.Types["cond"])
	}
}

// TestUnify_Idempotent verifies that running Unify twice on the same constraints
// produces identical solutions (determinism requirement).
func TestUnify_Idempotent(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	cs := []TypeConstraint{
		eqConstraint(tv("a"), tv("b")),
		eqConstraint(tv("b"), tvConcrete("c", i64)),
		ptrConstraint(tv("p"), tv("a")),
	}
	sol1 := Unify(cs)
	sol2 := Unify(cs)

	for name, t1 := range sol1.Types {
		t2 := sol2.Types[name]
		s1 := "<nil>"
		s2 := "<nil>"
		if t1 != nil {
			s1 = t1.String()
		}
		if t2 != nil {
			s2 = t2.String()
		}
		if s1 != s2 {
			t.Errorf("non-deterministic: %s: run1=%s run2=%s", name, s1, s2)
		}
	}
}

// TestTypesEqual verifies the structural equality helper.
func TestTypesEqual(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	if !typesEqual(i32, i32) {
		t.Error("i32 == i32 must be true")
	}
	if typesEqual(i32, i64) {
		t.Error("i32 == i64 must be false")
	}
	if !typesEqual(nil, nil) {
		t.Error("nil == nil must be true")
	}
	if typesEqual(nil, i32) {
		t.Error("nil == i32 must be false")
	}
}

// TestSortConstraintsByConfidence verifies that sorting places highest confidence first.
func TestSortConstraintsByConfidence(t *testing.T) {
	cs := []TypeConstraint{
		{Confidence: 0.3},
		{Confidence: 1.0},
		{Confidence: 0.5},
		{Confidence: 0.9},
	}
	sortConstraintsByConfidence(cs)
	for i := 1; i < len(cs); i++ {
		if cs[i].Confidence > cs[i-1].Confidence {
			t.Errorf("not sorted at index %d: %.2f > %.2f", i, cs[i].Confidence, cs[i-1].Confidence)
		}
	}
}

// TestTypeSolution_String verifies that TypeSolution.String() does not panic.
func TestTypeSolution_String(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	sol := &TypeSolution{
		Types: map[string]ir.Type{
			"x": i64,
			"y": nil,
		},
		Conflicts: []ConflictRecord{
			{Reason: "test conflict"},
		},
	}
	s := sol.String()
	if s == "" {
		t.Error("TypeSolution.String() returned empty string")
	}
}
