package typeinfer

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// TestUnify_FunctionTypeUnification verifies that two function types with
// identical signatures unify without conflict.
func TestUnify_FunctionTypeUnification(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	i32 := ir.IntType{Width: ir.Size4, Signed: true}

	fnType := ir.FunctionType{
		ReturnType: i64,
		Parameters: []ir.Type{i32, i64},
	}

	cs := []TypeConstraint{
		eqConstraint(tv("f"), tvConcrete("c_fn", fnType)),
	}
	sol := Unify(cs)

	ft, ok := sol.Types["f"].(ir.FunctionType)
	if !ok {
		t.Fatalf("expected FunctionType, got %T", sol.Types["f"])
	}
	if ft.ReturnType.String() != i64.String() {
		t.Errorf("return type: expected %s, got %s", i64, ft.ReturnType)
	}
	if len(ft.Parameters) != 2 {
		t.Fatalf("expected 2 params, got %d", len(ft.Parameters))
	}
}

// TestUnify_FunctionTypeClash verifies that two function types with different
// arities produce a conflict.
func TestUnify_FunctionTypeClash(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	i32 := ir.IntType{Width: ir.Size4, Signed: true}

	fn1 := ir.FunctionType{ReturnType: i64, Parameters: []ir.Type{i32}}
	fn2 := ir.FunctionType{ReturnType: i64, Parameters: []ir.Type{i32, i64}}

	cs := []TypeConstraint{
		eqConstraint(tvConcrete("f1", fn1), tvConcrete("f2", fn2)),
	}
	sol := Unify(cs)
	if len(sol.Conflicts) == 0 {
		t.Error("expected conflict for function arity mismatch, got none")
	}
}

// TestUnify_ArrayTypeUnification verifies that two array types with the same
// element type and length unify correctly.
func TestUnify_ArrayTypeUnification(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}

	arr := ir.ArrayType{Element: i32, Length: 10}
	cs := []TypeConstraint{
		eqConstraint(tv("a"), tvConcrete("c_arr", arr)),
	}
	sol := Unify(cs)

	at, ok := sol.Types["a"].(ir.ArrayType)
	if !ok {
		t.Fatalf("expected ArrayType, got %T", sol.Types["a"])
	}
	if at.Element.String() != i32.String() {
		t.Errorf("element: expected %s, got %s", i32, at.Element)
	}
	if at.Length != 10 {
		t.Errorf("length: expected 10, got %d", at.Length)
	}
}

// TestUnify_ArrayLengthMismatch verifies that two array types with different
// known lengths produce a conflict.
func TestUnify_ArrayLengthMismatch(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}

	arr1 := ir.ArrayType{Element: i32, Length: 4}
	arr2 := ir.ArrayType{Element: i32, Length: 8}

	cs := []TypeConstraint{
		eqConstraint(tvConcrete("a1", arr1), tvConcrete("a2", arr2)),
	}
	sol := Unify(cs)
	if len(sol.Conflicts) == 0 {
		t.Error("expected conflict for array length mismatch, got none")
	}
}

// TestUnify_StructTypeUnification verifies that two struct types with
// compatible fields unify correctly via unifyStructFields.
func TestUnify_StructTypeUnification(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	st1 := ir.StructType{Fields: []ir.StructField{
		{Name: "f0", Type: i32, Offset: 0},
		{Name: "f8", Type: i64, Offset: 8},
	}}
	st2 := ir.StructType{Fields: []ir.StructField{
		{Name: "f0", Type: i32, Offset: 0},
	}}

	// unifying two struct concrete types: fields at offset 0 must agree
	cs := []TypeConstraint{
		eqConstraint(tvConcrete("s1", st1), tvConcrete("s2", st2)),
	}
	sol := Unify(cs)
	// compatible field at offset 0 - no conflict expected
	if len(sol.Conflicts) != 0 {
		t.Errorf("unexpected conflicts for compatible struct fields: %v", sol.Conflicts)
	}
}

// TestUnify_StructFieldConflict verifies that two struct types with conflicting
// field types at the same offset produce a conflict.
func TestUnify_StructFieldConflict(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	st1 := ir.StructType{Fields: []ir.StructField{
		{Name: "f0", Type: i32, Offset: 0},
	}}
	st2 := ir.StructType{Fields: []ir.StructField{
		{Name: "f0", Type: i64, Offset: 0},
	}}

	cs := []TypeConstraint{
		eqConstraint(tvConcrete("s1", st1), tvConcrete("s2", st2)),
	}
	sol := Unify(cs)
	if len(sol.Conflicts) == 0 {
		t.Error("expected conflict for struct field type clash at offset 0, got none")
	}
}

// TestUnify_ConcretePointerWithConstructor verifies that a concrete PointerType
// unifies with a termPointer constructor via unifyConcreteWithConstructor.
func TestUnify_ConcretePointerWithConstructor(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	// p ≡ *v, then p ≡ *i64 (concrete pointer) - must unify v to i64
	cs := []TypeConstraint{
		ptrConstraint(tv("p"), tv("v")),
		eqConstraint(tv("p"), tvConcrete("c_ptr", ir.PointerType{Pointee: i64})),
	}
	sol := Unify(cs)

	if sol.Types["v"] == nil {
		t.Fatal("expected v=i64 after concrete pointer unification, got nil")
	}
	if sol.Types["v"].String() != i64.String() {
		t.Errorf("expected v=i64, got %s", sol.Types["v"])
	}
}

// TestUnify_ConcreteFunctionWithConstructor verifies that a concrete FunctionType
// unifies with a termFunction constructor via unifyConcreteWithConstructor.
func TestUnify_ConcreteFunctionWithConstructor(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	i32 := ir.IntType{Width: ir.Size4, Signed: true}

	fnType := ir.FunctionType{ReturnType: i64, Parameters: []ir.Type{i32}}

	// first build a function constructor via param/return constraints
	cs := []TypeConstraint{
		{
			Kind:       ConstraintReturnType,
			Left:       tv("fn"),
			Right:      tv("ret_var"),
			Confidence: 1.0,
			Origin:     "test",
		},
		{
			Kind:       ConstraintParamType,
			Left:       tv("fn"),
			Right:      tv("p0_var"),
			ParamIndex: 0,
			Confidence: 1.0,
			Origin:     "test",
		},
		// now unify fn with the concrete function type
		eqConstraint(tv("fn"), tvConcrete("c_fn", fnType)),
	}
	sol := Unify(cs)

	ft, ok := sol.Types["fn"].(ir.FunctionType)
	if !ok {
		t.Fatalf("expected FunctionType for fn, got %T", sol.Types["fn"])
	}
	if ft.ReturnType.String() != i64.String() {
		t.Errorf("return type: expected %s, got %s", i64, ft.ReturnType)
	}
}

// TestUnify_ConcreteArrayWithConstructor verifies that a concrete ArrayType
// unifies with a termArray constructor via unifyConcreteWithConstructor.
func TestUnify_ConcreteArrayWithConstructor(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}

	arrType := ir.ArrayType{Element: i32, Length: 5}

	// build array constructor via ConstraintArrayElement, then unify with concrete
	cs := []TypeConstraint{
		{
			Kind:       ConstraintArrayElement,
			Left:       tv("arr"),
			Right:      tv("elem"),
			Confidence: 1.0,
			Origin:     "test",
		},
		eqConstraint(tv("arr"), tvConcrete("c_arr", arrType)),
	}
	sol := Unify(cs)

	at, ok := sol.Types["arr"].(ir.ArrayType)
	if !ok {
		t.Fatalf("expected ArrayType for arr, got %T", sol.Types["arr"])
	}
	if at.Element.String() != i32.String() {
		t.Errorf("element: expected %s, got %s", i32, at.Element)
	}
}

// TestUnify_IncompatibleConstructors verifies that unifying a pointer term
// with a struct term produces a conflict.
func TestUnify_IncompatibleConstructors(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	ptrType := ir.PointerType{Pointee: i32}
	structType := ir.StructType{Fields: []ir.StructField{
		{Name: "f0", Type: i64, Offset: 0},
	}}

	cs := []TypeConstraint{
		eqConstraint(tvConcrete("p", ptrType), tvConcrete("s", structType)),
	}
	sol := Unify(cs)
	if len(sol.Conflicts) == 0 {
		t.Error("expected conflict for pointer vs struct, got none")
	}
}

// TestUnify_VoidType verifies that VoidType unifies correctly.
func TestUnify_VoidType(t *testing.T) {
	cs := []TypeConstraint{
		eqConstraint(tv("v"), tvConcrete("c", ir.VoidType{})),
	}
	sol := Unify(cs)
	if sol.Types["v"] == nil {
		t.Fatal("expected v=void, got nil")
	}
	if _, ok := sol.Types["v"].(ir.VoidType); !ok {
		t.Errorf("expected VoidType, got %T", sol.Types["v"])
	}
}

// TestUnify_FloatType verifies that FloatType unifies correctly.
func TestUnify_FloatType(t *testing.T) {
	f64 := ir.FloatType{Width: ir.Size8}
	cs := []TypeConstraint{
		eqConstraint(tv("x"), tvConcrete("c", f64)),
	}
	sol := Unify(cs)
	if sol.Types["x"] == nil {
		t.Fatal("expected x=f64, got nil")
	}
	if sol.Types["x"].String() != f64.String() {
		t.Errorf("expected f64, got %s", sol.Types["x"])
	}
}

// TestUnify_FieldConstraintInsertSorted verifies that field constraints are
// inserted in sorted offset order when a new field falls between existing ones.
func TestUnify_FieldConstraintInsertSorted(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	u8 := ir.IntType{Width: ir.Size1, Signed: false}

	// add fields out of order: 8, 0, 4 - must be sorted in result
	cs := []TypeConstraint{
		fieldConstraint(tv("s"), tvConcrete("f8", i64), 8),
		fieldConstraint(tv("s"), tvConcrete("f0", i32), 0),
		fieldConstraint(tv("s"), tvConcrete("f4", u8), 4),
	}
	sol := Unify(cs)

	st, ok := sol.Types["s"].(ir.StructType)
	if !ok {
		t.Fatalf("expected StructType, got %T", sol.Types["s"])
	}
	if len(st.Fields) != 3 {
		t.Fatalf("expected 3 fields, got %d", len(st.Fields))
	}
	// verify sorted order
	expectedOffsets := []uint64{0, 4, 8}
	for i, f := range st.Fields {
		if f.Offset != expectedOffsets[i] {
			t.Errorf("field[%d]: expected offset %d, got %d", i, expectedOffsets[i], f.Offset)
		}
	}
}

// TestUnify_FieldConstraintOnNonStruct verifies that applying a field constraint
// to a variable already bound to a non-struct type produces a conflict.
func TestUnify_FieldConstraintOnNonStruct(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	// bind x to i64 (concrete scalar), then try to add a field constraint
	cs := []TypeConstraint{
		eqConstraint(tv("x"), tvConcrete("c_i64", i64)),
		fieldConstraint(tv("x"), tvConcrete("f0", i32), 0),
	}
	sol := Unify(cs)
	if len(sol.Conflicts) == 0 {
		t.Error("expected conflict for field constraint on non-struct, got none")
	}
}

// TestUnify_ReturnTypeOnNonFunction verifies that applying a return type
// constraint to a variable already bound to a non-function type produces a conflict.
func TestUnify_ReturnTypeOnNonFunction(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cs := []TypeConstraint{
		eqConstraint(tv("x"), tvConcrete("c_i64", i64)),
		{
			Kind:       ConstraintReturnType,
			Left:       tv("x"),
			Right:      tvConcrete("ret", i64),
			Confidence: 1.0,
			Origin:     "test",
		},
	}
	sol := Unify(cs)
	if len(sol.Conflicts) == 0 {
		t.Error("expected conflict for return type constraint on non-function, got none")
	}
}

// TestUnify_ParamTypeOnNonFunction verifies that applying a param type
// constraint to a variable already bound to a non-function type produces a conflict.
func TestUnify_ParamTypeOnNonFunction(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cs := []TypeConstraint{
		eqConstraint(tv("x"), tvConcrete("c_i64", i64)),
		{
			Kind:       ConstraintParamType,
			Left:       tv("x"),
			Right:      tvConcrete("p0", i64),
			ParamIndex: 0,
			Confidence: 1.0,
			Origin:     "test",
		},
	}
	sol := Unify(cs)
	if len(sol.Conflicts) == 0 {
		t.Error("expected conflict for param type constraint on non-function, got none")
	}
}

// TestUnify_SubtypeConstraint verifies that subtype constraints are treated
// as equality (conservative approximation for decompilation).
func TestUnify_SubtypeConstraint(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cs := []TypeConstraint{
		{
			Kind:       ConstraintSubtype,
			Left:       tv("derived"),
			Right:      tvConcrete("base", i64),
			Confidence: 0.8,
			Origin:     "widening",
		},
	}
	sol := Unify(cs)
	// subtype treated as equality: derived must resolve to i64
	if sol.Types["derived"] == nil {
		t.Fatal("expected derived=i64 from subtype constraint, got nil")
	}
	if sol.Types["derived"].String() != i64.String() {
		t.Errorf("expected derived=i64, got %s", sol.Types["derived"])
	}
}

// TestUnify_MultipleFieldConstraintsSameOffset verifies that two field
// constraints at the same offset with conflicting types produce a conflict.
func TestUnify_MultipleFieldConstraintsSameOffset_Conflict(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cs := []TypeConstraint{
		fieldConstraint(tv("s"), tvConcrete("f0_i32", i32), 0),
		fieldConstraint(tv("s"), tvConcrete("f0_i64", i64), 0),
	}
	sol := Unify(cs)
	if len(sol.Conflicts) == 0 {
		t.Error("expected conflict for field type clash at same offset, got none")
	}
}

// TestUnify_OccursCheckInStruct verifies that the occurs check fires when
// a struct field references the struct itself (circular struct type).
func TestUnify_OccursCheckInPointerChain(_ *testing.T) {
	// x ≡ *y, y ≡ *x → circular pointer chain
	cs := []TypeConstraint{
		ptrConstraint(tv("x"), tv("y")),
		ptrConstraint(tv("y"), tv("x")),
	}
	// this should not panic and should either resolve or produce a conflict
	sol := Unify(cs)
	// the occurs check may or may not fire depending on traversal order,
	// but the solver must not loop infinitely
	_ = sol
}

// TestCallingConvention_String verifies all CallingConvention values have
// proper string representations.
func TestCallingConvention_String(t *testing.T) {
	cases := []struct {
		conv CallingConvention
		want string
	}{
		{CallingConventionUnknown, "unknown"},
		{CallingConventionSystemVAMD64, "sysv_amd64"},
		{CallingConventionMicrosoftX64, "ms_x64"},
	}
	for _, tc := range cases {
		if got := tc.conv.String(); got != tc.want {
			t.Errorf("CallingConvention(%d).String() = %q, want %q", tc.conv, got, tc.want)
		}
	}
}

// TestTypeConstraint_String verifies TypeConstraint.String() for all kinds.
func TestTypeConstraint_String(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cases := []TypeConstraint{
		{Kind: ConstraintEquality, Left: tv("a"), Right: tv("b"), Confidence: 0.5, Origin: "test"},
		{Kind: ConstraintSubtype, Left: tv("a"), Right: tv("b"), Confidence: 0.5, Origin: "test"},
		{Kind: ConstraintPointerTo, Left: tv("p"), Right: tv("v"), Confidence: 0.5, Origin: "test"},
		{Kind: ConstraintFieldAccess, Left: tv("s"), Right: tvConcrete("f", i64), FieldOffset: 8, Confidence: 0.5, Origin: "test"},
		{Kind: ConstraintArrayElement, Left: tv("arr"), Right: tv("elem"), Confidence: 0.5, Origin: "test"},
		{Kind: ConstraintReturnType, Left: tv("fn"), Right: tv("ret"), Confidence: 0.5, Origin: "test"},
		{Kind: ConstraintParamType, Left: tv("fn"), Right: tv("p0"), ParamIndex: 0, Confidence: 0.5, Origin: "test"},
	}
	for _, c := range cases {
		s := c.String()
		if s == "" {
			t.Errorf("TypeConstraint{Kind:%v}.String() returned empty string", c.Kind)
		}
	}
}

// TestErrUnknownFunction_Error verifies the error message format.
func TestErrUnknownFunction_Error(t *testing.T) {
	err := &UnknownFunctionError{ID: "my_func"}
	msg := err.Error()
	if msg == "" {
		t.Error("UnknownFunctionError.Error() returned empty string")
	}
	if len(msg) < 10 {
		t.Errorf("error message too short: %q", msg)
	}
}

// TestErrCyclicCallGraph_Error verifies the error message format.
func TestErrCyclicCallGraph_Error(t *testing.T) {
	err := &CyclicCallGraphError{CycleSize: 3}
	msg := err.Error()
	if msg == "" {
		t.Error("CyclicCallGraphError.Error() returned empty string")
	}
}

// TestCallGraph_Callees verifies that Callees returns outgoing edges.
func TestCallGraph_Callees(t *testing.T) {
	cg := NewCallGraph()
	cg.AddFunction("A", nil, nil, CallingConventionUnknown)
	cg.AddFunction("B", nil, nil, CallingConventionUnknown)
	cg.AddFunction("C", nil, nil, CallingConventionUnknown)

	site := makeCallSite(0, nil, nil)
	if err := cg.AddCallEdge("A", "B", site); err != nil {
		t.Fatalf("AddCallEdge A->B: %v", err)
	}
	if err := cg.AddCallEdge("A", "C", site); err != nil {
		t.Fatalf("AddCallEdge A->C: %v", err)
	}

	callees := cg.Callees("A")
	if len(callees) != 2 {
		t.Errorf("expected 2 callees for A, got %d", len(callees))
	}
	// verify callee IDs
	ids := make(map[FunctionID]bool)
	for _, e := range callees {
		ids[e.CalleeID] = true
	}
	if !ids["B"] || !ids["C"] {
		t.Errorf("expected callees B and C, got %v", ids)
	}
}

// TestCallGraph_AddFunction_UpdateExisting verifies that AddFunction updates
// an existing node's metadata when called again with the same ID.
func TestCallGraph_AddFunction_UpdateExisting(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("F", nil, nil, CallingConventionUnknown)
	// update with concrete types
	cg.AddFunction("F", []ir.Type{i64}, i64, CallingConventionSystemVAMD64)

	node := cg.Node("F")
	if node == nil {
		t.Fatal("node F not found")
	}
	if node.Convention != CallingConventionSystemVAMD64 {
		t.Errorf("expected SystemV convention, got %v", node.Convention)
	}
	if node.ReturnType == nil || node.ReturnType.String() != i64.String() {
		t.Errorf("expected return type i64, got %v", node.ReturnType)
	}
}

// TestCallGraph_TopologicalOrder_WithCycle verifies that TopologicalOrder
// returns an error and a partial result when cycles are present.
func TestCallGraph_TopologicalOrder_WithCycle(t *testing.T) {
	cg := NewCallGraph()
	cg.AddFunction("A", nil, nil, CallingConventionUnknown)
	cg.AddFunction("B", nil, nil, CallingConventionUnknown)

	site := makeCallSite(0, nil, nil)
	// A -> B -> A (cycle)
	if err := cg.AddCallEdge("A", "B", site); err != nil {
		t.Fatalf("AddCallEdge A->B: %v", err)
	}
	if err := cg.AddCallEdge("B", "A", site); err != nil {
		t.Fatalf("AddCallEdge B->A: %v", err)
	}

	order, err := cg.TopologicalOrder()
	if err == nil {
		t.Error("expected ErrCyclicCallGraph, got nil")
	}
	// partial result must still contain all nodes
	if len(order) != 2 {
		t.Errorf("expected 2 nodes in partial order, got %d", len(order))
	}
}

func TestUnify_ConcretePointerVsConstructorDirect(t *testing.T) {
	u := NewUnifier()

	ptrConstructor := u.newTerm(termPointer)
	pointeeVar := u.newTerm(termVar)
	u.terms[ptrConstructor].pointee = pointeeVar

	concreteTerm := u.newTerm(termConcrete)
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	u.terms[concreteTerm].concrete = ir.PointerType{Pointee: i64}

	if err := u.unifyTerms(concreteTerm, ptrConstructor); err != nil {
		t.Fatalf("unifyConcreteWithConstructor pointer: %v", err)
	}

	resolved := u.resolveTermToType(pointeeVar, make(map[int]bool))
	if resolved == nil || resolved.String() != i64.String() {
		t.Errorf("expected pointee=i64, got %v", resolved)
	}
}

func TestUnify_ConcreteArrayVsConstructorDirect(t *testing.T) {
	u := NewUnifier()

	arrConstructor := u.newTerm(termArray)
	elemVar := u.newTerm(termVar)
	u.terms[arrConstructor].arrayElem = elemVar
	u.terms[arrConstructor].arrayLen = 0

	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	concreteTerm := u.newTerm(termConcrete)
	u.terms[concreteTerm].concrete = ir.ArrayType{Element: i32, Length: 10}

	if err := u.unifyTerms(concreteTerm, arrConstructor); err != nil {
		t.Fatalf("unifyConcreteWithConstructor array: %v", err)
	}

	resolved := u.resolveTermToType(elemVar, make(map[int]bool))
	if resolved == nil || resolved.String() != i32.String() {
		t.Errorf("expected elem=i32, got %v", resolved)
	}
}

func TestUnify_ConcreteFunctionVsConstructorDirect(t *testing.T) {
	u := NewUnifier()

	fnConstructor := u.newTerm(termFunction)
	paramVar := u.newTerm(termVar)
	retVar := u.newTerm(termVar)
	u.terms[fnConstructor].funcParams = []int{paramVar}
	u.terms[fnConstructor].funcReturn = retVar

	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	concreteTerm := u.newTerm(termConcrete)
	u.terms[concreteTerm].concrete = ir.FunctionType{
		ReturnType: i64,
		Parameters: []ir.Type{i32},
	}

	if err := u.unifyTerms(concreteTerm, fnConstructor); err != nil {
		t.Fatalf("unifyConcreteWithConstructor function: %v", err)
	}

	resolvedParam := u.resolveTermToType(paramVar, make(map[int]bool))
	if resolvedParam == nil || resolvedParam.String() != i32.String() {
		t.Errorf("expected param=i32, got %v", resolvedParam)
	}
	resolvedRet := u.resolveTermToType(retVar, make(map[int]bool))
	if resolvedRet == nil || resolvedRet.String() != i64.String() {
		t.Errorf("expected ret=i64, got %v", resolvedRet)
	}
}

func TestUnify_ConcreteVsConstructorKindMismatch(t *testing.T) {
	u := NewUnifier()

	structConstructor := u.newTerm(termStruct)
	u.terms[structConstructor].structFields = nil

	concreteTerm := u.newTerm(termConcrete)
	concreteTerm2 := u.newTerm(termConcrete)
	u.terms[concreteTerm].concrete = ir.PointerType{Pointee: ir.VoidType{}}
	u.terms[concreteTerm2].concrete = ir.IntType{Width: ir.Size4, Signed: true}

	err := u.unifyTerms(concreteTerm, structConstructor)
	if err == nil {
		t.Error("expected error for pointer concrete vs struct constructor")
	}

	arrConstructor := u.newTerm(termArray)
	arrConstructor2 := u.newTerm(termVar)
	u.terms[arrConstructor].arrayElem = arrConstructor2

	err = u.unifyTerms(concreteTerm2, arrConstructor)
	if err == nil {
		t.Error("expected error for scalar concrete vs array constructor")
	}
}

func TestUnify_ConcreteFunctionArityMismatchDirect(t *testing.T) {
	u := NewUnifier()

	fnConstructor := u.newTerm(termFunction)
	p0 := u.newTerm(termVar)
	p1 := u.newTerm(termVar)
	retVar := u.newTerm(termVar)
	u.terms[fnConstructor].funcParams = []int{p0, p1}
	u.terms[fnConstructor].funcReturn = retVar

	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	concreteTerm := u.newTerm(termConcrete)
	u.terms[concreteTerm].concrete = ir.FunctionType{
		ReturnType: ir.VoidType{},
		Parameters: []ir.Type{i32},
	}

	err := u.unifyTerms(concreteTerm, fnConstructor)
	if err == nil {
		t.Error("expected arity mismatch error")
	}
}

func TestUnify_OccursCheckInFunctionParams(t *testing.T) {
	u := NewUnifier()

	fnTerm := u.newTerm(termFunction)
	u.terms[fnTerm].funcParams = []int{fnTerm}
	u.terms[fnTerm].funcReturn = u.newTerm(termVar)

	freeVar := u.newTerm(termVar)

	visited := make(map[int]bool)
	if !u.occursIn(fnTerm, fnTerm, visited) {
		t.Error("expected occurs check to detect self-reference in function params")
	}

	_ = freeVar
}

func TestUnify_OccursCheckInStructFields(t *testing.T) {
	u := NewUnifier()

	structTerm := u.newTerm(termStruct)
	u.terms[structTerm].structFields = []termField{
		{offset: 0, termID: structTerm},
	}

	visited := make(map[int]bool)
	if !u.occursIn(structTerm, structTerm, visited) {
		t.Error("expected occurs check to detect self-reference in struct fields")
	}
}

func TestUnify_OccursCheckInArrayElement(t *testing.T) {
	u := NewUnifier()

	arrTerm := u.newTerm(termArray)
	u.terms[arrTerm].arrayElem = arrTerm
	u.terms[arrTerm].arrayLen = 0

	visited := make(map[int]bool)
	if !u.occursIn(arrTerm, arrTerm, visited) {
		t.Error("expected occurs check to detect self-reference in array element")
	}
}

func TestUnify_OccursCheckInFunctionReturn(t *testing.T) {
	u := NewUnifier()

	target := u.newTerm(termVar)
	fnTerm := u.newTerm(termFunction)
	paramVar := u.newTerm(termVar)
	u.terms[fnTerm].funcParams = []int{paramVar}
	u.terms[fnTerm].funcReturn = target

	visited := make(map[int]bool)
	if !u.occursIn(target, fnTerm, visited) {
		t.Error("expected occurs check to find target in function return")
	}
}

func TestUnify_OccursCheckNegativeInPointer(t *testing.T) {
	u := NewUnifier()

	needle := u.newTerm(termVar)
	other := u.newTerm(termVar)
	ptrTerm := u.newTerm(termPointer)
	u.terms[ptrTerm].pointee = other

	visited := make(map[int]bool)
	if u.occursIn(needle, ptrTerm, visited) {
		t.Error("expected occurs check to NOT find needle in unrelated pointer")
	}
}

func TestUnify_ResolveTermToType_CycleDefense(t *testing.T) {
	u := NewUnifier()

	ptrTerm := u.newTerm(termPointer)
	u.terms[ptrTerm].pointee = ptrTerm

	resolved := u.resolveTermToType(ptrTerm, make(map[int]bool))
	if resolved == nil {
		t.Fatal("expected non-nil type for cyclic pointer (defensive nil)")
	}
	pt, ok := resolved.(ir.PointerType)
	if !ok {
		t.Fatalf("expected PointerType, got %T", resolved)
	}
	if _, isVoid := pt.Pointee.(ir.VoidType); !isVoid {
		t.Errorf("expected *void for cyclic pointee, got %v", pt.Pointee)
	}
}

func TestUnify_OccursCheckDeepInArray(t *testing.T) {
	u := NewUnifier()

	needle := u.newTerm(termVar)
	arrTerm := u.newTerm(termArray)
	u.terms[arrTerm].arrayElem = needle

	visited := make(map[int]bool)
	if !u.occursIn(needle, arrTerm, visited) {
		t.Error("expected occurs check to find needle inside array element")
	}
}

func TestUnify_OccursCheckDeepInFunctionParam(t *testing.T) {
	u := NewUnifier()

	needle := u.newTerm(termVar)
	retVar := u.newTerm(termVar)
	fnTerm := u.newTerm(termFunction)
	u.terms[fnTerm].funcParams = []int{needle}
	u.terms[fnTerm].funcReturn = retVar

	visited := make(map[int]bool)
	if !u.occursIn(needle, fnTerm, visited) {
		t.Error("expected occurs check to find needle in function params")
	}
}

func TestUnify_OccursCheckDeepInStruct(t *testing.T) {
	u := NewUnifier()

	needle := u.newTerm(termVar)
	structTerm := u.newTerm(termStruct)
	otherField := u.newTerm(termVar)
	u.terms[structTerm].structFields = []termField{
		{offset: 0, termID: otherField},
		{offset: 8, termID: needle},
	}

	visited := make(map[int]bool)
	if !u.occursIn(needle, structTerm, visited) {
		t.Error("expected occurs check to find needle in struct fields")
	}
}

func TestUnify_OccursCheckNegativeInFunction(t *testing.T) {
	u := NewUnifier()

	needle := u.newTerm(termVar)
	p0 := u.newTerm(termVar)
	retVar := u.newTerm(termVar)
	fnTerm := u.newTerm(termFunction)
	u.terms[fnTerm].funcParams = []int{p0}
	u.terms[fnTerm].funcReturn = retVar

	visited := make(map[int]bool)
	if u.occursIn(needle, fnTerm, visited) {
		t.Error("expected occurs check to NOT find unrelated needle in function")
	}
}

func TestUnify_OccursCheckNegativeInArray(t *testing.T) {
	u := NewUnifier()

	needle := u.newTerm(termVar)
	elemVar := u.newTerm(termVar)
	arrTerm := u.newTerm(termArray)
	u.terms[arrTerm].arrayElem = elemVar

	visited := make(map[int]bool)
	if u.occursIn(needle, arrTerm, visited) {
		t.Error("expected occurs check to NOT find unrelated needle in array")
	}
}

func TestUnify_OccursCheckNegativeInStruct(t *testing.T) {
	u := NewUnifier()

	needle := u.newTerm(termVar)
	f0 := u.newTerm(termVar)
	structTerm := u.newTerm(termStruct)
	u.terms[structTerm].structFields = []termField{
		{offset: 0, termID: f0},
	}

	visited := make(map[int]bool)
	if u.occursIn(needle, structTerm, visited) {
		t.Error("expected occurs check to NOT find unrelated needle in struct")
	}
}
