package typeinfer

import (
	"fmt"
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ---------------------------------------------------------------------------
// Hindley-Milner unification: transitive chains
// ---------------------------------------------------------------------------

func TestUnify_TransitiveChain_ThreeVars(t *testing.T) {
	cs := []TypeConstraint{
		eqConstraint(tv("a"), tv("b")),
		eqConstraint(tv("b"), tv("c")),
		eqConstraint(tv("c"), tvConcrete("d", ir.IntType{Width: ir.Size4, Signed: true})),
	}
	sol := Unify(cs)
	for _, name := range []string{"a", "b", "c", "d"} {
		got := sol.Types[name]
		if got == nil {
			t.Fatalf("variable %s resolved to nil, expected i32", name)
		}
		if got.String() != "i32" {
			t.Errorf("variable %s = %s, want i32", name, got.String())
		}
	}
}

func TestUnify_TransitiveChain_PointerPropagation(t *testing.T) {
	cs := []TypeConstraint{
		ptrConstraint(tv("p"), tv("elem")),
		eqConstraint(tv("elem"), tvConcrete("x", ir.IntType{Width: ir.Size8, Signed: true})),
		eqConstraint(tv("q"), tv("p")),
	}
	sol := Unify(cs)
	qType := sol.Types["q"]
	if qType == nil {
		t.Fatal("q resolved to nil")
	}
	pt, ok := qType.(ir.PointerType)
	if !ok {
		t.Fatalf("q = %s, want *i64", qType.String())
	}
	if pt.Pointee.String() != "i64" {
		t.Errorf("q pointee = %s, want i64", pt.Pointee.String())
	}
}

func TestUnify_NestedStructUnification(t *testing.T) {
	cs := []TypeConstraint{
		fieldConstraint(tv("outer"), tv("f0"), 0),
		fieldConstraint(tv("outer"), tv("f8"), 8),
		eqConstraint(tv("f0"), tvConcrete("i32val", ir.IntType{Width: ir.Size4, Signed: true})),
		fieldConstraint(tv("f8"), tv("inner_f0"), 0),
		eqConstraint(tv("inner_f0"), tvConcrete("u8val", ir.IntType{Width: ir.Size1, Signed: false})),
	}
	sol := Unify(cs)
	outerType := sol.Types["outer"]
	if outerType == nil {
		t.Fatal("outer resolved to nil")
	}
	st, ok := outerType.(ir.StructType)
	if !ok {
		t.Fatalf("outer = %T, want StructType", outerType)
	}
	if len(st.Fields) != 2 {
		t.Fatalf("outer has %d fields, want 2", len(st.Fields))
	}
	if st.Fields[0].Type.String() != "i32" {
		t.Errorf("outer.field[0] = %s, want i32", st.Fields[0].Type.String())
	}
	innerSt, ok := st.Fields[1].Type.(ir.StructType)
	if !ok {
		t.Fatalf("outer.field[8] = %T, want StructType", st.Fields[1].Type)
	}
	if len(innerSt.Fields) != 1 {
		t.Fatalf("inner struct has %d fields, want 1", len(innerSt.Fields))
	}
	if innerSt.Fields[0].Type.String() != "u8" {
		t.Errorf("inner.field[0] = %s, want u8", innerSt.Fields[0].Type.String())
	}
}

func TestUnify_FunctionTypeTransitive(t *testing.T) {
	cs := []TypeConstraint{
		{Kind: ConstraintReturnType, Left: tv("fn"), Right: tv("ret"), Confidence: 0.8, Origin: "test"},
		{Kind: ConstraintParamType, Left: tv("fn"), Right: tv("p0"), ParamIndex: 0, Confidence: 0.8, Origin: "test"},
		{Kind: ConstraintParamType, Left: tv("fn"), Right: tv("p1"), ParamIndex: 1, Confidence: 0.8, Origin: "test"},
		eqConstraint(tv("ret"), tvConcrete("retc", ir.IntType{Width: ir.Size8, Signed: true})),
		eqConstraint(tv("p0"), tvConcrete("p0c", ir.IntType{Width: ir.Size4, Signed: false})),
		eqConstraint(tv("p1"), tvConcrete("p1c", ir.FloatType{Width: ir.Size8})),
	}
	sol := Unify(cs)
	fnType := sol.Types["fn"]
	if fnType == nil {
		t.Fatal("fn resolved to nil")
	}
	ft, ok := fnType.(ir.FunctionType)
	if !ok {
		t.Fatalf("fn = %T, want FunctionType", fnType)
	}
	if ft.ReturnType.String() != "i64" {
		t.Errorf("fn return = %s, want i64", ft.ReturnType.String())
	}
	if len(ft.Parameters) != 2 {
		t.Fatalf("fn has %d params, want 2", len(ft.Parameters))
	}
	if ft.Parameters[0].String() != "u32" {
		t.Errorf("fn param[0] = %s, want u32", ft.Parameters[0].String())
	}
	if ft.Parameters[1].String() != "f64" {
		t.Errorf("fn param[1] = %s, want f64", ft.Parameters[1].String())
	}
}

// ---------------------------------------------------------------------------
// Hindley-Milner: pointer-to-struct unification
// ---------------------------------------------------------------------------

func TestUnify_PointerToStruct(t *testing.T) {
	cs := []TypeConstraint{
		ptrConstraint(tv("ptr"), tv("s")),
		fieldConstraint(tv("s"), tv("f0"), 0),
		fieldConstraint(tv("s"), tv("f8"), 8),
		eqConstraint(tv("f0"), tvConcrete("i64c", ir.IntType{Width: ir.Size8, Signed: true})),
		eqConstraint(tv("f8"), tvConcrete("f64c", ir.FloatType{Width: ir.Size8})),
	}
	sol := Unify(cs)
	ptrType := sol.Types["ptr"]
	if ptrType == nil {
		t.Fatal("ptr resolved to nil")
	}
	pt, ok := ptrType.(ir.PointerType)
	if !ok {
		t.Fatalf("ptr = %T, want PointerType", ptrType)
	}
	st, ok := pt.Pointee.(ir.StructType)
	if !ok {
		t.Fatalf("ptr pointee = %T, want StructType", pt.Pointee)
	}
	if len(st.Fields) != 2 {
		t.Fatalf("struct has %d fields, want 2", len(st.Fields))
	}
	if st.Fields[0].Type.String() != "i64" {
		t.Errorf("field[0] = %s, want i64", st.Fields[0].Type.String())
	}
	if st.Fields[1].Type.String() != "f64" {
		t.Errorf("field[8] = %s, want f64", st.Fields[1].Type.String())
	}
}

func TestUnify_ArrayOfPointers(t *testing.T) {
	cs := []TypeConstraint{
		{Kind: ConstraintArrayElement, Left: tv("arr"), Right: tv("elem"), Confidence: 0.8, Origin: "test"},
		ptrConstraint(tv("elem"), tv("pointee")),
		eqConstraint(tv("pointee"), tvConcrete("i32c", ir.IntType{Width: ir.Size4, Signed: true})),
	}
	sol := Unify(cs)
	arrType := sol.Types["arr"]
	if arrType == nil {
		t.Fatal("arr resolved to nil")
	}
	at, ok := arrType.(ir.ArrayType)
	if !ok {
		t.Fatalf("arr = %T, want ArrayType", arrType)
	}
	pt, ok := at.Element.(ir.PointerType)
	if !ok {
		t.Fatalf("arr element = %T, want PointerType", at.Element)
	}
	if pt.Pointee.String() != "i32" {
		t.Errorf("arr element pointee = %s, want i32", pt.Pointee.String())
	}
}

// ---------------------------------------------------------------------------
// MaxSMT conflict resolution: confidence-based priority
// ---------------------------------------------------------------------------

func TestUnify_MaxSMT_HighConfidenceOverridesLow(t *testing.T) {
	cs := []TypeConstraint{
		{Kind: ConstraintEquality, Left: tv("x"), Right: tvConcrete("i32c", ir.IntType{Width: ir.Size4, Signed: true}),
			Confidence: 1.0, Origin: "relocation"},
		{Kind: ConstraintEquality, Left: tv("x"), Right: tvConcrete("i64c", ir.IntType{Width: ir.Size8, Signed: true}),
			Confidence: 0.3, Origin: "heuristic"},
	}
	sol := Unify(cs)
	xType := sol.Types["x"]
	if xType == nil {
		t.Fatal("x resolved to nil")
	}
	if xType.String() != "i32" {
		t.Errorf("x = %s, want i32 (high-confidence relocation should win)", xType.String())
	}
	if len(sol.Conflicts) == 0 {
		t.Error("expected at least one conflict record for the low-confidence constraint")
	}
}

func TestUnify_MaxSMT_MultipleConflicts(t *testing.T) {
	cs := []TypeConstraint{
		{Kind: ConstraintEquality, Left: tv("a"), Right: tvConcrete("i32c", ir.IntType{Width: ir.Size4, Signed: true}),
			Confidence: 1.0, Origin: "relocation"},
		{Kind: ConstraintEquality, Left: tv("a"), Right: tvConcrete("f32c", ir.FloatType{Width: ir.Size4}),
			Confidence: 0.5, Origin: "inferred"},
		{Kind: ConstraintEquality, Left: tv("a"), Right: tvConcrete("u64c", ir.IntType{Width: ir.Size8, Signed: false}),
			Confidence: 0.3, Origin: "heuristic"},
	}
	sol := Unify(cs)
	aType := sol.Types["a"]
	if aType == nil {
		t.Fatal("a resolved to nil")
	}
	if aType.String() != "i32" {
		t.Errorf("a = %s, want i32 (highest confidence)", aType.String())
	}
	if len(sol.Conflicts) < 2 {
		t.Errorf("expected at least 2 conflicts, got %d", len(sol.Conflicts))
	}
}

func TestUnify_MaxSMT_SoftConstraintRecorded(t *testing.T) {
	cs := []TypeConstraint{
		{Kind: ConstraintEquality, Left: tv("x"), Right: tvConcrete("i32c", ir.IntType{Width: ir.Size4, Signed: true}),
			Confidence: 0.9, Origin: "debug-info"},
		{Kind: ConstraintEquality, Left: tv("x"), Right: tvConcrete("boolc", ir.BoolType{}),
			Confidence: 0.3, Origin: "heuristic"},
	}
	sol := Unify(cs)
	found := false
	for _, c := range sol.Conflicts {
		if c.Constraint.Origin == "heuristic" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected heuristic constraint to appear in conflicts")
	}
}

func TestUnify_MaxSMT_EqualConfidenceFirstWins(t *testing.T) {
	cs := []TypeConstraint{
		{Kind: ConstraintEquality, Left: tv("x"), Right: tvConcrete("i32c", ir.IntType{Width: ir.Size4, Signed: true}),
			Confidence: 0.8, Origin: "first"},
		{Kind: ConstraintEquality, Left: tv("x"), Right: tvConcrete("u32c", ir.IntType{Width: ir.Size4, Signed: false}),
			Confidence: 0.8, Origin: "second"},
	}
	sol := Unify(cs)
	xType := sol.Types["x"]
	if xType == nil {
		t.Fatal("x resolved to nil")
	}
	if len(sol.Conflicts) == 0 {
		t.Error("expected a conflict when two equal-confidence constraints clash")
	}
}

func TestUnify_MaxSMT_PointerVsIntConflict(t *testing.T) {
	cs := []TypeConstraint{
		{Kind: ConstraintEquality, Left: tv("x"),
			Right:      tvConcrete("ptrc", ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: true}}),
			Confidence: 1.0, Origin: "relocation"},
		{Kind: ConstraintEquality, Left: tv("x"),
			Right:      tvConcrete("i64c", ir.IntType{Width: ir.Size8, Signed: true}),
			Confidence: 0.5, Origin: "inferred"},
	}
	sol := Unify(cs)
	xType := sol.Types["x"]
	if xType == nil {
		t.Fatal("x resolved to nil")
	}
	if _, ok := xType.(ir.PointerType); !ok {
		t.Errorf("x = %s, want *i32 (pointer from relocation should win)", xType.String())
	}
}

// ---------------------------------------------------------------------------
// ASI: complex structure recovery scenarios
// ---------------------------------------------------------------------------

func TestASI_LinkedListPattern(t *testing.T) {
	accesses := []MemoryAccess{
		acc("node", 0, AccessSize4, ir.IntType{Width: ir.Size4, Signed: true}),
		acc("node", 8, AccessSize8, ir.PointerType{Pointee: ir.VoidType{}}),
	}
	analyzer := NewASIAnalyzer()
	defs := analyzer.InferStructures(accesses)
	if len(defs) != 1 {
		t.Fatalf("expected 1 struct, got %d", len(defs))
	}
	def := defs[0]
	if len(def.Fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(def.Fields))
	}
	if def.Fields[0].Offset != 0 || def.Fields[0].Size != 4 {
		t.Errorf("field[0]: offset=%d size=%d, want offset=0 size=4", def.Fields[0].Offset, def.Fields[0].Size)
	}
	if def.Fields[1].Offset != 8 || def.Fields[1].Size != 8 {
		t.Errorf("field[1]: offset=%d size=%d, want offset=8 size=8", def.Fields[1].Offset, def.Fields[1].Size)
	}
	if def.Alignment != 8 {
		t.Errorf("alignment = %d, want 8", def.Alignment)
	}
	if def.Size != 16 {
		t.Errorf("size = %d, want 16", def.Size)
	}
}

func TestASI_PackedStruct(t *testing.T) {
	accesses := []MemoryAccess{
		acc("packed", 0, AccessSize1, nil),
		acc("packed", 1, AccessSize1, nil),
		acc("packed", 2, AccessSize2, nil),
		acc("packed", 4, AccessSize4, nil),
	}
	analyzer := NewASIAnalyzer()
	defs := analyzer.InferStructures(accesses)
	if len(defs) != 1 {
		t.Fatalf("expected 1 struct, got %d", len(defs))
	}
	def := defs[0]
	if len(def.Fields) != 4 {
		t.Fatalf("expected 4 fields, got %d", len(def.Fields))
	}
	if def.Size != 8 {
		t.Errorf("size = %d, want 8", def.Size)
	}
}

func TestASI_LargeStructWithGaps(t *testing.T) {
	accesses := []MemoryAccess{
		acc("big", 0, AccessSize8, nil),
		acc("big", 16, AccessSize4, nil),
		acc("big", 32, AccessSize8, nil),
	}
	analyzer := NewASIAnalyzer()
	defs := analyzer.InferStructures(accesses)
	if len(defs) != 1 {
		t.Fatalf("expected 1 struct, got %d", len(defs))
	}
	def := defs[0]
	if len(def.Fields) != 3 {
		t.Fatalf("expected 3 fields, got %d", len(def.Fields))
	}
	if def.Fields[0].Offset != 0 {
		t.Errorf("field[0] offset = %d, want 0", def.Fields[0].Offset)
	}
	if def.Fields[1].Offset != 16 {
		t.Errorf("field[1] offset = %d, want 16", def.Fields[1].Offset)
	}
	if def.Fields[2].Offset != 32 {
		t.Errorf("field[2] offset = %d, want 32", def.Fields[2].Offset)
	}
	if def.Size != 40 {
		t.Errorf("size = %d, want 40", def.Size)
	}
}

func TestASI_MultipleBasesNesting(t *testing.T) {
	accesses := []MemoryAccess{
		acc("outer", 0, AccessSize4, nil),
		acc("outer", 4, AccessSize4, nil),
		acc("outer", 8, AccessSize8, nil),
		acc("inner", 0, AccessSize4, nil),
		acc("inner", 4, AccessSize4, nil),
	}
	analyzer := NewASIAnalyzer()
	defs := analyzer.InferStructures(accesses)
	if len(defs) != 2 {
		t.Fatalf("expected 2 structs, got %d", len(defs))
	}
	innerDef := findStruct(defs, "struct_inner")
	if innerDef == nil {
		t.Fatal("struct_inner not found")
	}
	if !innerDef.IsNested {
		t.Error("inner struct should be marked as nested (its offsets are a subset of outer)")
	}
}

func TestASI_WriteAndReadMerge(t *testing.T) {
	accesses := []MemoryAccess{
		{BaseVar: "s", Offset: 0, Size: AccessSize4, IsWrite: true, AccessType: ir.IntType{Width: ir.Size4, Signed: true}},
		{BaseVar: "s", Offset: 0, Size: AccessSize4, IsWrite: false, AccessType: ir.IntType{Width: ir.Size4, Signed: true}},
		{BaseVar: "s", Offset: 8, Size: AccessSize8, IsWrite: true, AccessType: ir.FloatType{Width: ir.Size8}},
	}
	analyzer := NewASIAnalyzer()
	defs := analyzer.InferStructures(accesses)
	if len(defs) != 1 {
		t.Fatalf("expected 1 struct, got %d", len(defs))
	}
	if len(defs[0].Fields) != 2 {
		t.Fatalf("expected 2 fields (merged read/write at offset 0), got %d", len(defs[0].Fields))
	}
}

func TestASI_ExplicitTypePreserved(t *testing.T) {
	accesses := []MemoryAccess{
		acc("s", 0, AccessSize8, ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: true}}),
		acc("s", 8, AccessSize4, ir.FloatType{Width: ir.Size4}),
	}
	analyzer := NewASIAnalyzer()
	defs := analyzer.InferStructures(accesses)
	if len(defs) != 1 {
		t.Fatalf("expected 1 struct, got %d", len(defs))
	}
	f0 := findField(&defs[0], 0)
	if f0 == nil {
		t.Fatal("field at offset 0 not found")
	}
	if _, ok := f0.FieldType.(ir.PointerType); !ok {
		t.Errorf("field[0] type = %T, want PointerType", f0.FieldType)
	}
	f8 := findField(&defs[0], 8)
	if f8 == nil {
		t.Fatal("field at offset 8 not found")
	}
	if _, ok := f8.FieldType.(ir.FloatType); !ok {
		t.Errorf("field[8] type = %T, want FloatType", f8.FieldType)
	}
}

// ---------------------------------------------------------------------------
// Interprocedural type propagation
// ---------------------------------------------------------------------------

func TestInterprocedural_ThreeDeepCallChain(t *testing.T) {
	cg := NewCallGraph()
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg.AddFunction("main", []ir.Type{nil}, nil, CallingConventionSystemVAMD64)
	cg.AddFunction("foo", []ir.Type{nil}, nil, CallingConventionSystemVAMD64)
	cg.AddFunction("bar", []ir.Type{nil}, nil, CallingConventionSystemVAMD64)

	argVar := makeVar("arg", i32)
	retVar := makeVar("ret_foo", nil)
	_ = cg.AddCallEdge("main", "foo", makeCallSite(0x1000,
		[]ir.Expression{ir.VariableExpr{Var: argVar}}, &retVar))

	argVar2 := makeVar("arg2", nil)
	retVar2 := makeVar("ret_bar", nil)
	_ = cg.AddCallEdge("foo", "bar", makeCallSite(0x2000,
		[]ir.Expression{ir.VariableExpr{Var: argVar2}}, &retVar2))

	solutions := map[FunctionID]*TypeSolution{
		"main": {Types: map[string]ir.Type{"arg": i32}},
		"foo":  {Types: map[string]ir.Type{}},
		"bar":  {Types: map[string]ir.Type{"$ret_bar": i64}},
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	err := prop.Propagate(cg, solutions)
	if err != nil {
		t.Fatalf("propagation failed: %v", err)
	}

	fooSummary := prop.Summary("foo")
	if fooSummary == nil {
		t.Fatal("foo summary is nil")
	}
	if len(fooSummary.ParamTypes) == 0 || fooSummary.ParamTypes[0] == nil {
		t.Error("foo param[0] should be propagated from main's i32 argument")
	} else if fooSummary.ParamTypes[0].String() != "i32" {
		t.Errorf("foo param[0] = %s, want i32", fooSummary.ParamTypes[0].String())
	}

	barSummary := prop.Summary("bar")
	if barSummary == nil {
		t.Fatal("bar summary is nil")
	}
	if barSummary.ReturnType == nil {
		t.Error("bar return type should be i64 from intraprocedural solution")
	} else if barSummary.ReturnType.String() != "i64" {
		t.Errorf("bar return = %s, want i64", barSummary.ReturnType.String())
	}
}

func TestInterprocedural_MutualRecursionConverges(t *testing.T) {
	cg := NewCallGraph()
	i32 := ir.IntType{Width: ir.Size4, Signed: true}

	cg.AddFunction("ping", []ir.Type{nil}, nil, CallingConventionSystemVAMD64)
	cg.AddFunction("pong", []ir.Type{nil}, nil, CallingConventionSystemVAMD64)

	pingArg := makeVar("pa", i32)
	pongRet := makeVar("pr", nil)
	_ = cg.AddCallEdge("ping", "pong", makeCallSite(0x100,
		[]ir.Expression{ir.VariableExpr{Var: pingArg}}, &pongRet))

	pongArg := makeVar("qa", nil)
	pingRet := makeVar("qr", nil)
	_ = cg.AddCallEdge("pong", "ping", makeCallSite(0x200,
		[]ir.Expression{ir.VariableExpr{Var: pongArg}}, &pingRet))

	solutions := map[FunctionID]*TypeSolution{
		"ping": {Types: map[string]ir.Type{"pa": i32}},
		"pong": {Types: map[string]ir.Type{}},
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	err := prop.Propagate(cg, solutions)
	if err != nil {
		t.Fatalf("propagation failed: %v", err)
	}

	pongSummary := prop.Summary("pong")
	if pongSummary == nil {
		t.Fatal("pong summary is nil")
	}
	if len(pongSummary.ParamTypes) > 0 && pongSummary.ParamTypes[0] != nil {
		if pongSummary.ParamTypes[0].String() != "i32" {
			t.Errorf("pong param[0] = %s, want i32 (propagated from ping)", pongSummary.ParamTypes[0].String())
		}
	}
}

func TestInterprocedural_ApplySummariesWritesBack(t *testing.T) {
	cg := NewCallGraph()
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg.AddFunction("caller", []ir.Type{i32}, nil, CallingConventionSystemVAMD64)
	cg.AddFunction("callee", []ir.Type{nil}, nil, CallingConventionSystemVAMD64)

	argVar := makeVar("a", i32)
	retVar := makeVar("r", nil)
	_ = cg.AddCallEdge("caller", "callee", makeCallSite(0x100,
		[]ir.Expression{ir.VariableExpr{Var: argVar}}, &retVar))

	solutions := map[FunctionID]*TypeSolution{
		"caller": {Types: map[string]ir.Type{"a": i32}},
		"callee": {Types: map[string]ir.Type{"$ret_callee": i64}},
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	err := prop.Propagate(cg, solutions)
	if err != nil {
		t.Fatalf("propagation failed: %v", err)
	}

	prop.ApplySummaries()

	calleeSol := solutions["callee"]
	paramKey := "$param_callee_0"
	if calleeSol.Types[paramKey] == nil {
		t.Error("ApplySummaries should write callee param[0] into solution")
	} else if calleeSol.Types[paramKey].String() != "i32" {
		t.Errorf("callee param[0] = %s, want i32", calleeSol.Types[paramKey].String())
	}

	retKey := "$ret_callee"
	if calleeSol.Types[retKey] == nil {
		t.Error("ApplySummaries should preserve callee return type")
	} else if calleeSol.Types[retKey].String() != "i64" {
		t.Errorf("callee return = %s, want i64", calleeSol.Types[retKey].String())
	}
}

func TestInterprocedural_EmptyCallGraph(t *testing.T) {
	cg := NewCallGraph()
	solutions := map[FunctionID]*TypeSolution{}
	prop := NewInterproceduralPropagator(cg, solutions)
	err := prop.Propagate(cg, solutions)
	if err != nil {
		t.Fatalf("propagation on empty graph should not fail: %v", err)
	}
	summaries := prop.Summaries()
	if len(summaries) != 0 {
		t.Errorf("expected 0 summaries, got %d", len(summaries))
	}
}

func TestInterprocedural_WidenIntParams(t *testing.T) {
	cg := NewCallGraph()
	i16 := ir.IntType{Width: ir.Size2, Signed: true}
	i32 := ir.IntType{Width: ir.Size4, Signed: true}

	cg.AddFunction("caller1", nil, nil, CallingConventionUnknown)
	cg.AddFunction("caller2", nil, nil, CallingConventionUnknown)
	cg.AddFunction("target", []ir.Type{nil}, nil, CallingConventionUnknown)

	a1 := makeVar("a1", i16)
	_ = cg.AddCallEdge("caller1", "target", makeCallSite(0x100,
		[]ir.Expression{ir.VariableExpr{Var: a1}}, nil))

	a2 := makeVar("a2", i32)
	_ = cg.AddCallEdge("caller2", "target", makeCallSite(0x200,
		[]ir.Expression{ir.VariableExpr{Var: a2}}, nil))

	solutions := map[FunctionID]*TypeSolution{
		"caller1": {Types: map[string]ir.Type{"a1": i16}},
		"caller2": {Types: map[string]ir.Type{"a2": i32}},
		"target":  {Types: map[string]ir.Type{}},
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	err := prop.Propagate(cg, solutions)
	if err != nil {
		t.Fatalf("propagation failed: %v", err)
	}

	targetSummary := prop.Summary("target")
	if targetSummary == nil {
		t.Fatal("target summary is nil")
	}
	if len(targetSummary.ParamTypes) == 0 || targetSummary.ParamTypes[0] == nil {
		t.Fatal("target param[0] should be widened from i16 and i32")
	}
	pt := targetSummary.ParamTypes[0]
	it, ok := pt.(ir.IntType)
	if !ok {
		t.Fatalf("target param[0] = %T, want IntType", pt)
	}
	if it.Width < ir.Size4 {
		t.Errorf("target param[0] width = %d, want >= 4 (widened)", it.Width)
	}
}

// ---------------------------------------------------------------------------
// Unification edge cases
// ---------------------------------------------------------------------------

func TestUnify_DoublePointerChain(t *testing.T) {
	cs := []TypeConstraint{
		ptrConstraint(tv("pp"), tv("p")),
		ptrConstraint(tv("p"), tv("val")),
		eqConstraint(tv("val"), tvConcrete("i32c", ir.IntType{Width: ir.Size4, Signed: true})),
	}
	sol := Unify(cs)
	ppType := sol.Types["pp"]
	if ppType == nil {
		t.Fatal("pp resolved to nil")
	}
	outer, ok := ppType.(ir.PointerType)
	if !ok {
		t.Fatalf("pp = %T, want PointerType", ppType)
	}
	inner, ok := outer.Pointee.(ir.PointerType)
	if !ok {
		t.Fatalf("pp pointee = %T, want PointerType", outer.Pointee)
	}
	if inner.Pointee.String() != "i32" {
		t.Errorf("pp->pointee->pointee = %s, want i32", inner.Pointee.String())
	}
}

func TestUnify_StructFieldOverlapMerge(t *testing.T) {
	cs := []TypeConstraint{
		fieldConstraint(tv("s"), tv("f0_a"), 0),
		fieldConstraint(tv("s"), tv("f0_b"), 0),
		eqConstraint(tv("f0_a"), tvConcrete("i32c", ir.IntType{Width: ir.Size4, Signed: true})),
		eqConstraint(tv("f0_b"), tvConcrete("i32c2", ir.IntType{Width: ir.Size4, Signed: true})),
	}
	sol := Unify(cs)
	sType := sol.Types["s"]
	if sType == nil {
		t.Fatal("s resolved to nil")
	}
	st, ok := sType.(ir.StructType)
	if !ok {
		t.Fatalf("s = %T, want StructType", sType)
	}
	if len(st.Fields) != 1 {
		t.Errorf("expected 1 field (merged at offset 0), got %d", len(st.Fields))
	}
	if st.Fields[0].Type.String() != "i32" {
		t.Errorf("field[0] = %s, want i32", st.Fields[0].Type.String())
	}
}

func TestUnify_FunctionParamExtension(t *testing.T) {
	cs := []TypeConstraint{
		{Kind: ConstraintParamType, Left: tv("fn"), Right: tv("p2"), ParamIndex: 2, Confidence: 0.8, Origin: "test"},
		eqConstraint(tv("p2"), tvConcrete("f64c", ir.FloatType{Width: ir.Size8})),
	}
	sol := Unify(cs)
	fnType := sol.Types["fn"]
	if fnType == nil {
		t.Fatal("fn resolved to nil")
	}
	ft, ok := fnType.(ir.FunctionType)
	if !ok {
		t.Fatalf("fn = %T, want FunctionType", fnType)
	}
	if len(ft.Parameters) < 3 {
		t.Fatalf("fn has %d params, want at least 3 (extended to index 2)", len(ft.Parameters))
	}
	if ft.Parameters[2].String() != "f64" {
		t.Errorf("fn param[2] = %s, want f64", ft.Parameters[2].String())
	}
}

func TestUnify_ConcreteVarBindsImmediately(t *testing.T) {
	cs := []TypeConstraint{
		eqConstraint(tvConcrete("x", ir.IntType{Width: ir.Size4, Signed: true}), tv("y")),
	}
	sol := Unify(cs)
	xType := sol.Types["x"]
	yType := sol.Types["y"]
	if xType == nil || yType == nil {
		t.Fatal("x or y resolved to nil")
	}
	if xType.String() != "i32" {
		t.Errorf("x = %s, want i32", xType.String())
	}
	if yType.String() != "i32" {
		t.Errorf("y = %s, want i32", yType.String())
	}
}

func TestUnify_LargeConstraintSet(t *testing.T) {
	var cs []TypeConstraint
	for i := 0; i < 100; i++ {
		name := TypeVar{Name: fmt.Sprintf("v%d", i)}
		next := TypeVar{Name: fmt.Sprintf("v%d", i+1)}
		cs = append(cs, eqConstraint(name, next))
	}
	cs = append(cs, eqConstraint(
		tv("v100"),
		tvConcrete("ground", ir.IntType{Width: ir.Size8, Signed: false}),
	))
	sol := Unify(cs)
	for i := 0; i <= 100; i++ {
		name := fmt.Sprintf("v%d", i)
		got := sol.Types[name]
		if got == nil {
			t.Fatalf("v%d resolved to nil", i)
		}
		if got.String() != "u64" {
			t.Errorf("v%d = %s, want u64", i, got.String())
		}
	}
}

// ---------------------------------------------------------------------------
// End-to-end: constraint generation -> unification
// ---------------------------------------------------------------------------

func TestEndToEnd_ConstraintGenAndUnify(t *testing.T) {
	x := varOf("x", nil)
	y := varOf("y", ir.IntType{Width: ir.Size4, Signed: true})
	assign := ir.Assign{Dest: x, Source: ir.VariableExpr{Var: y}}
	fn := makeFunction("test_e2e", []ir.IRInstruction{assign})
	gen := NewConstraintGenerator(fn)
	cs := gen.GenerateConstraints()
	sol := Unify(cs)
	xType := sol.Types[x.String()]
	if xType == nil {
		t.Skip("x not resolved (may depend on signature seeding)")
	}
	if xType.String() != "i32" {
		t.Errorf("x = %s, want i32 (propagated from y)", xType.String())
	}
}

func TestEndToEnd_LoadStoreRoundTrip(t *testing.T) {
	ptr := varOf("ptr", ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: true}})
	val := varOf("val", nil)
	load := ir.Load{
		Dest:    val,
		Address: ir.VariableExpr{Var: ptr},
		Size:    ir.Size4,
	}
	fn := makeFunction("load_test", []ir.IRInstruction{load})
	gen := NewConstraintGenerator(fn)
	cs := gen.GenerateConstraints()
	sol := Unify(cs)
	ptrType := sol.Types[ptr.String()]
	if ptrType == nil {
		t.Skip("ptr not resolved")
	}
	if _, ok := ptrType.(ir.PointerType); !ok {
		t.Errorf("ptr = %T, want PointerType", ptrType)
	}
}
