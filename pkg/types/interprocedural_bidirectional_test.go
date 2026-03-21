package typeinfer

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

func TestPropagateCalleeParamToCallerArg(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("Caller", nil, nil, CallingConventionUnknown)
	cg.AddFunction("Callee", []ir.Type{i64}, nil, CallingConventionUnknown)

	argVar := makeVar("x", nil)
	site := makeCallSite(0x100, []ir.Expression{ir.VariableExpr{Var: argVar}}, nil)
	if err := cg.AddCallEdge("Caller", "Callee", site); err != nil {
		t.Fatalf("AddCallEdge: %v", err)
	}

	callerSol := emptySolution()
	solutions := map[FunctionID]*TypeSolution{
		"Caller": callerSol,
		"Callee": emptySolution(),
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	got := callerSol.Types["x"]
	if got == nil {
		t.Fatal("expected caller's 'x' to be constrained to i64, got nil")
	}
	if got.String() != i64.String() {
		t.Errorf("expected %s, got %s", i64, got)
	}
}

func TestPropagateCalleeParamToCallerArg_MultipleCallees(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("Caller", nil, nil, CallingConventionUnknown)
	cg.AddFunction("F1", []ir.Type{i32}, nil, CallingConventionUnknown)
	cg.AddFunction("F2", []ir.Type{i64}, nil, CallingConventionUnknown)

	argVar := makeVar("y", nil)
	site1 := makeCallSite(0x100, []ir.Expression{ir.VariableExpr{Var: argVar}}, nil)
	site2 := makeCallSite(0x200, []ir.Expression{ir.VariableExpr{Var: argVar}}, nil)

	if err := cg.AddCallEdge("Caller", "F1", site1); err != nil {
		t.Fatalf("AddCallEdge: %v", err)
	}
	if err := cg.AddCallEdge("Caller", "F2", site2); err != nil {
		t.Fatalf("AddCallEdge: %v", err)
	}

	callerSol := emptySolution()
	solutions := map[FunctionID]*TypeSolution{
		"Caller": callerSol,
		"F1":     emptySolution(),
		"F2":     emptySolution(),
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	got := callerSol.Types["y"]
	if got == nil {
		t.Fatal("expected caller's 'y' to be constrained, got nil")
	}
	intT, ok := got.(ir.IntType)
	if !ok {
		t.Fatalf("expected IntType, got %T", got)
	}
	if intT.Width < i64.Width {
		t.Errorf("expected widened to at least i64, got %s", got)
	}
}

func TestReturnTypeFromIntraproceduralSolution(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("Caller", nil, nil, CallingConventionUnknown)
	cg.AddFunction("Callee", nil, nil, CallingConventionUnknown)

	retVar := makeVar("result", nil)
	site := makeCallSite(0x100, nil, &retVar)
	if err := cg.AddCallEdge("Caller", "Callee", site); err != nil {
		t.Fatalf("AddCallEdge: %v", err)
	}

	callerSol := emptySolution()
	calleeSol := &TypeSolution{
		Types: map[string]ir.Type{
			"$ret_Callee": i64,
		},
	}
	solutions := map[FunctionID]*TypeSolution{
		"Caller": callerSol,
		"Callee": calleeSol,
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	got := callerSol.Types["result"]
	if got == nil {
		t.Fatal("expected 'result' to be i64 from callee's intraprocedural solution, got nil")
	}
	if got.String() != i64.String() {
		t.Errorf("expected %s, got %s", i64, got)
	}
}

func TestFloatReturnSeedFromXMM0_SystemV(t *testing.T) {
	f64 := ir.FloatType{Width: ir.Size8}

	cg := NewCallGraph()
	cg.AddFunction("F", nil, nil, CallingConventionSystemVAMD64)

	sol := &TypeSolution{
		Types: map[string]ir.Type{
			"xmm0": f64,
		},
	}
	solutions := map[FunctionID]*TypeSolution{"F": sol}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	summary := prop.Summary("F")
	if summary == nil {
		t.Fatal("F summary is nil")
	}
	if summary.ReturnType == nil {
		t.Fatal("expected return type f64 from xmm0, got nil")
	}
	if summary.ReturnType.String() != f64.String() {
		t.Errorf("expected %s, got %s", f64, summary.ReturnType)
	}
}

func TestFloatReturnSeedFromXMM0_MicrosoftX64(t *testing.T) {
	f32 := ir.FloatType{Width: ir.Size4}

	cg := NewCallGraph()
	cg.AddFunction("G", nil, nil, CallingConventionMicrosoftX64)

	sol := &TypeSolution{
		Types: map[string]ir.Type{
			"xmm0": f32,
		},
	}
	solutions := map[FunctionID]*TypeSolution{"G": sol}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	summary := prop.Summary("G")
	if summary == nil {
		t.Fatal("G summary is nil")
	}
	if summary.ReturnType == nil {
		t.Fatal("expected return type f32 from xmm0, got nil")
	}
	if summary.ReturnType.String() != f32.String() {
		t.Errorf("expected %s, got %s", f32, summary.ReturnType)
	}
}

func TestMergeTypes_ArrayType(t *testing.T) {
	prop := &InterproceduralPropagator{}

	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	a := ir.ArrayType{Element: i32, Length: 10}
	b := ir.ArrayType{Element: i64, Length: 10}
	result := prop.mergeTypes(a, b)
	if result == nil {
		t.Fatal("expected merged array type, got nil")
	}
	arr, ok := result.(ir.ArrayType)
	if !ok {
		t.Fatalf("expected ArrayType, got %T", result)
	}
	if arr.Length != 10 {
		t.Errorf("expected length 10, got %d", arr.Length)
	}
	elemInt, ok := arr.Element.(ir.IntType)
	if !ok {
		t.Fatalf("expected IntType element, got %T", arr.Element)
	}
	if elemInt.Width < i64.Width {
		t.Errorf("expected element widened to i64, got %s", arr.Element)
	}
}

func TestMergeTypes_ArrayType_DifferentLength(t *testing.T) {
	prop := &InterproceduralPropagator{}

	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	a := ir.ArrayType{Element: i32, Length: 10}
	b := ir.ArrayType{Element: i32, Length: 20}
	result := prop.mergeTypes(a, b)
	if result != nil {
		t.Errorf("expected nil for arrays with different lengths, got %s", result)
	}
}

func TestMergeTypes_StructType(t *testing.T) {
	prop := &InterproceduralPropagator{}

	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	a := ir.StructType{
		Name: "point",
		Fields: []ir.StructField{
			{Name: "x", Type: i32, Offset: 0},
			{Name: "y", Type: i32, Offset: 4},
		},
	}
	b := ir.StructType{
		Fields: []ir.StructField{
			{Name: "", Type: i64, Offset: 0},
			{Name: "", Type: i64, Offset: 4},
		},
	}
	result := prop.mergeTypes(a, b)
	if result == nil {
		t.Fatal("expected merged struct type, got nil")
	}
	st, ok := result.(ir.StructType)
	if !ok {
		t.Fatalf("expected StructType, got %T", result)
	}
	if st.Name != "point" {
		t.Errorf("expected name 'point', got %q", st.Name)
	}
	if len(st.Fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(st.Fields))
	}
	if st.Fields[0].Name != "x" {
		t.Errorf("expected field name 'x', got %q", st.Fields[0].Name)
	}
}

func TestMergeTypes_StructType_IncompatibleOffsets(t *testing.T) {
	prop := &InterproceduralPropagator{}

	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	a := ir.StructType{
		Name: "s1",
		Fields: []ir.StructField{
			{Name: "x", Type: i32, Offset: 0},
		},
	}
	b := ir.StructType{
		Name: "s2",
		Fields: []ir.StructField{
			{Name: "x", Type: i32, Offset: 8},
		},
	}
	result := prop.mergeTypes(a, b)
	if result != nil {
		t.Errorf("expected nil for structs with different names and offsets, got %s", result)
	}
}

func TestMergeTypes_FunctionType(t *testing.T) {
	prop := &InterproceduralPropagator{}

	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	a := ir.FunctionType{
		ReturnType: i32,
		Parameters: []ir.Type{i32},
	}
	b := ir.FunctionType{
		ReturnType: i64,
		Parameters: []ir.Type{i64},
	}
	result := prop.mergeTypes(a, b)
	if result == nil {
		t.Fatal("expected merged function type, got nil")
	}
	fn, ok := result.(ir.FunctionType)
	if !ok {
		t.Fatalf("expected FunctionType, got %T", result)
	}
	if len(fn.Parameters) != 1 {
		t.Fatalf("expected 1 param, got %d", len(fn.Parameters))
	}
	paramInt, ok := fn.Parameters[0].(ir.IntType)
	if !ok {
		t.Fatalf("expected IntType param, got %T", fn.Parameters[0])
	}
	if paramInt.Width < i64.Width {
		t.Errorf("expected param widened to i64, got %s", fn.Parameters[0])
	}
}

func TestMergeTypes_FunctionType_ArityMismatch(t *testing.T) {
	prop := &InterproceduralPropagator{}

	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	a := ir.FunctionType{ReturnType: i32, Parameters: []ir.Type{i32}}
	b := ir.FunctionType{ReturnType: i32, Parameters: []ir.Type{i32, i32}}
	result := prop.mergeTypes(a, b)
	if result != nil {
		t.Errorf("expected nil for functions with different arity, got %s", result)
	}
}

func TestSummaries(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("A", []ir.Type{i64}, nil, CallingConventionUnknown)
	cg.AddFunction("B", nil, i64, CallingConventionUnknown)

	solutions := map[FunctionID]*TypeSolution{
		"A": emptySolution(),
		"B": emptySolution(),
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	summaries := prop.Summaries()
	if len(summaries) != 2 {
		t.Fatalf("expected 2 summaries, got %d", len(summaries))
	}
	if summaries["A"] == nil {
		t.Error("expected summary for A")
	}
	if summaries["B"] == nil {
		t.Error("expected summary for B")
	}
}

func TestPropagateCalleeParamToCallerArg_ConstantArgIgnored(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("Caller", nil, nil, CallingConventionUnknown)
	cg.AddFunction("Callee", []ir.Type{i64}, nil, CallingConventionUnknown)

	constExpr := ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size8, Signed: true}}
	site := makeCallSite(0x100, []ir.Expression{constExpr}, nil)
	if err := cg.AddCallEdge("Caller", "Callee", site); err != nil {
		t.Fatalf("AddCallEdge: %v", err)
	}

	callerSol := emptySolution()
	solutions := map[FunctionID]*TypeSolution{
		"Caller": callerSol,
		"Callee": emptySolution(),
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}
}

func TestMutualRecursion_Convergence(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("Even", []ir.Type{i64}, i64, CallingConventionUnknown)
	cg.AddFunction("Odd", []ir.Type{i64}, i64, CallingConventionUnknown)

	argE := makeVar("n_e", i64)
	retE := makeVar("r_e", nil)
	siteEO := makeCallSite(0x100, []ir.Expression{ir.VariableExpr{Var: argE}}, &retE)

	argO := makeVar("n_o", i64)
	retO := makeVar("r_o", nil)
	siteOE := makeCallSite(0x200, []ir.Expression{ir.VariableExpr{Var: argO}}, &retO)

	if err := cg.AddCallEdge("Even", "Odd", siteEO); err != nil {
		t.Fatalf("AddCallEdge: %v", err)
	}
	if err := cg.AddCallEdge("Odd", "Even", siteOE); err != nil {
		t.Fatalf("AddCallEdge: %v", err)
	}

	solutions := map[FunctionID]*TypeSolution{
		"Even": {Types: map[string]ir.Type{"n_e": i64}},
		"Odd":  {Types: map[string]ir.Type{"n_o": i64}},
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	evenSummary := prop.Summary("Even")
	oddSummary := prop.Summary("Odd")

	if evenSummary == nil || oddSummary == nil {
		t.Fatal("summaries should not be nil")
	}
	if evenSummary.ReturnType == nil {
		t.Error("Even return type should be i64")
	}
	if oddSummary.ReturnType == nil {
		t.Error("Odd return type should be i64")
	}

	if solutions["Even"].Types["r_e"] == nil {
		t.Error("Even's r_e should be constrained from Odd's return type")
	}
	if solutions["Odd"].Types["r_o"] == nil {
		t.Error("Odd's r_o should be constrained from Even's return type")
	}
}
