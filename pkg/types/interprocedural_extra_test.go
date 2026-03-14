package typeinfer

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// TestInterproceduralPropagation_TransitiveChain verifies that type information
// propagates transitively through a three-function call chain: A -> B -> C.
// C has a known param type; after propagation B's param must also be constrained.
func TestInterproceduralPropagation_TransitiveChain(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("A", nil, nil, CallingConventionUnknown)
	cg.AddFunction("B", []ir.Type{nil}, nil, CallingConventionUnknown)
	cg.AddFunction("C", []ir.Type{i64}, nil, CallingConventionUnknown)

	// A calls B with an i64 argument
	argA := makeVar("argA", i64)
	siteAB := makeCallSite(0x100, []ir.Expression{ir.VariableExpr{Var: argA}}, nil)
	if err := cg.AddCallEdge("A", "B", siteAB); err != nil {
		t.Fatalf("AddCallEdge A->B: %v", err)
	}

	// B calls C with its own parameter
	argB := makeVar("argB", nil)
	siteBC := makeCallSite(0x200, []ir.Expression{ir.VariableExpr{Var: argB}}, nil)
	if err := cg.AddCallEdge("B", "C", siteBC); err != nil {
		t.Fatalf("AddCallEdge B->C: %v", err)
	}

	solutions := map[FunctionID]*TypeSolution{
		"A": {Types: map[string]ir.Type{"argA": i64}},
		"B": emptySolution(),
		"C": emptySolution(),
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	// B's param[0] must be i64 (propagated from A's call site)
	bSummary := prop.Summary("B")
	if bSummary == nil {
		t.Fatal("B summary is nil")
	}
	if len(bSummary.ParamTypes) == 0 || bSummary.ParamTypes[0] == nil {
		t.Fatal("B param[0] should be i64 (from A's call), got nil")
	}
	if bSummary.ParamTypes[0].String() != i64.String() {
		t.Errorf("B param[0]: expected %s, got %s", i64, bSummary.ParamTypes[0])
	}
}

// TestInterproceduralPropagation_ReturnChain verifies that return type
// propagates from callee back through a chain of callers.
func TestInterproceduralPropagation_ReturnChain(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("A", nil, nil, CallingConventionUnknown)
	cg.AddFunction("B", nil, i64, CallingConventionUnknown)

	// A calls B and stores result in "result_a"
	retVarA := makeVar("result_a", nil)
	siteAB := makeCallSite(0x300, nil, &retVarA)
	if err := cg.AddCallEdge("A", "B", siteAB); err != nil {
		t.Fatalf("AddCallEdge A->B: %v", err)
	}

	solutions := map[FunctionID]*TypeSolution{
		"A": emptySolution(),
		"B": emptySolution(),
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	// A's solution must have result_a = i64
	checkReturnVarType(t, solutions["A"], "result_a", i64)
}

// checkReturnVarType is a shared assertion helper for return-type propagation tests.
func checkReturnVarType(t *testing.T, sol *TypeSolution, varName string, want ir.Type) {
	t.Helper()
	if sol.Types[varName] == nil {
		t.Fatalf("%s should be %s, got nil", varName, want)
	}
	if sol.Types[varName].String() != want.String() {
		t.Errorf("%s: expected %s, got %s", varName, want, sol.Types[varName])
	}
}

// TestInterproceduralPropagation_NoCallers verifies that a function with no
// callers still gets its summary initialized from its node descriptor.
func TestInterproceduralPropagation_NoCallers(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("Standalone", []ir.Type{i64}, i64, CallingConventionUnknown)

	solutions := map[FunctionID]*TypeSolution{
		"Standalone": emptySolution(),
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	summary := prop.Summary("Standalone")
	if summary == nil {
		t.Fatal("Standalone summary is nil")
	}
	// param and return types come from the node descriptor
	if len(summary.ParamTypes) == 0 || summary.ParamTypes[0] == nil {
		t.Fatal("Standalone param[0] should be i64")
	}
	if summary.ReturnType == nil {
		t.Fatal("Standalone return type should be i64")
	}
}

// TestInterproceduralPropagation_ConstantArgument verifies that a constant
// expression argument is resolved to its concrete type at the call site.
func TestInterproceduralPropagation_ConstantArgument(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("Caller", nil, nil, CallingConventionUnknown)
	cg.AddFunction("Callee", []ir.Type{nil}, nil, CallingConventionUnknown)

	// pass a constant i64 value as argument
	constExpr := ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size8, Signed: true}}
	site := makeCallSite(0x400, []ir.Expression{constExpr}, nil)
	if err := cg.AddCallEdge("Caller", "Callee", site); err != nil {
		t.Fatalf("AddCallEdge: %v", err)
	}

	solutions := map[FunctionID]*TypeSolution{
		"Caller": emptySolution(),
		"Callee": emptySolution(),
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	calleeSummary := prop.Summary("Callee")
	if calleeSummary == nil {
		t.Fatal("Callee summary is nil")
	}
	if len(calleeSummary.ParamTypes) == 0 || calleeSummary.ParamTypes[0] == nil {
		t.Fatal("Callee param[0] should be i64 from constant arg, got nil")
	}
	if calleeSummary.ParamTypes[0].String() != i64.String() {
		t.Errorf("Callee param[0]: expected %s, got %s", i64, calleeSummary.ParamTypes[0])
	}
}

// TestInterproceduralPropagation_NilReturnVar verifies that a call site with
// no return variable (void call) does not panic or produce errors.
func TestInterproceduralPropagation_NilReturnVar(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("A", nil, nil, CallingConventionUnknown)
	cg.AddFunction("B", nil, i64, CallingConventionUnknown)

	// call B but discard the return value (nil ReturnVar)
	site := makeCallSite(0x500, nil, nil)
	if err := cg.AddCallEdge("A", "B", site); err != nil {
		t.Fatalf("AddCallEdge: %v", err)
	}

	solutions := map[FunctionID]*TypeSolution{
		"A": emptySolution(),
		"B": emptySolution(),
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	// must not panic
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}
}

// TestInterproceduralPropagation_SystemVFloatParams verifies that XMM register
// types are seeded into float parameter slots under System V ABI.
func TestInterproceduralPropagation_SystemVFloatParams(t *testing.T) {
	f64 := ir.FloatType{Width: ir.Size8}
	checkXMMFloatParams(t, "FP", CallingConventionSystemVAMD64, f64)
}

// TestInterproceduralPropagation_MicrosoftX64FloatParams verifies that XMM
// register types are seeded into float parameter slots under Microsoft x64 ABI.
func TestInterproceduralPropagation_MicrosoftX64FloatParams(t *testing.T) {
	f32 := ir.FloatType{Width: ir.Size4}
	checkXMMFloatParams(t, "H", CallingConventionMicrosoftX64, f32)
}

// checkXMMFloatParams is a shared helper for XMM float parameter seeding tests.
func checkXMMFloatParams(t *testing.T, funcName FunctionID, conv CallingConvention, floatType ir.FloatType) {
	t.Helper()

	cg := NewCallGraph()
	cg.AddFunction(funcName, []ir.Type{nil, nil}, nil, conv)

	sol := &TypeSolution{
		Types: map[string]ir.Type{
			"xmm0": floatType,
			"xmm1": floatType,
		},
	}
	solutions := map[FunctionID]*TypeSolution{funcName: sol}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	summary := prop.Summary(funcName)
	if summary == nil {
		t.Fatalf("%s summary is nil", funcName)
	}
	if len(summary.ParamTypes) < 2 {
		t.Fatalf("expected at least 2 params, got %d", len(summary.ParamTypes))
	}
	for i := 0; i < 2; i++ {
		if summary.ParamTypes[i] == nil {
			t.Errorf("param[%d] should be %s from xmm%d, got nil", i, floatType, i)
			continue
		}
		if summary.ParamTypes[i].String() != floatType.String() {
			t.Errorf("param[%d]: expected %s, got %s", i, floatType, summary.ParamTypes[i])
		}
	}
}

// TestInterproceduralPropagation_MicrosoftX64ReturnFromRAX verifies that the
// RAX register type is seeded as the return type under Microsoft x64 ABI.
func TestInterproceduralPropagation_MicrosoftX64ReturnFromRAX(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("G", nil, nil, CallingConventionMicrosoftX64)

	gSol := &TypeSolution{
		Types: map[string]ir.Type{
			"rax": i64,
		},
	}
	solutions := map[FunctionID]*TypeSolution{"G": gSol}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	gSummary := prop.Summary("G")
	if gSummary == nil {
		t.Fatal("G summary is nil")
	}
	if gSummary.ReturnType == nil {
		t.Fatal("G return type should be i64 from rax, got nil")
	}
	if gSummary.ReturnType.String() != i64.String() {
		t.Errorf("G return type: expected %s, got %s", i64, gSummary.ReturnType)
	}
}

// TestInterproceduralPropagation_SystemVReturnFromRAX verifies that the RAX
// register type is seeded as the return type under System V ABI.
func TestInterproceduralPropagation_SystemVReturnFromRAX(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("F", nil, nil, CallingConventionSystemVAMD64)

	fSol := &TypeSolution{
		Types: map[string]ir.Type{
			"rax": i64,
		},
	}
	solutions := map[FunctionID]*TypeSolution{"F": fSol}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	fSummary := prop.Summary("F")
	if fSummary == nil {
		t.Fatal("F summary is nil")
	}
	if fSummary.ReturnType == nil {
		t.Fatal("F return type should be i64 from rax, got nil")
	}
	if fSummary.ReturnType.String() != i64.String() {
		t.Errorf("F return type: expected %s, got %s", i64, fSummary.ReturnType)
	}
}

// TestMergeConstraints verifies that mergeConstraints deduplicates and merges
// confidence values correctly.
func TestMergeConstraints(t *testing.T) {
	prop := &InterproceduralPropagator{}

	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	existing := []TypeConstraint{
		{
			Kind:       ConstraintEquality,
			Left:       TypeVar{Name: "a"},
			Right:      TypeVar{Name: "b", Concrete: i64},
			Confidence: 0.5,
			Origin:     "existing",
		},
	}
	incoming := []TypeConstraint{
		// same key as existing but higher confidence - should update
		{
			Kind:       ConstraintEquality,
			Left:       TypeVar{Name: "a"},
			Right:      TypeVar{Name: "b", Concrete: i64},
			Confidence: 0.9,
			Origin:     "incoming_high",
		},
		// new constraint not in existing - should be appended
		{
			Kind:       ConstraintPointerTo,
			Left:       TypeVar{Name: "p"},
			Right:      TypeVar{Name: "v"},
			Confidence: 0.7,
			Origin:     "incoming_new",
		},
	}

	result := prop.mergeConstraints(existing, incoming)

	if len(result) != 2 {
		t.Fatalf("expected 2 constraints after merge, got %d", len(result))
	}

	// first constraint must have confidence updated to 0.9
	if result[0].Confidence != 0.9 {
		t.Errorf("expected confidence 0.9 after merge, got %.2f", result[0].Confidence)
	}

	// second constraint must be the new pointer constraint
	if result[1].Kind != ConstraintPointerTo {
		t.Errorf("expected ConstraintPointerTo as second constraint, got %v", result[1].Kind)
	}
}

// TestMergeConstraints_EmptyExisting verifies that merging into an empty
// existing slice returns all incoming constraints.
func TestMergeConstraints_EmptyExisting(t *testing.T) {
	prop := &InterproceduralPropagator{}

	incoming := []TypeConstraint{
		{Kind: ConstraintEquality, Left: TypeVar{Name: "x"}, Right: TypeVar{Name: "y"}, Confidence: 0.5},
		{Kind: ConstraintPointerTo, Left: TypeVar{Name: "p"}, Right: TypeVar{Name: "v"}, Confidence: 0.8},
	}

	result := prop.mergeConstraints(nil, incoming)
	if len(result) != 2 {
		t.Fatalf("expected 2 constraints, got %d", len(result))
	}
}

// TestResolveExprType_NilExpr verifies that resolveExprType returns nil for
// a nil expression without panicking.
func TestResolveExprType_NilExpr(t *testing.T) {
	prop := &InterproceduralPropagator{}
	result := prop.resolveExprType(nil, nil)
	if result != nil {
		t.Errorf("expected nil for nil expression, got %v", result)
	}
}

// TestResolveExprType_VariableWithSolutionType verifies that resolveExprType
// returns the type from the solution when available.
func TestResolveExprType_VariableWithSolutionType(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	prop := &InterproceduralPropagator{}

	v := ir.Variable{Name: "rax", Type: nil}
	sol := &TypeSolution{Types: map[string]ir.Type{"rax": i64}}

	result := prop.resolveExprType(ir.VariableExpr{Var: v}, sol)
	if result == nil {
		t.Fatal("expected i64 from solution, got nil")
	}
	if result.String() != i64.String() {
		t.Errorf("expected i64, got %s", result)
	}
}

// TestResolveExprType_VariableFallbackToDeclaredType verifies that when the
// solution does not contain the variable, its declared type is returned.
func TestResolveExprType_VariableFallbackToDeclaredType(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	prop := &InterproceduralPropagator{}

	v := ir.Variable{Name: "rbx", Type: i32}
	sol := emptySolution() // rbx not in solution

	result := prop.resolveExprType(ir.VariableExpr{Var: v}, sol)
	if result == nil {
		t.Fatal("expected i32 from declared type, got nil")
	}
	if result.String() != i32.String() {
		t.Errorf("expected i32, got %s", result)
	}
}
