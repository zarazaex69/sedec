package typeinfer

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// helpers
// ============================================================================

// emptySolution creates an empty TypeSolution.
func emptySolution() *TypeSolution {
	return &TypeSolution{Types: make(map[string]ir.Type)}
}

// makeVar creates an ir.Variable with the given name and type.
func makeVar(name string, t ir.Type) ir.Variable {
	return ir.Variable{Name: name, Type: t}
}

// makeCallSite creates a CallSite with the given argument expressions.
func makeCallSite(addr ir.Address, args []ir.Expression, retVar *ir.Variable) CallSite {
	return CallSite{
		Address:   addr,
		ArgExprs:  args,
		ReturnVar: retVar,
	}
}

// ============================================================================
// TestInterproceduralPropagation_SimpleChain
// A calls B; B has a known param type → A's argument gets constrained.
// ============================================================================

func TestInterproceduralPropagation_SimpleChain(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	// B has one parameter of type i64
	cg.AddFunction("A", nil, nil, CallingConventionUnknown)
	cg.AddFunction("B", []ir.Type{i64}, nil, CallingConventionUnknown)

	// A calls B with argument variable "arg0"
	argVar := makeVar("arg0", nil)
	site := makeCallSite(0x1000, []ir.Expression{ir.VariableExpr{Var: argVar}}, nil)
	if err := cg.AddCallEdge("A", "B", site); err != nil {
		t.Fatalf("AddCallEdge: %v", err)
	}

	// A's solution has arg0 unresolved; B's solution is empty
	solutions := map[FunctionID]*TypeSolution{
		"A": emptySolution(),
		"B": emptySolution(),
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	// B's summary must have param[0] = i64
	bSummary := prop.Summary("B")
	if bSummary == nil {
		t.Fatal("B summary is nil")
	}
	if len(bSummary.ParamTypes) == 0 || bSummary.ParamTypes[0] == nil {
		t.Fatal("B param[0] should be i64, got nil")
	}
	if bSummary.ParamTypes[0].String() != i64.String() {
		t.Errorf("B param[0]: expected %s, got %s", i64, bSummary.ParamTypes[0])
	}
}

// ============================================================================
// TestInterproceduralPropagation_ReturnType
// B returns i64 → A's use of B's return value gets i64.
// ============================================================================

func TestInterproceduralPropagation_ReturnType(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("A", nil, nil, CallingConventionUnknown)
	cg.AddFunction("B", nil, i64, CallingConventionUnknown)

	// A calls B and stores the result in "result"
	retVar := makeVar("result", nil)
	site := makeCallSite(0x2000, nil, &retVar)
	if err := cg.AddCallEdge("A", "B", site); err != nil {
		t.Fatalf("AddCallEdge: %v", err)
	}

	solutions := map[FunctionID]*TypeSolution{
		"A": emptySolution(),
		"B": emptySolution(),
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	// A's solution must have "result" = i64
	checkReturnVarType(t, solutions["A"], "result", i64)
}

// ============================================================================
// TestInterproceduralPropagation_CallingConventionSeed
// System V ABI seeds RDI→param0, RSI→param1.
// ============================================================================

func TestInterproceduralPropagation_CallingConventionSeed(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	checkIntParamSeeding(t, "F", CallingConventionSystemVAMD64,
		map[string]ir.Type{"rdi": i64, "rsi": i32}, i64, i32)
}

// checkIntParamSeeding is a shared helper for integer register parameter seeding tests.
func checkIntParamSeeding(
	t *testing.T,
	funcName FunctionID,
	conv CallingConvention,
	regTypes map[string]ir.Type,
	wantParam0, wantParam1 ir.Type,
) {
	t.Helper()

	cg := NewCallGraph()
	cg.AddFunction(funcName, []ir.Type{nil, nil}, nil, conv)

	sol := &TypeSolution{Types: regTypes}
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
	if summary.ParamTypes[0] == nil || summary.ParamTypes[0].String() != wantParam0.String() {
		t.Errorf("param[0]: expected %s, got %v", wantParam0, summary.ParamTypes[0])
	}
	if summary.ParamTypes[1] == nil || summary.ParamTypes[1].String() != wantParam1.String() {
		t.Errorf("param[1]: expected %s, got %v", wantParam1, summary.ParamTypes[1])
	}
}

// ============================================================================
// TestInterproceduralPropagation_RecursiveFunction
// Recursive call converges correctly (no infinite loop).
// ============================================================================

func TestInterproceduralPropagation_RecursiveFunction(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("Fib", []ir.Type{i64}, i64, CallingConventionUnknown)

	// Fib calls itself recursively
	argVar := makeVar("n", i64)
	retVar := makeVar("r", nil)
	site := makeCallSite(0x3000, []ir.Expression{ir.VariableExpr{Var: argVar}}, &retVar)
	if err := cg.AddCallEdge("Fib", "Fib", site); err != nil {
		t.Fatalf("AddCallEdge: %v", err)
	}

	solutions := map[FunctionID]*TypeSolution{
		"Fib": {Types: map[string]ir.Type{"n": i64}},
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	// must not loop forever
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	fibSummary := prop.Summary("Fib")
	if fibSummary == nil {
		t.Fatal("Fib summary is nil")
	}
	// param[0] must remain i64 after convergence
	if len(fibSummary.ParamTypes) == 0 || fibSummary.ParamTypes[0] == nil {
		t.Fatal("Fib param[0] should be i64")
	}
	if fibSummary.ParamTypes[0].String() != i64.String() {
		t.Errorf("Fib param[0]: expected %s, got %s", i64, fibSummary.ParamTypes[0])
	}
}

// ============================================================================
// TestInterproceduralPropagation_MultipleCallers
// Multiple callers with compatible types merge correctly.
// ============================================================================

func TestInterproceduralPropagation_MultipleCallers(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("A", nil, nil, CallingConventionUnknown)
	cg.AddFunction("B", nil, nil, CallingConventionUnknown)
	cg.AddFunction("Target", []ir.Type{nil}, nil, CallingConventionUnknown)

	// both A and B call Target with an i64 argument
	argA := makeVar("argA", i64)
	argB := makeVar("argB", i64)
	siteA := makeCallSite(0x100, []ir.Expression{ir.VariableExpr{Var: argA}}, nil)
	siteB := makeCallSite(0x200, []ir.Expression{ir.VariableExpr{Var: argB}}, nil)

	if err := cg.AddCallEdge("A", "Target", siteA); err != nil {
		t.Fatalf("AddCallEdge A->Target: %v", err)
	}
	if err := cg.AddCallEdge("B", "Target", siteB); err != nil {
		t.Fatalf("AddCallEdge B->Target: %v", err)
	}

	solutions := map[FunctionID]*TypeSolution{
		"A":      {Types: map[string]ir.Type{"argA": i64}},
		"B":      {Types: map[string]ir.Type{"argB": i64}},
		"Target": emptySolution(),
	}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	targetSummary := prop.Summary("Target")
	if targetSummary == nil {
		t.Fatal("Target summary is nil")
	}
	if len(targetSummary.ParamTypes) == 0 || targetSummary.ParamTypes[0] == nil {
		t.Fatal("Target param[0] should be i64")
	}
	if targetSummary.ParamTypes[0].String() != i64.String() {
		t.Errorf("Target param[0]: expected %s, got %s", i64, targetSummary.ParamTypes[0])
	}
}

// ============================================================================
// TestInterproceduralPropagation_ConflictingCallers
// Multiple callers with conflicting types are handled gracefully (no panic).
// ============================================================================

func TestInterproceduralPropagation_ConflictingCallers(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("A", nil, nil, CallingConventionUnknown)
	cg.AddFunction("B", nil, nil, CallingConventionUnknown)
	cg.AddFunction("Target", []ir.Type{nil}, nil, CallingConventionUnknown)

	// A passes i32, B passes i64 - conflicting types
	argA := makeVar("argA", i32)
	argB := makeVar("argB", i64)
	siteA := makeCallSite(0x100, []ir.Expression{ir.VariableExpr{Var: argA}}, nil)
	siteB := makeCallSite(0x200, []ir.Expression{ir.VariableExpr{Var: argB}}, nil)

	if err := cg.AddCallEdge("A", "Target", siteA); err != nil {
		t.Fatalf("AddCallEdge A->Target: %v", err)
	}
	if err := cg.AddCallEdge("B", "Target", siteB); err != nil {
		t.Fatalf("AddCallEdge B->Target: %v", err)
	}

	solutions := map[FunctionID]*TypeSolution{
		"A":      {Types: map[string]ir.Type{"argA": i32}},
		"B":      {Types: map[string]ir.Type{"argB": i64}},
		"Target": emptySolution(),
	}

	// must not panic
	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}

	targetSummary := prop.Summary("Target")
	if targetSummary == nil {
		t.Fatal("Target summary is nil")
	}

	// with conflicting types, mergeTypes should widen to i64 (larger)
	if len(targetSummary.ParamTypes) > 0 && targetSummary.ParamTypes[0] != nil {
		merged := targetSummary.ParamTypes[0]
		// widened result must be at least as wide as the larger input
		if intT, ok := merged.(ir.IntType); ok {
			if intT.Width < i64.Width {
				t.Errorf("expected widened type >= i64, got %s", merged)
			}
		}
		// if mergeTypes returned nil (conservative), that is also acceptable
	}
}

// ============================================================================
// TestCallGraph_TopologicalOrder
// Verify topological ordering is correct for a DAG.
// ============================================================================

func TestCallGraph_TopologicalOrder(t *testing.T) {
	// build: A -> B -> D
	//        A -> C -> D
	// expected: D before B and C, B and C before A
	cg := NewCallGraph()
	cg.AddFunction("A", nil, nil, CallingConventionUnknown)
	cg.AddFunction("B", nil, nil, CallingConventionUnknown)
	cg.AddFunction("C", nil, nil, CallingConventionUnknown)
	cg.AddFunction("D", nil, nil, CallingConventionUnknown)

	site := makeCallSite(0, nil, nil)
	for _, edge := range [][2]FunctionID{{"A", "B"}, {"A", "C"}, {"B", "D"}, {"C", "D"}} {
		if err := cg.AddCallEdge(edge[0], edge[1], site); err != nil {
			t.Fatalf("AddCallEdge %s->%s: %v", edge[0], edge[1], err)
		}
	}

	order, err := cg.TopologicalOrder()
	if err != nil {
		t.Fatalf("TopologicalOrder: %v", err)
	}
	if len(order) != 4 {
		t.Fatalf("expected 4 nodes, got %d", len(order))
	}

	// build position map
	pos := make(map[FunctionID]int, len(order))
	for i, id := range order {
		pos[id] = i
	}

	// verify ordering constraints: caller must appear after callee
	// (bottom-up: leaves first)
	for _, edge := range [][2]FunctionID{{"A", "B"}, {"A", "C"}, {"B", "D"}, {"C", "D"}} {
		callerPos := pos[edge[0]]
		calleePos := pos[edge[1]]
		if calleePos >= callerPos {
			t.Errorf("expected %s (pos %d) before %s (pos %d) in bottom-up order",
				edge[1], calleePos, edge[0], callerPos)
		}
	}
}

// ============================================================================
// TestCallGraph_SCCDetection
// Verify SCC detection for recursive call cycles.
// ============================================================================

func TestCallGraph_SCCDetection(t *testing.T) {
	// build: A -> B -> C -> A (cycle), D -> A (external caller)
	cg := NewCallGraph()
	cg.AddFunction("A", nil, nil, CallingConventionUnknown)
	cg.AddFunction("B", nil, nil, CallingConventionUnknown)
	cg.AddFunction("C", nil, nil, CallingConventionUnknown)
	cg.AddFunction("D", nil, nil, CallingConventionUnknown)

	site := makeCallSite(0, nil, nil)
	for _, edge := range [][2]FunctionID{{"A", "B"}, {"B", "C"}, {"C", "A"}, {"D", "A"}} {
		if err := cg.AddCallEdge(edge[0], edge[1], site); err != nil {
			t.Fatalf("AddCallEdge %s->%s: %v", edge[0], edge[1], err)
		}
	}

	sccs := cg.SCCs()

	// find the SCC containing A, B, C
	var cycleSCC []FunctionID
	var dSCC []FunctionID
	for _, scc := range sccs {
		for _, id := range scc {
			if id == "A" {
				cycleSCC = scc
			}
			if id == "D" {
				dSCC = scc
			}
		}
	}

	if len(cycleSCC) != 3 {
		t.Errorf("expected SCC {A,B,C} of size 3, got %v", cycleSCC)
	}
	if len(dSCC) != 1 {
		t.Errorf("expected SCC {D} of size 1, got %v", dSCC)
	}

	// verify all three cycle members are in the same SCC
	cycleSet := make(map[FunctionID]bool)
	for _, id := range cycleSCC {
		cycleSet[id] = true
	}
	for _, expected := range []FunctionID{"A", "B", "C"} {
		if !cycleSet[expected] {
			t.Errorf("expected %s in cycle SCC, not found in %v", expected, cycleSCC)
		}
	}
}

// ============================================================================
// TestCallGraph_AddCallEdge_UnknownFunction
// Verify that AddCallEdge returns an error for unregistered functions.
// ============================================================================

func TestCallGraph_AddCallEdge_UnknownFunction(t *testing.T) {
	cg := NewCallGraph()
	cg.AddFunction("A", nil, nil, CallingConventionUnknown)

	site := makeCallSite(0, nil, nil)

	// callee not registered
	if err := cg.AddCallEdge("A", "B", site); err == nil {
		t.Error("expected error for unknown callee B, got nil")
	}

	// caller not registered
	if err := cg.AddCallEdge("X", "A", site); err == nil {
		t.Error("expected error for unknown caller X, got nil")
	}
}

// ============================================================================
// TestCallGraph_EmptyGraph
// Verify that an empty call graph behaves correctly.
// ============================================================================

func TestCallGraph_EmptyGraph(t *testing.T) {
	cg := NewCallGraph()

	order, err := cg.TopologicalOrder()
	if err != nil {
		t.Fatalf("TopologicalOrder on empty graph: %v", err)
	}
	if len(order) != 0 {
		t.Errorf("expected empty order, got %v", order)
	}

	sccs := cg.SCCs()
	if len(sccs) != 0 {
		t.Errorf("expected no SCCs, got %v", sccs)
	}
}

// ============================================================================
// TestMergeTypes_Lattice
// Verify the type lattice join rules.
// ============================================================================

func TestMergeTypes_Lattice(t *testing.T) {
	prop := &InterproceduralPropagator{}

	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	u32 := ir.IntType{Width: ir.Size4, Signed: false}
	f32 := ir.FloatType{Width: ir.Size4}
	f64 := ir.FloatType{Width: ir.Size8}

	tests := []struct {
		name    string
		a, b    ir.Type
		wantNil bool
		wantStr string
	}{
		{"nil join T = T", nil, i64, false, i64.String()},
		{"T join nil = T", i64, nil, false, i64.String()},
		{"T join T = T", i64, i64, false, i64.String()},
		{"i32 join i64 = i64 (widening)", i32, i64, false, i64.String()},
		{"i32 join u32 = i32 (signed wins)", i32, u32, false, ir.IntType{Width: ir.Size4, Signed: true}.String()},
		{"f32 join f64 = f64 (widening)", f32, f64, false, f64.String()},
		{"*i32 join *i64 = *i64 (ptr widening)", ir.PointerType{Pointee: i32}, ir.PointerType{Pointee: i64}, false, ir.PointerType{Pointee: i64}.String()},
		{"i64 join f64 = f64 (float wins)", i64, f64, false, f64.String()},
		{"bool join i64 = nil (conservative)", ir.BoolType{}, i64, true, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := prop.mergeTypes(tc.a, tc.b)
			if tc.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %s", result)
				}
				return
			}
			if result == nil {
				t.Fatalf("expected %s, got nil", tc.wantStr)
			}
			if result.String() != tc.wantStr {
				t.Errorf("expected %s, got %s", tc.wantStr, result)
			}
		})
	}
}

// ============================================================================
// TestApplySummaries
// Verify that ApplySummaries writes param/return types into solutions.
// ============================================================================

func TestApplySummaries(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	cg := NewCallGraph()
	cg.AddFunction("F", []ir.Type{i64}, i64, CallingConventionUnknown)

	sol := emptySolution()
	solutions := map[FunctionID]*TypeSolution{"F": sol}

	prop := NewInterproceduralPropagator(cg, solutions)
	if err := prop.Propagate(cg, solutions); err != nil {
		t.Fatalf("Propagate: %v", err)
	}
	prop.ApplySummaries()

	// check that param and return keys were written
	paramKey := "$param_F_0"
	retKey := "$ret_F"

	if sol.Types[paramKey] == nil {
		t.Errorf("expected %s in solution, got nil", paramKey)
	}
	if sol.Types[retKey] == nil {
		t.Errorf("expected %s in solution, got nil", retKey)
	}
}

// ============================================================================
// TestCallingConvention_MicrosoftX64
// Microsoft x64 ABI seeds RCX→param0, RDX→param1.
// ============================================================================

func TestCallingConvention_MicrosoftX64(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	checkIntParamSeeding(t, "G", CallingConventionMicrosoftX64,
		map[string]ir.Type{"rcx": i64, "rdx": i32}, i64, i32)
}
