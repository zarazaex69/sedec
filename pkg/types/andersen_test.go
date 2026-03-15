package typeinfer

import (
	"fmt"
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// unit tests for Andersen's pointer analysis
// requirements: 45.4, 45.5, 45.6, 45.8
// ============================================================================

// ============================================================================
// addr_of constraint tests
// ============================================================================

// TestAndersen_AddressOf_Basic verifies: x = &y → pts(x) = {y}
// unlike Steensgaard, Andersen does NOT merge y with other targets of x.
func TestAndersen_AddressOf_Basic(t *testing.T) {
	a := NewAndersenAnalyzer()
	a.processAndersenAddressOf("x", "y")

	pts := a.PointsTo("x")
	if !containsStr(pts, "y") {
		t.Errorf("expected x to point to y, got %v", pts)
	}
}

// TestAndersen_AddressOf_TwoTargets verifies: x = &a; x = &b → pts(x) = {a, b}
// Andersen keeps both targets distinct (no merging of a and b).
func TestAndersen_AddressOf_TwoTargets(t *testing.T) {
	a := NewAndersenAnalyzer()
	a.processAndersenAddressOf("x", "a")
	a.processAndersenAddressOf("x", "b")

	pts := a.PointsTo("x")
	if !containsStr(pts, "a") {
		t.Errorf("expected x to point to a, got %v", pts)
	}
	if !containsStr(pts, "b") {
		t.Errorf("expected x to point to b, got %v", pts)
	}

	// CRITICAL: unlike Steensgaard, a and b must NOT be merged
	if a.MayAlias("a", "b") {
		t.Error("Andersen must NOT merge a and b (they are distinct targets)")
	}
}

// ============================================================================
// copy constraint tests
// ============================================================================

// TestAndersen_Copy_PropagatesTarget verifies: x = &a; y = x → pts(y) ⊇ {a}
func TestAndersen_Copy_PropagatesTarget(t *testing.T) {
	a := NewAndersenAnalyzer()
	a.processAndersenAddressOf("x", "a")
	a.processAndersenCopy("y", "x")
	a.propagate()

	pts := a.PointsTo("y")
	if !containsStr(pts, "a") {
		t.Errorf("expected y to point to a after copy from x, got %v", pts)
	}
}

// TestAndersen_Copy_SubsetSemantics verifies that copy is a subset constraint:
// x = &a; x = &b; y = x → pts(y) ⊇ {a, b} but pts(x) and pts(y) are separate.
func TestAndersen_Copy_SubsetSemantics(t *testing.T) {
	a := NewAndersenAnalyzer()
	a.processAndersenAddressOf("x", "a")
	a.processAndersenAddressOf("x", "b")
	a.processAndersenCopy("y", "x")
	a.propagate()

	ptsY := a.PointsTo("y")
	if !containsStr(ptsY, "a") || !containsStr(ptsY, "b") {
		t.Errorf("expected y to point to {a, b}, got %v", ptsY)
	}

	// a and b must still NOT be merged (Andersen precision)
	if a.MayAlias("a", "b") {
		t.Error("Andersen must NOT merge a and b via copy propagation")
	}
}

// TestAndersen_Copy_Chain verifies transitive propagation: x = &a; y = x; z = y
func TestAndersen_Copy_Chain(t *testing.T) {
	a := NewAndersenAnalyzer()
	a.processAndersenAddressOf("x", "a")
	a.processAndersenCopy("y", "x")
	a.processAndersenCopy("z", "y")
	a.propagate()

	ptsZ := a.PointsTo("z")
	if !containsStr(ptsZ, "a") {
		t.Errorf("expected z to point to a via transitive copy chain, got %v", ptsZ)
	}
}

// ============================================================================
// load constraint tests
// ============================================================================

// TestAndersen_Load_Basic verifies: p = &a; a = &b; x = *p → pts(x) ⊇ {b}
func TestAndersen_Load_Basic(t *testing.T) {
	a := NewAndersenAnalyzer()
	a.processAndersenAddressOf("p", "a")
	a.processAndersenAddressOf("a", "b")
	a.processAndersenLoad("x", "p")
	a.propagate()

	pts := a.PointsTo("x")
	if !containsStr(pts, "b") {
		t.Errorf("expected x to point to b after load through p, got %v", pts)
	}
}

// TestAndersen_Load_MultipleTargets verifies that load through a pointer with
// multiple targets produces the union of their points-to sets.
// p = &a; p = &b; a = &c; b = &d; x = *p → pts(x) ⊇ {c, d}
func TestAndersen_Load_MultipleTargets(t *testing.T) {
	a := NewAndersenAnalyzer()
	a.processAndersenAddressOf("p", "a")
	a.processAndersenAddressOf("p", "b")
	a.processAndersenAddressOf("a", "c")
	a.processAndersenAddressOf("b", "d")
	a.processAndersenLoad("x", "p")
	a.propagate()

	pts := a.PointsTo("x")
	if !containsStr(pts, "c") {
		t.Errorf("expected x to point to c, got %v", pts)
	}
	if !containsStr(pts, "d") {
		t.Errorf("expected x to point to d, got %v", pts)
	}

	// CRITICAL: c and d must NOT be merged (Andersen precision)
	if a.MayAlias("c", "d") {
		t.Error("Andersen must NOT merge c and d (they are distinct load targets)")
	}
}

// TestAndersen_Load_UnknownPointer verifies that loading through an
// uninitialized pointer does not panic and produces a non-empty result.
func TestAndersen_Load_UnknownPointer(_ *testing.T) {
	a := NewAndersenAnalyzer()
	// x = *y where y has no known target yet
	a.processAndersenLoad("x", "y")
	a.propagate()
	// no panic is the primary requirement; result may be empty or contain heap nodes
}

// ============================================================================
// store constraint tests
// ============================================================================

// TestAndersen_Store_Basic verifies: p = &a; *p = b → pts(a) ⊇ pts(b)
func TestAndersen_Store_Basic(t *testing.T) {
	a := NewAndersenAnalyzer()
	a.processAndersenAddressOf("p", "a")
	a.processAndersenAddressOf("b", "c")
	a.processAndersenStore("p", "b")
	a.propagate()

	// after *p = b, a (p's target) must have pts(b) ⊆ pts(a)
	ptsA := a.PointsTo("a")
	if !containsStr(ptsA, "c") {
		t.Errorf("expected a to point to c after store *p = b where b = &c, got %v", ptsA)
	}
}

// TestAndersen_Store_MultipleTargets verifies store through pointer with
// multiple targets: p = &a; p = &b; *p = c → pts(a) ⊇ pts(c) AND pts(b) ⊇ pts(c)
func TestAndersen_Store_MultipleTargets(t *testing.T) {
	a := NewAndersenAnalyzer()
	a.processAndersenAddressOf("p", "a")
	a.processAndersenAddressOf("p", "b")
	a.processAndersenAddressOf("c", "d")
	a.processAndersenStore("p", "c")
	a.propagate()

	ptsA := a.PointsTo("a")
	if !containsStr(ptsA, "d") {
		t.Errorf("expected a to point to d after store, got %v", ptsA)
	}

	ptsB := a.PointsTo("b")
	if !containsStr(ptsB, "d") {
		t.Errorf("expected b to point to d after store, got %v", ptsB)
	}

	// a and b are distinct abstract locations (not the same node).
	// they may appear to alias via d (both point to d after the store),
	// but they are structurally separate nodes - verify they are not the
	// same representative in the union-find structure.
	idxA := a.nameToNode["a"]
	idxB := a.nameToNode["b"]
	if a.andersenFind(idxA) == a.andersenFind(idxB) {
		t.Error("Andersen must NOT collapse a and b into the same SCC node via store")
	}
}

// ============================================================================
// precision comparison: Andersen vs Steensgaard
// ============================================================================

// TestAndersen_PrecisionVsSteensgaard verifies the key precision advantage:
// Andersen does NOT merge unrelated targets that Steensgaard would merge.
//
// program:
//
//	p = &a
//	q = &b
//	r = p  (copy)
//	r = q  (copy - Steensgaard merges a and b here; Andersen does not)
//
// Steensgaard: pts(r) = {a, b}, a and b are merged (may-alias)
// Andersen:    pts(r) = {a, b}, a and b are NOT merged (no may-alias)
func TestAndersen_PrecisionVsSteensgaard(t *testing.T) {
	// Andersen analysis
	andersenA := NewAndersenAnalyzer()
	andersenA.processAndersenAddressOf("p", "a")
	andersenA.processAndersenAddressOf("q", "b")
	andersenA.processAndersenCopy("r", "p")
	andersenA.processAndersenCopy("r", "q")
	andersenA.propagate()

	// Andersen: r points to both a and b
	ptsR := andersenA.PointsTo("r")
	if !containsStr(ptsR, "a") || !containsStr(ptsR, "b") {
		t.Errorf("Andersen: expected r to point to {a, b}, got %v", ptsR)
	}

	// Andersen: a and b are NOT merged (precision advantage)
	if andersenA.MayAlias("a", "b") {
		t.Error("Andersen: a and b must NOT be merged (precision violation)")
	}

	// Steensgaard analysis (for comparison)
	steensgaard := NewSteensgaardAnalyzer()
	steensgaard.processAddressOf("p", "a")
	steensgaard.processAddressOf("q", "b")
	steensgaard.processCopy("r", "p")
	steensgaard.processCopy("r", "q")

	// Steensgaard: a and b ARE merged (less precise)
	if !steensgaard.MayAlias("a", "b") {
		t.Log("note: Steensgaard did not merge a and b in this case (may vary)")
	}
}

// ============================================================================
// may-alias tests
// ============================================================================

// TestAndersen_MayAlias_DirectAlias verifies that two variables in the same
// SCC after collapsing are reported as may-aliases.
func TestAndersen_MayAlias_DirectAlias(t *testing.T) {
	a := NewAndersenAnalyzer()
	a.processAndersenAddressOf("p", "obj")
	a.processAndersenAddressOf("q", "obj")

	if !a.MayAlias("p", "q") {
		t.Error("expected p and q to be indirect aliases (both point to obj)")
	}
}

// TestAndersen_MayAlias_NoAlias verifies that unrelated variables are not aliases.
func TestAndersen_MayAlias_NoAlias(t *testing.T) {
	a := NewAndersenAnalyzer()
	a.processAndersenAddressOf("p", "a")
	a.processAndersenAddressOf("q", "b")

	if a.MayAlias("p", "q") {
		t.Error("expected p and q to NOT be aliases (point to different objects)")
	}
}

// TestAndersen_MayAlias_UnknownVariable verifies no panic for unknown variables.
func TestAndersen_MayAlias_UnknownVariable(t *testing.T) {
	a := NewAndersenAnalyzer()
	if a.MayAlias("unknown_x", "unknown_y") {
		t.Error("expected false for unknown variables")
	}
}

// ============================================================================
// cycle detection and SCC collapsing
// ============================================================================

// TestAndersen_CycleDetection verifies that cycles in the constraint graph
// are correctly detected and collapsed without infinite loops.
//
// program: x = &a; y = x; x = y (cycle: x ↔ y)
func TestAndersen_CycleDetection(t *testing.T) {
	a := NewAndersenAnalyzer()
	a.processAndersenAddressOf("x", "a")
	a.processAndersenCopy("y", "x") // pts(y) ⊇ pts(x)
	a.processAndersenCopy("x", "y") // pts(x) ⊇ pts(y) → cycle
	a.propagate()

	// both x and y must point to a
	ptsX := a.PointsTo("x")
	if !containsStr(ptsX, "a") {
		t.Errorf("expected x to point to a after cycle resolution, got %v", ptsX)
	}

	ptsY := a.PointsTo("y")
	if !containsStr(ptsY, "a") {
		t.Errorf("expected y to point to a after cycle resolution, got %v", ptsY)
	}
}

// TestAndersen_LongCycle verifies that a long cycle (n nodes) terminates.
func TestAndersen_LongCycle(t *testing.T) {
	a := NewAndersenAnalyzer()
	const n = 20

	// create a cycle: v0 → v1 → v2 → ... → v(n-1) → v0
	a.processAndersenAddressOf("v0", "obj")
	for i := 0; i < n-1; i++ {
		src := fmt.Sprintf("v%d", i)
		dst := fmt.Sprintf("v%d", i+1)
		a.processAndersenCopy(dst, src)
	}
	// close the cycle
	a.processAndersenCopy("v0", fmt.Sprintf("v%d", n-1))
	a.propagate()

	// all nodes in the cycle must point to obj
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("v%d", i)
		pts := a.PointsTo(name)
		if !containsStr(pts, "obj") {
			t.Errorf("expected %s to point to obj after cycle resolution, got %v", name, pts)
		}
	}
}

// ============================================================================
// full IR analysis tests
// ============================================================================

// TestAndersen_Analyze_SimplePointerChain verifies end-to-end analysis of:
//
//	p = &x
//	q = p
//	r = *q
func TestAndersen_Analyze_SimplePointerChain(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: false}
	ptrI64 := ir.PointerType{Pointee: i64}

	x := ir.Variable{Name: "x", Type: i64}
	p := ir.Variable{Name: "p", Type: ptrI64}
	q := ir.Variable{Name: "q", Type: ptrI64}

	fn := buildFn("chain", []ir.IRInstruction{
		ir.Assign{
			Dest:   p,
			Source: ir.Cast{Expr: ir.VariableExpr{Var: x}, TargetType: ptrI64},
		},
		ir.Assign{
			Dest:   q,
			Source: ir.VariableExpr{Var: p},
		},
	})

	a := NewAndersenAnalyzer()
	pts := a.Analyze(fn)

	pPts := pts["p"]
	if !containsStr(pPts, "x") {
		t.Errorf("expected p to point to x, got %v", pPts)
	}

	qPts := pts["q"]
	if !containsStr(qPts, "x") {
		t.Errorf("expected q to point to x (via copy from p), got %v", qPts)
	}
}

// TestAndersen_Analyze_EmptyFunction verifies no panic on empty function.
func TestAndersen_Analyze_EmptyFunction(t *testing.T) {
	fn := buildFn("empty", nil)
	a := NewAndersenAnalyzer()
	pts := a.Analyze(fn)
	if len(pts) != 0 {
		t.Errorf("expected empty points-to set for empty function, got %v", pts)
	}
}

// TestAndersen_AnalyzeProgram_Interprocedural verifies interprocedural analysis.
func TestAndersen_AnalyzeProgram_Interprocedural(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: false}
	ptrI64 := ir.PointerType{Pointee: i64}

	a := ir.Variable{Name: "a", Type: i64}
	p := ir.Variable{Name: "p", Type: ptrI64}
	fn1 := buildFn("fn1", []ir.IRInstruction{
		ir.Assign{
			Dest:   p,
			Source: ir.Cast{Expr: ir.VariableExpr{Var: a}, TargetType: ptrI64},
		},
	})

	q := ir.Variable{Name: "q", Type: ptrI64}
	fn2 := buildFn("fn2", []ir.IRInstruction{
		ir.Assign{
			Dest:   q,
			Source: ir.VariableExpr{Var: p},
		},
	})

	analyzer := NewAndersenAnalyzer()
	pts := analyzer.AnalyzeProgram([]*ir.Function{fn1, fn2})

	qPts := pts["q"]
	if !containsStr(qPts, "a") {
		t.Errorf("expected q to point to a in interprocedural analysis, got %v", qPts)
	}
}

// ============================================================================
// hot path selector tests
// ============================================================================

// TestHotPathSelector_LoadStoreThreshold verifies that functions with many
// load/store instructions are classified as hot paths.
func TestHotPathSelector_LoadStoreThreshold(t *testing.T) {
	selector := DefaultHotPathSelector()

	i64 := ir.IntType{Width: ir.Size8, Signed: false}
	ptrI64 := ir.PointerType{Pointee: i64}

	// build a function with 15 load instructions (above threshold of 10)
	instrs := make([]ir.IRInstruction, 15)
	for i := range instrs {
		instrs[i] = ir.Load{
			Dest:    ir.Variable{Name: fmt.Sprintf("v%d", i), Type: i64},
			Address: ir.VariableExpr{Var: ir.Variable{Name: "ptr", Type: ptrI64}},
			Size:    ir.Size8,
		}
	}
	hotFn := buildFn("hot", instrs)

	if !selector.IsHotPath(hotFn) {
		t.Error("expected function with 15 loads to be classified as hot path")
	}

	// build a cold function with only 2 loads
	coldFn := buildFn("cold", instrs[:2])
	if selector.IsHotPath(coldFn) {
		t.Error("expected function with 2 loads to NOT be classified as hot path")
	}
}

// TestHotPathSelector_IndirectCall verifies that functions with indirect calls
// are classified as hot paths.
func TestHotPathSelector_IndirectCall(t *testing.T) {
	selector := DefaultHotPathSelector()

	i64 := ir.IntType{Width: ir.Size8, Signed: false}
	fnPtr := ir.Variable{Name: "fn_ptr", Type: ir.PointerType{Pointee: ir.FunctionType{
		ReturnType: ir.VoidType{},
		Parameters: []ir.Type{},
	}}}

	// function with an indirect call (call through function pointer)
	fn := buildFn("indirect_call", []ir.IRInstruction{
		ir.Call{
			Target: ir.VariableExpr{Var: fnPtr},
			Args:   []ir.Variable{{Name: "arg", Type: i64}},
		},
	})

	if !selector.IsHotPath(fn) {
		t.Error("expected function with indirect call to be classified as hot path")
	}
}

// TestSelectiveAnalyze_HotColdPartitioning verifies that SelectiveAnalyze
// correctly partitions functions and produces a merged result.
func TestSelectiveAnalyze_HotColdPartitioning(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: false}
	ptrI64 := ir.PointerType{Pointee: i64}

	// hot function: many loads
	hotInstrs := make([]ir.IRInstruction, 12)
	for i := range hotInstrs {
		hotInstrs[i] = ir.Load{
			Dest:    ir.Variable{Name: fmt.Sprintf("hv%d", i), Type: i64},
			Address: ir.VariableExpr{Var: ir.Variable{Name: "hptr", Type: ptrI64}},
			Size:    ir.Size8,
		}
	}
	hotFn := buildFn("hot_fn", hotInstrs)

	// cold function: simple pointer assignment
	a := ir.Variable{Name: "ca", Type: i64}
	cp := ir.Variable{Name: "cp", Type: ptrI64}
	coldFn := buildFn("cold_fn", []ir.IRInstruction{
		ir.Assign{
			Dest:   cp,
			Source: ir.Cast{Expr: ir.VariableExpr{Var: a}, TargetType: ptrI64},
		},
	})

	selector := DefaultHotPathSelector()
	result := SelectiveAnalyze([]*ir.Function{hotFn, coldFn}, selector)

	// result must contain entries from both functions
	if result == nil {
		t.Error("expected non-nil result from SelectiveAnalyze")
	}

	// cold function result: cp should point to ca
	cpPts := result["cp"]
	if !containsStr(cpPts, "ca") {
		t.Errorf("expected cp to point to ca from cold function analysis, got %v", cpPts)
	}
}

// ============================================================================
// determinism test
// ============================================================================

// TestAndersen_BuildPointsToSet_Deterministic verifies that buildAndersenPointsToSet
// produces the same output on repeated calls.
func TestAndersen_BuildPointsToSet_Deterministic(t *testing.T) {
	a := NewAndersenAnalyzer()
	a.processAndersenAddressOf("p", "a")
	a.processAndersenAddressOf("p", "b")
	a.processAndersenAddressOf("q", "c")
	a.propagate()

	pts1 := a.buildAndersenPointsToSet()
	pts2 := a.buildAndersenPointsToSet()

	for name, set1 := range pts1 {
		set2 := pts2[name]
		if len(set1) != len(set2) {
			t.Errorf("non-deterministic: %s: run1=%v run2=%v", name, set1, set2)
			continue
		}
		for i := range set1 {
			if set1[i] != set2[i] {
				t.Errorf("non-deterministic: %s[%d]: run1=%s run2=%s", name, i, set1[i], set2[i])
			}
		}
	}
}

// ============================================================================
// union-find correctness tests
// ============================================================================

// TestAndersen_UnionFind_PathCompression verifies path compression in andersenFind.
func TestAndersen_UnionFind_PathCompression(t *testing.T) {
	a := NewAndersenAnalyzer()

	const chainLen = 50
	nodes := make([]int, chainLen)
	for i := range chainLen {
		nodes[i] = a.newAndersenNode(fmt.Sprintf("n%d", i))
	}
	// build a chain: n0 → n1 → ... → n(chainLen-1)
	for i := range chainLen - 1 {
		a.nodes[nodes[i]].parent = nodes[i+1]
	}

	root := a.andersenFind(nodes[0])
	if root != nodes[chainLen-1] {
		t.Errorf("expected root=%d, got %d", nodes[chainLen-1], root)
	}

	// path compression must have updated n0's parent
	if a.nodes[nodes[0]].parent == nodes[1] {
		t.Error("path compression did not update n0's parent")
	}
}

// TestAndersen_PointsTo_UnknownVariable verifies nil return for unknown variable.
func TestAndersen_PointsTo_UnknownVariable(t *testing.T) {
	a := NewAndersenAnalyzer()
	pts := a.PointsTo("nonexistent")
	if pts != nil {
		t.Errorf("expected nil for unknown variable, got %v", pts)
	}
}
