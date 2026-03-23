package typeinfer

import (
	"fmt"
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// helpers
// ============================================================================

// buildFn constructs a minimal ir.Function with the given instructions in a
// single basic block. used to avoid boilerplate in every test case.
func buildFn(name string, instrs []ir.IRInstruction) *ir.Function {
	return &ir.Function{
		Name: name,
		Signature: ir.FunctionType{
			ReturnType: ir.VoidType{},
			Parameters: []ir.Type{},
		},
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {ID: 0, Instructions: instrs},
		},
		EntryBlock: 0,
	}
}

// varPtr creates an ir.Variable with a pointer type.
func varPtr(name string, pointee ir.Type) ir.Variable {
	return ir.Variable{Name: name, Type: ir.PointerType{Pointee: pointee}}
}

// varInt creates an ir.Variable with an integer type.
func varInt(name string) ir.Variable {
	return ir.Variable{Name: name, Type: ir.IntType{Width: ir.Size8, Signed: false}}
}

// ============================================================================
// union-find correctness tests
// ============================================================================

// TestSteensgaard_UnionFind_PathCompression verifies that find() with path
// compression terminates correctly on a long chain of nodes.
func TestSteensgaard_UnionFind_PathCompression(t *testing.T) {
	a := NewSteensgaardAnalyzer()

	// build a chain: n0 → n1 → n2 → ... → n99
	const chainLen = 100
	nodes := make([]int, chainLen)
	for i := 0; i < chainLen; i++ {
		nodes[i] = a.newNode(fmt.Sprintf("n%d", i))
	}
	// link into a chain by setting parent pointers directly
	for i := 0; i < chainLen-1; i++ {
		a.nodes[nodes[i]].parent = nodes[i+1]
	}

	// find the root of n0: must return nodes[chainLen-1]
	root := a.find(nodes[0])
	if root != nodes[chainLen-1] {
		t.Errorf("expected root=%d, got %d", nodes[chainLen-1], root)
	}

	// after path compression, n0's parent must be much closer to the root
	// (path halving: n0 should point to its grandparent after one find call)
	if a.nodes[nodes[0]].parent == nodes[1] {
		t.Error("path compression did not update n0's parent")
	}
}

// TestSteensgaard_Union_ByRank verifies that union-by-rank keeps trees shallow.
func TestSteensgaard_Union_ByRank(t *testing.T) {
	a := NewSteensgaardAnalyzer()

	// create two nodes with rank 0
	n0 := a.newNode("n0")
	n1 := a.newNode("n1")

	root := a.union(n0, n1)

	// after union of equal-rank nodes, one becomes root with rank 1
	rootNode := a.nodes[root]
	if rootNode.rank != 1 {
		t.Errorf("expected root rank=1 after union of equal-rank nodes, got %d", rootNode.rank)
	}

	// the non-root must point to the root
	other := n0
	if root == n0 {
		other = n1
	}
	if a.find(other) != root {
		t.Errorf("non-root node does not point to root after union")
	}
}

// ============================================================================
// address-of constraint tests
// ============================================================================

// TestSteensgaard_AddressOf_Basic verifies: x = &y → x points to y.
func TestSteensgaard_AddressOf_Basic(t *testing.T) {
	a := NewSteensgaardAnalyzer()
	a.processAddressOf("x", "y")

	pts := a.PointsTo("x")
	if !containsStr(pts, "y") {
		t.Errorf("expected x to point to y, got %v", pts)
	}
}

// TestSteensgaard_AddressOf_Merge verifies that two address-of constraints on
// the same pointer variable cause the targets to be merged:
// x = &a; x = &b → a and b are in the same equivalence class.
func TestSteensgaard_AddressOf_Merge(t *testing.T) {
	a := NewSteensgaardAnalyzer()
	a.processAddressOf("x", "a")
	a.processAddressOf("x", "b")

	// both a and b must be in x's points-to set
	pts := a.PointsTo("x")
	if !containsStr(pts, "a") {
		t.Errorf("expected x to point to a, got %v", pts)
	}
	if !containsStr(pts, "b") {
		t.Errorf("expected x to point to b, got %v", pts)
	}

	// a and b must be in the same equivalence class (may-alias)
	if !a.MayAlias("a", "b") {
		t.Error("expected a and b to be aliases after double address-of on x")
	}
}

// ============================================================================
// copy constraint tests
// ============================================================================

// TestSteensgaard_Copy_PropagatesTarget verifies: x = &a; y = x → y points to a.
func TestSteensgaard_Copy_PropagatesTarget(t *testing.T) {
	a := NewSteensgaardAnalyzer()
	a.processAddressOf("x", "a")
	a.processCopy("y", "x")

	pts := a.PointsTo("y")
	if !containsStr(pts, "a") {
		t.Errorf("expected y to point to a after copy from x, got %v", pts)
	}
}

// TestSteensgaard_Copy_BothHaveTargets verifies that when both sides of a copy
// already have targets, those targets are merged:
// x = &a; y = &b; y = x → a and b are merged.
func TestSteensgaard_Copy_BothHaveTargets(t *testing.T) {
	a := NewSteensgaardAnalyzer()
	a.processAddressOf("x", "a")
	a.processAddressOf("y", "b")
	a.processCopy("y", "x")

	// after copy, y's points-to set must contain both a and b
	pts := a.PointsTo("y")
	if !containsStr(pts, "a") || !containsStr(pts, "b") {
		t.Errorf("expected y to point to {a, b}, got %v", pts)
	}
}

// ============================================================================
// load constraint tests
// ============================================================================

// TestSteensgaard_Load_Basic verifies: x = &a; a = &b; y = *x → y points to b.
func TestSteensgaard_Load_Basic(t *testing.T) {
	a := NewSteensgaardAnalyzer()
	// x → a → b
	a.processAddressOf("x", "a")
	a.processAddressOf("a", "b")
	// y = *x: y should point to what a points to, i.e., b
	a.processLoad("y", "x")

	pts := a.PointsTo("y")
	if !containsStr(pts, "b") {
		t.Errorf("expected y to point to b after load through x, got %v", pts)
	}
}

// TestSteensgaard_Load_UnknownPointer verifies that loading through an
// uninitialized pointer creates fresh heap nodes (no panic, no nil dereference).
func TestSteensgaard_Load_UnknownPointer(t *testing.T) {
	a := NewSteensgaardAnalyzer()
	// y = *x where x has no known target yet
	a.processLoad("y", "x")

	// x must now point to some heap node
	ptsX := a.PointsTo("x")
	if len(ptsX) == 0 {
		t.Error("expected x to point to a fresh heap node after load, got empty set")
	}

	// y must also point to some node
	ptsY := a.PointsTo("y")
	if len(ptsY) == 0 {
		t.Error("expected y to point to a fresh heap node after load, got empty set")
	}
}

// ============================================================================
// store constraint tests
// ============================================================================

// TestSteensgaard_Store_Basic verifies: x = &a; *x = b → a and b are merged.
func TestSteensgaard_Store_Basic(t *testing.T) {
	a := NewSteensgaardAnalyzer()
	a.processAddressOf("x", "a")
	a.processStore("x", "b")

	// after *x = b, a (x's target) must be unified with b
	if !a.MayAlias("a", "b") {
		t.Error("expected a and b to be aliases after store through x")
	}
}

// TestSteensgaard_Store_UnknownPointer verifies that storing through an
// uninitialized pointer creates a fresh heap node (no panic).
func TestSteensgaard_Store_UnknownPointer(t *testing.T) {
	a := NewSteensgaardAnalyzer()
	// *x = y where x has no known target
	a.processStore("x", "y")

	// x must now point to some heap node
	ptsX := a.PointsTo("x")
	if len(ptsX) == 0 {
		t.Error("expected x to point to a fresh heap node after store, got empty set")
	}
}

// ============================================================================
// may-alias tests
// ============================================================================

// TestSteensgaard_MayAlias_DirectAlias verifies that two variables in the same
// equivalence class are reported as may-aliases.
func TestSteensgaard_MayAlias_DirectAlias(t *testing.T) {
	a := NewSteensgaardAnalyzer()
	a.processCopy("x", "y")

	if !a.MayAlias("x", "y") {
		t.Error("expected x and y to be direct aliases after copy")
	}
}

// TestSteensgaard_MayAlias_IndirectAlias verifies that two variables pointing
// to the same abstract location are reported as may-aliases.
func TestSteensgaard_MayAlias_IndirectAlias(t *testing.T) {
	a := NewSteensgaardAnalyzer()
	a.processAddressOf("p", "obj")
	a.processAddressOf("q", "obj")

	if !a.MayAlias("p", "q") {
		t.Error("expected p and q to be indirect aliases (both point to obj)")
	}
}

// TestSteensgaard_MayAlias_NoAlias verifies that unrelated variables are not
// reported as aliases.
func TestSteensgaard_MayAlias_NoAlias(t *testing.T) {
	a := NewSteensgaardAnalyzer()
	a.processAddressOf("p", "a")
	a.processAddressOf("q", "b")

	if a.MayAlias("p", "q") {
		t.Error("expected p and q to NOT be aliases (point to different objects)")
	}
}

// TestSteensgaard_MayAlias_UnknownVariable verifies that querying an unknown
// variable returns false (no panic).
func TestSteensgaard_MayAlias_UnknownVariable(t *testing.T) {
	a := NewSteensgaardAnalyzer()
	if a.MayAlias("unknown_x", "unknown_y") {
		t.Error("expected false for unknown variables")
	}
}

// ============================================================================
// IR extraction tests
// ============================================================================

// TestExtractPointerConstraints_Load verifies that a Load instruction produces
// a PtrConstraintLoad constraint.
func TestExtractPointerConstraints_Load(t *testing.T) {
	ptrVar := varPtr("ptr", ir.IntType{Width: ir.Size8, Signed: false})
	destVar := varInt("dest")

	fn := buildFn("test_load", []ir.IRInstruction{
		ir.Load{
			Dest:    destVar,
			Address: ir.VariableExpr{Var: ptrVar},
			Size:    ir.Size8,
		},
	})

	cs := ExtractPointerConstraints(fn)
	if len(cs) == 0 {
		t.Fatal("expected at least one constraint from Load instruction")
	}

	found := false
	for _, c := range cs {
		if c.Kind == PtrConstraintLoad && c.LHS == "dest" && c.RHS == "ptr" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PtrConstraintLoad{dest, ptr}, got %v", cs)
	}
}

// TestExtractPointerConstraints_Store verifies that a Store instruction produces
// a PtrConstraintStore constraint.
func TestExtractPointerConstraints_Store(t *testing.T) {
	ptrVar := varPtr("ptr", ir.IntType{Width: ir.Size8, Signed: false})
	valVar := varInt("val")

	fn := buildFn("test_store", []ir.IRInstruction{
		ir.Store{
			Address: ir.VariableExpr{Var: ptrVar},
			Value:   ir.VariableExpr{Var: valVar},
			Size:    ir.Size8,
		},
	})

	cs := ExtractPointerConstraints(fn)
	if len(cs) == 0 {
		t.Fatal("expected at least one constraint from Store instruction")
	}

	found := false
	for _, c := range cs {
		if c.Kind == PtrConstraintStore && c.LHS == "ptr" && c.RHS == "val" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PtrConstraintStore{ptr, val}, got %v", cs)
	}
}

// TestExtractPointerConstraints_Copy verifies that an Assign with a VariableExpr
// source produces a PtrConstraintCopy constraint.
func TestExtractPointerConstraints_Copy(t *testing.T) {
	src := varPtr("src", ir.IntType{Width: ir.Size8, Signed: false})
	dst := varPtr("dst", ir.IntType{Width: ir.Size8, Signed: false})

	fn := buildFn("test_copy", []ir.IRInstruction{
		ir.Assign{
			Dest:   dst,
			Source: ir.VariableExpr{Var: src},
		},
	})

	cs := ExtractPointerConstraints(fn)
	if len(cs) == 0 {
		t.Fatal("expected at least one constraint from Assign instruction")
	}

	found := false
	for _, c := range cs {
		if c.Kind == PtrConstraintCopy && c.LHS == "dst" && c.RHS == "src" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PtrConstraintCopy{dst, src}, got %v", cs)
	}
}

// TestExtractPointerConstraints_Phi verifies that a Phi node produces copy
// constraints from each source to the destination.
func TestExtractPointerConstraints_Phi(t *testing.T) {
	dest := varPtr("phi_dest", ir.IntType{Width: ir.Size8, Signed: false})
	src0 := varPtr("phi_src0", ir.IntType{Width: ir.Size8, Signed: false})
	src1 := varPtr("phi_src1", ir.IntType{Width: ir.Size8, Signed: false})

	fn := buildFn("test_phi", []ir.IRInstruction{
		ir.Phi{
			Dest: dest,
			Sources: []ir.PhiSource{
				{Block: 0, Var: src0},
				{Block: 1, Var: src1},
			},
		},
	})

	cs := ExtractPointerConstraints(fn)
	if len(cs) < 2 {
		t.Fatalf("expected 2 constraints from Phi, got %d: %v", len(cs), cs)
	}

	foundSrc0, foundSrc1 := false, false
	for _, c := range cs {
		if c.Kind == PtrConstraintCopy && c.LHS == "phi_dest" && c.RHS == "phi_src0" {
			foundSrc0 = true
		}
		if c.Kind == PtrConstraintCopy && c.LHS == "phi_dest" && c.RHS == "phi_src1" {
			foundSrc1 = true
		}
	}
	if !foundSrc0 {
		t.Error("expected copy constraint from phi_src0 to phi_dest")
	}
	if !foundSrc1 {
		t.Error("expected copy constraint from phi_src1 to phi_dest")
	}
}

// ============================================================================
// full IR analysis tests
// ============================================================================

// TestSteensgaard_Analyze_SimplePointerChain verifies end-to-end analysis of:
//
//	p = &x
//	q = p
//	r = *q
//
// expected: p and q point to x; r points to whatever x points to.
func TestSteensgaard_Analyze_SimplePointerChain(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: false}
	ptrI64 := ir.PointerType{Pointee: i64}

	x := ir.Variable{Name: "x", Type: i64}
	p := ir.Variable{Name: "p", Type: ptrI64}
	q := ir.Variable{Name: "q", Type: ptrI64}
	r := ir.Variable{Name: "r", Type: i64}

	fn := buildFn("chain", []ir.IRInstruction{
		// p = &x (modelled as cast to pointer)
		ir.Assign{
			Dest:   p,
			Source: ir.Cast{Expr: ir.VariableExpr{Var: x}, TargetType: ptrI64},
		},
		// q = p
		ir.Assign{
			Dest:   q,
			Source: ir.VariableExpr{Var: p},
		},
		// r = *q
		ir.Load{
			Dest:    r,
			Address: ir.VariableExpr{Var: q},
			Size:    ir.Size8,
		},
	})

	a := NewSteensgaardAnalyzer()
	pts := a.Analyze(fn)

	// p must point to x
	pPts := pts["p"]
	if !containsStr(pPts, "x") {
		t.Errorf("expected p to point to x, got %v", pPts)
	}

	// q must point to x (via copy from p)
	qPts := pts["q"]
	if !containsStr(qPts, "x") {
		t.Errorf("expected q to point to x (via copy from p), got %v", qPts)
	}
}

// TestSteensgaard_Analyze_StoreAndLoad verifies:
//
//	p = &a
//	*p = b
//	c = *p
//
// expected: a and b are merged; c points to the same set as a/b.
func TestSteensgaard_Analyze_StoreAndLoad(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: false}
	ptrI64 := ir.PointerType{Pointee: i64}

	a := ir.Variable{Name: "a", Type: i64}
	b := ir.Variable{Name: "b", Type: i64}
	c := ir.Variable{Name: "c", Type: i64}
	p := ir.Variable{Name: "p", Type: ptrI64}

	fn := buildFn("store_load", []ir.IRInstruction{
		// p = &a
		ir.Assign{
			Dest:   p,
			Source: ir.Cast{Expr: ir.VariableExpr{Var: a}, TargetType: ptrI64},
		},
		// *p = b
		ir.Store{
			Address: ir.VariableExpr{Var: p},
			Value:   ir.VariableExpr{Var: b},
			Size:    ir.Size8,
		},
		// c = *p
		ir.Load{
			Dest:    c,
			Address: ir.VariableExpr{Var: p},
			Size:    ir.Size8,
		},
	})

	analyzer := NewSteensgaardAnalyzer()
	analyzer.Analyze(fn)

	// a and b must be merged (store *p = b unifies p's target with b)
	if !analyzer.MayAlias("a", "b") {
		t.Error("expected a and b to be aliases after *p = b where p = &a")
	}
}

// TestSteensgaard_Analyze_PhiMerge verifies that phi nodes correctly merge
// pointer targets from different control flow paths.
func TestSteensgaard_Analyze_PhiMerge(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: false}
	ptrI64 := ir.PointerType{Pointee: i64}

	a := ir.Variable{Name: "a", Type: i64}
	b := ir.Variable{Name: "b", Type: i64}
	p0 := ir.Variable{Name: "p0", Type: ptrI64}
	p1 := ir.Variable{Name: "p1", Type: ptrI64}
	phi := ir.Variable{Name: "phi_p", Type: ptrI64}

	fn := &ir.Function{
		Name: "phi_merge",
		Signature: ir.FunctionType{
			ReturnType: ir.VoidType{},
			Parameters: []ir.Type{},
		},
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					// p0 = &a
					ir.Assign{
						Dest:   p0,
						Source: ir.Cast{Expr: ir.VariableExpr{Var: a}, TargetType: ptrI64},
					},
					// p1 = &b
					ir.Assign{
						Dest:   p1,
						Source: ir.Cast{Expr: ir.VariableExpr{Var: b}, TargetType: ptrI64},
					},
					// phi_p = phi(p0, p1)
					ir.Phi{
						Dest: phi,
						Sources: []ir.PhiSource{
							{Block: 0, Var: p0},
							{Block: 1, Var: p1},
						},
					},
				},
			},
		},
		EntryBlock: 0,
	}

	analyzer := NewSteensgaardAnalyzer()
	pts := analyzer.Analyze(fn)

	// phi_p must point to both a and b (merged via phi)
	phiPts := pts["phi_p"]
	if !containsStr(phiPts, "a") {
		t.Errorf("expected phi_p to point to a, got %v", phiPts)
	}
	if !containsStr(phiPts, "b") {
		t.Errorf("expected phi_p to point to b, got %v", phiPts)
	}
}

// TestSteensgaard_Analyze_EmptyFunction verifies that an empty function
// produces an empty points-to set without panicking.
func TestSteensgaard_Analyze_EmptyFunction(t *testing.T) {
	fn := buildFn("empty", nil)
	a := NewSteensgaardAnalyzer()
	pts := a.Analyze(fn)
	if len(pts) != 0 {
		t.Errorf("expected empty points-to set for empty function, got %v", pts)
	}
}

// TestSteensgaard_AnalyzeProgram_Interprocedural verifies that the interprocedural
// analysis correctly merges pointer information across function boundaries.
func TestSteensgaard_AnalyzeProgram_Interprocedural(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: false}
	ptrI64 := ir.PointerType{Pointee: i64}

	// function 1: p = &a
	a := ir.Variable{Name: "a", Type: i64}
	p := ir.Variable{Name: "p", Type: ptrI64}
	fn1 := buildFn("fn1", []ir.IRInstruction{
		ir.Assign{
			Dest:   p,
			Source: ir.Cast{Expr: ir.VariableExpr{Var: a}, TargetType: ptrI64},
		},
	})

	// function 2: q = p (copy from fn1's p)
	q := ir.Variable{Name: "q", Type: ptrI64}
	fn2 := buildFn("fn2", []ir.IRInstruction{
		ir.Assign{
			Dest:   q,
			Source: ir.VariableExpr{Var: p},
		},
	})

	analyzer := NewSteensgaardAnalyzer()
	pts := analyzer.AnalyzeProgram([]*ir.Function{fn1, fn2})

	// q must point to a (via copy from p which points to a)
	qPts := pts["q"]
	if !containsStr(qPts, "a") {
		t.Errorf("expected q to point to a in interprocedural analysis, got %v", qPts)
	}
}

// TestSteensgaard_PointerConstraintKind_String verifies String() for all kinds.
func TestSteensgaard_PointerConstraintKind_String(t *testing.T) {
	cases := []struct {
		kind PointerConstraintKind
		want string
	}{
		{PtrConstraintAddressOf, "addr_of"},
		{PtrConstraintCopy, "copy"},
		{PtrConstraintLoad, "load"},
		{PtrConstraintStore, "store"},
		{PointerConstraintKind(99), "unknown(99)"},
	}
	for _, tc := range cases {
		got := tc.kind.String()
		if got != tc.want {
			t.Errorf("kind %d: expected %q, got %q", tc.kind, tc.want, got)
		}
	}
}

// TestSteensgaard_PointsTo_UnknownVariable verifies that querying an unknown
// variable returns nil without panicking.
func TestSteensgaard_PointsTo_UnknownVariable(t *testing.T) {
	a := NewSteensgaardAnalyzer()
	pts := a.PointsTo("nonexistent")
	if pts != nil {
		t.Errorf("expected nil for unknown variable, got %v", pts)
	}
}

// TestSteensgaard_PointsTo_NonPointer verifies that a non-pointer variable
// returns nil from PointsTo.
func TestSteensgaard_PointsTo_NonPointer(t *testing.T) {
	a := NewSteensgaardAnalyzer()
	// register a node but don't set any points-to target
	a.nodeFor("x")
	pts := a.PointsTo("x")
	if pts != nil {
		t.Errorf("expected nil for non-pointer variable, got %v", pts)
	}
}

// TestSteensgaard_BuildPointsToSet_Deterministic verifies that buildPointsToSet
// produces the same output on repeated calls (determinism requirement).
func TestSteensgaard_BuildPointsToSet_Deterministic(t *testing.T) {
	a := NewSteensgaardAnalyzer()
	a.processAddressOf("p", "a")
	a.processAddressOf("p", "b")
	a.processAddressOf("q", "c")

	pts1 := a.buildPointsToSet()
	pts2 := a.buildPointsToSet()

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

// TestSteensgaard_SortStrings verifies the sortStrings utility.
func TestSteensgaard_SortStrings(t *testing.T) {
	ss := []string{"c", "a", "b", "aa"}
	sortStrings(ss)
	expected := []string{"a", "aa", "b", "c"}
	for i, s := range ss {
		if s != expected[i] {
			t.Errorf("sortStrings[%d]: expected %q, got %q", i, expected[i], s)
		}
	}
}

// ============================================================================
// extractFromCall tests
// ============================================================================

func TestExtractPointerConstraints_Call_WithDest(t *testing.T) {
	ptrI64 := ir.PointerType{Pointee: ir.IntType{Width: ir.Size8, Signed: false}}
	dest := varPtr("result", ir.IntType{Width: ir.Size8, Signed: false})
	arg0 := varPtr("arg0", ir.IntType{Width: ir.Size8, Signed: false})
	arg1 := varInt("arg1")
	target := ir.Variable{Name: "callee", Type: ir.FunctionType{
		ReturnType: ptrI64,
		Parameters: []ir.Type{ptrI64, ir.IntType{Width: ir.Size8, Signed: false}},
	}}

	fn := buildFn("test_call_dest", []ir.IRInstruction{
		ir.Call{
			Dest:   &dest,
			Target: ir.VariableExpr{Var: target},
			Args:   []ir.Variable{arg0, arg1},
		},
	})

	cs := ExtractPointerConstraints(fn)

	foundRetCopy := false
	foundParam0 := false
	foundParam1 := false
	for _, c := range cs {
		if c.Kind == PtrConstraintCopy && c.LHS == "result" && c.RHS == "$ret_callee" {
			foundRetCopy = true
		}
		if c.Kind == PtrConstraintCopy && c.LHS == "$param_callee_0" && c.RHS == "arg0" {
			foundParam0 = true
		}
		if c.Kind == PtrConstraintCopy && c.LHS == "$param_callee_1" && c.RHS == "arg1" {
			foundParam1 = true
		}
	}
	if !foundRetCopy {
		t.Errorf("expected copy constraint from $ret_callee to result, got %v", cs)
	}
	if !foundParam0 {
		t.Errorf("expected copy constraint from arg0 to $param_callee_0, got %v", cs)
	}
	if !foundParam1 {
		t.Errorf("expected copy constraint from arg1 to $param_callee_1, got %v", cs)
	}
}

func TestExtractPointerConstraints_Call_VoidReturn(t *testing.T) {
	target := ir.Variable{Name: "sink", Type: ir.FunctionType{
		ReturnType: ir.VoidType{},
		Parameters: []ir.Type{ir.IntType{Width: ir.Size8, Signed: false}},
	}}
	arg := varInt("val")

	fn := buildFn("test_call_void", []ir.IRInstruction{
		ir.Call{
			Dest:   nil,
			Target: ir.VariableExpr{Var: target},
			Args:   []ir.Variable{arg},
		},
	})

	cs := ExtractPointerConstraints(fn)

	for _, c := range cs {
		if c.LHS == "result" || c.RHS == "$ret_sink" {
			t.Errorf("void call should not produce return copy constraint, got %v", c)
		}
	}

	foundParam := false
	for _, c := range cs {
		if c.Kind == PtrConstraintCopy && c.LHS == "$param_sink_0" && c.RHS == "val" {
			foundParam = true
		}
	}
	if !foundParam {
		t.Errorf("expected parameter copy constraint for void call, got %v", cs)
	}
}

// ============================================================================
// extractFromAssign BinaryOp tests
// ============================================================================

func TestExtractPointerConstraints_Assign_BinaryOp(t *testing.T) {
	ptrI64 := ir.PointerType{Pointee: ir.IntType{Width: ir.Size8, Signed: false}}
	base := ir.Variable{Name: "base", Type: ptrI64}
	offset := ir.Variable{Name: "offset", Type: ir.IntType{Width: ir.Size8, Signed: false}}
	dest := ir.Variable{Name: "adjusted", Type: ptrI64}

	fn := buildFn("test_binop", []ir.IRInstruction{
		ir.Assign{
			Dest: dest,
			Source: ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  ir.VariableExpr{Var: base},
				Right: ir.VariableExpr{Var: offset},
			},
		},
	})

	cs := ExtractPointerConstraints(fn)

	found := false
	for _, c := range cs {
		if c.Kind == PtrConstraintCopy && c.LHS == "adjusted" && c.RHS == "base" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected copy constraint from base to adjusted for pointer arithmetic, got %v", cs)
	}
}

// ============================================================================
// exprRootVar Cast path test
// ============================================================================

func TestExtractPointerConstraints_Assign_NonPointerCast(t *testing.T) {
	src := varInt("src_val")
	dest := varInt("dest_val")

	fn := buildFn("test_nonptr_cast", []ir.IRInstruction{
		ir.Assign{
			Dest: dest,
			Source: ir.Cast{
				Expr:       ir.VariableExpr{Var: src},
				TargetType: ir.IntType{Width: ir.Size4, Signed: true},
			},
		},
	})

	cs := ExtractPointerConstraints(fn)

	found := false
	for _, c := range cs {
		if c.Kind == PtrConstraintCopy && c.LHS == "dest_val" && c.RHS == "src_val" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected copy constraint for non-pointer cast, got %v", cs)
	}
}

// ============================================================================
// exprRootVar nested Cast in BinaryOp
// ============================================================================

func TestExprRootVar_NestedCast(t *testing.T) {
	inner := ir.Variable{Name: "inner", Type: ir.IntType{Width: ir.Size8, Signed: false}}
	expr := ir.Cast{
		Expr:       ir.VariableExpr{Var: inner},
		TargetType: ir.IntType{Width: ir.Size4, Signed: true},
	}

	got := exprRootVar(expr)
	if got != "inner" {
		t.Errorf("expected exprRootVar to extract 'inner' from Cast, got %q", got)
	}
}

func TestExprRootVar_Nil(t *testing.T) {
	got := exprRootVar(nil)
	if got != "" {
		t.Errorf("expected empty string for nil expression, got %q", got)
	}
}

func TestExprRootVar_Constant(t *testing.T) {
	expr := ir.ConstantExpr{Value: ir.IntConstant{Value: 42}}
	got := exprRootVar(expr)
	if got != "" {
		t.Errorf("expected empty string for constant expression, got %q", got)
	}
}

// ============================================================================
// union edge case: higher rank left absorbs lower rank right
// ============================================================================

func TestSteensgaard_Union_HigherRankLeft(t *testing.T) {
	a := NewSteensgaardAnalyzer()

	n0 := a.newNode("n0")
	n1 := a.newNode("n1")
	n2 := a.newNode("n2")

	a.union(n0, n1)

	root := a.union(n0, n2)
	rootNode := a.nodes[a.find(root)]
	if rootNode.rank < 1 {
		t.Errorf("expected root rank >= 1, got %d", rootNode.rank)
	}

	if a.find(n2) != a.find(n0) {
		t.Error("n2 should be in the same equivalence class as n0 after union")
	}
}

// ============================================================================
// processLoad edge case: both x and yTarget have existing targets
// ============================================================================

func TestSteensgaard_Load_BothHaveTargets(t *testing.T) {
	a := NewSteensgaardAnalyzer()

	a.processAddressOf("x", "x_target")
	a.processAddressOf("y", "y_deref")
	a.processAddressOf("y_deref", "y_deep")

	a.processLoad("x", "y")

	ptsX := a.PointsTo("x")
	if len(ptsX) == 0 {
		t.Error("expected x to have a points-to set after load with both targets existing")
	}
}

// ============================================================================
// snapshotsEqual edge case: different lengths
// ============================================================================

func TestSnapshotsEqual_DifferentLengths(t *testing.T) {
	a := map[string][2]int{"x": {0, 1}}
	b := map[string][2]int{"x": {0, 1}, "y": {2, 3}}

	if snapshotsEqual(a, b) {
		t.Error("expected false for snapshots with different lengths")
	}
}

// ============================================================================
// Assign with constant source (no variable to extract)
// ============================================================================

func TestExtractPointerConstraints_Assign_ConstantSource(t *testing.T) {
	dest := varInt("dest")

	fn := buildFn("test_const_assign", []ir.IRInstruction{
		ir.Assign{
			Dest:   dest,
			Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 0}},
		},
	})

	cs := ExtractPointerConstraints(fn)
	if len(cs) != 0 {
		t.Errorf("expected no constraints for constant assignment, got %v", cs)
	}
}

// ============================================================================
// Branch and Jump instructions produce no constraints
// ============================================================================

func TestExtractPointerConstraints_BranchAndJump(t *testing.T) {
	cond := varInt("cond")

	fn := buildFn("test_branch_jump", []ir.IRInstruction{
		ir.Branch{
			Condition:   ir.VariableExpr{Var: cond},
			TrueTarget:  1,
			FalseTarget: 2,
		},
		ir.Jump{Target: 3},
		ir.Return{},
	})

	cs := ExtractPointerConstraints(fn)
	if len(cs) != 0 {
		t.Errorf("expected no constraints for branch/jump/return, got %v", cs)
	}
}

// ============================================================================
// Cast with constant inner expression (no variable)
// ============================================================================

func TestExtractPointerConstraints_Assign_CastConstant(t *testing.T) {
	ptrI64 := ir.PointerType{Pointee: ir.IntType{Width: ir.Size8, Signed: false}}
	dest := varPtr("dest", ir.IntType{Width: ir.Size8, Signed: false})

	fn := buildFn("test_cast_const", []ir.IRInstruction{
		ir.Assign{
			Dest: dest,
			Source: ir.Cast{
				Expr:       ir.ConstantExpr{Value: ir.IntConstant{Value: 0x1000}},
				TargetType: ptrI64,
			},
		},
	})

	cs := ExtractPointerConstraints(fn)
	if len(cs) != 0 {
		t.Errorf("expected no constraints for cast of constant to pointer, got %v", cs)
	}
}

// ============================================================================
// BinaryOp with constant left operand (no base pointer)
// ============================================================================

func TestExtractPointerConstraints_Assign_BinaryOp_ConstantBase(t *testing.T) {
	dest := varInt("dest")

	fn := buildFn("test_binop_const", []ir.IRInstruction{
		ir.Assign{
			Dest: dest,
			Source: ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  ir.ConstantExpr{Value: ir.IntConstant{Value: 10}},
				Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 20}},
			},
		},
	})

	cs := ExtractPointerConstraints(fn)
	if len(cs) != 0 {
		t.Errorf("expected no constraints for binary op with constant operands, got %v", cs)
	}
}

// ============================================================================
// helpers
// ============================================================================

// containsStr returns true if ss contains s.
func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
