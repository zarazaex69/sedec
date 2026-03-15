package analysis

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// test helpers for alias analysis
// ============================================================================

// ptrType creates a pointer type pointing to the given type.
func ptrType(pointee ir.Type) ir.Type {
	return ir.PointerType{Pointee: pointee}
}

// ptrVar creates a pointer-typed SSA variable.
func ptrVar(name string, version int, pointee ir.Type) ir.Variable {
	return ir.Variable{Name: name, Type: ptrType(pointee), Version: version}
}

// ptrVarExpr creates a variable expression for a pointer variable.
func ptrVarExpr(name string, version int, pointee ir.Type) ir.Expression {
	return &ir.VariableExpr{Var: ptrVar(name, version, pointee)}
}

// makeSimpleCFG creates a minimal single-block CFG for testing.
func makeSimpleCFG() *cfg.CFG {
	return &cfg.CFG{
		Blocks: map[cfg.BlockID]*cfg.BasicBlock{
			0: {
				ID:           0,
				Predecessors: []cfg.BlockID{},
				Successors:   []cfg.BlockID{},
			},
		},
		Entry: 0,
		Exits: []cfg.BlockID{0},
	}
}

// makeSimpleDomTree creates a trivial dominator tree for a single-block CFG.
func makeSimpleDomTree(cfgGraph *cfg.CFG) *cfg.DominatorTree {
	dt := cfg.NewDominatorTree(cfgGraph)
	dt.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	dt.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}
	return dt
}

// makeTwoBlockCFG creates a two-block CFG: bb0 → bb1.
func makeTwoBlockCFG() *cfg.CFG {
	return &cfg.CFG{
		Blocks: map[cfg.BlockID]*cfg.BasicBlock{
			0: {ID: 0, Predecessors: []cfg.BlockID{}, Successors: []cfg.BlockID{1}},
			1: {ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{}},
		},
		Entry: 0,
		Exits: []cfg.BlockID{1},
	}
}

// makeTwoBlockDomTree creates a dominator tree for a two-block CFG.
func makeTwoBlockDomTree(cfgGraph *cfg.CFG) *cfg.DominatorTree {
	dt := cfg.NewDominatorTree(cfgGraph)
	dt.Idom = map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0}
	dt.Children = map[cfg.BlockID][]cfg.BlockID{0: {1}, 1: {}}
	return dt
}

// ============================================================================
// AliasKind tests
// ============================================================================

func TestAliasKind_String(t *testing.T) {
	tests := []struct {
		kind AliasKind
		want string
	}{
		{AliasNo, "no-alias"},
		{AliasMay, "may-alias"},
		{AliasMust, "must-alias"},
	}
	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.want {
			t.Errorf("AliasKind(%d).String() = %q, want %q", tt.kind, got, tt.want)
		}
	}
}

// ============================================================================
// AliasSet tests
// ============================================================================

func TestAliasSet_SetGet(t *testing.T) {
	as := NewAliasSet()
	a := ptrVar("p", 1, intType())
	b := ptrVar("q", 1, intType())

	// default is may-alias
	if got := as.Get(a, b); got != AliasMay {
		t.Errorf("default alias kind = %v, want AliasMay", got)
	}

	// set no-alias
	as.Set(a, b, AliasNo)
	if got := as.Get(a, b); got != AliasNo {
		t.Errorf("after Set(AliasNo), Get = %v, want AliasNo", got)
	}

	// symmetric: get(b, a) should also return AliasNo
	if got := as.Get(b, a); got != AliasNo {
		t.Errorf("alias set must be symmetric: Get(b,a) = %v, want AliasNo", got)
	}
}

func TestAliasSet_MustAlias(t *testing.T) {
	as := NewAliasSet()
	a := ptrVar("p", 1, intType())
	b := ptrVar("q", 1, intType())

	as.Set(a, b, AliasMust)

	if !as.MustAlias(a, b) {
		t.Error("MustAlias should return true after Set(AliasMust)")
	}
	if !as.MayAlias(a, b) {
		t.Error("MayAlias should return true when MustAlias")
	}
	if as.NoAlias(a, b) {
		t.Error("NoAlias should return false when MustAlias")
	}
}

func TestAliasSet_NoAlias(t *testing.T) {
	as := NewAliasSet()
	a := ptrVar("p", 1, intType())
	b := ptrVar("q", 1, intType())

	as.Set(a, b, AliasNo)

	if !as.NoAlias(a, b) {
		t.Error("NoAlias should return true after Set(AliasNo)")
	}
	if as.MayAlias(a, b) {
		t.Error("MayAlias should return false when NoAlias")
	}
	if as.MustAlias(a, b) {
		t.Error("MustAlias should return false when NoAlias")
	}
}

// ============================================================================
// type compatibility tests
// ============================================================================

func TestTypesCompatible_SameType(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	if !typesCompatible(i32, i32) {
		t.Error("same type must be compatible")
	}
}

func TestTypesCompatible_DifferentIntWidths(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	if typesCompatible(i32, i64) {
		t.Error("int32 and int64 must be incompatible for strict aliasing")
	}
}

func TestTypesCompatible_IntVsFloat(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	f32 := ir.FloatType{Width: ir.Size4}
	if typesCompatible(i32, f32) {
		t.Error("int and float must be incompatible")
	}
}

func TestTypesCompatible_VoidPointer(t *testing.T) {
	voidPtr := ir.PointerType{Pointee: ir.VoidType{}}
	i32Ptr := ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: true}}
	// void pointer is compatible with anything
	if !typesCompatible(voidPtr, i32Ptr) {
		t.Error("void pointer must be compatible with any pointer")
	}
}

func TestTypesCompatible_StructsByName(t *testing.T) {
	structA := ir.StructType{Name: "Foo"}
	structB := ir.StructType{Name: "Bar"}
	if typesCompatible(structA, structB) {
		t.Error("structs with different names must be incompatible")
	}
	if !typesCompatible(structA, structA) {
		t.Error("same struct must be compatible")
	}
}

// ============================================================================
// AliasAnalyzer tests
// ============================================================================

// TestAliasAnalysis_SameVariable tests that the same SSA variable must-aliases itself.
func TestAliasAnalysis_SameVariable(t *testing.T) {
	// bb0: p_1 = &x; return
	p1 := ptrVar("p", 1, intType())
	x := ir.Variable{Name: "x", Type: intType(), Version: 0}

	fn := &ir.Function{
		Name: "test_same_var",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   p1,
						Source: ptrVarExpr("x", 0, intType()),
					},
					&ir.Return{Value: &x},
				},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	cfgGraph := makeSimpleCFG()
	domTree := makeSimpleDomTree(cfgGraph)

	result, err := PerformAliasAnalysis(fn, cfgGraph, domTree, nil, nil)
	if err != nil {
		t.Fatalf("PerformAliasAnalysis failed: %v", err)
	}

	// same variable must alias itself
	kind := result.GlobalAliases.Get(p1, p1)
	if kind != AliasMust {
		t.Errorf("same variable alias kind = %v, want AliasMust", kind)
	}
}

// TestAliasAnalysis_TypeIncompatible tests that type-incompatible pointers do not alias.
func TestAliasAnalysis_TypeIncompatible(t *testing.T) {
	// p_1: *i32, q_1: *f64 — cannot alias due to type incompatibility
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	f64 := ir.FloatType{Width: ir.Size8}

	p1 := ptrVar("p", 1, i32)
	q1 := ptrVar("q", 1, f64)

	fn := &ir.Function{
		Name: "test_type_incompat",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: p1, Source: ptrVarExpr("x", 0, i32)},
					&ir.Assign{Dest: q1, Source: ptrVarExpr("y", 0, f64)},
					&ir.Return{},
				},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	cfgGraph := makeSimpleCFG()
	domTree := makeSimpleDomTree(cfgGraph)

	result, err := PerformAliasAnalysis(fn, cfgGraph, domTree, nil, nil)
	if err != nil {
		t.Fatalf("PerformAliasAnalysis failed: %v", err)
	}

	// type-incompatible pointers must not alias
	if !result.GlobalAliases.NoAlias(p1, q1) {
		t.Errorf("type-incompatible pointers should be no-alias, got %v",
			result.GlobalAliases.Get(p1, q1))
	}
}

// TestAliasAnalysis_SamePointeeType tests that same-type pointers may alias by default.
func TestAliasAnalysis_SamePointeeType(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	p1 := ptrVar("p", 1, i32)
	q1 := ptrVar("q", 1, i32)

	fn := &ir.Function{
		Name: "test_same_type",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: p1, Source: ptrVarExpr("x", 0, i32)},
					&ir.Assign{Dest: q1, Source: ptrVarExpr("y", 0, i32)},
					&ir.Return{},
				},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	cfgGraph := makeSimpleCFG()
	domTree := makeSimpleDomTree(cfgGraph)

	result, err := PerformAliasAnalysis(fn, cfgGraph, domTree, nil, nil)
	if err != nil {
		t.Fatalf("PerformAliasAnalysis failed: %v", err)
	}

	// same-type pointers may alias (conservative)
	if result.GlobalAliases.NoAlias(p1, q1) {
		t.Error("same-type pointers should not be proven no-alias without points-to info")
	}
}

// TestAliasAnalysis_RegionDisjoint tests that pointers into disjoint regions do not alias.
func TestAliasAnalysis_RegionDisjoint(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	p1 := ptrVar("p", 1, i32) // stack pointer
	q1 := ptrVar("q", 1, i32) // global pointer

	fn := &ir.Function{
		Name: "test_region_disjoint",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: p1, Source: ptrVarExpr("x", 0, i32)},
					&ir.Assign{Dest: q1, Source: ptrVarExpr("y", 0, i32)},
					&ir.Return{},
				},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	cfgGraph := makeSimpleCFG()
	domTree := makeSimpleDomTree(cfgGraph)

	// create VSA result with disjoint regions for p1 and q1
	stackRegion := MemoryRegion{Kind: RegionStack, ID: 1}
	globalRegion := MemoryRegion{Kind: RegionGlobal, ID: 1}

	vsaResult := &VSAResult{
		ValueSets: map[string]*ValueSet{
			p1.String(): NewValueSetPointer(stackRegion, 0, 0, 0),
			q1.String(): NewValueSetPointer(globalRegion, 0, 0x1000, 0x1000),
		},
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	result, err := PerformAliasAnalysis(fn, cfgGraph, domTree, vsaResult, nil)
	if err != nil {
		t.Fatalf("PerformAliasAnalysis failed: %v", err)
	}

	// stack and global pointers are in disjoint regions: no-alias
	if !result.GlobalAliases.NoAlias(p1, q1) {
		t.Errorf("stack vs global pointers should be no-alias, got %v",
			result.GlobalAliases.Get(p1, q1))
	}
}

// TestAliasAnalysis_SameRegionOverlap tests that pointers in the same region may alias.
func TestAliasAnalysis_SameRegionOverlap(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	p1 := ptrVar("p", 1, i32)
	q1 := ptrVar("q", 1, i32)

	fn := &ir.Function{
		Name: "test_region_overlap",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: p1, Source: ptrVarExpr("x", 0, i32)},
					&ir.Assign{Dest: q1, Source: ptrVarExpr("y", 0, i32)},
					&ir.Return{},
				},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	cfgGraph := makeSimpleCFG()
	domTree := makeSimpleDomTree(cfgGraph)

	// both pointers in the same stack region with overlapping offsets
	stackRegion := MemoryRegion{Kind: RegionStack, ID: 1}
	vsaResult := &VSAResult{
		ValueSets: map[string]*ValueSet{
			p1.String(): NewValueSetPointer(stackRegion, 1, 0, 8),  // offsets [0, 8]
			q1.String(): NewValueSetPointer(stackRegion, 1, 4, 12), // offsets [4, 12]
		},
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	result, err := PerformAliasAnalysis(fn, cfgGraph, domTree, vsaResult, nil)
	if err != nil {
		t.Fatalf("PerformAliasAnalysis failed: %v", err)
	}

	// overlapping offsets in same region: may-alias
	if result.GlobalAliases.NoAlias(p1, q1) {
		t.Error("overlapping stack pointers should not be proven no-alias")
	}
}

// TestAliasAnalysis_SameRegionDisjointOffsets tests non-overlapping offsets in same region.
func TestAliasAnalysis_SameRegionDisjointOffsets(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	p1 := ptrVar("p", 1, i32)
	q1 := ptrVar("q", 1, i32)

	fn := &ir.Function{
		Name: "test_disjoint_offsets",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: p1, Source: ptrVarExpr("x", 0, i32)},
					&ir.Assign{Dest: q1, Source: ptrVarExpr("y", 0, i32)},
					&ir.Return{},
				},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	cfgGraph := makeSimpleCFG()
	domTree := makeSimpleDomTree(cfgGraph)

	// same stack region but non-overlapping offsets
	stackRegion := MemoryRegion{Kind: RegionStack, ID: 1}
	vsaResult := &VSAResult{
		ValueSets: map[string]*ValueSet{
			p1.String(): NewValueSetPointer(stackRegion, 1, 0, 4),  // offsets [0, 4]
			q1.String(): NewValueSetPointer(stackRegion, 1, 8, 12), // offsets [8, 12]
		},
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	result, err := PerformAliasAnalysis(fn, cfgGraph, domTree, vsaResult, nil)
	if err != nil {
		t.Fatalf("PerformAliasAnalysis failed: %v", err)
	}

	// non-overlapping offsets in same region: no-alias
	if !result.GlobalAliases.NoAlias(p1, q1) {
		t.Errorf("non-overlapping stack offsets should be no-alias, got %v",
			result.GlobalAliases.Get(p1, q1))
	}
}

// TestAliasAnalysis_FlowSensitiveMustAlias tests flow-sensitive must-alias at assignment.
func TestAliasAnalysis_FlowSensitiveMustAlias(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	p1 := ptrVar("p", 1, i32)
	q1 := ptrVar("q", 1, i32)

	// bb0: p_1 = &x; q_1 = p_1; return
	// at the assignment q_1 = p_1, q_1 must-aliases p_1
	fn := &ir.Function{
		Name: "test_flow_must_alias",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: p1, Source: ptrVarExpr("x", 0, i32)},
					&ir.Assign{Dest: q1, Source: &ir.VariableExpr{Var: p1}},
					&ir.Return{},
				},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	cfgGraph := makeSimpleCFG()
	domTree := makeSimpleDomTree(cfgGraph)

	result, err := PerformAliasAnalysis(fn, cfgGraph, domTree, nil, nil)
	if err != nil {
		t.Fatalf("PerformAliasAnalysis failed: %v", err)
	}

	// at the assignment point (bb0, instr 1), q_1 must-alias p_1
	assignPoint := ProgramPoint{BlockID: 0, InstrIdx: 1}
	if !result.MustAliasAt(assignPoint, q1, p1) {
		pointSet, hasPoint := result.PointAliases[assignPoint]
		if !hasPoint {
			t.Errorf("q_1 should must-alias p_1 at assignment point, but no point-specific data recorded")
		} else {
			t.Errorf("q_1 should must-alias p_1 at assignment point, got %v",
				pointSet.Get(q1, p1))
		}
	}
}

// TestAliasAnalysis_MustAliasSets tests that must-alias equivalence classes are built correctly.
func TestAliasAnalysis_MustAliasSets(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	p1 := ptrVar("p", 1, i32)
	q1 := ptrVar("q", 1, i32)
	r1 := ptrVar("r", 1, i32)

	// p_1 = q_1 = r_1 (all must-alias each other)
	fn := &ir.Function{
		Name: "test_must_alias_sets",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: p1, Source: ptrVarExpr("x", 0, i32)},
					&ir.Assign{Dest: q1, Source: &ir.VariableExpr{Var: p1}},
					&ir.Assign{Dest: r1, Source: &ir.VariableExpr{Var: p1}},
					&ir.Return{},
				},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	cfgGraph := makeSimpleCFG()
	domTree := makeSimpleDomTree(cfgGraph)

	// manually set must-alias in global aliases to test class building
	result, err := PerformAliasAnalysis(fn, cfgGraph, domTree, nil, nil)
	if err != nil {
		t.Fatalf("PerformAliasAnalysis failed: %v", err)
	}

	// manually inject must-alias pairs to test class building
	result.GlobalAliases.Set(p1, q1, AliasMust)
	result.GlobalAliases.Set(q1, r1, AliasMust)
	result.MustAliasSets = result.MustAliasSets[:0] // reset
	result.MustAliasSets = (&AliasAnalyzer{function: fn}).buildMustAliasSets(
		[]ir.Variable{p1, q1, r1},
		result.GlobalAliases,
	)

	// should have one equivalence class with all three variables
	if len(result.MustAliasSets) == 0 {
		t.Fatal("expected at least one must-alias equivalence class")
	}

	// find the class containing p1
	found := false
	for _, class := range result.MustAliasSets {
		hasP, hasQ, hasR := false, false, false
		for _, v := range class {
			if v.Name == "p" && v.Version == 1 {
				hasP = true
			}
			if v.Name == "q" && v.Version == 1 {
				hasQ = true
			}
			if v.Name == "r" && v.Version == 1 {
				hasR = true
			}
		}
		if hasP && hasQ && hasR {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected p_1, q_1, r_1 to be in the same must-alias equivalence class")
	}
}

// TestAliasAnalysis_MemoryDependency tests QueryMemoryDependency.
func TestAliasAnalysis_MemoryDependency(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	p1 := ptrVar("p", 1, i32)
	q1 := ptrVar("q", 1, i32)

	fn := &ir.Function{
		Name: "test_mem_dep",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Store{
						Address: &ir.VariableExpr{Var: p1},
						Value:   intConst(42),
						Size:    ir.Size4,
					},
					&ir.Load{
						Dest:    ssaVar("v", 1),
						Address: &ir.VariableExpr{Var: q1},
						Size:    ir.Size4,
					},
				},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	cfgGraph := makeSimpleCFG()
	domTree := makeSimpleDomTree(cfgGraph)

	// case 1: p and q may-alias → may-dependency
	result, err := PerformAliasAnalysis(fn, cfgGraph, domTree, nil, nil)
	if err != nil {
		t.Fatalf("PerformAliasAnalysis failed: %v", err)
	}

	storePoint := ProgramPoint{BlockID: 0, InstrIdx: 0}
	loadPoint := ProgramPoint{BlockID: 0, InstrIdx: 1}
	storeInstr := fn.Blocks[0].Instructions[0]
	loadInstr := fn.Blocks[0].Instructions[1]

	dep := QueryMemoryDependency(storeInstr, loadInstr, storePoint, loadPoint, result)
	if dep == MemDepNone {
		t.Error("may-aliasing pointers should produce at least may-dependency")
	}

	// case 2: p and q are no-alias → no dependency
	result.GlobalAliases.Set(p1, q1, AliasNo)
	dep = QueryMemoryDependency(storeInstr, loadInstr, storePoint, loadPoint, result)
	if dep != MemDepNone {
		t.Errorf("no-alias pointers should produce no-dependency, got %v", dep)
	}
}

// TestAliasAnalysis_ConstantAddresses tests dependency between constant addresses.
func TestAliasAnalysis_ConstantAddresses(t *testing.T) {
	// store [0x1000], 42
	// load v, [0x1000]  → must-dependency (same address)
	// load v, [0x2000]  → no-dependency (different address)

	storeInstr := &ir.Store{
		Address: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x1000, Width: ir.Size8}},
		Value:   intConst(42),
		Size:    ir.Size4,
	}
	loadSameAddr := &ir.Load{
		Dest:    ssaVar("v", 1),
		Address: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x1000, Width: ir.Size8}},
		Size:    ir.Size4,
	}
	loadDiffAddr := &ir.Load{
		Dest:    ssaVar("v", 2),
		Address: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x2000, Width: ir.Size8}},
		Size:    ir.Size4,
	}

	emptyResult := &AliasAnalysisResult{
		GlobalAliases: NewAliasSet(),
		PointAliases:  make(map[ProgramPoint]*AliasSet),
	}

	p0 := ProgramPoint{BlockID: 0, InstrIdx: 0}
	p1 := ProgramPoint{BlockID: 0, InstrIdx: 1}

	// same constant address → must-dependency
	dep := QueryMemoryDependency(storeInstr, loadSameAddr, p0, p1, emptyResult)
	if dep != MemDepMust {
		t.Errorf("same constant address should be must-dependency, got %v", dep)
	}

	// different constant addresses → no-dependency
	dep = QueryMemoryDependency(storeInstr, loadDiffAddr, p0, p1, emptyResult)
	if dep != MemDepNone {
		t.Errorf("different constant addresses should be no-dependency, got %v", dep)
	}
}

// TestAliasAnalysis_EmptyFunction tests that analysis handles empty functions gracefully.
func TestAliasAnalysis_EmptyFunction(t *testing.T) {
	fn := &ir.Function{
		Name:   "empty",
		Blocks: map[ir.BlockID]*ir.BasicBlock{},
	}
	cfgGraph := makeSimpleCFG()
	domTree := makeSimpleDomTree(cfgGraph)

	_, err := PerformAliasAnalysis(fn, cfgGraph, domTree, nil, nil)
	if err == nil {
		t.Error("expected error for empty function, got nil")
	}
}

// TestAliasAnalysis_NilFunction tests that analysis handles nil function gracefully.
func TestAliasAnalysis_NilFunction(t *testing.T) {
	cfgGraph := makeSimpleCFG()
	domTree := makeSimpleDomTree(cfgGraph)

	_, err := PerformAliasAnalysis(nil, cfgGraph, domTree, nil, nil)
	if err == nil {
		t.Error("expected error for nil function, got nil")
	}
}

// TestPointsToSetsIntersect tests the points-to set intersection helper.
func TestPointsToSetsIntersect(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want bool
	}{
		{"empty sets", nil, nil, false},
		{"disjoint", []string{"x", "y"}, []string{"z", "w"}, false},
		{"overlap", []string{"x", "y"}, []string{"y", "z"}, true},
		{"identical", []string{"x"}, []string{"x"}, true},
		{"one empty", []string{"x"}, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pointsToSetsIntersect(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("pointsToSetsIntersect(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
