package analysis

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// ipVar creates a typed integer variable for interprocedural tests.
func ipVar(name string, version int) ir.Variable {
	return ir.Variable{Name: name, Version: version, Type: ir.IntType{Width: ir.Size8, Signed: true}}
}

// ipConst creates a constant integer expression.
func ipConst(v int64) ir.Expression {
	return &ir.ConstantExpr{Value: ir.IntConstant{Value: v, Width: ir.Size8, Signed: true}}
}

// ipBuildFunction builds a single-block function with the given instructions.
func ipBuildFunction(name string, instrs []ir.IRInstruction) *ir.Function {
	const entryID ir.BlockID = 0
	block := &ir.BasicBlock{
		ID:           entryID,
		Instructions: instrs,
		Predecessors: nil,
		Successors:   nil,
	}
	return &ir.Function{
		Name:       name,
		EntryBlock: entryID,
		Blocks:     map[ir.BlockID]*ir.BasicBlock{entryID: block},
	}
}

// ipBuildCFG builds a trivial single-block CFG for a function.
func ipBuildCFG(fn *ir.Function) *cfg.CFG {
	entryID := cfg.BlockID(fn.EntryBlock)
	g := cfg.NewCFG()
	g.Blocks[entryID] = &cfg.BasicBlock{
		ID:           entryID,
		Predecessors: nil,
		Successors:   nil,
	}
	g.Entry = entryID
	return g
}

// ipBuildDomTree builds a trivial dominator tree for a single-block function.
func ipBuildDomTree(fn *ir.Function, cfgGraph *cfg.CFG) *cfg.DominatorTree {
	entryID := cfg.BlockID(fn.EntryBlock)
	dt := cfg.NewDominatorTree(cfgGraph)
	dt.Idom[entryID] = entryID
	dt.Children[entryID] = nil
	return dt
}

// ============================================================================
// FunctionSummaryDB tests
// ============================================================================

func TestFunctionSummaryDB_StoreLoad(t *testing.T) {
	db := NewFunctionSummaryDB()
	s := &FunctionSummary{
		FunctionName:   "foo",
		ReturnValueSet: NewValueSetConstant(42),
		Converged:      true,
	}
	db.Store("foo", s)

	got := db.Load("foo")
	if got == nil {
		t.Fatal("expected summary, got nil")
	}
	if got.FunctionName != "foo" {
		t.Errorf("name: want foo, got %s", got.FunctionName)
	}
	if db.Len() != 1 {
		t.Errorf("len: want 1, got %d", db.Len())
	}
}

func TestFunctionSummaryDB_LoadMissing(t *testing.T) {
	db := NewFunctionSummaryDB()
	if got := db.Load("nonexistent"); got != nil {
		t.Errorf("expected nil for missing key, got %v", got)
	}
}

func TestFunctionSummaryDB_Overwrite(t *testing.T) {
	db := NewFunctionSummaryDB()
	db.Store("f", &FunctionSummary{FunctionName: "f", ReturnValueSet: NewValueSetConstant(1)})
	db.Store("f", &FunctionSummary{FunctionName: "f", ReturnValueSet: NewValueSetConstant(2)})

	got := db.Load("f")
	si := got.ReturnValueSet.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if !si.IsSingleton() || si.Lo != 2 {
		t.Errorf("expected overwritten value {2}, got %s", got.ReturnValueSet)
	}
}

// ============================================================================
// DisambiguateMemoryAccesses tests
// ============================================================================

func TestDisambiguate_DisjointRegions(t *testing.T) {
	stackVS := NewValueSetPointer(MemoryRegion{Kind: RegionStack, ID: 1}, 0, 0, 0)
	heapVS := NewValueSetPointer(MemoryRegion{Kind: RegionHeap, ID: 1}, 0, 0, 0)

	a := &MemoryAccessInfo{Kind: MemAccessLoad, AddressVS: stackVS, Region: MemoryRegion{Kind: RegionStack, ID: 1}, Size: 8}
	b := &MemoryAccessInfo{Kind: MemAccessLoad, AddressVS: heapVS, Region: MemoryRegion{Kind: RegionHeap, ID: 1}, Size: 8}

	result := DisambiguateMemoryAccesses(a, b)
	if result.MayAlias {
		t.Error("stack and heap regions must not alias")
	}
	if result.Confidence < 0.9 {
		t.Errorf("confidence too low: %f", result.Confidence)
	}
}

func TestDisambiguate_SameRegionSingletonMustAlias(t *testing.T) {
	region := MemoryRegion{Kind: RegionStack, ID: 1}
	vs := NewValueSetPointer(region, 0, 100, 100)

	a := &MemoryAccessInfo{Kind: MemAccessLoad, AddressVS: vs, Region: region, Size: 8}
	b := &MemoryAccessInfo{Kind: MemAccessLoad, AddressVS: vs, Region: region, Size: 8}

	result := DisambiguateMemoryAccesses(a, b)
	if !result.MayAlias {
		t.Error("same singleton address must may-alias")
	}
	if !result.MustAlias {
		t.Error("same singleton address must must-alias")
	}
}

func TestDisambiguate_DisjointIntervals(t *testing.T) {
	region := MemoryRegion{Kind: RegionStack, ID: 1}
	vsA := NewValueSetPointer(region, 0, 0, 0)
	vsB := NewValueSetPointer(region, 0, 16, 16)

	a := &MemoryAccessInfo{Kind: MemAccessLoad, AddressVS: vsA, Region: region, Size: 8}
	b := &MemoryAccessInfo{Kind: MemAccessLoad, AddressVS: vsB, Region: region, Size: 8}

	result := DisambiguateMemoryAccesses(a, b)
	if result.MayAlias {
		t.Error("non-overlapping intervals must not alias")
	}
}

func TestDisambiguate_TopAddressMayAlias(t *testing.T) {
	a := &MemoryAccessInfo{Kind: MemAccessLoad, AddressVS: NewValueSetTop(), Size: 8}
	b := &MemoryAccessInfo{Kind: MemAccessLoad, AddressVS: NewValueSetTop(), Size: 8}

	result := DisambiguateMemoryAccesses(a, b)
	if !result.MayAlias {
		t.Error("top addresses must conservatively may-alias")
	}
}

func TestDisambiguate_NilInputs(t *testing.T) {
	result := DisambiguateMemoryAccesses(nil, nil)
	if !result.MayAlias {
		t.Error("nil inputs must conservatively may-alias")
	}
}

func TestDisambiguate_BottomAddressNoAlias(t *testing.T) {
	a := &MemoryAccessInfo{Kind: MemAccessLoad, AddressVS: NewValueSetBottom(), Size: 8}
	b := &MemoryAccessInfo{Kind: MemAccessLoad, AddressVS: NewValueSetBottom(), Size: 8}

	result := DisambiguateMemoryAccesses(a, b)
	if result.MayAlias {
		t.Error("bottom (unreachable) addresses must not alias")
	}
}

// ============================================================================
// InferArrayBounds tests
// ============================================================================

func TestInferArrayBounds_KnownInterval(t *testing.T) {
	indexVar := ipVar("idx", 1)
	vsaResult := &VSAResult{
		ValueSets: map[string]*ValueSet{
			indexVar.String(): NewValueSetInterval(1, 0, 9),
		},
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	bounds, err := InferArrayBounds(vsaResult, indexVar, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bounds.InferredLo != 0 {
		t.Errorf("lo: want 0, got %d", bounds.InferredLo)
	}
	if bounds.InferredHi != 9 {
		t.Errorf("hi: want 9, got %d", bounds.InferredHi)
	}
	if bounds.ElementSize != 4 {
		t.Errorf("element size: want 4, got %d", bounds.ElementSize)
	}
}

func TestInferArrayBounds_TopVariable(t *testing.T) {
	indexVar := ipVar("idx", 1)
	vsaResult := &VSAResult{
		ValueSets:      make(map[string]*ValueSet),
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	bounds, err := InferArrayBounds(vsaResult, indexVar, 8)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bounds.InferredHi != -1 {
		t.Errorf("expected unknown hi (-1), got %d", bounds.InferredHi)
	}
}

func TestInferArrayBounds_NilResult(t *testing.T) {
	_, err := InferArrayBounds(nil, ipVar("x", 0), 4)
	if err == nil {
		t.Error("expected error for nil result")
	}
}

func TestInferArrayBounds_ZeroElementSize(t *testing.T) {
	vsaResult := &VSAResult{
		ValueSets:      make(map[string]*ValueSet),
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}
	_, err := InferArrayBounds(vsaResult, ipVar("x", 0), 0)
	if err == nil {
		t.Error("expected error for zero element size")
	}
}

func TestInferArrayBounds_NegativeElementSize(t *testing.T) {
	vsaResult := &VSAResult{
		ValueSets:      make(map[string]*ValueSet),
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}
	_, err := InferArrayBounds(vsaResult, ipVar("x", 0), -1)
	if err == nil {
		t.Error("expected error for negative element size")
	}
}

func TestInferArrayBounds_StridedInterval(t *testing.T) {
	indexVar := ipVar("idx", 1)
	vsaResult := &VSAResult{
		ValueSets: map[string]*ValueSet{
			indexVar.String(): NewValueSetInterval(4, 0, 12),
		},
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	bounds, err := InferArrayBounds(vsaResult, indexVar, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bounds.InferredLo != 0 || bounds.InferredHi != 12 {
		t.Errorf("bounds: want [0,12], got [%d,%d]", bounds.InferredLo, bounds.InferredHi)
	}
}

// ============================================================================
// BufferOverflowDetector tests
// ============================================================================

func TestBufferOverflow_NoOverflow(t *testing.T) {
	region := MemoryRegion{Kind: RegionStack, ID: 1}
	detector := NewBufferOverflowDetector(map[MemoryRegion]int64{region: 64})
	vs := NewValueSetPointer(region, 1, 0, 55)
	v := ipVar("ptr", 1)

	report := detector.CheckAccess(v, vs, region, 8, ir.BlockID(0))
	if report != nil {
		t.Errorf("expected no overflow, got: %s", report.Message)
	}
}

func TestBufferOverflow_DefiniteOverflow(t *testing.T) {
	region := MemoryRegion{Kind: RegionStack, ID: 1}
	detector := NewBufferOverflowDetector(map[MemoryRegion]int64{region: 64})
	vs := NewValueSetPointer(region, 0, 64, 64)
	v := ipVar("ptr", 1)

	report := detector.CheckAccess(v, vs, region, 8, ir.BlockID(0))
	if report == nil {
		t.Fatal("expected overflow report, got nil")
	}
	if report.Severity != OverflowDefinite {
		t.Errorf("severity: want definite, got %s", report.Severity)
	}
}

func TestBufferOverflow_PossibleOverflow(t *testing.T) {
	region := MemoryRegion{Kind: RegionStack, ID: 1}
	detector := NewBufferOverflowDetector(map[MemoryRegion]int64{region: 64})
	vs := NewValueSetPointer(region, 1, 0, 60)
	v := ipVar("ptr", 1)

	report := detector.CheckAccess(v, vs, region, 8, ir.BlockID(0))
	if report == nil {
		t.Fatal("expected overflow report, got nil")
	}
	if report.Severity != OverflowPossible {
		t.Errorf("severity: want possible, got %s", report.Severity)
	}
}

func TestBufferOverflow_UnknownAllocation(t *testing.T) {
	region := MemoryRegion{Kind: RegionStack, ID: 99}
	detector := NewBufferOverflowDetector(nil)
	vs := NewValueSetPointer(region, 0, 1000, 1000)
	v := ipVar("ptr", 1)

	report := detector.CheckAccess(v, vs, region, 8, ir.BlockID(0))
	if report != nil {
		t.Errorf("expected nil for unknown allocation, got: %s", report.Message)
	}
}

func TestBufferOverflow_TopAddress(t *testing.T) {
	region := MemoryRegion{Kind: RegionStack, ID: 1}
	detector := NewBufferOverflowDetector(map[MemoryRegion]int64{region: 64})
	v := ipVar("ptr", 1)

	report := detector.CheckAccess(v, NewValueSetTop(), region, 8, ir.BlockID(0))
	if report == nil {
		t.Fatal("expected possible overflow for top address")
	}
	if report.Severity != OverflowPossible {
		t.Errorf("severity: want possible, got %s", report.Severity)
	}
}

func TestBufferOverflow_BottomAddress(t *testing.T) {
	region := MemoryRegion{Kind: RegionStack, ID: 1}
	detector := NewBufferOverflowDetector(map[MemoryRegion]int64{region: 64})
	v := ipVar("ptr", 1)

	report := detector.CheckAccess(v, NewValueSetBottom(), region, 8, ir.BlockID(0))
	if report != nil {
		t.Errorf("expected nil for bottom address, got: %s", report.Message)
	}
}

func TestBufferOverflow_ScanFunction(t *testing.T) {
	region := MemoryRegion{Kind: RegionStack, ID: 1}
	detector := NewBufferOverflowDetector(map[MemoryRegion]int64{region: 16})

	ptrVar := ipVar("ptr", 1)
	ptrVS := NewValueSetPointer(region, 0, 20, 20)

	storeInstr := &ir.Store{
		Address: &ir.VariableExpr{Var: ptrVar},
		Value:   ipConst(0),
		Size:    ir.Size8,
	}

	fn := ipBuildFunction("test_overflow", []ir.IRInstruction{storeInstr})
	vsaResult := &VSAResult{
		ValueSets: map[string]*ValueSet{
			ptrVar.String(): ptrVS,
		},
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	reports := detector.ScanFunction(fn, vsaResult)
	if len(reports) == 0 {
		t.Error("expected at least one overflow report from ScanFunction")
	}
}

func TestBufferOverflow_ScanFunction_NilInputs(t *testing.T) {
	detector := NewBufferOverflowDetector(nil)
	reports := detector.ScanFunction(nil, nil)
	if reports != nil {
		t.Error("expected nil for nil inputs")
	}
}

func TestBufferOverflow_ScanFunction_LoadOverflow(t *testing.T) {
	region := MemoryRegion{Kind: RegionStack, ID: 2}
	detector := NewBufferOverflowDetector(map[MemoryRegion]int64{region: 8})

	ptrVar := ipVar("ptr", 1)
	destVar := ipVar("val", 1)
	ptrVS := NewValueSetPointer(region, 0, 8, 8)

	loadInstr := &ir.Load{
		Dest:    destVar,
		Address: &ir.VariableExpr{Var: ptrVar},
		Size:    ir.Size8,
	}

	fn := ipBuildFunction("test_load_overflow", []ir.IRInstruction{loadInstr})
	vsaResult := &VSAResult{
		ValueSets: map[string]*ValueSet{
			ptrVar.String(): ptrVS,
		},
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	reports := detector.ScanFunction(fn, vsaResult)
	if len(reports) == 0 {
		t.Error("expected overflow report for load past end of allocation")
	}
}

// ============================================================================
// InterproceduralVSAAnalyzer tests
// ============================================================================

func TestInterproceduralVSA_SingleFunction(t *testing.T) {
	xVar := ipVar("x", 1)
	fn := ipBuildFunction("callee", []ir.IRInstruction{
		&ir.Assign{Dest: xVar, Source: ipConst(10)},
		&ir.Return{Value: &xVar},
	})
	cfgGraph := ipBuildCFG(fn)
	domTree := ipBuildDomTree(fn, cfgGraph)

	analyzer := NewInterproceduralVSAAnalyzer(DefaultInterproceduralVSAConfig())
	result, err := analyzer.AnalyzeFunction(fn, cfgGraph, domTree)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	vs := result.GetValueSet(xVar)
	si := vs.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if !si.IsSingleton() || si.Lo != 10 {
		t.Errorf("x: want singleton {10}, got %s", vs)
	}

	summary := analyzer.SummaryDB().Load("callee")
	if summary == nil {
		t.Fatal("expected summary to be stored")
	}
	if summary.ReturnValueSet == nil {
		t.Fatal("expected non-nil return value set in summary")
	}
	retSI := summary.ReturnValueSet.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if !retSI.IsSingleton() || retSI.Lo != 10 {
		t.Errorf("return value set: want {10}, got %s", summary.ReturnValueSet)
	}
}

func TestInterproceduralVSA_CalleeReturnPropagated(t *testing.T) {
	retVar := ipVar("ret", 1)
	callee := ipBuildFunction("get_answer", []ir.IRInstruction{
		&ir.Assign{Dest: retVar, Source: ipConst(42)},
		&ir.Return{Value: &retVar},
	})
	calleeCFG := ipBuildCFG(callee)
	calleeDom := ipBuildDomTree(callee, calleeCFG)

	yVar := ipVar("y", 1)
	caller := ipBuildFunction("caller", []ir.IRInstruction{
		&ir.Call{
			Dest:   &yVar,
			Target: &ir.VariableExpr{Var: ir.Variable{Name: "get_answer"}},
			Args:   nil,
		},
	})
	callerCFG := ipBuildCFG(caller)
	callerDom := ipBuildDomTree(caller, callerCFG)

	analyzer := NewInterproceduralVSAAnalyzer(DefaultInterproceduralVSAConfig())

	_, err := analyzer.AnalyzeFunction(callee, calleeCFG, calleeDom)
	if err != nil {
		t.Fatalf("callee analysis failed: %v", err)
	}

	callerResult, err := analyzer.AnalyzeFunction(caller, callerCFG, callerDom)
	if err != nil {
		t.Fatalf("caller analysis failed: %v", err)
	}

	vs := callerResult.GetValueSet(yVar)
	si := vs.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if !si.IsSingleton() || si.Lo != 42 {
		t.Errorf("y: want singleton {42} from callee summary, got %s", vs)
	}
}

func TestInterproceduralVSA_UnknownCalleeReturnsTop(t *testing.T) {
	yVar := ipVar("y", 1)
	caller := ipBuildFunction("caller", []ir.IRInstruction{
		&ir.Call{
			Dest:   &yVar,
			Target: &ir.VariableExpr{Var: ir.Variable{Name: "unknown_func"}},
			Args:   nil,
		},
	})
	callerCFG := ipBuildCFG(caller)
	callerDom := ipBuildDomTree(caller, callerCFG)

	analyzer := NewInterproceduralVSAAnalyzer(DefaultInterproceduralVSAConfig())
	result, err := analyzer.AnalyzeFunction(caller, callerCFG, callerDom)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	vs := result.GetValueSet(yVar)
	if !vs.IsTop() {
		t.Errorf("y: want top for unknown callee, got %s", vs)
	}
}

func TestInterproceduralVSA_DefaultConfig(t *testing.T) {
	c := DefaultInterproceduralVSAConfig()
	if c.MaxCallDepth <= 0 {
		t.Errorf("MaxCallDepth must be positive, got %d", c.MaxCallDepth)
	}
	if c.WideningThreshold <= 0 {
		t.Errorf("WideningThreshold must be positive, got %d", c.WideningThreshold)
	}
	if c.MaxIterations <= 0 {
		t.Errorf("MaxIterations must be positive, got %d", c.MaxIterations)
	}
}

func TestInterproceduralVSA_NilFunction(t *testing.T) {
	analyzer := NewInterproceduralVSAAnalyzer(DefaultInterproceduralVSAConfig())
	_, err := analyzer.AnalyzeFunction(nil, nil, nil)
	if err == nil {
		t.Error("expected error for nil function")
	}
}

// ============================================================================
// BufferOverflowSeverity.String tests
// ============================================================================

func TestBufferOverflowSeverity_String(t *testing.T) {
	if OverflowDefinite.String() != "definite" {
		t.Errorf("want definite, got %s", OverflowDefinite.String())
	}
	if OverflowPossible.String() != "possible" {
		t.Errorf("want possible, got %s", OverflowPossible.String())
	}
	unknown := BufferOverflowSeverity(99)
	if unknown.String() != "unknown" {
		t.Errorf("want unknown, got %s", unknown.String())
	}
}

// ============================================================================
// regionsDisjointSets tests
// ============================================================================

func TestRegionsDisjointSets_Disjoint(t *testing.T) {
	a := []MemoryRegion{{Kind: RegionStack, ID: 1}}
	b := []MemoryRegion{{Kind: RegionHeap, ID: 1}}
	if !regionsDisjointSets(a, b) {
		t.Error("stack and heap must be disjoint")
	}
}

func TestRegionsDisjointSets_SameRegion(t *testing.T) {
	r := MemoryRegion{Kind: RegionStack, ID: 1}
	a := []MemoryRegion{r}
	b := []MemoryRegion{r}
	if regionsDisjointSets(a, b) {
		t.Error("same region must not be disjoint")
	}
}

func TestRegionsDisjointSets_Empty(t *testing.T) {
	if !regionsDisjointSets(nil, nil) {
		t.Error("empty sets must be disjoint")
	}
}

func TestRegionsDisjointSets_DifferentIDs(t *testing.T) {
	a := []MemoryRegion{{Kind: RegionStack, ID: 1}}
	b := []MemoryRegion{{Kind: RegionStack, ID: 2}}
	if !regionsDisjointSets(a, b) {
		t.Error("different stack frame IDs must be disjoint")
	}
}

// ============================================================================
// sizeToBytes tests
// ============================================================================

func TestSizeToBytes(t *testing.T) {
	cases := []struct {
		size ir.Size
		want int
	}{
		{ir.Size1, 1},
		{ir.Size2, 2},
		{ir.Size4, 4},
		{ir.Size8, 8},
		{ir.Size16, 16},
	}
	for _, tc := range cases {
		got := sizeToBytes(tc.size)
		if got != tc.want {
			t.Errorf("sizeToBytes(%d): want %d, got %d", tc.size, tc.want, got)
		}
	}
}

// ============================================================================
// resolveCalleeName tests
// ============================================================================

func TestResolveCalleeName_Variable(t *testing.T) {
	expr := &ir.VariableExpr{Var: ir.Variable{Name: "my_func"}}
	got := resolveCalleeName(expr)
	if got != "my_func" {
		t.Errorf("want my_func, got %s", got)
	}
}

func TestResolveCalleeName_Nil(t *testing.T) {
	got := resolveCalleeName(nil)
	if got != "" {
		t.Errorf("want empty string for nil, got %s", got)
	}
}

func TestResolveCalleeName_Constant(t *testing.T) {
	expr := &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x401000}}
	got := resolveCalleeName(expr)
	if got != "" {
		t.Errorf("want empty string for constant target, got %s", got)
	}
}
