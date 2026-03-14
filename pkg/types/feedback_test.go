package typeinfer

import (
	"fmt"
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// mock implementations
// ============================================================================

// mockCFGBuilder records calls to AddIndirectTargetWithProvenance for assertions.
type mockCFGBuilder struct {
	calls      []mockAddCall
	failOnCall int // if > 0, return error on the n-th call (1-indexed)
	callCount  int
}

type mockAddCall struct {
	jumpSite   disasm.Address
	target     disasm.Address
	provenance *cfg.EdgeProvenance
}

func (m *mockCFGBuilder) AddIndirectTargetWithProvenance(
	jumpSite, target disasm.Address,
	provenance *cfg.EdgeProvenance,
) error {
	m.callCount++
	if m.failOnCall > 0 && m.callCount == m.failOnCall {
		return fmt.Errorf("mock error on call %d", m.callCount)
	}
	m.calls = append(m.calls, mockAddCall{jumpSite: jumpSite, target: target, provenance: provenance})
	return nil
}

func (m *mockCFGBuilder) GetUnresolvedIndirectJumps() []disasm.Address {
	return nil
}

// mockDiscoverer returns a fixed set of arrays on each call.
// after exhausting the perIterationArrays slice, returns nil (simulates convergence).
type mockDiscoverer struct {
	perIterationArrays [][]FunctionPointerArray
	callCount          int
}

func (d *mockDiscoverer) DiscoverFunctionPointers(_ *TypeSolution) []FunctionPointerArray {
	if d.callCount >= len(d.perIterationArrays) {
		d.callCount++
		return nil
	}
	result := d.perIterationArrays[d.callCount]
	d.callCount++
	return result
}

// ============================================================================
// helper constructors
// ============================================================================

func makeFuncPtrArray(addr ir.Address, targets []ir.Address, kind ArrayKind) FunctionPointerArray {
	return FunctionPointerArray{
		Address:     addr,
		ElementType: ir.FunctionType{ReturnType: ir.VoidType{}},
		Elements:    targets,
		Kind:        kind,
		Confidence:  0.9,
		Origin:      "test",
	}
}

func emptySol() *TypeSolution {
	return &TypeSolution{Types: make(map[string]ir.Type)}
}

// ============================================================================
// FunctionPointerArray and ArrayKind tests
// ============================================================================

func TestArrayKind_String(t *testing.T) {
	cases := []struct {
		kind ArrayKind
		want string
	}{
		{ArrayKindVTable, "vtable"},
		{ArrayKindHandlerTable, "handler_table"},
		{ArrayKindJumpTable, "jump_table"},
		{ArrayKindInterfaceTable, "interface_table"},
		{ArrayKind(99), "unknown_array_kind(99)"},
	}
	for _, tc := range cases {
		if got := tc.kind.String(); got != tc.want {
			t.Errorf("ArrayKind(%d).String() = %q, want %q", tc.kind, got, tc.want)
		}
	}
}

func TestConvergenceReason_String(t *testing.T) {
	if got := ConvergenceNoNewTargets.String(); got != "fixed_point" {
		t.Errorf("got %q", got)
	}
	if got := ConvergenceIterationLimit.String(); got != "iteration_limit" {
		t.Errorf("got %q", got)
	}
}

// ============================================================================
// CyclicFeedbackLoop.Run tests
// ============================================================================

// TestFeedbackLoop_ConvergesOnFirstIteration verifies that when the discoverer
// returns no arrays on the first call, the loop terminates immediately with
// ConvergenceNoNewTargets and zero iterations of actual work.
func TestFeedbackLoop_ConvergesOnFirstIteration(t *testing.T) {
	builder := &mockCFGBuilder{}
	discoverer := &mockDiscoverer{perIterationArrays: nil}

	loop := NewCyclicFeedbackLoop(discoverer, builder, 10)
	result, err := loop.Run(emptySol())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Reason != ConvergenceNoNewTargets {
		t.Errorf("reason = %v, want ConvergenceNoNewTargets", result.Reason)
	}
	if result.IterationsRun != 1 {
		t.Errorf("iterations = %d, want 1", result.IterationsRun)
	}
	if result.TotalTargetsResolved != 0 {
		t.Errorf("targets = %d, want 0", result.TotalTargetsResolved)
	}
	if len(builder.calls) != 0 {
		t.Errorf("builder calls = %d, want 0", len(builder.calls))
	}
}

// TestFeedbackLoop_SingleIterationWithTargets verifies that targets from the
// first iteration are transmitted to the builder and the loop converges on
// the second iteration (no new targets).
func TestFeedbackLoop_SingleIterationWithTargets(t *testing.T) {
	arr := makeFuncPtrArray(0x1000, []ir.Address{0x2000, 0x3000}, ArrayKindVTable)
	discoverer := &mockDiscoverer{
		perIterationArrays: [][]FunctionPointerArray{
			{arr}, // iteration 1: one array with 2 targets
			nil,   // iteration 2: nothing new → convergence
		},
	}
	builder := &mockCFGBuilder{}

	loop := NewCyclicFeedbackLoop(discoverer, builder, 10)
	result, err := loop.Run(emptySol())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Reason != ConvergenceNoNewTargets {
		t.Errorf("reason = %v, want ConvergenceNoNewTargets", result.Reason)
	}
	if result.IterationsRun != 2 {
		t.Errorf("iterations = %d, want 2", result.IterationsRun)
	}
	if result.TotalTargetsResolved != 2 {
		t.Errorf("targets = %d, want 2", result.TotalTargetsResolved)
	}
	if result.ArraysDiscovered != 1 {
		t.Errorf("arrays = %d, want 1", result.ArraysDiscovered)
	}
	if len(builder.calls) != 2 {
		t.Errorf("builder calls = %d, want 2", len(builder.calls))
	}
}

// TestFeedbackLoop_DeduplicatesTargets verifies that the same (jumpSite, target)
// pair is not sent to the builder twice across iterations.
func TestFeedbackLoop_DeduplicatesTargets(t *testing.T) {
	arr := makeFuncPtrArray(0x1000, []ir.Address{0x2000}, ArrayKindVTable)
	// both iterations return the same array
	discoverer := &mockDiscoverer{
		perIterationArrays: [][]FunctionPointerArray{
			{arr},
			{arr}, // duplicate — should be filtered
		},
	}
	builder := &mockCFGBuilder{}

	loop := NewCyclicFeedbackLoop(discoverer, builder, 10)
	result, err := loop.Run(emptySol())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// second iteration adds no new targets → convergence
	if result.Reason != ConvergenceNoNewTargets {
		t.Errorf("reason = %v, want ConvergenceNoNewTargets", result.Reason)
	}
	// builder should only have been called once (deduplication)
	if len(builder.calls) != 1 {
		t.Errorf("builder calls = %d, want 1 (deduplication)", len(builder.calls))
	}
}

// TestFeedbackLoop_HitsIterationLimit verifies that the loop terminates after
// MaxIterations even when new targets keep appearing.
func TestFeedbackLoop_HitsIterationLimit(t *testing.T) {
	// produce a new unique target on every iteration indefinitely
	infiniteDiscoverer := &infiniteUniqueDiscoverer{baseAddr: 0x1000}
	builder := &mockCFGBuilder{}

	const maxIter = 5
	loop := NewCyclicFeedbackLoop(infiniteDiscoverer, builder, maxIter)
	result, err := loop.Run(emptySol())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Reason != ConvergenceIterationLimit {
		t.Errorf("reason = %v, want ConvergenceIterationLimit", result.Reason)
	}
	if result.IterationsRun != maxIter {
		t.Errorf("iterations = %d, want %d", result.IterationsRun, maxIter)
	}
}

// infiniteUniqueDiscoverer returns a new unique target on every call.
type infiniteUniqueDiscoverer struct {
	baseAddr ir.Address
	counter  int
}

func (d *infiniteUniqueDiscoverer) DiscoverFunctionPointers(_ *TypeSolution) []FunctionPointerArray {
	d.counter++
	target := d.baseAddr + ir.Address(d.counter*0x100)
	return []FunctionPointerArray{
		makeFuncPtrArray(0x5000, []ir.Address{target}, ArrayKindHandlerTable),
	}
}

// TestFeedbackLoop_DefaultMaxIterations verifies that maxIterations=0 uses the default.
func TestFeedbackLoop_DefaultMaxIterations(t *testing.T) {
	infiniteDiscoverer := &infiniteUniqueDiscoverer{baseAddr: 0x2000}
	builder := &mockCFGBuilder{}

	loop := NewCyclicFeedbackLoop(infiniteDiscoverer, builder, 0)
	if loop.MaxIterations != defaultMaxIterations {
		t.Errorf("MaxIterations = %d, want %d", loop.MaxIterations, defaultMaxIterations)
	}

	result, _ := loop.Run(emptySol())
	if result.IterationsRun != defaultMaxIterations {
		t.Errorf("iterations = %d, want %d", result.IterationsRun, defaultMaxIterations)
	}
}

// TestFeedbackLoop_BuilderErrorIsNonFatal verifies that a builder error on one
// target does not abort the loop — remaining targets are still processed.
func TestFeedbackLoop_BuilderErrorIsNonFatal(t *testing.T) {
	arr := makeFuncPtrArray(0x1000, []ir.Address{0x2000, 0x3000}, ArrayKindVTable)
	discoverer := &mockDiscoverer{
		perIterationArrays: [][]FunctionPointerArray{{arr}},
	}
	// fail on the first call only
	builder := &mockCFGBuilder{failOnCall: 1}

	loop := NewCyclicFeedbackLoop(discoverer, builder, 10)
	result, err := loop.Run(emptySol())

	// error should be returned but loop should continue
	if err == nil {
		t.Error("expected non-nil error from builder failure")
	}
	// second target (0x3000) should still be processed
	if result.TotalTargetsResolved != 1 {
		t.Errorf("targets = %d, want 1 (one failed, one succeeded)", result.TotalTargetsResolved)
	}
}

// TestFeedbackLoop_ProvenanceContainsArrayKind verifies that the provenance
// passed to the builder contains the array kind string.
func TestFeedbackLoop_ProvenanceContainsArrayKind(t *testing.T) {
	arr := makeFuncPtrArray(0x1000, []ir.Address{0x2000}, ArrayKindInterfaceTable)
	discoverer := &mockDiscoverer{
		perIterationArrays: [][]FunctionPointerArray{{arr}},
	}
	builder := &mockCFGBuilder{}

	loop := NewCyclicFeedbackLoop(discoverer, builder, 10)
	_, _ = loop.Run(emptySol())

	if len(builder.calls) == 0 {
		t.Fatal("no builder calls recorded")
	}
	prov := builder.calls[0].provenance
	if prov == nil {
		t.Fatal("provenance is nil")
	}
	kindVal, ok := prov.Metadata["array_kind"]
	if !ok {
		t.Fatal("provenance metadata missing array_kind")
	}
	if kindVal != "interface_table" {
		t.Errorf("array_kind = %v, want interface_table", kindVal)
	}
}

// ============================================================================
// FunctionPointerAnalyzer tests
// ============================================================================

func TestFunctionPointerAnalyzer_NilSolution(t *testing.T) {
	a := NewFunctionPointerAnalyzer()
	arrays := a.DiscoverFunctionPointers(nil)
	if len(arrays) != 0 {
		t.Errorf("expected empty result for nil solution, got %d", len(arrays))
	}
}

func TestFunctionPointerAnalyzer_ArrayOfFunctionTypes(t *testing.T) {
	a := NewFunctionPointerAnalyzer()
	sol := &TypeSolution{
		Types: map[string]ir.Type{
			"vtable_MyClass": ir.ArrayType{
				Element: ir.FunctionType{ReturnType: ir.VoidType{}},
				Length:  3,
			},
		},
	}
	arrays := a.DiscoverFunctionPointers(sol)
	if len(arrays) != 1 {
		t.Fatalf("expected 1 array, got %d", len(arrays))
	}
	if arrays[0].Kind != ArrayKindVTable {
		t.Errorf("kind = %v, want ArrayKindVTable", arrays[0].Kind)
	}
}

func TestFunctionPointerAnalyzer_ArrayOfFunctionPointers(t *testing.T) {
	a := NewFunctionPointerAnalyzer()
	sol := &TypeSolution{
		Types: map[string]ir.Type{
			"handlers_dispatch": ir.ArrayType{
				Element: ir.PointerType{Pointee: ir.FunctionType{ReturnType: ir.IntType{Width: ir.Size4}}},
				Length:  4,
			},
		},
	}
	arrays := a.DiscoverFunctionPointers(sol)
	if len(arrays) != 1 {
		t.Fatalf("expected 1 array, got %d", len(arrays))
	}
	if arrays[0].Kind != ArrayKindHandlerTable {
		t.Errorf("kind = %v, want ArrayKindHandlerTable", arrays[0].Kind)
	}
}

func TestFunctionPointerAnalyzer_SkipsNonFunctionArrays(t *testing.T) {
	a := NewFunctionPointerAnalyzer()
	sol := &TypeSolution{
		Types: map[string]ir.Type{
			"int_array": ir.ArrayType{
				Element: ir.IntType{Width: ir.Size4},
				Length:  10,
			},
			"plain_int": ir.IntType{Width: ir.Size8},
		},
	}
	arrays := a.DiscoverFunctionPointers(sol)
	if len(arrays) != 0 {
		t.Errorf("expected 0 arrays, got %d", len(arrays))
	}
}

func TestFunctionPointerAnalyzer_SkipsShortArrays(t *testing.T) {
	a := NewFunctionPointerAnalyzer()
	// length=1 is below minArrayLen=2
	sol := &TypeSolution{
		Types: map[string]ir.Type{
			"vtable_x": ir.ArrayType{
				Element: ir.FunctionType{ReturnType: ir.VoidType{}},
				Length:  1,
			},
		},
	}
	arrays := a.DiscoverFunctionPointers(sol)
	if len(arrays) != 0 {
		t.Errorf("expected 0 arrays (too short), got %d", len(arrays))
	}
}

func TestFunctionPointerAnalyzer_KnownVTableBoostsConfidence(t *testing.T) {
	a := NewFunctionPointerAnalyzer()
	a.RegisterKnownVTable(0xDEAD)

	// manually call computeConfidence to verify boost
	conf := a.computeConfidence(0xDEAD, ArrayKindVTable)
	if conf != 1.0 {
		t.Errorf("confidence for known vtable = %.2f, want 1.0", conf)
	}

	confUnknown := a.computeConfidence(0xBEEF, ArrayKindVTable)
	if confUnknown >= 1.0 {
		t.Errorf("confidence for unknown vtable = %.2f, should be < 1.0", confUnknown)
	}
}

func TestFunctionPointerAnalyzer_InterfaceTableClassification(t *testing.T) {
	a := NewFunctionPointerAnalyzer()
	sol := &TypeSolution{
		Types: map[string]ir.Type{
			"itab_Stringer": ir.ArrayType{
				Element: ir.FunctionType{ReturnType: ir.VoidType{}},
				Length:  2,
			},
		},
	}
	arrays := a.DiscoverFunctionPointers(sol)
	if len(arrays) != 1 {
		t.Fatalf("expected 1 array, got %d", len(arrays))
	}
	if arrays[0].Kind != ArrayKindInterfaceTable {
		t.Errorf("kind = %v, want ArrayKindInterfaceTable", arrays[0].Kind)
	}
}

func TestFunctionPointerAnalyzer_JumpTableClassification(t *testing.T) {
	a := NewFunctionPointerAnalyzer()
	sol := &TypeSolution{
		Types: map[string]ir.Type{
			"jump_table_switch": ir.ArrayType{
				Element: ir.FunctionType{ReturnType: ir.VoidType{}},
				Length:  8,
			},
		},
	}
	arrays := a.DiscoverFunctionPointers(sol)
	if len(arrays) != 1 {
		t.Fatalf("expected 1 array, got %d", len(arrays))
	}
	if arrays[0].Kind != ArrayKindJumpTable {
		t.Errorf("kind = %v, want ArrayKindJumpTable", arrays[0].Kind)
	}
}

// ============================================================================
// helper utilities tests
// ============================================================================

func TestContainsSubstring(t *testing.T) {
	cases := []struct {
		s, sub string
		want   bool
	}{
		{"vtable_MyClass", "vtable", true},
		{"VTABLE_X", "vtable", true}, // case-insensitive
		{"handlers", "vtable", false},
		{"", "vtable", false},
		{"itab_Stringer", "itab", true},
	}
	for _, tc := range cases {
		if got := containsSubstring(tc.s, tc.sub); got != tc.want {
			t.Errorf("containsSubstring(%q, %q) = %v, want %v", tc.s, tc.sub, got, tc.want)
		}
	}
}

func TestClassifyByName(t *testing.T) {
	cases := []struct {
		name string
		want ArrayKind
	}{
		{"vtable_Foo", ArrayKindVTable},
		{"vptr_Bar", ArrayKindVTable},
		{"itab_Stringer", ArrayKindInterfaceTable},
		{"iface_methods", ArrayKindInterfaceTable},
		{"jump_table_switch", ArrayKindJumpTable},
		{"computed_goto", ArrayKindJumpTable},
		{"handlers_dispatch", ArrayKindHandlerTable},
		{"callbacks_list", ArrayKindHandlerTable},
		{"unknown_array", ArrayKindHandlerTable}, // default
	}
	for _, tc := range cases {
		if got := classifyByName(tc.name); got != tc.want {
			t.Errorf("classifyByName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestFeedbackLoopResult_String verifies the summary string is non-empty.
func TestFeedbackLoopResult_String(t *testing.T) {
	r := &FeedbackLoopResult{
		IterationsRun:        3,
		TotalTargetsResolved: 7,
		ArraysDiscovered:     2,
		Reason:               ConvergenceNoNewTargets,
	}
	s := r.String()
	if s == "" {
		t.Error("FeedbackLoopResult.String() returned empty string")
	}
}
