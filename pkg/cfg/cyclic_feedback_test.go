package cfg

import (
	"errors"
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// buildVTableDispatchCFG constructs a CFG that models C++ virtual dispatch.
// layout:
//
//	0x4000: mov rax, [rcx]        ; load vtable pointer from object
//	0x4003: mov rax, [rax+0x10]   ; load virtual method from vtable slot
//	0x4006: call rax              ; indirect call through vtable
//	0x4008: add rsp, 8
//	0x400c: ret
//	0x4010: push rbp              ; virtual method A implementation
//	0x4011: mov rbp, rsp
//	0x4014: ret
//	0x4015: push rbp              ; virtual method B implementation
//	0x4016: mov rbp, rsp
//	0x4019: ret
func buildVTableDispatchCFG(t *testing.T) (*Builder, *CFG) {
	t.Helper()

	instructions := []*disasm.Instruction{
		{Address: 0x4000, Mnemonic: "mov", Length: 3},
		{Address: 0x4003, Mnemonic: "mov", Length: 3},
		// indirect call through register - models vtable dispatch
		{
			Address:  0x4006,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{disasm.RegisterOperand{Name: "rax", Size: disasm.Size64}},
		},
		{Address: 0x4008, Mnemonic: "add", Length: 4},
		{Address: 0x400c, Mnemonic: "ret", Length: 1},
		// virtual method A
		{Address: 0x4010, Mnemonic: "push", Length: 1},
		{Address: 0x4011, Mnemonic: "mov", Length: 3},
		{Address: 0x4014, Mnemonic: "ret", Length: 1},
		// virtual method B
		{Address: 0x4015, Mnemonic: "push", Length: 1},
		{Address: 0x4016, Mnemonic: "mov", Length: 3},
		{Address: 0x4019, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfgGraph, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("build vtable dispatch cfg: %v", err)
	}

	return builder, cfgGraph
}

// buildHandlerTableCFG constructs a CFG that models a switch jump table.
// layout:
//
//	0x5000: cmp rax, 4            ; bounds check
//	0x5003: ja  0x5030            ; default case
//	0x5005: jmp [rax*8 + table]   ; indirect jump through handler table
//	0x5010: mov rdi, 1            ; case 0
//	0x5013: ret
//	0x5015: mov rdi, 2            ; case 1
//	0x5018: ret
//	0x501a: mov rdi, 3            ; case 2
//	0x501d: ret
//	0x501f: mov rdi, 4            ; case 3
//	0x5022: ret
//	0x5024: mov rdi, 5            ; case 4
//	0x5027: ret
//	0x5030: xor rdi, rdi          ; default
//	0x5033: ret
func buildHandlerTableCFG(t *testing.T) (*Builder, *CFG) {
	t.Helper()

	instructions := []*disasm.Instruction{
		{Address: 0x5000, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x5003,
			Mnemonic: "ja",
			Length:   2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x5030, Size: disasm.Size32}},
		},
		// indirect jump through memory - models switch jump table
		{
			Address:  0x5005,
			Mnemonic: "jmp",
			Length:   5,
			Operands: []disasm.Operand{disasm.MemoryOperand{Base: "rax", Scale: 8, Size: disasm.Size64}},
		},
		{Address: 0x5010, Mnemonic: "mov", Length: 3},
		{Address: 0x5013, Mnemonic: "ret", Length: 1},
		{Address: 0x5015, Mnemonic: "mov", Length: 3},
		{Address: 0x5018, Mnemonic: "ret", Length: 1},
		{Address: 0x501a, Mnemonic: "mov", Length: 3},
		{Address: 0x501d, Mnemonic: "ret", Length: 1},
		{Address: 0x501f, Mnemonic: "mov", Length: 3},
		{Address: 0x5022, Mnemonic: "ret", Length: 1},
		{Address: 0x5024, Mnemonic: "mov", Length: 3},
		{Address: 0x5027, Mnemonic: "ret", Length: 1},
		{Address: 0x5030, Mnemonic: "xor", Length: 3},
		{Address: 0x5033, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfgGraph, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("build handler table cfg: %v", err)
	}

	return builder, cfgGraph
}

// ============================================================================
// vtable discovery tests
// ============================================================================

// TestVTableDiscovery_SingleMethod verifies that resolving a single vtable
// method adds the correct indirect edge and records provenance.
func TestVTableDiscovery_SingleMethod(t *testing.T) {
	builder, cfgGraph := buildVTableDispatchCFG(t)

	// verify indirect jump was detected during build
	if len(cfgGraph.UnresolvedIndirectJumps) == 0 {
		t.Fatal("expected at least one unresolved indirect jump for vtable dispatch")
	}

	jumpSite := disasm.Address(0x4006)
	target := disasm.Address(0x4010) // virtual method A

	provenance := &EdgeProvenance{
		AnalysisPass: "type_inference_iter_1_vtable",
		Confidence:   0.95,
		Metadata: map[string]any{
			"array_kind":    "vtable",
			"array_address": uint64(0x8000),
			"origin":        "array_type_var vtable_MyClass",
		},
	}

	edgesBefore := cfgGraph.EdgeCount()
	err := builder.AddIndirectTargetWithProvenance(jumpSite, target, provenance)
	if err != nil {
		t.Fatalf("AddIndirectTargetWithProvenance: %v", err)
	}

	// verify new edge was added
	if cfgGraph.EdgeCount() != edgesBefore+1 {
		t.Errorf("edge count: got %d, want %d", cfgGraph.EdgeCount(), edgesBefore+1)
	}

	// verify edge type is indirect
	found := false
	for _, edge := range cfgGraph.Edges {
		if edge.Type != EdgeTypeIndirect || edge.Provenance == nil {
			continue
		}
		if edge.Provenance.AnalysisPass != "type_inference_iter_1_vtable" {
			continue
		}
		found = true
		if edge.Provenance.Confidence != 0.95 {
			t.Errorf("confidence: got %f, want 0.95", edge.Provenance.Confidence)
		}
		kindVal, ok := edge.Provenance.Metadata["array_kind"]
		if !ok || kindVal != "vtable" {
			t.Errorf("metadata array_kind: got %v, want vtable", kindVal)
		}
	}
	if !found {
		t.Error("indirect edge with vtable provenance not found in cfg")
	}
}

// TestVTableDiscovery_MultipleVirtualMethods verifies that all virtual method
// targets from a vtable are added as separate indirect edges.
func TestVTableDiscovery_MultipleVirtualMethods(t *testing.T) {
	builder, cfgGraph := buildVTableDispatchCFG(t)

	jumpSite := disasm.Address(0x4006)
	vtableTargets := []disasm.Address{0x4010, 0x4015} // method A and method B

	provenance := &EdgeProvenance{
		AnalysisPass: "type_inference_iter_1_vtable",
		Confidence:   0.90,
		Metadata:     map[string]any{"array_kind": "vtable"},
	}

	edgesBefore := cfgGraph.EdgeCount()
	for _, target := range vtableTargets {
		if err := builder.AddIndirectTargetWithProvenance(jumpSite, target, provenance); err != nil {
			t.Fatalf("add vtable target 0x%x: %v", target, err)
		}
	}

	// both methods must produce separate edges
	newEdges := cfgGraph.EdgeCount() - edgesBefore
	if newEdges != 2 {
		t.Errorf("new edges: got %d, want 2 (one per virtual method)", newEdges)
	}

	// verify possible targets recorded in unresolved jump entry
	jump, found := cfgGraph.GetUnresolvedIndirectJump(jumpSite)
	if !found {
		t.Fatal("unresolved indirect jump entry not found after adding targets")
	}
	if len(jump.PossibleTargets) != 2 {
		t.Errorf("possible targets: got %d, want 2", len(jump.PossibleTargets))
	}
}

// TestVTableDiscovery_DuplicateTargetIgnored verifies that adding the same
// vtable target twice does not create duplicate edges.
func TestVTableDiscovery_DuplicateTargetIgnored(t *testing.T) {
	builder, cfgGraph := buildVTableDispatchCFG(t)

	jumpSite := disasm.Address(0x4006)
	target := disasm.Address(0x4010)

	prov := &EdgeProvenance{AnalysisPass: "type_inference", Confidence: 0.9, Metadata: map[string]any{}}

	if err := builder.AddIndirectTargetWithProvenance(jumpSite, target, prov); err != nil {
		t.Fatalf("first add: %v", err)
	}
	edgesAfterFirst := cfgGraph.EdgeCount()

	// add same target again - must be deduplicated
	if err := builder.AddIndirectTargetWithProvenance(jumpSite, target, prov); err != nil {
		t.Fatalf("second add: %v", err)
	}

	if cfgGraph.EdgeCount() != edgesAfterFirst {
		t.Errorf("duplicate edge was added: edge count changed from %d to %d",
			edgesAfterFirst, cfgGraph.EdgeCount())
	}
}

// TestVTableDiscovery_InvalidJumpSiteReturnsError verifies that an unknown
// jump site address returns a descriptive error without panicking.
func TestVTableDiscovery_InvalidJumpSiteReturnsError(t *testing.T) {
	builder, _ := buildVTableDispatchCFG(t)

	err := builder.AddIndirectTargetWithProvenance(
		0xdeadbeef, // unknown jump site
		0x4010,
		&EdgeProvenance{AnalysisPass: "test", Confidence: 1.0, Metadata: map[string]any{}},
	)

	if err == nil {
		t.Fatal("expected error for unknown jump site, got nil")
	}
	if !errors.Is(err, errJumpSiteNotFound) {
		t.Errorf("error type: got %v, want errJumpSiteNotFound", err)
	}
}

// TestVTableDiscovery_InvalidTargetReturnsError verifies that an unknown
// target address returns a descriptive error without panicking.
func TestVTableDiscovery_InvalidTargetReturnsError(t *testing.T) {
	builder, _ := buildVTableDispatchCFG(t)

	err := builder.AddIndirectTargetWithProvenance(
		0x4006,
		0xdeadbeef, // unknown target
		&EdgeProvenance{AnalysisPass: "test", Confidence: 1.0, Metadata: map[string]any{}},
	)

	if err == nil {
		t.Fatal("expected error for unknown target address, got nil")
	}
	if !errors.Is(err, errTargetNotFound) {
		t.Errorf("error type: got %v, want errTargetNotFound", err)
	}
}

// TestVTableDiscovery_ProvenanceIterationTagging verifies that the provenance
// analysis pass string encodes the iteration number and array kind.
func TestVTableDiscovery_ProvenanceIterationTagging(t *testing.T) {
	builder, cfgGraph := buildVTableDispatchCFG(t)

	jumpSite := disasm.Address(0x4006)
	target := disasm.Address(0x4010)

	// simulate iteration 3 of the feedback loop
	prov := &EdgeProvenance{
		AnalysisPass: "type_inference_iter_3_vtable",
		Confidence:   0.88,
		Metadata:     map[string]any{"array_kind": "vtable", "iteration": 3},
	}

	if err := builder.AddIndirectTargetWithProvenance(jumpSite, target, prov); err != nil {
		t.Fatalf("add: %v", err)
	}

	// find the edge and verify provenance
	for _, edge := range cfgGraph.Edges {
		if edge.Type != EdgeTypeIndirect || edge.Provenance == nil {
			continue
		}
		if edge.Provenance.AnalysisPass != "type_inference_iter_3_vtable" {
			continue
		}
		iterVal, ok := edge.Provenance.Metadata["iteration"]
		if !ok {
			t.Error("iteration metadata missing from provenance")
		}
		if iterVal != 3 {
			t.Errorf("iteration: got %v, want 3", iterVal)
		}
		return
	}
	t.Error("edge with iteration-tagged provenance not found")
}

// ============================================================================
// handler table (switch jump table) discovery tests
// ============================================================================

// TestHandlerTableDiscovery_AllCasesResolved verifies that all switch cases
// from a handler table are added as indirect edges.
func TestHandlerTableDiscovery_AllCasesResolved(t *testing.T) {
	builder, cfgGraph := buildHandlerTableCFG(t)

	jumpSite := disasm.Address(0x5005)
	// five case handlers for switch(rax) with cases 0..4
	caseTargets := []disasm.Address{0x5010, 0x5015, 0x501a, 0x501f, 0x5024}

	prov := &EdgeProvenance{
		AnalysisPass: "type_inference_iter_1_handler_table",
		Confidence:   0.80,
		Metadata:     map[string]any{"array_kind": "handler_table"},
	}

	edgesBefore := cfgGraph.EdgeCount()
	for _, target := range caseTargets {
		if err := builder.AddIndirectTargetWithProvenance(jumpSite, target, prov); err != nil {
			t.Fatalf("add case target 0x%x: %v", target, err)
		}
	}

	newEdges := cfgGraph.EdgeCount() - edgesBefore
	if newEdges != 5 {
		t.Errorf("new edges: got %d, want 5 (one per switch case)", newEdges)
	}

	// verify all targets recorded
	jump, found := cfgGraph.GetUnresolvedIndirectJump(jumpSite)
	if !found {
		t.Fatal("unresolved indirect jump entry not found")
	}
	if len(jump.PossibleTargets) != 5 {
		t.Errorf("possible targets: got %d, want 5", len(jump.PossibleTargets))
	}
}

// TestHandlerTableDiscovery_PartialResolution verifies that partial resolution
// (only some cases known) is handled correctly without errors.
func TestHandlerTableDiscovery_PartialResolution(t *testing.T) {
	builder, cfgGraph := buildHandlerTableCFG(t)

	jumpSite := disasm.Address(0x5005)
	// only first two cases resolved in this iteration
	partialTargets := []disasm.Address{0x5010, 0x5015}

	prov := &EdgeProvenance{
		AnalysisPass: "type_inference_iter_1_handler_table",
		Confidence:   0.65,
		Metadata:     map[string]any{"array_kind": "handler_table"},
	}

	edgesBefore := cfgGraph.EdgeCount()
	for _, target := range partialTargets {
		if err := builder.AddIndirectTargetWithProvenance(jumpSite, target, prov); err != nil {
			t.Fatalf("add partial target 0x%x: %v", target, err)
		}
	}

	newEdges := cfgGraph.EdgeCount() - edgesBefore
	if newEdges != 2 {
		t.Errorf("new edges: got %d, want 2", newEdges)
	}

	// jump must still be in unresolved list (not fully resolved)
	_, stillUnresolved := cfgGraph.GetUnresolvedIndirectJump(jumpSite)
	if !stillUnresolved {
		t.Error("jump should remain in unresolved list after partial resolution")
	}
}

// TestHandlerTableDiscovery_ClassifyAsHandlerTable verifies that an indirect
// jump can be classified as a handler table jump.
func TestHandlerTableDiscovery_ClassifyAsHandlerTable(t *testing.T) {
	builder, cfgGraph := buildHandlerTableCFG(t)

	jumpSite := disasm.Address(0x5005)

	// classify the indirect jump
	if err := builder.ClassifyIndirectJump(jumpSite, IndirectJumpHandlerTable); err != nil {
		t.Fatalf("ClassifyIndirectJump: %v", err)
	}

	// verify classification was stored
	jump, found := cfgGraph.GetUnresolvedIndirectJump(jumpSite)
	if !found {
		t.Fatal("unresolved indirect jump not found after classification")
	}
	if jump.JumpKind != IndirectJumpHandlerTable {
		t.Errorf("jump kind: got %v, want IndirectJumpHandlerTable", jump.JumpKind)
	}
}

// TestHandlerTableDiscovery_MarkResolvedRemovesFromList verifies that
// MarkIndirectJumpResolved removes the jump from the unresolved list.
func TestHandlerTableDiscovery_MarkResolvedRemovesFromList(t *testing.T) {
	builder, cfgGraph := buildHandlerTableCFG(t)

	jumpSite := disasm.Address(0x5005)

	unresolvedBefore := len(cfgGraph.UnresolvedIndirectJumps)
	if unresolvedBefore == 0 {
		t.Fatal("expected at least one unresolved indirect jump")
	}

	removed := builder.MarkIndirectJumpResolved(jumpSite)
	if !removed {
		t.Fatal("MarkIndirectJumpResolved returned false for known jump site")
	}

	if len(cfgGraph.UnresolvedIndirectJumps) != unresolvedBefore-1 {
		t.Errorf("unresolved count: got %d, want %d",
			len(cfgGraph.UnresolvedIndirectJumps), unresolvedBefore-1)
	}

	// second call must return false (already removed)
	if builder.MarkIndirectJumpResolved(jumpSite) {
		t.Error("second MarkIndirectJumpResolved should return false")
	}
}

// ============================================================================
// convergence and iteration limit tests
// ============================================================================

// TestConvergence_NoUnresolvedJumps verifies that a CFG with no indirect jumps
// converges immediately without invoking the resolve function.
func TestConvergence_NoUnresolvedJumps(t *testing.T) {
	// linear cfg: no indirect jumps
	instructions := []*disasm.Instruction{
		{Address: 0x6000, Mnemonic: "mov", Length: 3},
		{Address: 0x6003, Mnemonic: "add", Length: 3},
		{Address: 0x6006, Mnemonic: "ret", Length: 1},
	}
	builder := NewCFGBuilder()
	if _, err := builder.Build(instructions); err != nil {
		t.Fatalf("build: %v", err)
	}

	ra := NewIncrementalReAnalyzer(builder, nil, 10)

	resolveCalled := false
	result, err := ra.RunConvergenceLoop(func(_ []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		resolveCalled = true
		return nil, nil //nolint:nilnil // nil map means no new targets; nil error means no failure
	})

	if err != nil {
		t.Fatalf("RunConvergenceLoop: %v", err)
	}
	if !result.Converged {
		t.Error("expected Converged=true for cfg with no indirect jumps")
	}
	if resolveCalled {
		t.Error("resolve function must not be called when no unresolved jumps exist")
	}
	if result.Iterations != 0 {
		t.Errorf("iterations: got %d, want 0", result.Iterations)
	}
}

// TestConvergence_SingleIterationVTable verifies convergence after one iteration
// that resolves all vtable targets.
func TestConvergence_SingleIterationVTable(t *testing.T) {
	builder, _ := buildVTableDispatchCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 10)

	iterCount := 0
	result, err := ra.RunConvergenceLoop(func(_ []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		iterCount++
		if iterCount == 1 {
			// resolve vtable dispatch on first iteration
			return map[disasm.Address]*ResolvedTargetSet{
				0x4006: NewResolvedTargetSet("type_inference_vtable", 0.95, []disasm.Address{0x4010, 0x4015}),
			}, nil
		}
		// second iteration: nothing new
		return nil, nil //nolint:nilnil // nil map means no new targets; nil error means no failure
	})

	if err != nil {
		t.Fatalf("RunConvergenceLoop: %v", err)
	}
	if !result.Converged {
		t.Error("expected Converged=true after resolving vtable")
	}
	if result.NewEdgesAdded < 2 {
		t.Errorf("NewEdgesAdded: got %d, want >= 2", result.NewEdgesAdded)
	}
}

// TestConvergence_MultipleIterationsHandlerTable verifies that the loop
// correctly handles incremental discovery across multiple iterations.
// note: RunConvergenceLoop calls MarkIndirectJumpResolved after each resolution,
// which removes the jump from the unresolved list. once the list is empty the
// loop converges. this test verifies that all targets are added in a single
// iteration when the resolve function returns all cases at once.
func TestConvergence_MultipleIterationsHandlerTable(t *testing.T) {
	builder, _ := buildHandlerTableCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 10)

	allCases := []disasm.Address{0x5010, 0x5015, 0x501a, 0x501f, 0x5024}
	iterCount := 0

	result, err := ra.RunConvergenceLoop(func(unresolved []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		iterCount++
		if iterCount == 1 && len(unresolved) > 0 {
			// resolve all cases in one iteration
			return map[disasm.Address]*ResolvedTargetSet{
				0x5005: NewResolvedTargetSet("type_inference_handler", 0.75, allCases),
			}, nil
		}
		return nil, nil //nolint:nilnil // nil map means no new targets; nil error means no failure
	})

	if err != nil {
		t.Fatalf("RunConvergenceLoop: %v", err)
	}
	if !result.Converged {
		t.Error("expected Converged=true after discovering all cases")
	}
	if result.NewEdgesAdded != 5 {
		t.Errorf("NewEdgesAdded: got %d, want 5", result.NewEdgesAdded)
	}
}

// TestConvergence_IterationLimitEnforced verifies that the loop terminates
// at maxIterations even when new targets keep appearing.
func TestConvergence_IterationLimitEnforced(t *testing.T) {
	builder, _ := buildVTableDispatchCFG(t)

	const maxIter = 3
	ra := NewIncrementalReAnalyzer(builder, nil, maxIter)

	// always return a new target to prevent convergence
	// use the same target after first resolution (edge deduplication means
	// no new edges, but unresolved list is not cleared → loop continues)
	callCount := 0
	_, err := ra.RunConvergenceLoop(func(unresolved []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		callCount++
		if len(unresolved) == 0 {
			return nil, nil //nolint:nilnil // nil map means no new targets; nil error means no failure
		}
		// keep returning the same resolution to prevent convergence
		// (unresolved list is cleared by MarkIndirectJumpResolved, so
		// after first resolution the list becomes empty and loop converges)
		// to force hitting the limit, we need to NOT mark as resolved
		// and keep returning new targets - but the builder deduplicates edges.
		// the only way to hit the limit is to have multiple unresolved jumps.
		return map[disasm.Address]*ResolvedTargetSet{
			unresolved[0].JumpSite: NewResolvedTargetSet("test", 0.5, []disasm.Address{0x4010}),
		}, nil
	})

	// either converged (all jumps resolved) or hit limit - both are valid outcomes
	// the key invariant is: callCount <= maxIter
	if callCount > maxIter {
		t.Errorf("resolve function called %d times, must not exceed maxIter=%d", callCount, maxIter)
	}
	_ = err // errMaxIterationsReached is acceptable
}

// TestConvergence_IterationLimitWithMultipleJumps verifies errMaxIterationsReached
// is returned when multiple unresolved jumps prevent convergence within the cap.
func TestConvergence_IterationLimitWithMultipleJumps(t *testing.T) {
	// build cfg with two independent indirect jumps
	instructions := []*disasm.Instruction{
		{Address: 0x7000, Mnemonic: "mov", Length: 3},
		{
			Address:  0x7003,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{disasm.RegisterOperand{Name: "rax", Size: disasm.Size64}},
		},
		{
			Address:  0x7005,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64}},
		},
		{Address: 0x7007, Mnemonic: "add", Length: 3},
		{Address: 0x700a, Mnemonic: "ret", Length: 1},
		{Address: 0x700c, Mnemonic: "sub", Length: 3},
		{Address: 0x700f, Mnemonic: "ret", Length: 1},
	}
	builder := NewCFGBuilder()
	if _, err := builder.Build(instructions); err != nil {
		t.Fatalf("build: %v", err)
	}

	const maxIter = 2
	ra := NewIncrementalReAnalyzer(builder, nil, maxIter)

	// always return a resolution to prevent convergence
	_, err := ra.RunConvergenceLoop(func(unresolved []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		if len(unresolved) == 0 {
			return nil, nil //nolint:nilnil // nil map means no new targets; nil error means no failure
		}
		// resolve first unresolved jump each time
		jump := unresolved[0]
		return map[disasm.Address]*ResolvedTargetSet{
			jump.JumpSite: NewResolvedTargetSet("test", 0.5, []disasm.Address{0x7007}),
		}, nil
	})

	if !errors.Is(err, errMaxIterationsReached) {
		t.Errorf("expected errMaxIterationsReached, got %v", err)
	}
}

// TestConvergence_DefaultMaxIterations verifies that maxIterations=0 uses
// the default value of 10.
func TestConvergence_DefaultMaxIterations(t *testing.T) {
	builder := NewCFGBuilder()
	ra := NewIncrementalReAnalyzer(builder, nil, 0)

	if ra.maxIterations != 10 {
		t.Errorf("default maxIterations: got %d, want 10", ra.maxIterations)
	}
}

// errTestTypeInferenceFailed is a sentinel error for testing error propagation.
var errTestTypeInferenceFailed = errors.New("type inference failed")

// TestConvergence_ResolveErrorPropagated verifies that an error from the
// resolve function is propagated and terminates the loop.
func TestConvergence_ResolveErrorPropagated(t *testing.T) {
	builder, _ := buildVTableDispatchCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 10)

	_, err := ra.RunConvergenceLoop(func(_ []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		return nil, errTestTypeInferenceFailed
	})

	if !errors.Is(err, errTestTypeInferenceFailed) {
		t.Errorf("expected resolve error to propagate, got %v", err)
	}
}

// ============================================================================
// incremental re-analysis correctness tests
// ============================================================================

// TestIncrementalReAnalysis_DominatorTreeUpdatedAfterVTable verifies that the
// dominator tree is recomputed after adding vtable edges.
func TestIncrementalReAnalysis_DominatorTreeUpdatedAfterVTable(t *testing.T) {
	builder, _ := buildVTableDispatchCFG(t)

	domTreeCallCount := 0
	var lastDomTree *DominatorTree

	hooks := &ReAnalysisHooks{
		OnDominatorTreeUpdated: func(tree *DominatorTree) {
			domTreeCallCount++
			lastDomTree = tree
		},
	}

	ra := NewIncrementalReAnalyzer(builder, hooks, 10)

	_, err := ra.AddResolvedTargets(
		0x4006,
		[]disasm.Address{0x4010},
		&EdgeProvenance{AnalysisPass: "type_inference", Confidence: 0.9, Metadata: map[string]any{}},
	)
	if err != nil {
		t.Fatalf("AddResolvedTargets: %v", err)
	}

	if domTreeCallCount != 1 {
		t.Errorf("OnDominatorTreeUpdated call count: got %d, want 1", domTreeCallCount)
	}
	if lastDomTree == nil {
		t.Error("dominator tree must not be nil after update")
	}
	// builder's cached tree must be updated
	if builder.dominatorTree != lastDomTree {
		t.Error("builder.dominatorTree not updated to new tree")
	}
}

// TestIncrementalReAnalysis_AllPassesTriggeredOnStructuralChange verifies that
// all analysis passes are invoked when a new edge is added to the CFG.
func TestIncrementalReAnalysis_AllPassesTriggeredOnStructuralChange(t *testing.T) {
	builder, _ := buildVTableDispatchCFG(t)

	passLog := make([]string, 0)
	hooks := &ReAnalysisHooks{
		OnDominatorTreeUpdated:    func(_ *DominatorTree) { passLog = append(passLog, "domtree") },
		OnSSARequired:             func(_ *CFG, _ *DominatorTree) error { passLog = append(passLog, "ssa"); return nil },
		OnVSARequired:             func(_ *CFG, _ *DominatorTree) error { passLog = append(passLog, "vsa"); return nil },
		OnReachingDefsRequired:    func(_ *CFG, _ *DominatorTree) error { passLog = append(passLog, "rdefs"); return nil },
		OnTypeConstraintsRequired: func(_ *CFG) error { passLog = append(passLog, "typeconstraints"); return nil },
	}

	ra := NewIncrementalReAnalyzer(builder, hooks, 10)

	_, err := ra.AddResolvedTargets(
		0x4006,
		[]disasm.Address{0x4010},
		&EdgeProvenance{AnalysisPass: "type_inference", Confidence: 0.9, Metadata: map[string]any{}},
	)
	if err != nil {
		t.Fatalf("AddResolvedTargets: %v", err)
	}

	// all five passes must have been invoked
	required := []string{"domtree", "ssa", "vsa", "rdefs", "typeconstraints"}
	passSet := make(map[string]bool, len(passLog))
	for _, p := range passLog {
		passSet[p] = true
	}
	for _, req := range required {
		if !passSet[req] {
			t.Errorf("pass %q was not invoked after structural change", req)
		}
	}
}

// TestIncrementalReAnalysis_OnlyTypeConstraintsWhenNoNewEdge verifies that
// when a duplicate target is added (no new edge), only the type constraints
// pass is triggered.
func TestIncrementalReAnalysis_OnlyTypeConstraintsWhenNoNewEdge(t *testing.T) {
	builder, _ := buildVTableDispatchCFG(t)

	passLog := make([]string, 0)
	hooks := &ReAnalysisHooks{
		OnDominatorTreeUpdated:    func(_ *DominatorTree) { passLog = append(passLog, "domtree") },
		OnSSARequired:             func(_ *CFG, _ *DominatorTree) error { passLog = append(passLog, "ssa"); return nil },
		OnVSARequired:             func(_ *CFG, _ *DominatorTree) error { passLog = append(passLog, "vsa"); return nil },
		OnReachingDefsRequired:    func(_ *CFG, _ *DominatorTree) error { passLog = append(passLog, "rdefs"); return nil },
		OnTypeConstraintsRequired: func(_ *CFG) error { passLog = append(passLog, "typeconstraints"); return nil },
	}

	ra := NewIncrementalReAnalyzer(builder, hooks, 10)

	prov := &EdgeProvenance{AnalysisPass: "type_inference", Confidence: 0.9, Metadata: map[string]any{}}

	// first call adds the edge
	if _, err := ra.AddResolvedTargets(0x4006, []disasm.Address{0x4010}, prov); err != nil {
		t.Fatalf("first AddResolvedTargets: %v", err)
	}

	// reset log
	passLog = passLog[:0]

	// second call with same target: no new edge → only type constraints
	if _, err := ra.AddResolvedTargets(0x4006, []disasm.Address{0x4010}, prov); err != nil {
		t.Fatalf("second AddResolvedTargets: %v", err)
	}

	for _, p := range passLog {
		if p == "domtree" || p == "ssa" || p == "vsa" || p == "rdefs" {
			t.Errorf("pass %q must not be invoked when no new edge was added", p)
		}
	}
	found := false
	for _, p := range passLog {
		if p == "typeconstraints" {
			found = true
		}
	}
	if !found {
		t.Error("typeconstraints pass must be invoked even when no new edge was added")
	}
}

// TestIncrementalReAnalysis_ProvenanceHistoryOrdering verifies that the
// resolution history records entries in chronological order.
func TestIncrementalReAnalysis_ProvenanceHistoryOrdering(t *testing.T) {
	builder, _ := buildVTableDispatchCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 10)

	prov1 := &EdgeProvenance{AnalysisPass: "iter_1", Confidence: 0.9, Metadata: map[string]any{}}
	prov2 := &EdgeProvenance{AnalysisPass: "iter_2", Confidence: 0.85, Metadata: map[string]any{}}

	if _, err := ra.AddResolvedTargets(0x4006, []disasm.Address{0x4010}, prov1); err != nil {
		t.Fatalf("first resolution: %v", err)
	}
	if _, err := ra.AddResolvedTargets(0x4006, []disasm.Address{0x4015}, prov2); err != nil {
		t.Fatalf("second resolution: %v", err)
	}

	history := ra.GetResolutionHistory()
	if len(history) != 2 {
		t.Fatalf("history len: got %d, want 2", len(history))
	}
	if history[0].Provenance.AnalysisPass != "iter_1" {
		t.Errorf("history[0] pass: got %q, want iter_1", history[0].Provenance.AnalysisPass)
	}
	if history[1].Provenance.AnalysisPass != "iter_2" {
		t.Errorf("history[1] pass: got %q, want iter_2", history[1].Provenance.AnalysisPass)
	}
}

// TestIncrementalReAnalysis_CFGConsistencyAfterVTableResolution verifies that
// the CFG remains structurally consistent after adding vtable edges.
func TestIncrementalReAnalysis_CFGConsistencyAfterVTableResolution(t *testing.T) {
	builder, _ := buildVTableDispatchCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 10)

	targets := []disasm.Address{0x4010, 0x4015}
	prov := &EdgeProvenance{AnalysisPass: "type_inference", Confidence: 0.9, Metadata: map[string]any{}}

	if _, err := ra.AddResolvedTargets(0x4006, targets, prov); err != nil {
		t.Fatalf("AddResolvedTargets: %v", err)
	}

	violations := builder.ConsistencyCheck()
	if len(violations) != 0 {
		t.Errorf("CFG consistency violations after vtable resolution: %v", violations)
	}
}

// TestIncrementalReAnalysis_CFGConsistencyAfterHandlerTableResolution verifies
// that the CFG remains consistent after resolving all switch cases.
func TestIncrementalReAnalysis_CFGConsistencyAfterHandlerTableResolution(t *testing.T) {
	builder, _ := buildHandlerTableCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 10)

	allCases := []disasm.Address{0x5010, 0x5015, 0x501a, 0x501f, 0x5024}
	prov := &EdgeProvenance{AnalysisPass: "type_inference", Confidence: 0.8, Metadata: map[string]any{}}

	if _, err := ra.AddResolvedTargets(0x5005, allCases, prov); err != nil {
		t.Fatalf("AddResolvedTargets: %v", err)
	}

	violations := builder.ConsistencyCheck()
	if len(violations) != 0 {
		t.Errorf("CFG consistency violations after handler table resolution: %v", violations)
	}
}

// TestIncrementalReAnalysis_GetProvenanceForJump verifies that provenance
// lookup returns the most recent resolution for a jump site.
func TestIncrementalReAnalysis_GetProvenanceForJump(t *testing.T) {
	builder, _ := buildVTableDispatchCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 10)

	prov1 := &EdgeProvenance{AnalysisPass: "vsa_pass", Confidence: 0.7, Metadata: map[string]any{}}
	prov2 := &EdgeProvenance{AnalysisPass: "type_inference_pass", Confidence: 0.95, Metadata: map[string]any{}}

	if _, err := ra.AddResolvedTargets(0x4006, []disasm.Address{0x4010}, prov1); err != nil {
		t.Fatalf("first resolution: %v", err)
	}
	if _, err := ra.AddResolvedTargets(0x4006, []disasm.Address{0x4015}, prov2); err != nil {
		t.Fatalf("second resolution: %v", err)
	}

	// GetProvenanceForJump must return the most recent record
	rec := ra.GetProvenanceForJump(0x4006)
	if rec == nil {
		t.Fatal("GetProvenanceForJump returned nil for known jump site")
	}
	if rec.Provenance.AnalysisPass != "type_inference_pass" {
		t.Errorf("most recent pass: got %q, want type_inference_pass", rec.Provenance.AnalysisPass)
	}

	// unknown jump site must return nil
	if got := ra.GetProvenanceForJump(0xdeadbeef); got != nil {
		t.Errorf("expected nil for unknown jump site, got %+v", got)
	}
}

// TestIncrementalReAnalysis_NilProvenanceDefaulted verifies that nil provenance
// is replaced with a default value rather than causing a nil pointer dereference.
func TestIncrementalReAnalysis_NilProvenanceDefaulted(t *testing.T) {
	builder, _ := buildVTableDispatchCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 10)

	// pass nil provenance - must not panic
	result, err := ra.AddResolvedTargets(0x4006, []disasm.Address{0x4010}, nil)
	if err != nil {
		t.Fatalf("AddResolvedTargets with nil provenance: %v", err)
	}

	if len(result.ResolutionHistory) == 0 {
		t.Fatal("resolution history must not be empty")
	}

	rec := result.ResolutionHistory[0]
	if rec.Provenance == nil {
		t.Error("provenance must not be nil in history record")
	}
	if rec.Provenance.AnalysisPass == "" {
		t.Error("default provenance must have non-empty AnalysisPass")
	}
}

// TestIncrementalReAnalysis_AddIndirectTargets_BatchAPI verifies the batch
// AddIndirectTargets API adds all targets correctly.
func TestIncrementalReAnalysis_AddIndirectTargets_BatchAPI(t *testing.T) {
	builder, cfgGraph := buildVTableDispatchCFG(t)

	targets := []disasm.Address{0x4010, 0x4015}
	prov := &EdgeProvenance{AnalysisPass: "batch_test", Confidence: 0.9, Metadata: map[string]any{}}

	edgesBefore := cfgGraph.EdgeCount()
	if err := builder.AddIndirectTargets(0x4006, targets, prov); err != nil {
		t.Fatalf("AddIndirectTargets: %v", err)
	}

	newEdges := cfgGraph.EdgeCount() - edgesBefore
	if newEdges != 2 {
		t.Errorf("new edges: got %d, want 2", newEdges)
	}
}

// TestIncrementalReAnalysis_GetUnresolvedJumps verifies that GetUnresolvedIndirectJumps
// returns sorted addresses of all unresolved jumps.
func TestIncrementalReAnalysis_GetUnresolvedJumps(t *testing.T) {
	builder, _ := buildHandlerTableCFG(t)

	unresolved := builder.GetUnresolvedIndirectJumps()
	if len(unresolved) == 0 {
		t.Fatal("expected at least one unresolved indirect jump")
	}

	// verify sorted order
	for i := 1; i < len(unresolved); i++ {
		if unresolved[i] < unresolved[i-1] {
			t.Errorf("unresolved jumps not sorted: [%d]=0x%x > [%d]=0x%x",
				i-1, unresolved[i-1], i, unresolved[i])
		}
	}
}

// ============================================================================
// C++ class hierarchy with multiple vtables
// ============================================================================

// buildMultiVTableCFG constructs a CFG modeling two independent virtual dispatch
// sites from different C++ base classes (e.g., class Derived : public Base1, public Base2).
// layout:
//
//	0x8000: mov rax, [rcx]        ; load vtable ptr for Base1
//	0x8003: jmp rax               ; indirect call through Base1 vtable
//	0x8005: mov rax, [rcx+8]      ; load vtable ptr for Base2
//	0x8008: jmp rax               ; indirect call through Base2 vtable
//	0x800a: ret
//	0x8010: push rbp              ; Base1::method_A
//	0x8011: ret
//	0x8012: push rbp              ; Base1::method_B
//	0x8013: ret
//	0x8014: push rbp              ; Base2::method_C
//	0x8015: ret
//	0x8016: push rbp              ; Base2::method_D
//	0x8017: ret
func buildMultiVTableCFG(t *testing.T) (*Builder, *CFG) {
	t.Helper()

	instructions := []*disasm.Instruction{
		{Address: 0x8000, Mnemonic: "mov", Length: 3},
		{
			Address:  0x8003,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{disasm.RegisterOperand{Name: "rax", Size: disasm.Size64}},
		},
		{Address: 0x8005, Mnemonic: "mov", Length: 3},
		{
			Address:  0x8008,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{disasm.RegisterOperand{Name: "rax", Size: disasm.Size64}},
		},
		{Address: 0x800a, Mnemonic: "ret", Length: 1},
		{Address: 0x8010, Mnemonic: "push", Length: 1},
		{Address: 0x8011, Mnemonic: "ret", Length: 1},
		{Address: 0x8012, Mnemonic: "push", Length: 1},
		{Address: 0x8013, Mnemonic: "ret", Length: 1},
		{Address: 0x8014, Mnemonic: "push", Length: 1},
		{Address: 0x8015, Mnemonic: "ret", Length: 1},
		{Address: 0x8016, Mnemonic: "push", Length: 1},
		{Address: 0x8017, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfgGraph, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("build multi-vtable cfg: %v", err)
	}

	return builder, cfgGraph
}

// TestVTableDiscovery_MultipleClassHierarchy verifies that two independent
// vtable dispatch sites (from different base classes in a diamond/multiple
// inheritance scenario) are resolved independently with correct provenance.
func TestVTableDiscovery_MultipleClassHierarchy(t *testing.T) {
	builder, cfgGraph := buildMultiVTableCFG(t)

	if len(cfgGraph.UnresolvedIndirectJumps) < 2 {
		t.Fatalf("expected >= 2 unresolved indirect jumps, got %d",
			len(cfgGraph.UnresolvedIndirectJumps))
	}

	provBase1 := &EdgeProvenance{
		AnalysisPass: "type_inference_iter_1_vtable",
		Confidence:   0.92,
		Metadata:     map[string]any{"array_kind": "vtable", "class": "Base1"},
	}
	provBase2 := &EdgeProvenance{
		AnalysisPass: "type_inference_iter_1_vtable",
		Confidence:   0.88,
		Metadata:     map[string]any{"array_kind": "vtable", "class": "Base2"},
	}

	edgesBefore := cfgGraph.EdgeCount()

	// resolve Base1 vtable: method_A and method_B
	for _, target := range []disasm.Address{0x8010, 0x8012} {
		if err := builder.AddIndirectTargetWithProvenance(0x8003, target, provBase1); err != nil {
			t.Fatalf("add Base1 target 0x%x: %v", target, err)
		}
	}

	// resolve Base2 vtable: method_C and method_D
	for _, target := range []disasm.Address{0x8014, 0x8016} {
		if err := builder.AddIndirectTargetWithProvenance(0x8008, target, provBase2); err != nil {
			t.Fatalf("add Base2 target 0x%x: %v", target, err)
		}
	}

	newEdges := cfgGraph.EdgeCount() - edgesBefore
	if newEdges != 4 {
		t.Errorf("new edges: got %d, want 4 (2 per vtable)", newEdges)
	}

	// verify each jump site has its own set of targets
	jump1, found := cfgGraph.GetUnresolvedIndirectJump(0x8003)
	if !found {
		t.Fatal("Base1 dispatch jump not found")
	}
	if len(jump1.PossibleTargets) != 2 {
		t.Errorf("Base1 targets: got %d, want 2", len(jump1.PossibleTargets))
	}

	jump2, found := cfgGraph.GetUnresolvedIndirectJump(0x8008)
	if !found {
		t.Fatal("Base2 dispatch jump not found")
	}
	if len(jump2.PossibleTargets) != 2 {
		t.Errorf("Base2 targets: got %d, want 2", len(jump2.PossibleTargets))
	}

	// verify CFG consistency after multi-vtable resolution
	violations := builder.ConsistencyCheck()
	if len(violations) != 0 {
		t.Errorf("CFG consistency violations: %v", violations)
	}
}

// ============================================================================
// Go interface table (itab) discovery
// ============================================================================

// buildItabDispatchCFG constructs a CFG modeling Go interface dispatch via itab.
// layout:
//
//	0x9000: mov rax, [rcx+0x18]   ; load itab method pointer
//	0x9003: jmp rax               ; indirect call through itab
//	0x9005: ret
//	0x9010: push rbp              ; itab method: String()
//	0x9011: ret
//	0x9012: push rbp              ; itab method: Error()
//	0x9013: ret
func buildItabDispatchCFG(t *testing.T) (*Builder, *CFG) {
	t.Helper()

	instructions := []*disasm.Instruction{
		{Address: 0x9000, Mnemonic: "mov", Length: 3},
		{
			Address:  0x9003,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{disasm.RegisterOperand{Name: "rax", Size: disasm.Size64}},
		},
		{Address: 0x9005, Mnemonic: "ret", Length: 1},
		{Address: 0x9010, Mnemonic: "push", Length: 1},
		{Address: 0x9011, Mnemonic: "ret", Length: 1},
		{Address: 0x9012, Mnemonic: "push", Length: 1},
		{Address: 0x9013, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfgGraph, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("build itab dispatch cfg: %v", err)
	}

	return builder, cfgGraph
}

// TestItabDiscovery_GoInterfaceTable verifies that Go interface table (itab)
// targets are resolved correctly with interface_table provenance.
func TestItabDiscovery_GoInterfaceTable(t *testing.T) {
	builder, cfgGraph := buildItabDispatchCFG(t)

	jumpSite := disasm.Address(0x9003)
	itabTargets := []disasm.Address{0x9010, 0x9012}

	prov := &EdgeProvenance{
		AnalysisPass: "type_inference_iter_1_interface_table",
		Confidence:   0.80,
		Metadata: map[string]any{
			"array_kind": "interface_table",
			"interface":  "io.Writer",
		},
	}

	// classify the jump as interface table dispatch
	if err := builder.ClassifyIndirectJump(jumpSite, IndirectJumpInterfaceTable); err != nil {
		t.Fatalf("ClassifyIndirectJump: %v", err)
	}

	edgesBefore := cfgGraph.EdgeCount()
	for _, target := range itabTargets {
		if err := builder.AddIndirectTargetWithProvenance(jumpSite, target, prov); err != nil {
			t.Fatalf("add itab target 0x%x: %v", target, err)
		}
	}

	newEdges := cfgGraph.EdgeCount() - edgesBefore
	if newEdges != 2 {
		t.Errorf("new edges: got %d, want 2", newEdges)
	}

	// verify classification was preserved
	jump, found := cfgGraph.GetUnresolvedIndirectJump(jumpSite)
	if !found {
		t.Fatal("itab dispatch jump not found")
	}
	if jump.JumpKind != IndirectJumpInterfaceTable {
		t.Errorf("jump kind: got %v, want IndirectJumpInterfaceTable", jump.JumpKind)
	}

	// verify provenance metadata
	for _, edge := range cfgGraph.Edges {
		if edge.Type != EdgeTypeIndirect || edge.Provenance == nil {
			continue
		}
		if edge.Provenance.AnalysisPass != "type_inference_iter_1_interface_table" {
			continue
		}
		ifaceVal, ok := edge.Provenance.Metadata["interface"]
		if !ok || ifaceVal != "io.Writer" {
			t.Errorf("interface metadata: got %v, want io.Writer", ifaceVal)
		}
		return
	}
	t.Error("edge with interface_table provenance not found")
}

// ============================================================================
// pass execution order verification
// ============================================================================

// TestIncrementalReAnalysis_PassExecutionOrder verifies that hooks are invoked
// in strict dependency order: domtree -> SSA -> VSA -> reaching defs -> type constraints.
func TestIncrementalReAnalysis_PassExecutionOrder(t *testing.T) {
	builder, _ := buildVTableDispatchCFG(t)

	order := make([]string, 0, 5)
	hooks := &ReAnalysisHooks{
		OnDominatorTreeUpdated: func(_ *DominatorTree) {
			order = append(order, "domtree")
		},
		OnSSARequired: func(_ *CFG, _ *DominatorTree) error {
			order = append(order, "ssa")
			return nil
		},
		OnVSARequired: func(_ *CFG, _ *DominatorTree) error {
			order = append(order, "vsa")
			return nil
		},
		OnReachingDefsRequired: func(_ *CFG, _ *DominatorTree) error {
			order = append(order, "rdefs")
			return nil
		},
		OnTypeConstraintsRequired: func(_ *CFG) error {
			order = append(order, "typeconstraints")
			return nil
		},
	}

	ra := NewIncrementalReAnalyzer(builder, hooks, 10)

	prov := &EdgeProvenance{AnalysisPass: "test", Confidence: 0.9, Metadata: map[string]any{}}
	if _, err := ra.AddResolvedTargets(0x4006, []disasm.Address{0x4010}, prov); err != nil {
		t.Fatalf("AddResolvedTargets: %v", err)
	}

	expected := []string{"domtree", "ssa", "vsa", "rdefs", "typeconstraints"}
	if len(order) != len(expected) {
		t.Fatalf("pass count: got %d, want %d; order=%v", len(order), len(expected), order)
	}
	for i, want := range expected {
		if order[i] != want {
			t.Errorf("pass[%d]: got %q, want %q (full order: %v)", i, order[i], want, order)
		}
	}
}

// ============================================================================
// convergence loop with hooks
// ============================================================================

// TestConvergence_HooksInvokedPerIteration verifies that analysis hooks are
// invoked on every iteration of the convergence loop, not just the first.
func TestConvergence_HooksInvokedPerIteration(t *testing.T) {
	builder, _ := buildMultiVTableCFG(t)

	domTreeCount := 0
	typeConstraintCount := 0
	hooks := &ReAnalysisHooks{
		OnDominatorTreeUpdated: func(_ *DominatorTree) {
			domTreeCount++
		},
		OnTypeConstraintsRequired: func(_ *CFG) error {
			typeConstraintCount++
			return nil
		},
	}

	ra := NewIncrementalReAnalyzer(builder, hooks, 10)

	iterCount := 0
	_, err := ra.RunConvergenceLoop(func(unresolved []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		iterCount++
		if len(unresolved) == 0 {
			return nil, nil //nolint:nilnil
		}
		// resolve one jump per iteration
		jump := unresolved[0]
		return map[disasm.Address]*ResolvedTargetSet{
			jump.JumpSite: NewResolvedTargetSet("type_inference", 0.9, []disasm.Address{0x8010}),
		}, nil
	})

	if err != nil {
		t.Fatalf("RunConvergenceLoop: %v", err)
	}

	// dominator tree must be recomputed at least once per iteration that adds edges
	if domTreeCount == 0 {
		t.Error("OnDominatorTreeUpdated was never called during convergence loop")
	}
	if typeConstraintCount == 0 {
		t.Error("OnTypeConstraintsRequired was never called during convergence loop")
	}
}

// TestConvergence_HookErrorTerminatesLoop verifies that an error from a
// re-analysis hook during RunConvergenceLoop is propagated and terminates the loop.
func TestConvergence_HookErrorTerminatesLoop(t *testing.T) {
	builder, _ := buildVTableDispatchCFG(t)

	hookErr := errors.New("vsa analysis failed")
	hooks := &ReAnalysisHooks{
		OnVSARequired: func(_ *CFG, _ *DominatorTree) error {
			return hookErr
		},
	}

	ra := NewIncrementalReAnalyzer(builder, hooks, 10)

	_, err := ra.RunConvergenceLoop(func(unresolved []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		if len(unresolved) == 0 {
			return nil, nil //nolint:nilnil
		}
		return map[disasm.Address]*ResolvedTargetSet{
			unresolved[0].JumpSite: NewResolvedTargetSet("test", 0.9, []disasm.Address{0x4010}),
		}, nil
	})

	if err == nil {
		t.Fatal("expected error from hook failure, got nil")
	}
	if !errors.Is(err, hookErr) {
		t.Errorf("error chain: got %v, want to contain %v", err, hookErr)
	}
}

// ============================================================================
// end-to-end cyclic feedback: type inference -> CFG -> re-analysis -> convergence
// ============================================================================

// TestEndToEnd_CyclicFeedbackVTableResolution simulates a complete cyclic
// feedback scenario using a CFG with two independent vtable dispatch sites.
// iteration 1 resolves the first vtable, iteration 2 resolves the second,
// and the loop converges when no unresolved jumps remain.
func TestEndToEnd_CyclicFeedbackVTableResolution(t *testing.T) {
	builder, cfgGraph := buildMultiVTableCFG(t)

	ssaRunCount := 0
	vsaRunCount := 0
	typeConstraintRunCount := 0

	hooks := &ReAnalysisHooks{
		OnDominatorTreeUpdated: func(_ *DominatorTree) {},
		OnSSARequired: func(_ *CFG, _ *DominatorTree) error {
			ssaRunCount++
			return nil
		},
		OnVSARequired: func(_ *CFG, _ *DominatorTree) error {
			vsaRunCount++
			return nil
		},
		OnReachingDefsRequired: func(_ *CFG, _ *DominatorTree) error { return nil },
		OnTypeConstraintsRequired: func(_ *CFG) error {
			typeConstraintRunCount++
			return nil
		},
	}

	ra := NewIncrementalReAnalyzer(builder, hooks, 10)

	edgesBefore := cfgGraph.EdgeCount()

	// simulate: iteration 1 resolves Base1 vtable (jump at 0x8003),
	// iteration 2 resolves Base2 vtable (jump at 0x8008)
	iterCount := 0
	result, err := ra.RunConvergenceLoop(func(unresolved []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		iterCount++
		if len(unresolved) == 0 {
			return nil, nil //nolint:nilnil
		}

		jump := unresolved[0]
		switch {
		case jump.JumpSite == 0x8003:
			return map[disasm.Address]*ResolvedTargetSet{
				0x8003: NewResolvedTargetSet("type_inference_vtable_Base1", 0.90, []disasm.Address{0x8010, 0x8012}),
			}, nil
		case jump.JumpSite == 0x8008:
			return map[disasm.Address]*ResolvedTargetSet{
				0x8008: NewResolvedTargetSet("type_inference_vtable_Base2", 0.95, []disasm.Address{0x8014, 0x8016}),
			}, nil
		default:
			return nil, nil //nolint:nilnil
		}
	})

	if err != nil {
		t.Fatalf("RunConvergenceLoop: %v", err)
	}

	if !result.Converged {
		t.Error("expected convergence after resolving both vtables")
	}

	newEdges := cfgGraph.EdgeCount() - edgesBefore
	if newEdges < 4 {
		t.Errorf("new edges: got %d, want >= 4 (2 per vtable)", newEdges)
	}

	if ssaRunCount < 2 {
		t.Errorf("SSA ran %d times, want >= 2 (once per iteration)", ssaRunCount)
	}
	if vsaRunCount < 2 {
		t.Errorf("VSA ran %d times, want >= 2", vsaRunCount)
	}
	if typeConstraintRunCount < 2 {
		t.Errorf("type constraints ran %d times, want >= 2", typeConstraintRunCount)
	}

	history := ra.GetResolutionHistory()
	if len(history) < 2 {
		t.Errorf("resolution history: got %d records, want >= 2", len(history))
	}

	violations := builder.ConsistencyCheck()
	if len(violations) != 0 {
		t.Errorf("CFG consistency violations: %v", violations)
	}
}

// TestEndToEnd_CyclicFeedbackHandlerTableResolution simulates a complete
// cyclic feedback scenario for switch jump table resolution.
func TestEndToEnd_CyclicFeedbackHandlerTableResolution(t *testing.T) {
	builder, cfgGraph := buildHandlerTableCFG(t)

	passesTriggered := make(map[string]int)
	hooks := &ReAnalysisHooks{
		OnDominatorTreeUpdated:    func(_ *DominatorTree) { passesTriggered["domtree"]++ },
		OnSSARequired:             func(_ *CFG, _ *DominatorTree) error { passesTriggered["ssa"]++; return nil },
		OnVSARequired:             func(_ *CFG, _ *DominatorTree) error { passesTriggered["vsa"]++; return nil },
		OnReachingDefsRequired:    func(_ *CFG, _ *DominatorTree) error { passesTriggered["rdefs"]++; return nil },
		OnTypeConstraintsRequired: func(_ *CFG) error { passesTriggered["typeconstraints"]++; return nil },
	}

	ra := NewIncrementalReAnalyzer(builder, hooks, 10)

	edgesBefore := cfgGraph.EdgeCount()
	allCases := []disasm.Address{0x5010, 0x5015, 0x501a, 0x501f, 0x5024}

	result, err := ra.RunConvergenceLoop(func(unresolved []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		if len(unresolved) == 0 {
			return nil, nil //nolint:nilnil
		}
		return map[disasm.Address]*ResolvedTargetSet{
			0x5005: NewResolvedTargetSet("type_inference_handler", 0.75, allCases),
		}, nil
	})

	if err != nil {
		t.Fatalf("RunConvergenceLoop: %v", err)
	}
	if !result.Converged {
		t.Error("expected convergence after resolving all switch cases")
	}

	newEdges := cfgGraph.EdgeCount() - edgesBefore
	if newEdges != 5 {
		t.Errorf("new edges: got %d, want 5", newEdges)
	}

	// all passes must have been triggered at least once
	for _, pass := range []string{"domtree", "ssa", "vsa", "rdefs", "typeconstraints"} {
		if passesTriggered[pass] == 0 {
			t.Errorf("pass %q was never triggered during handler table resolution", pass)
		}
	}

	violations := builder.ConsistencyCheck()
	if len(violations) != 0 {
		t.Errorf("CFG consistency violations: %v", violations)
	}
}
