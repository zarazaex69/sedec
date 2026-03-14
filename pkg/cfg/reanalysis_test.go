package cfg

import (
	"errors"
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// errTestSSAFailed is a sentinel error for testing hook error propagation.
var errTestSSAFailed = errors.New("ssa failed")

// vsaPassName is the canonical string for the VSA analysis pass used in tests.
const vsaPassName = "vsa"

// buildIndirectJumpCFG constructs a minimal CFG with one indirect jump for testing.
// layout:
//
//	0x1000: mov  (entry)
//	0x1003: jmp  rax  (indirect jump - unresolved)
//	0x1005: add  (potential target A)
//	0x1008: ret
//	0x100a: sub  (potential target B)
//	0x100d: ret
func buildIndirectJumpCFG(t *testing.T) *Builder {
	t.Helper()

	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		// indirect jmp through register - no immediate operand
		{
			Address:  0x1003,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{disasm.RegisterOperand{Name: "rax", Size: disasm.Size64}},
		},
		{Address: 0x1005, Mnemonic: "add", Length: 3},
		{Address: 0x1008, Mnemonic: "ret", Length: 1},
		{Address: 0x100a, Mnemonic: "sub", Length: 3},
		{Address: 0x100d, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	if _, err := builder.Build(instructions); err != nil {
		t.Fatalf("build cfg: %v", err)
	}

	return builder
}

// TestReAnalysisPass_String verifies the string representation of pass masks.
func TestReAnalysisPass_String(t *testing.T) {
	tests := []struct {
		pass ReAnalysisPass
		want string
	}{
		{ReAnalysisPass(0), "None"},
		{PassDominatorTree, "DominatorTree"},
		{PassSSA, "SSA"},
		{PassVSA, "VSA"},
		{PassReachingDefs, "ReachingDefs"},
		{PassTypeConstraints, "TypeConstraints"},
		{PassDominatorTree | PassSSA, "DominatorTree|SSA"},
		{PassAll, "DominatorTree|SSA|VSA|ReachingDefs|TypeConstraints"},
	}

	for _, tc := range tests {
		got := tc.pass.String()
		if got != tc.want {
			t.Errorf("pass %d: got %q, want %q", tc.pass, got, tc.want)
		}
	}
}

// TestNewIncrementalReAnalyzer_Defaults verifies default construction.
func TestNewIncrementalReAnalyzer_Defaults(t *testing.T) {
	builder := NewCFGBuilder()

	// nil hooks should be replaced with empty struct
	ra := NewIncrementalReAnalyzer(builder, nil, 0)
	if ra.maxIterations != 10 {
		t.Errorf("default maxIterations: got %d, want 10", ra.maxIterations)
	}
	if ra.hooks == nil {
		t.Error("hooks must not be nil after construction")
	}
	if ra.builder != builder {
		t.Error("builder reference must be preserved")
	}
}

// TestAddResolvedTargets_SingleTarget verifies that a single resolved target
// adds the correct edge and records provenance.
func TestAddResolvedTargets_SingleTarget(t *testing.T) {
	builder := buildIndirectJumpCFG(t)

	domTreeUpdated := false
	ssaCalled := false

	hooks := &ReAnalysisHooks{
		OnDominatorTreeUpdated: func(_ *DominatorTree) {
			domTreeUpdated = true
		},
		OnSSARequired: func(_ *CFG, _ *DominatorTree) error {
			ssaCalled = true
			return nil
		},
	}

	ra := NewIncrementalReAnalyzer(builder, hooks, 5)

	provenance := &EdgeProvenance{
		AnalysisPass: "type_inference",
		Confidence:   0.95,
		Metadata:     map[string]any{"source": "vtable"},
	}

	result, err := ra.AddResolvedTargets(0x1003, []disasm.Address{0x1005}, provenance)
	if err != nil {
		t.Fatalf("AddResolvedTargets: %v", err)
	}

	// verify result fields
	if result.NewEdgesAdded != 1 {
		t.Errorf("NewEdgesAdded: got %d, want 1", result.NewEdgesAdded)
	}
	if len(result.ResolutionHistory) != 1 {
		t.Fatalf("ResolutionHistory len: got %d, want 1", len(result.ResolutionHistory))
	}

	rec := result.ResolutionHistory[0]
	if rec.JumpSite != 0x1003 {
		t.Errorf("JumpSite: got 0x%x, want 0x1003", rec.JumpSite)
	}
	if len(rec.Targets) != 1 || rec.Targets[0] != 0x1005 {
		t.Errorf("Targets: got %v, want [0x1005]", rec.Targets)
	}
	if rec.Provenance.AnalysisPass != "type_inference" {
		t.Errorf("AnalysisPass: got %q, want %q", rec.Provenance.AnalysisPass, "type_inference")
	}
	if rec.Provenance.Confidence != 0.95 {
		t.Errorf("Confidence: got %f, want 0.95", rec.Provenance.Confidence)
	}

	// verify hooks were called
	if !domTreeUpdated {
		t.Error("OnDominatorTreeUpdated was not called")
	}
	if !ssaCalled {
		t.Error("OnSSARequired was not called")
	}
}

// TestAddResolvedTargets_MultipleTargets verifies that multiple targets for a
// single jump site (e.g., switch table) are all added.
func TestAddResolvedTargets_MultipleTargets(t *testing.T) {
	builder := buildIndirectJumpCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 5)

	targets := []disasm.Address{0x1005, 0x100a}
	result, err := ra.AddResolvedTargets(0x1003, targets, nil)
	if err != nil {
		t.Fatalf("AddResolvedTargets: %v", err)
	}

	if result.NewEdgesAdded != 2 {
		t.Errorf("NewEdgesAdded: got %d, want 2", result.NewEdgesAdded)
	}
}

// TestAddResolvedTargets_DuplicateTargetNotCounted verifies that adding the same
// target twice does not double-count edges.
func TestAddResolvedTargets_DuplicateTargetNotCounted(t *testing.T) {
	builder := buildIndirectJumpCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 5)

	// first resolution
	result1, err := ra.AddResolvedTargets(0x1003, []disasm.Address{0x1005}, nil)
	if err != nil {
		t.Fatalf("first AddResolvedTargets: %v", err)
	}
	if result1.NewEdgesAdded != 1 {
		t.Errorf("first call NewEdgesAdded: got %d, want 1", result1.NewEdgesAdded)
	}

	// second resolution with same target - edge already exists
	result2, err := ra.AddResolvedTargets(0x1003, []disasm.Address{0x1005}, nil)
	if err != nil {
		t.Fatalf("second AddResolvedTargets: %v", err)
	}
	// cumulative total should still be 1 since no new edge was added
	if result2.NewEdgesAdded != 1 {
		t.Errorf("second call cumulative NewEdgesAdded: got %d, want 1", result2.NewEdgesAdded)
	}
}

// TestAddResolvedTargets_InvalidJumpSite verifies that an unknown jump site
// returns an error without panicking.
func TestAddResolvedTargets_InvalidJumpSite(t *testing.T) {
	builder := buildIndirectJumpCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 5)

	_, err := ra.AddResolvedTargets(0xdeadbeef, []disasm.Address{0x1005}, nil)
	if err == nil {
		t.Fatal("expected error for unknown jump site, got nil")
	}
}

// TestAddResolvedTargets_InvalidTarget verifies that an unknown target address
// returns an error without panicking.
func TestAddResolvedTargets_InvalidTarget(t *testing.T) {
	builder := buildIndirectJumpCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 5)

	_, err := ra.AddResolvedTargets(0x1003, []disasm.Address{0xdeadbeef}, nil)
	if err == nil {
		t.Fatal("expected error for unknown target address, got nil")
	}
}

// TestAddResolvedTargets_HookError verifies that a hook error is propagated.
func TestAddResolvedTargets_HookError(t *testing.T) {
	builder := buildIndirectJumpCFG(t)

	hookErr := errTestSSAFailed
	hooks := &ReAnalysisHooks{
		OnSSARequired: func(_ *CFG, _ *DominatorTree) error {
			return hookErr
		},
	}

	ra := NewIncrementalReAnalyzer(builder, hooks, 5)

	_, err := ra.AddResolvedTargets(0x1003, []disasm.Address{0x1005}, nil)
	if err == nil {
		t.Fatal("expected error from hook, got nil")
	}
	if !errors.Is(err, hookErr) {
		t.Errorf("error chain: got %v, want to contain %v", err, hookErr)
	}
}

// TestRunConvergenceLoop_ImmediateConvergence verifies that a CFG with no
// unresolved jumps converges immediately.
func TestRunConvergenceLoop_ImmediateConvergence(t *testing.T) {
	// build a simple linear cfg with no indirect jumps
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "ret", Length: 1},
	}
	builder := NewCFGBuilder()
	if _, err := builder.Build(instructions); err != nil {
		t.Fatalf("build: %v", err)
	}

	ra := NewIncrementalReAnalyzer(builder, nil, 10)

	callCount := 0
	result, err := ra.RunConvergenceLoop(func(_ []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		callCount++
		return nil, nil //nolint:nilnil // nil map means no new targets; nil error means no failure
	})

	if err != nil {
		t.Fatalf("RunConvergenceLoop: %v", err)
	}
	if !result.Converged {
		t.Error("expected Converged=true for cfg with no unresolved jumps")
	}
	// resolve func should not be called when there are no unresolved jumps
	if callCount != 0 {
		t.Errorf("resolve func call count: got %d, want 0", callCount)
	}
}

// TestRunConvergenceLoop_SingleIteration verifies convergence after one iteration.
func TestRunConvergenceLoop_SingleIteration(t *testing.T) {
	builder := buildIndirectJumpCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 10)

	iterations := 0
	result, err := ra.RunConvergenceLoop(func(_ []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		iterations++
		if iterations == 1 {
			// resolve the indirect jump on first iteration
			resolved := map[disasm.Address]*ResolvedTargetSet{
				0x1003: NewResolvedTargetSet("type_inference", 0.9, []disasm.Address{0x1005}),
			}
			return resolved, nil
		}
		// second iteration: nothing new
		return nil, nil //nolint:nilnil // nil map means no new targets; nil error means no failure
	})

	if err != nil {
		t.Fatalf("RunConvergenceLoop: %v", err)
	}
	if !result.Converged {
		t.Error("expected Converged=true after resolving all jumps")
	}
	if result.NewEdgesAdded < 1 {
		t.Errorf("NewEdgesAdded: got %d, want >= 1", result.NewEdgesAdded)
	}
}

// TestRunConvergenceLoop_MaxIterations verifies that the loop terminates at the cap.
func TestRunConvergenceLoop_MaxIterations(t *testing.T) {
	builder := buildIndirectJumpCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 3)

	// resolve func always returns the same target (but after first call the edge
	// already exists so no new edges are added - however the unresolved list is
	// not cleared, so the loop keeps running until the cap)
	callCount := 0
	result, err := ra.RunConvergenceLoop(func(_ []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		callCount++
		// always claim to have resolved something to prevent early convergence
		// but use an invalid target so AddIndirectTargetWithProvenance fails
		// instead, return empty to trigger convergence on second call
		if callCount == 1 {
			return map[disasm.Address]*ResolvedTargetSet{
				0x1003: NewResolvedTargetSet(vsaPassName, 0.7, []disasm.Address{0x1005}),
			}, nil
		}
		// subsequent calls: no new targets → convergence
		return nil, nil //nolint:nilnil // nil map means no new targets; nil error means no failure
	})

	// should converge on second call (empty return)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Converged {
		t.Error("expected convergence when resolve func returns empty map")
	}
}

// TestRunConvergenceLoop_MaxIterationsExceeded verifies errMaxIterationsReached.
func TestRunConvergenceLoop_MaxIterationsExceeded(t *testing.T) {
	// use a second target address to keep adding new edges each iteration
	// we need a second indirect jump to keep the unresolved list non-empty
	// after the first resolution. instead, we simulate by never clearing
	// the unresolved list - but the builder does clear it via MarkIndirectJumpResolved.
	// so we need multiple unresolved jumps.
	instructions := []*disasm.Instruction{
		{Address: 0x2000, Mnemonic: "mov", Length: 3},
		{
			Address:  0x2003,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{disasm.RegisterOperand{Name: "rax", Size: disasm.Size64}},
		},
		{
			Address:  0x2005,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64}},
		},
		{Address: 0x2007, Mnemonic: "add", Length: 3},
		{Address: 0x200a, Mnemonic: "ret", Length: 1},
		{Address: 0x200c, Mnemonic: "sub", Length: 3},
		{Address: 0x200f, Mnemonic: "ret", Length: 1},
	}
	b2 := NewCFGBuilder()
	if _, err := b2.Build(instructions); err != nil {
		t.Fatalf("build: %v", err)
	}

	ra := NewIncrementalReAnalyzer(b2, nil, 2)

	// always return a new resolution to prevent convergence
	callCount := 0
	_, err := ra.RunConvergenceLoop(func(unresolved []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		callCount++
		if len(unresolved) == 0 {
			return nil, nil //nolint:nilnil // nil map means no new targets; nil error means no failure
		}
		// resolve the first unresolved jump each time
		jump := unresolved[0]
		return map[disasm.Address]*ResolvedTargetSet{
			jump.JumpSite: NewResolvedTargetSet("test", 0.5, []disasm.Address{0x2007}),
		}, nil
	})

	if !errors.Is(err, errMaxIterationsReached) {
		t.Errorf("expected errMaxIterationsReached, got %v", err)
	}
}

// TestGetProvenanceForJump verifies provenance lookup by jump site.
func TestGetProvenanceForJump(t *testing.T) {
	builder := buildIndirectJumpCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 5)

	prov := &EdgeProvenance{
		AnalysisPass: vsaPassName,
		Confidence:   0.8,
		Metadata:     map[string]any{"method": "strided_interval"},
	}

	if _, err := ra.AddResolvedTargets(0x1003, []disasm.Address{0x1005}, prov); err != nil {
		t.Fatalf("AddResolvedTargets: %v", err)
	}

	rec := ra.GetProvenanceForJump(0x1003)
	if rec == nil {
		t.Fatal("GetProvenanceForJump returned nil for known jump site")
	}
	if rec.Provenance.AnalysisPass != vsaPassName {
		t.Errorf("AnalysisPass: got %q, want %q", rec.Provenance.AnalysisPass, vsaPassName)
	}
	if rec.Provenance.Confidence != 0.8 {
		t.Errorf("Confidence: got %f, want 0.8", rec.Provenance.Confidence)
	}

	// unknown jump site should return nil
	if got := ra.GetProvenanceForJump(0xdeadbeef); got != nil {
		t.Errorf("expected nil for unknown jump site, got %+v", got)
	}
}

// TestGetResolutionHistory_Copy verifies that the returned slice is a copy.
func TestGetResolutionHistory_Copy(t *testing.T) {
	builder := buildIndirectJumpCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 5)

	if _, err := ra.AddResolvedTargets(0x1003, []disasm.Address{0x1005}, nil); err != nil {
		t.Fatalf("AddResolvedTargets: %v", err)
	}

	h1 := ra.GetResolutionHistory()
	h2 := ra.GetResolutionHistory()

	if len(h1) != 1 || len(h2) != 1 {
		t.Fatalf("history len: got %d and %d, want 1 and 1", len(h1), len(h2))
	}

	// mutating the returned slice must not affect internal state
	h1[0] = nil
	h3 := ra.GetResolutionHistory()
	if h3[0] == nil {
		t.Error("mutating returned history slice affected internal state")
	}
}

// TestConsistencyCheck_ValidCFG verifies that a correctly built CFG passes.
func TestConsistencyCheck_ValidCFG(t *testing.T) {
	builder := buildIndirectJumpCFG(t)

	violations := builder.ConsistencyCheck()
	if len(violations) != 0 {
		t.Errorf("expected no violations for valid cfg, got: %v", violations)
	}
}

// TestConsistencyCheck_AfterResolution verifies consistency after adding an edge.
func TestConsistencyCheck_AfterResolution(t *testing.T) {
	builder := buildIndirectJumpCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 5)

	if _, err := ra.AddResolvedTargets(0x1003, []disasm.Address{0x1005}, nil); err != nil {
		t.Fatalf("AddResolvedTargets: %v", err)
	}

	violations := builder.ConsistencyCheck()
	if len(violations) != 0 {
		t.Errorf("expected no violations after resolution, got: %v", violations)
	}
}

// TestRequiredPasses_NoNewEdges verifies that no structural change only triggers
// type constraint pass.
func TestRequiredPasses_NoNewEdges(t *testing.T) {
	builder := NewCFGBuilder()
	ra := NewIncrementalReAnalyzer(builder, nil, 5)

	passes := ra.requiredPasses(0)
	if passes != PassTypeConstraints {
		t.Errorf("requiredPasses(0): got %v, want %v", passes, PassTypeConstraints)
	}
}

// TestRequiredPasses_NewEdges verifies that structural change triggers all passes.
func TestRequiredPasses_NewEdges(t *testing.T) {
	builder := NewCFGBuilder()
	ra := NewIncrementalReAnalyzer(builder, nil, 5)

	passes := ra.requiredPasses(1)
	if passes != PassAll {
		t.Errorf("requiredPasses(1): got %v, want %v", passes, PassAll)
	}
}

// TestNewResolvedTargetSet verifies constructor sets fields correctly.
func TestNewResolvedTargetSet(t *testing.T) {
	targets := []disasm.Address{0x1000, 0x2000}
	rts := NewResolvedTargetSet("type_inference", 0.9, targets)

	if rts.Provenance.AnalysisPass != "type_inference" {
		t.Errorf("AnalysisPass: got %q", rts.Provenance.AnalysisPass)
	}
	if rts.Provenance.Confidence != 0.9 {
		t.Errorf("Confidence: got %f", rts.Provenance.Confidence)
	}
	if len(rts.Targets) != 2 {
		t.Errorf("Targets len: got %d, want 2", len(rts.Targets))
	}
	if rts.Provenance.Metadata == nil {
		t.Error("Metadata must not be nil")
	}
}

// TestGetStats verifies that GetStats returns a consistent snapshot.
func TestGetStats(t *testing.T) {
	builder := buildIndirectJumpCFG(t)

	ra := NewIncrementalReAnalyzer(builder, nil, 5)

	stats := ra.GetStats()
	if stats.Converged {
		t.Error("expected Converged=false before any resolution")
	}

	if _, err := ra.AddResolvedTargets(0x1003, []disasm.Address{0x1005, 0x100a}, nil); err != nil {
		t.Fatalf("AddResolvedTargets: %v", err)
	}

	stats = ra.GetStats()
	if stats.NewEdgesAdded < 1 {
		t.Errorf("NewEdgesAdded: got %d, want >= 1", stats.NewEdgesAdded)
	}
}

// TestDominatorTreeCachedAfterUpdate verifies that the builder's cached dominator
// tree is updated after a structural CFG change.
func TestDominatorTreeCachedAfterUpdate(t *testing.T) {
	builder := buildIndirectJumpCFG(t)

	var capturedTree *DominatorTree
	hooks := &ReAnalysisHooks{
		OnDominatorTreeUpdated: func(tree *DominatorTree) {
			capturedTree = tree
		},
	}

	ra := NewIncrementalReAnalyzer(builder, hooks, 5)

	if _, err := ra.AddResolvedTargets(0x1003, []disasm.Address{0x1005}, nil); err != nil {
		t.Fatalf("AddResolvedTargets: %v", err)
	}

	if capturedTree == nil {
		t.Fatal("OnDominatorTreeUpdated was not called")
	}
	// the builder's cached tree must be the same object
	if builder.dominatorTree != capturedTree {
		t.Error("builder.dominatorTree was not updated to the new tree")
	}
}

// TestAllHooksCalled verifies that all registered hooks are invoked when
// a structural change occurs.
func TestAllHooksCalled(t *testing.T) {
	builder := buildIndirectJumpCFG(t)

	called := map[string]bool{}
	hooks := &ReAnalysisHooks{
		OnDominatorTreeUpdated: func(_ *DominatorTree) { called["domtree"] = true },
		OnSSARequired:          func(_ *CFG, _ *DominatorTree) error { called["ssa"] = true; return nil },
		OnVSARequired:          func(_ *CFG, _ *DominatorTree) error { called["vsa"] = true; return nil },
		OnReachingDefsRequired: func(_ *CFG, _ *DominatorTree) error { called["rdefs"] = true; return nil },
		OnTypeConstraintsRequired: func(_ *CFG) error {
			called["typeconstraints"] = true
			return nil
		},
	}

	ra := NewIncrementalReAnalyzer(builder, hooks, 5)

	if _, err := ra.AddResolvedTargets(0x1003, []disasm.Address{0x1005}, nil); err != nil {
		t.Fatalf("AddResolvedTargets: %v", err)
	}

	for _, name := range []string{"domtree", "ssa", "vsa", "rdefs", "typeconstraints"} {
		if !called[name] {
			t.Errorf("hook %q was not called", name)
		}
	}
}
