package cfg

import (
	"errors"
	"fmt"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestProperty5: Cyclic Feedback Loop Convergence
//
// property 5: for all cfgs with indirect jumps and a resolve function:
//
//	RunConvergenceLoop terminates in <= maxIterations iterations
//
// validates requirements 3.10-3.17, 11.17-11.25:
//   - 3.10: type inferencer feedback resolves indirect jumps
//   - 3.11: cfg builder maintains cyclic feedback loop with type inferencer
//   - 3.12: new indirect jump targets trigger incremental cfg updates
//   - 3.13: incremental re-analysis of ssa, vsa, type constraints after update
//   - 3.14: unresolved indirect jumps tracked and prioritised
//   - 3.15: c++ vtables / go interface tables devirtualised via type info
//   - 3.16: iteration until no new targets or iteration limit reached
//   - 3.17: provenance tracking for each resolved indirect jump
//   - 11.17: type inferencer sends function pointer arrays to cfg builder
//   - 11.18: vtable discovery and target reporting
//   - 11.19: handler table discovery and target reporting
//   - 11.20: go interface table (itab) discovery
//   - 11.21: incremental type constraint update after cfg expansion
//   - 11.22: participation in cyclic refinement until convergence
//   - 11.23: incremental re-analysis correctness after cfg update
//   - 11.24: convergence or termination within iteration limit
//   - 11.25: provenance metadata for each discovered target
//
// minimum 100 iterations required.

// ============================================================================
// property test entry point
// ============================================================================

// TestProperty5 verifies that the cyclic feedback loop always terminates.
// runs 100+ iterations with gopter-generated cfg scenarios.
func TestProperty5(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	params.MaxSize = 8

	properties := gopter.NewProperties(params)

	// property 5a: loop terminates within maxIterations for any resolve function
	properties.Property("convergence loop terminates within maxIterations", prop.ForAll(
		func(scenario *feedbackScenario) bool {
			return checkConvergenceTermination(t, scenario)
		},
		genFeedbackScenario(),
	))

	// property 5b: converged result has no unresolved jumps when all targets provided
	properties.Property("fully resolved cfg has no unresolved indirect jumps", prop.ForAll(
		func(scenario *feedbackScenario) bool {
			return checkFullResolutionConvergence(t, scenario)
		},
		genFullyResolvableScenario(),
	))

	// property 5c: cfg structural consistency is preserved after every iteration
	properties.Property("cfg structural consistency preserved after feedback loop", prop.ForAll(
		func(scenario *feedbackScenario) bool {
			return checkCFGConsistencyAfterLoop(t, scenario)
		},
		genFeedbackScenario(),
	))

	// property 5d: iteration count never exceeds maxIterations
	properties.Property("iteration count never exceeds maxIterations", prop.ForAll(
		func(scenario *feedbackScenario) bool {
			return checkIterationCountBound(t, scenario)
		},
		genFeedbackScenario(),
	))

	// property 5e: provenance is recorded for every resolved jump
	properties.Property("provenance recorded for every resolved indirect jump", prop.ForAll(
		func(scenario *feedbackScenario) bool {
			return checkProvenanceRecorded(t, scenario)
		},
		genFullyResolvableScenario(),
	))

	// property 5f: new edges added monotonically (never removed)
	properties.Property("edge count is monotonically non-decreasing across iterations", prop.ForAll(
		func(scenario *feedbackScenario) bool {
			return checkEdgeMonotonicity(t, scenario)
		},
		genFeedbackScenario(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ============================================================================
// scenario types for generators
// ============================================================================

// indirectJumpSpec describes a single indirect jump in the generated cfg.
// each jump has a fixed set of targets that the simulated type inferencer
// will discover across one or more iterations.
type indirectJumpSpec struct {
	// jumpSite is the virtual address of the indirect jump instruction.
	jumpSite disasm.Address
	// targets are the resolved destination addresses for this jump.
	targets []disasm.Address
	// revealPerIteration controls how many targets are revealed per iteration.
	// 0 means all targets are revealed in the first iteration.
	revealPerIteration int
	// kind classifies the indirect jump for provenance metadata.
	kind IndirectJumpKind
}

// feedbackScenario is the complete input to a property check.
// it encodes a cfg with N indirect jumps and a simulated resolve function
// that reveals targets according to the revealPerIteration schedule.
type feedbackScenario struct {
	// jumps is the set of indirect jumps in the cfg.
	jumps []*indirectJumpSpec
	// maxIterations is the iteration cap passed to NewIncrementalReAnalyzer.
	maxIterations int
	// analysisPass is the provenance tag used by the simulated type inferencer.
	analysisPass string
}

// ============================================================================
// gopter generators
// ============================================================================

// genFeedbackScenario generates arbitrary feedback scenarios.
// the generated scenarios may or may not fully resolve all indirect jumps
// within maxIterations — both outcomes are valid (the loop must terminate).
func genFeedbackScenario() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		// number of indirect jumps: 1-4
		numJumps := int(params.NextUint64()%4) + 1

		// maxIterations: 3-10
		maxIter := int(params.NextUint64()%8) + 3

		// analysis pass names for provenance variety
		passTags := []string{
			"type_inference_vtable",
			"type_inference_handler",
			"vsa_strided_interval",
			"type_inference_itab",
		}
		passTag := passTags[params.NextUint64()%uint64(len(passTags))]

		jumps := make([]*indirectJumpSpec, numJumps)
		for i := range jumps {
			jumps[i] = genIndirectJumpSpec(params, i)
		}

		scenario := &feedbackScenario{
			jumps:         jumps,
			maxIterations: maxIter,
			analysisPass:  passTag,
		}
		return gopter.NewGenResult(scenario, gopter.NoShrinker)
	}
}

// genFullyResolvableScenario generates scenarios where all indirect jumps
// are fully resolved within the first iteration.
// used for properties that require convergence to be verified.
func genFullyResolvableScenario() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		// number of indirect jumps: 1-3
		numJumps := int(params.NextUint64()%3) + 1

		jumps := make([]*indirectJumpSpec, numJumps)
		for i := range jumps {
			spec := genIndirectJumpSpec(params, i)
			// force all targets revealed in iteration 0 (fully resolvable)
			spec.revealPerIteration = 0
			jumps[i] = spec
		}

		scenario := &feedbackScenario{
			jumps:         jumps,
			maxIterations: 10,
			analysisPass:  "type_inference_vtable",
		}
		return gopter.NewGenResult(scenario, gopter.NoShrinker)
	}
}

// genIndirectJumpSpec generates a single indirect jump specification.
// jump sites are spaced 0x100 apart starting at 0x1000 to avoid collisions.
// targets are placed at 0x2000 + offset to be distinct from jump sites.
func genIndirectJumpSpec(params *gopter.GenParameters, jumpIndex int) *indirectJumpSpec {
	// jump site: 0x1000 + jumpIndex*0x100
	//nolint:gosec // jumpIndex is small (0-3), no overflow
	jumpSite := disasm.Address(0x1000 + jumpIndex*0x100)

	// number of targets: 1-4
	numTargets := int(params.NextUint64()%4) + 1

	// targets: 0x2000 + jumpIndex*0x400 + targetIndex*0x10
	targets := make([]disasm.Address, numTargets)
	for j := range targets {
		//nolint:gosec // jumpIndex and j are small, no overflow
		targets[j] = disasm.Address(0x2000 + jumpIndex*0x400 + j*0x10)
	}

	// revealPerIteration: 0 (all at once) or 1 (one per iteration)
	revealPerIter := int(params.NextUint64() % 2)

	// jump kind: vtable, handler table, or function pointer
	kinds := []IndirectJumpKind{
		IndirectJumpVTable,
		IndirectJumpHandlerTable,
		IndirectJumpFunctionPointer,
	}
	kind := kinds[params.NextUint64()%uint64(len(kinds))]

	return &indirectJumpSpec{
		jumpSite:           jumpSite,
		targets:            targets,
		revealPerIteration: revealPerIter,
		kind:               kind,
	}
}

// ============================================================================
// cfg builder factory
// ============================================================================

// buildScenarioCFG constructs a cfg from a feedbackScenario.
//
// layout per indirect jump spec (jumpIndex i):
//
//	0x1000 + i*0x100 + 0x00: mov  (entry of this jump's block)
//	0x1000 + i*0x100 + 0x03: jmp  rax  (indirect jump)
//	0x2000 + i*0x400 + j*0x10: mov  (target j)
//	0x2000 + i*0x400 + j*0x10 + 0x03: ret
//
// the entry block at 0x0000 falls through to the first jump block.
// all target blocks are independent (no shared targets across jumps).
func buildScenarioCFG(t *testing.T, scenario *feedbackScenario) *Builder {
	t.Helper()

	instrs := make([]*disasm.Instruction, 0, 64)

	// entry instruction at 0x0000
	instrs = append(instrs, &disasm.Instruction{
		Address:  0x0000,
		Mnemonic: "mov",
		Length:   3,
	})

	// build instructions for each indirect jump
	for i, spec := range scenario.jumps {
		// preamble instruction before the indirect jump
		instrs = append(instrs, &disasm.Instruction{
			Address:  spec.jumpSite - 3,
			Mnemonic: "mov",
			Length:   3,
		})

		// the indirect jump itself (register operand → unresolved)
		regName := fmt.Sprintf("r%d", i+8) // r8, r9, r10, r11
		instrs = append(instrs, &disasm.Instruction{
			Address:  spec.jumpSite,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: regName, Size: disasm.Size64},
			},
		})

		// target blocks for this jump
		for _, target := range spec.targets {
			instrs = append(instrs, &disasm.Instruction{
				Address:  target,
				Mnemonic: "mov",
				Length:   3,
			})
			instrs = append(instrs, &disasm.Instruction{
				Address:  target + 3,
				Mnemonic: "ret",
				Length:   1,
			})
		}
	}

	builder := NewCFGBuilder()
	if _, err := builder.Build(instrs); err != nil {
		t.Fatalf("buildScenarioCFG: %v", err)
	}

	return builder
}

// makeResolveFunc creates a resolve function for RunConvergenceLoop that
// simulates the type inferencer discovering targets according to the scenario.
//
// for each jump spec:
//   - if revealPerIteration == 0: all targets revealed in iteration 0
//   - if revealPerIteration == 1: one target revealed per iteration
//
// the function tracks which targets have already been revealed to avoid
// re-sending already-resolved targets (simulating real type inferencer behaviour).
func makeResolveFunc(
	scenario *feedbackScenario,
	passTag string,
) func([]*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
	// track how many targets have been revealed per jump site
	revealedCount := make(map[disasm.Address]int)

	return func(unresolved []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		result := make(map[disasm.Address]*ResolvedTargetSet)

		// build a set of currently unresolved jump sites for fast lookup
		unresolvedSet := make(map[disasm.Address]bool, len(unresolved))
		for _, u := range unresolved {
			unresolvedSet[u.JumpSite] = true
		}

		for _, spec := range scenario.jumps {
			if !unresolvedSet[spec.jumpSite] {
				// already resolved in a previous iteration
				continue
			}

			alreadyRevealed := revealedCount[spec.jumpSite]
			if alreadyRevealed >= len(spec.targets) {
				// all targets already revealed but jump still unresolved
				// (this can happen if AddIndirectTargetWithProvenance failed)
				continue
			}

			var toReveal []disasm.Address
			if spec.revealPerIteration == 0 {
				// reveal all remaining targets at once
				toReveal = spec.targets[alreadyRevealed:]
			} else {
				// reveal one target per iteration
				toReveal = spec.targets[alreadyRevealed : alreadyRevealed+1]
			}

			revealedCount[spec.jumpSite] += len(toReveal)

			result[spec.jumpSite] = NewResolvedTargetSet(passTag, 0.9, toReveal)
		}

		return result, nil
	}
}

// ============================================================================
// property checkers
// ============================================================================

// checkConvergenceTermination verifies that RunConvergenceLoop always terminates.
//
// property: for all scenarios S with maxIterations N:
//
//	RunConvergenceLoop(S) terminates (returns a result or errMaxIterationsReached)
//
// the loop must never hang or panic regardless of the resolve function's behaviour.
// both convergence and hitting the iteration cap are valid outcomes.
func checkConvergenceTermination(t *testing.T, scenario *feedbackScenario) bool {
	t.Helper()

	builder := buildScenarioCFG(t, scenario)
	ra := NewIncrementalReAnalyzer(builder, nil, scenario.maxIterations)

	resolveFunc := makeResolveFunc(scenario, scenario.analysisPass)

	result, err := ra.RunConvergenceLoop(resolveFunc)

	// the loop must always return a non-nil result
	if result == nil {
		t.Logf("RunConvergenceLoop returned nil result (scenario: %s)", describeScenario(scenario))
		return false
	}

	// the only acceptable errors are nil (converged) or errMaxIterationsReached
	if err != nil && !errors.Is(err, errMaxIterationsReached) {
		t.Logf("unexpected error from RunConvergenceLoop: %v (scenario: %s)", err, describeScenario(scenario))
		return false
	}

	// iteration count must be within bounds
	if result.Iterations > scenario.maxIterations {
		t.Logf("iterations %d exceeded maxIterations %d (scenario: %s)",
			result.Iterations, scenario.maxIterations, describeScenario(scenario))
		return false
	}

	return true
}

// checkFullResolutionConvergence verifies that when all targets are provided
// in the first iteration, the loop converges with Converged=true.
//
// property: for all fully-resolvable scenarios S:
//
//	RunConvergenceLoop(S).Converged == true
func checkFullResolutionConvergence(t *testing.T, scenario *feedbackScenario) bool {
	t.Helper()

	builder := buildScenarioCFG(t, scenario)
	ra := NewIncrementalReAnalyzer(builder, nil, scenario.maxIterations)

	resolveFunc := makeResolveFunc(scenario, scenario.analysisPass)

	result, err := ra.RunConvergenceLoop(resolveFunc)
	if err != nil && !errors.Is(err, errMaxIterationsReached) {
		t.Logf("unexpected error: %v (scenario: %s)", err, describeScenario(scenario))
		return false
	}

	// for fully-resolvable scenarios (revealPerIteration==0 for all jumps),
	// the loop must converge (not hit the iteration cap)
	if errors.Is(err, errMaxIterationsReached) {
		t.Logf("fully-resolvable scenario hit iteration cap (scenario: %s)", describeScenario(scenario))
		return false
	}

	if !result.Converged {
		t.Logf("expected Converged=true for fully-resolvable scenario (scenario: %s)", describeScenario(scenario))
		return false
	}

	return true
}

// checkCFGConsistencyAfterLoop verifies that the cfg remains structurally
// consistent after the feedback loop completes.
//
// property: for all scenarios S:
//
//	ConsistencyCheck(cfg after RunConvergenceLoop(S)) == []
func checkCFGConsistencyAfterLoop(t *testing.T, scenario *feedbackScenario) bool {
	t.Helper()

	builder := buildScenarioCFG(t, scenario)
	ra := NewIncrementalReAnalyzer(builder, nil, scenario.maxIterations)

	resolveFunc := makeResolveFunc(scenario, scenario.analysisPass)

	_, err := ra.RunConvergenceLoop(resolveFunc)
	if err != nil && !errors.Is(err, errMaxIterationsReached) {
		t.Logf("unexpected error: %v", err)
		return false
	}

	violations := builder.ConsistencyCheck()
	if len(violations) != 0 {
		t.Logf("cfg consistency violations after feedback loop:\n  %v\n  scenario: %s",
			violations, describeScenario(scenario))
		return false
	}

	return true
}

// checkIterationCountBound verifies that the iteration count in the result
// never exceeds maxIterations.
//
// property: for all scenarios S with maxIterations N:
//
//	result.Iterations <= N
func checkIterationCountBound(t *testing.T, scenario *feedbackScenario) bool {
	t.Helper()

	builder := buildScenarioCFG(t, scenario)
	ra := NewIncrementalReAnalyzer(builder, nil, scenario.maxIterations)

	resolveFunc := makeResolveFunc(scenario, scenario.analysisPass)

	result, err := ra.RunConvergenceLoop(resolveFunc)
	if err != nil && !errors.Is(err, errMaxIterationsReached) {
		t.Logf("unexpected error: %v", err)
		return false
	}

	if result == nil {
		t.Log("nil result")
		return false
	}

	if result.Iterations > scenario.maxIterations {
		t.Logf("iteration count %d > maxIterations %d (scenario: %s)",
			result.Iterations, scenario.maxIterations, describeScenario(scenario))
		return false
	}

	return true
}

// checkProvenanceRecorded verifies that every resolved indirect jump has a
// corresponding entry in the resolution history with correct provenance.
//
// property: for all fully-resolvable scenarios S:
//
//	len(result.ResolutionHistory) == len(S.jumps)
//	for all records r in result.ResolutionHistory:
//	    r.Provenance.AnalysisPass == S.analysisPass
//	    r.Provenance.Confidence > 0
func checkProvenanceRecorded(t *testing.T, scenario *feedbackScenario) bool {
	t.Helper()

	builder := buildScenarioCFG(t, scenario)
	ra := NewIncrementalReAnalyzer(builder, nil, scenario.maxIterations)

	resolveFunc := makeResolveFunc(scenario, scenario.analysisPass)

	result, err := ra.RunConvergenceLoop(resolveFunc)
	if err != nil {
		// errMaxIterationsReached is not expected for fully-resolvable scenarios
		t.Logf("unexpected error: %v (scenario: %s)", err, describeScenario(scenario))
		return false
	}

	// every jump must have at least one history entry
	if len(result.ResolutionHistory) < len(scenario.jumps) {
		t.Logf("resolution history len %d < expected %d (scenario: %s)",
			len(result.ResolutionHistory), len(scenario.jumps), describeScenario(scenario))
		return false
	}

	// every history record must have valid provenance
	for i, rec := range result.ResolutionHistory {
		if rec.Provenance == nil {
			t.Logf("history[%d]: nil provenance (scenario: %s)", i, describeScenario(scenario))
			return false
		}
		if rec.Provenance.AnalysisPass != scenario.analysisPass {
			t.Logf("history[%d]: pass=%q, want %q (scenario: %s)",
				i, rec.Provenance.AnalysisPass, scenario.analysisPass, describeScenario(scenario))
			return false
		}
		if rec.Provenance.Confidence <= 0 {
			t.Logf("history[%d]: confidence=%f must be > 0 (scenario: %s)",
				i, rec.Provenance.Confidence, describeScenario(scenario))
			return false
		}
		if len(rec.Targets) == 0 {
			t.Logf("history[%d]: empty targets (scenario: %s)", i, describeScenario(scenario))
			return false
		}
	}

	return true
}

// checkEdgeMonotonicity verifies that the total edge count never decreases
// across iterations of the feedback loop.
//
// property: for all scenarios S:
//
//	edgeCount(cfg after iteration i) <= edgeCount(cfg after iteration i+1)
//
// this is enforced by tracking edge counts via the OnDominatorTreeUpdated hook
// which fires after each structural change.
func checkEdgeMonotonicity(t *testing.T, scenario *feedbackScenario) bool {
	t.Helper()

	builder := buildScenarioCFG(t, scenario)

	// track edge counts at each dominator tree update (fires after each structural change)
	edgeCounts := make([]int, 0, scenario.maxIterations+1)
	edgeCounts = append(edgeCounts, builder.cfg.EdgeCount()) // initial count

	hooks := &ReAnalysisHooks{
		OnDominatorTreeUpdated: func(_ *DominatorTree) {
			edgeCounts = append(edgeCounts, builder.cfg.EdgeCount())
		},
	}

	ra := NewIncrementalReAnalyzer(builder, hooks, scenario.maxIterations)
	resolveFunc := makeResolveFunc(scenario, scenario.analysisPass)

	_, err := ra.RunConvergenceLoop(resolveFunc)
	if err != nil && !errors.Is(err, errMaxIterationsReached) {
		t.Logf("unexpected error: %v", err)
		return false
	}

	// verify monotonicity: each recorded count must be >= the previous
	for i := 1; i < len(edgeCounts); i++ {
		if edgeCounts[i] < edgeCounts[i-1] {
			t.Logf("edge count decreased at update %d: %d → %d (scenario: %s)",
				i, edgeCounts[i-1], edgeCounts[i], describeScenario(scenario))
			return false
		}
	}

	return true
}

// ============================================================================
// additional targeted tests for requirements 3.10-3.17, 11.17-11.25
// ============================================================================

// TestProperty5_VTableConvergence verifies that vtable discovery (req 11.18)
// converges correctly when all virtual method targets are revealed at once.
func TestProperty5_VTableConvergence(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	params.MaxSize = 5

	properties := gopter.NewProperties(params)

	properties.Property("vtable discovery converges within maxIterations", prop.ForAll(
		func(numMethods int) bool {
			return checkVTableConvergence(t, numMethods)
		},
		genVTableMethodCount(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestProperty5_HandlerTableConvergence verifies that handler table discovery
// (req 11.19) converges correctly for switch jump tables.
func TestProperty5_HandlerTableConvergence(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	params.MaxSize = 5

	properties := gopter.NewProperties(params)

	properties.Property("handler table discovery converges within maxIterations", prop.ForAll(
		func(numCases int) bool {
			return checkHandlerTableConvergence(t, numCases)
		},
		genHandlerTableCaseCount(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestProperty5_IncrementalRevealConvergence verifies that incremental target
// discovery (one target per iteration) still converges within the iteration cap.
// this models the realistic scenario where the type inferencer discovers new
// vtable entries as it processes more code (req 3.16, 11.22).
func TestProperty5_IncrementalRevealConvergence(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	params.MaxSize = 5

	properties := gopter.NewProperties(params)

	properties.Property("incremental target reveal converges within maxIterations", prop.ForAll(
		func(numTargets int) bool {
			return checkIncrementalRevealConvergence(t, numTargets)
		},
		genIncrementalTargetCount(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ============================================================================
// targeted property checkers
// ============================================================================

// checkVTableConvergence builds a cfg with a single vtable dispatch and verifies
// that resolving all virtual methods in one iteration produces Converged=true.
func checkVTableConvergence(t *testing.T, numMethods int) bool {
	t.Helper()

	// build instructions: entry + indirect jmp + numMethods target blocks
	instrs := make([]*disasm.Instruction, 0, 2+numMethods*2)
	instrs = append(instrs,
		&disasm.Instruction{Address: 0x4000, Mnemonic: "mov", Length: 3},
		&disasm.Instruction{
			Address:  0x4003,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{disasm.RegisterOperand{Name: "rax", Size: disasm.Size64}},
		},
	)

	// virtual method implementations
	targets := make([]disasm.Address, numMethods)
	for i := range targets {
		base := disasm.Address(0x5000 + i*0x10)
		targets[i] = base
		instrs = append(instrs,
			&disasm.Instruction{Address: base, Mnemonic: "push", Length: 1},
			&disasm.Instruction{Address: base + 1, Mnemonic: "ret", Length: 1},
		)
	}

	builder := NewCFGBuilder()
	if _, err := builder.Build(instrs); err != nil {
		t.Logf("build vtable cfg: %v", err)
		return false
	}

	ra := NewIncrementalReAnalyzer(builder, nil, 10)

	called := false
	result, err := ra.RunConvergenceLoop(func(unresolved []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		if called || len(unresolved) == 0 {
			return nil, nil //nolint:nilnil // nil map means no new targets; nil error means no failure
		}
		called = true
		// reveal all virtual methods in one iteration (vtable fully known)
		return map[disasm.Address]*ResolvedTargetSet{
			0x4003: NewResolvedTargetSet("type_inference_vtable", 0.95, targets),
		}, nil
	})

	if err != nil {
		t.Logf("vtable convergence error: %v (numMethods=%d)", err, numMethods)
		return false
	}
	if !result.Converged {
		t.Logf("vtable not converged (numMethods=%d)", numMethods)
		return false
	}
	if result.NewEdgesAdded != numMethods {
		t.Logf("NewEdgesAdded=%d, want %d (numMethods=%d)", result.NewEdgesAdded, numMethods, numMethods)
		return false
	}

	return true
}

// checkHandlerTableConvergence builds a cfg with a switch jump table and verifies
// that resolving all cases in one iteration produces Converged=true.
func checkHandlerTableConvergence(t *testing.T, numCases int) bool {
	t.Helper()

	instrs := make([]*disasm.Instruction, 0, 2+numCases*2)
	instrs = append(instrs,
		&disasm.Instruction{Address: 0x6000, Mnemonic: "cmp", Length: 3},
		&disasm.Instruction{
			Address:  0x6003,
			Mnemonic: "jmp",
			Length:   5,
			Operands: []disasm.Operand{disasm.MemoryOperand{Base: "rax", Scale: 8, Size: disasm.Size64}},
		},
	)

	targets := make([]disasm.Address, numCases)
	for i := range targets {
		base := disasm.Address(0x7000 + i*0x10)
		targets[i] = base
		instrs = append(instrs,
			&disasm.Instruction{Address: base, Mnemonic: "mov", Length: 3},
			&disasm.Instruction{Address: base + 3, Mnemonic: "ret", Length: 1},
		)
	}

	builder := NewCFGBuilder()
	if _, err := builder.Build(instrs); err != nil {
		t.Logf("build handler table cfg: %v", err)
		return false
	}

	ra := NewIncrementalReAnalyzer(builder, nil, 10)

	called := false
	result, err := ra.RunConvergenceLoop(func(unresolved []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		if called || len(unresolved) == 0 {
			return nil, nil //nolint:nilnil // nil map means no new targets; nil error means no failure
		}
		called = true
		return map[disasm.Address]*ResolvedTargetSet{
			0x6003: NewResolvedTargetSet("type_inference_handler", 0.80, targets),
		}, nil
	})

	if err != nil {
		t.Logf("handler table convergence error: %v (numCases=%d)", err, numCases)
		return false
	}
	if !result.Converged {
		t.Logf("handler table not converged (numCases=%d)", numCases)
		return false
	}

	return true
}

// checkIncrementalRevealConvergence builds a cfg with N independent indirect
// jumps (one per target) and resolves each in a separate iteration.
// this models the realistic scenario where the type inferencer discovers new
// vtable entries one at a time as it processes more code (req 3.16, 11.22).
//
// each jump has exactly one target, so each iteration resolves one jump.
// after numTargets iterations all jumps are resolved and the loop converges.
func checkIncrementalRevealConvergence(t *testing.T, numTargets int) bool {
	t.Helper()

	// build N independent indirect jumps, each with one target
	instrs := make([]*disasm.Instruction, 0, numTargets*4)
	jumpSites := make([]disasm.Address, numTargets)
	targets := make([]disasm.Address, numTargets)

	for i := 0; i < numTargets; i++ {
		jumpSite := disasm.Address(0x8000 + i*0x100)
		target := disasm.Address(0x9000 + i*0x10)
		jumpSites[i] = jumpSite
		targets[i] = target

		// preamble before the indirect jump
		instrs = append(instrs,
			&disasm.Instruction{Address: jumpSite - 3, Mnemonic: "mov", Length: 3},
			&disasm.Instruction{
				Address:  jumpSite,
				Mnemonic: "jmp",
				Length:   2,
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: fmt.Sprintf("r%d", i+8), Size: disasm.Size64},
				},
			},
			// target block
			&disasm.Instruction{Address: target, Mnemonic: "mov", Length: 3},
			&disasm.Instruction{Address: target + 3, Mnemonic: "ret", Length: 1},
		)
	}

	builder := NewCFGBuilder()
	if _, err := builder.Build(instrs); err != nil {
		t.Logf("build incremental cfg: %v", err)
		return false
	}

	// maxIterations must be >= numTargets + 1 to allow full convergence
	// (numTargets iterations to resolve each jump + 1 empty iteration)
	maxIter := numTargets + 2
	ra := NewIncrementalReAnalyzer(builder, nil, maxIter)

	// resolve one jump per iteration using the unresolved list
	result, err := ra.RunConvergenceLoop(func(unresolved []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error) {
		if len(unresolved) == 0 {
			return nil, nil //nolint:nilnil // nil map means no new targets; nil error means no failure
		}
		// resolve the first unresolved jump in this iteration
		jump := unresolved[0]

		// find the corresponding target for this jump site
		var target disasm.Address
		found := false
		for i, site := range jumpSites {
			if site == jump.JumpSite {
				target = targets[i]
				found = true
				break
			}
		}
		if !found {
			return nil, nil //nolint:nilnil // jump site not in our list; nil error means no failure
		}

		return map[disasm.Address]*ResolvedTargetSet{
			jump.JumpSite: NewResolvedTargetSet("type_inference_vtable", 0.9, []disasm.Address{target}),
		}, nil
	})

	if err != nil {
		t.Logf("incremental reveal error: %v (numTargets=%d)", err, numTargets)
		return false
	}
	if !result.Converged {
		t.Logf("incremental reveal not converged (numTargets=%d iterations=%d)",
			numTargets, result.Iterations)
		return false
	}
	if result.NewEdgesAdded != numTargets {
		t.Logf("NewEdgesAdded=%d, want %d (numTargets=%d)",
			result.NewEdgesAdded, numTargets, numTargets)
		return false
	}

	return true
}

// ============================================================================
// generators for targeted tests
// ============================================================================

// genVTableMethodCount generates virtual method counts in range [1, 8].
func genVTableMethodCount() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		count := int(params.NextUint64()%8) + 1
		return gopter.NewGenResult(count, gopter.NoShrinker)
	}
}

// genHandlerTableCaseCount generates switch case counts in range [1, 8].
func genHandlerTableCaseCount() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		count := int(params.NextUint64()%8) + 1
		return gopter.NewGenResult(count, gopter.NoShrinker)
	}
}

// genIncrementalTargetCount generates target counts in range [1, 7].
// capped at 7 so that maxIter = numTargets+2 stays within a reasonable bound.
func genIncrementalTargetCount() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		count := int(params.NextUint64()%7) + 1
		return gopter.NewGenResult(count, gopter.NoShrinker)
	}
}

// ============================================================================
// description helpers
// ============================================================================

// describeScenario returns a compact human-readable description of a scenario
// for use in failure messages.
func describeScenario(scenario *feedbackScenario) string {
	jumpDescs := make([]string, len(scenario.jumps))
	for i, j := range scenario.jumps {
		jumpDescs[i] = fmt.Sprintf("{site=0x%x targets=%d reveal=%d kind=%s}",
			j.jumpSite, len(j.targets), j.revealPerIteration, j.kind)
	}
	return fmt.Sprintf("maxIter=%d pass=%q jumps=%v",
		scenario.maxIterations, scenario.analysisPass, jumpDescs)
}
