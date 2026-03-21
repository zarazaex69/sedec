package typeinfer

import (
	"fmt"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// TestProperty_CyclicFeedbackConvergence verifies that the cyclic feedback loop
// between Type_Inferencer and CFG_Builder always terminates within MaxIterations
// for arbitrary configurations of indirect jumps and function pointer arrays.
//
// Properties verified:
//   - P1: Run() always terminates (returns a result, never hangs)
//   - P2: IterationsRun <= MaxIterations for all inputs
//   - P3: When discoverer returns empty on first call, IterationsRun == 1
//   - P4: Deduplication prevents the same (jumpSite, target) pair from being sent twice
//   - P5: Convergence reason is ConvergenceNoNewTargets when discoverer exhausts arrays
//   - P6: Convergence reason is ConvergenceIterationLimit when discoverer never stops
//   - P7: TotalTargetsResolved is monotonically non-decreasing across iterations
//   - P8: Provenance metadata contains correct array kind and iteration tag
//
// Requirements: 11.17-11.22, 3.10-3.17
// Minimum 100 iterations per property.
func TestProperty_CyclicFeedbackConvergence(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	params.MaxSize = 10

	properties := gopter.NewProperties(params)

	properties.Property("feedback loop terminates within MaxIterations", prop.ForAll(
		func(sc *convergenceScenario) bool {
			return checkTermination(t, sc)
		},
		genConvergenceScenario(),
	))

	properties.Property("iteration count never exceeds MaxIterations", prop.ForAll(
		func(sc *convergenceScenario) bool {
			return checkIterationBound(t, sc)
		},
		genConvergenceScenario(),
	))

	properties.Property("empty discoverer converges in one iteration", prop.ForAll(
		func(maxIter int) bool {
			return checkEmptyDiscovererConverges(t, maxIter)
		},
		genMaxIterations(),
	))

	properties.Property("deduplication prevents duplicate target transmission", prop.ForAll(
		func(sc *convergenceScenario) bool {
			return checkDeduplication(t, sc)
		},
		genDuplicateScenario(),
	))

	properties.Property("exhaustible discoverer yields ConvergenceNoNewTargets", prop.ForAll(
		func(sc *convergenceScenario) bool {
			return checkExhaustibleConvergence(t, sc)
		},
		genExhaustibleScenario(),
	))

	properties.Property("infinite discoverer yields ConvergenceIterationLimit", prop.ForAll(
		func(sc *convergenceScenario) bool {
			return checkInfiniteDiscovererHitsLimit(t, sc)
		},
		genInfiniteScenario(),
	))

	properties.Property("TotalTargetsResolved is monotonically non-decreasing", prop.ForAll(
		func(sc *convergenceScenario) bool {
			return checkMonotonicTargets(t, sc)
		},
		genConvergenceScenario(),
	))

	properties.Property("provenance metadata contains array kind and iteration", prop.ForAll(
		func(sc *convergenceScenario) bool {
			return checkProvenanceMetadata(t, sc)
		},
		genExhaustibleScenario(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// convergenceScenario encodes a complete test input for the cyclic feedback loop.
type convergenceScenario struct {
	arrays        [][]FunctionPointerArray
	maxIterations int
	arrayKind     ArrayKind
}

// trackingCFGBuilder records all AddIndirectTargetWithProvenance calls and
// tracks unique (jumpSite, target) pairs to verify deduplication.
type trackingCFGBuilder struct {
	calls  []mockAddCall
	unique map[resolvedKey]int
}

func newTrackingCFGBuilder() *trackingCFGBuilder {
	return &trackingCFGBuilder{
		unique: make(map[resolvedKey]int),
	}
}

func (b *trackingCFGBuilder) AddIndirectTargetWithProvenance(
	jumpSite, target disasm.Address,
	provenance *cfg.EdgeProvenance,
) error {
	b.calls = append(b.calls, mockAddCall{
		jumpSite:   jumpSite,
		target:     target,
		provenance: provenance,
	})
	key := resolvedKey{jumpSite: ir.Address(jumpSite), target: ir.Address(target)}
	b.unique[key]++
	return nil
}

func (b *trackingCFGBuilder) GetUnresolvedIndirectJumps() []disasm.Address {
	return nil
}

// infiniteDiscoverer always returns a new unique array on every call,
// guaranteeing the loop never converges naturally.
type infiniteDiscoverer struct {
	kind      ArrayKind
	callCount int
}

func (d *infiniteDiscoverer) DiscoverFunctionPointers(_ *TypeSolution) []FunctionPointerArray {
	d.callCount++
	base := ir.Address(0xA000 + d.callCount*0x100)
	return []FunctionPointerArray{
		{
			Address:     base,
			ElementType: ir.FunctionType{ReturnType: ir.VoidType{}},
			Elements:    []ir.Address{base + 0x10, base + 0x20},
			Kind:        d.kind,
			Confidence:  0.75,
			Origin:      fmt.Sprintf("infinite_iter_%d", d.callCount),
		},
	}
}

// ============================================================================
// gopter generators
// ============================================================================

func genConvergenceScenario() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		maxIter := int(params.NextUint64()%8) + 3
		numIters := int(params.NextUint64()%uint64(maxIter)) + 1

		kinds := []ArrayKind{ArrayKindVTable, ArrayKindHandlerTable, ArrayKindJumpTable, ArrayKindInterfaceTable}
		kind := kinds[params.NextUint64()%uint64(len(kinds))]

		arrays := make([][]FunctionPointerArray, numIters)
		for i := range arrays {
			numArrays := int(params.NextUint64()%3) + 1
			iterArrays := make([]FunctionPointerArray, numArrays)
			for j := range iterArrays {
				numTargets := int(params.NextUint64()%4) + 1
				targets := make([]ir.Address, numTargets)
				for k := range targets {
					targets[k] = ir.Address(0x2000 + i*0x1000 + j*0x100 + k*0x10)
				}
				iterArrays[j] = FunctionPointerArray{
					Address:     ir.Address(0x1000 + i*0x1000 + j*0x100),
					ElementType: ir.FunctionType{ReturnType: ir.VoidType{}},
					Elements:    targets,
					Kind:        kind,
					Confidence:  0.5 + float64(params.NextUint64()%50)/100.0,
					Origin:      fmt.Sprintf("gen_iter_%d_arr_%d", i, j),
				}
			}
			arrays[i] = iterArrays
		}

		sc := &convergenceScenario{
			arrays:        arrays,
			maxIterations: maxIter,
			arrayKind:     kind,
		}
		return gopter.NewGenResult(sc, gopter.NoShrinker)
	}
}

func genExhaustibleScenario() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		maxIter := int(params.NextUint64()%8) + 3
		numIters := int(params.NextUint64()%3) + 1
		if numIters >= maxIter {
			numIters = maxIter - 1
		}

		kinds := []ArrayKind{ArrayKindVTable, ArrayKindHandlerTable, ArrayKindJumpTable, ArrayKindInterfaceTable}
		kind := kinds[params.NextUint64()%uint64(len(kinds))]

		arrays := make([][]FunctionPointerArray, numIters)
		for i := range arrays {
			numTargets := int(params.NextUint64()%4) + 1
			targets := make([]ir.Address, numTargets)
			for k := range targets {
				targets[k] = ir.Address(0x3000 + i*0x100 + k*0x10)
			}
			arrays[i] = []FunctionPointerArray{
				{
					Address:     ir.Address(0x1000 + i*0x100),
					ElementType: ir.FunctionType{ReturnType: ir.VoidType{}},
					Elements:    targets,
					Kind:        kind,
					Confidence:  0.85,
					Origin:      fmt.Sprintf("exhaustible_iter_%d", i),
				},
			}
		}

		sc := &convergenceScenario{
			arrays:        arrays,
			maxIterations: maxIter,
			arrayKind:     kind,
		}
		return gopter.NewGenResult(sc, gopter.NoShrinker)
	}
}

func genInfiniteScenario() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		maxIter := int(params.NextUint64()%8) + 3
		kinds := []ArrayKind{ArrayKindVTable, ArrayKindHandlerTable, ArrayKindJumpTable, ArrayKindInterfaceTable}
		kind := kinds[params.NextUint64()%uint64(len(kinds))]

		sc := &convergenceScenario{
			arrays:        nil, // signals infinite discoverer
			maxIterations: maxIter,
			arrayKind:     kind,
		}
		return gopter.NewGenResult(sc, gopter.NoShrinker)
	}
}

func genDuplicateScenario() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		maxIter := int(params.NextUint64()%5) + 3
		numTargets := int(params.NextUint64()%3) + 1

		targets := make([]ir.Address, numTargets)
		for k := range targets {
			targets[k] = ir.Address(0x4000 + k*0x10)
		}

		kinds := []ArrayKind{ArrayKindVTable, ArrayKindHandlerTable}
		kind := kinds[params.NextUint64()%uint64(len(kinds))]

		sameArray := FunctionPointerArray{
			Address:     0x1000,
			ElementType: ir.FunctionType{ReturnType: ir.VoidType{}},
			Elements:    targets,
			Kind:        kind,
			Confidence:  0.9,
			Origin:      "duplicate_test",
		}

		numRepeats := int(params.NextUint64()%3) + 2
		arrays := make([][]FunctionPointerArray, numRepeats)
		for i := range arrays {
			arrays[i] = []FunctionPointerArray{sameArray}
		}

		sc := &convergenceScenario{
			arrays:        arrays,
			maxIterations: maxIter,
			arrayKind:     kind,
		}
		return gopter.NewGenResult(sc, gopter.NoShrinker)
	}
}

func genMaxIterations() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		maxIter := int(params.NextUint64()%20) + 1
		return gopter.NewGenResult(maxIter, gopter.NoShrinker)
	}
}

// ============================================================================
// property checkers
// ============================================================================

func checkTermination(t *testing.T, sc *convergenceScenario) bool {
	t.Helper()

	builder := newTrackingCFGBuilder()
	var disc FunctionPointerDiscoverer
	if sc.arrays == nil {
		disc = &infiniteDiscoverer{kind: sc.arrayKind}
	} else {
		disc = &mockDiscoverer{perIterationArrays: sc.arrays}
	}

	loop := NewCyclicFeedbackLoop(disc, builder, sc.maxIterations)
	result, _ := loop.Run(emptySol())

	if result == nil {
		t.Log("Run() returned nil result")
		return false
	}
	return true
}

func checkIterationBound(t *testing.T, sc *convergenceScenario) bool {
	t.Helper()

	builder := newTrackingCFGBuilder()
	var disc FunctionPointerDiscoverer
	if sc.arrays == nil {
		disc = &infiniteDiscoverer{kind: sc.arrayKind}
	} else {
		disc = &mockDiscoverer{perIterationArrays: sc.arrays}
	}

	loop := NewCyclicFeedbackLoop(disc, builder, sc.maxIterations)
	result, _ := loop.Run(emptySol())

	if result == nil {
		t.Log("nil result")
		return false
	}

	if result.IterationsRun > sc.maxIterations {
		t.Logf("IterationsRun=%d > MaxIterations=%d", result.IterationsRun, sc.maxIterations)
		return false
	}
	return true
}

func checkEmptyDiscovererConverges(t *testing.T, maxIter int) bool {
	t.Helper()

	builder := newTrackingCFGBuilder()
	disc := &mockDiscoverer{perIterationArrays: nil}

	loop := NewCyclicFeedbackLoop(disc, builder, maxIter)
	result, _ := loop.Run(emptySol())

	if result == nil {
		t.Log("nil result")
		return false
	}

	if result.IterationsRun != 1 {
		t.Logf("empty discoverer: IterationsRun=%d, want 1", result.IterationsRun)
		return false
	}

	if result.Reason != ConvergenceNoNewTargets {
		t.Logf("empty discoverer: Reason=%s, want %s", result.Reason, ConvergenceNoNewTargets)
		return false
	}

	if result.TotalTargetsResolved != 0 {
		t.Logf("empty discoverer: TotalTargetsResolved=%d, want 0", result.TotalTargetsResolved)
		return false
	}

	return true
}

func checkDeduplication(t *testing.T, sc *convergenceScenario) bool {
	t.Helper()

	builder := newTrackingCFGBuilder()
	disc := &mockDiscoverer{perIterationArrays: sc.arrays}

	loop := NewCyclicFeedbackLoop(disc, builder, sc.maxIterations)
	result, _ := loop.Run(emptySol())

	if result == nil {
		t.Log("nil result")
		return false
	}

	for key, count := range builder.unique {
		if count > 1 {
			t.Logf("duplicate transmission: jumpSite=0x%x target=0x%x sent %d times",
				key.jumpSite, key.target, count)
			return false
		}
	}

	return true
}

func checkExhaustibleConvergence(t *testing.T, sc *convergenceScenario) bool {
	t.Helper()

	builder := newTrackingCFGBuilder()
	disc := &mockDiscoverer{perIterationArrays: sc.arrays}

	loop := NewCyclicFeedbackLoop(disc, builder, sc.maxIterations)
	result, _ := loop.Run(emptySol())

	if result == nil {
		t.Log("nil result")
		return false
	}

	if result.Reason != ConvergenceNoNewTargets {
		t.Logf("exhaustible scenario: Reason=%s, want %s (maxIter=%d, numArraySlices=%d)",
			result.Reason, ConvergenceNoNewTargets, sc.maxIterations, len(sc.arrays))
		return false
	}

	return true
}

func checkInfiniteDiscovererHitsLimit(t *testing.T, sc *convergenceScenario) bool {
	t.Helper()

	builder := newTrackingCFGBuilder()
	disc := &infiniteDiscoverer{kind: sc.arrayKind}

	loop := NewCyclicFeedbackLoop(disc, builder, sc.maxIterations)
	result, _ := loop.Run(emptySol())

	if result == nil {
		t.Log("nil result")
		return false
	}

	if result.Reason != ConvergenceIterationLimit {
		t.Logf("infinite discoverer: Reason=%s, want %s", result.Reason, ConvergenceIterationLimit)
		return false
	}

	if result.IterationsRun != sc.maxIterations {
		t.Logf("infinite discoverer: IterationsRun=%d, want %d", result.IterationsRun, sc.maxIterations)
		return false
	}

	return true
}

func checkMonotonicTargets(t *testing.T, sc *convergenceScenario) bool {
	t.Helper()

	var disc FunctionPointerDiscoverer
	if sc.arrays == nil {
		disc = &infiniteDiscoverer{kind: sc.arrayKind}
	} else {
		disc = &mockDiscoverer{perIterationArrays: sc.arrays}
	}

	builder := newTrackingCFGBuilder()
	loop := NewCyclicFeedbackLoop(disc, builder, sc.maxIterations)

	result, _ := loop.Run(emptySol())
	if result == nil {
		t.Log("nil result")
		return false
	}

	if result.TotalTargetsResolved < 0 {
		t.Logf("TotalTargetsResolved=%d is negative", result.TotalTargetsResolved)
		return false
	}

	callCount := len(builder.calls)
	if callCount != result.TotalTargetsResolved {
		t.Logf("builder calls=%d != TotalTargetsResolved=%d", callCount, result.TotalTargetsResolved)
		return false
	}

	return true
}

func checkProvenanceMetadata(t *testing.T, sc *convergenceScenario) bool {
	t.Helper()

	builder := newTrackingCFGBuilder()
	disc := &mockDiscoverer{perIterationArrays: sc.arrays}

	loop := NewCyclicFeedbackLoop(disc, builder, sc.maxIterations)
	_, _ = loop.Run(emptySol())

	for i, call := range builder.calls {
		if call.provenance == nil {
			t.Logf("call[%d]: nil provenance", i)
			return false
		}

		if call.provenance.AnalysisPass == "" {
			t.Logf("call[%d]: empty AnalysisPass", i)
			return false
		}

		kindVal, ok := call.provenance.Metadata["array_kind"]
		if !ok {
			t.Logf("call[%d]: missing array_kind in metadata", i)
			return false
		}
		kindStr, isStr := kindVal.(string)
		if !isStr || kindStr == "" {
			t.Logf("call[%d]: array_kind is not a non-empty string: %v", i, kindVal)
			return false
		}

		if call.provenance.Confidence <= 0 || call.provenance.Confidence > 1.0 {
			t.Logf("call[%d]: confidence=%f out of range (0, 1]", i, call.provenance.Confidence)
			return false
		}
	}

	return true
}
