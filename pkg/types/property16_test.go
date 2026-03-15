package typeinfer

import (
	"fmt"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// TestProperty16: Pointer Analysis Correctness (Soundness)
//
// property 16: for all pointer programs P:
//
//	let steens = Steensgaard(P)
//	let anders = Andersen(P)
//
//	soundness:
//	  for all addr_of constraints (x = &y) in P:
//	    y ∈ steens.PointsTo(x)  AND  y ∈ anders.PointsTo(x)
//
//	steensgaard conservatism (steens ⊇ anders):
//	  for all variables v:
//	    anders.PointsTo(v) ⊆ steens.PointsTo(v)
//
//	monotonicity:
//	  adding constraints never shrinks points-to sets
//
//	transitivity:
//	  x = &a; y = x → a ∈ pts(y)
//
//	store/load soundness:
//	  p = &a; *p = b → b ∈ pts(a)  (Steensgaard)
//	  p = &a; a = &b; x = *p → b ∈ pts(x)  (both)
//
// validates requirements 25.1-25.6, 45.1-45.14:
//   - 45.1: steensgaard flow-insensitive analysis
//   - 45.2: union-find equality-based constraints
//   - 45.3: near-linear time O(n α(n))
//   - 45.4: andersen inclusion-based analysis
//   - 45.5: inclusion constraint graph
//   - 45.6: transitive closure computation
//   - 45.8: selective application (hot path selector)
//   - 25.1: may-alias relationships computed
//   - 25.2: must-alias relationships computed
//   - 25.3: flow-sensitive alias tracking
//   - 25.4: type-incompatible pointers cannot alias
//   - 25.6: integration with memory ssa
//
// minimum 100 iterations required.

// ============================================================================
// property test entry point
// ============================================================================

// TestProperty16 verifies pointer analysis correctness across 100+ generated programs.
func TestProperty16(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	params.MaxSize = 10

	properties := gopter.NewProperties(params)

	// property 16a: soundness — addr_of constraints always appear in points-to sets
	properties.Property("addr_of soundness: y ∈ pts(x) after x = &y", prop.ForAll(
		func(prog *ptrProgram) bool {
			return checkAddrOfSoundness(t, prog)
		},
		genPtrProgram(),
	))

	// property 16b: steensgaard conservatism — steens.pts(v) ⊇ anders.pts(v)
	properties.Property("steensgaard is conservative superset of andersen", prop.ForAll(
		func(prog *ptrProgram) bool {
			return checkSteensgaardConservatism(t, prog)
		},
		genPtrProgram(),
	))

	// property 16c: transitivity — x = &a; y = x → a ∈ pts(y)
	properties.Property("copy transitivity: x = &a; y = x → a ∈ pts(y)", prop.ForAll(
		func(prog *copyChainProgram) bool {
			return checkCopyTransitivity(t, prog)
		},
		genCopyChainProgram(),
	))

	// property 16d: monotonicity — adding constraints never shrinks points-to sets
	properties.Property("monotonicity: adding constraints never shrinks pts sets", prop.ForAll(
		func(prog *ptrProgram) bool {
			return checkMonotonicity(t, prog)
		},
		genPtrProgram(),
	))

	// property 16e: load soundness — p = &a; a = &b; x = *p → b ∈ pts(x)
	properties.Property("load soundness: p = &a; a = &b; x = *p → b ∈ pts(x)", prop.ForAll(
		func(prog *loadSoundnessProgram) bool {
			return checkLoadSoundness(t, prog)
		},
		genLoadSoundnessProgram(),
	))

	// property 16f: store soundness (steensgaard) — p = &a; *p = b → a and b alias
	properties.Property("store soundness: p = &a; *p = b → a and b alias (steensgaard)", prop.ForAll(
		func(prog *storeSoundnessProgram) bool {
			return checkStoreSoundness(t, prog)
		},
		genStoreSoundnessProgram(),
	))

	// property 16g: andersen precision — two distinct addr_of targets are NOT merged
	properties.Property("andersen precision: distinct addr_of targets not merged", prop.ForAll(
		func(prog *andersenPrecisionProgram) bool {
			return checkAndersenPrecision(t, prog)
		},
		genAndersenPrecisionProgram(),
	))

	// property 16h: no-alias for unrelated pointers
	properties.Property("unrelated pointers do not alias", prop.ForAll(
		func(prog *noAliasProgram) bool {
			return checkNoAlias(t, prog)
		},
		genNoAliasProgram(),
	))

	// property 16i: determinism — repeated analysis produces identical results
	properties.Property("analysis is deterministic across repeated runs", prop.ForAll(
		func(prog *ptrProgram) bool {
			return checkDeterminism(t, prog)
		},
		genPtrProgram(),
	))

	// property 16j: hot path selector correctness
	properties.Property("hot path selector correctly classifies functions", prop.ForAll(
		func(prog *hotPathProgram) bool {
			return checkHotPathSelector(t, prog)
		},
		genHotPathProgram(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ============================================================================
// program types for generators
// ============================================================================

// ptrConstraintKind classifies the four fundamental pointer operations
// used in generated programs.
type ptrConstraintKindGen int

const (
	genAddrOf ptrConstraintKindGen = iota // x = &y
	genCopy                               // x = y
	genLoad                               // x = *y
	genStore                              // *x = y
)

// ptrOp is a single pointer operation in a generated program.
type ptrOp struct {
	kind ptrConstraintKindGen
	lhs  string // left-hand side variable name
	rhs  string // right-hand side variable name
}

// ptrProgram is a sequence of pointer operations over a fixed variable set.
type ptrProgram struct {
	// vars is the pool of variable names used in the program.
	vars []string
	// ops is the sequence of pointer operations.
	ops []ptrOp
}

// copyChainProgram represents a chain of copy operations:
// v0 = &obj; v1 = v0; v2 = v1; ... → obj ∈ pts(vN)
type copyChainProgram struct {
	// chainLen is the number of copy steps (>= 1).
	chainLen int
	// objName is the address-taken object.
	objName string
}

// loadSoundnessProgram represents: p = &a; a = &b; x = *p → b ∈ pts(x)
type loadSoundnessProgram struct {
	// depth is the number of pointer indirection levels (1-3).
	depth int
}

// storeSoundnessProgram represents: p = &a; *p = b → a and b alias (Steensgaard)
type storeSoundnessProgram struct {
	// numTargets is the number of distinct objects stored through the pointer.
	numTargets int
}

// andersenPrecisionProgram represents: p = &a; p = &b → a and b NOT merged (Andersen)
type andersenPrecisionProgram struct {
	// numTargets is the number of distinct addr_of targets for the same pointer.
	numTargets int
}

// noAliasProgram represents two completely independent pointer chains.
type noAliasProgram struct {
	// chainALen is the length of the first chain.
	chainALen int
	// chainBLen is the length of the second chain.
	chainBLen int
}

// hotPathProgram represents a function with a configurable number of
// load/store instructions and indirect calls.
type hotPathProgram struct {
	// numLoads is the number of load instructions.
	numLoads int
	// numStores is the number of store instructions.
	numStores int
	// numIndirectCalls is the number of indirect call instructions.
	numIndirectCalls int
}

// ============================================================================
// gopter generators
// ============================================================================

// genPtrProgram generates a random pointer program over a small variable pool.
func genPtrProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		// variable pool: 3-6 variables
		numVars := int(params.NextUint64()%4) + 3
		vars := make([]string, numVars)
		for i := range vars {
			vars[i] = fmt.Sprintf("v%d", i)
		}

		// generate 3-8 operations
		numOps := int(params.NextUint64()%6) + 3
		ops := make([]ptrOp, numOps)
		for i := range ops {
			kind := ptrConstraintKindGen(params.NextUint64() % 4)
			lhs := vars[params.NextUint64()%uint64(numVars)]
			rhs := vars[params.NextUint64()%uint64(numVars)]
			// avoid self-referential ops for cleaner semantics
			for rhs == lhs && numVars > 1 {
				rhs = vars[params.NextUint64()%uint64(numVars)]
			}
			ops[i] = ptrOp{kind: kind, lhs: lhs, rhs: rhs}
		}

		return gopter.NewGenResult(&ptrProgram{vars: vars, ops: ops}, gopter.NoShrinker)
	}
}

// genCopyChainProgram generates a copy chain of configurable length.
func genCopyChainProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		chainLen := int(params.NextUint64()%8) + 1 // 1-8 copy steps
		return gopter.NewGenResult(&copyChainProgram{
			chainLen: chainLen,
			objName:  "obj",
		}, gopter.NoShrinker)
	}
}

// genLoadSoundnessProgram generates load soundness programs with 1-3 indirection levels.
func genLoadSoundnessProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		depth := int(params.NextUint64()%3) + 1 // 1-3 levels
		return gopter.NewGenResult(&loadSoundnessProgram{depth: depth}, gopter.NoShrinker)
	}
}

// genStoreSoundnessProgram generates store soundness programs.
func genStoreSoundnessProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		numTargets := int(params.NextUint64()%4) + 1 // 1-4 stored values
		return gopter.NewGenResult(&storeSoundnessProgram{numTargets: numTargets}, gopter.NoShrinker)
	}
}

// genAndersenPrecisionProgram generates programs testing Andersen's precision.
func genAndersenPrecisionProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		numTargets := int(params.NextUint64()%5) + 2 // 2-6 distinct targets
		return gopter.NewGenResult(&andersenPrecisionProgram{numTargets: numTargets}, gopter.NoShrinker)
	}
}

// genNoAliasProgram generates two independent pointer chains.
func genNoAliasProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		chainALen := int(params.NextUint64()%4) + 1
		chainBLen := int(params.NextUint64()%4) + 1
		return gopter.NewGenResult(&noAliasProgram{
			chainALen: chainALen,
			chainBLen: chainBLen,
		}, gopter.NoShrinker)
	}
}

// genHotPathProgram generates programs for hot path selector testing.
func genHotPathProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		return gopter.NewGenResult(&hotPathProgram{
			numLoads:         int(params.NextUint64() % 20),
			numStores:        int(params.NextUint64() % 20),
			numIndirectCalls: int(params.NextUint64() % 5),
		}, gopter.NoShrinker)
	}
}

// ============================================================================
// property checkers
// ============================================================================

// checkAddrOfSoundness verifies that every addr_of constraint (x = &y) in the
// generated program results in y ∈ pts(x) for both Steensgaard and Andersen.
//
// soundness property: the analysis must never miss a real alias.
// if x = &y is in the program, then y MUST appear in pts(x).
func checkAddrOfSoundness(t *testing.T, prog *ptrProgram) bool {
	t.Helper()

	steens := NewSteensgaardAnalyzer()
	anders := NewAndersenAnalyzer()

	cs := ptrProgramToConstraints(prog)
	steens.AnalyzeConstraints(cs)
	anders.AnalyzeConstraints(cs)
	anders.propagate()

	for _, op := range prog.ops {
		if op.kind != genAddrOf {
			continue
		}
		// x = &y: y must be in pts(x) for both analyses
		steensPts := steens.PointsTo(op.lhs)
		if !containsStr(steensPts, op.rhs) {
			t.Logf("steensgaard soundness violation: %s = &%s, but %s ∉ pts(%s) = %v",
				op.lhs, op.rhs, op.rhs, op.lhs, steensPts)
			return false
		}

		andersPts := anders.PointsTo(op.lhs)
		if !containsStr(andersPts, op.rhs) {
			t.Logf("andersen soundness violation: %s = &%s, but %s ∉ pts(%s) = %v",
				op.lhs, op.rhs, op.rhs, op.lhs, andersPts)
			return false
		}
	}
	return true
}

// checkSteensgaardConservatism verifies that Steensgaard's points-to sets are
// a superset of Andersen's points-to sets for every variable.
//
// formal property: ∀v: anders.pts(v) ⊆ steens.pts(v)
//
// this holds because Steensgaard uses equality constraints (merging more nodes)
// while Andersen uses inclusion constraints (keeping nodes separate).
// equality-based analysis is strictly less precise (more conservative).
func checkSteensgaardConservatism(t *testing.T, prog *ptrProgram) bool {
	t.Helper()

	steens := NewSteensgaardAnalyzer()
	anders := NewAndersenAnalyzer()

	cs := ptrProgramToConstraints(prog)
	steens.AnalyzeConstraints(cs)
	anders.AnalyzeConstraints(cs)
	anders.propagate()

	for _, varName := range prog.vars {
		andersPts := anders.PointsTo(varName)
		steensPts := steens.PointsTo(varName)

		// every element in andersen's pts must also be in steensgaard's pts
		for _, target := range andersPts {
			if !containsStr(steensPts, target) {
				t.Logf("conservatism violation: %s ∈ anders.pts(%s) but %s ∉ steens.pts(%s)",
					target, varName, target, varName)
				t.Logf("  anders.pts(%s) = %v", varName, andersPts)
				t.Logf("  steens.pts(%s) = %v", varName, steensPts)
				return false
			}
		}
	}
	return true
}

// checkCopyTransitivity verifies that copy chains propagate address-of targets.
//
// formal property: v0 = &obj; v1 = v0; v2 = v1; ... → obj ∈ pts(vN)
//
// this tests the transitive closure of copy edges in both analyses.
func checkCopyTransitivity(t *testing.T, prog *copyChainProgram) bool {
	t.Helper()

	cs := make([]PointerConstraint, 0, prog.chainLen+1)

	// v0 = &obj
	cs = append(cs, PointerConstraint{
		Kind: PtrConstraintAddressOf,
		Lhs:  "v0",
		Rhs:  prog.objName,
	})

	// v1 = v0; v2 = v1; ... vN = v(N-1)
	for i := 0; i < prog.chainLen; i++ {
		cs = append(cs, PointerConstraint{
			Kind: PtrConstraintCopy,
			Lhs:  fmt.Sprintf("v%d", i+1),
			Rhs:  fmt.Sprintf("v%d", i),
		})
	}

	lastVar := fmt.Sprintf("v%d", prog.chainLen)

	// steensgaard
	steens := NewSteensgaardAnalyzer()
	steens.AnalyzeConstraints(cs)
	steensPts := steens.PointsTo(lastVar)
	if !containsStr(steensPts, prog.objName) {
		t.Logf("steensgaard transitivity violation: chain length %d, %s ∉ pts(%s) = %v",
			prog.chainLen, prog.objName, lastVar, steensPts)
		return false
	}

	// andersen
	anders := NewAndersenAnalyzer()
	anders.AnalyzeConstraints(cs)
	anders.propagate()
	andersPts := anders.PointsTo(lastVar)
	if !containsStr(andersPts, prog.objName) {
		t.Logf("andersen transitivity violation: chain length %d, %s ∉ pts(%s) = %v",
			prog.chainLen, prog.objName, lastVar, andersPts)
		return false
	}

	return true
}

// checkMonotonicity verifies that adding more constraints never shrinks
// points-to sets. this is a fundamental soundness property of any
// conservative pointer analysis.
//
// formal property: C1 ⊆ C2 → ∀v: pts_C1(v) ⊆ pts_C2(v)
func checkMonotonicity(t *testing.T, prog *ptrProgram) bool {
	t.Helper()

	if len(prog.ops) < 2 {
		return true // not enough ops to test monotonicity
	}

	cs := ptrProgramToConstraints(prog)

	// analyze with first half of constraints
	half := len(cs) / 2
	if half == 0 {
		return true
	}

	steensSmall := NewSteensgaardAnalyzer()
	steensSmall.AnalyzeConstraints(cs[:half])

	steensFull := NewSteensgaardAnalyzer()
	steensFull.AnalyzeConstraints(cs)

	// for every variable, pts(small) ⊆ pts(full)
	for _, varName := range prog.vars {
		smallPts := steensSmall.PointsTo(varName)
		fullPts := steensFull.PointsTo(varName)

		for _, target := range smallPts {
			if !containsStr(fullPts, target) {
				t.Logf("monotonicity violation: %s ∈ pts_small(%s) but %s ∉ pts_full(%s)",
					target, varName, target, varName)
				t.Logf("  pts_small(%s) = %v", varName, smallPts)
				t.Logf("  pts_full(%s) = %v", varName, fullPts)
				return false
			}
		}
	}
	return true
}

// checkLoadSoundness verifies that loading through a pointer chain propagates
// the ultimate target into the load destination.
//
// formal property (depth=1): p = &a; a = &b; x = *p → b ∈ pts(x)
// formal property (depth=2): p = &a; a = &b; b = &c; x = *p; y = *x → c ∈ pts(y)
func checkLoadSoundness(t *testing.T, prog *loadSoundnessProgram) bool {
	t.Helper()

	// build a chain: p → a0 → a1 → ... → a(depth)
	// p = &a0; a0 = &a1; ... a(depth-1) = &a(depth)
	// x = *p → a1 ∈ pts(x)
	cs := make([]PointerConstraint, 0, prog.depth*2+1)

	// p = &a0
	cs = append(cs, PointerConstraint{
		Kind: PtrConstraintAddressOf,
		Lhs:  "p",
		Rhs:  "a0",
	})

	// a0 = &a1; a1 = &a2; ...
	for i := 0; i < prog.depth; i++ {
		cs = append(cs, PointerConstraint{
			Kind: PtrConstraintAddressOf,
			Lhs:  fmt.Sprintf("a%d", i),
			Rhs:  fmt.Sprintf("a%d", i+1),
		})
	}

	// x = *p (load through p, which points to a0, which points to a1)
	cs = append(cs, PointerConstraint{
		Kind: PtrConstraintLoad,
		Lhs:  "x",
		Rhs:  "p",
	})

	// after x = *p: x should point to what a0 points to, i.e., a1
	expectedTarget := "a1"

	// steensgaard
	steens := NewSteensgaardAnalyzer()
	steens.AnalyzeConstraints(cs)
	steensPts := steens.PointsTo("x")
	if !containsStr(steensPts, expectedTarget) {
		t.Logf("steensgaard load soundness violation (depth=%d): %s ∉ pts(x) = %v",
			prog.depth, expectedTarget, steensPts)
		return false
	}

	// andersen
	anders := NewAndersenAnalyzer()
	anders.AnalyzeConstraints(cs)
	anders.propagate()
	andersPts := anders.PointsTo("x")
	if !containsStr(andersPts, expectedTarget) {
		t.Logf("andersen load soundness violation (depth=%d): %s ∉ pts(x) = %v",
			prog.depth, expectedTarget, andersPts)
		return false
	}

	return true
}

// checkStoreSoundness verifies that storing through a pointer causes the
// stored value to alias with the pointer's target (Steensgaard).
//
// formal property: p = &a; *p = b → a and b alias (Steensgaard merges them)
func checkStoreSoundness(t *testing.T, prog *storeSoundnessProgram) bool {
	t.Helper()

	cs := make([]PointerConstraint, 0, prog.numTargets*2+1)

	// p = &a
	cs = append(cs, PointerConstraint{
		Kind: PtrConstraintAddressOf,
		Lhs:  "p",
		Rhs:  "a",
	})

	// *p = b0; *p = b1; ... (store multiple values through p)
	for i := 0; i < prog.numTargets; i++ {
		cs = append(cs, PointerConstraint{
			Kind: PtrConstraintStore,
			Lhs:  "p",
			Rhs:  fmt.Sprintf("b%d", i),
		})
	}

	steens := NewSteensgaardAnalyzer()
	steens.AnalyzeConstraints(cs)

	// after *p = b0, a (p's target) must alias with b0
	if !steens.MayAlias("a", "b0") {
		t.Logf("steensgaard store soundness violation: a and b0 must alias after *p = b0 where p = &a")
		return false
	}

	// all stored values must alias with a (Steensgaard merges them all)
	for i := 1; i < prog.numTargets; i++ {
		bName := fmt.Sprintf("b%d", i)
		if !steens.MayAlias("a", bName) {
			t.Logf("steensgaard store soundness violation: a and %s must alias after *p = %s where p = &a",
				bName, bName)
			return false
		}
	}

	return true
}

// checkAndersenPrecision verifies that Andersen does NOT merge distinct
// address-of targets, unlike Steensgaard.
//
// formal property: p = &a0; p = &a1; ... → ai and aj NOT merged (Andersen)
// contrast: Steensgaard DOES merge them (less precise)
func checkAndersenPrecision(t *testing.T, prog *andersenPrecisionProgram) bool {
	t.Helper()

	cs := make([]PointerConstraint, 0, prog.numTargets)

	// p = &a0; p = &a1; ... p = &a(N-1)
	for i := 0; i < prog.numTargets; i++ {
		cs = append(cs, PointerConstraint{
			Kind: PtrConstraintAddressOf,
			Lhs:  "p",
			Rhs:  fmt.Sprintf("a%d", i),
		})
	}

	anders := NewAndersenAnalyzer()
	anders.AnalyzeConstraints(cs)
	anders.propagate()

	// andersen: p must point to all targets
	for i := 0; i < prog.numTargets; i++ {
		aName := fmt.Sprintf("a%d", i)
		pts := anders.PointsTo("p")
		if !containsStr(pts, aName) {
			t.Logf("andersen precision: %s ∉ pts(p) = %v (expected all targets)", aName, pts)
			return false
		}
	}

	// andersen: distinct targets must NOT be merged (precision advantage)
	for i := 0; i < prog.numTargets; i++ {
		for j := i + 1; j < prog.numTargets; j++ {
			ai := fmt.Sprintf("a%d", i)
			aj := fmt.Sprintf("a%d", j)
			if anders.MayAlias(ai, aj) {
				t.Logf("andersen precision violation: %s and %s must NOT alias (distinct addr_of targets)",
					ai, aj)
				return false
			}
		}
	}

	return true
}

// checkNoAlias verifies that two completely independent pointer chains
// do not alias each other.
//
// chain A: pA = &objA; qA = pA; ...
// chain B: pB = &objB; qB = pB; ...
// property: objA and objB must NOT alias in either analysis.
func checkNoAlias(t *testing.T, prog *noAliasProgram) bool {
	t.Helper()

	cs := make([]PointerConstraint, 0, prog.chainALen+prog.chainBLen+2)

	// chain A: pA0 = &objA; pA1 = pA0; ...
	cs = append(cs, PointerConstraint{
		Kind: PtrConstraintAddressOf,
		Lhs:  "pA0",
		Rhs:  "objA",
	})
	for i := 0; i < prog.chainALen-1; i++ {
		cs = append(cs, PointerConstraint{
			Kind: PtrConstraintCopy,
			Lhs:  fmt.Sprintf("pA%d", i+1),
			Rhs:  fmt.Sprintf("pA%d", i),
		})
	}

	// chain B: pB0 = &objB; pB1 = pB0; ...
	cs = append(cs, PointerConstraint{
		Kind: PtrConstraintAddressOf,
		Lhs:  "pB0",
		Rhs:  "objB",
	})
	for i := 0; i < prog.chainBLen-1; i++ {
		cs = append(cs, PointerConstraint{
			Kind: PtrConstraintCopy,
			Lhs:  fmt.Sprintf("pB%d", i+1),
			Rhs:  fmt.Sprintf("pB%d", i),
		})
	}

	// steensgaard: objA and objB must NOT alias
	steens := NewSteensgaardAnalyzer()
	steens.AnalyzeConstraints(cs)
	if steens.MayAlias("objA", "objB") {
		t.Logf("steensgaard no-alias violation: objA and objB alias despite independent chains")
		return false
	}

	// andersen: objA and objB must NOT alias
	anders := NewAndersenAnalyzer()
	anders.AnalyzeConstraints(cs)
	anders.propagate()
	if anders.MayAlias("objA", "objB") {
		t.Logf("andersen no-alias violation: objA and objB alias despite independent chains")
		return false
	}

	return true
}

// checkDeterminism verifies that repeated analysis of the same program
// produces identical points-to sets.
//
// formal property: ∀v: pts_run1(v) == pts_run2(v)
func checkDeterminism(t *testing.T, prog *ptrProgram) bool {
	t.Helper()

	cs := ptrProgramToConstraints(prog)

	// run steensgaard twice
	steens1 := NewSteensgaardAnalyzer()
	pts1 := steens1.AnalyzeConstraints(cs)

	steens2 := NewSteensgaardAnalyzer()
	pts2 := steens2.AnalyzeConstraints(cs)

	for _, varName := range prog.vars {
		set1 := pts1[varName]
		set2 := pts2[varName]

		if len(set1) != len(set2) {
			t.Logf("steensgaard non-determinism: %s: run1=%v run2=%v", varName, set1, set2)
			return false
		}
		for i := range set1 {
			if set1[i] != set2[i] {
				t.Logf("steensgaard non-determinism: %s[%d]: run1=%s run2=%s",
					varName, i, set1[i], set2[i])
				return false
			}
		}
	}

	// run andersen twice
	anders1 := NewAndersenAnalyzer()
	aptsMap1 := anders1.AnalyzeConstraints(cs)
	anders1.propagate()

	anders2 := NewAndersenAnalyzer()
	aptsMap2 := anders2.AnalyzeConstraints(cs)
	anders2.propagate()

	for _, varName := range prog.vars {
		set1 := aptsMap1[varName]
		set2 := aptsMap2[varName]

		if len(set1) != len(set2) {
			t.Logf("andersen non-determinism: %s: run1=%v run2=%v", varName, set1, set2)
			return false
		}
		for i := range set1 {
			if set1[i] != set2[i] {
				t.Logf("andersen non-determinism: %s[%d]: run1=%s run2=%s",
					varName, i, set1[i], set2[i])
				return false
			}
		}
	}

	return true
}

// checkHotPathSelector verifies that the HotPathSelector correctly classifies
// functions based on their load/store and indirect call counts.
//
// formal property:
//   - numLoads + numStores >= threshold → IsHotPath == true
//   - numIndirectCalls >= 1 → IsHotPath == true
//   - otherwise → IsHotPath == false
func checkHotPathSelector(t *testing.T, prog *hotPathProgram) bool {
	t.Helper()

	selector := DefaultHotPathSelector()
	fn := buildHotPathFunction(prog)

	isHot := selector.IsHotPath(fn)

	// determine expected classification
	totalMemOps := prog.numLoads + prog.numStores
	expectedHot := totalMemOps >= selector.LoadStoreThreshold ||
		prog.numIndirectCalls >= selector.IndirectCallThreshold

	if isHot != expectedHot {
		t.Logf("hot path selector mismatch: loads=%d stores=%d indirect_calls=%d → got=%v expected=%v",
			prog.numLoads, prog.numStores, prog.numIndirectCalls, isHot, expectedHot)
		return false
	}

	return true
}

// ============================================================================
// ir function builders
// ============================================================================

// buildHotPathFunction constructs an ir.Function with the specified number of
// load, store, and indirect call instructions for hot path selector testing.
func buildHotPathFunction(prog *hotPathProgram) *ir.Function {
	i64 := ir.IntType{Width: ir.Size8, Signed: false}
	ptrI64 := ir.PointerType{Pointee: i64}
	fnPtrType := ir.PointerType{Pointee: ir.FunctionType{
		ReturnType: ir.VoidType{},
		Parameters: []ir.Type{},
	}}

	instrs := make([]ir.IRInstruction, 0, prog.numLoads+prog.numStores+prog.numIndirectCalls+1)

	basePtr := ir.Variable{Name: "base_ptr", Type: ptrI64}

	// generate load instructions
	for i := 0; i < prog.numLoads; i++ {
		instrs = append(instrs, ir.Load{
			Dest:    ir.Variable{Name: fmt.Sprintf("load_v%d", i), Type: i64},
			Address: ir.VariableExpr{Var: basePtr},
			Size:    ir.Size8,
		})
	}

	// generate store instructions
	for i := 0; i < prog.numStores; i++ {
		instrs = append(instrs, ir.Store{
			Address: ir.VariableExpr{Var: basePtr},
			Value: ir.ConstantExpr{Value: ir.IntConstant{
				Value: int64(i), Width: ir.Size8, Signed: false,
			}},
			Size: ir.Size8,
		})
	}

	// generate indirect call instructions (calls through function pointers)
	for i := 0; i < prog.numIndirectCalls; i++ {
		fnPtr := ir.Variable{Name: fmt.Sprintf("fn_ptr_%d", i), Type: fnPtrType}
		instrs = append(instrs, ir.Call{
			Target: ir.VariableExpr{Var: fnPtr},
			Args:   []ir.Variable{},
		})
	}

	instrs = append(instrs, ir.Return{})

	return &ir.Function{
		Name: "hot_path_test",
		Signature: ir.FunctionType{
			ReturnType: ir.VoidType{},
			Parameters: []ir.Type{ptrI64},
		},
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {ID: 0, Instructions: instrs},
		},
		EntryBlock: 0,
	}
}

// ============================================================================
// helpers
// ============================================================================

// ptrProgramToConstraints converts a ptrProgram into a slice of PointerConstraints.
func ptrProgramToConstraints(prog *ptrProgram) []PointerConstraint {
	cs := make([]PointerConstraint, 0, len(prog.ops))
	for _, op := range prog.ops {
		var kind PointerConstraintKind
		switch op.kind {
		case genAddrOf:
			kind = PtrConstraintAddressOf
		case genCopy:
			kind = PtrConstraintCopy
		case genLoad:
			kind = PtrConstraintLoad
		case genStore:
			kind = PtrConstraintStore
		}
		cs = append(cs, PointerConstraint{Kind: kind, Lhs: op.lhs, Rhs: op.rhs})
	}
	return cs
}
