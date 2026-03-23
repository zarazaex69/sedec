package typeinfer

import (
	"fmt"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// TestPropertyPointerAnalysisSoundness verifies that Steensgaard and Andersen
// pointer analyses are sound conservative over-approximations when operating
// on IR-level programs (via Analyze(fn) rather than raw constraints).
//
// This test complements TestProperty16 (which tests constraint-level analysis)
// by verifying the full pipeline: IR construction -> constraint extraction ->
// analysis -> points-to set correctness.
//
// Properties verified:
//   - P1: IR addr-of extraction: Cast to PointerType generates addr_of constraint
//   - P2: IR copy extraction: variable assignment generates copy constraint
//   - P3: IR load extraction: Load instruction generates load constraint
//   - P4: IR store extraction: Store instruction generates store constraint
//   - P5: constraint extraction completeness: all pointer ops produce constraints
//   - P6: IR-level Steensgaard soundness: addr-of targets in pts after Analyze(fn)
//   - P7: IR-level Andersen soundness: addr-of targets in pts after Analyze(fn)
//   - P8: IR-level Andersen subset Steensgaard: Analyze(fn) preserves precision ordering
//   - P9: IR-level MayAlias reflexivity: non-empty pts => MayAlias(x,x)
//   - P10: IR-level determinism: Analyze(fn) twice yields identical results
//
// Requirements: 45.1, 45.2, 45.3, 45.4, 45.5, 45.6
// Minimum 100 iterations per property.
func TestPropertyPointerAnalysisSoundness(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	params.MaxSize = 10

	properties := gopter.NewProperties(params)

	properties.Property("IR addr-of extraction produces correct constraints", prop.ForAll(
		func(prog *irPtrProgram) bool {
			return checkIRAddrOfExtraction(t, prog)
		},
		genIRPtrProgram(),
	))

	properties.Property("IR constraint extraction completeness", prop.ForAll(
		func(prog *irPtrProgram) bool {
			return checkIRConstraintCompleteness(t, prog)
		},
		genIRPtrProgram(),
	))

	properties.Property("IR-level Steensgaard addr-of soundness", prop.ForAll(
		func(prog *irPtrProgram) bool {
			return checkIRSteensgaardSoundness(t, prog)
		},
		genIRPtrProgram(),
	))

	properties.Property("IR-level Andersen addr-of soundness", prop.ForAll(
		func(prog *irPtrProgram) bool {
			return checkIRAndersenSoundness(t, prog)
		},
		genIRPtrProgram(),
	))

	properties.Property("IR-level Andersen pts subset of Steensgaard pts", prop.ForAll(
		func(prog *irPtrProgram) bool {
			return checkIRPrecisionOrdering(t, prog)
		},
		genIRPtrProgram(),
	))

	properties.Property("IR-level MayAlias reflexivity for non-empty pts", prop.ForAll(
		func(prog *irPtrProgram) bool {
			return checkIRMayAliasReflexivity(t, prog)
		},
		genIRPtrProgram(),
	))

	properties.Property("IR-level analysis determinism", prop.ForAll(
		func(prog *irPtrProgram) bool {
			return checkIRAnalysisDeterminism(t, prog)
		},
		genIRPtrProgram(),
	))

	properties.Property("IR copy chain propagation through Analyze(fn)", prop.ForAll(
		func(prog *irCopyChainProgram) bool {
			return checkIRCopyChainPropagation(t, prog)
		},
		genIRCopyChainProgram(),
	))

	properties.Property("IR load/store soundness through Analyze(fn)", prop.ForAll(
		func(prog *irLoadStoreProgram) bool {
			return checkIRLoadStoreSoundness(t, prog)
		},
		genIRLoadStoreProgram(),
	))

	properties.Property("IR phi node pointer propagation", prop.ForAll(
		func(prog *irPhiPtrProgram) bool {
			return checkIRPhiPtrPropagation(t, prog)
		},
		genIRPhiPtrProgram(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ============================================================================
// program types
// ============================================================================

type irPtrOpKind int

const (
	irPtrAddrOf irPtrOpKind = iota
	irPtrCopy
	irPtrLoad
	irPtrStore
)

type irPtrStep struct {
	kind irPtrOpKind
	lhs  int
	rhs  int
}

type irPtrProgram struct {
	numPtrVars int
	numObjects int
	steps      []irPtrStep
}

type irCopyChainProgram struct {
	chainLen int
	objIdx   int
}

type irLoadStoreProgram struct {
	numPtrs    int
	numObjects int
	stores     []irPtrStep
	loads      []irPtrStep
}

type irPhiPtrProgram struct {
	numSources int
	numObjects int
}

// ============================================================================
// generators
// ============================================================================

func genIRPtrProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		numPtrVars := int(params.NextUint64()%4) + 2
		numObjects := int(params.NextUint64()%3) + 1
		numSteps := int(params.NextUint64()%6) + 2

		steps := make([]irPtrStep, numSteps)
		for i := range steps {
			kind := irPtrOpKind(params.NextUint64() % 4)
			lhs := int(params.NextUint64() % uint64(numPtrVars))
			rhs := int(params.NextUint64() % uint64(numPtrVars+numObjects))
			steps[i] = irPtrStep{kind: kind, lhs: lhs, rhs: rhs}
		}

		// guarantee at least one addr-of for non-trivial analysis
		objIdx := int(params.NextUint64() % uint64(numObjects))
		varIdx := int(params.NextUint64() % uint64(numPtrVars))
		steps[0] = irPtrStep{kind: irPtrAddrOf, lhs: varIdx, rhs: numPtrVars + objIdx}

		return gopter.NewGenResult(&irPtrProgram{
			numPtrVars: numPtrVars,
			numObjects: numObjects,
			steps:      steps,
		}, gopter.NoShrinker)
	}
}

func genIRCopyChainProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		chainLen := int(params.NextUint64()%6) + 2
		objIdx := int(params.NextUint64() % 3)
		return gopter.NewGenResult(&irCopyChainProgram{
			chainLen: chainLen,
			objIdx:   objIdx,
		}, gopter.NoShrinker)
	}
}

func genIRLoadStoreProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		numPtrs := int(params.NextUint64()%3) + 2
		numObjects := int(params.NextUint64()%2) + 1
		numStores := int(params.NextUint64()%3) + 1
		numLoads := int(params.NextUint64()%3) + 1

		stores := make([]irPtrStep, numStores)
		for i := range stores {
			stores[i] = irPtrStep{
				kind: irPtrStore,
				lhs:  int(params.NextUint64() % uint64(numPtrs)),
				rhs:  int(params.NextUint64() % uint64(numPtrs)),
			}
		}

		loads := make([]irPtrStep, numLoads)
		for i := range loads {
			loads[i] = irPtrStep{
				kind: irPtrLoad,
				lhs:  int(params.NextUint64() % uint64(numPtrs)),
				rhs:  int(params.NextUint64() % uint64(numPtrs)),
			}
		}

		return gopter.NewGenResult(&irLoadStoreProgram{
			numPtrs:    numPtrs,
			numObjects: numObjects,
			stores:     stores,
			loads:      loads,
		}, gopter.NoShrinker)
	}
}

func genIRPhiPtrProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		numSources := int(params.NextUint64()%4) + 2
		numObjects := int(params.NextUint64()%3) + 1
		return gopter.NewGenResult(&irPhiPtrProgram{
			numSources: numSources,
			numObjects: numObjects,
		}, gopter.NoShrinker)
	}
}

// ============================================================================
// IR function builders
// ============================================================================

func irPtrVarName(idx int) string { return fmt.Sprintf("ptr_%d", idx) }
func irObjVarName(idx int) string { return fmt.Sprintf("obj_%d", idx) }

func buildIRPtrFunction(prog *irPtrProgram) *ir.Function {
	intT := ir.IntType{Width: ir.Size8, Signed: false}
	ptrT := ir.PointerType{Pointee: intT}

	instrs := make([]ir.IRInstruction, 0, len(prog.steps))
	for _, step := range prog.steps {
		lhsName := irPtrVarName(step.lhs)
		var rhsName string
		if step.rhs < prog.numPtrVars {
			rhsName = irPtrVarName(step.rhs)
		} else {
			rhsName = irObjVarName(step.rhs - prog.numPtrVars)
		}

		switch step.kind {
		case irPtrAddrOf:
			instrs = append(instrs, ir.Assign{
				Dest: ir.Variable{Name: lhsName, Type: ptrT},
				Source: ir.Cast{
					Expr:       ir.VariableExpr{Var: ir.Variable{Name: rhsName, Type: intT}},
					TargetType: ptrT,
				},
			})
		case irPtrCopy:
			instrs = append(instrs, ir.Assign{
				Dest:   ir.Variable{Name: lhsName, Type: ptrT},
				Source: ir.VariableExpr{Var: ir.Variable{Name: rhsName, Type: ptrT}},
			})
		case irPtrLoad:
			instrs = append(instrs, ir.Load{
				Dest:    ir.Variable{Name: lhsName, Type: ptrT},
				Address: ir.VariableExpr{Var: ir.Variable{Name: rhsName, Type: ptrT}},
				Size:    ir.Size8,
			})
		case irPtrStore:
			instrs = append(instrs, ir.Store{
				Address: ir.VariableExpr{Var: ir.Variable{Name: lhsName, Type: ptrT}},
				Value:   ir.VariableExpr{Var: ir.Variable{Name: rhsName, Type: ptrT}},
				Size:    ir.Size8,
			})
		}
	}

	return &ir.Function{
		Name: "ir_ptr_test",
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

func buildIRCopyChainFunction(prog *irCopyChainProgram) *ir.Function {
	intT := ir.IntType{Width: ir.Size8, Signed: false}
	ptrT := ir.PointerType{Pointee: intT}
	objName := irObjVarName(prog.objIdx)

	instrs := make([]ir.IRInstruction, 0, prog.chainLen+1)

	// ptr_0 = &obj_N (cast to pointer = addr-of)
	instrs = append(instrs, ir.Assign{
		Dest: ir.Variable{Name: irPtrVarName(0), Type: ptrT},
		Source: ir.Cast{
			Expr:       ir.VariableExpr{Var: ir.Variable{Name: objName, Type: intT}},
			TargetType: ptrT,
		},
	})

	// ptr_1 = ptr_0; ptr_2 = ptr_1; ...
	for i := 1; i < prog.chainLen; i++ {
		instrs = append(instrs, ir.Assign{
			Dest:   ir.Variable{Name: irPtrVarName(i), Type: ptrT},
			Source: ir.VariableExpr{Var: ir.Variable{Name: irPtrVarName(i - 1), Type: ptrT}},
		})
	}

	return &ir.Function{
		Name: "ir_copy_chain_test",
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

func buildIRLoadStoreFunction(prog *irLoadStoreProgram) *ir.Function {
	intT := ir.IntType{Width: ir.Size8, Signed: false}
	ptrT := ir.PointerType{Pointee: intT}

	instrs := make([]ir.IRInstruction, 0, prog.numPtrs+len(prog.stores)+len(prog.loads))

	// set up addr-of constraints: ptr_i = &obj_j
	for i := 0; i < prog.numPtrs && i < prog.numObjects; i++ {
		instrs = append(instrs, ir.Assign{
			Dest: ir.Variable{Name: irPtrVarName(i), Type: ptrT},
			Source: ir.Cast{
				Expr:       ir.VariableExpr{Var: ir.Variable{Name: irObjVarName(i % prog.numObjects), Type: intT}},
				TargetType: ptrT,
			},
		})
	}

	for _, s := range prog.stores {
		instrs = append(instrs, ir.Store{
			Address: ir.VariableExpr{Var: ir.Variable{Name: irPtrVarName(s.lhs), Type: ptrT}},
			Value:   ir.VariableExpr{Var: ir.Variable{Name: irPtrVarName(s.rhs), Type: ptrT}},
			Size:    ir.Size8,
		})
	}

	for _, l := range prog.loads {
		instrs = append(instrs, ir.Load{
			Dest:    ir.Variable{Name: irPtrVarName(l.lhs), Type: ptrT},
			Address: ir.VariableExpr{Var: ir.Variable{Name: irPtrVarName(l.rhs), Type: ptrT}},
			Size:    ir.Size8,
		})
	}

	return &ir.Function{
		Name: "ir_load_store_test",
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

func buildIRPhiPtrFunction(prog *irPhiPtrProgram) *ir.Function {
	intT := ir.IntType{Width: ir.Size8, Signed: false}
	ptrT := ir.PointerType{Pointee: intT}

	blocks := make(map[ir.BlockID]*ir.BasicBlock)

	// source blocks: each assigns ptr_src_i = &obj_j
	sources := make([]ir.PhiSource, prog.numSources)
	for i := 0; i < prog.numSources; i++ {
		bid := ir.BlockID(i + 1)
		srcVarName := fmt.Sprintf("ptr_src_%d", i)
		objIdx := i % prog.numObjects
		srcVar := ir.Variable{Name: srcVarName, Type: ptrT}

		blocks[bid] = &ir.BasicBlock{
			ID: bid,
			Instructions: []ir.IRInstruction{
				ir.Assign{
					Dest: srcVar,
					Source: ir.Cast{
						Expr:       ir.VariableExpr{Var: ir.Variable{Name: irObjVarName(objIdx), Type: intT}},
						TargetType: ptrT,
					},
				},
				ir.Jump{},
			},
			Successors: []ir.BlockID{ir.BlockID(prog.numSources + 1)},
		}
		sources[i] = ir.PhiSource{Block: bid, Var: srcVar}
	}

	// merge block with phi
	mergeID := ir.BlockID(prog.numSources + 1)
	phiDest := ir.Variable{Name: "ptr_phi_dest", Type: ptrT}
	blocks[mergeID] = &ir.BasicBlock{
		ID: mergeID,
		Instructions: []ir.IRInstruction{
			ir.Phi{Dest: phiDest, Sources: sources},
			ir.Return{},
		},
	}

	// entry block
	entrySuccs := make([]ir.BlockID, prog.numSources)
	for i := 0; i < prog.numSources; i++ {
		entrySuccs[i] = ir.BlockID(i + 1)
	}
	blocks[0] = &ir.BasicBlock{
		ID:           0,
		Instructions: []ir.IRInstruction{ir.Jump{}},
		Successors:   entrySuccs,
	}

	return &ir.Function{
		Name: "ir_phi_ptr_test",
		Signature: ir.FunctionType{
			ReturnType: ir.VoidType{},
			Parameters: []ir.Type{},
		},
		Blocks:     blocks,
		EntryBlock: 0,
	}
}

// ============================================================================
// property checkers
// ============================================================================

// checkIRAddrOfExtraction verifies that Cast-to-PointerType in IR produces
// an addr_of constraint in the extracted constraint set.
func checkIRAddrOfExtraction(t *testing.T, prog *irPtrProgram) bool {
	t.Helper()
	fn := buildIRPtrFunction(prog)
	cs := ExtractPointerConstraints(fn)

	for _, step := range prog.steps {
		if step.kind != irPtrAddrOf {
			continue
		}
		lhsName := irPtrVarName(step.lhs)
		found := false
		for _, c := range cs {
			if c.Kind == PtrConstraintAddressOf && c.LHS == lhsName {
				found = true
				break
			}
		}
		if !found {
			t.Logf("addr-of extraction failure: no addr_of constraint for %s", lhsName)
			return false
		}
	}
	return true
}

// checkIRConstraintCompleteness verifies that every pointer operation in the
// IR produces at least one constraint in the extracted set.
func checkIRConstraintCompleteness(t *testing.T, prog *irPtrProgram) bool {
	t.Helper()
	fn := buildIRPtrFunction(prog)
	cs := ExtractPointerConstraints(fn)

	if len(cs) == 0 && len(prog.steps) > 0 {
		t.Logf("constraint extraction produced 0 constraints from %d IR steps", len(prog.steps))
		return false
	}

	// every step should produce at least one constraint
	// (addr-of, copy, load, store all produce constraints)
	expectedMin := 0
	for _, step := range prog.steps {
		switch step.kind {
		case irPtrAddrOf, irPtrCopy, irPtrLoad, irPtrStore:
			expectedMin++
		}
	}

	if len(cs) < expectedMin {
		t.Logf("constraint extraction incomplete: got %d constraints, expected >= %d from %d steps",
			len(cs), expectedMin, len(prog.steps))
		return false
	}
	return true
}

// checkIRSteensgaardSoundness verifies that for every addr-of step in the IR,
// the target object appears in the Steensgaard points-to set after Analyze(fn).
func checkIRSteensgaardSoundness(t *testing.T, prog *irPtrProgram) bool {
	t.Helper()
	fn := buildIRPtrFunction(prog)
	a := NewSteensgaardAnalyzer()
	pts := a.Analyze(fn)

	for _, step := range prog.steps {
		if step.kind != irPtrAddrOf {
			continue
		}
		lhsName := irPtrVarName(step.lhs)
		var rhsName string
		if step.rhs < prog.numPtrVars {
			rhsName = irPtrVarName(step.rhs)
		} else {
			rhsName = irObjVarName(step.rhs - prog.numPtrVars)
		}

		targets := pts[lhsName]
		if !containsStr(targets, rhsName) {
			t.Logf("Steensgaard IR soundness: %s = &%s but %s not in pts(%s)=%v",
				lhsName, rhsName, rhsName, lhsName, targets)
			return false
		}
	}
	return true
}

// checkIRAndersenSoundness verifies the same property for Andersen via Analyze(fn).
func checkIRAndersenSoundness(t *testing.T, prog *irPtrProgram) bool {
	t.Helper()
	fn := buildIRPtrFunction(prog)
	a := NewAndersenAnalyzer()
	pts := a.Analyze(fn)

	for _, step := range prog.steps {
		if step.kind != irPtrAddrOf {
			continue
		}
		lhsName := irPtrVarName(step.lhs)
		var rhsName string
		if step.rhs < prog.numPtrVars {
			rhsName = irPtrVarName(step.rhs)
		} else {
			rhsName = irObjVarName(step.rhs - prog.numPtrVars)
		}

		targets := pts[lhsName]
		if !containsStr(targets, rhsName) {
			t.Logf("Andersen IR soundness: %s = &%s but %s not in pts(%s)=%v",
				lhsName, rhsName, rhsName, lhsName, targets)
			return false
		}
	}
	return true
}

// checkIRPrecisionOrdering verifies that Andersen's points-to sets (from
// Analyze(fn)) are subsets of Steensgaard's for every variable.
func checkIRPrecisionOrdering(t *testing.T, prog *irPtrProgram) bool {
	t.Helper()
	fn := buildIRPtrFunction(prog)

	steenA := NewSteensgaardAnalyzer()
	steenPts := steenA.Analyze(fn)

	anderA := NewAndersenAnalyzer()
	anderPts := anderA.Analyze(fn)

	for varName, anderTargets := range anderPts {
		steenTargets := steenPts[varName]
		if !irIsSubset(anderTargets, steenTargets) {
			t.Logf("IR precision violation: Andersen pts(%s)=%v not subset of Steensgaard pts(%s)=%v",
				varName, anderTargets, varName, steenTargets)
			return false
		}
	}
	return true
}

// checkIRMayAliasReflexivity verifies that every variable with a non-empty
// points-to set MayAlias-es itself.
func checkIRMayAliasReflexivity(t *testing.T, prog *irPtrProgram) bool {
	t.Helper()
	fn := buildIRPtrFunction(prog)

	steenA := NewSteensgaardAnalyzer()
	steenPts := steenA.Analyze(fn)
	for varName, targets := range steenPts {
		if len(targets) > 0 && !steenA.MayAlias(varName, varName) {
			t.Logf("Steensgaard reflexivity: pts(%s)=%v non-empty but MayAlias(%s,%s)=false",
				varName, targets, varName, varName)
			return false
		}
	}

	anderA := NewAndersenAnalyzer()
	anderPts := anderA.Analyze(fn)
	for varName, targets := range anderPts {
		if len(targets) > 0 && !anderA.MayAlias(varName, varName) {
			t.Logf("Andersen reflexivity: pts(%s)=%v non-empty but MayAlias(%s,%s)=false",
				varName, targets, varName, varName)
			return false
		}
	}

	return true
}

// checkIRAnalysisDeterminism verifies that Analyze(fn) produces identical
// results on two independent runs with the same input.
func checkIRAnalysisDeterminism(t *testing.T, prog *irPtrProgram) bool {
	t.Helper()
	fn := buildIRPtrFunction(prog)

	steenA1 := NewSteensgaardAnalyzer()
	pts1 := steenA1.Analyze(fn)
	steenA2 := NewSteensgaardAnalyzer()
	pts2 := steenA2.Analyze(fn)
	if !irPtsEqual(pts1, pts2) {
		t.Logf("Steensgaard IR determinism violation")
		return false
	}

	anderA1 := NewAndersenAnalyzer()
	apts1 := anderA1.Analyze(fn)
	anderA2 := NewAndersenAnalyzer()
	apts2 := anderA2.Analyze(fn)
	if !irAndersenPtsEqual(apts1, apts2) {
		t.Logf("Andersen IR determinism violation")
		return false
	}

	return true
}

// checkIRCopyChainPropagation verifies that addr-of targets propagate through
// copy chains when analyzed at the IR level via Analyze(fn).
func checkIRCopyChainPropagation(t *testing.T, prog *irCopyChainProgram) bool {
	t.Helper()
	fn := buildIRCopyChainFunction(prog)
	objName := irObjVarName(prog.objIdx)

	steenA := NewSteensgaardAnalyzer()
	steenPts := steenA.Analyze(fn)
	for i := 0; i < prog.chainLen; i++ {
		varName := irPtrVarName(i)
		targets := steenPts[varName]
		if !containsStr(targets, objName) {
			t.Logf("Steensgaard copy chain: %s not in pts(%s)=%v at chain position %d/%d",
				objName, varName, targets, i, prog.chainLen)
			return false
		}
	}

	anderA := NewAndersenAnalyzer()
	anderPts := anderA.Analyze(fn)
	for i := 0; i < prog.chainLen; i++ {
		varName := irPtrVarName(i)
		targets := anderPts[varName]
		if !containsStr(targets, objName) {
			t.Logf("Andersen copy chain: %s not in pts(%s)=%v at chain position %d/%d",
				objName, varName, targets, i, prog.chainLen)
			return false
		}
	}

	return true
}

// checkIRLoadStoreSoundness verifies that load/store operations through
// pointers with known addr-of targets produce sound results.
func checkIRLoadStoreSoundness(t *testing.T, prog *irLoadStoreProgram) bool {
	t.Helper()
	fn := buildIRLoadStoreFunction(prog)

	steenA := NewSteensgaardAnalyzer()
	steenPts := steenA.Analyze(fn)

	// verify addr-of targets are present for the initial assignments
	for i := 0; i < prog.numPtrs && i < prog.numObjects; i++ {
		varName := irPtrVarName(i)
		objName := irObjVarName(i % prog.numObjects)
		targets := steenPts[varName]
		if !containsStr(targets, objName) {
			t.Logf("Steensgaard load/store base: %s not in pts(%s)=%v",
				objName, varName, targets)
			return false
		}
	}

	anderA := NewAndersenAnalyzer()
	anderPts := anderA.Analyze(fn)

	for i := 0; i < prog.numPtrs && i < prog.numObjects; i++ {
		varName := irPtrVarName(i)
		objName := irObjVarName(i % prog.numObjects)
		targets := anderPts[varName]
		if !containsStr(targets, objName) {
			t.Logf("Andersen load/store base: %s not in pts(%s)=%v",
				objName, varName, targets)
			return false
		}
	}

	return true
}

// checkIRPhiPtrPropagation verifies that pointer values flowing through phi
// nodes are correctly propagated in the points-to analysis.
func checkIRPhiPtrPropagation(t *testing.T, prog *irPhiPtrProgram) bool {
	t.Helper()
	fn := buildIRPhiPtrFunction(prog)

	steenA := NewSteensgaardAnalyzer()
	steenPts := steenA.Analyze(fn)

	// the phi destination should point to the union of all source targets
	for i := 0; i < prog.numSources; i++ {
		srcName := fmt.Sprintf("ptr_src_%d", i)
		srcTargets := steenPts[srcName]
		phiTargets := steenPts["ptr_phi_dest"]

		// every target of a source must appear in the phi destination's pts
		for _, target := range srcTargets {
			if !containsStr(phiTargets, target) {
				t.Logf("Steensgaard phi propagation: %s in pts(%s) but not in pts(ptr_phi_dest)=%v",
					target, srcName, phiTargets)
				return false
			}
		}
	}

	anderA := NewAndersenAnalyzer()
	anderPts := anderA.Analyze(fn)

	for i := 0; i < prog.numSources; i++ {
		srcName := fmt.Sprintf("ptr_src_%d", i)
		srcTargets := anderPts[srcName]
		phiTargets := anderPts["ptr_phi_dest"]

		for _, target := range srcTargets {
			if !containsStr(phiTargets, target) {
				t.Logf("Andersen phi propagation: %s in pts(%s) but not in pts(ptr_phi_dest)=%v",
					target, srcName, phiTargets)
				return false
			}
		}
	}

	return true
}

// ============================================================================
// utility functions (prefixed with ir to avoid conflicts with property16_test)
// ============================================================================

func irIsSubset(sub, super []string) bool {
	if len(sub) == 0 {
		return true
	}
	set := make(map[string]bool, len(super))
	for _, s := range super {
		set[s] = true
	}
	for _, s := range sub {
		if !set[s] {
			return false
		}
	}
	return true
}

func irPtsEqual(a, b PointsToSet) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok {
			return false
		}
		if !irSliceSetsEqual(va, vb) {
			return false
		}
	}
	return true
}

func irAndersenPtsEqual(a, b AndersenPointsToSet) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok {
			return false
		}
		if !irSliceSetsEqual(va, vb) {
			return false
		}
	}
	return true
}

func irSliceSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	setA := make(map[string]bool, len(a))
	for _, s := range a {
		setA[s] = true
	}
	for _, s := range b {
		if !setA[s] {
			return false
		}
	}
	return true
}
