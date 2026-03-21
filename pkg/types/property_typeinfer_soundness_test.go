package typeinfer

import (
	"fmt"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// TestPropertyTypeInferenceSoundness verifies type inference soundness across
// randomly generated IR programs containing mixed instruction types.
//
// Property (task 9.10): for all generated IR programs P:
//
//	let constraints = GenerateConstraints(P)
//	let solution    = Unify(constraints)
//	for all operations op in P:
//	    inferred types are compatible with the operation semantics
//
// This test goes beyond TestProperty13 by generating programs that combine
// arithmetic, memory, call, phi, cast, and return instructions in a single
// function, verifying that the full constraint generation + unification
// pipeline produces a sound type assignment for mixed-operation programs.
//
// Minimum 100 iterations per sub-property.
func TestPropertyTypeInferenceSoundness(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	params.MaxSize = 10

	properties := gopter.NewProperties(params)

	properties.Property("mixed-op programs have sound type assignments", prop.ForAll(
		func(prog *mixedOpProgram) bool {
			return checkMixedOpSoundness(t, prog)
		},
		genMixedOpProgram(),
	))

	properties.Property("call return types propagate correctly", prop.ForAll(
		func(prog *callReturnProgram) bool {
			return checkCallReturnSoundness(t, prog)
		},
		genCallReturnProgram(),
	))

	properties.Property("phi node sources unify to same type", prop.ForAll(
		func(prog *phiTypeProgram) bool {
			return checkPhiTypeSoundness(t, prog)
		},
		genPhiTypeProgram(),
	))

	properties.Property("cast constraints preserve target type", prop.ForAll(
		func(prog *castTypeProgram) bool {
			return checkCastTypeSoundness(t, prog)
		},
		genCastTypeProgram(),
	))

	properties.Property("nested pointer types are sound", prop.ForAll(
		func(prog *nestedPtrProgram) bool {
			return checkNestedPtrSoundness(t, prog)
		},
		genNestedPtrProgram(),
	))

	properties.Property("constraint generation is deterministic", prop.ForAll(
		func(prog *mixedOpProgram) bool {
			return checkConstraintDeterminism(t, prog)
		},
		genMixedOpProgram(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ============================================================================
// program types
// ============================================================================

type instrKind int

const (
	instrAssignArith instrKind = iota
	instrAssignCmp
	instrLoad
	instrStore
	instrCall
)

type mixedOpStep struct {
	kind     instrKind
	binOp    ir.BinaryOperator
	width    ir.Size
	signed   bool
	constVal int64
}

type mixedOpProgram struct {
	steps []mixedOpStep
	width ir.Size
}

type callReturnProgram struct {
	numParams  int
	paramWidth ir.Size
	retWidth   ir.Size
	numCalls   int
}

type phiTypeProgram struct {
	numSources int
	width      ir.Size
	signed     bool
}

type castTypeProgram struct {
	srcWidth  ir.Size
	dstWidth  ir.Size
	srcSigned bool
	dstSigned bool
}

type nestedPtrProgram struct {
	depth int
	width ir.Size
}

// ============================================================================
// generators
// ============================================================================

func genMixedOpProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		widths := []ir.Size{ir.Size1, ir.Size2, ir.Size4, ir.Size8}
		width := widths[params.NextUint64()%uint64(len(widths))]

		arithOps := []ir.BinaryOperator{
			ir.BinOpAdd, ir.BinOpSub, ir.BinOpMul,
			ir.BinOpAnd, ir.BinOpOr, ir.BinOpXor,
		}
		cmpOps := []ir.BinaryOperator{
			ir.BinOpEq, ir.BinOpNe, ir.BinOpLt, ir.BinOpGt,
		}

		kinds := []instrKind{instrAssignArith, instrAssignCmp, instrLoad, instrStore, instrCall}
		numSteps := int(params.NextUint64()%6) + 3
		steps := make([]mixedOpStep, numSteps)
		for i := range steps {
			k := kinds[params.NextUint64()%uint64(len(kinds))]
			var op ir.BinaryOperator
			switch k {
			case instrAssignArith:
				op = arithOps[params.NextUint64()%uint64(len(arithOps))]
			case instrAssignCmp:
				op = cmpOps[params.NextUint64()%uint64(len(cmpOps))]
			default:
				op = ir.BinOpAdd
			}
			steps[i] = mixedOpStep{
				kind:     k,
				binOp:    op,
				width:    width,
				signed:   params.NextUint64()%2 == 0,
				constVal: int64(params.NextUint64() % 128),
			}
		}

		return gopter.NewGenResult(&mixedOpProgram{steps: steps, width: width}, gopter.NoShrinker)
	}
}

func genCallReturnProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		widths := []ir.Size{ir.Size1, ir.Size2, ir.Size4, ir.Size8}
		return gopter.NewGenResult(&callReturnProgram{
			numParams:  int(params.NextUint64()%4) + 1,
			paramWidth: widths[params.NextUint64()%uint64(len(widths))],
			retWidth:   widths[params.NextUint64()%uint64(len(widths))],
			numCalls:   int(params.NextUint64()%3) + 1,
		}, gopter.NoShrinker)
	}
}

func genPhiTypeProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		widths := []ir.Size{ir.Size1, ir.Size2, ir.Size4, ir.Size8}
		return gopter.NewGenResult(&phiTypeProgram{
			numSources: int(params.NextUint64()%4) + 2,
			width:      widths[params.NextUint64()%uint64(len(widths))],
			signed:     params.NextUint64()%2 == 0,
		}, gopter.NoShrinker)
	}
}

func genCastTypeProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		widths := []ir.Size{ir.Size1, ir.Size2, ir.Size4, ir.Size8}
		return gopter.NewGenResult(&castTypeProgram{
			srcWidth:  widths[params.NextUint64()%uint64(len(widths))],
			dstWidth:  widths[params.NextUint64()%uint64(len(widths))],
			srcSigned: params.NextUint64()%2 == 0,
			dstSigned: params.NextUint64()%2 == 0,
		}, gopter.NoShrinker)
	}
}

func genNestedPtrProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		widths := []ir.Size{ir.Size1, ir.Size2, ir.Size4, ir.Size8}
		return gopter.NewGenResult(&nestedPtrProgram{
			depth: int(params.NextUint64()%3) + 1,
			width: widths[params.NextUint64()%uint64(len(widths))],
		}, gopter.NoShrinker)
	}
}

// ============================================================================
// property checkers
// ============================================================================

func checkMixedOpSoundness(t *testing.T, prog *mixedOpProgram) bool {
	t.Helper()
	fn := buildMixedOpFunction(prog)
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()
	sol := Unify(cs)

	for i, step := range prog.steps {
		switch step.kind {
		case instrAssignArith:
			destName := fmt.Sprintf("v_%d", i)
			destType := sol.Types[destName]
			if destType == nil {
				continue
			}
			if _, ok := destType.(ir.IntType); !ok {
				if _, ok2 := destType.(ir.BoolType); !ok2 {
					t.Logf("step %d arith: expected IntType or BoolType, got %T (%s)",
						i, destType, destType.String())
					return false
				}
			}

		case instrAssignCmp:
			destName := fmt.Sprintf("cmp_%d", i)
			destType := sol.Types[destName]
			if destType == nil {
				continue
			}
			if _, ok := destType.(ir.BoolType); !ok {
				t.Logf("step %d cmp: expected BoolType, got %T (%s)",
					i, destType, destType.String())
				return false
			}

		case instrLoad:
			ptrName := fmt.Sprintf("ptr_%d", i)
			ptrType := sol.Types[ptrName]
			if ptrType == nil {
				continue
			}
			if _, ok := ptrType.(ir.PointerType); !ok {
				t.Logf("step %d load: expected PointerType for %s, got %T (%s)",
					i, ptrName, ptrType, ptrType.String())
				return false
			}

		case instrStore:
			ptrName := fmt.Sprintf("sptr_%d", i)
			ptrType := sol.Types[ptrName]
			if ptrType == nil {
				continue
			}
			if _, ok := ptrType.(ir.PointerType); !ok {
				t.Logf("step %d store: expected PointerType for %s, got %T (%s)",
					i, ptrName, ptrType, ptrType.String())
				return false
			}

		case instrCall:
			retName := fmt.Sprintf("call_ret_%d", i)
			retType := sol.Types[retName]
			if retType == nil {
				continue
			}
			if _, ok := retType.(ir.IntType); !ok {
				if _, ok2 := retType.(ir.VoidType); !ok2 {
					t.Logf("step %d call: expected IntType or VoidType for return, got %T (%s)",
						i, retType, retType.String())
					return false
				}
			}
		}
	}
	return true
}

func checkCallReturnSoundness(t *testing.T, prog *callReturnProgram) bool {
	t.Helper()
	fn := buildCallReturnFunction(prog)
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()
	sol := Unify(cs)

	for i := 0; i < prog.numCalls; i++ {
		retName := fmt.Sprintf("ret_%d", i)
		retType := sol.Types[retName]
		if retType == nil {
			continue
		}
		if intT, ok := retType.(ir.IntType); ok {
			if intT.Width != prog.retWidth {
				t.Logf("call %d: return width mismatch: got %d, expected %d",
					i, intT.Width, prog.retWidth)
				return false
			}
		}
	}
	return true
}

func checkPhiTypeSoundness(t *testing.T, prog *phiTypeProgram) bool {
	t.Helper()
	fn := buildPhiTypeFunction(prog)
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()
	sol := Unify(cs)

	destType := sol.Types["phi_dest"]
	if destType == nil {
		return true
	}

	for i := 0; i < prog.numSources; i++ {
		srcName := fmt.Sprintf("phi_src_%d", i)
		srcType := sol.Types[srcName]
		if srcType == nil {
			continue
		}
		if !typesEqual(destType, srcType) {
			t.Logf("phi source %d type mismatch: dest=%s src=%s",
				i, destType.String(), srcType.String())
			return false
		}
	}
	return true
}

func checkCastTypeSoundness(t *testing.T, prog *castTypeProgram) bool {
	t.Helper()
	fn := buildCastTypeFunction(prog)
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()
	sol := Unify(cs)

	destType := sol.Types["cast_dest"]
	if destType == nil {
		return true
	}

	dstT := ir.IntType{Width: prog.dstWidth, Signed: prog.dstSigned}
	if typesEqual(destType, dstT) {
		return true
	}

	srcT := ir.IntType{Width: prog.srcWidth, Signed: prog.srcSigned}
	if typesEqual(destType, srcT) {
		return true
	}

	t.Logf("cast dest type %s is neither src (%s) nor dst (%s)",
		destType.String(), srcT.String(), dstT.String())
	return false
}

func checkNestedPtrSoundness(t *testing.T, prog *nestedPtrProgram) bool {
	t.Helper()
	fn := buildNestedPtrFunction(prog)
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()
	sol := Unify(cs)

	for i := 0; i < prog.depth; i++ {
		ptrName := fmt.Sprintf("ptr_%d", i)
		ptrType := sol.Types[ptrName]
		if ptrType == nil {
			continue
		}
		if _, ok := ptrType.(ir.PointerType); !ok {
			t.Logf("nested ptr level %d: expected PointerType, got %T (%s)",
				i, ptrType, ptrType.String())
			return false
		}
	}

	innerName := fmt.Sprintf("val_%d", prog.depth-1)
	innerType := sol.Types[innerName]
	if innerType == nil {
		return true
	}
	if _, ok := innerType.(ir.IntType); !ok {
		if _, ok2 := innerType.(ir.VoidType); !ok2 {
			t.Logf("innermost value: expected IntType, got %T (%s)",
				innerType, innerType.String())
			return false
		}
	}
	return true
}

func checkConstraintDeterminism(t *testing.T, prog *mixedOpProgram) bool {
	t.Helper()
	fn := buildMixedOpFunction(prog)

	g1 := NewConstraintGenerator(fn)
	cs1 := g1.GenerateConstraints()
	sol1 := Unify(cs1)

	g2 := NewConstraintGenerator(fn)
	cs2 := g2.GenerateConstraints()
	sol2 := Unify(cs2)

	// compare only IR-defined variable types (skip synthetic $expr_N / $const_N
	// variables whose names depend on the global atomic counter)
	irVarNames := collectIRVarNames(fn)

	for _, name := range irVarNames {
		t1 := sol1.Types[name]
		t2 := sol2.Types[name]
		s1 := typeString(t1)
		s2 := typeString(t2)
		if s1 != s2 {
			t.Logf("determinism violation: %s: %s vs %s", name, s1, s2)
			return false
		}
	}
	return true
}

func collectIRVarNames(fn *ir.Function) []string {
	seen := make(map[string]bool)
	for _, block := range fn.Blocks {
		for _, instr := range block.Instructions {
			switch inst := instr.(type) {
			case ir.Assign:
				seen[inst.Dest.String()] = true
			case ir.Load:
				seen[inst.Dest.String()] = true
			case ir.Call:
				if inst.Dest != nil {
					seen[inst.Dest.String()] = true
				}
			case ir.Phi:
				seen[inst.Dest.String()] = true
			}
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	return names
}

// ============================================================================
// IR function builders
// ============================================================================

func buildMixedOpFunction(prog *mixedOpProgram) *ir.Function {
	intT := ir.IntType{Width: prog.width, Signed: true}
	instrs := make([]ir.IRInstruction, 0, len(prog.steps)*2+2)

	seed := ir.Variable{Name: "seed", Type: intT}
	instrs = append(instrs, ir.Assign{
		Dest:   seed,
		Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: prog.width, Signed: true}},
	})

	prevVar := seed
	for i, step := range prog.steps {
		switch step.kind {
		case instrAssignArith:
			dest := ir.Variable{Name: fmt.Sprintf("v_%d", i), Type: intT}
			instrs = append(instrs, ir.Assign{
				Dest: dest,
				Source: ir.BinaryOp{
					Op:   step.binOp,
					Left: ir.VariableExpr{Var: prevVar},
					Right: ir.ConstantExpr{Value: ir.IntConstant{
						Value: step.constVal, Width: prog.width, Signed: step.signed,
					}},
				},
			})
			prevVar = dest

		case instrAssignCmp:
			dest := ir.Variable{Name: fmt.Sprintf("cmp_%d", i), Type: ir.BoolType{}}
			instrs = append(instrs, ir.Assign{
				Dest: dest,
				Source: ir.BinaryOp{
					Op:   step.binOp,
					Left: ir.VariableExpr{Var: prevVar},
					Right: ir.ConstantExpr{Value: ir.IntConstant{
						Value: step.constVal, Width: prog.width, Signed: step.signed,
					}},
				},
			})

		case instrLoad:
			ptrVar := ir.Variable{Name: fmt.Sprintf("ptr_%d", i), Type: ir.PointerType{Pointee: intT}}
			loadDest := ir.Variable{Name: fmt.Sprintf("loaded_%d", i), Type: intT}
			instrs = append(instrs, ir.Load{
				Dest:    loadDest,
				Address: ir.VariableExpr{Var: ptrVar},
				Size:    prog.width,
			})
			prevVar = loadDest

		case instrStore:
			ptrVar := ir.Variable{Name: fmt.Sprintf("sptr_%d", i), Type: ir.PointerType{Pointee: intT}}
			instrs = append(instrs, ir.Store{
				Address: ir.VariableExpr{Var: ptrVar},
				Value:   ir.VariableExpr{Var: prevVar},
				Size:    prog.width,
			})

		case instrCall:
			retVar := ir.Variable{Name: fmt.Sprintf("call_ret_%d", i), Type: intT}
			target := ir.Variable{Name: fmt.Sprintf("func_%d", i), Type: ir.FunctionType{
				ReturnType: intT,
				Parameters: []ir.Type{intT},
			}}
			instrs = append(instrs, ir.Call{
				Dest:   &retVar,
				Target: ir.VariableExpr{Var: target},
				Args:   []ir.Variable{prevVar},
			})
			prevVar = retVar
		}
	}

	instrs = append(instrs, ir.Return{Value: &prevVar})

	return &ir.Function{
		Name: "mixed_op_test",
		Signature: ir.FunctionType{
			ReturnType: intT,
			Parameters: []ir.Type{},
		},
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {ID: 0, Instructions: instrs},
		},
		EntryBlock: 0,
	}
}

func buildCallReturnFunction(prog *callReturnProgram) *ir.Function {
	retT := ir.IntType{Width: prog.retWidth, Signed: true}
	paramT := ir.IntType{Width: prog.paramWidth, Signed: true}

	paramTypes := make([]ir.Type, prog.numParams)
	for i := range paramTypes {
		paramTypes[i] = paramT
	}
	funcT := ir.FunctionType{ReturnType: retT, Parameters: paramTypes}

	instrs := make([]ir.IRInstruction, 0, prog.numCalls*2+1)

	params := make([]ir.Variable, prog.numParams)
	for i := range params {
		params[i] = ir.Variable{
			Name: fmt.Sprintf("p_%d", i),
			Type: paramT,
		}
		instrs = append(instrs, ir.Assign{
			Dest:   params[i],
			Source: ir.ConstantExpr{Value: ir.IntConstant{Value: int64(i), Width: prog.paramWidth, Signed: true}},
		})
	}

	target := ir.Variable{Name: "callee", Type: funcT}
	var lastRet ir.Variable
	for i := 0; i < prog.numCalls; i++ {
		retVar := ir.Variable{Name: fmt.Sprintf("ret_%d", i), Type: retT}
		instrs = append(instrs, ir.Call{
			Dest:   &retVar,
			Target: ir.VariableExpr{Var: target},
			Args:   params,
		})
		lastRet = retVar
	}

	instrs = append(instrs, ir.Return{Value: &lastRet})

	return &ir.Function{
		Name: "call_return_test",
		Signature: ir.FunctionType{
			ReturnType: retT,
			Parameters: paramTypes,
		},
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {ID: 0, Instructions: instrs},
		},
		EntryBlock: 0,
	}
}

func buildPhiTypeFunction(prog *phiTypeProgram) *ir.Function {
	intT := ir.IntType{Width: prog.width, Signed: prog.signed}

	blocks := make(map[ir.BlockID]*ir.BasicBlock)

	sources := make([]ir.PhiSource, prog.numSources)
	for i := 0; i < prog.numSources; i++ {
		bid := ir.BlockID(i + 1)
		srcVar := ir.Variable{
			Name: fmt.Sprintf("phi_src_%d", i),
			Type: intT,
		}
		sources[i] = ir.PhiSource{Block: bid, Var: srcVar}

		blocks[bid] = &ir.BasicBlock{
			ID: bid,
			Instructions: []ir.IRInstruction{
				ir.Assign{
					Dest:   srcVar,
					Source: ir.ConstantExpr{Value: ir.IntConstant{Value: int64(i), Width: prog.width, Signed: prog.signed}},
				},
				ir.Jump{},
			},
			Successors: []ir.BlockID{ir.BlockID(prog.numSources + 1)},
		}
	}

	mergeID := ir.BlockID(prog.numSources + 1)
	phiDest := ir.Variable{Name: "phi_dest", Type: intT}
	blocks[mergeID] = &ir.BasicBlock{
		ID: mergeID,
		Instructions: []ir.IRInstruction{
			ir.Phi{Dest: phiDest, Sources: sources},
			ir.Return{Value: &phiDest},
		},
	}

	entrySuccessors := make([]ir.BlockID, prog.numSources)
	for i := 0; i < prog.numSources; i++ {
		entrySuccessors[i] = ir.BlockID(i + 1)
	}
	blocks[0] = &ir.BasicBlock{
		ID:           0,
		Instructions: []ir.IRInstruction{ir.Jump{}},
		Successors:   entrySuccessors,
	}

	return &ir.Function{
		Name: "phi_type_test",
		Signature: ir.FunctionType{
			ReturnType: intT,
			Parameters: []ir.Type{},
		},
		Blocks:     blocks,
		EntryBlock: 0,
	}
}

func buildCastTypeFunction(prog *castTypeProgram) *ir.Function {
	srcT := ir.IntType{Width: prog.srcWidth, Signed: prog.srcSigned}
	dstT := ir.IntType{Width: prog.dstWidth, Signed: prog.dstSigned}

	srcVar := ir.Variable{Name: "cast_src", Type: srcT}
	destVar := ir.Variable{Name: "cast_dest", Type: dstT}

	return &ir.Function{
		Name: "cast_type_test",
		Signature: ir.FunctionType{
			ReturnType: dstT,
			Parameters: []ir.Type{srcT},
		},
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					ir.Assign{
						Dest:   srcVar,
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: prog.srcWidth, Signed: prog.srcSigned}},
					},
					ir.Assign{
						Dest: destVar,
						Source: ir.Cast{
							Expr:       ir.VariableExpr{Var: srcVar},
							TargetType: dstT,
						},
					},
					ir.Return{Value: &destVar},
				},
			},
		},
		EntryBlock: 0,
	}
}

func buildNestedPtrFunction(prog *nestedPtrProgram) *ir.Function {
	innerT := ir.Type(ir.IntType{Width: prog.width, Signed: true})

	ptrTypes := make([]ir.Type, prog.depth)
	for i := prog.depth - 1; i >= 0; i-- {
		if i == prog.depth-1 {
			ptrTypes[i] = ir.PointerType{Pointee: innerT}
		} else {
			ptrTypes[i] = ir.PointerType{Pointee: ptrTypes[i+1]}
		}
	}

	instrs := make([]ir.IRInstruction, 0, prog.depth+1)

	for i := 0; i < prog.depth; i++ {
		ptrVar := ir.Variable{Name: fmt.Sprintf("ptr_%d", i), Type: ptrTypes[i]}
		var destType ir.Type
		if i < prog.depth-1 {
			destType = ptrTypes[i+1]
		} else {
			destType = innerT
		}
		valVar := ir.Variable{Name: fmt.Sprintf("val_%d", i), Type: destType}
		instrs = append(instrs, ir.Load{
			Dest:    valVar,
			Address: ir.VariableExpr{Var: ptrVar},
			Size:    ir.Size8,
		})
	}

	lastVal := ir.Variable{Name: fmt.Sprintf("val_%d", prog.depth-1), Type: innerT}
	instrs = append(instrs, ir.Return{Value: &lastVal})

	return &ir.Function{
		Name: "nested_ptr_test",
		Signature: ir.FunctionType{
			ReturnType: innerT,
			Parameters: []ir.Type{ptrTypes[0]},
		},
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {ID: 0, Instructions: instrs},
		},
		EntryBlock: 0,
	}
}
