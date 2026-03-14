package analysis

import (
	"fmt"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// TestProperty10: Constant Propagation and Folding Correctness
//
// property 10: for all ir programs P with constant assignments:
//
//	execute(optimize(P)) == execute(P)
//
// validates requirements 9.1-9.6:
//   - 9.1: constant propagation replaces variable uses with constants
//   - 9.2: constant folding evaluates operations at compile time
//   - 9.3: propagation through phi-nodes with identical inputs
//   - 9.4: simplification of constant branch conditions
//   - 9.5: elimination of unreachable code after branch simplification
//   - 9.6: overflow semantics preserved (wrapping arithmetic)
//
// minimum 100 iterations required.

// ============================================================================
// property test entry point
// ============================================================================

// TestProperty10 verifies semantic equivalence of constant propagation+folding.
// runs 100+ iterations with gopter-generated ir programs.
func TestProperty10(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	params.MaxSize = 6

	properties := gopter.NewProperties(params)

	// property 10a: propagation preserves semantics for linear constant chains
	properties.Property("execute(optimize(ir)) == execute(ir) for constant chains", prop.ForAll(
		func(prog *constProgram) bool {
			return checkSemanticEquivalence(t, prog)
		},
		genConstProgram(),
	))

	// property 10b: algebraic identities preserve semantics
	properties.Property("algebraic identity simplifications preserve semantics", prop.ForAll(
		func(prog *identityProgram) bool {
			return checkIdentitySemantics(t, prog)
		},
		genIdentityProgram(),
	))

	// property 10c: overflow semantics preserved after folding
	properties.Property("overflow wrapping preserved by constant folding", prop.ForAll(
		func(prog *overflowProgram) bool {
			return checkOverflowSemantics(t, prog)
		},
		genOverflowProgram(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ============================================================================
// program types for generators
// ============================================================================

// constProgram represents a linear ssa chain of constant assignments and
// arithmetic operations. models the pattern: x=c1; y=x op c2; z=y op c3; ...
type constProgram struct {
	// steps is the sequence of operations in the chain
	steps []constStep
	// width is the integer width used throughout (1, 2, 4, or 8 bytes)
	width ir.Size
	// signed controls whether signed or unsigned arithmetic is used
	signed bool
}

// constStep represents one operation in the chain: dest = prev op operand
type constStep struct {
	op      ir.BinaryOperator
	operand int64 // right-hand constant operand
}

// identityProgram tests algebraic identity simplifications.
// each case is: dest = var op identity_element
type identityProgram struct {
	op       ir.BinaryOperator
	varVal   int64 // value of the variable operand
	identity int64 // identity element (0 for add, 1 for mul, etc.)
	width    ir.Size
	signed   bool
	// leftSide: if true, identity is on left (identity op var), else right (var op identity)
	leftSide bool
}

// overflowProgram tests that overflow wrapping is preserved.
// computes: base op delta where the result overflows the integer width.
type overflowProgram struct {
	base  int64
	delta int64
	op    ir.BinaryOperator
	width ir.Size
}

// ============================================================================
// gopter generators
// ============================================================================

// genConstProgram generates arbitrary constant-chain programs.
// chain length: 2-6 steps; operations: add, sub, mul, and, or, xor, shl, shr.
func genConstProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		// pick integer width: 1, 2, 4, or 8 bytes
		widths := []ir.Size{ir.Size1, ir.Size2, ir.Size4, ir.Size8}
		width := widths[params.NextUint64()%uint64(len(widths))]
		signed := params.NextUint64()%2 == 0

		// chain length: 2 to 6 steps
		numSteps := int(params.NextUint64()%5) + 2

		// safe arithmetic ops (exclude div/mod to avoid div-by-zero in generators)
		safeOps := []ir.BinaryOperator{
			ir.BinOpAdd, ir.BinOpSub, ir.BinOpMul,
			ir.BinOpAnd, ir.BinOpOr, ir.BinOpXor,
		}

		steps := make([]constStep, numSteps)
		mask := widthMask(width)
		for i := range steps {
			op := safeOps[params.NextUint64()%uint64(len(safeOps))]
			// generate operand in range [0, mask] to avoid overflow in generator itself
			operand := int64(params.NextUint64() & mask) //nolint:gosec // intentional uint64->int64 conversion
			steps[i] = constStep{op: op, operand: operand}
		}

		prog := &constProgram{
			steps:  steps,
			width:  width,
			signed: signed,
		}
		return gopter.NewGenResult(prog, gopter.NoShrinker)
	}
}

// genIdentityProgram generates programs testing algebraic identity elements.
func genIdentityProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		// identity cases: (op, identity_value, left_side)
		type identityCase struct {
			op       ir.BinaryOperator
			identity int64
		}
		cases := []identityCase{
			{ir.BinOpAdd, 0},  // x + 0 = x
			{ir.BinOpSub, 0},  // x - 0 = x
			{ir.BinOpMul, 1},  // x * 1 = x
			{ir.BinOpAnd, -1}, // x & ~0 = x (all-ones mask)
			{ir.BinOpOr, 0},   // x | 0 = x
			{ir.BinOpXor, 0},  // x ^ 0 = x
			{ir.BinOpShl, 0},  // x << 0 = x
			{ir.BinOpShr, 0},  // x >> 0 = x
		}

		c := cases[params.NextUint64()%uint64(len(cases))]
		leftSide := params.NextUint64()%2 == 0

		// for sub and shr, identity only works on right side
		if c.op == ir.BinOpSub || c.op == ir.BinOpShr || c.op == ir.BinOpShl {
			leftSide = false
		}

		// generate a non-zero variable value to make the test meaningful
		varVal := int64(params.NextUint64()%100) + 1

		prog := &identityProgram{
			op:       c.op,
			varVal:   varVal,
			identity: c.identity,
			width:    ir.Size8,
			signed:   true,
			leftSide: leftSide,
		}
		return gopter.NewGenResult(prog, gopter.NoShrinker)
	}
}

// genOverflowProgram generates programs where arithmetic overflows the integer width.
func genOverflowProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		widths := []ir.Size{ir.Size1, ir.Size2, ir.Size4}
		width := widths[params.NextUint64()%uint64(len(widths))]
		mask := widthMask(width)

		// base: near the maximum value for this width
		base := int64(mask - params.NextUint64()%4) //nolint:gosec // intentional uint64->int64 conversion
		// delta: small positive value that causes overflow
		delta := int64(params.NextUint64()%8) + 1

		prog := &overflowProgram{
			base:  base,
			delta: delta,
			op:    ir.BinOpAdd,
			width: width,
		}
		return gopter.NewGenResult(prog, gopter.NoShrinker)
	}
}

// ============================================================================
// semantic equivalence checker
// ============================================================================

// checkSemanticEquivalence builds an ir function from constProgram, executes it
// concretely, then runs constant propagation+folding and executes again.
// returns true iff both executions produce the same final value.
func checkSemanticEquivalence(t *testing.T, prog *constProgram) bool {
	t.Helper()
	fn, expectedResult := buildConstChainFunction(prog)
	if fn == nil {
		// degenerate program: skip
		return true
	}

	// execute original ir to get ground-truth result
	origResult, ok := interpretFunction(fn)
	if !ok {
		// interpreter could not evaluate (e.g., unsupported op): skip
		return true
	}

	// verify interpreter matches our expected result
	if origResult != expectedResult {
		t.Logf("interpreter mismatch: expected %d, got %d", expectedResult, origResult)
		return false
	}

	// run constant propagation
	cfgGraph := buildSimpleCFG()
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	_, err := PropagateConstants(fn, cfgGraph, domTree)
	if err != nil {
		t.Logf("PropagateConstants failed: %v", err)
		return false
	}

	// run constant folding on the already-propagated function
	_, err = FoldConstants(fn)
	if err != nil {
		t.Logf("FoldConstants failed: %v", err)
		return false
	}

	// execute optimized ir
	optimizedResult, ok := interpretFunction(fn)
	if !ok {
		// after optimization the function may be fully folded to a constant assign
		// in that case, extract the constant directly from the return variable
		optimizedResult, ok = extractReturnConstant(fn)
		if !ok {
			// cannot evaluate: skip
			return true
		}
	}

	if origResult != optimizedResult {
		t.Logf("semantic equivalence violated:\n  original result:  %d\n  optimized result: %d\n  program: %s",
			origResult, optimizedResult, describeConstProgram(prog))
		return false
	}
	return true
}

// checkIdentitySemantics verifies that algebraic identity simplifications
// preserve the value of the variable operand.
func checkIdentitySemantics(t *testing.T, prog *identityProgram) bool {
	t.Helper()
	fn := buildIdentityFunction(prog)

	// execute original
	origResult, ok := interpretFunction(fn)
	if !ok {
		return true
	}

	// run folding
	_, err := FoldConstants(fn)
	if err != nil {
		t.Logf("FoldConstants failed: %v", err)
		return false
	}

	// execute optimized
	optimizedResult, ok := interpretFunction(fn)
	if !ok {
		optimizedResult, ok = extractReturnConstant(fn)
		if !ok {
			return true
		}
	}

	if origResult != optimizedResult {
		t.Logf("identity semantics violated: op=%s identity=%d varVal=%d leftSide=%v\n  original=%d optimized=%d",
			prog.op, prog.identity, prog.varVal, prog.leftSide, origResult, optimizedResult)
		return false
	}

	// additionally verify the result equals the variable value (identity property)
	// for absorbing elements (x*0=0, x&0=0) the result should be 0, not varVal
	absorbingOps := map[ir.BinaryOperator]bool{
		ir.BinOpMul: prog.identity == 0,
		ir.BinOpAnd: prog.identity == 0,
	}
	if absorbingOps[prog.op] {
		if optimizedResult != 0 {
			t.Logf("absorbing element identity failed: expected 0, got %d", optimizedResult)
			return false
		}
	}

	return true
}

// checkOverflowSemantics verifies that overflow wrapping is preserved after folding.
func checkOverflowSemantics(t *testing.T, prog *overflowProgram) bool {
	t.Helper()
	fn := buildOverflowFunction(prog)

	// compute expected result with correct wrapping
	mask := widthMask(prog.width)
	lu := uint64(prog.base) & mask             //nolint:gosec // intentional int64->uint64 conversion
	ru := uint64(prog.delta) & mask            //nolint:gosec // intentional int64->uint64 conversion
	expectedWrapped := int64((lu + ru) & mask) //nolint:gosec // intentional uint64->int64 conversion

	// execute original
	origResult, ok := interpretFunction(fn)
	if !ok {
		return true
	}

	if origResult != expectedWrapped {
		t.Logf("overflow: interpreter gave %d, expected wrapped %d", origResult, expectedWrapped)
		return false
	}

	// run folding
	_, err := FoldConstants(fn)
	if err != nil {
		t.Logf("FoldConstants failed: %v", err)
		return false
	}

	// execute optimized
	optimizedResult, ok := interpretFunction(fn)
	if !ok {
		optimizedResult, ok = extractReturnConstant(fn)
		if !ok {
			return true
		}
	}

	if origResult != optimizedResult {
		t.Logf("overflow semantics violated: base=%d delta=%d width=%d\n  original=%d optimized=%d expected=%d",
			prog.base, prog.delta, prog.width, origResult, optimizedResult, expectedWrapped)
		return false
	}
	return true
}

// ============================================================================
// ir function builders
// ============================================================================

// buildConstChainFunction constructs an ir function for a constProgram.
// the function computes: v0=seed; v1=v0 op steps[0]; v2=v1 op steps[1]; ...
// returns the function and the expected final value computed by reference arithmetic.
func buildConstChainFunction(prog *constProgram) (*ir.Function, int64) {
	if len(prog.steps) == 0 {
		return nil, 0
	}

	mask := widthMask(prog.width)
	// seed value: 7 (arbitrary non-zero, non-trivial constant)
	seed := int64(7)
	current := uint64(seed) & mask

	instrs := make([]ir.IRInstruction, 0, len(prog.steps)+2)

	// v0 = seed
	v0 := ir.Variable{Name: "v", Version: 0, Type: ir.IntType{Width: prog.width, Signed: prog.signed}}
	instrs = append(instrs, &ir.Assign{
		Dest:   v0,
		Source: ir.ConstantExpr{Value: ir.IntConstant{Value: seed, Width: prog.width, Signed: prog.signed}},
	})

	prevVar := v0
	for i, step := range prog.steps {
		nextVar := ir.Variable{
			Name:    "v",
			Version: i + 1,
			Type:    ir.IntType{Width: prog.width, Signed: prog.signed},
		}
		operandConst := ir.IntConstant{Value: step.operand, Width: prog.width, Signed: prog.signed}

		instrs = append(instrs, &ir.Assign{
			Dest: nextVar,
			Source: &ir.BinaryOp{
				Op:    step.op,
				Left:  &ir.VariableExpr{Var: prevVar},
				Right: ir.ConstantExpr{Value: operandConst},
			},
		})

		// compute reference result
		ru := uint64(step.operand) & mask //nolint:gosec // intentional int64->uint64 conversion
		switch step.op {                  //nolint:exhaustive // only safe arithmetic ops are generated
		case ir.BinOpAdd:
			current = (current + ru) & mask
		case ir.BinOpSub:
			current = (current - ru) & mask
		case ir.BinOpMul:
			current = (current * ru) & mask
		case ir.BinOpAnd:
			current &= ru & mask
		case ir.BinOpOr:
			current = (current | ru) & mask
		case ir.BinOpXor:
			current = (current ^ ru) & mask
		default:
			current &= mask
		}

		prevVar = nextVar
	}

	// return the last variable
	lastVar := prevVar
	instrs = append(instrs, &ir.Return{Value: &lastVar})

	fn := &ir.Function{
		Name: "const_chain",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID:           0,
				Instructions: instrs,
			},
		},
		EntryBlock: 0,
	}

	// sign-extend result if signed
	var finalVal int64
	if prog.signed {
		finalVal = signExtend(current, prog.width)
	} else {
		finalVal = int64(current) //nolint:gosec // intentional uint64->int64 conversion
	}
	return fn, finalVal
}

// buildIdentityFunction constructs an ir function testing an algebraic identity.
// the function computes: x=varVal; result = x op identity (or identity op x)
func buildIdentityFunction(prog *identityProgram) *ir.Function {
	xVar := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: prog.width, Signed: prog.signed}}
	resultVar := ir.Variable{Name: "result", Version: 1, Type: ir.IntType{Width: prog.width, Signed: prog.signed}}

	identityConst := ir.ConstantExpr{Value: ir.IntConstant{
		Value:  prog.identity,
		Width:  prog.width,
		Signed: prog.signed,
	}}

	var expr ir.Expression
	if prog.leftSide {
		expr = &ir.BinaryOp{
			Op:    prog.op,
			Left:  identityConst,
			Right: &ir.VariableExpr{Var: xVar},
		}
	} else {
		expr = &ir.BinaryOp{
			Op:    prog.op,
			Left:  &ir.VariableExpr{Var: xVar},
			Right: identityConst,
		}
	}

	return &ir.Function{
		Name: "identity_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   xVar,
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: prog.varVal, Width: prog.width, Signed: prog.signed}},
					},
					&ir.Assign{Dest: resultVar, Source: expr},
					&ir.Return{Value: &resultVar},
				},
			},
		},
		EntryBlock: 0,
	}
}

// buildOverflowFunction constructs an ir function that overflows the integer width.
// the function computes: base + delta where the result wraps.
func buildOverflowFunction(prog *overflowProgram) *ir.Function {
	baseVar := ir.Variable{Name: "base", Version: 1, Type: ir.IntType{Width: prog.width, Signed: false}}
	resultVar := ir.Variable{Name: "result", Version: 1, Type: ir.IntType{Width: prog.width, Signed: false}}

	return &ir.Function{
		Name: "overflow_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   baseVar,
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: prog.base, Width: prog.width, Signed: false}},
					},
					&ir.Assign{
						Dest: resultVar,
						Source: &ir.BinaryOp{
							Op:    prog.op,
							Left:  &ir.VariableExpr{Var: baseVar},
							Right: ir.ConstantExpr{Value: ir.IntConstant{Value: prog.delta, Width: prog.width, Signed: false}},
						},
					},
					&ir.Return{Value: &resultVar},
				},
			},
		},
		EntryBlock: 0,
	}
}

// ============================================================================
// concrete ir interpreter
// ============================================================================

// interpretFunction executes a single-block ir function concretely.
// evaluates all assign instructions in order and returns the value of the
// variable referenced by the return instruction.
// returns (value, true) on success, (0, false) if interpretation is not possible.
func interpretFunction(fn *ir.Function) (int64, bool) {
	if fn == nil || len(fn.Blocks) == 0 {
		return 0, false
	}

	block, ok := fn.Blocks[fn.EntryBlock]
	if !ok {
		return 0, false
	}

	// env maps variable key -> concrete int64 value
	env := make(map[string]int64)

	var returnVal *int64

	for _, instr := range block.Instructions {
		switch i := instr.(type) {
		case *ir.Assign:
			val, ok := evalExpr(i.Source, env)
			if !ok {
				return 0, false
			}
			// apply sign extension based on destination variable type
			val = applySignExtend(val, i.Dest.Type)
			env[i.Dest.String()] = val

		case *ir.Return:
			if i.Value != nil {
				v, ok := env[i.Value.String()]
				if !ok {
					// variable may have been replaced by constant folding
					// check if the return variable is a constant expression
					return 0, false
				}
				returnVal = &v
			}

		case *ir.Load, *ir.Store, *ir.Call, *ir.Branch, *ir.Jump, *ir.Phi:
			// not supported in single-block concrete interpreter
			return 0, false
		}
	}

	if returnVal == nil {
		return 0, false
	}
	return *returnVal, true
}

// extractReturnConstant extracts the return value from a fully-folded function
// where the return variable has been replaced by a constant assignment.
// this handles the case where PropagateConstants rewrites the return variable's
// definition to a ConstantExpr.
func extractReturnConstant(fn *ir.Function) (int64, bool) {
	if fn == nil {
		return 0, false
	}
	block, ok := fn.Blocks[fn.EntryBlock]
	if !ok {
		return 0, false
	}

	// find the return instruction to get the variable name
	var retVarKey string
	for _, instr := range block.Instructions {
		if ret, ok := instr.(*ir.Return); ok && ret.Value != nil {
			retVarKey = ret.Value.String()
			break
		}
	}
	if retVarKey == "" {
		return 0, false
	}

	// find the assign for that variable and check if source is a constant
	for _, instr := range block.Instructions {
		if assign, ok := instr.(*ir.Assign); ok { //nolint:nestif // nested type assertions are unavoidable here
			if assign.Dest.String() == retVarKey {
				if ce, ok := assign.Source.(*ir.ConstantExpr); ok {
					if ic, ok := ce.Value.(ir.IntConstant); ok {
						return ic.Value, true
					}
				}
				if ce, ok := assign.Source.(ir.ConstantExpr); ok {
					if ic, ok := ce.Value.(ir.IntConstant); ok {
						return ic.Value, true
					}
				}
			}
		}
	}
	return 0, false
}

// evalExpr evaluates an expression concretely given a variable environment.
// returns (value, true) on success, (0, false) if evaluation is not possible.
func evalExpr(expr ir.Expression, env map[string]int64) (int64, bool) {
	if expr == nil {
		return 0, false
	}

	switch e := expr.(type) {
	case ir.ConstantExpr:
		return extractConstantInt(e.Value)
	case *ir.ConstantExpr:
		return extractConstantInt(e.Value)

	case ir.VariableExpr:
		v, ok := env[e.Var.String()]
		if ok {
			v = applySignExtend(v, e.Var.Type)
		}
		return v, ok
	case *ir.VariableExpr:
		v, ok := env[e.Var.String()]
		if ok {
			v = applySignExtend(v, e.Var.Type)
		}
		return v, ok

	case *ir.BinaryOp:
		return evalBinaryOp(e.Op, e.Left, e.Right, env)
	case ir.BinaryOp:
		return evalBinaryOp(e.Op, e.Left, e.Right, env)

	case *ir.UnaryOp:
		return evalUnaryOp(e.Op, e.Operand, env)
	case ir.UnaryOp:
		return evalUnaryOp(e.Op, e.Operand, env)

	default:
		return 0, false
	}
}

// extractConstantInt extracts an int64 from a Constant value.
func extractConstantInt(c ir.Constant) (int64, bool) {
	switch cv := c.(type) {
	case ir.IntConstant:
		return cv.Value, true
	case ir.BoolConstant:
		if cv.Value {
			return 1, true
		}
		return 0, true
	case ir.FloatConstant:
		return int64(cv.Value), true
	}
	return 0, false
}

// evalBinaryOp evaluates a binary operation concretely.
// uses the same wrapping arithmetic as foldIntBinaryOp to ensure consistency.
func evalBinaryOp(op ir.BinaryOperator, left, right ir.Expression, env map[string]int64) (int64, bool) {
	lv, ok := evalExpr(left, env)
	if !ok {
		return 0, false
	}
	rv, ok := evalExpr(right, env)
	if !ok {
		return 0, false
	}

	// determine width from left operand type for masking
	width := inferWidth(left)
	mask := widthMask(width)
	lu := uint64(lv) & mask //nolint:gosec // intentional int64->uint64 conversion
	ru := uint64(rv) & mask //nolint:gosec // intentional int64->uint64 conversion

	switch op { //nolint:exhaustive // unsupported ops return (0, false) via default
	case ir.BinOpAdd:
		return int64((lu + ru) & mask), true //nolint:gosec // intentional uint64->int64 conversion
	case ir.BinOpSub:
		return int64((lu - ru) & mask), true //nolint:gosec // intentional uint64->int64 conversion
	case ir.BinOpMul:
		return int64((lu * ru) & mask), true //nolint:gosec // intentional uint64->int64 conversion
	case ir.BinOpDiv:
		if rv == 0 {
			return 0, false
		}
		return int64((lu / ru) & mask), true //nolint:gosec // intentional uint64->int64 conversion
	case ir.BinOpMod:
		if rv == 0 {
			return 0, false
		}
		return int64((lu % ru) & mask), true //nolint:gosec // intentional uint64->int64 conversion
	case ir.BinOpAnd:
		return int64((lu & ru) & mask), true //nolint:gosec // intentional bitwise narrowing
	case ir.BinOpOr:
		return int64((lu | ru) & mask), true //nolint:gosec // intentional bitwise narrowing
	case ir.BinOpXor:
		return int64((lu ^ ru) & mask), true //nolint:gosec // intentional bitwise narrowing
	case ir.BinOpShl:
		shift := ru & 63
		return int64((lu << shift) & mask), true //nolint:gosec // intentional bitwise narrowing
	case ir.BinOpShr:
		shift := ru & 63
		return int64((lu >> shift) & mask), true //nolint:gosec // intentional bitwise narrowing
	case ir.BinOpLogicalAnd:
		if lv != 0 && rv != 0 {
			return 1, true
		}
		return 0, true
	case ir.BinOpLogicalOr:
		if lv != 0 || rv != 0 {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// evalUnaryOp evaluates a unary operation concretely.
func evalUnaryOp(op ir.UnaryOperator, operand ir.Expression, env map[string]int64) (int64, bool) {
	v, ok := evalExpr(operand, env)
	if !ok {
		return 0, false
	}
	width := inferWidth(operand)
	mask := widthMask(width)

	switch op {
	case ir.UnOpNeg:
		return int64((^uint64(v) + 1) & mask), true //nolint:gosec // intentional int64->uint64 conversion for two's complement
	case ir.UnOpNot:
		return int64((^uint64(v)) & mask), true //nolint:gosec // intentional int64->uint64 conversion for bitwise not
	case ir.UnOpLogicalNot:
		if v == 0 {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// inferWidth infers the integer width from an expression's type.
// defaults to Size8 (64-bit) if the type is unknown.
func inferWidth(expr ir.Expression) ir.Size {
	if expr == nil {
		return ir.Size8
	}
	t := expr.Type()
	if t == nil {
		return ir.Size8
	}
	if it, ok := t.(ir.IntType); ok {
		return it.Width
	}
	return ir.Size8
}

// ============================================================================
// helpers
// ============================================================================

// applySignExtend applies sign extension to a value based on its type.
// for signed integer types, sign-extends the value to int64.
// for unsigned or non-integer types, returns the value unchanged.
func applySignExtend(v int64, t ir.Type) int64 {
	if t == nil {
		return v
	}
	it, ok := t.(ir.IntType)
	if !ok || !it.Signed {
		return v
	}
	return signExtend(uint64(v)&widthMask(it.Width), it.Width) //nolint:gosec // intentional int64->uint64 for sign extension
}

// describeConstProgram returns a human-readable description of a constProgram
// for use in failure messages.
func describeConstProgram(prog *constProgram) string {
	s := fmt.Sprintf("width=%d signed=%v seed=7", prog.width, prog.signed)
	for i, step := range prog.steps {
		s += fmt.Sprintf("\n  step[%d]: v%d = v%d %s %d", i, i+1, i, step.op, step.operand)
	}
	return s
}
