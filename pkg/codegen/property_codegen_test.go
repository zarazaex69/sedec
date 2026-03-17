// package codegen — property-based test for defect 4:
// dead code (statements after return) must not be emitted in the same scope.
//
// **Validates: Requirements 2.7, 2.8**
//
// property 4 (bug condition): for all structuring.Block instances that contain
// a ReturnStatement (or an IRBlock with ir.Return) at position i, the code
// generator must NOT emit any non-whitespace C statement after the return line
// within the same scope.
//
// this test MUST FAIL on unfixed code — failure confirms the bug exists.
// the bug: genBlock iterates over all statements unconditionally, so instructions
// that follow an ir.Return inside the same IRBlock are emitted verbatim after
// the "return rax;" line, producing unreachable dead code.
//
// documented counterexample (from running on unfixed code):
// output contains "return rax;\n    rsp = (rsp + 8U);" — a dead assignment to
// rsp appears after the return statement in the same function scope, violating
// C semantics (unreachable code) and confusing readers.
package codegen

import (
	"regexp"
	"strings"
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
	"github.com/zarazaex69/sedec/pkg/structuring"
	"pgregory.net/rapid"
)

// returnFollowedByDeadCodePattern matches a return statement followed by any
// non-whitespace content before the closing brace of the same scope.
// this detects the bug: "return rax;\n    rsp = (rsp + 8U);"
var returnFollowedByDeadCodePattern = regexp.MustCompile(`return[^;]*;[^\}]*\S[^\}]*`)

// makeUint64Var creates an unsigned 64-bit ir.Variable with the given name.
func makeUint64Var(name string) ir.Variable {
	return ir.Variable{Name: name, Type: ir.IntType{Width: ir.Size8, Signed: false}}
}

// makeInt64Var creates a signed 64-bit ir.Variable with the given name.
func makeInt64Var(name string) ir.Variable {
	return ir.Variable{Name: name, Type: ir.IntType{Width: ir.Size8, Signed: true}}
}

// buildDeadCodeIRBlock constructs an IRBlock that contains:
//  1. ir.Return{Value: &retVar}  — the return instruction
//  2. ir.Assign{Dest: rspVar, Source: ...} — dead code after return
//
// this directly encodes the bug condition from defect 4.
func buildDeadCodeIRBlock() structuring.IRBlock {
	retVar := makeInt64Var("rax")
	rspVar := makeUint64Var("rsp")

	// rsp = (rsp + 8U) — the dead stack-pointer adjustment that appears after return
	deadSource := ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  ir.VariableExpr{Var: rspVar},
		Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 8, Width: ir.Size4, Signed: false}},
	}

	return structuring.IRBlock{
		BlockID: 0,
		Instructions: []ir.IRInstruction{
			ir.Return{Value: &retVar},
			ir.Assign{Dest: rspVar, Source: deadSource},
		},
	}
}

// buildFunctionForBlock constructs a minimal ir.Function suitable for generating
// the given block. the function has an int64 return type to match the return var.
func buildFunctionForBlock(vars []ir.Variable) *ir.Function {
	return &ir.Function{
		Name: "test_dead_code",
		Signature: ir.FunctionType{
			ReturnType: ir.IntType{Width: ir.Size8, Signed: true},
			Parameters: nil,
		},
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
		EntryBlock: 0,
		Variables:  vars,
	}
}

// hasDeadCodeAfterReturn checks whether the generated C output contains any
// non-whitespace content after a return statement within the same scope.
// returns the offending snippet if found, empty string otherwise.
func hasDeadCodeAfterReturn(cOutput string) string {
	if returnFollowedByDeadCodePattern.MatchString(cOutput) {
		// extract the match for the error message
		match := returnFollowedByDeadCodePattern.FindString(cOutput)
		return match
	}
	return ""
}

// TestProperty4_BugCondition_ConcreteReturnFollowedByDeadAssign is the
// deterministic test for the concrete case: return rax; followed by rsp = (rsp + 8U);
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// the bug causes genIRBlock to emit all instructions unconditionally, so the
// dead assignment "rsp = (rsp + 8U);" appears after "return rax;" in the output.
//
// documented counterexample:
// output contains "return rax;\n    rsp = (rsp + 8U);" — dead code after return.
func TestProperty4_BugCondition_ConcreteReturnFollowedByDeadAssign(t *testing.T) {
	retVar := makeInt64Var("rax")
	rspVar := makeUint64Var("rsp")

	irBlock := buildDeadCodeIRBlock()
	block := structuring.Block{Stmts: []structuring.Statement{irBlock}}

	fn := buildFunctionForBlock([]ir.Variable{retVar, rspVar})
	ast := &structuring.StructuredAST{
		Body:       block,
		FunctionID: 0,
	}

	state := newGeneratorState(fn, ast)
	generated := state.genBlock(block, 0)

	if snippet := hasDeadCodeAfterReturn(generated); snippet != "" {
		t.Errorf(
			"bug confirmed (defect 4): dead code emitted after return statement\n"+
				"offending snippet: %q\n"+
				"full generated block:\n%s",
			snippet, generated,
		)
	}
}

// TestProperty4_BugCondition_ReturnStatementFollowedByIRBlock tests the case
// where a structuring.ReturnStatement is followed by an IRBlock in the same Block.
// this covers the scenario where the structuring engine emits a ReturnStatement
// node followed by additional IRBlock nodes in the same Block.Stmts slice.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// genBlock iterates all stmts unconditionally, emitting the IRBlock after the return.
func TestProperty4_BugCondition_ReturnStatementFollowedByIRBlock(t *testing.T) {
	retVar := makeInt64Var("rax")
	rspVar := makeUint64Var("rsp")

	deadSource := ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  ir.VariableExpr{Var: rspVar},
		Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 8, Width: ir.Size4, Signed: false}},
	}

	// structuring.ReturnStatement followed by a dead IRBlock in the same Block
	block := structuring.Block{
		Stmts: []structuring.Statement{
			structuring.ReturnStatement{
				Value: ir.VariableExpr{Var: retVar},
			},
			structuring.IRBlock{
				BlockID: 1,
				Instructions: []ir.IRInstruction{
					ir.Assign{Dest: rspVar, Source: deadSource},
				},
			},
		},
	}

	fn := buildFunctionForBlock([]ir.Variable{retVar, rspVar})
	ast := &structuring.StructuredAST{Body: block, FunctionID: 0}

	state := newGeneratorState(fn, ast)
	generated := state.genBlock(block, 0)

	if snippet := hasDeadCodeAfterReturn(generated); snippet != "" {
		t.Errorf(
			"bug confirmed (defect 4): IRBlock emitted after ReturnStatement in same Block\n"+
				"offending snippet: %q\n"+
				"full generated block:\n%s",
			snippet, generated,
		)
	}
}

// ============================================================================
// rapid property-based test
// ============================================================================

// stmtKind enumerates the kinds of statements the generator can produce.
type stmtKind int

const (
	stmtKindAssign stmtKind = iota
	stmtKindReturn
)

// drawSimpleAssign generates a random ir.Assign instruction using one of a
// fixed set of synthetic variable names to keep the output deterministic.
func drawSimpleAssign(t *rapid.T, label string) structuring.IRBlock {
	varNames := []string{"v0", "v1", "v2", "v3", "v4"}
	destIdx := rapid.IntRange(0, len(varNames)-1).Draw(t, label+"_dest")
	srcIdx := rapid.IntRange(0, len(varNames)-1).Draw(t, label+"_src")

	dest := makeInt64Var(varNames[destIdx])
	src := makeInt64Var(varNames[srcIdx])

	return structuring.IRBlock{
		BlockID: cfg.BlockID(rapid.IntRange(1, 100).Draw(t, label+"_bid")),
		Instructions: []ir.IRInstruction{
			ir.Assign{Dest: dest, Source: ir.VariableExpr{Var: src}},
		},
	}
}

// drawReturnStatement generates a ReturnStatement with a random variable value.
func drawReturnStatement(t *rapid.T, label string) structuring.ReturnStatement {
	varNames := []string{"rax", "v0", "result", "ret"}
	idx := rapid.IntRange(0, len(varNames)-1).Draw(t, label+"_retvar")
	retVar := makeInt64Var(varNames[idx])
	return structuring.ReturnStatement{
		Value: ir.VariableExpr{Var: retVar},
	}
}

// buildBlockWithReturnAtPosition constructs a structuring.Block where a
// ReturnStatement appears at position returnPos, followed by numAfter
// additional IRBlock statements (dead code).
func buildBlockWithReturnAtPosition(
	t *rapid.T,
	returnPos int,
	numBefore int,
	numAfter int,
) structuring.Block {
	stmts := make([]structuring.Statement, 0, numBefore+1+numAfter)

	// statements before the return
	for i := range numBefore {
		stmts = append(stmts, drawSimpleAssign(t, "before_"+strings.Repeat("x", i+1)))
	}

	// the return statement at returnPos
	_ = returnPos // position is implicit: numBefore statements precede it
	stmts = append(stmts, drawReturnStatement(t, "ret"))

	// dead statements after the return
	for i := range numAfter {
		stmts = append(stmts, drawSimpleAssign(t, "after_"+strings.Repeat("y", i+1)))
	}

	return structuring.Block{Stmts: stmts}
}

// TestProperty4_BugCondition_RapidReturnWithDeadCode is the property-based test
// using pgregory.net/rapid to generate random structuring.Block instances that
// contain a ReturnStatement at a random position followed by additional statements.
//
// **Validates: Requirements 2.7, 2.8**
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// rapid will find a counterexample demonstrating that dead code is emitted after
// the return statement in the generated C output.
//
// documented counterexample (from running on unfixed code):
// block with ReturnStatement{rax} followed by IRBlock{v0 = v1}:
// output contains "return rax;\n    v0 = v1;" — dead assignment after return.
func TestProperty4_BugCondition_RapidReturnWithDeadCode(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// generate 0–3 statements before the return
		numBefore := rapid.IntRange(0, 3).Draw(rt, "numBefore")
		// generate 1–3 dead statements after the return (must be > 0 to trigger bug)
		numAfter := rapid.IntRange(1, 3).Draw(rt, "numAfter")

		block := buildBlockWithReturnAtPosition(rt, numBefore, numBefore, numAfter)

		fn := buildFunctionForBlock([]ir.Variable{
			makeInt64Var("rax"),
			makeInt64Var("v0"),
			makeInt64Var("v1"),
			makeInt64Var("v2"),
			makeInt64Var("v3"),
			makeInt64Var("v4"),
			makeInt64Var("result"),
			makeInt64Var("ret"),
		})
		ast := &structuring.StructuredAST{Body: block, FunctionID: 0}

		state := newGeneratorState(fn, ast)
		generated := state.genBlock(block, 0)

		// property: no non-whitespace content must appear after return in same scope
		if snippet := hasDeadCodeAfterReturn(generated); snippet != "" {
			rt.Errorf(
				"counterexample: dead code emitted after return statement\n"+
					"numBefore=%d numAfter=%d\n"+
					"offending snippet: %q\n"+
					"full generated block:\n%s",
				numBefore, numAfter, snippet, generated,
			)
		}
	})
}
