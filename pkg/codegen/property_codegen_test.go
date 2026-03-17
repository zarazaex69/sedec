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
	"fmt"
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

// ============================================================================
// preservation 3: synthetic variable names emitted verbatim
// ============================================================================

// TestPreservation3_SyntheticVarNamesEmittedVerbatim verifies that ir.Function
// instances with ONLY synthetic variable names (matching /^t\d+$/ or /^local_\d+$/)
// have those names emitted verbatim in the generated c output.
//
// **Validates: Requirements 3.5, 3.6**
//
// this is the preservation guarantee for fix 3: the register-renaming pass must
// not rename synthetic variables that do not match any hardware register name.
// names like "t1", "t2", "local_8" must pass through unchanged.
//
// EXPECTED OUTCOME: PASS on both unfixed and fixed code.
// synthetic names are not in the x86-64 register name set and are never renamed.
func TestPreservation3_SyntheticVarNamesEmittedVerbatim(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// generate 1–4 synthetic variable names matching /^t\d+$/ or /^local_\d+$/
		numVars := rapid.IntRange(1, 4).Draw(rt, "numVars")

		// choose name pattern: 0 = t\d+, 1 = local_\d+
		useLocalPrefix := rapid.IntRange(0, 1).Draw(rt, "useLocalPrefix")

		vars := make([]ir.Variable, numVars)
		for i := range vars {
			var name string
			if useLocalPrefix == 1 {
				name = fmt.Sprintf("local_%d", i*8)
			} else {
				name = fmt.Sprintf("t%d", i+1)
			}
			vars[i] = ir.Variable{
				Name: name,
				Type: ir.IntType{Width: ir.Size8, Signed: false},
			}
		}

		// build a minimal ir.Function with one assign per variable
		instrs := make([]ir.IRInstruction, numVars)
		for i, v := range vars {
			src := ir.ConstantExpr{
				Value: ir.IntConstant{Value: int64(i), Width: ir.Size8},
			}
			instrs[i] = ir.Assign{Dest: v, Source: src}
		}

		block := &ir.BasicBlock{
			ID:           0,
			Instructions: instrs,
		}

		fn := &ir.Function{
			Name: "test_synthetic",
			Signature: ir.FunctionType{
				ReturnType: ir.VoidType{},
			},
			Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
			EntryBlock: 0,
			Variables:  vars,
		}

		ast := &structuring.StructuredAST{
			Body: structuring.IRBlock{
				BlockID:      0,
				Instructions: instrs,
			},
			FunctionID: 0,
		}

		gen := New()
		decl := gen.GenerateFunction(fn, ast)
		cOutput := RenderDecl(decl)

		// preservation property: each synthetic name must appear in the output
		for _, v := range vars {
			if !strings.Contains(cOutput, v.Name) {
				rt.Errorf(
					"preservation violated: synthetic variable %q not found in generated output\n"+
						"generated output:\n%s",
					v.Name, cOutput,
				)
			}
		}
	})
}

// ============================================================================
// preservation 4: blocks without return emit all statements
// ============================================================================

// TestPreservation4_BlockWithoutReturnEmitsAllStatements verifies that
// structuring.Block instances with NO ReturnStatement nodes have all their
// statements emitted in the generated c output.
//
// **Validates: Requirements 3.7, 3.8**
//
// this is the preservation guarantee for fix 4: the dead-code truncation must
// not suppress statements in blocks that contain no return.
// a block with only assignments must emit all assignments verbatim.
//
// EXPECTED OUTCOME: PASS on both unfixed and fixed code.
// blocks without return are never truncated by the dead-code suppression logic.
func TestPreservation4_BlockWithoutReturnEmitsAllStatements(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// generate 1–5 assign statements with no return
		numStmts := rapid.IntRange(1, 5).Draw(rt, "numStmts")

		varNames := []string{"v0", "v1", "v2", "v3", "v4"}
		stmts := make([]structuring.Statement, numStmts)
		sentinels := make([]string, numStmts)

		for i := range numStmts {
			destIdx := i % len(varNames)
			srcIdx := (i + 1) % len(varNames)
			dest := makeInt64Var(varNames[destIdx])
			src := makeInt64Var(varNames[srcIdx])
			// use a unique constant as sentinel to verify emission
			sentinel := fmt.Sprintf("sentinel_%d", i)
			sentinels[i] = sentinel

			// build an irblock with a unique assign using a constant that encodes the sentinel
			stmts[i] = structuring.IRBlock{
				BlockID: cfg.BlockID(i),
				Instructions: []ir.IRInstruction{
					ir.Assign{
						Dest: dest,
						Source: ir.BinaryOp{
							Op:    ir.BinOpAdd,
							Left:  ir.VariableExpr{Var: src},
							Right: ir.ConstantExpr{Value: ir.IntConstant{Value: int64(i * 1000), Width: ir.Size8}},
						},
					},
				},
			}
		}

		block := structuring.Block{Stmts: stmts}

		fn := buildFunctionForBlock([]ir.Variable{
			makeInt64Var("v0"),
			makeInt64Var("v1"),
			makeInt64Var("v2"),
			makeInt64Var("v3"),
			makeInt64Var("v4"),
		})
		ast := &structuring.StructuredAST{Body: block, FunctionID: 0}

		state := newGeneratorState(fn, ast)
		generated := state.genBlock(block, 0)

		// preservation property: all constant values must appear in the output
		// each assign uses a unique constant i*1000 that must be present
		for i := range numStmts {
			sentinel := fmt.Sprintf("%d", i*1000)
			if !strings.Contains(generated, sentinel) {
				rt.Errorf(
					"preservation violated: statement %d (constant %s) not found in output\n"+
						"numStmts=%d\ngenerated:\n%s",
					i, sentinel, numStmts, generated,
				)
			}
		}
	})
}
