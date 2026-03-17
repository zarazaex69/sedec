// package main — property-based test for defect 3:
// raw x86-64 register names must not appear as standalone c identifiers in generated output.
//
// **Validates: Requirements 2.5, 2.6**
//
// property 3 (bug condition): for all ir.Function instances whose variables carry
// x86-64 hardware register names (rax, rdi, rbp, etc.), codegen.GenerateFunction
// must NOT emit those names as standalone c identifier tokens in the output body.
//
// this test MUST FAIL on unfixed code — failure confirms the bug exists.
// the bug: ir.Variable.Name is set to the raw register name by the lifter,
// and the variable-naming pass (renameRegisterVariables) has not been applied,
// so codegen emits "rax = rdi;" and "uint64_t rax;" verbatim.
//
// documented counterexample (from running on unfixed code):
// output contains "uint64_t rax;" and "rax = rdi;" — raw register names
// appear as c identifiers, violating c readability and semantic correctness.
package main

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/zarazaex69/sedec/pkg/codegen"
	"github.com/zarazaex69/sedec/pkg/ir"
	"github.com/zarazaex69/sedec/pkg/structuring"
	"pgregory.net/rapid"
)

// x86_64RegisterNamesList is the complete set of x86-64 hardware register names
// that must never appear as standalone c identifier tokens in generated output.
// this covers all general-purpose registers in all widths, xmm registers,
// and all sub-register aliases.
var x86_64RegisterNamesList = []string{
	// 64-bit general purpose
	"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
	// 32-bit sub-registers
	"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
	"r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
	// 16-bit sub-registers
	"ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
	"r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
	// 8-bit sub-registers (low)
	"al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
	"r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
	// 8-bit sub-registers (high)
	"ah", "bh", "ch", "dh",
	// xmm registers (128-bit sse)
	"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
	"xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
}

// buildRegisterBoundaryPattern compiles a word-boundary regex for a register name.
// uses \b anchors so "rax" matches "rax" and "rax;" but not "prax" or "raxval".
func buildRegisterBoundaryPattern(regName string) *regexp.Regexp {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(regName) + `\b`)
}

// containsRegisterToken checks whether the given c source string contains
// any x86-64 register name as a standalone identifier token.
// returns the first offending register name found, or empty string if clean.
func containsRegisterToken(cSource string) string {
	for _, reg := range x86_64RegisterNamesList {
		pat := buildRegisterBoundaryPattern(reg)
		if pat.MatchString(cSource) {
			return reg
		}
	}
	return ""
}

// makeRegVar creates an ir.Variable with the given register name and uint64 type.
// this mirrors what the lifter produces for x86-64 general-purpose registers.
func makeRegVar(regName string) ir.Variable {
	return ir.Variable{
		Name: regName,
		Type: ir.IntType{Width: ir.Size8, Signed: false},
	}
}

// buildMinimalIRFunction constructs a minimal ir.Function containing a single
// basic block with one ir.Assign instruction: rax = rdi.
// this directly encodes the "mov rax, rdi" instruction in IR form.
func buildMinimalIRFunction() *ir.Function {
	raxVar := makeRegVar("rax")
	rdiVar := makeRegVar("rdi")

	assignInstr := ir.Assign{
		Dest:   raxVar,
		Source: ir.VariableExpr{Var: rdiVar},
	}

	block := &ir.BasicBlock{
		ID:           0,
		Instructions: []ir.IRInstruction{assignInstr},
		Predecessors: nil,
		Successors:   nil,
	}

	return &ir.Function{
		Name: "test_func",
		Signature: ir.FunctionType{
			ReturnType: ir.VoidType{},
			Parameters: nil,
		},
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		EntryBlock: 0,
		Variables:  []ir.Variable{raxVar, rdiVar},
	}
}

// buildASTForFunction constructs a minimal structuring.StructuredAST for the
// given ir.Function, wrapping the single block as an IRBlock statement.
func buildASTForFunction(fn *ir.Function) *structuring.StructuredAST {
	block, ok := fn.Blocks[fn.EntryBlock]
	if !ok {
		return &structuring.StructuredAST{
			Body:       structuring.Block{},
			FunctionID: 0,
		}
	}
	return &structuring.StructuredAST{
		Body: structuring.IRBlock{
			BlockID:      0,
			Instructions: block.Instructions,
		},
		FunctionID: 0,
	}
}

// TestProperty3_BugCondition_ConcreteMovRaxRdi is the deterministic test for
// the concrete "mov rax, rdi" instruction lifted to IR.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// the bug causes the output to contain "uint64_t rax;" and "rax = rdi;"
// because the variable-naming pass has not been applied before codegen.
func TestProperty3_BugCondition_ConcreteMovRaxRdi(t *testing.T) {
	irFunc := buildMinimalIRFunction()
	ast := buildASTForFunction(irFunc)

	decl := codegen.New().GenerateFunction(irFunc, ast)
	body := decl.Body

	// check the body for any register name token
	if offender := containsRegisterToken(body); offender != "" {
		t.Errorf(
			"bug confirmed: generated c body contains raw register name %q as c identifier\n"+
				"body:\n%s",
			offender, body,
		)
	}

	// also check the full rendered output (includes declarations)
	fullOutput := codegen.RenderDecl(decl)
	if offender := containsRegisterToken(fullOutput); offender != "" {
		t.Errorf(
			"bug confirmed: full c output contains raw register name %q as c identifier\n"+
				"full output:\n%s",
			offender, fullOutput,
		)
	}
}

// registerNameGenerator is a rapid generator that draws a random x86-64 register name.
func registerNameGenerator() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		idx := rapid.IntRange(0, len(x86_64RegisterNamesList)-1).Draw(t, "regIdx")
		return x86_64RegisterNamesList[idx]
	})
}

// buildRandomRegisterFunction constructs an ir.Function with numVars register-named
// variables, each assigned from another register-named variable.
// this simulates a sequence of register-to-register moves lifted from x86-64 assembly.
func buildRandomRegisterFunction(regNames []string) *ir.Function {
	if len(regNames) < 2 {
		// need at least dest and source
		regNames = append(regNames, "rax")
	}

	vars := make([]ir.Variable, len(regNames))
	for i, name := range regNames {
		vars[i] = makeRegVar(name)
	}

	// build a chain of assignments: vars[1] = vars[0], vars[2] = vars[1], ...
	instrs := make([]ir.IRInstruction, 0, len(vars)-1)
	for i := 1; i < len(vars); i++ {
		instrs = append(instrs, ir.Assign{
			Dest:   vars[i],
			Source: ir.VariableExpr{Var: vars[i-1]},
		})
	}

	block := &ir.BasicBlock{
		ID:           0,
		Instructions: instrs,
		Predecessors: nil,
		Successors:   nil,
	}

	return &ir.Function{
		Name: "rand_func",
		Signature: ir.FunctionType{
			ReturnType: ir.VoidType{},
			Parameters: nil,
		},
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		EntryBlock: 0,
		Variables:  vars,
	}
}

// TestProperty3_BugCondition_RapidRegisterVariables is the property-based test
// using pgregory.net/rapid to generate random ir.Function instances with
// register-named variables.
//
// **Validates: Requirements 2.5, 2.6**
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// rapid will find a counterexample demonstrating that register names survive
// into the generated c output verbatim.
//
// documented counterexample (from running on unfixed code):
// regNames=["rax","rdi"]:
// output contains "uint64_t rax;" and "rax = rdi;" — raw x86-64 register
// names appear as c identifiers in the generated pseudocode.
func TestProperty3_BugCondition_RapidRegisterVariables(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// generate 2–6 distinct register names for this function's variables
		numVars := rapid.IntRange(2, 6).Draw(rt, "numVars")
		regNames := make([]string, numVars)
		usedNames := make(map[string]bool, numVars)

		for i := 0; i < numVars; i++ {
			// draw a register name; allow repeats (ssa versions handle uniqueness)
			name := registerNameGenerator().Draw(rt, fmt.Sprintf("reg_%d", i))
			regNames[i] = name
			usedNames[name] = true
		}

		irFunc := buildRandomRegisterFunction(regNames)
		ast := buildASTForFunction(irFunc)

		decl := codegen.New().GenerateFunction(irFunc, ast)
		fullOutput := codegen.RenderDecl(decl)

		// property: no x86-64 register name must appear as a standalone c token
		for _, reg := range regNames {
			pat := buildRegisterBoundaryPattern(reg)
			if pat.MatchString(fullOutput) {
				rt.Errorf(
					"counterexample: register name %q appears as c identifier in output\n"+
						"regNames=%v\noutput:\n%s",
					reg, regNames, fullOutput,
				)
			}
		}
	})
}

// TestProperty3_BugCondition_AllCommonRegisters tests that none of the most
// commonly used x86-64 registers appear in the output when used as variable names.
// covers rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp — the 8 classic registers.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// all 8 registers appear verbatim in declarations and assignments.
func TestProperty3_BugCondition_AllCommonRegisters(t *testing.T) {
	commonRegs := []string{"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"}

	irFunc := buildRandomRegisterFunction(commonRegs)
	ast := buildASTForFunction(irFunc)

	decl := codegen.New().GenerateFunction(irFunc, ast)
	fullOutput := codegen.RenderDecl(decl)

	var violations []string
	for _, reg := range commonRegs {
		pat := buildRegisterBoundaryPattern(reg)
		if pat.MatchString(fullOutput) {
			violations = append(violations, reg)
		}
	}

	if len(violations) > 0 {
		t.Errorf(
			"bug confirmed: %d register name(s) appear as c identifiers: %s\nfull output:\n%s",
			len(violations), strings.Join(violations, ", "), fullOutput,
		)
	}
}
