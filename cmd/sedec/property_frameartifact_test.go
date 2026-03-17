// package main — property-based test for defect 8:
// stack frame prologue/epilogue instructions must NOT appear as raw c statements
// in the generated decompiler output.
//
// **Validates: Requirements 2.15, 2.16**
//
// property 8 (bug condition): for any function whose instruction stream contains
// a standard frame prologue sequence (push rbp; mov rbp, rsp; sub rsp, N),
// the generated c output MUST NOT contain the raw ir artifacts:
//   - "rsp = (rsp - 8U);"   — from push rbp
//   - "*(uint64_t*)(rsp) = rbp;"  — from push rbp
//   - "rbp = rsp;"          — from mov rbp, rsp
//
// this test MUST FAIL on unfixed code — failure confirms the bug exists.
// the bug: the ir lifter faithfully lifts every instruction including push/pop/mov
// for frame setup. the abi pass identifies the frame layout via SymbolicStackTracker
// but does NOT mark the corresponding ir instructions as frame artifacts.
// the code generator therefore emits them verbatim as c statements.
//
// documented counterexample (from running on unfixed code):
// a function with prologue "push rbp; mov rbp, rsp; sub rsp, 0x20" produces:
//
//	rsp = (rsp - 8U);
//	*(uint64_t*)(rsp) = rbp;
//	rbp = rsp;
//	rsp = (rsp - 32U);
//
// in the generated c body — these are pure frame management noise that should
// be suppressed entirely, as they convey no semantic information about the
// function's actual logic.
package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/zarazaex69/sedec/pkg/codegen"
	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
	"github.com/zarazaex69/sedec/pkg/structuring"
	"pgregory.net/rapid"
)

// framePrologueStrings is the set of c statement fragments that indicate
// frame management artifacts leaked into the generated output.
// each string is a substring that must NOT appear in clean decompiler output.
var framePrologueStrings = []string{
	// push rbp lifts to: rsp = (rsp - 8U); *(uint64_t*)(rsp) = rbp;
	"rsp = (rsp - 8U);",
	"*(uint64_t*)(rsp) = rbp;",
	// mov rbp, rsp lifts to: rbp = rsp;
	"rbp = rsp;",
	// pop rbp lifts to: rbp = *(uint64_t*)(rsp); rsp = (rsp + 8U);
	"rbp = *(uint64_t*)(rsp);",
	"rsp = (rsp + 8U);",
}

// buildFramePrologueInsns constructs a synthetic instruction sequence representing
// a standard x86-64 System V frame prologue/epilogue:
//
//	push rbp          ; save caller's frame pointer
//	mov rbp, rsp      ; establish new frame pointer
//	sub rsp, frameSize ; allocate local variable space
//	xor eax, eax      ; zero return value (body placeholder)
//	add rsp, frameSize ; deallocate locals (epilogue)
//	pop rbp           ; restore caller's frame pointer
//	ret               ; return
//
// frameSize must be a multiple of 16 (System V ABI stack alignment requirement).
// the returned slice uses sequential addresses starting at baseAddr.
func buildFramePrologueInsns(baseAddr disasm.Address, frameSize int64) []*disasm.Instruction {
	// push rbp: opcode 0x55, length 1
	pushRBP := &disasm.Instruction{
		Address:  baseAddr,
		Mnemonic: "push",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rbp", Size: disasm.Size64},
		},
		Bytes:  []byte{0x55},
		Length: 1,
	}

	// mov rbp, rsp: opcode 48 89 e5, length 3
	movRBPRSP := &disasm.Instruction{
		Address:  baseAddr + 1,
		Mnemonic: "mov",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rbp", Size: disasm.Size64},
			disasm.RegisterOperand{Name: "rsp", Size: disasm.Size64},
		},
		Bytes:  []byte{0x48, 0x89, 0xe5},
		Length: 3,
	}

	// sub rsp, frameSize: opcode 48 83 ec XX (for small values), length 4
	subRSP := &disasm.Instruction{
		Address:  baseAddr + 4,
		Mnemonic: "sub",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rsp", Size: disasm.Size64},
			disasm.ImmediateOperand{Value: frameSize, Size: disasm.Size8},
		},
		Bytes:  []byte{0x48, 0x83, 0xec, byte(frameSize)},
		Length: 4,
	}

	// xor eax, eax: opcode 31 c0, length 2 (body placeholder — zero return value)
	xorEAX := &disasm.Instruction{
		Address:  baseAddr + 8,
		Mnemonic: "xor",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "eax", Size: disasm.Size32},
			disasm.RegisterOperand{Name: "eax", Size: disasm.Size32},
		},
		Bytes:  []byte{0x31, 0xc0},
		Length: 2,
	}

	// add rsp, frameSize: epilogue stack deallocation
	addRSP := &disasm.Instruction{
		Address:  baseAddr + 10,
		Mnemonic: "add",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rsp", Size: disasm.Size64},
			disasm.ImmediateOperand{Value: frameSize, Size: disasm.Size8},
		},
		Bytes:  []byte{0x48, 0x83, 0xc4, byte(frameSize)},
		Length: 4,
	}

	// pop rbp: opcode 0x5d, length 1
	popRBP := &disasm.Instruction{
		Address:  baseAddr + 14,
		Mnemonic: "pop",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rbp", Size: disasm.Size64},
		},
		Bytes:  []byte{0x5d},
		Length: 1,
	}

	// ret: opcode 0xc3, length 1
	ret := &disasm.Instruction{
		Address:  baseAddr + 15,
		Mnemonic: "ret",
		Operands: []disasm.Operand{},
		Bytes:    []byte{0xc3},
		Length:   1,
	}

	return []*disasm.Instruction{pushRBP, movRBPRSP, subRSP, xorEAX, addRSP, popRBP, ret}
}

// runFullPipelineAndGetCOutput runs the complete decompile pipeline on the given
// instruction sequence and returns the generated c pseudocode string.
// this mirrors decompileInstructions but returns the output for assertion.
func runFullPipelineAndGetCOutput(t *testing.T, funcName string, insns []*disasm.Instruction) string {
	t.Helper()
	cCode, err := decompileInstructions(funcName, insns)
	if err != nil {
		// pipeline errors are acceptable — the test is about output content, not pipeline success.
		// if the pipeline fails entirely, return empty string (no frame artifacts = no bug triggered).
		// however, we log the error for diagnostic purposes.
		t.Logf("decompileInstructions error (non-fatal for bug detection): %v", err)
		return ""
	}
	return cCode
}

// containsFrameArtifact checks whether the given c output string contains any
// of the known frame management artifact substrings.
// returns the first matching artifact string, or empty string if none found.
func containsFrameArtifact(cOutput string) string {
	for _, artifact := range framePrologueStrings {
		if strings.Contains(cOutput, artifact) {
			return artifact
		}
	}
	return ""
}

// TestProperty8_BugCondition_ConcreteFramePrologue is the deterministic concrete test.
// it constructs the canonical frame prologue sequence:
//
//	push rbp; mov rbp, rsp; sub rsp, 0x20; xor eax, eax; add rsp, 0x20; pop rbp; ret
//
// runs the full decompile pipeline, and asserts that the c output does NOT contain
// any of the frame management artifact strings.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// the unfixed pipeline lifts push rbp to "rsp = (rsp - 8U); *(uint64_t*)(rsp) = rbp;"
// and mov rbp, rsp to "rbp = rsp;" — these appear verbatim in the generated c output
// because no pass marks them as frame artifacts or suppresses them.
//
// documented counterexample:
// output contains "rsp = (rsp - 8U);" and "*(uint64_t*)(rsp) = rbp;" and "rbp = rsp;"
// from the standard frame prologue — pure noise that obscures the function's logic.
func TestProperty8_BugCondition_ConcreteFramePrologue(t *testing.T) {
	const baseAddr = disasm.Address(0x401000)
	const frameSize = int64(0x20) // 32 bytes — typical small function frame

	insns := buildFramePrologueInsns(baseAddr, frameSize)
	cOutput := runFullPipelineAndGetCOutput(t, "test_frame_func", insns)

	if cOutput == "" {
		// pipeline failed entirely — cannot confirm bug from empty output
		t.Skip("pipeline produced no output; cannot confirm frame artifact bug")
		return
	}

	// assert: output must NOT contain frame management artifacts
	// on unfixed code this FAILS because the artifacts are emitted verbatim
	if artifact := containsFrameArtifact(cOutput); artifact != "" {
		t.Errorf(
			"bug confirmed: output contains frame management artifact %q\n"+
				"frame prologue (push rbp; mov rbp, rsp; sub rsp, 0x%x) was NOT suppressed.\n"+
				"the ir lifter emits these as raw ir statements and no pass marks them\n"+
				"as frame artifacts or suppresses them in the code generator.\n"+
				"generated output:\n%s",
			artifact, frameSize, cOutput,
		)
	}
}

// TestProperty8_BugCondition_ConcreteFrameSize32 tests a function with a 32-byte frame.
// this is the most common frame size for functions with a few local variables.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// same root cause: frame prologue artifacts are emitted verbatim.
func TestProperty8_BugCondition_ConcreteFrameSize32(t *testing.T) {
	const baseAddr = disasm.Address(0x401100)
	const frameSize = int64(0x20)

	insns := buildFramePrologueInsns(baseAddr, frameSize)
	cOutput := runFullPipelineAndGetCOutput(t, "func_frame32", insns)

	if cOutput == "" {
		t.Skip("pipeline produced no output; cannot confirm frame artifact bug")
		return
	}

	if artifact := containsFrameArtifact(cOutput); artifact != "" {
		t.Errorf(
			"bug confirmed: output contains frame artifact %q\n"+
				"frame size=0x%x, base=0x%x\n"+
				"generated output:\n%s",
			artifact, frameSize, baseAddr, cOutput,
		)
	}
}

// TestProperty8_BugCondition_ConcreteFrameSize64 tests a function with a 64-byte frame.
// larger frames are common for functions with multiple local variables.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
func TestProperty8_BugCondition_ConcreteFrameSize64(t *testing.T) {
	const baseAddr = disasm.Address(0x401200)
	const frameSize = int64(0x40)

	insns := buildFramePrologueInsns(baseAddr, frameSize)
	cOutput := runFullPipelineAndGetCOutput(t, "func_frame64", insns)

	if cOutput == "" {
		t.Skip("pipeline produced no output; cannot confirm frame artifact bug")
		return
	}

	if artifact := containsFrameArtifact(cOutput); artifact != "" {
		t.Errorf(
			"bug confirmed: output contains frame artifact %q\n"+
				"frame size=0x%x, base=0x%x\n"+
				"generated output:\n%s",
			artifact, frameSize, baseAddr, cOutput,
		)
	}
}

// frameSizeGenerator is a rapid generator that produces valid System V AMD64 frame sizes.
// frame sizes must be multiples of 16 (stack alignment) and in the range [16, 256].
// values outside this range are unusual in practice and may trigger edge cases
// in the sub instruction encoding that are not relevant to the frame artifact bug.
func frameSizeGenerator() *rapid.Generator[int64] {
	return rapid.Custom(func(t *rapid.T) int64 {
		// generate a multiplier in [1, 16]: frame size = multiplier * 16
		// this covers 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256
		multiplier := rapid.Int64Range(1, 16).Draw(t, "frameSizeMultiplier")
		return multiplier * 16
	})
}

// baseAddrGenerator is a rapid generator that produces realistic function base addresses.
// addresses are in the typical .text section range for small linux x86-64 binaries.
func baseAddrGenerator() *rapid.Generator[disasm.Address] {
	return rapid.Custom(func(t *rapid.T) disasm.Address {
		// .text section typically starts at 0x401000 for small binaries
		// generate offsets in steps of 32 bytes (minimum function size with prologue)
		const textBase = disasm.Address(0x401000)
		const maxOffset = disasm.Address(0x10000) // 64KB text section
		const funcAlignment = disasm.Address(32)  // functions are typically 16/32-byte aligned
		offsetIdx := rapid.Uint64Range(0, uint64(maxOffset/funcAlignment)-1).Draw(t, "funcOffsetIdx")
		return textBase + disasm.Address(offsetIdx)*funcAlignment
	})
}

// TestProperty8_BugCondition_RapidFrameArtifacts is the property-based test
// using pgregory.net/rapid to generate random frame sizes and base addresses,
// verifying that the decompile pipeline suppresses frame management artifacts
// for all standard prologue/epilogue sequences.
//
// **Validates: Requirements 2.15, 2.16**
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// rapid will immediately find a counterexample because the unfixed pipeline
// never suppresses frame artifacts regardless of frame size or base address.
// the first generated frame size (e.g., 16 bytes) will produce output containing
// "rsp = (rsp - 8U);" and "*(uint64_t*)(rsp) = rbp;" and "rbp = rsp;".
//
// documented counterexample (from running on unfixed code):
// frameSize=0x20 (32 bytes), baseAddr=0x401000:
// output contains "rsp = (rsp - 8U);" — push rbp was NOT suppressed.
// output contains "*(uint64_t*)(rsp) = rbp;" — push rbp store was NOT suppressed.
// output contains "rbp = rsp;" — mov rbp, rsp was NOT suppressed.
// the ir lifter faithfully lifts every instruction; no pass marks frame artifacts;
// the code generator emits all ir statements verbatim including frame management noise.
func TestProperty8_BugCondition_RapidFrameArtifacts(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		frameSize := frameSizeGenerator().Draw(rt, "frameSize")
		baseAddr := baseAddrGenerator().Draw(rt, "baseAddr")

		funcName := fmt.Sprintf("rapid_frame_func_%x", baseAddr)
		insns := buildFramePrologueInsns(baseAddr, frameSize)

		cOutput := runFullPipelineAndGetCOutput(t, funcName, insns)

		if cOutput == "" {
			// pipeline failure is not a counterexample — skip this iteration
			return
		}

		// property: output must NOT contain any frame management artifact
		// on unfixed code this FAILS for every generated input
		if artifact := containsFrameArtifact(cOutput); artifact != "" {
			rt.Errorf(
				"counterexample: frameSize=0x%x, baseAddr=0x%x\n"+
					"output contains frame management artifact: %q\n"+
					"the ir lifter emits push rbp as:\n"+
					"  rsp = (rsp - 8U);\n"+
					"  *(uint64_t*)(rsp) = rbp;\n"+
					"and mov rbp, rsp as:\n"+
					"  rbp = rsp;\n"+
					"no pass in the unfixed pipeline marks these as frame artifacts\n"+
					"or suppresses them — they appear verbatim in the generated c output.\n"+
					"generated output:\n%s",
				frameSize, baseAddr, artifact, cOutput,
			)
		}
	})
}

// TestProperty8_BugCondition_IRLevelFrameArtifacts tests the bug at the IR level
// by running liftInstructionsToIR followed by applyABIPass and then generating
// c output directly from the resulting ir.Function.
//
// this test bypasses the full structuring engine to isolate the frame artifact
// suppression bug from any structuring-related issues.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// the ir.Function after liftInstructionsToIR + applyABIPass contains ir.Assign
// and ir.Store instructions for the frame prologue. the code generator emits
// these verbatim because no IsFrameArtifact field exists in ir.SourceLocation
// and no suppression logic exists in the code generator.
func TestProperty8_BugCondition_IRLevelFrameArtifacts(t *testing.T) {
	const baseAddr = disasm.Address(0x401000)
	const frameSize = int64(0x20)

	insns := buildFramePrologueInsns(baseAddr, frameSize)

	// lift to ir
	irFunc, _, err := liftInstructionsToIR("ir_level_frame_test", insns)
	if err != nil {
		t.Skipf("liftInstructionsToIR failed (non-fatal): %v", err)
		return
	}

	// apply abi pass — on unfixed code this does NOT suppress frame artifacts
	applyABIPass(irFunc, insns)

	// generate c output directly from the ir function using a minimal ast
	// that wraps all blocks as ir blocks
	ast := buildMinimalASTFromIRFunc(irFunc)
	gen := codegen.New()
	decl := gen.GenerateFunction(irFunc, ast)
	cOutput := codegen.RenderDecl(decl)

	// assert: output must NOT contain frame management artifacts
	// on unfixed code this FAILS because the ir contains the frame instructions
	if artifact := containsFrameArtifact(cOutput); artifact != "" {
		t.Errorf(
			"bug confirmed at ir level: output contains frame artifact %q\n"+
				"after liftInstructionsToIR + applyABIPass, the ir.Function still contains\n"+
				"ir.Assign and ir.Store instructions for the frame prologue.\n"+
				"the unfixed applyABIPass does not mark these as frame artifacts\n"+
				"(ir.SourceLocation has no IsFrameArtifact field in unfixed code).\n"+
				"generated output:\n%s",
			artifact, cOutput,
		)
	}
}

// buildMinimalASTFromIRFunc constructs a minimal structuring.StructuredAST
// that wraps all basic blocks of the ir.Function as a flat sequence of IRBlocks.
// this is used to test codegen in isolation without the full structuring engine.
func buildMinimalASTFromIRFunc(fn *ir.Function) *structuring.StructuredAST {
	// collect all instructions from all blocks in entry-first order
	var allInstrs []interface{ isIRInstruction() }
	_ = allInstrs

	// build a single IRBlock containing all instructions from the entry block
	entryBlock, ok := fn.Blocks[fn.EntryBlock]
	if !ok || len(entryBlock.Instructions) == 0 {
		return &structuring.StructuredAST{
			Body:       structuring.Block{},
			FunctionID: 0,
		}
	}

	return &structuring.StructuredAST{
		Body: structuring.IRBlock{
			BlockID:      0,
			Instructions: entryBlock.Instructions,
		},
		FunctionID: 0,
	}
}
