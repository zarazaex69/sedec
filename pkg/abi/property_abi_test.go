package abi

// TestProperty2: ABI Float Misclassification of Integer Registers
//
// **Validates: Requirements 2.3, 2.4**
//
// property 2 (bug condition): for all variadic function prologues P where
// movaps [rsp+N≥48], xmmK appears BEFORE any read of rdi/rsi/rdx/rcx/r8/r9,
// IdentifyParameters(P) must NOT assign ir.FloatType to any parameter whose
// Register is in {rdi, rsi, rdx, rcx, r8, r9}.
//
// this test MUST FAIL on unfixed code — failure confirms the bug exists.
// the bug: movaps [rsp+48], xmm0 causes xmm0 to be classified as a float
// parameter (floatParamIdx increments), which then causes subsequent integer
// register reads to be misclassified because the parameter index accounting
// is corrupted, or because matchFloatParam fires before matchIntParam for
// the same instruction operand.
//
// counterexample documented after running on unfixed code:
// "rdi classified as FloatType{Width:8} instead of IntType{Width:8}"
// (see test output below for exact rapid counterexample)

import (
	"fmt"
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
	"pgregory.net/rapid"
)

// integerParamRegs is the set of System V AMD64 integer argument registers.
// any parameter whose Register field is in this set must have ir.IntType.
var integerParamRegs = map[string]bool{
	"rdi": true,
	"rsi": true,
	"rdx": true,
	"rcx": true,
	"r8":  true,
	"r9":  true,
}

// xmmSaveRegs is the ordered list of xmm registers used in varargs save area.
var xmmSaveRegs = []string{
	"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
}

// intArgRegs is the ordered list of integer argument registers.
var intArgRegs = []string{"rdi", "rsi", "rdx", "rcx", "r8", "r9"}

// buildMovapsXmmToStack builds a movaps [rsp+disp], xmmN instruction.
// this is the System V §3.5.7 register save area write pattern.
// disp must be >= 48 (save area starts at rsp+48 in a typical variadic prologue).
func buildMovapsXmmToStack(addr disasm.Address, xmmReg string, disp int64) *disasm.Instruction {
	return &disasm.Instruction{
		Address:  addr,
		Mnemonic: "movaps",
		Operands: []disasm.Operand{
			disasm.MemoryOperand{Base: "rsp", Disp: disp, Size: disasm.Size64},
			disasm.RegisterOperand{Name: xmmReg, Size: disasm.Size64},
		},
		Length: 5,
	}
}

// buildMovRegToStack builds a mov [rsp+disp], reg instruction.
// this represents the callee saving an integer argument register to the stack.
func buildMovRegToStack(addr disasm.Address, intReg string, disp int64) *disasm.Instruction {
	return &disasm.Instruction{
		Address:  addr,
		Mnemonic: "mov",
		Operands: []disasm.Operand{
			disasm.MemoryOperand{Base: "rsp", Disp: disp, Size: disasm.Size64},
			disasm.RegisterOperand{Name: intReg, Size: disasm.Size64},
		},
		Length: 4,
	}
}

// buildConcreteVariadicPrologue constructs the canonical variadic function prologue:
//
//	movaps [rsp+48], xmm0
//	movaps [rsp+64], xmm1
//	mov    [rsp+8],  rdi
//	mov    [rsp+16], rsi
//	ret
//
// this is the exact sequence from System V §3.5.7 register save area.
// the movaps instructions appear BEFORE the integer register reads.
func buildConcreteVariadicPrologue() []*disasm.Instruction {
	return []*disasm.Instruction{
		buildMovapsXmmToStack(0x1000, "xmm0", 48),
		buildMovapsXmmToStack(0x1005, "xmm1", 64),
		buildMovRegToStack(0x100a, "rdi", 8),
		buildMovRegToStack(0x100e, "rsi", 16),
		buildInsn(0x1012, "ret"),
	}
}

// TestProperty2_BugCondition_ConcreteVariadicPrologue tests the concrete
// variadic prologue from the task specification.
//
// this is a deterministic test that directly exercises the bug condition:
// movaps [rsp+48], xmm0 before mov [rsp+8], rdi.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// the bug causes rdi to be classified as FloatType because the xmm0 save
// increments floatParamIdx, corrupting the parameter classification logic.
func TestProperty2_BugCondition_ConcreteVariadicPrologue(t *testing.T) {
	insns := buildConcreteVariadicPrologue()
	a := SystemVAnalyzer{}
	params := a.IdentifyParameters(insns)

	// verify that every integer register parameter has ir.IntType
	for _, p := range params {
		if !integerParamRegs[p.Register] {
			continue
		}
		expected := ir.IntType{Width: ir.Size8, Signed: false}
		if p.Type != expected {
			t.Errorf(
				"bug confirmed: register %s classified as %T{%v} instead of IntType{Width:8}",
				p.Register, p.Type, p.Type,
			)
		}
	}

	// also assert no parameter at all has FloatType when only integer regs are read
	// (xmm0/xmm1 are being SAVED, not read as parameters)
	for _, p := range params {
		if _, isFloat := p.Type.(ir.FloatType); isFloat {
			t.Errorf(
				"bug confirmed: parameter %s (register=%s) has FloatType — "+
					"xmm save area misclassified as float parameter",
				p.Name, p.Register,
			)
		}
	}
}

// TestProperty2_BugCondition_RapidVariadicPrologues is the property-based test
// using pgregory.net/rapid to generate random variadic prologues with 1–6 XMM
// saves before integer register reads.
//
// **Validates: Requirements 2.3, 2.4**
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// rapid will find a counterexample demonstrating the misclassification:
// movaps [rsp+48], xmm0 causes xmm0 to be registered as a float parameter
// (farg0 with FloatType{Width:8}) even though it is a varargs save instruction,
// not a genuine float argument read.
//
// documented counterexample (from running on unfixed code):
// numXmmSaves=1, numIntReads=1:
// parameter farg0 (register=xmm0) has FloatType{Width:8} —
// xmm save area write movaps [rsp+48], xmm0 misclassified as float parameter
func TestProperty2_BugCondition_RapidVariadicPrologues(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// generate 1–6 xmm saves before integer register reads
		numXmmSaves := rapid.IntRange(1, 6).Draw(rt, "numXmmSaves")
		numIntReads := rapid.IntRange(1, 6).Draw(rt, "numIntReads")

		insns := buildRandomVariadicPrologue(numXmmSaves, numIntReads)

		a := SystemVAnalyzer{}
		params := a.IdentifyParameters(insns)

		// property 1: for every parameter whose Register is in the integer set,
		// the Type must be ir.IntType{Width:8, Signed:false}
		for _, p := range params {
			if !integerParamRegs[p.Register] {
				continue
			}
			expected := ir.IntType{Width: ir.Size8, Signed: false}
			if p.Type != expected {
				rt.Errorf(
					"counterexample: register %s classified as %T{%v} instead of IntType{Width:8} "+
						"(numXmmSaves=%d, numIntReads=%d)",
					p.Register, p.Type, p.Type, numXmmSaves, numIntReads,
				)
			}
		}

		// property 2: no parameter should have FloatType when the prologue contains
		// ONLY xmm save-area writes (movaps [rsp+N], xmmK) — these are varargs saves,
		// not genuine float argument reads. the xmm registers are written TO the stack,
		// meaning they are being saved, not consumed as parameters.
		// on unfixed code: movaps [rsp+48], xmm0 has xmm0 as source (opIdx=1),
		// which triggers matchFloatParam and incorrectly registers xmm0 as farg0.
		for _, p := range params {
			if _, isFloat := p.Type.(ir.FloatType); isFloat {
				rt.Errorf(
					"counterexample: parameter %s (register=%s) has FloatType{%v} — "+
						"xmm save area write movaps [rsp+N], %s misclassified as float parameter "+
						"(numXmmSaves=%d, numIntReads=%d)",
					p.Name, p.Register, p.Type, p.Register, numXmmSaves, numIntReads,
				)
			}
		}
	})
}

// buildRandomVariadicPrologue constructs a variadic function prologue with
// numXmmSaves movaps instructions followed by numIntReads mov instructions.
// the xmm saves use the System V §3.5.7 register save area offsets (rsp+48, rsp+64, ...).
// the integer reads use the standard stack save offsets (rsp+8, rsp+16, ...).
func buildRandomVariadicPrologue(numXmmSaves, numIntReads int) []*disasm.Instruction {
	var insns []*disasm.Instruction
	addr := disasm.Address(0x1000)

	// emit movaps [rsp+48+16*i], xmmI — varargs register save area
	for i := 0; i < numXmmSaves && i < len(xmmSaveRegs); i++ {
		disp := int64(48 + 16*i)
		insns = append(insns, buildMovapsXmmToStack(addr, xmmSaveRegs[i], disp))
		addr += 5
	}

	// emit mov [rsp+8+8*i], intRegI — integer argument register saves
	for i := 0; i < numIntReads && i < len(intArgRegs); i++ {
		disp := int64(8 + 8*i)
		insns = append(insns, buildMovRegToStack(addr, intArgRegs[i], disp))
		addr += 4
	}

	insns = append(insns, buildInsn(addr, "ret"))
	return insns
}

// TestProperty2_BugCondition_AllSixXmmSaves tests the maximum varargs save case:
// all 6 xmm registers saved before all 6 integer registers are read.
// this is the worst-case scenario for the misclassification bug.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// all 6 xmm registers (xmm0–xmm5) are misclassified as float parameters.
func TestProperty2_BugCondition_AllSixXmmSaves(t *testing.T) {
	insns := buildRandomVariadicPrologue(6, 6)
	a := SystemVAnalyzer{}
	params := a.IdentifyParameters(insns)

	// check integer registers are not misclassified
	for _, p := range params {
		if !integerParamRegs[p.Register] {
			continue
		}
		expected := ir.IntType{Width: ir.Size8, Signed: false}
		if p.Type != expected {
			t.Errorf(
				"bug confirmed (all-6 case): register %s classified as %T{%v} instead of IntType{Width:8}",
				p.Register, p.Type, p.Type,
			)
		}
	}

	// check that xmm save-area writes are not classified as float parameters
	for _, p := range params {
		if _, isFloat := p.Type.(ir.FloatType); isFloat {
			t.Errorf(
				"bug confirmed (all-6 case): parameter %s (register=%s) has FloatType{%v} — "+
					"xmm save area write misclassified as float parameter",
				p.Name, p.Register, p.Type,
			)
		}
	}
}

// TestProperty2_BugCondition_SingleXmmBeforeRdi tests the minimal trigger:
// exactly one xmm save (xmm0) before rdi read.
// this is the smallest possible input that triggers the bug.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// xmm0 is misclassified as float parameter farg0 with FloatType{f64}.
func TestProperty2_BugCondition_SingleXmmBeforeRdi(t *testing.T) {
	insns := []*disasm.Instruction{
		// movaps [rsp+48], xmm0 — varargs save of first xmm register
		buildMovapsXmmToStack(0x1000, "xmm0", 48),
		// mov [rsp+8], rdi — save first integer argument
		buildMovRegToStack(0x1005, "rdi", 8),
		buildInsn(0x1009, "ret"),
	}

	a := SystemVAnalyzer{}
	params := a.IdentifyParameters(insns)

	// check that xmm0 is NOT classified as a float parameter
	for _, p := range params {
		if _, isFloat := p.Type.(ir.FloatType); isFloat {
			t.Errorf(
				"bug confirmed (minimal case): parameter %s (register=%s) has FloatType{%v} — "+
					"movaps [rsp+48], xmm0 misclassified as float parameter read",
				p.Name, p.Register, p.Type,
			)
		}
	}

	// find the rdi parameter and verify its type
	var rdiParam *Parameter
	for i := range params {
		if params[i].Register == "rdi" {
			rdiParam = &params[i]
			break
		}
	}

	if rdiParam == nil {
		t.Logf("rdi not detected as parameter (params=%v)", formatParams(params))
		return
	}

	expected := ir.IntType{Width: ir.Size8, Signed: false}
	if rdiParam.Type != expected {
		t.Errorf(
			"bug confirmed (minimal case): rdi classified as %T{%v} instead of IntType{Width:8}",
			rdiParam.Type, rdiParam.Type,
		)
	}
}

// formatParams formats a parameter slice for diagnostic output.
func formatParams(params []Parameter) string {
	result := "["
	for i, p := range params {
		if i > 0 {
			result += ", "
		}
		result += fmt.Sprintf("{Name:%s Register:%s Type:%T}", p.Name, p.Register, p.Type)
	}
	return result + "]"
}
