package abi

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestMicrosoftX64Analyzer_IdentifyCallingConvention verifies the convention identifier
func TestMicrosoftX64Analyzer_IdentifyCallingConvention(t *testing.T) {
	a := NewMicrosoftX64Analyzer()
	if got := a.IdentifyCallingConvention(); got != CallingConventionMicrosoftX64 {
		t.Errorf("IdentifyCallingConvention() = %v, want %v", got, CallingConventionMicrosoftX64)
	}
}

// TestMicrosoftX64Analyzer_IdentifyParameters_NoParams tests a function with no parameters
func TestMicrosoftX64Analyzer_IdentifyParameters_NoParams(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "mov", reg("rax", disasm.Size64), imm(42, disasm.Size64)),
		buildInsn(0x1007, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1008, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	params := a.IdentifyParameters(insns)
	if len(params) != 0 {
		t.Errorf("expected 0 parameters, got %d: %v", len(params), params)
	}
}

// TestMicrosoftX64Analyzer_IdentifyParameters_OneIntParam tests first integer parameter (rcx)
//
//nolint:dupl // intentionally tests microsoft x64 analyzer with similar pattern
func TestMicrosoftX64Analyzer_IdentifyParameters_OneIntParam(t *testing.T) {
	// microsoft x64: first integer param is rcx (not rdi like system v)
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		// read rcx as source — this is the first parameter
		buildInsn(0x1004, "mov", reg("rax", disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x1007, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1008, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	params := a.IdentifyParameters(insns)
	if len(params) != 1 {
		t.Fatalf("expected 1 parameter, got %d", len(params))
	}
	if params[0].Register != "rcx" {
		t.Errorf("expected first parameter in rcx, got %s", params[0].Register)
	}
	if params[0].Location != ParameterLocationRegister {
		t.Errorf("expected register location, got %v", params[0].Location)
	}
	if params[0].Index != 0 {
		t.Errorf("expected index 0, got %d", params[0].Index)
	}
}

// TestMicrosoftX64Analyzer_IdentifyParameters_FourIntParams tests all four integer parameter registers
func TestMicrosoftX64Analyzer_IdentifyParameters_FourIntParams(t *testing.T) {
	// function(a, b, c, d) — reads rcx, rdx, r8, r9
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "add", reg("rcx", disasm.Size64), reg("rdx", disasm.Size64)),
		buildInsn(0x1007, "add", reg("r8", disasm.Size64), reg("r9", disasm.Size64)),
		buildInsn(0x100a, "mov", reg("rax", disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x100d, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x100e, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	params := a.IdentifyParameters(insns)
	if len(params) != 4 {
		t.Fatalf("expected 4 parameters, got %d", len(params))
	}

	expectedRegs := []string{"rcx", "rdx", "r8", "r9"}
	for i, p := range params {
		if p.Register != expectedRegs[i] {
			t.Errorf("param[%d]: expected register %s, got %s", i, expectedRegs[i], p.Register)
		}
		if p.Index != i {
			t.Errorf("param[%d]: expected index %d, got %d", i, i, p.Index)
		}
		if p.Location != ParameterLocationRegister {
			t.Errorf("param[%d]: expected register location", i)
		}
	}
}

// TestMicrosoftX64Analyzer_IdentifyParameters_FloatParam tests float parameter via xmm0
func TestMicrosoftX64Analyzer_IdentifyParameters_FloatParam(t *testing.T) {
	// function(double x) — reads xmm0 (slot 0, not rcx)
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		// movsd xmm1, xmm0 — reads xmm0 as source (float param in slot 0)
		buildInsn(0x1004, "movsd", reg("xmm1", disasm.Size64), reg("xmm0", disasm.Size64)),
		buildInsn(0x1008, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1009, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	params := a.IdentifyParameters(insns)
	if len(params) != 1 {
		t.Fatalf("expected 1 float parameter, got %d", len(params))
	}
	if params[0].Register != "xmm0" {
		t.Errorf("expected parameter in xmm0, got %s", params[0].Register)
	}
	if params[0].Index != 0 {
		t.Errorf("expected slot index 0, got %d", params[0].Index)
	}
}

// TestMicrosoftX64Analyzer_IdentifyParameters_UnifiedSlots tests that integer and float
// slots are unified — if slot 0 is float (xmm0), rcx is NOT also slot 0
func TestMicrosoftX64Analyzer_IdentifyParameters_UnifiedSlots(t *testing.T) {
	// function(double x, int y) — xmm0 is slot 0, rdx is slot 1
	// rcx must NOT be detected as a parameter (slot 0 is taken by xmm0)
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		// read xmm0 (slot 0 = float)
		buildInsn(0x1004, "movsd", reg("xmm1", disasm.Size64), reg("xmm0", disasm.Size64)),
		// read rdx (slot 1 = integer)
		buildInsn(0x1008, "mov", reg("rax", disasm.Size64), reg("rdx", disasm.Size64)),
		buildInsn(0x100b, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x100c, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	params := a.IdentifyParameters(insns)

	// expect exactly 2 params: xmm0 (slot 0) and rdx (slot 1)
	if len(params) != 2 {
		t.Fatalf("expected 2 parameters (xmm0 + rdx), got %d: %v", len(params), params)
	}

	// verify no rcx was detected (slot 0 already taken by xmm0)
	for _, p := range params {
		if p.Register == "rcx" {
			t.Error("rcx must not be detected as parameter when slot 0 is taken by xmm0")
		}
	}
}

// TestMicrosoftX64Analyzer_IdentifyParameters_ShadowSpaceNotParam tests that
// shadow space accesses ([rsp+8] through [rsp+32]) are NOT treated as parameters
func TestMicrosoftX64Analyzer_IdentifyParameters_ShadowSpaceNotParam(t *testing.T) {
	// callee spilling rcx into its shadow space: mov [rsp+8], rcx
	// this is NOT a stack parameter — it is the callee using its home space
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x28, disasm.Size64)),
		// spill rcx into shadow space (home space at [rsp+8] after sub rsp,0x28 → [rsp+8] = rsp_entry+8)
		buildInsn(0x1004, "mov", mem("rsp", 8, disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x1009, "mov", mem("rsp", 16, disasm.Size64), reg("rdx", disasm.Size64)),
		buildInsn(0x100e, "mov", mem("rsp", 24, disasm.Size64), reg("r8", disasm.Size64)),
		buildInsn(0x1013, "mov", mem("rsp", 32, disasm.Size64), reg("r9", disasm.Size64)),
		buildInsn(0x1018, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	params := a.IdentifyParameters(insns)

	// shadow space writes ([rsp+8..32] after sub rsp,0x28) must not be stack params
	for _, p := range params {
		if p.Location == ParameterLocationStack {
			t.Errorf("shadow space access incorrectly detected as stack parameter at offset %d", p.StackOffset)
		}
	}
}

// TestMicrosoftX64Analyzer_IdentifyParameters_StackParam tests 5th argument via stack
func TestMicrosoftX64Analyzer_IdentifyParameters_StackParam(t *testing.T) {
	// function with 5 args: first 4 in registers, 5th at [rsp+40] inside callee
	// layout: [rsp+0]=ret_addr, [rsp+8..32]=shadow, [rsp+40]=5th_arg
	insns := []*disasm.Instruction{
		// read all 4 register params
		buildInsn(0x1000, "add", reg("rcx", disasm.Size64), reg("rdx", disasm.Size64)),
		buildInsn(0x1003, "add", reg("r8", disasm.Size64), reg("r9", disasm.Size64)),
		// read 5th arg from stack: [rsp+40] = shadow(32) + return_addr(8)
		buildInsn(0x1006, "mov", reg("rax", disasm.Size64), mem("rsp", 40, disasm.Size64)),
		buildInsn(0x100a, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	params := a.IdentifyParameters(insns)

	// should detect 4 register params + 1 stack param
	if len(params) < 5 {
		t.Fatalf("expected at least 5 parameters (4 reg + 1 stack), got %d", len(params))
	}

	var stackParam *Parameter
	for i := range params {
		if params[i].Location == ParameterLocationStack {
			stackParam = &params[i]
			break
		}
	}
	if stackParam == nil {
		t.Fatal("no stack parameter detected")
	}
	if stackParam.StackOffset != 40 {
		t.Errorf("stack param offset: expected 40, got %d", stackParam.StackOffset)
	}
	if stackParam.Index != 4 {
		t.Errorf("stack param index: expected 4 (5th slot), got %d", stackParam.Index)
	}
}

// TestMicrosoftX64Analyzer_IdentifyReturnValues_IntReturn tests integer return via rax
func TestMicrosoftX64Analyzer_IdentifyReturnValues_IntReturn(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "mov", reg("rax", disasm.Size64), imm(42, disasm.Size64)),
		buildInsn(0x1007, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1008, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	retVals := a.IdentifyReturnValues(insns)
	if len(retVals) != 1 {
		t.Fatalf("expected 1 return value, got %d", len(retVals))
	}
	if retVals[0].Register != "rax" {
		t.Errorf("expected return in rax, got %s", retVals[0].Register)
	}
}

// TestMicrosoftX64Analyzer_IdentifyReturnValues_FloatReturn tests float return via xmm0
func TestMicrosoftX64Analyzer_IdentifyReturnValues_FloatReturn(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "movsd", reg("xmm0", disasm.Size64), mem("rbp", -8, disasm.Size64)),
		buildInsn(0x1008, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1009, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	retVals := a.IdentifyReturnValues(insns)
	if len(retVals) != 1 {
		t.Fatalf("expected 1 float return value, got %d", len(retVals))
	}
	if retVals[0].Register != "xmm0" {
		t.Errorf("expected return in xmm0, got %s", retVals[0].Register)
	}
}

// TestMicrosoftX64Analyzer_IdentifyReturnValues_VoidReturn tests void function
func TestMicrosoftX64Analyzer_IdentifyReturnValues_VoidReturn(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "mov", mem("rcx", 0, disasm.Size64), imm(0, disasm.Size64)),
		buildInsn(0x1007, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1008, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	retVals := a.IdentifyReturnValues(insns)
	if len(retVals) != 0 {
		t.Errorf("expected 0 return values (void), got %d: %v", len(retVals), retVals)
	}
}

// TestMicrosoftX64Analyzer_IdentifyReturnValues_NoRet tests noreturn function
func TestMicrosoftX64Analyzer_IdentifyReturnValues_NoRet(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "jmp", imm(0x2000, disasm.Size64)),
	}

	a := NewMicrosoftX64Analyzer()
	retVals := a.IdentifyReturnValues(insns)
	if len(retVals) != 0 {
		t.Errorf("expected 0 return values for noreturn function, got %d", len(retVals))
	}
}

// TestMicrosoftX64Analyzer_VerifyCalleeSavedRegisters_RdiRsiAreCalleeSaved tests that
// rdi and rsi are callee-saved in Microsoft x64 (unlike System V where they are params)
func TestMicrosoftX64Analyzer_VerifyCalleeSavedRegisters_RdiRsiAreCalleeSaved(t *testing.T) {
	// function that saves and restores rdi and rsi (callee-saved in ms x64)
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rdi", disasm.Size64)),
		buildInsn(0x1001, "push", reg("rsi", disasm.Size64)),
		buildInsn(0x1002, "mov", reg("rdi", disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x1005, "mov", reg("rsi", disasm.Size64), reg("rdx", disasm.Size64)),
		buildInsn(0x1008, "pop", reg("rsi", disasm.Size64)),
		buildInsn(0x1009, "pop", reg("rdi", disasm.Size64)),
		buildInsn(0x100a, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	statuses := a.VerifyCalleeSavedRegisters(insns)

	// verify rdi and rsi are in the callee-saved list and properly preserved
	rdiFound, rsiFound := false, false
	for _, s := range statuses {
		if s.Register == "rdi" {
			rdiFound = true
			if !s.Preserved {
				t.Error("rdi was saved and restored but Preserved=false")
			}
		}
		if s.Register == "rsi" {
			rsiFound = true
			if !s.Preserved {
				t.Error("rsi was saved and restored but Preserved=false")
			}
		}
	}
	if !rdiFound {
		t.Error("rdi not found in Microsoft x64 callee-saved register list")
	}
	if !rsiFound {
		t.Error("rsi not found in Microsoft x64 callee-saved register list")
	}
}

// TestMicrosoftX64Analyzer_VerifyCalleeSavedRegisters_Clobbered tests clobbered detection
func TestMicrosoftX64Analyzer_VerifyCalleeSavedRegisters_Clobbered(t *testing.T) {
	// function that writes r12 without saving it — ABI violation
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "mov", reg("r12", disasm.Size64), imm(0, disasm.Size64)),
		buildInsn(0x1007, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1008, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	statuses := a.VerifyCalleeSavedRegisters(insns)

	var r12Status *CalleeSavedRegisterStatus
	for i := range statuses {
		if statuses[i].Register == "r12" {
			r12Status = &statuses[i]
			break
		}
	}
	if r12Status == nil {
		t.Fatal("r12 not found in callee-saved register statuses")
	}
	if r12Status.Preserved {
		t.Error("r12 should NOT be preserved (written without save), but Preserved=true")
	}
}

// TestMicrosoftX64Analyzer_VerifyCalleeSavedRegisters_AllEight tests all 8 integer callee-saved
func TestMicrosoftX64Analyzer_VerifyCalleeSavedRegisters_AllEight(t *testing.T) {
	// function that saves and restores all 8 integer callee-saved registers
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbx", disasm.Size64)),
		buildInsn(0x1001, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1002, "push", reg("rdi", disasm.Size64)),
		buildInsn(0x1003, "push", reg("rsi", disasm.Size64)),
		buildInsn(0x1004, "push", reg("r12", disasm.Size64)),
		buildInsn(0x1006, "push", reg("r13", disasm.Size64)),
		buildInsn(0x1008, "push", reg("r14", disasm.Size64)),
		buildInsn(0x100a, "push", reg("r15", disasm.Size64)),
		buildInsn(0x100c, "pop", reg("r15", disasm.Size64)),
		buildInsn(0x100e, "pop", reg("r14", disasm.Size64)),
		buildInsn(0x1010, "pop", reg("r13", disasm.Size64)),
		buildInsn(0x1012, "pop", reg("r12", disasm.Size64)),
		buildInsn(0x1014, "pop", reg("rsi", disasm.Size64)),
		buildInsn(0x1015, "pop", reg("rdi", disasm.Size64)),
		buildInsn(0x1016, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1017, "pop", reg("rbx", disasm.Size64)),
		buildInsn(0x1018, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	statuses := a.VerifyCalleeSavedRegisters(insns)

	if len(statuses) != 8 {
		t.Fatalf("expected 8 callee-saved register statuses, got %d", len(statuses))
	}
	for _, s := range statuses {
		if !s.Preserved {
			t.Errorf("register %s was saved and restored but Preserved=false", s.Register)
		}
	}
}

// TestMicrosoftX64Analyzer_TrackStackPointer_StandardPrologue tests standard ms x64 prologue
func TestMicrosoftX64Analyzer_TrackStackPointer_StandardPrologue(t *testing.T) {
	// typical ms x64 prologue: push rbp; mov rbp, rsp; sub rsp, 0x20
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		buildInsn(0x1008, "nop"),
	}

	a := NewMicrosoftX64Analyzer()
	tracker := a.TrackStackPointer(insns)

	// at 0x1000: rsp offset = 0
	off0, ok := tracker.GetOffset(0x1000)
	if !ok {
		t.Fatal("no offset at 0x1000")
	}
	if c, ok := off0.(ConcreteOffset); !ok || c.Value != 0 {
		t.Errorf("offset at 0x1000: expected 0, got %v", off0)
	}

	// at 0x1001 (after push rbp): rsp offset = -8
	off1, ok := tracker.GetOffset(0x1001)
	if !ok {
		t.Fatal("no offset at 0x1001")
	}
	if c, ok := off1.(ConcreteOffset); !ok || c.Value != -8 {
		t.Errorf("offset at 0x1001: expected -8, got %v", off1)
	}

	// at 0x1008 (after sub rsp, 0x20): rsp offset = -8 - 0x20 = -40
	off3, ok := tracker.GetOffset(0x1008)
	if !ok {
		t.Fatal("no offset at 0x1008")
	}
	if c, ok := off3.(ConcreteOffset); !ok || c.Value != -40 {
		t.Errorf("offset at 0x1008: expected -40, got %v", off3)
	}
}

// TestMicrosoftX64Analyzer_TrackStackPointer_FramePointerDetection tests rbp detection
func TestMicrosoftX64Analyzer_TrackStackPointer_FramePointerDetection(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	tracker := a.TrackStackPointer(insns)

	if !tracker.HasFramePointer() {
		t.Error("expected frame pointer to be detected after 'mov rbp, rsp'")
	}
	fpOffset, ok := tracker.FramePointerRSPOffset()
	if !ok {
		t.Fatal("FramePointerRSPOffset returned false")
	}
	// after push rbp, rsp = -8; mov rbp, rsp sets frame pointer at rsp=-8
	if fpOffset != -8 {
		t.Errorf("frame pointer RSP offset: expected -8, got %d", fpOffset)
	}
}

// TestMicrosoftX64Analyzer_TrackStackPointer_SymbolicAlloca tests dynamic allocation
func TestMicrosoftX64Analyzer_TrackStackPointer_SymbolicAlloca(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		// sub rsp, rcx — dynamic allocation (alloca)
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x1007, "nop"),
	}

	a := NewMicrosoftX64Analyzer()
	tracker := a.TrackStackPointer(insns)

	off, ok := tracker.GetOffset(0x1007)
	if !ok {
		t.Fatal("no offset at 0x1007")
	}
	sym, isSym := off.(SymbolicOffset)
	if !isSym {
		t.Fatalf("expected SymbolicOffset after alloca, got %T", off)
	}
	if sym.VarName != "rcx" {
		t.Errorf("symbolic variable: expected 'rcx', got '%s'", sym.VarName)
	}
	if sym.Base != -8 {
		t.Errorf("symbolic base: expected -8, got %d", sym.Base)
	}
}

// TestMicrosoftX64Analyzer_AnalyzeStackFrame_LocalVariables tests local variable identification
func TestMicrosoftX64Analyzer_AnalyzeStackFrame_LocalVariables(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), imm(0x30, disasm.Size64)),
		// store to local variable at [rbp-8]
		buildInsn(0x1008, "mov", mem("rbp", -8, disasm.Size64), imm(42, disasm.Size64)),
		// store to local variable at [rbp-16]
		buildInsn(0x100c, "mov", mem("rbp", -16, disasm.Size64), imm(99, disasm.Size64)),
		buildInsn(0x1010, "add", reg("rsp", disasm.Size64), imm(0x30, disasm.Size64)),
		buildInsn(0x1014, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1015, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	frame := a.AnalyzeStackFrame(insns)

	if !frame.HasFramePointer {
		t.Error("expected frame to have frame pointer")
	}
	if frame.Size < 0x30 {
		t.Errorf("frame size: expected >= 0x30, got %d", frame.Size)
	}
	if len(frame.LocalVariables) < 2 {
		t.Errorf("expected at least 2 local variables, got %d", len(frame.LocalVariables))
	}
}

// TestMicrosoftX64Analyzer_Analyze_Complete tests full ABI analysis pipeline
//
//nolint:dupl // intentionally tests microsoft x64 analyzer with similar pattern
func TestMicrosoftX64Analyzer_Analyze_Complete(t *testing.T) {
	// function(int a, int b) -> int: a + b
	// uses rbx as callee-saved scratch register
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbx", disasm.Size64)),
		buildInsn(0x1001, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1002, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1005, "sub", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		// use rcx and rdx (microsoft x64 params 1 and 2)
		buildInsn(0x1009, "mov", reg("rbx", disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x100c, "add", reg("rbx", disasm.Size64), reg("rdx", disasm.Size64)),
		buildInsn(0x100f, "mov", reg("rax", disasm.Size64), reg("rbx", disasm.Size64)),
		buildInsn(0x1012, "add", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		buildInsn(0x1016, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1017, "pop", reg("rbx", disasm.Size64)),
		buildInsn(0x1018, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	result := a.Analyze(insns)

	if result.Convention != CallingConventionMicrosoftX64 {
		t.Errorf("convention: expected MicrosoftX64, got %v", result.Convention)
	}
	if len(result.Parameters) != 2 {
		t.Errorf("expected 2 parameters (rcx, rdx), got %d", len(result.Parameters))
	}
	if len(result.ReturnValues) != 1 || result.ReturnValues[0].Register != "rax" {
		t.Errorf("expected 1 return value in rax, got %v", result.ReturnValues)
	}
	if !result.IsLeaf {
		t.Error("expected leaf function (no calls)")
	}
	if result.IsVariadic {
		t.Error("expected non-variadic function")
	}

	// rbx and rbp must be preserved
	for _, s := range result.CalleeSavedRegs {
		if (s.Register == "rbx" || s.Register == "rbp") && !s.Preserved {
			t.Errorf("register %s should be preserved", s.Register)
		}
	}
}

// TestMicrosoftX64Analyzer_Analyze_NonLeafFunction tests non-leaf detection
func TestMicrosoftX64Analyzer_Analyze_NonLeafFunction(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), imm(0x28, disasm.Size64)),
		buildInsn(0x1008, "call", imm(0x2000, disasm.Size64)),
		buildInsn(0x100d, "add", reg("rsp", disasm.Size64), imm(0x28, disasm.Size64)),
		buildInsn(0x1011, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1012, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	result := a.Analyze(insns)

	if result.IsLeaf {
		t.Error("expected non-leaf function (has call instruction)")
	}
}

// TestNewAnalyzer_MicrosoftX64 tests factory function for Microsoft x64 convention
func TestNewAnalyzer_MicrosoftX64(t *testing.T) {
	analyzer, err := NewAnalyzer(CallingConventionMicrosoftX64)
	if err != nil {
		t.Fatalf("NewAnalyzer(MicrosoftX64) returned error: %v", err)
	}
	if analyzer == nil {
		t.Fatal("NewAnalyzer returned nil analyzer")
	}
	if analyzer.IdentifyCallingConvention() != CallingConventionMicrosoftX64 {
		t.Errorf("wrong convention from factory-created analyzer")
	}
}

// TestMicrosoftX64Analyzer_ShadowSpaceConstants verifies shadow space constants are correct
func TestMicrosoftX64Analyzer_ShadowSpaceConstants(t *testing.T) {
	// shadow space must be exactly 32 bytes (4 * 8 bytes for rcx/rdx/r8/r9 home space)
	if msX64ShadowSpaceSize != 32 {
		t.Errorf("shadow space size: expected 32, got %d", msX64ShadowSpaceSize)
	}
	// first stack arg offset = shadow(32) + return_addr(8) = 40
	if msX64FirstStackArgOffset != 40 {
		t.Errorf("first stack arg offset: expected 40, got %d", msX64FirstStackArgOffset)
	}
}

// TestMicrosoftX64Analyzer_CalleeSavedList verifies the callee-saved register list
// contains exactly the registers mandated by the Microsoft x64 ABI
func TestMicrosoftX64Analyzer_CalleeSavedList(t *testing.T) {
	// microsoft x64 integer callee-saved: rbx, rbp, rdi, rsi, r12-r15
	// note: rdi and rsi are callee-saved (unlike system v where they are params)
	required := map[string]bool{
		"rbx": true, "rbp": true,
		"rdi": true, "rsi": true,
		"r12": true, "r13": true, "r14": true, "r15": true,
	}

	if len(msX64CalleeSavedInt) != len(required) {
		t.Errorf("callee-saved list length: expected %d, got %d", len(required), len(msX64CalleeSavedInt))
	}
	for _, r := range msX64CalleeSavedInt {
		if !required[r] {
			t.Errorf("unexpected register in callee-saved list: %s", r)
		}
	}
}

// TestMicrosoftX64Analyzer_ParamRegList verifies the parameter register lists
func TestMicrosoftX64Analyzer_ParamRegList(t *testing.T) {
	// microsoft x64: only 4 integer param regs (vs 6 in system v)
	expectedInt := []string{"rcx", "rdx", "r8", "r9"}
	if len(msX64IntParamRegs) != len(expectedInt) {
		t.Errorf("int param reg count: expected %d, got %d", len(expectedInt), len(msX64IntParamRegs))
	}
	for i, r := range expectedInt {
		if msX64IntParamRegs[i] != r {
			t.Errorf("int param reg[%d]: expected %s, got %s", i, r, msX64IntParamRegs[i])
		}
	}

	// microsoft x64: only 4 float param regs (vs 8 in system v)
	expectedFloat := []string{"xmm0", "xmm1", "xmm2", "xmm3"}
	if len(msX64FloatParamRegs) != len(expectedFloat) {
		t.Errorf("float param reg count: expected %d, got %d", len(expectedFloat), len(msX64FloatParamRegs))
	}
	for i, r := range expectedFloat {
		if msX64FloatParamRegs[i] != r {
			t.Errorf("float param reg[%d]: expected %s, got %s", i, r, msX64FloatParamRegs[i])
		}
	}
}
