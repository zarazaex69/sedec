package abi

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// buildInsn is a test helper that creates a minimal Instruction
func buildInsn(addr disasm.Address, mnemonic string, ops ...disasm.Operand) *disasm.Instruction {
	return &disasm.Instruction{
		Address:  addr,
		Mnemonic: mnemonic,
		Operands: ops,
		Length:   4,
	}
}

func reg(name string, size disasm.Size) disasm.RegisterOperand {
	return disasm.RegisterOperand{Name: name, Size: size}
}

func imm(value int64, size disasm.Size) disasm.ImmediateOperand {
	return disasm.ImmediateOperand{Value: value, Size: size}
}

func mem(base string, disp int64, size disasm.Size) disasm.MemoryOperand {
	return disasm.MemoryOperand{Base: base, Disp: disp, Size: size}
}

// TestSystemVAnalyzer_IdentifyCallingConvention verifies the convention identifier
func TestSystemVAnalyzer_IdentifyCallingConvention(t *testing.T) {
	a := NewSystemVAnalyzer()
	if got := a.IdentifyCallingConvention(); got != CallingConventionSystemVAMD64 {
		t.Errorf("IdentifyCallingConvention() = %v, want %v", got, CallingConventionSystemVAMD64)
	}
}

// TestSystemVAnalyzer_IdentifyParameters_NoParams tests a function with no parameters
func TestSystemVAnalyzer_IdentifyParameters_NoParams(t *testing.T) {
	// function that never reads any parameter registers
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "mov", reg("rax", disasm.Size64), imm(42, disasm.Size64)),
		buildInsn(0x1007, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1008, "ret"),
	}

	a := NewSystemVAnalyzer()
	params := a.IdentifyParameters(insns)
	if len(params) != 0 {
		t.Errorf("expected 0 parameters, got %d: %v", len(params), params)
	}
}

// TestSystemVAnalyzer_IdentifyParameters_OneIntParam tests a function with one integer parameter
//
//nolint:dupl // intentionally tests system v analyzer with similar pattern
func TestSystemVAnalyzer_IdentifyParameters_OneIntParam(t *testing.T) {
	// function that reads rdi (first integer parameter) before writing it
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		// use rdi as source — this is a parameter read
		buildInsn(0x1004, "mov", reg("rax", disasm.Size64), reg("rdi", disasm.Size64)),
		buildInsn(0x1007, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1008, "ret"),
	}

	a := NewSystemVAnalyzer()
	params := a.IdentifyParameters(insns)
	if len(params) != 1 {
		t.Fatalf("expected 1 parameter, got %d", len(params))
	}
	if params[0].Register != "rdi" {
		t.Errorf("expected parameter in rdi, got %s", params[0].Register)
	}
	if params[0].Location != ParameterLocationRegister {
		t.Errorf("expected register location, got %v", params[0].Location)
	}
	if params[0].Index != 0 {
		t.Errorf("expected index 0, got %d", params[0].Index)
	}
}

// TestSystemVAnalyzer_IdentifyParameters_ThreeIntParams tests three integer parameters
func TestSystemVAnalyzer_IdentifyParameters_ThreeIntParams(t *testing.T) {
	// function(a, b, c) — reads rdi, rsi, rdx
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "add", reg("rdi", disasm.Size64), reg("rsi", disasm.Size64)),
		buildInsn(0x1007, "add", reg("rdi", disasm.Size64), reg("rdx", disasm.Size64)),
		buildInsn(0x100a, "mov", reg("rax", disasm.Size64), reg("rdi", disasm.Size64)),
		buildInsn(0x100d, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x100e, "ret"),
	}

	a := NewSystemVAnalyzer()
	params := a.IdentifyParameters(insns)
	if len(params) != 3 {
		t.Fatalf("expected 3 parameters, got %d", len(params))
	}

	expectedRegs := []string{"rdi", "rsi", "rdx"}
	for i, p := range params {
		if p.Register != expectedRegs[i] {
			t.Errorf("param[%d]: expected register %s, got %s", i, expectedRegs[i], p.Register)
		}
		if p.Index != i {
			t.Errorf("param[%d]: expected index %d, got %d", i, i, p.Index)
		}
	}
}

// TestSystemVAnalyzer_IdentifyReturnValues_IntReturn tests integer return value detection
func TestSystemVAnalyzer_IdentifyReturnValues_IntReturn(t *testing.T) {
	// function that writes rax before ret
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "mov", reg("rax", disasm.Size64), imm(42, disasm.Size64)),
		buildInsn(0x1007, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1008, "ret"),
	}

	a := NewSystemVAnalyzer()
	retVals := a.IdentifyReturnValues(insns)
	if len(retVals) != 1 {
		t.Fatalf("expected 1 return value, got %d", len(retVals))
	}
	if retVals[0].Register != "rax" {
		t.Errorf("expected return in rax, got %s", retVals[0].Register)
	}
}

// TestSystemVAnalyzer_IdentifyReturnValues_VoidReturn tests void function detection
func TestSystemVAnalyzer_IdentifyReturnValues_VoidReturn(t *testing.T) {
	// function that does not write rax before ret
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "mov", mem("rdi", 0, disasm.Size64), imm(0, disasm.Size64)),
		buildInsn(0x1007, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1008, "ret"),
	}

	a := NewSystemVAnalyzer()
	retVals := a.IdentifyReturnValues(insns)
	if len(retVals) != 0 {
		t.Errorf("expected 0 return values (void), got %d: %v", len(retVals), retVals)
	}
}

// TestSystemVAnalyzer_IdentifyReturnValues_NoRet tests function with no ret instruction
func TestSystemVAnalyzer_IdentifyReturnValues_NoRet(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "jmp", imm(0x2000, disasm.Size64)),
	}

	a := NewSystemVAnalyzer()
	retVals := a.IdentifyReturnValues(insns)
	if len(retVals) != 0 {
		t.Errorf("expected 0 return values for noreturn function, got %d", len(retVals))
	}
}

// TestSystemVAnalyzer_VerifyCalleeSavedRegisters_AllPreserved tests proper register preservation
func TestSystemVAnalyzer_VerifyCalleeSavedRegisters_AllPreserved(t *testing.T) {
	// function that saves and restores rbx
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbx", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbx", disasm.Size64), reg("rdi", disasm.Size64)),
		buildInsn(0x1004, "add", reg("rbx", disasm.Size64), imm(1, disasm.Size64)),
		buildInsn(0x1007, "mov", reg("rax", disasm.Size64), reg("rbx", disasm.Size64)),
		buildInsn(0x100a, "pop", reg("rbx", disasm.Size64)),
		buildInsn(0x100b, "ret"),
	}

	a := NewSystemVAnalyzer()
	statuses := a.VerifyCalleeSavedRegisters(insns)

	// find rbx status
	var rbxStatus *CalleeSavedRegisterStatus
	for i := range statuses {
		if statuses[i].Register == "rbx" {
			rbxStatus = &statuses[i]
			break
		}
	}

	if rbxStatus == nil {
		t.Fatal("rbx not found in callee-saved register statuses")
	}
	if !rbxStatus.Preserved {
		t.Errorf("rbx should be preserved (saved and restored), but Preserved=false")
	}
	if rbxStatus.SaveSite != 0x1000 {
		t.Errorf("rbx save site: expected 0x1000, got 0x%x", rbxStatus.SaveSite)
	}
	if rbxStatus.RestoreSite != 0x100a {
		t.Errorf("rbx restore site: expected 0x100a, got 0x%x", rbxStatus.RestoreSite)
	}
}

// TestSystemVAnalyzer_VerifyCalleeSavedRegisters_Clobbered tests detection of clobbered register
func TestSystemVAnalyzer_VerifyCalleeSavedRegisters_Clobbered(t *testing.T) {
	// function that writes r12 without saving it first
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		// r12 written without prior save — ABI violation
		buildInsn(0x1004, "mov", reg("r12", disasm.Size64), imm(0, disasm.Size64)),
		buildInsn(0x1007, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1008, "ret"),
	}

	a := NewSystemVAnalyzer()
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
	// r12 was written but never saved — not preserved
	if r12Status.Preserved {
		t.Errorf("r12 should NOT be preserved (written without save), but Preserved=true")
	}
}

// TestSystemVAnalyzer_IdentifyParameters_AllSixIntRegs tests all six integer parameter registers
func TestSystemVAnalyzer_IdentifyParameters_AllSixIntRegs(t *testing.T) {
	// function(a, b, c, d, e, f) — reads rdi, rsi, rdx, rcx, r8, r9
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		// read all six integer parameter registers
		buildInsn(0x1004, "add", reg("rdi", disasm.Size64), reg("rsi", disasm.Size64)),
		buildInsn(0x1007, "add", reg("rdx", disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x100a, "add", reg("r8", disasm.Size64), reg("r9", disasm.Size64)),
		buildInsn(0x100d, "mov", reg("rax", disasm.Size64), reg("rdi", disasm.Size64)),
		buildInsn(0x1010, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1011, "ret"),
	}

	a := NewSystemVAnalyzer()
	params := a.IdentifyParameters(insns)
	if len(params) != 6 {
		t.Fatalf("expected 6 parameters, got %d", len(params))
	}

	expectedRegs := []string{"rdi", "rsi", "rdx", "rcx", "r8", "r9"}
	for i, p := range params {
		if p.Register != expectedRegs[i] {
			t.Errorf("param[%d]: expected register %s, got %s", i, expectedRegs[i], p.Register)
		}
		if p.Location != ParameterLocationRegister {
			t.Errorf("param[%d]: expected register location", i)
		}
		if p.Index != i {
			t.Errorf("param[%d]: expected index %d, got %d", i, i, p.Index)
		}
	}
}

// TestSystemVAnalyzer_IdentifyParameters_FloatParam tests float parameter detection via xmm0
func TestSystemVAnalyzer_IdentifyParameters_FloatParam(t *testing.T) {
	// function(double x) — reads xmm0 before writing it
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		// movsd xmm1, xmm0 — reads xmm0 as source
		buildInsn(0x1004, "movsd", reg("xmm1", disasm.Size64), reg("xmm0", disasm.Size64)),
		buildInsn(0x1008, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1009, "ret"),
	}

	a := NewSystemVAnalyzer()
	params := a.IdentifyParameters(insns)
	if len(params) != 1 {
		t.Fatalf("expected 1 float parameter, got %d", len(params))
	}
	if params[0].Register != "xmm0" {
		t.Errorf("expected parameter in xmm0, got %s", params[0].Register)
	}
	if params[0].Location != ParameterLocationRegister {
		t.Errorf("expected register location for float param")
	}
}

// TestSystemVAnalyzer_IdentifyParameters_StackParam tests 7th argument via stack
func TestSystemVAnalyzer_IdentifyParameters_StackParam(t *testing.T) {
	// function with 7 args: first 6 in registers, 7th at [rsp+16] inside callee
	// (return address is at [rsp+0], first stack arg at [rsp+8] from call site = [rsp+16] inside callee
	// after push rbp which shifts rsp by 8 — but we detect before frame setup)
	insns := []*disasm.Instruction{
		// read all 6 register params
		buildInsn(0x1000, "add", reg("rdi", disasm.Size64), reg("rsi", disasm.Size64)),
		buildInsn(0x1003, "add", reg("rdx", disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x1006, "add", reg("r8", disasm.Size64), reg("r9", disasm.Size64)),
		// read 7th arg from stack: [rsp+16] (rsp+8 is return addr, rsp+16 is first stack arg)
		buildInsn(0x1009, "mov", reg("rax", disasm.Size64), mem("rsp", 16, disasm.Size64)),
		buildInsn(0x100d, "ret"),
	}

	a := NewSystemVAnalyzer()
	params := a.IdentifyParameters(insns)

	// should detect 6 register params + 1 stack param
	if len(params) < 7 {
		t.Fatalf("expected at least 7 parameters (6 reg + 1 stack), got %d", len(params))
	}

	// find the stack parameter
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
	if stackParam.StackOffset != 16 {
		t.Errorf("stack param offset: expected 16, got %d", stackParam.StackOffset)
	}
}

// TestSystemVAnalyzer_IdentifyReturnValues_128BitReturn tests 128-bit return via rax+rdx
func TestSystemVAnalyzer_IdentifyReturnValues_128BitReturn(t *testing.T) {
	// function returning __int128 or struct in rax:rdx
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "mov", reg("rax", disasm.Size64), imm(0x1234, disasm.Size64)),
		buildInsn(0x1007, "mov", reg("rdx", disasm.Size64), imm(0x5678, disasm.Size64)),
		buildInsn(0x100a, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x100b, "ret"),
	}

	a := NewSystemVAnalyzer()
	retVals := a.IdentifyReturnValues(insns)
	if len(retVals) != 2 {
		t.Fatalf("expected 2 return values (rax+rdx for 128-bit), got %d", len(retVals))
	}
	if retVals[0].Register != "rax" {
		t.Errorf("first return value: expected rax, got %s", retVals[0].Register)
	}
	if retVals[1].Register != "rdx" {
		t.Errorf("second return value: expected rdx, got %s", retVals[1].Register)
	}
}

// TestSystemVAnalyzer_IdentifyReturnValues_FloatReturn tests float return via xmm0
func TestSystemVAnalyzer_IdentifyReturnValues_FloatReturn(t *testing.T) {
	// function returning double via xmm0
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		// movsd xmm0, [rbp-8] — writes xmm0 as return value
		buildInsn(0x1004, "movsd", reg("xmm0", disasm.Size64), mem("rbp", -8, disasm.Size64)),
		buildInsn(0x1008, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1009, "ret"),
	}

	a := NewSystemVAnalyzer()
	retVals := a.IdentifyReturnValues(insns)
	if len(retVals) != 1 {
		t.Fatalf("expected 1 float return value, got %d", len(retVals))
	}
	if retVals[0].Register != "xmm0" {
		t.Errorf("expected return in xmm0, got %s", retVals[0].Register)
	}
}

// TestSystemVAnalyzer_VerifyCalleeSavedRegisters_AllSix tests all six callee-saved registers
func TestSystemVAnalyzer_VerifyCalleeSavedRegisters_AllSix(t *testing.T) {
	// function that saves and restores all six callee-saved registers
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbx", disasm.Size64)),
		buildInsn(0x1001, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1002, "push", reg("r12", disasm.Size64)),
		buildInsn(0x1004, "push", reg("r13", disasm.Size64)),
		buildInsn(0x1006, "push", reg("r14", disasm.Size64)),
		buildInsn(0x1008, "push", reg("r15", disasm.Size64)),
		// use them
		buildInsn(0x100a, "mov", reg("rbx", disasm.Size64), reg("rdi", disasm.Size64)),
		buildInsn(0x100d, "mov", reg("r12", disasm.Size64), reg("rsi", disasm.Size64)),
		// restore in reverse order
		buildInsn(0x1010, "pop", reg("r15", disasm.Size64)),
		buildInsn(0x1012, "pop", reg("r14", disasm.Size64)),
		buildInsn(0x1014, "pop", reg("r13", disasm.Size64)),
		buildInsn(0x1016, "pop", reg("r12", disasm.Size64)),
		buildInsn(0x1018, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1019, "pop", reg("rbx", disasm.Size64)),
		buildInsn(0x101a, "ret"),
	}

	a := NewSystemVAnalyzer()
	statuses := a.VerifyCalleeSavedRegisters(insns)

	if len(statuses) != 6 {
		t.Fatalf("expected 6 callee-saved register statuses, got %d", len(statuses))
	}

	// all registers that were saved must be reported as preserved
	savedRegs := map[string]bool{"rbx": true, "rbp": true, "r12": true, "r13": true, "r14": true, "r15": true}
	for _, s := range statuses {
		if savedRegs[s.Register] && !s.Preserved {
			t.Errorf("register %s was saved and restored but Preserved=false", s.Register)
		}
	}
}

// TestSystemVAnalyzer_VerifyCalleeSavedRegisters_NeverUsed tests untouched registers
func TestSystemVAnalyzer_VerifyCalleeSavedRegisters_NeverUsed(t *testing.T) {
	// function that never touches any callee-saved register
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), reg("rdi", disasm.Size64)),
		buildInsn(0x1003, "ret"),
	}

	a := NewSystemVAnalyzer()
	statuses := a.VerifyCalleeSavedRegisters(insns)

	// all callee-saved registers should be reported as preserved (never touched)
	for _, s := range statuses {
		if !s.Preserved {
			t.Errorf("register %s was never touched but Preserved=false", s.Register)
		}
	}
}

// TestSystemVAnalyzer_VerifyCalleeSavedRegisters_MovSpill tests mov-based spill/restore
//
//nolint:dupl // intentionally tests system v analyzer with similar pattern
func TestSystemVAnalyzer_VerifyCalleeSavedRegisters_MovSpill(t *testing.T) {
	// function that saves r12 via mov [rsp-8], r12 and restores via mov r12, [rsp-8]
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(16, disasm.Size64)),
		// save r12 via mov to stack
		buildInsn(0x1004, "mov", mem("rsp", 0, disasm.Size64), reg("r12", disasm.Size64)),
		// use r12
		buildInsn(0x1008, "mov", reg("r12", disasm.Size64), reg("rdi", disasm.Size64)),
		buildInsn(0x100b, "add", reg("r12", disasm.Size64), imm(1, disasm.Size64)),
		// restore r12 from stack
		buildInsn(0x100f, "mov", reg("r12", disasm.Size64), mem("rsp", 0, disasm.Size64)),
		buildInsn(0x1013, "add", reg("rsp", disasm.Size64), imm(16, disasm.Size64)),
		buildInsn(0x1017, "ret"),
	}

	a := NewSystemVAnalyzer()
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
	if !r12Status.Preserved {
		t.Errorf("r12 was saved via mov and restored via mov but Preserved=false")
	}
}

// TestSystemVAnalyzer_Analyze_VariadicFunction tests variadic function detection
func TestSystemVAnalyzer_Analyze_VariadicFunction(t *testing.T) {
	// variadic function prologue: reads al (xmm count) before writing it
	// typical pattern: test al, al; je .no_xmm; ...
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		// test al, al — reads al as source (variadic xmm count check)
		buildInsn(0x1004, "test", reg("al", disasm.Size8), reg("al", disasm.Size8)),
		buildInsn(0x1006, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1007, "ret"),
	}

	a := NewSystemVAnalyzer()
	result := a.Analyze(insns)

	if !result.IsVariadic {
		t.Error("expected function to be detected as variadic (reads al before write)")
	}
}

// TestSystemVAnalyzer_Analyze_Complete tests full ABI analysis pipeline
//
//nolint:dupl // intentionally tests system v analyzer with similar pattern
func TestSystemVAnalyzer_Analyze_Complete(t *testing.T) {
	// function(int a, int b) -> int: a + b
	// uses rbx as callee-saved scratch register
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbx", disasm.Size64)),
		buildInsn(0x1001, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1002, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1005, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		// use rdi and rsi (parameters)
		buildInsn(0x1009, "mov", reg("rbx", disasm.Size64), reg("rdi", disasm.Size64)),
		buildInsn(0x100c, "add", reg("rbx", disasm.Size64), reg("rsi", disasm.Size64)),
		buildInsn(0x100f, "mov", reg("rax", disasm.Size64), reg("rbx", disasm.Size64)),
		// epilogue
		buildInsn(0x1012, "add", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		buildInsn(0x1016, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1017, "pop", reg("rbx", disasm.Size64)),
		buildInsn(0x1018, "ret"),
	}

	a := NewSystemVAnalyzer()
	result := a.Analyze(insns)

	if result.Convention != CallingConventionSystemVAMD64 {
		t.Errorf("convention: expected SystemV, got %v", result.Convention)
	}
	if len(result.Parameters) != 2 {
		t.Errorf("expected 2 parameters, got %d", len(result.Parameters))
	}
	if len(result.ReturnValues) != 1 || result.ReturnValues[0].Register != "rax" {
		t.Errorf("expected 1 return value in rax, got %v", result.ReturnValues)
	}
	if !result.IsLeaf {
		// this function has no call instructions — it is a leaf
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

// TestIdentifyParametersVariadicNoFloatMisclassification verifies that a variadic
// function prologue containing movaps [rsp+N], xmmK BEFORE integer register reads
// does NOT produce float-typed parameters for the integer registers.
//
// sequence under test:
//
//	movaps [rsp+48], xmm0   ; varargs save area write - NOT a float param
//	movaps [rsp+64], xmm1   ; varargs save area write - NOT a float param
//	mov    [rsp+8],  rdi    ; first integer argument save
//	mov    [rsp+16], rsi    ; second integer argument save
//	ret
func TestIdentifyParametersVariadicNoFloatMisclassification(t *testing.T) {
	insns := []*disasm.Instruction{
		// varargs register save area writes (System V §3.5.7)
		{
			Address:  0x1000,
			Mnemonic: "movaps",
			Operands: []disasm.Operand{
				disasm.MemoryOperand{Base: "rsp", Disp: 48, Size: disasm.Size64},
				disasm.RegisterOperand{Name: "xmm0", Size: disasm.Size64},
			},
			Length: 5,
		},
		{
			Address:  0x1005,
			Mnemonic: "movaps",
			Operands: []disasm.Operand{
				disasm.MemoryOperand{Base: "rsp", Disp: 64, Size: disasm.Size64},
				disasm.RegisterOperand{Name: "xmm1", Size: disasm.Size64},
			},
			Length: 5,
		},
		// integer argument register saves
		{
			Address:  0x100a,
			Mnemonic: "mov",
			Operands: []disasm.Operand{
				disasm.MemoryOperand{Base: "rsp", Disp: 8, Size: disasm.Size64},
				disasm.RegisterOperand{Name: "rdi", Size: disasm.Size64},
			},
			Length: 4,
		},
		{
			Address:  0x100e,
			Mnemonic: "mov",
			Operands: []disasm.Operand{
				disasm.MemoryOperand{Base: "rsp", Disp: 16, Size: disasm.Size64},
				disasm.RegisterOperand{Name: "rsi", Size: disasm.Size64},
			},
			Length: 4,
		},
		buildInsn(0x1012, "ret"),
	}

	a := SystemVAnalyzer{}
	params := a.IdentifyParameters(insns)

	// assert rdi parameter has IntType
	var rdiParam, rsiParam *Parameter
	for i := range params {
		switch params[i].Register {
		case "rdi":
			rdiParam = &params[i]
		case "rsi":
			rsiParam = &params[i]
		}
	}

	expectedIntType := ir.IntType{Width: ir.Size8, Signed: false}

	if rdiParam == nil {
		t.Error("rdi not detected as parameter")
	} else if rdiParam.Type != expectedIntType {
		t.Errorf("rdi type: expected IntType{Size8,false}, got %T(%v)", rdiParam.Type, rdiParam.Type)
	}

	if rsiParam == nil {
		t.Error("rsi not detected as parameter")
	} else if rsiParam.Type != expectedIntType {
		t.Errorf("rsi type: expected IntType{Size8,false}, got %T(%v)", rsiParam.Type, rsiParam.Type)
	}

	// assert no parameter has FloatType - xmm0/xmm1 were saved, not read as args
	for _, p := range params {
		if _, isFloat := p.Type.(ir.FloatType); isFloat {
			t.Errorf("parameter %s (register=%s) has FloatType - varargs save misclassified as float param",
				p.Name, p.Register)
		}
	}
}

// TestIdentifyParametersGenuineFloatPreservation verifies that a genuine float
// argument prologue (xmm0 read before any integer register) still produces
// ir.FloatType for xmm0. this is the preservation test for the varargs fix.
//
// sequence under test:
//
//	movsd xmm1, xmm0   ; reads xmm0 as source - genuine float argument
//	mov   rax, rdi     ; reads rdi - integer argument
//	ret
func TestIdentifyParametersGenuineFloatPreservation(t *testing.T) {
	insns := []*disasm.Instruction{
		// movsd xmm1, xmm0 - reads xmm0 as a genuine float argument
		{
			Address:  0x1000,
			Mnemonic: "movsd",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "xmm1", Size: disasm.Size64},
				disasm.RegisterOperand{Name: "xmm0", Size: disasm.Size64},
			},
			Length: 4,
		},
		// mov rax, rdi - reads rdi as integer argument
		buildInsn(0x1004, "mov",
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.RegisterOperand{Name: "rdi", Size: disasm.Size64},
		),
		buildInsn(0x1007, "ret"),
	}

	a := SystemVAnalyzer{}
	params := a.IdentifyParameters(insns)

	// xmm0 must be classified as FloatType - it was read as a genuine float arg
	var xmm0Param *Parameter
	for i := range params {
		if params[i].Register == "xmm0" {
			xmm0Param = &params[i]
			break
		}
	}

	if xmm0Param == nil {
		t.Fatal("xmm0 not detected as parameter in genuine float prologue")
	}

	expectedFloatType := ir.FloatType{Width: ir.Size8}
	if xmm0Param.Type != expectedFloatType {
		t.Errorf("xmm0 type: expected FloatType{Size8}, got %T(%v)", xmm0Param.Type, xmm0Param.Type)
	}
}
