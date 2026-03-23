package abi

import (
	"errors"
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// ---------------------------------------------------------------------------
// SystemV x64 calling convention tests
// ---------------------------------------------------------------------------

func TestSystemV_IdentifyParameters_MixedIntAndFloat(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", mem("rbp", -8, disasm.Size64), reg("rdi", disasm.Size64)),
		buildInsn(0x1004, "movsd", mem("rbp", -16, disasm.Size64), reg("xmm0", disasm.Size64)),
		buildInsn(0x1008, "mov", mem("rbp", -24, disasm.Size64), reg("rsi", disasm.Size64)),
		buildInsn(0x100c, "ret"),
	}

	a := NewSystemVAnalyzer()
	params := a.IdentifyParameters(insns)

	intCount := 0
	floatCount := 0
	for _, p := range params {
		if p.Location == ParameterLocationRegister {
			switch p.Register {
			case "rdi", "rsi":
				intCount++
			case "xmm0":
				floatCount++
			}
		}
	}
	if intCount < 2 {
		t.Errorf("expected at least 2 integer params, got %d", intCount)
	}
	if floatCount < 1 {
		t.Errorf("expected at least 1 float param, got %d", floatCount)
	}
}

func TestSystemV_IdentifyParameters_SubRegisterRead(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "test", reg("edi", disasm.Size32), reg("edi", disasm.Size32)),
		buildInsn(0x1002, "ret"),
	}

	a := NewSystemVAnalyzer()
	params := a.IdentifyParameters(insns)

	found := false
	for _, p := range params {
		if p.Register == "rdi" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected rdi parameter from edi read (sub-register canonicalization)")
	}
}

func TestSystemV_IdentifyReturnValues_SubRegisterWidth(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "xor", reg("eax", disasm.Size32), reg("eax", disasm.Size32)),
		buildInsn(0x1002, "ret"),
	}

	a := NewSystemVAnalyzer()
	retVals := a.IdentifyReturnValues(insns)

	if len(retVals) != 1 {
		t.Fatalf("expected 1 return value, got %d", len(retVals))
	}
	intType, ok := retVals[0].Type.(ir.IntType)
	if !ok {
		t.Fatalf("expected IntType, got %T", retVals[0].Type)
	}
	if intType.Width != ir.Size4 {
		t.Errorf("expected 32-bit return (eax), got width %d", intType.Width)
	}
}

func TestSystemV_VerifyCalleeSaved_PartialSave(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbx", disasm.Size64)),
		buildInsn(0x1001, "add", reg("r12", disasm.Size64), imm(1, disasm.Size64)),
		buildInsn(0x1005, "pop", reg("rbx", disasm.Size64)),
		buildInsn(0x1006, "ret"),
	}

	a := NewSystemVAnalyzer()
	statuses := a.VerifyCalleeSavedRegisters(insns)

	for _, s := range statuses {
		switch s.Register {
		case "rbx":
			if !s.Preserved {
				t.Error("rbx should be preserved (push/pop pair)")
			}
		case "r12":
			if s.Preserved {
				t.Error("r12 should NOT be preserved (modified without save)")
			}
		}
	}
}

func TestSystemV_Analyze_FullPipeline(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), imm(0x30, disasm.Size64)),
		buildInsn(0x1008, "mov", mem("rbp", -8, disasm.Size64), reg("rdi", disasm.Size64)),
		buildInsn(0x100c, "mov", mem("rbp", -16, disasm.Size64), reg("rsi", disasm.Size64)),
		buildInsn(0x1010, "mov", reg("rax", disasm.Size64), mem("rbp", -8, disasm.Size64)),
		buildInsn(0x1014, "add", reg("rax", disasm.Size64), mem("rbp", -16, disasm.Size64)),
		buildInsn(0x1018, "add", reg("rsp", disasm.Size64), imm(0x30, disasm.Size64)),
		buildInsn(0x101c, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x101d, "ret"),
	}

	a := NewSystemVAnalyzer()
	result := a.Analyze(insns)

	if result.Convention != CallingConventionSystemVAMD64 {
		t.Errorf("convention: expected SystemV, got %v", result.Convention)
	}
	if len(result.Parameters) < 2 {
		t.Errorf("expected at least 2 parameters, got %d", len(result.Parameters))
	}
	if len(result.ReturnValues) < 1 {
		t.Errorf("expected at least 1 return value, got %d", len(result.ReturnValues))
	}
	if result.Frame == nil {
		t.Fatal("expected non-nil stack frame")
	}
	if !result.Frame.HasFramePointer {
		t.Error("expected frame pointer (push rbp; mov rbp, rsp)")
	}
	if !result.IsLeaf {
		t.Error("expected leaf function (no call instructions)")
	}
}

// ---------------------------------------------------------------------------
// Microsoft x64 calling convention tests
// ---------------------------------------------------------------------------

func TestMsX64_IdentifyParameters_MixedIntAndFloat(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", mem("rsp", 8, disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x1005, "movsd", mem("rsp", 16, disasm.Size64), reg("xmm1", disasm.Size64)),
		buildInsn(0x100a, "mov", mem("rsp", 24, disasm.Size64), reg("r8", disasm.Size64)),
		buildInsn(0x100f, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	params := a.IdentifyParameters(insns)

	intCount := 0
	floatCount := 0
	for _, p := range params {
		switch p.Register {
		case "rcx", "r8":
			intCount++
		case "xmm1":
			floatCount++
		}
	}
	if intCount < 2 {
		t.Errorf("expected at least 2 integer params, got %d", intCount)
	}
	if floatCount < 1 {
		t.Errorf("expected at least 1 float param, got %d", floatCount)
	}
}

func TestMsX64_IdentifyReturnValues_BothIntAndFloat(t *testing.T) {
	insnsInt := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(42, disasm.Size64)),
		buildInsn(0x1007, "ret"),
	}
	insnsFloat := []*disasm.Instruction{
		buildInsn(0x1000, "movsd", reg("xmm0", disasm.Size64), mem("rbp", -8, disasm.Size64)),
		buildInsn(0x1005, "ret"),
	}

	a := NewMicrosoftX64Analyzer()

	retInt := a.IdentifyReturnValues(insnsInt)
	if len(retInt) != 1 || retInt[0].Register != "rax" {
		t.Errorf("expected rax return, got %v", retInt)
	}

	retFloat := a.IdentifyReturnValues(insnsFloat)
	if len(retFloat) != 1 || retFloat[0].Register != "xmm0" {
		t.Errorf("expected xmm0 return, got %v", retFloat)
	}
}

func TestMsX64_VerifyCalleeSaved_RdiRsiPreserved(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rdi", disasm.Size64)),
		buildInsn(0x1001, "push", reg("rsi", disasm.Size64)),
		buildInsn(0x1002, "mov", reg("rdi", disasm.Size64), imm(0, disasm.Size64)),
		buildInsn(0x1009, "pop", reg("rsi", disasm.Size64)),
		buildInsn(0x100a, "pop", reg("rdi", disasm.Size64)),
		buildInsn(0x100b, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	statuses := a.VerifyCalleeSavedRegisters(insns)

	for _, s := range statuses {
		if s.Register == "rdi" && !s.Preserved {
			t.Error("rdi should be preserved (push/pop pair) in Microsoft x64")
		}
		if s.Register == "rsi" && !s.Preserved {
			t.Error("rsi should be preserved (push/pop pair) in Microsoft x64")
		}
	}
}

func TestMsX64_Analyze_FullPipeline(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbx", disasm.Size64)),
		buildInsn(0x1001, "sub", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		buildInsn(0x1005, "mov", mem("rsp", 8, disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x100a, "mov", reg("rax", disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x100d, "add", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		buildInsn(0x1011, "pop", reg("rbx", disasm.Size64)),
		buildInsn(0x1012, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	result := a.Analyze(insns)

	if result.Convention != CallingConventionMicrosoftX64 {
		t.Errorf("convention: expected Microsoft x64, got %v", result.Convention)
	}
	if len(result.ReturnValues) < 1 {
		t.Errorf("expected at least 1 return value, got %d", len(result.ReturnValues))
	}
	if result.Frame == nil {
		t.Fatal("expected non-nil stack frame")
	}
}

// ---------------------------------------------------------------------------
// Symbolic stack tracking tests
// ---------------------------------------------------------------------------

func TestStackTracker_SystemV_NestedPushPopWithSubAlloc(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "push", reg("rbx", disasm.Size64)),
		buildInsn(0x1005, "push", reg("r12", disasm.Size64)),
		buildInsn(0x1007, "sub", reg("rsp", disasm.Size64), imm(0x40, disasm.Size64)),
		buildInsn(0x100b, "nop"),
		buildInsn(0x100c, "add", reg("rsp", disasm.Size64), imm(0x40, disasm.Size64)),
		buildInsn(0x1010, "pop", reg("r12", disasm.Size64)),
		buildInsn(0x1012, "pop", reg("rbx", disasm.Size64)),
		buildInsn(0x1013, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1014, "ret"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	expected := map[disasm.Address]int64{
		0x1000: 0,
		0x1001: -8,
		0x1004: -8,
		0x1005: -16,
		0x1007: -24,
		0x100b: -88,
		0x100c: -88,
		0x1010: -24,
		0x1012: -16,
		0x1013: -8,
		0x1014: 0,
	}

	for addr, want := range expected {
		off, ok := tracker.GetOffset(addr)
		if !ok {
			t.Errorf("no offset at 0x%x", addr)
			continue
		}
		c, isConcrete := off.(ConcreteOffset)
		if !isConcrete {
			t.Errorf("offset at 0x%x: expected ConcreteOffset, got %T", addr, off)
			continue
		}
		if c.Value != want {
			t.Errorf("offset at 0x%x: expected %d, got %d", addr, want, c.Value)
		}
	}

	if !tracker.HasFramePointer() {
		t.Error("expected frame pointer to be detected")
	}
}

func TestStackTracker_MsX64_ShadowSpaceAllocation(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x28, disasm.Size64)),
		buildInsn(0x1004, "mov", mem("rsp", 0x20, disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x1009, "call", imm(0x2000, disasm.Size64)),
		buildInsn(0x100e, "add", reg("rsp", disasm.Size64), imm(0x28, disasm.Size64)),
		buildInsn(0x1012, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	tracker := a.TrackStackPointer(insns)

	off0, _ := tracker.GetOffset(0x1000)
	if c, ok := off0.(ConcreteOffset); !ok || c.Value != 0 {
		t.Errorf("entry offset: expected 0, got %v", off0)
	}

	off1, _ := tracker.GetOffset(0x1004)
	if c, ok := off1.(ConcreteOffset); !ok || c.Value != -0x28 {
		t.Errorf("after sub: expected -0x28, got %v", off1)
	}

	offEnd, _ := tracker.GetOffset(0x1012)
	if c, ok := offEnd.(ConcreteOffset); !ok || c.Value != 0 {
		t.Errorf("after add (epilogue): expected 0, got %v", offEnd)
	}
}

func TestStackTracker_SystemV_DynamicAllocaThenAlignment(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), reg("rdi", disasm.Size64)),
		buildInsn(0x1007, "and", reg("rsp", disasm.Size64), imm(-16, disasm.Size64)),
		buildInsn(0x100b, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	off, ok := tracker.GetOffset(0x100b)
	if !ok {
		t.Fatal("no offset at 0x100b")
	}
	sym, isSym := off.(SymbolicOffset)
	if !isSym {
		t.Fatalf("expected SymbolicOffset, got %T", off)
	}
	if sym.VarName != "rdi" {
		t.Errorf("var name: expected 'rdi', got '%s'", sym.VarName)
	}
	if sym.Base != -16 {
		t.Errorf("aligned base: expected -16, got %d", sym.Base)
	}
}

func TestStackTracker_DetectFramePointerSetup_SymbolicOffset(t *testing.T) {
	tracker := NewSymbolicStackTracker()
	insn := buildInsn(0x1000, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64))
	symOffset := SymbolicOffset{Base: -8, VarName: "rax"}
	detectFramePointerSetup(insn, symOffset, tracker)
	if tracker.HasFramePointer() {
		t.Error("frame pointer should NOT be set when current offset is symbolic")
	}
}

func TestStackTracker_DetectFramePointerSetup_NonRbpDest(t *testing.T) {
	tracker := NewSymbolicStackTracker()
	insn := buildInsn(0x1000, "mov", reg("r12", disasm.Size64), reg("rsp", disasm.Size64))
	detectFramePointerSetup(insn, ConcreteOffset{Value: -8}, tracker)
	if tracker.HasFramePointer() {
		t.Error("frame pointer should NOT be set for mov r12, rsp")
	}
}

func TestStackTracker_DetectFramePointerSetup_SingleOperand(t *testing.T) {
	tracker := NewSymbolicStackTracker()
	insn := buildInsn(0x1000, "mov", reg("rbp", disasm.Size64))
	detectFramePointerSetup(insn, ConcreteOffset{Value: 0}, tracker)
	if tracker.HasFramePointer() {
		t.Error("frame pointer should NOT be set for single-operand mov")
	}
}

// ---------------------------------------------------------------------------
// Stack frame layout recovery tests
// ---------------------------------------------------------------------------

func TestStackFrame_SystemV_MultipleLocalsAndSpills(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "push", reg("rbx", disasm.Size64)),
		buildInsn(0x1005, "sub", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		buildInsn(0x1009, "mov", mem("rbp", -24, disasm.Size64), imm(1, disasm.Size64)),
		buildInsn(0x1011, "mov", mem("rbp", -32, disasm.Size32), imm(2, disasm.Size32)),
		buildInsn(0x1019, "add", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		buildInsn(0x101d, "pop", reg("rbx", disasm.Size64)),
		buildInsn(0x101e, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x101f, "ret"),
	}

	a := NewSystemVAnalyzer()
	frame := a.AnalyzeStackFrame(insns)

	if !frame.HasFramePointer {
		t.Error("expected frame pointer")
	}
	if frame.Size < 0x28 {
		t.Errorf("frame size: expected >= 0x28, got %d", frame.Size)
	}
	totalItems := len(frame.LocalVariables) + len(frame.SpillSlots)
	if totalItems < 2 {
		t.Errorf("expected at least 2 stack items (locals + spills), got %d", totalItems)
	}
}

func TestStackFrame_MsX64_WithShadowSpace(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x38, disasm.Size64)),
		buildInsn(0x1004, "mov", mem("rsp", 0x20, disasm.Size64), imm(0, disasm.Size64)),
		buildInsn(0x100c, "mov", mem("rsp", 0x28, disasm.Size64), imm(0, disasm.Size64)),
		buildInsn(0x1014, "add", reg("rsp", disasm.Size64), imm(0x38, disasm.Size64)),
		buildInsn(0x1018, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	frame := a.AnalyzeStackFrame(insns)

	if frame.Size < 0x38 {
		t.Errorf("frame size: expected >= 0x38, got %d", frame.Size)
	}
}

func TestStackFrame_SystemV_RSPBasedNoFramePointer(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x18, disasm.Size64)),
		buildInsn(0x1004, "mov", mem("rsp", 0, disasm.Size64), imm(10, disasm.Size64)),
		buildInsn(0x100c, "mov", mem("rsp", 8, disasm.Size32), imm(20, disasm.Size32)),
		buildInsn(0x1014, "mov", reg("rax", disasm.Size64), mem("rsp", 0, disasm.Size64)),
		buildInsn(0x1018, "add", reg("rsp", disasm.Size64), imm(0x18, disasm.Size64)),
		buildInsn(0x101c, "ret"),
	}

	a := NewSystemVAnalyzer()
	frame := a.AnalyzeStackFrame(insns)

	if frame.HasFramePointer {
		t.Error("expected no frame pointer for RSP-based frame")
	}
	if frame.Size != 0x18 {
		t.Errorf("frame size: expected 0x18, got %d", frame.Size)
	}
	if len(frame.LocalVariables) < 2 {
		t.Errorf("expected at least 2 local variables, got %d", len(frame.LocalVariables))
	}
}

func TestStackFrame_SystemV_EmptyFunctionNoFrame(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "xor", reg("eax", disasm.Size32), reg("eax", disasm.Size32)),
		buildInsn(0x1002, "ret"),
	}

	a := NewSystemVAnalyzer()
	frame := a.AnalyzeStackFrame(insns)

	if frame.HasFramePointer {
		t.Error("expected no frame pointer for trivial function")
	}
	if frame.Size != 0 {
		t.Errorf("frame size: expected 0, got %d", frame.Size)
	}
}

// ---------------------------------------------------------------------------
// Coverage gap tests: isVarargsSaveInstruction (70.6%)
// ---------------------------------------------------------------------------

func TestIsVarargsSaveInstruction_ValidMovaps(t *testing.T) {
	insn := buildInsn(0x1000, "movaps",
		mem("rsp", 48, disasm.Size64),
		reg("xmm0", disasm.Size64),
	)
	if !isVarargsSaveInstruction(insn) {
		t.Error("movaps [rsp+48], xmm0 should be a varargs save instruction")
	}
}

func TestIsVarargsSaveInstruction_ValidMovdqa(t *testing.T) {
	insn := buildInsn(0x1000, "movdqa",
		mem("rsp", 64, disasm.Size64),
		reg("xmm1", disasm.Size64),
	)
	if !isVarargsSaveInstruction(insn) {
		t.Error("movdqa [rsp+64], xmm1 should be a varargs save instruction")
	}
}

func TestIsVarargsSaveInstruction_ValidVmovaps(t *testing.T) {
	insn := buildInsn(0x1000, "vmovaps",
		mem("rsp", 80, disasm.Size64),
		reg("xmm2", disasm.Size64),
	)
	if !isVarargsSaveInstruction(insn) {
		t.Error("vmovaps [rsp+80], xmm2 should be a varargs save instruction")
	}
}

func TestIsVarargsSaveInstruction_ValidMovups(t *testing.T) {
	insn := buildInsn(0x1000, "movups",
		mem("rsp", 96, disasm.Size64),
		reg("xmm3", disasm.Size64),
	)
	if !isVarargsSaveInstruction(insn) {
		t.Error("movups [rsp+96], xmm3 should be a varargs save instruction")
	}
}

func TestIsVarargsSaveInstruction_ValidMovdqu(t *testing.T) {
	insn := buildInsn(0x1000, "movdqu",
		mem("rsp", 112, disasm.Size64),
		reg("xmm7", disasm.Size64),
	)
	if !isVarargsSaveInstruction(insn) {
		t.Error("movdqu [rsp+112], xmm7 should be a varargs save instruction")
	}
}

func TestIsVarargsSaveInstruction_DispTooLow(t *testing.T) {
	insn := buildInsn(0x1000, "movaps",
		mem("rsp", 32, disasm.Size64),
		reg("xmm0", disasm.Size64),
	)
	if isVarargsSaveInstruction(insn) {
		t.Error("movaps [rsp+32], xmm0 should NOT be varargs save (disp < 48)")
	}
}

func TestIsVarargsSaveInstruction_NonRspBase(t *testing.T) {
	insn := buildInsn(0x1000, "movaps",
		mem("rbp", 48, disasm.Size64),
		reg("xmm0", disasm.Size64),
	)
	if isVarargsSaveInstruction(insn) {
		t.Error("movaps [rbp+48], xmm0 should NOT be varargs save (base != rsp)")
	}
}

func TestIsVarargsSaveInstruction_NonXmmSource(t *testing.T) {
	insn := buildInsn(0x1000, "movaps",
		mem("rsp", 48, disasm.Size64),
		reg("rax", disasm.Size64),
	)
	if isVarargsSaveInstruction(insn) {
		t.Error("movaps [rsp+48], rax should NOT be varargs save (source not xmm)")
	}
}

func TestIsVarargsSaveInstruction_DestNotMemory(t *testing.T) {
	insn := buildInsn(0x1000, "movaps",
		reg("xmm0", disasm.Size64),
		reg("xmm1", disasm.Size64),
	)
	if isVarargsSaveInstruction(insn) {
		t.Error("movaps xmm0, xmm1 should NOT be varargs save (dest not memory)")
	}
}

func TestIsVarargsSaveInstruction_WrongOperandCount(t *testing.T) {
	insn := &disasm.Instruction{
		Address:  0x1000,
		Mnemonic: "movaps",
		Operands: []disasm.Operand{
			mem("rsp", 48, disasm.Size64),
		},
		Length: 4,
	}
	if isVarargsSaveInstruction(insn) {
		t.Error("single-operand movaps should NOT be varargs save")
	}
}

func TestIsVarargsSaveInstruction_SourceNotRegister(t *testing.T) {
	insn := buildInsn(0x1000, "movaps",
		mem("rsp", 48, disasm.Size64),
		imm(0, disasm.Size64),
	)
	if isVarargsSaveInstruction(insn) {
		t.Error("movaps [rsp+48], 0 should NOT be varargs save (source not register)")
	}
}

// ---------------------------------------------------------------------------
// Coverage gap tests: RegisterWidthFromName (42.9%)
// ---------------------------------------------------------------------------

func TestRegisterWidthFromName_AllCategories(t *testing.T) {
	tests := []struct {
		name string
		want ir.Size
	}{
		{"al", ir.Size1}, {"ah", ir.Size1}, {"bl", ir.Size1}, {"bh", ir.Size1},
		{"cl", ir.Size1}, {"ch", ir.Size1}, {"dl", ir.Size1}, {"dh", ir.Size1},
		{"sil", ir.Size1}, {"dil", ir.Size1}, {"bpl", ir.Size1}, {"spl", ir.Size1},
		{"r8b", ir.Size1}, {"r9b", ir.Size1}, {"r10b", ir.Size1}, {"r11b", ir.Size1},
		{"r12b", ir.Size1}, {"r13b", ir.Size1}, {"r14b", ir.Size1}, {"r15b", ir.Size1},

		{"ax", ir.Size2}, {"bx", ir.Size2}, {"cx", ir.Size2}, {"dx", ir.Size2},
		{"si", ir.Size2}, {"di", ir.Size2}, {"bp", ir.Size2}, {"sp", ir.Size2},
		{"r8w", ir.Size2}, {"r9w", ir.Size2}, {"r10w", ir.Size2}, {"r11w", ir.Size2},
		{"r12w", ir.Size2}, {"r13w", ir.Size2}, {"r14w", ir.Size2}, {"r15w", ir.Size2},

		{"eax", ir.Size4}, {"ebx", ir.Size4}, {"ecx", ir.Size4}, {"edx", ir.Size4},
		{"esi", ir.Size4}, {"edi", ir.Size4}, {"ebp", ir.Size4}, {"esp", ir.Size4},
		{"r8d", ir.Size4}, {"r9d", ir.Size4}, {"r10d", ir.Size4}, {"r11d", ir.Size4},
		{"r12d", ir.Size4}, {"r13d", ir.Size4}, {"r14d", ir.Size4}, {"r15d", ir.Size4},

		{"rax", ir.Size8}, {"rbx", ir.Size8}, {"rcx", ir.Size8}, {"rdx", ir.Size8},
		{"rsi", ir.Size8}, {"rdi", ir.Size8}, {"rbp", ir.Size8}, {"rsp", ir.Size8},
		{"r8", ir.Size8}, {"r9", ir.Size8}, {"r10", ir.Size8}, {"r11", ir.Size8},
		{"r12", ir.Size8}, {"r13", ir.Size8}, {"r14", ir.Size8}, {"r15", ir.Size8},
		{"rip", ir.Size8},

		{"xmm0", ir.Size16}, {"xmm1", ir.Size16}, {"xmm2", ir.Size16}, {"xmm3", ir.Size16},
		{"xmm4", ir.Size16}, {"xmm5", ir.Size16}, {"xmm6", ir.Size16}, {"xmm7", ir.Size16},
		{"xmm8", ir.Size16}, {"xmm9", ir.Size16}, {"xmm10", ir.Size16}, {"xmm11", ir.Size16},
		{"xmm12", ir.Size16}, {"xmm13", ir.Size16}, {"xmm14", ir.Size16}, {"xmm15", ir.Size16},

		{"ymm0", ir.Size8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RegisterWidthFromName(tt.name)
			if got != tt.want {
				t.Errorf("RegisterWidthFromName(%q) = %d, want %d", tt.name, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Coverage gap tests: handleSubInstruction non-register dest (SystemV)
// ---------------------------------------------------------------------------

func TestSystemV_HandleSub_DestNotRegister(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		{
			Address:  0x1004,
			Mnemonic: "sub",
			Operands: []disasm.Operand{
				mem("rsp", 0, disasm.Size64),
				imm(8, disasm.Size64),
			},
			Length: 4,
		},
		buildInsn(0x1008, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	off, ok := tracker.GetOffset(0x1008)
	if !ok {
		t.Fatal("no offset at 0x1008")
	}
	c, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Fatalf("expected ConcreteOffset, got %T", off)
	}
	if c.Value != -0x10 {
		t.Errorf("offset: expected -0x10, got %d (sub [mem], imm should not affect RSP tracking)", c.Value)
	}
}

func TestMsX64_HandleSub_DestNotRegister(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		{
			Address:  0x1004,
			Mnemonic: "sub",
			Operands: []disasm.Operand{
				mem("rsp", 0, disasm.Size64),
				imm(8, disasm.Size64),
			},
			Length: 4,
		},
		buildInsn(0x1008, "nop"),
	}

	a := NewMicrosoftX64Analyzer()
	tracker := a.TrackStackPointer(insns)

	off, ok := tracker.GetOffset(0x1008)
	if !ok {
		t.Fatal("no offset at 0x1008")
	}
	c, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Fatalf("expected ConcreteOffset, got %T", off)
	}
	if c.Value != -0x10 {
		t.Errorf("offset: expected -0x10, got %d", c.Value)
	}
}

// ---------------------------------------------------------------------------
// Coverage gap tests: handleAndInstruction non-register dest
// ---------------------------------------------------------------------------

func TestSystemV_HandleAnd_DestNotRegister(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		{
			Address:  0x1004,
			Mnemonic: "and",
			Operands: []disasm.Operand{
				mem("rsp", 0, disasm.Size64),
				imm(-16, disasm.Size64),
			},
			Length: 4,
		},
		buildInsn(0x1008, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	off, ok := tracker.GetOffset(0x1008)
	if !ok {
		t.Fatal("no offset at 0x1008")
	}
	c, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Fatalf("expected ConcreteOffset, got %T", off)
	}
	if c.Value != -0x20 {
		t.Errorf("offset: expected -0x20, got %d (and [mem], imm should not affect RSP tracking)", c.Value)
	}
}

func TestMsX64_HandleAnd_DestNotRegister(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		{
			Address:  0x1004,
			Mnemonic: "and",
			Operands: []disasm.Operand{
				mem("rsp", 0, disasm.Size64),
				imm(-16, disasm.Size64),
			},
			Length: 4,
		},
		buildInsn(0x1008, "nop"),
	}

	a := NewMicrosoftX64Analyzer()
	tracker := a.TrackStackPointer(insns)

	off, ok := tracker.GetOffset(0x1008)
	if !ok {
		t.Fatal("no offset at 0x1008")
	}
	c, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Fatalf("expected ConcreteOffset, got %T", off)
	}
	if c.Value != -0x20 {
		t.Errorf("offset: expected -0x20, got %d", c.Value)
	}
}

// ---------------------------------------------------------------------------
// Coverage gap tests: handleAddInstruction non-register dest
// ---------------------------------------------------------------------------

func TestSystemV_HandleAdd_DestNotRegister(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		{
			Address:  0x1004,
			Mnemonic: "add",
			Operands: []disasm.Operand{
				mem("rsp", 0, disasm.Size64),
				imm(8, disasm.Size64),
			},
			Length: 4,
		},
		buildInsn(0x1008, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	off, ok := tracker.GetOffset(0x1008)
	if !ok {
		t.Fatal("no offset at 0x1008")
	}
	c, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Fatalf("expected ConcreteOffset, got %T", off)
	}
	if c.Value != -0x20 {
		t.Errorf("offset: expected -0x20, got %d", c.Value)
	}
}

func TestMsX64_HandleAdd_DestNotRegister(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		{
			Address:  0x1004,
			Mnemonic: "add",
			Operands: []disasm.Operand{
				mem("rsp", 0, disasm.Size64),
				imm(8, disasm.Size64),
			},
			Length: 4,
		},
		buildInsn(0x1008, "nop"),
	}

	a := NewMicrosoftX64Analyzer()
	tracker := a.TrackStackPointer(insns)

	off, ok := tracker.GetOffset(0x1008)
	if !ok {
		t.Fatal("no offset at 0x1008")
	}
	c, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Fatalf("expected ConcreteOffset, got %T", off)
	}
	if c.Value != -0x20 {
		t.Errorf("offset: expected -0x20, got %d", c.Value)
	}
}

// ---------------------------------------------------------------------------
// Coverage gap tests: TrackStackPointer pop with non-register operand
// ---------------------------------------------------------------------------

func TestSystemV_TrackStackPointer_PopMemoryOperand(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbx", disasm.Size64)),
		{
			Address:  0x1001,
			Mnemonic: "pop",
			Operands: []disasm.Operand{
				mem("rsp", 0, disasm.Size64),
			},
			Length: 2,
		},
		buildInsn(0x1003, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	off, ok := tracker.GetOffset(0x1003)
	if !ok {
		t.Fatal("no offset at 0x1003")
	}
	c, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Fatalf("expected ConcreteOffset, got %T", off)
	}
	if c.Value != 0 {
		t.Errorf("offset after pop [mem]: expected 0, got %d", c.Value)
	}
}

func TestSystemV_TrackStackPointer_PushImmediateOperand(t *testing.T) {
	insns := []*disasm.Instruction{
		{
			Address:  0x1000,
			Mnemonic: "push",
			Operands: []disasm.Operand{
				imm(42, disasm.Size64),
			},
			Length: 5,
		},
		buildInsn(0x1005, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	off, ok := tracker.GetOffset(0x1005)
	if !ok {
		t.Fatal("no offset at 0x1005")
	}
	c, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Fatalf("expected ConcreteOffset, got %T", off)
	}
	if c.Value != -8 {
		t.Errorf("offset after push imm: expected -8, got %d", c.Value)
	}
}

// ---------------------------------------------------------------------------
// Coverage gap tests: MicrosoftX64 handleSubInstruction fallback branch
// ---------------------------------------------------------------------------

func TestMsX64_HandleSub_MemorySecondOperand(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), mem("rbp", -8, disasm.Size64)),
		buildInsn(0x1008, "nop"),
	}

	a := NewMicrosoftX64Analyzer()
	tracker := a.TrackStackPointer(insns)

	off, ok := tracker.GetOffset(0x1008)
	if !ok {
		t.Fatal("no offset at 0x1008")
	}
	c, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Fatalf("expected ConcreteOffset, got %T", off)
	}
	if c.Value != -0x10 {
		t.Errorf("offset: expected -0x10, got %d (sub rsp, [mem] should not change offset)", c.Value)
	}
}

func TestSystemV_HandleSub_MemorySecondOperand(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), mem("rbp", -8, disasm.Size64)),
		buildInsn(0x1008, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	off, ok := tracker.GetOffset(0x1008)
	if !ok {
		t.Fatal("no offset at 0x1008")
	}
	c, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Fatalf("expected ConcreteOffset, got %T", off)
	}
	if c.Value != -0x10 {
		t.Errorf("offset: expected -0x10, got %d", c.Value)
	}
}

// ---------------------------------------------------------------------------
// Coverage gap tests: NewAnalyzer factory with CallingConventionCustom
// ---------------------------------------------------------------------------

func TestNewAnalyzer_CustomConvention(t *testing.T) {
	_, err := NewAnalyzer(CallingConventionCustom)
	if err == nil {
		t.Error("expected error for CallingConventionCustom")
	}
	var uce *UnsupportedConventionError
	if !errors.As(err, &uce) {
		t.Fatalf("expected *UnsupportedConventionError, got %T", err)
	}
	if uce.Convention != CallingConventionCustom {
		t.Errorf("error convention: expected Custom, got %v", uce.Convention)
	}
}

func TestNewAnalyzer_InvalidConvention(t *testing.T) {
	_, err := NewAnalyzer(CallingConvention(99))
	if err == nil {
		t.Error("expected error for invalid convention value")
	}
}

// ---------------------------------------------------------------------------
// Coverage gap tests: IdentifyReturnValues with zero-operand instruction
// ---------------------------------------------------------------------------

func TestSystemV_IdentifyReturnValues_ZeroOperandBeforeRet(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(1, disasm.Size64)),
		{Address: 0x1007, Mnemonic: "nop", Operands: nil, Length: 1},
		buildInsn(0x1008, "ret"),
	}

	a := NewSystemVAnalyzer()
	retVals := a.IdentifyReturnValues(insns)

	if len(retVals) != 1 {
		t.Fatalf("expected 1 return value, got %d", len(retVals))
	}
	if retVals[0].Register != "rax" {
		t.Errorf("expected rax return, got %s", retVals[0].Register)
	}
}

func TestMsX64_IdentifyReturnValues_ZeroOperandBeforeRet(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(1, disasm.Size64)),
		{Address: 0x1007, Mnemonic: "nop", Operands: nil, Length: 1},
		buildInsn(0x1008, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	retVals := a.IdentifyReturnValues(insns)

	if len(retVals) != 1 {
		t.Fatalf("expected 1 return value, got %d", len(retVals))
	}
	if retVals[0].Register != "rax" {
		t.Errorf("expected rax return, got %s", retVals[0].Register)
	}
}

// ---------------------------------------------------------------------------
// Coverage gap tests: push/pop with Size=0 (default to 8)
// ---------------------------------------------------------------------------

func TestSystemV_TrackStackPointer_PushPopZeroSize(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", disasm.RegisterOperand{Name: "rbx", Size: 0}),
		buildInsn(0x1001, "pop", disasm.RegisterOperand{Name: "rbx", Size: 0}),
		buildInsn(0x1002, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	off1, _ := tracker.GetOffset(0x1001)
	if c, ok := off1.(ConcreteOffset); !ok || c.Value != -8 {
		t.Errorf("after push with Size=0: expected -8, got %v", off1)
	}

	off2, _ := tracker.GetOffset(0x1002)
	if c, ok := off2.(ConcreteOffset); !ok || c.Value != 0 {
		t.Errorf("after pop with Size=0: expected 0, got %v", off2)
	}
}
