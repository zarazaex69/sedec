package abi

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestSymbolicStackTracker_ConcreteFrameSetup tests standard prologue tracking
func TestSymbolicStackTracker_ConcreteFrameSetup(t *testing.T) {
	// standard prologue: push rbp; mov rbp, rsp; sub rsp, 0x20
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		buildInsn(0x1008, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	// at 0x1000 (push rbp): rsp offset = 0
	off0, ok := tracker.GetOffset(0x1000)
	if !ok {
		t.Fatal("no offset recorded at 0x1000")
	}
	if concrete, ok := off0.(ConcreteOffset); !ok || concrete.Value != 0 {
		t.Errorf("offset at 0x1000: expected 0, got %v", off0)
	}

	// at 0x1001 (mov rbp, rsp): rsp offset = -8 (after push rbp)
	off1, ok := tracker.GetOffset(0x1001)
	if !ok {
		t.Fatal("no offset recorded at 0x1001")
	}
	if concrete, ok := off1.(ConcreteOffset); !ok || concrete.Value != -8 {
		t.Errorf("offset at 0x1001: expected -8, got %v", off1)
	}

	// at 0x1004 (sub rsp, 0x20): rsp offset = -8 (before sub executes)
	off2, ok := tracker.GetOffset(0x1004)
	if !ok {
		t.Fatal("no offset recorded at 0x1004")
	}
	if concrete, ok := off2.(ConcreteOffset); !ok || concrete.Value != -8 {
		t.Errorf("offset at 0x1004: expected -8, got %v", off2)
	}

	// at 0x1008 (nop): rsp offset = -8 - 0x20 = -40
	off3, ok := tracker.GetOffset(0x1008)
	if !ok {
		t.Fatal("no offset recorded at 0x1008")
	}
	if concrete, ok := off3.(ConcreteOffset); !ok || concrete.Value != -40 {
		t.Errorf("offset at 0x1008: expected -40, got %v", off3)
	}
}

// TestSymbolicStackTracker_FramePointerDetection tests RBP frame pointer detection
func TestSymbolicStackTracker_FramePointerDetection(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "ret"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	if !tracker.HasFramePointer() {
		t.Error("expected frame pointer to be detected after 'mov rbp, rsp'")
	}

	fpOffset, ok := tracker.FramePointerRSPOffset()
	if !ok {
		t.Fatal("FramePointerRSPOffset returned false")
	}
	// after push rbp, rsp is at -8; mov rbp, rsp sets frame pointer at rsp=-8
	if fpOffset != -8 {
		t.Errorf("frame pointer RSP offset: expected -8, got %d", fpOffset)
	}
}

// TestSymbolicStackTracker_SymbolicAlloca tests dynamic stack allocation tracking
func TestSymbolicStackTracker_SymbolicAlloca(t *testing.T) {
	// sub rsp, rax — dynamic allocation (alloca)
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), reg("rax", disasm.Size64)),
		buildInsn(0x1007, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	// after sub rsp, rax: offset becomes symbolic
	off, ok := tracker.GetOffset(0x1007)
	if !ok {
		t.Fatal("no offset recorded at 0x1007")
	}
	sym, isSym := off.(SymbolicOffset)
	if !isSym {
		t.Fatalf("expected SymbolicOffset after alloca, got %T", off)
	}
	if sym.VarName != "rax" {
		t.Errorf("symbolic variable: expected 'rax', got '%s'", sym.VarName)
	}
	// base should be -8 (after push rbp)
	if sym.Base != -8 {
		t.Errorf("symbolic base: expected -8, got %d", sym.Base)
	}
}

// TestSymbolicStackTracker_StackAlignment tests and rsp, -16 alignment
func TestSymbolicStackTracker_StackAlignment(t *testing.T) {
	// and rsp, -16 aligns stack to 16-byte boundary
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(8, disasm.Size64)),
		buildInsn(0x1004, "and", reg("rsp", disasm.Size64), imm(-16, disasm.Size64)),
		buildInsn(0x1008, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	// after sub rsp, 8: offset = -8
	// after and rsp, -16: offset = -8 & -16 = -16
	off, ok := tracker.GetOffset(0x1008)
	if !ok {
		t.Fatal("no offset recorded at 0x1008")
	}
	concrete, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Fatalf("expected ConcreteOffset after alignment, got %T", off)
	}
	if concrete.Value != -16 {
		t.Errorf("aligned offset: expected -16, got %d", concrete.Value)
	}
}

// TestSystemVAnalyzer_AnalyzeStackFrame_LocalVariables tests local variable identification
func TestSystemVAnalyzer_AnalyzeStackFrame_LocalVariables(t *testing.T) {
	// function with two local variables accessed via [rbp-8] and [rbp-16]
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		// store to local variable at [rbp-8]
		buildInsn(0x1008, "mov", mem("rbp", -8, disasm.Size64), imm(42, disasm.Size64)),
		// store to local variable at [rbp-16]
		buildInsn(0x100c, "mov", mem("rbp", -16, disasm.Size64), imm(99, disasm.Size64)),
		buildInsn(0x1010, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1011, "ret"),
	}

	a := NewSystemVAnalyzer()
	frame := a.AnalyzeStackFrame(insns)

	if !frame.HasFramePointer {
		t.Error("expected frame to have frame pointer")
	}
	if frame.Size < 0x20 {
		t.Errorf("frame size: expected >= 0x20, got %d", frame.Size)
	}
	if len(frame.LocalVariables) < 2 {
		t.Errorf("expected at least 2 local variables, got %d", len(frame.LocalVariables))
	}
}

// TestSystemVAnalyzer_Analyze_LeafFunction tests leaf function detection
func TestSystemVAnalyzer_Analyze_LeafFunction(t *testing.T) {
	// leaf function: no call instructions
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), reg("rdi", disasm.Size64)),
		buildInsn(0x1003, "add", reg("rax", disasm.Size64), reg("rsi", disasm.Size64)),
		buildInsn(0x1006, "ret"),
	}

	a := NewSystemVAnalyzer()
	abi := a.Analyze(insns)

	if !abi.IsLeaf {
		t.Error("expected function to be identified as leaf (no calls)")
	}
	if abi.Convention != CallingConventionSystemVAMD64 {
		t.Errorf("convention: expected SystemV, got %v", abi.Convention)
	}
}

// TestSystemVAnalyzer_Analyze_NonLeafFunction tests non-leaf function detection
func TestSystemVAnalyzer_Analyze_NonLeafFunction(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "call", imm(0x2000, disasm.Size64)),
		buildInsn(0x1009, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x100a, "ret"),
	}

	a := NewSystemVAnalyzer()
	result := a.Analyze(insns)

	if result.IsLeaf {
		t.Error("expected function to be non-leaf (has call instruction)")
	}
}

// TestNewAnalyzer_SystemV tests factory function for SystemV convention
func TestNewAnalyzer_SystemV(t *testing.T) {
	analyzer, err := NewAnalyzer(CallingConventionSystemVAMD64)
	if err != nil {
		t.Fatalf("NewAnalyzer(SystemV) returned error: %v", err)
	}
	if analyzer == nil {
		t.Fatal("NewAnalyzer returned nil analyzer")
	}
	if analyzer.IdentifyCallingConvention() != CallingConventionSystemVAMD64 {
		t.Errorf("wrong convention from factory-created analyzer")
	}
}

// TestNewAnalyzer_Unsupported tests factory function with unsupported convention
func TestNewAnalyzer_Unsupported(t *testing.T) {
	_, err := NewAnalyzer(CallingConventionUnknown)
	if err == nil {
		t.Error("expected error for unsupported convention, got nil")
	}
}

// TestCanonicalizeRegister tests register name normalization
func TestCanonicalizeRegister(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"rax", "rax"},
		{"eax", "rax"},
		{"ax", "rax"},
		{"al", "rax"},
		{"ah", "rax"},
		{"rdi", "rdi"},
		{"edi", "rdi"},
		{"dil", "rdi"},
		{"r8", "r8"},
		{"r8d", "r8"},
		{"r8w", "r8"},
		{"r8b", "r8"},
		{"r15", "r15"},
		{"r15b", "r15"},
		{"xmm0", "xmm0"},
		{"xmm7", "xmm7"},
		{"rsp", "rsp"},
		{"esp", "rsp"},
		{"rbp", "rbp"},
		{"ebp", "rbp"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := canonicalizeRegister(tt.input)
			if got != tt.want {
				t.Errorf("canonicalizeRegister(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
