package abi

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestSystemVAnalyzer_TrackStackPointer_PushPopSequence tests push/pop balance.
func TestSystemVAnalyzer_TrackStackPointer_PushPopSequence(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbx", disasm.Size64)),
		buildInsn(0x1001, "push", reg("r12", disasm.Size64)),
		buildInsn(0x1003, "pop", reg("r12", disasm.Size64)),
		buildInsn(0x1005, "pop", reg("rbx", disasm.Size64)),
		buildInsn(0x1006, "ret"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	// at entry: 0
	off0, _ := tracker.GetOffset(0x1000)
	if c, ok := off0.(ConcreteOffset); !ok || c.Value != 0 {
		t.Errorf("offset at 0x1000: expected 0, got %v", off0)
	}
	// after push rbx: -8
	off1, _ := tracker.GetOffset(0x1001)
	if c, ok := off1.(ConcreteOffset); !ok || c.Value != -8 {
		t.Errorf("offset at 0x1001: expected -8, got %v", off1)
	}
	// after push r12: -16
	off2, _ := tracker.GetOffset(0x1003)
	if c, ok := off2.(ConcreteOffset); !ok || c.Value != -16 {
		t.Errorf("offset at 0x1003: expected -16, got %v", off2)
	}
	// after pop r12: -8
	off3, _ := tracker.GetOffset(0x1005)
	if c, ok := off3.(ConcreteOffset); !ok || c.Value != -8 {
		t.Errorf("offset at 0x1005: expected -8, got %v", off3)
	}
	// after pop rbx: 0
	off4, _ := tracker.GetOffset(0x1006)
	if c, ok := off4.(ConcreteOffset); !ok || c.Value != 0 {
		t.Errorf("offset at 0x1006: expected 0, got %v", off4)
	}
}

// TestSystemVAnalyzer_TrackStackPointer_AlignmentOnSymbolic tests and rsp, -16
// applied to a symbolic offset — exercises the SymbolicOffset branch in handleAndInstruction.
//
//nolint:dupl // intentionally tests system v analyzer with similar pattern
func TestSystemVAnalyzer_TrackStackPointer_AlignmentOnSymbolic(t *testing.T) {
	// sub rsp, rax (symbolic), then and rsp, -16 (alignment on symbolic base)
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(8, disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), reg("rax", disasm.Size64)),
		buildInsn(0x1007, "and", reg("rsp", disasm.Size64), imm(-16, disasm.Size64)),
		buildInsn(0x100b, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	// after sub rsp,8 then sub rsp,rax: SymbolicOffset{Base:-8, VarName:"rax"}
	// after and rsp,-16: base = -8 & -16 = -16, varname preserved
	off, ok := tracker.GetOffset(0x100b)
	if !ok {
		t.Fatal("no offset at 0x100b")
	}
	sym, isSym := off.(SymbolicOffset)
	if !isSym {
		t.Fatalf("expected SymbolicOffset after alignment of symbolic, got %T", off)
	}
	if sym.Base != -16 {
		t.Errorf("aligned symbolic base: expected -16, got %d", sym.Base)
	}
	if sym.VarName != "rax" {
		t.Errorf("var name: expected 'rax', got '%s'", sym.VarName)
	}
}

// TestSystemVAnalyzer_TrackStackPointer_AddRSPNonImmediate tests add rsp, reg
// (non-immediate operand) — the add handler must return current unchanged.
func TestSystemVAnalyzer_TrackStackPointer_AddRSPNonImmediate(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		// add rsp, rbx — non-immediate, offset must remain unchanged
		buildInsn(0x1004, "add", reg("rsp", disasm.Size64), reg("rbx", disasm.Size64)),
		buildInsn(0x1007, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	// offset at 0x1004 is -0x20 (before add executes)
	// after add rsp, rbx (non-immediate): offset stays at -0x20
	off, ok := tracker.GetOffset(0x1007)
	if !ok {
		t.Fatal("no offset at 0x1007")
	}
	c, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Fatalf("expected ConcreteOffset, got %T", off)
	}
	if c.Value != -0x20 {
		t.Errorf("offset after add rsp,reg: expected -0x20, got %d", c.Value)
	}
}

// TestSystemVAnalyzer_TrackStackPointer_SubNonRSP tests sub on non-RSP register
// — must not affect the tracked RSP offset.
func TestSystemVAnalyzer_TrackStackPointer_SubNonRSP(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		// sub rax, 8 — does not affect rsp
		buildInsn(0x1004, "sub", reg("rax", disasm.Size64), imm(8, disasm.Size64)),
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
		t.Errorf("offset after sub rax,8: expected -0x10, got %d", c.Value)
	}
}

// TestSystemVAnalyzer_TrackStackPointer_AndNonRSP tests and on non-RSP register
// — must not affect the tracked RSP offset.
func TestSystemVAnalyzer_TrackStackPointer_AndNonRSP(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		// and rax, -16 — does not affect rsp
		buildInsn(0x1004, "and", reg("rax", disasm.Size64), imm(-16, disasm.Size64)),
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
		t.Errorf("offset after and rax,-16: expected -0x10, got %d", c.Value)
	}
}

// TestSystemVAnalyzer_TrackStackPointer_AndNonImmediate tests and rsp, reg
// (non-immediate) — must not affect the tracked RSP offset.
func TestSystemVAnalyzer_TrackStackPointer_AndNonImmediate(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		// and rsp, rbx — non-immediate, offset must remain unchanged
		buildInsn(0x1004, "and", reg("rsp", disasm.Size64), reg("rbx", disasm.Size64)),
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
		t.Errorf("offset after and rsp,reg: expected -0x10, got %d", c.Value)
	}
}

// TestSystemVAnalyzer_TrackStackPointer_PushWithExplicitSize tests push with
// non-default operand size (exercises the size branch in push handling).
func TestSystemVAnalyzer_TrackStackPointer_PushWithExplicitSize(t *testing.T) {
	// push with Size64 explicitly set — should decrement by 8
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbx", disasm.Size64)),
		buildInsn(0x1001, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	off, ok := tracker.GetOffset(0x1001)
	if !ok {
		t.Fatal("no offset at 0x1001")
	}
	c, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Fatalf("expected ConcreteOffset, got %T", off)
	}
	if c.Value != -8 {
		t.Errorf("offset after push rbx: expected -8, got %d", c.Value)
	}
}

// TestSystemVAnalyzer_TrackStackPointer_SubWrongOperandCount tests sub with
// wrong operand count — must return current offset unchanged.
func TestSystemVAnalyzer_TrackStackPointer_SubWrongOperandCount(t *testing.T) {
	// sub with single operand (malformed) — should not crash or change offset
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		// sub with only one operand — malformed, offset must stay at -0x10
		{Address: 0x1004, Mnemonic: "sub", Operands: []disasm.Operand{reg("rsp", disasm.Size64)}, Length: 2},
		buildInsn(0x1006, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	off, ok := tracker.GetOffset(0x1006)
	if !ok {
		t.Fatal("no offset at 0x1006")
	}
	c, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Fatalf("expected ConcreteOffset, got %T", off)
	}
	if c.Value != -0x10 {
		t.Errorf("offset after malformed sub: expected -0x10, got %d", c.Value)
	}
}

// TestSystemVAnalyzer_TrackStackPointer_GetOffsetMiss tests GetOffset for unknown address.
func TestSystemVAnalyzer_TrackStackPointer_GetOffsetMiss(t *testing.T) {
	tracker := NewSymbolicStackTracker()
	_, ok := tracker.GetOffset(0xDEADBEEF)
	if ok {
		t.Error("expected GetOffset to return false for untracked address")
	}
}

// TestSystemVAnalyzer_TrackStackPointer_NoFramePointerByDefault tests that a fresh
// tracker has no frame pointer set.
func TestSystemVAnalyzer_TrackStackPointer_NoFramePointerByDefault(t *testing.T) {
	tracker := NewSymbolicStackTracker()
	if tracker.HasFramePointer() {
		t.Error("fresh tracker must not have frame pointer")
	}
	_, ok := tracker.FramePointerRSPOffset()
	if ok {
		t.Error("FramePointerRSPOffset must return false when no frame pointer set")
	}
}
