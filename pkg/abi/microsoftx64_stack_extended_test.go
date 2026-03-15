package abi

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestMicrosoftX64Analyzer_TrackStackPointer_StackAlignment tests and rsp, -16.
// This exercises handleAndInstruction in microsoftx64.go which was at 0% coverage.
func TestMicrosoftX64Analyzer_TrackStackPointer_StackAlignment(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(8, disasm.Size64)),
		buildInsn(0x1004, "and", reg("rsp", disasm.Size64), imm(-16, disasm.Size64)),
		buildInsn(0x1008, "nop"),
	}

	a := NewMicrosoftX64Analyzer()
	tracker := a.TrackStackPointer(insns)

	// after sub rsp,8: offset = -8
	// after and rsp,-16: -8 & -16 = -16
	off, ok := tracker.GetOffset(0x1008)
	if !ok {
		t.Fatal("no offset at 0x1008")
	}
	c, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Fatalf("expected ConcreteOffset after alignment, got %T", off)
	}
	if c.Value != -16 {
		t.Errorf("aligned offset: expected -16, got %d", c.Value)
	}
}

// TestMicrosoftX64Analyzer_TrackStackPointer_AlignmentOnSymbolic tests and rsp, -16
// applied to a symbolic offset — exercises the SymbolicOffset branch.
//
//nolint:dupl // intentionally tests microsoft x64 analyzer with similar pattern
func TestMicrosoftX64Analyzer_TrackStackPointer_AlignmentOnSymbolic(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(8, disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x1007, "and", reg("rsp", disasm.Size64), imm(-16, disasm.Size64)),
		buildInsn(0x100b, "nop"),
	}

	a := NewMicrosoftX64Analyzer()
	tracker := a.TrackStackPointer(insns)

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
	if sym.VarName != "rcx" {
		t.Errorf("var name: expected 'rcx', got '%s'", sym.VarName)
	}
}

// TestMicrosoftX64Analyzer_TrackStackPointer_AndNonRSP tests and on non-RSP register.
func TestMicrosoftX64Analyzer_TrackStackPointer_AndNonRSP(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		buildInsn(0x1004, "and", reg("rax", disasm.Size64), imm(-16, disasm.Size64)),
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
		t.Errorf("offset after and rax,-16: expected -0x20, got %d", c.Value)
	}
}

// TestMicrosoftX64Analyzer_TrackStackPointer_AndNonImmediate tests and rsp, reg.
func TestMicrosoftX64Analyzer_TrackStackPointer_AndNonImmediate(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		buildInsn(0x1004, "and", reg("rsp", disasm.Size64), reg("rbx", disasm.Size64)),
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
		t.Errorf("offset after and rsp,reg: expected -0x20, got %d", c.Value)
	}
}

// TestMicrosoftX64Analyzer_TrackStackPointer_SubNonRSP tests sub on non-RSP register.
func TestMicrosoftX64Analyzer_TrackStackPointer_SubNonRSP(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rax", disasm.Size64), imm(4, disasm.Size64)),
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
		t.Errorf("offset after sub rax,4: expected -0x10, got %d", c.Value)
	}
}

// TestMicrosoftX64Analyzer_TrackStackPointer_AddNonImmediate tests add rsp, reg.
func TestMicrosoftX64Analyzer_TrackStackPointer_AddNonImmediate(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		buildInsn(0x1004, "add", reg("rsp", disasm.Size64), reg("rbx", disasm.Size64)),
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
	// add rsp, reg (non-immediate) must not change offset
	if c.Value != -0x20 {
		t.Errorf("offset after add rsp,reg: expected -0x20, got %d", c.Value)
	}
}

// TestMicrosoftX64Analyzer_TrackStackPointer_PushPopBalance tests push/pop balance.
func TestMicrosoftX64Analyzer_TrackStackPointer_PushPopBalance(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbx", disasm.Size64)),
		buildInsn(0x1001, "push", reg("rdi", disasm.Size64)),
		buildInsn(0x1002, "pop", reg("rdi", disasm.Size64)),
		buildInsn(0x1003, "pop", reg("rbx", disasm.Size64)),
		buildInsn(0x1004, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	tracker := a.TrackStackPointer(insns)

	// after two pushes: -16
	off2, _ := tracker.GetOffset(0x1002)
	if c, ok := off2.(ConcreteOffset); !ok || c.Value != -16 {
		t.Errorf("offset at 0x1002: expected -16, got %v", off2)
	}
	// after two pops: 0
	off4, _ := tracker.GetOffset(0x1004)
	if c, ok := off4.(ConcreteOffset); !ok || c.Value != 0 {
		t.Errorf("offset at 0x1004: expected 0, got %v", off4)
	}
}
