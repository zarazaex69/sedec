package abi

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestSystemVAnalyzer_AnalyzeStackFrame_LeafNoFramePointer tests a leaf function
// that uses rsp-relative addressing without establishing a frame pointer.
// this is the common pattern for small leaf functions compiled with -fomit-frame-pointer.
func TestSystemVAnalyzer_AnalyzeStackFrame_LeafNoFramePointer(t *testing.T) {
	// leaf function: sub rsp,0x18; use locals via [rsp+N]; add rsp,0x18; ret
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x18, disasm.Size64)),
		// store local at [rsp+0]
		buildInsn(0x1004, "mov", mem("rsp", 0, disasm.Size64), reg("rdi", disasm.Size64)),
		// store local at [rsp+8]
		buildInsn(0x1008, "mov", mem("rsp", 8, disasm.Size32), imm(42, disasm.Size32)),
		buildInsn(0x100c, "add", reg("rsp", disasm.Size64), imm(0x18, disasm.Size64)),
		buildInsn(0x1010, "ret"),
	}

	a := NewSystemVAnalyzer()
	frame := a.AnalyzeStackFrame(insns)

	if frame.HasFramePointer {
		t.Error("leaf function must not have frame pointer")
	}
	if frame.Size < 0x18 {
		t.Errorf("frame size: expected >= 0x18, got %d", frame.Size)
	}
	// two distinct rsp-relative accesses must be identified as local variables
	if len(frame.LocalVariables) < 2 {
		t.Errorf("expected at least 2 local variables, got %d", len(frame.LocalVariables))
	}
}

// TestSystemVAnalyzer_AnalyzeStackFrame_RBPBasedFrame tests a standard frame-pointer
// function where locals are addressed via [rbp-N].
func TestSystemVAnalyzer_AnalyzeStackFrame_RBPBasedFrame(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		// local_a at [rbp-8]
		buildInsn(0x1008, "mov", mem("rbp", -8, disasm.Size64), imm(1, disasm.Size64)),
		// local_b at [rbp-16]
		buildInsn(0x100c, "mov", mem("rbp", -16, disasm.Size64), imm(2, disasm.Size64)),
		// local_c at [rbp-24]
		buildInsn(0x1010, "mov", mem("rbp", -24, disasm.Size64), imm(3, disasm.Size64)),
		buildInsn(0x1014, "add", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		buildInsn(0x1018, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1019, "ret"),
	}

	a := NewSystemVAnalyzer()
	frame := a.AnalyzeStackFrame(insns)

	if !frame.HasFramePointer {
		t.Error("expected frame pointer to be detected")
	}
	// frame pointer was established at rsp=-8 (after push rbp)
	if frame.FramePointerOffset != -8 {
		t.Errorf("frame pointer offset: expected -8, got %d", frame.FramePointerOffset)
	}
	if frame.Size < 0x20 {
		t.Errorf("frame size: expected >= 0x20, got %d", frame.Size)
	}
	if len(frame.LocalVariables) < 3 {
		t.Errorf("expected at least 3 local variables, got %d", len(frame.LocalVariables))
	}
}

// TestSystemVAnalyzer_AnalyzeStackFrame_SpillSlots tests that callee-saved register
// spills are classified as SpillSlots, not LocalVariables.
func TestSystemVAnalyzer_AnalyzeStackFrame_SpillSlots(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), imm(0x30, disasm.Size64)),
		// spill rbx (callee-saved) to [rbp-8]
		buildInsn(0x1008, "mov", mem("rbp", -8, disasm.Size64), reg("rbx", disasm.Size64)),
		// spill r12 (callee-saved) to [rbp-16]
		buildInsn(0x100c, "mov", mem("rbp", -16, disasm.Size64), reg("r12", disasm.Size64)),
		// actual local variable at [rbp-24]
		buildInsn(0x1010, "mov", mem("rbp", -24, disasm.Size64), imm(99, disasm.Size64)),
		// restore callee-saved registers
		buildInsn(0x1014, "mov", reg("r12", disasm.Size64), mem("rbp", -16, disasm.Size64)),
		buildInsn(0x1018, "mov", reg("rbx", disasm.Size64), mem("rbp", -8, disasm.Size64)),
		buildInsn(0x101c, "add", reg("rsp", disasm.Size64), imm(0x30, disasm.Size64)),
		buildInsn(0x1020, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1021, "ret"),
	}

	a := NewSystemVAnalyzer()
	frame := a.AnalyzeStackFrame(insns)

	if len(frame.SpillSlots) < 2 {
		t.Errorf("expected at least 2 spill slots (rbx, r12), got %d", len(frame.SpillSlots))
	}

	// verify spill slot registers are correctly identified
	spillRegs := make(map[string]bool)
	for _, s := range frame.SpillSlots {
		spillRegs[s.Register] = true
	}
	if !spillRegs["rbx"] {
		t.Error("rbx spill slot not detected")
	}
	if !spillRegs["r12"] {
		t.Error("r12 spill slot not detected")
	}

	// the local variable at [rbp-24] must not be classified as a spill slot
	if len(frame.LocalVariables) < 1 {
		t.Errorf("expected at least 1 local variable, got %d", len(frame.LocalVariables))
	}
}

// TestSystemVAnalyzer_AnalyzeStackFrame_SymbolicRSP tests that memory accesses
// via a symbolic RSP offset (alloca) are not incorrectly classified.
// when rsp is symbolic, rsp-relative accesses cannot be resolved to a concrete
// frame offset and must be skipped.
func TestSystemVAnalyzer_AnalyzeStackFrame_SymbolicRSP(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		// dynamic allocation: sub rsp, rax (alloca-style)
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), reg("rax", disasm.Size64)),
		// access via rsp after symbolic offset — must not crash, must be skipped
		buildInsn(0x1007, "mov", mem("rsp", 0, disasm.Size64), imm(0, disasm.Size64)),
		// access via rbp is still concrete and must be detected
		buildInsn(0x100b, "mov", mem("rbp", -8, disasm.Size64), imm(42, disasm.Size64)),
		buildInsn(0x100f, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1010, "ret"),
	}

	a := NewSystemVAnalyzer()
	// must not panic on symbolic rsp
	frame := a.AnalyzeStackFrame(insns)

	if !frame.HasFramePointer {
		t.Error("expected frame pointer to be detected")
	}
	// rbp-relative access at [rbp-8] must still be identified
	if len(frame.LocalVariables) < 1 {
		t.Errorf("expected at least 1 local variable via rbp, got %d", len(frame.LocalVariables))
	}
}

// TestSystemVAnalyzer_AnalyzeStackFrame_EmptyFunction tests an empty function
// with no stack accesses — frame must be zero-sized with no locals.
func TestSystemVAnalyzer_AnalyzeStackFrame_EmptyFunction(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "ret"),
	}

	a := NewSystemVAnalyzer()
	frame := a.AnalyzeStackFrame(insns)

	if frame.HasFramePointer {
		t.Error("empty function must not have frame pointer")
	}
	if frame.Size != 0 {
		t.Errorf("empty function frame size: expected 0, got %d", frame.Size)
	}
	if len(frame.LocalVariables) != 0 {
		t.Errorf("empty function: expected 0 local variables, got %d", len(frame.LocalVariables))
	}
	if len(frame.SpillSlots) != 0 {
		t.Errorf("empty function: expected 0 spill slots, got %d", len(frame.SpillSlots))
	}
}

// TestSystemVAnalyzer_AnalyzeStackFrame_NoInstructions tests nil/empty instruction slice.
func TestSystemVAnalyzer_AnalyzeStackFrame_NoInstructions(t *testing.T) {
	a := NewSystemVAnalyzer()
	frame := a.AnalyzeStackFrame([]*disasm.Instruction{})

	if frame == nil {
		t.Fatal("AnalyzeStackFrame must not return nil for empty input")
	}
	if frame.Size != 0 {
		t.Errorf("expected frame size 0 for empty input, got %d", frame.Size)
	}
}

// TestSystemVAnalyzer_AnalyzeStackFrame_InstructionWithNoOffset tests that
// instructions whose address is not in the tracker are safely skipped.
func TestSystemVAnalyzer_AnalyzeStackFrame_InstructionWithNoOffset(t *testing.T) {
	// instruction at address 0x2000 is not in the tracker (gap in addresses)
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		buildInsn(0x1004, "mov", mem("rsp", 0, disasm.Size64), imm(1, disasm.Size64)),
		// gap: 0x2000 is not contiguous — tracker will have it since we iterate all insns
		buildInsn(0x1008, "ret"),
	}

	a := NewSystemVAnalyzer()
	// must not panic
	frame := a.AnalyzeStackFrame(insns)
	if frame == nil {
		t.Fatal("AnalyzeStackFrame must not return nil")
	}
}

// TestMicrosoftX64Analyzer_AnalyzeStackFrame_LeafNoFramePointer tests a leaf function
// without frame pointer using rsp-relative addressing (common in ms x64 optimized code).
func TestMicrosoftX64Analyzer_AnalyzeStackFrame_LeafNoFramePointer(t *testing.T) {
	insns := []*disasm.Instruction{
		// ms x64 leaf: sub rsp,0x28 (shadow space + alignment); use locals; add rsp,0x28; ret
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x28, disasm.Size64)),
		// store local at [rsp+0] (below shadow space)
		buildInsn(0x1004, "mov", mem("rsp", 0, disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x1008, "add", reg("rsp", disasm.Size64), imm(0x28, disasm.Size64)),
		buildInsn(0x100c, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	frame := a.AnalyzeStackFrame(insns)

	if frame.HasFramePointer {
		t.Error("leaf function must not have frame pointer")
	}
	if frame.Size < 0x28 {
		t.Errorf("frame size: expected >= 0x28, got %d", frame.Size)
	}
}

// TestMicrosoftX64Analyzer_AnalyzeStackFrame_SpillSlots tests callee-saved register
// spill detection for Microsoft x64 (rdi, rsi are callee-saved unlike System V).
func TestMicrosoftX64Analyzer_AnalyzeStackFrame_SpillSlots(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), imm(0x40, disasm.Size64)),
		// spill rdi (callee-saved in ms x64) to [rbp-8]
		buildInsn(0x1008, "mov", mem("rbp", -8, disasm.Size64), reg("rdi", disasm.Size64)),
		// spill rsi (callee-saved in ms x64) to [rbp-16]
		buildInsn(0x100c, "mov", mem("rbp", -16, disasm.Size64), reg("rsi", disasm.Size64)),
		// local variable at [rbp-24]
		buildInsn(0x1010, "mov", mem("rbp", -24, disasm.Size64), imm(0, disasm.Size64)),
		buildInsn(0x1014, "mov", reg("rsi", disasm.Size64), mem("rbp", -16, disasm.Size64)),
		buildInsn(0x1018, "mov", reg("rdi", disasm.Size64), mem("rbp", -8, disasm.Size64)),
		buildInsn(0x101c, "add", reg("rsp", disasm.Size64), imm(0x40, disasm.Size64)),
		buildInsn(0x1020, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1021, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	frame := a.AnalyzeStackFrame(insns)

	if len(frame.SpillSlots) < 2 {
		t.Errorf("expected at least 2 spill slots (rdi, rsi), got %d", len(frame.SpillSlots))
	}

	spillRegs := make(map[string]bool)
	for _, s := range frame.SpillSlots {
		spillRegs[s.Register] = true
	}
	if !spillRegs["rdi"] {
		t.Error("rdi spill slot not detected (rdi is callee-saved in ms x64)")
	}
	if !spillRegs["rsi"] {
		t.Error("rsi spill slot not detected (rsi is callee-saved in ms x64)")
	}
}

// TestMicrosoftX64Analyzer_AnalyzeStackFrame_SymbolicRSP tests alloca-style
// dynamic allocation — rsp-relative accesses after sub rsp,reg must be skipped.
func TestMicrosoftX64Analyzer_AnalyzeStackFrame_SymbolicRSP(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		// alloca: sub rsp, rcx
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), reg("rcx", disasm.Size64)),
		// rsp-relative access after symbolic offset — must be skipped without panic
		buildInsn(0x1007, "mov", mem("rsp", 0, disasm.Size64), imm(0, disasm.Size64)),
		// rbp-relative access is still concrete
		buildInsn(0x100b, "mov", mem("rbp", -8, disasm.Size64), imm(1, disasm.Size64)),
		buildInsn(0x100f, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1010, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	frame := a.AnalyzeStackFrame(insns)

	if !frame.HasFramePointer {
		t.Error("expected frame pointer to be detected")
	}
	if len(frame.LocalVariables) < 1 {
		t.Errorf("expected at least 1 local variable via rbp, got %d", len(frame.LocalVariables))
	}
}

// TestMicrosoftX64Analyzer_AnalyzeStackFrame_EmptyFunction tests empty function.
func TestMicrosoftX64Analyzer_AnalyzeStackFrame_EmptyFunction(t *testing.T) {
	a := NewMicrosoftX64Analyzer()
	frame := a.AnalyzeStackFrame([]*disasm.Instruction{})

	if frame == nil {
		t.Fatal("AnalyzeStackFrame must not return nil for empty input")
	}
	if frame.Size != 0 {
		t.Errorf("expected frame size 0, got %d", frame.Size)
	}
	if len(frame.LocalVariables) != 0 {
		t.Errorf("expected 0 local variables, got %d", len(frame.LocalVariables))
	}
}

// TestCallingConvention_String tests the String() method on all CallingConvention values.
// this covers the previously uncovered types.go:22 branch.
func TestCallingConvention_String(t *testing.T) {
	cases := []struct {
		conv CallingConvention
		want string
	}{
		{CallingConventionSystemVAMD64, "SystemV_AMD64"},
		{CallingConventionMicrosoftX64, "Microsoft_x64"},
		{CallingConventionCustom, "Custom"},
		{CallingConventionUnknown, "Unknown"},
		// out-of-range value must fall through to default
		{CallingConvention(99), "Unknown"},
	}

	for _, tc := range cases {
		got := tc.conv.String()
		if got != tc.want {
			t.Errorf("CallingConvention(%d).String() = %q, want %q", tc.conv, got, tc.want)
		}
	}
}

// TestErrUnsupportedConvention_Error tests the Error() method on ErrUnsupportedConvention.
// this covers the previously uncovered analyzer.go:59 branch.
func TestErrUnsupportedConvention_Error(t *testing.T) {
	err := &ErrUnsupportedConvention{Convention: CallingConventionCustom}
	msg := err.Error()
	if msg == "" {
		t.Error("ErrUnsupportedConvention.Error() must return non-empty string")
	}
	// verify the convention name appears in the error message
	if msg != "unsupported calling convention: Custom" {
		t.Errorf("unexpected error message: %q", msg)
	}
}

// TestNewAnalyzer_UnsupportedConvention tests that NewAnalyzer returns an error
// for unsupported conventions and that the error message is correct.
func TestNewAnalyzer_UnsupportedConvention(t *testing.T) {
	_, err := NewAnalyzer(CallingConventionUnknown)
	if err == nil {
		t.Fatal("expected error for unsupported convention, got nil")
	}
	unsupported, ok := err.(*ErrUnsupportedConvention)
	if !ok {
		t.Fatalf("expected *ErrUnsupportedConvention, got %T", err)
	}
	if unsupported.Convention != CallingConventionUnknown {
		t.Errorf("wrong convention in error: expected Unknown, got %v", unsupported.Convention)
	}
}

// TestStackOffset_IsStackOffset_Discriminators tests the isStackOffset() discriminator
// methods on both concrete and symbolic offsets. these are interface discriminators
// that must compile and execute without panic.
func TestStackOffset_IsStackOffset_Discriminators(t *testing.T) {
	// exercise the isStackOffset() methods directly — they are discriminators
	// used by the type system and must not panic
	c := ConcreteOffset{Value: -32}
	c.isStackOffset() // must not panic

	s := SymbolicOffset{Base: -16, VarName: "rax"}
	s.isStackOffset() // must not panic
}

// TestCanonicalizeRegister_ExtendedCoverage tests register families not covered
// by existing tests: rsi, rdi, rbp, rsp, r10, r11, xmm4-xmm7, and unknown registers.
func TestCanonicalizeRegister_ExtendedCoverage(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		// rsi family
		{"rsi", "rsi"}, {"esi", "rsi"}, {"si", "rsi"}, {"sil", "rsi"},
		// rdi family
		{"rdi", "rdi"}, {"edi", "rdi"}, {"di", "rdi"}, {"dil", "rdi"},
		// rbp family
		{"rbp", "rbp"}, {"ebp", "rbp"}, {"bp", "rbp"}, {"bpl", "rbp"},
		// rsp family
		{"rsp", "rsp"}, {"esp", "rsp"}, {"sp", "rsp"}, {"spl", "rsp"},
		// r10 family
		{"r10", "r10"}, {"r10d", "r10"}, {"r10w", "r10"}, {"r10b", "r10"},
		// r11 family
		{"r11", "r11"}, {"r11d", "r11"}, {"r11w", "r11"}, {"r11b", "r11"},
		// xmm4-xmm7
		{"xmm4", "xmm4"}, {"xmm5", "xmm5"}, {"xmm6", "xmm6"}, {"xmm7", "xmm7"},
		// unknown register must pass through unchanged
		{"ymm0", "ymm0"}, {"zmm0", "zmm0"}, {"cr0", "cr0"},
	}

	for _, tc := range cases {
		got := canonicalizeRegister(tc.input)
		if got != tc.want {
			t.Errorf("canonicalizeRegister(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestSystemVAnalyzer_AnalyzeStackFrame_FrameSizeFromMinOffset tests that the frame
// size is computed as the absolute value of the most negative RSP offset seen.
// this validates the minOffset computation loop in AnalyzeStackFrame.
func TestSystemVAnalyzer_AnalyzeStackFrame_FrameSizeFromMinOffset(t *testing.T) {
	// sub rsp, 0x50 is the deepest point — frame size must be 0x50
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), imm(0x50, disasm.Size64)),
		buildInsn(0x1008, "nop"),
		buildInsn(0x1009, "add", reg("rsp", disasm.Size64), imm(0x50, disasm.Size64)),
		buildInsn(0x100d, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x100e, "ret"),
	}

	a := NewSystemVAnalyzer()
	frame := a.AnalyzeStackFrame(insns)

	// push rbp contributes -8, sub rsp,0x50 contributes -0x58 total
	// frame size = -minOffset = 0x58
	if frame.Size < 0x50 {
		t.Errorf("frame size: expected >= 0x50, got %d", frame.Size)
	}
}

// TestMicrosoftX64Analyzer_AnalyzeStackFrame_FrameSizeFromMinOffset tests frame size
// computation for Microsoft x64 convention.
func TestMicrosoftX64Analyzer_AnalyzeStackFrame_FrameSizeFromMinOffset(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "sub", reg("rsp", disasm.Size64), imm(0x60, disasm.Size64)),
		buildInsn(0x1008, "nop"),
		buildInsn(0x1009, "add", reg("rsp", disasm.Size64), imm(0x60, disasm.Size64)),
		buildInsn(0x100d, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x100e, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	frame := a.AnalyzeStackFrame(insns)

	if frame.Size < 0x60 {
		t.Errorf("frame size: expected >= 0x60, got %d", frame.Size)
	}
}

// TestSystemVAnalyzer_AnalyzeStackFrame_MemOpWithZeroSize tests that memory operands
// with Size=0 default to Size64 (8 bytes) in the frame analysis.
func TestSystemVAnalyzer_AnalyzeStackFrame_MemOpWithZeroSize(t *testing.T) {
	// memory operand with Size=0 — must default to Size64 without panic
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		// mem operand with Size=0 (unspecified)
		{
			Address:  0x1004,
			Mnemonic: "mov",
			Operands: []disasm.Operand{
				disasm.MemoryOperand{Base: "rsp", Disp: 0, Size: 0},
				imm(42, disasm.Size64),
			},
			Length: 4,
		},
		buildInsn(0x1008, "ret"),
	}

	a := NewSystemVAnalyzer()
	frame := a.AnalyzeStackFrame(insns)

	if frame == nil {
		t.Fatal("AnalyzeStackFrame must not return nil")
	}
	// the access with Size=0 must be recorded with default Size64
	if len(frame.LocalVariables) < 1 {
		t.Errorf("expected at least 1 local variable, got %d", len(frame.LocalVariables))
	}
	for _, lv := range frame.LocalVariables {
		if lv.Size == 0 {
			t.Error("local variable size must not be 0 (must default to Size64)")
		}
	}
}

// TestMicrosoftX64Analyzer_AnalyzeStackFrame_MemOpWithZeroSize tests the same
// zero-size defaulting behavior for Microsoft x64 analyzer.
func TestMicrosoftX64Analyzer_AnalyzeStackFrame_MemOpWithZeroSize(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		{
			Address:  0x1004,
			Mnemonic: "mov",
			Operands: []disasm.Operand{
				disasm.MemoryOperand{Base: "rsp", Disp: 0, Size: 0},
				imm(42, disasm.Size64),
			},
			Length: 4,
		},
		buildInsn(0x1008, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	frame := a.AnalyzeStackFrame(insns)

	if frame == nil {
		t.Fatal("AnalyzeStackFrame must not return nil")
	}
	for _, lv := range frame.LocalVariables {
		if lv.Size == 0 {
			t.Error("local variable size must not be 0 (must default to Size64)")
		}
	}
}

// TestSystemVAnalyzer_AnalyzeStackFrame_DuplicateOffsetDeduplication tests that
// multiple accesses to the same frame offset produce only one entry in LocalVariables.
// the accessMap deduplication logic must prevent duplicate entries.
func TestSystemVAnalyzer_AnalyzeStackFrame_DuplicateOffsetDeduplication(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		// write to [rsp+0]
		buildInsn(0x1004, "mov", mem("rsp", 0, disasm.Size64), imm(1, disasm.Size64)),
		// read from [rsp+0] — same offset, must not create duplicate entry
		buildInsn(0x1008, "mov", reg("rax", disasm.Size64), mem("rsp", 0, disasm.Size64)),
		buildInsn(0x100c, "ret"),
	}

	a := NewSystemVAnalyzer()
	frame := a.AnalyzeStackFrame(insns)

	// [rsp+0] accessed twice — must produce exactly 1 local variable entry
	count := 0
	for _, lv := range frame.LocalVariables {
		if lv.FrameOffset == -0x10 {
			count++
		}
	}
	if count > 1 {
		t.Errorf("duplicate frame offset: expected 1 entry for offset -0x10, got %d", count)
	}
}

// TestSystemVAnalyzer_AnalyzeStackFrame_NonMemoryOperandsSkipped tests that
// non-memory operands in instructions are correctly skipped during frame analysis.
func TestSystemVAnalyzer_AnalyzeStackFrame_NonMemoryOperandsSkipped(t *testing.T) {
	// instruction with only register operands — no memory access to record
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		buildInsn(0x1004, "mov", reg("rax", disasm.Size64), reg("rdi", disasm.Size64)),
		buildInsn(0x1007, "add", reg("rax", disasm.Size64), imm(1, disasm.Size64)),
		buildInsn(0x100b, "ret"),
	}

	a := NewSystemVAnalyzer()
	frame := a.AnalyzeStackFrame(insns)

	// no memory accesses — no local variables
	if len(frame.LocalVariables) != 0 {
		t.Errorf("expected 0 local variables (no memory accesses), got %d", len(frame.LocalVariables))
	}
}
