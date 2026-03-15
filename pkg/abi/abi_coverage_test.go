// package abi — additional unit tests covering branches missed by existing test suite.
// focuses on: syscall recovery, systemv/ms-x64 edge cases, adjustOffset default branch.
package abi

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// ---------------------------------------------------------------------------
// syscall.go — OSKind.String default branch
// ---------------------------------------------------------------------------

// TestOSKind_String covers all OSKind values including the default branch.
func TestOSKind_String(t *testing.T) {
	cases := []struct {
		kind OSKind
		want string
	}{
		{OSLinuxAMD64, "Linux_AMD64"},
		{OSWindowsNT, "Windows_NT"},
		{OSKind(99), "Unknown"},
	}
	for _, tc := range cases {
		got := tc.kind.String()
		if got != tc.want {
			t.Errorf("OSKind(%d).String() = %q, want %q", tc.kind, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// syscall.go — SyscallKind.String default branch
// ---------------------------------------------------------------------------

// TestSyscallKind_String covers all SyscallKind values including the default branch.
func TestSyscallKind_String(t *testing.T) {
	cases := []struct {
		kind SyscallKind
		want string
	}{
		{SyscallKindSyscall, "syscall"},
		{SyscallKindSysenter, "sysenter"},
		{SyscallKindInt80, "int 0x80"},
		{SyscallKindInt2E, "int 0x2e"},
		{SyscallKind(99), "unknown"},
	}
	for _, tc := range cases {
		got := tc.kind.String()
		if got != tc.want {
			t.Errorf("SyscallKind(%d).String() = %q, want %q", tc.kind, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// syscall.go — selectTable default branch (unknown OS)
// ---------------------------------------------------------------------------

// TestSelectTable_DefaultBranch exercises the default branch in selectTable
// by passing an unknown OSKind value. it must return the linux table (fallback).
func TestSelectTable_DefaultBranch(t *testing.T) {
	// unknown os kind — selectTable must fall through to linux table
	table := selectTable(OSKind(99))
	if table == nil {
		t.Fatal("selectTable with unknown OSKind must return non-nil table")
	}
	// linux table contains syscall 0 (read) — verify it is the linux table
	sig, ok := table[0]
	if !ok {
		t.Fatal("expected syscall 0 in fallback linux table")
	}
	if sig.OS != OSLinuxAMD64 {
		t.Errorf("fallback table OS: expected OSLinuxAMD64, got %v", sig.OS)
	}
}

// TestSelectTable_WindowsNT verifies selectTable returns the windows NT table.
func TestSelectTable_WindowsNT(t *testing.T) {
	table := selectTable(OSWindowsNT)
	if table == nil {
		t.Fatal("selectTable(OSWindowsNT) must return non-nil table")
	}
}

// ---------------------------------------------------------------------------
// syscall.go — resolveNumber: xor eax,eax zeroing idiom
// ---------------------------------------------------------------------------

// TestSyscallRecovery_XorRaxZeroingIdiom tests that xor rax,rax (64-bit variant)
// before syscall resolves to syscall number 0.
func TestSyscallRecovery_XorRaxZeroingIdiom(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "xor", reg("rax", disasm.Size64), reg("rax", disasm.Size64)),
		buildInsn(0x1003, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil {
		t.Fatal("syscall number must be resolved for xor rax,rax")
	}
	if *sites[0].Number != 0 {
		t.Errorf("syscall number: expected 0 (xor zeroing), got %d", *sites[0].Number)
	}
}

// TestSyscallRecovery_XorpsZeroingIdiom tests that xorps xmm0,xmm0 does NOT
// resolve rax — only xor on rax/eax counts as zeroing idiom.
func TestSyscallRecovery_XorpsZeroingIdiom(t *testing.T) {
	// xorps xmm0,xmm0 — not a rax zeroing, syscall number must remain unresolved
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "xorps", reg("xmm0", disasm.Size64), reg("xmm0", disasm.Size64)),
		buildInsn(0x1002, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	// xorps on xmm0 does not set rax — number must be nil
	if sites[0].Number != nil {
		t.Errorf("syscall number must be nil for xorps xmm0,xmm0, got %d", *sites[0].Number)
	}
}

// ---------------------------------------------------------------------------
// syscall.go — resolveNumber: stop at call/ret boundary
// ---------------------------------------------------------------------------

// TestSyscallRecovery_StopAtCallBoundary tests that backward scan stops at
// a call instruction — syscall number must be unresolved.
func TestSyscallRecovery_StopAtCallBoundary(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(1, disasm.Size64)),
		// call resets the scan boundary — rax value from before call is not trusted
		buildInsn(0x1004, "call", imm(0x2000, disasm.Size64)),
		buildInsn(0x1009, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	// backward scan hits call before finding mov rax,1 — number must be nil
	if sites[0].Number != nil {
		t.Errorf("syscall number must be nil when call boundary is hit, got %d", *sites[0].Number)
	}
}

// TestSyscallRecovery_StopAtRetBoundary tests that backward scan stops at ret.
func TestSyscallRecovery_StopAtRetBoundary(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(2, disasm.Size64)),
		buildInsn(0x1004, "ret"),
		buildInsn(0x1005, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number != nil {
		t.Errorf("syscall number must be nil when ret boundary is hit, got %d", *sites[0].Number)
	}
}

// ---------------------------------------------------------------------------
// syscall.go — resolveNumber: non-rax write breaks scan
// ---------------------------------------------------------------------------

// TestSyscallRecovery_NonRaxWriteBreaksScan tests that a write to rax via
// a non-mov/xor instruction (e.g., add rax, 1) breaks the backward scan.
func TestSyscallRecovery_NonRaxWriteBreaksScan(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(3, disasm.Size64)),
		// add rax,1 — writes rax with non-constant value, breaks scan
		buildInsn(0x1004, "add", reg("rax", disasm.Size64), imm(1, disasm.Size64)),
		buildInsn(0x1008, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	// add rax,1 is not a constant assignment — number must be nil
	if sites[0].Number != nil {
		t.Errorf("syscall number must be nil when non-const rax write found, got %d", *sites[0].Number)
	}
}

// ---------------------------------------------------------------------------
// syscall.go — sysenter and int 0x80 / int 0x2e detection
// ---------------------------------------------------------------------------

// TestSyscallRecovery_Sysenter tests sysenter instruction detection.
func TestSyscallRecovery_Sysenter(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("eax", disasm.Size32), imm(11, disasm.Size64)),
		buildInsn(0x1005, "sysenter"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 sysenter site, got %d", len(sites))
	}
	if sites[0].Kind != SyscallKindSysenter {
		t.Errorf("kind: expected SyscallKindSysenter, got %v", sites[0].Kind)
	}
	if sites[0].Number == nil || *sites[0].Number != 11 {
		t.Errorf("syscall number: expected 11, got %v", sites[0].Number)
	}
}

// TestSyscallRecovery_Int80 tests int 0x80 instruction detection.
func TestSyscallRecovery_Int80(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("eax", disasm.Size32), imm(1, disasm.Size64)),
		{
			Address:  0x1005,
			Mnemonic: "int",
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x80, Size: disasm.Size8}},
			Length:   2,
		},
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 int 0x80 site, got %d", len(sites))
	}
	if sites[0].Kind != SyscallKindInt80 {
		t.Errorf("kind: expected SyscallKindInt80, got %v", sites[0].Kind)
	}
}

// TestSyscallRecovery_Int2E tests int 0x2e (Windows NT) instruction detection.
func TestSyscallRecovery_Int2E(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("eax", disasm.Size32), imm(0x25, disasm.Size64)),
		{
			Address:  0x1005,
			Mnemonic: "int",
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x2e, Size: disasm.Size8}},
			Length:   2,
		},
	}

	r := NewSyscallRecovery(OSWindowsNT)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 int 0x2e site, got %d", len(sites))
	}
	if sites[0].Kind != SyscallKindInt2E {
		t.Errorf("kind: expected SyscallKindInt2E, got %v", sites[0].Kind)
	}
}

// ---------------------------------------------------------------------------
// syscall.go — int with non-matching immediate (not 0x80 or 0x2e)
// ---------------------------------------------------------------------------

// TestSyscallRecovery_IntOtherImmediate tests that int with an unrecognized
// immediate (e.g., int 0x03) is not classified as a syscall site.
func TestSyscallRecovery_IntOtherImmediate(t *testing.T) {
	insns := []*disasm.Instruction{
		{
			Address:  0x1000,
			Mnemonic: "int",
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x03, Size: disasm.Size8}},
			Length:   2,
		},
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 0 {
		t.Errorf("int 0x03 must not be classified as syscall, got %d sites", len(sites))
	}
}

// TestSyscallRecovery_IntNoOperands tests that int with no operands is ignored.
func TestSyscallRecovery_IntNoOperands(t *testing.T) {
	insns := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "int", Operands: []disasm.Operand{}, Length: 1},
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 0 {
		t.Errorf("int with no operands must not be classified as syscall, got %d sites", len(sites))
	}
}

// TestSyscallRecovery_IntRegOperand tests that int with a register operand is ignored.
func TestSyscallRecovery_IntRegOperand(t *testing.T) {
	insns := []*disasm.Instruction{
		{
			Address:  0x1000,
			Mnemonic: "int",
			Operands: []disasm.Operand{reg("rax", disasm.Size64)},
			Length:   2,
		},
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 0 {
		t.Errorf("int with register operand must not be classified as syscall, got %d sites", len(sites))
	}
}

// ---------------------------------------------------------------------------
// syscall.go — resolveNumber: mov with non-immediate source (not constant)
// ---------------------------------------------------------------------------

// TestSyscallRecovery_MovRaxNonImmediate tests that mov rax, rbx (non-immediate)
// does not resolve the syscall number — the scan must break.
func TestSyscallRecovery_MovRaxNonImmediate(t *testing.T) {
	insns := []*disasm.Instruction{
		// mov rax, rbx — writes rax but not with a constant
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), reg("rbx", disasm.Size64)),
		buildInsn(0x1003, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	// mov rax, rbx is not a constant — number must be nil
	if sites[0].Number != nil {
		t.Errorf("syscall number must be nil for mov rax,rbx, got %d", *sites[0].Number)
	}
}

// ---------------------------------------------------------------------------
// syscall.go — resolveNumber: instruction with < 2 operands is skipped
// ---------------------------------------------------------------------------

// TestSyscallRecovery_SingleOperandInsnSkipped tests that single-operand
// instructions before syscall are skipped without breaking the scan.
func TestSyscallRecovery_SingleOperandInsnSkipped(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(60, disasm.Size64)),
		// push rbx — single operand, must be skipped (not break scan)
		buildInsn(0x1004, "push", reg("rbx", disasm.Size64)),
		buildInsn(0x1005, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	// push rbx has 1 operand — scan continues past it and finds mov rax,60
	if sites[0].Number == nil || *sites[0].Number != 60 {
		t.Errorf("syscall number: expected 60, got %v", sites[0].Number)
	}
}

// ---------------------------------------------------------------------------
// syscall.go — signature lookup: known and unknown syscall numbers
// ---------------------------------------------------------------------------

// TestSyscallRecovery_KnownLinuxSyscall tests that a known linux syscall number
// resolves to a non-nil signature.
func TestSyscallRecovery_KnownLinuxSyscall(t *testing.T) {
	// syscall 0 = read on linux amd64
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(0, disasm.Size64)),
		buildInsn(0x1004, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Signature == nil {
		t.Fatal("expected non-nil signature for known linux syscall 0")
	}
	if sites[0].Signature.Number != 0 {
		t.Errorf("signature number: expected 0, got %d", sites[0].Signature.Number)
	}
}

// TestSyscallRecovery_UnknownSyscallNumber tests that an unknown syscall number
// results in a nil signature.
func TestSyscallRecovery_UnknownSyscallNumber(t *testing.T) {
	// syscall 0xFFFF is not in any table
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(0xFFFF, disasm.Size64)),
		buildInsn(0x1004, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 0xFFFF {
		t.Errorf("syscall number: expected 0xFFFF, got %v", sites[0].Number)
	}
	if sites[0].Signature != nil {
		t.Errorf("signature must be nil for unknown syscall number 0xFFFF")
	}
}

// TestSyscallRecovery_EmptyInstructionsSlice tests recovery on empty (non-nil) instruction slice.
// complements the existing TestSyscallRecovery_EmptyInstructions which tests nil input.
func TestSyscallRecovery_EmptyInstructionsSlice(t *testing.T) {
	r := NewSyscallRecovery(OSWindowsNT)
	sites := r.Recover([]*disasm.Instruction{})
	if len(sites) != 0 {
		t.Errorf("expected 0 sites for empty windows input, got %d", len(sites))
	}
}

// TestSyscallRecovery_MultipleSyscalls tests detection of multiple syscall sites.
func TestSyscallRecovery_MultipleSyscalls(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(1, disasm.Size64)),
		buildInsn(0x1004, "syscall"),
		buildInsn(0x1006, "mov", reg("rax", disasm.Size64), imm(60, disasm.Size64)),
		buildInsn(0x100a, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 2 {
		t.Fatalf("expected 2 syscall sites, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 1 {
		t.Errorf("first syscall number: expected 1, got %v", sites[0].Number)
	}
	if sites[1].Number == nil || *sites[1].Number != 60 {
		t.Errorf("second syscall number: expected 60, got %v", sites[1].Number)
	}
}

// ---------------------------------------------------------------------------
// systemv.go — IdentifyReturnValues: xmm0 + xmm1 (complex/128-bit float return)
// ---------------------------------------------------------------------------

// TestSystemVAnalyzer_IdentifyReturnValues_ComplexFloatReturn tests that both
// xmm0 and xmm1 are detected when a function returns a complex/128-bit float.
func TestSystemVAnalyzer_IdentifyReturnValues_ComplexFloatReturn(t *testing.T) {
	// function returning complex double: xmm0 = real part, xmm1 = imaginary part
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "movsd", reg("xmm0", disasm.Size64), mem("rbp", -8, disasm.Size64)),
		buildInsn(0x1008, "movsd", reg("xmm1", disasm.Size64), mem("rbp", -16, disasm.Size64)),
		buildInsn(0x100c, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x100d, "ret"),
	}

	a := NewSystemVAnalyzer()
	retVals := a.IdentifyReturnValues(insns)

	if len(retVals) != 2 {
		t.Fatalf("expected 2 return values (xmm0+xmm1 for complex float), got %d", len(retVals))
	}
	if retVals[0].Register != "xmm0" {
		t.Errorf("first return value: expected xmm0, got %s", retVals[0].Register)
	}
	if retVals[1].Register != "xmm1" {
		t.Errorf("second return value: expected xmm1, got %s", retVals[1].Register)
	}
}

// ---------------------------------------------------------------------------
// systemv.go — detectVariadic: al written before read (not variadic)
// ---------------------------------------------------------------------------

// TestSystemVAnalyzer_DetectVariadic_AlWrittenFirst tests that a function
// that writes al before reading it is NOT detected as variadic.
func TestSystemVAnalyzer_DetectVariadic_AlWrittenFirst(t *testing.T) {
	// function writes al first (e.g., xor al,al), then reads it — not variadic
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		// write al first — not a variadic xmm count read
		buildInsn(0x1004, "mov", reg("al", disasm.Size8), imm(0, disasm.Size64)),
		// now read al — but it was already written, so not variadic
		buildInsn(0x1007, "test", reg("al", disasm.Size8), reg("al", disasm.Size8)),
		buildInsn(0x1009, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x100a, "ret"),
	}

	a := NewSystemVAnalyzer()
	result := a.Analyze(insns)

	if result.IsVariadic {
		t.Error("function that writes al before reading it must NOT be variadic")
	}
}

// TestSystemVAnalyzer_DetectVariadic_NoAlAccess tests that a function with
// no al access is not variadic.
func TestSystemVAnalyzer_DetectVariadic_NoAlAccess(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), reg("rdi", disasm.Size64)),
		buildInsn(0x1003, "ret"),
	}

	a := NewSystemVAnalyzer()
	result := a.Analyze(insns)

	if result.IsVariadic {
		t.Error("function with no al access must not be variadic")
	}
}

// ---------------------------------------------------------------------------
// systemv.go — IdentifyReturnValues: rdx written but rax not written
// ---------------------------------------------------------------------------

// TestSystemVAnalyzer_IdentifyReturnValues_RdxWithoutRax tests that rdx alone
// does not produce a return value — rdx is secondary and requires rax.
func TestSystemVAnalyzer_IdentifyReturnValues_RdxWithoutRax(t *testing.T) {
	// function writes rdx but not rax before ret — no return value expected
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "mov", reg("rdx", disasm.Size64), imm(42, disasm.Size64)),
		buildInsn(0x1007, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x1008, "ret"),
	}

	a := NewSystemVAnalyzer()
	retVals := a.IdentifyReturnValues(insns)

	// rdx without rax is not a valid return — system v requires rax as primary
	if len(retVals) != 0 {
		t.Errorf("rdx without rax must not produce return values, got %d", len(retVals))
	}
}

// ---------------------------------------------------------------------------
// microsoftx64.go — VerifyCalleeSavedRegisters: mov-based spill for ms x64
// ---------------------------------------------------------------------------

// TestMicrosoftX64Analyzer_VerifyCalleeSavedRegisters_MovSpill tests that
// callee-saved registers saved via mov [mem], reg and restored via mov reg, [mem]
// are correctly detected as preserved in the Microsoft x64 convention.
//
//nolint:dupl // intentionally tests microsoft x64 analyzer with similar pattern
func TestMicrosoftX64Analyzer_VerifyCalleeSavedRegisters_MovSpill(t *testing.T) {
	// save rdi via mov (ms x64: rdi is callee-saved, unlike system v)
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		// spill rdi to [rsp+0]
		buildInsn(0x1004, "mov", mem("rsp", 0, disasm.Size64), reg("rdi", disasm.Size64)),
		// use rdi
		buildInsn(0x1008, "mov", reg("rdi", disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x100b, "add", reg("rdi", disasm.Size64), imm(1, disasm.Size64)),
		// restore rdi from [rsp+0]
		buildInsn(0x100f, "mov", reg("rdi", disasm.Size64), mem("rsp", 0, disasm.Size64)),
		buildInsn(0x1013, "add", reg("rsp", disasm.Size64), imm(0x20, disasm.Size64)),
		buildInsn(0x1017, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	statuses := a.VerifyCalleeSavedRegisters(insns)

	var rdiStatus *CalleeSavedRegisterStatus
	for i := range statuses {
		if statuses[i].Register == "rdi" {
			rdiStatus = &statuses[i]
			break
		}
	}
	if rdiStatus == nil {
		t.Fatal("rdi not found in ms x64 callee-saved register statuses")
	}
	if !rdiStatus.Preserved {
		t.Error("rdi was saved via mov and restored via mov but Preserved=false")
	}
}

// TestMicrosoftX64Analyzer_VerifyCalleeSavedRegisters_NeverUsed tests that
// registers never touched are reported as preserved.
func TestMicrosoftX64Analyzer_VerifyCalleeSavedRegisters_NeverUsed(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x1003, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	statuses := a.VerifyCalleeSavedRegisters(insns)

	for _, s := range statuses {
		if !s.Preserved {
			t.Errorf("register %s was never touched but Preserved=false", s.Register)
		}
	}
}

// TestMicrosoftX64Analyzer_VerifyCalleeSavedRegisters_MovWithWrongOperandCount
// tests that mov instructions with operand count != 2 are safely skipped.
func TestMicrosoftX64Analyzer_VerifyCalleeSavedRegisters_MovWithWrongOperandCount(t *testing.T) {
	insns := []*disasm.Instruction{
		// mov with single operand — malformed, must not panic
		{Address: 0x1000, Mnemonic: "mov", Operands: []disasm.Operand{reg("rbx", disasm.Size64)}, Length: 2},
		buildInsn(0x1002, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	// must not panic
	statuses := a.VerifyCalleeSavedRegisters(insns)
	if len(statuses) != 8 {
		t.Errorf("expected 8 callee-saved statuses, got %d", len(statuses))
	}
}

// ---------------------------------------------------------------------------
// microsoftx64.go — handleSubInstruction: sub with wrong operand count
// ---------------------------------------------------------------------------

// TestMicrosoftX64Analyzer_TrackStackPointer_SubWrongOperandCount tests that
// sub with a single operand (malformed) does not change the tracked offset.
func TestMicrosoftX64Analyzer_TrackStackPointer_SubWrongOperandCount(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		// sub with single operand — malformed
		{Address: 0x1004, Mnemonic: "sub", Operands: []disasm.Operand{reg("rsp", disasm.Size64)}, Length: 2},
		buildInsn(0x1006, "nop"),
	}

	a := NewMicrosoftX64Analyzer()
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

// ---------------------------------------------------------------------------
// microsoftx64.go — IdentifyReturnValues: no ret instruction
// ---------------------------------------------------------------------------

// TestMicrosoftX64Analyzer_IdentifyReturnValues_RetnInstruction tests that
// the "retn" mnemonic variant is also recognized as a return instruction.
func TestMicrosoftX64Analyzer_IdentifyReturnValues_RetnInstruction(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(7, disasm.Size64)),
		buildInsn(0x1004, "retn"),
	}

	a := NewMicrosoftX64Analyzer()
	retVals := a.IdentifyReturnValues(insns)

	if len(retVals) != 1 {
		t.Fatalf("expected 1 return value for retn, got %d", len(retVals))
	}
	if retVals[0].Register != "rax" {
		t.Errorf("expected return in rax, got %s", retVals[0].Register)
	}
}

// ---------------------------------------------------------------------------
// systemv.go — IdentifyParameters: write to param reg before read (not a param)
// ---------------------------------------------------------------------------

// TestSystemVAnalyzer_IdentifyParameters_WriteBeforeRead tests that a register
// written before being read is NOT detected as a parameter.
func TestSystemVAnalyzer_IdentifyParameters_WriteBeforeRead(t *testing.T) {
	// rdi is written first (not a parameter read), then used
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		// write rdi first — this is NOT a parameter read
		buildInsn(0x1004, "mov", reg("rdi", disasm.Size64), imm(0, disasm.Size64)),
		// now read rdi — but it was already written, so not a parameter
		buildInsn(0x1007, "mov", reg("rax", disasm.Size64), reg("rdi", disasm.Size64)),
		buildInsn(0x100a, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x100b, "ret"),
	}

	a := NewSystemVAnalyzer()
	params := a.IdentifyParameters(insns)

	for _, p := range params {
		if p.Register == "rdi" {
			t.Error("rdi was written before read — must NOT be detected as parameter")
		}
	}
}

// ---------------------------------------------------------------------------
// systemv.go — IdentifyParameters: stack param at [rsp+8] is return addr, not param
// ---------------------------------------------------------------------------

// TestSystemVAnalyzer_IdentifyParameters_ReturnAddrNotParam tests that
// [rsp+8] (return address slot) is not classified as a stack parameter.
// system v §3.2.3: stack args start at [rsp+16] inside callee (disp >= 16).
func TestSystemVAnalyzer_IdentifyParameters_ReturnAddrNotParam(t *testing.T) {
	insns := []*disasm.Instruction{
		// read [rsp+8] — this is the return address, not a parameter
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), mem("rsp", 8, disasm.Size64)),
		buildInsn(0x1004, "ret"),
	}

	a := NewSystemVAnalyzer()
	params := a.IdentifyParameters(insns)

	for _, p := range params {
		if p.Location == ParameterLocationStack && p.StackOffset == 8 {
			t.Error("[rsp+8] is the return address and must not be classified as a stack parameter")
		}
	}
}

// ---------------------------------------------------------------------------
// systemv.go — TrackStackPointer: call instruction net-zero effect
// ---------------------------------------------------------------------------

// TestSystemVAnalyzer_TrackStackPointer_CallNetZero tests that a call instruction
// does not change the tracked RSP offset (net effect is zero from caller's view).
func TestSystemVAnalyzer_TrackStackPointer_CallNetZero(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x28, disasm.Size64)),
		buildInsn(0x1004, "call", imm(0x2000, disasm.Size64)),
		buildInsn(0x1009, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	// after sub rsp,0x28: offset = -0x28
	// after call: net effect is 0 (callee manages its own frame)
	off, ok := tracker.GetOffset(0x1009)
	if !ok {
		t.Fatal("no offset at 0x1009")
	}
	c, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Fatalf("expected ConcreteOffset after call, got %T", off)
	}
	if c.Value != -0x28 {
		t.Errorf("offset after call: expected -0x28, got %d", c.Value)
	}
}

// ---------------------------------------------------------------------------
// systemv.go — TrackStackPointer: ret instruction stops tracking
// ---------------------------------------------------------------------------

// TestSystemVAnalyzer_TrackStackPointer_RetStopsTracking tests that the offset
// at the ret instruction itself is recorded (before ret executes).
func TestSystemVAnalyzer_TrackStackPointer_RetStopsTracking(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		buildInsn(0x1004, "add", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		buildInsn(0x1008, "ret"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	// at ret: offset should be 0 (sub then add cancel out)
	off, ok := tracker.GetOffset(0x1008)
	if !ok {
		t.Fatal("no offset recorded at ret instruction")
	}
	c, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Fatalf("expected ConcreteOffset at ret, got %T", off)
	}
	if c.Value != 0 {
		t.Errorf("offset at ret: expected 0, got %d", c.Value)
	}
}

// ---------------------------------------------------------------------------
// systemv.go — VerifyCalleeSavedRegisters: mov with wrong operand count
// ---------------------------------------------------------------------------

// TestSystemVAnalyzer_VerifyCalleeSavedRegisters_MovWrongOperandCount tests
// that mov with operand count != 2 is safely skipped via continue.
// the register is not marked modified — it is treated as untouched.
func TestSystemVAnalyzer_VerifyCalleeSavedRegisters_MovWrongOperandCount(t *testing.T) {
	insns := []*disasm.Instruction{
		// mov with single operand — malformed, must not panic
		{Address: 0x1000, Mnemonic: "mov", Operands: []disasm.Operand{reg("rbx", disasm.Size64)}, Length: 2},
		buildInsn(0x1002, "ret"),
	}

	a := NewSystemVAnalyzer()
	// must not panic — malformed mov is silently skipped via continue
	statuses := a.VerifyCalleeSavedRegisters(insns)

	if len(statuses) != 6 {
		t.Errorf("expected 6 callee-saved statuses, got %d", len(statuses))
	}
}

// ---------------------------------------------------------------------------
// systemv.go — VerifyCalleeSavedRegisters: default branch (non-push/pop/mov)
// ---------------------------------------------------------------------------

// TestSystemVAnalyzer_VerifyCalleeSavedRegisters_DefaultBranchModifies tests
// that instructions other than push/pop/mov that write to a callee-saved register
// mark it as modified (not preserved).
func TestSystemVAnalyzer_VerifyCalleeSavedRegisters_DefaultBranchModifies(t *testing.T) {
	// lea r12, [rip+0] — writes r12 via non-push/pop/mov instruction
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "lea", reg("r12", disasm.Size64), mem("rip", 0, disasm.Size64)),
		buildInsn(0x1004, "ret"),
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
	if r12Status.Preserved {
		t.Error("r12 written via lea without save must not be preserved")
	}
}

// ---------------------------------------------------------------------------
// microsoftx64.go — VerifyCalleeSavedRegisters: default branch (non-push/pop/mov)
// ---------------------------------------------------------------------------

// TestMicrosoftX64Analyzer_VerifyCalleeSavedRegisters_DefaultBranchModifies tests
// that non-push/pop/mov instructions writing to callee-saved registers mark them modified.
func TestMicrosoftX64Analyzer_VerifyCalleeSavedRegisters_DefaultBranchModifies(t *testing.T) {
	// lea rsi, [rip+0] — writes rsi (callee-saved in ms x64) via lea
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "lea", reg("rsi", disasm.Size64), mem("rip", 0, disasm.Size64)),
		buildInsn(0x1004, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	statuses := a.VerifyCalleeSavedRegisters(insns)

	var rsiStatus *CalleeSavedRegisterStatus
	for i := range statuses {
		if statuses[i].Register == "rsi" {
			rsiStatus = &statuses[i]
			break
		}
	}
	if rsiStatus == nil {
		t.Fatal("rsi not found in ms x64 callee-saved register statuses")
	}
	if rsiStatus.Preserved {
		t.Error("rsi written via lea without save must not be preserved in ms x64")
	}
}

// ---------------------------------------------------------------------------
// microsoftx64.go — VerifyCalleeSavedRegisters: default branch with no operands
// ---------------------------------------------------------------------------

// TestMicrosoftX64Analyzer_VerifyCalleeSavedRegisters_NoOperandInsn tests that
// instructions with no operands in the default branch are safely skipped.
func TestMicrosoftX64Analyzer_VerifyCalleeSavedRegisters_NoOperandInsn(t *testing.T) {
	insns := []*disasm.Instruction{
		// nop has no operands — must not panic in default branch
		buildInsn(0x1000, "nop"),
		buildInsn(0x1001, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	statuses := a.VerifyCalleeSavedRegisters(insns)

	if len(statuses) != 8 {
		t.Errorf("expected 8 callee-saved statuses, got %d", len(statuses))
	}
	for _, s := range statuses {
		if !s.Preserved {
			t.Errorf("register %s must be preserved (never touched), got Preserved=false", s.Register)
		}
	}
}

// ---------------------------------------------------------------------------
// systemv.go — VerifyCalleeSavedRegisters: no operands in default branch
// ---------------------------------------------------------------------------

// TestSystemVAnalyzer_VerifyCalleeSavedRegisters_NoOperandInsn tests that
// instructions with no operands in the default branch are safely skipped.
func TestSystemVAnalyzer_VerifyCalleeSavedRegisters_NoOperandInsn(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "nop"),
		buildInsn(0x1001, "ret"),
	}

	a := NewSystemVAnalyzer()
	statuses := a.VerifyCalleeSavedRegisters(insns)

	if len(statuses) != 6 {
		t.Errorf("expected 6 callee-saved statuses, got %d", len(statuses))
	}
	for _, s := range statuses {
		if !s.Preserved {
			t.Errorf("register %s must be preserved (never touched), got Preserved=false", s.Register)
		}
	}
}

// ---------------------------------------------------------------------------
// systemv.go — IdentifyParameters: rmw instruction reads param register
// ---------------------------------------------------------------------------

// TestSystemVAnalyzer_IdentifyParameters_RMWReadsParam tests that a read-modify-write
// instruction (e.g., inc rdi) correctly identifies rdi as a parameter.
func TestSystemVAnalyzer_IdentifyParameters_RMWReadsParam(t *testing.T) {
	// inc rdi — rdi is both read and written (rmw), so it is a parameter
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "inc", reg("rdi", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rax", disasm.Size64), reg("rdi", disasm.Size64)),
		buildInsn(0x1004, "ret"),
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
		t.Error("rdi used in inc (rmw) before write must be detected as parameter")
	}
}

// ---------------------------------------------------------------------------
// microsoftx64.go — IdentifyParameters: rmw instruction reads param register
// ---------------------------------------------------------------------------

// TestMicrosoftX64Analyzer_IdentifyParameters_RMWReadsParam tests that a
// read-modify-write instruction correctly identifies rcx as a parameter.
func TestMicrosoftX64Analyzer_IdentifyParameters_RMWReadsParam(t *testing.T) {
	// inc rcx — rcx is both read and written (rmw), so it is a parameter
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "inc", reg("rcx", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rax", disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x1004, "ret"),
	}

	a := NewMicrosoftX64Analyzer()
	params := a.IdentifyParameters(insns)

	found := false
	for _, p := range params {
		if p.Register == "rcx" {
			found = true
			break
		}
	}
	if !found {
		t.Error("rcx used in inc (rmw) before write must be detected as parameter in ms x64")
	}
}

// ---------------------------------------------------------------------------
// systemv.go — IdentifyParameters: stop at ret instruction
// ---------------------------------------------------------------------------

// TestSystemVAnalyzer_IdentifyParameters_StopAtRet tests that parameter scanning
// stops at the ret instruction.
func TestSystemVAnalyzer_IdentifyParameters_StopAtRet(t *testing.T) {
	// rdi is read AFTER ret — must not be detected as parameter
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "ret"),
		// this instruction is after ret — must not be scanned
		buildInsn(0x1001, "mov", reg("rax", disasm.Size64), reg("rdi", disasm.Size64)),
	}

	a := NewSystemVAnalyzer()
	params := a.IdentifyParameters(insns)

	for _, p := range params {
		if p.Register == "rdi" {
			t.Error("rdi read after ret must not be detected as parameter")
		}
	}
}

// ---------------------------------------------------------------------------
// microsoftx64.go — IdentifyParameters: stop at retn instruction
// ---------------------------------------------------------------------------

// TestMicrosoftX64Analyzer_IdentifyParameters_StopAtRetn tests that parameter
// scanning stops at the retn instruction.
func TestMicrosoftX64Analyzer_IdentifyParameters_StopAtRetn(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "retn"),
		buildInsn(0x1001, "mov", reg("rax", disasm.Size64), reg("rcx", disasm.Size64)),
	}

	a := NewMicrosoftX64Analyzer()
	params := a.IdentifyParameters(insns)

	for _, p := range params {
		if p.Register == "rcx" {
			t.Error("rcx read after retn must not be detected as parameter")
		}
	}
}

// ---------------------------------------------------------------------------
// systemv.go — handleAddInstruction: add rsp with wrong operand count
// ---------------------------------------------------------------------------

// TestSystemVAnalyzer_TrackStackPointer_AddWrongOperandCount tests that add
// with a single operand (malformed) does not change the tracked offset.
func TestSystemVAnalyzer_TrackStackPointer_AddWrongOperandCount(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		// add with single operand — malformed
		{Address: 0x1004, Mnemonic: "add", Operands: []disasm.Operand{reg("rsp", disasm.Size64)}, Length: 2},
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
		t.Errorf("offset after malformed add: expected -0x10, got %d", c.Value)
	}
}

// TestMicrosoftX64Analyzer_TrackStackPointer_AddWrongOperandCount tests the same
// for Microsoft x64 analyzer.
func TestMicrosoftX64Analyzer_TrackStackPointer_AddWrongOperandCount(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		{Address: 0x1004, Mnemonic: "add", Operands: []disasm.Operand{reg("rsp", disasm.Size64)}, Length: 2},
		buildInsn(0x1006, "nop"),
	}

	a := NewMicrosoftX64Analyzer()
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
		t.Errorf("offset after malformed add: expected -0x10, got %d", c.Value)
	}
}

// ---------------------------------------------------------------------------
// systemv.go — handleAndInstruction: and with wrong operand count
// ---------------------------------------------------------------------------

// TestSystemVAnalyzer_TrackStackPointer_AndWrongOperandCount tests that and
// with a single operand (malformed) does not change the tracked offset.
func TestSystemVAnalyzer_TrackStackPointer_AndWrongOperandCount(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		{Address: 0x1004, Mnemonic: "and", Operands: []disasm.Operand{reg("rsp", disasm.Size64)}, Length: 2},
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
		t.Errorf("offset after malformed and: expected -0x10, got %d", c.Value)
	}
}

// TestMicrosoftX64Analyzer_TrackStackPointer_AndWrongOperandCount tests the same
// for Microsoft x64 analyzer.
func TestMicrosoftX64Analyzer_TrackStackPointer_AndWrongOperandCount(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		{Address: 0x1004, Mnemonic: "and", Operands: []disasm.Operand{reg("rsp", disasm.Size64)}, Length: 2},
		buildInsn(0x1006, "nop"),
	}

	a := NewMicrosoftX64Analyzer()
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
		t.Errorf("offset after malformed and: expected -0x10, got %d", c.Value)
	}
}

// ---------------------------------------------------------------------------
// systemv.go — TrackStackPointer: mov rbp, rsp with symbolic current offset
// ---------------------------------------------------------------------------

// TestSystemVAnalyzer_TrackStackPointer_FramePointerSymbolicRSP tests that
// mov rbp, rsp when RSP is symbolic does NOT set the frame pointer
// (only concrete RSP offsets can establish a frame pointer).
func TestSystemVAnalyzer_TrackStackPointer_FramePointerSymbolicRSP(t *testing.T) {
	insns := []*disasm.Instruction{
		// sub rsp, rax — makes rsp symbolic
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), reg("rax", disasm.Size64)),
		// mov rbp, rsp — rsp is symbolic, frame pointer must NOT be set
		buildInsn(0x1004, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1007, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	// frame pointer must not be set when rsp is symbolic
	if tracker.HasFramePointer() {
		t.Error("frame pointer must not be set when RSP is symbolic at mov rbp,rsp")
	}
}

// TestMicrosoftX64Analyzer_TrackStackPointer_FramePointerSymbolicRSP tests the same
// for Microsoft x64 analyzer.
func TestMicrosoftX64Analyzer_TrackStackPointer_FramePointerSymbolicRSP(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), reg("rcx", disasm.Size64)),
		buildInsn(0x1004, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1007, "nop"),
	}

	a := NewMicrosoftX64Analyzer()
	tracker := a.TrackStackPointer(insns)

	if tracker.HasFramePointer() {
		t.Error("frame pointer must not be set when RSP is symbolic at mov rbp,rsp")
	}
}

// ---------------------------------------------------------------------------
// systemv.go — TrackStackPointer: mov with non-rbp destination is ignored
// ---------------------------------------------------------------------------

// TestSystemVAnalyzer_TrackStackPointer_MovNonRbpDest tests that mov to a
// register other than rbp does not affect frame pointer tracking.
func TestSystemVAnalyzer_TrackStackPointer_MovNonRbpDest(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "sub", reg("rsp", disasm.Size64), imm(0x10, disasm.Size64)),
		// mov rax, rsp — not a frame pointer setup
		buildInsn(0x1004, "mov", reg("rax", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1007, "nop"),
	}

	a := NewSystemVAnalyzer()
	tracker := a.TrackStackPointer(insns)

	if tracker.HasFramePointer() {
		t.Error("mov rax,rsp must not set frame pointer (only mov rbp,rsp does)")
	}
}

// ---------------------------------------------------------------------------
// table-driven: isReadModifyWrite coverage for all supported mnemonics
// ---------------------------------------------------------------------------

// TestIsReadModifyWrite_AllMnemonics verifies isReadModifyWrite returns true
// for all documented rmw mnemonics and false for non-rmw ones.
func TestIsReadModifyWrite_AllMnemonics(t *testing.T) {
	rmwTrue := []string{
		"add", "sub", "adc", "sbb", "and", "or", "xor",
		"imul", "mul", "idiv", "div",
		"shl", "shr", "sar", "rol", "ror", "rcl", "rcr",
		"inc", "dec", "neg", "not",
		"xchg", "xadd",
		"test", "cmp",
		"lea",
	}
	for _, m := range rmwTrue {
		if !isReadModifyWrite(m) {
			t.Errorf("isReadModifyWrite(%q) = false, want true", m)
		}
	}

	rmwFalse := []string{"mov", "push", "pop", "call", "ret", "nop", "jmp", "je", "movsd"}
	for _, m := range rmwFalse {
		if isReadModifyWrite(m) {
			t.Errorf("isReadModifyWrite(%q) = true, want false", m)
		}
	}
}
