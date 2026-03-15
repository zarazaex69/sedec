package abi

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestClassifySyscallInsn_Syscall verifies detection of the syscall instruction
func TestClassifySyscallInsn_Syscall(t *testing.T) {
	insn := buildInsn(0x1000, "syscall")
	kind, ok := classifySyscallInsn(insn)
	if !ok {
		t.Fatal("expected syscall instruction to be classified")
	}
	if kind != SyscallKindSyscall {
		t.Errorf("expected SyscallKindSyscall, got %v", kind)
	}
}

// TestClassifySyscallInsn_Sysenter verifies detection of the sysenter instruction
func TestClassifySyscallInsn_Sysenter(t *testing.T) {
	insn := buildInsn(0x1000, "sysenter")
	kind, ok := classifySyscallInsn(insn)
	if !ok {
		t.Fatal("expected sysenter instruction to be classified")
	}
	if kind != SyscallKindSysenter {
		t.Errorf("expected SyscallKindSysenter, got %v", kind)
	}
}

// TestClassifySyscallInsn_Int80 verifies detection of int 0x80
func TestClassifySyscallInsn_Int80(t *testing.T) {
	insn := buildInsn(0x1000, "int", imm(0x80, disasm.Size8))
	kind, ok := classifySyscallInsn(insn)
	if !ok {
		t.Fatal("expected int 0x80 to be classified as syscall")
	}
	if kind != SyscallKindInt80 {
		t.Errorf("expected SyscallKindInt80, got %v", kind)
	}
}

// TestClassifySyscallInsn_Int2E verifies detection of int 0x2e (Windows NT)
func TestClassifySyscallInsn_Int2E(t *testing.T) {
	insn := buildInsn(0x1000, "int", imm(0x2e, disasm.Size8))
	kind, ok := classifySyscallInsn(insn)
	if !ok {
		t.Fatal("expected int 0x2e to be classified as syscall")
	}
	if kind != SyscallKindInt2E {
		t.Errorf("expected SyscallKindInt2E, got %v", kind)
	}
}

// TestClassifySyscallInsn_NotSyscall verifies non-syscall instructions are rejected
func TestClassifySyscallInsn_NotSyscall(t *testing.T) {
	cases := []struct {
		mnemonic string
		ops      []disasm.Operand
	}{
		{"mov", []disasm.Operand{reg("rax", disasm.Size64), imm(1, disasm.Size64)}},
		{"call", []disasm.Operand{imm(0x4000, disasm.Size64)}},
		{"int", []disasm.Operand{imm(0x03, disasm.Size8)}}, // int 3 = breakpoint, not syscall
		{"int", []disasm.Operand{imm(0x21, disasm.Size8)}}, // int 0x21 = DOS, not syscall
		{"ret", nil},
	}

	for _, tc := range cases {
		insn := buildInsn(0x1000, tc.mnemonic, tc.ops...)
		_, ok := classifySyscallInsn(insn)
		if ok {
			t.Errorf("instruction %q should NOT be classified as syscall", tc.mnemonic)
		}
	}
}

// TestSyscallRecovery_LinuxRead verifies recovery of Linux read(2) syscall
func TestSyscallRecovery_LinuxRead(t *testing.T) {
	// mov rax, 0 (SYS_read); mov rdi, fd; mov rsi, buf; mov rdx, count; syscall
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(0, disasm.Size64)),
		buildInsn(0x1007, "mov", reg("rdi", disasm.Size64), imm(0, disasm.Size64)),
		buildInsn(0x100e, "mov", reg("rsi", disasm.Size64), mem("rsp", -8, disasm.Size64)),
		buildInsn(0x1012, "mov", reg("rdx", disasm.Size64), imm(4096, disasm.Size64)),
		buildInsn(0x1019, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}

	site := sites[0]
	if site.Address != 0x1019 {
		t.Errorf("site address: expected 0x1019, got 0x%x", site.Address)
	}
	if site.Kind != SyscallKindSyscall {
		t.Errorf("site kind: expected SyscallKindSyscall, got %v", site.Kind)
	}
	if site.Number == nil {
		t.Fatal("syscall number must be resolved")
	}
	if *site.Number != 0 {
		t.Errorf("syscall number: expected 0 (read), got %d", *site.Number)
	}
	if site.Signature == nil {
		t.Fatal("signature must be resolved for known syscall number")
	}
	if site.Signature.Name != "read" {
		t.Errorf("signature name: expected 'read', got %q", site.Signature.Name)
	}
	if len(site.Signature.Params) != 3 {
		t.Errorf("read must have 3 params, got %d", len(site.Signature.Params))
	}
}

// TestSyscallRecovery_LinuxWrite verifies recovery of Linux write(2) syscall
func TestSyscallRecovery_LinuxWrite(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(1, disasm.Size64)),
		buildInsn(0x1007, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "write" {
		t.Errorf("expected 'write' signature, got %v", sites[0].Signature)
	}
}

// TestSyscallRecovery_LinuxExitGroup verifies recovery of exit_group(2)
func TestSyscallRecovery_LinuxExitGroup(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rdi", disasm.Size64), imm(0, disasm.Size64)),
		buildInsn(0x1007, "mov", reg("rax", disasm.Size64), imm(231, disasm.Size64)),
		buildInsn(0x100e, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if *sites[0].Number != 231 {
		t.Errorf("expected syscall 231, got %d", *sites[0].Number)
	}
	if sites[0].Signature.Name != "exit_group" {
		t.Errorf("expected 'exit_group', got %q", sites[0].Signature.Name)
	}
}

// TestSyscallRecovery_XorZeroingIdiom verifies xor eax, eax → syscall 0
func TestSyscallRecovery_XorZeroingIdiom(t *testing.T) {
	// xor eax, eax is the canonical zeroing idiom; syscall number = 0 (read)
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "xor", reg("eax", disasm.Size32), reg("eax", disasm.Size32)),
		buildInsn(0x1002, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil {
		t.Fatal("xor eax,eax must resolve to syscall number 0")
	}
	if *sites[0].Number != 0 {
		t.Errorf("expected syscall 0, got %d", *sites[0].Number)
	}
}

// TestSyscallRecovery_UnknownNumber verifies handling of non-constant rax
func TestSyscallRecovery_UnknownNumber(t *testing.T) {
	// rax is loaded from memory — not statically determinable
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), mem("rdi", 0, disasm.Size64)),
		buildInsn(0x1003, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number != nil {
		t.Errorf("expected nil number for non-constant rax, got %d", *sites[0].Number)
	}
	if sites[0].Signature != nil {
		t.Errorf("expected nil signature when number is unknown")
	}
}

// TestSyscallRecovery_MultipleSites verifies detection of multiple syscall sites
func TestSyscallRecovery_MultipleSites(t *testing.T) {
	insns := []*disasm.Instruction{
		// first syscall: read (0)
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(0, disasm.Size64)),
		buildInsn(0x1007, "syscall"),
		// second syscall: write (1)
		buildInsn(0x1009, "mov", reg("rax", disasm.Size64), imm(1, disasm.Size64)),
		buildInsn(0x1010, "syscall"),
		// third syscall: exit_group (231)
		buildInsn(0x1012, "mov", reg("rax", disasm.Size64), imm(231, disasm.Size64)),
		buildInsn(0x1019, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 3 {
		t.Fatalf("expected 3 syscall sites, got %d", len(sites))
	}

	expectedNames := []string{"read", "write", "exit_group"}
	for i, site := range sites {
		if site.Signature == nil {
			t.Errorf("site[%d]: expected signature, got nil", i)
			continue
		}
		if site.Signature.Name != expectedNames[i] {
			t.Errorf("site[%d]: expected %q, got %q", i, expectedNames[i], site.Signature.Name)
		}
	}
}

// TestSyscallRecovery_NoSyscalls verifies empty result for non-syscall code
func TestSyscallRecovery_NoSyscalls(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "push", reg("rbp", disasm.Size64)),
		buildInsn(0x1001, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)),
		buildInsn(0x1004, "mov", reg("rax", disasm.Size64), imm(42, disasm.Size64)),
		buildInsn(0x100b, "pop", reg("rbp", disasm.Size64)),
		buildInsn(0x100c, "ret"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 0 {
		t.Errorf("expected 0 syscall sites, got %d", len(sites))
	}
}

// TestSyscallRecovery_Int80Linux verifies int 0x80 detection
func TestSyscallRecovery_Int80Linux(t *testing.T) {
	// int 0x80 with eax = 1 (write in ia32 compat — not in amd64 table, so no signature)
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("eax", disasm.Size32), imm(4, disasm.Size32)),
		buildInsn(0x1005, "int", imm(0x80, disasm.Size8)),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Kind != SyscallKindInt80 {
		t.Errorf("expected SyscallKindInt80, got %v", sites[0].Kind)
	}
	if sites[0].Number == nil || *sites[0].Number != 4 {
		t.Errorf("expected syscall number 4, got %v", sites[0].Number)
	}
}

// TestSyscallRecovery_WindowsNT_NtClose verifies Windows NT NtClose recovery
func TestSyscallRecovery_WindowsNT_NtClose(t *testing.T) {
	// NtClose: mov eax, 0x04; syscall
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("eax", disasm.Size32), imm(0x04, disasm.Size32)),
		buildInsn(0x1005, "syscall"),
	}

	r := NewSyscallRecovery(OSWindowsNT)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Signature == nil {
		t.Fatal("expected NtClose signature")
	}
	if sites[0].Signature.Name != "NtClose" {
		t.Errorf("expected 'NtClose', got %q", sites[0].Signature.Name)
	}
}

// TestSyscallRecovery_WindowsNT_NtAllocateVirtualMemory verifies NtAllocateVirtualMemory
func TestSyscallRecovery_WindowsNT_NtAllocateVirtualMemory(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("eax", disasm.Size32), imm(0x12, disasm.Size32)),
		buildInsn(0x1005, "syscall"),
	}

	r := NewSyscallRecovery(OSWindowsNT)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "NtAllocateVirtualMemory" {
		t.Errorf("expected 'NtAllocateVirtualMemory', got %v", sites[0].Signature)
	}
}

// TestSyscallRecovery_NumberResolvedAcrossInstructions verifies backward scan
// skips non-rax instructions correctly
func TestSyscallRecovery_NumberResolvedAcrossInstructions(t *testing.T) {
	// rax set early, then other registers set, then syscall
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(9, disasm.Size64)), // mmap
		buildInsn(0x1007, "mov", reg("rdi", disasm.Size64), imm(0, disasm.Size64)),
		buildInsn(0x100e, "mov", reg("rsi", disasm.Size64), imm(4096, disasm.Size64)),
		buildInsn(0x1015, "mov", reg("rdx", disasm.Size64), imm(3, disasm.Size64)),
		buildInsn(0x101c, "mov", reg("r10", disasm.Size64), imm(0x22, disasm.Size64)),
		buildInsn(0x1023, "mov", reg("r8", disasm.Size64), imm(-1, disasm.Size64)),
		buildInsn(0x102a, "mov", reg("r9", disasm.Size64), imm(0, disasm.Size64)),
		buildInsn(0x1031, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "mmap" {
		t.Errorf("expected 'mmap', got %v", sites[0].Signature)
	}
	if len(sites[0].Signature.Params) != 6 {
		t.Errorf("mmap must have 6 params, got %d", len(sites[0].Signature.Params))
	}
}

// TestSyscallRecovery_CallBoundaryStopsBackwardScan verifies that a call
// instruction terminates the backward scan for the syscall number
func TestSyscallRecovery_CallBoundaryStopsBackwardScan(t *testing.T) {
	// rax set before a call, then syscall — the call boundary must stop the scan
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(0, disasm.Size64)),
		buildInsn(0x1007, "call", imm(0x2000, disasm.Size64)), // call clobbers rax
		buildInsn(0x100c, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	// number must be nil because the call boundary stops the backward scan
	if sites[0].Number != nil {
		t.Errorf("expected nil number after call boundary, got %d", *sites[0].Number)
	}
}

// TestSyscallRecovery_SyscallKindString verifies string representation
func TestSyscallRecovery_SyscallKindString(t *testing.T) {
	cases := []struct {
		kind SyscallKind
		want string
	}{
		{SyscallKindSyscall, "syscall"},
		{SyscallKindSysenter, "sysenter"},
		{SyscallKindInt80, "int 0x80"},
		{SyscallKindInt2E, "int 0x2e"},
	}
	for _, tc := range cases {
		if got := tc.kind.String(); got != tc.want {
			t.Errorf("SyscallKind(%d).String() = %q, want %q", tc.kind, got, tc.want)
		}
	}
}

// TestSyscallRecovery_OSKindString verifies OS kind string representation
func TestSyscallRecovery_OSKindString(t *testing.T) {
	if got := OSLinuxAMD64.String(); got != "Linux_AMD64" {
		t.Errorf("OSLinuxAMD64.String() = %q, want 'Linux_AMD64'", got)
	}
	if got := OSWindowsNT.String(); got != "Windows_NT" {
		t.Errorf("OSWindowsNT.String() = %q, want 'Windows_NT'", got)
	}
}

// TestLinuxSyscallTable_Completeness verifies that the Linux table has no duplicate numbers
func TestLinuxSyscallTable_Completeness(t *testing.T) {
	seen := make(map[uint64]string)
	for num, sig := range linuxAMD64SyscallTable {
		if prev, exists := seen[num]; exists {
			t.Errorf("duplicate syscall number %d: %q and %q", num, prev, sig.Name)
		}
		seen[num] = sig.Name
		// verify the number field matches the map key
		if sig.Number != num {
			t.Errorf("syscall %q: map key %d != sig.Number %d", sig.Name, num, sig.Number)
		}
		// verify OS field
		if sig.OS != OSLinuxAMD64 {
			t.Errorf("syscall %q: expected OS=OSLinuxAMD64, got %v", sig.Name, sig.OS)
		}
	}
}

// TestWindowsSyscallTable_Completeness verifies that the Windows table has no duplicate numbers
func TestWindowsSyscallTable_Completeness(t *testing.T) {
	seen := make(map[uint64]string)
	for num, sig := range windowsNTSyscallTable {
		if prev, exists := seen[num]; exists {
			t.Errorf("duplicate syscall number 0x%x: %q and %q", num, prev, sig.Name)
		}
		seen[num] = sig.Name
		if sig.Number != num {
			t.Errorf("syscall %q: map key 0x%x != sig.Number 0x%x", sig.Name, num, sig.Number)
		}
		if sig.OS != OSWindowsNT {
			t.Errorf("syscall %q: expected OS=OSWindowsNT, got %v", sig.Name, sig.OS)
		}
	}
}

// TestSyscallRecovery_EmptyInstructions verifies graceful handling of empty input
func TestSyscallRecovery_EmptyInstructions(t *testing.T) {
	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(nil)
	if len(sites) != 0 {
		t.Errorf("expected 0 sites for nil input, got %d", len(sites))
	}

	sites = r.Recover([]*disasm.Instruction{})
	if len(sites) != 0 {
		t.Errorf("expected 0 sites for empty input, got %d", len(sites))
	}
}

// TestSyscallRecovery_SyscallAtStart verifies syscall as first instruction (no backward scan)
func TestSyscallRecovery_SyscallAtStart(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	// no preceding instructions — number must be nil
	if sites[0].Number != nil {
		t.Errorf("expected nil number for syscall with no preceding instructions")
	}
}
