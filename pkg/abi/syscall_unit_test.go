package abi

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

func TestSyscallRecovery_RetnBoundaryStopsBackwardScan(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(1, disasm.Size64)),
		buildInsn(0x1004, "retn"),
		buildInsn(0x1005, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number != nil {
		t.Errorf("retn boundary must stop backward scan, got number %d", *sites[0].Number)
	}
}

func TestSyscallRecovery_TestInsnDoesNotBreakScan(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(60, disasm.Size64)),
		buildInsn(0x1007, "test", reg("rax", disasm.Size64), reg("rax", disasm.Size64)),
		buildInsn(0x100a, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 60 {
		t.Errorf("test rax,rax must not break scan, expected 60, got %v", sites[0].Number)
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "exit" {
		t.Errorf("expected 'exit' signature, got %v", sites[0].Signature)
	}
}

func TestSyscallRecovery_CmpInsnDoesNotBreakScan(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("eax", disasm.Size32), imm(1, disasm.Size32)),
		buildInsn(0x1005, "cmp", reg("eax", disasm.Size32), imm(0, disasm.Size32)),
		buildInsn(0x1008, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 1 {
		t.Errorf("cmp eax,imm must not break scan, expected 1, got %v", sites[0].Number)
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "write" {
		t.Errorf("expected 'write' signature, got %v", sites[0].Signature)
	}
}

func TestSyscallRecovery_Sysenter_LinuxWithNumberResolution(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("eax", disasm.Size32), imm(1, disasm.Size32)),
		buildInsn(0x1005, "mov", reg("ebx", disasm.Size32), imm(1, disasm.Size32)),
		buildInsn(0x100a, "sysenter"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 sysenter site, got %d", len(sites))
	}
	if sites[0].Kind != SyscallKindSysenter {
		t.Errorf("expected SyscallKindSysenter, got %v", sites[0].Kind)
	}
	if sites[0].Number == nil || *sites[0].Number != 1 {
		t.Errorf("expected syscall number 1 (write), got %v", sites[0].Number)
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "write" {
		t.Errorf("expected 'write' signature, got %v", sites[0].Signature)
	}
}

func TestSyscallRecovery_Int80_WithNumberResolution(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("eax", disasm.Size32), imm(3, disasm.Size32)),
		buildInsn(0x1005, "int", imm(0x80, disasm.Size8)),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 int 0x80 site, got %d", len(sites))
	}
	if sites[0].Kind != SyscallKindInt80 {
		t.Errorf("expected SyscallKindInt80, got %v", sites[0].Kind)
	}
	if sites[0].Number == nil || *sites[0].Number != 3 {
		t.Errorf("expected syscall number 3, got %v", sites[0].Number)
	}
}

func TestSyscallRecovery_WindowsNT_Int2E_WithNumberResolution(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("eax", disasm.Size32), imm(0x02, disasm.Size32)),
		buildInsn(0x1005, "int", imm(0x2e, disasm.Size8)),
	}

	r := NewSyscallRecovery(OSWindowsNT)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 int 0x2e site, got %d", len(sites))
	}
	if sites[0].Kind != SyscallKindInt2E {
		t.Errorf("expected SyscallKindInt2E, got %v", sites[0].Kind)
	}
	if sites[0].Number == nil || *sites[0].Number != 0x02 {
		t.Errorf("expected syscall number 0x02 (NtCreateFile), got %v", sites[0].Number)
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "NtCreateFile" {
		t.Errorf("expected 'NtCreateFile' signature, got %v", sites[0].Signature)
	}
}

func TestSyscallRecovery_StaticallyLinked_MixedSyscallTypes(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x401000, "mov", reg("eax", disasm.Size32), imm(0, disasm.Size32)),
		buildInsn(0x401005, "syscall"),
		buildInsn(0x401007, "ret"),
		buildInsn(0x401010, "mov", reg("eax", disasm.Size32), imm(1, disasm.Size32)),
		buildInsn(0x401015, "sysenter"),
		buildInsn(0x401017, "ret"),
		buildInsn(0x401020, "mov", reg("eax", disasm.Size32), imm(60, disasm.Size32)),
		buildInsn(0x401025, "int", imm(0x80, disasm.Size8)),
		buildInsn(0x401027, "ret"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 3 {
		t.Fatalf("expected 3 syscall sites, got %d", len(sites))
	}

	if sites[0].Kind != SyscallKindSyscall {
		t.Errorf("site[0]: expected SyscallKindSyscall, got %v", sites[0].Kind)
	}
	if sites[1].Kind != SyscallKindSysenter {
		t.Errorf("site[1]: expected SyscallKindSysenter, got %v", sites[1].Kind)
	}
	if sites[2].Kind != SyscallKindInt80 {
		t.Errorf("site[2]: expected SyscallKindInt80, got %v", sites[2].Kind)
	}

	if sites[0].Number == nil || *sites[0].Number != 0 {
		t.Errorf("site[0]: expected number 0, got %v", sites[0].Number)
	}
	if sites[1].Number == nil || *sites[1].Number != 1 {
		t.Errorf("site[1]: expected number 1, got %v", sites[1].Number)
	}
	if sites[2].Number == nil || *sites[2].Number != 60 {
		t.Errorf("site[2]: expected number 60, got %v", sites[2].Number)
	}
}

func TestSyscallRecovery_GoRuntime_Sigaltstack(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x401000, "mov", reg("rdi", disasm.Size64), reg("r13", disasm.Size64)),
		buildInsn(0x401003, "xor", reg("esi", disasm.Size32), reg("esi", disasm.Size32)),
		buildInsn(0x401005, "mov", reg("eax", disasm.Size32), imm(131, disasm.Size32)),
		buildInsn(0x40100a, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 131 {
		t.Errorf("expected syscall 131, got %v", sites[0].Number)
	}
}

func TestSyscallRecovery_GoRuntime_RtSigaction(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x401000, "mov", reg("edi", disasm.Size32), imm(11, disasm.Size32)),
		buildInsn(0x401005, "lea", reg("rsi", disasm.Size64), mem("rsp", 0x10, disasm.Size64)),
		buildInsn(0x40100a, "xor", reg("edx", disasm.Size32), reg("edx", disasm.Size32)),
		buildInsn(0x40100c, "mov", reg("r10d", disasm.Size32), imm(8, disasm.Size32)),
		buildInsn(0x401012, "mov", reg("eax", disasm.Size32), imm(13, disasm.Size32)),
		buildInsn(0x401017, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 13 {
		t.Errorf("expected syscall 13 (rt_sigaction), got %v", sites[0].Number)
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "rt_sigaction" {
		t.Errorf("expected 'rt_sigaction' signature, got %v", sites[0].Signature)
	}
	if len(sites[0].Signature.Params) != 4 {
		t.Errorf("rt_sigaction must have 4 params, got %d", len(sites[0].Signature.Params))
	}
}

func TestSyscallRecovery_GoRuntime_RtSigprocmask(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x401000, "mov", reg("edi", disasm.Size32), imm(2, disasm.Size32)),
		buildInsn(0x401005, "mov", reg("rsi", disasm.Size64), reg("r14", disasm.Size64)),
		buildInsn(0x401008, "mov", reg("rdx", disasm.Size64), reg("r15", disasm.Size64)),
		buildInsn(0x40100b, "mov", reg("r10d", disasm.Size32), imm(8, disasm.Size32)),
		buildInsn(0x401011, "mov", reg("eax", disasm.Size32), imm(14, disasm.Size32)),
		buildInsn(0x401016, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 14 {
		t.Errorf("expected syscall 14 (rt_sigprocmask), got %v", sites[0].Number)
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "rt_sigprocmask" {
		t.Errorf("expected 'rt_sigprocmask' signature, got %v", sites[0].Signature)
	}
}

func TestSyscallRecovery_DestNotRegister_SkippedInScan(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("eax", disasm.Size32), imm(1, disasm.Size32)),
		buildInsn(0x1005, "mov", mem("rsp", -8, disasm.Size64), imm(42, disasm.Size64)),
		buildInsn(0x100c, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 1 {
		t.Errorf("mov to memory must be skipped, expected number 1, got %v", sites[0].Number)
	}
}

func TestSyscallRecovery_NonRaxRegister_ContinuesScan(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("rax", disasm.Size64), imm(39, disasm.Size64)),
		buildInsn(0x1007, "mov", reg("rbx", disasm.Size64), imm(99, disasm.Size64)),
		buildInsn(0x100e, "mov", reg("rcx", disasm.Size64), imm(88, disasm.Size64)),
		buildInsn(0x1015, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 39 {
		t.Errorf("writes to non-rax registers must not break scan, expected 39, got %v", sites[0].Number)
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "getpid" {
		t.Errorf("expected 'getpid' signature, got %v", sites[0].Signature)
	}
}

func TestSyscallRecovery_WindowsNT_NtTerminateProcess(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x7ffe0000, "mov", reg("eax", disasm.Size32), imm(0x2c, disasm.Size32)),
		buildInsn(0x7ffe0005, "syscall"),
	}

	r := NewSyscallRecovery(OSWindowsNT)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "NtTerminateProcess" {
		t.Errorf("expected 'NtTerminateProcess', got %v", sites[0].Signature)
	}
	if len(sites[0].Signature.Params) != 2 {
		t.Errorf("NtTerminateProcess must have 2 params, got %d", len(sites[0].Signature.Params))
	}
}

func TestSyscallRecovery_WindowsNT_ParamRegisters(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("eax", disasm.Size32), imm(0x12, disasm.Size32)),
		buildInsn(0x1005, "syscall"),
	}

	r := NewSyscallRecovery(OSWindowsNT)
	sites := r.Recover(insns)

	if len(sites) != 1 || sites[0].Signature == nil {
		t.Fatal("expected NtAllocateVirtualMemory signature")
	}

	expectedRegs := []string{"rcx", "rdx", "r8", "r9"}
	params := sites[0].Signature.Params
	if len(params) != 4 {
		t.Fatalf("NtAllocateVirtualMemory must have 4 params, got %d", len(params))
	}
	for i, p := range params {
		if p.Register != expectedRegs[i] {
			t.Errorf("param[%d]: expected register %s, got %s", i, expectedRegs[i], p.Register)
		}
	}
}
