package abi

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestClassifySyscallInsn_Int70_NotSyscall verifies that int 0x70 is NOT classified
// as a syscall — the task description mentions int 0x70 but the actual kernel
// syscall vectors are 0x80 (linux ia32) and 0x2e (windows nt); 0x70 is a
// user-defined software interrupt unrelated to syscall dispatch.
func TestClassifySyscallInsn_Int70_NotSyscall(t *testing.T) {
	insn := buildInsn(0x1000, "int", imm(0x70, disasm.Size8))
	_, ok := classifySyscallInsn(insn)
	if ok {
		t.Error("int 0x70 must NOT be classified as a syscall instruction")
	}
}

// TestClassifySyscallInsn_Int_NoOperands verifies that bare int without operands
// does not panic and returns false.
func TestClassifySyscallInsn_Int_NoOperands(t *testing.T) {
	insn := buildInsn(0x1000, "int")
	_, ok := classifySyscallInsn(insn)
	if ok {
		t.Error("int with no operands must not be classified as syscall")
	}
}

// TestClassifySyscallInsn_Int_RegisterOperand verifies that int with a register
// operand (malformed encoding) does not panic and returns false.
func TestClassifySyscallInsn_Int_RegisterOperand(t *testing.T) {
	insn := buildInsn(0x1000, "int", reg("al", disasm.Size8))
	_, ok := classifySyscallInsn(insn)
	if ok {
		t.Error("int with register operand must not be classified as syscall")
	}
}

// TestSyscallRecovery_StaticallyLinked_GlibcWrapper tests the canonical glibc
// syscall wrapper pattern found in statically-linked binaries.
// glibc wraps each syscall as: mov eax, NR; syscall; ret
// there is no call boundary between the mov and the syscall.
func TestSyscallRecovery_StaticallyLinked_GlibcWrapper(t *testing.T) {
	// simulates the glibc read() wrapper body in a statically-linked binary:
	//   mov eax, 0   ; SYS_read
	//   syscall
	//   ret
	insns := []*disasm.Instruction{
		buildInsn(0x401000, "mov", reg("eax", disasm.Size32), imm(0, disasm.Size32)),
		buildInsn(0x401005, "syscall"),
		buildInsn(0x401007, "ret"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site in glibc wrapper, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 0 {
		t.Errorf("expected syscall number 0 (read), got %v", sites[0].Number)
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "read" {
		t.Errorf("expected 'read' signature, got %v", sites[0].Signature)
	}
}

// TestSyscallRecovery_StaticallyLinked_MultipleWrappers tests a sequence of
// glibc-style wrappers as they appear in a statically-linked binary's .text section.
// each wrapper is a self-contained mov+syscall+ret triple.
func TestSyscallRecovery_StaticallyLinked_MultipleWrappers(t *testing.T) {
	// three consecutive glibc wrappers: write(1), open(2), close(3)
	insns := []*disasm.Instruction{
		// write wrapper
		buildInsn(0x401000, "mov", reg("eax", disasm.Size32), imm(1, disasm.Size32)),
		buildInsn(0x401005, "syscall"),
		buildInsn(0x401007, "ret"),
		// open wrapper
		buildInsn(0x401010, "mov", reg("eax", disasm.Size32), imm(2, disasm.Size32)),
		buildInsn(0x401015, "syscall"),
		buildInsn(0x401017, "ret"),
		// close wrapper
		buildInsn(0x401020, "mov", reg("eax", disasm.Size32), imm(3, disasm.Size32)),
		buildInsn(0x401025, "syscall"),
		buildInsn(0x401027, "ret"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 3 {
		t.Fatalf("expected 3 syscall sites, got %d", len(sites))
	}

	expected := []struct {
		num  uint64
		name string
	}{
		{1, "write"},
		{2, "open"},
		{3, "close"},
	}

	for i, e := range expected {
		if sites[i].Number == nil || *sites[i].Number != e.num {
			t.Errorf("site[%d]: expected number %d, got %v", i, e.num, sites[i].Number)
		}
		if sites[i].Signature == nil || sites[i].Signature.Name != e.name {
			t.Errorf("site[%d]: expected %q, got %v", i, e.name, sites[i].Signature)
		}
	}
}

// TestSyscallRecovery_StaticallyLinked_RetBoundaryIsolatesWrappers verifies that
// the ret instruction between two wrappers correctly isolates their syscall numbers.
// the backward scan must stop at ret, so the second syscall cannot see the first mov.
func TestSyscallRecovery_StaticallyLinked_RetBoundaryIsolatesWrappers(t *testing.T) {
	// first wrapper sets rax=1 (write), then ret, then second syscall with no preceding mov
	insns := []*disasm.Instruction{
		buildInsn(0x401000, "mov", reg("eax", disasm.Size32), imm(1, disasm.Size32)),
		buildInsn(0x401005, "syscall"),
		buildInsn(0x401007, "ret"),
		// second syscall: no preceding mov — number must be nil
		buildInsn(0x401010, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 2 {
		t.Fatalf("expected 2 syscall sites, got %d", len(sites))
	}
	// first site: number resolved
	if sites[0].Number == nil || *sites[0].Number != 1 {
		t.Errorf("first site: expected number 1, got %v", sites[0].Number)
	}
	// second site: ret boundary stops backward scan — number must be nil
	if sites[1].Number != nil {
		t.Errorf("second site: ret boundary must prevent number resolution, got %d", *sites[1].Number)
	}
}

// TestSyscallRecovery_GoRuntime_ArchPrctl verifies recovery of arch_prctl(158),
// which the Go runtime uses at startup to set the FS base register for TLS
// (goroutine-local storage). pattern: mov edi, 0x1002; mov rax, 158; syscall
func TestSyscallRecovery_GoRuntime_ArchPrctl(t *testing.T) {
	// go runtime startup: arch_prctl(ARCH_SET_FS, tls_base)
	// ARCH_SET_FS = 0x1002
	insns := []*disasm.Instruction{
		buildInsn(0x401000, "mov", reg("edi", disasm.Size32), imm(0x1002, disasm.Size32)),
		buildInsn(0x401005, "mov", reg("rsi", disasm.Size64), reg("r14", disasm.Size64)),
		buildInsn(0x401008, "mov", reg("eax", disasm.Size32), imm(158, disasm.Size32)),
		buildInsn(0x40100d, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 158 {
		t.Errorf("expected syscall 158 (arch_prctl), got %v", sites[0].Number)
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "arch_prctl" {
		t.Errorf("expected 'arch_prctl' signature, got %v", sites[0].Signature)
	}
	if len(sites[0].Signature.Params) != 2 {
		t.Errorf("arch_prctl must have 2 params, got %d", len(sites[0].Signature.Params))
	}
}

// TestSyscallRecovery_GoRuntime_Futex verifies recovery of futex(202), which the
// Go runtime uses extensively for goroutine scheduling and mutex implementation.
// pattern: mov eax, 202; syscall
func TestSyscallRecovery_GoRuntime_Futex(t *testing.T) {
	// go runtime futex call: futex(addr, FUTEX_WAIT, val, timeout, nil, 0)
	insns := []*disasm.Instruction{
		buildInsn(0x401000, "mov", reg("rdi", disasm.Size64), reg("r13", disasm.Size64)),
		buildInsn(0x401003, "mov", reg("esi", disasm.Size32), imm(0, disasm.Size32)),
		buildInsn(0x401008, "mov", reg("edx", disasm.Size32), imm(1, disasm.Size32)),
		buildInsn(0x40100d, "xor", reg("r10d", disasm.Size32), reg("r10d", disasm.Size32)),
		buildInsn(0x401010, "mov", reg("eax", disasm.Size32), imm(202, disasm.Size32)),
		buildInsn(0x401015, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 202 {
		t.Errorf("expected syscall 202 (futex), got %v", sites[0].Number)
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "futex" {
		t.Errorf("expected 'futex' signature, got %v", sites[0].Signature)
	}
	// futex has 6 parameters
	if len(sites[0].Signature.Params) != 6 {
		t.Errorf("futex must have 6 params, got %d", len(sites[0].Signature.Params))
	}
}

// TestSyscallRecovery_GoRuntime_Clone verifies recovery of clone(56), which the
// Go runtime uses to create OS threads for new goroutine M (machine) objects.
// pattern: mov eax, 56; syscall
func TestSyscallRecovery_GoRuntime_Clone(t *testing.T) {
	// go runtime: clone(CLONE_VM|CLONE_FS|..., stack, &parent_tid, &child_tid, tls)
	insns := []*disasm.Instruction{
		buildInsn(0x401000, "mov", reg("rdi", disasm.Size64), imm(0x3d0f00, disasm.Size64)),
		buildInsn(0x401007, "mov", reg("rsi", disasm.Size64), reg("r8", disasm.Size64)),
		buildInsn(0x40100a, "mov", reg("rdx", disasm.Size64), reg("r9", disasm.Size64)),
		buildInsn(0x40100d, "mov", reg("r10", disasm.Size64), reg("r11", disasm.Size64)),
		buildInsn(0x401010, "mov", reg("r8", disasm.Size64), reg("r12", disasm.Size64)),
		buildInsn(0x401013, "mov", reg("eax", disasm.Size32), imm(56, disasm.Size32)),
		buildInsn(0x401018, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 56 {
		t.Errorf("expected syscall 56 (clone), got %v", sites[0].Number)
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "clone" {
		t.Errorf("expected 'clone' signature, got %v", sites[0].Signature)
	}
	if len(sites[0].Signature.Params) != 5 {
		t.Errorf("clone must have 5 params, got %d", len(sites[0].Signature.Params))
	}
}

// TestSyscallRecovery_GoRuntime_Mmap verifies recovery of mmap(9), used by the
// Go runtime for heap allocation and goroutine stack allocation.
func TestSyscallRecovery_GoRuntime_Mmap(t *testing.T) {
	// go runtime: mmap(nil, size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0)
	insns := []*disasm.Instruction{
		buildInsn(0x401000, "xor", reg("edi", disasm.Size32), reg("edi", disasm.Size32)),
		buildInsn(0x401002, "mov", reg("rsi", disasm.Size64), imm(65536, disasm.Size64)),
		buildInsn(0x401009, "mov", reg("edx", disasm.Size32), imm(3, disasm.Size32)),
		buildInsn(0x40100e, "mov", reg("r10d", disasm.Size32), imm(0x22, disasm.Size32)),
		buildInsn(0x401013, "mov", reg("r8d", disasm.Size32), imm(-1, disasm.Size32)),
		buildInsn(0x401018, "xor", reg("r9d", disasm.Size32), reg("r9d", disasm.Size32)),
		buildInsn(0x40101b, "mov", reg("eax", disasm.Size32), imm(9, disasm.Size32)),
		buildInsn(0x401020, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 9 {
		t.Errorf("expected syscall 9 (mmap), got %v", sites[0].Number)
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "mmap" {
		t.Errorf("expected 'mmap' signature, got %v", sites[0].Signature)
	}
}

// TestSyscallRecovery_GoRuntime_ExitGroup verifies recovery of exit_group(231),
// used by the Go runtime for os.Exit() and panic termination.
func TestSyscallRecovery_GoRuntime_ExitGroup(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x401000, "mov", reg("edi", disasm.Size32), reg("ebx", disasm.Size32)),
		buildInsn(0x401002, "mov", reg("eax", disasm.Size32), imm(231, disasm.Size32)),
		buildInsn(0x401007, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 231 {
		t.Errorf("expected syscall 231 (exit_group), got %v", sites[0].Number)
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "exit_group" {
		t.Errorf("expected 'exit_group' signature, got %v", sites[0].Signature)
	}
}

// TestSyscallRecovery_GoRuntime_GetTID verifies recovery of gettid(186),
// used by the Go runtime to identify OS thread IDs for goroutine scheduling.
func TestSyscallRecovery_GoRuntime_GetTID(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x401000, "mov", reg("eax", disasm.Size32), imm(186, disasm.Size32)),
		buildInsn(0x401005, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 186 {
		t.Errorf("expected syscall 186 (gettid), got %v", sites[0].Number)
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "gettid" {
		t.Errorf("expected 'gettid' signature, got %v", sites[0].Signature)
	}
}

// TestSyscallRecovery_GoRuntime_Sequence verifies a realistic Go runtime startup
// sequence: arch_prctl → mmap → clone → futex, as seen in statically-linked Go binaries.
func TestSyscallRecovery_GoRuntime_Sequence(t *testing.T) {
	insns := []*disasm.Instruction{
		// arch_prctl: set FS base for TLS
		buildInsn(0x401000, "mov", reg("eax", disasm.Size32), imm(158, disasm.Size32)),
		buildInsn(0x401005, "syscall"),
		buildInsn(0x401007, "ret"),
		// mmap: allocate goroutine stack
		buildInsn(0x401010, "mov", reg("eax", disasm.Size32), imm(9, disasm.Size32)),
		buildInsn(0x401015, "syscall"),
		buildInsn(0x401017, "ret"),
		// clone: create OS thread
		buildInsn(0x401020, "mov", reg("eax", disasm.Size32), imm(56, disasm.Size32)),
		buildInsn(0x401025, "syscall"),
		buildInsn(0x401027, "ret"),
		// futex: goroutine park/unpark
		buildInsn(0x401030, "mov", reg("eax", disasm.Size32), imm(202, disasm.Size32)),
		buildInsn(0x401035, "syscall"),
		buildInsn(0x401037, "ret"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 4 {
		t.Fatalf("expected 4 syscall sites in Go runtime sequence, got %d", len(sites))
	}

	expected := []struct {
		num  uint64
		name string
	}{
		{158, "arch_prctl"},
		{9, "mmap"},
		{56, "clone"},
		{202, "futex"},
	}

	for i, e := range expected {
		if sites[i].Number == nil || *sites[i].Number != e.num {
			t.Errorf("site[%d]: expected number %d, got %v", i, e.num, sites[i].Number)
		}
		if sites[i].Signature == nil || sites[i].Signature.Name != e.name {
			t.Errorf("site[%d]: expected %q, got %v", i, e.name, sites[i].Signature)
		}
	}
}

// TestSyscallRecovery_Sysenter_WindowsNT_Pattern verifies sysenter detection in
// the Windows NT syscall stub pattern used by ntdll.dll on 32-bit compat mode.
// pattern: mov eax, NR; mov edx, 0x7ffe0300; call [edx]; ret
// the sysenter itself is inside the KUSER_SHARED_DATA page — we test the stub.
func TestSyscallRecovery_Sysenter_DirectDetection(t *testing.T) {
	// direct sysenter instruction (as seen in some Windows 32-bit stubs)
	insns := []*disasm.Instruction{
		buildInsn(0x7ffe0300, "mov", reg("eax", disasm.Size32), imm(0x04, disasm.Size32)),
		buildInsn(0x7ffe0305, "sysenter"),
	}

	r := NewSyscallRecovery(OSWindowsNT)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 sysenter site, got %d", len(sites))
	}
	if sites[0].Kind != SyscallKindSysenter {
		t.Errorf("expected SyscallKindSysenter, got %v", sites[0].Kind)
	}
	if sites[0].Number == nil || *sites[0].Number != 0x04 {
		t.Errorf("expected syscall number 0x04 (NtClose), got %v", sites[0].Number)
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "NtClose" {
		t.Errorf("expected 'NtClose' signature, got %v", sites[0].Signature)
	}
}

// TestSyscallRecovery_NumberResolution_EaxAlias verifies that eax (32-bit alias)
// is correctly canonicalized to rax for syscall number resolution.
// this is critical for statically-linked binaries where compilers emit mov eax, NR
// (4 bytes) instead of mov rax, NR (7 bytes) for the zero-extension optimization.
func TestSyscallRecovery_NumberResolution_EaxAlias(t *testing.T) {
	// mov eax, 60 (exit) — 32-bit form, zero-extends to rax
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("eax", disasm.Size32), imm(60, disasm.Size32)),
		buildInsn(0x1005, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 60 {
		t.Errorf("expected syscall 60 (exit) via eax alias, got %v", sites[0].Number)
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "exit" {
		t.Errorf("expected 'exit' signature, got %v", sites[0].Signature)
	}
}

// TestSyscallRecovery_NumberResolution_AxAlias verifies that ax (16-bit alias)
// is correctly canonicalized to rax.
func TestSyscallRecovery_NumberResolution_AxAlias(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("ax", disasm.Size16), imm(39, disasm.Size16)),
		buildInsn(0x1003, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 39 {
		t.Errorf("expected syscall 39 (getpid) via ax alias, got %v", sites[0].Number)
	}
	if sites[0].Signature == nil || sites[0].Signature.Name != "getpid" {
		t.Errorf("expected 'getpid' signature, got %v", sites[0].Signature)
	}
}

// TestSyscallRecovery_UnknownSyscallNumber_NoSignature verifies that a resolved
// syscall number not present in the table produces a site with Number set but
// Signature nil — this is the correct behavior for unknown/undocumented syscalls.
func TestSyscallRecovery_UnknownSyscallNumber_NoSignature(t *testing.T) {
	// syscall number 9999 — not in any table
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("eax", disasm.Size32), imm(9999, disasm.Size32)),
		buildInsn(0x1005, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Number == nil || *sites[0].Number != 9999 {
		t.Errorf("expected number 9999, got %v", sites[0].Number)
	}
	// number is known but not in table — signature must be nil
	if sites[0].Signature != nil {
		t.Errorf("expected nil signature for unknown syscall 9999, got %v", sites[0].Signature)
	}
}

// TestSyscallRecovery_LinuxTable_ClonePresent verifies that clone(56) is present
// in the Linux syscall table — required for Go runtime analysis.
func TestSyscallRecovery_LinuxTable_ClonePresent(t *testing.T) {
	sig, ok := linuxAMD64SyscallTable[56]
	if !ok {
		t.Fatal("clone (syscall 56) must be present in linuxAMD64SyscallTable")
	}
	if sig.Name != "clone" {
		t.Errorf("syscall 56: expected name 'clone', got %q", sig.Name)
	}
	if len(sig.Params) != 5 {
		t.Errorf("clone must have 5 params (flags, stack, parent_tid, child_tid, tls), got %d", len(sig.Params))
	}
	// verify parameter registers follow Linux syscall ABI
	expectedRegs := []string{"rdi", "rsi", "rdx", "r10", "r8"}
	for i, p := range sig.Params {
		if p.Register != expectedRegs[i] {
			t.Errorf("clone param[%d]: expected register %s, got %s", i, expectedRegs[i], p.Register)
		}
	}
}

// TestSyscallRecovery_LinuxTable_GoRuntimeSyscalls verifies that all syscalls
// used by the Go runtime are present in the Linux table with correct numbers.
func TestSyscallRecovery_LinuxTable_GoRuntimeSyscalls(t *testing.T) {
	// syscalls that every statically-linked Go binary will invoke
	required := map[uint64]string{
		9:   "mmap",
		56:  "clone",
		158: "arch_prctl",
		186: "gettid",
		202: "futex",
		231: "exit_group",
	}

	for num, name := range required {
		sig, ok := linuxAMD64SyscallTable[num]
		if !ok {
			t.Errorf("Go runtime syscall %d (%s) missing from linuxAMD64SyscallTable", num, name)
			continue
		}
		if sig.Name != name {
			t.Errorf("syscall %d: expected name %q, got %q", num, name, sig.Name)
		}
		if sig.Number != num {
			t.Errorf("syscall %q: Number field %d != map key %d", name, sig.Number, num)
		}
	}
}

// TestSyscallRecovery_SyscallSiteAddress verifies that the Address field of each
// SyscallSite points to the syscall/sysenter/int instruction itself, not to the
// preceding mov instruction.
func TestSyscallRecovery_SyscallSiteAddress(t *testing.T) {
	insns := []*disasm.Instruction{
		buildInsn(0x401000, "mov", reg("eax", disasm.Size32), imm(1, disasm.Size32)),
		buildInsn(0x401005, "syscall"), // address of syscall instruction
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 {
		t.Fatalf("expected 1 syscall site, got %d", len(sites))
	}
	if sites[0].Address != 0x401005 {
		t.Errorf("site address must point to syscall instruction (0x401005), got 0x%x", sites[0].Address)
	}
}

// TestSyscallRecovery_SignatureParamRegisters verifies that parameter registers
// in recovered signatures match the Linux syscall ABI (rdi, rsi, rdx, r10, r8, r9).
func TestSyscallRecovery_SignatureParamRegisters(t *testing.T) {
	// mmap has 6 params using all 6 syscall ABI registers
	insns := []*disasm.Instruction{
		buildInsn(0x1000, "mov", reg("eax", disasm.Size32), imm(9, disasm.Size32)),
		buildInsn(0x1005, "syscall"),
	}

	r := NewSyscallRecovery(OSLinuxAMD64)
	sites := r.Recover(insns)

	if len(sites) != 1 || sites[0].Signature == nil {
		t.Fatal("expected mmap signature")
	}

	// linux syscall ABI: arg1=rdi, arg2=rsi, arg3=rdx, arg4=r10, arg5=r8, arg6=r9
	// note: r10 (not rcx) is used for arg4 in syscall ABI (rcx is clobbered by syscall)
	expectedRegs := []string{"rdi", "rsi", "rdx", "r10", "r8", "r9"}
	params := sites[0].Signature.Params
	if len(params) != 6 {
		t.Fatalf("mmap must have 6 params, got %d", len(params))
	}
	for i, p := range params {
		if p.Register != expectedRegs[i] {
			t.Errorf("mmap param[%d]: expected register %s, got %s", i, expectedRegs[i], p.Register)
		}
	}
}
