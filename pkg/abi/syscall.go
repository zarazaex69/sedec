// Package abi — syscall recovery for x86_64 Linux and Windows NT.
// detects syscall/sysenter/int 0x80 instructions, tracks the syscall number
// via backward data flow on RAX/EAX, and maps numbers to OS-specific signatures.
package abi

import (
	"strings"

	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// OSKind identifies the target operating system for syscall table selection.
type OSKind int

const (
	// OSLinuxAMD64 selects the Linux x86_64 syscall table (syscall ABI).
	OSLinuxAMD64 OSKind = iota
	// OSWindowsNT selects the Windows NT Native API syscall table (int 2e / syscall).
	OSWindowsNT
)

const unknownStr = "Unknown"

// os kind string constants
const (
	osLinuxAMD64Str = "Linux_AMD64"
	osWindowsNTStr  = "Windows_NT"
)

// syscall kind string constants
const (
	mnemonicSyscall  = "syscall"
	mnemonicSysenter = "sysenter"
	mnemonicXor      = "xor"
)

func (o OSKind) String() string {
	switch o {
	case OSLinuxAMD64:
		return osLinuxAMD64Str
	case OSWindowsNT:
		return osWindowsNTStr
	default:
		return unknownStr
	}
}

// SyscallKind identifies the instruction used to invoke the kernel.
type SyscallKind int

const (
	// SyscallKindSyscall is the modern x86_64 syscall instruction (Linux, Windows 8+).
	SyscallKindSyscall SyscallKind = iota
	// SyscallKindSysenter is the fast system call instruction (Linux ia32, Windows).
	SyscallKindSysenter
	// SyscallKindInt80 is the legacy int 0x80 software interrupt (Linux ia32 compat).
	SyscallKindInt80
	// SyscallKindInt2E is the Windows NT int 0x2e software interrupt.
	SyscallKindInt2E
)

func (k SyscallKind) String() string {
	switch k {
	case SyscallKindSyscall:
		return mnemonicSyscall
	case SyscallKindSysenter:
		return mnemonicSysenter
	case SyscallKindInt80:
		return "int 0x80"
	case SyscallKindInt2E:
		return "int 0x2e"
	default:
		return "unknown"
	}
}

// SyscallParam describes a single parameter of a syscall.
type SyscallParam struct {
	Name     string  // parameter name from OS documentation
	Type     ir.Type // inferred type
	Register string  // register carrying this parameter
}

// SyscallSignature describes the complete signature of a known syscall.
type SyscallSignature struct {
	Name       string         // syscall name (e.g., "read", "NtWriteFile")
	Number     uint64         // syscall number
	OS         OSKind         // target OS
	ReturnType ir.Type        // return type (typically ssize_t or NTSTATUS)
	Params     []SyscallParam // ordered parameter list
}

// SyscallSite represents a detected syscall invocation in the binary.
type SyscallSite struct {
	Address   disasm.Address    // address of the syscall/sysenter/int instruction
	Kind      SyscallKind       // instruction kind
	Number    *uint64           // resolved syscall number (nil if not statically determinable)
	Signature *SyscallSignature // matched signature (nil if number unknown or not in table)
}

// SyscallRecovery performs syscall detection and signature resolution for a
// sequence of disassembled instructions.
//
// algorithm:
//  1. scan instructions for syscall/sysenter/int 0x80/int 0x2e
//  2. for each site, walk backwards to find the last write to rax/eax
//     before the syscall instruction — that value is the syscall number
//  3. look up the number in the OS-specific syscall table
//  4. return all detected SyscallSite records
type SyscallRecovery struct {
	os OSKind
}

// NewSyscallRecovery creates a syscall recovery analyzer for the given OS.
func NewSyscallRecovery(os OSKind) *SyscallRecovery {
	return &SyscallRecovery{os: os}
}

// Recover scans the instruction sequence and returns all detected syscall sites.
// the instructions must be in program order (ascending address).
func (r *SyscallRecovery) Recover(insns []*disasm.Instruction) []SyscallSite {
	var sites []SyscallSite

	for i, insn := range insns {
		kind, isSyscall := classifySyscallInsn(insn)
		if !isSyscall {
			continue
		}

		// backward scan from i-1 to find the last rax/eax write
		num := r.resolveNumber(insns, i)

		site := SyscallSite{
			Address: insn.Address,
			Kind:    kind,
			Number:  num,
		}

		if num != nil {
			table := selectTable(r.os)
			if sig, ok := table[*num]; ok {
				site.Signature = &sig
			}
		}

		sites = append(sites, site)
	}

	return sites
}

// classifySyscallInsn returns the SyscallKind if the instruction is a syscall
// invocation, and false otherwise.
func classifySyscallInsn(insn *disasm.Instruction) (SyscallKind, bool) {
	m := strings.ToLower(insn.Mnemonic)
	switch m {
	case mnemonicSyscall:
		return SyscallKindSyscall, true
	case mnemonicSysenter:
		return SyscallKindSysenter, true
	case "int":
		// int 0x80 (linux ia32 compat) or int 0x2e (windows nt)
		if len(insn.Operands) == 1 {
			if imm, ok := insn.Operands[0].(disasm.ImmediateOperand); ok {
				switch imm.Value {
				case 0x80:
					return SyscallKindInt80, true
				case 0x2e:
					return SyscallKindInt2E, true
				}
			}
		}
	}
	return 0, false
}

// resolveNumber performs backward data flow on rax/eax to find the syscall number.
// it walks backwards from the instruction at index siteIdx and returns the first
// constant written to rax or eax. returns nil if the value is not statically known.
func (r *SyscallRecovery) resolveNumber(insns []*disasm.Instruction, siteIdx int) *uint64 {
	for i := siteIdx - 1; i >= 0; i-- {
		insn := insns[i]
		m := strings.ToLower(insn.Mnemonic)

		// stop at call boundaries — the syscall number must be set in this basic block
		if m == "call" || m == "ret" || m == "retn" {
			break
		}

		if len(insn.Operands) < 2 {
			continue
		}

		// check if destination is rax or eax
		destReg, ok := insn.Operands[0].(disasm.RegisterOperand)
		if !ok {
			continue
		}
		canonical := canonicalizeRegister(strings.ToLower(destReg.Name))
		if canonical != "rax" {
			continue
		}

		// mov rax/eax, imm — direct constant assignment
		if m == "mov" {
			if immOp, ok := insn.Operands[1].(disasm.ImmediateOperand); ok {
				//nolint:gosec // syscall numbers are non-negative
				v := uint64(immOp.Value)
				return &v
			}
		}

		// xor eax, eax — zeroing idiom (syscall 0)
		if (m == mnemonicXor || m == "xorps") && len(insn.Operands) == 2 {
			src, ok := insn.Operands[1].(disasm.RegisterOperand)
			if ok && canonicalizeRegister(strings.ToLower(src.Name)) == "rax" {
				v := uint64(0)
				return &v
			}
		}

		// any other write to rax means the value is not statically known
		if m != mnemonicTest && m != mnemonicCmp {
			break
		}
	}

	return nil
}

// selectTable returns the syscall signature table for the given OS.
func selectTable(os OSKind) map[uint64]SyscallSignature {
	switch os {
	case OSLinuxAMD64:
		return linuxAMD64SyscallTable
	case OSWindowsNT:
		return windowsNTSyscallTable
	default:
		return linuxAMD64SyscallTable
	}
}
