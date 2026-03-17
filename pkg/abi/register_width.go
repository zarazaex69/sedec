package abi

import "github.com/zarazaex69/sedec/pkg/ir"

// RegisterWidthFromName returns the operand width in bytes for a given x86-64
// register name. the width is determined by the register alias:
//   - 64-bit (rax, rdi, r8, ...): 8
//   - 32-bit (eax, edi, r8d, ...): 4
//   - 16-bit (ax, di, r8w, ...): 2
//   - 8-bit  (al, ah, dil, r8b, ...): 1
//   - xmm registers: 16
//
// returns 8 (64-bit) for unrecognized names as a safe default.
func RegisterWidthFromName(name string) ir.Size {
	switch name {
	// 8-bit registers
	case "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh",
		"sil", "dil", "bpl", "spl",
		"r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b":
		return ir.Size1

	// 16-bit registers
	case "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
		"r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w":
		return ir.Size2

	// 32-bit registers
	case "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
		"r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d":
		return ir.Size4

	// 64-bit registers
	case "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
		"rip":
		return ir.Size8

	// xmm registers (128-bit)
	case "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
		"xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15":
		return ir.Size16

	default:
		return ir.Size8
	}
}
