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
		subregSil, subregDil, subregBpl, subregSpl,
		subregR8b, subregR9b, subregR10b, subregR11b, subregR12b, subregR13b, subregR14b, subregR15b:
		return ir.Size1

	// 16-bit registers
	case "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
		subregR8w, subregR9w, subregR10w, subregR11w, subregR12w, subregR13w, subregR14w, subregR15w:
		return ir.Size2

	// 32-bit registers
	case subregEax, subregEbx, subregEcx, subregEdx, subregEsi, subregEdi, subregEbp, subregEsp,
		subregR8d, subregR9d, subregR10d, subregR11d, subregR12d, subregR13d, subregR14d, subregR15d:
		return ir.Size4

	// 64-bit registers
	case regRax, regRbx, regRcx, regRdx, regRsi, regRdi, regRbp, regRsp,
		"r8", "r9", regR10, regR11, regR12, regR13, regR14, regR15,
		"rip":
		return ir.Size8

	// xmm registers (128-bit)
	case regXmm0, regXmm1, regXmm2, regXmm3, regXmm4, regXmm5, regXmm6, regXmm7,
		"xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15":
		return ir.Size16

	default:
		return ir.Size8
	}
}
