package abi

// canonicalizeRegister maps any x86_64 register alias to its 64-bit canonical name.
// This is required because the same physical register has multiple names depending
// on the access width: AL/AH/AX/EAX all refer to the lower portion of RAX.
//
// System V AMD64 ABI parameter registers are always referenced by their 64-bit names
// in this analysis, so we normalize all aliases to the 64-bit form.
func canonicalizeRegister(name string) string {
	switch name {
	case regRax, "eax", "ax", "al", "ah":
		return regRax
	case regRbx, "ebx", "bx", "bl", "bh":
		return regRbx
	case regRcx, "ecx", "cx", "cl", "ch":
		return regRcx
	case regRdx, "edx", "dx", "dl", "dh":
		return regRdx
	case regRsi, "esi", "si", "sil":
		return regRsi
	case regRdi, "edi", "di", "dil":
		return regRdi
	case regRbp, "ebp", "bp", "bpl":
		return regRbp
	case regRsp, "esp", "sp", "spl":
		return regRsp
	case "r8", "r8d", "r8w", "r8b":
		return "r8"
	case "r9", "r9d", "r9w", "r9b":
		return "r9"
	case regR10, "r10d", "r10w", "r10b":
		return regR10
	case regR11, "r11d", "r11w", "r11b":
		return regR11
	case regR12, "r12d", "r12w", "r12b":
		return regR12
	case regR13, "r13d", "r13w", "r13b":
		return regR13
	case regR14, "r14d", "r14w", "r14b":
		return regR14
	case regR15, "r15d", "r15w", "r15b":
		return regR15
	case regXmm0:
		return regXmm0
	case regXmm1:
		return regXmm1
	case regXmm2:
		return regXmm2
	case regXmm3:
		return regXmm3
	case regXmm4:
		return regXmm4
	case regXmm5:
		return regXmm5
	case regXmm6:
		return regXmm6
	case regXmm7:
		return regXmm7
	default:
		return name
	}
}
