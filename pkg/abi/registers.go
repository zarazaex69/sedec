package abi

// canonicalizeRegister maps any x86_64 register alias to its 64-bit canonical name.
// This is required because the same physical register has multiple names depending
// on the access width: AL/AH/AX/EAX all refer to the lower portion of RAX.
//
// System V AMD64 ABI parameter registers are always referenced by their 64-bit names
// in this analysis, so we normalize all aliases to the 64-bit form.
func canonicalizeRegister(name string) string {
	switch name {
	case regRax, subregEax, "ax", "al", "ah":
		return regRax
	case regRbx, subregEbx, "bx", "bl", "bh":
		return regRbx
	case regRcx, subregEcx, "cx", "cl", "ch":
		return regRcx
	case regRdx, subregEdx, "dx", "dl", "dh":
		return regRdx
	case regRsi, subregEsi, "si", subregSil:
		return regRsi
	case regRdi, subregEdi, "di", subregDil:
		return regRdi
	case regRbp, subregEbp, "bp", subregBpl:
		return regRbp
	case regRsp, subregEsp, "sp", subregSpl:
		return regRsp
	case "r8", subregR8d, subregR8w, subregR8b:
		return "r8"
	case "r9", subregR9d, subregR9w, subregR9b:
		return "r9"
	case regR10, subregR10d, subregR10w, subregR10b:
		return regR10
	case regR11, subregR11d, subregR11w, subregR11b:
		return regR11
	case regR12, subregR12d, subregR12w, subregR12b:
		return regR12
	case regR13, subregR13d, subregR13w, subregR13b:
		return regR13
	case regR14, subregR14d, subregR14w, subregR14b:
		return regR14
	case regR15, subregR15d, subregR15w, subregR15b:
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
