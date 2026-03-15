package abi

// canonicalizeRegister maps any x86_64 register alias to its 64-bit canonical name.
// This is required because the same physical register has multiple names depending
// on the access width: AL/AH/AX/EAX all refer to the lower portion of RAX.
//
// System V AMD64 ABI parameter registers are always referenced by their 64-bit names
// in this analysis, so we normalize all aliases to the 64-bit form.
func canonicalizeRegister(name string) string {
	switch name {
	// rax family
	case "rax", "eax", "ax", "al", "ah":
		return "rax"
	// rbx family
	case "rbx", "ebx", "bx", "bl", "bh":
		return "rbx"
	// rcx family
	case "rcx", "ecx", "cx", "cl", "ch":
		return "rcx"
	// rdx family
	case "rdx", "edx", "dx", "dl", "dh":
		return "rdx"
	// rsi family
	case "rsi", "esi", "si", "sil":
		return "rsi"
	// rdi family
	case "rdi", "edi", "di", "dil":
		return "rdi"
	// rbp family
	case "rbp", "ebp", "bp", "bpl":
		return "rbp"
	// rsp family
	case "rsp", "esp", "sp", "spl":
		return "rsp"
	// r8 family
	case "r8", "r8d", "r8w", "r8b":
		return "r8"
	// r9 family
	case "r9", "r9d", "r9w", "r9b":
		return "r9"
	// r10 family
	case "r10", "r10d", "r10w", "r10b":
		return "r10"
	// r11 family
	case "r11", "r11d", "r11w", "r11b":
		return "r11"
	// r12 family
	case "r12", "r12d", "r12w", "r12b":
		return "r12"
	// r13 family
	case "r13", "r13d", "r13w", "r13b":
		return "r13"
	// r14 family
	case "r14", "r14d", "r14w", "r14b":
		return "r14"
	// r15 family
	case "r15", "r15d", "r15w", "r15b":
		return "r15"
	// xmm registers (no sub-register aliasing in this context)
	case "xmm0":
		return "xmm0"
	case "xmm1":
		return "xmm1"
	case "xmm2":
		return "xmm2"
	case "xmm3":
		return "xmm3"
	case "xmm4":
		return "xmm4"
	case "xmm5":
		return "xmm5"
	case "xmm6":
		return "xmm6"
	case "xmm7":
		return "xmm7"
	default:
		return name
	}
}
