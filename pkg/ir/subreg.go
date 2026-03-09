package ir

import "fmt"

// ============================================================================
// Sub-Register Aliasing Operations
// ============================================================================
//
// x86_64 has complex register aliasing where smaller registers share storage
// with larger registers:
//
// RAX (64-bit) contains:
//   - EAX (bits 0-31, lower 32 bits)
//   - AX  (bits 0-15, lower 16 bits)
//   - AL  (bits 0-7,  lower 8 bits)
//   - AH  (bits 8-15, bits 8-15)
//
// critical semantic rules:
//   - writing to 32-bit register (eax) zeros upper 32 bits of 64-bit register (rax)
//   - writing to 8/16-bit registers (ax, al, ah) preserves upper bits
//
// these operations model partial register updates in ir to ensure correct
// data-flow analysis and prevent decompilation errors.

// SubRegisterOp represents operations for modeling partial register updates
type SubRegisterOp interface {
	isSubRegisterOp()
	isExpression() // sub-register ops are expressions
	Type() Type
	String() string
}

// ============================================================================
// Extract Operation
// ============================================================================

// Extract extracts a sub-register from a parent register
//
// semantics: extract bits [offset*8, offset*8 + size*8) from source
//
// example: extracting al from rax
//
//	extract(rax, offset=0, size=1) -> al (bits 0-7)
//
// example: extracting ah from rax
//
//	extract(rax, offset=1, size=1) -> ah (bits 8-15)
//
// example: extracting ax from rax
//
//	extract(rax, offset=0, size=2) -> ax (bits 0-15)
//
// example: extracting eax from rax
//
//	extract(rax, offset=0, size=4) -> eax (bits 0-31)
type Extract struct {
	Source Variable // parent register (e.g., rax)
	Offset uint8    // byte offset from lsb (0 for al/ax/eax, 1 for ah)
	Size   Size     // size of extracted value in bytes
}

func (Extract) isSubRegisterOp() {}
func (Extract) isExpression()    {}

// Type returns the type of the extracted value
func (e Extract) Type() Type {
	// extracted value is unsigned integer of specified size
	return IntType{Width: e.Size, Signed: false}
}

func (e Extract) String() string {
	return fmt.Sprintf("extract(%s, offset=%d, size=%d)", e.Source.String(), e.Offset, e.Size)
}

// ============================================================================
// Insert Operation
// ============================================================================

// Insert inserts a value into a sub-register, preserving other bits
//
// semantics: replace bits [offset*8, offset*8 + size*8) in dest with value,
//
//	preserve all other bits
//
// example: writing to al preserves upper bits of rax
//
//	rax_new = insert(rax_old, al_value, offset=0, size=1)
//	result: bits 0-7 = al_value, bits 8-63 = rax_old[8:63]
//
// example: writing to ah preserves other bits of rax
//
//	rax_new = insert(rax_old, ah_value, offset=1, size=1)
//	result: bits 8-15 = ah_value, bits 0-7 and 16-63 = rax_old
//
// example: writing to ax preserves upper bits of rax
//
//	rax_new = insert(rax_old, ax_value, offset=0, size=2)
//	result: bits 0-15 = ax_value, bits 16-63 = rax_old[16:63]
type Insert struct {
	Dest   Variable   // parent register to modify (e.g., rax)
	Value  Expression // value to insert (e.g., al, ah, ax)
	Offset uint8      // byte offset from lsb (0 for al/ax, 1 for ah)
	Size   Size       // size of value to insert in bytes
}

func (Insert) isSubRegisterOp() {}
func (Insert) isExpression()    {}

// Type returns the type of the result (same as dest)
func (i Insert) Type() Type {
	return i.Dest.Type
}

func (i Insert) String() string {
	return fmt.Sprintf("insert(%s, %s, offset=%d, size=%d)",
		i.Dest.String(), i.Value.String(), i.Offset, i.Size)
}

// ============================================================================
// ZeroExtend Operation
// ============================================================================

// ZeroExtend extends a value to larger size, zeroing upper bits
//
// semantics: extend value from fromsize to tosize, filling upper bits with zeros
//
// critical x86_64 rule: writing to 32-bit register zeros upper 32 bits
//
// example: mov eax, ebx (writing to eax zeros upper 32 bits of rax)
//
//	rax_new = zeroextend(ebx_value, from=4, to=8)
//	result: bits 0-31 = ebx_value, bits 32-63 = 0
//
// this is different from insert, which preserves upper bits:
//   - insert(rax, eax_value, 0, 4) would preserve bits 32-63
//   - zeroextend(eax_value, 4, 8) zeros bits 32-63
//
// the x86_64 isa explicitly defines this behavior for 32-bit operations
// to simplify register renaming in modern cpus
type ZeroExtend struct {
	Source   Variable // source register (e.g., eax)
	FromSize Size     // original size in bytes (e.g., 4 for eax)
	ToSize   Size     // target size in bytes (e.g., 8 for rax)
}

func (ZeroExtend) isSubRegisterOp() {}
func (ZeroExtend) isExpression()    {}

// Type returns the type of the result
func (z ZeroExtend) Type() Type {
	// result is unsigned integer of target size
	return IntType{Width: z.ToSize, Signed: false}
}

func (z ZeroExtend) String() string {
	return fmt.Sprintf("zeroextend(%s, from=%d, to=%d)", z.Source.String(), z.FromSize, z.ToSize)
}

// ============================================================================
// Register Aliasing Relationships
// ============================================================================

// RegisterAlias defines the aliasing relationship between registers
type RegisterAlias struct {
	Parent string // parent register name (e.g., "rax")
	Sub    string // sub-register name (e.g., "al", "ah", "ax", "eax")
	Offset uint8  // byte offset from lsb
	Size   Size   // size in bytes
}

// x86_64RegisterAliases defines all register aliasing relationships for x86_64
//
// this table is used by ir_lifter to correctly model partial register updates
var x86_64RegisterAliases = []RegisterAlias{
	// rax family
	{"rax", "eax", 0, Size4},
	{"rax", "ax", 0, Size2},
	{"rax", "al", 0, Size1},
	{"rax", "ah", 1, Size1},

	// rbx family
	{"rbx", "ebx", 0, Size4},
	{"rbx", "bx", 0, Size2},
	{"rbx", "bl", 0, Size1},
	{"rbx", "bh", 1, Size1},

	// rcx family
	{"rcx", "ecx", 0, Size4},
	{"rcx", "cx", 0, Size2},
	{"rcx", "cl", 0, Size1},
	{"rcx", "ch", 1, Size1},

	// rdx family
	{"rdx", "edx", 0, Size4},
	{"rdx", "dx", 0, Size2},
	{"rdx", "dl", 0, Size1},
	{"rdx", "dh", 1, Size1},

	// rsi family
	{"rsi", "esi", 0, Size4},
	{"rsi", "si", 0, Size2},
	{"rsi", "sil", 0, Size1},

	// rdi family
	{"rdi", "edi", 0, Size4},
	{"rdi", "di", 0, Size2},
	{"rdi", "dil", 0, Size1},

	// rbp family
	{"rbp", "ebp", 0, Size4},
	{"rbp", "bp", 0, Size2},
	{"rbp", "bpl", 0, Size1},

	// rsp family
	{"rsp", "esp", 0, Size4},
	{"rsp", "sp", 0, Size2},
	{"rsp", "spl", 0, Size1},

	// r8-r15 families (no high byte registers)
	{"r8", "r8d", 0, Size4},
	{"r8", "r8w", 0, Size2},
	{"r8", "r8b", 0, Size1},

	{"r9", "r9d", 0, Size4},
	{"r9", "r9w", 0, Size2},
	{"r9", "r9b", 0, Size1},

	{"r10", "r10d", 0, Size4},
	{"r10", "r10w", 0, Size2},
	{"r10", "r10b", 0, Size1},

	{"r11", "r11d", 0, Size4},
	{"r11", "r11w", 0, Size2},
	{"r11", "r11b", 0, Size1},

	{"r12", "r12d", 0, Size4},
	{"r12", "r12w", 0, Size2},
	{"r12", "r12b", 0, Size1},

	{"r13", "r13d", 0, Size4},
	{"r13", "r13w", 0, Size2},
	{"r13", "r13b", 0, Size1},

	{"r14", "r14d", 0, Size4},
	{"r14", "r14w", 0, Size2},
	{"r14", "r14b", 0, Size1},

	{"r15", "r15d", 0, Size4},
	{"r15", "r15w", 0, Size2},
	{"r15", "r15b", 0, Size1},
}

// GetParentRegister returns the parent register for a given sub-register
//
// example: getparentregister("al") -> "rax"
// example: getparentregister("eax") -> "rax"
// example: getparentregister("ah") -> "rax"
func GetParentRegister(subReg string) (parent string, offset uint8, size Size, found bool) {
	for _, alias := range x86_64RegisterAliases {
		if alias.Sub == subReg {
			return alias.Parent, alias.Offset, alias.Size, true
		}
	}
	return "", 0, 0, false
}

// IsSubRegister checks if a register is a sub-register of another
//
// example: issubregister("al", "rax") -> true
// example: issubregister("eax", "rax") -> true
// example: issubregister("rbx", "rax") -> false
func IsSubRegister(subReg, parentReg string) bool {
	for _, alias := range x86_64RegisterAliases {
		if alias.Sub == subReg && alias.Parent == parentReg {
			return true
		}
	}
	return false
}

// Is32BitRegister checks if a register is a 32-bit register (eax, ebx, etc.)
//
// this is critical because writing to 32-bit registers zeros upper 32 bits,
// unlike 8/16-bit registers which preserve upper bits
func Is32BitRegister(reg string) bool {
	// check if register ends with common 32-bit suffixes
	if len(reg) < 2 {
		return false
	}

	// eax, ebx, ecx, edx, esi, edi, ebp, esp
	if reg[0] == 'e' && len(reg) == 3 {
		return true
	}

	// r8d-r15d
	if len(reg) >= 3 && reg[len(reg)-1] == 'd' {
		return true
	}

	return false
}
