package disasm

// Address represents a virtual address in the binary.
type Address uint64

// Size represents operand size in bytes.
type Size uint8

const (
	// Size8 represents 8-bit (1 byte) operand size.
	Size8 Size = 1
	// Size16 represents 16-bit (2 bytes) operand size.
	Size16 Size = 2
	// Size32 represents 32-bit (4 bytes) operand size.
	Size32 Size = 4
	// Size64 represents 64-bit (8 bytes) operand size.
	Size64 Size = 8
)

// Instruction represents a single disassembled instruction.
type Instruction struct {
	Bytes    []byte    // raw instruction bytes
	Mnemonic string    // instruction mnemonic (e.g., "mov", "add")
	Operands []Operand // instruction operands
	Address  Address   // virtual address of instruction
	Length   int       // instruction length in bytes
}

// Operand represents an instruction operand.
type Operand interface {
	isOperand()
	String() string
}

// RegisterOperand represents a register operand.
type RegisterOperand struct {
	Name string // register name (e.g., "rax", "xmm0")
	Size Size   // register size
}

func (RegisterOperand) isOperand() {}

func (r RegisterOperand) String() string {
	return r.Name
}

// ImmediateOperand represents an immediate value operand.
type ImmediateOperand struct {
	Value int64 // immediate value
	Size  Size  // operand size
}

func (ImmediateOperand) isOperand() {}

func (i ImmediateOperand) String() string {
	return formatImmediate(i.Value)
}

// MemoryOperand represents a memory reference operand.
type MemoryOperand struct {
	Segment string // segment register (optional, e.g., "gs")
	Base    string // base register (e.g., "rsp")
	Index   string // index register (e.g., "rax")
	Scale   int    // scale factor (1, 2, 4, 8)
	Disp    int64  // displacement
	Size    Size   // memory access size
}

func (MemoryOperand) isOperand() {}

func (m MemoryOperand) String() string {
	return formatMemory(m)
}

// formatImmediate formats immediate value as hex string.
func formatImmediate(value int64) string {
	if value >= 0 {
		return "0x" + formatHex(uint64(value))
	}
	return "-0x" + formatHex(uint64(-value))
}

// formatHex formats unsigned value as hex without leading zeros.
func formatHex(value uint64) string {
	if value == 0 {
		return "0"
	}

	hex := "0123456789abcdef"
	var buf [16]byte
	i := len(buf)

	for value > 0 {
		i--
		buf[i] = hex[value&0xf]
		value >>= 4
	}

	return string(buf[i:])
}

// formatMemory formats memory operand as string.
func formatMemory(m MemoryOperand) string {
	result := ""

	if m.Segment != "" {
		result += m.Segment + ":"
	}

	result += "["

	hasBase := m.Base != ""
	hasIndex := m.Index != ""
	hasDisp := m.Disp != 0

	if hasBase {
		result += m.Base
	}

	if hasIndex {
		if hasBase {
			result += " + "
		}
		result += m.Index
		if m.Scale > 1 {
			result += "*" + formatInt(m.Scale)
		}
	}

	result = formatDisplacement(result, hasBase, hasIndex, hasDisp, m.Disp)

	result += "]"

	return result
}

// formatDisplacement formats displacement part of memory operand.
func formatDisplacement(result string, hasBase, hasIndex, hasDisp bool, disp int64) string {
	if !hasDisp {
		return result
	}

	if hasBase || hasIndex {
		if disp > 0 {
			result += " + "
		} else {
			result += " - "
		}
		//nolint:gosec // abs value conversion is safe
		result += "0x" + formatHex(uint64(abs(disp)))
	} else {
		result += formatImmediate(disp)
	}

	return result
}

// formatInt formats integer as decimal string
func formatInt(n int) string {
	if n == 0 {
		return "0"
	}

	if n < 0 {
		return "-" + formatInt(-n)
	}

	var buf [20]byte
	i := len(buf)

	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}

	return string(buf[i:])
}

// abs returns absolute value of integer
func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
