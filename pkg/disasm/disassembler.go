package disasm

import (
	"fmt"

	"github.com/zarazaex69/sedec/pkg/disasm/capstone"
)

// Disassembler provides x86_64 disassembly using Capstone Engine
type Disassembler struct {
	engine *capstone.Engine
}

// NewDisassembler creates a new x86_64 disassembler with full ISA extension support
func NewDisassembler() (*Disassembler, error) {
	// initialize capstone engine for x86_64
	engine, err := capstone.New(
		capstone.ArchX86,
		capstone.Mode64,
	)
	if err != nil {
		return nil, EngineInitError{Reason: err.Error()}
	}

	// enable detailed instruction information for operand extraction
	if optErr := engine.SetOption(capstone.OptDetail, capstone.OptDetailOn); optErr != nil {
		// ignore close error during cleanup in error path - engine is being discarded anyway
		//nolint:errcheck,gosec // cleanup in error path, engine will be garbage collected
		engine.Close()
		return nil, EngineInitError{Reason: fmt.Sprintf("failed to enable detail mode: %v", optErr)}
	}

	// enable syntax mode for intel syntax (standard for reverse engineering)
	if optErr := engine.SetOption(capstone.OptSyntax, capstone.OptSyntaxIntel); optErr != nil {
		// ignore close error during cleanup in error path - engine is being discarded anyway
		//nolint:errcheck,gosec // cleanup in error path, engine will be garbage collected
		engine.Close()
		return nil, EngineInitError{Reason: fmt.Sprintf("failed to set intel syntax: %v", optErr)}
	}

	return &Disassembler{
		engine: engine,
	}, nil
}

// Close releases resources held by the disassembler engine
func (d *Disassembler) Close() error {
	return d.engine.Close()
}

// Disassemble decodes a single instruction at the given address
func (d *Disassembler) Disassemble(bytes []byte, address Address) (*Instruction, error) {
	if len(bytes) == 0 {
		return nil, InsufficientBytesError{
			VA:        address,
			Available: 0,
			Required:  1,
		}
	}

	// disassemble single instruction
	insns, err := d.engine.Disasm(bytes, uint64(address), 1)
	if err != nil {
		// capstone error - likely invalid opcode
		return nil, InvalidOpcodeError{
			VA:   address,
			Byte: bytes[0],
		}
	}

	if len(insns) == 0 {
		// no instruction decoded - invalid opcode
		return nil, InvalidOpcodeError{
			VA:   address,
			Byte: bytes[0],
		}
	}

	return d.convertInstruction(&insns[0]), nil
}

// DisassembleBytes decodes all instructions from the given byte slice
// Returns partial results even if some instructions fail to decode
func (d *Disassembler) DisassembleBytes(bytes []byte, startAddress Address) ([]*Instruction, error) {
	if len(bytes) == 0 {
		return nil, nil
	}

	var result []*Instruction
	offset := 0
	currentAddr := startAddress

	for offset < len(bytes) {
		// attempt to disassemble single instruction
		remaining := bytes[offset:]
		insns, err := d.engine.Disasm(remaining, uint64(currentAddr), 1)

		if err != nil || len(insns) == 0 {
			// invalid opcode - skip single byte and continue
			// this handles obfuscated code and data embedded in code sections
			offset++
			currentAddr++
			continue
		}

		// successfully decoded instruction
		instr := d.convertInstruction(&insns[0])
		result = append(result, instr)

		// advance by instruction length
		offset += instr.Length
		//nolint:gosec // length is validated by capstone, overflow impossible in practice
		currentAddr += Address(instr.Length)
	}

	return result, nil
}

// DisassembleFunction decodes all instructions in a function
// Stops at return instruction or when bytes are exhausted
func (d *Disassembler) DisassembleFunction(bytes []byte, startAddress Address) ([]*Instruction, error) {
	if len(bytes) == 0 {
		return nil, nil
	}

	// disassemble all instructions at once for performance
	insns, err := d.engine.Disasm(bytes, uint64(startAddress), 0)
	if err != nil {
		// fallback to byte-by-byte disassembly on error
		return d.DisassembleBytes(bytes, startAddress)
	}

	if len(insns) == 0 {
		return nil, InvalidOpcodeError{
			VA:   startAddress,
			Byte: bytes[0],
		}
	}

	result := make([]*Instruction, len(insns))
	for i := range insns {
		result[i] = d.convertInstruction(&insns[i])
	}

	return result, nil
}

// convertInstruction converts capstone instruction to internal Instruction type
func (d *Disassembler) convertInstruction(insn *capstone.Instruction) *Instruction {
	instr := &Instruction{
		Address:  Address(insn.Address),
		Bytes:    make([]byte, len(insn.Bytes)),
		Mnemonic: insn.Mnemonic,
		Length:   int(insn.Size),
		Operands: make([]Operand, 0, 4), // preallocate for typical instruction
	}

	// copy instruction bytes
	copy(instr.Bytes, insn.Bytes)

	// extract operands from capstone detail information
	if insn.Detail != nil && insn.Detail.X86 != nil && insn.Detail.X86.OpCount > 0 {
		instr.Operands = d.extractOperands(insn)
	}

	return instr
}

// extractOperands extracts operand information from capstone instruction
func (d *Disassembler) extractOperands(insn *capstone.Instruction) []Operand {
	if insn.Detail == nil || insn.Detail.X86 == nil {
		return nil
	}

	x86 := insn.Detail.X86
	operands := make([]Operand, 0, x86.OpCount)

	for i := uint8(0); i < x86.OpCount; i++ {
		op := x86.Operands[i]

		switch op.Type {
		case capstone.OpReg:
			// register operand
			regName := d.getRegisterName(op.Reg)
			regSize := d.getRegisterSize(op.Reg)
			operands = append(operands, RegisterOperand{
				Name: regName,
				Size: regSize,
			})

		case capstone.OpImm:
			// immediate operand
			operands = append(operands, ImmediateOperand{
				Value: op.Imm,
				Size:  Size(op.Size),
			})

		case capstone.OpMem:
			// memory operand
			mem := op.Mem
			operands = append(operands, MemoryOperand{
				Segment: d.getRegisterName(mem.Segment),
				Base:    d.getRegisterName(mem.Base),
				Index:   d.getRegisterName(mem.Index),
				Scale:   int(mem.Scale),
				Disp:    mem.Disp,
				Size:    Size(op.Size),
			})
		}
	}

	return operands
}

// getRegisterName converts capstone register ID to register name string
func (d *Disassembler) getRegisterName(reg uint32) string {
	if reg == capstone.RegInvalid {
		return ""
	}

	// get register name from capstone
	name := d.engine.RegName(reg)
	if name == "" {
		return fmt.Sprintf("reg_%d", reg)
	}

	return name
}

// getRegisterSize determines register size from capstone register ID
func (d *Disassembler) getRegisterSize(reg uint32) Size {
	if reg == capstone.RegInvalid {
		return 0
	}

	// check specific register categories
	if size := d.get8BitRegisterSize(reg); size != 0 {
		return size
	}
	if size := d.get16BitRegisterSize(reg); size != 0 {
		return size
	}
	if size := d.get32BitRegisterSize(reg); size != 0 {
		return size
	}
	if size := d.get64BitRegisterSize(reg); size != 0 {
		return size
	}
	if size := d.getVectorRegisterSize(reg); size != 0 {
		return size
	}

	// default to 64-bit for unknown registers in x86_64 mode
	return Size64
}

// get8BitRegisterSize checks if register is 8-bit
func (d *Disassembler) get8BitRegisterSize(reg uint32) Size {
	// 8-bit registers (al, ah, bl, bh, cl, ch, dl, dh, spl, bpl, sil, dil, r8b-r15b)
	if (reg >= capstone.RegAL && reg <= capstone.RegDH) ||
		(reg >= 61 && reg <= 68) || // spl, bpl, sil, dil
		(reg >= 69 && reg <= 76) { // r8b-r15b
		return Size8
	}
	return 0
}

// get16BitRegisterSize checks if register is 16-bit
func (d *Disassembler) get16BitRegisterSize(reg uint32) Size {
	// 16-bit registers (ax, bx, cx, dx, si, di, bp, sp, r8w-r15w)
	if (reg >= capstone.RegAX && reg <= capstone.RegSP) ||
		(reg >= 77 && reg <= 84) { // r8w-r15w
		return Size16
	}

	// segment registers (16-bit)
	if reg >= capstone.RegCS && reg <= capstone.RegSS {
		return Size16
	}

	return 0
}

// get32BitRegisterSize checks if register is 32-bit
func (d *Disassembler) get32BitRegisterSize(reg uint32) Size {
	// 32-bit registers (eax, ebx, ecx, edx, esi, edi, ebp, esp, r8d-r15d)
	if (reg >= capstone.RegEAX && reg <= capstone.RegESP) ||
		(reg >= 34 && reg <= 41) { // r8d-r15d
		return Size32
	}
	return 0
}

// get64BitRegisterSize checks if register is 64-bit
func (d *Disassembler) get64BitRegisterSize(reg uint32) Size {
	// 64-bit general purpose registers (rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8-r15)
	if reg >= capstone.RegRAX && reg <= capstone.RegR15 {
		return Size64
	}

	// instruction pointer (64-bit in x86_64)
	if reg == capstone.RegRIP {
		return Size64
	}

	// mmx registers (64-bit)
	if reg >= 85 && reg <= 92 { // mm0-mm7
		return Size64
	}

	return 0
}

// getVectorRegisterSize checks if register is vector register (xmm, ymm, zmm)
func (d *Disassembler) getVectorRegisterSize(reg uint32) Size {
	// xmm registers (128-bit) - sse
	if reg >= 224 && reg <= 255 { // xmm0-xmm31
		return 16 // 128 bits
	}

	// ymm registers (256-bit) - avx/avx2
	if reg >= 192 && reg <= 223 { // ymm0-ymm31
		return 32 // 256 bits
	}

	// zmm registers (512-bit) - avx-512
	if reg >= 160 && reg <= 191 { // zmm0-zmm31
		return 64 // 512 bits
	}

	return 0
}
