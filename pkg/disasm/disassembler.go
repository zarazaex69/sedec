package disasm

import (
	"fmt"

	"github.com/zarazaex69/sedec/pkg/disasm/capstone"
)

// Disassembler provides x86_64 disassembly using Capstone Engine.
type Disassembler struct {
	engine *capstone.Engine
}

// NewDisassembler creates a new x86_64 disassembler with full ISA extension support.
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

// Close releases resources held by the disassembler engine.
func (d *Disassembler) Close() error {
	return d.engine.Close()
}

// Disassemble decodes a single instruction at the given address.
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

// DisassembleBytes decodes all instructions from the given byte slice.
// Returns partial results even if some instructions fail to decode.
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

// DisassembleFunction decodes all instructions in a function.
// Stops at return instruction or when bytes are exhausted.
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

// convertInstruction converts capstone instruction to internal Instruction type.
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

// extractOperands extracts operand information from capstone instruction.
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
			// use op.Size from capstone directly — it contains the operand size in bytes
			regName := d.getRegisterName(op.Reg)
			operands = append(operands, RegisterOperand{
				Name: regName,
				Size: Size(op.Size),
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
			baseName := d.getRegisterName(mem.Base)
			disp := mem.Disp

			// rip-relative: resolve to absolute va = insn_end + disp
			// capstone gives raw displacement, not the resolved address
			if baseName == "rip" {
				//nolint:gosec // address arithmetic is safe for valid binary addresses
				absAddr := int64(insn.Address) + int64(insn.Size) + disp
				operands = append(operands, MemoryOperand{
					Segment: d.getRegisterName(mem.Segment),
					Base:    "",
					Index:   "",
					Scale:   0,
					Disp:    absAddr,
					Size:    Size(op.Size),
				})
				continue
			}

			operands = append(operands, MemoryOperand{
				Segment: d.getRegisterName(mem.Segment),
				Base:    baseName,
				Index:   d.getRegisterName(mem.Index),
				Scale:   int(mem.Scale),
				Disp:    disp,
				Size:    Size(op.Size),
			})
		}
	}

	return operands
}

// getRegisterName converts capstone register ID to register name string.
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
