// Package capstone provides CGO bindings to Capstone disassembly engine for x86_64 architecture.
// It wraps the C API with type-safe Go interfaces and handles memory management automatically.
//
//nolint:godot // CGO file with many C-style comments
package capstone

/*
#cgo LDFLAGS: -lcapstone
#include <capstone/capstone.h>
#include <stdlib.h>

// helper function to access x86 union member from cs_detail
static inline cs_x86* get_x86_detail(cs_detail* detail) {
	return &(detail->x86);
}

// helper functions to access x86 operand union members
static inline x86_reg get_op_reg(cs_x86_op* op) {
	return op->reg;
}

static inline int64_t get_op_imm(cs_x86_op* op) {
	return op->imm;
}

static inline x86_op_mem get_op_mem(cs_x86_op* op) {
	return op->mem;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

var (
	// errCSOpenFailed indicates cs_open failed.
	errCSOpenFailed = errors.New("cs_open failed")
	// errCSCloseFailed indicates cs_close failed.
	errCSCloseFailed = errors.New("cs_close failed")
	// errCSOptionFailed indicates cs_option failed.
	errCSOptionFailed = errors.New("cs_option failed")
	// errDisassemblyFailed indicates disassembly failed.
	errDisassemblyFailed = errors.New("disassembly failed")
)

// Architecture types.
const (
	ArchX86 = C.CS_ARCH_X86
)

// Mode types.
const (
	Mode64 = C.CS_MODE_64
)

// Option types.
const (
	OptDetail      = C.CS_OPT_DETAIL
	OptDetailOn    = C.CS_OPT_ON
	OptSyntax      = C.CS_OPT_SYNTAX
	OptSyntaxIntel = C.CS_OPT_SYNTAX_INTEL
)

// Operand types.
const (
	OpReg = C.X86_OP_REG
	OpImm = C.X86_OP_IMM
	OpMem = C.X86_OP_MEM
)

// Register constants for x86_64.
const (
	RegInvalid = C.X86_REG_INVALID

	// 8-bit registers.
	RegAL = C.X86_REG_AL
	RegAH = C.X86_REG_AH
	RegBL = C.X86_REG_BL
	RegBH = C.X86_REG_BH
	RegCL = C.X86_REG_CL
	RegCH = C.X86_REG_CH
	RegDL = C.X86_REG_DL
	RegDH = C.X86_REG_DH

	// 16-bit registers.
	RegAX = C.X86_REG_AX
	RegBX = C.X86_REG_BX
	RegCX = C.X86_REG_CX
	RegDX = C.X86_REG_DX
	RegSI = C.X86_REG_SI
	RegDI = C.X86_REG_DI
	RegBP = C.X86_REG_BP
	RegSP = C.X86_REG_SP

	// 32-bit registers.
	RegEAX = C.X86_REG_EAX
	RegEBX = C.X86_REG_EBX
	RegECX = C.X86_REG_ECX
	RegEDX = C.X86_REG_EDX
	RegESI = C.X86_REG_ESI
	RegEDI = C.X86_REG_EDI
	RegEBP = C.X86_REG_EBP
	RegESP = C.X86_REG_ESP

	// 64-bit registers.
	RegRAX = C.X86_REG_RAX
	RegRBX = C.X86_REG_RBX
	RegRCX = C.X86_REG_RCX
	RegRDX = C.X86_REG_RDX
	RegRSI = C.X86_REG_RSI
	RegRDI = C.X86_REG_RDI
	RegRBP = C.X86_REG_RBP
	RegRSP = C.X86_REG_RSP
	RegR8  = C.X86_REG_R8
	RegR9  = C.X86_REG_R9
	RegR10 = C.X86_REG_R10
	RegR11 = C.X86_REG_R11
	RegR12 = C.X86_REG_R12
	RegR13 = C.X86_REG_R13
	RegR14 = C.X86_REG_R14
	RegR15 = C.X86_REG_R15

	// instruction pointer.
	RegRIP = C.X86_REG_RIP

	// segment registers.
	RegCS = C.X86_REG_CS
	RegDS = C.X86_REG_DS
	RegES = C.X86_REG_ES
	RegFS = C.X86_REG_FS
	RegGS = C.X86_REG_GS
	RegSS = C.X86_REG_SS
)

// Engine represents capstone disassembly engine.
type Engine struct {
	handle C.csh
}

// Instruction represents a disassembled instruction.
type Instruction struct {
	Detail   *InstructionDetail
	Bytes    []byte
	Mnemonic string
	OpStr    string
	Address  uint64
	Size     uint16
}

// InstructionDetail contains detailed instruction information.
type InstructionDetail struct {
	X86 *X86Detail
}

// X86Detail contains x86-specific instruction details.
type X86Detail struct {
	Operands []X86Operand
	OpCount  uint8
}

// X86Operand represents an x86 operand.
type X86Operand struct {
	Type uint32
	Reg  uint32
	Imm  int64
	Mem  X86OpMem
	Size uint8
}

// X86OpMem represents a memory operand.
type X86OpMem struct {
	Segment uint32
	Base    uint32
	Index   uint32
	Scale   int32
	Disp    int64
}

// New creates a new capstone engine.
func New(arch, mode int) (*Engine, error) {
	var handle C.csh

	err := C.cs_open(C.cs_arch(arch), C.cs_mode(mode), &handle)
	if err != C.CS_ERR_OK {
		return nil, fmt.Errorf("%w: %d", errCSOpenFailed, err)
	}

	return &Engine{handle: handle}, nil
}

// Close closes the capstone engine
func (e *Engine) Close() error {
	err := C.cs_close(&e.handle)
	if err != C.CS_ERR_OK {
		return fmt.Errorf("%w: %d", errCSCloseFailed, err)
	}
	return nil
}

// SetOption sets an option for the engine
func (e *Engine) SetOption(optType, value int) error {
	err := C.cs_option(e.handle, C.cs_opt_type(optType), C.size_t(value))
	if err != C.CS_ERR_OK {
		return fmt.Errorf("%w: %d", errCSOptionFailed, err)
	}
	return nil
}

// Disasm disassembles instructions from byte slice
func (e *Engine) Disasm(code []byte, address uint64, count int) ([]Instruction, error) {
	if len(code) == 0 {
		return nil, nil
	}

	var insn *C.cs_insn

	// disassemble instructions
	//nolint:gocritic // CGO pointer usage required by capstone API
	n := C.cs_disasm(
		e.handle,
		(*C.uint8_t)(unsafe.Pointer(&code[0])),
		C.size_t(len(code)),
		C.uint64_t(address),
		C.size_t(count),
		&insn,
	)

	if n == 0 {
		return nil, errDisassemblyFailed
	}

	defer C.cs_free(insn, n)

	// convert c instructions to go structs
	instructions := make([]Instruction, n)

	// create slice from c array
	cInsns := unsafe.Slice(insn, n)

	for i := 0; i < int(n); i++ {
		cInsn := &cInsns[i]

		//nolint:gocritic // CGO array access pattern required
		instructions[i] = Instruction{
			Address:  uint64(cInsn.address),
			Detail:   nil,
			Bytes:    C.GoBytes(unsafe.Pointer(&cInsn.bytes), C.int(cInsn.size)),
			Mnemonic: C.GoString(&cInsn.mnemonic[0]),
			OpStr:    C.GoString(&cInsn.op_str[0]),
			Size:     uint16(cInsn.size),
		}

		// extract detail information if available
		if cInsn.detail != nil {
			instructions[i].Detail = e.extractDetail(cInsn.detail)
		}
	}

	return instructions, nil
}

// extractDetail extracts detailed instruction information
func (e *Engine) extractDetail(detail *C.cs_detail) *InstructionDetail {
	if detail == nil {
		return nil
	}

	// extract x86 specific details using helper function
	x86Ptr := C.get_x86_detail(detail)

	operands := make([]X86Operand, x86Ptr.op_count)

	// convert c operand array to go slice
	if x86Ptr.op_count > 0 {
		cOps := unsafe.Slice(&x86Ptr.operands[0], x86Ptr.op_count)

		for i := 0; i < int(x86Ptr.op_count); i++ {
			cOp := &cOps[i]

			operands[i] = X86Operand{
				Type: uint32(cOp._type),
				Size: uint8(cOp.size),
			}

			// extract operand-specific data based on type
			switch cOp._type {
			case C.X86_OP_REG:
				operands[i].Reg = uint32(C.get_op_reg(cOp))

			case C.X86_OP_IMM:
				operands[i].Imm = int64(C.get_op_imm(cOp))

			case C.X86_OP_MEM:
				mem := C.get_op_mem(cOp)
				operands[i].Mem = X86OpMem{
					Segment: uint32(mem.segment),
					Base:    uint32(mem.base),
					Index:   uint32(mem.index),
					Scale:   int32(mem.scale),
					Disp:    int64(mem.disp),
				}
			}
		}
	}

	return &InstructionDetail{
		X86: &X86Detail{
			OpCount:  uint8(x86Ptr.op_count),
			Operands: operands,
		},
	}
}

// RegName returns the name of a register
func (e *Engine) RegName(reg uint32) string {
	name := C.cs_reg_name(e.handle, C.uint(reg))
	if name == nil {
		return ""
	}
	return C.GoString(name)
}
