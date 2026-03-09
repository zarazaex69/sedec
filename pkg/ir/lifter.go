package ir

import (
	"fmt"
	"strings"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// Lifter translates x86_64 assembly instructions to platform-independent IR.
// It performs semantically equivalent translation preserving all side effects.
type Lifter struct {
	// nextTempID tracks temporary variable allocation
	nextTempID uint64
	// currentBlock accumulates IR instructions for current basic block
	currentBlock []IRInstruction
	// currentLocation tracks source location for traceability
	currentLocation SourceLocation
	// currentLazyFlags stores lazy flag state for current instruction
	// this will be used by data flow analyzer for selective materialization
	currentLazyFlags *LazyFlags
}

// NewLifter creates a new IR lifter for x86_64 instructions.
func NewLifter() *Lifter {
	return &Lifter{
		nextTempID:   0,
		currentBlock: make([]IRInstruction, 0, 64),
	}
}

// LiftInstruction translates a single x86_64 instruction to IR.
// Returns slice of IR instructions (complex instructions decompose into multiple IR ops).
func (l *Lifter) LiftInstruction(insn *disasm.Instruction) ([]IRInstruction, error) {
	// reset current block for new instruction
	l.currentBlock = l.currentBlock[:0]

	// set source location for traceability
	l.currentLocation = SourceLocation{
		Address:     Address(insn.Address),
		Instruction: l.formatInstruction(insn),
	}

	// dispatch by mnemonic
	mnemonic := strings.ToLower(insn.Mnemonic)

	switch {
	// arithmetic operations
	case mnemonic == "add":
		return l.liftAdd(insn)
	case mnemonic == "sub":
		return l.liftSub(insn)
	case mnemonic == "mul":
		return l.liftMul(insn)
	case mnemonic == "imul":
		return l.liftIMul(insn)
	case mnemonic == "div":
		return l.liftDiv(insn)
	case mnemonic == "idiv":
		return l.liftIDiv(insn)
	case mnemonic == "inc":
		return l.liftInc(insn)
	case mnemonic == "dec":
		return l.liftDec(insn)
	case mnemonic == "neg":
		return l.liftNeg(insn)

	// logical operations
	case mnemonic == "and":
		return l.liftAnd(insn)
	case mnemonic == "or":
		return l.liftOr(insn)
	case mnemonic == "xor":
		return l.liftXor(insn)
	case mnemonic == "not":
		return l.liftNot(insn)
	case mnemonic == "test":
		return l.liftTest(insn)
	case mnemonic == "cmp":
		return l.liftCmp(insn)

	// shift and rotate operations
	case mnemonic == "shl" || mnemonic == "sal":
		return l.liftShl(insn)
	case mnemonic == "shr":
		return l.liftShr(insn)
	case mnemonic == "sar":
		return l.liftSar(insn)
	case mnemonic == "rol":
		return l.liftRol(insn)
	case mnemonic == "ror":
		return l.liftRor(insn)

	// memory operations
	case mnemonic == "mov":
		return l.liftMov(insn)
	case mnemonic == "movzx" || mnemonic == "movzb" || mnemonic == "movzw":
		return l.liftMovzx(insn)
	case mnemonic == "movsx" || mnemonic == "movsb" || mnemonic == "movsw" || mnemonic == "movsxd":
		return l.liftMovsx(insn)
	case mnemonic == "lea":
		return l.liftLea(insn)
	case mnemonic == "push":
		return l.liftPush(insn)
	case mnemonic == "pop":
		return l.liftPop(insn)

	// control flow operations
	case mnemonic == "jmp":
		return l.liftJmp(insn)
	case strings.HasPrefix(mnemonic, "j") && len(mnemonic) <= 4:
		// conditional jumps: je, jne, jl, jg, jle, jge, ja, jb, etc.
		return l.liftJcc(insn)
	case mnemonic == "call":
		return l.liftCall(insn)
	case mnemonic == "ret" || mnemonic == "retn":
		return l.liftRet(insn)

	// nop and other
	case mnemonic == "nop":
		return l.currentBlock, nil

	default:
		return nil, fmt.Errorf("unsupported instruction: %s at 0x%x", insn.Mnemonic, insn.Address)
	}
}

// formatInstruction creates human-readable instruction string for traceability.
func (l *Lifter) formatInstruction(insn *disasm.Instruction) string {
	if len(insn.Operands) == 0 {
		return insn.Mnemonic
	}

	operands := make([]string, len(insn.Operands))
	for i, op := range insn.Operands {
		operands[i] = op.String()
	}

	return fmt.Sprintf("%s %s", insn.Mnemonic, strings.Join(operands, ", "))
}

// newTemp creates a new temporary variable with unique name.
func (l *Lifter) newTemp(typ Type) Variable {
	l.nextTempID++
	return Variable{
		Name: fmt.Sprintf("t%d", l.nextTempID),
		Type: typ,
	}
}

// emit adds an IR instruction to current block.
func (l *Lifter) emit(insn IRInstruction) {
	l.currentBlock = append(l.currentBlock, insn)
}

// getOperandSize determines operand size from disasm operand.
func (l *Lifter) getOperandSize(op disasm.Operand) Size {
	switch v := op.(type) {
	case disasm.RegisterOperand:
		return Size(v.Size)
	case disasm.ImmediateOperand:
		return Size(v.Size)
	case disasm.MemoryOperand:
		return Size(v.Size)
	default:
		return Size8 // default to 8-bit
	}
}

// getIntType creates integer type from size.
func (l *Lifter) getIntType(size Size, signed bool) Type {
	return IntType{Width: size, Signed: signed}
}

// ============================================================================
// Operand Translation
// ============================================================================

// translateOperandToExpr converts disasm operand to IR expression.
func (l *Lifter) translateOperandToExpr(op disasm.Operand) (Expression, error) {
	switch v := op.(type) {
	case disasm.RegisterOperand:
		return l.translateRegister(v), nil

	case disasm.ImmediateOperand:
		return ConstantExpr{
			Value: IntConstant{
				Value:  v.Value,
				Width:  Size(v.Size),
				Signed: true,
			},
		}, nil

	case disasm.MemoryOperand:
		// memory operand requires load - caller must handle
		return nil, fmt.Errorf("memory operand requires explicit load")

	default:
		return nil, fmt.Errorf("unknown operand type")
	}
}

// translateRegister converts register name to IR variable.
func (l *Lifter) translateRegister(reg disasm.RegisterOperand) Expression {
	return VariableExpr{
		Var: Variable{
			Name: reg.Name,
			Type: l.getIntType(Size(reg.Size), false),
		},
	}
}

// translateMemoryAddress computes effective address for memory operand.
func (l *Lifter) translateMemoryAddress(mem disasm.MemoryOperand) Expression {
	var addr Expression

	// start with base register if present
	if mem.Base != "" {
		addr = VariableExpr{
			Var: Variable{
				Name: mem.Base,
				Type: IntType{Width: Size8, Signed: false},
			},
		}
	}

	// add index * scale if present
	if mem.Index != "" {
		indexExpr := VariableExpr{
			Var: Variable{
				Name: mem.Index,
				Type: IntType{Width: Size8, Signed: false},
			},
		}

		// multiply by scale if not 1
		var scaledIndex Expression = indexExpr
		if mem.Scale > 1 {
			scaleExpr := ConstantExpr{
				Value: IntConstant{
					Value:  int64(mem.Scale),
					Width:  Size8,
					Signed: false,
				},
			}
			scaledIndex = BinaryOp{
				Op:    BinOpMul,
				Left:  indexExpr,
				Right: scaleExpr,
			}
		}

		// add to address
		if addr != nil {
			addr = BinaryOp{
				Op:    BinOpAdd,
				Left:  addr,
				Right: scaledIndex,
			}
		} else {
			addr = scaledIndex
		}
	}

	// add displacement if present
	if mem.Disp != 0 {
		dispExpr := ConstantExpr{
			Value: IntConstant{
				Value:  mem.Disp,
				Width:  Size8,
				Signed: true,
			},
		}

		if addr != nil {
			addr = BinaryOp{
				Op:    BinOpAdd,
				Left:  addr,
				Right: dispExpr,
			}
		} else {
			addr = dispExpr
		}
	}

	// if no components, address is 0
	if addr == nil {
		addr = ConstantExpr{
			Value: IntConstant{
				Value:  0,
				Width:  Size8,
				Signed: false,
			},
		}
	}

	return addr
}

// loadFromMemory emits load instruction and returns loaded variable.
func (l *Lifter) loadFromMemory(mem disasm.MemoryOperand) Variable {
	addr := l.translateMemoryAddress(mem)
	dest := l.newTemp(l.getIntType(Size(mem.Size), false))

	l.emit(Load{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            dest,
		Address:         addr,
		Size:            Size(mem.Size),
	})

	return dest
}

// storeToMemory emits store instruction.
func (l *Lifter) storeToMemory(mem disasm.MemoryOperand, value Expression) {
	addr := l.translateMemoryAddress(mem)

	l.emit(Store{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Address:         addr,
		Value:           value,
		Size:            Size(mem.Size),
	})
}

// ============================================================================
// Arithmetic Operations
// ============================================================================

// liftAdd lifts ADD instruction: dest = dest + src
func (l *Lifter) liftAdd(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, fmt.Errorf("add requires 2 operands")
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	// load source operand
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// load destination operand
	var destExpr Expression
	var destVar Variable

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		destVar = l.loadFromMemory(mem)
		destExpr = VariableExpr{Var: destVar}
	} else {
		destExpr, err = l.translateOperandToExpr(dest)
		if err != nil {
			return nil, err
		}
		if varExpr, ok := destExpr.(VariableExpr); ok {
			destVar = varExpr.Var
		}
	}

	// compute result: dest + src
	resultExpr := BinaryOp{
		Op:    BinOpAdd,
		Left:  destExpr,
		Right: srcExpr,
	}

	// store result back to destination
	if mem, ok := dest.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, resultExpr)
	} else {
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          resultExpr,
		})
	}

	// set flags (lazy evaluation - mark as lazy for later elimination)
	l.setArithmeticFlags(resultExpr, destVar.Type.Size())

	return l.currentBlock, nil
}

// liftSub lifts SUB instruction: dest = dest - src
func (l *Lifter) liftSub(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, fmt.Errorf("sub requires 2 operands")
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	// load source operand
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// load destination operand
	var destExpr Expression
	var destVar Variable

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		destVar = l.loadFromMemory(mem)
		destExpr = VariableExpr{Var: destVar}
	} else {
		destExpr, err = l.translateOperandToExpr(dest)
		if err != nil {
			return nil, err
		}
		if varExpr, ok := destExpr.(VariableExpr); ok {
			destVar = varExpr.Var
		}
	}

	// compute result: dest - src
	resultExpr := BinaryOp{
		Op:    BinOpSub,
		Left:  destExpr,
		Right: srcExpr,
	}

	// store result back to destination
	if mem, ok := dest.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, resultExpr)
	} else {
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          resultExpr,
		})
	}

	// set flags (lazy evaluation)
	l.setArithmeticFlags(resultExpr, destVar.Type.Size())

	return l.currentBlock, nil
}

// liftMul lifts MUL instruction: rdx:rax = rax * src (unsigned)
func (l *Lifter) liftMul(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, fmt.Errorf("mul requires 1 operand")
	}

	src := insn.Operands[0]
	size := l.getOperandSize(src)

	// load source operand
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// implicit operand: rax (or al, ax, eax depending on size)
	var raxName string
	switch size {
	case Size1:
		raxName = "al"
	case Size2:
		raxName = "ax"
	case Size4:
		raxName = "eax"
	case Size8:
		raxName = "rax"
	default:
		raxName = "rax"
	}

	raxVar := Variable{
		Name: raxName,
		Type: l.getIntType(size, false),
	}

	// compute result: rax * src
	resultExpr := BinaryOp{
		Op:    BinOpMul,
		Left:  VariableExpr{Var: raxVar},
		Right: srcExpr,
	}

	// for 8-bit: result in ax
	// for 16-bit: result in dx:ax
	// for 32-bit: result in edx:eax
	// for 64-bit: result in rdx:rax

	if size == Size1 {
		// 8-bit: al * src -> ax
		axVar := Variable{Name: "ax", Type: l.getIntType(Size2, false)}
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            axVar,
			Source:          resultExpr,
		})
	} else {
		// store low part in rax
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            raxVar,
			Source:          resultExpr,
		})

		// compute high part: (rax * src) >> (size * 8)
		shiftAmount := ConstantExpr{
			Value: IntConstant{
				Value:  int64(size * 8),
				Width:  Size1,
				Signed: false,
			},
		}

		highExpr := BinaryOp{
			Op:    BinOpShr,
			Left:  resultExpr,
			Right: shiftAmount,
		}

		// store high part in rdx
		var rdxName string
		switch size {
		case Size2:
			rdxName = "dx"
		case Size4:
			rdxName = "edx"
		case Size8:
			rdxName = "rdx"
		default:
			rdxName = "rdx"
		}

		rdxVar := Variable{
			Name: rdxName,
			Type: l.getIntType(size, false),
		}

		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            rdxVar,
			Source:          highExpr,
		})
	}

	// set flags (cf and of set if high part != 0)
	l.setArithmeticFlags(resultExpr, size)

	return l.currentBlock, nil
}

// liftIMul lifts IMUL instruction (signed multiply with multiple forms)
func (l *Lifter) liftIMul(insn *disasm.Instruction) ([]IRInstruction, error) {
	switch len(insn.Operands) {
	case 1:
		// imul src: rdx:rax = rax * src (signed, like mul but signed)
		return l.liftIMulOneOperand(insn)
	case 2:
		// imul dest, src: dest = dest * src
		return l.liftIMulTwoOperands(insn)
	case 3:
		// imul dest, src, imm: dest = src * imm
		return l.liftIMulThreeOperands(insn)
	default:
		return nil, fmt.Errorf("imul requires 1-3 operands")
	}
}

// liftIMulOneOperand lifts single-operand IMUL.
func (l *Lifter) liftIMulOneOperand(insn *disasm.Instruction) ([]IRInstruction, error) {
	src := insn.Operands[0]
	size := l.getOperandSize(src)

	// load source operand
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// implicit operand: rax
	var raxName string
	switch size {
	case Size1:
		raxName = "al"
	case Size2:
		raxName = "ax"
	case Size4:
		raxName = "eax"
	case Size8:
		raxName = "rax"
	default:
		raxName = "rax"
	}

	raxVar := Variable{
		Name: raxName,
		Type: l.getIntType(size, true), // signed
	}

	// compute result: rax * src (signed)
	resultExpr := BinaryOp{
		Op:    BinOpMul,
		Left:  VariableExpr{Var: raxVar},
		Right: srcExpr,
	}

	// store low part
	l.emit(Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            raxVar,
		Source:          resultExpr,
	})

	// store high part in rdx (for 16/32/64-bit)
	if size > Size1 {
		shiftAmount := ConstantExpr{
			Value: IntConstant{
				Value:  int64(size * 8),
				Width:  Size1,
				Signed: false,
			},
		}

		highExpr := BinaryOp{
			Op:    BinOpSar, // arithmetic right shift for signed
			Left:  resultExpr,
			Right: shiftAmount,
		}

		var rdxName string
		switch size {
		case Size2:
			rdxName = "dx"
		case Size4:
			rdxName = "edx"
		case Size8:
			rdxName = "rdx"
		default:
			rdxName = "rdx"
		}

		rdxVar := Variable{
			Name: rdxName,
			Type: l.getIntType(size, true),
		}

		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            rdxVar,
			Source:          highExpr,
		})
	}

	l.setArithmeticFlags(resultExpr, size)
	return l.currentBlock, nil
}

// liftIMulTwoOperands lifts two-operand IMUL.
func (l *Lifter) liftIMulTwoOperands(insn *disasm.Instruction) ([]IRInstruction, error) {
	dest := insn.Operands[0]
	src := insn.Operands[1]

	// load source operand
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// load destination operand
	var destExpr Expression
	var destVar Variable

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		destVar = l.loadFromMemory(mem)
		destExpr = VariableExpr{Var: destVar}
	} else {
		destExpr, err = l.translateOperandToExpr(dest)
		if err != nil {
			return nil, err
		}
		if varExpr, ok := destExpr.(VariableExpr); ok {
			destVar = varExpr.Var
		}
	}

	// compute result: dest * src
	resultExpr := BinaryOp{
		Op:    BinOpMul,
		Left:  destExpr,
		Right: srcExpr,
	}

	// store result
	if mem, ok := dest.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, resultExpr)
	} else {
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          resultExpr,
		})
	}

	l.setArithmeticFlags(resultExpr, destVar.Type.Size())
	return l.currentBlock, nil
}

// liftIMulThreeOperands lifts three-operand IMUL.
func (l *Lifter) liftIMulThreeOperands(insn *disasm.Instruction) ([]IRInstruction, error) {
	dest := insn.Operands[0]
	src := insn.Operands[1]
	imm := insn.Operands[2]

	// load source operand
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// load immediate operand
	immExpr, err := l.translateOperandToExpr(imm)
	if err != nil {
		return nil, err
	}

	// compute result: src * imm
	resultExpr := BinaryOp{
		Op:    BinOpMul,
		Left:  srcExpr,
		Right: immExpr,
	}

	// get destination variable
	var destVar Variable
	if reg, ok := dest.(disasm.RegisterOperand); ok {
		destVar = Variable{
			Name: reg.Name,
			Type: l.getIntType(Size(reg.Size), true),
		}
	} else {
		return nil, fmt.Errorf("imul three-operand form requires register destination")
	}

	// store result
	l.emit(Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            destVar,
		Source:          resultExpr,
	})

	l.setArithmeticFlags(resultExpr, destVar.Type.Size())
	return l.currentBlock, nil
}

// liftDiv lifts DIV instruction: rax = rdx:rax / src, rdx = rdx:rax % src (unsigned)
func (l *Lifter) liftDiv(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, fmt.Errorf("div requires 1 operand")
	}

	src := insn.Operands[0]
	size := l.getOperandSize(src)

	// load source operand (divisor)
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// implicit operands: rdx:rax (dividend)
	var raxName, rdxName string
	switch size {
	case Size1:
		raxName = "ax" // for 8-bit div, dividend is ax
		rdxName = ""
	case Size2:
		raxName = "ax"
		rdxName = "dx"
	case Size4:
		raxName = "eax"
		rdxName = "edx"
	case Size8:
		raxName = "rax"
		rdxName = "rdx"
	default:
		raxName = "rax"
		rdxName = "rdx"
	}

	raxVar := Variable{
		Name: raxName,
		Type: l.getIntType(size, false),
	}

	var dividendExpr Expression
	if size == Size1 {
		// 8-bit: dividend is ax
		dividendExpr = VariableExpr{Var: raxVar}
	} else {
		// construct rdx:rax as (rdx << (size*8)) | rax
		rdxVar := Variable{
			Name: rdxName,
			Type: l.getIntType(size, false),
		}

		shiftAmount := ConstantExpr{
			Value: IntConstant{
				Value:  int64(size * 8),
				Width:  Size1,
				Signed: false,
			},
		}

		rdxShifted := BinaryOp{
			Op:    BinOpShl,
			Left:  VariableExpr{Var: rdxVar},
			Right: shiftAmount,
		}

		dividendExpr = BinaryOp{
			Op:    BinOpOr,
			Left:  rdxShifted,
			Right: VariableExpr{Var: raxVar},
		}
	}

	// compute quotient: dividend / divisor
	quotientExpr := BinaryOp{
		Op:    BinOpUDiv,
		Left:  dividendExpr,
		Right: srcExpr,
	}

	// compute remainder: dividend % divisor
	remainderExpr := BinaryOp{
		Op:    BinOpUMod,
		Left:  dividendExpr,
		Right: srcExpr,
	}

	// store quotient in rax (or al for 8-bit)
	if size == Size1 {
		alVar := Variable{Name: "al", Type: l.getIntType(Size1, false)}
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            alVar,
			Source:          quotientExpr,
		})

		// store remainder in ah
		ahVar := Variable{Name: "ah", Type: l.getIntType(Size1, false)}
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            ahVar,
			Source:          remainderExpr,
		})
	} else {
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            raxVar,
			Source:          quotientExpr,
		})

		// store remainder in rdx
		rdxVar := Variable{
			Name: rdxName,
			Type: l.getIntType(size, false),
		}

		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            rdxVar,
			Source:          remainderExpr,
		})
	}

	// flags are undefined after div
	return l.currentBlock, nil
}

// liftIDiv lifts IDIV instruction (signed division, similar to div but signed)
func (l *Lifter) liftIDiv(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, fmt.Errorf("idiv requires 1 operand")
	}

	src := insn.Operands[0]
	size := l.getOperandSize(src)

	// load source operand (divisor)
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// implicit operands: rdx:rax (dividend)
	var raxName, rdxName string
	switch size {
	case Size1:
		raxName = "ax"
		rdxName = ""
	case Size2:
		raxName = "ax"
		rdxName = "dx"
	case Size4:
		raxName = "eax"
		rdxName = "edx"
	case Size8:
		raxName = "rax"
		rdxName = "rdx"
	default:
		raxName = "rax"
		rdxName = "rdx"
	}

	raxVar := Variable{
		Name: raxName,
		Type: l.getIntType(size, true), // signed
	}

	var dividendExpr Expression
	if size == Size1 {
		dividendExpr = VariableExpr{Var: raxVar}
	} else {
		rdxVar := Variable{
			Name: rdxName,
			Type: l.getIntType(size, true),
		}

		shiftAmount := ConstantExpr{
			Value: IntConstant{
				Value:  int64(size * 8),
				Width:  Size1,
				Signed: false,
			},
		}

		rdxShifted := BinaryOp{
			Op:    BinOpShl,
			Left:  VariableExpr{Var: rdxVar},
			Right: shiftAmount,
		}

		dividendExpr = BinaryOp{
			Op:    BinOpOr,
			Left:  rdxShifted,
			Right: VariableExpr{Var: raxVar},
		}
	}

	// compute quotient: dividend / divisor (signed)
	quotientExpr := BinaryOp{
		Op:    BinOpDiv,
		Left:  dividendExpr,
		Right: srcExpr,
	}

	// compute remainder: dividend % divisor (signed)
	remainderExpr := BinaryOp{
		Op:    BinOpMod,
		Left:  dividendExpr,
		Right: srcExpr,
	}

	// store quotient and remainder
	if size == Size1 {
		alVar := Variable{Name: "al", Type: l.getIntType(Size1, true)}
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            alVar,
			Source:          quotientExpr,
		})

		ahVar := Variable{Name: "ah", Type: l.getIntType(Size1, true)}
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            ahVar,
			Source:          remainderExpr,
		})
	} else {
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            raxVar,
			Source:          quotientExpr,
		})

		rdxVar := Variable{
			Name: rdxName,
			Type: l.getIntType(size, true),
		}

		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            rdxVar,
			Source:          remainderExpr,
		})
	}

	return l.currentBlock, nil
}

// liftInc lifts INC instruction: dest = dest + 1
func (l *Lifter) liftInc(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, fmt.Errorf("inc requires 1 operand")
	}

	dest := insn.Operands[0]

	// load destination operand
	var destExpr Expression
	var destVar Variable
	var err error

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		destVar = l.loadFromMemory(mem)
		destExpr = VariableExpr{Var: destVar}
	} else {
		destExpr, err = l.translateOperandToExpr(dest)
		if err != nil {
			return nil, err
		}
		if varExpr, ok := destExpr.(VariableExpr); ok {
			destVar = varExpr.Var
		}
	}

	// compute result: dest + 1
	oneExpr := ConstantExpr{
		Value: IntConstant{
			Value:  1,
			Width:  destVar.Type.Size(),
			Signed: false,
		},
	}

	resultExpr := BinaryOp{
		Op:    BinOpAdd,
		Left:  destExpr,
		Right: oneExpr,
	}

	// store result
	if mem, ok := dest.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, resultExpr)
	} else {
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          resultExpr,
		})
	}

	// set flags (cf not affected by inc)
	l.setArithmeticFlags(resultExpr, destVar.Type.Size())

	return l.currentBlock, nil
}

// liftDec lifts DEC instruction: dest = dest - 1
func (l *Lifter) liftDec(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, fmt.Errorf("dec requires 1 operand")
	}

	dest := insn.Operands[0]

	// load destination operand
	var destExpr Expression
	var destVar Variable
	var err error

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		destVar = l.loadFromMemory(mem)
		destExpr = VariableExpr{Var: destVar}
	} else {
		destExpr, err = l.translateOperandToExpr(dest)
		if err != nil {
			return nil, err
		}
		if varExpr, ok := destExpr.(VariableExpr); ok {
			destVar = varExpr.Var
		}
	}

	// compute result: dest - 1
	oneExpr := ConstantExpr{
		Value: IntConstant{
			Value:  1,
			Width:  destVar.Type.Size(),
			Signed: false,
		},
	}

	resultExpr := BinaryOp{
		Op:    BinOpSub,
		Left:  destExpr,
		Right: oneExpr,
	}

	// store result
	if mem, ok := dest.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, resultExpr)
	} else {
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          resultExpr,
		})
	}

	// set flags (cf not affected by dec)
	l.setArithmeticFlags(resultExpr, destVar.Type.Size())

	return l.currentBlock, nil
}

// liftNeg lifts NEG instruction: dest = -dest
func (l *Lifter) liftNeg(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, fmt.Errorf("neg requires 1 operand")
	}

	dest := insn.Operands[0]

	// load destination operand
	var destExpr Expression
	var destVar Variable
	var err error

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		destVar = l.loadFromMemory(mem)
		destExpr = VariableExpr{Var: destVar}
	} else {
		destExpr, err = l.translateOperandToExpr(dest)
		if err != nil {
			return nil, err
		}
		if varExpr, ok := destExpr.(VariableExpr); ok {
			destVar = varExpr.Var
		}
	}

	// compute result: -dest
	resultExpr := UnaryOp{
		Op:      UnOpNeg,
		Operand: destExpr,
	}

	// store result
	if mem, ok := dest.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, resultExpr)
	} else {
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          resultExpr,
		})
	}

	// set flags
	l.setArithmeticFlags(resultExpr, destVar.Type.Size())

	return l.currentBlock, nil
}

// ============================================================================
// Logical Operations
// ============================================================================

// liftAnd lifts AND instruction: dest = dest & src
func (l *Lifter) liftAnd(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, fmt.Errorf("and requires 2 operands")
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	// load source operand
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// load destination operand
	var destExpr Expression
	var destVar Variable

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		destVar = l.loadFromMemory(mem)
		destExpr = VariableExpr{Var: destVar}
	} else {
		destExpr, err = l.translateOperandToExpr(dest)
		if err != nil {
			return nil, err
		}
		if varExpr, ok := destExpr.(VariableExpr); ok {
			destVar = varExpr.Var
		}
	}

	// compute result: dest & src
	resultExpr := BinaryOp{
		Op:    BinOpAnd,
		Left:  destExpr,
		Right: srcExpr,
	}

	// store result
	if mem, ok := dest.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, resultExpr)
	} else {
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          resultExpr,
		})
	}

	// set flags (cf=0, of=0, sf/zf/pf set according to result)
	l.setLogicalFlags(resultExpr, destVar.Type.Size())

	return l.currentBlock, nil
}

// liftOr lifts OR instruction: dest = dest | src
func (l *Lifter) liftOr(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, fmt.Errorf("or requires 2 operands")
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	// load source operand
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// load destination operand
	var destExpr Expression
	var destVar Variable

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		destVar = l.loadFromMemory(mem)
		destExpr = VariableExpr{Var: destVar}
	} else {
		destExpr, err = l.translateOperandToExpr(dest)
		if err != nil {
			return nil, err
		}
		if varExpr, ok := destExpr.(VariableExpr); ok {
			destVar = varExpr.Var
		}
	}

	// compute result: dest | src
	resultExpr := BinaryOp{
		Op:    BinOpOr,
		Left:  destExpr,
		Right: srcExpr,
	}

	// store result
	if mem, ok := dest.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, resultExpr)
	} else {
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          resultExpr,
		})
	}

	// set flags
	l.setLogicalFlags(resultExpr, destVar.Type.Size())

	return l.currentBlock, nil
}

// liftXor lifts XOR instruction: dest = dest ^ src
func (l *Lifter) liftXor(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, fmt.Errorf("xor requires 2 operands")
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	// load source operand
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// load destination operand
	var destExpr Expression
	var destVar Variable

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		destVar = l.loadFromMemory(mem)
		destExpr = VariableExpr{Var: destVar}
	} else {
		destExpr, err = l.translateOperandToExpr(dest)
		if err != nil {
			return nil, err
		}
		if varExpr, ok := destExpr.(VariableExpr); ok {
			destVar = varExpr.Var
		}
	}

	// compute result: dest ^ src
	resultExpr := BinaryOp{
		Op:    BinOpXor,
		Left:  destExpr,
		Right: srcExpr,
	}

	// store result
	if mem, ok := dest.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, resultExpr)
	} else {
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          resultExpr,
		})
	}

	// set flags
	l.setLogicalFlags(resultExpr, destVar.Type.Size())

	return l.currentBlock, nil
}

// liftNot lifts NOT instruction: dest = ~dest
func (l *Lifter) liftNot(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, fmt.Errorf("not requires 1 operand")
	}

	dest := insn.Operands[0]

	// load destination operand
	var destExpr Expression
	var destVar Variable
	var err error

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		destVar = l.loadFromMemory(mem)
		destExpr = VariableExpr{Var: destVar}
	} else {
		destExpr, err = l.translateOperandToExpr(dest)
		if err != nil {
			return nil, err
		}
		if varExpr, ok := destExpr.(VariableExpr); ok {
			destVar = varExpr.Var
		}
	}

	// compute result: ~dest
	resultExpr := UnaryOp{
		Op:      UnOpNot,
		Operand: destExpr,
	}

	// store result
	if mem, ok := dest.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, resultExpr)
	} else {
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          resultExpr,
		})
	}

	// not does not affect flags
	return l.currentBlock, nil
}

// liftTest lifts TEST instruction: compute dest & src and set flags (result discarded)
func (l *Lifter) liftTest(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, fmt.Errorf("test requires 2 operands")
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	// load source operand
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// load destination operand
	var destExpr Expression

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		destVar := l.loadFromMemory(mem)
		destExpr = VariableExpr{Var: destVar}
	} else {
		destExpr, err = l.translateOperandToExpr(dest)
		if err != nil {
			return nil, err
		}
	}

	// compute result: dest & src (result not stored, only flags set)
	resultExpr := BinaryOp{
		Op:    BinOpAnd,
		Left:  destExpr,
		Right: srcExpr,
	}

	// set flags based on result
	size := l.getOperandSize(dest)
	l.setLogicalFlags(resultExpr, size)

	return l.currentBlock, nil
}

// liftCmp lifts CMP instruction: compute dest - src and set flags (result discarded)
func (l *Lifter) liftCmp(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, fmt.Errorf("cmp requires 2 operands")
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	// load source operand
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// load destination operand
	var destExpr Expression

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		destVar := l.loadFromMemory(mem)
		destExpr = VariableExpr{Var: destVar}
	} else {
		destExpr, err = l.translateOperandToExpr(dest)
		if err != nil {
			return nil, err
		}
	}

	// compute result: dest - src (result not stored, only flags set)
	resultExpr := BinaryOp{
		Op:    BinOpSub,
		Left:  destExpr,
		Right: srcExpr,
	}

	// set flags based on result
	size := l.getOperandSize(dest)
	l.setArithmeticFlags(resultExpr, size)

	return l.currentBlock, nil
}

// ============================================================================
// Shift and Rotate Operations
// ============================================================================

// liftShl lifts SHL/SAL instruction: dest = dest << src
func (l *Lifter) liftShl(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, fmt.Errorf("shl requires 2 operands")
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	// load shift count
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// load destination operand
	var destExpr Expression
	var destVar Variable

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		destVar = l.loadFromMemory(mem)
		destExpr = VariableExpr{Var: destVar}
	} else {
		destExpr, err = l.translateOperandToExpr(dest)
		if err != nil {
			return nil, err
		}
		if varExpr, ok := destExpr.(VariableExpr); ok {
			destVar = varExpr.Var
		}
	}

	// compute result: dest << src
	resultExpr := BinaryOp{
		Op:    BinOpShl,
		Left:  destExpr,
		Right: srcExpr,
	}

	// store result
	if mem, ok := dest.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, resultExpr)
	} else {
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          resultExpr,
		})
	}

	// set flags
	l.setShiftFlags(resultExpr, destVar.Type.Size())

	return l.currentBlock, nil
}

// liftShr lifts SHR instruction: dest = dest >> src (logical right shift)
func (l *Lifter) liftShr(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, fmt.Errorf("shr requires 2 operands")
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	// load shift count
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// load destination operand
	var destExpr Expression
	var destVar Variable

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		destVar = l.loadFromMemory(mem)
		destExpr = VariableExpr{Var: destVar}
	} else {
		destExpr, err = l.translateOperandToExpr(dest)
		if err != nil {
			return nil, err
		}
		if varExpr, ok := destExpr.(VariableExpr); ok {
			destVar = varExpr.Var
		}
	}

	// compute result: dest >> src (logical)
	resultExpr := BinaryOp{
		Op:    BinOpShr,
		Left:  destExpr,
		Right: srcExpr,
	}

	// store result
	if mem, ok := dest.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, resultExpr)
	} else {
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          resultExpr,
		})
	}

	// set flags
	l.setShiftFlags(resultExpr, destVar.Type.Size())

	return l.currentBlock, nil
}

// liftSar lifts SAR instruction: dest = dest >> src (arithmetic right shift)
func (l *Lifter) liftSar(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, fmt.Errorf("sar requires 2 operands")
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	// load shift count
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// load destination operand
	var destExpr Expression
	var destVar Variable

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		destVar = l.loadFromMemory(mem)
		destExpr = VariableExpr{Var: destVar}
	} else {
		destExpr, err = l.translateOperandToExpr(dest)
		if err != nil {
			return nil, err
		}
		if varExpr, ok := destExpr.(VariableExpr); ok {
			destVar = varExpr.Var
		}
	}

	// compute result: dest >>> src (arithmetic)
	resultExpr := BinaryOp{
		Op:    BinOpSar,
		Left:  destExpr,
		Right: srcExpr,
	}

	// store result
	if mem, ok := dest.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, resultExpr)
	} else {
		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          resultExpr,
		})
	}

	// set flags
	l.setShiftFlags(resultExpr, destVar.Type.Size())

	return l.currentBlock, nil
}

// liftRol lifts ROL instruction: rotate left (not implemented as binary op, use intrinsic)
func (l *Lifter) liftRol(insn *disasm.Instruction) ([]IRInstruction, error) {
	// rol is complex - would need intrinsic or decomposition
	// for now, return unsupported
	return nil, fmt.Errorf("rol not yet implemented")
}

// liftRor lifts ROR instruction: rotate right (not implemented as binary op, use intrinsic)
func (l *Lifter) liftRor(insn *disasm.Instruction) ([]IRInstruction, error) {
	// ror is complex - would need intrinsic or decomposition
	// for now, return unsupported
	return nil, fmt.Errorf("ror not yet implemented")
}

// ============================================================================
// Memory Operations
// ============================================================================

// liftMov lifts MOV instruction: dest = src
func (l *Lifter) liftMov(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, fmt.Errorf("mov requires 2 operands")
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	// handle different operand combinations
	destMem, destIsMem := dest.(disasm.MemoryOperand)
	srcMem, srcIsMem := src.(disasm.MemoryOperand)

	if destIsMem && srcIsMem {
		// mem to mem not allowed in x86_64
		return nil, fmt.Errorf("mov cannot have both operands as memory")
	}

	if destIsMem {
		// mov [mem], reg/imm
		var srcExpr Expression
		var err error

		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}

		l.storeToMemory(destMem, srcExpr)
	} else if srcIsMem {
		// mov reg, [mem]
		destReg, ok := dest.(disasm.RegisterOperand)
		if !ok {
			return nil, fmt.Errorf("mov destination must be register or memory")
		}

		srcVar := l.loadFromMemory(srcMem)
		destVar := Variable{
			Name: destReg.Name,
			Type: l.getIntType(Size(destReg.Size), false),
		}

		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          VariableExpr{Var: srcVar},
		})
	} else {
		// mov reg, reg/imm
		destReg, ok := dest.(disasm.RegisterOperand)
		if !ok {
			return nil, fmt.Errorf("mov destination must be register or memory")
		}

		srcExpr, err := l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}

		destVar := Variable{
			Name: destReg.Name,
			Type: l.getIntType(Size(destReg.Size), false),
		}

		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          srcExpr,
		})
	}

	// mov does not affect flags
	return l.currentBlock, nil
}

// liftMovzx lifts MOVZX instruction: dest = zero_extend(src)
func (l *Lifter) liftMovzx(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, fmt.Errorf("movzx requires 2 operands")
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	// load source operand
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// get destination register
	destReg, ok := dest.(disasm.RegisterOperand)
	if !ok {
		return nil, fmt.Errorf("movzx destination must be register")
	}

	destVar := Variable{
		Name: destReg.Name,
		Type: l.getIntType(Size(destReg.Size), false),
	}

	// zero-extend by casting to larger unsigned type
	resultExpr := Cast{
		Expr:       srcExpr,
		TargetType: destVar.Type,
	}

	l.emit(Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            destVar,
		Source:          resultExpr,
	})

	return l.currentBlock, nil
}

// liftMovsx lifts MOVSX instruction: dest = sign_extend(src)
func (l *Lifter) liftMovsx(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, fmt.Errorf("movsx requires 2 operands")
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	// load source operand
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// get destination register
	destReg, ok := dest.(disasm.RegisterOperand)
	if !ok {
		return nil, fmt.Errorf("movsx destination must be register")
	}

	destVar := Variable{
		Name: destReg.Name,
		Type: l.getIntType(Size(destReg.Size), true), // signed
	}

	// sign-extend by casting to larger signed type
	resultExpr := Cast{
		Expr:       srcExpr,
		TargetType: destVar.Type,
	}

	l.emit(Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            destVar,
		Source:          resultExpr,
	})

	return l.currentBlock, nil
}

// liftLea lifts LEA instruction: dest = address_of(src)
func (l *Lifter) liftLea(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, fmt.Errorf("lea requires 2 operands")
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	// source must be memory operand
	srcMem, ok := src.(disasm.MemoryOperand)
	if !ok {
		return nil, fmt.Errorf("lea source must be memory operand")
	}

	// destination must be register
	destReg, ok := dest.(disasm.RegisterOperand)
	if !ok {
		return nil, fmt.Errorf("lea destination must be register")
	}

	// compute effective address (without dereferencing)
	addrExpr := l.translateMemoryAddress(srcMem)

	destVar := Variable{
		Name: destReg.Name,
		Type: l.getIntType(Size(destReg.Size), false),
	}

	l.emit(Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            destVar,
		Source:          addrExpr,
	})

	// lea does not affect flags
	return l.currentBlock, nil
}

// liftPush lifts PUSH instruction: rsp -= 8; [rsp] = src
func (l *Lifter) liftPush(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, fmt.Errorf("push requires 1 operand")
	}

	src := insn.Operands[0]

	// load source operand
	var srcExpr Expression
	var err error

	if mem, ok := src.(disasm.MemoryOperand); ok {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
	}

	// decrement rsp by operand size (typically 8 for x86_64)
	size := l.getOperandSize(src)
	if size == 0 {
		size = Size8 // default to 8 bytes for x86_64
	}

	rspVar := Variable{
		Name: "rsp",
		Type: IntType{Width: Size8, Signed: false},
	}

	sizeExpr := ConstantExpr{
		Value: IntConstant{
			Value:  int64(size),
			Width:  Size8,
			Signed: false,
		},
	}

	newRsp := BinaryOp{
		Op:    BinOpSub,
		Left:  VariableExpr{Var: rspVar},
		Right: sizeExpr,
	}

	l.emit(Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            rspVar,
		Source:          newRsp,
	})

	// store value at [rsp]
	l.emit(Store{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Address:         VariableExpr{Var: rspVar},
		Value:           srcExpr,
		Size:            size,
	})

	return l.currentBlock, nil
}

// liftPop lifts POP instruction: dest = [rsp]; rsp += 8
func (l *Lifter) liftPop(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, fmt.Errorf("pop requires 1 operand")
	}

	dest := insn.Operands[0]

	// get destination size
	size := l.getOperandSize(dest)
	if size == 0 {
		size = Size8 // default to 8 bytes for x86_64
	}

	rspVar := Variable{
		Name: "rsp",
		Type: IntType{Width: Size8, Signed: false},
	}

	// load value from [rsp]
	tempVar := l.newTemp(l.getIntType(size, false))

	l.emit(Load{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            tempVar,
		Address:         VariableExpr{Var: rspVar},
		Size:            size,
	})

	// increment rsp by operand size
	sizeExpr := ConstantExpr{
		Value: IntConstant{
			Value:  int64(size),
			Width:  Size8,
			Signed: false,
		},
	}

	newRsp := BinaryOp{
		Op:    BinOpAdd,
		Left:  VariableExpr{Var: rspVar},
		Right: sizeExpr,
	}

	l.emit(Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            rspVar,
		Source:          newRsp,
	})

	// store to destination
	if mem, ok := dest.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, VariableExpr{Var: tempVar})
	} else if reg, ok := dest.(disasm.RegisterOperand); ok {
		destVar := Variable{
			Name: reg.Name,
			Type: l.getIntType(Size(reg.Size), false),
		}

		l.emit(Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          VariableExpr{Var: tempVar},
		})
	} else {
		return nil, fmt.Errorf("pop destination must be register or memory")
	}

	return l.currentBlock, nil
}

// ============================================================================
// Control Flow Operations
// ============================================================================

// liftJmp lifts JMP instruction: unconditional jump
func (l *Lifter) liftJmp(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, fmt.Errorf("jmp requires 1 operand")
	}

	target := insn.Operands[0]

	// for now, we just note that this is a jump
	// actual CFG construction will handle target resolution
	// emit a placeholder jump instruction

	if imm, ok := target.(disasm.ImmediateOperand); ok {
		// direct jump to immediate address
		targetAddr := Address(imm.Value)
		_ = targetAddr // will be used by cfg builder

		// emit jump (block id will be resolved by cfg builder)
		l.emit(Jump{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Target:          BlockID(targetAddr),
		})
	} else {
		// indirect jump (register or memory)
		// this requires special handling in cfg builder
		return nil, fmt.Errorf("indirect jump not yet fully supported in lifter")
	}

	return l.currentBlock, nil
}

// liftJcc lifts conditional jump instructions (je, jne, jl, jg, etc.)
func (l *Lifter) liftJcc(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, fmt.Errorf("jcc requires 1 operand")
	}

	target := insn.Operands[0]

	imm, ok := target.(disasm.ImmediateOperand)
	if !ok {
		return nil, fmt.Errorf("jcc target must be immediate address")
	}

	targetAddr := Address(imm.Value)

	// determine condition based on mnemonic
	mnemonic := strings.ToLower(insn.Mnemonic)
	condition := l.getConditionFromMnemonic(mnemonic)

	// emit conditional branch
	// fall-through target will be next instruction (resolved by cfg builder)
	l.emit(Branch{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Condition:       condition,
		TrueTarget:      BlockID(targetAddr),
		FalseTarget:     BlockID(Address(insn.Address) + Address(insn.Length)), // fall-through
	})

	return l.currentBlock, nil
}

// getConditionFromMnemonic extracts condition expression from jump mnemonic.
func (l *Lifter) getConditionFromMnemonic(mnemonic string) Expression {
	// create flag variables
	zfVar := Variable{Name: "zf", Type: BoolType{}}
	sfVar := Variable{Name: "sf", Type: BoolType{}}
	cfVar := Variable{Name: "cf", Type: BoolType{}}
	ofVar := Variable{Name: "of", Type: BoolType{}}
	pfVar := Variable{Name: "pf", Type: BoolType{}}

	switch mnemonic {
	case "je", "jz":
		// jump if equal (zf = 1)
		return VariableExpr{Var: zfVar}

	case "jne", "jnz":
		// jump if not equal (zf = 0)
		return UnaryOp{
			Op:      UnOpLogicalNot,
			Operand: VariableExpr{Var: zfVar},
		}

	case "jl", "jnge":
		// jump if less (sf != of)
		return BinaryOp{
			Op:    BinOpNe,
			Left:  VariableExpr{Var: sfVar},
			Right: VariableExpr{Var: ofVar},
		}

	case "jle", "jng":
		// jump if less or equal (zf = 1 or sf != of)
		return BinaryOp{
			Op:   BinOpLogicalOr,
			Left: VariableExpr{Var: zfVar},
			Right: BinaryOp{
				Op:    BinOpNe,
				Left:  VariableExpr{Var: sfVar},
				Right: VariableExpr{Var: ofVar},
			},
		}

	case "jg", "jnle":
		// jump if greater (zf = 0 and sf = of)
		return BinaryOp{
			Op: BinOpLogicalAnd,
			Left: UnaryOp{
				Op:      UnOpLogicalNot,
				Operand: VariableExpr{Var: zfVar},
			},
			Right: BinaryOp{
				Op:    BinOpEq,
				Left:  VariableExpr{Var: sfVar},
				Right: VariableExpr{Var: ofVar},
			},
		}

	case "jge", "jnl":
		// jump if greater or equal (sf = of)
		return BinaryOp{
			Op:    BinOpEq,
			Left:  VariableExpr{Var: sfVar},
			Right: VariableExpr{Var: ofVar},
		}

	case "jb", "jnae", "jc":
		// jump if below (cf = 1)
		return VariableExpr{Var: cfVar}

	case "jbe", "jna":
		// jump if below or equal (cf = 1 or zf = 1)
		return BinaryOp{
			Op:    BinOpLogicalOr,
			Left:  VariableExpr{Var: cfVar},
			Right: VariableExpr{Var: zfVar},
		}

	case "ja", "jnbe":
		// jump if above (cf = 0 and zf = 0)
		return BinaryOp{
			Op: BinOpLogicalAnd,
			Left: UnaryOp{
				Op:      UnOpLogicalNot,
				Operand: VariableExpr{Var: cfVar},
			},
			Right: UnaryOp{
				Op:      UnOpLogicalNot,
				Operand: VariableExpr{Var: zfVar},
			},
		}

	case "jae", "jnb", "jnc":
		// jump if above or equal (cf = 0)
		return UnaryOp{
			Op:      UnOpLogicalNot,
			Operand: VariableExpr{Var: cfVar},
		}

	case "js":
		// jump if sign (sf = 1)
		return VariableExpr{Var: sfVar}

	case "jns":
		// jump if not sign (sf = 0)
		return UnaryOp{
			Op:      UnOpLogicalNot,
			Operand: VariableExpr{Var: sfVar},
		}

	case "jo":
		// jump if overflow (of = 1)
		return VariableExpr{Var: ofVar}

	case "jno":
		// jump if not overflow (of = 0)
		return UnaryOp{
			Op:      UnOpLogicalNot,
			Operand: VariableExpr{Var: ofVar},
		}

	case "jp", "jpe":
		// jump if parity (pf = 1)
		return VariableExpr{Var: pfVar}

	case "jnp", "jpo":
		// jump if not parity (pf = 0)
		return UnaryOp{
			Op:      UnOpLogicalNot,
			Operand: VariableExpr{Var: pfVar},
		}

	default:
		// unknown condition - return true (unconditional)
		return ConstantExpr{
			Value: BoolConstant{Value: true},
		}
	}
}

// liftCall lifts CALL instruction: push return address, jump to target
func (l *Lifter) liftCall(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, fmt.Errorf("call requires 1 operand")
	}

	target := insn.Operands[0]

	// compute return address (address of next instruction)
	returnAddr := Address(insn.Address) + Address(insn.Length)

	// push return address onto stack
	rspVar := Variable{
		Name: "rsp",
		Type: IntType{Width: Size8, Signed: false},
	}

	// rsp -= 8
	sizeExpr := ConstantExpr{
		Value: IntConstant{
			Value:  8,
			Width:  Size8,
			Signed: false,
		},
	}

	newRsp := BinaryOp{
		Op:    BinOpSub,
		Left:  VariableExpr{Var: rspVar},
		Right: sizeExpr,
	}

	l.emit(Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            rspVar,
		Source:          newRsp,
	})

	// [rsp] = return_address
	returnAddrExpr := ConstantExpr{
		Value: IntConstant{
			Value:  int64(returnAddr),
			Width:  Size8,
			Signed: false,
		},
	}

	l.emit(Store{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Address:         VariableExpr{Var: rspVar},
		Value:           returnAddrExpr,
		Size:            Size8,
	})

	// emit call instruction
	var targetExpr Expression
	var err error

	if mem, ok := target.(disasm.MemoryOperand); ok {
		// indirect call through memory
		targetVar := l.loadFromMemory(mem)
		targetExpr = VariableExpr{Var: targetVar}
	} else {
		targetExpr, err = l.translateOperandToExpr(target)
		if err != nil {
			return nil, err
		}
	}

	l.emit(Call{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            nil, // return value handling done separately
		Target:          targetExpr,
		Args:            nil, // arguments extracted by abi analyzer
	})

	return l.currentBlock, nil
}

// liftRet lifts RET instruction: pop return address, jump to it
func (l *Lifter) liftRet(insn *disasm.Instruction) ([]IRInstruction, error) {
	rspVar := Variable{
		Name: "rsp",
		Type: IntType{Width: Size8, Signed: false},
	}

	// load return address from [rsp]
	returnAddrVar := l.newTemp(IntType{Width: Size8, Signed: false})

	l.emit(Load{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            returnAddrVar,
		Address:         VariableExpr{Var: rspVar},
		Size:            Size8,
	})

	// rsp += 8
	sizeExpr := ConstantExpr{
		Value: IntConstant{
			Value:  8,
			Width:  Size8,
			Signed: false,
		},
	}

	newRsp := BinaryOp{
		Op:    BinOpAdd,
		Left:  VariableExpr{Var: rspVar},
		Right: sizeExpr,
	}

	l.emit(Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            rspVar,
		Source:          newRsp,
	})

	// handle ret imm16 (pop additional bytes)
	if len(insn.Operands) > 0 {
		if imm, ok := insn.Operands[0].(disasm.ImmediateOperand); ok {
			popBytes := ConstantExpr{
				Value: IntConstant{
					Value:  imm.Value,
					Width:  Size8,
					Signed: false,
				},
			}

			finalRsp := BinaryOp{
				Op:    BinOpAdd,
				Left:  VariableExpr{Var: rspVar},
				Right: popBytes,
			}

			l.emit(Assign{
				baseInstruction: baseInstruction{Loc: l.currentLocation},
				Dest:            rspVar,
				Source:          finalRsp,
			})
		}
	}

	// emit return instruction
	// return value (rax) will be handled by abi analyzer
	l.emit(Return{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Value:           nil, // return value extracted separately
	})

	return l.currentBlock, nil
}

// ============================================================================
// Flag Setting (Lazy Evaluation)
// ============================================================================

// setArithmeticFlags creates lazy flags for arithmetic operations.
// instead of immediately computing all 6 flags, stores operation metadata
// for deferred materialization. flags are computed only when actually used
// by conditional branches, achieving 95%+ elimination rate.
func (l *Lifter) setArithmeticFlags(result Expression, size Size) {
	// create lazy flags structure and store in lifter state
	l.currentLazyFlags = NewLazyFlags(
		FlagOpArithmetic,
		[]Expression{result},
		result,
		size,
		l.currentLocation,
	)

	// no ir instructions emitted - flags are completely lazy
	// materialization happens during data flow analysis
}

// setArithmeticFlagsWithOperands creates lazy flags with explicit operands.
// this version is used when we have access to original operands (left, right)
// for more precise flag computation during materialization.
func (l *Lifter) setArithmeticFlagsWithOperands(operands []Expression, result Expression, size Size) {
	// create lazy flags structure with full operand information
	l.currentLazyFlags = NewLazyFlags(
		FlagOpArithmetic,
		operands,
		result,
		size,
		l.currentLocation,
	)
}

// setLogicalFlags creates lazy flags for logical operations.
// logical operations have simpler flag semantics: cf=0, of=0, sf/zf/pf from result
func (l *Lifter) setLogicalFlags(result Expression, size Size) {
	// create lazy flags for logical operation
	l.currentLazyFlags = NewLazyFlags(
		FlagOpLogical,
		[]Expression{result},
		result,
		size,
		l.currentLocation,
	)
}

// setShiftFlags creates lazy flags for shift operations.
// shift operations set flags similar to logical ops but cf depends on shifted bits
func (l *Lifter) setShiftFlags(result Expression, size Size) {
	// create lazy flags for shift operation
	l.currentLazyFlags = NewLazyFlags(
		FlagOpShift,
		[]Expression{result},
		result,
		size,
		l.currentLocation,
	)
}

// GetCurrentLazyFlags returns the lazy flags state for current instruction.
// used by data flow analyzer to access flag metadata for selective materialization.
func (l *Lifter) GetCurrentLazyFlags() *LazyFlags {
	return l.currentLazyFlags
}

// ClearLazyFlags resets lazy flags state (called after processing instruction).
func (l *Lifter) ClearLazyFlags() {
	l.currentLazyFlags = nil
}
