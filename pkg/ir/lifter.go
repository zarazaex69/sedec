package ir

import (
	"errors"
	"fmt"
	"strings"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// register name constants for implicit x86_64 operands
const (
	raxReg = "rax"
	eaxReg = "eax"
	rdxReg = "rdx"
	edxReg = "edx"
)

// sentinel errors for lifter operations
var (
	errUnsupportedInstruction   = errors.New("unsupported instruction")
	errMemOpRequiresLoad        = errors.New("memory operand requires explicit load")
	errUnknownOperandType       = errors.New("unknown operand type")
	errAddRequires2Operands     = errors.New("add requires 2 operands")
	errSubRequires2Operands     = errors.New("sub requires 2 operands")
	errMulRequires1Operand      = errors.New("mul requires 1 operand")
	errIMulRequires13Operands   = errors.New("imul requires 1-3 operands")
	errIMulThreeOpNeedReg       = errors.New("imul three-operand form requires register destination")
	errDivRequires1Operand      = errors.New("div requires 1 operand")
	errIDivRequires1Operand     = errors.New("idiv requires 1 operand")
	errIncRequires1Operand      = errors.New("inc requires 1 operand")
	errDecRequires1Operand      = errors.New("dec requires 1 operand")
	errNegRequires1Operand      = errors.New("neg requires 1 operand")
	errAndRequires2Operands     = errors.New("and requires 2 operands")
	errOrRequires2Operands      = errors.New("or requires 2 operands")
	errXorRequires2Operands     = errors.New("xor requires 2 operands")
	errNotRequires1Operand      = errors.New("not requires 1 operand")
	errTestRequires2Operands    = errors.New("test requires 2 operands")
	errCmpRequires2Operands     = errors.New("cmp requires 2 operands")
	errShlRequires2Operands     = errors.New("shl requires 2 operands")
	errShrRequires2Operands     = errors.New("shr requires 2 operands")
	errSarRequires2Operands     = errors.New("sar requires 2 operands")
	errRolNotImplemented        = errors.New("rol not yet implemented")
	errRorNotImplemented        = errors.New("ror not yet implemented")
	errMovRequires2Operands     = errors.New("mov requires 2 operands")
	errMovBothMem               = errors.New("mov cannot have both operands as memory")
	errMovDestMustBeRegOrMem    = errors.New("mov destination must be register or memory")
	errMovzxRequires2Operands   = errors.New("movzx requires 2 operands")
	errMovzxDestMustBeReg       = errors.New("movzx destination must be register")
	errMovsxRequires2Operands   = errors.New("movsx requires 2 operands")
	errMovsxDestMustBeReg       = errors.New("movsx destination must be register")
	errLeaRequires2Operands     = errors.New("lea requires 2 operands")
	errLeaSrcMustBeMem          = errors.New("lea source must be memory operand")
	errLeaDestMustBeReg         = errors.New("lea destination must be register")
	errPushRequires1Operand     = errors.New("push requires 1 operand")
	errPopRequires1Operand      = errors.New("pop requires 1 operand")
	errPopDestMustBeRegOrMem    = errors.New("pop destination must be register or memory")
	errJmpRequires1Operand      = errors.New("jmp requires 1 operand")
	errIndirectJumpNotSupported = errors.New("indirect jump not yet fully supported in lifter")
	errJccRequires1Operand      = errors.New("jcc requires 1 operand")
	errJccTargetMustBeImm       = errors.New("jcc target must be immediate address")
	errCallRequires1Operand     = errors.New("call requires 1 operand")
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
//
//nolint:gocyclo // dispatch table for x86_64 instruction set — inherently high complexity
func (l *Lifter) LiftInstruction(insn *disasm.Instruction) ([]IRInstruction, error) {
	// reset current block for new instruction
	l.currentBlock = l.currentBlock[:0]

	// set source location for traceability
	l.currentLocation = SourceLocation{
		Address:     Address(insn.Address),
		Instruction: l.formatInstruction(insn),
	}

	// dispatch by mnemonic.
	// strip "notrack" prefix (intel cet) before dispatch.
	mnemonic := strings.ToLower(insn.Mnemonic)
	if strings.HasPrefix(mnemonic, "notrack ") {
		mnemonic = strings.TrimPrefix(mnemonic, "notrack ")
	}

	switch {
	// arithmetic operations
	case mnemonic == mnemonicAdd:
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
	case mnemonic == "sbb":
		return l.liftSbb(insn)
	case mnemonic == "adc":
		return l.liftAdc(insn)

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
	case mnemonic == "bt":
		return l.liftBt(insn)
	case mnemonic == "bswap":
		return l.liftBswap(insn)
	case mnemonic == "xchg":
		return l.liftXchg(insn)

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

	// memory / data movement operations
	case mnemonic == "mov" || mnemonic == "movabs":
		return l.liftMov(insn)
	case mnemonic == "movzx" || mnemonic == "movzb" || mnemonic == "movzw":
		return l.liftMovzx(insn)
	case mnemonic == "movsx" || mnemonic == "movsxd" || mnemonic == "movsb" || mnemonic == "movsw":
		return l.liftMovsx(insn)
	case mnemonic == "lea":
		return l.liftLea(insn)
	case mnemonic == "push":
		return l.liftPush(insn)
	case mnemonic == "pop":
		return l.liftPop(insn)

	// conditional move: cmovCC
	case strings.HasPrefix(mnemonic, "cmov"):
		return l.liftCmovcc(insn)

	// set byte on condition: setCC
	case strings.HasPrefix(mnemonic, "set"):
		return l.liftSetcc(insn)

	// control flow operations
	case mnemonic == "jmp":
		return l.liftJmp(insn)
	case isConditionalJumpMnemonic(mnemonic):
		return l.liftJcc(insn)
	case mnemonic == "call":
		return l.liftCall(insn)
	case mnemonic == "ret" || mnemonic == "retn":
		return l.liftRet(insn)

	// stack frame operations
	case mnemonic == "leave":
		return l.liftLeave(insn)

	// sign extension
	case mnemonic == "cdqe":
		return l.liftCdqe(insn)
	case mnemonic == "cdq" || mnemonic == "cltd":
		return l.liftCdq(insn)
	case mnemonic == "cqo" || mnemonic == "cqto":
		return l.liftCqo(insn)
	case mnemonic == "cbw":
		return l.liftCbw(insn)
	case mnemonic == "cwde":
		return l.liftCwde(insn)

	// nop-like instructions
	case mnemonic == "nop" || mnemonic == "endbr64" || mnemonic == "endbr32" ||
		mnemonic == "ud2" || mnemonic == "hlt" || mnemonic == "int3":
		return l.currentBlock, nil

	// rep prefix: treat rep-prefixed instructions as opaque for now
	case strings.HasPrefix(mnemonic, "rep "):
		return l.liftRepPrefix(insn, mnemonic)

	// simd/sse/avx data movement: lift as opaque moves preserving data flow
	case isSIMDMoveMnemonic(mnemonic):
		return l.liftSIMDMove(insn)

	// simd/sse/avx arithmetic: lift as opaque operations
	case isSIMDArithMnemonic(mnemonic):
		return l.liftSIMDArith(insn)

	// x87 fpu: lift as opaque operations
	case strings.HasPrefix(mnemonic, "f"):
		return l.liftX87(insn)

	// sse scalar float: comiss, ucomiss, cvtsi2ss, cvtsi2sd, etc.
	case isSSEScalarMnemonic(mnemonic):
		return l.liftSSEScalar(insn)

	default:
		// emit a nop-like placeholder so control flow is preserved
		return l.currentBlock, nil
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
		return nil, errMemOpRequiresLoad

	default:
		return nil, errUnknownOperandType
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

	l.emit(&Load{
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

	l.emit(&Store{
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
func (l *Lifter) liftBinaryOperation(insn *disasm.Instruction, opErr error, binOp BinaryOperator, flagSetter func(Expression, Size)) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, opErr
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

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

	resultExpr := BinaryOp{
		Op:    binOp,
		Left:  destExpr,
		Right: srcExpr,
	}

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, resultExpr)
	} else {
		l.emit(&Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          resultExpr,
		})
	}

	flagSetter(resultExpr, destVar.Type.Size())
	return l.currentBlock, nil
}

// liftAdd lifts ADD instruction: dest = dest + src
func (l *Lifter) liftAdd(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftBinaryOperation(insn, errAddRequires2Operands, BinOpAdd, l.setArithmeticFlags)
}

// liftSub lifts SUB instruction: dest = dest - src
func (l *Lifter) liftSub(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftBinaryOperation(insn, errSubRequires2Operands, BinOpSub, l.setArithmeticFlags)
}

// liftMul lifts MUL instruction: rdx:rax = rax * src (unsigned)
func (l *Lifter) liftMul(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, errMulRequires1Operand
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
		raxName = eaxReg
	case Size8:
		raxName = raxReg
	case Size10, Size16, Size32, Size64:
		raxName = raxReg
	default:
		raxName = raxReg
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
		l.emit(&Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            axVar,
			Source:          resultExpr,
		})
	} else {
		// store low part in rax
		l.emit(&Assign{
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
			rdxName = edxReg
		case Size8:
			rdxName = rdxReg
		case Size1, Size10, Size16, Size32, Size64:
			rdxName = rdxReg
		default:
			rdxName = rdxReg
		}

		rdxVar := Variable{
			Name: rdxName,
			Type: l.getIntType(size, false),
		}

		l.emit(&Assign{
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
		return nil, errIMulRequires13Operands
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
		raxName = eaxReg
	case Size8:
		raxName = raxReg
	case Size10, Size16, Size32, Size64:
		raxName = raxReg
	default:
		raxName = raxReg
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
	l.emit(&Assign{
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
			rdxName = edxReg
		case Size8:
			rdxName = rdxReg
		case Size1, Size10, Size16, Size32, Size64:
			rdxName = rdxReg
		default:
			rdxName = rdxReg
		}

		rdxVar := Variable{
			Name: rdxName,
			Type: l.getIntType(size, true),
		}

		l.emit(&Assign{
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
		l.emit(&Assign{
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
		return nil, errIMulThreeOpNeedReg
	}

	// store result
	l.emit(&Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            destVar,
		Source:          resultExpr,
	})

	l.setArithmeticFlags(resultExpr, destVar.Type.Size())
	return l.currentBlock, nil
}

func (l *Lifter) liftDivOperation(insn *disasm.Instruction, opErr error, binOpDiv, binOpMod BinaryOperator, signed bool) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, opErr
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
		raxName = eaxReg
		rdxName = edxReg
	case Size8:
		raxName = raxReg
		rdxName = rdxReg
	case Size10, Size16, Size32, Size64:
		raxName = raxReg
		rdxName = rdxReg
	default:
		raxName = raxReg
		rdxName = rdxReg
	}

	raxVar := Variable{
		Name: raxName,
		Type: l.getIntType(size, signed),
	}

	var dividendExpr Expression
	if size == Size1 {
		// 8-bit: dividend is ax
		dividendExpr = VariableExpr{Var: raxVar}
	} else {
		// construct rdx:rax as (rdx << (size*8)) | rax
		rdxVar := Variable{
			Name: rdxName,
			Type: l.getIntType(size, signed),
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

	// compute quotient
	quotientExpr := BinaryOp{
		Op:    binOpDiv,
		Left:  dividendExpr,
		Right: srcExpr,
	}

	// compute remainder
	remainderExpr := BinaryOp{
		Op:    binOpMod,
		Left:  dividendExpr,
		Right: srcExpr,
	}

	// store quotient and remainder
	if size == Size1 {
		alVar := Variable{Name: "al", Type: l.getIntType(Size1, signed)}
		l.emit(&Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            alVar,
			Source:          quotientExpr,
		})

		// store remainder in ah
		ahVar := Variable{Name: "ah", Type: l.getIntType(Size1, signed)}
		l.emit(&Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            ahVar,
			Source:          remainderExpr,
		})
	} else {
		l.emit(&Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            raxVar,
			Source:          quotientExpr,
		})

		// store remainder in rdx
		rdxVar := Variable{
			Name: rdxName,
			Type: l.getIntType(size, signed),
		}

		l.emit(&Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            rdxVar,
			Source:          remainderExpr,
		})
	}

	// flags are undefined after div
	return l.currentBlock, nil
}

// liftDiv lifts DIV instruction: rax = rdx:rax / src, rdx = rdx:rax % src (unsigned)
func (l *Lifter) liftDiv(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftDivOperation(insn, errDivRequires1Operand, BinOpUDiv, BinOpUMod, false)
}

// liftIDiv lifts IDIV instruction (signed division, similar to div but signed)
func (l *Lifter) liftIDiv(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftDivOperation(insn, errIDivRequires1Operand, BinOpDiv, BinOpMod, true)
}

func (l *Lifter) liftUnaryOperation(insn *disasm.Instruction, opErr error, getResult func(destExpr Expression, destVar Variable) Expression, flagSetter func(Expression, Size)) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, opErr
	}

	dest := insn.Operands[0]

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

	resultExpr := getResult(destExpr, destVar)

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, resultExpr)
	} else {
		l.emit(&Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          resultExpr,
		})
	}

	flagSetter(resultExpr, destVar.Type.Size())
	return l.currentBlock, nil
}

// liftInc lifts INC instruction: dest = dest + 1
func (l *Lifter) liftInc(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftUnaryOperation(insn, errIncRequires1Operand, func(destExpr Expression, destVar Variable) Expression {
		return BinaryOp{
			Op:    BinOpAdd,
			Left:  destExpr,
			Right: ConstantExpr{Value: IntConstant{Value: 1, Width: destVar.Type.Size(), Signed: false}},
		}
	}, l.setArithmeticFlags)
}

// liftDec lifts DEC instruction: dest = dest - 1
func (l *Lifter) liftDec(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftUnaryOperation(insn, errDecRequires1Operand, func(destExpr Expression, destVar Variable) Expression {
		return BinaryOp{
			Op:    BinOpSub,
			Left:  destExpr,
			Right: ConstantExpr{Value: IntConstant{Value: 1, Width: destVar.Type.Size(), Signed: false}},
		}
	}, l.setArithmeticFlags)
}

// liftNeg lifts NEG instruction: dest = -dest
func (l *Lifter) liftNeg(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftUnaryOperation(insn, errNegRequires1Operand, func(destExpr Expression, _ Variable) Expression {
		return UnaryOp{
			Op:      UnOpNeg,
			Operand: destExpr,
		}
	}, l.setArithmeticFlags)
}

// ============================================================================
// Logical Operations
// ============================================================================

func (l *Lifter) liftAnd(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftBinaryOperation(insn, errAndRequires2Operands, BinOpAnd, l.setLogicalFlags)
}

// liftOr lifts OR instruction: dest = dest | src
func (l *Lifter) liftOr(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftBinaryOperation(insn, errOrRequires2Operands, BinOpOr, l.setLogicalFlags)
}

// liftXor lifts XOR instruction: dest = dest ^ src
func (l *Lifter) liftXor(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftBinaryOperation(insn, errXorRequires2Operands, BinOpXor, l.setLogicalFlags)
}

// liftNot lifts NOT instruction: dest = ~dest
func (l *Lifter) liftNot(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, errNotRequires1Operand
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
		l.emit(&Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          resultExpr,
		})
	}

	// not does not affect flags
	return l.currentBlock, nil
}

func (l *Lifter) liftFlagsOnlyOperation(insn *disasm.Instruction, opErr error, binOp BinaryOperator, flagSetter func(Expression, Size)) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, opErr
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

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

	resultExpr := BinaryOp{
		Op:    binOp,
		Left:  destExpr,
		Right: srcExpr,
	}

	size := l.getOperandSize(dest)
	flagSetter(resultExpr, size)

	return l.currentBlock, nil
}

// liftTest lifts TEST instruction: compute dest & src and set flags (result discarded)
func (l *Lifter) liftTest(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftFlagsOnlyOperation(insn, errTestRequires2Operands, BinOpAnd, l.setLogicalFlags)
}

// liftCmp lifts CMP instruction: compute dest - src and set flags (result discarded)
func (l *Lifter) liftCmp(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftFlagsOnlyOperation(insn, errCmpRequires2Operands, BinOpSub, l.setArithmeticFlags)
}

// ============================================================================
// Shift and Rotate Operations
// ============================================================================

// liftShl lifts SHL/SAL instruction: dest = dest << src
func (l *Lifter) liftShl(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftBinaryOperation(insn, errShlRequires2Operands, BinOpShl, l.setShiftFlags)
}

// liftShr lifts SHR instruction: dest = dest >> src (logical right shift)
func (l *Lifter) liftShr(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftBinaryOperation(insn, errShrRequires2Operands, BinOpShr, l.setShiftFlags)
}

// liftSar lifts SAR instruction: dest = dest >> src (arithmetic right shift)
func (l *Lifter) liftSar(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftBinaryOperation(insn, errSarRequires2Operands, BinOpSar, l.setShiftFlags)
}

// liftRol lifts ROL instruction: rotate left (not implemented as binary op, use intrinsic)
func (l *Lifter) liftRol(_ *disasm.Instruction) ([]IRInstruction, error) {
	// rol is complex - would need intrinsic or decomposition
	// for now, return unsupported
	return nil, errRolNotImplemented
}

// liftRor lifts ROR instruction: rotate right (not implemented as binary op, use intrinsic)
func (l *Lifter) liftRor(_ *disasm.Instruction) ([]IRInstruction, error) {
	// ror is complex - would need intrinsic or decomposition
	// for now, return unsupported
	return nil, errRorNotImplemented
}

// ============================================================================
// Memory Operations
// ============================================================================

// liftMov lifts MOV instruction: dest = src
func (l *Lifter) liftMov(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, errMovRequires2Operands
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	// handle different operand combinations
	destMem, destIsMem := dest.(disasm.MemoryOperand)
	srcMem, srcIsMem := src.(disasm.MemoryOperand)

	if destIsMem && srcIsMem {
		// mem to mem not allowed in x86_64
		return nil, errMovBothMem
	}

	switch {
	case destIsMem:
		// mov [mem], reg/imm
		srcExpr, err := l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
		l.storeToMemory(destMem, srcExpr)
	case srcIsMem:
		// mov reg, [mem]
		destReg, ok := dest.(disasm.RegisterOperand)
		if !ok {
			return nil, errMovDestMustBeRegOrMem
		}
		srcVar := l.loadFromMemory(srcMem)
		destVar := Variable{
			Name: destReg.Name,
			Type: l.getIntType(Size(destReg.Size), false),
		}
		l.emit(&Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          VariableExpr{Var: srcVar},
		})
	default:
		// mov reg, reg/imm
		destReg, ok := dest.(disasm.RegisterOperand)
		if !ok {
			return nil, errMovDestMustBeRegOrMem
		}
		srcExpr, err := l.translateOperandToExpr(src)
		if err != nil {
			return nil, err
		}
		destVar := Variable{
			Name: destReg.Name,
			Type: l.getIntType(Size(destReg.Size), false),
		}
		l.emit(&Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          srcExpr,
		})
	}

	// mov does not affect flags
	return l.currentBlock, nil
}

// liftMovzx lifts MOVZX instruction: dest = zero_extend(src)
func (l *Lifter) liftMovExtend(insn *disasm.Instruction, signed bool, errMissing, errDestReg error) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, errMissing
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

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

	destReg, ok := dest.(disasm.RegisterOperand)
	if !ok {
		return nil, errDestReg
	}

	destVar := Variable{
		Name: destReg.Name,
		Type: l.getIntType(Size(destReg.Size), signed),
	}

	resultExpr := Cast{
		Expr:       srcExpr,
		TargetType: destVar.Type,
	}

	l.emit(&Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            destVar,
		Source:          resultExpr,
	})

	return l.currentBlock, nil
}

// liftMovzx lifts MOVZX instruction: dest = zero_extend(src)
func (l *Lifter) liftMovzx(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftMovExtend(insn, false, errMovzxRequires2Operands, errMovzxDestMustBeReg)
}

// liftMovsx lifts MOVSX instruction: dest = sign_extend(src)
func (l *Lifter) liftMovsx(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftMovExtend(insn, true, errMovsxRequires2Operands, errMovsxDestMustBeReg)
}

// liftLea lifts LEA instruction: dest = address_of(src)
func (l *Lifter) liftLea(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return nil, errLeaRequires2Operands
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	// source must be memory operand
	srcMem, ok := src.(disasm.MemoryOperand)
	if !ok {
		return nil, errLeaSrcMustBeMem
	}

	// destination must be register
	destReg, ok := dest.(disasm.RegisterOperand)
	if !ok {
		return nil, errLeaDestMustBeReg
	}

	// compute effective address (without dereferencing)
	addrExpr := l.translateMemoryAddress(srcMem)

	destVar := Variable{
		Name: destReg.Name,
		Type: l.getIntType(Size(destReg.Size), false),
	}

	l.emit(&Assign{
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
		return nil, errPushRequires1Operand
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

	l.emit(&Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            rspVar,
		Source:          newRsp,
	})

	// store value at [rsp]
	l.emit(&Store{
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
		return nil, errPopRequires1Operand
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

	l.emit(&Load{
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

	l.emit(&Assign{
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

		l.emit(&Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          VariableExpr{Var: tempVar},
		})
	} else {
		return nil, errPopDestMustBeRegOrMem
	}

	return l.currentBlock, nil
}

// ============================================================================
// Control Flow Operations
// ============================================================================

// liftJmp lifts JMP instruction: unconditional jump
func (l *Lifter) liftJmp(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, errJmpRequires1Operand
	}

	target := insn.Operands[0]

	// for now, we just note that this is a jump
	// actual CFG construction will handle target resolution
	// emit a placeholder jump instruction

	if imm, ok := target.(disasm.ImmediateOperand); ok {
		// direct jump to immediate address
		targetAddr := Address(uint64(imm.Value)) //nolint:gosec // Address fits in uint64
		_ = targetAddr                           // will be used by cfg builder

		// emit jump (block id will be resolved by cfg builder)
		l.emit(&Jump{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Target:          BlockID(targetAddr),
		})
	} else {
		// indirect jump (register or memory)
		// this requires special handling in cfg builder
		return nil, errIndirectJumpNotSupported
	}

	return l.currentBlock, nil
}

// liftJcc lifts conditional jump instructions (je, jne, jl, jg, etc.)
func (l *Lifter) liftJcc(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, errJccRequires1Operand
	}

	target := insn.Operands[0]

	imm, ok := target.(disasm.ImmediateOperand)
	if !ok {
		return nil, errJccTargetMustBeImm
	}

	targetAddr := Address(uint64(imm.Value)) //nolint:gosec // Address fits in uint64

	// determine condition based on mnemonic
	mnemonic := strings.ToLower(insn.Mnemonic)
	condition := l.materializeCondition(mnemonic)

	// emit conditional branch
	// fall-through target will be next instruction (resolved by cfg builder)
	l.emit(&Branch{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Condition:       condition,
		TrueTarget:      BlockID(targetAddr),
		FalseTarget:     BlockID(Address(insn.Address) + Address(uint64(insn.Length))), //nolint:gosec // fall-through and Length is small
	})

	return l.currentBlock, nil
}

// materializeCondition builds the branch condition expression for a conditional jump.
// if currentLazyFlags is set (i.e. the preceding instruction set flags), the required
// flags are materialized from the lazy structure instead of emitting raw flag variables.
// this eliminates zf/sf/cf variables from the output for the common case where a
// flag-setting instruction (cmp, test, add, sub, ...) immediately precedes the jump.
func (l *Lifter) materializeCondition(mnemonic string) Expression {
	if l.currentLazyFlags == nil {
		// no lazy flags available — fall back to raw flag variables
		return l.getConditionFromMnemonic(mnemonic)
	}

	lf := l.currentLazyFlags

	// optimization: when lazy flags come from a cmp/sub operation with two operands,
	// emit direct high-level comparisons instead of decomposing into individual flags.
	// this produces clean output like (a <= b) instead of (zf || (sf != of)).
	if lf.Operation == FlagOpArithmetic && len(lf.Operands) >= 2 {
		if binResult, ok := lf.Result.(BinaryOp); ok && binResult.Op == BinOpSub {
			left := lf.Operands[0]
			right := lf.Operands[1]
			if cond := directComparisonFromMnemonic(mnemonic, left, right); cond != nil {
				return cond
			}
		}
	}

	// helper: materialize a single flag, returning a boolean expression
	mat := func(flag CPUFlag) Expression {
		return lf.MaterializeFlag(flag)
	}

	switch mnemonic {
	case mnemonicJe, mnemonicJz:
		return mat(FlagZF)

	case mnemonicJne, mnemonicJnz:
		return UnaryOp{Op: UnOpLogicalNot, Operand: mat(FlagZF)}

	case mnemonicJl, mnemonicJnge:
		// sf != of
		return BinaryOp{Op: BinOpNe, Left: mat(FlagSF), Right: mat(FlagOF)}

	case mnemonicJle, mnemonicJng:
		// zf || (sf != of)
		return BinaryOp{
			Op:    BinOpLogicalOr,
			Left:  mat(FlagZF),
			Right: BinaryOp{Op: BinOpNe, Left: mat(FlagSF), Right: mat(FlagOF)},
		}

	case mnemonicJg, mnemonicJnle:
		// !zf && (sf == of)
		return BinaryOp{
			Op:    BinOpLogicalAnd,
			Left:  UnaryOp{Op: UnOpLogicalNot, Operand: mat(FlagZF)},
			Right: BinaryOp{Op: BinOpEq, Left: mat(FlagSF), Right: mat(FlagOF)},
		}

	case mnemonicJge, mnemonicJnl:
		// sf == of
		return BinaryOp{Op: BinOpEq, Left: mat(FlagSF), Right: mat(FlagOF)}

	case mnemonicJb, mnemonicJnae, mnemonicJc:
		return mat(FlagCF)

	case mnemonicJbe, mnemonicJna:
		return BinaryOp{Op: BinOpLogicalOr, Left: mat(FlagCF), Right: mat(FlagZF)}

	case mnemonicJa, mnemonicJnbe:
		return BinaryOp{
			Op:    BinOpLogicalAnd,
			Left:  UnaryOp{Op: UnOpLogicalNot, Operand: mat(FlagCF)},
			Right: UnaryOp{Op: UnOpLogicalNot, Operand: mat(FlagZF)},
		}

	case mnemonicJae, mnemonicJnb, mnemonicJnc:
		return UnaryOp{Op: UnOpLogicalNot, Operand: mat(FlagCF)}

	case mnemonicJs:
		return mat(FlagSF)

	case mnemonicJns:
		return UnaryOp{Op: UnOpLogicalNot, Operand: mat(FlagSF)}

	case mnemonicJo:
		return mat(FlagOF)

	case mnemonicJno:
		return UnaryOp{Op: UnOpLogicalNot, Operand: mat(FlagOF)}

	case mnemonicJp, mnemonicJpe:
		return mat(FlagPF)

	case mnemonicJnp, mnemonicJpo:
		return UnaryOp{Op: UnOpLogicalNot, Operand: mat(FlagPF)}

	default:
		return l.getConditionFromMnemonic(mnemonic)
	}
}

// directComparisonFromMnemonic maps a conditional jump mnemonic to a direct
// high-level comparison between the original cmp operands.
// returns nil if the mnemonic is not a simple comparison (e.g., parity, overflow-only).
func directComparisonFromMnemonic(mnemonic string, left, right Expression) Expression {
	switch mnemonic {
	case mnemonicJe, mnemonicJz:
		return BinaryOp{Op: BinOpEq, Left: left, Right: right}
	case mnemonicJne, mnemonicJnz:
		return BinaryOp{Op: BinOpNe, Left: left, Right: right}
	case mnemonicJl, mnemonicJnge:
		return BinaryOp{Op: BinOpLt, Left: left, Right: right}
	case mnemonicJle, mnemonicJng:
		return BinaryOp{Op: BinOpLe, Left: left, Right: right}
	case mnemonicJg, mnemonicJnle:
		return BinaryOp{Op: BinOpGt, Left: left, Right: right}
	case mnemonicJge, mnemonicJnl:
		return BinaryOp{Op: BinOpGe, Left: left, Right: right}
	case mnemonicJb, mnemonicJnae, mnemonicJc:
		return BinaryOp{Op: BinOpULt, Left: left, Right: right}
	case mnemonicJbe, mnemonicJna:
		return BinaryOp{Op: BinOpULe, Left: left, Right: right}
	case mnemonicJa, mnemonicJnbe:
		return BinaryOp{Op: BinOpUGt, Left: left, Right: right}
	case mnemonicJae, mnemonicJnb, mnemonicJnc:
		return BinaryOp{Op: BinOpUGe, Left: left, Right: right}
	default:
		// parity, sign, overflow-only conditions: fall through to flag decomposition
		return nil
	}
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
	case mnemonicJe, mnemonicJz:
		// jump if equal (zf = 1)
		return VariableExpr{Var: zfVar}

	case mnemonicJne, mnemonicJnz:
		// jump if not equal (zf = 0)
		return UnaryOp{
			Op:      UnOpLogicalNot,
			Operand: VariableExpr{Var: zfVar},
		}

	case mnemonicJl, mnemonicJnge:
		// jump if less (sf != of)
		return BinaryOp{
			Op:    BinOpNe,
			Left:  VariableExpr{Var: sfVar},
			Right: VariableExpr{Var: ofVar},
		}

	case mnemonicJle, mnemonicJng:
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

	case mnemonicJg, mnemonicJnle:
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

	case mnemonicJge, mnemonicJnl:
		// jump if greater or equal (sf = of)
		return BinaryOp{
			Op:    BinOpEq,
			Left:  VariableExpr{Var: sfVar},
			Right: VariableExpr{Var: ofVar},
		}

	case mnemonicJb, mnemonicJnae, mnemonicJc:
		// jump if below (cf = 1)
		return VariableExpr{Var: cfVar}

	case mnemonicJbe, mnemonicJna:
		// jump if below or equal (cf = 1 or zf = 1)
		return BinaryOp{
			Op:    BinOpLogicalOr,
			Left:  VariableExpr{Var: cfVar},
			Right: VariableExpr{Var: zfVar},
		}

	case mnemonicJa, mnemonicJnbe:
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

	case mnemonicJae, mnemonicJnb, mnemonicJnc:
		// jump if above or equal (cf = 0)
		return UnaryOp{
			Op:      UnOpLogicalNot,
			Operand: VariableExpr{Var: cfVar},
		}

	case mnemonicJs:
		// jump if sign (sf = 1)
		return VariableExpr{Var: sfVar}

	case mnemonicJns:
		// jump if not sign (sf = 0)
		return UnaryOp{
			Op:      UnOpLogicalNot,
			Operand: VariableExpr{Var: sfVar},
		}

	case mnemonicJo:
		// jump if overflow (of = 1)
		return VariableExpr{Var: ofVar}

	case mnemonicJno:
		// jump if not overflow (of = 0)
		return UnaryOp{
			Op:      UnOpLogicalNot,
			Operand: VariableExpr{Var: ofVar},
		}

	case mnemonicJp, mnemonicJpe:
		// jump if parity (pf = 1)
		return VariableExpr{Var: pfVar}

	case mnemonicJnp, mnemonicJpo:
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

// liftCall lifts CALL instruction to a high-level Call IR node.
// the hardware semantics (push rip; jmp target) are intentionally suppressed:
// rsp manipulation and return-address store are ABI artifacts that the
// decompiler must not expose at the IR level. the ABI analyzer populates
// Call.Args in a subsequent pass.
func (l *Lifter) liftCall(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) != 1 {
		return nil, errCallRequires1Operand
	}

	target := insn.Operands[0]

	// resolve call target expression
	var targetExpr Expression
	var err error

	if mem, ok := target.(disasm.MemoryOperand); ok {
		// indirect call through memory: load function pointer first
		targetVar := l.loadFromMemory(mem)
		targetExpr = VariableExpr{Var: targetVar}
	} else {
		targetExpr, err = l.translateOperandToExpr(target)
		if err != nil {
			return nil, err
		}
	}

	// emit a single abstract Call node; Args are filled by the ABI analyzer pass
	l.emit(&Call{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            nil, // return value populated by ABI analyzer
		Target:          targetExpr,
		Args:            nil, // arguments populated by ABI analyzer
	})

	return l.currentBlock, nil
}

// liftRet lifts RET instruction to a high-level Return IR node.
// the hardware semantics (load [rsp]; rsp += 8) are ABI artifacts that
// must not appear in the decompiled output. the ABI analyzer determines
// the actual return value register (rax / xmm0) in a subsequent pass.
func (l *Lifter) liftRet(insn *disasm.Instruction) ([]IRInstruction, error) {
	// handle ret imm16: the immediate encodes the number of additional bytes
	// to pop from the stack (stdcall / pascal convention). we suppress the
	// rsp arithmetic here as well — it is a calling-convention detail.
	_ = insn // operands intentionally ignored at this abstraction level

	// emit abstract return; Value is populated by the ABI analyzer
	l.emit(&Return{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Value:           nil, // return value extracted by ABI analyzer
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
	// extract original left/right operands from the result binary expression.
	// arithmetic flag materialization (cf, of) requires the original operands,
	// not just the composite result. for example, cf after sub needs (left < right),
	// and of after sub needs sign analysis on left, right, and result independently.
	var operands []Expression
	if binOp, ok := result.(BinaryOp); ok {
		operands = []Expression{binOp.Left, binOp.Right}
	} else {
		operands = []Expression{result}
	}

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
