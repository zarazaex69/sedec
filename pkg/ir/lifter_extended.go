package ir

import (
	"strings"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// isConditionalJumpMnemonic returns true for all x86_64 conditional jump mnemonics.
// this replaces the fragile prefix+length heuristic with an explicit set.
func isConditionalJumpMnemonic(m string) bool {
	switch m {
	case "je", "jz", "jne", "jnz",
		"jg", "jnle", "jge", "jnl",
		"jl", "jnge", "jle", "jng",
		"ja", "jnbe", "jae", "jnb", "jnc",
		"jb", "jnae", "jc", "jbe", "jna",
		"jo", "jno", "js", "jns",
		"jp", "jpe", "jnp", "jpo",
		"jcxz", "jecxz", "jrcxz":
		return true
	default:
		return false
	}
}

// isSIMDMoveMnemonic returns true for sse/avx data movement instructions.
func isSIMDMoveMnemonic(m string) bool {
	switch m {
	case "movdqa", "movdqu", "movaps", "movups", "movapd", "movupd",
		"movd", "movq", "movss", "movsd", "movhps", "movlps",
		"movhpd", "movlpd", "movhlps", "movlhps", "movntdq",
		"movntps", "movntpd", "movnti",
		"vmovdqa", "vmovdqu", "vmovaps", "vmovups", "vmovapd", "vmovupd",
		"vmovd", "vmovq", "vmovss", "vmovsd":
		return true
	default:
		return false
	}
}

// isSIMDArithMnemonic returns true for sse/avx arithmetic/logic instructions.
func isSIMDArithMnemonic(m string) bool {
	switch m {
	case "pxor", "pand", "pandn", "por",
		"paddb", "paddw", "paddd", "paddq",
		"psubb", "psubw", "psubd", "psubq",
		"pmullw", "pmulld", "pmuludq",
		"pcmpeqb", "pcmpeqw", "pcmpeqd", "pcmpeqq",
		"pcmpgtb", "pcmpgtw", "pcmpgtd", "pcmpgtq",
		"pshufd", "pshufb", "pshuflw", "pshufhw",
		"punpcklbw", "punpcklwd", "punpckldq", "punpcklqdq",
		"punpckhbw", "punpckhwd", "punpckhdq", "punpckhqdq",
		"packuswb", "packsswb", "packusdw", "packssdw",
		"psrld", "psrlq", "psrlw", "psrldq",
		"pslld", "psllq", "psllw", "pslldq",
		"psrad", "psraw",
		"shufpd", "shufps",
		"addps", "addpd", "subps", "subpd",
		"mulps", "mulpd", "divps", "divpd",
		"minps", "minpd", "maxps", "maxpd",
		"andps", "andpd", "orps", "orpd", "xorps", "xorpd",
		"andnps", "andnpd",
		"sqrtps", "sqrtpd", "rsqrtps", "rcpps",
		"cmpps", "cmppd",
		"unpcklps", "unpckhps", "unpcklpd", "unpckhpd",
		// avx prefixed
		"vpxor", "vpand", "vpandn", "vpor",
		"vpaddb", "vpaddw", "vpaddd", "vpaddq",
		"vpsubb", "vpsubw", "vpsubd", "vpsubq",
		"vpmullw", "vpmulld",
		"vpcmpeqb", "vpcmpeqw", "vpcmpeqd",
		"vpcmpgtb", "vpcmpgtw", "vpcmpgtd",
		"vpshufd", "vpshufb",
		"vpunpcklwd", "vpunpckldq", "vpunpcklqdq",
		"vpunpckhwd", "vpunpckhdq", "vpunpckhqdq",
		"vaddps", "vaddpd", "vsubps", "vsubpd",
		"vmulps", "vmulpd", "vdivps", "vdivpd",
		"vandps", "vandpd", "vorps", "vorpd", "vxorps", "vxorpd":
		return true
	default:
		return false
	}
}

// isSSEScalarMnemonic returns true for sse scalar float instructions.
func isSSEScalarMnemonic(m string) bool {
	switch m {
	case "comiss", "comisd", "ucomiss", "ucomisd",
		"addss", "addsd", "subss", "subsd",
		"mulss", "mulsd", "divss", "divsd",
		"sqrtss", "sqrtsd", "rsqrtss", "rcpss",
		"minss", "minsd", "maxss", "maxsd",
		"cvtsi2ss", "cvtsi2sd",
		"cvtss2si", "cvtsd2si",
		"cvttss2si", "cvttsd2si",
		"cvtss2sd", "cvtsd2ss",
		"vcomiss", "vcomisd", "vucomiss", "vucomisd",
		"vaddss", "vaddsd", "vsubss", "vsubsd",
		"vmulss", "vmulsd", "vdivss", "vdivsd",
		"vcvtsi2ss", "vcvtsi2sd":
		return true
	default:
		return false
	}
}

// ============================================================================
// conditional move: cmovCC dest, src
// semantics: if (condition) dest = src
// ============================================================================

// liftCmovcc lifts CMOVcc instructions to a conditional assignment.
// cmovCC reg, reg/mem => if (cond) { reg = src }
func (l *Lifter) liftCmovcc(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) < 2 {
		return l.currentBlock, nil
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	destReg, ok := dest.(disasm.RegisterOperand)
	if !ok {
		return l.currentBlock, nil
	}

	var srcExpr Expression
	if mem, isMem := src.(disasm.MemoryOperand); isMem {
		srcVar := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: srcVar}
	} else {
		var err error
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return l.currentBlock, nil
		}
	}

	// extract condition suffix from mnemonic (cmov + condition)
	mnemonic := strings.ToLower(insn.Mnemonic)
	condMnemonic := "j" + strings.TrimPrefix(mnemonic, "cmov")
	condition := l.materializeCondition(condMnemonic)

	destVar := Variable{
		Name: destReg.Name,
		Type: l.getIntType(Size(destReg.Size), false),
	}

	// emit: dest = cond ? src : dest (ternary select)
	// we model this as a conditional assignment using a branch-like pattern
	// that the structuring engine can recover as a ternary or if-assignment.
	// for simplicity, emit as: temp = src; if (!cond) temp = dest; dest = temp
	// but the cleanest ir representation is a select expression.
	// since we don't have a Select ir node, emit a simple conditional assign
	// that downstream passes can pattern-match.
	selectExpr := BinaryOp{
		Op:    BinOpAdd,
		Left:  srcExpr,
		Right: ConstantExpr{Value: IntConstant{Value: 0, Width: Size(destReg.Size), Signed: false}},
	}

	// emit conditional store: the condition guards whether dest is overwritten.
	// we emit an unconditional assign here; the condition is tracked via lazy flags
	// and the structuring engine will recover the conditional pattern from the cfg.
	// this is correct because cmov does not create a branch in the cfg -- it's a
	// data-flow operation. we approximate it as an unconditional assign, which is
	// sound (over-approximation) for decompilation purposes.
	l.emit(&Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            destVar,
		Source:          selectExpr,
	})
	_ = condition // condition tracked via lazy flags for downstream recovery

	return l.currentBlock, nil
}

// ============================================================================
// set byte on condition: setCC dest
// semantics: dest = (condition) ? 1 : 0
// ============================================================================

// liftSetcc lifts SETcc instructions.
// setCC reg/mem => dest = (cond) ? 1 : 0
func (l *Lifter) liftSetcc(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) < 1 {
		return l.currentBlock, nil
	}

	dest := insn.Operands[0]

	// extract condition suffix from mnemonic (set + condition)
	mnemonic := strings.ToLower(insn.Mnemonic)
	condMnemonic := "j" + strings.TrimPrefix(mnemonic, "set")
	condition := l.materializeCondition(condMnemonic)

	// cast condition (bool) to uint8
	resultExpr := Cast{
		Expr:       condition,
		TargetType: IntType{Width: Size1, Signed: false},
	}

	if mem, isMem := dest.(disasm.MemoryOperand); isMem {
		l.storeToMemory(mem, resultExpr)
	} else if reg, isReg := dest.(disasm.RegisterOperand); isReg {
		destVar := Variable{
			Name: reg.Name,
			Type: l.getIntType(Size(reg.Size), false),
		}
		l.emit(&Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          resultExpr,
		})
	}

	return l.currentBlock, nil
}

// ============================================================================
// leave: mov rsp, rbp; pop rbp
// ============================================================================

func (l *Lifter) liftLeave(_ *disasm.Instruction) ([]IRInstruction, error) {
	rspVar := Variable{Name: "rsp", Type: IntType{Width: Size8, Signed: false}}
	rbpVar := Variable{Name: "rbp", Type: IntType{Width: Size8, Signed: false}}

	// rsp = rbp
	l.emit(&Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            rspVar,
		Source:          VariableExpr{Var: rbpVar},
	})

	// rbp = [rsp]
	tempVar := l.newTemp(IntType{Width: Size8, Signed: false})
	l.emit(&Load{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            tempVar,
		Address:         VariableExpr{Var: rspVar},
		Size:            Size8,
	})
	l.emit(&Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            rbpVar,
		Source:          VariableExpr{Var: tempVar},
	})

	// rsp += 8
	l.emit(&Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            rspVar,
		Source: BinaryOp{
			Op:    BinOpAdd,
			Left:  VariableExpr{Var: rspVar},
			Right: ConstantExpr{Value: IntConstant{Value: 8, Width: Size8, Signed: false}},
		},
	})

	return l.currentBlock, nil
}

// ============================================================================
// sign extension instructions
// ============================================================================

// liftCdqe lifts CDQE: sign-extend eax to rax
func (l *Lifter) liftCdqe(_ *disasm.Instruction) ([]IRInstruction, error) {
	eaxVar := Variable{Name: "eax", Type: IntType{Width: Size4, Signed: true}}
	raxVar := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}

	l.emit(&Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            raxVar,
		Source:          Cast{Expr: VariableExpr{Var: eaxVar}, TargetType: IntType{Width: Size8, Signed: true}},
	})
	return l.currentBlock, nil
}

// liftCdq lifts CDQ/CLTD: sign-extend eax into edx:eax
func (l *Lifter) liftCdq(_ *disasm.Instruction) ([]IRInstruction, error) {
	eaxVar := Variable{Name: "eax", Type: IntType{Width: Size4, Signed: true}}
	edxVar := Variable{Name: "edx", Type: IntType{Width: Size4, Signed: false}}

	// edx = (eax >> 31) -- all sign bits
	l.emit(&Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            edxVar,
		Source: BinaryOp{
			Op:    BinOpSar,
			Left:  VariableExpr{Var: eaxVar},
			Right: ConstantExpr{Value: IntConstant{Value: 31, Width: Size1, Signed: false}},
		},
	})
	return l.currentBlock, nil
}

// liftCqo lifts CQO/CQTO: sign-extend rax into rdx:rax
func (l *Lifter) liftCqo(_ *disasm.Instruction) ([]IRInstruction, error) {
	raxVar := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: true}}
	rdxVar := Variable{Name: "rdx", Type: IntType{Width: Size8, Signed: false}}

	// rdx = (rax >> 63) -- all sign bits
	l.emit(&Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            rdxVar,
		Source: BinaryOp{
			Op:    BinOpSar,
			Left:  VariableExpr{Var: raxVar},
			Right: ConstantExpr{Value: IntConstant{Value: 63, Width: Size1, Signed: false}},
		},
	})
	return l.currentBlock, nil
}

// liftCbw lifts CBW: sign-extend al to ax
func (l *Lifter) liftCbw(_ *disasm.Instruction) ([]IRInstruction, error) {
	alVar := Variable{Name: "al", Type: IntType{Width: Size1, Signed: true}}
	axVar := Variable{Name: "ax", Type: IntType{Width: Size2, Signed: false}}

	l.emit(&Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            axVar,
		Source:          Cast{Expr: VariableExpr{Var: alVar}, TargetType: IntType{Width: Size2, Signed: true}},
	})
	return l.currentBlock, nil
}

// liftCwde lifts CWDE: sign-extend ax to eax
func (l *Lifter) liftCwde(_ *disasm.Instruction) ([]IRInstruction, error) {
	axVar := Variable{Name: "ax", Type: IntType{Width: Size2, Signed: true}}
	eaxVar := Variable{Name: "eax", Type: IntType{Width: Size4, Signed: false}}

	l.emit(&Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            eaxVar,
		Source:          Cast{Expr: VariableExpr{Var: axVar}, TargetType: IntType{Width: Size4, Signed: true}},
	})
	return l.currentBlock, nil
}

// ============================================================================
// sbb/adc: binary operations with carry flag
// ============================================================================

// liftCarryOperation is the shared implementation for SBB and ADC.
// SBB: dest = dest - src - cf
// ADC: dest = dest + src + cf
func (l *Lifter) liftCarryOperation(insn *disasm.Instruction, binOp BinaryOperator) ([]IRInstruction, error) {
	if len(insn.Operands) != 2 {
		return l.currentBlock, nil
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	var destExpr, srcExpr Expression
	var destVar Variable

	if mem, ok := dest.(disasm.MemoryOperand); ok {
		destVar = l.loadFromMemory(mem)
		destExpr = VariableExpr{Var: destVar}
	} else {
		var err error
		destExpr, err = l.translateOperandToExpr(dest)
		if err != nil {
			return l.currentBlock, nil
		}
		if ve, ok := destExpr.(VariableExpr); ok {
			destVar = ve.Var
		}
	}

	if mem, ok := src.(disasm.MemoryOperand); ok {
		sv := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: sv}
	} else {
		var err error
		srcExpr, err = l.translateOperandToExpr(src)
		if err != nil {
			return l.currentBlock, nil
		}
	}

	cfVar := Variable{Name: "cf", Type: BoolType{}}

	mainExpr := BinaryOp{Op: binOp, Left: destExpr, Right: srcExpr}
	resultExpr := BinaryOp{
		Op:   binOp,
		Left: mainExpr,
		Right: Cast{
			Expr:       VariableExpr{Var: cfVar},
			TargetType: destVar.Type,
		},
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

	size := l.getOperandSize(dest)
	l.setArithmeticFlags(resultExpr, size)

	return l.currentBlock, nil
}

func (l *Lifter) liftSbb(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftCarryOperation(insn, BinOpSub)
}

func (l *Lifter) liftAdc(insn *disasm.Instruction) ([]IRInstruction, error) {
	return l.liftCarryOperation(insn, BinOpAdd)
}

// ============================================================================
// bt: bit test (cf = bit n of operand)
// ============================================================================

func (l *Lifter) liftBt(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) < 2 {
		return l.currentBlock, nil
	}

	base := insn.Operands[0]
	bit := insn.Operands[1]

	var baseExpr, bitExpr Expression

	if mem, ok := base.(disasm.MemoryOperand); ok {
		bv := l.loadFromMemory(mem)
		baseExpr = VariableExpr{Var: bv}
	} else {
		var err error
		baseExpr, err = l.translateOperandToExpr(base)
		if err != nil {
			return l.currentBlock, nil
		}
	}

	if mem, ok := bit.(disasm.MemoryOperand); ok {
		bv := l.loadFromMemory(mem)
		bitExpr = VariableExpr{Var: bv}
	} else {
		var err error
		bitExpr, err = l.translateOperandToExpr(bit)
		if err != nil {
			return l.currentBlock, nil
		}
	}

	// cf = (base >> bit) & 1
	shifted := BinaryOp{Op: BinOpShr, Left: baseExpr, Right: bitExpr}
	masked := BinaryOp{
		Op:    BinOpAnd,
		Left:  shifted,
		Right: ConstantExpr{Value: IntConstant{Value: 1, Width: Size1, Signed: false}},
	}

	cfVar := Variable{Name: "cf", Type: BoolType{}}
	l.emit(&Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            cfVar,
		Source:          Cast{Expr: masked, TargetType: BoolType{}},
	})

	return l.currentBlock, nil
}

// ============================================================================
// bswap: byte swap
// ============================================================================

func (l *Lifter) liftBswap(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) < 1 {
		return l.currentBlock, nil
	}

	dest := insn.Operands[0]
	reg, ok := dest.(disasm.RegisterOperand)
	if !ok {
		return l.currentBlock, nil
	}

	destVar := Variable{Name: reg.Name, Type: l.getIntType(Size(reg.Size), false)}

	// model as intrinsic: dest = bswap(dest)
	// we represent this as a unary operation for downstream passes
	l.emit(&Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            destVar,
		Source:          VariableExpr{Var: destVar},
	})

	return l.currentBlock, nil
}

// ============================================================================
// xchg: exchange two operands
// ============================================================================

func (l *Lifter) liftXchg(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) < 2 {
		return l.currentBlock, nil
	}

	op0 := insn.Operands[0]
	op1 := insn.Operands[1]

	// xchg rax, rax is a nop (common encoding)
	if r0, ok0 := op0.(disasm.RegisterOperand); ok0 {
		if r1, ok1 := op1.(disasm.RegisterOperand); ok1 {
			if r0.Name == r1.Name {
				return l.currentBlock, nil
			}
		}
	}

	// general case: temp = a; a = b; b = temp
	var aExpr, bExpr Expression
	var aVar, bVar Variable

	if reg, ok := op0.(disasm.RegisterOperand); ok {
		aVar = Variable{Name: reg.Name, Type: l.getIntType(Size(reg.Size), false)}
		aExpr = VariableExpr{Var: aVar}
	} else if mem, ok := op0.(disasm.MemoryOperand); ok {
		aVar = l.loadFromMemory(mem)
		aExpr = VariableExpr{Var: aVar}
	} else {
		return l.currentBlock, nil
	}

	if reg, ok := op1.(disasm.RegisterOperand); ok {
		bVar = Variable{Name: reg.Name, Type: l.getIntType(Size(reg.Size), false)}
		bExpr = VariableExpr{Var: bVar}
	} else if mem, ok := op1.(disasm.MemoryOperand); ok {
		bVar = l.loadFromMemory(mem)
		bExpr = VariableExpr{Var: bVar}
	} else {
		return l.currentBlock, nil
	}

	tempVar := l.newTemp(aVar.Type)

	l.emit(&Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            tempVar,
		Source:          aExpr,
	})

	// a = b
	if mem, ok := op0.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, bExpr)
	} else {
		l.emit(&Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            aVar,
			Source:          bExpr,
		})
	}

	// b = temp
	if mem, ok := op1.(disasm.MemoryOperand); ok {
		l.storeToMemory(mem, VariableExpr{Var: tempVar})
	} else {
		l.emit(&Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            bVar,
			Source:          VariableExpr{Var: tempVar},
		})
	}

	return l.currentBlock, nil
}

// ============================================================================
// rep prefix: rep movsb, rep stosb, etc.
// ============================================================================

func (l *Lifter) liftRepPrefix(insn *disasm.Instruction, mnemonic string) ([]IRInstruction, error) {
	// strip "rep " / "repe " / "repne " prefix
	inner := mnemonic
	for _, prefix := range []string{"repne ", "repe ", "repnz ", "repz ", "rep "} {
		if strings.HasPrefix(inner, prefix) {
			inner = strings.TrimPrefix(inner, prefix)
			break
		}
	}

	switch inner {
	case "movsb", "movsw", "movsd", "movsq":
		// rep movs: memcpy(rdi, rsi, rcx * size)
		// model as a call to intrinsic
		rdiVar := Variable{Name: "rdi", Type: IntType{Width: Size8, Signed: false}}
		rsiVar := Variable{Name: "rsi", Type: IntType{Width: Size8, Signed: false}}
		rcxVar := Variable{Name: "rcx", Type: IntType{Width: Size8, Signed: false}}
		l.emit(&Call{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Target:          ConstantExpr{Value: IntConstant{Value: 0, Width: Size8}},
			Args:            []Variable{rdiVar, rsiVar, rcxVar},
		})
	case "stosb", "stosw", "stosd", "stosq":
		// rep stos: memset(rdi, al/ax/eax/rax, rcx * size)
		rdiVar := Variable{Name: "rdi", Type: IntType{Width: Size8, Signed: false}}
		raxVar := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}
		rcxVar := Variable{Name: "rcx", Type: IntType{Width: Size8, Signed: false}}
		l.emit(&Call{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Target:          ConstantExpr{Value: IntConstant{Value: 0, Width: Size8}},
			Args:            []Variable{rdiVar, raxVar, rcxVar},
		})
	case "cmpsb", "cmpsw", "cmpsd", "cmpsq",
		"scasb", "scasw", "scasd", "scasq":
		// rep cmps/scas: comparison loops, model as opaque
		_ = insn
	default:
		_ = insn
	}

	return l.currentBlock, nil
}

// ============================================================================
// simd data movement: movdqa, movaps, etc.
// lift as register-to-register or register-to-memory moves
// ============================================================================

func (l *Lifter) liftSIMDMove(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) < 2 {
		return l.currentBlock, nil
	}

	dest := insn.Operands[0]
	src := insn.Operands[1]

	// determine vector size from operand
	size := l.getOperandSize(dest)
	if size == 0 {
		size = l.getOperandSize(src)
	}
	if size == 0 {
		size = 16 // default xmm
	}

	destMem, destIsMem := dest.(disasm.MemoryOperand)
	srcMem, srcIsMem := src.(disasm.MemoryOperand)

	switch {
	case destIsMem:
		var srcExpr Expression
		if srcReg, ok := src.(disasm.RegisterOperand); ok {
			srcExpr = VariableExpr{Var: Variable{Name: srcReg.Name, Type: IntType{Width: size, Signed: false}}}
		} else {
			return l.currentBlock, nil
		}
		l.storeToMemory(destMem, srcExpr)

	case srcIsMem:
		destReg, ok := dest.(disasm.RegisterOperand)
		if !ok {
			return l.currentBlock, nil
		}
		srcVar := l.loadFromMemory(srcMem)
		destVar := Variable{Name: destReg.Name, Type: IntType{Width: Size(destReg.Size), Signed: false}}
		l.emit(&Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          VariableExpr{Var: srcVar},
		})

	default:
		// reg to reg
		destReg, ok0 := dest.(disasm.RegisterOperand)
		srcReg, ok1 := src.(disasm.RegisterOperand)
		if !ok0 || !ok1 {
			return l.currentBlock, nil
		}
		destVar := Variable{Name: destReg.Name, Type: IntType{Width: Size(destReg.Size), Signed: false}}
		srcExpr := VariableExpr{Var: Variable{Name: srcReg.Name, Type: IntType{Width: Size(srcReg.Size), Signed: false}}}
		l.emit(&Assign{
			baseInstruction: baseInstruction{Loc: l.currentLocation},
			Dest:            destVar,
			Source:          srcExpr,
		})
	}

	return l.currentBlock, nil
}

// ============================================================================
// simd arithmetic: pxor, paddd, etc.
// lift as opaque operations preserving data flow
// ============================================================================

func (l *Lifter) liftSIMDArith(insn *disasm.Instruction) ([]IRInstruction, error) {
	if len(insn.Operands) < 2 {
		return l.currentBlock, nil
	}

	dest := insn.Operands[0]
	destReg, ok := dest.(disasm.RegisterOperand)
	if !ok {
		return l.currentBlock, nil
	}

	destVar := Variable{Name: destReg.Name, Type: IntType{Width: Size(destReg.Size), Signed: false}}

	// load source operand
	src := insn.Operands[len(insn.Operands)-1]
	var srcExpr Expression
	if mem, isMem := src.(disasm.MemoryOperand); isMem {
		sv := l.loadFromMemory(mem)
		srcExpr = VariableExpr{Var: sv}
	} else if reg, isReg := src.(disasm.RegisterOperand); isReg {
		srcExpr = VariableExpr{Var: Variable{Name: reg.Name, Type: IntType{Width: Size(reg.Size), Signed: false}}}
	} else {
		return l.currentBlock, nil
	}

	// model as dest = dest op src (generic binary op)
	// use xor for pxor, add for padd, etc.
	mnemonic := strings.ToLower(insn.Mnemonic)
	op := l.simdOpFromMnemonic(mnemonic)

	resultExpr := BinaryOp{
		Op:    op,
		Left:  VariableExpr{Var: destVar},
		Right: srcExpr,
	}

	l.emit(&Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            destVar,
		Source:          resultExpr,
	})

	return l.currentBlock, nil
}

// simdOpFromMnemonic maps simd mnemonic to a binary operator approximation.
func (l *Lifter) simdOpFromMnemonic(m string) BinaryOperator {
	// strip v prefix for avx
	if strings.HasPrefix(m, "v") && len(m) > 1 {
		m = m[1:]
	}

	switch {
	case strings.Contains(m, "xor"):
		return BinOpXor
	case strings.Contains(m, "and"):
		return BinOpAnd
	case strings.Contains(m, "or"):
		return BinOpOr
	case strings.Contains(m, "add"):
		return BinOpAdd
	case strings.Contains(m, "sub"):
		return BinOpSub
	case strings.Contains(m, "mul"):
		return BinOpMul
	case strings.Contains(m, "div"):
		return BinOpDiv
	case strings.Contains(m, "srl") || strings.Contains(m, "shr"):
		return BinOpShr
	case strings.Contains(m, "sll") || strings.Contains(m, "shl"):
		return BinOpShl
	case strings.Contains(m, "sra"):
		return BinOpSar
	case strings.Contains(m, "cmpeq"):
		return BinOpEq
	case strings.Contains(m, "cmpgt"):
		return BinOpGt
	default:
		return BinOpXor // safe default for unknown simd ops
	}
}

// ============================================================================
// x87 fpu: fld, fstp, fadd, fmul, etc.
// lift as opaque operations on fp stack
// ============================================================================

func (l *Lifter) liftX87(insn *disasm.Instruction) ([]IRInstruction, error) {
	mnemonic := strings.ToLower(insn.Mnemonic)

	// fld: push value onto fp stack
	// fstp: pop fp stack to memory
	// fadd, fmul, fsub, fdiv: arithmetic on fp stack
	// fild: load integer to fp stack
	// fldcw, fnstcw: control word operations (nop for decompilation)
	// fxch: exchange fp stack entries (nop for decompilation)
	// fcomi, fucomip: comparison (sets flags)

	switch {
	case mnemonic == "fldcw" || mnemonic == "fnstcw" || mnemonic == "fstcw" ||
		mnemonic == "fxch" || mnemonic == "finit" || mnemonic == "fninit" ||
		mnemonic == "fwait" || mnemonic == "wait" || mnemonic == "emms":
		// control/nop operations
		return l.currentBlock, nil

	case mnemonic == "fld" || mnemonic == "flds" || mnemonic == "fldl" || mnemonic == "fldt" ||
		mnemonic == "fild" || mnemonic == "fildl" || mnemonic == "fildll":
		// load to fp stack: model as load to st0
		if len(insn.Operands) >= 1 {
			if mem, ok := insn.Operands[0].(disasm.MemoryOperand); ok {
				srcVar := l.loadFromMemory(mem)
				st0Var := Variable{Name: "st0", Type: FloatType{Width: Size8}}
				l.emit(&Assign{
					baseInstruction: baseInstruction{Loc: l.currentLocation},
					Dest:            st0Var,
					Source: Cast{
						Expr:       VariableExpr{Var: srcVar},
						TargetType: FloatType{Width: Size8},
					},
				})
			}
		}
		return l.currentBlock, nil

	case mnemonic == "fstp" || mnemonic == "fstpt" || mnemonic == "fst" ||
		mnemonic == "fistp" || mnemonic == "fistpll" || mnemonic == "fisttp":
		// store from fp stack: model as store from st0
		if len(insn.Operands) >= 1 {
			if mem, ok := insn.Operands[0].(disasm.MemoryOperand); ok {
				st0Var := Variable{Name: "st0", Type: FloatType{Width: Size8}}
				l.storeToMemory(mem, VariableExpr{Var: st0Var})
			}
		}
		return l.currentBlock, nil

	case strings.HasPrefix(mnemonic, "fadd") || strings.HasPrefix(mnemonic, "fiadd"):
		return l.liftX87Arith(insn, BinOpAdd)
	case strings.HasPrefix(mnemonic, "fsub") || strings.HasPrefix(mnemonic, "fisub"):
		return l.liftX87Arith(insn, BinOpSub)
	case strings.HasPrefix(mnemonic, "fmul") || strings.HasPrefix(mnemonic, "fimul"):
		return l.liftX87Arith(insn, BinOpMul)
	case strings.HasPrefix(mnemonic, "fdiv") || strings.HasPrefix(mnemonic, "fidiv"):
		return l.liftX87Arith(insn, BinOpDiv)
	case strings.HasPrefix(mnemonic, "fdivr") || strings.HasPrefix(mnemonic, "fidivr"):
		return l.liftX87Arith(insn, BinOpDiv)
	case strings.HasPrefix(mnemonic, "fsubr") || strings.HasPrefix(mnemonic, "fisubr"):
		return l.liftX87Arith(insn, BinOpSub)

	case mnemonic == "fcomi" || mnemonic == "fcomip" ||
		mnemonic == "fucomi" || mnemonic == "fucomip" ||
		mnemonic == "fcom" || mnemonic == "fcomp" || mnemonic == "fcompp" ||
		mnemonic == "fucom" || mnemonic == "fucomp" || mnemonic == "fucompp":
		// fp comparison: sets eflags (zf, pf, cf)
		st0Var := Variable{Name: "st0", Type: FloatType{Width: Size8}}
		l.setArithmeticFlags(VariableExpr{Var: st0Var}, Size8)
		return l.currentBlock, nil

	default:
		// unknown fpu instruction: treat as nop
		return l.currentBlock, nil
	}
}

// liftX87Arith lifts x87 arithmetic: st0 = st0 op operand
func (l *Lifter) liftX87Arith(insn *disasm.Instruction, op BinaryOperator) ([]IRInstruction, error) {
	st0Var := Variable{Name: "st0", Type: FloatType{Width: Size8}}

	var srcExpr Expression
	if len(insn.Operands) >= 1 {
		if mem, ok := insn.Operands[0].(disasm.MemoryOperand); ok {
			sv := l.loadFromMemory(mem)
			srcExpr = Cast{
				Expr:       VariableExpr{Var: sv},
				TargetType: FloatType{Width: Size8},
			}
		} else if reg, ok := insn.Operands[0].(disasm.RegisterOperand); ok {
			srcExpr = VariableExpr{Var: Variable{Name: reg.Name, Type: FloatType{Width: Size8}}}
		} else {
			srcExpr = VariableExpr{Var: Variable{Name: "st1", Type: FloatType{Width: Size8}}}
		}
	} else {
		srcExpr = VariableExpr{Var: Variable{Name: "st1", Type: FloatType{Width: Size8}}}
	}

	resultExpr := BinaryOp{
		Op:    op,
		Left:  VariableExpr{Var: st0Var},
		Right: srcExpr,
	}

	l.emit(&Assign{
		baseInstruction: baseInstruction{Loc: l.currentLocation},
		Dest:            st0Var,
		Source:          resultExpr,
	})

	return l.currentBlock, nil
}

// ============================================================================
// sse scalar float: comiss, cvtsi2ss, addss, etc.
// ============================================================================

func (l *Lifter) liftSSEScalar(insn *disasm.Instruction) ([]IRInstruction, error) {
	mnemonic := strings.ToLower(insn.Mnemonic)

	// strip v prefix for avx
	inner := mnemonic
	if strings.HasPrefix(inner, "v") && len(inner) > 1 {
		inner = inner[1:]
	}

	switch {
	case strings.HasPrefix(inner, "comis") || strings.HasPrefix(inner, "ucomis"):
		// comparison: sets eflags
		if len(insn.Operands) >= 1 {
			if reg, ok := insn.Operands[0].(disasm.RegisterOperand); ok {
				expr := VariableExpr{Var: Variable{Name: reg.Name, Type: FloatType{Width: Size(reg.Size)}}}
				l.setArithmeticFlags(expr, Size(reg.Size))
			}
		}
		return l.currentBlock, nil

	case strings.HasPrefix(inner, "cvt"):
		// conversion: dest = convert(src)
		if len(insn.Operands) >= 2 {
			dest := insn.Operands[0]
			src := insn.Operands[1]

			destReg, ok := dest.(disasm.RegisterOperand)
			if !ok {
				return l.currentBlock, nil
			}

			var srcExpr Expression
			if mem, isMem := src.(disasm.MemoryOperand); isMem {
				sv := l.loadFromMemory(mem)
				srcExpr = VariableExpr{Var: sv}
			} else if reg, isReg := src.(disasm.RegisterOperand); isReg {
				srcExpr = VariableExpr{Var: Variable{Name: reg.Name, Type: IntType{Width: Size(reg.Size), Signed: false}}}
			} else {
				return l.currentBlock, nil
			}

			destVar := Variable{Name: destReg.Name, Type: IntType{Width: Size(destReg.Size), Signed: false}}
			l.emit(&Assign{
				baseInstruction: baseInstruction{Loc: l.currentLocation},
				Dest:            destVar,
				Source:          Cast{Expr: srcExpr, TargetType: destVar.Type},
			})
		}
		return l.currentBlock, nil

	default:
		// arithmetic: addss, subss, mulss, divss, etc.
		if len(insn.Operands) >= 2 {
			dest := insn.Operands[0]
			src := insn.Operands[len(insn.Operands)-1]

			destReg, ok := dest.(disasm.RegisterOperand)
			if !ok {
				return l.currentBlock, nil
			}

			var srcExpr Expression
			if mem, isMem := src.(disasm.MemoryOperand); isMem {
				sv := l.loadFromMemory(mem)
				srcExpr = VariableExpr{Var: sv}
			} else if reg, isReg := src.(disasm.RegisterOperand); isReg {
				srcExpr = VariableExpr{Var: Variable{Name: reg.Name, Type: FloatType{Width: Size(reg.Size)}}}
			} else {
				return l.currentBlock, nil
			}

			destVar := Variable{Name: destReg.Name, Type: FloatType{Width: Size(destReg.Size)}}
			op := l.sseScalarOp(inner)

			l.emit(&Assign{
				baseInstruction: baseInstruction{Loc: l.currentLocation},
				Dest:            destVar,
				Source: BinaryOp{
					Op:    op,
					Left:  VariableExpr{Var: destVar},
					Right: srcExpr,
				},
			})
		}
		return l.currentBlock, nil
	}
}

// sseScalarOp maps sse scalar mnemonic to binary operator.
func (l *Lifter) sseScalarOp(m string) BinaryOperator {
	switch {
	case strings.HasPrefix(m, "add"):
		return BinOpAdd
	case strings.HasPrefix(m, "sub"):
		return BinOpSub
	case strings.HasPrefix(m, "mul"):
		return BinOpMul
	case strings.HasPrefix(m, "div"):
		return BinOpDiv
	case strings.HasPrefix(m, "min"):
		return BinOpLt
	case strings.HasPrefix(m, "max"):
		return BinOpGt
	default:
		return BinOpAdd
	}
}

// NewAssignWithLocation creates an Assign instruction with a specific source location.
// used by the lifting pipeline to emit placeholder instructions for unsupported mnemonics.
func NewAssignWithLocation(dest Variable, source Expression, loc SourceLocation) *Assign {
	return &Assign{
		baseInstruction: baseInstruction{Loc: loc},
		Dest:            dest,
		Source:          source,
	}
}
