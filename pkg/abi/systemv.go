package abi

import (
	"fmt"
	"strings"

	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// systemV integer parameter registers in order (System V AMD64 ABI §3.2.3)
var systemVIntParamRegs = []string{"rdi", "rsi", "rdx", "rcx", "r8", "r9"}

// systemV float parameter registers in order (xmm0-xmm7)
var systemVFloatParamRegs = []string{
	"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
}

// systemV callee-saved registers (System V AMD64 ABI §3.2.1 table 3.4)
var systemVCalleeSaved = []string{"rbx", "rbp", "r12", "r13", "r14", "r15"}

// SystemVAnalyzer implements ABI analysis for the System V AMD64 calling convention.
// This is the standard ABI on Linux, macOS, FreeBSD, and other Unix-like systems.
type SystemVAnalyzer struct{}

// NewSystemVAnalyzer creates a new System V AMD64 ABI analyzer
func NewSystemVAnalyzer() *SystemVAnalyzer {
	return &SystemVAnalyzer{}
}

// IdentifyCallingConvention returns the calling convention for this analyzer
func (a *SystemVAnalyzer) IdentifyCallingConvention() CallingConvention {
	return CallingConventionSystemVAMD64
}

// isReadModifyWrite returns true for instructions where the first operand is
// both read and written (e.g., add, sub, and, or, xor, imul, shl, shr, etc.).
// for these instructions operand[0] must be treated as a source even though
// it is also the destination.
func isReadModifyWrite(mnemonic string) bool {
	switch mnemonic {
	case "add", "sub", "adc", "sbb", "and", "or", "xor",
		"imul", "mul", "idiv", "div",
		"shl", "shr", "sar", "rol", "ror", "rcl", "rcr",
		"inc", "dec", "neg", "not",
		"xchg", "xadd",
		"test", "cmp",
		"lea":
		return true
	}
	return false
}

// isVarargsSaveInstruction returns true when the instruction is a System V §3.5.7
// register save area write: movaps/movdqa/vmovaps/movups/movdqu [rsp+N>=48], xmmK.
// these instructions save xmm parameter registers to the varargs register save area
// and must NOT be treated as genuine float parameter reads.
func isVarargsSaveInstruction(insn *disasm.Instruction) bool {
	// check mnemonic - only vector store mnemonics used for varargs saves
	switch strings.ToLower(insn.Mnemonic) {
	case "movaps", "movdqa", "vmovaps", "movups", "movdqu":
		// valid mnemonic - continue checking
	default:
		return false
	}

	// must have exactly two operands: [rsp+N] as destination, xmmK as source
	if len(insn.Operands) != 2 {
		return false
	}

	// operand[0] must be a memory operand with base=rsp and disp>=48
	memOp, isMem := insn.Operands[0].(disasm.MemoryOperand)
	if !isMem {
		return false
	}
	if strings.ToLower(memOp.Base) != regRsp || memOp.Disp < 48 {
		return false
	}

	// operand[1] must be a register operand whose canonical name is in systemVFloatParamRegs
	regOp, isReg := insn.Operands[1].(disasm.RegisterOperand)
	if !isReg {
		return false
	}
	canonical := canonicalizeRegister(strings.ToLower(regOp.Name))
	for _, xmmReg := range systemVFloatParamRegs {
		if canonical == xmmReg {
			return true
		}
	}
	return false
}

// IdentifyParameters extracts function parameters from a sequence of instructions.
// It scans the function prologue and call sites to determine which argument
// registers and stack slots are used as parameters.
//
// System V AMD64 parameter passing rules (§3.2.3):
//   - Integer/pointer args 1-6: RDI, RSI, RDX, RCX, R8, R9
//   - Float/SSE args 1-8: XMM0-XMM7
//   - Additional args: pushed on stack right-to-left, 8-byte aligned
//   - Variadic functions: AL must contain the number of XMM registers used
func (a *SystemVAnalyzer) IdentifyParameters(insns []*disasm.Instruction) []Parameter {
	// track which parameter registers are read before being written.
	// a register read before any write in the function body is a parameter.
	intRegWritten := make(map[string]bool)
	floatRegWritten := make(map[string]bool)

	// use a set to avoid duplicate parameter entries
	intParamSeen := make(map[string]bool)
	floatParamSeen := make(map[string]bool)

	var params []Parameter
	intParamIdx := 0
	floatParamIdx := 0

	// stack parameter index starts after the 6 register params.
	// system v §3.2.3: additional args are at [rsp+8], [rsp+16], ... at call site.
	// inside the callee they appear at [rsp+8] (above return address) before any frame setup.
	stackParamIdx := 0
	stackParamsSeen := make(map[int64]bool)

	// detect variadic: al read before write signals varargs (al = count of xmm args used)
	alRead := false
	alWritten := false

	for _, insn := range insns {
		mnemonic := strings.ToLower(insn.Mnemonic)

		// stop scanning at first call or ret - we only care about prologue reads
		if mnemonic == mnemonicCall || mnemonic == mnemonicRet || mnemonic == mnemonicRetn {
			break
		}

		// detect varargs save area writes: movaps [rsp+N>=48], xmmK.
		// pre-mark all xmm registers as written so matchFloatParam will skip them.
		// this prevents xmm save-area stores from being misclassified as float params.
		if isVarargsSaveInstruction(insn) {
			for _, xmmReg := range systemVFloatParamRegs {
				floatRegWritten[xmmReg] = true
			}
			continue
		}

		rmw := isReadModifyWrite(mnemonic)

		// check each operand for register reads (source operands)
		for opIdx, op := range insn.Operands {
			switch typedOp := op.(type) {
			case disasm.RegisterOperand:
				regName := strings.ToLower(typedOp.Name)
				canonical := canonicalizeRegister(regName)
				isSource := opIdx > 0 || len(insn.Operands) == 1 || rmw

				if isSource {
					if regName == "al" && !alWritten {
						alRead = true
					}
					a.matchIntParam(canonical, &intParamIdx, intRegWritten, intParamSeen, systemVIntParamRegs, &params)
					a.matchFloatParam(canonical, &floatParamIdx, floatRegWritten, floatParamSeen, systemVFloatParamRegs, &params)
				}

				isWrite := opIdx == 0 && len(insn.Operands) > 1 && mnemonic != mnemonicTest && mnemonic != mnemonicCmp
				if isWrite {
					markRegWritten(canonical, systemVIntParamRegs, intRegWritten)
					markRegWritten(canonical, systemVFloatParamRegs, floatRegWritten)
					if regName == "al" {
						alWritten = true
					}
				}

			case disasm.MemoryOperand:
				base := strings.ToLower(typedOp.Base)
				if base == regRsp && typedOp.Disp >= 16 && !stackParamsSeen[typedOp.Disp] {
					stackParamsSeen[typedOp.Disp] = true
					// use len(params) to avoid gaps when float params are skipped
					totalIdx := len(params)
					params = append(params, Parameter{
						Name:        fmt.Sprintf("arg%d", totalIdx),
						Type:        ir.IntType{Width: ir.Size8, Signed: false},
						Location:    ParameterLocationStack,
						StackOffset: typedOp.Disp,
						Index:       totalIdx,
					})
					stackParamIdx++
				}
			}
		}
	}

	_ = alRead // consumed by Analyze() to set IsVariadic

	return params
}

// matchIntParam checks if canonical matches a sequential integer parameter register
// and appends the parameter if it is the next expected slot.
func (a *SystemVAnalyzer) matchIntParam(
	canonical string,
	nextIdx *int,
	written, seen map[string]bool,
	regs []string,
	params *[]Parameter,
) {
	for i, paramReg := range regs {
		if canonical == paramReg && !written[paramReg] && !seen[paramReg] && i == *nextIdx {
			*params = append(*params, Parameter{
				Name:     fmt.Sprintf("arg%d", *nextIdx),
				Type:     ir.IntType{Width: ir.Size8, Signed: false},
				Register: paramReg,
				Location: ParameterLocationRegister,
				Index:    *nextIdx,
			})
			seen[paramReg] = true
			(*nextIdx)++
		}
	}
}

// matchFloatParam checks if canonical matches a sequential float parameter register
// and appends the parameter if it is the next expected slot.
func (a *SystemVAnalyzer) matchFloatParam(
	canonical string,
	nextIdx *int,
	written, seen map[string]bool,
	regs []string,
	params *[]Parameter,
) {
	for i, paramReg := range regs {
		if canonical == paramReg && !written[paramReg] && !seen[paramReg] && i == *nextIdx {
			*params = append(*params, Parameter{
				Name:     fmt.Sprintf("farg%d", *nextIdx),
				Type:     ir.FloatType{Width: ir.Size8},
				Register: paramReg,
				Location: ParameterLocationRegister,
				Index:    *nextIdx,
			})
			seen[paramReg] = true
			(*nextIdx)++
		}
	}
}

// markRegWritten marks a register as written if it matches any register in the list.
func markRegWritten(canonical string, regs []string, written map[string]bool) {
	for _, paramReg := range regs {
		if canonical == paramReg {
			written[paramReg] = true
		}
	}
}

// IdentifyReturnValues determines what the function returns.
// System V AMD64 return value rules (§3.2.3):
//   - Integer/pointer: RAX (and RDX for 128-bit values)
//   - Float/SSE: XMM0 (and XMM1 for complex/128-bit)
//   - Void: no return register written before ret
func (a *SystemVAnalyzer) IdentifyReturnValues(insns []*disasm.Instruction) []ReturnValue {
	// scan backwards from ret instruction to find last writes to return registers
	raxWritten := false
	rdxWritten := false
	xmm0Written := false
	xmm1Written := false

	// find the ret instruction and scan backwards
	retIdx := -1
	for i := len(insns) - 1; i >= 0; i-- {
		mnemonic := strings.ToLower(insns[i].Mnemonic)
		if mnemonic == mnemonicRet || mnemonic == mnemonicRetn {
			retIdx = i
			break
		}
	}

	if retIdx < 0 {
		// no ret found - function may be a noreturn or tail-call
		return nil
	}

	// scan from ret backwards to find which return registers are written
	for i := retIdx - 1; i >= 0; i-- {
		insn := insns[i]
		mnemonic := strings.ToLower(insn.Mnemonic)

		// stop at call boundaries - return value must be set after last call
		if mnemonic == mnemonicCall {
			break
		}

		if len(insn.Operands) == 0 {
			continue
		}

		// destination operand (index 0) for most instructions
		destOp, ok := insn.Operands[0].(disasm.RegisterOperand)
		if !ok {
			continue
		}
		canonical := canonicalizeRegister(strings.ToLower(destOp.Name))

		switch canonical {
		case regRax:
			raxWritten = true
		case regRdx:
			rdxWritten = true
		case regXmm0:
			xmm0Written = true
		case regXmm1:
			xmm1Written = true
		}
	}

	var retVals []ReturnValue

	if xmm0Written {
		retVals = append(retVals, ReturnValue{
			Type:     ir.FloatType{Width: ir.Size8},
			Register: regXmm0,
		})
		if xmm1Written {
			retVals = append(retVals, ReturnValue{
				Type:     ir.FloatType{Width: ir.Size8},
				Register: regXmm1,
			})
		}
	} else if raxWritten {
		retVals = append(retVals, ReturnValue{
			Type:     ir.IntType{Width: ir.Size8, Signed: false},
			Register: regRax,
		})
		if rdxWritten {
			// 128-bit integer return (e.g., __int128 or struct returned in regs)
			retVals = append(retVals, ReturnValue{
				Type:     ir.IntType{Width: ir.Size8, Signed: false},
				Register: regRdx,
			})
		}
	}

	return retVals
}

// VerifyCalleeSavedRegisters checks whether each callee-saved register is
// properly saved on entry and restored before return, as required by the
// System V AMD64 ABI §3.2.1.
//
// Callee-saved registers: RBX, RBP, R12, R13, R14, R15.
// The function must save these on entry (push or mov to stack) and restore
// them before returning (pop or mov from stack).
//
// A register is considered "clobbered" (not preserved) if it is written
// without a prior save to the stack. Any write to the register's destination
// operand counts as a modification - not just push/pop.
func (a *SystemVAnalyzer) VerifyCalleeSavedRegisters(insns []*disasm.Instruction) []CalleeSavedRegisterStatus {
	return verifyCalleeSavedRegistersCommon(insns, systemVCalleeSaved)
}

// TrackStackPointer performs symbolic stack pointer tracking throughout the function.
// It computes the RSP offset relative to function entry at each instruction address.
//
// The algorithm processes instructions sequentially and updates the running offset:
//   - sub rsp, N  -> offset -= N
//   - add rsp, N  -> offset += N
//   - push        -> offset -= 8
//   - pop         -> offset += 8
//   - call        -> offset -= 8 (return address pushed), then +8 after return
//   - and rsp, -N -> alignment: new offset = offset & (-N), computed symbolically
//   - sub rsp, reg -> symbolic offset (alloca-style dynamic allocation)
func (a *SystemVAnalyzer) TrackStackPointer(insns []*disasm.Instruction) *SymbolicStackTracker {
	tracker := NewSymbolicStackTracker()

	// rsp offset starts at 0 at function entry (relative to caller's RSP)
	var currentOffset StackOffset = ConcreteOffset{Value: 0}

	for _, insn := range insns {
		// record offset at this instruction's address before processing it
		tracker.SetOffset(insn.Address, currentOffset)

		mnemonic := strings.ToLower(insn.Mnemonic)

		switch mnemonic {
		case mnemonicPush:
			size := int64(8)
			if len(insn.Operands) == 1 {
				if regOp, ok := insn.Operands[0].(disasm.RegisterOperand); ok {
					size = int64(regOp.Size)
					if size == 0 {
						size = 8
					}
				}
			}
			currentOffset = adjustOffset(currentOffset, -size)

		case mnemonicPop:
			size := int64(8)
			if len(insn.Operands) == 1 {
				if regOp, ok := insn.Operands[0].(disasm.RegisterOperand); ok {
					size = int64(regOp.Size)
					if size == 0 {
						size = 8
					}
				}
			}
			currentOffset = adjustOffset(currentOffset, size)

		case mnemonicCall:
			// after the call returns, RSP is restored - we model the net effect as 0.
			// (the callee is responsible for its own frame)
			// no change to currentOffset from caller's perspective

		case mnemonicRet, mnemonicRetn:

		case mnemonicSub:
			currentOffset = a.handleSubInstruction(insn, currentOffset, tracker)

		case mnemonicAdd:
			currentOffset = a.handleAddInstruction(insn, currentOffset)

		case mnemonicAnd:
			currentOffset = a.handleAndInstruction(insn, currentOffset)

		case mnemonicMov:
			detectFramePointerSetup(insn, currentOffset, tracker)
		}
	}

	return tracker
}

// handleSubInstruction processes sub instructions affecting RSP.
// tracker is retained for future inconsistency recording but not used yet.
func (a *SystemVAnalyzer) handleSubInstruction(
	insn *disasm.Instruction,
	current StackOffset,
	_ *SymbolicStackTracker,
) StackOffset {
	if len(insn.Operands) != 2 {
		return current
	}

	destReg, destIsReg := insn.Operands[0].(disasm.RegisterOperand)
	if !destIsReg {
		return current
	}

	destName := strings.ToLower(destReg.Name)
	if destName != regRsp {
		return current
	}

	if immOp, ok := insn.Operands[1].(disasm.ImmediateOperand); ok {
		return adjustOffset(current, -immOp.Value)
	}

	// sub rsp, register - dynamic allocation (alloca)
	if regOp, ok := insn.Operands[1].(disasm.RegisterOperand); ok {
		varName := strings.ToLower(regOp.Name)
		base := current.BaseOffset()
		return SymbolicOffset{Base: base, VarName: varName}
	}

	return current
}

// handleAddInstruction processes add instructions affecting RSP
func (a *SystemVAnalyzer) handleAddInstruction(
	insn *disasm.Instruction,
	current StackOffset,
) StackOffset {
	if len(insn.Operands) != 2 {
		return current
	}

	destReg, destIsReg := insn.Operands[0].(disasm.RegisterOperand)
	if !destIsReg {
		return current
	}

	destName := strings.ToLower(destReg.Name)
	if destName != regRsp {
		return current
	}

	// add rsp, immediate - frame deallocation
	if immOp, ok := insn.Operands[1].(disasm.ImmediateOperand); ok {
		return adjustOffset(current, immOp.Value)
	}

	return current
}

// handleAndInstruction processes and rsp, -N (stack alignment)
func (a *SystemVAnalyzer) handleAndInstruction(
	insn *disasm.Instruction,
	current StackOffset,
) StackOffset {
	if len(insn.Operands) != 2 {
		return current
	}

	destReg, destIsReg := insn.Operands[0].(disasm.RegisterOperand)
	if !destIsReg {
		return current
	}

	destName := strings.ToLower(destReg.Name)
	if destName != regRsp {
		return current
	}

	// and rsp, -N aligns RSP down to N-byte boundary
	if immOp, ok := insn.Operands[1].(disasm.ImmediateOperand); ok {
		alignMask := immOp.Value // typically -16 (0xFFFFFFFFFFFFFFF0)
		if concrete, ok := current.(ConcreteOffset); ok {
			aligned := concrete.Value & alignMask
			return ConcreteOffset{Value: aligned}
		}
		// symbolic: we can only track the base component
		base := current.BaseOffset()
		aligned := base & alignMask
		if sym, ok := current.(SymbolicOffset); ok {
			return SymbolicOffset{Base: aligned, VarName: sym.VarName}
		}
		return ConcreteOffset{Value: aligned}
	}

	return current
}

// adjustOffset applies a concrete delta to a stack offset
func adjustOffset(current StackOffset, delta int64) StackOffset {
	switch off := current.(type) {
	case ConcreteOffset:
		return ConcreteOffset{Value: off.Value + delta}
	case SymbolicOffset:
		return SymbolicOffset{Base: off.Base + delta, VarName: off.VarName}
	default:
		return ConcreteOffset{Value: delta}
	}
}

// resolveFrameOffset computes the frame-relative offset for a memory operand.
// returns the offset and true if resolved, or 0 and false if unresolvable.
func resolveFrameOffset(
	base string,
	memOp disasm.MemoryOperand,
	isConcreteRSP bool,
	concreteRSP ConcreteOffset,
	tracker *SymbolicStackTracker,
) (int64, bool) {
	if base == regRsp && isConcreteRSP {
		return concreteRSP.Value + memOp.Disp, true
	}
	if base == regRbp && tracker.HasFramePointer() {
		return memOp.Disp, true
	}
	return 0, false
}

// detectSpillSlot checks whether a memory write is a callee-saved register spill.
// returns (isSpill, spillRegName).
func detectSpillSlot(
	mnemonic string,
	opIdx int,
	insn *disasm.Instruction,
	calleeSavedRegs []string,
) (bool, string) {
	if mnemonic != mnemonicMov || opIdx != 0 || len(insn.Operands) < 2 {
		return false, ""
	}
	srcReg, ok := insn.Operands[1].(disasm.RegisterOperand)
	if !ok {
		return false, ""
	}
	canonical := canonicalizeRegister(strings.ToLower(srcReg.Name))
	for _, csr := range calleeSavedRegs {
		if canonical == csr {
			return true, canonical
		}
	}
	return false, ""
}

// AnalyzeStackFrame recovers the stack frame layout from the instruction sequence.
func (a *SystemVAnalyzer) AnalyzeStackFrame(insns []*disasm.Instruction) *StackFrame {
	tracker := a.TrackStackPointer(insns)
	return analyzeStackFrameCommon(insns, tracker, systemVCalleeSaved)
}

// Analyze performs complete ABI analysis for a function using System V AMD64 convention.
// It identifies parameters, return values, callee-saved register usage, and stack frame layout.
func (a *SystemVAnalyzer) Analyze(insns []*disasm.Instruction) *FunctionABI {
	params := a.IdentifyParameters(insns)
	retVals := a.IdentifyReturnValues(insns)
	calleeSaved := a.VerifyCalleeSavedRegisters(insns)
	frame := a.AnalyzeStackFrame(insns)

	// detect leaf function: no call instructions
	isLeaf := true
	for _, insn := range insns {
		if strings.ToLower(insn.Mnemonic) == mnemonicCall {
			isLeaf = false
			break
		}
	}

	// detect variadic: al is read before write in prologue (system v §3.5.7).
	// the caller sets al = number of xmm registers used for varargs.
	isVariadic := a.detectVariadic(insns)

	return &FunctionABI{
		Convention:      CallingConventionSystemVAMD64,
		Parameters:      params,
		ReturnValues:    retVals,
		Frame:           frame,
		CalleeSavedRegs: calleeSaved,
		IsLeaf:          isLeaf,
		IsVariadic:      isVariadic,
	}
}

// detectVariadic returns true if the function reads AL before writing it in the prologue.
// system v §3.5.7: for variadic functions, the caller sets AL to the number of
// vector (xmm) registers used to pass arguments. the callee reads AL to know
// how many xmm registers to save in the register save area.
func (a *SystemVAnalyzer) detectVariadic(insns []*disasm.Instruction) bool {
	alWritten := false
	for _, insn := range insns {
		mnemonic := strings.ToLower(insn.Mnemonic)
		if mnemonic == mnemonicCall || mnemonic == mnemonicRet || mnemonic == mnemonicRetn {
			break
		}
		rmw := isReadModifyWrite(mnemonic)
		for opIdx, op := range insn.Operands {
			regOp, ok := op.(disasm.RegisterOperand)
			if !ok {
				continue
			}
			regName := strings.ToLower(regOp.Name)
			// al is the low byte of rax; it carries the xmm count for varargs
			if regName != "al" {
				continue
			}
			isSource := opIdx > 0 || len(insn.Operands) == 1 || rmw
			isWrite := opIdx == 0 && len(insn.Operands) > 1 && mnemonic != mnemonicTest && mnemonic != mnemonicCmp
			if isSource && !alWritten {
				return true
			}
			if isWrite {
				alWritten = true
			}
		}
	}
	return false
}
