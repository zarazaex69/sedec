package abi

import (
	"fmt"
	"strings"

	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// microsoft x64 integer parameter registers in order (MSDN: parameter passing)
// rcx, rdx, r8, r9 — only 4 integer/pointer registers (vs 6 in system v)
var msX64IntParamRegs = []string{"rcx", "rdx", "r8", "r9"}

// microsoft x64 float parameter registers in order (xmm0–xmm3)
// note: integer and float slots are unified — slot 1 is either rcx or xmm0, not both
var msX64FloatParamRegs = []string{"xmm0", "xmm1", "xmm2", "xmm3"}

// microsoft x64 callee-saved registers (MSDN: caller/callee saved registers)
// rbx, rbp, rdi, rsi, r12-r15 are integer callee-saved
// xmm6-xmm15 are xmm callee-saved (volatile: xmm0-xmm5)
var msX64CalleeSavedInt = []string{"rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"}

// msX64ShadowSpaceSize is the 32-byte home space (shadow space) that the caller
// always allocates on the stack before a call, regardless of argument count.
// this space is owned by the callee and may be used to spill rcx/rdx/r8/r9.
// inside the callee: [rsp+8]=shadow_rcx, [rsp+16]=shadow_rdx, [rsp+24]=shadow_r8, [rsp+32]=shadow_r9
// first stack argument (5th param) is at [rsp+40] = shadow(32) + return_addr(8)
const msX64ShadowSpaceSize = 32

// msX64FirstStackArgOffset is the offset from RSP at function entry to the first
// stack-passed argument (5th parameter). layout at callee entry:
//
//	[rsp+0]  = return address
//	[rsp+8]  = shadow space for rcx (home space, owned by callee)
//	[rsp+16] = shadow space for rdx
//	[rsp+24] = shadow space for r8
//	[rsp+32] = shadow space for r9
//	[rsp+40] = 5th argument (first stack argument)
const msX64FirstStackArgOffset = msX64ShadowSpaceSize + 8

// MicrosoftX64Analyzer implements ABI analysis for the Microsoft x64 calling convention.
// this is the standard ABI on Windows x86_64 (MSVC, MinGW, clang-cl).
type MicrosoftX64Analyzer struct{}

// NewMicrosoftX64Analyzer creates a new Microsoft x64 ABI analyzer
func NewMicrosoftX64Analyzer() *MicrosoftX64Analyzer {
	return &MicrosoftX64Analyzer{}
}

// IdentifyCallingConvention returns the calling convention for this analyzer
func (a *MicrosoftX64Analyzer) IdentifyCallingConvention() CallingConvention {
	return CallingConventionMicrosoftX64
}

// IdentifyParameters extracts function parameters from a sequence of instructions.
//
// Microsoft x64 parameter passing rules (MSDN: x64 calling convention):
//   - Slots 1–4: RCX/XMM0, RDX/XMM1, R8/XMM2, R9/XMM3 (integer or float, not both)
//   - Slots 5+: pushed on stack right-to-left, 8-byte aligned
//   - Shadow space: caller always reserves 32 bytes above return address
//   - Stack args start at [RSP+40] inside callee (32 shadow + 8 return addr)
//   - Variadic: no AL convention; caller must pass count via explicit parameter
func (a *MicrosoftX64Analyzer) IdentifyParameters(insns []*disasm.Instruction) []Parameter {
	// track which parameter registers are read before being written.
	// unified slot model: slot i uses either int reg or float reg, not both.
	// we track per-slot whether it was consumed as int or float.
	intRegWritten := make(map[string]bool)
	floatRegWritten := make(map[string]bool)

	intParamSeen := make(map[string]bool)
	floatParamSeen := make(map[string]bool)

	var params []Parameter
	// slotUsed tracks which parameter slot (0-3) has been claimed.
	// microsoft x64 uses unified slots: if slot 0 is float (xmm0), rcx is not slot 0.
	slotUsed := make(map[int]bool)

	stackParamsSeen := make(map[int64]bool)
	stackParamIdx := 0

	for _, insn := range insns {
		mnemonic := strings.ToLower(insn.Mnemonic)

		// stop at first call or ret — only prologue reads matter
		if mnemonic == mnemonicCall || mnemonic == mnemonicRet || mnemonic == mnemonicRetn {
			break
		}

		rmw := isReadModifyWrite(mnemonic)

		for opIdx, op := range insn.Operands {
			switch typedOp := op.(type) {
			case disasm.RegisterOperand:
				regName := strings.ToLower(typedOp.Name)
				canonical := canonicalizeRegister(regName)

				isSource := opIdx > 0 || len(insn.Operands) == 1 || rmw
				isWrite := opIdx == 0 && len(insn.Operands) > 1 &&
					mnemonic != mnemonicTest && mnemonic != mnemonicCmp

				if isSource {
					a.matchMsIntParam(canonical, slotUsed, intRegWritten, intParamSeen, &params)
					a.matchMsFloatParam(canonical, slotUsed, floatRegWritten, floatParamSeen, &params)
				}

				if isWrite {
					markRegWritten(canonical, msX64IntParamRegs, intRegWritten)
					markRegWritten(canonical, msX64FloatParamRegs, floatRegWritten)
				}

			case disasm.MemoryOperand:
				base := strings.ToLower(typedOp.Base)
				if base == regRsp && typedOp.Disp >= msX64FirstStackArgOffset && !stackParamsSeen[typedOp.Disp] {
					stackParamsSeen[typedOp.Disp] = true
					slotIdx := 4 + stackParamIdx
					params = append(params, Parameter{
						Name:        fmt.Sprintf("arg%d", slotIdx),
						Type:        ir.IntType{Width: ir.Size8, Signed: false},
						Location:    ParameterLocationStack,
						StackOffset: typedOp.Disp,
						Index:       slotIdx,
					})
					stackParamIdx++
				}
			}
		}
	}

	return params
}

// matchMsIntParam checks if canonical matches a microsoft x64 integer parameter register
// and appends the parameter if the slot is unclaimed.
func (a *MicrosoftX64Analyzer) matchMsIntParam(
	canonical string,
	slotUsed map[int]bool,
	written, seen map[string]bool,
	params *[]Parameter,
) {
	for slotIdx, paramReg := range msX64IntParamRegs {
		if canonical == paramReg && !written[paramReg] && !seen[paramReg] && !slotUsed[slotIdx] {
			*params = append(*params, Parameter{
				Name:     fmt.Sprintf("arg%d", slotIdx),
				Type:     ir.IntType{Width: ir.Size8, Signed: false},
				Register: paramReg,
				Location: ParameterLocationRegister,
				Index:    slotIdx,
			})
			seen[paramReg] = true
			slotUsed[slotIdx] = true
		}
	}
}

// matchMsFloatParam checks if canonical matches a microsoft x64 float parameter register
// and appends the parameter if the slot is unclaimed.
func (a *MicrosoftX64Analyzer) matchMsFloatParam(
	canonical string,
	slotUsed map[int]bool,
	written, seen map[string]bool,
	params *[]Parameter,
) {
	for slotIdx, paramReg := range msX64FloatParamRegs {
		if canonical == paramReg && !written[paramReg] && !seen[paramReg] && !slotUsed[slotIdx] {
			*params = append(*params, Parameter{
				Name:     fmt.Sprintf("farg%d", slotIdx),
				Type:     ir.FloatType{Width: ir.Size8},
				Register: paramReg,
				Location: ParameterLocationRegister,
				Index:    slotIdx,
			})
			seen[paramReg] = true
			slotUsed[slotIdx] = true
		}
	}
}

// IdentifyReturnValues determines what the function returns.
// Microsoft x64 return value rules (MSDN: return values):
//   - Integer/pointer <= 64 bits: RAX
//   - Float/SSE: XMM0
//   - Structs <= 64 bits: RAX
//   - Structs > 64 bits: caller allocates buffer, passes pointer in RCX (hidden first param)
//   - __m128 / __m256: XMM0
func (a *MicrosoftX64Analyzer) IdentifyReturnValues(insns []*disasm.Instruction) []ReturnValue {
	raxWritten := false
	xmm0Written := false

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
		return nil
	}

	for i := retIdx - 1; i >= 0; i-- {
		insn := insns[i]
		mnemonic := strings.ToLower(insn.Mnemonic)

		if mnemonic == mnemonicCall {
			break
		}

		if len(insn.Operands) == 0 {
			continue
		}

		destOp, ok := insn.Operands[0].(disasm.RegisterOperand)
		if !ok {
			continue
		}
		canonical := canonicalizeRegister(strings.ToLower(destOp.Name))

		switch canonical {
		case regRax:
			raxWritten = true
		case regXmm0:
			xmm0Written = true
		}
	}

	var retVals []ReturnValue

	if xmm0Written {
		retVals = append(retVals, ReturnValue{
			Type:     ir.FloatType{Width: ir.Size8},
			Register: regXmm0,
		})
	} else if raxWritten {
		retVals = append(retVals, ReturnValue{
			Type:     ir.IntType{Width: ir.Size8, Signed: false},
			Register: regRax,
		})
	}

	return retVals
}

// VerifyCalleeSavedRegisters checks whether each callee-saved register is
// properly saved on entry and restored before return, as required by the
// Microsoft x64 ABI (MSDN: caller/callee saved registers).
//
// Integer callee-saved: RBX, RBP, RDI, RSI, R12, R13, R14, R15.
// XMM callee-saved: XMM6–XMM15 (not tracked here — requires full xmm save analysis).
//
// Note: RDI and RSI are callee-saved in Microsoft x64 (unlike System V where they
// are parameter registers). This is a critical difference between the two ABIs.
func (a *MicrosoftX64Analyzer) VerifyCalleeSavedRegisters(insns []*disasm.Instruction) []CalleeSavedRegisterStatus {
	return verifyCalleeSavedRegistersCommon(insns, msX64CalleeSavedInt)
}

// TrackStackPointer performs symbolic stack pointer tracking throughout the function.
// Microsoft x64 stack discipline (MSDN: stack usage):
//   - RSP must be 16-byte aligned before any call instruction
//   - Caller allocates shadow space (32 bytes) before call, deallocates after
//   - sub rsp, N  → offset -= N
//   - add rsp, N  → offset += N
//   - push        → offset -= 8
//   - pop         → offset += 8
//   - and rsp, -N → alignment
//   - sub rsp, reg → symbolic (alloca)
func (a *MicrosoftX64Analyzer) TrackStackPointer(insns []*disasm.Instruction) *SymbolicStackTracker {
	tracker := NewSymbolicStackTracker()
	var currentOffset StackOffset = ConcreteOffset{Value: 0}

	for _, insn := range insns {
		tracker.SetOffset(insn.Address, currentOffset)

		mnemonic := strings.ToLower(insn.Mnemonic)

		switch mnemonic {
		case mnemonicPush:
			size := int64(8)
			if len(insn.Operands) == 1 {
				if regOp, ok := insn.Operands[0].(disasm.RegisterOperand); ok {
					if regOp.Size > 0 {
						size = int64(regOp.Size)
					}
				}
			}
			currentOffset = adjustOffset(currentOffset, -size)

		case mnemonicPop:
			size := int64(8)
			if len(insn.Operands) == 1 {
				if regOp, ok := insn.Operands[0].(disasm.RegisterOperand); ok {
					if regOp.Size > 0 {
						size = int64(regOp.Size)
					}
				}
			}
			currentOffset = adjustOffset(currentOffset, size)

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

// handleSubInstruction processes sub instructions affecting RSP
func (a *MicrosoftX64Analyzer) handleSubInstruction(
	insn *disasm.Instruction,
	current StackOffset,
	_ *SymbolicStackTracker,
) StackOffset {
	if len(insn.Operands) != 2 {
		return current
	}
	destReg, destIsReg := insn.Operands[0].(disasm.RegisterOperand)
	if !destIsReg || strings.ToLower(destReg.Name) != regRsp {
		return current
	}
	if immOp, ok := insn.Operands[1].(disasm.ImmediateOperand); ok {
		return adjustOffset(current, -immOp.Value)
	}
	if regOp, ok := insn.Operands[1].(disasm.RegisterOperand); ok {
		varName := strings.ToLower(regOp.Name)
		return SymbolicOffset{Base: current.BaseOffset(), VarName: varName}
	}
	return current
}

// handleAddInstruction processes add instructions affecting RSP
func (a *MicrosoftX64Analyzer) handleAddInstruction(
	insn *disasm.Instruction,
	current StackOffset,
) StackOffset {
	if len(insn.Operands) != 2 {
		return current
	}
	destReg, destIsReg := insn.Operands[0].(disasm.RegisterOperand)
	if !destIsReg || strings.ToLower(destReg.Name) != regRsp {
		return current
	}
	if immOp, ok := insn.Operands[1].(disasm.ImmediateOperand); ok {
		return adjustOffset(current, immOp.Value)
	}
	return current
}

// handleAndInstruction processes and rsp, -N (stack alignment)
func (a *MicrosoftX64Analyzer) handleAndInstruction(
	insn *disasm.Instruction,
	current StackOffset,
) StackOffset {
	if len(insn.Operands) != 2 {
		return current
	}
	destReg, destIsReg := insn.Operands[0].(disasm.RegisterOperand)
	if !destIsReg || strings.ToLower(destReg.Name) != regRsp {
		return current
	}
	if immOp, ok := insn.Operands[1].(disasm.ImmediateOperand); ok {
		alignMask := immOp.Value
		if concrete, ok := current.(ConcreteOffset); ok {
			return ConcreteOffset{Value: concrete.Value & alignMask}
		}
		base := current.BaseOffset() & alignMask
		if sym, ok := current.(SymbolicOffset); ok {
			return SymbolicOffset{Base: base, VarName: sym.VarName}
		}
		return ConcreteOffset{Value: base}
	}
	return current
}

// AnalyzeStackFrame recovers the stack frame layout from the instruction sequence.
// Microsoft x64 frame layout (MSDN: stack frame layout):
//
//	[rsp+0]  = return address (at callee entry)
//	[rsp+8]  = shadow space (home space for rcx)
//	[rsp+16] = shadow space (home space for rdx)
//	[rsp+24] = shadow space (home space for r8)
//	[rsp+32] = shadow space (home space for r9)
//	[rsp+40] = 5th argument (if any)
//	...
//	[rsp-N]  = local variables (after sub rsp, N in prologue)
func (a *MicrosoftX64Analyzer) AnalyzeStackFrame(insns []*disasm.Instruction) *StackFrame {
	tracker := a.TrackStackPointer(insns)
	return analyzeStackFrameCommon(insns, tracker, msX64CalleeSavedInt)
}

// Analyze performs complete ABI analysis for a function using Microsoft x64 convention.
func (a *MicrosoftX64Analyzer) Analyze(insns []*disasm.Instruction) *FunctionABI {
	params := a.IdentifyParameters(insns)
	retVals := a.IdentifyReturnValues(insns)
	calleeSaved := a.VerifyCalleeSavedRegisters(insns)
	frame := a.AnalyzeStackFrame(insns)

	isLeaf := true
	for _, insn := range insns {
		if strings.ToLower(insn.Mnemonic) == mnemonicCall {
			isLeaf = false
			break
		}
	}

	return &FunctionABI{
		Convention:      CallingConventionMicrosoftX64,
		Parameters:      params,
		ReturnValues:    retVals,
		Frame:           frame,
		CalleeSavedRegs: calleeSaved,
		IsLeaf:          isLeaf,
		// microsoft x64 has no al-based variadic detection; variadic is explicit
		IsVariadic: false,
	}
}
