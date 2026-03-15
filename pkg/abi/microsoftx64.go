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
		if mnemonic == "call" || mnemonic == "ret" || mnemonic == "retn" {
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
					mnemonic != "test" && mnemonic != "cmp"

				if isSource {
					// check integer parameter registers (rcx, rdx, r8, r9)
					for slotIdx, paramReg := range msX64IntParamRegs {
						if canonical == paramReg &&
							!intRegWritten[paramReg] &&
							!intParamSeen[paramReg] &&
							!slotUsed[slotIdx] {
							params = append(params, Parameter{
								Name:     fmt.Sprintf("arg%d", slotIdx),
								Type:     ir.IntType{Width: ir.Size8, Signed: false},
								Register: paramReg,
								Location: ParameterLocationRegister,
								Index:    slotIdx,
							})
							intParamSeen[paramReg] = true
							slotUsed[slotIdx] = true
						}
					}
					// check float parameter registers (xmm0–xmm3)
					for slotIdx, paramReg := range msX64FloatParamRegs {
						if canonical == paramReg &&
							!floatRegWritten[paramReg] &&
							!floatParamSeen[paramReg] &&
							!slotUsed[slotIdx] {
							params = append(params, Parameter{
								Name:     fmt.Sprintf("farg%d", slotIdx),
								Type:     ir.FloatType{Width: ir.Size8},
								Register: paramReg,
								Location: ParameterLocationRegister,
								Index:    slotIdx,
							})
							floatParamSeen[paramReg] = true
							slotUsed[slotIdx] = true
						}
					}
				}

				if isWrite {
					for _, paramReg := range msX64IntParamRegs {
						if canonical == paramReg {
							intRegWritten[paramReg] = true
						}
					}
					for _, paramReg := range msX64FloatParamRegs {
						if canonical == paramReg {
							floatRegWritten[paramReg] = true
						}
					}
				}

			case disasm.MemoryOperand:
				// detect stack parameter reads: [rsp + disp] where disp >= msX64FirstStackArgOffset.
				// layout at callee entry (before any frame modification):
				//   [rsp+0]  = return address
				//   [rsp+8]  = shadow rcx  (home space)
				//   [rsp+16] = shadow rdx  (home space)
				//   [rsp+24] = shadow r8   (home space)
				//   [rsp+32] = shadow r9   (home space)
				//   [rsp+40] = 5th argument (first stack param)
				base := strings.ToLower(typedOp.Base)
				if base == "rsp" && typedOp.Disp >= msX64FirstStackArgOffset {
					if !stackParamsSeen[typedOp.Disp] {
						stackParamsSeen[typedOp.Disp] = true
						// slot index for stack params starts at 4 (after 4 register slots)
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
	}

	return params
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
		if mnemonic == "ret" || mnemonic == "retn" {
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

		// stop at call — return value must be set after last call
		if mnemonic == "call" {
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
		case "rax":
			raxWritten = true
		case "xmm0":
			xmm0Written = true
		}
	}

	var retVals []ReturnValue

	if xmm0Written {
		retVals = append(retVals, ReturnValue{
			Type:     ir.FloatType{Width: ir.Size8},
			Register: "xmm0",
		})
	} else if raxWritten {
		retVals = append(retVals, ReturnValue{
			Type:     ir.IntType{Width: ir.Size8, Signed: false},
			Register: "rax",
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
	type saveInfo struct {
		saveAddr    disasm.Address
		restoreAddr disasm.Address
		saved       bool
		restored    bool
		modified    bool
	}

	regInfo := make(map[string]*saveInfo, len(msX64CalleeSavedInt))
	for _, r := range msX64CalleeSavedInt {
		regInfo[r] = &saveInfo{}
	}

	for _, insn := range insns {
		mnemonic := strings.ToLower(insn.Mnemonic)

		switch mnemonic {
		case "push":
			if len(insn.Operands) == 1 {
				if regOp, ok := insn.Operands[0].(disasm.RegisterOperand); ok {
					canonical := canonicalizeRegister(strings.ToLower(regOp.Name))
					if info, isCSR := regInfo[canonical]; isCSR && !info.saved {
						info.saved = true
						info.saveAddr = insn.Address
					}
				}
			}

		case "pop":
			if len(insn.Operands) == 1 {
				if regOp, ok := insn.Operands[0].(disasm.RegisterOperand); ok {
					canonical := canonicalizeRegister(strings.ToLower(regOp.Name))
					if info, isCSR := regInfo[canonical]; isCSR && info.saved {
						info.restored = true
						info.restoreAddr = insn.Address
					}
				}
			}

		case "mov":
			if len(insn.Operands) != 2 {
				continue
			}
			dest := insn.Operands[0]
			src := insn.Operands[1]

			// mov [mem], reg — spill to stack (save)
			if _, destIsMem := dest.(disasm.MemoryOperand); destIsMem {
				if regOp, srcIsReg := src.(disasm.RegisterOperand); srcIsReg {
					canonical := canonicalizeRegister(strings.ToLower(regOp.Name))
					if info, isCSR := regInfo[canonical]; isCSR && !info.saved {
						info.saved = true
						info.saveAddr = insn.Address
					}
				}
			}

			// mov reg, [mem] — reload from stack (restore)
			if regOp, destIsReg := dest.(disasm.RegisterOperand); destIsReg {
				canonical := canonicalizeRegister(strings.ToLower(regOp.Name))
				if info, isCSR := regInfo[canonical]; isCSR {
					if _, srcIsMem := src.(disasm.MemoryOperand); srcIsMem && info.saved {
						info.restored = true
						info.restoreAddr = insn.Address
					} else {
						info.modified = true
					}
				}
			}

		default:
			if len(insn.Operands) == 0 {
				continue
			}
			if regOp, ok := insn.Operands[0].(disasm.RegisterOperand); ok {
				canonical := canonicalizeRegister(strings.ToLower(regOp.Name))
				if info, isCSR := regInfo[canonical]; isCSR {
					info.modified = true
				}
			}
		}
	}

	statuses := make([]CalleeSavedRegisterStatus, 0, len(msX64CalleeSavedInt))
	for _, r := range msX64CalleeSavedInt {
		info := regInfo[r]
		neverTouched := !info.saved && !info.modified
		properlyPreserved := info.saved && info.restored
		preserved := neverTouched || properlyPreserved
		statuses = append(statuses, CalleeSavedRegisterStatus{
			Register:    r,
			Preserved:   preserved,
			SaveSite:    info.saveAddr,
			RestoreSite: info.restoreAddr,
		})
	}

	return statuses
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
		case "push":
			size := int64(8)
			if len(insn.Operands) == 1 {
				if regOp, ok := insn.Operands[0].(disasm.RegisterOperand); ok {
					if regOp.Size > 0 {
						size = int64(regOp.Size)
					}
				}
			}
			currentOffset = adjustOffset(currentOffset, -size)

		case "pop":
			size := int64(8)
			if len(insn.Operands) == 1 {
				if regOp, ok := insn.Operands[0].(disasm.RegisterOperand); ok {
					if regOp.Size > 0 {
						size = int64(regOp.Size)
					}
				}
			}
			currentOffset = adjustOffset(currentOffset, size)

		case "sub":
			currentOffset = a.handleSubInstruction(insn, currentOffset, tracker)

		case "add":
			currentOffset = a.handleAddInstruction(insn, currentOffset)

		case "and":
			currentOffset = a.handleAndInstruction(insn, currentOffset)

		case "mov":
			// detect frame pointer setup: mov rbp, rsp
			if len(insn.Operands) == 2 {
				destReg, destIsReg := insn.Operands[0].(disasm.RegisterOperand)
				srcReg, srcIsReg := insn.Operands[1].(disasm.RegisterOperand)
				if destIsReg && srcIsReg {
					destName := strings.ToLower(destReg.Name)
					srcName := strings.ToLower(srcReg.Name)
					if destName == "rbp" && srcName == "rsp" {
						if concrete, ok := currentOffset.(ConcreteOffset); ok {
							tracker.SetFramePointer(concrete.Value)
						}
					}
				}
			}
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
	if !destIsReg || strings.ToLower(destReg.Name) != "rsp" {
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
	if !destIsReg || strings.ToLower(destReg.Name) != "rsp" {
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
	if !destIsReg || strings.ToLower(destReg.Name) != "rsp" {
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

	frame := &StackFrame{
		HasFramePointer: tracker.HasFramePointer(),
		LocalVariables:  make([]LocalVariable, 0),
		SpillSlots:      make([]SpillSlot, 0),
	}

	if fpOffset, ok := tracker.FramePointerRSPOffset(); ok {
		frame.FramePointerOffset = fpOffset
	}

	type stackAccess struct {
		offset   int64
		size     disasm.Size
		isSpill  bool
		spillReg string
	}
	accessMap := make(map[int64]stackAccess)

	for _, insn := range insns {
		mnemonic := strings.ToLower(insn.Mnemonic)

		rspOff, hasOff := tracker.GetOffset(insn.Address)
		if !hasOff {
			continue
		}
		concreteRSP, isConcreteRSP := rspOff.(ConcreteOffset)

		for opIdx, op := range insn.Operands {
			memOp, ok := op.(disasm.MemoryOperand)
			if !ok {
				continue
			}

			base := strings.ToLower(memOp.Base)
			var frameOffset int64
			var resolved bool

			if base == "rsp" && isConcreteRSP {
				frameOffset = concreteRSP.Value + memOp.Disp
				resolved = true
			} else if base == "rbp" && tracker.HasFramePointer() {
				frameOffset = memOp.Disp
				resolved = true
			}

			if !resolved {
				continue
			}

			// detect spill slots: mov [rsp+off], reg where reg is callee-saved
			isSpill := false
			spillReg := ""
			if mnemonic == "mov" && opIdx == 0 {
				if len(insn.Operands) > 1 {
					if srcReg, ok := insn.Operands[1].(disasm.RegisterOperand); ok {
						canonical := canonicalizeRegister(strings.ToLower(srcReg.Name))
						for _, csr := range msX64CalleeSavedInt {
							if canonical == csr {
								isSpill = true
								spillReg = canonical
								break
							}
						}
					}
				}
			}

			size := memOp.Size
			if size == 0 {
				size = disasm.Size64
			}

			if _, exists := accessMap[frameOffset]; !exists {
				accessMap[frameOffset] = stackAccess{
					offset:   frameOffset,
					size:     size,
					isSpill:  isSpill,
					spillReg: spillReg,
				}
			}
		}
	}

	// compute frame size as the most negative RSP offset seen
	minOffset := int64(0)
	for _, insn := range insns {
		if off, ok := tracker.GetOffset(insn.Address); ok {
			if concrete, ok := off.(ConcreteOffset); ok {
				if concrete.Value < minOffset {
					minOffset = concrete.Value
				}
			}
		}
	}
	frame.Size = -minOffset

	localIdx := 0
	for _, acc := range accessMap {
		if acc.isSpill {
			frame.SpillSlots = append(frame.SpillSlots, SpillSlot{
				Register:    acc.spillReg,
				FrameOffset: acc.offset,
				Size:        acc.size,
			})
		} else {
			frame.LocalVariables = append(frame.LocalVariables, LocalVariable{
				Name:        fmt.Sprintf("local_%d", localIdx),
				Type:        ir.IntType{Width: ir.Size(acc.size), Signed: false},
				FrameOffset: acc.offset,
				Size:        acc.size,
			})
			localIdx++
		}
	}

	return frame
}

// Analyze performs complete ABI analysis for a function using Microsoft x64 convention.
func (a *MicrosoftX64Analyzer) Analyze(insns []*disasm.Instruction) *FunctionABI {
	params := a.IdentifyParameters(insns)
	retVals := a.IdentifyReturnValues(insns)
	calleeSaved := a.VerifyCalleeSavedRegisters(insns)
	frame := a.AnalyzeStackFrame(insns)

	isLeaf := true
	for _, insn := range insns {
		if strings.ToLower(insn.Mnemonic) == "call" {
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
