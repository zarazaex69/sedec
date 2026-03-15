package abi

import (
	"strings"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// verifyCalleeSavedRegistersCommon is the shared implementation for callee-saved
// register verification used by both system v and microsoft x64 analyzers.
// it checks whether each register in calleeSavedRegs is properly saved on entry
// and restored before return.
func verifyCalleeSavedRegistersCommon(insns []*disasm.Instruction, calleeSavedRegs []string) []CalleeSavedRegisterStatus {
	type saveInfo struct {
		saveAddr    disasm.Address
		restoreAddr disasm.Address
		saved       bool
		restored    bool
		modified    bool
	}

	regInfo := make(map[string]*saveInfo, len(calleeSavedRegs))
	for _, r := range calleeSavedRegs {
		regInfo[r] = &saveInfo{}
	}

	for _, insn := range insns {
		mnemonic := strings.ToLower(insn.Mnemonic)

		switch mnemonic {
		case mnemonicPush:
			if len(insn.Operands) == 1 {
				if regOp, ok := insn.Operands[0].(disasm.RegisterOperand); ok {
					canonical := canonicalizeRegister(strings.ToLower(regOp.Name))
					if info, isCSR := regInfo[canonical]; isCSR && !info.saved {
						info.saved = true
						info.saveAddr = insn.Address
					}
				}
			}

		case mnemonicPop:
			if len(insn.Operands) == 1 {
				if regOp, ok := insn.Operands[0].(disasm.RegisterOperand); ok {
					canonical := canonicalizeRegister(strings.ToLower(regOp.Name))
					if info, isCSR := regInfo[canonical]; isCSR && info.saved {
						info.restored = true
						info.restoreAddr = insn.Address
					}
				}
			}

		case mnemonicMov:
			if len(insn.Operands) != 2 {
				continue
			}
			dest := insn.Operands[0]
			src := insn.Operands[1]

			// mov [mem], reg -- spill to stack (save)
			if _, destIsMem := dest.(disasm.MemoryOperand); destIsMem {
				if regOp, srcIsReg := src.(disasm.RegisterOperand); srcIsReg {
					canonical := canonicalizeRegister(strings.ToLower(regOp.Name))
					if info, isCSR := regInfo[canonical]; isCSR && !info.saved {
						info.saved = true
						info.saveAddr = insn.Address
					}
				}
			}

			// mov reg, [mem] -- reload from stack (restore)
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

	statuses := make([]CalleeSavedRegisterStatus, 0, len(calleeSavedRegs))
	for _, r := range calleeSavedRegs {
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

// detectFramePointerSetup checks if the instruction is "mov rbp, rsp" and
// records the frame pointer in the tracker if so.
func detectFramePointerSetup(insn *disasm.Instruction, currentOffset StackOffset, tracker *SymbolicStackTracker) {
	if len(insn.Operands) != 2 {
		return
	}
	destReg, destIsReg := insn.Operands[0].(disasm.RegisterOperand)
	srcReg, srcIsReg := insn.Operands[1].(disasm.RegisterOperand)
	if !destIsReg || !srcIsReg {
		return
	}
	if strings.ToLower(destReg.Name) != regRbp || strings.ToLower(srcReg.Name) != regRsp {
		return
	}
	if concrete, ok := currentOffset.(ConcreteOffset); ok {
		tracker.SetFramePointer(concrete.Value)
	}
}
