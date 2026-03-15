package abi

import (
	"fmt"
	"strings"

	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// stackAccess records a single memory access to a stack location.
type stackAccess struct {
	offset   int64
	size     disasm.Size
	isSpill  bool
	spillReg string
}

// analyzeStackFrameCommon is the shared implementation for stack frame recovery
// used by both system v and microsoft x64 analyzers.
func analyzeStackFrameCommon(
	insns []*disasm.Instruction,
	tracker *SymbolicStackTracker,
	calleeSavedRegs []string,
) *StackFrame {
	frame := &StackFrame{
		HasFramePointer: tracker.HasFramePointer(),
		LocalVariables:  make([]LocalVariable, 0),
		SpillSlots:      make([]SpillSlot, 0),
	}

	if fpOffset, ok := tracker.FramePointerRSPOffset(); ok {
		frame.FramePointerOffset = fpOffset
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
			frameOffset, resolved := resolveFrameOffset(base, memOp, isConcreteRSP, concreteRSP, tracker)
			if !resolved {
				continue
			}

			isSpill, spillReg := detectSpillSlot(mnemonic, opIdx, insn, calleeSavedRegs)

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

	// compute frame size as the most negative rsp offset seen
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

	// build local variables and spill slots from access map
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
