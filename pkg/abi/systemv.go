package abi

import (
	"fmt"
	"strings"

	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// systemV integer parameter registers in order (System V AMD64 ABI §3.2.3)
var systemVIntParamRegs = []string{"rdi", "rsi", "rdx", "rcx", "r8", "r9"}

// systemV float parameter registers in order (xmm0–xmm7)
var systemVFloatParamRegs = []string{
	"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
}

// systemV callee-saved registers (System V AMD64 ABI §3.2.1 table 3.4)
var systemVCalleeSaved = []string{"rbx", "rbp", "r12", "r13", "r14", "r15"}

// systemV return value registers (used for documentation; logic is inline)
// integer: rax (primary), rdx (secondary for 128-bit)
// float:   xmm0 (primary), xmm1 (secondary for complex/128-bit)

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

// IdentifyParameters extracts function parameters from a sequence of instructions.
// It scans the function prologue and call sites to determine which argument
// registers and stack slots are used as parameters.
//
// System V AMD64 parameter passing rules (§3.2.3):
//   - Integer/pointer args 1–6: RDI, RSI, RDX, RCX, R8, R9
//   - Float/SSE args 1–8: XMM0–XMM7
//   - Additional args: pushed on stack right-to-left, 8-byte aligned
//
// IdentifyParameters extracts function parameters from a sequence of instructions.
// It scans the function prologue and call sites to determine which argument
// registers and stack slots are used as parameters.
//
// System V AMD64 parameter passing rules (§3.2.3):
//   - Integer/pointer args 1–6: RDI, RSI, RDX, RCX, R8, R9
//   - Float/SSE args 1–8: XMM0–XMM7
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

		// stop scanning at first call or ret — we only care about prologue reads
		if mnemonic == "call" || mnemonic == "ret" || mnemonic == "retn" {
			break
		}

		rmw := isReadModifyWrite(mnemonic)

		// check each operand for register reads (source operands)
		for opIdx, op := range insn.Operands {
			switch typedOp := op.(type) {
			case disasm.RegisterOperand:
				regName := strings.ToLower(typedOp.Name)
				canonical := canonicalizeRegister(regName)

				// operand[0] is a source when:
				//   - single-operand instruction (push, inc, etc.)
				//   - read-modify-write instruction (add, sub, xor, etc.)
				// operand[1+] are always sources
				isSource := opIdx > 0 || len(insn.Operands) == 1 || rmw

				if isSource {
					// detect variadic: al read before write means caller set xmm count
					if (regName == "al" || regName == "ax" || regName == "eax" || regName == "rax") &&
						regName == "al" && !alWritten {
						alRead = true
					}

					// check integer parameter registers
					for i, paramReg := range systemVIntParamRegs {
						if canonical == paramReg && !intRegWritten[paramReg] && !intParamSeen[paramReg] {
							if i == intParamIdx {
								params = append(params, Parameter{
									Name:     fmt.Sprintf("arg%d", intParamIdx),
									Type:     ir.IntType{Width: ir.Size8, Signed: false},
									Register: paramReg,
									Location: ParameterLocationRegister,
									Index:    intParamIdx,
								})
								intParamSeen[paramReg] = true
								intParamIdx++
							}
						}
					}
					// check float parameter registers
					for i, paramReg := range systemVFloatParamRegs {
						if canonical == paramReg && !floatRegWritten[paramReg] && !floatParamSeen[paramReg] {
							if i == floatParamIdx {
								params = append(params, Parameter{
									Name:     fmt.Sprintf("farg%d", floatParamIdx),
									Type:     ir.FloatType{Width: ir.Size8},
									Register: paramReg,
									Location: ParameterLocationRegister,
									Index:    floatParamIdx,
								})
								floatParamSeen[paramReg] = true
								floatParamIdx++
							}
						}
					}
				}

				// track writes to parameter registers.
				// for non-rmw instructions: only operand[0] with multiple operands is a write.
				// for rmw instructions: operand[0] is written but also read (handled above).
				// test/cmp never write their operands despite being rmw-like — exclude them.
				isWrite := opIdx == 0 && len(insn.Operands) > 1 && mnemonic != "test" && mnemonic != "cmp"
				if isWrite {
					for _, paramReg := range systemVIntParamRegs {
						if canonical == paramReg {
							intRegWritten[paramReg] = true
						}
					}
					for _, paramReg := range systemVFloatParamRegs {
						if canonical == paramReg {
							floatRegWritten[paramReg] = true
						}
					}
					// track al write for variadic detection
					if regName == "al" {
						alWritten = true
					}
				}

			case disasm.MemoryOperand:
				// detect stack parameter reads: [rsp + disp] where disp > 0.
				// at function entry (before any sub rsp), [rsp+8] is arg7, [rsp+16] is arg8, etc.
				// we only detect these in the prologue before any frame modification.
				base := strings.ToLower(typedOp.Base)
				if base == "rsp" && typedOp.Disp > 0 {
					// disp=8 is return address; disp=16 is first stack param, etc.
					// system v §3.2.3: stack args start at [rsp+8] relative to call site,
					// which inside callee is [rsp+8] (return addr at [rsp+0]).
					if typedOp.Disp >= 16 && !stackParamsSeen[typedOp.Disp] {
						stackParamsSeen[typedOp.Disp] = true
						totalIdx := intParamIdx + floatParamIdx + stackParamIdx
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
	}

	// if al was read before write and float params were detected, function is likely variadic.
	// the caller sets al = number of xmm registers used for varargs (system v §3.5.7).
	_ = alRead // consumed by Analyze() to set IsVariadic

	return params
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
		if mnemonic == "ret" || mnemonic == "retn" {
			retIdx = i
			break
		}
	}

	if retIdx < 0 {
		// no ret found — function may be a noreturn or tail-call
		return nil
	}

	// scan from ret backwards to find which return registers are written
	for i := retIdx - 1; i >= 0; i-- {
		insn := insns[i]
		mnemonic := strings.ToLower(insn.Mnemonic)

		// stop at call boundaries — return value must be set after last call
		if mnemonic == "call" {
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
		case "rax":
			raxWritten = true
		case "rdx":
			rdxWritten = true
		case "xmm0":
			xmm0Written = true
		case "xmm1":
			xmm1Written = true
		}
	}

	var retVals []ReturnValue

	if xmm0Written {
		retVals = append(retVals, ReturnValue{
			Type:     ir.FloatType{Width: ir.Size8},
			Register: "xmm0",
		})
		if xmm1Written {
			retVals = append(retVals, ReturnValue{
				Type:     ir.FloatType{Width: ir.Size8},
				Register: "xmm1",
			})
		}
	} else if raxWritten {
		retVals = append(retVals, ReturnValue{
			Type:     ir.IntType{Width: ir.Size8, Signed: false},
			Register: "rax",
		})
		if rdxWritten {
			// 128-bit integer return (e.g., __int128 or struct returned in regs)
			retVals = append(retVals, ReturnValue{
				Type:     ir.IntType{Width: ir.Size8, Signed: false},
				Register: "rdx",
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
// operand counts as a modification — not just push/pop.
func (a *SystemVAnalyzer) VerifyCalleeSavedRegisters(insns []*disasm.Instruction) []CalleeSavedRegisterStatus {
	type saveInfo struct {
		saveAddr    disasm.Address
		restoreAddr disasm.Address
		saved       bool // register was spilled to stack
		restored    bool // register was reloaded from stack
		modified    bool // register was written at least once
	}

	regInfo := make(map[string]*saveInfo, len(systemVCalleeSaved))
	for _, r := range systemVCalleeSaved {
		regInfo[r] = &saveInfo{}
	}

	for _, insn := range insns {
		mnemonic := strings.ToLower(insn.Mnemonic)

		switch mnemonic {
		case "push":
			// push <reg> — spills register to stack (save)
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
			// pop <reg> — reloads register from stack (restore)
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
						// mov reg, reg or mov reg, imm — direct write without save
						info.modified = true
					}
				}
			}

		default:
			// any other instruction that writes to a callee-saved register
			// as its destination operand (index 0) counts as a modification
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

	statuses := make([]CalleeSavedRegisterStatus, 0, len(systemVCalleeSaved))
	for _, r := range systemVCalleeSaved {
		info := regInfo[r]
		// preserved if:
		//   - register was never modified at all (not used), OR
		//   - register was explicitly saved to stack AND restored from stack
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
// It computes the RSP offset relative to function entry at each instruction address.
//
// The algorithm processes instructions sequentially and updates the running offset:
//   - sub rsp, N  → offset -= N
//   - add rsp, N  → offset += N
//   - push        → offset -= 8
//   - pop         → offset += 8
//   - call        → offset -= 8 (return address pushed), then +8 after return
//   - and rsp, -N → alignment: new offset = offset & (-N), computed symbolically
//   - sub rsp, reg → symbolic offset (alloca-style dynamic allocation)
func (a *SystemVAnalyzer) TrackStackPointer(insns []*disasm.Instruction) *SymbolicStackTracker {
	tracker := NewSymbolicStackTracker()

	// rsp offset starts at 0 at function entry (relative to caller's RSP)
	var currentOffset StackOffset = ConcreteOffset{Value: 0}

	for _, insn := range insns {
		// record offset at this instruction's address before processing it
		tracker.SetOffset(insn.Address, currentOffset)

		mnemonic := strings.ToLower(insn.Mnemonic)

		switch mnemonic {
		case "push":
			// push decrements RSP by operand size (8 bytes for 64-bit push)
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

		case "pop":
			// pop increments RSP by operand size
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

		case "call":
			// call pushes return address (8 bytes) then transfers control.
			// after the call returns, RSP is restored — we model the net effect as 0.
			// (the callee is responsible for its own frame)
			// no change to currentOffset from caller's perspective

		case "ret", "retn":
			// ret pops return address — but we stop tracking here
			// (function is returning, no further instructions matter)

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
						// rbp is now the frame pointer at current rsp offset
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
	if destName != "rsp" {
		return current
	}

	// sub rsp, immediate — concrete frame allocation
	if immOp, ok := insn.Operands[1].(disasm.ImmediateOperand); ok {
		return adjustOffset(current, -immOp.Value)
	}

	// sub rsp, register — dynamic allocation (alloca)
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
	if destName != "rsp" {
		return current
	}

	// add rsp, immediate — frame deallocation
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
	if destName != "rsp" {
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

// AnalyzeStackFrame recovers the stack frame layout from the instruction sequence.
// It uses symbolic stack tracking to identify local variables and spill slots.
func (a *SystemVAnalyzer) AnalyzeStackFrame(insns []*disasm.Instruction) *StackFrame {
	tracker := a.TrackStackPointer(insns)

	frame := &StackFrame{
		HasFramePointer: tracker.HasFramePointer(),
		LocalVariables:  make([]LocalVariable, 0),
		SpillSlots:      make([]SpillSlot, 0),
	}

	if fpOffset, ok := tracker.FramePointerRSPOffset(); ok {
		frame.FramePointerOffset = fpOffset
	}

	// track unique stack offsets accessed as memory operands
	type stackAccess struct {
		offset   int64
		size     disasm.Size
		isSpill  bool
		spillReg string
	}
	accessMap := make(map[int64]stackAccess)

	for _, insn := range insns {
		mnemonic := strings.ToLower(insn.Mnemonic)

		// get rsp offset at this instruction
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
				// [rsp + disp]: frame offset = rsp_offset_from_entry + disp
				frameOffset = concreteRSP.Value + memOp.Disp
				resolved = true
			} else if base == "rbp" && tracker.HasFramePointer() {
				// [rbp - disp]: frame offset relative to saved rbp
				// rbp points to saved rbp on stack; locals are at negative offsets
				frameOffset = memOp.Disp
				resolved = true
			}

			if !resolved {
				continue
			}

			// detect spill slots: mov [rsp+off], reg (save) or mov reg, [rsp+off] (restore)
			isSpill := false
			spillReg := ""
			if mnemonic == "mov" {
				if opIdx == 0 {
					// destination is memory — check if source is a callee-saved register
					if len(insn.Operands) > 1 {
						if srcReg, ok := insn.Operands[1].(disasm.RegisterOperand); ok {
							canonical := canonicalizeRegister(strings.ToLower(srcReg.Name))
							for _, csr := range systemVCalleeSaved {
								if canonical == csr {
									isSpill = true
									spillReg = canonical
									break
								}
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
		if strings.ToLower(insn.Mnemonic) == "call" {
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
		if mnemonic == "call" || mnemonic == "ret" || mnemonic == "retn" {
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
			isWrite := opIdx == 0 && len(insn.Operands) > 1 && mnemonic != "test" && mnemonic != "cmp"
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
