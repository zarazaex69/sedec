package abi

// TestProperty15: Symbolic Stack Tracking Correctness
//
// property 15: for all sequences of stack operations S:
//
//	TrackStackPointer(S)[addr] == expected_offset(S, addr)
//
// validates requirements 12.9-12.21:
//   - 12.9:  symbolic stack pointer tracking throughout function
//   - 12.10: track rsp offset relative to function entry at each instruction
//   - 12.11: handle stack modifications (sub rsp, add rsp, push, pop)
//   - 12.12: handle stack alignment (and rsp, -16)
//   - 12.13: handle dynamic allocation (sub rsp, rax) with symbolic component
//   - 12.14: identify local variables from [rsp+offset] and [rbp-offset] accesses
//   - 12.15: compute stack frame size
//   - 12.18: detect frame pointer setup (push rbp; mov rbp, rsp)
//   - 12.19: handle leaf functions without frame pointers
//   - 12.20: rsp offset at function entry is 0
//   - 12.21: push decrements rsp by operand size, pop increments
//
// minimum 100 iterations required.

import (
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
	"github.com/zarazaex69/sedec/pkg/disasm"
)

// ============================================================================
// property test entry point
// ============================================================================

// TestProperty15 verifies symbolic stack tracking correctness across 100+ generated
// instruction sequences for both System V AMD64 and Microsoft x64 conventions.
func TestProperty15(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	params.MaxSize = 12

	properties := gopter.NewProperties(params)

	// property 15a: rsp offset at function entry is always 0
	properties.Property("rsp offset at function entry is 0 (system v)", prop.ForAll(
		func(prog *stackOpProgram) bool {
			return checkEntryOffsetIsZero(t, prog, CallingConventionSystemVAMD64)
		},
		genStackOpProgram(),
	))

	// property 15b: push decrements rsp by 8, pop increments rsp by 8
	properties.Property("push/pop balance preserves rsp offset (system v)", prop.ForAll(
		func(prog *pushPopProgram) bool {
			return checkPushPopBalance(t, prog, CallingConventionSystemVAMD64)
		},
		genPushPopProgram(),
	))

	// property 15c: sub rsp, N decrements offset by exactly N
	properties.Property("sub rsp,N decrements offset by N (system v)", prop.ForAll(
		func(prog *subRspProgram) bool {
			return checkSubRspDecrement(t, prog, CallingConventionSystemVAMD64)
		},
		genSubRspProgram(),
	))

	// property 15d: add rsp, N increments offset by exactly N
	properties.Property("add rsp,N increments offset by N (system v)", prop.ForAll(
		func(prog *addRspProgram) bool {
			return checkAddRspIncrement(t, prog, CallingConventionSystemVAMD64)
		},
		genAddRspProgram(),
	))

	// property 15e: and rsp, -N aligns offset down to N-byte boundary
	properties.Property("and rsp,-N aligns offset to N-byte boundary (system v)", prop.ForAll(
		func(prog *alignRspProgram) bool {
			return checkAlignRsp(t, prog, CallingConventionSystemVAMD64)
		},
		genAlignRspProgram(),
	))

	// property 15f: sub rsp, reg produces symbolic offset with correct base
	properties.Property("sub rsp,reg produces symbolic offset (system v)", prop.ForAll(
		func(prog *allocaProgram) bool {
			return checkAllocaSymbolic(t, prog, CallingConventionSystemVAMD64)
		},
		genAllocaProgram(),
	))

	// property 15g: frame pointer setup detected when mov rbp,rsp present
	properties.Property("frame pointer setup detected (system v)", prop.ForAll(
		func(prog *framePointerProgram) bool {
			return checkFramePointerDetection(t, prog, CallingConventionSystemVAMD64)
		},
		genFramePointerProgram(),
	))

	// property 15h: microsoft x64 push/pop balance
	properties.Property("push/pop balance preserves rsp offset (ms x64)", prop.ForAll(
		func(prog *pushPopProgram) bool {
			return checkPushPopBalance(t, prog, CallingConventionMicrosoftX64)
		},
		genPushPopProgram(),
	))

	// property 15i: microsoft x64 sub rsp,N decrement
	properties.Property("sub rsp,N decrements offset by N (ms x64)", prop.ForAll(
		func(prog *subRspProgram) bool {
			return checkSubRspDecrement(t, prog, CallingConventionMicrosoftX64)
		},
		genSubRspProgram(),
	))

	// property 15j: frame size equals absolute value of minimum rsp offset
	properties.Property("frame size equals abs(min rsp offset)", prop.ForAll(
		func(prog *frameSizeProgram) bool {
			return checkFrameSize(t, prog, CallingConventionSystemVAMD64)
		},
		genFrameSizeProgram(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ============================================================================
// program types for generators
// ============================================================================

// stackOpProgram is a generic sequence of stack-modifying instructions
// used to verify that the entry offset is always 0.
type stackOpProgram struct {
	// ops is the sequence of stack operations (push, pop, sub rsp, add rsp)
	ops []*disasm.Instruction
}

// pushPopProgram is a balanced sequence of push/pop pairs.
// invariant: every push is matched by a pop, so net rsp change is 0.
type pushPopProgram struct {
	// depth is the number of push/pop pairs (1-6)
	depth int
	// regs is the sequence of registers used for push/pop
	regs []string
}

// subRspProgram is a sequence of sub rsp, N instructions.
// invariant: after each sub rsp, N, the offset decreases by exactly N.
type subRspProgram struct {
	// allocations is the sequence of frame allocation sizes (8-256, multiples of 8)
	allocations []int64
}

// addRspProgram is a sequence of sub rsp, N followed by add rsp, N.
// invariant: after add rsp, N, the offset increases by exactly N.
type addRspProgram struct {
	// size is the allocation size (8-256, multiple of 8)
	size int64
}

// alignRspProgram tests and rsp, -N alignment.
// invariant: result is aligned down to N-byte boundary.
type alignRspProgram struct {
	// preAlloc is the sub rsp amount before alignment (8-128)
	preAlloc int64
	// alignPow is the alignment power (4=16-byte, 5=32-byte, 6=64-byte)
	alignPow uint
}

// allocaProgram tests sub rsp, reg (dynamic allocation).
// invariant: result is SymbolicOffset with correct base.
type allocaProgram struct {
	// preAlloc is the concrete sub rsp before the alloca (0 or 8-64)
	preAlloc int64
	// varReg is the register used as the dynamic size
	varReg string
}

// framePointerProgram tests frame pointer detection.
// invariant: HasFramePointer() == true iff mov rbp,rsp is present.
type framePointerProgram struct {
	// hasFramePointer indicates whether the sequence includes push rbp; mov rbp,rsp
	hasFramePointer bool
	// frameSize is the sub rsp amount after frame pointer setup (0 or 8-128)
	frameSize int64
}

// frameSizeProgram tests that frame.Size == abs(min rsp offset).
type frameSizeProgram struct {
	// allocations is the sequence of sub rsp amounts (each 8-128)
	allocations []int64
}

// ============================================================================
// gopter generators
// ============================================================================

// genStackOpProgram generates arbitrary sequences of stack operations.
// the sequence always starts at address 0x1000 with monotonically increasing addresses.
func genStackOpProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		n := int(params.NextUint64()%8) + 1 // 1-8 operations
		regs := []string{"rbx", "r12", "r13", "r14", "r15"}
		ops := make([]*disasm.Instruction, 0, n+1)
		addr := disasm.Address(0x1000)

		for i := 0; i < n; i++ {
			choice := params.NextUint64() % 4
			switch choice {
			case 0: // push reg
				r := regs[params.NextUint64()%uint64(len(regs))]
				ops = append(ops, buildInsn(addr, "push", reg(r, disasm.Size64)))
				addr += 1
			case 1: // pop reg
				r := regs[params.NextUint64()%uint64(len(regs))]
				ops = append(ops, buildInsn(addr, "pop", reg(r, disasm.Size64)))
				addr += 1
			case 2: // sub rsp, N
				n8 := int64((params.NextUint64()%16)+1) * 8
				ops = append(ops, buildInsn(addr, "sub", reg("rsp", disasm.Size64), imm(n8, disasm.Size64)))
				addr += 4
			case 3: // add rsp, N
				n8 := int64((params.NextUint64()%16)+1) * 8
				ops = append(ops, buildInsn(addr, "add", reg("rsp", disasm.Size64), imm(n8, disasm.Size64)))
				addr += 4
			}
		}
		ops = append(ops, buildInsn(addr, "ret"))
		return gopter.NewGenResult(&stackOpProgram{ops: ops}, gopter.NoShrinker)
	}
}

// genPushPopProgram generates balanced push/pop sequences.
func genPushPopProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		depth := int(params.NextUint64()%6) + 1 // 1-6 pairs
		regs := []string{"rbx", "r12", "r13", "r14", "r15", "rbp"}
		chosen := make([]string, depth)
		for i := range chosen {
			chosen[i] = regs[params.NextUint64()%uint64(len(regs))]
		}
		return gopter.NewGenResult(&pushPopProgram{depth: depth, regs: chosen}, gopter.NoShrinker)
	}
}

// genSubRspProgram generates sequences of sub rsp, N instructions.
func genSubRspProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		n := int(params.NextUint64()%5) + 1 // 1-5 allocations
		allocs := make([]int64, n)
		for i := range allocs {
			allocs[i] = int64((params.NextUint64()%32)+1) * 8 // 8-256, multiple of 8
		}
		return gopter.NewGenResult(&subRspProgram{allocations: allocs}, gopter.NoShrinker)
	}
}

// genAddRspProgram generates a sub rsp, N followed by add rsp, N.
func genAddRspProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		size := int64((params.NextUint64()%32)+1) * 8 // 8-256, multiple of 8
		return gopter.NewGenResult(&addRspProgram{size: size}, gopter.NoShrinker)
	}
}

// genAlignRspProgram generates and rsp, -N alignment sequences.
func genAlignRspProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		preAlloc := int64((params.NextUint64()%16)+1) * 8 // 8-128
		// alignment: 16, 32, or 64 bytes
		pows := []uint{4, 5, 6}
		alignPow := pows[params.NextUint64()%uint64(len(pows))]
		return gopter.NewGenResult(&alignRspProgram{preAlloc: preAlloc, alignPow: alignPow}, gopter.NoShrinker)
	}
}

// genAllocaProgram generates alloca-style sub rsp, reg sequences.
func genAllocaProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		// optional concrete pre-allocation (0 or 8-64)
		var preAlloc int64
		if params.NextUint64()%2 == 0 {
			preAlloc = int64((params.NextUint64()%8)+1) * 8
		}
		varRegs := []string{"rax", "rcx", "rdx", "rsi", "rdi"}
		varReg := varRegs[params.NextUint64()%uint64(len(varRegs))]
		return gopter.NewGenResult(&allocaProgram{preAlloc: preAlloc, varReg: varReg}, gopter.NoShrinker)
	}
}

// genFramePointerProgram generates frame pointer setup sequences.
func genFramePointerProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		hasFP := params.NextUint64()%2 == 0
		var frameSize int64
		if hasFP {
			frameSize = int64((params.NextUint64()%16)+1) * 8 // 8-128
		}
		return gopter.NewGenResult(&framePointerProgram{hasFramePointer: hasFP, frameSize: frameSize}, gopter.NoShrinker)
	}
}

// genFrameSizeProgram generates sequences to test frame size computation.
func genFrameSizeProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		n := int(params.NextUint64()%4) + 1 // 1-4 allocations
		allocs := make([]int64, n)
		for i := range allocs {
			allocs[i] = int64((params.NextUint64()%16)+1) * 8 // 8-128
		}
		return gopter.NewGenResult(&frameSizeProgram{allocations: allocs}, gopter.NoShrinker)
	}
}

// ============================================================================
// property checkers
// ============================================================================

// newAnalyzerForConvention creates an Analyzer for the given calling convention.
// panics on unsupported convention — this is a test-only helper.
func newAnalyzerForConvention(conv CallingConvention) Analyzer {
	a, err := NewAnalyzer(conv)
	if err != nil {
		panic("unsupported convention in test: " + err.Error())
	}
	return a
}

// checkEntryOffsetIsZero verifies that the rsp offset at the first instruction
// is always 0, regardless of what operations follow.
// requirement 12.20: rsp offset at function entry is 0.
func checkEntryOffsetIsZero(t *testing.T, prog *stackOpProgram, conv CallingConvention) bool {
	t.Helper()
	if len(prog.ops) == 0 {
		return true
	}
	a := newAnalyzerForConvention(conv)
	tracker := a.TrackStackPointer(prog.ops)

	firstAddr := prog.ops[0].Address
	off, ok := tracker.GetOffset(firstAddr)
	if !ok {
		t.Errorf("no offset recorded at entry address 0x%x", firstAddr)
		return false
	}
	concrete, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Errorf("entry offset must be ConcreteOffset, got %T", off)
		return false
	}
	if concrete.Value != 0 {
		t.Errorf("entry rsp offset: expected 0, got %d", concrete.Value)
		return false
	}
	return true
}

// checkPushPopBalance verifies that a balanced push/pop sequence returns rsp to 0.
// requirement 12.21: push decrements rsp by operand size, pop increments.
func checkPushPopBalance(t *testing.T, prog *pushPopProgram, conv CallingConvention) bool {
	t.Helper()
	// build: push r0, push r1, ..., pop r(n-1), ..., pop r0, ret
	insns := make([]*disasm.Instruction, 0, prog.depth*2+1)
	addr := disasm.Address(0x1000)

	for _, r := range prog.regs {
		insns = append(insns, buildInsn(addr, "push", reg(r, disasm.Size64)))
		addr++
	}
	// pop in reverse order
	for i := len(prog.regs) - 1; i >= 0; i-- {
		insns = append(insns, buildInsn(addr, "pop", reg(prog.regs[i], disasm.Size64)))
		addr++
	}
	retAddr := addr
	insns = append(insns, buildInsn(retAddr, "ret"))

	a := newAnalyzerForConvention(conv)
	tracker := a.TrackStackPointer(insns)

	// at ret: all pushes and pops cancel out, offset must be 0
	off, ok := tracker.GetOffset(retAddr)
	if !ok {
		t.Errorf("no offset at ret address 0x%x", retAddr)
		return false
	}
	concrete, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Errorf("offset at ret must be ConcreteOffset after balanced push/pop, got %T", off)
		return false
	}
	if concrete.Value != 0 {
		t.Errorf("balanced push/pop: expected rsp offset 0 at ret, got %d (depth=%d)", concrete.Value, prog.depth)
		return false
	}
	return true
}

// checkSubRspDecrement verifies that each sub rsp, N decrements the offset by exactly N.
// requirement 12.11: handle stack modifications (sub rsp).
func checkSubRspDecrement(t *testing.T, prog *subRspProgram, conv CallingConvention) bool {
	t.Helper()
	insns := make([]*disasm.Instruction, 0, len(prog.allocations)+1)
	addr := disasm.Address(0x1000)
	// record the address after each sub rsp for verification
	checkAddrs := make([]disasm.Address, len(prog.allocations))

	for i, n := range prog.allocations {
		insns = append(insns, buildInsn(addr, "sub", reg("rsp", disasm.Size64), imm(n, disasm.Size64)))
		addr += 4
		checkAddrs[i] = addr
		// nop to have an address to check after each sub
		insns = append(insns, buildInsn(addr, "nop"))
		addr++
	}
	insns = append(insns, buildInsn(addr, "ret"))

	a := newAnalyzerForConvention(conv)
	tracker := a.TrackStackPointer(insns)

	// verify cumulative offset after each sub rsp
	cumulative := int64(0)
	for i, checkAddr := range checkAddrs {
		cumulative -= prog.allocations[i]
		off, ok := tracker.GetOffset(checkAddr)
		if !ok {
			t.Errorf("no offset at 0x%x after sub rsp,%d", checkAddr, prog.allocations[i])
			return false
		}
		concrete, isConcrete := off.(ConcreteOffset)
		if !isConcrete {
			t.Errorf("offset after sub rsp,%d must be ConcreteOffset, got %T", prog.allocations[i], off)
			return false
		}
		if concrete.Value != cumulative {
			t.Errorf("after sub rsp,%d: expected offset %d, got %d", prog.allocations[i], cumulative, concrete.Value)
			return false
		}
	}
	return true
}

// checkAddRspIncrement verifies that add rsp, N increments the offset by exactly N.
// requirement 12.11: handle stack modifications (add rsp).
func checkAddRspIncrement(t *testing.T, prog *addRspProgram, conv CallingConvention) bool {
	t.Helper()
	// sub rsp, N then add rsp, N — net effect must be 0
	subAddr := disasm.Address(0x1000)
	nopAddr := disasm.Address(0x1004)
	addAddr := disasm.Address(0x1005)
	retAddr := disasm.Address(0x1009)

	insns := []*disasm.Instruction{
		buildInsn(subAddr, "sub", reg("rsp", disasm.Size64), imm(prog.size, disasm.Size64)),
		buildInsn(nopAddr, "nop"),
		buildInsn(addAddr, "add", reg("rsp", disasm.Size64), imm(prog.size, disasm.Size64)),
		buildInsn(retAddr, "ret"),
	}

	a := newAnalyzerForConvention(conv)
	tracker := a.TrackStackPointer(insns)

	// after sub rsp, N: offset must be -N
	offAfterSub, ok := tracker.GetOffset(nopAddr)
	if !ok {
		t.Errorf("no offset at nop after sub rsp,%d", prog.size)
		return false
	}
	cSub, isConcrete := offAfterSub.(ConcreteOffset)
	if !isConcrete {
		t.Errorf("offset after sub rsp must be ConcreteOffset, got %T", offAfterSub)
		return false
	}
	if cSub.Value != -prog.size {
		t.Errorf("after sub rsp,%d: expected -%d, got %d", prog.size, prog.size, cSub.Value)
		return false
	}

	// after add rsp, N: offset must be 0
	offAfterAdd, ok := tracker.GetOffset(retAddr)
	if !ok {
		t.Errorf("no offset at ret after add rsp,%d", prog.size)
		return false
	}
	cAdd, isConcrete := offAfterAdd.(ConcreteOffset)
	if !isConcrete {
		t.Errorf("offset after add rsp must be ConcreteOffset, got %T", offAfterAdd)
		return false
	}
	if cAdd.Value != 0 {
		t.Errorf("after sub+add rsp,%d: expected 0, got %d", prog.size, cAdd.Value)
		return false
	}
	return true
}

// checkAlignRsp verifies that and rsp, -N aligns the offset down to N-byte boundary.
// requirement 12.12: handle stack alignment (and rsp, -16).
func checkAlignRsp(t *testing.T, prog *alignRspProgram, conv CallingConvention) bool {
	t.Helper()
	alignMask := -int64(1 << prog.alignPow) // e.g., -16 = 0xFFFFFFFFFFFFFFF0

	subAddr := disasm.Address(0x1000)
	andAddr := disasm.Address(0x1004)
	nopAddr := disasm.Address(0x1008)

	insns := []*disasm.Instruction{
		buildInsn(subAddr, "sub", reg("rsp", disasm.Size64), imm(prog.preAlloc, disasm.Size64)),
		buildInsn(andAddr, "and", reg("rsp", disasm.Size64), imm(alignMask, disasm.Size64)),
		buildInsn(nopAddr, "nop"),
	}

	a := newAnalyzerForConvention(conv)
	tracker := a.TrackStackPointer(insns)

	// compute expected aligned offset
	offsetAfterSub := -prog.preAlloc
	expectedAligned := offsetAfterSub & alignMask

	off, ok := tracker.GetOffset(nopAddr)
	if !ok {
		t.Errorf("no offset at nop after and rsp,%d", alignMask)
		return false
	}
	concrete, isConcrete := off.(ConcreteOffset)
	if !isConcrete {
		t.Errorf("offset after and rsp must be ConcreteOffset, got %T", off)
		return false
	}
	if concrete.Value != expectedAligned {
		t.Errorf("and rsp,%d after sub rsp,%d: expected %d, got %d",
			alignMask, prog.preAlloc, expectedAligned, concrete.Value)
		return false
	}
	return true
}

// checkAllocaSymbolic verifies that sub rsp, reg produces a SymbolicOffset.
// requirement 12.13: handle dynamic allocation (sub rsp, rax) with symbolic component.
func checkAllocaSymbolic(t *testing.T, prog *allocaProgram, conv CallingConvention) bool {
	t.Helper()
	insns := make([]*disasm.Instruction, 0, 4)
	addr := disasm.Address(0x1000)

	// optional concrete pre-allocation
	if prog.preAlloc > 0 {
		insns = append(insns, buildInsn(addr, "sub", reg("rsp", disasm.Size64), imm(prog.preAlloc, disasm.Size64)))
		addr += 4
	}

	// dynamic allocation: sub rsp, varReg
	allocaAddr := addr
	insns = append(insns, buildInsn(allocaAddr, "sub", reg("rsp", disasm.Size64), reg(prog.varReg, disasm.Size64)))
	addr += 3
	nopAddr := addr
	insns = append(insns, buildInsn(nopAddr, "nop"))

	a := newAnalyzerForConvention(conv)
	tracker := a.TrackStackPointer(insns)

	// after sub rsp, reg: offset must be SymbolicOffset
	off, ok := tracker.GetOffset(nopAddr)
	if !ok {
		t.Errorf("no offset at nop after sub rsp,%s", prog.varReg)
		return false
	}
	sym, isSym := off.(SymbolicOffset)
	if !isSym {
		t.Errorf("sub rsp,%s must produce SymbolicOffset, got %T", prog.varReg, off)
		return false
	}
	// base must equal the concrete pre-allocation (negated)
	expectedBase := -prog.preAlloc
	if sym.Base != expectedBase {
		t.Errorf("symbolic offset base: expected %d, got %d (preAlloc=%d)", expectedBase, sym.Base, prog.preAlloc)
		return false
	}
	// var name must match the register used
	expectedVarName := canonicalizeRegister(prog.varReg)
	if sym.VarName != expectedVarName {
		t.Errorf("symbolic offset var name: expected %q, got %q", expectedVarName, sym.VarName)
		return false
	}
	return true
}

// checkFramePointerDetection verifies that HasFramePointer() correctly reflects
// whether push rbp; mov rbp, rsp is present in the instruction sequence.
// requirement 12.18: detect frame pointer setup (push rbp; mov rbp, rsp).
func checkFramePointerDetection(t *testing.T, prog *framePointerProgram, conv CallingConvention) bool {
	t.Helper()
	insns := make([]*disasm.Instruction, 0, 6)
	addr := disasm.Address(0x1000)

	if prog.hasFramePointer {
		insns = append(insns, buildInsn(addr, "push", reg("rbp", disasm.Size64)))
		addr++
		insns = append(insns, buildInsn(addr, "mov", reg("rbp", disasm.Size64), reg("rsp", disasm.Size64)))
		addr += 3
		if prog.frameSize > 0 {
			insns = append(insns, buildInsn(addr, "sub", reg("rsp", disasm.Size64), imm(prog.frameSize, disasm.Size64)))
			addr += 4
		}
	} else {
		// leaf function: just sub rsp, 8 (no frame pointer)
		insns = append(insns, buildInsn(addr, "sub", reg("rsp", disasm.Size64), imm(8, disasm.Size64)))
		addr += 4
	}
	insns = append(insns, buildInsn(addr, "ret"))

	a := newAnalyzerForConvention(conv)
	tracker := a.TrackStackPointer(insns)

	if tracker.HasFramePointer() != prog.hasFramePointer {
		t.Errorf("HasFramePointer(): expected %v, got %v (hasFramePointer=%v)",
			prog.hasFramePointer, tracker.HasFramePointer(), prog.hasFramePointer)
		return false
	}

	// when frame pointer is present, verify the recorded rsp offset at setup point
	if prog.hasFramePointer {
		fpRSPOff, ok := tracker.FramePointerRSPOffset()
		if !ok {
			t.Error("FramePointerRSPOffset() returned false despite HasFramePointer() == true")
			return false
		}
		// after push rbp: rsp offset = -8
		if fpRSPOff != -8 {
			t.Errorf("frame pointer rsp offset: expected -8 (after push rbp), got %d", fpRSPOff)
			return false
		}
	}
	return true
}

// checkFrameSize verifies that StackFrame.Size equals the absolute value of the
// minimum rsp offset observed during the function.
// requirement 12.15: compute stack frame size.
func checkFrameSize(t *testing.T, prog *frameSizeProgram, conv CallingConvention) bool {
	t.Helper()
	insns := make([]*disasm.Instruction, 0, len(prog.allocations)*2+1)
	addr := disasm.Address(0x1000)

	// build: sub rsp, a0; sub rsp, a1; ...; add rsp, a(n-1); ...; add rsp, a0; ret
	for _, n := range prog.allocations {
		insns = append(insns, buildInsn(addr, "sub", reg("rsp", disasm.Size64), imm(n, disasm.Size64)))
		addr += 4
	}
	// add rsp back in reverse to restore stack
	for i := len(prog.allocations) - 1; i >= 0; i-- {
		insns = append(insns, buildInsn(addr, "add", reg("rsp", disasm.Size64), imm(prog.allocations[i], disasm.Size64)))
		addr += 4
	}
	insns = append(insns, buildInsn(addr, "ret"))

	// compute expected frame size: sum of all allocations
	var expectedSize int64
	for _, n := range prog.allocations {
		expectedSize += n
	}

	a := newAnalyzerForConvention(conv)
	frame := a.AnalyzeStackFrame(insns)

	if frame.Size != expectedSize {
		t.Errorf("frame size: expected %d (sum of allocations), got %d (allocations=%v)",
			expectedSize, frame.Size, prog.allocations)
		return false
	}
	return true
}
