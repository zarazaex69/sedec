package cfg

import "github.com/zarazaex69/sedec/pkg/disasm"

// loopInstruction represents a single instruction in a test loop.
type loopInstruction struct {
	addr    uint64
	mnem    string
	length  int
	target  uint64
	comment string
}

// buildLoopInstructions constructs instruction slice from compact representation.
func buildLoopInstructions(specs []loopInstruction) []*disasm.Instruction {
	result := make([]*disasm.Instruction, 0, len(specs))
	for _, spec := range specs {
		instr := &disasm.Instruction{
			Address:  disasm.Address(spec.addr),
			Mnemonic: spec.mnem,
			Length:   spec.length,
		}
		// add operand if target is specified
		if spec.target != 0 {
			instr.Operands = []disasm.Operand{
				//nolint:gosec // G115: safe conversion - target is validated test data
				disasm.ImmediateOperand{Value: int64(spec.target), Size: disasm.Size32},
			}
		}
		result = append(result, instr)
	}
	return result
}

// createNestedLoopInstructions creates instruction sequence for nested loop testing.
// outer loop header (0x1000-0x1006)
// inner loop header (0x1008-0x100b)
// inner loop body (0x100d-0x1010)
// outer loop body (0x1012-0x1014)
// exit (0x1016)
//
//nolint:dupl // test helper functions have similar structure by design
func createNestedLoopInstructions() []*disasm.Instruction {
	return buildLoopInstructions([]loopInstruction{
		{addr: 0x1000, mnem: "mov", length: 3, comment: "entry"},
		{addr: 0x1003, mnem: "cmp", length: 3, comment: "outer loop header"},
		{addr: 0x1006, mnem: "jge", length: 2, target: 0x1016, comment: "exit outer"},
		{addr: 0x1008, mnem: "cmp", length: 3, comment: "inner loop header"},
		{addr: 0x100b, mnem: "jge", length: 2, target: 0x1012, comment: "exit inner"},
		{addr: 0x100d, mnem: "add", length: 3, comment: "inner loop body"},
		{addr: 0x1010, mnem: "jmp", length: 2, target: 0x1008, comment: "back to inner"},
		{addr: 0x1012, mnem: "inc", length: 2, comment: "outer loop body"},
		{addr: 0x1014, mnem: "jmp", length: 2, target: 0x1003, comment: "back to outer"},
		{addr: 0x1016, mnem: "ret", length: 1, comment: "exit"},
	})
}

// createLoopWithBreakContinueInstructions creates instruction sequence for loop with break/continue.
// init (0x1000)
// loop condition (0x1003-0x1006)
// continue check (0x1008-0x100b)
// break check (0x100d-0x1010)
// loop body (0x1012-0x1015)
// exit (0x1025)
//
//nolint:dupl // test helper functions have similar structure by design
func createLoopWithBreakContinueInstructions() []*disasm.Instruction {
	return buildLoopInstructions([]loopInstruction{
		{addr: 0x1000, mnem: "mov", length: 3, comment: "init"},
		{addr: 0x1003, mnem: "cmp", length: 3, comment: "loop condition"},
		{addr: 0x1006, mnem: "je", length: 2, target: 0x1025, comment: "exit loop"},
		{addr: 0x1008, mnem: "test", length: 3, comment: "continue check"},
		{addr: 0x100b, mnem: "jne", length: 2, target: 0x1003, comment: "continue"},
		{addr: 0x100d, mnem: "test", length: 3, comment: "break check"},
		{addr: 0x1010, mnem: "jne", length: 2, target: 0x1025, comment: "break"},
		{addr: 0x1012, mnem: "add", length: 3, comment: "loop body"},
		{addr: 0x1015, mnem: "jmp", length: 2, target: 0x1003, comment: "back to header"},
		{addr: 0x1025, mnem: "ret", length: 1, comment: "exit"},
	})
}

// createLoopWithMultipleExitsInstructions creates instruction sequence for loop with multiple exits.
// init (0x1000)
// condition 1 (0x1003-0x1006)
// condition 2 (0x1008-0x100b)
// condition 3 (0x100d-0x1010)
// body (0x1012-0x1015)
// common exit (0x1020)
//
//nolint:dupl // test helper functions have similar structure by design
func createLoopWithMultipleExitsInstructions() []*disasm.Instruction {
	return buildLoopInstructions([]loopInstruction{
		{addr: 0x1000, mnem: "xor", length: 3, comment: "init"},
		{addr: 0x1003, mnem: "cmp", length: 3, comment: "condition 1"},
		{addr: 0x1006, mnem: "je", length: 2, target: 0x1020, comment: "exit 1"},
		{addr: 0x1008, mnem: "test", length: 3, comment: "condition 2"},
		{addr: 0x100b, mnem: "js", length: 2, target: 0x1020, comment: "exit 2"},
		{addr: 0x100d, mnem: "cmp", length: 3, comment: "condition 3"},
		{addr: 0x1010, mnem: "jg", length: 2, target: 0x1020, comment: "exit 3"},
		{addr: 0x1012, mnem: "inc", length: 3, comment: "body"},
		{addr: 0x1015, mnem: "jmp", length: 2, target: 0x1003, comment: "back edge"},
		{addr: 0x1020, mnem: "ret", length: 1, comment: "exit"},
	})
}

// createSequentialLoopsInstructions creates instruction sequence for two sequential loops.
// entry (0x1000-0x1003)
// first loop header (0x1005-0x1008)
// first loop body (0x100a-0x100d)
// second loop header (0x1010-0x1013)
// second loop body (0x1015-0x1018)
// exit (0x101a)
func createSequentialLoopsInstructions() []*disasm.Instruction {
	return []*disasm.Instruction{
		// block 0: entry
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "jmp", Length: 2, Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005}}},
		// block 1: first loop header
		{Address: 0x1005, Mnemonic: "cmp", Length: 3},
		{Address: 0x1008, Mnemonic: "jg", Length: 2, Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1010}}},
		// block 2: first loop body
		{Address: 0x100a, Mnemonic: "add", Length: 3},
		{Address: 0x100d, Mnemonic: "jmp", Length: 2, Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005}}},
		// block 3: second loop header
		{Address: 0x1010, Mnemonic: "cmp", Length: 3},
		{Address: 0x1013, Mnemonic: "jg", Length: 2, Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x101a}}},
		// block 4: second loop body
		{Address: 0x1015, Mnemonic: "sub", Length: 3},
		{Address: 0x1018, Mnemonic: "jmp", Length: 2, Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1010}}},
		// block 5: exit
		{Address: 0x101a, Mnemonic: "ret", Length: 1},
	}
}
