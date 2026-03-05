package cfg

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestCFGBuilder_DoWhileLoop tests CFG construction for do-while loop pattern
// do-while executes body at least once before checking condition
func TestCFGBuilder_DoWhileLoop(t *testing.T) {
	// create instruction sequence with do-while loop
	// 0x1000: mov rcx, 10    (init)
	// 0x1003: dec rcx        (loop body - executes first)
	// 0x1006: cmp rcx, 0     (condition check)
	// 0x1009: jne 0x1003     (back edge if not zero)
	// 0x100b: ret            (exit)
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "dec", Length: 3},
		{Address: 0x1006, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1009,
			Mnemonic: "jne",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32},
			},
		},
		{Address: 0x100b, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify 3 basic blocks (init, body+condition, exit)
	if cfg.BlockCount() != 3 {
		t.Errorf("expected 3 basic blocks for do-while, got %d", cfg.BlockCount())
	}

	// verify back edge exists (condition -> body)
	hasBackEdge := false
	for _, edge := range cfg.Edges {
		fromBlock := cfg.Blocks[edge.From]
		toBlock := cfg.Blocks[edge.To]
		// back edge: target address < source end address
		if toBlock.StartAddress < fromBlock.EndAddress && edge.Type == EdgeTypeConditional {
			hasBackEdge = true
			break
		}
	}
	if !hasBackEdge {
		t.Error("expected back edge for do-while loop, but none found")
	}

	// verify loop body block has 2 successors (back edge and exit)
	bodyBlockFound := false
	for _, block := range cfg.Blocks {
		if block.StartAddress == 0x1003 {
			bodyBlockFound = true
			if len(block.Successors) != 2 {
				t.Errorf("expected 2 successors for do-while body block, got %d", len(block.Successors))
			}
		}
	}
	if !bodyBlockFound {
		t.Error("do-while body block not found")
	}
}

// TestCFGBuilder_ForLoop tests CFG construction for for loop pattern
// for loop has init, condition, increment, and body
func TestCFGBuilder_ForLoop(t *testing.T) {
	// create instruction sequence with for loop
	// 0x1000: xor rcx, rcx   (init: i = 0)
	// 0x1003: cmp rcx, 10    (condition: i < 10)
	// 0x1006: jge 0x1013     (exit if i >= 10)
	// 0x1008: add rax, rcx   (body: sum += i)
	// 0x100b: inc rcx        (increment: i++)
	// 0x100e: jmp 0x1003     (back to condition)
	// 0x1013: ret            (exit)
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "xor", Length: 3},
		{Address: 0x1003, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1006,
			Mnemonic: "jge",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1013, Size: disasm.Size32},
			},
		},
		{Address: 0x1008, Mnemonic: "add", Length: 3},
		{Address: 0x100b, Mnemonic: "inc", Length: 3},
		{
			Address:  0x100e,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32},
			},
		},
		{Address: 0x1013, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify 4 basic blocks (init, condition, body+increment, exit)
	if cfg.BlockCount() != 4 {
		t.Errorf("expected 4 basic blocks for for loop, got %d", cfg.BlockCount())
	}

	// verify back edge from increment to condition
	hasBackEdge := false
	for _, edge := range cfg.Edges {
		fromBlock := cfg.Blocks[edge.From]
		toBlock := cfg.Blocks[edge.To]
		if toBlock.StartAddress == 0x1003 && fromBlock.EndAddress == 0x100e {
			hasBackEdge = true
			if edge.Type != EdgeTypeUnconditional {
				t.Errorf("expected unconditional back edge, got %v", edge.Type)
			}
		}
	}
	if !hasBackEdge {
		t.Error("expected back edge from increment to condition in for loop")
	}

	// verify condition block has 2 successors (body and exit)
	conditionBlock := findBlockByStartAddress(cfg, 0x1003)
	if conditionBlock == nil {
		t.Fatal("condition block not found")
	}
	if len(conditionBlock.Successors) != 2 {
		t.Errorf("expected 2 successors for condition block, got %d", len(conditionBlock.Successors))
	}
}

// TestCFGBuilder_NestedLoopsComplex tests deeply nested loops with multiple levels
func TestCFGBuilder_NestedLoopsComplex(t *testing.T) {
	// create instruction sequence with 3-level nested loops
	// outer loop -> middle loop -> inner loop
	instructions := []*disasm.Instruction{
		// outer loop init and header
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1006,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1040, Size: disasm.Size32},
			},
		},
		// middle loop init and header
		{Address: 0x1008, Mnemonic: "mov", Length: 3},
		{Address: 0x100b, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x100e,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1030, Size: disasm.Size32},
			},
		},
		// inner loop init and header
		{Address: 0x1010, Mnemonic: "mov", Length: 3},
		{Address: 0x1013, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1016,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1020, Size: disasm.Size32},
			},
		},
		// inner loop body and back edge
		{Address: 0x1018, Mnemonic: "add", Length: 3},
		{
			Address:  0x101b,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1013, Size: disasm.Size32},
			},
		},
		// middle loop body and back edge
		{Address: 0x1020, Mnemonic: "sub", Length: 3},
		{
			Address:  0x1023,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x100b, Size: disasm.Size32},
			},
		},
		// outer loop body and back edge
		{Address: 0x1030, Mnemonic: "dec", Length: 3},
		{
			Address:  0x1033,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32},
			},
		},
		// exit
		{Address: 0x1040, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify sufficient blocks for 3-level nesting
	if cfg.BlockCount() < 9 {
		t.Errorf("expected at least 9 basic blocks for 3-level nested loops, got %d", cfg.BlockCount())
	}

	// count back edges (should have 3 for 3 nested loops)
	backEdgeCount := 0
	for _, edge := range cfg.Edges {
		fromBlock := cfg.Blocks[edge.From]
		toBlock := cfg.Blocks[edge.To]
		if toBlock.StartAddress < fromBlock.EndAddress {
			backEdgeCount++
		}
	}
	if backEdgeCount != 3 {
		t.Errorf("expected exactly 3 back edges for 3-level nested loops, got %d", backEdgeCount)
	}

	// verify each loop header has correct number of predecessors
	// inner loop header (0x1013) should have 2 predecessors: entry and back edge
	innerHeader := findBlockByStartAddress(cfg, 0x1013)
	if innerHeader != nil && len(innerHeader.Predecessors) != 2 {
		t.Errorf("expected 2 predecessors for inner loop header, got %d", len(innerHeader.Predecessors))
	}
}

// TestCFGBuilder_SwitchStatement tests CFG construction for switch-like control flow
// switch statements compile to multiple conditional jumps or jump tables
func TestCFGBuilder_SwitchStatement(t *testing.T) {
	// create instruction sequence simulating switch with 4 cases
	// switch (x) {
	//   case 0: ...
	//   case 1: ...
	//   case 2: ...
	//   default: ...
	// }
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3}, // load switch value
		{Address: 0x1003, Mnemonic: "cmp", Length: 3}, // compare with 0
		{
			Address:  0x1006,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1020, Size: disasm.Size32}, // case 0
			},
		},
		{Address: 0x1008, Mnemonic: "cmp", Length: 3}, // compare with 1
		{
			Address:  0x100b,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1028, Size: disasm.Size32}, // case 1
			},
		},
		{Address: 0x100d, Mnemonic: "cmp", Length: 3}, // compare with 2
		{
			Address:  0x1010,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1030, Size: disasm.Size32}, // case 2
			},
		},
		{Address: 0x1012, Mnemonic: "mov", Length: 3}, // default case
		{
			Address:  0x1015,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1038, Size: disasm.Size32}, // exit
			},
		},
		{Address: 0x1020, Mnemonic: "add", Length: 3}, // case 0 body
		{
			Address:  0x1023,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1038, Size: disasm.Size32},
			},
		},
		{Address: 0x1028, Mnemonic: "sub", Length: 3}, // case 1 body
		{
			Address:  0x102b,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1038, Size: disasm.Size32},
			},
		},
		{Address: 0x1030, Mnemonic: "mul", Length: 3}, // case 2 body
		{
			Address:  0x1033,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1038, Size: disasm.Size32},
			},
		},
		{Address: 0x1038, Mnemonic: "ret", Length: 1}, // exit
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify sufficient blocks for switch structure
	// should have: entry comparisons, 4 case bodies, exit
	if cfg.BlockCount() < 8 {
		t.Errorf("expected at least 8 basic blocks for switch, got %d", cfg.BlockCount())
	}

	// verify exit block has multiple predecessors (all cases converge)
	exitBlock := findBlockByStartAddress(cfg, 0x1038)
	if exitBlock == nil {
		t.Fatal("exit block not found")
	}
	if len(exitBlock.Predecessors) < 4 {
		t.Errorf("expected at least 4 predecessors for exit block (all cases), got %d", len(exitBlock.Predecessors))
	}

	// verify each case block has exactly 1 successor (jump to exit)
	caseAddresses := []disasm.Address{0x1020, 0x1028, 0x1030}
	for _, addr := range caseAddresses {
		caseBlock := findBlockByStartAddress(cfg, addr)
		if caseBlock != nil && len(caseBlock.Successors) != 1 {
			t.Errorf("expected 1 successor for case block at 0x%x, got %d", addr, len(caseBlock.Successors))
		}
	}
}

// TestCFGBuilder_LoopWithBreakContinue tests loop with break and continue statements
func TestCFGBuilder_LoopWithBreakContinue(t *testing.T) {
	// create instruction sequence with loop containing break and continue
	// while (condition) {
	//   if (x) continue;
	//   if (y) break;
	//   body;
	// }
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3}, // init
		{Address: 0x1003, Mnemonic: "cmp", Length: 3}, // loop condition
		{
			Address:  0x1006,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1025, Size: disasm.Size32}, // exit loop
			},
		},
		{Address: 0x1008, Mnemonic: "test", Length: 3}, // check continue condition
		{
			Address:  0x100b,
			Mnemonic: "jne",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32}, // continue (back to header)
			},
		},
		{Address: 0x100d, Mnemonic: "test", Length: 3}, // check break condition
		{
			Address:  0x1010,
			Mnemonic: "jne",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1025, Size: disasm.Size32}, // break (exit loop)
			},
		},
		{Address: 0x1012, Mnemonic: "add", Length: 3}, // loop body
		{
			Address:  0x1015,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32}, // back to header
			},
		},
		{Address: 0x1025, Mnemonic: "ret", Length: 1}, // exit
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify loop header has multiple predecessors (entry, continue, normal back edge)
	loopHeader := findBlockByStartAddress(cfg, 0x1003)
	if loopHeader == nil {
		t.Fatal("loop header not found")
	}
	if len(loopHeader.Predecessors) < 3 {
		t.Errorf("expected at least 3 predecessors for loop header (entry, continue, back edge), got %d", len(loopHeader.Predecessors))
	}

	// verify exit block has multiple predecessors (normal exit, break)
	exitBlock := findBlockByStartAddress(cfg, 0x1025)
	if exitBlock == nil {
		t.Fatal("exit block not found")
	}
	if len(exitBlock.Predecessors) < 2 {
		t.Errorf("expected at least 2 predecessors for exit (normal exit, break), got %d", len(exitBlock.Predecessors))
	}

	// verify back edges exist
	backEdgeCount := 0
	for _, edge := range cfg.Edges {
		fromBlock := cfg.Blocks[edge.From]
		toBlock := cfg.Blocks[edge.To]
		if toBlock.StartAddress < fromBlock.EndAddress {
			backEdgeCount++
		}
	}
	if backEdgeCount < 2 {
		t.Errorf("expected at least 2 back edges (continue and normal), got %d", backEdgeCount)
	}
}

// TestCFGBuilder_LoopWithMultipleExits tests loop with multiple exit points
func TestCFGBuilder_LoopWithMultipleExits(t *testing.T) {
	// create loop with multiple exit conditions
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "xor", Length: 3}, // init
		{Address: 0x1003, Mnemonic: "cmp", Length: 3}, // condition 1
		{
			Address:  0x1006,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1020, Size: disasm.Size32}, // exit 1
			},
		},
		{Address: 0x1008, Mnemonic: "test", Length: 3}, // condition 2
		{
			Address:  0x100b,
			Mnemonic: "js",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1020, Size: disasm.Size32}, // exit 2
			},
		},
		{Address: 0x100d, Mnemonic: "cmp", Length: 3}, // condition 3
		{
			Address:  0x1010,
			Mnemonic: "jg",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1020, Size: disasm.Size32}, // exit 3
			},
		},
		{Address: 0x1012, Mnemonic: "inc", Length: 3}, // body
		{
			Address:  0x1015,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32}, // back edge
			},
		},
		{Address: 0x1020, Mnemonic: "ret", Length: 1}, // common exit
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify exit block has multiple predecessors (all exit paths)
	exitBlock := findBlockByStartAddress(cfg, 0x1020)
	if exitBlock == nil {
		t.Fatal("exit block not found")
	}
	if len(exitBlock.Predecessors) < 3 {
		t.Errorf("expected at least 3 predecessors for exit (multiple exit conditions), got %d", len(exitBlock.Predecessors))
	}

	// verify loop structure exists
	hasBackEdge := false
	for _, edge := range cfg.Edges {
		fromBlock := cfg.Blocks[edge.From]
		toBlock := cfg.Blocks[edge.To]
		if toBlock.StartAddress < fromBlock.EndAddress {
			hasBackEdge = true
			break
		}
	}
	if !hasBackEdge {
		t.Error("expected back edge for loop")
	}
}

// TestCFGBuilder_IrreducibleControlFlow tests handling of irreducible control flow
// irreducible CFG has multiple entry points to a loop (cannot be reduced to structured control flow)
func TestCFGBuilder_IrreducibleControlFlow(t *testing.T) {
	// create irreducible control flow with two entries to loop
	// this pattern can occur with goto statements or optimized code
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1003,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x100d, Size: disasm.Size32}, // jump to middle of loop
			},
		},
		{Address: 0x1005, Mnemonic: "mov", Length: 3}, // first entry to loop
		{Address: 0x1008, Mnemonic: "add", Length: 3},
		{
			Address:  0x100b,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1010, Size: disasm.Size32},
			},
		},
		{Address: 0x100d, Mnemonic: "sub", Length: 3}, // second entry to loop
		{Address: 0x1010, Mnemonic: "dec", Length: 3}, // loop body (common part)
		{Address: 0x1013, Mnemonic: "test", Length: 3},
		{
			Address:  0x1016,
			Mnemonic: "jne",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1005, Size: disasm.Size32}, // back edge to first entry
			},
		},
		{Address: 0x1018, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify CFG is constructed without errors
	if cfg.BlockCount() < 5 {
		t.Errorf("expected at least 5 basic blocks for irreducible flow, got %d", cfg.BlockCount())
	}

	// verify loop body block has multiple predecessors from different paths
	loopBodyBlock := findBlockByStartAddress(cfg, 0x1010)
	if loopBodyBlock != nil && len(loopBodyBlock.Predecessors) < 2 {
		t.Errorf("expected at least 2 predecessors for loop body (multiple entries), got %d", len(loopBodyBlock.Predecessors))
	}

	// verify back edge exists
	hasBackEdge := false
	for _, edge := range cfg.Edges {
		fromBlock := cfg.Blocks[edge.From]
		toBlock := cfg.Blocks[edge.To]
		if toBlock.StartAddress < fromBlock.EndAddress {
			hasBackEdge = true
			break
		}
	}
	if !hasBackEdge {
		t.Error("expected back edge in irreducible control flow")
	}
}

// TestCFGBuilder_LoopWithNestedIfElse tests loop containing nested if-else
func TestCFGBuilder_LoopWithNestedIfElse(t *testing.T) {
	// create loop with nested if-else inside body
	// while (cond1) {
	//   if (cond2) {
	//     if (cond3) { ... } else { ... }
	//   } else { ... }
	// }
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3}, // init
		{Address: 0x1003, Mnemonic: "cmp", Length: 3}, // loop condition
		{
			Address:  0x1006,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1040, Size: disasm.Size32}, // exit loop
			},
		},
		{Address: 0x1008, Mnemonic: "test", Length: 3}, // outer if condition
		{
			Address:  0x100b,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1030, Size: disasm.Size32}, // outer else
			},
		},
		{Address: 0x100d, Mnemonic: "cmp", Length: 3}, // inner if condition
		{
			Address:  0x1010,
			Mnemonic: "jne",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1020, Size: disasm.Size32}, // inner else
			},
		},
		{Address: 0x1012, Mnemonic: "add", Length: 3}, // inner then
		{
			Address:  0x1015,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1028, Size: disasm.Size32}, // skip inner else
			},
		},
		{Address: 0x1020, Mnemonic: "sub", Length: 3}, // inner else
		{
			Address:  0x1023,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1028, Size: disasm.Size32},
			},
		},
		{Address: 0x1028, Mnemonic: "inc", Length: 3}, // after inner if-else
		{
			Address:  0x102b,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1038, Size: disasm.Size32}, // skip outer else
			},
		},
		{Address: 0x1030, Mnemonic: "dec", Length: 3}, // outer else
		{Address: 0x1038, Mnemonic: "nop", Length: 1}, // merge point
		{
			Address:  0x1039,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32}, // back to loop header
			},
		},
		{Address: 0x1040, Mnemonic: "ret", Length: 1}, // exit
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify complex structure with sufficient blocks
	if cfg.BlockCount() < 10 {
		t.Errorf("expected at least 10 basic blocks for loop with nested if-else, got %d", cfg.BlockCount())
	}

	// verify merge point exists and has predecessors
	mergeBlock := findBlockByStartAddress(cfg, 0x1038)
	if mergeBlock == nil {
		t.Error("merge point block not found")
	} else if len(mergeBlock.Predecessors) == 0 {
		t.Error("merge point has no predecessors")
	}

	// verify back edge exists
	hasBackEdge := false
	for _, edge := range cfg.Edges {
		fromBlock := cfg.Blocks[edge.From]
		toBlock := cfg.Blocks[edge.To]
		if toBlock.StartAddress == 0x1003 && fromBlock.EndAddress > 0x1003 {
			hasBackEdge = true
			break
		}
	}
	if !hasBackEdge {
		t.Error("expected back edge to loop header")
	}
}

// TestCFGBuilder_InfiniteLoop tests handling of infinite loop (no exit condition)
func TestCFGBuilder_InfiniteLoop(t *testing.T) {
	// create infinite loop: while(true) { ... }
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3}, // init
		{Address: 0x1003, Mnemonic: "add", Length: 3}, // loop body
		{Address: 0x1006, Mnemonic: "sub", Length: 3},
		{
			Address:  0x1009,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32}, // unconditional back edge
			},
		},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify 2 basic blocks (init, loop body)
	if cfg.BlockCount() != 2 {
		t.Errorf("expected 2 basic blocks for infinite loop, got %d", cfg.BlockCount())
	}

	// verify no exit blocks (infinite loop has no return)
	if len(cfg.Exits) != 0 {
		t.Errorf("expected 0 exit blocks for infinite loop, got %d", len(cfg.Exits))
	}

	// verify unconditional back edge exists
	hasUnconditionalBackEdge := false
	for _, edge := range cfg.Edges {
		fromBlock := cfg.Blocks[edge.From]
		toBlock := cfg.Blocks[edge.To]
		if toBlock.StartAddress < fromBlock.EndAddress && edge.Type == EdgeTypeUnconditional {
			hasUnconditionalBackEdge = true
			break
		}
	}
	if !hasUnconditionalBackEdge {
		t.Error("expected unconditional back edge for infinite loop")
	}

	// verify loop body has exactly 1 successor (back to itself)
	loopBody := findBlockByStartAddress(cfg, 0x1003)
	if loopBody != nil && len(loopBody.Successors) != 1 {
		t.Errorf("expected 1 successor for infinite loop body, got %d", len(loopBody.Successors))
	}
}

// TestCFGBuilder_AllConditionalBranches tests all x86_64 conditional branch types
func TestCFGBuilder_AllConditionalBranches(t *testing.T) {
	// test various conditional branch mnemonics
	conditionalBranches := []string{
		"je", "jz", "jne", "jnz",
		"jg", "jnle", "jge", "jnl",
		"jl", "jnge", "jle", "jng",
		"ja", "jnbe", "jae", "jnb", "jnc",
		"jb", "jnae", "jc", "jbe", "jna",
		"jo", "jno", "js", "jns",
		"jp", "jpe", "jnp", "jpo",
	}

	for _, mnemonic := range conditionalBranches {
		t.Run(mnemonic, func(t *testing.T) {
			instructions := []*disasm.Instruction{
				{Address: 0x1000, Mnemonic: "cmp", Length: 3},
				{
					Address:  0x1003,
					Mnemonic: mnemonic,
					Length:   2,
					Operands: []disasm.Operand{
						disasm.ImmediateOperand{Value: 0x1008, Size: disasm.Size32},
					},
				},
				{Address: 0x1005, Mnemonic: "mov", Length: 3}, // fall-through
				{Address: 0x1008, Mnemonic: "ret", Length: 1}, // target
			}

			builder := NewCFGBuilder()
			cfg, err := builder.Build(instructions)
			if err != nil {
				t.Fatalf("failed to build cfg for %s: %v", mnemonic, err)
			}

			// verify conditional branch creates 2 successors
			entryBlock, exists := cfg.GetBlock(cfg.Entry)
			if !exists {
				t.Fatal("entry block not found")
			}
			if len(entryBlock.Successors) != 2 {
				t.Errorf("expected 2 successors for %s, got %d", mnemonic, len(entryBlock.Successors))
			}

			// verify one conditional edge and one fallthrough edge
			hasConditional := false
			hasFallthrough := false
			for _, edge := range cfg.Edges {
				if edge.From == cfg.Entry {
					if edge.Type == EdgeTypeConditional {
						hasConditional = true
					}
					if edge.Type == EdgeTypeFallthrough {
						hasFallthrough = true
					}
				}
			}
			if !hasConditional {
				t.Errorf("expected conditional edge for %s", mnemonic)
			}
			if !hasFallthrough {
				t.Errorf("expected fallthrough edge for %s", mnemonic)
			}
		})
	}
}

// TestCFGBuilder_BlockAddressRanges tests that block address ranges are correct
func TestCFGBuilder_BlockAddressRanges(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "push", Length: 1},
		{Address: 0x1001, Mnemonic: "mov", Length: 5},
		{Address: 0x1006, Mnemonic: "add", Length: 3},
		{
			Address:  0x1009,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1010, Size: disasm.Size32},
			},
		},
		{Address: 0x100b, Mnemonic: "sub", Length: 3},
		{Address: 0x100e, Mnemonic: "nop", Length: 2},
		{Address: 0x1010, Mnemonic: "pop", Length: 1},
		{Address: 0x1011, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify all blocks have valid address ranges
	for _, block := range cfg.Blocks {
		if block.StartAddress > block.EndAddress {
			t.Errorf("block %d has invalid range: start=0x%x > end=0x%x",
				block.ID, block.StartAddress, block.EndAddress)
		}

		// verify start address matches first instruction
		if len(block.Instructions) > 0 {
			firstInstr := block.Instructions[0]
			if block.StartAddress != firstInstr.Address {
				t.Errorf("block %d start address 0x%x != first instruction address 0x%x",
					block.ID, block.StartAddress, firstInstr.Address)
			}

			// verify end address matches last instruction
			lastInstr := block.Instructions[len(block.Instructions)-1]
			if block.EndAddress != lastInstr.Address {
				t.Errorf("block %d end address 0x%x != last instruction address 0x%x",
					block.ID, block.EndAddress, lastInstr.Address)
			}
		}

		// verify instructions are in address order
		for i := 1; i < len(block.Instructions); i++ {
			prev := block.Instructions[i-1]
			curr := block.Instructions[i]
			if prev.Address >= curr.Address {
				t.Errorf("block %d has out-of-order instructions: 0x%x >= 0x%x",
					block.ID, prev.Address, curr.Address)
			}
		}
	}
}

// TestCFGBuilder_PredecessorSuccessorConsistency tests bidirectional edge consistency
func TestCFGBuilder_PredecessorSuccessorConsistency(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1003,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x100a, Size: disasm.Size32},
			},
		},
		{Address: 0x1005, Mnemonic: "mov", Length: 3},
		{
			Address:  0x1008,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x100d, Size: disasm.Size32},
			},
		},
		{Address: 0x100a, Mnemonic: "add", Length: 3},
		{Address: 0x100d, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify predecessor-successor consistency
	for _, block := range cfg.Blocks {
		// for each successor, verify this block is in its predecessors
		for _, succID := range block.Successors {
			succBlock, exists := cfg.GetBlock(succID)
			if !exists {
				t.Errorf("successor block %d not found", succID)
				continue
			}

			found := false
			for _, predID := range succBlock.Predecessors {
				if predID == block.ID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("block %d has successor %d, but %d doesn't have %d as predecessor",
					block.ID, succID, succID, block.ID)
			}
		}

		// for each predecessor, verify this block is in its successors
		for _, predID := range block.Predecessors {
			predBlock, exists := cfg.GetBlock(predID)
			if !exists {
				t.Errorf("predecessor block %d not found", predID)
				continue
			}

			found := false
			for _, succID := range predBlock.Successors {
				if succID == block.ID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("block %d has predecessor %d, but %d doesn't have %d as successor",
					block.ID, predID, predID, block.ID)
			}
		}
	}
}

// TestCFGBuilder_EdgeCountCorrectness tests that edge count matches actual edges
func TestCFGBuilder_EdgeCountCorrectness(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{
			Address:  0x1003,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1008, Size: disasm.Size32},
			},
		},
		{Address: 0x1005, Mnemonic: "nop", Length: 1},
		{Address: 0x1006, Mnemonic: "nop", Length: 1},
		{Address: 0x1008, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// count edges manually
	edgeCount := len(cfg.Edges)

	// verify edge count matches
	if cfg.EdgeCount() != edgeCount {
		t.Errorf("edge count mismatch: EdgeCount()=%d, len(Edges)=%d",
			cfg.EdgeCount(), edgeCount)
	}

	// verify each edge has valid from/to blocks
	for i, edge := range cfg.Edges {
		if _, exists := cfg.GetBlock(edge.From); !exists {
			t.Errorf("edge %d has invalid from block %d", i, edge.From)
		}
		if _, exists := cfg.GetBlock(edge.To); !exists {
			t.Errorf("edge %d has invalid to block %d", i, edge.To)
		}
	}
}

// helper function to find block by start address
func findBlockByStartAddress(cfg *CFG, addr disasm.Address) *BasicBlock {
	for _, block := range cfg.Blocks {
		if block.StartAddress == addr {
			return block
		}
	}
	return nil
}
