package cfg

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestCFGBuilder_LinearCode tests CFG construction for simple linear code (no branches)
func TestCFGBuilder_LinearCode(t *testing.T) {
	// create simple linear instruction sequence
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "add", Length: 3},
		{Address: 0x1006, Mnemonic: "sub", Length: 3},
		{Address: 0x1009, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify single basic block
	if cfg.BlockCount() != 1 {
		t.Errorf("expected 1 basic block, got %d", cfg.BlockCount())
	}

	// verify entry block
	entryBlock, exists := cfg.GetBlock(cfg.Entry)
	if !exists {
		t.Fatal("entry block not found")
	}

	// verify all instructions in single block
	if len(entryBlock.Instructions) != 4 {
		t.Errorf("expected 4 instructions in block, got %d", len(entryBlock.Instructions))
	}

	// verify no successors (ends with return)
	if len(entryBlock.Successors) != 0 {
		t.Errorf("expected 0 successors, got %d", len(entryBlock.Successors))
	}

	// verify exit block
	if len(cfg.Exits) != 1 {
		t.Errorf("expected 1 exit block, got %d", len(cfg.Exits))
	}
}

// TestCFGBuilder_ConditionalBranch tests CFG construction for if-then-else pattern
func TestCFGBuilder_ConditionalBranch(t *testing.T) {
	// create instruction sequence with conditional branch
	// 0x1000: cmp rax, rbx
	// 0x1003: je 0x100a      (branch to then block)
	// 0x1005: mov rcx, 1     (else block)
	// 0x1008: jmp 0x100d     (skip then block)
	// 0x100a: mov rcx, 2     (then block)
	// 0x100d: ret            (merge point)
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
		{Address: 0x100a, Mnemonic: "mov", Length: 3},
		{Address: 0x100d, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify 4 basic blocks (entry, else, then, exit)
	if cfg.BlockCount() != 4 {
		t.Errorf("expected 4 basic blocks, got %d", cfg.BlockCount())
	}

	// verify entry block has 2 successors (conditional branch)
	entryBlock, exists := cfg.GetBlock(cfg.Entry)
	if !exists {
		t.Fatal("entry block not found")
	}
	if len(entryBlock.Successors) != 2 {
		t.Errorf("expected 2 successors for entry block, got %d", len(entryBlock.Successors))
	}

	// verify edges exist
	if cfg.EdgeCount() < 4 {
		t.Errorf("expected at least 4 edges, got %d", cfg.EdgeCount())
	}
}

// TestCFGBuilder_UnconditionalJump tests CFG construction with unconditional jumps
func TestCFGBuilder_UnconditionalJump(t *testing.T) {
	// create instruction sequence with unconditional jump
	// 0x1000: mov rax, 1
	// 0x1003: jmp 0x1009
	// 0x1005: mov rbx, 2     (unreachable)
	// 0x1009: ret
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{
			Address:  0x1003,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1009, Size: disasm.Size32},
			},
		},
		{Address: 0x1005, Mnemonic: "mov", Length: 4},
		{Address: 0x1009, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify 3 basic blocks (entry with jump, unreachable, exit)
	if cfg.BlockCount() != 3 {
		t.Errorf("expected 3 basic blocks, got %d", cfg.BlockCount())
	}

	// verify entry block has 1 successor (unconditional jump)
	entryBlock, exists := cfg.GetBlock(cfg.Entry)
	if !exists {
		t.Fatal("entry block not found")
	}
	if len(entryBlock.Successors) != 1 {
		t.Errorf("expected 1 successor for entry block, got %d", len(entryBlock.Successors))
	}
}

// TestCFGBuilder_WhileLoop tests CFG construction for while loop pattern
func TestCFGBuilder_WhileLoop(t *testing.T) {
	// create instruction sequence with while loop
	// 0x1000: mov rcx, 10    (init)
	// 0x1003: cmp rcx, 0     (loop header)
	// 0x1006: je 0x1010      (exit loop)
	// 0x1008: dec rcx        (loop body)
	// 0x100b: jmp 0x1003     (back edge)
	// 0x1010: ret            (after loop)
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1006,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1010, Size: disasm.Size32},
			},
		},
		{Address: 0x1008, Mnemonic: "dec", Length: 3},
		{
			Address:  0x100b,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32},
			},
		},
		{Address: 0x1010, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify 4 basic blocks (init, header, body, exit)
	if cfg.BlockCount() != 4 {
		t.Errorf("expected 4 basic blocks, got %d", cfg.BlockCount())
	}

	// verify back edge exists (loop body -> header)
	hasBackEdge := false
	for _, edge := range cfg.Edges {
		fromBlock := cfg.Blocks[edge.From]
		toBlock := cfg.Blocks[edge.To]
		// back edge: edge where target address < source address
		if toBlock.StartAddress < fromBlock.EndAddress {
			hasBackEdge = true
			break
		}
	}
	if !hasBackEdge {
		t.Error("expected back edge for loop, but none found")
	}
}

// TestCFGBuilder_NestedLoops tests CFG construction for nested loop pattern
func TestCFGBuilder_NestedLoops(t *testing.T) {
	// create instruction sequence with nested loops
	// outer loop with inner loop
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3}, // outer init
		{Address: 0x1003, Mnemonic: "cmp", Length: 3}, // outer header
		{
			Address:  0x1006,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1020, Size: disasm.Size32},
			},
		},
		{Address: 0x1008, Mnemonic: "mov", Length: 3}, // inner init
		{Address: 0x100b, Mnemonic: "cmp", Length: 3}, // inner header
		{
			Address:  0x100e,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1018, Size: disasm.Size32},
			},
		},
		{Address: 0x1010, Mnemonic: "dec", Length: 3}, // inner body
		{
			Address:  0x1013,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x100b, Size: disasm.Size32},
			},
		},
		{Address: 0x1018, Mnemonic: "dec", Length: 3}, // outer body
		{
			Address:  0x101b,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32},
			},
		},
		{Address: 0x1020, Mnemonic: "ret", Length: 1}, // exit
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify multiple basic blocks for nested structure
	if cfg.BlockCount() < 6 {
		t.Errorf("expected at least 6 basic blocks for nested loops, got %d", cfg.BlockCount())
	}

	// count back edges (should have 2 for nested loops)
	backEdgeCount := 0
	for _, edge := range cfg.Edges {
		fromBlock := cfg.Blocks[edge.From]
		toBlock := cfg.Blocks[edge.To]
		if toBlock.StartAddress < fromBlock.EndAddress {
			backEdgeCount++
		}
	}
	if backEdgeCount < 2 {
		t.Errorf("expected at least 2 back edges for nested loops, got %d", backEdgeCount)
	}
}

// TestCFGBuilder_IndirectJump tests handling of indirect jumps
func TestCFGBuilder_IndirectJump(t *testing.T) {
	// create instruction sequence with indirect jump
	// 0x1000: mov rax, [rbx]
	// 0x1003: jmp rax        (indirect jump)
	// 0x1005: ret
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{
			Address:  0x1003,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			},
		},
		{Address: 0x1005, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	_, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify indirect jump is tracked as unresolved
	unresolvedJumps := builder.GetUnresolvedIndirectJumps()
	if len(unresolvedJumps) != 1 {
		t.Errorf("expected 1 unresolved indirect jump, got %d", len(unresolvedJumps))
	}

	if len(unresolvedJumps) > 0 && unresolvedJumps[0] != 0x1003 {
		t.Errorf("expected unresolved jump at 0x1003, got 0x%x", unresolvedJumps[0])
	}
}

// TestCFGBuilder_AddIndirectTarget tests adding resolved indirect jump target
func TestCFGBuilder_AddIndirectTarget(t *testing.T) {
	// create instruction sequence with indirect jump
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{
			Address:  0x1003,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			},
		},
		{Address: 0x1005, Mnemonic: "nop", Length: 1},
		{Address: 0x1006, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify unresolved jump exists
	unresolvedBefore := builder.GetUnresolvedIndirectJumps()
	if len(unresolvedBefore) != 1 {
		t.Fatalf("expected 1 unresolved jump before resolution, got %d", len(unresolvedBefore))
	}

	// resolve indirect jump to target address
	err = builder.AddIndirectTarget(0x1003, 0x1005)
	if err != nil {
		t.Fatalf("failed to add indirect target: %v", err)
	}

	// verify jump is now resolved
	unresolvedAfter := builder.GetUnresolvedIndirectJumps()
	if len(unresolvedAfter) != 0 {
		t.Errorf("expected 0 unresolved jumps after resolution, got %d", len(unresolvedAfter))
	}

	// verify edge was added
	edgeFound := false
	for _, edge := range cfg.Edges {
		if edge.Type == EdgeTypeIndirect {
			edgeFound = true
			break
		}
	}
	if !edgeFound {
		t.Error("expected indirect edge to be added, but none found")
	}
}

// TestCFGBuilder_CallInstruction tests handling of call instructions
func TestCFGBuilder_CallInstruction(t *testing.T) {
	// create instruction sequence with call
	// 0x1000: mov rax, 1
	// 0x1003: call 0x2000
	// 0x1008: mov rbx, 2
	// 0x100b: ret
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{
			Address:  0x1003,
			Mnemonic: "call",
			Length:   5,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x2000, Size: disasm.Size32},
			},
		},
		{Address: 0x1008, Mnemonic: "mov", Length: 3},
		{Address: 0x100b, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify basic blocks are split at call boundary
	// should have at least 2 blocks (before call, after call)
	if cfg.BlockCount() < 2 {
		t.Errorf("expected at least 2 basic blocks with call, got %d", cfg.BlockCount())
	}

	// verify fall-through edge exists after call
	hasFallthrough := false
	for _, edge := range cfg.Edges {
		if edge.Type == EdgeTypeFallthrough {
			hasFallthrough = true
			break
		}
	}
	if !hasFallthrough {
		t.Error("expected fall-through edge after call instruction")
	}
}

// TestCFGBuilder_EmptyInstructions tests error handling for empty instruction list
func TestCFGBuilder_EmptyInstructions(t *testing.T) {
	builder := NewCFGBuilder()
	cfg, err := builder.Build([]*disasm.Instruction{})
	if err == nil {
		t.Error("expected error for empty instruction list, got nil")
	}
	if cfg != nil {
		t.Error("expected nil cfg for empty instruction list")
	}
}

// TestCFGBuilder_MultipleExits tests CFG with multiple return points
func TestCFGBuilder_MultipleExits(t *testing.T) {
	// create instruction sequence with multiple returns
	// 0x1000: cmp rax, 0
	// 0x1003: je 0x1008
	// 0x1005: ret            (early return)
	// 0x1008: mov rbx, 1
	// 0x100b: ret            (normal return)
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1003,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1008, Size: disasm.Size32},
			},
		},
		{Address: 0x1005, Mnemonic: "ret", Length: 1},
		{Address: 0x1008, Mnemonic: "mov", Length: 3},
		{Address: 0x100b, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify 2 exit blocks
	if len(cfg.Exits) != 2 {
		t.Errorf("expected 2 exit blocks, got %d", len(cfg.Exits))
	}
}

// TestCFGBuilder_ComplexControlFlow tests complex control flow with multiple patterns
func TestCFGBuilder_ComplexControlFlow(t *testing.T) {
	// create complex instruction sequence combining multiple patterns
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "push", Length: 1},
		{Address: 0x1001, Mnemonic: "mov", Length: 3},
		{Address: 0x1004, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1007,
			Mnemonic: "jle",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1020, Size: disasm.Size32},
			},
		},
		{Address: 0x1009, Mnemonic: "mov", Length: 3},
		{Address: 0x100c, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x100f,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1018, Size: disasm.Size32},
			},
		},
		{Address: 0x1011, Mnemonic: "add", Length: 3},
		{
			Address:  0x1014,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1020, Size: disasm.Size32},
			},
		},
		{Address: 0x1018, Mnemonic: "sub", Length: 3},
		{
			Address:  0x101b,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1020, Size: disasm.Size32},
			},
		},
		{Address: 0x1020, Mnemonic: "pop", Length: 1},
		{Address: 0x1021, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify reasonable number of blocks for complex control flow
	if cfg.BlockCount() < 5 {
		t.Errorf("expected at least 5 basic blocks for complex control flow, got %d", cfg.BlockCount())
	}

	// verify entry and exit exist
	if _, exists := cfg.GetBlock(cfg.Entry); !exists {
		t.Error("entry block not found in complex control flow")
	}

	if len(cfg.Exits) == 0 {
		t.Error("no exit blocks found in complex control flow")
	}

	// verify all blocks have valid address ranges
	for _, block := range cfg.Blocks {
		if block.StartAddress > block.EndAddress {
			t.Errorf("block %d has invalid address range: start=0x%x, end=0x%x",
				block.ID, block.StartAddress, block.EndAddress)
		}
		if len(block.Instructions) == 0 {
			t.Errorf("block %d has no instructions", block.ID)
		}
	}
}

// TestCFGBuilder_EdgeTypes tests that correct edge types are assigned
func TestCFGBuilder_EdgeTypes(t *testing.T) {
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

	// verify edge types
	hasConditional := false
	hasFallthrough := false
	hasUnconditional := false

	for _, edge := range cfg.Edges {
		switch edge.Type {
		case EdgeTypeConditional:
			hasConditional = true
		case EdgeTypeFallthrough:
			hasFallthrough = true
		case EdgeTypeUnconditional:
			hasUnconditional = true
		case EdgeTypeUnknown, EdgeTypeCall, EdgeTypeReturn, EdgeTypeIndirect:
			// skip other edge types
		}
	}

	if !hasConditional {
		t.Error("expected conditional edge type, but none found")
	}
	if !hasFallthrough {
		t.Error("expected fallthrough edge type, but none found")
	}
	if !hasUnconditional {
		t.Error("expected unconditional edge type, but none found")
	}
}
