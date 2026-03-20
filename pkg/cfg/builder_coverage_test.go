package cfg

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

func TestCFGBuilder_BlockIDForAddress(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "add", Length: 3},
		{Address: 0x1006, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	_, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	id, ok := builder.BlockIDForAddress(0x1000)
	if !ok {
		t.Fatal("expected to find block for address 0x1000")
	}
	block, exists := builder.cfg.GetBlock(id)
	if !exists {
		t.Fatal("block not found by returned id")
	}
	if block.StartAddress != 0x1000 {
		t.Errorf("expected block start 0x1000, got 0x%x", block.StartAddress)
	}

	id2, ok2 := builder.BlockIDForAddress(0x1003)
	if !ok2 {
		t.Fatal("expected to find block for address 0x1003")
	}
	if id2 != id {
		t.Error("instructions in same block should map to same block id")
	}

	_, ok3 := builder.BlockIDForAddress(0xDEAD)
	if ok3 {
		t.Error("expected false for address not in any block")
	}
}

func TestCFGBuilder_ExtractJumpTarget_NoOperands(t *testing.T) {
	instr := &disasm.Instruction{
		Address:  0x1000,
		Mnemonic: "jmp",
		Length:   2,
	}
	target := extractJumpTarget(instr)
	if target != 0 {
		t.Errorf("expected 0 for instruction with no operands, got 0x%x", target)
	}
}

func TestCFGBuilder_ExtractJumpTarget_MemoryOperand(t *testing.T) {
	instr := &disasm.Instruction{
		Address:  0x1000,
		Mnemonic: "jmp",
		Length:   6,
		Operands: []disasm.Operand{
			disasm.MemoryOperand{Base: "rax", Disp: 0x10, Size: disasm.Size64},
		},
	}
	target := extractJumpTarget(instr)
	if target != 0 {
		t.Errorf("expected 0 for memory operand indirect jump, got 0x%x", target)
	}
}

func TestCFGBuilder_ExtractJumpTarget_NegativeImmediate(t *testing.T) {
	instr := &disasm.Instruction{
		Address:  0x1000,
		Mnemonic: "jmp",
		Length:   5,
		Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: -1, Size: disasm.Size32},
		},
	}
	target := extractJumpTarget(instr)
	if target != 0 {
		t.Errorf("expected 0 for negative immediate, got 0x%x", target)
	}
}

func TestCFGBuilder_ClassifyIndirectJump_NotFound(t *testing.T) {
	builder := NewCFGBuilder()
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "ret", Length: 1},
	}
	_, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	err = builder.ClassifyIndirectJump(0xBEEF, IndirectJumpVTable)
	if err == nil {
		t.Error("expected error classifying non-existent indirect jump")
	}
}

func TestCFGBuilder_AddIndirectTargets_ErrorPropagation(t *testing.T) {
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
	_, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	provenance := &EdgeProvenance{
		AnalysisPass: "test",
		Confidence:   1.0,
		Metadata:     make(map[string]any),
	}
	err = builder.AddIndirectTargets(0x1003, []disasm.Address{0x1005, 0xDEAD}, provenance)
	if err == nil {
		t.Error("expected error when one target address is invalid")
	}
}

func TestCFGBuilder_LinearCode_MultipleInstructions(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x2000, Mnemonic: "push", Length: 1},
		{Address: 0x2001, Mnemonic: "mov", Length: 3},
		{Address: 0x2004, Mnemonic: "sub", Length: 4},
		{Address: 0x2008, Mnemonic: "xor", Length: 3},
		{Address: 0x200b, Mnemonic: "add", Length: 3},
		{Address: 0x200e, Mnemonic: "pop", Length: 1},
		{Address: 0x200f, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	if cfg.BlockCount() != 1 {
		t.Errorf("expected 1 block for linear code, got %d", cfg.BlockCount())
	}

	entry, exists := cfg.GetBlock(cfg.Entry)
	if !exists {
		t.Fatal("entry block not found")
	}
	if len(entry.Instructions) != 7 {
		t.Errorf("expected 7 instructions, got %d", len(entry.Instructions))
	}
	if len(entry.Successors) != 0 {
		t.Errorf("expected 0 successors for ret-terminated block, got %d", len(entry.Successors))
	}
	if len(entry.Predecessors) != 0 {
		t.Errorf("expected 0 predecessors for entry block, got %d", len(entry.Predecessors))
	}
	if entry.StartAddress != 0x2000 {
		t.Errorf("expected start 0x2000, got 0x%x", entry.StartAddress)
	}
	if entry.EndAddress != 0x200f {
		t.Errorf("expected end 0x200f, got 0x%x", entry.EndAddress)
	}
	if cfg.EdgeCount() != 0 {
		t.Errorf("expected 0 edges for single-block linear code, got %d", cfg.EdgeCount())
	}
	if len(cfg.Exits) != 1 {
		t.Errorf("expected 1 exit, got %d", len(cfg.Exits))
	}
}

func TestCFGBuilder_IfThenElse_DetailedEdgeVerification(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1003,
			Mnemonic: "jne",
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
		t.Fatalf("build failed: %v", err)
	}

	if cfg.BlockCount() != 4 {
		t.Fatalf("expected 4 blocks, got %d", cfg.BlockCount())
	}

	entryBlock, _ := cfg.GetBlock(cfg.Entry)
	if len(entryBlock.Successors) != 2 {
		t.Fatalf("expected 2 successors for entry, got %d", len(entryBlock.Successors))
	}

	conditionalEdges := 0
	fallthroughEdges := 0
	unconditionalEdges := 0
	for _, edge := range cfg.Edges {
		switch edge.Type {
		case EdgeTypeConditional:
			conditionalEdges++
		case EdgeTypeFallthrough:
			fallthroughEdges++
		case EdgeTypeUnconditional:
			unconditionalEdges++
		}
	}
	if conditionalEdges != 1 {
		t.Errorf("expected 1 conditional edge, got %d", conditionalEdges)
	}
	if unconditionalEdges != 1 {
		t.Errorf("expected 1 unconditional edge, got %d", unconditionalEdges)
	}

	mergeBlock := findBlockByStartAddress(cfg, 0x100d)
	if mergeBlock == nil {
		t.Fatal("merge block not found")
	}
	if len(mergeBlock.Predecessors) != 2 {
		t.Errorf("expected 2 predecessors for merge block, got %d", len(mergeBlock.Predecessors))
	}
}

func TestCFGBuilder_WhileLoop_StructuralProperties(t *testing.T) {
	instructions := buildLoopInstructions([]loopInstruction{
		{addr: 0x1000, mnem: "xor", length: 3},
		{addr: 0x1003, mnem: "cmp", length: 3},
		{addr: 0x1006, mnem: "jge", length: 2, target: 0x1010},
		{addr: 0x1008, mnem: "inc", length: 3},
		{addr: 0x100b, mnem: "jmp", length: 2, target: 0x1003},
		{addr: 0x1010, mnem: "ret", length: 1},
	})

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	header := findBlockByStartAddress(cfg, 0x1003)
	if header == nil {
		t.Fatal("loop header not found")
	}
	if len(header.Predecessors) != 2 {
		t.Errorf("expected 2 predecessors for header (entry + back edge), got %d", len(header.Predecessors))
	}
	if len(header.Successors) != 2 {
		t.Errorf("expected 2 successors for header (body + exit), got %d", len(header.Successors))
	}

	body := findBlockByStartAddress(cfg, 0x1008)
	if body == nil {
		t.Fatal("loop body not found")
	}
	if len(body.Successors) != 1 {
		t.Errorf("expected 1 successor for body (back to header), got %d", len(body.Successors))
	}

	exit := findBlockByStartAddress(cfg, 0x1010)
	if exit == nil {
		t.Fatal("exit block not found")
	}
	if len(exit.Predecessors) != 1 {
		t.Errorf("expected 1 predecessor for exit, got %d", len(exit.Predecessors))
	}
}

func TestCFGBuilder_DoWhileLoop_StructuralProperties(t *testing.T) {
	instructions := buildLoopInstructions([]loopInstruction{
		{addr: 0x1000, mnem: "mov", length: 3},
		{addr: 0x1003, mnem: "add", length: 3},
		{addr: 0x1006, mnem: "cmp", length: 3},
		{addr: 0x1009, mnem: "jl", length: 2, target: 0x1003},
		{addr: 0x100b, mnem: "ret", length: 1},
	})

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	body := findBlockByStartAddress(cfg, 0x1003)
	if body == nil {
		t.Fatal("body block not found")
	}
	if len(body.Successors) != 2 {
		t.Errorf("expected 2 successors (back edge + exit), got %d", len(body.Successors))
	}
	if len(body.Predecessors) < 2 {
		t.Errorf("expected >= 2 predecessors (init + back edge), got %d", len(body.Predecessors))
	}

	hasConditionalBackEdge := false
	for _, edge := range cfg.Edges {
		toBlock := cfg.Blocks[edge.To]
		if toBlock.StartAddress == 0x1003 && edge.Type == EdgeTypeConditional {
			hasConditionalBackEdge = true
		}
	}
	if !hasConditionalBackEdge {
		t.Error("expected conditional back edge in do-while loop")
	}
}

func TestCFGBuilder_SequentialLoops(t *testing.T) {
	instructions := createSequentialLoopsInstructions()

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	if cfg.BlockCount() < 5 {
		t.Errorf("expected at least 5 blocks for two sequential loops, got %d", cfg.BlockCount())
	}

	backEdgeTargets := make(map[disasm.Address]bool)
	for _, edge := range cfg.Edges {
		fromBlock := cfg.Blocks[edge.From]
		toBlock := cfg.Blocks[edge.To]
		if toBlock.StartAddress < fromBlock.EndAddress {
			backEdgeTargets[toBlock.StartAddress] = true
		}
	}
	if len(backEdgeTargets) < 2 {
		t.Errorf("expected at least 2 distinct back edge targets for sequential loops, got %d", len(backEdgeTargets))
	}

	if len(cfg.Exits) != 1 {
		t.Errorf("expected 1 exit block, got %d", len(cfg.Exits))
	}
}

func TestCFGBuilder_NestedLoops_InnerLoopIsolation(t *testing.T) {
	instructions := createNestedLoopInstructions()

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	innerHeader := findBlockByStartAddress(cfg, 0x1008)
	if innerHeader == nil {
		t.Fatal("inner loop header not found")
	}
	if len(innerHeader.Predecessors) != 2 {
		t.Errorf("expected 2 predecessors for inner header (outer body + inner back edge), got %d",
			len(innerHeader.Predecessors))
	}

	outerHeader := findBlockByStartAddress(cfg, 0x1003)
	if outerHeader == nil {
		t.Fatal("outer loop header not found")
	}
	if len(outerHeader.Predecessors) != 2 {
		t.Errorf("expected 2 predecessors for outer header (entry + outer back edge), got %d",
			len(outerHeader.Predecessors))
	}

	backEdgeCount := 0
	for _, edge := range cfg.Edges {
		fromBlock := cfg.Blocks[edge.From]
		toBlock := cfg.Blocks[edge.To]
		if toBlock.StartAddress < fromBlock.EndAddress {
			backEdgeCount++
		}
	}
	if backEdgeCount != 2 {
		t.Errorf("expected exactly 2 back edges, got %d", backEdgeCount)
	}
}

func TestCFGBuilder_ComplexControlFlow_DiamondPattern(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "test", Length: 3},
		{
			Address:  0x1003,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x100a, Size: disasm.Size32},
			},
		},
		{Address: 0x1005, Mnemonic: "add", Length: 3},
		{
			Address:  0x1008,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x100d, Size: disasm.Size32},
			},
		},
		{Address: 0x100a, Mnemonic: "sub", Length: 3},
		{Address: 0x100d, Mnemonic: "mov", Length: 3},
		{Address: 0x1010, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	if cfg.BlockCount() != 4 {
		t.Errorf("expected 4 blocks for diamond pattern, got %d", cfg.BlockCount())
	}

	merge := findBlockByStartAddress(cfg, 0x100d)
	if merge == nil {
		t.Fatal("merge block not found")
	}
	if len(merge.Predecessors) != 2 {
		t.Errorf("expected 2 predecessors for diamond merge, got %d", len(merge.Predecessors))
	}

	for _, block := range cfg.Blocks {
		for _, succID := range block.Successors {
			succ, exists := cfg.GetBlock(succID)
			if !exists {
				t.Errorf("block %d references non-existent successor %d", block.ID, succID)
				continue
			}
			found := false
			for _, predID := range succ.Predecessors {
				if predID == block.ID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("block %d -> %d: successor missing reverse predecessor link", block.ID, succID)
			}
		}
	}
}

func TestCFGBuilder_IndirectJump_MemoryOperand(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{
			Address:  0x1003,
			Mnemonic: "jmp",
			Length:   6,
			Operands: []disasm.Operand{
				disasm.MemoryOperand{Base: "rax", Scale: 8, Index: "rcx", Size: disasm.Size64},
			},
		},
		{Address: 0x1009, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	_, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	unresolvedJumps := builder.GetUnresolvedIndirectJumps()
	if len(unresolvedJumps) != 1 {
		t.Errorf("expected 1 unresolved jump for memory operand, got %d", len(unresolvedJumps))
	}
}

func TestCFGBuilder_ReturnVariants(t *testing.T) {
	variants := []string{"ret", "retf", "retn"}
	for _, mnem := range variants {
		t.Run(mnem, func(t *testing.T) {
			instructions := []*disasm.Instruction{
				{Address: 0x1000, Mnemonic: "nop", Length: 1},
				{Address: 0x1001, Mnemonic: mnem, Length: 1},
			}
			builder := NewCFGBuilder()
			cfg, err := builder.Build(instructions)
			if err != nil {
				t.Fatalf("build failed: %v", err)
			}
			if len(cfg.Exits) != 1 {
				t.Errorf("expected 1 exit for %s, got %d", mnem, len(cfg.Exits))
			}
		})
	}
}

func TestCFGBuilder_CallVariants(t *testing.T) {
	variants := []string{"call", "callf"}
	for _, mnem := range variants {
		t.Run(mnem, func(t *testing.T) {
			instructions := []*disasm.Instruction{
				{Address: 0x1000, Mnemonic: "mov", Length: 3},
				{
					Address:  0x1003,
					Mnemonic: mnem,
					Length:   5,
					Operands: []disasm.Operand{
						disasm.ImmediateOperand{Value: 0x2000, Size: disasm.Size32},
					},
				},
				{Address: 0x1008, Mnemonic: "ret", Length: 1},
			}
			builder := NewCFGBuilder()
			cfg, err := builder.Build(instructions)
			if err != nil {
				t.Fatalf("build failed: %v", err)
			}
			if cfg.BlockCount() < 2 {
				t.Errorf("expected at least 2 blocks for %s, got %d", mnem, cfg.BlockCount())
			}
		})
	}
}

func TestCFGBuilder_JcxzConditionalBranch(t *testing.T) {
	variants := []string{"jcxz", "jecxz", "jrcxz"}
	for _, mnem := range variants {
		t.Run(mnem, func(t *testing.T) {
			instructions := []*disasm.Instruction{
				{Address: 0x1000, Mnemonic: "mov", Length: 3},
				{
					Address:  0x1003,
					Mnemonic: mnem,
					Length:   2,
					Operands: []disasm.Operand{
						disasm.ImmediateOperand{Value: 0x1008, Size: disasm.Size32},
					},
				},
				{Address: 0x1005, Mnemonic: "nop", Length: 1},
				{Address: 0x1008, Mnemonic: "ret", Length: 1},
			}
			builder := NewCFGBuilder()
			cfg, err := builder.Build(instructions)
			if err != nil {
				t.Fatalf("build failed: %v", err)
			}
			entry, _ := cfg.GetBlock(cfg.Entry)
			if len(entry.Successors) != 2 {
				t.Errorf("expected 2 successors for %s, got %d", mnem, len(entry.Successors))
			}
		})
	}
}

func TestCFGBuilder_SingleInstruction(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	if cfg.BlockCount() != 1 {
		t.Errorf("expected 1 block, got %d", cfg.BlockCount())
	}
	if len(cfg.Exits) != 1 {
		t.Errorf("expected 1 exit, got %d", len(cfg.Exits))
	}
	if cfg.EdgeCount() != 0 {
		t.Errorf("expected 0 edges, got %d", cfg.EdgeCount())
	}
}

func TestCFGBuilder_NoReturnFunction(t *testing.T) {
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
		{Address: 0x1008, Mnemonic: "nop", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	if len(cfg.Exits) != 0 {
		t.Errorf("expected 0 exits for function without ret, got %d", len(cfg.Exits))
	}
}
