package cfg

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestDetectLoops_SimpleWhileLoop tests detection of a simple while loop
func TestDetectLoops_SimpleWhileLoop(t *testing.T) {
	// construct cfg for:
	// block 0: entry -> block 1
	// block 1: loop header (condition check) -> block 2 (true) or block 3 (false/exit)
	// block 2: loop body -> block 1 (back-edge)
	// block 3: exit

	instructions := []*disasm.Instruction{
		// block 0: entry
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "jmp", Length: 2, Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005}}},

		// block 1: loop header (0x1005-0x1009)
		{Address: 0x1005, Mnemonic: "cmp", Length: 3},
		// jg jumps to exit (0x1010), fallthrough goes to loop body (0x100a)
		{Address: 0x1008, Mnemonic: "jg", Length: 2, Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1010}}},

		// block 2: loop body (0x100a-0x100e)
		{Address: 0x100a, Mnemonic: "add", Length: 3},
		{Address: 0x100d, Mnemonic: "jmp", Length: 2, Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005}}},

		// block 3: exit (0x1010)
		{Address: 0x1010, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// detect loops
	loopInfo, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("failed to detect loops: %v", err)
	}

	// verify one loop detected
	if loopInfo.LoopCount() != 1 {
		t.Errorf("expected 1 loop, got %d", loopInfo.LoopCount())
	}

	// verify loop structure
	loop := loopInfo.Loops[0]

	// verify header is block 1 (address 0x1005)
	headerBlock, _ := cfg.GetBlock(loop.Header)
	if headerBlock.StartAddress != 0x1005 {
		t.Errorf("expected loop header at 0x1005, got 0x%x", headerBlock.StartAddress)
	}

	// verify loop body contains header and body block
	if len(loop.Body) < 2 {
		t.Errorf("expected at least 2 blocks in loop body, got %d", len(loop.Body))
	}

	// verify back-edge exists
	if len(loop.BackEdges) != 1 {
		t.Errorf("expected 1 back-edge, got %d", len(loop.BackEdges))
	}

	// verify exit edge exists
	if len(loop.ExitEdges) != 1 {
		t.Errorf("expected 1 exit edge, got %d", len(loop.ExitEdges))
	}

	// verify loop is not irreducible
	if loop.IsIrreducible {
		t.Error("simple while loop should not be irreducible")
	}

	// verify loop depth is 0 (top-level)
	if loop.Depth != 0 {
		t.Errorf("expected loop depth 0, got %d", loop.Depth)
	}

	// verify loop info
	if verifyErr := loopInfo.VerifyLoopInfo(); verifyErr != nil {
		t.Errorf("loop info verification failed: %v", verifyErr)
	}
}

// TestDetectLoops_NestedLoops tests detection of nested loop structures
func TestDetectLoops_NestedLoops(t *testing.T) {
	// construct cfg for nested loops:
	// block 0: entry -> block 1
	// block 1: outer loop header -> block 2 (true) or block 5 (false/exit)
	// block 2: inner loop header -> block 3 (true) or block 4 (false)
	// block 3: inner loop body -> block 2 (inner back-edge)
	// block 4: outer loop body -> block 1 (outer back-edge)
	// block 5: exit

	instructions := createNestedLoopInstructions()

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// detect loops
	loopInfo, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("failed to detect loops: %v", err)
	}

	// verify two loops detected (outer and inner)
	if loopInfo.LoopCount() != 2 {
		t.Errorf("expected 2 loops, got %d", loopInfo.LoopCount())
	}

	// find outer and inner loops
	var outerLoop, innerLoop *Loop
	for _, loop := range loopInfo.Loops {
		headerBlock, _ := cfg.GetBlock(loop.Header)
		switch headerBlock.StartAddress {
		case 0x1003: // outer loop header
			outerLoop = loop
		case 0x1008: // inner loop header
			innerLoop = loop
		}
	}

	if outerLoop == nil {
		t.Fatal("outer loop not detected")
	}
	if innerLoop == nil {
		t.Fatal("inner loop not detected")
	}

	// verify nesting relationship
	if innerLoop.ParentLoop != outerLoop {
		t.Error("inner loop should have outer loop as parent")
	}

	if len(outerLoop.NestedLoops) != 1 {
		t.Errorf("outer loop should have 1 nested loop, got %d", len(outerLoop.NestedLoops))
	}

	// verify depths
	if outerLoop.Depth != 0 {
		t.Errorf("expected outer loop depth 0, got %d", outerLoop.Depth)
	}
	if innerLoop.Depth != 1 {
		t.Errorf("expected inner loop depth 1, got %d", innerLoop.Depth)
	}

	// verify max depth
	if loopInfo.MaxLoopDepth() != 1 {
		t.Errorf("expected max loop depth 1, got %d", loopInfo.MaxLoopDepth())
	}

	// verify loop info
	if verifyErr := loopInfo.VerifyLoopInfo(); verifyErr != nil {
		t.Errorf("loop info verification failed: %v", verifyErr)
	}
}

// TestDetectLoops_DoWhileLoop tests detection of do-while loop (self-loop)
func TestDetectLoops_DoWhileLoop(t *testing.T) {
	// construct cfg for do-while loop:
	// block 0: entry -> block 1
	// block 1: loop header/body -> block 1 (back-edge, condition true) or block 2 (condition false)
	// block 2: exit

	instructions := []*disasm.Instruction{
		// block 0: entry
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "jmp", Length: 2, Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005}}},

		// block 1: loop header/body (0x1005-0x100c)
		{Address: 0x1005, Mnemonic: "add", Length: 3},
		{Address: 0x1008, Mnemonic: "cmp", Length: 3},
		// jle jumps back to self (0x1005), fallthrough goes to exit (0x100d)
		{Address: 0x100b, Mnemonic: "jle", Length: 2, Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005}}},

		// block 2: exit (0x100d)
		{Address: 0x100d, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	_, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// detect loops
	loopInfo, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("failed to detect loops: %v", err)
	}

	// verify one loop detected
	if loopInfo.LoopCount() != 1 {
		t.Errorf("expected 1 loop, got %d", loopInfo.LoopCount())
	}

	loop := loopInfo.Loops[0]

	// verify self-loop (header has back-edge to itself)
	if len(loop.BackEdges) != 1 {
		t.Errorf("expected 1 back-edge, got %d", len(loop.BackEdges))
	}

	backEdge := loop.BackEdges[0]
	if backEdge.From != backEdge.To {
		t.Error("expected self-loop (back-edge from header to itself)")
	}

	// verify loop is not irreducible
	if loop.IsIrreducible {
		t.Error("do-while loop should not be irreducible")
	}

	// verify loop info
	if verifyErr := loopInfo.VerifyLoopInfo(); verifyErr != nil {
		t.Errorf("loop info verification failed: %v", verifyErr)
	}
}

// TestDetectLoops_NoLoops tests cfg without any loops
func TestDetectLoops_NoLoops(t *testing.T) {
	// construct linear cfg without loops:
	// block 0 -> block 1 -> block 2 -> exit

	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "add", Length: 3},
		{Address: 0x1006, Mnemonic: "sub", Length: 3},
		{Address: 0x1009, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	_, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// detect loops
	loopInfo, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("failed to detect loops: %v", err)
	}

	// verify no loops detected
	if loopInfo.LoopCount() != 0 {
		t.Errorf("expected 0 loops, got %d", loopInfo.LoopCount())
	}

	// verify max depth is 0
	if loopInfo.MaxLoopDepth() != 0 {
		t.Errorf("expected max loop depth 0, got %d", loopInfo.MaxLoopDepth())
	}

	// verify loop info
	if verifyErr := loopInfo.VerifyLoopInfo(); verifyErr != nil {
		t.Errorf("loop info verification failed: %v", verifyErr)
	}
}

// TestLoopInfo_BlockToLoopsMapping tests block-to-loops mapping
func TestLoopInfo_BlockToLoopsMapping(t *testing.T) {
	// construct nested loops to test mapping
	instructions := createNestedLoopInstructions()

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	loopInfo, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("failed to detect loops: %v", err)
	}

	// find inner loop header block
	var innerLoopHeaderBlock BlockID
	for id, block := range cfg.Blocks {
		if block.StartAddress == 0x1008 { // inner loop header
			innerLoopHeaderBlock = id
			break
		}
	}

	// verify inner loop header is in both loops (innermost first)
	loops := loopInfo.BlockToLoops[innerLoopHeaderBlock]
	if len(loops) != 2 {
		t.Errorf("expected inner loop header in 2 loops, got %d", len(loops))
	}

	// verify ordering (innermost first)
	if len(loops) >= 2 && loops[0].Depth <= loops[1].Depth {
		t.Error("loops should be ordered innermost first (highest depth first)")
	}

	// test GetInnermostLoop
	innermostLoop := loopInfo.GetInnermostLoop(innerLoopHeaderBlock)
	if innermostLoop == nil {
		t.Fatal("GetInnermostLoop returned nil")
	}
	if innermostLoop.Depth != 1 {
		t.Errorf("expected innermost loop depth 1, got %d", innermostLoop.Depth)
	}

	// test GetOutermostLoop
	outermostLoop := loopInfo.GetOutermostLoop(innerLoopHeaderBlock)
	if outermostLoop == nil {
		t.Fatal("GetOutermostLoop returned nil")
	}
	if outermostLoop.Depth != 0 {
		t.Errorf("expected outermost loop depth 0, got %d", outermostLoop.Depth)
	}

	// test GetLoopDepth
	depth := loopInfo.GetLoopDepth(innerLoopHeaderBlock)
	if depth != 2 {
		t.Errorf("expected loop depth 2 (nested in 2 loops), got %d", depth)
	}
}

// TestLoopInfo_IsLoopHeader tests loop header detection
func TestLoopInfo_IsLoopHeader(t *testing.T) {
	instructions := createNestedLoopInstructions()

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	loopInfo, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("failed to detect loops: %v", err)
	}

	// find loop header and body blocks
	var headerBlock, bodyBlock BlockID
	for id, block := range cfg.Blocks {
		switch block.StartAddress {
		case 0x1003: // outer loop header
			headerBlock = id
		case 0x100d: // inner loop body
			bodyBlock = id
		}
	}

	// verify header is detected as loop header
	if !loopInfo.IsLoopHeader(headerBlock) {
		t.Error("expected block to be loop header")
	}

	// verify body is not detected as loop header
	if loopInfo.IsLoopHeader(bodyBlock) {
		t.Error("expected block to not be loop header")
	}
}

// TestLoopInfo_GetTopLevelLoops tests retrieval of top-level loops
func TestLoopInfo_GetTopLevelLoops(t *testing.T) {
	// construct two separate top-level loops
	instructions := createSequentialLoopsInstructions()

	builder := NewCFGBuilder()
	_, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	loopInfo, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("failed to detect loops: %v", err)
	}

	// get top-level loops
	topLevel := loopInfo.GetTopLevelLoops()

	// verify two top-level loops
	if len(topLevel) != 2 {
		t.Errorf("expected 2 top-level loops, got %d", len(topLevel))
	}

	// verify all are depth 0
	for _, loop := range topLevel {
		if loop.Depth != 0 {
			t.Errorf("expected top-level loop depth 0, got %d", loop.Depth)
		}
		if loop.ParentLoop != nil {
			t.Error("top-level loop should have no parent")
		}
	}
}
