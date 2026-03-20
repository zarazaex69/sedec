package cfg

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

func TestComputeDominatorsForCFG_Standalone(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "cmp", Length: 3},
		{Address: 0x1003, Mnemonic: "je", Length: 2, Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x100a, Size: disasm.Size32},
		}},
		{Address: 0x1005, Mnemonic: "mov", Length: 3},
		{Address: 0x1008, Mnemonic: "jmp", Length: 2, Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x100d, Size: disasm.Size32},
		}},
		{Address: 0x100a, Mnemonic: "mov", Length: 3},
		{Address: 0x100d, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfgGraph, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := ComputeDominatorsForCFG(cfgGraph)
	if err != nil {
		t.Fatalf("ComputeDominatorsForCFG failed: %v", err)
	}

	if verifyErr := dt.VerifyDominatorTree(); verifyErr != nil {
		t.Fatalf("verification failed: %v", verifyErr)
	}

	for id := range cfgGraph.Blocks {
		if !dt.Dominates(cfgGraph.Entry, id) {
			t.Errorf("entry does not dominate block %d", id)
		}
	}
}

func TestComputeDominatorsForCFG_NilCFG(t *testing.T) {
	_, err := ComputeDominatorsForCFG(nil)
	if err == nil {
		t.Fatal("expected error for nil cfg")
	}
}

func TestComputeDominatorsForCFG_EmptyBlocks(t *testing.T) {
	cfgGraph := NewCFG()
	_, err := ComputeDominatorsForCFG(cfgGraph)
	if err == nil {
		t.Fatal("expected error for cfg with no blocks")
	}
}

func TestDominatorTree_SingleBlock(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfgGraph, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	if verifyErr := dt.VerifyDominatorTree(); verifyErr != nil {
		t.Fatalf("verification failed: %v", verifyErr)
	}

	if len(cfgGraph.Blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(cfgGraph.Blocks))
	}

	idom, exists := dt.GetImmediateDominator(cfgGraph.Entry)
	if !exists {
		t.Fatal("entry should have idom")
	}
	if idom != cfgGraph.Entry {
		t.Errorf("single block idom should be itself, got %d", idom)
	}

	children := dt.GetChildren(cfgGraph.Entry)
	if len(children) != 0 {
		t.Errorf("single block should have no children, got %d", len(children))
	}

	depth := dt.GetDominatorTreeDepth()
	if depth != 0 {
		t.Errorf("single block tree depth should be 0, got %d", depth)
	}
}

func TestDominatorTree_SelfLoop(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "cmp", Length: 3},
		{Address: 0x1003, Mnemonic: "jne", Length: 2, Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x1000, Size: disasm.Size32},
		}},
		{Address: 0x1005, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfgGraph, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	if verifyErr := dt.VerifyDominatorTree(); verifyErr != nil {
		t.Fatalf("verification failed: %v", verifyErr)
	}

	for id := range cfgGraph.Blocks {
		if !dt.Dominates(cfgGraph.Entry, id) {
			t.Errorf("entry does not dominate block %d", id)
		}
	}

	var backEdges []*Edge
	for _, edge := range cfgGraph.Edges {
		if dt.Dominates(edge.To, edge.From) {
			backEdges = append(backEdges, edge)
		}
	}
	if len(backEdges) == 0 {
		t.Error("self-loop should produce at least one back-edge")
	}
}

func TestDominatorTree_Antisymmetry(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "cmp", Length: 3},
		{Address: 0x1003, Mnemonic: "je", Length: 2, Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x100a, Size: disasm.Size32},
		}},
		{Address: 0x1005, Mnemonic: "mov", Length: 3},
		{Address: 0x1008, Mnemonic: "jmp", Length: 2, Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x100d, Size: disasm.Size32},
		}},
		{Address: 0x100a, Mnemonic: "mov", Length: 3},
		{Address: 0x100d, Mnemonic: "add", Length: 3},
		{Address: 0x1010, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfgGraph, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	for a := range cfgGraph.Blocks {
		for b := range cfgGraph.Blocks {
			if a == b {
				continue
			}
			if dt.Dominates(a, b) && dt.Dominates(b, a) {
				t.Errorf("antisymmetry violated: %d and %d mutually dominate", a, b)
			}
		}
	}
}

func TestDominatorTree_DiamondDominanceFrontiers(t *testing.T) {
	//     entry (0x1000)
	//      / \
	//  left   right
	//  (05)   (0a)
	//      \ /
	//     merge (0x100d)
	//       |
	//      exit (0x1010)
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "cmp", Length: 3},
		{Address: 0x1003, Mnemonic: "je", Length: 2, Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x100a, Size: disasm.Size32},
		}},
		{Address: 0x1005, Mnemonic: "mov", Length: 3},
		{Address: 0x1008, Mnemonic: "jmp", Length: 2, Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x100d, Size: disasm.Size32},
		}},
		{Address: 0x100a, Mnemonic: "mov", Length: 3},
		{Address: 0x100d, Mnemonic: "add", Length: 3},
		{Address: 0x1010, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfgGraph, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	df := dt.ComputeDominanceFrontiers()

	var mergeBlock BlockID
	for id, block := range cfgGraph.Blocks {
		if len(block.Predecessors) == 2 {
			mergeBlock = id
			break
		}
	}
	if mergeBlock == 0 {
		t.Fatal("merge block not found")
	}

	var leftBlock, rightBlock BlockID
	for _, pred := range cfgGraph.Blocks[mergeBlock].Predecessors {
		if pred == cfgGraph.Entry {
			continue
		}
		if leftBlock == 0 {
			leftBlock = pred
		} else {
			rightBlock = pred
		}
	}

	checkInDF := func(block, target BlockID) {
		for _, dfBlock := range df[block] {
			if dfBlock == target {
				return
			}
		}
		t.Errorf("block %d should have %d in its dominance frontier", block, target)
	}

	if leftBlock != 0 {
		checkInDF(leftBlock, mergeBlock)
	}
	if rightBlock != 0 {
		checkInDF(rightBlock, mergeBlock)
	}

	if len(df[cfgGraph.Entry]) != 0 {
		t.Errorf("entry should have empty dominance frontier in diamond, got %v", df[cfgGraph.Entry])
	}
}

func TestDominatorTree_SequentialLoops(t *testing.T) {
	instructions := createSequentialLoopsInstructions()

	builder := NewCFGBuilder()
	cfgGraph, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	if verifyErr := dt.VerifyDominatorTree(); verifyErr != nil {
		t.Fatalf("verification failed: %v", verifyErr)
	}

	for id := range cfgGraph.Blocks {
		if !dt.Dominates(cfgGraph.Entry, id) {
			t.Errorf("entry does not dominate block %d", id)
		}
	}

	loopInfo, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("failed to detect loops: %v", err)
	}

	if loopInfo.LoopCount() < 2 {
		t.Fatalf("expected at least 2 sequential loops, got %d", loopInfo.LoopCount())
	}

	for _, loop := range loopInfo.Loops {
		if loop.ParentLoop != nil {
			t.Errorf("sequential loops should not be nested, but loop at header %d has parent", loop.Header)
		}
	}

	for _, loop := range loopInfo.Loops {
		for _, bodyBlock := range loop.Body {
			if !dt.Dominates(loop.Header, bodyBlock) {
				t.Errorf("loop header %d does not dominate body block %d", loop.Header, bodyBlock)
			}
		}
	}
}

func TestDominatorTree_DoWhileLoop(t *testing.T) {
	// do-while: body executes at least once
	//   entry -> body -> cond --(back)--> body
	//                       \--> exit
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "add", Length: 3},
		{Address: 0x1006, Mnemonic: "cmp", Length: 3},
		{Address: 0x1009, Mnemonic: "jl", Length: 2, Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32},
		}},
		{Address: 0x100b, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfgGraph, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	if verifyErr := dt.VerifyDominatorTree(); verifyErr != nil {
		t.Fatalf("verification failed: %v", verifyErr)
	}

	loopInfo, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("failed to detect loops: %v", err)
	}

	if loopInfo.LoopCount() != 1 {
		t.Fatalf("expected 1 loop, got %d", loopInfo.LoopCount())
	}

	loop := loopInfo.Loops[0]
	for _, bodyBlock := range loop.Body {
		if !dt.Dominates(loop.Header, bodyBlock) {
			t.Errorf("do-while header %d does not dominate body block %d", loop.Header, bodyBlock)
		}
	}

	if !dt.Dominates(cfgGraph.Entry, loop.Header) {
		t.Errorf("entry does not dominate do-while header %d", loop.Header)
	}
}

func TestDominatorTree_VerifyDetectsCorruption(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "cmp", Length: 3},
		{Address: 0x1003, Mnemonic: "je", Length: 2, Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x100a, Size: disasm.Size32},
		}},
		{Address: 0x1005, Mnemonic: "mov", Length: 3},
		{Address: 0x1008, Mnemonic: "jmp", Length: 2, Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x100d, Size: disasm.Size32},
		}},
		{Address: 0x100a, Mnemonic: "mov", Length: 3},
		{Address: 0x100d, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	_, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	if verifyErr := dt.VerifyDominatorTree(); verifyErr != nil {
		t.Fatalf("valid tree should pass verification: %v", verifyErr)
	}

	var nonEntryBlock BlockID
	for id := range dt.Idom {
		if id != dt.cfg.Entry {
			nonEntryBlock = id
			break
		}
	}
	if nonEntryBlock == 0 {
		t.Fatal("no non-entry block found for corruption test")
	}

	originalIdom := dt.Idom[nonEntryBlock]
	dt.Idom[nonEntryBlock] = nonEntryBlock
	if verifyErr := dt.VerifyDominatorTree(); verifyErr == nil {
		t.Error("corrupted idom (self-referencing non-entry) should fail verification")
	}
	dt.Idom[nonEntryBlock] = originalIdom

	dt.Children[nonEntryBlock] = append(dt.Children[nonEntryBlock], dt.cfg.Entry)
	if verifyErr := dt.VerifyDominatorTree(); verifyErr == nil {
		t.Error("inconsistent children mapping should fail verification")
	}
}

func TestDominatorTree_DepthVariousTopologies(t *testing.T) {
	tests := []struct {
		name         string
		instructions []*disasm.Instruction
		minDepth     int
	}{
		{
			name: "linear_chain",
			instructions: []*disasm.Instruction{
				{Address: 0x1000, Mnemonic: "mov", Length: 3},
				{Address: 0x1003, Mnemonic: "add", Length: 3},
				{Address: 0x1006, Mnemonic: "sub", Length: 3},
				{Address: 0x1009, Mnemonic: "xor", Length: 3},
				{Address: 0x100c, Mnemonic: "ret", Length: 1},
			},
			minDepth: 0,
		},
		{
			name: "wide_branch",
			instructions: []*disasm.Instruction{
				{Address: 0x1000, Mnemonic: "cmp", Length: 3},
				{Address: 0x1003, Mnemonic: "je", Length: 2, Operands: []disasm.Operand{
					disasm.ImmediateOperand{Value: 0x100a, Size: disasm.Size32},
				}},
				{Address: 0x1005, Mnemonic: "mov", Length: 3},
				{Address: 0x1008, Mnemonic: "jmp", Length: 2, Operands: []disasm.Operand{
					disasm.ImmediateOperand{Value: 0x100d, Size: disasm.Size32},
				}},
				{Address: 0x100a, Mnemonic: "mov", Length: 3},
				{Address: 0x100d, Mnemonic: "ret", Length: 1},
			},
			minDepth: 1,
		},
		{
			name:         "nested_loops",
			instructions: createNestedLoopInstructions(),
			minDepth:     2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			builder := NewCFGBuilder()
			_, err := builder.Build(tc.instructions)
			if err != nil {
				t.Fatalf("failed to build cfg: %v", err)
			}

			dt, err := builder.ComputeDominators()
			if err != nil {
				t.Fatalf("failed to compute dominators: %v", err)
			}

			depth := dt.GetDominatorTreeDepth()
			if depth < tc.minDepth {
				t.Errorf("expected depth >= %d, got %d", tc.minDepth, depth)
			}
		})
	}
}

func TestDominanceFrontiers_LoopPhiPlacement(t *testing.T) {
	//   entry -> header <-- body
	//              |
	//            exit
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "cmp", Length: 3},
		{Address: 0x1006, Mnemonic: "jge", Length: 2, Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x100d, Size: disasm.Size32},
		}},
		{Address: 0x1008, Mnemonic: "add", Length: 3},
		{Address: 0x100b, Mnemonic: "jmp", Length: 2, Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32},
		}},
		{Address: 0x100d, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfgGraph, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	df := dt.ComputeDominanceFrontiers()

	var headerBlock BlockID
	for id, block := range cfgGraph.Blocks {
		if len(block.Predecessors) >= 2 {
			headerBlock = id
			break
		}
	}
	if headerBlock == 0 {
		t.Fatal("loop header not found")
	}

	var bodyBlock BlockID
	for _, pred := range cfgGraph.Blocks[headerBlock].Predecessors {
		if pred != cfgGraph.Entry {
			bodyBlock = pred
			break
		}
	}
	if bodyBlock == 0 {
		t.Fatal("loop body block not found")
	}

	headerInBodyDF := false
	for _, dfBlock := range df[bodyBlock] {
		if dfBlock == headerBlock {
			headerInBodyDF = true
			break
		}
	}
	if !headerInBodyDF {
		t.Errorf("loop header %d should be in DF of body block %d (phi-node placement site)", headerBlock, bodyBlock)
	}

	for block, frontier := range df {
		for _, y := range frontier {
			yBlock, exists := cfgGraph.Blocks[y]
			if !exists {
				continue
			}
			dominatesPred := false
			for _, pred := range yBlock.Predecessors {
				if dt.Dominates(block, pred) {
					dominatesPred = true
					break
				}
			}
			if !dominatesPred {
				t.Errorf("DF property violated: %d in DF[%d] but %d does not dominate any predecessor of %d",
					y, block, block, y)
			}
			if dt.StrictlyDominates(block, y) {
				t.Errorf("DF property violated: %d strictly dominates %d but %d is in DF[%d]",
					block, y, y, block)
			}
		}
	}
}

func TestDominatorTree_IdomUniqueness(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "cmp", Length: 3},
		{Address: 0x1003, Mnemonic: "je", Length: 2, Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x100a, Size: disasm.Size32},
		}},
		{Address: 0x1005, Mnemonic: "mov", Length: 3},
		{Address: 0x1008, Mnemonic: "jmp", Length: 2, Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x100d, Size: disasm.Size32},
		}},
		{Address: 0x100a, Mnemonic: "mov", Length: 3},
		{Address: 0x100d, Mnemonic: "cmp", Length: 3},
		{Address: 0x1010, Mnemonic: "je", Length: 2, Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x1017, Size: disasm.Size32},
		}},
		{Address: 0x1012, Mnemonic: "mov", Length: 3},
		{Address: 0x1015, Mnemonic: "jmp", Length: 2, Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x101a, Size: disasm.Size32},
		}},
		{Address: 0x1017, Mnemonic: "mov", Length: 3},
		{Address: 0x101a, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfgGraph, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	for id := range cfgGraph.Blocks {
		if id == cfgGraph.Entry {
			continue
		}
		idom, exists := dt.GetImmediateDominator(id)
		if !exists {
			t.Errorf("block %d has no idom", id)
			continue
		}
		if !dt.Dominates(idom, id) {
			t.Errorf("idom %d does not dominate block %d", idom, id)
		}
		if !dt.StrictlyDominates(idom, id) {
			t.Errorf("idom %d does not strictly dominate block %d", idom, id)
		}
		for other := range cfgGraph.Blocks {
			if other == idom || other == id {
				continue
			}
			if dt.StrictlyDominates(other, id) && dt.StrictlyDominates(idom, other) {
				t.Errorf("idom(%d)=%d is not immediate: %d strictly dominates %d and is strictly dominated by %d",
					id, idom, other, id, idom)
			}
		}
	}
}
