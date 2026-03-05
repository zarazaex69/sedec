package cfg

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestComputeDominators_LinearCode tests dominator tree for simple linear code
func TestComputeDominators_LinearCode(t *testing.T) {
	// create linear cfg: entry -> b1 -> b2 -> exit
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "add", Length: 3},
		{Address: 0x1006, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// compute dominator tree
	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	// verify entry dominates all blocks
	for id := range cfg.Blocks {
		if !dt.Dominates(cfg.Entry, id) {
			t.Errorf("entry block %d does not dominate block %d", cfg.Entry, id)
		}
	}

	// verify dominator tree structure
	if err := dt.VerifyDominatorTree(); err != nil {
		t.Errorf("dominator tree verification failed: %v", err)
	}

	// in linear code, each block's idom is its predecessor
	for id, block := range cfg.Blocks {
		if id == cfg.Entry {
			// entry's idom is itself
			if dt.Idom[id] != id {
				t.Errorf("entry block idom should be itself, got %d", dt.Idom[id])
			}
			continue
		}

		if len(block.Predecessors) == 1 {
			pred := block.Predecessors[0]
			if dt.Idom[id] != pred {
				t.Errorf("block %d idom should be %d, got %d", id, pred, dt.Idom[id])
			}
		}
	}
}

// TestComputeDominators_IfThenElse tests dominator tree for if-then-else structure
func TestComputeDominators_IfThenElse(t *testing.T) {
	// create if-then-else cfg:
	//     entry
	//      / \
	//   then  else
	//      \ /
	//     merge
	//       |
	//      exit
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
		// then branch
		{Address: 0x1005, Mnemonic: "mov", Length: 3},
		{
			Address:  0x1008,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x100d, Size: disasm.Size32},
			},
		},
		// else branch
		{Address: 0x100a, Mnemonic: "mov", Length: 3},
		// merge point
		{Address: 0x100d, Mnemonic: "add", Length: 3},
		{Address: 0x1010, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	// verify entry dominates all blocks
	for id := range cfg.Blocks {
		if !dt.Dominates(cfg.Entry, id) {
			t.Errorf("entry does not dominate block %d", id)
		}
	}

	// verify dominator tree correctness
	if err := dt.VerifyDominatorTree(); err != nil {
		t.Errorf("dominator tree verification failed: %v", err)
	}

	// find merge block (has 2 predecessors)
	var mergeBlock BlockID
	for id, block := range cfg.Blocks {
		if len(block.Predecessors) == 2 {
			mergeBlock = id
			break
		}
	}

	if mergeBlock == 0 {
		t.Fatal("merge block not found")
	}

	// merge block's idom should be entry (entry dominates both paths)
	if dt.Idom[mergeBlock] != cfg.Entry {
		t.Errorf("merge block idom should be entry %d, got %d", cfg.Entry, dt.Idom[mergeBlock])
	}
}

// TestComputeDominators_Loop tests dominator tree for loop structure
func TestComputeDominators_Loop(t *testing.T) {
	// create loop cfg:
	//     entry
	//       |
	//     header <--+
	//      / \      |
	//   body  exit  |
	//     |         |
	//     +-------- +
	instructions := []*disasm.Instruction{
		// entry
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		// loop header
		{Address: 0x1003, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1006,
			Mnemonic: "jge",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x100d, Size: disasm.Size32},
			},
		},
		// loop body
		{Address: 0x1008, Mnemonic: "add", Length: 3},
		{
			Address:  0x100b,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32},
			},
		},
		// exit
		{Address: 0x100d, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	// verify entry dominates all blocks
	for id := range cfg.Blocks {
		if !dt.Dominates(cfg.Entry, id) {
			t.Errorf("entry does not dominate block %d", id)
		}
	}

	// verify dominator tree correctness
	if err := dt.VerifyDominatorTree(); err != nil {
		t.Errorf("dominator tree verification failed: %v", err)
	}

	// find loop header (has back edge - predecessor with higher address)
	var headerBlock BlockID
	for id, block := range cfg.Blocks {
		if id == cfg.Entry {
			continue
		}

		// header has predecessor from both entry and loop body
		if len(block.Predecessors) >= 2 {
			headerBlock = id
			break
		}
	}

	if headerBlock == 0 {
		t.Fatal("loop header not found")
	}

	// header should dominate all blocks in loop body
	for id, block := range cfg.Blocks {
		if id == cfg.Entry || id == headerBlock {
			continue
		}

		// if block is in loop (has path back to header)
		hasPathToHeader := false
		for _, succ := range block.Successors {
			if succ == headerBlock {
				hasPathToHeader = true
				break
			}
		}

		if hasPathToHeader {
			if !dt.Dominates(headerBlock, id) {
				t.Errorf("loop header %d should dominate loop body block %d", headerBlock, id)
			}
		}
	}
}

// TestComputeDominanceFrontiers tests dominance frontier computation
func TestComputeDominanceFrontiers(t *testing.T) {
	// create cfg with merge point for testing dominance frontiers
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
		{Address: 0x100d, Mnemonic: "add", Length: 3},
		{Address: 0x1010, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	// compute dominance frontiers
	df := dt.ComputeDominanceFrontiers()

	// find merge block (has 2 predecessors)
	var mergeBlock BlockID
	for id, block := range cfg.Blocks {
		if len(block.Predecessors) == 2 {
			mergeBlock = id
			break
		}
	}

	if mergeBlock == 0 {
		t.Fatal("merge block not found")
	}

	// both branch blocks should have merge in their dominance frontier
	for id := range cfg.Blocks {
		if id == cfg.Entry || id == mergeBlock {
			continue
		}

		// if this block is a predecessor of merge
		isPredOfMerge := false
		for _, pred := range cfg.Blocks[mergeBlock].Predecessors {
			if pred == id {
				isPredOfMerge = true
				break
			}
		}

		if isPredOfMerge {
			// check if merge is in dominance frontier
			found := false
			for _, dfBlock := range df[id] {
				if dfBlock == mergeBlock {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("merge block %d should be in dominance frontier of block %d", mergeBlock, id)
			}
		}
	}

	// verify dominance frontier properties
	for block, frontier := range df {
		for _, y := range frontier {
			// block should dominate a predecessor of y
			yBlock := cfg.Blocks[y]
			dominatesPred := false

			for _, pred := range yBlock.Predecessors {
				if dt.Dominates(block, pred) {
					dominatesPred = true
					break
				}
			}

			if !dominatesPred {
				t.Errorf("block %d in df[%d] but %d does not dominate any predecessor of %d",
					y, block, block, y)
			}

			// block should not strictly dominate y
			if dt.StrictlyDominates(block, y) {
				t.Errorf("block %d strictly dominates %d but %d is in df[%d]",
					block, y, y, block)
			}
		}
	}
}

// TestDominatorTree_Dominates tests the dominates query
func TestDominatorTree_Dominates(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "add", Length: 3},
		{Address: 0x1006, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	// test reflexivity: every block dominates itself
	for id := range cfg.Blocks {
		if !dt.Dominates(id, id) {
			t.Errorf("block %d should dominate itself", id)
		}
	}

	// test entry dominates all
	for id := range cfg.Blocks {
		if !dt.Dominates(cfg.Entry, id) {
			t.Errorf("entry %d should dominate block %d", cfg.Entry, id)
		}
	}

	// test transitivity
	for a := range cfg.Blocks {
		for b := range cfg.Blocks {
			if !dt.Dominates(a, b) {
				continue
			}

			for c := range cfg.Blocks {
				if dt.Dominates(b, c) && !dt.Dominates(a, c) {
					t.Errorf("transitivity violated: %d dom %d, %d dom %d, but %d does not dom %d",
						a, b, b, c, a, c)
				}
			}
		}
	}
}

// TestDominatorTree_StrictlyDominates tests strict dominance
func TestDominatorTree_StrictlyDominates(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "add", Length: 3},
		{Address: 0x1006, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	// no block strictly dominates itself
	for id := range cfg.Blocks {
		if dt.StrictlyDominates(id, id) {
			t.Errorf("block %d should not strictly dominate itself", id)
		}
	}

	// if a strictly dominates b, then a dominates b
	for a := range cfg.Blocks {
		for b := range cfg.Blocks {
			if dt.StrictlyDominates(a, b) {
				if !dt.Dominates(a, b) {
					t.Errorf("block %d strictly dominates %d but does not dominate it", a, b)
				}

				if a == b {
					t.Errorf("block %d strictly dominates itself (impossible)", a)
				}
			}
		}
	}
}

// TestDominatorTree_GetImmediateDominator tests idom queries
func TestDominatorTree_GetImmediateDominator(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "add", Length: 3},
		{Address: 0x1006, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	// every block except entry should have an idom
	for id := range cfg.Blocks {
		idom, exists := dt.GetImmediateDominator(id)

		if id == cfg.Entry {
			// entry's idom is itself
			if !exists || idom != id {
				t.Errorf("entry block idom should be itself")
			}
		} else {
			if !exists {
				t.Errorf("block %d should have an immediate dominator", id)
			}

			// idom should dominate the block
			if !dt.Dominates(idom, id) {
				t.Errorf("idom %d should dominate block %d", idom, id)
			}
		}
	}
}

// TestDominatorTree_GetChildren tests children mapping
func TestDominatorTree_GetChildren(t *testing.T) {
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

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	// verify children consistency with idom
	for parent, children := range dt.Children {
		for _, child := range children {
			idom, exists := dt.GetImmediateDominator(child)
			if !exists {
				t.Errorf("child %d has no idom", child)
				continue
			}

			if idom != parent {
				t.Errorf("child %d has idom %d but listed as child of %d", child, idom, parent)
			}
		}
	}

	// verify all non-entry blocks appear as children
	childCount := 0
	for _, children := range dt.Children {
		childCount += len(children)
	}

	// should have n-1 children total (all blocks except entry)
	expectedChildren := len(cfg.Blocks) - 1
	if childCount != expectedChildren {
		t.Errorf("expected %d total children, got %d", expectedChildren, childCount)
	}
}

// TestDominatorTree_DFSNumbering tests dfs numbering
func TestDominatorTree_DFSNumbering(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "add", Length: 3},
		{Address: 0x1006, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	// entry should have dfs number 0
	entryNum, exists := dt.GetDFSNumber(cfg.Entry)
	if !exists {
		t.Error("entry block should have dfs number")
	}
	if entryNum != 0 {
		t.Errorf("entry dfs number should be 0, got %d", entryNum)
	}

	// all reachable blocks should have unique dfs numbers
	seen := make(map[int]BlockID)
	for id := range cfg.Blocks {
		num, exists := dt.GetDFSNumber(id)
		if !exists {
			t.Errorf("block %d should have dfs number", id)
			continue
		}

		if prevID, duplicate := seen[num]; duplicate {
			t.Errorf("duplicate dfs number %d for blocks %d and %d", num, prevID, id)
		}
		seen[num] = id
	}
}

// TestDominatorTree_GetDominatorPath tests dominator path extraction
func TestDominatorTree_GetDominatorPath(t *testing.T) {
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

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	// get path for each block
	for id := range cfg.Blocks {
		path := dt.GetDominatorPath(id)

		if len(path) == 0 {
			t.Errorf("block %d should have non-empty dominator path", id)
			continue
		}

		// first element should be the block itself
		if path[0] != id {
			t.Errorf("dominator path should start with block %d, got %d", id, path[0])
		}

		// last element should be entry
		if path[len(path)-1] != cfg.Entry {
			t.Errorf("dominator path should end with entry %d, got %d", cfg.Entry, path[len(path)-1])
		}

		// verify each step is valid idom relationship
		for i := 0; i < len(path)-1; i++ {
			current := path[i]
			next := path[i+1]

			idom, exists := dt.GetImmediateDominator(current)
			if !exists {
				t.Errorf("block %d in path should have idom", current)
				continue
			}

			if idom != next {
				t.Errorf("path step invalid: idom of %d is %d, but next in path is %d", current, idom, next)
			}
		}
	}
}

// TestDominatorTree_EmptyCFG tests error handling for empty cfg
func TestDominatorTree_EmptyCFG(t *testing.T) {
	builder := NewCFGBuilder()

	// try to compute dominators without building cfg
	_, err := builder.ComputeDominators()
	if err == nil {
		t.Error("should return error for empty cfg")
	}
}

// TestDominatorTree_NestedLoops tests dominator tree for nested loops
func TestDominatorTree_NestedLoops(t *testing.T) {
	// create nested loop structure
	instructions := []*disasm.Instruction{
		// outer loop header
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1006,
			Mnemonic: "jge",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1016, Size: disasm.Size32},
			},
		},
		// inner loop header
		{Address: 0x1008, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x100b,
			Mnemonic: "jge",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1012, Size: disasm.Size32},
			},
		},
		// inner loop body
		{Address: 0x100d, Mnemonic: "add", Length: 3},
		{
			Address:  0x1010,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1008, Size: disasm.Size32},
			},
		},
		// outer loop body (after inner)
		{Address: 0x1012, Mnemonic: "inc", Length: 2},
		{
			Address:  0x1014,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x1003, Size: disasm.Size32},
			},
		},
		// exit
		{Address: 0x1016, Mnemonic: "ret", Length: 1},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("failed to compute dominators: %v", err)
	}

	// verify dominator tree correctness
	if err := dt.VerifyDominatorTree(); err != nil {
		t.Errorf("dominator tree verification failed: %v", err)
	}

	// verify entry dominates all
	for id := range cfg.Blocks {
		if !dt.Dominates(cfg.Entry, id) {
			t.Errorf("entry should dominate all blocks, failed for %d", id)
		}
	}

	// verify tree depth is reasonable for nested structure
	depth := dt.GetDominatorTreeDepth()
	if depth < 2 {
		t.Errorf("nested loops should have dominator tree depth >= 2, got %d", depth)
	}
}
