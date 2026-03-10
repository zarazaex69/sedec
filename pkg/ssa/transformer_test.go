package ssa

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// TestTransformer_LinearCode tests phi-node placement for linear code (no branches)
// linear code should have no phi-nodes since there are no merge points
func TestTransformer_LinearCode(t *testing.T) {
	// create simple linear cfg: entry -> block1 -> exit
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0

	// create blocks
	entry := &cfg.BasicBlock{ID: 0, Predecessors: []cfg.BlockID{}, Successors: []cfg.BlockID{1}}
	block1 := &cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{2}}
	exit := &cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{}}

	cfgGraph.AddBlock(entry)
	cfgGraph.AddBlock(block1)
	cfgGraph.AddBlock(exit)
	cfgGraph.AddEdge(0, 1, cfg.EdgeTypeFallthrough)
	cfgGraph.AddEdge(1, 2, cfg.EdgeTypeFallthrough)

	// create ir function with linear code
	// x = 1
	// x = x + 1
	// return x
	function := &ir.Function{
		Name: "linear",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8, Signed: true}},
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
					},
				},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest: ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8, Signed: true}},
						Source: ir.BinaryOp{
							Op:    ir.BinOpAdd,
							Left:  ir.VariableExpr{Var: ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8, Signed: true}}},
							Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
						},
					},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{2},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Return{
						Value: &ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8, Signed: true}},
					},
				},
				Predecessors: []ir.BlockID{1},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	// create mock dominator tree
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{
		0: 0, // entry dominates itself
		1: 0, // entry dominates block1
		2: 1, // block1 dominates exit
	}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{
		0: {1},
		1: {2},
		2: {},
	}

	// create transformer and run ssa transformation
	transformer := NewTransformer(function, cfgGraph, domTree)
	err := transformer.TransformToSSA()
	if err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	// verify no phi-nodes placed (linear code has no merge points)
	phiCount := transformer.GetPhiNodeCount()
	if phiCount != 0 {
		t.Errorf("expected 0 phi-nodes for linear code, got %d", phiCount)
	}
}

// TestTransformer_IfThenElse tests phi-node placement for if-then-else pattern
// merge point after conditional should have phi-node for variables defined in both branches
func TestTransformer_IfThenElse(t *testing.T) {
	// create if-then-else cfg:
	//   entry (block 0)
	//     |
	//     v
	//   condition (block 1)
	//    / \
	//   /   \
	//  v     v
	// then  else (blocks 2, 3)
	//  \     /
	//   \   /
	//    v v
	//   merge (block 4)
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0

	entry := &cfg.BasicBlock{ID: 0, Predecessors: []cfg.BlockID{}, Successors: []cfg.BlockID{1}}
	condition := &cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{2, 3}}
	thenBlock := &cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{4}}
	elseBlock := &cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{4}}
	merge := &cfg.BasicBlock{ID: 4, Predecessors: []cfg.BlockID{2, 3}, Successors: []cfg.BlockID{}}

	cfgGraph.AddBlock(entry)
	cfgGraph.AddBlock(condition)
	cfgGraph.AddBlock(thenBlock)
	cfgGraph.AddBlock(elseBlock)
	cfgGraph.AddBlock(merge)

	cfgGraph.AddEdge(0, 1, cfg.EdgeTypeFallthrough)
	cfgGraph.AddEdge(1, 2, cfg.EdgeTypeConditional)
	cfgGraph.AddEdge(1, 3, cfg.EdgeTypeConditional)
	cfgGraph.AddEdge(2, 4, cfg.EdgeTypeFallthrough)
	cfgGraph.AddEdge(3, 4, cfg.EdgeTypeFallthrough)

	// create ir function with if-then-else
	// if (cond) { x = 1; } else { x = 2; }
	// return x;
	function := &ir.Function{
		Name: "if_then_else",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID:           0,
				Instructions: []ir.IRInstruction{},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Branch{
						Condition:   ir.VariableExpr{Var: ir.Variable{Name: "cond", Type: ir.BoolType{}}},
						TrueTarget:  2,
						FalseTarget: 3,
					},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{2, 3},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8, Signed: true}},
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
					},
				},
				Predecessors: []ir.BlockID{1},
				Successors:   []ir.BlockID{4},
			},
			3: {
				ID: 3,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8, Signed: true}},
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 2, Width: ir.Size8, Signed: true}},
					},
				},
				Predecessors: []ir.BlockID{1},
				Successors:   []ir.BlockID{4},
			},
			4: {
				ID: 4,
				Instructions: []ir.IRInstruction{
					&ir.Return{
						Value: &ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8, Signed: true}},
					},
				},
				Predecessors: []ir.BlockID{2, 3},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	// create dominator tree
	// entry dominates all, condition dominates then/else/merge, then/else dominate nothing
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{
		0: 0,
		1: 0,
		2: 1,
		3: 1,
		4: 1,
	}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{
		0: {1},
		1: {2, 3, 4},
		2: {},
		3: {},
		4: {},
	}

	// create transformer and run ssa transformation
	transformer := NewTransformer(function, cfgGraph, domTree)
	err := transformer.TransformToSSA()
	if err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	// verify phi-node placed at merge block for variable x
	phiCount := transformer.GetPhiNodeCount()
	if phiCount != 1 {
		t.Errorf("expected 1 phi-node for if-then-else, got %d", phiCount)
	}

	// verify phi-node is for variable x
	varsWithPhi := transformer.GetVariablesWithPhiNodes()
	if len(varsWithPhi) != 1 || varsWithPhi[0] != "x" {
		t.Errorf("expected phi-node for variable 'x', got %v", varsWithPhi)
	}

	// verify phi-node is at merge block (block 4)
	phiLocations := transformer.GetPhiNodeLocations("x")
	if len(phiLocations) != 1 || phiLocations[0] != 4 {
		t.Errorf("expected phi-node at block 4, got blocks %v", phiLocations)
	}

	// verify phi-node is inserted at beginning of merge block
	mergeBlock := function.Blocks[4]
	if len(mergeBlock.Instructions) < 1 {
		t.Fatal("merge block has no instructions")
	}

	firstInstr := mergeBlock.Instructions[0]
	phi, ok := firstInstr.(*ir.Phi)
	if !ok {
		t.Fatalf("first instruction in merge block is not phi-node, got %T", firstInstr)
	}

	// verify phi-node has correct structure
	if phi.Dest.Name != "x" {
		t.Errorf("phi-node dest is %s, expected 'x'", phi.Dest.Name)
	}

	if len(phi.Sources) != 2 {
		t.Errorf("phi-node has %d sources, expected 2", len(phi.Sources))
	}
}

// TestTransformer_WhileLoop tests phi-node placement for while loop
// loop header should have phi-node for variables modified in loop body
func TestTransformer_WhileLoop(t *testing.T) {
	// create while loop cfg:
	//   entry (block 0)
	//     |
	//     v
	//   header (block 1) <--+
	//     |                |
	//     v                |
	//   body (block 2) ----+
	//     |
	//     v
	//   exit (block 3)
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0

	entry := &cfg.BasicBlock{ID: 0, Predecessors: []cfg.BlockID{}, Successors: []cfg.BlockID{1}}
	header := &cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0, 2}, Successors: []cfg.BlockID{2, 3}}
	body := &cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{1}}
	exit := &cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{}}

	cfgGraph.AddBlock(entry)
	cfgGraph.AddBlock(header)
	cfgGraph.AddBlock(body)
	cfgGraph.AddBlock(exit)

	cfgGraph.AddEdge(0, 1, cfg.EdgeTypeFallthrough)
	cfgGraph.AddEdge(1, 2, cfg.EdgeTypeConditional)
	cfgGraph.AddEdge(1, 3, cfg.EdgeTypeConditional)
	cfgGraph.AddEdge(2, 1, cfg.EdgeTypeFallthrough) // back-edge

	// create ir function with while loop
	// x = 0;
	// while (x < 10) { x = x + 1; }
	// return x;
	function := &ir.Function{
		Name: "while_loop",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8, Signed: true}},
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size8, Signed: true}},
					},
				},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Branch{
						Condition: ir.BinaryOp{
							Op:    ir.BinOpLt,
							Left:  ir.VariableExpr{Var: ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8, Signed: true}}},
							Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 10, Width: ir.Size8, Signed: true}},
						},
						TrueTarget:  2,
						FalseTarget: 3,
					},
				},
				Predecessors: []ir.BlockID{0, 2},
				Successors:   []ir.BlockID{2, 3},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest: ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8, Signed: true}},
						Source: ir.BinaryOp{
							Op:    ir.BinOpAdd,
							Left:  ir.VariableExpr{Var: ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8, Signed: true}}},
							Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
						},
					},
				},
				Predecessors: []ir.BlockID{1},
				Successors:   []ir.BlockID{1},
			},
			3: {
				ID: 3,
				Instructions: []ir.IRInstruction{
					&ir.Return{
						Value: &ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8, Signed: true}},
					},
				},
				Predecessors: []ir.BlockID{1},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	// create dominator tree
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{
		0: 0,
		1: 0,
		2: 1,
		3: 1,
	}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{
		0: {1},
		1: {2, 3},
		2: {},
		3: {},
	}

	// create transformer and run ssa transformation
	transformer := NewTransformer(function, cfgGraph, domTree)
	err := transformer.TransformToSSA()
	if err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	// verify phi-node placed at loop header for variable x
	phiCount := transformer.GetPhiNodeCount()
	if phiCount != 1 {
		t.Errorf("expected 1 phi-node for while loop, got %d", phiCount)
	}

	// verify phi-node is for variable x
	varsWithPhi := transformer.GetVariablesWithPhiNodes()
	if len(varsWithPhi) != 1 || varsWithPhi[0] != "x" {
		t.Errorf("expected phi-node for variable 'x', got %v", varsWithPhi)
	}

	// verify phi-node is at loop header (block 1)
	phiLocations := transformer.GetPhiNodeLocations("x")
	if len(phiLocations) != 1 || phiLocations[0] != 1 {
		t.Errorf("expected phi-node at block 1 (header), got blocks %v", phiLocations)
	}

	// verify phi-node structure
	headerBlock := function.Blocks[1]
	if len(headerBlock.Instructions) < 1 {
		t.Fatal("header block has no instructions")
	}

	firstInstr := headerBlock.Instructions[0]
	phi, ok := firstInstr.(*ir.Phi)
	if !ok {
		t.Fatalf("first instruction in header is not phi-node, got %T", firstInstr)
	}

	if phi.Dest.Name != "x" {
		t.Errorf("phi-node dest is %s, expected 'x'", phi.Dest.Name)
	}

	// phi-node should have 2 sources: from entry (block 0) and from body (block 2)
	if len(phi.Sources) != 2 {
		t.Errorf("phi-node has %d sources, expected 2", len(phi.Sources))
	}
}

// TestTransformer_NestedLoops tests phi-node placement for nested loops
// both outer and inner loop headers should have phi-nodes
func TestTransformer_NestedLoops(t *testing.T) {
	// create nested loops cfg:
	//   entry (block 0)
	//     |
	//     v
	//   outer_header (block 1) <----+
	//     |                         |
	//     v                         |
	//   inner_header (block 2) <-+  |
	//     |                      |  |
	//     v                      |  |
	//   inner_body (block 3) ----+  |
	//     |                         |
	//     v                         |
	//   outer_body (block 4) -------+
	//     |
	//     v
	//   exit (block 5)
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0

	entry := &cfg.BasicBlock{ID: 0, Predecessors: []cfg.BlockID{}, Successors: []cfg.BlockID{1}}
	outerHeader := &cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0, 4}, Successors: []cfg.BlockID{2, 5}}
	innerHeader := &cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{1, 3}, Successors: []cfg.BlockID{3, 4}}
	innerBody := &cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{2}, Successors: []cfg.BlockID{2}}
	outerBody := &cfg.BasicBlock{ID: 4, Predecessors: []cfg.BlockID{2}, Successors: []cfg.BlockID{1}}
	exit := &cfg.BasicBlock{ID: 5, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{}}

	cfgGraph.AddBlock(entry)
	cfgGraph.AddBlock(outerHeader)
	cfgGraph.AddBlock(innerHeader)
	cfgGraph.AddBlock(innerBody)
	cfgGraph.AddBlock(outerBody)
	cfgGraph.AddBlock(exit)

	cfgGraph.AddEdge(0, 1, cfg.EdgeTypeFallthrough)
	cfgGraph.AddEdge(1, 2, cfg.EdgeTypeConditional)
	cfgGraph.AddEdge(1, 5, cfg.EdgeTypeConditional)
	cfgGraph.AddEdge(2, 3, cfg.EdgeTypeConditional)
	cfgGraph.AddEdge(2, 4, cfg.EdgeTypeConditional)
	cfgGraph.AddEdge(3, 2, cfg.EdgeTypeFallthrough) // inner back-edge
	cfgGraph.AddEdge(4, 1, cfg.EdgeTypeFallthrough) // outer back-edge

	// create ir function with nested loops
	// i = 0;
	// while (i < 10) {
	//   j = 0;
	//   while (j < 5) { j = j + 1; }
	//   i = i + 1;
	// }
	function := &ir.Function{
		Name: "nested_loops",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   ir.Variable{Name: "i", Type: ir.IntType{Width: ir.Size8, Signed: true}},
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size8, Signed: true}},
					},
				},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Branch{
						Condition: ir.BinaryOp{
							Op:    ir.BinOpLt,
							Left:  ir.VariableExpr{Var: ir.Variable{Name: "i", Type: ir.IntType{Width: ir.Size8, Signed: true}}},
							Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 10, Width: ir.Size8, Signed: true}},
						},
						TrueTarget:  2,
						FalseTarget: 5,
					},
				},
				Predecessors: []ir.BlockID{0, 4},
				Successors:   []ir.BlockID{2, 5},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   ir.Variable{Name: "j", Type: ir.IntType{Width: ir.Size8, Signed: true}},
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size8, Signed: true}},
					},
					&ir.Branch{
						Condition: ir.BinaryOp{
							Op:    ir.BinOpLt,
							Left:  ir.VariableExpr{Var: ir.Variable{Name: "j", Type: ir.IntType{Width: ir.Size8, Signed: true}}},
							Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 5, Width: ir.Size8, Signed: true}},
						},
						TrueTarget:  3,
						FalseTarget: 4,
					},
				},
				Predecessors: []ir.BlockID{1, 3},
				Successors:   []ir.BlockID{3, 4},
			},
			3: {
				ID: 3,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest: ir.Variable{Name: "j", Type: ir.IntType{Width: ir.Size8, Signed: true}},
						Source: ir.BinaryOp{
							Op:    ir.BinOpAdd,
							Left:  ir.VariableExpr{Var: ir.Variable{Name: "j", Type: ir.IntType{Width: ir.Size8, Signed: true}}},
							Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
						},
					},
				},
				Predecessors: []ir.BlockID{2},
				Successors:   []ir.BlockID{2},
			},
			4: {
				ID: 4,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest: ir.Variable{Name: "i", Type: ir.IntType{Width: ir.Size8, Signed: true}},
						Source: ir.BinaryOp{
							Op:    ir.BinOpAdd,
							Left:  ir.VariableExpr{Var: ir.Variable{Name: "i", Type: ir.IntType{Width: ir.Size8, Signed: true}}},
							Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
						},
					},
				},
				Predecessors: []ir.BlockID{2},
				Successors:   []ir.BlockID{1},
			},
			5: {
				ID:           5,
				Instructions: []ir.IRInstruction{&ir.Return{}},
				Predecessors: []ir.BlockID{1},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	// create dominator tree
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{
		0: 0,
		1: 0,
		2: 1,
		3: 2,
		4: 2,
		5: 1,
	}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{
		0: {1},
		1: {2, 5},
		2: {3, 4},
		3: {},
		4: {},
		5: {},
	}

	// create transformer and run ssa transformation
	transformer := NewTransformer(function, cfgGraph, domTree)
	err := transformer.TransformToSSA()
	if err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	// verify phi-nodes placed for both i and j
	// note: j gets phi-nodes at both block 1 and block 2 because:
	// - block 2 has multiple predecessors (1, 3) → phi-node at block 2
	// - block 2 also contains definition j=0 → another definition site
	// - phi-node at block 2 is itself a definition → triggers phi at dominance frontier (block 1)
	phiCount := transformer.GetPhiNodeCount()
	if phiCount != 3 {
		t.Errorf("expected 3 phi-nodes for nested loops (i at block 1, j at blocks 1 and 2), got %d", phiCount)
	}

	// verify phi-node for i at outer header (block 1)
	iLocations := transformer.GetPhiNodeLocations("i")
	if len(iLocations) != 1 || iLocations[0] != 1 {
		t.Errorf("expected phi-node for 'i' at block 1, got blocks %v", iLocations)
	}

	// verify phi-nodes for j at both inner header (block 2) and outer header (block 1)
	// this is correct ssa behavior for nested loops with variable redefinition
	jLocations := transformer.GetPhiNodeLocations("j")
	if len(jLocations) != 2 {
		t.Errorf("expected 2 phi-nodes for 'j' (at blocks 1 and 2), got %d at blocks %v", len(jLocations), jLocations)
	}

	// verify j has phi-node at block 2 (inner loop header)
	hasBlock2 := false
	for _, loc := range jLocations {
		if loc == 2 {
			hasBlock2 = true
			break
		}
	}
	if !hasBlock2 {
		t.Errorf("expected phi-node for 'j' at block 2 (inner header), got blocks %v", jLocations)
	}
}

// TestTransformer_MultipleVariables tests phi-node placement for multiple variables
// each variable with multiple definitions should get phi-nodes independently
func TestTransformer_MultipleVariables(t *testing.T) {
	// create cfg with if-then-else modifying multiple variables
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0

	entry := &cfg.BasicBlock{ID: 0, Predecessors: []cfg.BlockID{}, Successors: []cfg.BlockID{1}}
	condition := &cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{2, 3}}
	thenBlock := &cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{4}}
	elseBlock := &cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{4}}
	merge := &cfg.BasicBlock{ID: 4, Predecessors: []cfg.BlockID{2, 3}, Successors: []cfg.BlockID{}}

	cfgGraph.AddBlock(entry)
	cfgGraph.AddBlock(condition)
	cfgGraph.AddBlock(thenBlock)
	cfgGraph.AddBlock(elseBlock)
	cfgGraph.AddBlock(merge)

	cfgGraph.AddEdge(0, 1, cfg.EdgeTypeFallthrough)
	cfgGraph.AddEdge(1, 2, cfg.EdgeTypeConditional)
	cfgGraph.AddEdge(1, 3, cfg.EdgeTypeConditional)
	cfgGraph.AddEdge(2, 4, cfg.EdgeTypeFallthrough)
	cfgGraph.AddEdge(3, 4, cfg.EdgeTypeFallthrough)

	// create ir function modifying x, y, z in both branches
	function := &ir.Function{
		Name: "multiple_vars",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID:           0,
				Instructions: []ir.IRInstruction{},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Branch{
						Condition:   ir.VariableExpr{Var: ir.Variable{Name: "cond", Type: ir.BoolType{}}},
						TrueTarget:  2,
						FalseTarget: 3,
					},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{2, 3},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8, Signed: true}},
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
					},
					&ir.Assign{
						Dest:   ir.Variable{Name: "y", Type: ir.IntType{Width: ir.Size8, Signed: true}},
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 2, Width: ir.Size8, Signed: true}},
					},
					&ir.Assign{
						Dest:   ir.Variable{Name: "z", Type: ir.IntType{Width: ir.Size8, Signed: true}},
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 3, Width: ir.Size8, Signed: true}},
					},
				},
				Predecessors: []ir.BlockID{1},
				Successors:   []ir.BlockID{4},
			},
			3: {
				ID: 3,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8, Signed: true}},
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 10, Width: ir.Size8, Signed: true}},
					},
					&ir.Assign{
						Dest:   ir.Variable{Name: "y", Type: ir.IntType{Width: ir.Size8, Signed: true}},
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 20, Width: ir.Size8, Signed: true}},
					},
					&ir.Assign{
						Dest:   ir.Variable{Name: "z", Type: ir.IntType{Width: ir.Size8, Signed: true}},
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 30, Width: ir.Size8, Signed: true}},
					},
				},
				Predecessors: []ir.BlockID{1},
				Successors:   []ir.BlockID{4},
			},
			4: {
				ID:           4,
				Instructions: []ir.IRInstruction{&ir.Return{}},
				Predecessors: []ir.BlockID{2, 3},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	// create dominator tree
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{
		0: 0,
		1: 0,
		2: 1,
		3: 1,
		4: 1,
	}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{
		0: {1},
		1: {2, 3, 4},
		2: {},
		3: {},
		4: {},
	}

	// create transformer and run ssa transformation
	transformer := NewTransformer(function, cfgGraph, domTree)
	err := transformer.TransformToSSA()
	if err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	// verify phi-nodes placed for x, y, z at merge block
	phiCount := transformer.GetPhiNodeCount()
	if phiCount != 3 {
		t.Errorf("expected 3 phi-nodes (x, y, z), got %d", phiCount)
	}

	// verify all three variables have phi-nodes
	varsWithPhi := transformer.GetVariablesWithPhiNodes()
	if len(varsWithPhi) != 3 {
		t.Errorf("expected 3 variables with phi-nodes, got %d: %v", len(varsWithPhi), varsWithPhi)
	}

	// verify each variable has phi-node at merge block
	for _, varName := range []string{"x", "y", "z"} {
		locations := transformer.GetPhiNodeLocations(varName)
		if len(locations) != 1 || locations[0] != 4 {
			t.Errorf("expected phi-node for '%s' at block 4, got blocks %v", varName, locations)
		}
	}
}

// TestTransformer_SingleDefinition tests that variables with single definition get no phi-nodes
func TestTransformer_SingleDefinition(t *testing.T) {
	// create cfg with if-then-else where variable is only defined in one branch
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0

	entry := &cfg.BasicBlock{ID: 0, Predecessors: []cfg.BlockID{}, Successors: []cfg.BlockID{1}}
	condition := &cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{2, 3}}
	thenBlock := &cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{4}}
	elseBlock := &cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{4}}
	merge := &cfg.BasicBlock{ID: 4, Predecessors: []cfg.BlockID{2, 3}, Successors: []cfg.BlockID{}}

	cfgGraph.AddBlock(entry)
	cfgGraph.AddBlock(condition)
	cfgGraph.AddBlock(thenBlock)
	cfgGraph.AddBlock(elseBlock)
	cfgGraph.AddBlock(merge)

	cfgGraph.AddEdge(0, 1, cfg.EdgeTypeFallthrough)
	cfgGraph.AddEdge(1, 2, cfg.EdgeTypeConditional)
	cfgGraph.AddEdge(1, 3, cfg.EdgeTypeConditional)
	cfgGraph.AddEdge(2, 4, cfg.EdgeTypeFallthrough)
	cfgGraph.AddEdge(3, 4, cfg.EdgeTypeFallthrough)

	// create ir function where x is only defined in then branch
	function := &ir.Function{
		Name: "single_def",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID:           0,
				Instructions: []ir.IRInstruction{},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Branch{
						Condition:   ir.VariableExpr{Var: ir.Variable{Name: "cond", Type: ir.BoolType{}}},
						TrueTarget:  2,
						FalseTarget: 3,
					},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{2, 3},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8, Signed: true}},
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
					},
				},
				Predecessors: []ir.BlockID{1},
				Successors:   []ir.BlockID{4},
			},
			3: {
				ID:           3,
				Instructions: []ir.IRInstruction{}, // no definition of x here
				Predecessors: []ir.BlockID{1},
				Successors:   []ir.BlockID{4},
			},
			4: {
				ID:           4,
				Instructions: []ir.IRInstruction{&ir.Return{}},
				Predecessors: []ir.BlockID{2, 3},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	// create dominator tree
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{
		0: 0,
		1: 0,
		2: 1,
		3: 1,
		4: 1,
	}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{
		0: {1},
		1: {2, 3, 4},
		2: {},
		3: {},
		4: {},
	}

	// create transformer and run ssa transformation
	transformer := NewTransformer(function, cfgGraph, domTree)
	err := transformer.TransformToSSA()
	if err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	// verify no phi-nodes placed (x has only one definition)
	phiCount := transformer.GetPhiNodeCount()
	if phiCount != 0 {
		t.Errorf("expected 0 phi-nodes for single definition, got %d", phiCount)
	}
}
