package ssa

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// TestRenaming_LinearCode tests ssa variable renaming for simple linear code
// verifies that each definition gets a unique version number
func TestRenaming_LinearCode(t *testing.T) {
	// create simple linear ir:
	// bb0:
	//   x = 1
	//   y = x + 2
	//   z = y * 3
	//   return z

	function := &ir.Function{
		Name: "test_linear",
		Signature: ir.FunctionType{
			ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
			Parameters: []ir.Type{},
		},
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	// create basic block
	block := &ir.BasicBlock{
		ID:           0,
		Instructions: []ir.IRInstruction{},
		Predecessors: []ir.BlockID{},
		Successors:   []ir.BlockID{},
	}

	// x = 1
	block.Instructions = append(block.Instructions, &ir.Assign{
		Dest: ir.Variable{
			Name: "x",
			Type: ir.IntType{Width: ir.Size4, Signed: true},
		},
		Source: &ir.ConstantExpr{
			Value: ir.IntConstant{Value: 1, Width: ir.Size4, Signed: true},
		},
	})

	// y = x + 2
	block.Instructions = append(block.Instructions, &ir.Assign{
		Dest: ir.Variable{
			Name: "y",
			Type: ir.IntType{Width: ir.Size4, Signed: true},
		},
		Source: &ir.BinaryOp{
			Op: ir.BinOpAdd,
			Left: &ir.VariableExpr{
				Var: ir.Variable{
					Name: "x",
					Type: ir.IntType{Width: ir.Size4, Signed: true},
				},
			},
			Right: &ir.ConstantExpr{
				Value: ir.IntConstant{Value: 2, Width: ir.Size4, Signed: true},
			},
		},
	})

	// z = y * 3
	block.Instructions = append(block.Instructions, &ir.Assign{
		Dest: ir.Variable{
			Name: "z",
			Type: ir.IntType{Width: ir.Size4, Signed: true},
		},
		Source: &ir.BinaryOp{
			Op: ir.BinOpMul,
			Left: &ir.VariableExpr{
				Var: ir.Variable{
					Name: "y",
					Type: ir.IntType{Width: ir.Size4, Signed: true},
				},
			},
			Right: &ir.ConstantExpr{
				Value: ir.IntConstant{Value: 3, Width: ir.Size4, Signed: true},
			},
		},
	})

	// return z
	block.Instructions = append(block.Instructions, &ir.Return{
		Value: &ir.Variable{
			Name: "z",
			Type: ir.IntType{Width: ir.Size4, Signed: true},
		},
	})

	function.Blocks[0] = block

	// create cfg
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{
		ID:           0,
		Predecessors: []cfg.BlockID{},
		Successors:   []cfg.BlockID{},
	})

	// create dominator tree (trivial for single block)
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom[0] = 0 // entry dominates itself
	domTree.Children[0] = []cfg.BlockID{}

	// create transformer and run ssa transformation
	transformer := NewTransformer(function, cfgGraph, domTree)
	err := transformer.TransformToSSA()
	if err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	// verify ssa properties
	// 1. each definition should have unique version
	// 2. each use should reference correct version

	// check x = 1 (should be x_1)
	assign1, ok := block.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[0])
	}
	if assign1.Dest.Version != 1 {
		t.Errorf("expected x_1, got x_%d", assign1.Dest.Version)
	}

	// check y = x + 2 (should be y_1 = x_1 + 2)
	assign2, ok := block.Instructions[1].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[1])
	}
	if assign2.Dest.Version != 1 {
		t.Errorf("expected y_1, got y_%d", assign2.Dest.Version)
	}
	binOp2, ok := assign2.Source.(*ir.BinaryOp)
	if !ok {
		t.Fatalf("expected *ir.BinaryOp, got %T", assign2.Source)
	}
	varExpr2, ok := binOp2.Left.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("expected *ir.VariableExpr, got %T", binOp2.Left)
	}
	if varExpr2.Var.Version != 1 {
		t.Errorf("expected x_1 in use, got x_%d", varExpr2.Var.Version)
	}

	// check z = y * 3 (should be z_1 = y_1 * 3)
	assign3, ok := block.Instructions[2].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[2])
	}
	if assign3.Dest.Version != 1 {
		t.Errorf("expected z_1, got z_%d", assign3.Dest.Version)
	}
	binOp3, ok := assign3.Source.(*ir.BinaryOp)
	if !ok {
		t.Fatalf("expected *ir.BinaryOp, got %T", assign3.Source)
	}
	varExpr3, ok := binOp3.Left.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("expected *ir.VariableExpr, got %T", binOp3.Left)
	}
	if varExpr3.Var.Version != 1 {
		t.Errorf("expected y_1 in use, got y_%d", varExpr3.Var.Version)
	}

	// check return z (should be return z_1)
	ret, ok := block.Instructions[3].(*ir.Return)
	if !ok {
		t.Fatalf("expected *ir.Return, got %T", block.Instructions[3])
	}
	if ret.Value.Version != 1 {
		t.Errorf("expected z_1 in return, got z_%d", ret.Value.Version)
	}
}

// TestRenaming_MultipleDefinitions tests ssa renaming with multiple definitions of same variable
// verifies that each definition gets incrementing version numbers
func TestRenaming_MultipleDefinitions(t *testing.T) {
	// create ir with multiple definitions:
	// bb0:
	//   x = 1
	//   x = x + 2
	//   x = x * 3
	//   return x

	function := &ir.Function{
		Name:       "test_multiple_defs",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	block := &ir.BasicBlock{
		ID:           0,
		Instructions: []ir.IRInstruction{},
		Predecessors: []ir.BlockID{},
		Successors:   []ir.BlockID{},
	}

	// x = 1
	block.Instructions = append(block.Instructions, &ir.Assign{
		Dest: ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
		Source: &ir.ConstantExpr{
			Value: ir.IntConstant{Value: 1, Width: ir.Size4, Signed: true},
		},
	})

	// x = x + 2
	block.Instructions = append(block.Instructions, &ir.Assign{
		Dest: ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
		Source: &ir.BinaryOp{
			Op: ir.BinOpAdd,
			Left: &ir.VariableExpr{
				Var: ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
			},
			Right: &ir.ConstantExpr{
				Value: ir.IntConstant{Value: 2, Width: ir.Size4, Signed: true},
			},
		},
	})

	// x = x * 3
	block.Instructions = append(block.Instructions, &ir.Assign{
		Dest: ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
		Source: &ir.BinaryOp{
			Op: ir.BinOpMul,
			Left: &ir.VariableExpr{
				Var: ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
			},
			Right: &ir.ConstantExpr{
				Value: ir.IntConstant{Value: 3, Width: ir.Size4, Signed: true},
			},
		},
	})

	// return x
	block.Instructions = append(block.Instructions, &ir.Return{
		Value: &ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
	})

	function.Blocks[0] = block

	// create cfg
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0})

	// create dominator tree
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom[0] = 0
	domTree.Children[0] = []cfg.BlockID{}

	// run ssa transformation
	transformer := NewTransformer(function, cfgGraph, domTree)
	err := transformer.TransformToSSA()
	if err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	// verify version progression: x_1, x_2, x_3
	// x = 1 → x_1 = 1
	assign1, ok := block.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[0])
	}
	if assign1.Dest.Version != 1 {
		t.Errorf("first definition: expected x_1, got x_%d", assign1.Dest.Version)
	}

	// x = x + 2 → x_2 = x_1 + 2
	assign2, ok := block.Instructions[1].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[1])
	}
	if assign2.Dest.Version != 2 {
		t.Errorf("second definition: expected x_2, got x_%d", assign2.Dest.Version)
	}
	binOp2, ok := assign2.Source.(*ir.BinaryOp)
	if !ok {
		t.Fatalf("expected *ir.BinaryOp, got %T", assign2.Source)
	}
	varExpr2, ok := binOp2.Left.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("expected *ir.VariableExpr, got %T", binOp2.Left)
	}
	if varExpr2.Var.Version != 1 {
		t.Errorf("second definition use: expected x_1, got x_%d", varExpr2.Var.Version)
	}

	// x = x * 3 → x_3 = x_2 * 3
	assign3, ok := block.Instructions[2].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[2])
	}
	if assign3.Dest.Version != 3 {
		t.Errorf("third definition: expected x_3, got x_%d", assign3.Dest.Version)
	}
	binOp3, ok := assign3.Source.(*ir.BinaryOp)
	if !ok {
		t.Fatalf("expected *ir.BinaryOp, got %T", assign3.Source)
	}
	varExpr3, ok := binOp3.Left.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("expected *ir.VariableExpr, got %T", binOp3.Left)
	}
	if varExpr3.Var.Version != 2 {
		t.Errorf("third definition use: expected x_2, got x_%d", varExpr3.Var.Version)
	}

	// return x → return x_3
	ret, ok := block.Instructions[3].(*ir.Return)
	if !ok {
		t.Fatalf("expected *ir.Return, got %T", block.Instructions[3])
	}
	if ret.Value.Version != 3 {
		t.Errorf("return: expected x_3, got x_%d", ret.Value.Version)
	}
}

// TestRenaming_PhiNodes tests ssa renaming with phi-nodes
// verifies that phi-node sources are correctly filled with versions from predecessor blocks
func TestRenaming_PhiNodes(t *testing.T) {
	// create if-then-else with phi-node:
	// bb0:
	//   x = 1
	//   if (cond) goto bb1 else goto bb2
	// bb1:
	//   x = 2
	//   goto bb3
	// bb2:
	//   x = 3
	//   goto bb3
	// bb3:
	//   x = phi [bb1: x, bb2: x]
	//   return x

	function := &ir.Function{
		Name:       "test_phi",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	// bb0: x = 1; branch
	bb0 := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size4, Signed: true}},
			},
			&ir.Branch{
				Condition: &ir.VariableExpr{
					Var: ir.Variable{Name: "cond", Type: ir.BoolType{}},
				},
				TrueTarget:  1,
				FalseTarget: 2,
			},
		},
		Predecessors: []ir.BlockID{},
		Successors:   []ir.BlockID{1, 2},
	}

	// bb1: x = 2; jump bb3
	bb1 := &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 2, Width: ir.Size4, Signed: true}},
			},
			&ir.Jump{Target: 3},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{3},
	}

	// bb2: x = 3; jump bb3
	bb2 := &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 3, Width: ir.Size4, Signed: true}},
			},
			&ir.Jump{Target: 3},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{3},
	}

	// bb3: return x (phi-node will be inserted automatically by insertPhiNodes)
	bb3 := &ir.BasicBlock{
		ID: 3,
		Instructions: []ir.IRInstruction{
			&ir.Return{
				Value: &ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
			},
		},
		Predecessors: []ir.BlockID{1, 2},
		Successors:   []ir.BlockID{},
	}

	function.Blocks[0] = bb0
	function.Blocks[1] = bb1
	function.Blocks[2] = bb2
	function.Blocks[3] = bb3

	// create cfg
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0, Successors: []cfg.BlockID{1, 2}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{1, 2}})

	// create dominator tree
	// bb0 dominates all, bb0 is parent of bb1, bb2, bb3
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom[0] = 0
	domTree.Idom[1] = 0
	domTree.Idom[2] = 0
	domTree.Idom[3] = 0
	domTree.Children[0] = []cfg.BlockID{1, 2, 3}
	domTree.Children[1] = []cfg.BlockID{}
	domTree.Children[2] = []cfg.BlockID{}
	domTree.Children[3] = []cfg.BlockID{}

	// run ssa transformation
	transformer := NewTransformer(function, cfgGraph, domTree)
	err := transformer.TransformToSSA()
	if err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	// verify versions:
	// bb0: x_1 = 1
	assign0, ok := bb0.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("bb0: expected *ir.Assign, got %T", bb0.Instructions[0])
	}
	if assign0.Dest.Version != 1 {
		t.Errorf("bb0: expected x_1, got x_%d", assign0.Dest.Version)
	}

	// bb1: x_2 = 2
	assign1, ok := bb1.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("bb1: expected *ir.Assign, got %T", bb1.Instructions[0])
	}
	if assign1.Dest.Version != 2 {
		t.Errorf("bb1: expected x_2, got x_%d", assign1.Dest.Version)
	}

	// bb2: x_3 = 3
	assign2, ok := bb2.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("bb2: expected *ir.Assign, got %T", bb2.Instructions[0])
	}
	if assign2.Dest.Version != 3 {
		t.Errorf("bb2: expected x_3, got x_%d", assign2.Dest.Version)
	}

	// bb3: x_4 = phi [bb1: x_2, bb2: x_3]
	phi, ok := bb3.Instructions[0].(*ir.Phi)
	if !ok {
		t.Fatalf("bb3: expected *ir.Phi, got %T", bb3.Instructions[0])
	}
	if phi.Dest.Version != 4 {
		t.Errorf("bb3 phi dest: expected x_4, got x_%d", phi.Dest.Version)
	}

	// verify phi sources
	for _, src := range phi.Sources {
		switch src.Block {
		case 1:
			if src.Var.Version != 2 {
				t.Errorf("phi source from bb1: expected x_2, got x_%d", src.Var.Version)
			}
		case 2:
			if src.Var.Version != 3 {
				t.Errorf("phi source from bb2: expected x_3, got x_%d", src.Var.Version)
			}
		}
	}

	// bb3: return x_4
	ret, ok := bb3.Instructions[1].(*ir.Return)
	if !ok {
		t.Fatalf("bb3: expected *ir.Return, got %T", bb3.Instructions[1])
	}
	if ret.Value.Version != 4 {
		t.Errorf("bb3 return: expected x_4, got x_%d", ret.Value.Version)
	}
}

// TestRenaming_NestedBlocks tests ssa renaming with nested dominator tree structure
// verifies correct backtracking when exiting nested blocks
func TestRenaming_NestedBlocks(t *testing.T) {
	// create nested structure:
	// bb0:
	//   x = 1
	//   goto bb1
	// bb1:
	//   x = 2
	//   goto bb2
	// bb2:
	//   y = x
	//   goto bb3
	// bb3:
	//   z = x
	//   return z

	function := &ir.Function{
		Name:       "test_nested",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	// bb0: x = 1
	bb0 := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size4, Signed: true}},
			},
			&ir.Jump{Target: 1},
		},
		Successors: []ir.BlockID{1},
	}

	// bb1: x = 2
	bb1 := &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 2, Width: ir.Size4, Signed: true}},
			},
			&ir.Jump{Target: 2},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{2},
	}

	// bb2: y = x
	bb2 := &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: ir.Variable{Name: "y", Type: ir.IntType{Width: ir.Size4, Signed: true}},
				Source: &ir.VariableExpr{
					Var: ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
				},
			},
			&ir.Jump{Target: 3},
		},
		Predecessors: []ir.BlockID{1},
		Successors:   []ir.BlockID{3},
	}

	// bb3: z = x; return z
	bb3 := &ir.BasicBlock{
		ID: 3,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: ir.Variable{Name: "z", Type: ir.IntType{Width: ir.Size4, Signed: true}},
				Source: &ir.VariableExpr{
					Var: ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}},
				},
			},
			&ir.Return{
				Value: &ir.Variable{Name: "z", Type: ir.IntType{Width: ir.Size4, Signed: true}},
			},
		},
		Predecessors: []ir.BlockID{2},
		Successors:   []ir.BlockID{},
	}

	function.Blocks[0] = bb0
	function.Blocks[1] = bb1
	function.Blocks[2] = bb2
	function.Blocks[3] = bb3

	// create cfg
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0, Successors: []cfg.BlockID{1}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{2}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{2}})

	// create dominator tree (linear chain)
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom[0] = 0
	domTree.Idom[1] = 0
	domTree.Idom[2] = 1
	domTree.Idom[3] = 2
	domTree.Children[0] = []cfg.BlockID{1}
	domTree.Children[1] = []cfg.BlockID{2}
	domTree.Children[2] = []cfg.BlockID{3}
	domTree.Children[3] = []cfg.BlockID{}

	// run ssa transformation
	transformer := NewTransformer(function, cfgGraph, domTree)
	err := transformer.TransformToSSA()
	if err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	// verify versions:
	// bb0: x_1 = 1
	assign0, ok := bb0.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("bb0: expected *ir.Assign, got %T", bb0.Instructions[0])
	}
	if assign0.Dest.Version != 1 {
		t.Errorf("bb0: expected x_1, got x_%d", assign0.Dest.Version)
	}

	// bb1: x_2 = 2
	assign1, ok := bb1.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("bb1: expected *ir.Assign, got %T", bb1.Instructions[0])
	}
	if assign1.Dest.Version != 2 {
		t.Errorf("bb1: expected x_2, got x_%d", assign1.Dest.Version)
	}

	// bb2: y_1 = x_2 (x_2 is current version after bb1)
	assign2, ok := bb2.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("bb2: expected *ir.Assign, got %T", bb2.Instructions[0])
	}
	if assign2.Dest.Version != 1 {
		t.Errorf("bb2 dest: expected y_1, got y_%d", assign2.Dest.Version)
	}
	varExpr2, ok := assign2.Source.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("bb2: expected *ir.VariableExpr, got %T", assign2.Source)
	}
	if varExpr2.Var.Version != 2 {
		t.Errorf("bb2 source: expected x_2, got x_%d", varExpr2.Var.Version)
	}

	// bb3: z_1 = x_2 (x_2 still current, no redefinition in bb2)
	assign3, ok := bb3.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("bb3: expected *ir.Assign, got %T", bb3.Instructions[0])
	}
	if assign3.Dest.Version != 1 {
		t.Errorf("bb3 dest: expected z_1, got z_%d", assign3.Dest.Version)
	}
	varExpr3, ok := assign3.Source.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("bb3: expected *ir.VariableExpr, got %T", assign3.Source)
	}
	if varExpr3.Var.Version != 2 {
		t.Errorf("bb3 source: expected x_2, got x_%d", varExpr3.Var.Version)
	}

	// bb3: return z_1
	ret, ok := bb3.Instructions[1].(*ir.Return)
	if !ok {
		t.Fatalf("bb3: expected *ir.Return, got %T", bb3.Instructions[1])
	}
	if ret.Value.Version != 1 {
		t.Errorf("bb3 return: expected z_1, got z_%d", ret.Value.Version)
	}
}
