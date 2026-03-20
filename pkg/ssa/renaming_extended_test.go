package ssa

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

func TestRenaming_IntrinsicInstruction(t *testing.T) {
	function := &ir.Function{
		Name:       "test_intrinsic",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: false}

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   ir.Variable{Name: "x", Type: i32},
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size4, Signed: true}},
			},
			&ir.Intrinsic{
				Dest: &ir.Variable{Name: "result", Type: i64},
				Name: "bswap",
				Args: []ir.Expression{
					&ir.VariableExpr{Var: ir.Variable{Name: "x", Type: i32}},
				},
			},
			&ir.Return{
				Value: &ir.Variable{Name: "result", Type: i64},
			},
		},
		Predecessors: []ir.BlockID{},
		Successors:   []ir.BlockID{},
	}

	function.Blocks[0] = block

	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0})

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom[0] = 0
	domTree.Children[0] = []cfg.BlockID{}

	transformer := NewTransformer(function, cfgGraph, domTree)
	err := transformer.TransformToSSA()
	if err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	assign, ok := block.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[0])
	}
	if assign.Dest.Version != 1 {
		t.Errorf("expected x_1, got x_%d", assign.Dest.Version)
	}

	intrinsic, ok := block.Instructions[1].(*ir.Intrinsic)
	if !ok {
		t.Fatalf("expected *ir.Intrinsic, got %T", block.Instructions[1])
	}
	if intrinsic.Dest.Version != 1 {
		t.Errorf("expected result_1, got result_%d", intrinsic.Dest.Version)
	}
	argExpr, ok := intrinsic.Args[0].(*ir.VariableExpr)
	if !ok {
		t.Fatalf("expected *ir.VariableExpr in intrinsic arg, got %T", intrinsic.Args[0])
	}
	if argExpr.Var.Version != 1 {
		t.Errorf("expected x_1 in intrinsic arg, got x_%d", argExpr.Var.Version)
	}

	ret, ok := block.Instructions[2].(*ir.Return)
	if !ok {
		t.Fatalf("expected *ir.Return, got %T", block.Instructions[2])
	}
	if ret.Value.Version != 1 {
		t.Errorf("expected result_1 in return, got result_%d", ret.Value.Version)
	}
}

func TestRenaming_SubRegisterExtract(t *testing.T) {
	function := &ir.Function{
		Name:       "test_extract",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	i64 := ir.IntType{Width: ir.Size8, Signed: false}
	i32 := ir.IntType{Width: ir.Size4, Signed: false}

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   ir.Variable{Name: "rax", Type: i64},
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0xDEADBEEF, Width: ir.Size8}},
			},
			&ir.Assign{
				Dest: ir.Variable{Name: "eax", Type: i32},
				Source: &ir.Extract{
					Source: ir.Variable{Name: "rax", Type: i64},
					Offset: 0,
					Size:   ir.Size4,
				},
			},
			&ir.Return{
				Value: &ir.Variable{Name: "eax", Type: i32},
			},
		},
		Predecessors: []ir.BlockID{},
		Successors:   []ir.BlockID{},
	}

	function.Blocks[0] = block

	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0})

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom[0] = 0
	domTree.Children[0] = []cfg.BlockID{}

	transformer := NewTransformer(function, cfgGraph, domTree)
	err := transformer.TransformToSSA()
	if err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	assign1, ok := block.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[0])
	}
	if assign1.Dest.Version != 1 {
		t.Errorf("expected rax_1, got rax_%d", assign1.Dest.Version)
	}

	assign2, ok := block.Instructions[1].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[1])
	}
	if assign2.Dest.Version != 1 {
		t.Errorf("expected eax_1, got eax_%d", assign2.Dest.Version)
	}
	extract, ok := assign2.Source.(*ir.Extract)
	if !ok {
		t.Fatalf("expected *ir.Extract, got %T", assign2.Source)
	}
	if extract.Source.Version != 1 {
		t.Errorf("expected rax_1 in extract source, got rax_%d", extract.Source.Version)
	}
}

func TestRenaming_SubRegisterInsert(t *testing.T) {
	function := &ir.Function{
		Name:       "test_insert",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	i64 := ir.IntType{Width: ir.Size8, Signed: false}
	i8 := ir.IntType{Width: ir.Size1, Signed: false}

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   ir.Variable{Name: "rax", Type: i64},
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0xFF00, Width: ir.Size8}},
			},
			&ir.Assign{
				Dest:   ir.Variable{Name: "val", Type: i8},
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x42, Width: ir.Size1}},
			},
			&ir.Assign{
				Dest: ir.Variable{Name: "rax", Type: i64},
				Source: &ir.Insert{
					Dest:   ir.Variable{Name: "rax", Type: i64},
					Value:  &ir.VariableExpr{Var: ir.Variable{Name: "val", Type: i8}},
					Offset: 0,
					Size:   ir.Size1,
				},
			},
			&ir.Return{
				Value: &ir.Variable{Name: "rax", Type: i64},
			},
		},
		Predecessors: []ir.BlockID{},
		Successors:   []ir.BlockID{},
	}

	function.Blocks[0] = block

	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0})

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom[0] = 0
	domTree.Children[0] = []cfg.BlockID{}

	transformer := NewTransformer(function, cfgGraph, domTree)
	err := transformer.TransformToSSA()
	if err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	// rax_1 = 0xFF00
	assign1, ok := block.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[0])
	}
	if assign1.Dest.Version != 1 || assign1.Dest.Name != "rax" {
		t.Errorf("expected rax_1, got %s_%d", assign1.Dest.Name, assign1.Dest.Version)
	}

	// val_1 = 0x42
	assign2, ok := block.Instructions[1].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[1])
	}
	if assign2.Dest.Version != 1 || assign2.Dest.Name != "val" {
		t.Errorf("expected val_1, got %s_%d", assign2.Dest.Name, assign2.Dest.Version)
	}

	// rax_2 = insert(rax_1, val_1, 0, 1)
	assign3, ok := block.Instructions[2].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[2])
	}
	if assign3.Dest.Version != 2 || assign3.Dest.Name != "rax" {
		t.Errorf("expected rax_2, got %s_%d", assign3.Dest.Name, assign3.Dest.Version)
	}
	insert, ok := assign3.Source.(*ir.Insert)
	if !ok {
		t.Fatalf("expected *ir.Insert, got %T", assign3.Source)
	}
	if insert.Dest.Version != 1 {
		t.Errorf("expected rax_1 in insert dest, got rax_%d", insert.Dest.Version)
	}
	valExpr, ok := insert.Value.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("expected *ir.VariableExpr in insert value, got %T", insert.Value)
	}
	if valExpr.Var.Version != 1 {
		t.Errorf("expected val_1 in insert value, got val_%d", valExpr.Var.Version)
	}

	// return rax_2
	ret, ok := block.Instructions[3].(*ir.Return)
	if !ok {
		t.Fatalf("expected *ir.Return, got %T", block.Instructions[3])
	}
	if ret.Value.Version != 2 {
		t.Errorf("expected rax_2 in return, got rax_%d", ret.Value.Version)
	}
}

func TestRenaming_SubRegisterZeroExtend(t *testing.T) {
	function := &ir.Function{
		Name:       "test_zeroextend",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	i32 := ir.IntType{Width: ir.Size4, Signed: false}
	i64 := ir.IntType{Width: ir.Size8, Signed: false}

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   ir.Variable{Name: "eax", Type: i32},
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 100, Width: ir.Size4}},
			},
			&ir.Assign{
				Dest: ir.Variable{Name: "rax", Type: i64},
				Source: &ir.ZeroExtend{
					Source:   ir.Variable{Name: "eax", Type: i32},
					FromSize: ir.Size4,
					ToSize:   ir.Size8,
				},
			},
			&ir.Return{
				Value: &ir.Variable{Name: "rax", Type: i64},
			},
		},
		Predecessors: []ir.BlockID{},
		Successors:   []ir.BlockID{},
	}

	function.Blocks[0] = block

	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0})

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom[0] = 0
	domTree.Children[0] = []cfg.BlockID{}

	transformer := NewTransformer(function, cfgGraph, domTree)
	err := transformer.TransformToSSA()
	if err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	// eax_1 = 100
	assign1, ok := block.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[0])
	}
	if assign1.Dest.Version != 1 {
		t.Errorf("expected eax_1, got eax_%d", assign1.Dest.Version)
	}

	// rax_1 = zeroextend(eax_1, 4, 8)
	assign2, ok := block.Instructions[1].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[1])
	}
	if assign2.Dest.Version != 1 {
		t.Errorf("expected rax_1, got rax_%d", assign2.Dest.Version)
	}
	ze, ok := assign2.Source.(*ir.ZeroExtend)
	if !ok {
		t.Fatalf("expected *ir.ZeroExtend, got %T", assign2.Source)
	}
	if ze.Source.Version != 1 {
		t.Errorf("expected eax_1 in zeroextend source, got eax_%d", ze.Source.Version)
	}
}

func TestRenaming_LoadExpr(t *testing.T) {
	function := &ir.Function{
		Name:       "test_loadexpr",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	i64 := ir.IntType{Width: ir.Size8, Signed: false}
	ptrType := ir.PointerType{Pointee: i64}

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   ir.Variable{Name: "base", Type: ptrType},
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x400000, Width: ir.Size8}},
			},
			&ir.Assign{
				Dest: ir.Variable{Name: "val", Type: i64},
				Source: &ir.LoadExpr{
					Address: &ir.VariableExpr{Var: ir.Variable{Name: "base", Type: ptrType}},
					Size:    ir.Size8,
				},
			},
			&ir.Return{
				Value: &ir.Variable{Name: "val", Type: i64},
			},
		},
		Predecessors: []ir.BlockID{},
		Successors:   []ir.BlockID{},
	}

	function.Blocks[0] = block

	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0})

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom[0] = 0
	domTree.Children[0] = []cfg.BlockID{}

	transformer := NewTransformer(function, cfgGraph, domTree)
	err := transformer.TransformToSSA()
	if err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	// base_1 = 0x400000
	assign1, ok := block.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[0])
	}
	if assign1.Dest.Version != 1 {
		t.Errorf("expected base_1, got base_%d", assign1.Dest.Version)
	}

	// val_1 = *(uint64_t*)(base_1)
	assign2, ok := block.Instructions[1].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[1])
	}
	if assign2.Dest.Version != 1 {
		t.Errorf("expected val_1, got val_%d", assign2.Dest.Version)
	}
	loadExpr, ok := assign2.Source.(*ir.LoadExpr)
	if !ok {
		t.Fatalf("expected *ir.LoadExpr, got %T", assign2.Source)
	}
	addrExpr, ok := loadExpr.Address.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("expected *ir.VariableExpr in loadexpr address, got %T", loadExpr.Address)
	}
	if addrExpr.Var.Version != 1 {
		t.Errorf("expected base_1 in loadexpr address, got base_%d", addrExpr.Var.Version)
	}
}

func TestRenaming_LoopWithBackedge(t *testing.T) {
	function := &ir.Function{
		Name:       "test_loop",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	i32 := ir.IntType{Width: ir.Size4, Signed: true}

	// bb0: i = 0; goto bb1
	bb0 := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   ir.Variable{Name: "i", Type: i32},
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size4, Signed: true}},
			},
			&ir.Jump{Target: 1},
		},
		Predecessors: []ir.BlockID{},
		Successors:   []ir.BlockID{1},
	}

	// bb1: (phi for i); if i < 10 goto bb2 else goto bb3
	bb1 := &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Branch{
				Condition: &ir.BinaryOp{
					Op:    ir.BinOpLt,
					Left:  &ir.VariableExpr{Var: ir.Variable{Name: "i", Type: i32}},
					Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 10, Width: ir.Size4, Signed: true}},
				},
				TrueTarget:  2,
				FalseTarget: 3,
			},
		},
		Predecessors: []ir.BlockID{0, 2},
		Successors:   []ir.BlockID{2, 3},
	}

	// bb2: i = i + 1; goto bb1
	bb2 := &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: ir.Variable{Name: "i", Type: i32},
				Source: &ir.BinaryOp{
					Op:    ir.BinOpAdd,
					Left:  &ir.VariableExpr{Var: ir.Variable{Name: "i", Type: i32}},
					Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size4, Signed: true}},
				},
			},
			&ir.Jump{Target: 1},
		},
		Predecessors: []ir.BlockID{1},
		Successors:   []ir.BlockID{1},
	}

	// bb3: return i
	bb3 := &ir.BasicBlock{
		ID: 3,
		Instructions: []ir.IRInstruction{
			&ir.Return{
				Value: &ir.Variable{Name: "i", Type: i32},
			},
		},
		Predecessors: []ir.BlockID{1},
		Successors:   []ir.BlockID{},
	}

	function.Blocks[0] = bb0
	function.Blocks[1] = bb1
	function.Blocks[2] = bb2
	function.Blocks[3] = bb3

	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0, Successors: []cfg.BlockID{1}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0, 2}, Successors: []cfg.BlockID{2, 3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{1}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{1}})

	// dominator tree: 0 dominates 1, 1 dominates 2 and 3
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom[0] = 0
	domTree.Idom[1] = 0
	domTree.Idom[2] = 1
	domTree.Idom[3] = 1
	domTree.Children[0] = []cfg.BlockID{1}
	domTree.Children[1] = []cfg.BlockID{2, 3}
	domTree.Children[2] = []cfg.BlockID{}
	domTree.Children[3] = []cfg.BlockID{}

	transformer := NewTransformer(function, cfgGraph, domTree)
	err := transformer.TransformToSSA()
	if err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	// bb0: i_1 = 0
	assign0, ok := bb0.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("bb0: expected *ir.Assign, got %T", bb0.Instructions[0])
	}
	if assign0.Dest.Version != 1 {
		t.Errorf("bb0: expected i_1, got i_%d", assign0.Dest.Version)
	}

	// bb1 should have phi-node: i_2 = phi [bb0: i_1, bb2: i_3]
	phi, ok := bb1.Instructions[0].(*ir.Phi)
	if !ok {
		t.Fatalf("bb1: expected *ir.Phi as first instruction, got %T", bb1.Instructions[0])
	}
	if phi.Dest.Name != "i" {
		t.Errorf("bb1 phi: expected variable 'i', got '%s'", phi.Dest.Name)
	}
	if phi.Dest.Version != 2 {
		t.Errorf("bb1 phi: expected i_2, got i_%d", phi.Dest.Version)
	}

	// phi sources: bb0 -> i_1, bb2 -> i_3
	for _, src := range phi.Sources {
		switch src.Block {
		case 0:
			if src.Var.Version != 1 {
				t.Errorf("phi source from bb0: expected i_1, got i_%d", src.Var.Version)
			}
		case 2:
			if src.Var.Version != 3 {
				t.Errorf("phi source from bb2: expected i_3, got i_%d", src.Var.Version)
			}
		}
	}

	// bb2: i_3 = i_2 + 1
	assign2, ok := bb2.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("bb2: expected *ir.Assign, got %T", bb2.Instructions[0])
	}
	if assign2.Dest.Version != 3 {
		t.Errorf("bb2: expected i_3, got i_%d", assign2.Dest.Version)
	}
	binOp, ok := assign2.Source.(*ir.BinaryOp)
	if !ok {
		t.Fatalf("bb2: expected *ir.BinaryOp, got %T", assign2.Source)
	}
	useExpr, ok := binOp.Left.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("bb2: expected *ir.VariableExpr, got %T", binOp.Left)
	}
	if useExpr.Var.Version != 2 {
		t.Errorf("bb2 use: expected i_2, got i_%d", useExpr.Var.Version)
	}

	// bb3: return i_2
	ret, ok := bb3.Instructions[0].(*ir.Return)
	if !ok {
		t.Fatalf("bb3: expected *ir.Return, got %T", bb3.Instructions[0])
	}
	if ret.Value.Version != 2 {
		t.Errorf("bb3 return: expected i_2, got i_%d", ret.Value.Version)
	}
}

func TestRenaming_StoreInstruction(t *testing.T) {
	function := &ir.Function{
		Name:       "test_store",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	i64 := ir.IntType{Width: ir.Size8, Signed: false}
	ptrType := ir.PointerType{Pointee: i64}

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   ir.Variable{Name: "ptr", Type: ptrType},
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x1000, Width: ir.Size8}},
			},
			&ir.Assign{
				Dest:   ir.Variable{Name: "val", Type: i64},
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 99, Width: ir.Size8}},
			},
			&ir.Store{
				Address: &ir.VariableExpr{Var: ir.Variable{Name: "ptr", Type: ptrType}},
				Value:   &ir.VariableExpr{Var: ir.Variable{Name: "val", Type: i64}},
				Size:    ir.Size8,
			},
		},
		Predecessors: []ir.BlockID{},
		Successors:   []ir.BlockID{},
	}

	function.Blocks[0] = block

	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0})

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom[0] = 0
	domTree.Children[0] = []cfg.BlockID{}

	transformer := NewTransformer(function, cfgGraph, domTree)
	err := transformer.TransformToSSA()
	if err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	store, ok := block.Instructions[2].(*ir.Store)
	if !ok {
		t.Fatalf("expected *ir.Store, got %T", block.Instructions[2])
	}
	addrExpr, ok := store.Address.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("expected *ir.VariableExpr in store address, got %T", store.Address)
	}
	if addrExpr.Var.Version != 1 {
		t.Errorf("expected ptr_1 in store address, got ptr_%d", addrExpr.Var.Version)
	}
	valExpr, ok := store.Value.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("expected *ir.VariableExpr in store value, got %T", store.Value)
	}
	if valExpr.Var.Version != 1 {
		t.Errorf("expected val_1 in store value, got val_%d", valExpr.Var.Version)
	}
}
