package ssa

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// Dominance Property Verification Tests
// ============================================================================

// TestDominance_EntryDominatesAll verifies the fundamental dominance property:
// the entry block dominates all reachable blocks.
// after ssa transformation, every use of a versioned variable must be dominated
// by its definition — this is the core correctness guarantee of ssa form.
func TestDominance_EntryDominatesAll(t *testing.T) {
	// create diamond cfg: entry → {left, right} → merge
	// entry defines x, both branches use x, merge uses x via phi
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0, Successors: []cfg.BlockID{1, 2}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{1, 2}})

	fn := &ir.Function{
		Name:       "dominance_test",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	xVar := ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size4, Signed: true}}
	yVar := ir.Variable{Name: "y", Type: ir.IntType{Width: ir.Size4, Signed: true}}

	// entry: x = 1
	fn.Blocks[0] = &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   xVar,
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size4, Signed: true}},
			},
			&ir.Branch{
				Condition:   &ir.VariableExpr{Var: ir.Variable{Name: "cond", Type: ir.BoolType{}}},
				TrueTarget:  1,
				FalseTarget: 2,
			},
		},
		Successors: []ir.BlockID{1, 2},
	}
	// left: y = x + 1
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: yVar,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpAdd,
					Left:  &ir.VariableExpr{Var: xVar},
					Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size4, Signed: true}},
				},
			},
			&ir.Jump{Target: 3},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{3},
	}
	// right: y = x + 2
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: yVar,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpAdd,
					Left:  &ir.VariableExpr{Var: xVar},
					Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 2, Width: ir.Size4, Signed: true}},
				},
			},
			&ir.Jump{Target: 3},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{3},
	}
	// merge: return y
	fn.Blocks[3] = &ir.BasicBlock{
		ID: 3,
		Instructions: []ir.IRInstruction{
			&ir.Return{Value: &yVar},
		},
		Predecessors: []ir.BlockID{1, 2},
	}

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 0, 3: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {1, 2, 3}, 1: {}, 2: {}, 3: {}}

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	// verify ssa property: single definition per variable
	verifySSAProperty(t, fn)

	// verify dominance property: phi-nodes at correct positions
	verifyDominanceProperty(t, fn)

	// x is defined only in entry (block 0), so no phi-node for x
	xLocations := transformer.GetPhiNodeLocations("x")
	if len(xLocations) != 0 {
		t.Errorf("x defined only in entry, should have no phi-nodes, got %v", xLocations)
	}

	// y is defined in both branches (blocks 1, 2), so phi-node at merge (block 3)
	yLocations := transformer.GetPhiNodeLocations("y")
	if len(yLocations) != 1 || yLocations[0] != 3 {
		t.Errorf("y should have phi-node at block 3, got %v", yLocations)
	}

	// verify x_1 is used in both branches (dominance: entry def reaches all blocks)
	leftAssign, ok := fn.Blocks[1].Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("left block: expected *ir.Assign")
	}
	leftBinOp, ok := leftAssign.Source.(*ir.BinaryOp)
	if !ok {
		t.Fatalf("left assign source: expected *ir.BinaryOp")
	}
	leftXExpr, ok := leftBinOp.Left.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("left binop left: expected *ir.VariableExpr")
	}
	if leftXExpr.Var.Version != 1 {
		t.Errorf("left branch: expected x_1, got x_%d", leftXExpr.Var.Version)
	}

	rightAssign, ok := fn.Blocks[2].Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("right block: expected *ir.Assign")
	}
	rightBinOp, ok := rightAssign.Source.(*ir.BinaryOp)
	if !ok {
		t.Fatalf("right assign source: expected *ir.BinaryOp")
	}
	rightXExpr, ok := rightBinOp.Left.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("right binop left: expected *ir.VariableExpr")
	}
	if rightXExpr.Var.Version != 1 {
		t.Errorf("right branch: expected x_1, got x_%d", rightXExpr.Var.Version)
	}
}

// TestDominance_PhiSourceVersions verifies that phi-node sources carry
// the correct ssa versions from their respective predecessor blocks.
// this is the critical correctness property for phi-node renaming.
func TestDominance_PhiSourceVersions(t *testing.T) {
	// create loop: entry → header ↔ body → exit
	// header has phi-node for loop variable i
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0, Successors: []cfg.BlockID{1}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0, 2}, Successors: []cfg.BlockID{2, 3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{1}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{1}})

	fn := &ir.Function{
		Name:       "phi_sources",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	iVar := ir.Variable{Name: "i", Type: ir.IntType{Width: ir.Size4, Signed: true}}

	// entry: i = 0
	fn.Blocks[0] = &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   iVar,
				Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size4, Signed: true}},
			},
			&ir.Jump{Target: 1},
		},
		Successors: []ir.BlockID{1},
	}
	// header: branch i < 10
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Branch{
				Condition: &ir.BinaryOp{
					Op:    ir.BinOpLt,
					Left:  &ir.VariableExpr{Var: iVar},
					Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 10, Width: ir.Size4, Signed: true}},
				},
				TrueTarget:  2,
				FalseTarget: 3,
			},
		},
		Predecessors: []ir.BlockID{0, 2},
		Successors:   []ir.BlockID{2, 3},
	}
	// body: i = i + 1
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: iVar,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpAdd,
					Left:  &ir.VariableExpr{Var: iVar},
					Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size4, Signed: true}},
				},
			},
			&ir.Jump{Target: 1},
		},
		Predecessors: []ir.BlockID{1},
		Successors:   []ir.BlockID{1},
	}
	// exit: return i
	fn.Blocks[3] = &ir.BasicBlock{
		ID: 3,
		Instructions: []ir.IRInstruction{
			&ir.Return{Value: &iVar},
		},
		Predecessors: []ir.BlockID{1},
	}

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 1, 3: 1}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {1}, 1: {2, 3}, 2: {}, 3: {}}

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	verifySSAProperty(t, fn)
	verifyDominanceProperty(t, fn)

	// phi-node must be at header (block 1)
	iLocations := transformer.GetPhiNodeLocations("i")
	if len(iLocations) != 1 || iLocations[0] != 1 {
		t.Fatalf("expected phi-node for i at block 1, got %v", iLocations)
	}

	// get phi-node from header
	headerBlock := fn.Blocks[1]
	phi, ok := headerBlock.Instructions[0].(*ir.Phi)
	if !ok {
		t.Fatalf("header block[0]: expected *ir.Phi, got %T", headerBlock.Instructions[0])
	}

	// phi must have 2 sources: from entry (block 0) and from body (block 2)
	if len(phi.Sources) != 2 {
		t.Fatalf("phi has %d sources, expected 2", len(phi.Sources))
	}

	// find source versions
	sourceVersions := make(map[ir.BlockID]int)
	for _, src := range phi.Sources {
		sourceVersions[src.Block] = src.Var.Version
	}

	// source from entry (block 0): must be i_1 (first definition in entry)
	entryVersion, hasEntry := sourceVersions[0]
	if !hasEntry {
		t.Error("phi missing source from entry block 0")
	} else if entryVersion != 1 {
		t.Errorf("phi source from entry: expected i_1, got i_%d", entryVersion)
	}

	// phi dest is i_2 (created during renaming of header block)
	// body block (child of header in domtree) is processed after header,
	// so body's i = i+1 becomes i_3 = i_2 + 1
	phiDestVersion := phi.Dest.Version
	if phiDestVersion == 0 {
		t.Error("phi dest must have a non-zero ssa version")
	}

	// source from body (block 2): must be the version created in body (phiDestVersion + 1)
	bodyVersion, hasBody := sourceVersions[2]
	if !hasBody {
		t.Error("phi missing source from body block 2")
	} else if bodyVersion != phiDestVersion+1 {
		t.Errorf("phi source from body: expected i_%d (phi_dest+1), got i_%d",
			phiDestVersion+1, bodyVersion)
	}

	// branch condition in header must use phi result (phi dest version)
	branch, ok := headerBlock.Instructions[1].(*ir.Branch)
	if !ok {
		t.Fatalf("header block[1]: expected *ir.Branch, got %T", headerBlock.Instructions[1])
	}
	condBinOp, ok := branch.Condition.(*ir.BinaryOp)
	if !ok {
		t.Fatalf("branch condition: expected *ir.BinaryOp, got %T", branch.Condition)
	}
	condVar, ok := condBinOp.Left.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("condition left: expected *ir.VariableExpr, got %T", condBinOp.Left)
	}
	if condVar.Var.Version != phiDestVersion {
		t.Errorf("loop condition: expected i_%d (phi result), got i_%d",
			phiDestVersion, condVar.Var.Version)
	}
}

// TestDominance_MultiplePhiNodes verifies correct phi-node placement
// when multiple variables require phi-nodes at the same merge point.
func TestDominance_MultiplePhiNodes(t *testing.T) {
	// if-then-else where both branches define a, b, c
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = 0
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 0, Successors: []cfg.BlockID{1, 2}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 1, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 2, Predecessors: []cfg.BlockID{0}, Successors: []cfg.BlockID{3}})
	cfgGraph.AddBlock(&cfg.BasicBlock{ID: 3, Predecessors: []cfg.BlockID{1, 2}})

	fn := &ir.Function{
		Name:       "multi_phi",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	makeIntVar := func(name string) ir.Variable {
		return ir.Variable{Name: name, Type: ir.IntType{Width: ir.Size4, Signed: true}}
	}
	makeConst := func(v int64) *ir.ConstantExpr {
		return &ir.ConstantExpr{Value: ir.IntConstant{Value: v, Width: ir.Size4, Signed: true}}
	}

	fn.Blocks[0] = &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Branch{
				Condition:   &ir.VariableExpr{Var: ir.Variable{Name: "cond", Type: ir.BoolType{}}},
				TrueTarget:  1,
				FalseTarget: 2,
			},
		},
		Successors: []ir.BlockID{1, 2},
	}
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: makeIntVar("a"), Source: makeConst(1)},
			&ir.Assign{Dest: makeIntVar("b"), Source: makeConst(2)},
			&ir.Assign{Dest: makeIntVar("c"), Source: makeConst(3)},
			&ir.Jump{Target: 3},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{3},
	}
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			&ir.Assign{Dest: makeIntVar("a"), Source: makeConst(10)},
			&ir.Assign{Dest: makeIntVar("b"), Source: makeConst(20)},
			&ir.Assign{Dest: makeIntVar("c"), Source: makeConst(30)},
			&ir.Jump{Target: 3},
		},
		Predecessors: []ir.BlockID{0},
		Successors:   []ir.BlockID{3},
	}
	fn.Blocks[3] = &ir.BasicBlock{
		ID:           3,
		Instructions: []ir.IRInstruction{&ir.Return{}},
		Predecessors: []ir.BlockID{1, 2},
	}

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 0, 3: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {1, 2, 3}, 1: {}, 2: {}, 3: {}}

	transformer := NewTransformer(fn, cfgGraph, domTree)
	if err := transformer.TransformToSSA(); err != nil {
		t.Fatalf("TransformToSSA failed: %v", err)
	}

	verifySSAProperty(t, fn)
	verifyDominanceProperty(t, fn)

	// all three variables must have phi-nodes at merge block (3)
	for _, varName := range []string{"a", "b", "c"} {
		locs := transformer.GetPhiNodeLocations(varName)
		if len(locs) != 1 || locs[0] != 3 {
			t.Errorf("variable %s: expected phi-node at block 3, got %v", varName, locs)
		}
	}

	// merge block must start with exactly 3 phi-nodes
	mergeBlock := fn.Blocks[3]
	phiCount := 0
	for _, instr := range mergeBlock.Instructions {
		if _, isPhi := instr.(*ir.Phi); isPhi {
			phiCount++
		}
	}
	if phiCount != 3 {
		t.Errorf("merge block: expected 3 phi-nodes, got %d", phiCount)
	}
}
