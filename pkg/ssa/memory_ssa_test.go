package ssa

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// Memory SSA Construction Tests
// ============================================================================

// helper function to create dominator tree for tests
func createTestDomTree(cfgGraph *cfg.CFG, idom map[cfg.BlockID]cfg.BlockID, children map[cfg.BlockID][]cfg.BlockID) *cfg.DominatorTree {
	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = idom
	domTree.Children = children
	return domTree
}

// TestMemorySSA_SimpleStore tests memory ssa for a simple store operation
func TestMemorySSA_SimpleStore(t *testing.T) {
	// create simple function with one store
	// bb0:
	//   store [0x1000], 42
	//   return

	function := &ir.Function{
		Name: "test_simple_store",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Store{
						Address: &ir.ConstantExpr{
							Value: ir.IntConstant{Value: 0x1000, Width: ir.Size8, Signed: false},
						},
						Value: &ir.ConstantExpr{
							Value: ir.IntConstant{Value: 42, Width: ir.Size4, Signed: true},
						},
						Size: ir.Size4,
					},
					&ir.Return{Value: nil},
				},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	// create cfg
	cfgGraph := &cfg.CFG{
		Blocks: map[cfg.BlockID]*cfg.BasicBlock{
			0: {
				ID:           0,
				Instructions: nil,
				Predecessors: []cfg.BlockID{},
				Successors:   []cfg.BlockID{},
			},
		},
		Entry: 0,
		Exits: []cfg.BlockID{0},
	}

	// create dominator tree
	domTree := createTestDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{0: 0},
		map[cfg.BlockID][]cfg.BlockID{0: {}})

	// build memory ssa
	builder := NewMemorySSABuilder(function, cfgGraph, domTree)
	memInfo, err := builder.BuildMemorySSA()
	if err != nil {
		t.Fatalf("BuildMemorySSA failed: %v", err)
	}

	// verify memory def created for store
	defs := memInfo.GetMemoryDefsInBlock(0)
	if len(defs) != 1 {
		t.Errorf("expected 1 memory def, got %d", len(defs))
	}

	// verify memory def has valid version
	if defs[0].Version.ID == 0 {
		t.Errorf("memory def has invalid version 0")
	}

	// verify no memory uses (no loads)
	uses := memInfo.GetMemoryUsesInBlock(0)
	if len(uses) != 0 {
		t.Errorf("expected 0 memory uses, got %d", len(uses))
	}

	// verify no memory phi-nodes (single block)
	if memInfo.GetTotalMemoryPhis() != 0 {
		t.Errorf("expected 0 memory phi-nodes, got %d", memInfo.GetTotalMemoryPhis())
	}
}

// TestMemorySSA_LoadStore tests memory ssa for load-store sequence
func TestMemorySSA_LoadStore(t *testing.T) {
	// create function with load and store
	// bb0:
	//   v0 = load [0x1000]
	//   store [0x2000], v0
	//   return

	v0 := ir.Variable{Name: "v0", Type: ir.IntType{Width: ir.Size4, Signed: true}, Version: 0}

	function := &ir.Function{
		Name: "test_load_store",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Load{
						Dest: v0,
						Address: &ir.ConstantExpr{
							Value: ir.IntConstant{Value: 0x1000, Width: ir.Size8, Signed: false},
						},
						Size: ir.Size4,
					},
					&ir.Store{
						Address: &ir.ConstantExpr{
							Value: ir.IntConstant{Value: 0x2000, Width: ir.Size8, Signed: false},
						},
						Value: &ir.VariableExpr{Var: v0},
						Size:  ir.Size4,
					},
					&ir.Return{Value: nil},
				},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	// create cfg
	cfgGraph := &cfg.CFG{
		Blocks: map[cfg.BlockID]*cfg.BasicBlock{
			0: {
				ID:           0,
				Instructions: nil,
				Predecessors: []cfg.BlockID{},
				Successors:   []cfg.BlockID{},
			},
		},
		Entry: 0,
		Exits: []cfg.BlockID{0},
	}

	// create dominator tree
	domTree := createTestDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{0: 0},
		map[cfg.BlockID][]cfg.BlockID{0: {}})

	// build memory ssa
	builder := NewMemorySSABuilder(function, cfgGraph, domTree)
	memInfo, err := builder.BuildMemorySSA()
	if err != nil {
		t.Fatalf("BuildMemorySSA failed: %v", err)
	}

	// verify memory use created for load
	uses := memInfo.GetMemoryUsesInBlock(0)
	if len(uses) != 1 {
		t.Errorf("expected 1 memory use, got %d", len(uses))
	}

	// verify memory def created for store
	defs := memInfo.GetMemoryDefsInBlock(0)
	if len(defs) != 1 {
		t.Errorf("expected 1 memory def, got %d", len(defs))
	}

	// verify def-use chain: load uses initial memory, store defines new memory
	if uses[0].Version.ID != 0 {
		t.Errorf("load should use initial memory version 0, got %d", uses[0].Version.ID)
	}

	if defs[0].PrevVersion.ID != 0 {
		t.Errorf("store should have previous version 0, got %d", defs[0].PrevVersion.ID)
	}

	if defs[0].Version.ID == 0 {
		t.Errorf("store should create new memory version, got 0")
	}
}

// TestMemorySSA_IfThenElse tests memory ssa for if-then-else control flow
func TestMemorySSA_IfThenElse(t *testing.T) {
	// create function with if-then-else
	// bb0:
	//   branch cond, bb1, bb2
	// bb1:
	//   store [0x1000], 1
	//   jump bb3
	// bb2:
	//   store [0x2000], 2
	//   jump bb3
	// bb3:
	//   return

	cond := ir.Variable{Name: "cond", Type: ir.BoolType{}, Version: 0}

	function := &ir.Function{
		Name: "test_if_then_else",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Branch{
						Condition:   &ir.VariableExpr{Var: cond},
						TrueTarget:  1,
						FalseTarget: 2,
					},
				},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{1, 2},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Store{
						Address: &ir.ConstantExpr{
							Value: ir.IntConstant{Value: 0x1000, Width: ir.Size8, Signed: false},
						},
						Value: &ir.ConstantExpr{
							Value: ir.IntConstant{Value: 1, Width: ir.Size4, Signed: true},
						},
						Size: ir.Size4,
					},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Store{
						Address: &ir.ConstantExpr{
							Value: ir.IntConstant{Value: 0x2000, Width: ir.Size8, Signed: false},
						},
						Value: &ir.ConstantExpr{
							Value: ir.IntConstant{Value: 2, Width: ir.Size4, Signed: true},
						},
						Size: ir.Size4,
					},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			3: {
				ID: 3,
				Instructions: []ir.IRInstruction{
					&ir.Return{Value: nil},
				},
				Predecessors: []ir.BlockID{1, 2},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	// create cfg
	cfgGraph := &cfg.CFG{
		Blocks: map[cfg.BlockID]*cfg.BasicBlock{
			0: {
				ID:           0,
				Instructions: nil,
				Predecessors: []cfg.BlockID{},
				Successors:   []cfg.BlockID{1, 2},
			},
			1: {
				ID:           1,
				Instructions: nil,
				Predecessors: []cfg.BlockID{0},
				Successors:   []cfg.BlockID{3},
			},
			2: {
				ID:           2,
				Instructions: nil,
				Predecessors: []cfg.BlockID{0},
				Successors:   []cfg.BlockID{3},
			},
			3: {
				ID:           3,
				Instructions: nil,
				Predecessors: []cfg.BlockID{1, 2},
				Successors:   []cfg.BlockID{},
			},
		},
		Entry: 0,
		Exits: []cfg.BlockID{3},
	}

	// create dominator tree
	// 0 dominates all, 0 is idom of 1,2,3
	domTree := createTestDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{
			0: 0,
			1: 0,
			2: 0,
			3: 0,
		},
		map[cfg.BlockID][]cfg.BlockID{
			0: {1, 2, 3},
			1: {},
			2: {},
			3: {},
		})

	// build memory ssa
	builder := NewMemorySSABuilder(function, cfgGraph, domTree)
	memInfo, err := builder.BuildMemorySSA()
	if err != nil {
		t.Fatalf("BuildMemorySSA failed: %v", err)
	}

	// verify memory defs in bb1 and bb2
	defs1 := memInfo.GetMemoryDefsInBlock(1)
	if len(defs1) != 1 {
		t.Errorf("expected 1 memory def in bb1, got %d", len(defs1))
	}

	defs2 := memInfo.GetMemoryDefsInBlock(2)
	if len(defs2) != 1 {
		t.Errorf("expected 1 memory def in bb2, got %d", len(defs2))
	}

	// verify memory phi-node at bb3 (merge point)
	phi, hasPhi := memInfo.GetMemoryPhiForBlock(3)
	if !hasPhi {
		t.Fatalf("expected memory phi-node at bb3")
	}

	// verify phi has sources from bb1 and bb2
	if len(phi.Sources) != 2 {
		t.Errorf("expected 2 phi sources, got %d", len(phi.Sources))
	}

	_, hasBB1Source := phi.Sources[1]
	_, hasBB2Source := phi.Sources[2]
	if !hasBB1Source || !hasBB2Source {
		t.Errorf("phi-node missing sources from bb1 or bb2")
	}

	// verify phi creates new memory version
	if phi.Version.ID == 0 {
		t.Errorf("phi-node should create new memory version, got 0")
	}
}

// TestMemorySSA_FunctionCall tests memory ssa for function calls
func TestMemorySSA_FunctionCall(t *testing.T) {
	// create function with call
	// bb0:
	//   call foo()
	//   return

	function := &ir.Function{
		Name: "test_call",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Call{
						Dest: nil,
						Target: &ir.ConstantExpr{
							Value: ir.IntConstant{Value: 0x1000, Width: ir.Size8, Signed: false},
						},
						Args: []ir.Variable{},
					},
					&ir.Return{Value: nil},
				},
				Predecessors: []ir.BlockID{},
				Successors:   []ir.BlockID{},
			},
		},
		EntryBlock: 0,
	}

	// create cfg
	cfgGraph := &cfg.CFG{
		Blocks: map[cfg.BlockID]*cfg.BasicBlock{
			0: {
				ID:           0,
				Instructions: nil,
				Predecessors: []cfg.BlockID{},
				Successors:   []cfg.BlockID{},
			},
		},
		Entry: 0,
		Exits: []cfg.BlockID{0},
	}

	// create dominator tree
	domTree := createTestDomTree(cfgGraph,
		map[cfg.BlockID]cfg.BlockID{0: 0},
		map[cfg.BlockID][]cfg.BlockID{0: {}})

	// build memory ssa
	builder := NewMemorySSABuilder(function, cfgGraph, domTree)
	memInfo, err := builder.BuildMemorySSA()
	if err != nil {
		t.Fatalf("BuildMemorySSA failed: %v", err)
	}

	// verify memory use created for call (may read memory)
	uses := memInfo.GetMemoryUsesInBlock(0)
	if len(uses) != 1 {
		t.Errorf("expected 1 memory use for call, got %d", len(uses))
	}

	// verify memory def created for call (may modify memory)
	defs := memInfo.GetMemoryDefsInBlock(0)
	if len(defs) != 1 {
		t.Errorf("expected 1 memory def for call, got %d", len(defs))
	}
}
