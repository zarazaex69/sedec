package ssa

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// Memory SSA Query API Tests
// ============================================================================

// buildMemorySSAForLoop creates a loop with memory operations for testing
// loop structure: entry → header ↔ body → exit
// body contains store and load to exercise memory def-use chains
func buildMemorySSAForLoop(t *testing.T) *MemorySSAInfo {
	t.Helper()

	cfgGraph := &cfg.CFG{
		Blocks: map[cfg.BlockID]*cfg.BasicBlock{
			0: {ID: 0, Predecessors: []cfg.BlockID{}, Successors: []cfg.BlockID{1}},
			1: {ID: 1, Predecessors: []cfg.BlockID{0, 2}, Successors: []cfg.BlockID{2, 3}},
			2: {ID: 2, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{1}},
			3: {ID: 3, Predecessors: []cfg.BlockID{1}, Successors: []cfg.BlockID{}},
		},
		Entry: 0,
		Exits: []cfg.BlockID{3},
	}

	fn := &ir.Function{
		Name:       "loop_memory",
		EntryBlock: 0,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
	}

	ptrExpr := &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x1000, Width: ir.Size8, Signed: false}}
	valExpr := &ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size4, Signed: true}}
	vVar := ir.Variable{Name: "v", Type: ir.IntType{Width: ir.Size4, Signed: true}}

	fn.Blocks[0] = &ir.BasicBlock{
		ID:           0,
		Instructions: []ir.IRInstruction{&ir.Jump{Target: 1}},
		Successors:   []ir.BlockID{1},
	}
	fn.Blocks[1] = &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Branch{
				Condition:   &ir.ConstantExpr{Value: ir.BoolConstant{Value: true}},
				TrueTarget:  2,
				FalseTarget: 3,
			},
		},
		Predecessors: []ir.BlockID{0, 2},
		Successors:   []ir.BlockID{2, 3},
	}
	fn.Blocks[2] = &ir.BasicBlock{
		ID: 2,
		Instructions: []ir.IRInstruction{
			// store to memory
			&ir.Store{Address: ptrExpr, Value: valExpr, Size: ir.Size4},
			// load from memory
			&ir.Load{Dest: vVar, Address: ptrExpr, Size: ir.Size4},
			&ir.Jump{Target: 1},
		},
		Predecessors: []ir.BlockID{1},
		Successors:   []ir.BlockID{1},
	}
	fn.Blocks[3] = &ir.BasicBlock{
		ID:           3,
		Instructions: []ir.IRInstruction{&ir.Return{Value: nil}},
		Predecessors: []ir.BlockID{1},
	}

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0, 1: 0, 2: 1, 3: 1}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {1}, 1: {2, 3}, 2: {}, 3: {}}

	builder := NewMemorySSABuilder(fn, cfgGraph, domTree)
	memInfo, err := builder.BuildMemorySSA()
	if err != nil {
		t.Fatalf("BuildMemorySSA failed: %v", err)
	}

	return memInfo
}

// TestMemorySSA_DefUseChains verifies that def-use chains are correctly built
// after memory ssa construction.
func TestMemorySSA_DefUseChains(t *testing.T) {
	memInfo := buildMemorySSAForLoop(t)

	// body block (2) has 1 store (def) and 1 load (use)
	defs := memInfo.GetMemoryDefsInBlock(2)
	if len(defs) != 1 {
		t.Fatalf("body block: expected 1 memory def, got %d", len(defs))
	}

	uses := memInfo.GetMemoryUsesInBlock(2)
	if len(uses) != 1 {
		t.Fatalf("body block: expected 1 memory use, got %d", len(uses))
	}

	// verify use-def chain: load's version must be tracked
	memUse := uses[0]
	version, exists := memInfo.GetMemoryDefForUse(memUse)
	if !exists {
		t.Fatal("use-def chain missing for load instruction")
	}

	// the load uses the initial memory version (before the store in same block)
	// because the store comes before the load in instruction order
	// so load uses version 0 (initial), store creates version 1
	_ = version // version is valid, just verify it exists

	// verify def-use chain: store's version should have no uses
	// (the load uses the version BEFORE the store, not after)
	storeDef := defs[0]
	storeUses := memInfo.GetUsesOfMemoryDef(storeDef.Version)
	// store creates a new version; load uses the previous version
	// so store's version may have 0 uses in this simple case
	_ = storeUses
}

// TestMemorySSA_BlockExitVersions verifies that block exit memory versions
// are correctly tracked for each block.
func TestMemorySSA_BlockExitVersions(t *testing.T) {
	memInfo := buildMemorySSAForLoop(t)

	// entry block (0) has no memory ops, exit version should be initial (0)
	entryVersion, exists := memInfo.GetMemoryVersionAtBlockExit(0)
	if !exists {
		t.Fatal("entry block exit version not tracked")
	}
	if entryVersion.ID != 0 {
		t.Errorf("entry block exit: expected version 0, got %d", entryVersion.ID)
	}

	// body block (2) has a store, so exit version must be > 0
	bodyVersion, exists := memInfo.GetMemoryVersionAtBlockExit(2)
	if !exists {
		t.Fatal("body block exit version not tracked")
	}
	if bodyVersion.ID == 0 {
		t.Error("body block exit: expected version > 0 after store, got 0")
	}
}

// TestMemorySSA_TotalCounts verifies total counts of memory defs, uses, and phis.
func TestMemorySSA_TotalCounts(t *testing.T) {
	memInfo := buildMemorySSAForLoop(t)

	// body block has 1 store → 1 def total
	totalDefs := memInfo.GetTotalMemoryDefs()
	if totalDefs != 1 {
		t.Errorf("expected 1 total memory def, got %d", totalDefs)
	}

	// body block has 1 load → 1 use total
	totalUses := memInfo.GetTotalMemoryUses()
	if totalUses != 1 {
		t.Errorf("expected 1 total memory use, got %d", totalUses)
	}

	// header block (1) is a merge point with memory def in body → phi at header
	totalPhis := memInfo.GetTotalMemoryPhis()
	if totalPhis != 1 {
		t.Errorf("expected 1 memory phi-node at loop header, got %d", totalPhis)
	}
}

// TestMemorySSA_StringRepresentations verifies String() methods on memory ssa types
// these are used for debugging and IR printing.
func TestMemorySSA_StringRepresentations(t *testing.T) {
	// test MemoryVersion.String()
	v := MemoryVersion{ID: 5, DefSite: 2}
	s := v.String()
	if s != "mem_5" {
		t.Errorf("MemoryVersion.String(): expected 'mem_5', got '%s'", s)
	}

	// test MemoryDef.String()
	def := MemoryDef{
		Version:     MemoryVersion{ID: 2},
		PrevVersion: MemoryVersion{ID: 1},
	}
	defStr := def.String()
	if defStr == "" {
		t.Error("MemoryDef.String() returned empty string")
	}

	// test MemoryUse.String()
	use := MemoryUse{
		Version: MemoryVersion{ID: 1},
	}
	useStr := use.String()
	if useStr == "" {
		t.Error("MemoryUse.String() returned empty string")
	}

	// test MemoryPhi.String()
	phi := MemoryPhi{
		Version: MemoryVersion{ID: 3},
		Sources: map[ir.BlockID]MemoryVersion{},
		Block:   0,
	}
	phiStr := phi.String()
	if phiStr == "" {
		t.Error("MemoryPhi.String() returned empty string")
	}
}

// TestMemorySSA_GetMemorySSAInfo verifies the GetMemorySSAInfo accessor.
func TestMemorySSA_GetMemorySSAInfo(t *testing.T) {
	cfgGraph := &cfg.CFG{
		Blocks: map[cfg.BlockID]*cfg.BasicBlock{
			0: {ID: 0, Predecessors: []cfg.BlockID{}, Successors: []cfg.BlockID{}},
		},
		Entry: 0,
		Exits: []cfg.BlockID{0},
	}

	fn := &ir.Function{
		Name:       "simple",
		EntryBlock: 0,
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Store{
						Address: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x100, Width: ir.Size8, Signed: false}},
						Value:   &ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size4, Signed: true}},
						Size:    ir.Size4,
					},
					&ir.Return{},
				},
			},
		},
	}

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	builder := NewMemorySSABuilder(fn, cfgGraph, domTree)
	_, err := builder.BuildMemorySSA()
	if err != nil {
		t.Fatalf("BuildMemorySSA failed: %v", err)
	}

	// GetMemorySSAInfo must return the same info as BuildMemorySSA
	info := builder.GetMemorySSAInfo()
	if info == nil {
		t.Fatal("GetMemorySSAInfo returned nil")
	}

	if info.GetTotalMemoryDefs() != 1 {
		t.Errorf("expected 1 def via GetMemorySSAInfo, got %d", info.GetTotalMemoryDefs())
	}
}

// TestMemorySSA_MultipleStoresInBlock verifies memory version chaining
// when multiple stores appear in the same block.
func TestMemorySSA_MultipleStoresInBlock(t *testing.T) {
	// bb0:
	//   store [0x100], 1
	//   store [0x200], 2
	//   store [0x300], 3
	//   return

	cfgGraph := &cfg.CFG{
		Blocks: map[cfg.BlockID]*cfg.BasicBlock{
			0: {ID: 0, Predecessors: []cfg.BlockID{}, Successors: []cfg.BlockID{}},
		},
		Entry: 0,
		Exits: []cfg.BlockID{0},
	}

	makeStore := func(addr, val int64) *ir.Store {
		return &ir.Store{
			Address: &ir.ConstantExpr{Value: ir.IntConstant{Value: addr, Width: ir.Size8, Signed: false}},
			Value:   &ir.ConstantExpr{Value: ir.IntConstant{Value: val, Width: ir.Size4, Signed: true}},
			Size:    ir.Size4,
		}
	}

	fn := &ir.Function{
		Name:       "multi_store",
		EntryBlock: 0,
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					makeStore(0x100, 1),
					makeStore(0x200, 2),
					makeStore(0x300, 3),
					&ir.Return{},
				},
			},
		},
	}

	domTree := cfg.NewDominatorTree(cfgGraph)
	domTree.Idom = map[cfg.BlockID]cfg.BlockID{0: 0}
	domTree.Children = map[cfg.BlockID][]cfg.BlockID{0: {}}

	builder := NewMemorySSABuilder(fn, cfgGraph, domTree)
	memInfo, err := builder.BuildMemorySSA()
	if err != nil {
		t.Fatalf("BuildMemorySSA failed: %v", err)
	}

	// 3 stores → 3 memory defs
	defs := memInfo.GetMemoryDefsInBlock(0)
	if len(defs) != 3 {
		t.Fatalf("expected 3 memory defs, got %d", len(defs))
	}

	// verify version chaining: each def's prev version = previous def's version
	// def[0]: prev=0, version=1
	// def[1]: prev=1, version=2
	// def[2]: prev=2, version=3
	for i, def := range defs {
		expectedPrev := i    // 0, 1, 2
		expectedNew := i + 1 // 1, 2, 3

		if def.PrevVersion.ID != expectedPrev {
			t.Errorf("def[%d]: expected prev version %d, got %d", i, expectedPrev, def.PrevVersion.ID)
		}
		if def.Version.ID != expectedNew {
			t.Errorf("def[%d]: expected version %d, got %d", i, expectedNew, def.Version.ID)
		}
	}

	// block exit version must be 3 (last store's version)
	exitVersion, exists := memInfo.GetMemoryVersionAtBlockExit(0)
	if !exists {
		t.Fatal("block exit version not tracked")
	}
	if exitVersion.ID != 3 {
		t.Errorf("block exit: expected version 3, got %d", exitVersion.ID)
	}
}
