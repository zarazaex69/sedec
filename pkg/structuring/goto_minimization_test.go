// package structuring - tests for goto minimization pass
package structuring

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/disasm"
)

// buildReducibleCFG builds a simple reducible cfg (linear + loop).
// reducible means every SCC has exactly one entry node.
//
//	bb0 -> bb1 -> bb2 (back-edge bb2->bb1) -> bb3 (ret)
func buildReducibleCFG(t *testing.T) *cfg.CFG {
	t.Helper()
	instrs := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "jmp", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005, Size: disasm.Size32}},
		},
		{Address: 0x1005, Mnemonic: "cmp", Length: 3},
		{Address: 0x1008, Mnemonic: "jge", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1010, Size: disasm.Size32}},
		},
		{Address: 0x100a, Mnemonic: "inc", Length: 2},
		{Address: 0x100c, Mnemonic: "jmp", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005, Size: disasm.Size32}},
		},
		{Address: 0x1010, Mnemonic: "ret", Length: 1},
	}
	builder := cfg.NewCFGBuilder()
	c, err := builder.Build(instrs)
	if err != nil {
		t.Fatalf("build cfg: %v", err)
	}
	return c
}

// buildIrreducibleCFG builds a minimal irreducible cfg.
// classic irreducible pattern: two nodes each with a back-edge to the other.
//
//	entry -> A -> B -> A (back-edge)
//	entry -> B -> A -> B (back-edge)
//
// both A and B are entry nodes of the SCC {A, B}, making it irreducible.
// we construct this manually since the cfg builder cannot produce it from
// linear instruction sequences.
func buildIrreducibleCFG(t *testing.T) *cfg.CFG {
	t.Helper()
	c := cfg.NewCFG()

	// entry block
	entry := &cfg.BasicBlock{
		ID:           1,
		StartAddress: 0x1000,
		EndAddress:   0x1002,
		Instructions: []*disasm.Instruction{
			{Address: 0x1000, Mnemonic: "mov", Length: 3},
		},
	}
	// block A
	blockA := &cfg.BasicBlock{
		ID:           2,
		StartAddress: 0x1003,
		EndAddress:   0x1005,
		Instructions: []*disasm.Instruction{
			{Address: 0x1003, Mnemonic: "inc", Length: 2},
		},
	}
	// block B
	blockB := &cfg.BasicBlock{
		ID:           3,
		StartAddress: 0x1006,
		EndAddress:   0x1008,
		Instructions: []*disasm.Instruction{
			{Address: 0x1006, Mnemonic: "dec", Length: 2},
		},
	}
	// exit block
	exitBlock := &cfg.BasicBlock{
		ID:           4,
		StartAddress: 0x1009,
		EndAddress:   0x100a,
		Instructions: []*disasm.Instruction{
			{Address: 0x1009, Mnemonic: "ret", Length: 1},
		},
	}

	c.AddBlock(entry)
	c.AddBlock(blockA)
	c.AddBlock(blockB)
	c.AddBlock(exitBlock)
	c.Entry = 1
	c.Exits = []cfg.BlockID{4}

	// entry -> A, entry -> B (two entry points into the SCC)
	c.AddEdge(1, 2, cfg.EdgeTypeConditional)
	c.AddEdge(1, 3, cfg.EdgeTypeConditional)
	// A -> B (forward edge within SCC)
	c.AddEdge(2, 3, cfg.EdgeTypeUnconditional)
	// B -> A (back-edge creating the irreducible cycle)
	c.AddEdge(3, 2, cfg.EdgeTypeUnconditional)
	// A -> exit
	c.AddEdge(2, 4, cfg.EdgeTypeConditional)

	return c
}

// TestIsReducible_ReducibleCFG verifies that a simple while-loop cfg is reducible.
func TestIsReducible_ReducibleCFG(t *testing.T) {
	c := buildReducibleCFG(t)
	if !IsReducible(c) {
		t.Error("expected reducible cfg to be detected as reducible")
	}
}

// TestIsReducible_IrreducibleCFG verifies that the classic irreducible cfg is detected.
func TestIsReducible_IrreducibleCFG(t *testing.T) {
	c := buildIrreducibleCFG(t)
	if IsReducible(c) {
		t.Error("expected irreducible cfg to be detected as irreducible")
	}
}

// TestIsReducible_NilCFG verifies that nil cfg is treated as reducible.
func TestIsReducible_NilCFG(t *testing.T) {
	if !IsReducible(nil) {
		t.Error("expected nil cfg to be treated as reducible")
	}
}

// TestTarjanSCC_LinearCFG verifies SCC detection on a linear cfg (each block is its own SCC).
func TestTarjanSCC_LinearCFG(t *testing.T) {
	c := buildReducibleCFG(t)
	g := newGotoMinimizer(c, nil, make(IRBlockMap))
	sccs := g.tarjanSCC()

	// a reducible cfg with a loop has one SCC of size >= 2 (the loop) and
	// the rest are singleton SCCs
	totalNodes := 0
	for _, scc := range sccs {
		totalNodes += len(scc)
	}
	if totalNodes != len(c.Blocks) {
		t.Errorf("expected %d total nodes in SCCs, got %d", len(c.Blocks), totalNodes)
	}
}

// TestTarjanSCC_IrreducibleCFG verifies that the irreducible cfg has an SCC of size >= 2.
func TestTarjanSCC_IrreducibleCFG(t *testing.T) {
	c := buildIrreducibleCFG(t)
	g := newGotoMinimizer(c, nil, make(IRBlockMap))
	sccs := g.tarjanSCC()

	// must have at least one SCC with 2+ nodes (the irreducible cycle A-B)
	found := false
	for _, scc := range sccs {
		if len(scc) >= 2 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one SCC with 2+ nodes in irreducible cfg")
	}
}

// TestFindIrreducibleSCCs_ReducibleCFG verifies no irreducible SCCs in a reducible cfg.
func TestFindIrreducibleSCCs_ReducibleCFG(t *testing.T) {
	c := buildReducibleCFG(t)
	g := newGotoMinimizer(c, nil, make(IRBlockMap))
	irreducible := g.findIrreducibleSCCs()
	if len(irreducible) != 0 {
		t.Errorf("expected 0 irreducible SCCs in reducible cfg, got %d", len(irreducible))
	}
}

// TestFindIrreducibleSCCs_IrreducibleCFG verifies irreducible SCCs are found.
func TestFindIrreducibleSCCs_IrreducibleCFG(t *testing.T) {
	c := buildIrreducibleCFG(t)
	g := newGotoMinimizer(c, nil, make(IRBlockMap))
	irreducible := g.findIrreducibleSCCs()
	if len(irreducible) == 0 {
		t.Error("expected at least one irreducible SCC in irreducible cfg")
	}
}

// TestNodeSplitting_MakesReducible verifies that node splitting transforms
// the irreducible cfg into a reducible one.
func TestNodeSplitting_MakesReducible(t *testing.T) {
	c := buildIrreducibleCFG(t)

	// verify it starts as irreducible
	if IsReducible(c) {
		t.Fatal("precondition: cfg must be irreducible before splitting")
	}

	g := newGotoMinimizer(c, nil, make(IRBlockMap))
	g.splitIrreducibleRegions()

	// after splitting, the cfg should be reducible
	if !IsReducible(c) {
		t.Error("expected cfg to be reducible after node splitting")
	}
}

// TestNodeSplitting_PreservesBlockCount verifies that splitting adds blocks
// (clones) rather than removing them.
func TestNodeSplitting_PreservesBlockCount(t *testing.T) {
	c := buildIrreducibleCFG(t)
	originalCount := len(c.Blocks)

	g := newGotoMinimizer(c, nil, make(IRBlockMap))
	g.splitIrreducibleRegions()

	if len(c.Blocks) < originalCount {
		t.Errorf("expected block count to be >= %d after splitting, got %d",
			originalCount, len(c.Blocks))
	}
}

// TestNodeSplitting_SplitCountTracked verifies that split counts are tracked.
func TestNodeSplitting_SplitCountTracked(t *testing.T) {
	c := buildIrreducibleCFG(t)
	g := newGotoMinimizer(c, nil, make(IRBlockMap))
	g.splitIrreducibleRegions()

	// at least one block must have been split
	totalSplits := 0
	for _, count := range g.splitCount {
		totalSplits += count
	}
	if totalSplits == 0 {
		t.Error("expected at least one node to be split")
	}
}

// TestMinimizeGotos_ReducibleCFG verifies that a reducible cfg produces zero gotos.
func TestMinimizeGotos_ReducibleCFG(t *testing.T) {
	c, dt, li := buildWhileLoopCFG(t)
	irBlocks := irBlocksFromCFG(c)

	engine, err := New(c, dt, li, irBlocks)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ast, err := engine.Structure()
	if err != nil {
		t.Fatalf("Structure: %v", err)
	}

	// apply goto minimization
	minimized := MinimizeGotos(ast, c, dt, irBlocks)
	if minimized == nil {
		t.Fatal("expected non-nil minimized ast")
	}

	// a reducible cfg should produce zero gotos after minimization
	gotoCount := CountGotos(minimized.Body)
	if gotoCount != 0 {
		t.Errorf("expected 0 gotos for reducible cfg, got %d", gotoCount)
	}
}

// TestMinimizeGotos_NilInputs verifies that nil inputs are handled gracefully.
func TestMinimizeGotos_NilInputs(t *testing.T) {
	c, dt, li := buildLinearCFG(t)
	irBlocks := irBlocksFromCFG(c)

	engine, err := New(c, dt, li, irBlocks)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ast, err := engine.Structure()
	if err != nil {
		t.Fatalf("Structure: %v", err)
	}

	// nil ast
	result := MinimizeGotos(nil, c, dt, irBlocks)
	if result != nil {
		t.Error("expected nil result for nil ast")
	}

	// nil cfg
	result = MinimizeGotos(ast, nil, dt, irBlocks)
	if result == nil {
		t.Error("expected non-nil result when cfg is nil (pass-through)")
	}

	// nil dt
	result = MinimizeGotos(ast, c, nil, irBlocks)
	if result == nil {
		t.Error("expected non-nil result when dt is nil (pass-through)")
	}
}

// TestCountGotos_NoGotos verifies CountGotos returns 0 for goto-free AST.
func TestCountGotos_NoGotos(t *testing.T) {
	stmt := Block{Stmts: []Statement{
		IRBlock{BlockID: 1},
		WhileStatement{
			Condition: nil,
			Body:      IRBlock{BlockID: 2},
		},
	}}
	if count := CountGotos(stmt); count != 0 {
		t.Errorf("expected 0 gotos, got %d", count)
	}
}

// TestCountGotos_WithGotos verifies CountGotos counts correctly.
func TestCountGotos_WithGotos(t *testing.T) {
	stmt := Block{Stmts: []Statement{
		GotoStatement{Target: 1, Label: "L1"},
		IfStatement{
			Condition: nil,
			Then:      GotoStatement{Target: 2, Label: "L2"},
			Else:      GotoStatement{Target: 3, Label: "L3"},
		},
	}}
	if count := CountGotos(stmt); count != 3 {
		t.Errorf("expected 3 gotos, got %d", count)
	}
}

// TestCountGotos_Nil verifies CountGotos handles nil gracefully.
func TestCountGotos_Nil(t *testing.T) {
	if count := CountGotos(nil); count != 0 {
		t.Errorf("expected 0 for nil, got %d", count)
	}
}

// TestMinimizeGotos_LinearCFG verifies that a linear cfg produces zero gotos.
func TestMinimizeGotos_LinearCFG(t *testing.T) {
	c, dt, li := buildLinearCFG(t)
	irBlocks := irBlocksFromCFG(c)

	engine, err := New(c, dt, li, irBlocks)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ast, err := engine.Structure()
	if err != nil {
		t.Fatalf("Structure: %v", err)
	}

	minimized := MinimizeGotos(ast, c, dt, irBlocks)
	if minimized == nil {
		t.Fatal("expected non-nil minimized ast")
	}

	gotoCount := CountGotos(minimized.Body)
	if gotoCount != 0 {
		t.Errorf("expected 0 gotos for linear cfg, got %d", gotoCount)
	}
}

// TestMinimizeGotos_IfThenElseCFG verifies that an if-then-else cfg produces zero gotos.
func TestMinimizeGotos_IfThenElseCFG(t *testing.T) {
	c, dt, li := buildIfThenElseCFG(t)
	irBlocks := irBlocksFromCFG(c)

	engine, err := New(c, dt, li, irBlocks)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ast, err := engine.Structure()
	if err != nil {
		t.Fatalf("Structure: %v", err)
	}

	minimized := MinimizeGotos(ast, c, dt, irBlocks)
	if minimized == nil {
		t.Fatal("expected non-nil minimized ast")
	}

	gotoCount := CountGotos(minimized.Body)
	if gotoCount != 0 {
		t.Errorf("expected 0 gotos for if-then-else cfg, got %d", gotoCount)
	}
}

// TestMinimizeGotos_PreservesStructure verifies that minimization does not
// destroy the structured AST (loops, ifs still present after minimization).
func TestMinimizeGotos_PreservesStructure(t *testing.T) {
	c, dt, li := buildWhileLoopCFG(t)
	irBlocks := irBlocksFromCFG(c)

	engine, err := New(c, dt, li, irBlocks)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ast, err := engine.Structure()
	if err != nil {
		t.Fatalf("Structure: %v", err)
	}

	minimized := MinimizeGotos(ast, c, dt, irBlocks)
	if minimized == nil {
		t.Fatal("expected non-nil minimized ast")
	}

	// loop structure must be preserved
	if !containsLoopStatement(minimized.Body) {
		t.Error("expected loop statement to be preserved after goto minimization")
	}
}

// TestLabelFixer_CollectsGotoTargets verifies that collectTargets registers
// all GotoStatement targets.
func TestLabelFixer_CollectsGotoTargets(t *testing.T) {
	lf := newLabelFixer()

	ast := Block{Stmts: []Statement{
		GotoStatement{Target: 42, Label: ""},
		IfStatement{
			Condition: nil,
			Then:      GotoStatement{Target: 99, Label: ""},
			Else:      nil,
		},
	}}

	lf.collectTargets(ast)

	if _, ok := lf.gotoTargets[42]; !ok {
		t.Error("expected block 42 to be registered as goto target")
	}
	if _, ok := lf.gotoTargets[99]; !ok {
		t.Error("expected block 99 to be registered as goto target")
	}
}

// TestLabelFixer_InsertsLabelAtTarget verifies that insertLabels prepends
// a LabelStatement to an IRBlock that is a goto target.
func TestLabelFixer_InsertsLabelAtTarget(t *testing.T) {
	lf := newLabelFixer()

	// register block 99 as a goto target
	label := lf.label(99)
	if label == "" {
		t.Fatal("expected non-empty label")
	}

	// insert labels: block 99 should get a label prepended
	result := lf.insertLabels(IRBlock{BlockID: 99})
	block, ok := result.(Block)
	if !ok {
		t.Fatalf("expected Block with label prepended, got %T", result)
	}
	if len(block.Stmts) < 2 {
		t.Fatalf("expected at least 2 statements (label + irblock), got %d", len(block.Stmts))
	}
	if _, ok := block.Stmts[0].(LabelStatement); !ok {
		t.Errorf("expected LabelStatement as first statement, got %T", block.Stmts[0])
	}
}

// TestLabelFixer_NoLabelForNonTarget verifies that non-target IRBlocks are unchanged.
func TestLabelFixer_NoLabelForNonTarget(t *testing.T) {
	lf := newLabelFixer()

	// block 5 is not a goto target
	result := lf.insertLabels(IRBlock{BlockID: 5})
	if _, ok := result.(IRBlock); !ok {
		t.Errorf("expected IRBlock unchanged for non-target, got %T", result)
	}
}

// TestOriginalID verifies that originalID correctly traces back through splits.
func TestOriginalID(t *testing.T) {
	c := buildReducibleCFG(t)
	g := newGotoMinimizer(c, nil, make(IRBlockMap))

	// simulate a split: block 100 is a clone of block 5
	g.splitOrigin[100] = 5

	if g.originalID(100) != 5 {
		t.Errorf("expected originalID(100) = 5, got %d", g.originalID(100))
	}
	if g.originalID(5) != 5 {
		t.Errorf("expected originalID(5) = 5 (no split), got %d", g.originalID(5))
	}
}

// TestSplitIterationLimit verifies that splitting terminates within maxSplitIterations.
func TestSplitIterationLimit(t *testing.T) {
	// build a deeply irreducible cfg (chain of irreducible pairs)
	c := buildIrreducibleCFG(t)
	g := newGotoMinimizer(c, nil, make(IRBlockMap))

	// this must terminate without hanging
	g.splitIrreducibleRegions()

	// verify total splits are bounded
	totalSplits := 0
	for _, count := range g.splitCount {
		totalSplits += count
	}
	if totalSplits > maxSplitIterations {
		t.Errorf("expected at most %d splits, got %d", maxSplitIterations, totalSplits)
	}
}
