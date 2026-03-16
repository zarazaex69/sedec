package structuring

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// buildLinearCFG builds a 3-block linear cfg: bb0 -> bb1 -> bb2 (ret)
func buildLinearCFG(t *testing.T) (*cfg.CFG, *cfg.DominatorTree, *cfg.LoopInfo) {
	t.Helper()
	instrs := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "add", Length: 3},
		{Address: 0x1006, Mnemonic: "ret", Length: 1},
	}
	builder := cfg.NewCFGBuilder()
	c, err := builder.Build(instrs)
	if err != nil {
		t.Fatalf("build cfg: %v", err)
	}
	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("compute dominators: %v", err)
	}
	li, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("detect loops: %v", err)
	}
	return c, dt, li
}

// buildIfThenCFG builds a diamond cfg:
//
//	bb_entry (cmp+je) -> bb_then (mov) -> bb_merge (ret)
//	bb_entry           -> bb_merge
func buildIfThenCFG(t *testing.T) (*cfg.CFG, *cfg.DominatorTree, *cfg.LoopInfo) {
	t.Helper()
	instrs := []*disasm.Instruction{
		{Address: 0x1000, Mnemonic: "cmp", Length: 3},
		{
			Address:  0x1003,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x100a, Size: disasm.Size32}},
		},
		{Address: 0x1005, Mnemonic: "mov", Length: 3},
		{Address: 0x1008, Mnemonic: "jmp", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x100a, Size: disasm.Size32}},
		},
		{Address: 0x100a, Mnemonic: "ret", Length: 1},
	}
	builder := cfg.NewCFGBuilder()
	c, err := builder.Build(instrs)
	if err != nil {
		t.Fatalf("build cfg: %v", err)
	}
	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("compute dominators: %v", err)
	}
	li, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("detect loops: %v", err)
	}
	return c, dt, li
}

// buildWhileLoopCFG builds a while-loop cfg:
//
//	bb_entry -> bb_header (cmp+je) -> bb_body (inc+jmp->header) back-edge
//	bb_header -> bb_exit (ret)
func buildWhileLoopCFG(t *testing.T) (*cfg.CFG, *cfg.DominatorTree, *cfg.LoopInfo) {
	t.Helper()
	instrs := []*disasm.Instruction{
		// entry: initialize
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "jmp", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005, Size: disasm.Size32}},
		},
		// header: condition check
		{Address: 0x1005, Mnemonic: "cmp", Length: 3},
		{Address: 0x1008, Mnemonic: "jge", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1010, Size: disasm.Size32}},
		},
		// body: loop body + back-edge
		{Address: 0x100a, Mnemonic: "inc", Length: 2},
		{Address: 0x100c, Mnemonic: "jmp", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005, Size: disasm.Size32}},
		},
		// exit
		{Address: 0x1010, Mnemonic: "ret", Length: 1},
	}
	builder := cfg.NewCFGBuilder()
	c, err := builder.Build(instrs)
	if err != nil {
		t.Fatalf("build cfg: %v", err)
	}
	dt, err := builder.ComputeDominators()
	if err != nil {
		t.Fatalf("compute dominators: %v", err)
	}
	li, err := builder.DetectLoops()
	if err != nil {
		t.Fatalf("detect loops: %v", err)
	}
	return c, dt, li
}

// irBlocksFromCFG creates an IRBlockMap with empty instruction slices for all blocks
func irBlocksFromCFG(c *cfg.CFG) IRBlockMap {
	m := make(IRBlockMap, len(c.Blocks))
	for id := range c.Blocks {
		m[id] = []ir.IRInstruction{}
	}
	return m
}

// TestNew_NilInputs verifies that New returns errors for nil inputs
func TestNew_NilInputs(t *testing.T) {
	c, dt, li := buildLinearCFG(t)
	irBlocks := irBlocksFromCFG(c)

	if _, err := New(nil, dt, li, irBlocks); err == nil {
		t.Error("expected error for nil cfg")
	}
	if _, err := New(c, nil, li, irBlocks); err == nil {
		t.Error("expected error for nil dominator tree")
	}
	if _, err := New(c, dt, nil, irBlocks); err == nil {
		t.Error("expected error for nil loop info")
	}
	if _, err := New(c, dt, li, nil); err == nil {
		t.Error("expected error for nil ir blocks")
	}
}

// TestStructure_LinearSequence verifies structuring of a linear 3-block sequence
func TestStructure_LinearSequence(t *testing.T) {
	c, dt, li := buildLinearCFG(t)
	engine, err := New(c, dt, li, irBlocksFromCFG(c))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ast, err := engine.Structure()
	if err != nil {
		t.Fatalf("Structure: %v", err)
	}
	if ast == nil {
		t.Fatal("expected non-nil ast")
	}
	if ast.FunctionID != c.Entry {
		t.Errorf("expected function id %d, got %d", c.Entry, ast.FunctionID)
	}
}

// TestStructure_IfThen verifies structuring of an if-then pattern
func TestStructure_IfThen(t *testing.T) {
	c, dt, li := buildIfThenCFG(t)
	engine, err := New(c, dt, li, irBlocksFromCFG(c))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ast, err := engine.Structure()
	if err != nil {
		t.Fatalf("Structure: %v", err)
	}
	if ast == nil {
		t.Fatal("expected non-nil ast")
	}
}

// TestStructure_WhileLoop verifies structuring of a while loop
func TestStructure_WhileLoop(t *testing.T) {
	c, dt, li := buildWhileLoopCFG(t)
	engine, err := New(c, dt, li, irBlocksFromCFG(c))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ast, err := engine.Structure()
	if err != nil {
		t.Fatalf("Structure: %v", err)
	}
	if ast == nil {
		t.Fatal("expected non-nil ast")
	}
	if !containsLoopStatement(ast.Body) {
		t.Error("expected loop statement in structured ast")
	}
}

// TestIsBackEdge verifies back-edge detection in a loop cfg
func TestIsBackEdge(t *testing.T) {
	c, dt, li := buildWhileLoopCFG(t)
	engine, err := New(c, dt, li, irBlocksFromCFG(c))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// find the back-edge: body -> header
	foundBackEdge := false
	for _, edge := range c.Edges {
		if engine.isBackEdge(edge.From, edge.To) {
			foundBackEdge = true
			break
		}
	}
	if !foundBackEdge {
		t.Error("expected at least one back-edge in while loop cfg")
	}
}

// TestMergeSequential verifies sequential statement merging
func TestMergeSequential(t *testing.T) {
	engine := &Engine{gotoLabels: make(map[cfg.BlockID]string)}

	a := IRBlock{BlockID: 1}
	b := IRBlock{BlockID: 2}
	result := engine.mergeSequential(a, b)

	block, ok := result.(Block)
	if !ok {
		t.Fatalf("expected Block, got %T", result)
	}
	if len(block.Stmts) != 2 {
		t.Errorf("expected 2 statements, got %d", len(block.Stmts))
	}

	// merging with empty block should return the non-empty one
	empty := Block{Stmts: nil}
	result2 := engine.mergeSequential(empty, a)
	if _, ok := result2.(IRBlock); !ok {
		t.Errorf("expected IRBlock when merging with empty, got %T", result2)
	}
}

// TestStructuredAST_String verifies that String() methods don't panic
func TestStructuredAST_String(t *testing.T) {
	cond := ir.ConstantExpr{Value: ir.BoolConstant{Value: true}}
	stmts := []Statement{
		IRBlock{BlockID: 1, Instructions: []ir.IRInstruction{ir.Return{}}},
		IfStatement{Condition: cond, Then: Block{Stmts: nil}, Else: nil},
		IfStatement{Condition: cond, Then: Block{Stmts: nil}, Else: Block{Stmts: nil}},
		WhileStatement{Condition: cond, Body: Block{Stmts: nil}},
		DoWhileStatement{Body: Block{Stmts: nil}, Condition: cond},
		GotoStatement{Target: 5, Label: "L1"},
		LabelStatement{Name: "L1"},
		ReturnStatement{Value: nil},
		ReturnStatement{Value: cond},
	}
	for _, stmt := range stmts {
		s := stmt.String()
		if s == "" {
			t.Errorf("expected non-empty string for %T", stmt)
		}
	}
}

// TestExtractBranchCondition verifies condition extraction from IR blocks
func TestExtractBranchCondition(t *testing.T) {
	c, dt, li := buildLinearCFG(t)
	cond := ir.ConstantExpr{Value: ir.BoolConstant{Value: false}}

	irBlocks := irBlocksFromCFG(c)
	// inject a branch instruction into entry block
	irBlocks[c.Entry] = []ir.IRInstruction{
		ir.Branch{Condition: cond, TrueTarget: 1, FalseTarget: 2},
	}

	engine, err := New(c, dt, li, irBlocks)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	extracted := engine.extractBranchCondition(c.Entry)
	if extracted == nil {
		t.Fatal("expected non-nil condition")
	}
}

// containsLoopStatement recursively checks if stmt contains a loop statement
func containsLoopStatement(stmt Statement) bool {
	switch s := stmt.(type) {
	case WhileStatement:
		return true
	case DoWhileStatement:
		return true
	case Block:
		for _, child := range s.Stmts {
			if containsLoopStatement(child) {
				return true
			}
		}
	case IfStatement:
		if containsLoopStatement(s.Then) {
			return true
		}
		if s.Else != nil && containsLoopStatement(s.Else) {
			return true
		}
	}
	return false
}
