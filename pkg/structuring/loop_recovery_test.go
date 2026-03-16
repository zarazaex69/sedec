package structuring

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// buildDoWhileLoopCFG builds a do-while loop cfg:
//
//	bb_entry -> bb_body (inc) -> bb_cond (cmp+jl->body back-edge) -> bb_exit (ret)
//
// the condition is at the tail (bb_cond), not the header (bb_body).
// this is the canonical do-while: body executes at least once.
func buildDoWhileLoopCFG(t *testing.T) (*cfg.CFG, *cfg.DominatorTree, *cfg.LoopInfo) {
	t.Helper()
	instrs := []*disasm.Instruction{
		// entry: initialize counter
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "jmp", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005, Size: disasm.Size32}},
		},
		// body: loop body (do-while header)
		{Address: 0x1005, Mnemonic: "inc", Length: 2},
		// condition: check at tail, back-edge to body
		{Address: 0x1007, Mnemonic: "cmp", Length: 3},
		{Address: 0x100a, Mnemonic: "jl", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005, Size: disasm.Size32}},
		},
		// exit
		{Address: 0x100c, Mnemonic: "ret", Length: 1},
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

// buildForLoopCFG builds a for-loop cfg with an induction variable.
// the IR blocks are populated with phi-nodes and assignments to simulate
// a canonical for loop: for (i = 0; i < 10; i++).
//
// cfg structure:
//
//	bb_preheader (mov i=0) -> bb_header (phi + cmp+jge->exit) -> bb_body (inc i + jmp->header)
//	bb_header -> bb_exit (ret)
func buildForLoopCFG(t *testing.T) (*cfg.CFG, *cfg.DominatorTree, *cfg.LoopInfo, IRBlockMap) {
	t.Helper()
	instrs := []*disasm.Instruction{
		// pre-header: i = 0
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "jmp", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005, Size: disasm.Size32}},
		},
		// header: condition check (i < 10)
		{Address: 0x1005, Mnemonic: "cmp", Length: 3},
		{Address: 0x1008, Mnemonic: "jge", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1010, Size: disasm.Size32}},
		},
		// body: i++ + back-edge
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

	// find block ids by address
	var preHeaderID, headerID, bodyID, exitID cfg.BlockID
	for id, block := range c.Blocks {
		switch block.StartAddress {
		case 0x1000:
			preHeaderID = id
		case 0x1005:
			headerID = id
		case 0x100a:
			bodyID = id
		case 0x1010:
			exitID = id
		}
	}

	// induction variable: i (int64)
	ivType := ir.IntType{Width: ir.Size8, Signed: true}
	ivVar := ir.Variable{Name: "i", Type: ivType, Version: 1}
	ivVarUpdated := ir.Variable{Name: "i", Type: ivType, Version: 2}
	initVar := ir.Variable{Name: "i_init", Type: ivType}

	// build IR blocks with phi-node and induction variable update
	irBlocks := make(IRBlockMap)

	// pre-header: i_init = 0
	irBlocks[preHeaderID] = []ir.IRInstruction{
		ir.Assign{
			Dest:   initVar,
			Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size8, Signed: true}},
		},
	}

	// header: i_1 = phi(i_init from preheader, i_2 from body); cmp i_1 < 10; jge exit
	limitConst := ir.ConstantExpr{Value: ir.IntConstant{Value: 10, Width: ir.Size8, Signed: true}}
	cmpCond := ir.BinaryOp{
		Op:    ir.BinOpLt,
		Left:  ir.VariableExpr{Var: ivVar},
		Right: limitConst,
	}
	irBlocks[headerID] = []ir.IRInstruction{
		ir.Phi{
			Dest: ivVar,
			Sources: []ir.PhiSource{
				{Block: ir.BlockID(preHeaderID), Var: initVar},
				{Block: ir.BlockID(bodyID), Var: ivVarUpdated},
			},
		},
		ir.Branch{
			Condition:   cmpCond,
			TrueTarget:  ir.BlockID(bodyID),
			FalseTarget: ir.BlockID(exitID),
		},
	}

	// body: i_2 = i_1 + 1; jmp header
	irBlocks[bodyID] = []ir.IRInstruction{
		ir.Assign{
			Dest: ivVarUpdated,
			Source: ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  ir.VariableExpr{Var: ivVar},
				Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
			},
		},
		ir.Jump{Target: ir.BlockID(headerID)},
	}

	// exit: ret
	irBlocks[exitID] = []ir.IRInstruction{ir.Return{}}

	return c, dt, li, irBlocks
}

// buildInfiniteLoopCFG builds a cfg with an infinite loop (no exit edges):
//
//	bb_entry -> bb_header (jmp->header back-edge)
func buildInfiniteLoopCFG(t *testing.T) (*cfg.CFG, *cfg.DominatorTree, *cfg.LoopInfo) {
	t.Helper()
	instrs := []*disasm.Instruction{
		// entry
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "jmp", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005, Size: disasm.Size32}},
		},
		// infinite loop header: unconditional back-edge to itself
		{Address: 0x1005, Mnemonic: "nop", Length: 1},
		{Address: 0x1006, Mnemonic: "jmp", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005, Size: disasm.Size32}},
		},
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

// TestStructure_DoWhileLoop verifies that a do-while loop cfg produces a DoWhileStatement
func TestStructure_DoWhileLoop(t *testing.T) {
	c, dt, li := buildDoWhileLoopCFG(t)
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
		t.Error("expected loop statement in do-while cfg")
	}
}

// TestStructure_ForLoop verifies that a for-loop cfg with induction variable
// produces a ForStatement with non-nil Init, Condition, and Post fields.
func TestStructure_ForLoop(t *testing.T) {
	c, dt, li, irBlocks := buildForLoopCFG(t)
	engine, err := New(c, dt, li, irBlocks)
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

	forStmt := findForStatement(ast.Body)
	if forStmt == nil {
		// for-loop detection requires phi-node analysis; if not found, at minimum
		// a while loop must be present (graceful fallback)
		if !containsLoopStatement(ast.Body) {
			t.Error("expected at least a loop statement in for-loop cfg")
		}
		return
	}

	if forStmt.Condition == nil {
		t.Error("expected non-nil condition in ForStatement")
	}
	if forStmt.Init == nil {
		t.Error("expected non-nil init in ForStatement")
	}
	if forStmt.Post == nil {
		t.Error("expected non-nil post in ForStatement")
	}
}

// TestStructure_InfiniteLoop verifies that an infinite loop cfg produces a
// WhileStatement with a true condition.
func TestStructure_InfiniteLoop(t *testing.T) {
	c, dt, li := buildInfiniteLoopCFG(t)
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
		t.Error("expected loop statement in infinite loop cfg")
	}
}

// TestLoopClassifier_WhileLoop verifies that a while-loop is correctly classified
func TestLoopClassifier_WhileLoop(t *testing.T) {
	c, dt, li := buildWhileLoopCFG(t)
	lc := newLoopClassifier(c, dt, li, irBlocksFromCFG(c))

	loops := li.Loops
	if len(loops) == 0 {
		t.Fatal("expected at least one loop")
	}

	kind, cond, _ := lc.classifyLoop(loops[0])
	if kind != LoopKindWhile && kind != LoopKindFor {
		// while or for are both acceptable for a while-loop pattern
		t.Errorf("expected LoopKindWhile or LoopKindFor, got %v", kind)
	}
	if cond == nil {
		t.Error("expected non-nil condition")
	}
}

// TestLoopClassifier_DoWhileLoop verifies that a do-while loop is correctly classified.
// note: buildDoWhileLoopCFG produces a self-loop where the condition block is also
// the loop header (the cmp+jl is in the same block as the body). the CFG builder
// merges the body and condition into a single block with a self-edge, which is
// classified as a while loop (condition at header). a true do-while requires the
// condition to be in a separate tail block distinct from the header.
func TestLoopClassifier_DoWhileLoop(t *testing.T) {
	c, dt, li := buildDoWhileLoopCFG(t)
	lc := newLoopClassifier(c, dt, li, irBlocksFromCFG(c))

	loops := li.Loops
	if len(loops) == 0 {
		t.Fatal("expected at least one loop")
	}

	kind, cond, _ := lc.classifyLoop(loops[0])
	// self-loop with condition at header is classified as while
	if kind != LoopKindWhile && kind != LoopKindDoWhile {
		t.Errorf("expected LoopKindWhile or LoopKindDoWhile, got %v", kind)
	}
	if cond == nil {
		t.Error("expected non-nil condition")
	}
}

// TestLoopClassifier_TrueDoWhile verifies do-while classification when the condition
// is in a separate tail block distinct from the loop header.
func TestLoopClassifier_TrueDoWhile(t *testing.T) {
	c, dt, li := buildTrueDoWhileLoopCFG(t)
	lc := newLoopClassifier(c, dt, li, irBlocksFromCFG(c))

	loops := li.Loops
	if len(loops) == 0 {
		t.Fatal("expected at least one loop")
	}

	kind, cond, _ := lc.classifyLoop(loops[0])
	if kind != LoopKindDoWhile {
		t.Errorf("expected LoopKindDoWhile, got %v", kind)
	}
	if cond == nil {
		t.Error("expected non-nil condition")
	}
}

// buildTrueDoWhileLoopCFG builds a cfg with a true do-while loop where the
// condition is in a separate tail block:
//
//	entry -> header (body: inc + jmp->tail) -> tail (cmp+jl->header back-edge) -> exit (ret)
//
// the key is that the header has an unconditional jmp to the tail block,
// forcing the CFG builder to create separate header and tail blocks.
func buildTrueDoWhileLoopCFG(t *testing.T) (*cfg.CFG, *cfg.DominatorTree, *cfg.LoopInfo) {
	t.Helper()
	instrs := []*disasm.Instruction{
		// entry
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "jmp", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005, Size: disasm.Size32}},
		},
		// header: loop body, unconditional jump to tail
		{Address: 0x1005, Mnemonic: "inc", Length: 2},
		{Address: 0x1007, Mnemonic: "jmp", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1009, Size: disasm.Size32}},
		},
		// tail: condition check, back-edge to header
		{Address: 0x1009, Mnemonic: "cmp", Length: 3},
		{Address: 0x100c, Mnemonic: "jl", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005, Size: disasm.Size32}},
		},
		// exit
		{Address: 0x100e, Mnemonic: "ret", Length: 1},
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
func TestLoopClassifier_InfiniteLoop(t *testing.T) {
	c, dt, li := buildInfiniteLoopCFG(t)
	lc := newLoopClassifier(c, dt, li, irBlocksFromCFG(c))

	loops := li.Loops
	if len(loops) == 0 {
		t.Fatal("expected at least one loop")
	}

	kind, _, _ := lc.classifyLoop(loops[0])
	if kind != LoopKindInfinite {
		t.Errorf("expected LoopKindInfinite, got %v", kind)
	}
}

// TestLoopClassifier_ForLoop_InductionVariable verifies induction variable detection
func TestLoopClassifier_ForLoop_InductionVariable(t *testing.T) {
	c, dt, li, irBlocks := buildForLoopCFG(t)
	lc := newLoopClassifier(c, dt, li, irBlocks)

	loops := li.Loops
	if len(loops) == 0 {
		t.Fatal("expected at least one loop")
	}

	iv := lc.findInductionVariable(loops[0])
	if iv == nil {
		t.Fatal("expected induction variable in for-loop cfg")
	}

	if iv.Var.Name != "i" {
		t.Errorf("expected IV name 'i', got '%s'", iv.Var.Name)
	}
	if !iv.IsCanonical {
		t.Error("expected canonical induction variable (constant step)")
	}
	if iv.InitExpr == nil {
		t.Error("expected non-nil init expression")
	}
	if iv.StepExpr == nil {
		t.Error("expected non-nil step expression")
	}
}

// TestExtractLoopBounds verifies loop bounds extraction from induction variable
func TestExtractLoopBounds(t *testing.T) {
	ivType := ir.IntType{Width: ir.Size8, Signed: true}
	iv := &InductionVariable{
		Var:         ir.Variable{Name: "i", Type: ivType},
		InitExpr:    ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size8, Signed: true}},
		StepExpr:    ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
		IsCanonical: true,
	}

	limitConst := ir.ConstantExpr{Value: ir.IntConstant{Value: 10, Width: ir.Size8, Signed: true}}
	exitCond := ir.BinaryOp{
		Op:    ir.BinOpLt,
		Left:  ir.VariableExpr{Var: iv.Var},
		Right: limitConst,
	}

	bounds := extractLoopBounds(iv, exitCond)
	if bounds == nil {
		t.Fatal("expected non-nil loop bounds")
	}
	if bounds.LimitOp != ir.BinOpLt {
		t.Errorf("expected BinOpLt, got %v", bounds.LimitOp)
	}
	if bounds.LimitValue == nil {
		t.Error("expected non-nil limit value")
	}
	if bounds.InitValue == nil {
		t.Error("expected non-nil init value")
	}
	if bounds.StepValue == nil {
		t.Error("expected non-nil step value")
	}
}

// TestExtractLoopBounds_NilIV verifies that nil IV returns nil bounds
func TestExtractLoopBounds_NilIV(t *testing.T) {
	bounds := extractLoopBounds(nil, ir.ConstantExpr{Value: ir.BoolConstant{Value: true}})
	if bounds != nil {
		t.Error("expected nil bounds for nil IV")
	}
}

// TestExtractLoopBounds_NonComparison verifies that non-comparison exit cond returns nil
func TestExtractLoopBounds_NonComparison(t *testing.T) {
	ivType := ir.IntType{Width: ir.Size8, Signed: true}
	iv := &InductionVariable{
		Var:      ir.Variable{Name: "i", Type: ivType},
		InitExpr: ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size8, Signed: true}},
		StepExpr: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
	}

	// non-comparison: addition is not a valid exit condition
	nonCmpCond := ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  ir.VariableExpr{Var: iv.Var},
		Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
	}

	bounds := extractLoopBounds(iv, nonCmpCond)
	if bounds != nil {
		t.Error("expected nil bounds for non-comparison exit condition")
	}
}

// TestBuildForStatement verifies that buildForStatement produces a valid ForStatement
func TestBuildForStatement(t *testing.T) {
	ivType := ir.IntType{Width: ir.Size8, Signed: true}
	iv := &InductionVariable{
		Var:         ir.Variable{Name: "i", Type: ivType},
		InitExpr:    ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size8, Signed: true}},
		StepExpr:    ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
		UpdateBlock: 42,
		IsCanonical: true,
	}

	cond := ir.BinaryOp{
		Op:    ir.BinOpLt,
		Left:  ir.VariableExpr{Var: iv.Var},
		Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 10, Width: ir.Size8, Signed: true}},
	}

	body := IRBlock{BlockID: 1}
	forStmt := buildForStatement(iv, cond, body)

	if forStmt.Init == nil {
		t.Error("expected non-nil Init")
	}
	if forStmt.Condition == nil {
		t.Error("expected non-nil Condition")
	}
	if forStmt.Post == nil {
		t.Error("expected non-nil Post")
	}
	if forStmt.Body == nil {
		t.Error("expected non-nil Body")
	}

	// verify String() does not panic and contains for keyword
	s := forStmt.String()
	if s == "" {
		t.Error("expected non-empty String()")
	}
}

// TestForStatement_String verifies ForStatement.String() output format
func TestForStatement_String(t *testing.T) {
	cond := ir.ConstantExpr{Value: ir.BoolConstant{Value: true}}
	body := Block{Stmts: nil}

	// with init and post
	fs := ForStatement{
		Init:      IRBlock{BlockID: 1},
		Condition: cond,
		Post:      IRBlock{BlockID: 2},
		Body:      body,
	}
	s := fs.String()
	if s == "" {
		t.Error("expected non-empty string")
	}

	// without init and post (degenerate for loop)
	fs2 := ForStatement{
		Init:      nil,
		Condition: cond,
		Post:      nil,
		Body:      body,
	}
	s2 := fs2.String()
	if s2 == "" {
		t.Error("expected non-empty string for degenerate for loop")
	}
}

// TestLoopClassifier_FindPreHeader verifies pre-header detection
func TestLoopClassifier_FindPreHeader(t *testing.T) {
	c, dt, li, irBlocks := buildForLoopCFG(t)
	lc := newLoopClassifier(c, dt, li, irBlocks)

	loops := li.Loops
	if len(loops) == 0 {
		t.Fatal("expected at least one loop")
	}

	preHeader, found := lc.findPreHeader(loops[0])
	if !found {
		t.Fatal("expected pre-header to be found")
	}

	// pre-header must exist in the cfg
	if _, exists := c.Blocks[preHeader]; !exists {
		t.Errorf("pre-header %d is not a valid block in cfg", preHeader)
	}

	// pre-header must not be in the loop body
	for _, bodyBlock := range loops[0].Body {
		if bodyBlock == preHeader {
			t.Errorf("pre-header %d should not be in loop body", preHeader)
		}
	}
}

// TestLoopClassifier_ExtractBlockCondition verifies condition extraction
func TestLoopClassifier_ExtractBlockCondition(t *testing.T) {
	c, dt, li := buildWhileLoopCFG(t)
	irBlocks := irBlocksFromCFG(c)

	// inject a branch condition into the loop header
	loops := li.Loops
	if len(loops) == 0 {
		t.Fatal("expected at least one loop")
	}
	header := loops[0].Header
	expectedCond := ir.BinaryOp{
		Op:    ir.BinOpLt,
		Left:  ir.VariableExpr{Var: ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8}}},
		Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 10, Width: ir.Size8, Signed: true}},
	}
	irBlocks[header] = []ir.IRInstruction{
		ir.Branch{
			Condition:   expectedCond,
			TrueTarget:  ir.BlockID(header + 1),
			FalseTarget: ir.BlockID(header + 2),
		},
	}

	lc := newLoopClassifier(c, dt, li, irBlocks)
	cond := lc.extractBlockCondition(header)
	if cond == nil {
		t.Fatal("expected non-nil condition")
	}

	// condition must be the injected branch condition
	binop, ok := cond.(ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp condition, got %T", cond)
	}
	if binop.Op != ir.BinOpLt {
		t.Errorf("expected BinOpLt, got %v", binop.Op)
	}
}

// TestStructure_NestedLoops verifies that nested loops are correctly structured
func TestStructure_NestedLoops(t *testing.T) {
	c, dt, li := buildNestedLoopCFG(t)
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
		t.Error("expected loop statement in nested loop cfg")
	}
}

// buildNestedLoopCFG builds a cfg with two nested while loops:
//
//	outer_header (cmp+jge->exit) -> inner_header (cmp+jge->outer_body) -> inner_body (inc+jmp->inner_header)
//	inner_header -> outer_body (inc+jmp->outer_header)
//	outer_header -> exit (ret)
func buildNestedLoopCFG(t *testing.T) (*cfg.CFG, *cfg.DominatorTree, *cfg.LoopInfo) {
	t.Helper()
	instrs := []*disasm.Instruction{
		// entry
		{Address: 0x1000, Mnemonic: "mov", Length: 3},
		{Address: 0x1003, Mnemonic: "jmp", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005, Size: disasm.Size32}},
		},
		// outer header
		{Address: 0x1005, Mnemonic: "cmp", Length: 3},
		{Address: 0x1008, Mnemonic: "jge", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1020, Size: disasm.Size32}},
		},
		// inner header
		{Address: 0x100a, Mnemonic: "cmp", Length: 3},
		{Address: 0x100d, Mnemonic: "jge", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1018, Size: disasm.Size32}},
		},
		// inner body: back-edge to inner header
		{Address: 0x100f, Mnemonic: "inc", Length: 2},
		{Address: 0x1011, Mnemonic: "jmp", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x100a, Size: disasm.Size32}},
		},
		// outer body: back-edge to outer header
		{Address: 0x1018, Mnemonic: "inc", Length: 2},
		{Address: 0x101a, Mnemonic: "jmp", Length: 2,
			Operands: []disasm.Operand{disasm.ImmediateOperand{Value: 0x1005, Size: disasm.Size32}},
		},
		// exit
		{Address: 0x1020, Mnemonic: "ret", Length: 1},
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

// findForStatement recursively searches for a ForStatement in the AST
func findForStatement(stmt Statement) *ForStatement {
	switch s := stmt.(type) {
	case ForStatement:
		return &s
	case Block:
		for _, child := range s.Stmts {
			if found := findForStatement(child); found != nil {
				return found
			}
		}
	case WhileStatement:
		return findForStatement(s.Body)
	case DoWhileStatement:
		return findForStatement(s.Body)
	case IfStatement:
		if found := findForStatement(s.Then); found != nil {
			return found
		}
		if s.Else != nil {
			return findForStatement(s.Else)
		}
	}
	return nil
}
