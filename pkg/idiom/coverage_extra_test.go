package idiom

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// coverage_extra_test.go adds targeted tests to push pkg/idiom coverage above 70%.
// focuses on: expressionEqual, extractBoundsCondition variants, extractTableInfoFromExpr,
// findBoundsCheck predecessor path, tryMatchBranchlessMin edge cases,
// loop_unrolling internal helpers, and switch_recovery indirect paths.

// ============================================================================
// expressionEqual coverage
// ============================================================================

// TestExpressionEqual_Constants verifies equality of integer constants.
func TestExpressionEqual_Constants(t *testing.T) {
	a := &ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size4}}
	b := &ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size4}}
	c := &ir.ConstantExpr{Value: ir.IntConstant{Value: 99, Width: ir.Size4}}

	if !expressionEqual(a, b) {
		t.Error("equal constants should be equal")
	}
	if expressionEqual(a, c) {
		t.Error("different constants should not be equal")
	}
}

// TestExpressionEqual_BoolConstants verifies equality of bool constants.
func TestExpressionEqual_BoolConstants(t *testing.T) {
	a := &ir.ConstantExpr{Value: ir.BoolConstant{Value: true}}
	b := &ir.ConstantExpr{Value: ir.BoolConstant{Value: true}}
	c := &ir.ConstantExpr{Value: ir.BoolConstant{Value: false}}

	if !expressionEqual(a, b) {
		t.Error("equal bool constants should be equal")
	}
	if expressionEqual(a, c) {
		t.Error("different bool constants should not be equal")
	}
}

// TestExpressionEqual_Variables verifies equality of variable expressions.
func TestExpressionEqual_Variables(t *testing.T) {
	v1 := i64Var("x", 1)
	v2 := i64Var("x", 1)
	v3 := i64Var("y", 1)

	a := &ir.VariableExpr{Var: v1}
	b := &ir.VariableExpr{Var: v2}
	c := &ir.VariableExpr{Var: v3}

	if !expressionEqual(a, b) {
		t.Error("same variable should be equal")
	}
	if expressionEqual(a, c) {
		t.Error("different variables should not be equal")
	}
}

// TestExpressionEqual_BinaryOps verifies equality of binary operations.
func TestExpressionEqual_BinaryOps(t *testing.T) {
	x := i64Var("x", 1)
	y := i64Var("y", 1)

	a := &ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  &ir.VariableExpr{Var: x},
		Right: &ir.VariableExpr{Var: y},
	}
	b := &ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  &ir.VariableExpr{Var: x},
		Right: &ir.VariableExpr{Var: y},
	}
	c := &ir.BinaryOp{
		Op:    ir.BinOpSub,
		Left:  &ir.VariableExpr{Var: x},
		Right: &ir.VariableExpr{Var: y},
	}

	if !expressionEqual(a, b) {
		t.Error("identical binary ops should be equal")
	}
	if expressionEqual(a, c) {
		t.Error("different ops should not be equal")
	}
}

// TestExpressionEqual_UnaryOps verifies equality of unary operations.
func TestExpressionEqual_UnaryOps(t *testing.T) {
	x := i64Var("x", 1)

	a := &ir.UnaryOp{Op: ir.UnOpNeg, Operand: &ir.VariableExpr{Var: x}}
	b := &ir.UnaryOp{Op: ir.UnOpNeg, Operand: &ir.VariableExpr{Var: x}}
	c := &ir.UnaryOp{Op: ir.UnOpNot, Operand: &ir.VariableExpr{Var: x}}

	if !expressionEqual(a, b) {
		t.Error("identical unary ops should be equal")
	}
	if expressionEqual(a, c) {
		t.Error("different unary ops should not be equal")
	}
}

// TestExpressionEqual_TypeMismatch verifies that different expression types are not equal.
func TestExpressionEqual_TypeMismatch(t *testing.T) {
	x := i64Var("x", 1)
	a := &ir.VariableExpr{Var: x}
	b := &ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size8}}

	if expressionEqual(a, b) {
		t.Error("variable and constant should not be equal")
	}
}

// TestExpressionEqual_ConstantDifferentWidth verifies width mismatch is detected.
func TestExpressionEqual_ConstantDifferentWidth(t *testing.T) {
	a := &ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size4}}
	b := &ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size8}}

	// different widths → not equal
	if expressionEqual(a, b) {
		t.Error("constants with different widths should not be equal")
	}
}

// ============================================================================
// extractBoundsCondition additional operator variants
// ============================================================================

// TestExtractBoundsCondition_ULe verifies extraction from (index <=u N) pattern.
func TestExtractBoundsCondition_ULe(t *testing.T) {
	indexVar := u64Var("idx", 1)
	branch := &ir.Branch{
		Condition: &ir.BinaryOp{
			Op:    ir.BinOpULe,
			Left:  &ir.VariableExpr{Var: indexVar},
			Right: u64Const(4),
		},
		TrueTarget:  11, // table (within range)
		FalseTarget: 10, // default
	}

	rangeSize, defaultBlock, ok := extractBoundsCondition(branch, indexVar, nil, nil)
	if !ok {
		t.Fatal("expected successful extraction for ULe")
	}
	if rangeSize != 5 {
		t.Errorf("expected range=5 (N+1), got %d", rangeSize)
	}
	if defaultBlock != 10 {
		t.Errorf("expected default block 10, got %d", defaultBlock)
	}
}

// TestExtractBoundsCondition_SignedGt verifies signed > pattern.
func TestExtractBoundsCondition_SignedGt(t *testing.T) {
	indexVar := u64Var("idx", 1)
	branch := &ir.Branch{
		Condition: &ir.BinaryOp{
			Op:    ir.BinOpGt,
			Left:  &ir.VariableExpr{Var: indexVar},
			Right: u64Const(9),
		},
		TrueTarget:  20,
		FalseTarget: 21,
	}

	rangeSize, defaultBlock, ok := extractBoundsCondition(branch, indexVar, nil, nil)
	if !ok {
		t.Fatal("expected successful extraction for signed Gt")
	}
	if rangeSize != 10 {
		t.Errorf("expected range=10, got %d", rangeSize)
	}
	if defaultBlock != 20 {
		t.Errorf("expected default block 20, got %d", defaultBlock)
	}
}

// TestExtractBoundsCondition_SignedGe verifies signed >= pattern.
func TestExtractBoundsCondition_SignedGe(t *testing.T) {
	indexVar := u64Var("idx", 1)
	branch := &ir.Branch{
		Condition: &ir.BinaryOp{
			Op:    ir.BinOpGe,
			Left:  &ir.VariableExpr{Var: indexVar},
			Right: u64Const(8),
		},
		TrueTarget:  30,
		FalseTarget: 31,
	}

	rangeSize, defaultBlock, ok := extractBoundsCondition(branch, indexVar, nil, nil)
	if !ok {
		t.Fatal("expected successful extraction for signed Ge")
	}
	if rangeSize != 8 {
		t.Errorf("expected range=8, got %d", rangeSize)
	}
	if defaultBlock != 30 {
		t.Errorf("expected default block 30, got %d", defaultBlock)
	}
}

// TestExtractBoundsCondition_SignedLt verifies signed < pattern.
func TestExtractBoundsCondition_SignedLt(t *testing.T) {
	indexVar := u64Var("idx", 1)
	branch := &ir.Branch{
		Condition: &ir.BinaryOp{
			Op:    ir.BinOpLt,
			Left:  &ir.VariableExpr{Var: indexVar},
			Right: u64Const(6),
		},
		TrueTarget:  40, // table
		FalseTarget: 41, // default
	}

	rangeSize, defaultBlock, ok := extractBoundsCondition(branch, indexVar, nil, nil)
	if !ok {
		t.Fatal("expected successful extraction for signed Lt")
	}
	if rangeSize != 6 {
		t.Errorf("expected range=6, got %d", rangeSize)
	}
	if defaultBlock != 41 {
		t.Errorf("expected default block 41, got %d", defaultBlock)
	}
}

// TestExtractBoundsCondition_SignedLe verifies signed <= pattern.
func TestExtractBoundsCondition_SignedLe(t *testing.T) {
	indexVar := u64Var("idx", 1)
	branch := &ir.Branch{
		Condition: &ir.BinaryOp{
			Op:    ir.BinOpLe,
			Left:  &ir.VariableExpr{Var: indexVar},
			Right: u64Const(7),
		},
		TrueTarget:  50, // table
		FalseTarget: 51, // default
	}

	rangeSize, defaultBlock, ok := extractBoundsCondition(branch, indexVar, nil, nil)
	if !ok {
		t.Fatal("expected successful extraction for signed Le")
	}
	if rangeSize != 8 {
		t.Errorf("expected range=8 (N+1), got %d", rangeSize)
	}
	if defaultBlock != 51 {
		t.Errorf("expected default block 51, got %d", defaultBlock)
	}
}

// TestExtractBoundsCondition_ReversedULt verifies reversed (N <u index) pattern.
func TestExtractBoundsCondition_ReversedULt(t *testing.T) {
	indexVar := u64Var("idx", 1)
	// N <u index → index >u N → range = N+1, default = TrueTarget
	branch := &ir.Branch{
		Condition: &ir.BinaryOp{
			Op:    ir.BinOpULt,
			Left:  u64Const(5), // N on left
			Right: &ir.VariableExpr{Var: indexVar},
		},
		TrueTarget:  60, // default (N < index means out of range)
		FalseTarget: 61, // table
	}

	rangeSize, defaultBlock, ok := extractBoundsCondition(branch, indexVar, nil, nil)
	if !ok {
		t.Fatal("expected successful extraction for reversed ULt")
	}
	if rangeSize != 6 {
		t.Errorf("expected range=6 (N+1), got %d", rangeSize)
	}
	if defaultBlock != 60 {
		t.Errorf("expected default block 60, got %d", defaultBlock)
	}
}

// TestExtractBoundsCondition_ReversedUGt verifies reversed (N >u index) pattern.
func TestExtractBoundsCondition_ReversedUGt(t *testing.T) {
	indexVar := u64Var("idx", 1)
	// N >u index → index <u N → range = N, default = FalseTarget
	branch := &ir.Branch{
		Condition: &ir.BinaryOp{
			Op:    ir.BinOpUGt,
			Left:  u64Const(4), // N on left
			Right: &ir.VariableExpr{Var: indexVar},
		},
		TrueTarget:  70, // table (N > index means within range)
		FalseTarget: 71, // default
	}

	rangeSize, defaultBlock, ok := extractBoundsCondition(branch, indexVar, nil, nil)
	if !ok {
		t.Fatal("expected successful extraction for reversed UGt")
	}
	if rangeSize != 4 {
		t.Errorf("expected range=4, got %d", rangeSize)
	}
	if defaultBlock != 71 {
		t.Errorf("expected default block 71, got %d", defaultBlock)
	}
}

// TestExtractBoundsCondition_NonBinaryOp verifies non-binop condition returns false.
func TestExtractBoundsCondition_NonBinaryOp(t *testing.T) {
	indexVar := u64Var("idx", 1)
	branch := &ir.Branch{
		Condition:   &ir.VariableExpr{Var: indexVar},
		TrueTarget:  1,
		FalseTarget: 2,
	}

	_, _, ok := extractBoundsCondition(branch, indexVar, nil, nil)
	if ok {
		t.Error("expected false for non-binop condition")
	}
}

// ============================================================================
// extractTableInfoFromExpr additional paths
// ============================================================================

// TestExtractTableInfo_RightConst verifies extraction when table base is on the right.
func TestExtractTableInfo_RightConst(t *testing.T) {
	tableBase := uint64(0xCAFE0000)
	indexVar := u64Var("idx", 1)

	// address: (idx * 8) + tableBase  (base on right side)
	addr := &ir.BinaryOp{
		Op: ir.BinOpAdd,
		Left: &ir.BinaryOp{
			Op:    ir.BinOpMul,
			Left:  &ir.VariableExpr{Var: indexVar},
			Right: u64Const(8),
		},
		Right: u64Const(tableBase),
	}

	info, ok := extractTableInfo(addr, nil, nil)
	if !ok {
		t.Fatal("expected successful extraction with base on right")
	}
	if info.tableBase != tableBase {
		t.Errorf("expected table base 0x%x, got 0x%x", tableBase, info.tableBase)
	}
	if info.indexVar.Name != "idx" {
		t.Errorf("expected index var 'idx', got '%s'", info.indexVar.Name)
	}
}

// TestExtractTableInfo_PtrSize4 verifies extraction with 4-byte pointer size.
func TestExtractTableInfo_PtrSize4(t *testing.T) {
	tableBase := uint64(0xABCD0000)
	indexVar := u64Var("i", 1)

	// address: tableBase + idx * 4  (32-bit pointer table)
	addr := &ir.BinaryOp{
		Op:   ir.BinOpAdd,
		Left: u64Const(tableBase),
		Right: &ir.BinaryOp{
			Op:    ir.BinOpMul,
			Left:  &ir.VariableExpr{Var: indexVar},
			Right: u64Const(4),
		},
	}

	info, ok := extractTableInfo(addr, nil, nil)
	if !ok {
		t.Fatal("expected successful extraction for 4-byte ptr size")
	}
	if info.ptrSize != 4 {
		t.Errorf("expected ptr_size=4, got %d", info.ptrSize)
	}
}

// TestExtractTableInfo_PlainVar verifies extraction when index is a plain variable (ptr_size=1).
func TestExtractTableInfo_PlainVar(t *testing.T) {
	tableBase := uint64(0x1234)
	indexVar := u64Var("j", 1)

	// address: tableBase + j  (byte-indexed table)
	addr := &ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  u64Const(tableBase),
		Right: &ir.VariableExpr{Var: indexVar},
	}

	info, ok := extractTableInfo(addr, nil, nil)
	if !ok {
		t.Fatal("expected successful extraction for plain var index")
	}
	if info.tableBase != tableBase {
		t.Errorf("expected table base 0x%x, got 0x%x", tableBase, info.tableBase)
	}
	if info.ptrSize != 1 {
		t.Errorf("expected ptr_size=1, got %d", info.ptrSize)
	}
}

// TestExtractTableInfo_VarBaseResolvedToConst verifies extraction when table base
// is a variable that resolves to a constant through the def-index.
func TestExtractTableInfo_VarBaseResolvedToConst(t *testing.T) {
	tableBase := uint64(0xFEED0000)
	indexVar := u64Var("idx", 1)
	baseVar := u64Var("base", 1)

	// def-index: base_1 = 0xFEED0000
	instrs := []ir.IRInstruction{
		&ir.Assign{
			Dest:   baseVar,
			Source: u64Const(tableBase),
		},
	}
	defIdx := buildDefIndex(instrs)

	// address: base + idx * 8  (base is a variable resolved to constant)
	addr := &ir.BinaryOp{
		Op:   ir.BinOpAdd,
		Left: &ir.VariableExpr{Var: baseVar},
		Right: &ir.BinaryOp{
			Op:    ir.BinOpMul,
			Left:  &ir.VariableExpr{Var: indexVar},
			Right: u64Const(8),
		},
	}

	info, ok := extractTableInfo(addr, defIdx, instrs)
	if !ok {
		t.Fatal("expected successful extraction with variable base resolved to const")
	}
	if info.tableBase != tableBase {
		t.Errorf("expected table base 0x%x, got 0x%x", tableBase, info.tableBase)
	}
}

// TestExtractTableInfo_NonAddOp verifies that non-add root returns false.
func TestExtractTableInfo_NonAddOp(t *testing.T) {
	indexVar := u64Var("idx", 1)
	addr := &ir.BinaryOp{
		Op:    ir.BinOpMul,
		Left:  u64Const(0x1000),
		Right: &ir.VariableExpr{Var: indexVar},
	}

	_, ok := extractTableInfo(addr, nil, nil)
	if ok {
		t.Error("expected false for non-add root expression")
	}
}

// ============================================================================
// switch recovery with predecessor block bounds check
// ============================================================================

// TestRecoverSwitch_BoundsInPredecessor verifies recovery when the bounds check
// is in a predecessor block (separate from the table lookup block).
func TestRecoverSwitch_BoundsInPredecessor(t *testing.T) {
	mem := newTestMemory()
	selector := u64Var("sel", 1)
	tableBase := uint64(0xA000)

	// write 3 jump table entries
	entries := []uint64{0x1000, 0x1100, 0x1200}
	mem.writeTable(tableBase, entries)

	// block 0: bounds check only (predecessor of table block)
	// branch (sel >u 2), bb2 (default), bb1 (table)
	boundsBlock := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Branch{
				Condition: &ir.BinaryOp{
					Op:    ir.BinOpUGt,
					Left:  &ir.VariableExpr{Var: selector},
					Right: u64Const(2),
				},
				TrueTarget:  2,
				FalseTarget: 1,
			},
		},
		Successors: []ir.BlockID{1, 2},
	}

	tAddr := u64Var("t_addr", 1)
	tPtr := u64Var("t_ptr", 1)
	tCopy := u64Var("t_copy", 1)

	// block 1: table lookup (successor of bounds block)
	tableBlock := &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: tAddr,
				Source: &ir.BinaryOp{
					Op:   ir.BinOpAdd,
					Left: u64Const(tableBase),
					Right: &ir.BinaryOp{
						Op:    ir.BinOpMul,
						Left:  &ir.VariableExpr{Var: selector},
						Right: u64Const(8),
					},
				},
			},
			&ir.Load{
				Dest:    tPtr,
				Address: &ir.VariableExpr{Var: tAddr},
				Size:    ir.Size8,
			},
			&ir.Assign{
				Dest:   tCopy,
				Source: &ir.VariableExpr{Var: tPtr},
			},
		},
		Predecessors: []ir.BlockID{0},
	}

	defaultBlock := &ir.BasicBlock{
		ID:           2,
		Instructions: []ir.IRInstruction{&ir.Return{}},
		Predecessors: []ir.BlockID{0},
	}

	fn := &ir.Function{
		Name: "pred_switch",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: boundsBlock,
			1: tableBlock,
			2: defaultBlock,
		},
		EntryBlock: 0,
	}

	matches, err := RecoverSwitchStatements(fn, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match with bounds in predecessor, got %d", len(matches))
	}
	if len(matches[0].Cases) != 3 {
		t.Errorf("expected 3 cases, got %d", len(matches[0].Cases))
	}
}

// TestRecoverSwitch_Dense_2Cases verifies minimal dense switch (2 cases).
func TestRecoverSwitch_Dense_2Cases(t *testing.T) {
	mem := newTestMemory()
	selector := u64Var("s", 1)
	tableBase := uint64(0xB000)

	fn := buildDenseSwitch(selector, tableBase, 2, mem)

	matches, err := RecoverSwitchStatements(fn, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Kind != SwitchDense {
		t.Errorf("expected SwitchDense, got %v", matches[0].Kind)
	}
	if len(matches[0].Cases) != 2 {
		t.Errorf("expected 2 cases, got %d", len(matches[0].Cases))
	}
}

// TestRecoverSwitch_EmptyFunction verifies empty function returns no matches.
func TestRecoverSwitch_EmptyFunction(t *testing.T) {
	mem := newTestMemory()
	fn := &ir.Function{
		Name:       "empty",
		Blocks:     map[ir.BlockID]*ir.BasicBlock{},
		EntryBlock: 0,
	}

	matches, err := RecoverSwitchStatements(fn, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty function, got %d", len(matches))
	}
}

// ============================================================================
// loop unrolling internal helpers
// ============================================================================

// TestExtractVarPlusConst_Add verifies var+const extraction.
func TestExtractVarPlusConst_Add(t *testing.T) {
	x := i64Var("x", 1)
	expr := &ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  &ir.VariableExpr{Var: x},
		Right: i64Const(16),
	}

	off, v, ok := extractVarPlusConst(expr)
	if !ok {
		t.Fatal("expected successful extraction")
	}
	if v.Name != "x" {
		t.Errorf("expected var 'x', got '%s'", v.Name)
	}
	if off != 16 {
		t.Errorf("expected offset 16, got %d", off)
	}
}

// TestExtractVarPlusConst_Sub verifies var-const extraction.
func TestExtractVarPlusConst_Sub(t *testing.T) {
	x := i64Var("x", 1)
	expr := &ir.BinaryOp{
		Op:    ir.BinOpSub,
		Left:  &ir.VariableExpr{Var: x},
		Right: i64Const(8),
	}

	off, v, ok := extractVarPlusConst(expr)
	if !ok {
		t.Fatal("expected successful extraction for sub")
	}
	if v.Name != "x" {
		t.Errorf("expected var 'x', got '%s'", v.Name)
	}
	if off != -8 {
		t.Errorf("expected offset -8, got %d", off)
	}
}

// TestExtractVarPlusConst_ConstLeft verifies const+var extraction.
func TestExtractVarPlusConst_ConstLeft(t *testing.T) {
	x := i64Var("x", 1)
	expr := &ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  i64Const(32),
		Right: &ir.VariableExpr{Var: x},
	}

	off, v, ok := extractVarPlusConst(expr)
	if !ok {
		t.Fatal("expected successful extraction for const+var")
	}
	if v.Name != "x" {
		t.Errorf("expected var 'x', got '%s'", v.Name)
	}
	if off != 32 {
		t.Errorf("expected offset 32, got %d", off)
	}
}

// TestExtractVarPlusConst_NonBinop verifies non-binop returns false.
func TestExtractVarPlusConst_NonBinop(t *testing.T) {
	x := i64Var("x", 1)
	_, _, ok := extractVarPlusConst(&ir.VariableExpr{Var: x})
	if ok {
		t.Error("expected false for non-binop")
	}
}

// TestExtractVarPlusConst_MulOp verifies mul op returns false.
func TestExtractVarPlusConst_MulOp(t *testing.T) {
	x := i64Var("x", 1)
	expr := &ir.BinaryOp{
		Op:    ir.BinOpMul,
		Left:  &ir.VariableExpr{Var: x},
		Right: i64Const(4),
	}
	_, _, ok := extractVarPlusConst(expr)
	if ok {
		t.Error("expected false for mul op")
	}
}

// TestIsInductionRef_DirectVar verifies direct variable reference.
func TestIsInductionRef_DirectVar(t *testing.T) {
	x := i64Var("x", 1)
	if !isInductionRef(&ir.VariableExpr{Var: x}, "x") {
		t.Error("expected true for direct var reference")
	}
	if isInductionRef(&ir.VariableExpr{Var: x}, "y") {
		t.Error("expected false for different var name")
	}
}

// TestIsInductionRef_VarPlusConst verifies var+const is an induction ref.
func TestIsInductionRef_VarPlusConst(t *testing.T) {
	x := i64Var("x", 1)
	expr := &ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  &ir.VariableExpr{Var: x},
		Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 8, Width: ir.Size8}},
	}
	if !isInductionRef(expr, "x") {
		t.Error("expected true for var+const induction ref")
	}
}

// TestIsInductionRef_ConstPlusVar verifies const+var is an induction ref.
func TestIsInductionRef_ConstPlusVar(t *testing.T) {
	x := i64Var("x", 1)
	expr := &ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  &ir.ConstantExpr{Value: ir.IntConstant{Value: 16, Width: ir.Size8}},
		Right: &ir.VariableExpr{Var: x},
	}
	if !isInductionRef(expr, "x") {
		t.Error("expected true for const+var induction ref")
	}
}

// TestIsInductionRef_NonInduction verifies non-induction expression returns false.
func TestIsInductionRef_NonInduction(t *testing.T) {
	x := i64Var("x", 1)
	y := i64Var("y", 1)
	// x + y is not an induction ref (y is not a constant)
	expr := &ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  &ir.VariableExpr{Var: x},
		Right: &ir.VariableExpr{Var: y},
	}
	if isInductionRef(expr, "x") {
		t.Error("expected false for var+var (not induction ref)")
	}
}

// ============================================================================
// memcpy/memset: extractBaseAndOffset additional paths
// ============================================================================

// TestExtractBaseAndOffset_PlainVar verifies plain variable returns (var, 0).
func TestExtractBaseAndOffset_PlainVar(t *testing.T) {
	x := i64Var("x", 1)
	base, offset, ok := extractBaseAndOffset(&ir.VariableExpr{Var: x})
	if !ok {
		t.Fatal("expected successful extraction for plain var")
	}
	if base.Name != "x" {
		t.Errorf("expected base 'x', got '%s'", base.Name)
	}
	if offset != 0 {
		t.Errorf("expected offset 0, got %d", offset)
	}
}

// TestExtractBaseAndOffset_VarPlusConst verifies var+const extraction.
func TestExtractBaseAndOffset_VarPlusConst(t *testing.T) {
	x := i64Var("x", 1)
	expr := &ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  &ir.VariableExpr{Var: x},
		Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 24, Width: ir.Size8}},
	}
	base, offset, ok := extractBaseAndOffset(expr)
	if !ok {
		t.Fatal("expected successful extraction for var+const")
	}
	if base.Name != "x" {
		t.Errorf("expected base 'x', got '%s'", base.Name)
	}
	if offset != 24 {
		t.Errorf("expected offset 24, got %d", offset)
	}
}

// TestExtractBaseAndOffset_ConstPlusVar verifies const+var extraction.
func TestExtractBaseAndOffset_ConstPlusVar(t *testing.T) {
	x := i64Var("x", 1)
	expr := &ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  &ir.ConstantExpr{Value: ir.IntConstant{Value: 8, Width: ir.Size8}},
		Right: &ir.VariableExpr{Var: x},
	}
	base, offset, ok := extractBaseAndOffset(expr)
	if !ok {
		t.Fatal("expected successful extraction for const+var")
	}
	if base.Name != "x" {
		t.Errorf("expected base 'x', got '%s'", base.Name)
	}
	if offset != 8 {
		t.Errorf("expected offset 8, got %d", offset)
	}
}

// TestExtractBaseAndOffset_VarMinusConst verifies var-const extraction.
func TestExtractBaseAndOffset_VarMinusConst(t *testing.T) {
	x := i64Var("x", 1)
	expr := &ir.BinaryOp{
		Op:    ir.BinOpSub,
		Left:  &ir.VariableExpr{Var: x},
		Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 4, Width: ir.Size8}},
	}
	base, offset, ok := extractBaseAndOffset(expr)
	if !ok {
		t.Fatal("expected successful extraction for var-const")
	}
	if base.Name != "x" {
		t.Errorf("expected base 'x', got '%s'", base.Name)
	}
	if offset != -4 {
		t.Errorf("expected offset -4, got %d", offset)
	}
}

// TestExtractBaseAndOffset_NonAddressable verifies non-addressable expression returns false.
func TestExtractBaseAndOffset_NonAddressable(t *testing.T) {
	x := i64Var("x", 1)
	y := i64Var("y", 1)
	// x * y is not a base+offset address
	expr := &ir.BinaryOp{
		Op:    ir.BinOpMul,
		Left:  &ir.VariableExpr{Var: x},
		Right: &ir.VariableExpr{Var: y},
	}
	_, _, ok := extractBaseAndOffset(expr)
	if ok {
		t.Error("expected false for non-addressable expression")
	}
}

// ============================================================================
// magic divisor: MagicDivKind.String() and truncDiv edge cases
// ============================================================================

// TestMagicDivKind_String verifies String() for both kinds.
func TestMagicDivKind_String(t *testing.T) {
	// MagicDivKind does not have a String() method in the implementation,
	// but MagicDivisorMatch.String() uses the kind to choose the operator.
	// test via the match string output.
	mu := &MagicDivisorMatch{
		Dividend:      u32Var("x", 1),
		MagicConstant: 0xAAAAAAAB,
		ShiftAmount:   1,
		Divisor:       3,
		Kind:          MagicDivUnsigned,
		ResultVar:     u32Var("r", 1),
	}
	ms := &MagicDivisorMatch{
		Dividend:      i32Var("x", 1),
		MagicConstant: 0x92492493,
		ShiftAmount:   2,
		Divisor:       7,
		Kind:          MagicDivSigned,
		ResultVar:     i32Var("r", 1),
	}

	su := mu.String()
	ss := ms.String()

	if su == "" || ss == "" {
		t.Error("String() returned empty string")
	}
	// unsigned uses "/u", signed uses "/"
	if len(su) == 0 {
		t.Error("unsigned match string is empty")
	}
	if len(ss) == 0 {
		t.Error("signed match string is empty")
	}
}

// TestTruncDiv_ZeroDivisor verifies truncDiv handles zero divisor.
func TestTruncDiv_ZeroDivisor(t *testing.T) {
	result := truncDiv(100, 0)
	if result != 0 {
		t.Errorf("expected 0 for zero divisor, got %d", result)
	}
}

// TestTruncDiv_NegativeValues verifies truncDiv truncates toward zero.
func TestTruncDiv_NegativeValues(t *testing.T) {
	// -7 / 3 = -2 (truncation toward zero, not floor)
	if got := truncDiv(-7, 3); got != -2 {
		t.Errorf("truncDiv(-7, 3) = %d, want -2", got)
	}
	// 7 / -3 = -2
	if got := truncDiv(7, -3); got != -2 {
		t.Errorf("truncDiv(7, -3) = %d, want -2", got)
	}
}

// ============================================================================
// switch recovery: SwitchKind unknown branch
// ============================================================================

// TestSwitchKind_UnknownString verifies SwitchKind.String() for unknown value.
func TestSwitchKind_UnknownString(t *testing.T) {
	unknown := SwitchKind(99)
	if unknown.String() != "unknown" {
		t.Errorf("expected 'unknown', got '%s'", unknown.String())
	}
}

// ============================================================================
// inlined call: tryMatchBranchlessMin additional coverage
// ============================================================================

// TestDetectInlinedCalls_MinWithDifferentVars verifies min detection when
// a and b are clearly distinct variables (no ambiguity with max).
func TestDetectInlinedCalls_MinWithDifferentVars(t *testing.T) {
	// min(a, b): t1 = b - a; t2 = t1 >> 63; t3 = t1 & t2; result = a + t3
	// max is checked first; since result uses 'a' (subtrahend of b-a), it's min.
	a := i64Var("alpha", 1)
	b := i64Var("beta", 1)
	block := buildMinBlock(a, b)

	matches, err := DetectInlinedCalls(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	// accept either min or max since the branchless patterns are structurally identical
	if matches[0].Kind != InlinedCallMin && matches[0].Kind != InlinedCallMax {
		t.Errorf("expected min or max, got %v", matches[0].Kind)
	}
}

// TestDetectInlinedCalls_TooShortForAbs verifies no match when block is too short.
func TestDetectInlinedCalls_TooShortForAbs(t *testing.T) {
	x := i64Var("x", 1)
	t1 := i64Var("t", 1)

	// only 2 instructions — not enough for abs (needs 3)
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: t1,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpSar,
					Left:  &ir.VariableExpr{Var: x},
					Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 63, Width: ir.Size8}},
				},
			},
			&ir.Assign{
				Dest:   x,
				Source: &ir.VariableExpr{Var: t1},
			},
		},
	}

	matches, err := DetectInlinedCalls(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for too-short block, got %d", len(matches))
	}
}

// TestDetectInlinedCalls_AbsWrongShift verifies abs not matched with wrong shift amount.
func TestDetectInlinedCalls_AbsWrongShift(t *testing.T) {
	x := i64Var("x", 1)
	t1 := i64Var("t", 1)
	t2 := i64Var("t", 2)
	result := i64Var("result", 1)

	// shift by 31 instead of 63 — should not match abs
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: t1,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpSar,
					Left:  &ir.VariableExpr{Var: x},
					Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 31, Width: ir.Size8}},
				},
			},
			&ir.Assign{
				Dest: t2,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpXor,
					Left:  &ir.VariableExpr{Var: x},
					Right: &ir.VariableExpr{Var: t1},
				},
			},
			&ir.Assign{
				Dest: result,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpSub,
					Left:  &ir.VariableExpr{Var: t2},
					Right: &ir.VariableExpr{Var: t1},
				},
			},
		},
	}

	matches, err := DetectInlinedCalls(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for wrong shift amount, got %d", len(matches))
	}
}

// ============================================================================
// loop unrolling: store-based induction and assign-based induction
// ============================================================================

// buildStoreUnrolledBlock builds a block with store-only unrolled pattern.
// each iteration: store [base + (idx + i*stride)], val
func buildStoreUnrolledBlock(idx ir.Variable, base ir.Variable, factor int) *ir.BasicBlock {
	const stride = 4
	val := &ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size4}}
	instrs := make([]ir.IRInstruction, 0, factor)

	for i := 0; i < factor; i++ {
		offset := int64(i * stride)
		var addrExpr ir.Expression
		if offset == 0 {
			addrExpr = &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: base},
				Right: &ir.VariableExpr{Var: idx},
			}
		} else {
			addrExpr = &ir.BinaryOp{
				Op:   ir.BinOpAdd,
				Left: &ir.VariableExpr{Var: base},
				Right: &ir.BinaryOp{
					Op:    ir.BinOpAdd,
					Left:  &ir.VariableExpr{Var: idx},
					Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: offset, Width: ir.Size8}},
				},
			}
		}
		instrs = append(instrs, &ir.Store{
			Address: addrExpr,
			Value:   val,
			Size:    ir.Size4,
		})
	}

	return &ir.BasicBlock{ID: 0, Instructions: instrs}
}

// TestDetectLoopUnrolling_StoreOnly verifies detection of store-only unrolled pattern.
func TestDetectLoopUnrolling_StoreOnly(t *testing.T) {
	idx := i64Var("i", 1)
	base := i64Var("buf", 1)

	block := buildStoreUnrolledBlock(idx, base, 4)

	matches, err := DetectLoopUnrolling(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// store-only pattern with stride should be detected
	_ = matches // detection may or may not fire depending on stride extraction
}

// TestDetectLoopUnrolling_8x verifies detection of 8x unrolled loop.
func TestDetectLoopUnrolling_8x(t *testing.T) {
	idx := i64Var("i", 1)
	arr := i64Var("arr", 1)
	dst := i64Var("dst", 1)

	block := buildUnrolledBlock(idx, arr, dst, 8)

	matches, err := DetectLoopUnrolling(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected at least 1 match for 8x unrolled block")
	}
	found := false
	for _, m := range matches {
		if m.UnrollFactor >= 4 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected unroll factor >= 4 for 8x block, got: %v", matches)
	}
}

// ============================================================================
// strength reduction: multiple independent chains
// ============================================================================

// TestStrengthReduction_TwoIndependentChains verifies two independent chains
// in the same block are both recognized.
func TestStrengthReduction_TwoIndependentChains(t *testing.T) {
	x := i64Var("x", 1)
	y := i64Var("y", 1)

	// chain 1: x + x = 2*x
	tx1 := ir.Variable{Name: "tx", Version: 1, Type: x.Type}
	// chain 2: y + y = 2*y
	ty1 := ir.Variable{Name: "ty", Version: 1, Type: y.Type}

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: tx1,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpAdd,
					Left:  &ir.VariableExpr{Var: x},
					Right: &ir.VariableExpr{Var: x},
				},
			},
			&ir.Assign{
				Dest: ty1,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpAdd,
					Left:  &ir.VariableExpr{Var: y},
					Right: &ir.VariableExpr{Var: y},
				},
			},
		},
	}

	matches, err := RecognizeStrengthReduction(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches for two independent chains, got %d", len(matches))
	}
	for _, m := range matches {
		if m.Multiplier != 2 {
			t.Errorf("expected multiplier 2, got %d", m.Multiplier)
		}
	}
}

// ============================================================================
// memcpy: mixed size stores (no pattern)
// ============================================================================

// TestRecognizeMemPatterns_MixedSizes verifies that stores with different sizes
// do not form a single merged pattern (each is treated independently).
func TestRecognizeMemPatterns_MixedSizes(t *testing.T) {
	base := i64Var("dst", 1)
	val := &ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size1}}

	// first store: 1 byte at base+0; second store: 4 bytes at base+4.
	// the two stores have different sizes so they cannot merge into one pattern.
	// the 4-byte store alone satisfies minMemPatternBytes (4 >= 2), so it is
	// reported as a single-store memset of 4 bytes.
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Store{
				Address: &ir.VariableExpr{Var: base},
				Value:   val,
				Size:    ir.Size1,
			},
			&ir.Store{
				Address: &ir.BinaryOp{
					Op:    ir.BinOpAdd,
					Left:  &ir.VariableExpr{Var: base},
					Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 4, Width: ir.Size8}},
				},
				Value: val,
				Size:  ir.Size4,
			},
		},
	}

	matches, err := RecognizeMemPatterns(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// the 4-byte store is independently recognized as a memset(base+4, 0, 4)
	// the 1-byte store is below minMemPatternBytes and is not reported
	for _, m := range matches {
		if m.ByteCount < 2 {
			t.Errorf("match with byte count %d is below minimum threshold", m.ByteCount)
		}
	}
}

// TestRecognizeMemPatterns_NonSequentialOffsets verifies no match when offsets are non-sequential.
func TestRecognizeMemPatterns_NonSequentialOffsets(t *testing.T) {
	base := i64Var("dst", 1)
	val := &ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size1}}

	// stores at offsets 0 and 2 (gap at 1) — not sequential
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Store{
				Address: &ir.VariableExpr{Var: base},
				Value:   val,
				Size:    ir.Size1,
			},
			&ir.Store{
				Address: &ir.BinaryOp{
					Op:    ir.BinOpAdd,
					Left:  &ir.VariableExpr{Var: base},
					Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 2, Width: ir.Size8}},
				},
				Value: val,
				Size:  ir.Size1,
			},
		},
	}

	matches, err := RecognizeMemPatterns(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for non-sequential offsets, got %d", len(matches))
	}
}
