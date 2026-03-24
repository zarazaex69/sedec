package idiom

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

func TestUsesVarAsJumpTarget_CallTarget(t *testing.T) {
	v := u64Var("ptr", 1)
	call := &ir.Call{
		Target: &ir.VariableExpr{Var: v},
	}
	if !usesVarAsJumpTarget(call, v) {
		t.Error("expected Call with matching variable target to return true")
	}
}

func TestUsesVarAsJumpTarget_CallNonMatch(t *testing.T) {
	v := u64Var("ptr", 1)
	other := u64Var("other", 2)
	call := &ir.Call{
		Target: &ir.VariableExpr{Var: other},
	}
	if usesVarAsJumpTarget(call, v) {
		t.Error("expected Call with non-matching target to return false")
	}
}

func TestUsesVarAsJumpTarget_CallConstTarget(t *testing.T) {
	v := u64Var("ptr", 1)
	call := &ir.Call{
		Target: u64Const(0x1000),
	}
	if usesVarAsJumpTarget(call, v) {
		t.Error("expected Call with constant target to return false")
	}
}

func TestUsesVarAsJumpTarget_AssignMatch(t *testing.T) {
	v := u64Var("ptr", 1)
	assign := &ir.Assign{
		Dest:   u64Var("dst", 1),
		Source: &ir.VariableExpr{Var: v},
	}
	if !usesVarAsJumpTarget(assign, v) {
		t.Error("expected Assign copying matching variable to return true")
	}
}

func TestUsesVarAsJumpTarget_AssignNonMatch(t *testing.T) {
	v := u64Var("ptr", 1)
	assign := &ir.Assign{
		Dest:   u64Var("dst", 1),
		Source: &ir.VariableExpr{Var: u64Var("other", 2)},
	}
	if usesVarAsJumpTarget(assign, v) {
		t.Error("expected Assign with non-matching source to return false")
	}
}

func TestUsesVarAsJumpTarget_OtherInstr(t *testing.T) {
	v := u64Var("ptr", 1)
	ret := &ir.Return{}
	if usesVarAsJumpTarget(ret, v) {
		t.Error("expected Return instruction to return false")
	}
}

func TestIsIndexVar_DirectMatch(t *testing.T) {
	idx := u64Var("idx", 1)
	expr := &ir.VariableExpr{Var: idx}
	if !isIndexVar(expr, idx, nil, nil) {
		t.Error("expected direct variable match to return true")
	}
}

func TestIsIndexVar_ThroughDefChain(t *testing.T) {
	idx := u64Var("idx", 1)
	alias := u64Var("alias", 1)
	instrs := []ir.IRInstruction{
		&ir.Assign{
			Dest:   alias,
			Source: &ir.VariableExpr{Var: idx},
		},
	}
	defIdx := buildDefIndex(instrs)
	expr := &ir.VariableExpr{Var: alias}
	if !isIndexVar(expr, idx, defIdx, instrs) {
		t.Error("expected alias through def chain to return true")
	}
}

func TestIsIndexVar_NonVariable(t *testing.T) {
	idx := u64Var("idx", 1)
	expr := u64Const(42)
	if isIndexVar(expr, idx, nil, nil) {
		t.Error("expected constant expression to return false")
	}
}

func TestIsIndexVar_UndefinedVar(t *testing.T) {
	idx := u64Var("idx", 1)
	other := u64Var("other", 1)
	expr := &ir.VariableExpr{Var: other}
	if isIndexVar(expr, idx, nil, nil) {
		t.Error("expected undefined non-matching variable to return false")
	}
}

func TestIsIndexVar_DefChainNonAssign(t *testing.T) {
	idx := u64Var("idx", 1)
	other := u64Var("other", 1)
	instrs := []ir.IRInstruction{
		&ir.Load{
			Dest:    other,
			Address: u64Const(0x1000),
			Size:    ir.Size8,
		},
	}
	defIdx := buildDefIndex(instrs)
	expr := &ir.VariableExpr{Var: other}
	if isIndexVar(expr, idx, defIdx, instrs) {
		t.Error("expected non-Assign def to return false")
	}
}

func TestIsIndexVar_DefChainConstSource(t *testing.T) {
	idx := u64Var("idx", 1)
	other := u64Var("other", 1)
	instrs := []ir.IRInstruction{
		&ir.Assign{
			Dest:   other,
			Source: u64Const(42),
		},
	}
	defIdx := buildDefIndex(instrs)
	expr := &ir.VariableExpr{Var: other}
	if isIndexVar(expr, idx, defIdx, instrs) {
		t.Error("expected constant source in def chain to return false")
	}
}

func TestIsIndirectJumpLoad_LastInBlock(t *testing.T) {
	load := &ir.Load{
		Dest:    u64Var("ptr", 1),
		Address: u64Const(0x1000),
		Size:    ir.Size8,
	}
	instrs := []ir.IRInstruction{load}
	if !isIndirectJumpLoad(load, instrs, 1) {
		t.Error("expected load as last instruction to be detected as indirect jump")
	}
}

func TestIsIndirectJumpLoad_Size2Rejected(t *testing.T) {
	load := &ir.Load{
		Dest:    u64Var("ptr", 1),
		Address: u64Const(0x1000),
		Size:    ir.Size2,
	}
	instrs := []ir.IRInstruction{load}
	if isIndirectJumpLoad(load, instrs, 1) {
		t.Error("expected 2-byte load to be rejected")
	}
}

func TestIsIndirectJumpLoad_UsedAsCallTarget(t *testing.T) {
	ptr := u64Var("ptr", 1)
	load := &ir.Load{
		Dest:    ptr,
		Address: u64Const(0x1000),
		Size:    ir.Size8,
	}
	call := &ir.Call{
		Target: &ir.VariableExpr{Var: ptr},
	}
	instrs := []ir.IRInstruction{load, call}
	if !isIndirectJumpLoad(load, instrs, 1) {
		t.Error("expected load used as call target to be detected")
	}
}

func TestIsIndirectJumpLoad_Size4Accepted(t *testing.T) {
	ptr := u64Var("ptr", 1)
	load := &ir.Load{
		Dest:    ptr,
		Address: u64Const(0x1000),
		Size:    ir.Size4,
	}
	instrs := []ir.IRInstruction{load}
	if !isIndirectJumpLoad(load, instrs, 1) {
		t.Error("expected 4-byte load as last instruction to be detected")
	}
}

func TestFindBoundsCheck_FallbackZeroMinCase(t *testing.T) {
	selector := u64Var("sel", 1)
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Branch{
				Condition: &ir.BinaryOp{
					Op:    ir.BinOpUGt,
					Left:  &ir.VariableExpr{Var: selector},
					Right: u64Const(3),
				},
				TrueTarget:  10,
				FalseTarget: 11,
			},
		},
	}
	fn := &ir.Function{
		Name:       "f",
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		EntryBlock: 0,
	}
	defIdx := buildDefIndex(block.Instructions)
	info, ok := findBoundsCheck(selector, block, fn, defIdx)
	if !ok {
		t.Fatal("expected bounds check to be found")
	}
	if info.rangeSize != 4 {
		t.Errorf("expected range=4, got %d", info.rangeSize)
	}
	if info.defaultBlock != 10 {
		t.Errorf("expected default=10, got %d", info.defaultBlock)
	}
}

func TestFindBoundsCheck_InPredecessorWithNormalization(t *testing.T) {
	selector := u64Var("sel", 1)
	normalized := u64Var("norm", 1)

	predBlock := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: normalized,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpSub,
					Left:  &ir.VariableExpr{Var: selector},
					Right: i64Const(5),
				},
			},
			&ir.Branch{
				Condition: &ir.BinaryOp{
					Op:    ir.BinOpUGt,
					Left:  &ir.VariableExpr{Var: normalized},
					Right: u64Const(9),
				},
				TrueTarget:  2,
				FalseTarget: 1,
			},
		},
		Successors: []ir.BlockID{1, 2},
	}

	tableBlock := &ir.BasicBlock{
		ID:           1,
		Instructions: []ir.IRInstruction{},
		Predecessors: []ir.BlockID{0},
	}

	fn := &ir.Function{
		Name: "f",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: predBlock,
			1: tableBlock,
		},
		EntryBlock: 0,
	}

	defIdx := buildDefIndex(tableBlock.Instructions)
	info, ok := findBoundsCheck(normalized, tableBlock, fn, defIdx)
	if !ok {
		t.Fatal("expected bounds check in predecessor to be found")
	}
	if info.rangeSize != 10 {
		t.Errorf("expected range=10, got %d", info.rangeSize)
	}
	if info.minCase != 5 {
		t.Errorf("expected minCase=5, got %d", info.minCase)
	}
	if info.defaultBlock != 2 {
		t.Errorf("expected default=2, got %d", info.defaultBlock)
	}
}

func TestFindBoundsCheck_PredecessorOriginalSelector(t *testing.T) {
	selector := u64Var("sel", 1)
	normalized := u64Var("norm", 1)

	predBlock := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: normalized,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpSub,
					Left:  &ir.VariableExpr{Var: selector},
					Right: i64Const(10),
				},
			},
			&ir.Branch{
				Condition: &ir.BinaryOp{
					Op:    ir.BinOpUGt,
					Left:  &ir.VariableExpr{Var: selector},
					Right: u64Const(15),
				},
				TrueTarget:  2,
				FalseTarget: 1,
			},
		},
		Successors: []ir.BlockID{1, 2},
	}

	tableBlock := &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: normalized,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpSub,
					Left:  &ir.VariableExpr{Var: selector},
					Right: i64Const(10),
				},
			},
		},
		Predecessors: []ir.BlockID{0},
	}

	fn := &ir.Function{
		Name: "f",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: predBlock,
			1: tableBlock,
		},
		EntryBlock: 0,
	}

	defIdx := buildDefIndex(tableBlock.Instructions)
	info, ok := findBoundsCheck(normalized, tableBlock, fn, defIdx)
	if !ok {
		t.Fatal("expected bounds check via original selector in predecessor")
	}
	if info.defaultBlock != 2 {
		t.Errorf("expected default=2, got %d", info.defaultBlock)
	}
}

func TestExtractBoundsCondition_ViaDefChain(t *testing.T) {
	indexVar := u64Var("idx", 1)
	condVar := u64Var("cond", 1)

	instrs := []ir.IRInstruction{
		&ir.Assign{
			Dest: condVar,
			Source: &ir.BinaryOp{
				Op:    ir.BinOpUGt,
				Left:  &ir.VariableExpr{Var: indexVar},
				Right: u64Const(5),
			},
		},
	}
	defIdx := buildDefIndex(instrs)

	branch := &ir.Branch{
		Condition:   &ir.VariableExpr{Var: condVar},
		TrueTarget:  10,
		FalseTarget: 11,
	}

	rangeSize, defaultBlock, ok := extractBoundsCondition(branch, indexVar, defIdx, instrs)
	if !ok {
		t.Fatal("expected extraction through def chain")
	}
	if rangeSize != 6 {
		t.Errorf("expected range=6, got %d", rangeSize)
	}
	if defaultBlock != 10 {
		t.Errorf("expected default=10, got %d", defaultBlock)
	}
}

func TestExtractBoundsCondition_ReversedULe(t *testing.T) {
	indexVar := u64Var("idx", 1)
	branch := &ir.Branch{
		Condition: &ir.BinaryOp{
			Op:    ir.BinOpULe,
			Left:  u64Const(3),
			Right: &ir.VariableExpr{Var: indexVar},
		},
		TrueTarget:  10,
		FalseTarget: 11,
	}
	rangeSize, defaultBlock, ok := extractBoundsCondition(branch, indexVar, nil, nil)
	if !ok {
		t.Fatal("expected extraction for reversed ULe")
	}
	if rangeSize != 3 {
		t.Errorf("expected range=3, got %d", rangeSize)
	}
	if defaultBlock != 10 {
		t.Errorf("expected default=10, got %d", defaultBlock)
	}
}

func TestExtractBoundsCondition_ReversedUGe(t *testing.T) {
	indexVar := u64Var("idx", 1)
	branch := &ir.Branch{
		Condition: &ir.BinaryOp{
			Op:    ir.BinOpUGe,
			Left:  u64Const(3),
			Right: &ir.VariableExpr{Var: indexVar},
		},
		TrueTarget:  10,
		FalseTarget: 11,
	}
	rangeSize, defaultBlock, ok := extractBoundsCondition(branch, indexVar, nil, nil)
	if !ok {
		t.Fatal("expected extraction for reversed UGe")
	}
	if rangeSize != 4 {
		t.Errorf("expected range=4, got %d", rangeSize)
	}
	if defaultBlock != 11 {
		t.Errorf("expected default=11, got %d", defaultBlock)
	}
}

func TestResolveExprThroughDefs_MaxDepthZero(t *testing.T) {
	v := u64Var("x", 1)
	expr := &ir.VariableExpr{Var: v}
	result := resolveExprThroughDefs(expr, nil, nil, 0)
	ve, ok := result.(*ir.VariableExpr)
	if !ok {
		t.Fatal("expected VariableExpr returned unchanged at depth 0")
	}
	if ve.Var.Name != "x" {
		t.Errorf("expected 'x', got '%s'", ve.Var.Name)
	}
}

func TestResolveExprThroughDefs_NonVariable(t *testing.T) {
	expr := u64Const(42)
	result := resolveExprThroughDefs(expr, nil, nil, 4)
	if _, ok := result.(*ir.ConstantExpr); !ok {
		t.Error("expected constant to be returned unchanged")
	}
}

func TestResolveVarToConst_NonAssign(t *testing.T) {
	v := u64Var("x", 1)
	instrs := []ir.IRInstruction{
		&ir.Load{
			Dest:    v,
			Address: u64Const(0x1000),
			Size:    ir.Size8,
		},
	}
	defIdx := buildDefIndex(instrs)
	_, ok := resolveVarToConst(v, defIdx, instrs)
	if ok {
		t.Error("expected false for non-Assign definition")
	}
}

func TestResolveVarToConst_NonConstSource(t *testing.T) {
	v := u64Var("x", 1)
	other := u64Var("y", 1)
	instrs := []ir.IRInstruction{
		&ir.Assign{
			Dest:   v,
			Source: &ir.VariableExpr{Var: other},
		},
	}
	defIdx := buildDefIndex(instrs)
	_, ok := resolveVarToConst(v, defIdx, instrs)
	if ok {
		t.Error("expected false for non-constant source")
	}
}

func TestResolveNormalization_NonAssign(t *testing.T) {
	v := u64Var("x", 1)
	instrs := []ir.IRInstruction{
		&ir.Load{
			Dest:    v,
			Address: u64Const(0x1000),
			Size:    ir.Size8,
		},
	}
	defIdx := buildDefIndex(instrs)
	original, minCase := resolveNormalization(v, defIdx, instrs)
	if original.Name != "x" {
		t.Errorf("expected 'x', got '%s'", original.Name)
	}
	if minCase != 0 {
		t.Errorf("expected 0, got %d", minCase)
	}
}

func TestResolveNormalization_NonBinaryOp(t *testing.T) {
	v := u64Var("x", 1)
	instrs := []ir.IRInstruction{
		&ir.Assign{
			Dest:   v,
			Source: u64Const(42),
		},
	}
	defIdx := buildDefIndex(instrs)
	original, minCase := resolveNormalization(v, defIdx, instrs)
	if original.Name != "x" {
		t.Errorf("expected 'x', got '%s'", original.Name)
	}
	if minCase != 0 {
		t.Errorf("expected 0, got %d", minCase)
	}
}

func TestResolveNormalization_NonSubOp(t *testing.T) {
	v := u64Var("x", 1)
	instrs := []ir.IRInstruction{
		&ir.Assign{
			Dest: v,
			Source: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: u64Var("y", 1)},
				Right: u64Const(10),
			},
		},
	}
	defIdx := buildDefIndex(instrs)
	original, minCase := resolveNormalization(v, defIdx, instrs)
	if original.Name != "x" {
		t.Errorf("expected 'x', got '%s'", original.Name)
	}
	if minCase != 0 {
		t.Errorf("expected 0, got %d", minCase)
	}
}

func TestResolveNormalization_SubWithNonConstRight(t *testing.T) {
	v := u64Var("x", 1)
	instrs := []ir.IRInstruction{
		&ir.Assign{
			Dest: v,
			Source: &ir.BinaryOp{
				Op:    ir.BinOpSub,
				Left:  &ir.VariableExpr{Var: u64Var("a", 1)},
				Right: &ir.VariableExpr{Var: u64Var("b", 1)},
			},
		},
	}
	defIdx := buildDefIndex(instrs)
	original, minCase := resolveNormalization(v, defIdx, instrs)
	if original.Name != "x" {
		t.Errorf("expected 'x', got '%s'", original.Name)
	}
	if minCase != 0 {
		t.Errorf("expected 0, got %d", minCase)
	}
}

func TestExtractIndexExpr_MulRightVar(t *testing.T) {
	idx := u64Var("idx", 1)
	expr := &ir.BinaryOp{
		Op:    ir.BinOpMul,
		Left:  u64Const(8),
		Right: &ir.VariableExpr{Var: idx},
	}
	v, ptrSize, ok := extractIndexExpr(expr, nil, nil)
	if !ok {
		t.Fatal("expected extraction with variable on right of mul")
	}
	if v.Name != "idx" {
		t.Errorf("expected 'idx', got '%s'", v.Name)
	}
	if ptrSize != 8 {
		t.Errorf("expected ptrSize=8, got %d", ptrSize)
	}
}

func TestExtractIndexExpr_InvalidPtrSize(t *testing.T) {
	idx := u64Var("idx", 1)
	expr := &ir.BinaryOp{
		Op:    ir.BinOpMul,
		Left:  &ir.VariableExpr{Var: idx},
		Right: u64Const(3),
	}
	_, _, ok := extractIndexExpr(expr, nil, nil)
	if ok {
		t.Error("expected false for invalid ptr size 3")
	}
}

func TestExtractIndexExpr_ShiftInvalidSize(t *testing.T) {
	idx := u64Var("idx", 1)
	expr := &ir.BinaryOp{
		Op:    ir.BinOpShl,
		Left:  &ir.VariableExpr{Var: idx},
		Right: u64Const(5),
	}
	_, _, ok := extractIndexExpr(expr, nil, nil)
	if ok {
		t.Error("expected false for shift producing invalid ptr size 32")
	}
}

func TestClassifySwitchKind_DuplicateTargets(t *testing.T) {
	cases := []CaseEntry{
		{CaseValue: 0, TargetAddress: 0x1000},
		{CaseValue: 1, TargetAddress: 0x1000},
		{CaseValue: 2, TargetAddress: 0x1200},
	}
	if got := classifySwitchKind(cases); got != SwitchSparse {
		t.Errorf("expected SwitchSparse for duplicate targets, got %v", got)
	}
}

func TestReadJumpTable_NullEntrySkipped(t *testing.T) {
	mem := newTestMemory()
	tableBase := uint64(0xA000)
	mem.data[tableBase+0] = 0x1000
	mem.data[tableBase+8] = 0
	mem.data[tableBase+16] = 0x1200

	cases, err := readJumpTable(tableBase, 3, 0, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cases) != 2 {
		t.Errorf("expected 2 cases (null skipped), got %d", len(cases))
	}
	if cases[0].CaseValue != 0 || cases[0].TargetAddress != 0x1000 {
		t.Errorf("case 0 mismatch: %+v", cases[0])
	}
	if cases[1].CaseValue != 2 || cases[1].TargetAddress != 0x1200 {
		t.Errorf("case 1 mismatch: %+v", cases[1])
	}
}

func TestFindBoundsCheck_PredecessorZeroMinCaseFallback(t *testing.T) {
	selector := u64Var("sel", 1)

	predBlock := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Branch{
				Condition: &ir.BinaryOp{
					Op:    ir.BinOpUGt,
					Left:  &ir.VariableExpr{Var: selector},
					Right: u64Const(7),
				},
				TrueTarget:  2,
				FalseTarget: 1,
			},
		},
		Successors: []ir.BlockID{1, 2},
	}

	tableBlock := &ir.BasicBlock{
		ID:           1,
		Instructions: []ir.IRInstruction{},
		Predecessors: []ir.BlockID{0},
	}

	fn := &ir.Function{
		Name: "f",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: predBlock,
			1: tableBlock,
		},
		EntryBlock: 0,
	}

	defIdx := buildDefIndex(tableBlock.Instructions)
	info, ok := findBoundsCheck(selector, tableBlock, fn, defIdx)
	if !ok {
		t.Fatal("expected bounds check in predecessor with zero min case")
	}
	if info.rangeSize != 8 {
		t.Errorf("expected range=8, got %d", info.rangeSize)
	}
	if info.minCase != 0 {
		t.Errorf("expected minCase=0, got %d", info.minCase)
	}
}

func TestFindBoundsCheck_NoPredecessorFound(t *testing.T) {
	v := u64Var("x", 1)
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   v,
				Source: u64Const(42),
			},
		},
		Predecessors: []ir.BlockID{99},
	}
	fn := &ir.Function{
		Name: "f",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: block,
		},
		EntryBlock: 0,
	}
	defIdx := buildDefIndex(block.Instructions)
	_, ok := findBoundsCheck(v, block, fn, defIdx)
	if ok {
		t.Error("expected no bounds check found for missing predecessor")
	}
}

func TestRecoverSwitch_MultipleBlocks(t *testing.T) {
	mem := newTestMemory()
	selector := u64Var("sel", 1)
	tableBase1 := uint64(0xA000)
	tableBase2 := uint64(0xB000)

	entries1 := []uint64{0x1000, 0x1100, 0x1200}
	entries2 := []uint64{0x2000, 0x2100}
	mem.writeTable(tableBase1, entries1)
	mem.writeTable(tableBase2, entries2)

	tAddr1 := u64Var("t_addr1", 1)
	tPtr1 := u64Var("t_ptr1", 1)
	tCopy1 := u64Var("t_copy1", 1)

	block0 := &ir.BasicBlock{
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

	block1 := &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: tAddr1,
				Source: &ir.BinaryOp{
					Op:   ir.BinOpAdd,
					Left: u64Const(tableBase1),
					Right: &ir.BinaryOp{
						Op:    ir.BinOpMul,
						Left:  &ir.VariableExpr{Var: selector},
						Right: u64Const(8),
					},
				},
			},
			&ir.Load{
				Dest:    tPtr1,
				Address: &ir.VariableExpr{Var: tAddr1},
				Size:    ir.Size8,
			},
			&ir.Assign{
				Dest:   tCopy1,
				Source: &ir.VariableExpr{Var: tPtr1},
			},
		},
		Predecessors: []ir.BlockID{0},
	}

	block2 := &ir.BasicBlock{
		ID:           2,
		Instructions: []ir.IRInstruction{&ir.Return{}},
		Predecessors: []ir.BlockID{0},
	}

	fn := &ir.Function{
		Name: "multi_switch",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: block0,
			1: block1,
			2: block2,
		},
		EntryBlock: 0,
	}

	matches, err := RecoverSwitchStatements(fn, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if len(matches[0].Cases) != 3 {
		t.Errorf("expected 3 cases, got %d", len(matches[0].Cases))
	}
}
