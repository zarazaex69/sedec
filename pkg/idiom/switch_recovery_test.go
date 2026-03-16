package idiom

import (
	"fmt"
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// test memory reader
// ============================================================================

// testMemory implements MemoryReader backed by a map for unit tests.
type testMemory struct {
	data map[uint64]uint64
}

func newTestMemory() *testMemory {
	return &testMemory{data: make(map[uint64]uint64)}
}

// writeTable writes a jump table at the given base address.
// entries is a slice of target virtual addresses.
func (m *testMemory) writeTable(base uint64, entries []uint64) {
	for i, entry := range entries {
		m.data[base+uint64(i)*8] = entry
	}
}

// ReadUint64 implements MemoryReader.
func (m *testMemory) ReadUint64(addr uint64) (uint64, error) {
	v, ok := m.data[addr]
	if !ok {
		return 0, fmt.Errorf("address 0x%x not mapped", addr)
	}
	return v, nil
}

// ============================================================================
// IR construction helpers
// ============================================================================

// u64Var creates a 64-bit unsigned integer variable.
func u64Var(name string, version int) ir.Variable { //nolint:unparam // version parameter is intentional for future test cases
	return ir.Variable{Name: name, Version: version, Type: ir.IntType{Width: ir.Size8, Signed: false}}
}

// u64Const creates a 64-bit unsigned constant expression.
func u64Const(v uint64) ir.Expression {
	return &ir.ConstantExpr{Value: ir.IntConstant{
		Value: int64(v), Width: ir.Size8, Signed: false, //nolint:gosec
	}}
}

// buildDenseSwitch constructs a function with a dense switch pattern.
//
// the function contains two blocks:
//   - block 0 (bounds check): branch (selector >u rangeSize-1), defaultBlock, tableBlock
//   - block 1 (table block): t_addr = tableBase + selector*8; t_ptr = load t_addr, 8; assign t_copy = t_ptr
//
// the jump table at tableBase contains rangeSize entries pointing to case blocks.
func buildDenseSwitch(selector ir.Variable, tableBase uint64, rangeSize int, mem *testMemory) *ir.Function {
	// write jump table entries: case i → address 0x1000 + i*0x100
	entries := make([]uint64, rangeSize)
	for i := range entries {
		entries[i] = 0x1000 + uint64(i)*0x100
	}
	mem.writeTable(tableBase, entries)

	// block 0: bounds check
	// branch (selector >u rangeSize-1), bb2 (default), bb1 (table)
	boundsBlock := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Branch{
				Condition: &ir.BinaryOp{
					Op:    ir.BinOpUGt,
					Left:  &ir.VariableExpr{Var: selector},
					Right: u64Const(uint64(rangeSize - 1)),
				},
				TrueTarget:  2, // default block
				FalseTarget: 1, // table block
			},
		},
		Successors: []ir.BlockID{1, 2},
	}

	// block 1: table lookup + indirect jump
	tAddr := u64Var("t_addr", 1)
	tPtr := u64Var("t_ptr", 1)
	tCopy := u64Var("t_copy", 1)

	tableBlock := &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			// t_addr = tableBase + selector * 8
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
			// t_ptr = load [t_addr], 8
			&ir.Load{
				Dest:    tPtr,
				Address: &ir.VariableExpr{Var: tAddr},
				Size:    ir.Size8,
			},
			// t_copy = t_ptr  (indirect jump preparation)
			&ir.Assign{
				Dest:   tCopy,
				Source: &ir.VariableExpr{Var: tPtr},
			},
		},
		Predecessors: []ir.BlockID{0},
	}

	// block 2: default case
	defaultBlock := &ir.BasicBlock{
		ID:           2,
		Instructions: []ir.IRInstruction{&ir.Return{}},
		Predecessors: []ir.BlockID{0},
	}

	return &ir.Function{
		Name: "switch_func",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: boundsBlock,
			1: tableBlock,
			2: defaultBlock,
		},
		EntryBlock: 0,
	}
}

// buildSparseSwitch constructs a function with a sparse switch pattern.
// the selector is normalized: normalized = selector - minCase.
// the jump table has rangeSize entries but some point to the default block (gaps).
func buildSparseSwitch(selector ir.Variable, tableBase uint64, minCase int64, rangeSize int, gapIndices []int, mem *testMemory) *ir.Function {
	// write jump table: gaps point to default (0x9000), others to case handlers
	entries := make([]uint64, rangeSize)
	gapSet := make(map[int]bool)
	for _, g := range gapIndices {
		gapSet[g] = true
	}
	for i := range entries {
		if gapSet[i] {
			entries[i] = 0x9000 // default handler address
		} else {
			entries[i] = 0x2000 + uint64(i)*0x100
		}
	}
	mem.writeTable(tableBase, entries)

	normalized := u64Var("norm", 1)

	// block 0: normalization + bounds check
	boundsBlock := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			// normalized = selector - minCase
			&ir.Assign{
				Dest: normalized,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpSub,
					Left:  &ir.VariableExpr{Var: selector},
					Right: i64Const(minCase),
				},
			},
			// branch (normalized >u rangeSize-1), default, table
			&ir.Branch{
				Condition: &ir.BinaryOp{
					Op:    ir.BinOpUGt,
					Left:  &ir.VariableExpr{Var: normalized},
					Right: u64Const(uint64(rangeSize - 1)),
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
						Left:  &ir.VariableExpr{Var: normalized},
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

	return &ir.Function{
		Name: "sparse_switch",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: boundsBlock,
			1: tableBlock,
			2: defaultBlock,
		},
		EntryBlock: 0,
	}
}

// ============================================================================
// dense switch tests
// ============================================================================

// TestRecoverSwitch_Dense_4Cases verifies recovery of a dense switch with 4 cases (0..3).
func TestRecoverSwitch_Dense_4Cases(t *testing.T) {
	mem := newTestMemory()
	selector := u64Var("sel", 1)
	tableBase := uint64(0x4000)

	fn := buildDenseSwitch(selector, tableBase, 4, mem)

	matches, err := RecoverSwitchStatements(fn, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	m := matches[0]
	if m.Kind != SwitchDense {
		t.Errorf("expected SwitchDense, got %v", m.Kind)
	}
	if len(m.Cases) != 4 {
		t.Errorf("expected 4 cases, got %d", len(m.Cases))
	}
	if m.MinCase != 0 {
		t.Errorf("expected min_case=0, got %d", m.MinCase)
	}
	if m.DefaultBlock != 2 {
		t.Errorf("expected default block 2, got %d", m.DefaultBlock)
	}
	if m.TableBase != tableBase {
		t.Errorf("expected table base 0x%x, got 0x%x", tableBase, m.TableBase)
	}

	// verify case values are 0..3
	for i, c := range m.Cases {
		if c.CaseValue != int64(i) {
			t.Errorf("case %d: expected value %d, got %d", i, i, c.CaseValue)
		}
		expectedTarget := uint64(0x1000 + i*0x100)
		if c.TargetAddress != expectedTarget {
			t.Errorf("case %d: expected target 0x%x, got 0x%x", i, expectedTarget, c.TargetAddress)
		}
	}
}

// TestRecoverSwitch_Dense_8Cases verifies recovery of a dense switch with 8 cases (0..7).
func TestRecoverSwitch_Dense_8Cases(t *testing.T) {
	mem := newTestMemory()
	selector := u64Var("x", 1)
	tableBase := uint64(0x8000)

	fn := buildDenseSwitch(selector, tableBase, 8, mem)

	matches, err := RecoverSwitchStatements(fn, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	m := matches[0]
	if m.Kind != SwitchDense {
		t.Errorf("expected SwitchDense, got %v", m.Kind)
	}
	if len(m.Cases) != 8 {
		t.Errorf("expected 8 cases, got %d", len(m.Cases))
	}
}

// TestRecoverSwitch_Dense_DefaultBlock verifies that the default block is correctly identified.
func TestRecoverSwitch_Dense_DefaultBlock(t *testing.T) {
	mem := newTestMemory()
	selector := u64Var("n", 1)
	tableBase := uint64(0x5000)

	fn := buildDenseSwitch(selector, tableBase, 3, mem)

	matches, err := RecoverSwitchStatements(fn, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	// default block must be the true target of the bounds check branch (block 2)
	if matches[0].DefaultBlock != 2 {
		t.Errorf("expected default block 2, got %d", matches[0].DefaultBlock)
	}
}

// ============================================================================
// sparse switch tests
// ============================================================================

// TestRecoverSwitch_Sparse_WithGaps verifies recovery of a sparse switch with gaps.
// cases: 10, 11, 13, 14 (gap at 12 → default handler)
// the gap entry points to the same address as the default block, creating a
// duplicate target address that triggers sparse classification.
func TestRecoverSwitch_Sparse_WithGaps(t *testing.T) {
	mem := newTestMemory()
	selector := u64Var("v", 1)
	tableBase := uint64(0x6000)
	minCase := int64(10)
	rangeSize := 5 // covers 10..14

	// write table manually: gap at index 2 (case 12) points to same address as another case
	// to trigger sparse detection via duplicate targets
	entries := []uint64{
		0x2000, // case 10
		0x2100, // case 11
		0x2000, // case 12 → same as case 10 (gap: compiler reuses an existing target)
		0x2300, // case 13
		0x2400, // case 14
	}
	mem.writeTable(tableBase, entries)

	normalized := u64Var("norm", 1)

	// block 0: normalization + bounds check
	boundsBlock := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: normalized,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpSub,
					Left:  &ir.VariableExpr{Var: selector},
					Right: i64Const(minCase),
				},
			},
			&ir.Branch{
				Condition: &ir.BinaryOp{
					Op:    ir.BinOpUGt,
					Left:  &ir.VariableExpr{Var: normalized},
					Right: u64Const(uint64(rangeSize - 1)),
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
						Left:  &ir.VariableExpr{Var: normalized},
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
		Name: "sparse_switch",
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
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	m := matches[0]
	if m.Kind != SwitchSparse {
		t.Errorf("expected SwitchSparse, got %v", m.Kind)
	}
	if m.MinCase != minCase {
		t.Errorf("expected min_case=%d, got %d", minCase, m.MinCase)
	}
	if len(m.Cases) == 0 {
		t.Error("expected non-empty cases")
	}
}

// TestRecoverSwitch_Sparse_NonZeroBase verifies normalization with non-zero min_case.
func TestRecoverSwitch_Sparse_NonZeroBase(t *testing.T) {
	mem := newTestMemory()
	selector := u64Var("c", 1)
	tableBase := uint64(0x7000)
	minCase := int64(100)
	rangeSize := 6 // covers 100..105

	// gaps at indices 1 and 3 (cases 101, 103)
	fn := buildSparseSwitch(selector, tableBase, minCase, rangeSize, []int{1, 3}, mem)

	matches, err := RecoverSwitchStatements(fn, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	m := matches[0]
	if m.MinCase != minCase {
		t.Errorf("expected min_case=%d, got %d", minCase, m.MinCase)
	}
	// original selector must be the pre-normalization variable
	if m.OriginalSelector.Name != "c" {
		t.Errorf("expected original selector 'c', got '%s'", m.OriginalSelector.Name)
	}
}

// ============================================================================
// classification tests
// ============================================================================

// TestClassifySwitchKind_Dense verifies dense classification for consecutive cases.
func TestClassifySwitchKind_Dense(t *testing.T) {
	cases := []CaseEntry{
		{CaseValue: 0, TargetAddress: 0x1000},
		{CaseValue: 1, TargetAddress: 0x1100},
		{CaseValue: 2, TargetAddress: 0x1200},
		{CaseValue: 3, TargetAddress: 0x1300},
	}
	if got := classifySwitchKind(cases); got != SwitchDense {
		t.Errorf("expected SwitchDense, got %v", got)
	}
}

// TestClassifySwitchKind_Sparse verifies sparse classification for non-consecutive cases.
func TestClassifySwitchKind_Sparse(t *testing.T) {
	cases := []CaseEntry{
		{CaseValue: 0, TargetAddress: 0x1000},
		{CaseValue: 1, TargetAddress: 0x1100},
		{CaseValue: 3, TargetAddress: 0x1300}, // gap at 2
		{CaseValue: 4, TargetAddress: 0x1400},
	}
	if got := classifySwitchKind(cases); got != SwitchSparse {
		t.Errorf("expected SwitchSparse, got %v", got)
	}
}

// TestClassifySwitchKind_SingleCase verifies that a single case is classified as dense.
func TestClassifySwitchKind_SingleCase(t *testing.T) {
	cases := []CaseEntry{{CaseValue: 5, TargetAddress: 0x1000}}
	if got := classifySwitchKind(cases); got != SwitchDense {
		t.Errorf("expected SwitchDense for single case, got %v", got)
	}
}

// TestClassifySwitchKind_Empty verifies that empty cases are classified as dense.
func TestClassifySwitchKind_Empty(t *testing.T) {
	if got := classifySwitchKind(nil); got != SwitchDense {
		t.Errorf("expected SwitchDense for empty cases, got %v", got)
	}
}

// ============================================================================
// bounds condition extraction tests
// ============================================================================

// TestExtractBoundsCondition_UGt verifies extraction from (index >u N) pattern.
func TestExtractBoundsCondition_UGt(t *testing.T) {
	indexVar := u64Var("idx", 1)
	branch := &ir.Branch{
		Condition: &ir.BinaryOp{
			Op:    ir.BinOpUGt,
			Left:  &ir.VariableExpr{Var: indexVar},
			Right: u64Const(7),
		},
		TrueTarget:  10, // default
		FalseTarget: 11, // table
	}

	rangeSize, defaultBlock, ok := extractBoundsCondition(branch, indexVar, nil, nil)
	if !ok {
		t.Fatal("expected successful extraction")
	}
	if rangeSize != 8 {
		t.Errorf("expected range=8 (N+1), got %d", rangeSize)
	}
	if defaultBlock != 10 {
		t.Errorf("expected default block 10, got %d", defaultBlock)
	}
}

// TestExtractBoundsCondition_ULt verifies extraction from (index <u N) pattern.
func TestExtractBoundsCondition_ULt(t *testing.T) {
	indexVar := u64Var("idx", 1)
	branch := &ir.Branch{
		Condition: &ir.BinaryOp{
			Op:    ir.BinOpULt,
			Left:  &ir.VariableExpr{Var: indexVar},
			Right: u64Const(5),
		},
		TrueTarget:  11, // table (condition true → within range)
		FalseTarget: 10, // default
	}

	rangeSize, defaultBlock, ok := extractBoundsCondition(branch, indexVar, nil, nil)
	if !ok {
		t.Fatal("expected successful extraction")
	}
	if rangeSize != 5 {
		t.Errorf("expected range=5, got %d", rangeSize)
	}
	if defaultBlock != 10 {
		t.Errorf("expected default block 10, got %d", defaultBlock)
	}
}

// TestExtractBoundsCondition_UGe verifies extraction from (index >=u N) pattern.
func TestExtractBoundsCondition_UGe(t *testing.T) {
	indexVar := u64Var("idx", 1)
	branch := &ir.Branch{
		Condition: &ir.BinaryOp{
			Op:    ir.BinOpUGe,
			Left:  &ir.VariableExpr{Var: indexVar},
			Right: u64Const(6),
		},
		TrueTarget:  20, // default
		FalseTarget: 21, // table
	}

	rangeSize, defaultBlock, ok := extractBoundsCondition(branch, indexVar, nil, nil)
	if !ok {
		t.Fatal("expected successful extraction")
	}
	if rangeSize != 6 {
		t.Errorf("expected range=6, got %d", rangeSize)
	}
	if defaultBlock != 20 {
		t.Errorf("expected default block 20, got %d", defaultBlock)
	}
}

// ============================================================================
// normalization tests
// ============================================================================

// TestResolveNormalization_WithSub verifies detection of selector - min_case pattern.
func TestResolveNormalization_WithSub(t *testing.T) {
	selector := u64Var("sel", 1)
	normalized := u64Var("norm", 1)

	instrs := []ir.IRInstruction{
		&ir.Assign{
			Dest: normalized,
			Source: &ir.BinaryOp{
				Op:    ir.BinOpSub,
				Left:  &ir.VariableExpr{Var: selector},
				Right: i64Const(10),
			},
		},
	}
	defIdx := buildDefIndex(instrs)

	original, minCase := resolveNormalization(normalized, defIdx, instrs)
	if original.Name != "sel" {
		t.Errorf("expected original selector 'sel', got '%s'", original.Name)
	}
	if minCase != 10 {
		t.Errorf("expected min_case=10, got %d", minCase)
	}
}

// TestResolveNormalization_NoSub verifies that a non-sub definition returns (var, 0).
func TestResolveNormalization_NoSub(t *testing.T) {
	v := u64Var("x", 1)
	original, minCase := resolveNormalization(v, nil, nil)
	if original.Name != "x" {
		t.Errorf("expected original 'x', got '%s'", original.Name)
	}
	if minCase != 0 {
		t.Errorf("expected min_case=0, got %d", minCase)
	}
}

// ============================================================================
// table info extraction tests
// ============================================================================

// TestExtractTableInfo_DirectConst verifies extraction when table base is a constant.
func TestExtractTableInfo_DirectConst(t *testing.T) {
	tableBase := uint64(0xDEAD0000)
	indexVar := u64Var("idx", 1)

	// address: tableBase + idx * 8
	addr := &ir.BinaryOp{
		Op:   ir.BinOpAdd,
		Left: u64Const(tableBase),
		Right: &ir.BinaryOp{
			Op:    ir.BinOpMul,
			Left:  &ir.VariableExpr{Var: indexVar},
			Right: u64Const(8),
		},
	}

	info, ok := extractTableInfo(addr, nil, nil)
	if !ok {
		t.Fatal("expected successful extraction")
	}
	if info.tableBase != tableBase {
		t.Errorf("expected table base 0x%x, got 0x%x", tableBase, info.tableBase)
	}
	if info.indexVar.Name != "idx" {
		t.Errorf("expected index var 'idx', got '%s'", info.indexVar.Name)
	}
	if info.ptrSize != 8 {
		t.Errorf("expected ptr_size=8, got %d", info.ptrSize)
	}
}

// TestExtractTableInfo_ShiftForm verifies extraction when index uses left shift.
func TestExtractTableInfo_ShiftForm(t *testing.T) {
	tableBase := uint64(0xBEEF0000)
	indexVar := u64Var("i", 1)

	// address: tableBase + (idx << 3)  equivalent to tableBase + idx*8
	addr := &ir.BinaryOp{
		Op:   ir.BinOpAdd,
		Left: u64Const(tableBase),
		Right: &ir.BinaryOp{
			Op:    ir.BinOpShl,
			Left:  &ir.VariableExpr{Var: indexVar},
			Right: u64Const(3), // 1 << 3 = 8
		},
	}

	info, ok := extractTableInfo(addr, nil, nil)
	if !ok {
		t.Fatal("expected successful extraction for shift form")
	}
	if info.tableBase != tableBase {
		t.Errorf("expected table base 0x%x, got 0x%x", tableBase, info.tableBase)
	}
	if info.ptrSize != 8 {
		t.Errorf("expected ptr_size=8 from shift 3, got %d", info.ptrSize)
	}
}

// ============================================================================
// jump table read tests
// ============================================================================

// TestReadJumpTable_AllEntries verifies that all table entries are read correctly.
func TestReadJumpTable_AllEntries(t *testing.T) {
	mem := newTestMemory()
	tableBase := uint64(0x3000)
	entries := []uint64{0x1000, 0x1100, 0x1200, 0x1300}
	mem.writeTable(tableBase, entries)

	cases, err := readJumpTable(tableBase, 4, 0, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cases) != 4 {
		t.Fatalf("expected 4 cases, got %d", len(cases))
	}
	for i, c := range cases {
		if c.CaseValue != int64(i) {
			t.Errorf("case %d: expected value %d, got %d", i, i, c.CaseValue)
		}
		if c.TargetAddress != entries[i] {
			t.Errorf("case %d: expected target 0x%x, got 0x%x", i, entries[i], c.TargetAddress)
		}
	}
}

// TestReadJumpTable_WithMinCase verifies case value offset by min_case.
func TestReadJumpTable_WithMinCase(t *testing.T) {
	mem := newTestMemory()
	tableBase := uint64(0x4000)
	entries := []uint64{0xA000, 0xB000, 0xC000}
	mem.writeTable(tableBase, entries)

	cases, err := readJumpTable(tableBase, 3, 5, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cases) != 3 {
		t.Fatalf("expected 3 cases, got %d", len(cases))
	}
	// case values should be 5, 6, 7
	for i, c := range cases {
		expected := int64(5 + i)
		if c.CaseValue != expected {
			t.Errorf("case %d: expected value %d, got %d", i, expected, c.CaseValue)
		}
	}
}

// TestReadJumpTable_ZeroRange verifies that zero range returns empty result.
func TestReadJumpTable_ZeroRange(t *testing.T) {
	mem := newTestMemory()
	cases, err := readJumpTable(0x1000, 0, 0, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cases) != 0 {
		t.Errorf("expected 0 cases for zero range, got %d", len(cases))
	}
}

// TestReadJumpTable_ExceedsMax verifies that oversized range returns empty result.
func TestReadJumpTable_ExceedsMax(t *testing.T) {
	mem := newTestMemory()
	cases, err := readJumpTable(0x1000, maxTableEntries+1, 0, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cases) != 0 {
		t.Errorf("expected 0 cases for oversized range, got %d", len(cases))
	}
}

// TestReadJumpTable_PartialRead verifies graceful handling of partial table reads.
func TestReadJumpTable_PartialRead(t *testing.T) {
	mem := newTestMemory()
	tableBase := uint64(0x5000)
	// only write 2 of 4 expected entries
	mem.data[tableBase+0] = 0xA000
	mem.data[tableBase+8] = 0xB000
	// entries at +16 and +24 are missing

	cases, err := readJumpTable(tableBase, 4, 0, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// should return 2 cases (partial read stops at first missing entry)
	if len(cases) != 2 {
		t.Errorf("expected 2 cases from partial read, got %d", len(cases))
	}
}

// ============================================================================
// nil / error handling tests
// ============================================================================

// TestRecoverSwitchStatements_NilFunction verifies nil function returns error.
func TestRecoverSwitchStatements_NilFunction(t *testing.T) {
	mem := newTestMemory()
	_, err := RecoverSwitchStatements(nil, mem)
	if err == nil {
		t.Error("expected error for nil function")
	}
}

// TestRecoverSwitchStatements_NilMemory verifies nil memory returns error.
func TestRecoverSwitchStatements_NilMemory(t *testing.T) {
	fn := &ir.Function{
		Name:   "f",
		Blocks: map[ir.BlockID]*ir.BasicBlock{},
	}
	_, err := RecoverSwitchStatements(fn, nil)
	if err == nil {
		t.Error("expected error for nil memory")
	}
}

// TestRecoverSwitchInBlock_NilBlock verifies nil block returns error.
func TestRecoverSwitchInBlock_NilBlock(t *testing.T) {
	mem := newTestMemory()
	fn := &ir.Function{Name: "f", Blocks: map[ir.BlockID]*ir.BasicBlock{}}
	_, err := RecoverSwitchInBlock(nil, fn, mem)
	if err == nil {
		t.Error("expected error for nil block")
	}
}

// TestRecoverSwitchInBlock_NilFunction verifies nil function returns error.
func TestRecoverSwitchInBlock_NilFunction(t *testing.T) {
	mem := newTestMemory()
	block := &ir.BasicBlock{ID: 0}
	_, err := RecoverSwitchInBlock(block, nil, mem)
	if err == nil {
		t.Error("expected error for nil function")
	}
}

// TestRecoverSwitchInBlock_NilMemory verifies nil memory returns error.
func TestRecoverSwitchInBlock_NilMemory(t *testing.T) {
	fn := &ir.Function{Name: "f", Blocks: map[ir.BlockID]*ir.BasicBlock{}}
	block := &ir.BasicBlock{ID: 0}
	_, err := RecoverSwitchInBlock(block, fn, nil)
	if err == nil {
		t.Error("expected error for nil memory")
	}
}

// TestRecoverSwitch_NoPattern verifies no false positives on plain loads.
func TestRecoverSwitch_NoPattern(t *testing.T) {
	mem := newTestMemory()
	x := u64Var("x", 1)
	y := u64Var("y", 1)

	// plain load with no switch pattern
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Load{
				Dest:    y,
				Address: &ir.VariableExpr{Var: x},
				Size:    ir.Size8,
			},
		},
	}

	fn := &ir.Function{
		Name:       "no_switch",
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		EntryBlock: 0,
	}

	matches, err := RecoverSwitchStatements(fn, mem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for plain load, got %d", len(matches))
	}
}

// ============================================================================
// SwitchMatch.String() test
// ============================================================================

// TestSwitchMatch_String verifies the String() method produces non-empty output.
func TestSwitchMatch_String(t *testing.T) {
	m := &SwitchMatch{
		SelectorVar:      u64Var("idx", 1),
		OriginalSelector: u64Var("sel", 1),
		TableBase:        0xDEAD0000,
		MinCase:          10,
		Cases: []CaseEntry{
			{CaseValue: 10, TargetAddress: 0x1000},
			{CaseValue: 11, TargetAddress: 0x1100},
		},
		DefaultBlock: 5,
		Kind:         SwitchDense,
	}
	s := m.String()
	if s == "" {
		t.Error("String() returned empty string")
	}
}

// TestSwitchKind_String verifies SwitchKind.String() for all values.
func TestSwitchKind_String(t *testing.T) {
	if SwitchDense.String() != "dense" {
		t.Errorf("expected 'dense', got '%s'", SwitchDense.String())
	}
	if SwitchSparse.String() != "sparse" {
		t.Errorf("expected 'sparse', got '%s'", SwitchSparse.String())
	}
}

// ============================================================================
// benchmarks
// ============================================================================

// BenchmarkRecoverSwitchStatements measures switch recovery cost on a dense switch.
func BenchmarkRecoverSwitchStatements(b *testing.B) {
	mem := newTestMemory()
	selector := u64Var("sel", 1)
	tableBase := uint64(0x4000)
	fn := buildDenseSwitch(selector, tableBase, 16, mem)

	b.ResetTimer()
	for b.Loop() {
		_, _ = RecoverSwitchStatements(fn, mem)
	}
}

// BenchmarkReadJumpTable measures jump table read cost.
func BenchmarkReadJumpTable(b *testing.B) {
	mem := newTestMemory()
	tableBase := uint64(0x3000)
	entries := make([]uint64, 64)
	for i := range entries {
		entries[i] = 0x1000 + uint64(i)*0x100
	}
	mem.writeTable(tableBase, entries)

	b.ResetTimer()
	for b.Loop() {
		_, _ = readJumpTable(tableBase, 64, 0, mem)
	}
}
