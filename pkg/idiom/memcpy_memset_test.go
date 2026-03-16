package idiom

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// helpers
// ============================================================================

// buildMemsetBlock constructs a basic block with N consecutive stores of the
// same value to sequential addresses: store [base + i*size], val, size
func buildMemsetBlock(base ir.Variable, val ir.Expression, count int, storeSize ir.Size) *ir.BasicBlock {
	instrs := make([]ir.IRInstruction, 0, count)
	stride := int64(storeSize)

	for i := 0; i < count; i++ {
		offset := int64(i) * stride
		var addrExpr ir.Expression
		if offset == 0 {
			addrExpr = &ir.VariableExpr{Var: base}
		} else {
			addrExpr = &ir.BinaryOp{
				Op:   ir.BinOpAdd,
				Left: &ir.VariableExpr{Var: base},
				Right: &ir.ConstantExpr{Value: ir.IntConstant{
					Value: offset, Width: ir.Size8,
				}},
			}
		}
		instrs = append(instrs, &ir.Store{
			Address: addrExpr,
			Value:   val,
			Size:    storeSize,
		})
	}

	return &ir.BasicBlock{ID: 0, Instructions: instrs}
}

// buildMemcpyBlock constructs a basic block with N consecutive load/store pairs:
//
//	t_i = load [src + i*size], size
//	store [dst + i*size], t_i, size
func buildMemcpyBlock(src, dst ir.Variable, count int, copySize ir.Size) *ir.BasicBlock {
	instrs := make([]ir.IRInstruction, 0, count*2)
	stride := int64(copySize)

	for i := 0; i < count; i++ {
		offset := int64(i) * stride
		tVar := ir.Variable{Name: "t", Version: i + 1, Type: ir.IntType{Width: copySize}}

		var addrExpr ir.Expression
		if offset == 0 {
			addrExpr = &ir.VariableExpr{Var: src}
		} else {
			addrExpr = &ir.BinaryOp{
				Op:   ir.BinOpAdd,
				Left: &ir.VariableExpr{Var: src},
				Right: &ir.ConstantExpr{Value: ir.IntConstant{
					Value: offset, Width: ir.Size8,
				}},
			}
		}

		var dstAddrExpr ir.Expression
		if offset == 0 {
			dstAddrExpr = &ir.VariableExpr{Var: dst}
		} else {
			dstAddrExpr = &ir.BinaryOp{
				Op:   ir.BinOpAdd,
				Left: &ir.VariableExpr{Var: dst},
				Right: &ir.ConstantExpr{Value: ir.IntConstant{
					Value: offset, Width: ir.Size8,
				}},
			}
		}

		instrs = append(instrs, &ir.Load{
			Dest:    tVar,
			Address: addrExpr,
			Size:    copySize,
		})
		instrs = append(instrs, &ir.Store{
			Address: dstAddrExpr,
			Value:   &ir.VariableExpr{Var: tVar},
			Size:    copySize,
		})
	}

	return &ir.BasicBlock{ID: 0, Instructions: instrs}
}

// ============================================================================
// memset tests
// ============================================================================

// TestRecognizeMemPatterns_Memset_4Bytes verifies detection of 4-byte memset
// (4 byte stores = 4 bytes total).
func TestRecognizeMemPatterns_Memset_4Bytes(t *testing.T) {
	base := i64Var("dst", 1)
	val := &ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size1}}

	// 4 single-byte stores = 4 bytes
	block := buildMemsetBlock(base, val, 4, ir.Size1)

	matches, err := RecognizeMemPatterns(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	m := matches[0]
	if m.Kind != MemPatternMemset {
		t.Errorf("expected MemPatternMemset, got %v", m.Kind)
	}
	if m.ByteCount != 4 {
		t.Errorf("expected 4 bytes, got %d", m.ByteCount)
	}
	if m.DstBase.Name != "dst" {
		t.Errorf("expected dst base, got %s", m.DstBase.Name)
	}
}

// TestRecognizeMemPatterns_Memset_16Bytes verifies detection of 16-byte memset
// using 8-byte (qword) stores.
func TestRecognizeMemPatterns_Memset_16Bytes(t *testing.T) {
	base := i64Var("buf", 1)
	val := &ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size8}}

	// 2 qword stores = 16 bytes
	block := buildMemsetBlock(base, val, 2, ir.Size8)

	matches, err := RecognizeMemPatterns(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].ByteCount != 16 {
		t.Errorf("expected 16 bytes, got %d", matches[0].ByteCount)
	}
}

// TestRecognizeMemPatterns_Memset_NonZero verifies detection of non-zero fill.
func TestRecognizeMemPatterns_Memset_NonZero(t *testing.T) {
	base := i64Var("dst", 1)
	val := &ir.ConstantExpr{Value: ir.IntConstant{Value: 0xFF, Width: ir.Size1}}

	block := buildMemsetBlock(base, val, 8, ir.Size1)

	matches, err := RecognizeMemPatterns(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].ByteCount != 8 {
		t.Errorf("expected 8 bytes, got %d", matches[0].ByteCount)
	}
}

// ============================================================================
// memcpy tests
// ============================================================================

// TestRecognizeMemPatterns_Memcpy_8Bytes verifies detection of 8-byte memcpy
// (8 byte-sized load/store pairs).
func TestRecognizeMemPatterns_Memcpy_8Bytes(t *testing.T) {
	src := i64Var("src", 1)
	dst := i64Var("dst", 1)

	// 8 byte-sized load/store pairs = 8 bytes
	block := buildMemcpyBlock(src, dst, 8, ir.Size1)

	matches, err := RecognizeMemPatterns(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	m := matches[0]
	if m.Kind != MemPatternMemcpy {
		t.Errorf("expected MemPatternMemcpy, got %v", m.Kind)
	}
	if m.ByteCount != 8 {
		t.Errorf("expected 8 bytes, got %d", m.ByteCount)
	}
	if m.SrcBase.Name != "src" {
		t.Errorf("expected src base, got %s", m.SrcBase.Name)
	}
	if m.DstBase.Name != "dst" {
		t.Errorf("expected dst base, got %s", m.DstBase.Name)
	}
}

// TestRecognizeMemPatterns_Memcpy_32Bytes verifies detection of 32-byte memcpy
// using 8-byte (qword) load/store pairs.
func TestRecognizeMemPatterns_Memcpy_32Bytes(t *testing.T) {
	src := i64Var("src", 1)
	dst := i64Var("dst", 1)

	// 4 qword load/store pairs = 32 bytes
	block := buildMemcpyBlock(src, dst, 4, ir.Size8)

	matches, err := RecognizeMemPatterns(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].ByteCount != 32 {
		t.Errorf("expected 32 bytes, got %d", matches[0].ByteCount)
	}
}

// ============================================================================
// negative tests
// ============================================================================

// TestRecognizeMemPatterns_NoPattern verifies no false positives on plain stores
// with different values.
func TestRecognizeMemPatterns_NoPattern(t *testing.T) {
	base := i64Var("dst", 1)

	// stores with different values - not a memset
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Store{
				Address: &ir.VariableExpr{Var: base},
				Value:   &ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size1}},
				Size:    ir.Size1,
			},
			&ir.Store{
				Address: &ir.BinaryOp{
					Op:    ir.BinOpAdd,
					Left:  &ir.VariableExpr{Var: base},
					Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8}},
				},
				Value: &ir.ConstantExpr{Value: ir.IntConstant{Value: 2, Width: ir.Size1}},
				Size:  ir.Size1,
			},
		},
	}

	matches, err := RecognizeMemPatterns(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for different values, got %d", len(matches))
	}
}

// TestRecognizeMemPatterns_SingleStore verifies that a single store is not
// recognized (below minimum byte count).
func TestRecognizeMemPatterns_SingleStore(t *testing.T) {
	base := i64Var("dst", 1)
	val := &ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size1}}

	block := buildMemsetBlock(base, val, 1, ir.Size1)

	matches, err := RecognizeMemPatterns(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for single store, got %d", len(matches))
	}
}

// TestRecognizeMemPatterns_NilBlock verifies nil block returns error.
func TestRecognizeMemPatterns_NilBlock(t *testing.T) {
	_, err := RecognizeMemPatterns(nil)
	if err == nil {
		t.Error("expected error for nil block")
	}
}

// TestRecognizeMemPatterns_NilFunction verifies nil function returns error.
func TestRecognizeMemPatterns_NilFunction(t *testing.T) {
	_, err := RecognizeMemPatternsInFunction(nil)
	if err == nil {
		t.Error("expected error for nil function")
	}
}

// TestRecognizeMemPatterns_Function verifies function-level entry point.
func TestRecognizeMemPatterns_Function(t *testing.T) {
	src := i64Var("src", 1)
	dst := i64Var("dst", 1)
	block := buildMemcpyBlock(src, dst, 4, ir.Size8)

	fn := &ir.Function{
		Name:       "test",
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		EntryBlock: 0,
	}

	matches, err := RecognizeMemPatternsInFunction(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
}

// TestRecognizeMemPatterns_KindString verifies String() methods.
func TestRecognizeMemPatterns_KindString(t *testing.T) {
	if MemPatternMemset.String() != "memset" {
		t.Errorf("expected memset, got %s", MemPatternMemset.String())
	}
	if MemPatternMemcpy.String() != "memcpy" {
		t.Errorf("expected memcpy, got %s", MemPatternMemcpy.String())
	}
}

// TestRecognizeMemPatterns_MatchString verifies MemPatternMatch.String().
func TestRecognizeMemPatterns_MatchString(t *testing.T) {
	m := &MemPatternMatch{
		StartIdx:  0,
		EndIdx:    7,
		Kind:      MemPatternMemset,
		DstBase:   i64Var("dst", 1),
		FillValue: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size1}},
		ByteCount: 8,
	}
	s := m.String()
	if s == "" {
		t.Error("String() returned empty string")
	}

	m2 := &MemPatternMatch{
		StartIdx:  0,
		EndIdx:    7,
		Kind:      MemPatternMemcpy,
		DstBase:   i64Var("dst", 1),
		SrcBase:   i64Var("src", 1),
		ByteCount: 8,
	}
	s2 := m2.String()
	if s2 == "" {
		t.Error("String() returned empty string for memcpy")
	}
}

// ============================================================================
// benchmarks
// ============================================================================

// BenchmarkRecognizeMemPatterns_Memset measures memset detection cost.
func BenchmarkRecognizeMemPatterns_Memset(b *testing.B) {
	base := i64Var("dst", 1)
	val := &ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size8}}
	b.ResetTimer()
	for b.Loop() {
		block := buildMemsetBlock(base, val, 4, ir.Size8)
		_, _ = RecognizeMemPatterns(block)
	}
}

// BenchmarkRecognizeMemPatterns_Memcpy measures memcpy detection cost.
func BenchmarkRecognizeMemPatterns_Memcpy(b *testing.B) {
	src := i64Var("src", 1)
	dst := i64Var("dst", 1)
	b.ResetTimer()
	for b.Loop() {
		block := buildMemcpyBlock(src, dst, 4, ir.Size8)
		_, _ = RecognizeMemPatterns(block)
	}
}
