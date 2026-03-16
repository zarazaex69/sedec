package idiom

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// buildUnrolledBlock constructs a basic block with an unrolled loop body.
// it creates `factor` copies of a load/store pair accessing consecutive
// offsets of the induction variable `idx`.
//
// each copy:
//
//	t_i = load [arr + (idx + i*stride)]
//	store [dst + (idx + i*stride)], t_i
func buildUnrolledBlock(idx ir.Variable, arr, dst ir.Variable, factor int) *ir.BasicBlock {
	const stride = 8
	instrs := make([]ir.IRInstruction, 0, factor*2)

	for i := 0; i < factor; i++ {
		offset := int64(i * stride)
		tVar := ir.Variable{Name: "t", Version: i + 1, Type: ir.IntType{Width: ir.Size8}}

		var addrExpr ir.Expression
		if offset == 0 {
			addrExpr = &ir.VariableExpr{Var: idx}
		} else {
			addrExpr = &ir.BinaryOp{
				Op:   ir.BinOpAdd,
				Left: &ir.VariableExpr{Var: idx},
				Right: &ir.ConstantExpr{Value: ir.IntConstant{
					Value: offset, Width: ir.Size8,
				}},
			}
		}

		// load from arr + (idx + offset)
		loadAddr := &ir.BinaryOp{
			Op:    ir.BinOpAdd,
			Left:  &ir.VariableExpr{Var: arr},
			Right: addrExpr,
		}
		instrs = append(instrs, &ir.Load{
			Dest:    tVar,
			Address: loadAddr,
			Size:    ir.Size8,
		})

		// store to dst + (idx + offset)
		storeAddr := &ir.BinaryOp{
			Op:    ir.BinOpAdd,
			Left:  &ir.VariableExpr{Var: dst},
			Right: addrExpr,
		}
		instrs = append(instrs, &ir.Store{
			Address: storeAddr,
			Value:   &ir.VariableExpr{Var: tVar},
			Size:    ir.Size8,
		})
	}

	return &ir.BasicBlock{ID: 0, Instructions: instrs}
}

// ============================================================================
// tests
// ============================================================================

// TestDetectLoopUnrolling_2x verifies detection of a 2x unrolled loop.
func TestDetectLoopUnrolling_2x(t *testing.T) {
	idx := i64Var("idx", 1)
	arr := i64Var("arr", 1)
	dst := i64Var("dst", 1)

	block := buildUnrolledBlock(idx, arr, dst, 2)

	matches, err := DetectLoopUnrolling(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected at least 1 match, got 0")
	}

	found := false
	for _, m := range matches {
		if m.UnrollFactor >= 2 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected unroll factor >= 2, matches: %v", matches)
	}
}

// TestDetectLoopUnrolling_4x verifies detection of a 4x unrolled loop.
func TestDetectLoopUnrolling_4x(t *testing.T) {
	idx := i64Var("i", 1)
	arr := i64Var("src", 1)
	dst := i64Var("dst", 1)

	block := buildUnrolledBlock(idx, arr, dst, 4)

	matches, err := DetectLoopUnrolling(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected at least 1 match, got 0")
	}
}

// TestDetectLoopUnrolling_TooSmall verifies that a block with fewer than
// 4 instructions (minimum for 2x unroll of 2-instruction body) returns no matches.
func TestDetectLoopUnrolling_TooSmall(t *testing.T) {
	x := i64Var("x", 1)
	y := i64Var("y", 1)

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   y,
				Source: &ir.VariableExpr{Var: x},
			},
		},
	}

	matches, err := DetectLoopUnrolling(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for tiny block, got %d", len(matches))
	}
}

// TestDetectLoopUnrolling_NilBlock verifies nil block returns error.
func TestDetectLoopUnrolling_NilBlock(t *testing.T) {
	_, err := DetectLoopUnrolling(nil)
	if err == nil {
		t.Error("expected error for nil block")
	}
}

// TestDetectLoopUnrolling_NilFunction verifies nil function returns error.
func TestDetectLoopUnrolling_NilFunction(t *testing.T) {
	_, err := DetectLoopUnrollingInFunction(nil)
	if err == nil {
		t.Error("expected error for nil function")
	}
}

// TestDetectLoopUnrolling_Function verifies function-level entry point.
func TestDetectLoopUnrolling_Function(t *testing.T) {
	idx := i64Var("i", 1)
	arr := i64Var("arr", 1)
	dst := i64Var("dst", 1)

	block := buildUnrolledBlock(idx, arr, dst, 4)

	fn := &ir.Function{
		Name:       "test",
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		EntryBlock: 0,
	}

	matches, err := DetectLoopUnrollingInFunction(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected at least 1 match from function-level detection")
	}
}

// TestDetectLoopUnrolling_MatchString verifies String() method.
func TestDetectLoopUnrolling_MatchString(t *testing.T) {
	m := &UnrollMatch{
		UnrollFactor: 4,
		BodySize:     2,
		StartIdx:     0,
		InductionVar: i64Var("i", 1),
		Stride:       8,
	}
	s := m.String()
	if s == "" {
		t.Error("String() returned empty string")
	}
}

// BenchmarkDetectLoopUnrolling measures detection cost on a 4x unrolled block.
func BenchmarkDetectLoopUnrolling(b *testing.B) {
	idx := i64Var("i", 1)
	arr := i64Var("arr", 1)
	dst := i64Var("dst", 1)
	b.ResetTimer()
	for b.Loop() {
		block := buildUnrolledBlock(idx, arr, dst, 4)
		_, _ = DetectLoopUnrolling(block)
	}
}
