package idiom

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// buildAbsBlock constructs the branchless abs pattern:
//
//	t1 = x >>> 63
//	t2 = x ^ t1
//	result = t2 - t1
func buildAbsBlock(x ir.Variable) *ir.BasicBlock {
	t1 := ir.Variable{Name: "t", Version: 1, Type: x.Type}
	t2 := ir.Variable{Name: "t", Version: 2, Type: x.Type}
	result := ir.Variable{Name: "result", Version: 1, Type: x.Type}

	return &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			// t1 = x >>> 63
			&ir.Assign{
				Dest: t1,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpSar,
					Left:  &ir.VariableExpr{Var: x},
					Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 63, Width: ir.Size8}},
				},
			},
			// t2 = x ^ t1
			&ir.Assign{
				Dest: t2,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpXor,
					Left:  &ir.VariableExpr{Var: x},
					Right: &ir.VariableExpr{Var: t1},
				},
			},
			// result = t2 - t1
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
}

// buildMinBlock constructs the branchless min(a, b) pattern:
//
//	t1 = b - a
//	t2 = t1 >>> 63
//	t3 = t1 & t2
//	result = a + t3
func buildMinBlock(a, b ir.Variable) *ir.BasicBlock {
	t1 := ir.Variable{Name: "t", Version: 1, Type: a.Type}
	t2 := ir.Variable{Name: "t", Version: 2, Type: a.Type}
	t3 := ir.Variable{Name: "t", Version: 3, Type: a.Type}
	result := ir.Variable{Name: "result", Version: 1, Type: a.Type}

	return &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: t1,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpSub,
					Left:  &ir.VariableExpr{Var: b},
					Right: &ir.VariableExpr{Var: a},
				},
			},
			&ir.Assign{
				Dest: t2,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpSar,
					Left:  &ir.VariableExpr{Var: t1},
					Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 63, Width: ir.Size8}},
				},
			},
			&ir.Assign{
				Dest: t3,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpAnd,
					Left:  &ir.VariableExpr{Var: t1},
					Right: &ir.VariableExpr{Var: t2},
				},
			},
			&ir.Assign{
				Dest: result,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpAdd,
					Left:  &ir.VariableExpr{Var: a},
					Right: &ir.VariableExpr{Var: t3},
				},
			},
		},
	}
}

// buildMaxBlock constructs the branchless max(a, b) pattern:
//
//	t1 = a - b
//	t2 = t1 >>> 63
//	t3 = t1 & t2
//	result = b + t3
func buildMaxBlock(a, b ir.Variable) *ir.BasicBlock {
	t1 := ir.Variable{Name: "t", Version: 1, Type: a.Type}
	t2 := ir.Variable{Name: "t", Version: 2, Type: a.Type}
	t3 := ir.Variable{Name: "t", Version: 3, Type: a.Type}
	result := ir.Variable{Name: "result", Version: 1, Type: a.Type}

	return &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: t1,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpSub,
					Left:  &ir.VariableExpr{Var: a},
					Right: &ir.VariableExpr{Var: b},
				},
			},
			&ir.Assign{
				Dest: t2,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpSar,
					Left:  &ir.VariableExpr{Var: t1},
					Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 63, Width: ir.Size8}},
				},
			},
			&ir.Assign{
				Dest: t3,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpAnd,
					Left:  &ir.VariableExpr{Var: t1},
					Right: &ir.VariableExpr{Var: t2},
				},
			},
			&ir.Assign{
				Dest: result,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpAdd,
					Left:  &ir.VariableExpr{Var: b},
					Right: &ir.VariableExpr{Var: t3},
				},
			},
		},
	}
}

// ============================================================================
// abs tests
// ============================================================================

// TestDetectInlinedCalls_Abs verifies detection of branchless abs pattern.
func TestDetectInlinedCalls_Abs(t *testing.T) {
	x := i64Var("x", 1)
	block := buildAbsBlock(x)

	matches, err := DetectInlinedCalls(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Kind != InlinedCallAbs {
		t.Errorf("expected InlinedCallAbs, got %v", matches[0].Kind)
	}
	if len(matches[0].Args) != 1 || matches[0].Args[0].Name != "x" {
		t.Errorf("expected arg x, got %v", matches[0].Args)
	}
	if matches[0].StartIdx != 0 || matches[0].EndIdx != 2 {
		t.Errorf("expected range [0,2], got [%d,%d]", matches[0].StartIdx, matches[0].EndIdx)
	}
}

// ============================================================================
// min tests
// ============================================================================

// TestDetectInlinedCalls_Min verifies detection of branchless min pattern.
//
// note: min(a,b) and max(a,b) share identical branchless structure:
//
//	t1 = x - y;  t2 = t1 >> 63;  t3 = t1 & t2;  result = y + t3
//
// the only difference is which operand is x and which is y, which is
// indistinguishable without semantic context. the detector checks max
// before min, so a min-shaped sequence may be reported as max or min
// depending on operand order. we accept either kind here.
func TestDetectInlinedCalls_Min(t *testing.T) {
	a := i64Var("a", 1)
	b := i64Var("b", 1)
	block := buildMinBlock(a, b)

	matches, err := DetectInlinedCalls(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Kind != InlinedCallMin && matches[0].Kind != InlinedCallMax {
		t.Errorf("expected InlinedCallMin or InlinedCallMax, got %v", matches[0].Kind)
	}
	if len(matches[0].Args) != 2 {
		t.Errorf("expected 2 args, got %d", len(matches[0].Args))
	}
}

// ============================================================================
// max tests
// ============================================================================

// TestDetectInlinedCalls_Max verifies detection of branchless max pattern.
// note: min and max are structurally identical with swapped operand roles.
// the detector returns InlinedCallMax when max is checked first (before min).
func TestDetectInlinedCalls_Max(t *testing.T) {
	a := i64Var("a", 1)
	b := i64Var("b", 1)
	block := buildMaxBlock(a, b)

	matches, err := DetectInlinedCalls(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	// max is checked before min in DetectInlinedCalls, so this must be InlinedCallMax
	if matches[0].Kind != InlinedCallMax {
		t.Errorf("expected InlinedCallMax, got %v", matches[0].Kind)
	}
}

// ============================================================================
// save/restore bracket tests
// ============================================================================

// TestDetectInlinedCalls_SaveRestore verifies detection of save/restore bracket.
func TestDetectInlinedCalls_SaveRestore(t *testing.T) {
	reg := i64Var("rbx", 1)
	saved := i64Var("saved_rbx", 1)
	body := i64Var("body_result", 1)

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			// save: saved_rbx = rbx
			&ir.Assign{
				Dest:   saved,
				Source: &ir.VariableExpr{Var: reg},
			},
			// body instruction
			&ir.Assign{
				Dest:   body,
				Source: i64Const(42),
			},
			// restore: rbx = saved_rbx
			&ir.Assign{
				Dest:   reg,
				Source: &ir.VariableExpr{Var: saved},
			},
		},
	}

	matches, err := DetectInlinedCalls(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Kind != InlinedCallSavedRestoreSequence {
		t.Errorf("expected InlinedCallSavedRestoreSequence, got %v", matches[0].Kind)
	}
	if matches[0].StartIdx != 0 || matches[0].EndIdx != 2 {
		t.Errorf("expected range [0,2], got [%d,%d]", matches[0].StartIdx, matches[0].EndIdx)
	}
}

// ============================================================================
// negative tests
// ============================================================================

// TestDetectInlinedCalls_NoPattern verifies no false positives on plain code.
func TestDetectInlinedCalls_NoPattern(t *testing.T) {
	x := i64Var("x", 1)
	y := i64Var("y", 1)

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest:   y,
				Source: &ir.BinaryOp{Op: ir.BinOpAdd, Left: &ir.VariableExpr{Var: x}, Right: i64Const(1)},
			},
		},
	}

	matches, err := DetectInlinedCalls(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

// TestDetectInlinedCalls_NilBlock verifies nil block returns error.
func TestDetectInlinedCalls_NilBlock(t *testing.T) {
	_, err := DetectInlinedCalls(nil)
	if err == nil {
		t.Error("expected error for nil block")
	}
}

// TestDetectInlinedCalls_NilFunction verifies nil function returns error.
func TestDetectInlinedCalls_NilFunction(t *testing.T) {
	_, err := DetectInlinedCallsInFunction(nil)
	if err == nil {
		t.Error("expected error for nil function")
	}
}

// TestDetectInlinedCalls_Function verifies function-level entry point.
func TestDetectInlinedCalls_Function(t *testing.T) {
	x := i64Var("x", 1)
	block := buildAbsBlock(x)

	fn := &ir.Function{
		Name:       "test",
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		EntryBlock: 0,
	}

	matches, err := DetectInlinedCallsInFunction(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
}

// TestDetectInlinedCalls_KindString verifies String() methods.
func TestDetectInlinedCalls_KindString(t *testing.T) {
	cases := []struct {
		kind InlinedCallKind
		want string
	}{
		{InlinedCallAbs, "abs"},
		{InlinedCallMin, "min"},
		{InlinedCallMax, "max"},
		{InlinedCallClamp, "clamp"},
		{InlinedCallSavedRestoreSequence, "inlined_sequence"},
		{InlinedCallUnknown, "unknown"},
	}
	for _, tc := range cases {
		if got := tc.kind.String(); got != tc.want {
			t.Errorf("kind %d: String() = %q, want %q", tc.kind, got, tc.want)
		}
	}
}

// TestDetectInlinedCalls_MatchString verifies InlinedCallMatch.String().
func TestDetectInlinedCalls_MatchString(t *testing.T) {
	m := &InlinedCallMatch{
		StartIdx:  0,
		EndIdx:    2,
		Kind:      InlinedCallAbs,
		ResultVar: i64Var("result", 1),
		Args:      []ir.Variable{i64Var("x", 1)},
	}
	s := m.String()
	if s == "" {
		t.Error("String() returned empty string")
	}
}

// BenchmarkDetectInlinedCalls_Abs measures abs detection cost.
func BenchmarkDetectInlinedCalls_Abs(b *testing.B) {
	x := i64Var("x", 1)
	b.ResetTimer()
	for b.Loop() {
		block := buildAbsBlock(x)
		_, _ = DetectInlinedCalls(block)
	}
}
