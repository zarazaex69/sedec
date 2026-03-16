package idiom

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// helpers
// ============================================================================

func i64Var(name string, version int) ir.Variable { //nolint:unparam // version used for test clarity
	return ir.Variable{Name: name, Version: version, Type: ir.IntType{Width: ir.Size8, Signed: true}}
}

func i64Const(v int64) ir.Expression {
	return &ir.ConstantExpr{Value: ir.IntConstant{Value: v, Width: ir.Size8, Signed: true}}
}

// buildAddChain builds a basic block with an addition chain representing x * count.
// for count=4 and base variable x:
//
//	t1 = x + x       (2*x)
//	t2 = t1 + x      (3*x)
//	t3 = t2 + x      (4*x)
func buildAddChain(base ir.Variable, count int) *ir.BasicBlock {
	if count < 2 {
		panic("count must be >= 2")
	}

	instrs := make([]ir.IRInstruction, 0, count-1)

	// first instruction: t1 = x + x
	t1 := ir.Variable{Name: "t", Version: 1, Type: base.Type}
	instrs = append(instrs, &ir.Assign{
		Dest: t1,
		Source: &ir.BinaryOp{
			Op:    ir.BinOpAdd,
			Left:  &ir.VariableExpr{Var: base},
			Right: &ir.VariableExpr{Var: base},
		},
	})

	prev := t1
	for i := 2; i < count; i++ {
		curr := ir.Variable{Name: "t", Version: i, Type: base.Type}
		instrs = append(instrs, &ir.Assign{
			Dest: curr,
			Source: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: prev},
				Right: &ir.VariableExpr{Var: base},
			},
		})
		prev = curr
	}

	return &ir.BasicBlock{ID: 0, Instructions: instrs}
}

// ============================================================================
// tests
// ============================================================================

// TestStrengthReduction_2x verifies detection of x + x = 2*x.
func TestStrengthReduction_2x(t *testing.T) {
	x := i64Var("x", 1)
	block := buildAddChain(x, 2)

	matches, err := RecognizeStrengthReduction(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Multiplier != 2 {
		t.Errorf("expected multiplier 2, got %d", matches[0].Multiplier)
	}
	if matches[0].Operand.Name != "x" {
		t.Errorf("expected operand x, got %s", matches[0].Operand.Name)
	}
}

// TestStrengthReduction_4x verifies detection of a 4-step addition chain = 4*x.
func TestStrengthReduction_4x(t *testing.T) {
	x := i64Var("x", 1)
	block := buildAddChain(x, 4)

	matches, err := RecognizeStrengthReduction(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Multiplier != 4 {
		t.Errorf("expected multiplier 4, got %d", matches[0].Multiplier)
	}
}

// TestStrengthReduction_8x verifies detection of an 8-step addition chain = 8*x.
func TestStrengthReduction_8x(t *testing.T) {
	x := i64Var("n", 1)
	block := buildAddChain(x, 8)

	matches, err := RecognizeStrengthReduction(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Multiplier != 8 {
		t.Errorf("expected multiplier 8, got %d", matches[0].Multiplier)
	}
}

// TestStrengthReduction_RewritesToMul verifies that the block is rewritten
// to a single multiply instruction.
func TestStrengthReduction_RewritesToMul(t *testing.T) {
	x := i64Var("x", 1)
	block := buildAddChain(x, 3)
	originalLen := len(block.Instructions)

	matches, err := RecognizeStrengthReduction(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	// 3*x chain has 2 add instructions; after rewrite: 1 multiply
	if len(block.Instructions) != 1 {
		t.Errorf("expected 1 instruction after rewrite, got %d (was %d)", len(block.Instructions), originalLen)
	}

	assign, ok := block.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[0])
	}
	binop, ok := assign.Source.(*ir.BinaryOp)
	if !ok {
		t.Fatalf("expected *ir.BinaryOp, got %T", assign.Source)
	}
	if binop.Op != ir.BinOpMul {
		t.Errorf("expected BinOpMul, got %v", binop.Op)
	}

	// verify multiplier constant
	ce, ok := binop.Right.(*ir.ConstantExpr)
	if !ok {
		t.Fatalf("expected *ir.ConstantExpr, got %T", binop.Right)
	}
	ic, ok := ce.Value.(ir.IntConstant)
	if !ok {
		t.Fatalf("expected ir.IntConstant, got %T", ce.Value)
	}
	if ic.Value != 3 {
		t.Errorf("expected multiplier 3, got %d", ic.Value)
	}
}

// TestStrengthReduction_NoPattern verifies that a block without the pattern
// produces no matches.
func TestStrengthReduction_NoPattern(t *testing.T) {
	x := i64Var("x", 1)
	y := i64Var("y", 1)

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: y,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpAdd,
					Left:  &ir.VariableExpr{Var: x},
					Right: i64Const(42),
				},
			},
		},
	}

	matches, err := RecognizeStrengthReduction(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

// TestStrengthReduction_NilBlock verifies nil block returns error.
func TestStrengthReduction_NilBlock(t *testing.T) {
	_, err := RecognizeStrengthReduction(nil)
	if err == nil {
		t.Error("expected error for nil block")
	}
}

// TestStrengthReduction_NilFunction verifies nil function returns error.
func TestStrengthReduction_NilFunction(t *testing.T) {
	_, err := RecognizeStrengthReductionInFunction(nil)
	if err == nil {
		t.Error("expected error for nil function")
	}
}

// TestStrengthReduction_Function verifies function-level entry point.
func TestStrengthReduction_Function(t *testing.T) {
	x := i64Var("x", 1)
	block := buildAddChain(x, 4)

	fn := &ir.Function{
		Name:       "test",
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		EntryBlock: 0,
	}

	matches, err := RecognizeStrengthReductionInFunction(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Multiplier != 4 {
		t.Errorf("expected multiplier 4, got %d", matches[0].Multiplier)
	}
}

// TestStrengthReduction_MatchString verifies String() method.
func TestStrengthReduction_MatchString(t *testing.T) {
	m := &StrengthReductionMatch{
		Multiplier: 4,
		Operand:    i64Var("x", 1),
		ResultVar:  i64Var("result", 1),
	}
	s := m.String()
	if s == "" {
		t.Error("String() returned empty string")
	}
}

// BenchmarkStrengthReduction measures recognition cost on a 4-step chain.
func BenchmarkStrengthReduction(b *testing.B) {
	x := i64Var("x", 1)
	b.ResetTimer()
	for b.Loop() {
		block := buildAddChain(x, 4)
		_, _ = RecognizeStrengthReduction(block)
	}
}
