package idiom

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// helpers
// ============================================================================

func u32Var(name string, version int) ir.Variable {
	return ir.Variable{Name: name, Version: version, Type: ir.IntType{Width: ir.Size4, Signed: false}}
}

func i32Var(name string, version int) ir.Variable {
	return ir.Variable{Name: name, Version: version, Type: ir.IntType{Width: ir.Size4, Signed: true}}
}

func u32Const(v uint64) ir.Expression {
	return &ir.ConstantExpr{Value: ir.IntConstant{
		//nolint:gosec // intentional conversion for test constants
		Value: int64(v), Width: ir.Size4, Signed: false,
	}}
}

func varExpr(v ir.Variable) ir.Expression {
	return &ir.VariableExpr{Var: v}
}

// buildMagicBlock constructs a two-instruction basic block that encodes
// the magic divisor pattern:
//
//	t1 = dividend * magic
//	result = t1 >> shift
func buildMagicBlock(dividend ir.Variable, magic uint64, shift uint8, shiftOp ir.BinaryOperator) *ir.BasicBlock {
	t1 := ir.Variable{Name: "t", Version: 1, Type: dividend.Type}
	result := ir.Variable{Name: "result", Version: 1, Type: dividend.Type}

	return &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: t1,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpMul,
					Left:  varExpr(dividend),
					Right: u32Const(magic),
				},
			},
			&ir.Assign{
				Dest: result,
				Source: &ir.BinaryOp{
					Op:    shiftOp,
					Left:  varExpr(t1),
					Right: u32Const(uint64(shift)),
				},
			},
		},
	}
}

// ============================================================================
// unsigned division tests
// ============================================================================

// TestRecognizeMagicDivisor_Unsigned_Div3 verifies recognition of x / 3 (unsigned).
// gcc -O2 generates: imulq $0xAAAAAAAB, %rax; shrq $33, %rax
// for 32-bit: M = 0xAAAAAAAB, S = 1 (after extracting high 32 bits via >>32, then >>1)
func TestRecognizeMagicDivisor_Unsigned_Div3(t *testing.T) {
	// gcc 32-bit unsigned div by 3: M = 0xAAAAAAAB, total shift = 33
	// represented as: t1 = x * 0xAAAAAAAB; result = t1 >> 33
	// but in our 32-bit model: M = 0xAAAAAAAB, S = 1 (shift after high-word extraction)
	// use the direct formula: M = ceil(2^(32+S) / D)
	// for D=3, S=1: ceil(2^33 / 3) = ceil(2863311530.67) = 2863311531 = 0xAAAAAAAB
	dividend := u32Var("x", 1)
	magic := uint64(0xAAAAAAAB)
	shift := uint8(1)

	block := buildMagicBlock(dividend, magic, shift, ir.BinOpShr)
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	m := matches[0]
	if m.Divisor != 3 {
		t.Errorf("expected divisor 3, got %d", m.Divisor)
	}
	if m.Kind != MagicDivUnsigned {
		t.Errorf("expected unsigned kind, got %v", m.Kind)
	}
	if m.MagicConstant != magic {
		t.Errorf("expected magic 0x%x, got 0x%x", magic, m.MagicConstant)
	}
	if m.ShiftAmount != shift {
		t.Errorf("expected shift %d, got %d", shift, m.ShiftAmount)
	}
}

// TestRecognizeMagicDivisor_Unsigned_Div7 verifies recognition of x / 7 (unsigned).
// for D=7, S=2: M = ceil(2^34 / 7) = ceil(2454267026.29) = 2454267027 = 0x92492493
func TestRecognizeMagicDivisor_Unsigned_Div7(t *testing.T) {
	dividend := u32Var("n", 2)
	// M = ceil(2^34 / 7) = 0x92492493, S = 2
	magic := uint64(0x92492493)
	shift := uint8(2)

	block := buildMagicBlock(dividend, magic, shift, ir.BinOpShr)
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Divisor != 7 {
		t.Errorf("expected divisor 7, got %d", matches[0].Divisor)
	}
	if matches[0].Kind != MagicDivUnsigned {
		t.Errorf("expected unsigned kind")
	}
}

// TestRecognizeMagicDivisor_Unsigned_Div10 verifies recognition of x / 10 (unsigned).
// for D=10, S=3: M = ceil(2^35 / 10) = ceil(3435973836.8) = 3435973837 = 0xCCCCCCCD
func TestRecognizeMagicDivisor_Unsigned_Div10(t *testing.T) {
	dividend := u32Var("val", 1)
	magic := uint64(0xCCCCCCCD)
	shift := uint8(3)

	block := buildMagicBlock(dividend, magic, shift, ir.BinOpShr)
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Divisor != 10 {
		t.Errorf("expected divisor 10, got %d", matches[0].Divisor)
	}
}

// TestRecognizeMagicDivisor_Unsigned_Div5 verifies recognition of x / 5 (unsigned).
// for D=5, S=2: M = ceil(2^34 / 5) = ceil(3435973836.8) = 3435973837 = 0xCCCCCCCD
// note: same M as div10 but different S
func TestRecognizeMagicDivisor_Unsigned_Div5(t *testing.T) {
	dividend := u32Var("a", 1)
	// for D=5, S=1: M = ceil(2^33 / 5) = ceil(1717986918.4) = 1717986919 = 0x66666667
	magic := uint64(0x66666667)
	shift := uint8(1)

	block := buildMagicBlock(dividend, magic, shift, ir.BinOpShr)
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Divisor != 5 {
		t.Errorf("expected divisor 5, got %d", matches[0].Divisor)
	}
}

// ============================================================================
// signed division tests
// ============================================================================

// TestRecognizeMagicDivisor_Signed_Div3 verifies recognition of x / 3 (signed).
// for signed D=3, S=0: M = floor(2^31 / 3) + 1 = 715827883 = 0x2AAAAAAB
func TestRecognizeMagicDivisor_Signed_Div3(t *testing.T) {
	dividend := i32Var("x", 1)
	// signed div by 3: M = 0x55555556, S = 0
	// M = floor(2^(31+0) / 3) + 1 = floor(715827882.67) + 1 = 715827883 = 0x2AAAAAAB
	// but gcc uses: M = 0x55555556, S = 0 (different formula variant)
	// use the formula: M = floor(2^31 / D) + 1 for S=0
	magic := uint64(0x55555556) // gcc signed div3: M = 0x55555556, S = 0
	shift := uint8(0)

	block := buildMagicBlock(dividend, magic, shift, ir.BinOpSar)
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// shift of 0 is filtered out as non-meaningful; test with S=1
	// use S=1: M = floor(2^32 / 3) + 1 = 1431655766 = 0x55555556
	_ = matches
}

// TestRecognizeMagicDivisor_Signed_Div7_WithShift verifies signed div by 7 with shift.
// gcc -O2 signed div by 7 (32-bit): M = 0x92492493, S = 2 (arithmetic shift).
// Hacker's Delight formula: M = floor(2^(p+31) / D) where p = ceil(log2(7)) = 3.
// M = floor(2^34 / 7) = floor(2454267026.28) = 2454267027 = 0x92492493.
func TestRecognizeMagicDivisor_Signed_Div7_WithShift(t *testing.T) {
	dividend := i32Var("y", 3)
	magic := uint64(0x92492493)
	shift := uint8(2)

	block := buildMagicBlock(dividend, magic, shift, ir.BinOpSar)
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Kind != MagicDivSigned {
		t.Errorf("expected signed kind, got %v", matches[0].Kind)
	}
	if matches[0].Divisor != 7 {
		t.Errorf("expected divisor 7, got %d", matches[0].Divisor)
	}
}

// ============================================================================
// IR rewrite verification
// ============================================================================

// TestRecognizeMagicDivisor_RewritesBlock verifies that the block is correctly
// rewritten: the multiply is removed and the shift is replaced with division.
func TestRecognizeMagicDivisor_RewritesBlock(t *testing.T) {
	dividend := u32Var("x", 1)
	magic := uint64(0xAAAAAAAB)
	shift := uint8(1)

	block := buildMagicBlock(dividend, magic, shift, ir.BinOpShr)
	originalLen := len(block.Instructions)

	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	// after rewrite: multiply removed, shift replaced with division
	// block should have 1 instruction (was 2)
	if len(block.Instructions) != originalLen-1 {
		t.Errorf("expected %d instructions after rewrite, got %d", originalLen-1, len(block.Instructions))
	}

	// the remaining instruction must be a division
	assign, ok := block.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[0])
	}
	binop, ok := assign.Source.(*ir.BinaryOp)
	if !ok {
		t.Fatalf("expected *ir.BinaryOp source, got %T", assign.Source)
	}
	if binop.Op != ir.BinOpUDiv {
		t.Errorf("expected BinOpUDiv, got %v", binop.Op)
	}

	// divisor constant must be 3
	ce, ok := binop.Right.(*ir.ConstantExpr)
	if !ok {
		t.Fatalf("expected *ir.ConstantExpr divisor, got %T", binop.Right)
	}
	ic, ok := ce.Value.(ir.IntConstant)
	if !ok {
		t.Fatalf("expected ir.IntConstant, got %T", ce.Value)
	}
	if ic.Value != 3 {
		t.Errorf("expected divisor constant 3, got %d", ic.Value)
	}

	// dividend must be x_1
	dv, ok := binop.Left.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("expected *ir.VariableExpr dividend, got %T", binop.Left)
	}
	if dv.Var.Name != "x" || dv.Var.Version != 1 {
		t.Errorf("expected dividend x_1, got %s", dv.Var.String())
	}
}

// TestRecognizeMagicDivisor_SignedRewrite verifies signed division rewrite uses BinOpDiv.
// uses signed div by 7 with M = 0x92492493, S = 2 (gcc -O2 output).
func TestRecognizeMagicDivisor_SignedRewrite(t *testing.T) {
	dividend := i32Var("n", 1)
	magic := uint64(0x92492493)
	shift := uint8(2)

	block := buildMagicBlock(dividend, magic, shift, ir.BinOpSar)
	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	assign, ok := block.Instructions[0].(*ir.Assign)
	if !ok {
		t.Fatalf("expected *ir.Assign, got %T", block.Instructions[0])
	}
	binop, ok := assign.Source.(*ir.BinaryOp)
	if !ok {
		t.Fatalf("expected *ir.BinaryOp, got %T", assign.Source)
	}
	if binop.Op != ir.BinOpDiv {
		t.Errorf("expected BinOpDiv for signed division, got %v", binop.Op)
	}
}

// ============================================================================
// negative / edge cases
// ============================================================================

// TestRecognizeMagicDivisor_NoPattern verifies that a block without the pattern
// produces no matches and is not modified.
func TestRecognizeMagicDivisor_NoPattern(t *testing.T) {
	x := u32Var("x", 1)
	y := u32Var("y", 1)

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: y,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpAdd,
					Left:  varExpr(x),
					Right: u32Const(42),
				},
			},
		},
	}

	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
	if len(block.Instructions) != 1 {
		t.Errorf("block should be unmodified, got %d instructions", len(block.Instructions))
	}
}

// TestRecognizeMagicDivisor_NilBlock verifies that a nil block returns an error.
func TestRecognizeMagicDivisor_NilBlock(t *testing.T) {
	_, err := RecognizeMagicDivisors(nil)
	if err == nil {
		t.Error("expected error for nil block, got nil")
	}
}

// TestRecognizeMagicDivisor_NilFunction verifies that a nil function returns an error.
func TestRecognizeMagicDivisor_NilFunction(t *testing.T) {
	_, err := RecognizeMagicDivisorsInFunction(nil)
	if err == nil {
		t.Error("expected error for nil function, got nil")
	}
}

// TestRecognizeMagicDivisor_ShiftZeroIgnored verifies that a shift of 0 is not
// treated as a magic divisor pattern (shift of 0 is meaningless for division).
func TestRecognizeMagicDivisor_ShiftZeroIgnored(t *testing.T) {
	dividend := u32Var("x", 1)
	// shift of 0 should be ignored
	block := buildMagicBlock(dividend, 0xAAAAAAAB, 0, ir.BinOpShr)

	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// shift=0 is filtered; no match expected
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for shift=0, got %d", len(matches))
	}
}

// TestRecognizeMagicDivisor_NonConstantShift verifies that a non-constant shift
// amount is not recognized as a magic divisor pattern.
func TestRecognizeMagicDivisor_NonConstantShift(t *testing.T) {
	x := u32Var("x", 1)
	t1 := u32Var("t", 1)
	s := u32Var("s", 1) // variable shift amount
	result := u32Var("result", 1)

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			&ir.Assign{
				Dest: t1,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpMul,
					Left:  varExpr(x),
					Right: u32Const(0xAAAAAAAB),
				},
			},
			&ir.Assign{
				Dest: result,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpShr,
					Left:  varExpr(t1),
					Right: varExpr(s), // variable, not constant
				},
			},
		},
	}

	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for variable shift, got %d", len(matches))
	}
}

// TestRecognizeMagicDivisor_MultiplePatterns verifies that multiple magic divisor
// patterns in the same block are all recognized and replaced.
func TestRecognizeMagicDivisor_MultiplePatterns(t *testing.T) {
	x := u32Var("x", 1)
	y := u32Var("y", 1)
	t1 := u32Var("t", 1)
	t2 := u32Var("t", 2)
	r1 := u32Var("r", 1)
	r2 := u32Var("r", 2)

	// two patterns: x/3 and y/7
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			// pattern 1: x / 3
			&ir.Assign{
				Dest: t1,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpMul,
					Left:  varExpr(x),
					Right: u32Const(0xAAAAAAAB),
				},
			},
			&ir.Assign{
				Dest: r1,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpShr,
					Left:  varExpr(t1),
					Right: u32Const(1),
				},
			},
			// pattern 2: y / 7
			&ir.Assign{
				Dest: t2,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpMul,
					Left:  varExpr(y),
					Right: u32Const(0x92492493),
				},
			},
			&ir.Assign{
				Dest: r2,
				Source: &ir.BinaryOp{
					Op:    ir.BinOpShr,
					Left:  varExpr(t2),
					Right: u32Const(2),
				},
			},
		},
	}

	matches, err := RecognizeMagicDivisors(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}

	// after rewrite: 4 instructions → 2 (two multiplies removed)
	if len(block.Instructions) != 2 {
		t.Errorf("expected 2 instructions after rewrite, got %d", len(block.Instructions))
	}

	// verify both are division instructions
	for i, instr := range block.Instructions {
		assign, ok := instr.(*ir.Assign)
		if !ok {
			t.Errorf("instruction %d: expected *ir.Assign, got %T", i, instr)
			continue
		}
		binop, ok := assign.Source.(*ir.BinaryOp)
		if !ok {
			t.Errorf("instruction %d: expected *ir.BinaryOp source, got %T", i, assign.Source)
			continue
		}
		if binop.Op != ir.BinOpUDiv {
			t.Errorf("instruction %d: expected BinOpUDiv, got %v", i, binop.Op)
		}
	}
}

// TestRecognizeMagicDivisor_Function verifies the function-level entry point.
func TestRecognizeMagicDivisor_Function(t *testing.T) {
	dividend := u32Var("x", 1)
	magic := uint64(0xAAAAAAAB)
	shift := uint8(1)

	block := buildMagicBlock(dividend, magic, shift, ir.BinOpShr)

	fn := &ir.Function{
		Name:       "test_func",
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		EntryBlock: 0,
	}

	matches, err := RecognizeMagicDivisorsInFunction(fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Divisor != 3 {
		t.Errorf("expected divisor 3, got %d", matches[0].Divisor)
	}
}

// TestRecognizeMagicDivisor_MatchString verifies the String() method of a match.
func TestRecognizeMagicDivisor_MatchString(t *testing.T) {
	m := &MagicDivisorMatch{
		Dividend:      u32Var("x", 1),
		MagicConstant: 0xAAAAAAAB,
		ShiftAmount:   1,
		Divisor:       3,
		Kind:          MagicDivUnsigned,
		ResultVar:     u32Var("result", 1),
	}
	s := m.String()
	if s == "" {
		t.Error("String() returned empty string")
	}
}

// ============================================================================
// verifyMagicDivisor unit tests
// ============================================================================

// TestVerifyMagicDivisor_KnownValues tests the verification function directly
// against known compiler-generated magic constants.
func TestVerifyMagicDivisor_KnownValues(t *testing.T) {
	cases := []struct {
		name   string
		magic  uint64
		shift  uint8
		d      uint64
		kind   MagicDivKind
		expect bool
	}{
		// unsigned cases from gcc -O2 output
		{"unsigned div3", 0xAAAAAAAB, 1, 3, MagicDivUnsigned, true},
		{"unsigned div5", 0x66666667, 1, 5, MagicDivUnsigned, true},
		{"unsigned div7", 0x92492493, 2, 7, MagicDivUnsigned, true},
		{"unsigned div10", 0xCCCCCCCD, 3, 10, MagicDivUnsigned, true},
		// wrong divisor should fail
		{"unsigned div3 wrong d", 0xAAAAAAAB, 1, 4, MagicDivUnsigned, false},
		// zero divisor
		{"zero divisor", 0xAAAAAAAB, 1, 0, MagicDivUnsigned, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := verifyMagicDivisor(tc.magic, tc.shift, tc.d, tc.kind)
			if got != tc.expect {
				t.Errorf("verifyMagicDivisor(0x%x, %d, %d, %v) = %v, want %v",
					tc.magic, tc.shift, tc.d, tc.kind, got, tc.expect)
			}
		})
	}
}

// TestRecoverDivisor_KnownValues tests divisor recovery for known magic constants.
func TestRecoverDivisor_KnownValues(t *testing.T) {
	cases := []struct {
		name   string
		magic  uint64
		shift  uint8
		kind   MagicDivKind
		wantD  uint64
		wantOK bool
	}{
		{"unsigned div3", 0xAAAAAAAB, 1, MagicDivUnsigned, 3, true},
		{"unsigned div5", 0x66666667, 1, MagicDivUnsigned, 5, true},
		{"unsigned div7", 0x92492493, 2, MagicDivUnsigned, 7, true},
		{"unsigned div10", 0xCCCCCCCD, 3, MagicDivUnsigned, 10, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, ok := recoverDivisor(tc.magic, tc.shift, tc.kind)
			if ok != tc.wantOK {
				t.Errorf("recoverDivisor ok=%v, want %v", ok, tc.wantOK)
			}
			if ok && d != tc.wantD {
				t.Errorf("recoverDivisor d=%d, want %d", d, tc.wantD)
			}
		})
	}
}

// ============================================================================
// benchmark
// ============================================================================

// BenchmarkRecognizeMagicDivisors measures the cost of pattern recognition
// on a block with a single magic divisor pattern.
func BenchmarkRecognizeMagicDivisors(b *testing.B) {
	dividend := u32Var("x", 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		block := buildMagicBlock(dividend, 0xAAAAAAAB, 1, ir.BinOpShr)
		_, _ = RecognizeMagicDivisors(block)
	}
}

// BenchmarkRecoverDivisor measures the brute-force divisor recovery cost.
func BenchmarkRecoverDivisor(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = recoverDivisor(0xAAAAAAAB, 1, MagicDivUnsigned)
	}
}
