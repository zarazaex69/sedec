package ir

import (
	"testing"
)

// TestLazyFlagsCreation tests basic lazy flags structure creation
func TestLazyFlagsCreation(t *testing.T) {
	// create operands
	left := VariableExpr{
		Var: Variable{
			Name: "rax",
			Type: IntType{Width: Size8, Signed: false},
		},
	}
	right := VariableExpr{
		Var: Variable{
			Name: "rbx",
			Type: IntType{Width: Size8, Signed: false},
		},
	}

	// create result
	result := BinaryOp{
		Op:    BinOpAdd,
		Left:  left,
		Right: right,
	}

	// create lazy flags
	loc := SourceLocation{
		Address:     0x1000,
		Instruction: "add rax, rbx",
	}

	lf := NewLazyFlags(
		FlagOpArithmetic,
		[]Expression{left, right},
		result,
		Size8,
		loc,
	)

	// verify structure
	if lf.Operation != FlagOpArithmetic {
		t.Errorf("expected operation %v, got %v", FlagOpArithmetic, lf.Operation)
	}

	if len(lf.Operands) != 2 {
		t.Errorf("expected 2 operands, got %d", len(lf.Operands))
	}

	if lf.Size != Size8 {
		t.Errorf("expected size %v, got %v", Size8, lf.Size)
	}

	if lf.IsAnyMaterialized() {
		t.Error("expected no materialized flags initially")
	}
}

// TestLazyFlagsMaterialization tests flag materialization tracking
func TestLazyFlagsMaterialization(t *testing.T) {
	// create simple lazy flags
	result := ConstantExpr{
		Value: IntConstant{Value: 42, Width: Size8, Signed: false},
	}

	lf := NewLazyFlags(
		FlagOpArithmetic,
		[]Expression{result},
		result,
		Size8,
		SourceLocation{},
	)

	// initially no flags materialized
	if lf.IsMaterialized(FlagZF) {
		t.Error("zf should not be materialized initially")
	}

	// mark zf as materialized
	lf.MarkMaterialized(FlagZF)

	if !lf.IsMaterialized(FlagZF) {
		t.Error("zf should be materialized after marking")
	}

	if !lf.IsAnyMaterialized() {
		t.Error("should have at least one materialized flag")
	}

	// verify other flags still not materialized
	if lf.IsMaterialized(FlagSF) {
		t.Error("sf should not be materialized")
	}

	// get materialized flags
	materialized := lf.GetMaterializedFlags()
	if len(materialized) != 1 {
		t.Errorf("expected 1 materialized flag, got %d", len(materialized))
	}

	if materialized[0] != FlagZF {
		t.Errorf("expected zf, got %v", materialized[0])
	}
}

// TestMaterializeZeroFlag tests zero flag materialization
func TestMaterializeZeroFlag(t *testing.T) {
	// create result expression
	result := VariableExpr{
		Var: Variable{
			Name: "result",
			Type: IntType{Width: Size4, Signed: false},
		},
	}

	lf := NewLazyFlags(
		FlagOpArithmetic,
		[]Expression{result},
		result,
		Size4,
		SourceLocation{},
	)

	// materialize zf
	zfExpr := lf.MaterializeFlag(FlagZF)

	// verify it's a comparison with zero
	binOp, ok := zfExpr.(BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp, got %T", zfExpr)
	}

	if binOp.Op != BinOpEq {
		t.Errorf("expected equality comparison, got %v", binOp.Op)
	}

	// verify right operand is zero
	constExpr, ok := binOp.Right.(ConstantExpr)
	if !ok {
		t.Fatalf("expected ConstantExpr, got %T", binOp.Right)
	}

	intConst, ok := constExpr.Value.(IntConstant)
	if !ok {
		t.Fatalf("expected IntConstant, got %T", constExpr.Value)
	}

	if intConst.Value != 0 {
		t.Errorf("expected zero constant, got %d", intConst.Value)
	}

	// verify flag marked as materialized
	if !lf.IsMaterialized(FlagZF) {
		t.Error("zf should be marked as materialized")
	}
}

// TestMaterializeSignFlag tests sign flag materialization
func TestMaterializeSignFlag(t *testing.T) {
	result := VariableExpr{
		Var: Variable{
			Name: "result",
			Type: IntType{Width: Size8, Signed: true},
		},
	}

	lf := NewLazyFlags(
		FlagOpArithmetic,
		[]Expression{result},
		result,
		Size8,
		SourceLocation{},
	)

	// materialize sf
	sfExpr := lf.MaterializeFlag(FlagSF)

	// verify it's checking sign bit
	binOp, ok := sfExpr.(BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp, got %T", sfExpr)
	}

	if binOp.Op != BinOpNe {
		t.Errorf("expected inequality comparison, got %v", binOp.Op)
	}

	// verify flag marked as materialized
	if !lf.IsMaterialized(FlagSF) {
		t.Error("sf should be marked as materialized")
	}
}

// TestLogicalOperationFlags tests flag materialization for logical operations
func TestLogicalOperationFlags(t *testing.T) {
	result := VariableExpr{
		Var: Variable{
			Name: "result",
			Type: IntType{Width: Size4, Signed: false},
		},
	}

	lf := NewLazyFlags(
		FlagOpLogical,
		[]Expression{result},
		result,
		Size4,
		SourceLocation{},
	)

	// materialize cf (should be false for logical ops)
	cfExpr := lf.MaterializeFlag(FlagCF)

	constExpr, ok := cfExpr.(ConstantExpr)
	if !ok {
		t.Fatalf("expected ConstantExpr for cf, got %T", cfExpr)
	}

	boolConst, ok := constExpr.Value.(BoolConstant)
	if !ok {
		t.Fatalf("expected BoolConstant, got %T", constExpr.Value)
	}

	if boolConst.Value != false {
		t.Error("cf should be false for logical operations")
	}

	// materialize of (should be false for logical ops)
	ofExpr := lf.MaterializeFlag(FlagOF)

	constExpr, ok = ofExpr.(ConstantExpr)
	if !ok {
		t.Fatalf("expected ConstantExpr for of, got %T", ofExpr)
	}

	boolConst, ok = constExpr.Value.(BoolConstant)
	if !ok {
		t.Fatalf("expected BoolConstant, got %T", constExpr.Value)
	}

	if boolConst.Value != false {
		t.Error("of should be false for logical operations")
	}
}

// TestGetRequiredFlags tests flag requirement analysis for conditional jumps
func TestGetRequiredFlags(t *testing.T) {
	tests := []struct {
		mnemonic string
		expected []CPUFlag
	}{
		{"je", []CPUFlag{FlagZF}},
		{"jne", []CPUFlag{FlagZF}},
		{"jz", []CPUFlag{FlagZF}},
		{"jnz", []CPUFlag{FlagZF}},
		{"jl", []CPUFlag{FlagSF, FlagOF}},
		{"jge", []CPUFlag{FlagSF, FlagOF}},
		{"jle", []CPUFlag{FlagZF, FlagSF, FlagOF}},
		{"jg", []CPUFlag{FlagZF, FlagSF, FlagOF}},
		{"jb", []CPUFlag{FlagCF}},
		{"jae", []CPUFlag{FlagCF}},
		{"jbe", []CPUFlag{FlagCF, FlagZF}},
		{"ja", []CPUFlag{FlagCF, FlagZF}},
		{"js", []CPUFlag{FlagSF}},
		{"jns", []CPUFlag{FlagSF}},
		{"jo", []CPUFlag{FlagOF}},
		{"jno", []CPUFlag{FlagOF}},
		{"jp", []CPUFlag{FlagPF}},
		{"jnp", []CPUFlag{FlagPF}},
	}

	for _, tt := range tests {
		t.Run(tt.mnemonic, func(t *testing.T) {
			required := GetRequiredFlags(tt.mnemonic)

			if len(required) != len(tt.expected) {
				t.Errorf("expected %d flags, got %d", len(tt.expected), len(required))
				return
			}

			// verify all expected flags present
			for _, expectedFlag := range tt.expected {
				found := false
				for _, actualFlag := range required {
					if actualFlag == expectedFlag {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected flag %v not found in result", expectedFlag)
				}
			}
		})
	}
}

// TestIsConditionalJump tests conditional jump detection
func TestIsConditionalJump(t *testing.T) {
	tests := []struct {
		mnemonic string
		expected bool
	}{
		{"je", true},
		{"jne", true},
		{"jl", true},
		{"jg", true},
		{"jmp", false},
		{"call", false},
		{"ret", false},
		{"add", false},
		{"mov", false},
	}

	for _, tt := range tests {
		t.Run(tt.mnemonic, func(t *testing.T) {
			result := IsConditionalJump(tt.mnemonic)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestIsFlagReadingInstruction tests flag-reading instruction detection
func TestIsFlagReadingInstruction(t *testing.T) {
	tests := []struct {
		mnemonic string
		expected bool
	}{
		// conditional jumps
		{"je", true},
		{"jne", true},
		{"jl", true},

		// conditional moves
		{"cmove", true},
		{"cmovne", true},
		{"cmovl", true},

		// set byte on condition
		{"sete", true},
		{"setne", true},
		{"setl", true},

		// flag manipulation
		{"lahf", true},
		{"sahf", true},
		{"pushf", true},
		{"popf", true},
		{"clc", true},
		{"stc", true},

		// non-flag instructions
		{"add", false},
		{"mov", false},
		{"jmp", false},
		{"call", false},
		{"ret", false},
	}

	for _, tt := range tests {
		t.Run(tt.mnemonic, func(t *testing.T) {
			result := IsFlagReadingInstruction(tt.mnemonic)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestFlagOperationString tests string representation of flag operations
func TestFlagOperationString(t *testing.T) {
	tests := []struct {
		op       FlagOperation
		expected string
	}{
		{FlagOpArithmetic, "arithmetic"},
		{FlagOpLogical, "logical"},
		{FlagOpShift, "shift"},
		{FlagOpMultiply, "multiply"},
		{FlagOpDivide, "divide"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.op.String()
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestCPUFlagString tests string representation of cpu flags
func TestCPUFlagString(t *testing.T) {
	tests := []struct {
		flag     CPUFlag
		expected string
	}{
		{FlagZF, "zf"},
		{FlagSF, "sf"},
		{FlagCF, "cf"},
		{FlagOF, "of"},
		{FlagPF, "pf"},
		{FlagAF, "af"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.flag.String()
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestSelectiveMaterialization tests that only required flags are materialized
func TestSelectiveMaterialization(t *testing.T) {
	// create lazy flags for add operation
	left := VariableExpr{
		Var: Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}},
	}
	right := VariableExpr{
		Var: Variable{Name: "rbx", Type: IntType{Width: Size8, Signed: false}},
	}
	result := BinaryOp{Op: BinOpAdd, Left: left, Right: right}

	lf := NewLazyFlags(
		FlagOpArithmetic,
		[]Expression{left, right},
		result,
		Size8,
		SourceLocation{},
	)

	// simulate je instruction (only needs zf)
	requiredFlags := GetRequiredFlags("je")

	// materialize only required flags
	for _, flag := range requiredFlags {
		_ = lf.MaterializeFlag(flag)
	}

	// verify only zf materialized
	if !lf.IsMaterialized(FlagZF) {
		t.Error("zf should be materialized for je")
	}

	if lf.IsMaterialized(FlagSF) {
		t.Error("sf should not be materialized for je")
	}

	if lf.IsMaterialized(FlagCF) {
		t.Error("cf should not be materialized for je")
	}

	if lf.IsMaterialized(FlagOF) {
		t.Error("of should not be materialized for je")
	}

	// verify elimination rate
	materializedCount := len(lf.GetMaterializedFlags())
	totalFlags := 6 // zf, sf, cf, of, pf, af

	eliminationRate := float64(totalFlags-materializedCount) / float64(totalFlags)

	// for je, we eliminate 5 out of 6 flags = 83.3% elimination
	expectedRate := 5.0 / 6.0 // ~0.833

	if eliminationRate < expectedRate-0.01 {
		t.Errorf("expected elimination rate >= %.2f, got %.2f", expectedRate, eliminationRate)
	}
}

// TestMultipleOperations tests lazy flags with multiple consecutive operations
func TestMultipleOperations(t *testing.T) {
	// simulate: add rax, rbx; add rcx, rdx; je target
	// first add flags should be completely eliminated
	// second add flags: only zf materialized

	// first add
	lf1 := NewLazyFlags(
		FlagOpArithmetic,
		[]Expression{
			VariableExpr{Var: Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}},
			VariableExpr{Var: Variable{Name: "rbx", Type: IntType{Width: Size8, Signed: false}}},
		},
		BinaryOp{Op: BinOpAdd},
		Size8,
		SourceLocation{Address: 0x1000},
	)

	// second add
	lf2 := NewLazyFlags(
		FlagOpArithmetic,
		[]Expression{
			VariableExpr{Var: Variable{Name: "rcx", Type: IntType{Width: Size8, Signed: false}}},
			VariableExpr{Var: Variable{Name: "rdx", Type: IntType{Width: Size8, Signed: false}}},
		},
		BinaryOp{Op: BinOpAdd},
		Size8,
		SourceLocation{Address: 0x1006},
	)

	// je only uses flags from second add
	requiredFlags := GetRequiredFlags("je")
	for _, flag := range requiredFlags {
		_ = lf2.MaterializeFlag(flag)
	}

	// verify first add has no materialized flags (100% elimination)
	if lf1.IsAnyMaterialized() {
		t.Error("first add should have no materialized flags")
	}

	// verify second add has only zf materialized
	if !lf2.IsMaterialized(FlagZF) {
		t.Error("second add should have zf materialized")
	}

	materializedCount := len(lf2.GetMaterializedFlags())
	if materializedCount != 1 {
		t.Errorf("expected 1 materialized flag, got %d", materializedCount)
	}
}

// BenchmarkFlagMaterialization benchmarks flag materialization performance
func BenchmarkFlagMaterialization(b *testing.B) {
	result := VariableExpr{
		Var: Variable{
			Name: "result",
			Type: IntType{Width: Size8, Signed: false},
		},
	}

	lf := NewLazyFlags(
		FlagOpArithmetic,
		[]Expression{result},
		result,
		Size8,
		SourceLocation{},
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// materialize all flags
		_ = lf.MaterializeFlag(FlagZF)
		_ = lf.MaterializeFlag(FlagSF)
		_ = lf.MaterializeFlag(FlagCF)
		_ = lf.MaterializeFlag(FlagOF)
		_ = lf.MaterializeFlag(FlagPF)
		_ = lf.MaterializeFlag(FlagAF)

		// reset for next iteration
		lf.Materialized = make(map[CPUFlag]bool)
	}
}

// BenchmarkGetRequiredFlags benchmarks flag requirement analysis
func BenchmarkGetRequiredFlags(b *testing.B) {
	mnemonics := []string{"je", "jne", "jl", "jg", "jle", "jge", "jb", "ja", "jbe", "jae"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, mnemonic := range mnemonics {
			_ = GetRequiredFlags(mnemonic)
		}
	}
}
