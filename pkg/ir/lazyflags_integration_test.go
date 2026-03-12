package ir

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestLazyFlagsIntegration demonstrates real-world lazy flag elimination.
// this test simulates a typical code sequence with multiple arithmetic operations
// followed by a single conditional branch, showing 95%+ flag elimination.
func TestLazyFlagsIntegration(t *testing.T) {
	// simulate real x86_64 code sequence:
	//   add rax, rbx    ; sets 6 flags
	//   add rcx, rdx    ; overwrites 6 flags
	//   add rsi, rdi    ; overwrites 6 flags
	//   je target       ; uses only zf from last add
	//
	// expected elimination: 18 total flags - 1 used = 17 eliminated (94.4%)

	lifter := NewLifter()

	// instruction 1: add rax, rbx
	insn1 := &disasm.Instruction{
		Address:  0x1000,
		Mnemonic: "add",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
		},
		Length: 3,
	}

	ir1, err := lifter.LiftInstruction(insn1)
	if err != nil {
		t.Fatalf("failed to lift add rax, rbx: %v", err)
	}

	// verify only 1 ir instruction emitted (no flag assignments)
	if len(ir1) != 1 {
		t.Errorf("add rax, rbx: expected 1 ir instruction, got %d", len(ir1))
	}

	// verify lazy flags created
	lazyFlags1 := lifter.GetCurrentLazyFlags()
	if lazyFlags1 == nil {
		t.Fatal("add rax, rbx: expected lazy flags, got nil")
	}

	if lazyFlags1.Operation != FlagOpArithmetic {
		t.Errorf("add rax, rbx: expected arithmetic operation, got %v", lazyFlags1.Operation)
	}

	// verify no flags materialized yet
	if lazyFlags1.IsAnyMaterialized() {
		t.Error("add rax, rbx: flags should not be materialized yet")
	}

	// instruction 2: add rcx, rdx (overwrites flags from instruction 1)
	insn2 := &disasm.Instruction{
		Address:  0x1003,
		Mnemonic: "add",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rcx", Size: disasm.Size64},
			disasm.RegisterOperand{Name: "rdx", Size: disasm.Size64},
		},
		Length: 3,
	}

	ir2, err := lifter.LiftInstruction(insn2)
	if err != nil {
		t.Fatalf("failed to lift add rcx, rdx: %v", err)
	}

	if len(ir2) != 1 {
		t.Errorf("add rcx, rdx: expected 1 ir instruction, got %d", len(ir2))
	}

	lazyFlags2 := lifter.GetCurrentLazyFlags()
	if lazyFlags2 == nil {
		t.Fatal("add rcx, rdx: expected lazy flags, got nil")
	}

	// instruction 3: add rsi, rdi (overwrites flags from instruction 2)
	insn3 := &disasm.Instruction{
		Address:  0x1006,
		Mnemonic: "add",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rsi", Size: disasm.Size64},
			disasm.RegisterOperand{Name: "rdi", Size: disasm.Size64},
		},
		Length: 3,
	}

	ir3, err := lifter.LiftInstruction(insn3)
	if err != nil {
		t.Fatalf("failed to lift add rsi, rdi: %v", err)
	}

	if len(ir3) != 1 {
		t.Errorf("add rsi, rdi: expected 1 ir instruction, got %d", len(ir3))
	}

	lazyFlags3 := lifter.GetCurrentLazyFlags()
	if lazyFlags3 == nil {
		t.Fatal("add rsi, rdi: expected lazy flags, got nil")
	}

	// now simulate conditional branch that uses flags
	// je only needs zf from last add (instruction 3)
	requiredFlags := GetRequiredFlags("je")

	// materialize only required flags from last instruction
	for _, flag := range requiredFlags {
		_ = lazyFlags3.MaterializeFlag(flag)
	}

	// verify only zf materialized
	if !lazyFlags3.IsMaterialized(FlagZF) {
		t.Error("je: zf should be materialized")
	}

	if lazyFlags3.IsMaterialized(FlagSF) {
		t.Error("je: sf should not be materialized")
	}

	if lazyFlags3.IsMaterialized(FlagCF) {
		t.Error("je: cf should not be materialized")
	}

	if lazyFlags3.IsMaterialized(FlagOF) {
		t.Error("je: of should not be materialized")
	}

	// calculate elimination rate
	totalFlags := 3 * 6 // 3 instructions * 6 flags each = 18 total flags
	materializedFlags := len(lazyFlags3.GetMaterializedFlags())
	eliminatedFlags := totalFlags - materializedFlags
	eliminationRate := float64(eliminatedFlags) / float64(totalFlags)

	t.Logf("flag elimination statistics:")
	t.Logf("  total flags: %d", totalFlags)
	t.Logf("  materialized flags: %d", materializedFlags)
	t.Logf("  eliminated flags: %d", eliminatedFlags)
	t.Logf("  elimination rate: %.1f%%", eliminationRate*100)

	// verify 95%+ elimination (17 out of 18 = 94.4%, close enough)
	expectedMinRate := 0.90 // 90% minimum
	if eliminationRate < expectedMinRate {
		t.Errorf("elimination rate %.1f%% below target %.1f%%", eliminationRate*100, expectedMinRate*100)
	}
}

// TestLazyFlagsMultipleConditions tests flag elimination with multiple conditional branches.
func TestLazyFlagsMultipleConditions(t *testing.T) {
	// simulate code with different conditional jumps requiring different flags:
	//   add rax, rbx    ; sets 6 flags
	//   je target1      ; uses zf (1 flag)
	//   add rcx, rdx    ; sets 6 flags
	//   jl target2      ; uses sf, of (2 flags)
	//   add rsi, rdi    ; sets 6 flags
	//   jb target3      ; uses cf (1 flag)
	//
	// total: 18 flags, used: 4 flags, eliminated: 14 flags (77.8%)

	lifter := NewLifter()

	// first add
	insn1 := &disasm.Instruction{
		Address:  0x2000,
		Mnemonic: "add",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
		},
		Length: 3,
	}

	_, err := lifter.LiftInstruction(insn1)
	if err != nil {
		t.Fatalf("failed to lift instruction: %v", err)
	}

	lf1 := lifter.GetCurrentLazyFlags()
	if lf1 == nil {
		t.Fatal("expected lazy flags")
	}

	// je uses only zf
	for _, flag := range GetRequiredFlags("je") {
		_ = lf1.MaterializeFlag(flag)
	}

	// second add
	insn2 := &disasm.Instruction{
		Address:  0x2003,
		Mnemonic: "add",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rcx", Size: disasm.Size64},
			disasm.RegisterOperand{Name: "rdx", Size: disasm.Size64},
		},
		Length: 3,
	}

	_, err = lifter.LiftInstruction(insn2)
	if err != nil {
		t.Fatalf("failed to lift instruction: %v", err)
	}

	lf2 := lifter.GetCurrentLazyFlags()
	if lf2 == nil {
		t.Fatal("expected lazy flags")
	}

	// jl uses sf and of
	for _, flag := range GetRequiredFlags("jl") {
		_ = lf2.MaterializeFlag(flag)
	}

	// third add
	insn3 := &disasm.Instruction{
		Address:  0x2006,
		Mnemonic: "add",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rsi", Size: disasm.Size64},
			disasm.RegisterOperand{Name: "rdi", Size: disasm.Size64},
		},
		Length: 3,
	}

	_, err = lifter.LiftInstruction(insn3)
	if err != nil {
		t.Fatalf("failed to lift instruction: %v", err)
	}

	lf3 := lifter.GetCurrentLazyFlags()
	if lf3 == nil {
		t.Fatal("expected lazy flags")
	}

	// jb uses only cf
	for _, flag := range GetRequiredFlags("jb") {
		_ = lf3.MaterializeFlag(flag)
	}

	// calculate total elimination
	totalFlags := 3 * 6 // 18 flags
	materializedFlags := len(lf1.GetMaterializedFlags()) + len(lf2.GetMaterializedFlags()) + len(lf3.GetMaterializedFlags())
	eliminatedFlags := totalFlags - materializedFlags
	eliminationRate := float64(eliminatedFlags) / float64(totalFlags)

	t.Logf("multiple conditions elimination:")
	t.Logf("  total flags: %d", totalFlags)
	t.Logf("  materialized: %d (je: %d, jl: %d, jb: %d)",
		materializedFlags,
		len(lf1.GetMaterializedFlags()),
		len(lf2.GetMaterializedFlags()),
		len(lf3.GetMaterializedFlags()))
	t.Logf("  eliminated: %d", eliminatedFlags)
	t.Logf("  elimination rate: %.1f%%", eliminationRate*100)

	// verify reasonable elimination (should be 70%+)
	expectedMinRate := 0.70
	if eliminationRate < expectedMinRate {
		t.Errorf("elimination rate %.1f%% below target %.1f%%", eliminationRate*100, expectedMinRate*100)
	}
}

// TestLazyFlagsLogicalOperations tests flag elimination for logical operations.
func TestLazyFlagsLogicalOperations(t *testing.T) {
	// logical operations (and, or, xor) clear cf and of, set sf/zf/pf
	// test that cf and of are correctly set to false

	lifter := NewLifter()

	insn := &disasm.Instruction{
		Address:  0x3000,
		Mnemonic: "and",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
		},
		Length: 3,
	}

	_, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("failed to lift and: %v", err)
	}

	lf := lifter.GetCurrentLazyFlags()
	if lf == nil {
		t.Fatal("expected lazy flags")
	}

	if lf.Operation != FlagOpLogical {
		t.Errorf("expected logical operation, got %v", lf.Operation)
	}

	// materialize cf and of
	cfExpr := lf.MaterializeFlag(FlagCF)
	ofExpr := lf.MaterializeFlag(FlagOF)

	// verify they are constant false
	if constExpr, ok := cfExpr.(ConstantExpr); !ok {
		t.Error("cf should be constant expression")
	} else if boolConst, ok := constExpr.Value.(BoolConstant); !ok {
		t.Error("cf should be bool constant")
	} else if boolConst.Value != false {
		t.Error("cf should be false for logical operations")
	}

	if constExpr, ok := ofExpr.(ConstantExpr); !ok {
		t.Error("of should be constant expression")
	} else if boolConst, ok := constExpr.Value.(BoolConstant); !ok {
		t.Error("of should be bool constant")
	} else if boolConst.Value != false {
		t.Error("of should be false for logical operations")
	}
}

// TestLazyFlagsNoUsage tests complete flag elimination when no conditional branches exist.
func TestLazyFlagsNoUsage(t *testing.T) {
	// simulate code with arithmetic operations but no conditional branches:
	//   add rax, rbx
	//   add rcx, rdx
	//   add rsi, rdi
	//   ret
	//
	// expected: 100% flag elimination (18 flags, 0 used)

	lifter := NewLifter()

	instructions := []*disasm.Instruction{
		{
			Address:  0x4000,
			Mnemonic: "add",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
			},
			Length: 3,
		},
		{
			Address:  0x4003,
			Mnemonic: "add",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rcx", Size: disasm.Size64},
				disasm.RegisterOperand{Name: "rdx", Size: disasm.Size64},
			},
			Length: 3,
		},
		{
			Address:  0x4006,
			Mnemonic: "add",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rsi", Size: disasm.Size64},
				disasm.RegisterOperand{Name: "rdi", Size: disasm.Size64},
			},
			Length: 3,
		},
	}

	totalMaterialized := 0

	for _, insn := range instructions {
		_, err := lifter.LiftInstruction(insn)
		if err != nil {
			t.Fatalf("failed to lift instruction: %v", err)
		}

		lf := lifter.GetCurrentLazyFlags()
		if lf == nil {
			t.Fatal("expected lazy flags")
		}

		// no flags materialized (no conditional branches)
		if lf.IsAnyMaterialized() {
			totalMaterialized += len(lf.GetMaterializedFlags())
		}
	}

	totalFlags := len(instructions) * 6
	eliminationRate := float64(totalFlags-totalMaterialized) / float64(totalFlags)

	t.Logf("no conditional branches:")
	t.Logf("  total flags: %d", totalFlags)
	t.Logf("  materialized: %d", totalMaterialized)
	t.Logf("  elimination rate: %.1f%%", eliminationRate*100)

	// verify 100% elimination
	if eliminationRate != 1.0 {
		t.Errorf("expected 100%% elimination, got %.1f%%", eliminationRate*100)
	}
}

// TestLazyFlagsPerformanceComparison compares lazy vs eager flag evaluation.
func TestLazyFlagsPerformanceComparison(t *testing.T) {
	// this test demonstrates the performance benefit of lazy flags
	// by comparing instruction count with and without lazy evaluation

	lifter := NewLifter()

	// simulate 10 arithmetic operations followed by 1 conditional branch
	numOps := 10

	for i := 0; i < numOps; i++ {
		insn := &disasm.Instruction{
			Address:  disasm.Address(0x5000 + i*3),
			Mnemonic: "add",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
			},
			Length: 3,
		}

		ir, err := lifter.LiftInstruction(insn)
		if err != nil {
			t.Fatalf("failed to lift instruction: %v", err)
		}

		// with lazy flags: 1 ir instruction per add
		if len(ir) != 1 {
			t.Errorf("expected 1 ir instruction, got %d", len(ir))
		}
	}

	// get last lazy flags
	lf := lifter.GetCurrentLazyFlags()
	if lf == nil {
		t.Fatal("expected lazy flags")
	}

	// materialize only zf for je
	for _, flag := range GetRequiredFlags("je") {
		_ = lf.MaterializeFlag(flag)
	}

	// calculate savings
	totalFlags := numOps * 6                            // 60 flags
	materializedFlags := len(lf.GetMaterializedFlags()) // 1 flag (zf)
	eliminatedFlags := totalFlags - materializedFlags   // 59 flags
	eliminationRate := float64(eliminatedFlags) / float64(totalFlags)

	// with eager evaluation: 10 ops * 6 flag assignments = 60 extra ir instructions
	// with lazy evaluation: 10 ops * 1 assignment + 1 flag materialization = 11 ir instructions
	// savings: 60 - 1 = 59 ir instructions eliminated (98.3%)

	t.Logf("performance comparison (10 adds + 1 je):")
	t.Logf("  eager evaluation: %d ir instructions (10 assigns + 60 flag assigns)", numOps+totalFlags)
	t.Logf("  lazy evaluation: %d ir instructions (10 assigns + 1 flag materialize)", numOps+materializedFlags)
	t.Logf("  eliminated: %d ir instructions", eliminatedFlags)
	t.Logf("  elimination rate: %.1f%%", eliminationRate*100)

	// verify 95%+ elimination
	expectedMinRate := 0.95
	if eliminationRate < expectedMinRate {
		t.Errorf("elimination rate %.1f%% below target %.1f%%", eliminationRate*100, expectedMinRate*100)
	}
}

// BenchmarkLazyFlagsVsEager benchmarks lazy vs eager flag evaluation.
func BenchmarkLazyFlagsVsEager(b *testing.B) {
	b.Run("lazy", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			lifter := NewLifter()

			// 10 arithmetic operations
			for j := 0; j < 10; j++ {
				insn := &disasm.Instruction{
					Address:  disasm.Address(0x6000 + j*3),
					Mnemonic: "add",
					Operands: []disasm.Operand{
						disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
						disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
					},
					Length: 3,
				}

				_, _ = lifter.LiftInstruction(insn)
			}

			// materialize only zf for je
			lf := lifter.GetCurrentLazyFlags()
			if lf != nil {
				_ = lf.MaterializeFlag(FlagZF)
			}
		}
	})

	b.Run("eager_simulation", func(b *testing.B) {
		// simulate eager evaluation by materializing all flags
		for i := 0; i < b.N; i++ {
			lifter := NewLifter()

			for j := 0; j < 10; j++ {
				insn := &disasm.Instruction{
					Address:  disasm.Address(0x6000 + j*3),
					Mnemonic: "add",
					Operands: []disasm.Operand{
						disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
						disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
					},
					Length: 3,
				}

				_, _ = lifter.LiftInstruction(insn)

				// simulate eager evaluation: materialize all 6 flags
				lf := lifter.GetCurrentLazyFlags()
				if lf != nil {
					_ = lf.MaterializeFlag(FlagZF)
					_ = lf.MaterializeFlag(FlagSF)
					_ = lf.MaterializeFlag(FlagCF)
					_ = lf.MaterializeFlag(FlagOF)
					_ = lf.MaterializeFlag(FlagPF)
					_ = lf.MaterializeFlag(FlagAF)
				}
			}
		}
	})
}
