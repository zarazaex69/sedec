package cfg

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// BenchmarkComputeDominators_Small benchmarks dominator computation for small cfg (< 100 blocks)
func BenchmarkComputeDominators_Small(b *testing.B) {
	// create cfg with ~50 blocks (nested loops)
	instructions := make([]*disasm.Instruction, 0, 200)
	addr := disasm.Address(0x1000)

	// outer loop
	for i := 0; i < 10; i++ {
		instructions = append(instructions, &disasm.Instruction{
			Address:  addr,
			Mnemonic: "cmp",
			Length:   3,
		})
		addr += 3

		instructions = append(instructions, &disasm.Instruction{
			Address:  addr,
			Mnemonic: "jge",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: int64(addr + 100), Size: disasm.Size32},
			},
		})
		addr += 2

		// inner loop
		for j := 0; j < 3; j++ {
			instructions = append(instructions, &disasm.Instruction{
				Address:  addr,
				Mnemonic: "add",
				Length:   3,
			})
			addr += 3
		}

		instructions = append(instructions, &disasm.Instruction{
			Address:  addr,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: int64(addr - 20), Size: disasm.Size32},
			},
		})
		addr += 2
	}

	instructions = append(instructions, &disasm.Instruction{
		Address:  addr,
		Mnemonic: "ret",
		Length:   1,
	})

	builder := NewCFGBuilder()
	_, err := builder.Build(instructions)
	if err != nil {
		b.Fatalf("failed to build cfg: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, computeErr := builder.ComputeDominators()
		if computeErr != nil {
			b.Fatalf("failed to compute dominators: %v", computeErr)
		}
	}
}

// BenchmarkComputeDominators_Medium benchmarks dominator computation for medium cfg (< 500 blocks)
func BenchmarkComputeDominators_Medium(b *testing.B) {
	// create cfg with ~300 blocks
	instructions := make([]*disasm.Instruction, 0, 1000)
	addr := disasm.Address(0x1000)

	// create complex nested structure
	for i := 0; i < 50; i++ {
		instructions = append(instructions, &disasm.Instruction{
			Address:  addr,
			Mnemonic: "cmp",
			Length:   3,
		})
		addr += 3

		instructions = append(instructions, &disasm.Instruction{
			Address:  addr,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: int64(addr + 20), Size: disasm.Size32},
			},
		})
		addr += 2

		// then branch
		for j := 0; j < 3; j++ {
			instructions = append(instructions, &disasm.Instruction{
				Address:  addr,
				Mnemonic: "mov",
				Length:   3,
			})
			addr += 3
		}

		instructions = append(instructions, &disasm.Instruction{
			Address:  addr,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: int64(addr + 15), Size: disasm.Size32},
			},
		})
		addr += 2

		// else branch
		for j := 0; j < 3; j++ {
			instructions = append(instructions, &disasm.Instruction{
				Address:  addr,
				Mnemonic: "add",
				Length:   3,
			})
			addr += 3
		}
	}

	instructions = append(instructions, &disasm.Instruction{
		Address:  addr,
		Mnemonic: "ret",
		Length:   1,
	})

	builder := NewCFGBuilder()
	_, err := builder.Build(instructions)
	if err != nil {
		b.Fatalf("failed to build cfg: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, computeErr := builder.ComputeDominators()
		if computeErr != nil {
			b.Fatalf("failed to compute dominators: %v", computeErr)
		}
	}
}

// BenchmarkComputeDominanceFrontiers benchmarks dominance frontier computation
func BenchmarkComputeDominanceFrontiers(b *testing.B) {
	// create cfg with multiple merge points
	instructions := make([]*disasm.Instruction, 0, 500)
	addr := disasm.Address(0x1000)

	for i := 0; i < 30; i++ {
		instructions = append(instructions, &disasm.Instruction{
			Address:  addr,
			Mnemonic: "cmp",
			Length:   3,
		})
		addr += 3

		instructions = append(instructions, &disasm.Instruction{
			Address:  addr,
			Mnemonic: "je",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: int64(addr + 15), Size: disasm.Size32},
			},
		})
		addr += 2

		instructions = append(instructions, &disasm.Instruction{
			Address:  addr,
			Mnemonic: "mov",
			Length:   3,
		})
		addr += 3

		instructions = append(instructions, &disasm.Instruction{
			Address:  addr,
			Mnemonic: "jmp",
			Length:   2,
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: int64(addr + 10), Size: disasm.Size32},
			},
		})
		addr += 2

		instructions = append(instructions, &disasm.Instruction{
			Address:  addr,
			Mnemonic: "add",
			Length:   3,
		})
		addr += 3
	}

	instructions = append(instructions, &disasm.Instruction{
		Address:  addr,
		Mnemonic: "ret",
		Length:   1,
	})

	builder := NewCFGBuilder()
	_, err := builder.Build(instructions)
	if err != nil {
		b.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		b.Fatalf("failed to compute dominators: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dt.ComputeDominanceFrontiers()
	}
}

// BenchmarkDominates benchmarks dominance query
func BenchmarkDominates(b *testing.B) {
	// create linear cfg for simple dominance queries
	instructions := make([]*disasm.Instruction, 0, 100)
	addr := disasm.Address(0x1000)

	for i := 0; i < 50; i++ {
		instructions = append(instructions, &disasm.Instruction{
			Address:  addr,
			Mnemonic: "mov",
			Length:   3,
		})
		addr += 3
	}

	instructions = append(instructions, &disasm.Instruction{
		Address:  addr,
		Mnemonic: "ret",
		Length:   1,
	})

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		b.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		b.Fatalf("failed to compute dominators: %v", err)
	}

	// get two blocks for testing
	var block1, block2 BlockID
	count := 0
	for id := range cfg.Blocks {
		if count == 0 {
			block1 = id
		} else if count == 10 {
			block2 = id
			break
		}
		count++
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dt.Dominates(block1, block2)
	}
}

// BenchmarkGetDominatorPath benchmarks dominator path extraction
func BenchmarkGetDominatorPath(b *testing.B) {
	// create deep dominator tree
	instructions := make([]*disasm.Instruction, 0, 200)
	addr := disasm.Address(0x1000)

	for i := 0; i < 100; i++ {
		instructions = append(instructions, &disasm.Instruction{
			Address:  addr,
			Mnemonic: "mov",
			Length:   3,
		})
		addr += 3
	}

	instructions = append(instructions, &disasm.Instruction{
		Address:  addr,
		Mnemonic: "ret",
		Length:   1,
	})

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		b.Fatalf("failed to build cfg: %v", err)
	}

	dt, err := builder.ComputeDominators()
	if err != nil {
		b.Fatalf("failed to compute dominators: %v", err)
	}

	// get last block for deepest path
	var lastBlock BlockID
	for id := range cfg.Blocks {
		lastBlock = id
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dt.GetDominatorPath(lastBlock)
	}
}
