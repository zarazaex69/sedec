package disasm

import (
	"testing"
)

// TestNewDisassembler verifies disassembler initialization
func TestNewDisassembler(t *testing.T) {
	d, err := NewDisassembler()
	if err != nil {
		t.Fatalf("failed to create disassembler: %v", err)
	}
	defer d.Close()

	if d.engine == nil {
		t.Fatal("engine is nil after initialization")
	}
}

// TestDisassemble_ValidInstructions tests disassembly of valid x86_64 instructions
func TestDisassemble_ValidInstructions(t *testing.T) {
	d, err := NewDisassembler()
	if err != nil {
		t.Fatalf("failed to create disassembler: %v", err)
	}
	defer d.Close()

	tests := []struct {
		name     string
		bytes    []byte
		address  Address
		mnemonic string
		length   int
	}{
		{
			name:     "mov rax, rbx",
			bytes:    []byte{0x48, 0x89, 0xd8},
			address:  0x1000,
			mnemonic: "mov",
			length:   3,
		},
		{
			name:     "add rax, 0x42",
			bytes:    []byte{0x48, 0x83, 0xc0, 0x42},
			address:  0x2000,
			mnemonic: "add",
			length:   4,
		},
		{
			name:     "push rbp",
			bytes:    []byte{0x55},
			address:  0x3000,
			mnemonic: "push",
			length:   1,
		},
		{
			name:     "ret",
			bytes:    []byte{0xc3},
			address:  0x4000,
			mnemonic: "ret",
			length:   1,
		},
		{
			name:     "call relative",
			bytes:    []byte{0xe8, 0x00, 0x00, 0x00, 0x00},
			address:  0x5000,
			mnemonic: "call",
			length:   5,
		},
		{
			name:     "jmp relative",
			bytes:    []byte{0xe9, 0x00, 0x00, 0x00, 0x00},
			address:  0x6000,
			mnemonic: "jmp",
			length:   5,
		},
		{
			name:     "je relative",
			bytes:    []byte{0x74, 0x10},
			address:  0x7000,
			mnemonic: "je",
			length:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insn, err := d.Disassemble(tt.bytes, tt.address)
			if err != nil {
				t.Fatalf("disassemble failed: %v", err)
			}

			if insn.Address != tt.address {
				t.Errorf("address mismatch: got 0x%x, want 0x%x", insn.Address, tt.address)
			}

			if insn.Mnemonic != tt.mnemonic {
				t.Errorf("mnemonic mismatch: got %q, want %q", insn.Mnemonic, tt.mnemonic)
			}

			if insn.Length != tt.length {
				t.Errorf("length mismatch: got %d, want %d", insn.Length, tt.length)
			}

			if len(insn.Bytes) != tt.length {
				t.Errorf("bytes length mismatch: got %d, want %d", len(insn.Bytes), tt.length)
			}
		})
	}
}

// TestDisassemble_SSE_Instructions tests sse instruction support
func TestDisassemble_SSE_Instructions(t *testing.T) {
	d, err := NewDisassembler()
	if err != nil {
		t.Fatalf("failed to create disassembler: %v", err)
	}
	defer d.Close()

	tests := []struct {
		name     string
		bytes    []byte
		mnemonic string
	}{
		{
			name:     "movaps xmm0, xmm1",
			bytes:    []byte{0x0f, 0x28, 0xc1},
			mnemonic: "movaps",
		},
		{
			name:     "addps xmm0, xmm1",
			bytes:    []byte{0x0f, 0x58, 0xc1},
			mnemonic: "addps",
		},
		{
			name:     "mulps xmm0, xmm1",
			bytes:    []byte{0x0f, 0x59, 0xc1},
			mnemonic: "mulps",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insn, err := d.Disassemble(tt.bytes, 0x1000)
			if err != nil {
				t.Fatalf("disassemble failed: %v", err)
			}

			if insn.Mnemonic != tt.mnemonic {
				t.Errorf("mnemonic mismatch: got %q, want %q", insn.Mnemonic, tt.mnemonic)
			}
		})
	}
}

// TestDisassemble_AVX_Instructions tests avx instruction support
func TestDisassemble_AVX_Instructions(t *testing.T) {
	d, err := NewDisassembler()
	if err != nil {
		t.Fatalf("failed to create disassembler: %v", err)
	}
	defer d.Close()

	tests := []struct {
		name     string
		bytes    []byte
		mnemonic string
	}{
		{
			name:     "vmovaps ymm0, ymm1",
			bytes:    []byte{0xc5, 0xfc, 0x28, 0xc1},
			mnemonic: "vmovaps",
		},
		{
			name:     "vaddps ymm0, ymm1, ymm2",
			bytes:    []byte{0xc5, 0xf4, 0x58, 0xc2},
			mnemonic: "vaddps",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insn, err := d.Disassemble(tt.bytes, 0x1000)
			if err != nil {
				t.Fatalf("disassemble failed: %v", err)
			}

			if insn.Mnemonic != tt.mnemonic {
				t.Errorf("mnemonic mismatch: got %q, want %q", insn.Mnemonic, tt.mnemonic)
			}
		})
	}
}

// TestDisassemble_AVX512_Instructions tests avx-512 instruction support
func TestDisassemble_AVX512_Instructions(t *testing.T) {
	d, err := NewDisassembler()
	if err != nil {
		t.Fatalf("failed to create disassembler: %v", err)
	}
	defer d.Close()

	tests := []struct {
		name     string
		bytes    []byte
		mnemonic string
	}{
		{
			name:     "vmovaps zmm0, zmm1",
			bytes:    []byte{0x62, 0xf1, 0x7c, 0x48, 0x28, 0xc1},
			mnemonic: "vmovaps",
		},
		{
			name:     "vaddps zmm0, zmm1, zmm2",
			bytes:    []byte{0x62, 0xf1, 0x74, 0x48, 0x58, 0xc2},
			mnemonic: "vaddps",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insn, err := d.Disassemble(tt.bytes, 0x1000)
			if err != nil {
				t.Fatalf("disassemble failed: %v", err)
			}

			if insn.Mnemonic != tt.mnemonic {
				t.Errorf("mnemonic mismatch: got %q, want %q", insn.Mnemonic, tt.mnemonic)
			}
		})
	}
}

// TestDisassemble_InvalidOpcode tests handling of invalid opcodes
func TestDisassemble_InvalidOpcode(t *testing.T) {
	d, err := NewDisassembler()
	if err != nil {
		t.Fatalf("failed to create disassembler: %v", err)
	}
	defer d.Close()

	// invalid opcode sequence
	invalidBytes := []byte{0xff, 0xff, 0xff, 0xff}
	_, err = d.Disassemble(invalidBytes, 0x1000)

	if err == nil {
		t.Fatal("expected error for invalid opcode, got nil")
	}

	// verify error type
	if _, ok := err.(ErrInvalidOpcode); !ok {
		t.Errorf("expected ErrInvalidOpcode, got %T", err)
	}
}

// TestDisassemble_InsufficientBytes tests handling of insufficient bytes
func TestDisassemble_InsufficientBytes(t *testing.T) {
	d, err := NewDisassembler()
	if err != nil {
		t.Fatalf("failed to create disassembler: %v", err)
	}
	defer d.Close()

	// empty byte slice
	_, err = d.Disassemble([]byte{}, 0x1000)

	if err == nil {
		t.Fatal("expected error for empty bytes, got nil")
	}

	// verify error type
	if _, ok := err.(ErrInsufficientBytes); !ok {
		t.Errorf("expected ErrInsufficientBytes, got %T", err)
	}
}

// TestDisassembleBytes_MixedValidInvalid tests continued disassembly with invalid opcodes
func TestDisassembleBytes_MixedValidInvalid(t *testing.T) {
	d, err := NewDisassembler()
	if err != nil {
		t.Fatalf("failed to create disassembler: %v", err)
	}
	defer d.Close()

	// mix of valid and invalid bytes
	// 0x90 = nop, 0xff 0xff = invalid, 0x90 = nop
	bytes := []byte{0x90, 0xff, 0xff, 0x90}

	insns, err := d.DisassembleBytes(bytes, 0x1000)
	if err != nil {
		t.Fatalf("disassemble bytes failed: %v", err)
	}

	// should have decoded the two nop instructions
	if len(insns) < 2 {
		t.Errorf("expected at least 2 instructions, got %d", len(insns))
	}

	// verify first instruction is nop
	if insns[0].Mnemonic != "nop" {
		t.Errorf("first instruction mnemonic: got %q, want %q", insns[0].Mnemonic, "nop")
	}

	// verify last instruction is nop
	lastIdx := len(insns) - 1
	if insns[lastIdx].Mnemonic != "nop" {
		t.Errorf("last instruction mnemonic: got %q, want %q", insns[lastIdx].Mnemonic, "nop")
	}
}

// TestDisassembleFunction_CompleteFunction tests disassembly of complete function
func TestDisassembleFunction_CompleteFunction(t *testing.T) {
	d, err := NewDisassembler()
	if err != nil {
		t.Fatalf("failed to create disassembler: %v", err)
	}
	defer d.Close()

	// simple function: push rbp; mov rbp, rsp; pop rbp; ret
	funcBytes := []byte{
		0x55,             // push rbp
		0x48, 0x89, 0xe5, // mov rbp, rsp
		0x5d, // pop rbp
		0xc3, // ret
	}

	insns, err := d.DisassembleFunction(funcBytes, 0x1000)
	if err != nil {
		t.Fatalf("disassemble function failed: %v", err)
	}

	if len(insns) != 4 {
		t.Fatalf("expected 4 instructions, got %d", len(insns))
	}

	expectedMnemonics := []string{"push", "mov", "pop", "ret"}
	for i, expected := range expectedMnemonics {
		if insns[i].Mnemonic != expected {
			t.Errorf("instruction %d mnemonic: got %q, want %q", i, insns[i].Mnemonic, expected)
		}
	}
}

// TestDisassemble_OperandExtraction tests operand extraction
func TestDisassemble_OperandExtraction(t *testing.T) {
	d, err := NewDisassembler()
	if err != nil {
		t.Fatalf("failed to create disassembler: %v", err)
	}
	defer d.Close()

	tests := []struct {
		name          string
		bytes         []byte
		operandCount  int
		firstOperand  string
		secondOperand string
	}{
		{
			name:          "mov rax, rbx",
			bytes:         []byte{0x48, 0x89, 0xd8},
			operandCount:  2,
			firstOperand:  "rax",
			secondOperand: "rbx",
		},
		{
			name:          "add rax, 0x10",
			bytes:         []byte{0x48, 0x83, 0xc0, 0x10},
			operandCount:  2,
			firstOperand:  "rax",
			secondOperand: "0x10",
		},
		{
			name:         "push rbp",
			bytes:        []byte{0x55},
			operandCount: 1,
			firstOperand: "rbp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insn, err := d.Disassemble(tt.bytes, 0x1000)
			if err != nil {
				t.Fatalf("disassemble failed: %v", err)
			}

			if len(insn.Operands) != tt.operandCount {
				t.Errorf("operand count: got %d, want %d", len(insn.Operands), tt.operandCount)
			}

			if len(insn.Operands) > 0 {
				firstOp := insn.Operands[0].String()
				if firstOp != tt.firstOperand {
					t.Errorf("first operand: got %q, want %q", firstOp, tt.firstOperand)
				}
			}

			if len(insn.Operands) > 1 && tt.secondOperand != "" {
				secondOp := insn.Operands[1].String()
				if secondOp != tt.secondOperand {
					t.Errorf("second operand: got %q, want %q", secondOp, tt.secondOperand)
				}
			}
		})
	}
}

// TestDisassemble_MemoryOperands tests memory operand extraction
func TestDisassemble_MemoryOperands(t *testing.T) {
	d, err := NewDisassembler()
	if err != nil {
		t.Fatalf("failed to create disassembler: %v", err)
	}
	defer d.Close()

	tests := []struct {
		name  string
		bytes []byte
	}{
		{
			name:  "mov rax, [rbx]",
			bytes: []byte{0x48, 0x8b, 0x03},
		},
		{
			name:  "mov rax, [rbx + 0x10]",
			bytes: []byte{0x48, 0x8b, 0x43, 0x10},
		},
		{
			name:  "mov rax, [rbx + rcx*4]",
			bytes: []byte{0x48, 0x8b, 0x04, 0x8b},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insn, err := d.Disassemble(tt.bytes, 0x1000)
			if err != nil {
				t.Fatalf("disassemble failed: %v", err)
			}

			if len(insn.Operands) < 2 {
				t.Fatalf("expected at least 2 operands, got %d", len(insn.Operands))
			}

			// second operand should be memory operand
			if _, ok := insn.Operands[1].(MemoryOperand); !ok {
				t.Errorf("second operand is not MemoryOperand, got %T", insn.Operands[1])
			}
		})
	}
}

// TestDisassemble_InstructionBoundaries tests accurate instruction boundary detection
func TestDisassemble_InstructionBoundaries(t *testing.T) {
	d, err := NewDisassembler()
	if err != nil {
		t.Fatalf("failed to create disassembler: %v", err)
	}
	defer d.Close()

	// sequence of instructions with varying lengths
	bytes := []byte{
		0x90,             // nop (1 byte)
		0x48, 0x89, 0xc3, // mov rbx, rax (3 bytes)
		0x48, 0x83, 0xc0, 0x01, // add rax, 1 (4 bytes)
		0xc3, // ret (1 byte)
	}

	insns, err := d.DisassembleBytes(bytes, 0x1000)
	if err != nil {
		t.Fatalf("disassemble bytes failed: %v", err)
	}

	if len(insns) != 4 {
		t.Fatalf("expected 4 instructions, got %d", len(insns))
	}

	// verify addresses are sequential
	expectedAddresses := []Address{0x1000, 0x1001, 0x1004, 0x1008}
	for i, expected := range expectedAddresses {
		if insns[i].Address != expected {
			t.Errorf("instruction %d address: got 0x%x, want 0x%x", i, insns[i].Address, expected)
		}
	}

	// verify lengths
	expectedLengths := []int{1, 3, 4, 1}
	for i, expected := range expectedLengths {
		if insns[i].Length != expected {
			t.Errorf("instruction %d length: got %d, want %d", i, insns[i].Length, expected)
		}
	}
}

// TestDisassemble_AllOperandTypes tests all operand type extraction
func TestDisassemble_AllOperandTypes(t *testing.T) {
	d, err := NewDisassembler()
	if err != nil {
		t.Fatalf("failed to create disassembler: %v", err)
	}
	defer d.Close()

	// register operand
	insn, err := d.Disassemble([]byte{0x48, 0x89, 0xd8}, 0x1000) // mov rax, rbx
	if err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}
	if _, ok := insn.Operands[0].(RegisterOperand); !ok {
		t.Errorf("expected RegisterOperand, got %T", insn.Operands[0])
	}

	// immediate operand
	insn, err = d.Disassemble([]byte{0x48, 0xc7, 0xc0, 0x2a, 0x00, 0x00, 0x00}, 0x1000) // mov rax, 0x2a
	if err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}
	if _, ok := insn.Operands[1].(ImmediateOperand); !ok {
		t.Errorf("expected ImmediateOperand, got %T", insn.Operands[1])
	}

	// memory operand
	insn, err = d.Disassemble([]byte{0x48, 0x8b, 0x03}, 0x1000) // mov rax, [rbx]
	if err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}
	if _, ok := insn.Operands[1].(MemoryOperand); !ok {
		t.Errorf("expected MemoryOperand, got %T", insn.Operands[1])
	}
}

// TestDisassemble_Performance tests disassembly performance
func TestDisassemble_Performance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	d, err := NewDisassembler()
	if err != nil {
		t.Fatalf("failed to create disassembler: %v", err)
	}
	defer d.Close()

	// generate 1000 nop instructions
	bytes := make([]byte, 1000)
	for i := range bytes {
		bytes[i] = 0x90 // nop
	}

	insns, err := d.DisassembleFunction(bytes, 0x1000)
	if err != nil {
		t.Fatalf("disassemble function failed: %v", err)
	}

	if len(insns) != 1000 {
		t.Errorf("expected 1000 instructions, got %d", len(insns))
	}
}

// BenchmarkDisassemble benchmarks single instruction disassembly
func BenchmarkDisassemble(b *testing.B) {
	d, err := NewDisassembler()
	if err != nil {
		b.Fatalf("failed to create disassembler: %v", err)
	}
	defer d.Close()

	bytes := []byte{0x48, 0x89, 0xd8} // mov rax, rbx

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := d.Disassemble(bytes, 0x1000)
		if err != nil {
			b.Fatalf("disassemble failed: %v", err)
		}
	}
}

// BenchmarkDisassembleFunction benchmarks function disassembly
func BenchmarkDisassembleFunction(b *testing.B) {
	d, err := NewDisassembler()
	if err != nil {
		b.Fatalf("failed to create disassembler: %v", err)
	}
	defer d.Close()

	// simple function with 100 nop instructions
	bytes := make([]byte, 100)
	for i := range bytes {
		bytes[i] = 0x90
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := d.DisassembleFunction(bytes, 0x1000)
		if err != nil {
			b.Fatalf("disassemble function failed: %v", err)
		}
	}
}
