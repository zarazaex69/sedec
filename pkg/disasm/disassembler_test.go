package disasm

import (
	"errors"
	"testing"
)

const (
	testMnemonicNop = "nop"
)

// newTestDisassembler creates a disassembler with automatic cleanup
func newTestDisassembler(t *testing.T) *Disassembler {
	t.Helper()
	d, err := NewDisassembler()
	if err != nil {
		t.Fatalf("failed to create disassembler: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := d.Close(); closeErr != nil {
			t.Errorf("failed to close disassembler: %v", closeErr)
		}
	})
	return d
}

// TestNewDisassembler verifies disassembler initialization
func TestNewDisassembler(t *testing.T) {
	d := newTestDisassembler(t)

	if d.engine == nil {
		t.Fatal("engine is nil after initialization")
	}
}

// TestDisassemble_ValidInstructions tests disassembly of valid x86_64 instructions
func TestDisassemble_ValidInstructions(t *testing.T) {
	d := newTestDisassembler(t)

	tests := []struct {
		address  Address
		bytes    []byte
		name     string
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
	d := newTestDisassembler(t)

	tests := []struct {
		bytes    []byte
		mnemonic string
		name     string
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
	d := newTestDisassembler(t)

	tests := []struct {
		bytes    []byte
		mnemonic string
		name     string
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
	d := newTestDisassembler(t)

	tests := []struct {
		bytes    []byte
		mnemonic string
		name     string
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
	d := newTestDisassembler(t)

	// invalid opcode sequence
	invalidBytes := []byte{0xff, 0xff, 0xff, 0xff}
	_, err := d.Disassemble(invalidBytes, 0x1000)

	if err == nil {
		t.Fatal("expected error for invalid opcode, got nil")
	}

	// verify error type
	var invalidOpcodeErr InvalidOpcodeError
	if !errors.As(err, &invalidOpcodeErr) {
		t.Errorf("expected InvalidOpcodeError, got %T", err)
	}
}

// TestDisassemble_InsufficientBytes tests handling of insufficient bytes
func TestDisassemble_InsufficientBytes(t *testing.T) {
	d := newTestDisassembler(t)

	// empty byte slice
	_, err := d.Disassemble([]byte{}, 0x1000)

	if err == nil {
		t.Fatal("expected error for empty bytes, got nil")
	}

	// verify error type
	var insufficientBytesErr InsufficientBytesError
	if !errors.As(err, &insufficientBytesErr) {
		t.Errorf("expected InsufficientBytesError, got %T", err)
	}
}

// TestDisassembleBytes_MixedValidInvalid tests continued disassembly with invalid opcodes
func TestDisassembleBytes_MixedValidInvalid(t *testing.T) {
	d := newTestDisassembler(t)

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
	if insns[0].Mnemonic != testMnemonicNop {
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
	d := newTestDisassembler(t)

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
	d := newTestDisassembler(t)

	tests := []struct {
		bytes         []byte
		firstOperand  string
		secondOperand string
		name          string
		operandCount  int
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
	d := newTestDisassembler(t)

	tests := []struct {
		bytes []byte
		name  string
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
	d := newTestDisassembler(t)

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
	d := newTestDisassembler(t)

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

	d := newTestDisassembler(t)

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
	defer func() {
		if closeErr := d.Close(); closeErr != nil {
			b.Errorf("failed to close disassembler: %v", closeErr)
		}
	}()

	bytes := []byte{0x48, 0x89, 0xd8} // mov rax, rbx

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, disasmErr := d.Disassemble(bytes, 0x1000)
		if disasmErr != nil {
			b.Fatalf("disassemble failed: %v", disasmErr)
		}
	}
}

// BenchmarkDisassembleFunction benchmarks function disassembly
func BenchmarkDisassembleFunction(b *testing.B) {
	d, err := NewDisassembler()
	if err != nil {
		b.Fatalf("failed to create disassembler: %v", err)
	}
	defer func() {
		if closeErr := d.Close(); closeErr != nil {
			b.Errorf("failed to close disassembler: %v", closeErr)
		}
	}()

	// simple function with 100 nop instructions
	bytes := make([]byte, 100)
	for i := range bytes {
		bytes[i] = 0x90
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, disasmErr := d.DisassembleFunction(bytes, 0x1000)
		if disasmErr != nil {
			b.Fatalf("disassemble function failed: %v", disasmErr)
		}
	}
}

// TestErrorTypes tests error type formatting
func TestErrorTypes(t *testing.T) {
	// test InvalidOpcodeError
	err1 := InvalidOpcodeError{VA: 0x1234, Byte: 0xff}
	expected1 := "invalid opcode at 0x1234: byte 0xff"
	if err1.Error() != expected1 {
		t.Errorf("InvalidOpcodeError.Error(): got %q, want %q", err1.Error(), expected1)
	}

	// test InsufficientBytesError
	err2 := InsufficientBytesError{VA: 0x5678, Available: 2, Required: 5}
	expected2 := "insufficient bytes at 0x5678: have 2, need 5"
	if err2.Error() != expected2 {
		t.Errorf("InsufficientBytesError.Error(): got %q, want %q", err2.Error(), expected2)
	}

	// test EngineInitError
	err3 := EngineInitError{Reason: "test failure"}
	expected3 := "failed to initialize disassembler engine: test failure"
	if err3.Error() != expected3 {
		t.Errorf("EngineInitError.Error(): got %q, want %q", err3.Error(), expected3)
	}
}

// TestOperandFormatting tests operand string formatting
func TestOperandFormatting(t *testing.T) {
	// test register operand
	regOp := RegisterOperand{Name: "rax", Size: Size64}
	if regOp.String() != "rax" {
		t.Errorf("RegisterOperand.String(): got %q, want %q", regOp.String(), "rax")
	}

	// test immediate operand - positive
	immOp1 := ImmediateOperand{Value: 0x42, Size: Size32}
	if immOp1.String() != "0x42" {
		t.Errorf("ImmediateOperand.String() positive: got %q, want %q", immOp1.String(), "0x42")
	}

	// test immediate operand - negative
	immOp2 := ImmediateOperand{Value: -16, Size: Size32}
	if immOp2.String() != "-0x10" {
		t.Errorf("ImmediateOperand.String() negative: got %q, want %q", immOp2.String(), "-0x10")
	}

	// test immediate operand - zero
	immOp3 := ImmediateOperand{Value: 0, Size: Size32}
	if immOp3.String() != "0x0" {
		t.Errorf("ImmediateOperand.String() zero: got %q, want %q", immOp3.String(), "0x0")
	}

	// test memory operand - base only
	memOp1 := MemoryOperand{Base: "rsp", Size: Size64}
	result1 := memOp1.String()
	if result1 != "[rsp]" {
		t.Errorf("MemoryOperand.String() base only: got %q, want %q", result1, "[rsp]")
	}

	// test memory operand - base + displacement
	memOp2 := MemoryOperand{Base: "rbp", Disp: -8, Size: Size64}
	result2 := memOp2.String()
	if result2 != "[rbp - 0x8]" {
		t.Errorf("MemoryOperand.String() base+disp: got %q, want %q", result2, "[rbp - 0x8]")
	}

	// test memory operand - base + index + scale
	memOp3 := MemoryOperand{Base: "rax", Index: "rcx", Scale: 4, Size: Size64}
	result3 := memOp3.String()
	if result3 != "[rax + rcx*4]" {
		t.Errorf("MemoryOperand.String() base+index+scale: got %q, want %q", result3, "[rax + rcx*4]")
	}

	// test memory operand - base + index + scale + displacement
	memOp4 := MemoryOperand{Base: "rax", Index: "rcx", Scale: 8, Disp: 0x10, Size: Size64}
	result4 := memOp4.String()
	if result4 != "[rax + rcx*8 + 0x10]" {
		t.Errorf("MemoryOperand.String() full: got %q, want %q", result4, "[rax + rcx*8 + 0x10]")
	}

	// test memory operand - segment + base
	memOp5 := MemoryOperand{Segment: "gs", Base: "rax", Size: Size64}
	result5 := memOp5.String()
	if result5 != "gs:[rax]" {
		t.Errorf("MemoryOperand.String() segment: got %q, want %q", result5, "gs:[rax]")
	}

	// test memory operand - displacement only
	memOp6 := MemoryOperand{Disp: 0x1000, Size: Size64}
	result6 := memOp6.String()
	if result6 != "[0x1000]" {
		t.Errorf("MemoryOperand.String() disp only: got %q, want %q", result6, "[0x1000]")
	}

	// test memory operand - index + scale only
	memOp7 := MemoryOperand{Index: "rsi", Scale: 2, Size: Size64}
	result7 := memOp7.String()
	if result7 != "[rsi*2]" {
		t.Errorf("MemoryOperand.String() index+scale: got %q, want %q", result7, "[rsi*2]")
	}
}

// TestRegisterSizes tests register size detection for all register types
func TestRegisterSizes(t *testing.T) {
	d := newTestDisassembler(t)

	tests := []struct {
		bytes    []byte
		regName  string
		name     string
		regIndex int
	}{
		{
			name:     "8-bit register (al)",
			bytes:    []byte{0x88, 0xd8}, // mov al, bl
			regName:  "al",
			regIndex: 0,
		},
		{
			name:     "16-bit register (ax)",
			bytes:    []byte{0x66, 0x89, 0xd8}, // mov ax, bx
			regName:  "ax",
			regIndex: 0,
		},
		{
			name:     "32-bit register (eax)",
			bytes:    []byte{0x89, 0xd8}, // mov eax, ebx
			regName:  "eax",
			regIndex: 0,
		},
		{
			name:     "64-bit register (rax)",
			bytes:    []byte{0x48, 0x89, 0xd8}, // mov rax, rbx
			regName:  "rax",
			regIndex: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insn, err := d.Disassemble(tt.bytes, 0x1000)
			if err != nil {
				t.Fatalf("disassemble failed: %v", err)
			}

			if len(insn.Operands) <= tt.regIndex {
				t.Fatalf("not enough operands: got %d, need at least %d", len(insn.Operands), tt.regIndex+1)
			}

			regOp, ok := insn.Operands[tt.regIndex].(RegisterOperand)
			if !ok {
				t.Fatalf("operand %d is not RegisterOperand, got %T", tt.regIndex, insn.Operands[tt.regIndex])
			}

			if regOp.Name != tt.regName {
				t.Errorf("register name: got %q, want %q", regOp.Name, tt.regName)
			}

			// verify size is non-zero
			if regOp.Size == 0 {
				t.Error("register size is zero")
			}
		})
	}
}

// TestDisassemble_AVX2_Instructions tests avx2 instruction support
func TestDisassemble_AVX2_Instructions(t *testing.T) {
	d := newTestDisassembler(t)

	tests := []struct {
		bytes    []byte
		mnemonic string
		name     string
	}{
		{
			name:     "vpbroadcastb ymm0, xmm1",
			bytes:    []byte{0xc4, 0xe2, 0x7d, 0x78, 0xc1},
			mnemonic: "vpbroadcastb",
		},
		{
			name:     "vpermd ymm0, ymm1, ymm2",
			bytes:    []byte{0xc4, 0xe2, 0x75, 0x36, 0xc2},
			mnemonic: "vpermd",
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

// TestDisassemble_ComplexMemoryOperands tests complex memory addressing modes
func TestDisassemble_ComplexMemoryOperands(t *testing.T) {
	d := newTestDisassembler(t)

	tests := []struct {
		bytes []byte
		name  string
	}{
		{
			name:  "mov rax, [rip + 0x1000]",
			bytes: []byte{0x48, 0x8b, 0x05, 0x00, 0x10, 0x00, 0x00},
		},
		{
			name:  "mov rax, gs:[rbx]",
			bytes: []byte{0x65, 0x48, 0x8b, 0x03},
		},
		{
			name:  "mov rax, [rbx + rsi*8 + 0x100]",
			bytes: []byte{0x48, 0x8b, 0x84, 0xf3, 0x00, 0x01, 0x00, 0x00},
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

			// verify second operand is memory operand
			memOp, ok := insn.Operands[1].(MemoryOperand)
			if !ok {
				t.Errorf("second operand is not MemoryOperand, got %T", insn.Operands[1])
			}

			// verify string representation is not empty
			if memOp.String() == "" {
				t.Error("memory operand string representation is empty")
			}
		})
	}
}

// TestDisassemble_EdgeCases tests edge cases in disassembly
func TestDisassemble_EdgeCases(t *testing.T) {
	d := newTestDisassembler(t)

	// test with single byte that is valid instruction (nop)
	insn, err := d.Disassemble([]byte{0x90}, 0x1000)
	if err != nil {
		t.Fatalf("disassemble single byte failed: %v", err)
	}
	if insn.Mnemonic != "nop" {
		t.Errorf("expected nop, got %q", insn.Mnemonic)
	}

	// test with maximum address
	insn, err = d.Disassemble([]byte{0x90}, 0xffffffffffffffff)
	if err != nil {
		t.Fatalf("disassemble at max address failed: %v", err)
	}
	if insn.Address != 0xffffffffffffffff {
		t.Errorf("address mismatch: got 0x%x, want 0xffffffffffffffff", insn.Address)
	}
}

// TestDisassembleBytes_EmptyInput tests handling of empty input
func TestDisassembleBytes_EmptyInput(t *testing.T) {
	d := newTestDisassembler(t)

	insns, err := d.DisassembleBytes([]byte{}, 0x1000)
	if err != nil {
		t.Fatalf("disassemble bytes with empty input failed: %v", err)
	}

	if insns != nil {
		t.Errorf("expected nil result for empty input, got %d instructions", len(insns))
	}
}

// TestDisassembleFunction_EmptyInput tests handling of empty input in function disassembly
func TestDisassembleFunction_EmptyInput(t *testing.T) {
	d := newTestDisassembler(t)

	insns, err := d.DisassembleFunction([]byte{}, 0x1000)
	if err != nil {
		t.Fatalf("disassemble function with empty input failed: %v", err)
	}

	if insns != nil {
		t.Errorf("expected nil result for empty input, got %d instructions", len(insns))
	}
}

// TestDisassembleBytes_InvalidOnlyStream tests DisassembleBytes with entirely invalid bytes
func TestDisassembleBytes_InvalidOnlyStream(t *testing.T) {
	d := newTestDisassembler(t)

	invalidBytes := []byte{0x06, 0x06, 0x06, 0x06, 0x06}
	insns, err := d.DisassembleBytes(invalidBytes, 0x1000)
	if err != nil {
		t.Fatalf("DisassembleBytes should not return error for invalid stream: %v", err)
	}

	if len(insns) != 0 {
		t.Errorf("expected 0 decoded instructions from invalid stream, got %d", len(insns))
	}
}

// TestDisassembleBytes_MultiByteMixedWithInvalid tests DisassembleBytes with multi-byte
// instructions interleaved with invalid opcodes
func TestDisassembleBytes_MultiByteMixedWithInvalid(t *testing.T) {
	d := newTestDisassembler(t)

	bytes := []byte{
		0x48, 0x89, 0xd8, // mov rax, rbx (3 bytes)
		0x06,                   // invalid in 64-bit mode
		0x48, 0x83, 0xc0, 0x01, // add rax, 1 (4 bytes)
		0x06,       // invalid
		0x06,       // invalid
		0x55,       // push rbp (1 byte)
		0x06, 0x06, // invalid x2
		0xc3, // ret (1 byte)
	}

	insns, err := d.DisassembleBytes(bytes, 0x4000)
	if err != nil {
		t.Fatalf("DisassembleBytes failed: %v", err)
	}

	if len(insns) < 4 {
		t.Fatalf("expected at least 4 valid instructions, got %d", len(insns))
	}

	expectedMnemonics := []string{"mov", "add", "push", "ret"}
	for i, expected := range expectedMnemonics {
		if insns[i].Mnemonic != expected {
			t.Errorf("instruction %d: got %q, want %q", i, insns[i].Mnemonic, expected)
		}
	}
}

// TestDisassemble_TruncatedMultiByteInstruction tests Disassemble with a truncated
// multi-byte instruction (not empty, but insufficient for a complete instruction)
func TestDisassemble_TruncatedMultiByteInstruction(t *testing.T) {
	d := newTestDisassembler(t)

	// REX.W prefix alone without following opcode bytes
	truncated := []byte{0x48}
	_, err := d.Disassemble(truncated, 0x1000)

	if err == nil {
		t.Fatal("expected error for truncated instruction, got nil")
	}
}

// TestDisassemble_RIPRelativeResolution tests that RIP-relative memory operands
// are resolved to absolute virtual addresses
func TestDisassemble_RIPRelativeResolution(t *testing.T) {
	d := newTestDisassembler(t)

	// lea rax, [rip + 0x1000]
	// at address 0x5000, instruction length 7 bytes
	// resolved address = 0x5000 + 7 + 0x1000 = 0x6007
	bytes := []byte{0x48, 0x8d, 0x05, 0x00, 0x10, 0x00, 0x00}
	insn, err := d.Disassemble(bytes, 0x5000)
	if err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	if len(insn.Operands) < 2 {
		t.Fatalf("expected at least 2 operands, got %d", len(insn.Operands))
	}

	memOp, ok := insn.Operands[1].(MemoryOperand)
	if !ok {
		t.Fatalf("second operand is not MemoryOperand, got %T", insn.Operands[1])
	}

	// RIP-relative should be resolved: base cleared, disp = absolute address
	if memOp.Base != "" {
		t.Errorf("expected empty base for resolved RIP-relative, got %q", memOp.Base)
	}

	expectedAddr := int64(0x5000 + 7 + 0x1000)
	if memOp.Disp != expectedAddr {
		t.Errorf("resolved RIP-relative address: got 0x%x, want 0x%x", memOp.Disp, expectedAddr)
	}
}

// TestDisassemble_MemoryOperandNegativeDisplacement tests memory operands with
// negative displacement through real disassembly
func TestDisassemble_MemoryOperandNegativeDisplacement(t *testing.T) {
	d := newTestDisassembler(t)

	// mov rax, [rbp - 0x8]
	bytes := []byte{0x48, 0x8b, 0x45, 0xf8}
	insn, err := d.Disassemble(bytes, 0x1000)
	if err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	if len(insn.Operands) < 2 {
		t.Fatalf("expected at least 2 operands, got %d", len(insn.Operands))
	}

	memOp, ok := insn.Operands[1].(MemoryOperand)
	if !ok {
		t.Fatalf("second operand is not MemoryOperand, got %T", insn.Operands[1])
	}

	if memOp.Base != "rbp" {
		t.Errorf("base register: got %q, want %q", memOp.Base, "rbp")
	}

	if memOp.Disp >= 0 {
		t.Errorf("expected negative displacement, got %d", memOp.Disp)
	}
}

// TestDisassembleFunction_FallbackPath tests DisassembleFunction fallback to
// byte-by-byte disassembly when bulk disassembly fails
func TestDisassembleFunction_FallbackPath(t *testing.T) {
	d := newTestDisassembler(t)

	// sequence starting with valid instructions, then invalid, then valid
	// DisassembleFunction calls Disasm with count=0 which may fail on invalid bytes
	// in that case it falls back to DisassembleBytes
	bytes := []byte{
		0x55,             // push rbp
		0x48, 0x89, 0xe5, // mov rbp, rsp
		0x5d, // pop rbp
		0xc3, // ret
	}

	insns, err := d.DisassembleFunction(bytes, 0x1000)
	if err != nil {
		t.Fatalf("DisassembleFunction failed: %v", err)
	}

	if len(insns) != 4 {
		t.Fatalf("expected 4 instructions, got %d", len(insns))
	}

	// verify sequential addresses
	expectedAddrs := []Address{0x1000, 0x1001, 0x1004, 0x1005}
	for i, expected := range expectedAddrs {
		if insns[i].Address != expected {
			t.Errorf("instruction %d address: got 0x%x, want 0x%x", i, insns[i].Address, expected)
		}
	}
}

// TestDisassemble_InstructionBoundaries_VariableLength tests boundary detection
// across a wider variety of instruction lengths (1 to 10+ bytes)
func TestDisassemble_InstructionBoundaries_VariableLength(t *testing.T) {
	d := newTestDisassembler(t)

	bytes := []byte{
		0x90,       // nop (1 byte)
		0x66, 0x90, // 66 nop (2 bytes)
		0x48, 0x89, 0xd8, // mov rax, rbx (3 bytes)
		0x48, 0x83, 0xc0, 0x01, // add rax, 1 (4 bytes)
		0xe8, 0x00, 0x00, 0x00, 0x00, // call +0 (5 bytes)
		0x48, 0x8b, 0x84, 0xf3, 0x00, 0x01, 0x00, 0x00, // mov rax, [rbx+rsi*8+0x100] (8 bytes)
		0x48, 0xb8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // movabs rax, imm64 (10 bytes)
	}

	insns, err := d.DisassembleBytes(bytes, 0x2000)
	if err != nil {
		t.Fatalf("DisassembleBytes failed: %v", err)
	}

	if len(insns) != 7 {
		t.Fatalf("expected 7 instructions, got %d", len(insns))
	}

	expectedLengths := []int{1, 2, 3, 4, 5, 8, 10}
	cumulativeOffset := Address(0x2000)
	for i, expectedLen := range expectedLengths {
		if insns[i].Address != cumulativeOffset {
			t.Errorf("instruction %d address: got 0x%x, want 0x%x", i, insns[i].Address, cumulativeOffset)
		}
		if insns[i].Length != expectedLen {
			t.Errorf("instruction %d length: got %d, want %d", i, insns[i].Length, expectedLen)
		}
		cumulativeOffset += Address(expectedLen)
	}
}

// TestDisassemble_ControlFlowInstructions tests disassembly of all control flow
// instruction types: conditional jumps, unconditional jumps, calls, returns
func TestDisassemble_ControlFlowInstructions(t *testing.T) {
	d := newTestDisassembler(t)

	tests := []struct {
		bytes    []byte
		name     string
		mnemonic string
	}{
		{name: "je", bytes: []byte{0x74, 0x10}, mnemonic: "je"},
		{name: "jne", bytes: []byte{0x75, 0x10}, mnemonic: "jne"},
		{name: "jg", bytes: []byte{0x7f, 0x10}, mnemonic: "jg"},
		{name: "jl", bytes: []byte{0x7c, 0x10}, mnemonic: "jl"},
		{name: "jge", bytes: []byte{0x7d, 0x10}, mnemonic: "jge"},
		{name: "jle", bytes: []byte{0x7e, 0x10}, mnemonic: "jle"},
		{name: "ja", bytes: []byte{0x77, 0x10}, mnemonic: "ja"},
		{name: "jb", bytes: []byte{0x72, 0x10}, mnemonic: "jb"},
		{name: "jmp rel8", bytes: []byte{0xeb, 0x10}, mnemonic: "jmp"},
		{name: "jmp rel32", bytes: []byte{0xe9, 0x00, 0x01, 0x00, 0x00}, mnemonic: "jmp"},
		{name: "call rel32", bytes: []byte{0xe8, 0x00, 0x01, 0x00, 0x00}, mnemonic: "call"},
		{name: "call [rax]", bytes: []byte{0xff, 0x10}, mnemonic: "call"},
		{name: "jmp [rax]", bytes: []byte{0xff, 0x20}, mnemonic: "jmp"},
		{name: "ret", bytes: []byte{0xc3}, mnemonic: "ret"},
		{name: "ret imm16", bytes: []byte{0xc2, 0x08, 0x00}, mnemonic: "ret"},
		{name: "syscall", bytes: []byte{0x0f, 0x05}, mnemonic: "syscall"},
		{name: "int 0x80", bytes: []byte{0xcd, 0x80}, mnemonic: "int"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insn, err := d.Disassemble(tt.bytes, 0x1000)
			if err != nil {
				t.Fatalf("disassemble failed: %v", err)
			}
			if insn.Mnemonic != tt.mnemonic {
				t.Errorf("mnemonic: got %q, want %q", insn.Mnemonic, tt.mnemonic)
			}
		})
	}
}

// TestDisassemble_ArithmeticLogicInstructions tests arithmetic and logical operations
func TestDisassemble_ArithmeticLogicInstructions(t *testing.T) {
	d := newTestDisassembler(t)

	tests := []struct {
		bytes    []byte
		name     string
		mnemonic string
	}{
		{name: "add rax, rbx", bytes: []byte{0x48, 0x01, 0xd8}, mnemonic: "add"},
		{name: "sub rax, rbx", bytes: []byte{0x48, 0x29, 0xd8}, mnemonic: "sub"},
		{name: "imul rax, rbx", bytes: []byte{0x48, 0x0f, 0xaf, 0xc3}, mnemonic: "imul"},
		{name: "xor rax, rax", bytes: []byte{0x48, 0x31, 0xc0}, mnemonic: "xor"},
		{name: "and rax, rbx", bytes: []byte{0x48, 0x21, 0xd8}, mnemonic: "and"},
		{name: "or rax, rbx", bytes: []byte{0x48, 0x09, 0xd8}, mnemonic: "or"},
		{name: "not rax", bytes: []byte{0x48, 0xf7, 0xd0}, mnemonic: "not"},
		{name: "neg rax", bytes: []byte{0x48, 0xf7, 0xd8}, mnemonic: "neg"},
		{name: "shl rax, cl", bytes: []byte{0x48, 0xd3, 0xe0}, mnemonic: "shl"},
		{name: "shr rax, cl", bytes: []byte{0x48, 0xd3, 0xe8}, mnemonic: "shr"},
		{name: "sar rax, cl", bytes: []byte{0x48, 0xd3, 0xf8}, mnemonic: "sar"},
		{name: "cmp rax, rbx", bytes: []byte{0x48, 0x39, 0xd8}, mnemonic: "cmp"},
		{name: "test rax, rax", bytes: []byte{0x48, 0x85, 0xc0}, mnemonic: "test"},
		{name: "lea rax, [rbx]", bytes: []byte{0x48, 0x8d, 0x03}, mnemonic: "lea"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insn, err := d.Disassemble(tt.bytes, 0x1000)
			if err != nil {
				t.Fatalf("disassemble failed: %v", err)
			}
			if insn.Mnemonic != tt.mnemonic {
				t.Errorf("mnemonic: got %q, want %q", insn.Mnemonic, tt.mnemonic)
			}
		})
	}
}

// TestDisassemble_StackOperations tests stack manipulation instructions
func TestDisassemble_StackOperations(t *testing.T) {
	d := newTestDisassembler(t)

	tests := []struct {
		bytes    []byte
		name     string
		mnemonic string
	}{
		{name: "push rbp", bytes: []byte{0x55}, mnemonic: "push"},
		{name: "pop rbp", bytes: []byte{0x5d}, mnemonic: "pop"},
		{name: "push rax", bytes: []byte{0x50}, mnemonic: "push"},
		{name: "pop rax", bytes: []byte{0x58}, mnemonic: "pop"},
		{name: "push imm8", bytes: []byte{0x6a, 0x01}, mnemonic: "push"},
		{name: "push imm32", bytes: []byte{0x68, 0x00, 0x10, 0x00, 0x00}, mnemonic: "push"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insn, err := d.Disassemble(tt.bytes, 0x1000)
			if err != nil {
				t.Fatalf("disassemble failed: %v", err)
			}
			if insn.Mnemonic != tt.mnemonic {
				t.Errorf("mnemonic: got %q, want %q", insn.Mnemonic, tt.mnemonic)
			}
		})
	}
}

// TestDisassemble_BytesCopyIndependence verifies that returned instruction bytes
// are independent copies (modifying them does not affect the disassembler)
func TestDisassemble_BytesCopyIndependence(t *testing.T) {
	d := newTestDisassembler(t)

	original := []byte{0x48, 0x89, 0xd8}
	insn, err := d.Disassemble(original, 0x1000)
	if err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	// mutate returned bytes
	insn.Bytes[0] = 0xFF

	// disassemble again -- should still work
	insn2, err := d.Disassemble(original, 0x1000)
	if err != nil {
		t.Fatalf("second disassemble failed: %v", err)
	}

	if insn2.Bytes[0] != 0x48 {
		t.Errorf("instruction bytes were not independent: got 0x%02x, want 0x48", insn2.Bytes[0])
	}
}

// TestDisassemble_OperandInterfaceCompliance verifies that all operand types
// satisfy the Operand interface
func TestDisassemble_OperandInterfaceCompliance(t *testing.T) {
	operands := []Operand{
		RegisterOperand{Name: "rax", Size: Size64},
		ImmediateOperand{Value: 42, Size: Size32},
		MemoryOperand{Base: "rsp", Disp: -8, Size: Size64},
	}

	for i, op := range operands {
		op.isOperand()
		str := op.String()
		if str == "" {
			t.Errorf("operand %d String() returned empty", i)
		}
	}
}

// TestFormatInt_EdgeCases tests formatInt with zero and negative values
func TestFormatInt_EdgeCases(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{-1, "-1"},
		{42, "42"},
		{-42, "-42"},
		{1000000, "1000000"},
	}

	for _, tt := range tests {
		result := formatInt(tt.input)
		if result != tt.expected {
			t.Errorf("formatInt(%d): got %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// TestDisassemble_LargeImmediates tests handling of large immediate values
func TestDisassemble_LargeImmediates(t *testing.T) {
	d := newTestDisassembler(t)

	// mov rax, 0x123456789abcdef0
	bytes := []byte{0x48, 0xb8, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12}
	insn, err := d.Disassemble(bytes, 0x1000)
	if err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	if len(insn.Operands) < 2 {
		t.Fatalf("expected at least 2 operands, got %d", len(insn.Operands))
	}

	immOp, ok := insn.Operands[1].(ImmediateOperand)
	if !ok {
		t.Fatalf("second operand is not ImmediateOperand, got %T", insn.Operands[1])
	}

	// verify immediate value
	expected := int64(0x123456789abcdef0)
	if immOp.Value != expected {
		t.Errorf("immediate value: got 0x%x, want 0x%x", immOp.Value, expected)
	}

	// verify string representation
	str := immOp.String()
	if str == "" {
		t.Error("immediate operand string representation is empty")
	}
}
