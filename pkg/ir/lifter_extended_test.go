package ir

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// ============================================================================
// MUL / IMUL
// ============================================================================

// TestLifterMul tests unsigned multiply in all operand-size variants.
//
//nolint:dupl // test struct repetition
func TestLifterMul(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantOps int
		wantErr bool
	}{
		{
			// 8-bit: al * src -> ax (single assign, no high-part rdx)
			name: "mul bl (8-bit)",
			insn: &disasm.Instruction{
				Address:  0x1000,
				Mnemonic: "mul",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "bl", Size: disasm.Size8},
				},
				Length: 2,
			},
			wantOps: 1, // assign ax only (8-bit result fits in ax, no rdx)
			wantErr: false,
		},
		{
			// 64-bit: rax * src -> rdx:rax (2 assigns: rax low, rdx high)
			name: "mul rbx (64-bit)",
			insn: &disasm.Instruction{
				Address:  0x1002,
				Mnemonic: "mul",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 2, // assign rax + assign rdx
			wantErr: false,
		},
		{
			// 32-bit: eax * src -> edx:eax
			name: "mul ecx (32-bit)",
			insn: &disasm.Instruction{
				Address:  0x1005,
				Mnemonic: "mul",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "ecx", Size: disasm.Size32},
				},
				Length: 2,
			},
			wantOps: 2,
			wantErr: false,
		},
		{
			// 16-bit: ax * src -> dx:ax
			name: "mul cx (16-bit)",
			insn: &disasm.Instruction{
				Address:  0x1007,
				Mnemonic: "mul",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "cx", Size: disasm.Size16},
				},
				Length: 2,
			},
			wantOps: 2,
			wantErr: false,
		},
		{
			// wrong operand count
			name: "mul with 0 operands",
			insn: &disasm.Instruction{
				Address:  0x1009,
				Mnemonic: "mul",
				Operands: []disasm.Operand{},
				Length:   1,
			},
			wantOps: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifter := NewLifter()
			result, err := lifter.LiftInstruction(tt.insn)
			if (err != nil) != tt.wantErr {
				t.Errorf("LiftInstruction() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(result) != tt.wantOps {
				t.Errorf("got %d ops, want %d", len(result), tt.wantOps)
				for i, op := range result {
					t.Logf("  [%d] %s", i, op.String())
				}
			}
		})
	}
}

// TestLifterIMul tests signed multiply in all three encoding forms.
func TestLifterIMul(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantOps int
		wantErr bool
	}{
		{
			// 1-operand: rdx:rax = rax * src (signed)
			name: "imul rbx (1-operand)",
			insn: &disasm.Instruction{
				Address:  0x2000,
				Mnemonic: "imul",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 2, // assign rax + assign rdx
			wantErr: false,
		},
		{
			// 1-operand 8-bit: ax = al * src (no rdx)
			name: "imul bl (1-operand 8-bit)",
			insn: &disasm.Instruction{
				Address:  0x2003,
				Mnemonic: "imul",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "bl", Size: disasm.Size8},
				},
				Length: 2,
			},
			wantOps: 1, // only assign al
			wantErr: false,
		},
		{
			// 2-operand: dest = dest * src
			name: "imul rax, rbx (2-operand)",
			insn: &disasm.Instruction{
				Address:  0x2005,
				Mnemonic: "imul",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 1,
			wantErr: false,
		},
		{
			// 3-operand: dest = src * imm
			name: "imul rax, rbx, 4 (3-operand)",
			insn: &disasm.Instruction{
				Address:  0x2008,
				Mnemonic: "imul",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
					disasm.ImmediateOperand{Value: 4, Size: disasm.Size8},
				},
				Length: 4,
			},
			wantOps: 1,
			wantErr: false,
		},
		{
			// 3-operand with memory source
			name: "imul rax, [rbx], 8 (3-operand mem)",
			insn: &disasm.Instruction{
				Address:  0x200c,
				Mnemonic: "imul",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.MemoryOperand{Base: "rbx", Size: disasm.Size64},
					disasm.ImmediateOperand{Value: 8, Size: disasm.Size8},
				},
				Length: 4,
			},
			wantOps: 2, // load + assign
			wantErr: false,
		},
		{
			// 3-operand: non-register destination must fail
			name: "imul [rax], rbx, 4 (invalid dest)",
			insn: &disasm.Instruction{
				Address:  0x2010,
				Mnemonic: "imul",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
					disasm.ImmediateOperand{Value: 4, Size: disasm.Size8},
				},
				Length: 4,
			},
			wantOps: 0,
			wantErr: true,
		},
		{
			// wrong operand count
			name: "imul with 0 operands",
			insn: &disasm.Instruction{
				Address:  0x2014,
				Mnemonic: "imul",
				Operands: []disasm.Operand{},
				Length:   1,
			},
			wantOps: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifter := NewLifter()
			result, err := lifter.LiftInstruction(tt.insn)
			if (err != nil) != tt.wantErr {
				t.Errorf("LiftInstruction() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(result) != tt.wantOps {
				t.Errorf("got %d ops, want %d", len(result), tt.wantOps)
				for i, op := range result {
					t.Logf("  [%d] %s", i, op.String())
				}
			}
		})
	}
}

// ============================================================================
// DIV / IDIV
// ============================================================================

// TestLifterDiv tests unsigned division in all size variants.
func TestLifterDiv(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantOps int
		wantErr bool
	}{
		{
			// 8-bit: al = ax / src, ah = ax % src
			name: "div bl (8-bit)",
			insn: &disasm.Instruction{
				Address:  0x3000,
				Mnemonic: "div",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "bl", Size: disasm.Size8},
				},
				Length: 2,
			},
			wantOps: 2, // assign al + assign ah
			wantErr: false,
		},
		{
			// 64-bit: rax = rdx:rax / src, rdx = rdx:rax % src
			name: "div rbx (64-bit)",
			insn: &disasm.Instruction{
				Address:  0x3002,
				Mnemonic: "div",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 2, // assign rax + assign rdx
			wantErr: false,
		},
		{
			// 32-bit
			name: "div ecx (32-bit)",
			insn: &disasm.Instruction{
				Address:  0x3005,
				Mnemonic: "div",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "ecx", Size: disasm.Size32},
				},
				Length: 2,
			},
			wantOps: 2,
			wantErr: false,
		},
		{
			// 16-bit
			name: "div cx (16-bit)",
			insn: &disasm.Instruction{
				Address:  0x3007,
				Mnemonic: "div",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "cx", Size: disasm.Size16},
				},
				Length: 2,
			},
			wantOps: 2,
			wantErr: false,
		},
		{
			// memory operand as divisor
			name: "div [rbx] (memory)",
			insn: &disasm.Instruction{
				Address:  0x3009,
				Mnemonic: "div",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 3, // load + assign rax + assign rdx
			wantErr: false,
		},
		{
			// wrong operand count
			name: "div with 0 operands",
			insn: &disasm.Instruction{
				Address:  0x300c,
				Mnemonic: "div",
				Operands: []disasm.Operand{},
				Length:   1,
			},
			wantOps: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifter := NewLifter()
			result, err := lifter.LiftInstruction(tt.insn)
			if (err != nil) != tt.wantErr {
				t.Errorf("LiftInstruction() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(result) != tt.wantOps {
				t.Errorf("got %d ops, want %d", len(result), tt.wantOps)
				for i, op := range result {
					t.Logf("  [%d] %s", i, op.String())
				}
			}
		})
	}
}

// TestLifterIDiv tests signed division in all size variants.
func TestLifterIDiv(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantOps int
		wantErr bool
	}{
		{
			name: "idiv bl (8-bit)",
			insn: &disasm.Instruction{
				Address:  0x4000,
				Mnemonic: "idiv",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "bl", Size: disasm.Size8},
				},
				Length: 2,
			},
			wantOps: 2,
			wantErr: false,
		},
		{
			name: "idiv rbx (64-bit)",
			insn: &disasm.Instruction{
				Address:  0x4002,
				Mnemonic: "idiv",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 2,
			wantErr: false,
		},
		{
			name: "idiv [rcx] (memory)",
			insn: &disasm.Instruction{
				Address:  0x4005,
				Mnemonic: "idiv",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rcx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 3, // load + assign rax + assign rdx
			wantErr: false,
		},
		{
			name: "idiv with 0 operands",
			insn: &disasm.Instruction{
				Address:  0x4008,
				Mnemonic: "idiv",
				Operands: []disasm.Operand{},
				Length:   1,
			},
			wantOps: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifter := NewLifter()
			result, err := lifter.LiftInstruction(tt.insn)
			if (err != nil) != tt.wantErr {
				t.Errorf("LiftInstruction() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(result) != tt.wantOps {
				t.Errorf("got %d ops, want %d", len(result), tt.wantOps)
				for i, op := range result {
					t.Logf("  [%d] %s", i, op.String())
				}
			}
		})
	}
}

// ============================================================================
// MOVZX / MOVSX
// ============================================================================

// TestLifterMovzx tests zero-extension move.
//
//nolint:dupl // test struct repetition
func TestLifterMovzx(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantOps int
		wantErr bool
	}{
		{
			name: "movzx rax, bl",
			insn: &disasm.Instruction{
				Address:  0x5000,
				Mnemonic: "movzx",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "bl", Size: disasm.Size8},
				},
				Length: 3,
			},
			wantOps: 1, // assign with cast
			wantErr: false,
		},
		{
			name: "movzx eax, [rbx] (memory source)",
			insn: &disasm.Instruction{
				Address:  0x5003,
				Mnemonic: "movzx",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "eax", Size: disasm.Size32},
					disasm.MemoryOperand{Base: "rbx", Size: disasm.Size8},
				},
				Length: 3,
			},
			wantOps: 2, // load + assign
			wantErr: false,
		},
		{
			// movzb alias
			name: "movzb rax, cl",
			insn: &disasm.Instruction{
				Address:  0x5006,
				Mnemonic: "movzb",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "cl", Size: disasm.Size8},
				},
				Length: 3,
			},
			wantOps: 1,
			wantErr: false,
		},
		{
			// non-register destination must fail
			name: "movzx [rax], bl (invalid dest)",
			insn: &disasm.Instruction{
				Address:  0x5009,
				Mnemonic: "movzx",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "bl", Size: disasm.Size8},
				},
				Length: 3,
			},
			wantOps: 0,
			wantErr: true,
		},
		{
			name: "movzx with wrong operand count",
			insn: &disasm.Instruction{
				Address:  0x500c,
				Mnemonic: "movzx",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				},
				Length: 2,
			},
			wantOps: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifter := NewLifter()
			result, err := lifter.LiftInstruction(tt.insn)
			if (err != nil) != tt.wantErr {
				t.Errorf("LiftInstruction() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(result) != tt.wantOps {
				t.Errorf("got %d ops, want %d", len(result), tt.wantOps)
				for i, op := range result {
					t.Logf("  [%d] %s", i, op.String())
				}
			}
		})
	}
}

// TestLifterMovsx tests sign-extension move.
//
//nolint:dupl // test struct repetition
func TestLifterMovsx(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantOps int
		wantErr bool
	}{
		{
			name: "movsx rax, bl",
			insn: &disasm.Instruction{
				Address:  0x6000,
				Mnemonic: "movsx",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "bl", Size: disasm.Size8},
				},
				Length: 3,
			},
			wantOps: 1,
			wantErr: false,
		},
		{
			// movsxd: sign-extend 32-bit to 64-bit
			name: "movsxd rax, ecx",
			insn: &disasm.Instruction{
				Address:  0x6003,
				Mnemonic: "movsxd",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "ecx", Size: disasm.Size32},
				},
				Length: 3,
			},
			wantOps: 1,
			wantErr: false,
		},
		{
			name: "movsx eax, [rbx] (memory source)",
			insn: &disasm.Instruction{
				Address:  0x6006,
				Mnemonic: "movsx",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "eax", Size: disasm.Size32},
					disasm.MemoryOperand{Base: "rbx", Size: disasm.Size8},
				},
				Length: 3,
			},
			wantOps: 2, // load + assign
			wantErr: false,
		},
		{
			// non-register destination must fail
			name: "movsx [rax], bl (invalid dest)",
			insn: &disasm.Instruction{
				Address:  0x6009,
				Mnemonic: "movsx",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "bl", Size: disasm.Size8},
				},
				Length: 3,
			},
			wantOps: 0,
			wantErr: true,
		},
		{
			name: "movsx with wrong operand count",
			insn: &disasm.Instruction{
				Address:  0x600c,
				Mnemonic: "movsx",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				},
				Length: 2,
			},
			wantOps: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifter := NewLifter()
			result, err := lifter.LiftInstruction(tt.insn)
			if (err != nil) != tt.wantErr {
				t.Errorf("LiftInstruction() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(result) != tt.wantOps {
				t.Errorf("got %d ops, want %d", len(result), tt.wantOps)
				for i, op := range result {
					t.Logf("  [%d] %s", i, op.String())
				}
			}
		})
	}
}

// ============================================================================
// ROL / ROR (currently unimplemented — must return error)
// ============================================================================

// TestLifterRotate verifies that rotate instructions return an error until implemented.
func TestLifterRotate(t *testing.T) {
	tests := []struct {
		name     string
		mnemonic string
	}{
		{"rol rax, 1", "rol"},
		{"ror rbx, cl", "ror"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifter := NewLifter()
			insn := &disasm.Instruction{
				Address:  0x7000,
				Mnemonic: tt.mnemonic,
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.ImmediateOperand{Value: 1, Size: disasm.Size8},
				},
				Length: 3,
			}
			_, err := lifter.LiftInstruction(insn)
			if err == nil {
				t.Errorf("expected error for unimplemented %s, got nil", tt.mnemonic)
			}
		})
	}
}

// ============================================================================
// NOP
// ============================================================================

// TestLifterNop verifies that nop produces zero IR instructions.
func TestLifterNop(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x8000,
		Mnemonic: "nop",
		Operands: []disasm.Operand{},
		Length:   1,
	}
	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("nop should produce 0 IR instructions, got %d", len(result))
	}
}

// ============================================================================
// Memory operand paths for arithmetic/logical/shift
// ============================================================================

// TestLifterArithmeticMemoryOperands tests arithmetic instructions with memory operands.
func TestLifterArithmeticMemoryOperands(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantOps int
		wantErr bool
	}{
		{
			// add [rax], rbx: load + binop store
			name: "add [rax], rbx",
			insn: &disasm.Instruction{
				Address:  0x9000,
				Mnemonic: "add",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 2, // load dest + store result
			wantErr: false,
		},
		{
			// add rax, [rbx]: load src + assign
			name: "add rax, [rbx]",
			insn: &disasm.Instruction{
				Address:  0x9003,
				Mnemonic: "add",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.MemoryOperand{Base: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 2, // load src + assign dest
			wantErr: false,
		},
		{
			// sub [rax], 0x10
			name: "sub [rax], 0x10",
			insn: &disasm.Instruction{
				Address:  0x9006,
				Mnemonic: "sub",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rax", Size: disasm.Size64},
					disasm.ImmediateOperand{Value: 0x10, Size: disasm.Size64},
				},
				Length: 4,
			},
			wantOps: 2, // load + store
			wantErr: false,
		},
		{
			// inc [rax]
			name: "inc [rax]",
			insn: &disasm.Instruction{
				Address:  0x900a,
				Mnemonic: "inc",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rax", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 2, // load + store
			wantErr: false,
		},
		{
			// dec [rbx]
			name: "dec [rbx]",
			insn: &disasm.Instruction{
				Address:  0x900d,
				Mnemonic: "dec",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 2, // load + store
			wantErr: false,
		},
		{
			// neg [rcx]
			name: "neg [rcx]",
			insn: &disasm.Instruction{
				Address:  0x9010,
				Mnemonic: "neg",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rcx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 2, // load + store
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifter := NewLifter()
			result, err := lifter.LiftInstruction(tt.insn)
			if (err != nil) != tt.wantErr {
				t.Errorf("LiftInstruction() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(result) != tt.wantOps {
				t.Errorf("got %d ops, want %d", len(result), tt.wantOps)
				for i, op := range result {
					t.Logf("  [%d] %s", i, op.String())
				}
			}
		})
	}
}

// TestLifterLogicalMemoryOperands tests logical instructions with memory operands.
func TestLifterLogicalMemoryOperands(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantOps int
		wantErr bool
	}{
		{
			name: "and [rax], rbx",
			insn: &disasm.Instruction{
				Address:  0xa000,
				Mnemonic: "and",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 2,
			wantErr: false,
		},
		{
			name: "or rax, [rbx]",
			insn: &disasm.Instruction{
				Address:  0xa003,
				Mnemonic: "or",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.MemoryOperand{Base: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 2,
			wantErr: false,
		},
		{
			name: "xor [rcx], rdx",
			insn: &disasm.Instruction{
				Address:  0xa006,
				Mnemonic: "xor",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rcx", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rdx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 2,
			wantErr: false,
		},
		{
			name: "not [rdi]",
			insn: &disasm.Instruction{
				Address:  0xa009,
				Mnemonic: "not",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rdi", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 2, // load + store
			wantErr: false,
		},
		{
			name: "test [rax], rbx",
			insn: &disasm.Instruction{
				Address:  0xa00c,
				Mnemonic: "test",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 1, // load only (result discarded)
			wantErr: false,
		},
		{
			name: "cmp [rax], rbx",
			insn: &disasm.Instruction{
				Address:  0xa00f,
				Mnemonic: "cmp",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 1, // load only (result discarded)
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifter := NewLifter()
			result, err := lifter.LiftInstruction(tt.insn)
			if (err != nil) != tt.wantErr {
				t.Errorf("LiftInstruction() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(result) != tt.wantOps {
				t.Errorf("got %d ops, want %d", len(result), tt.wantOps)
				for i, op := range result {
					t.Logf("  [%d] %s", i, op.String())
				}
			}
		})
	}
}

// TestLifterShiftMemoryOperands tests shift instructions with memory operands.
func TestLifterShiftMemoryOperands(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantOps int
		wantErr bool
	}{
		{
			name: "shl [rax], 1",
			insn: &disasm.Instruction{
				Address:  0xb000,
				Mnemonic: "shl",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rax", Size: disasm.Size64},
					disasm.ImmediateOperand{Value: 1, Size: disasm.Size8},
				},
				Length: 3,
			},
			wantOps: 2, // load + store
			wantErr: false,
		},
		{
			name: "shr [rbx], cl",
			insn: &disasm.Instruction{
				Address:  0xb003,
				Mnemonic: "shr",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rbx", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "cl", Size: disasm.Size8},
				},
				Length: 3,
			},
			wantOps: 2,
			wantErr: false,
		},
		{
			name: "sar [rcx], 4",
			insn: &disasm.Instruction{
				Address:  0xb006,
				Mnemonic: "sar",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rcx", Size: disasm.Size64},
					disasm.ImmediateOperand{Value: 4, Size: disasm.Size8},
				},
				Length: 4,
			},
			wantOps: 2,
			wantErr: false,
		},
		{
			// sal is alias for shl
			name: "sal rax, 2",
			insn: &disasm.Instruction{
				Address:  0xb009,
				Mnemonic: "sal",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.ImmediateOperand{Value: 2, Size: disasm.Size8},
				},
				Length: 3,
			},
			wantOps: 1,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifter := NewLifter()
			result, err := lifter.LiftInstruction(tt.insn)
			if (err != nil) != tt.wantErr {
				t.Errorf("LiftInstruction() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(result) != tt.wantOps {
				t.Errorf("got %d ops, want %d", len(result), tt.wantOps)
				for i, op := range result {
					t.Logf("  [%d] %s", i, op.String())
				}
			}
		})
	}
}

// ============================================================================
// Control flow: all conditional jump mnemonics
// ============================================================================

// TestLifterJccAllConditions tests every conditional jump mnemonic for correct
// condition expression construction and branch IR emission.
func TestLifterJccAllConditions(t *testing.T) {
	mnemonics := []string{
		"je", "jz",
		"jne", "jnz",
		"jl", "jnge",
		"jle", "jng",
		"jg", "jnle",
		"jge", "jnl",
		"jb", "jnae", "jc",
		"jbe", "jna",
		"ja", "jnbe",
		"jae", "jnb", "jnc",
		"js", "jns",
		"jo", "jno",
		"jp", "jpe",
		"jnp", "jpo",
	}

	for _, mnemonic := range mnemonics {
		mnemonic := mnemonic // capture
		t.Run(mnemonic, func(t *testing.T) {
			lifter := NewLifter()
			insn := &disasm.Instruction{
				Address:  0xc000,
				Mnemonic: mnemonic,
				Operands: []disasm.Operand{
					disasm.ImmediateOperand{Value: 0xc100, Size: disasm.Size64},
				},
				Length: 2,
			}
			result, err := lifter.LiftInstruction(insn)
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", mnemonic, err)
			}
			if len(result) != 1 {
				t.Errorf("%s: expected 1 branch instruction, got %d", mnemonic, len(result))
				return
			}
			branch, ok := result[0].(*Branch)
			if !ok {
				t.Errorf("%s: expected Branch instruction, got %T", mnemonic, result[0])
				return
			}
			// true target must be the jump destination
			if branch.TrueTarget != BlockID(0xc100) {
				t.Errorf("%s: TrueTarget = %d, want 0xc100", mnemonic, branch.TrueTarget)
			}
			// fall-through = address + length
			wantFallThrough := BlockID(0xc000 + 2)
			if branch.FalseTarget != wantFallThrough {
				t.Errorf("%s: FalseTarget = %d, want %d", mnemonic, branch.FalseTarget, wantFallThrough)
			}
			// condition must not be nil
			if branch.Condition == nil {
				t.Errorf("%s: Condition is nil", mnemonic)
			}
		})
	}
}

// TestLifterJccNonImmediateTarget verifies that indirect jcc returns an error.
func TestLifterJccNonImmediateTarget(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0xd000,
		Mnemonic: "je",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
		},
		Length: 2,
	}
	_, err := lifter.LiftInstruction(insn)
	if err == nil {
		t.Error("expected error for non-immediate jcc target, got nil")
	}
}

// TestLifterJmpIndirect verifies that indirect jmp returns an error.
func TestLifterJmpIndirect(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0xe000,
		Mnemonic: "jmp",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
		},
		Length: 2,
	}
	_, err := lifter.LiftInstruction(insn)
	if err == nil {
		t.Error("expected error for indirect jmp, got nil")
	}
}

// TestLifterRetWithImmediate tests ret imm16 (stdcall convention).
func TestLifterRetWithImmediate(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0xf000,
		Mnemonic: "ret",
		Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x10, Size: disasm.Size16},
		},
		Length: 3,
	}
	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// single abstract Return node; rsp adjustment is an ABI artifact, suppressed
	if len(result) != 1 {
		t.Errorf("ret imm16: expected 1 IR instruction, got %d", len(result))
		for i, op := range result {
			t.Logf("  [%d] %s", i, op.String())
		}
	}
}

// TestLifterCallIndirectMemory tests indirect call through memory operand.
func TestLifterCallIndirectMemory(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x10000,
		Mnemonic: "call",
		Operands: []disasm.Operand{
			disasm.MemoryOperand{Base: "rax", Size: disasm.Size64},
		},
		Length: 3,
	}
	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// load target pointer + abstract Call node (rsp manipulation suppressed)
	if len(result) != 2 {
		t.Errorf("call [mem]: expected 2 IR instructions, got %d", len(result))
		for i, op := range result {
			t.Logf("  [%d] %s", i, op.String())
		}
	}
}

// ============================================================================
// MOV edge cases
// ============================================================================

// TestLifterMovEdgeCases tests error paths in liftMov.
func TestLifterMovEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantErr bool
	}{
		{
			// mem-to-mem is illegal in x86_64
			name: "mov [rax], [rbx] (mem-to-mem)",
			insn: &disasm.Instruction{
				Address:  0x11000,
				Mnemonic: "mov",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rax", Size: disasm.Size64},
					disasm.MemoryOperand{Base: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantErr: true,
		},
		{
			// wrong operand count
			name: "mov with 1 operand",
			insn: &disasm.Instruction{
				Address:  0x11003,
				Mnemonic: "mov",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				},
				Length: 2,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifter := NewLifter()
			_, err := lifter.LiftInstruction(tt.insn)
			if (err != nil) != tt.wantErr {
				t.Errorf("LiftInstruction() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestLifterLeaEdgeCases tests error paths in liftLea.
func TestLifterLeaEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantErr bool
	}{
		{
			// source must be memory operand
			name: "lea rax, rbx (non-memory source)",
			insn: &disasm.Instruction{
				Address:  0x12000,
				Mnemonic: "lea",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantErr: true,
		},
		{
			// destination must be register
			name: "lea [rax], [rbx] (non-register dest)",
			insn: &disasm.Instruction{
				Address:  0x12003,
				Mnemonic: "lea",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rax", Size: disasm.Size64},
					disasm.MemoryOperand{Base: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantErr: true,
		},
		{
			// wrong operand count
			name: "lea with 1 operand",
			insn: &disasm.Instruction{
				Address:  0x12006,
				Mnemonic: "lea",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				},
				Length: 2,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifter := NewLifter()
			_, err := lifter.LiftInstruction(tt.insn)
			if (err != nil) != tt.wantErr {
				t.Errorf("LiftInstruction() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ============================================================================
// translateMemoryAddress edge cases
// ============================================================================

// TestLifterMemoryAddressVariants tests all combinations of base/index/disp.
func TestLifterMemoryAddressVariants(t *testing.T) {
	tests := []struct {
		name    string
		mem     disasm.MemoryOperand
		wantOps int
	}{
		{
			// [disp] — no base, no index
			name:    "load [0x1000]",
			mem:     disasm.MemoryOperand{Disp: 0x1000, Size: disasm.Size64},
			wantOps: 2, // load + assign
		},
		{
			// [base + index] — no scale, no disp
			name:    "load [rax + rbx]",
			mem:     disasm.MemoryOperand{Base: "rax", Index: "rbx", Scale: 1, Size: disasm.Size64},
			wantOps: 2,
		},
		{
			// [base + index*scale + disp]
			name:    "load [rax + rbx*8 + 0x20]",
			mem:     disasm.MemoryOperand{Base: "rax", Index: "rbx", Scale: 8, Disp: 0x20, Size: disasm.Size64},
			wantOps: 2,
		},
		{
			// [index*scale] — no base, no disp
			name:    "load [rbx*4]",
			mem:     disasm.MemoryOperand{Index: "rbx", Scale: 4, Size: disasm.Size64},
			wantOps: 2,
		},
		{
			// [index + disp] — no base
			name:    "load [rbx + 0x8]",
			mem:     disasm.MemoryOperand{Index: "rbx", Scale: 1, Disp: 0x8, Size: disasm.Size64},
			wantOps: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifter := NewLifter()
			// use mov rax, [mem] to exercise translateMemoryAddress
			insn := &disasm.Instruction{
				Address:  0x13000,
				Mnemonic: "mov",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					tt.mem,
				},
				Length: 4,
			}
			result, err := lifter.LiftInstruction(insn)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result) != tt.wantOps {
				t.Errorf("got %d ops, want %d", len(result), tt.wantOps)
				for i, op := range result {
					t.Logf("  [%d] %s", i, op.String())
				}
			}
		})
	}
}

// ============================================================================
// pop to memory destination
// ============================================================================

// TestLifterPopToMemory tests pop with memory destination operand.
func TestLifterPopToMemory(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x14000,
		Mnemonic: "pop",
		Operands: []disasm.Operand{
			disasm.MemoryOperand{Base: "rax", Size: disasm.Size64},
		},
		Length: 2,
	}
	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// load from [rsp] + assign rsp + store to [rax]
	if len(result) != 3 {
		t.Errorf("pop [mem]: expected 3 IR instructions, got %d", len(result))
		for i, op := range result {
			t.Logf("  [%d] %s", i, op.String())
		}
	}
}

// ============================================================================
// Lazy flags: GetCurrentLazyFlags and ClearLazyFlags
// ============================================================================

// TestLifterLazyFlagsState verifies that lazy flags are set after flag-setting
// instructions and cleared after non-flag instructions.
func TestLifterLazyFlagsState(t *testing.T) {
	lifter := NewLifter()

	// after add, lazy flags must be set
	addInsn := &disasm.Instruction{
		Address:  0x15000,
		Mnemonic: "add",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
		},
		Length: 3,
	}
	_, err := lifter.LiftInstruction(addInsn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lifter.GetCurrentLazyFlags() == nil {
		t.Error("expected lazy flags to be set after add instruction")
	}
	if lifter.GetCurrentLazyFlags().Operation != FlagOpArithmetic {
		t.Errorf("expected arithmetic flags, got %v", lifter.GetCurrentLazyFlags().Operation)
	}

	// after and, lazy flags must reflect logical operation
	andInsn := &disasm.Instruction{
		Address:  0x15003,
		Mnemonic: "and",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
		},
		Length: 3,
	}
	_, err = lifter.LiftInstruction(andInsn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lifter.GetCurrentLazyFlags() == nil {
		t.Error("expected lazy flags to be set after and instruction")
	}
	if lifter.GetCurrentLazyFlags().Operation != FlagOpLogical {
		t.Errorf("expected logical flags, got %v", lifter.GetCurrentLazyFlags().Operation)
	}

	// after shl, lazy flags must reflect shift operation
	shlInsn := &disasm.Instruction{
		Address:  0x15006,
		Mnemonic: "shl",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.ImmediateOperand{Value: 1, Size: disasm.Size8},
		},
		Length: 3,
	}
	_, err = lifter.LiftInstruction(shlInsn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lifter.GetCurrentLazyFlags() == nil {
		t.Error("expected lazy flags to be set after shl instruction")
	}
	if lifter.GetCurrentLazyFlags().Operation != FlagOpShift {
		t.Errorf("expected shift flags, got %v", lifter.GetCurrentLazyFlags().Operation)
	}
}

// ============================================================================
// IR instruction type assertions
// ============================================================================

// TestLifterIRInstructionTypes verifies that lifted instructions have the
// correct concrete IR types.
func TestLifterIRInstructionTypes(t *testing.T) {
	t.Run("add produces Assign", func(t *testing.T) {
		lifter := NewLifter()
		insn := &disasm.Instruction{
			Address:  0x16000,
			Mnemonic: "add",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
			},
			Length: 3,
		}
		result, err := lifter.LiftInstruction(insn)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := result[0].(*Assign); !ok {
			t.Errorf("expected Assign, got %T", result[0])
		}
	})

	t.Run("mov reg,[mem] produces Load then Assign", func(t *testing.T) {
		lifter := NewLifter()
		insn := &disasm.Instruction{
			Address:  0x16003,
			Mnemonic: "mov",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				disasm.MemoryOperand{Base: "rbx", Size: disasm.Size64},
			},
			Length: 3,
		}
		result, err := lifter.LiftInstruction(insn)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) < 2 {
			t.Fatalf("expected at least 2 instructions, got %d", len(result))
		}
		if _, ok := result[0].(*Load); !ok {
			t.Errorf("expected Load at [0], got %T", result[0])
		}
		if _, ok := result[1].(*Assign); !ok {
			t.Errorf("expected Assign at [1], got %T", result[1])
		}
	})

	t.Run("mov [mem],reg produces Store", func(t *testing.T) {
		lifter := NewLifter()
		insn := &disasm.Instruction{
			Address:  0x16006,
			Mnemonic: "mov",
			Operands: []disasm.Operand{
				disasm.MemoryOperand{Base: "rax", Size: disasm.Size64},
				disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
			},
			Length: 3,
		}
		result, err := lifter.LiftInstruction(insn)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := result[0].(*Store); !ok {
			t.Errorf("expected Store, got %T", result[0])
		}
	})

	t.Run("jmp produces Jump", func(t *testing.T) {
		lifter := NewLifter()
		insn := &disasm.Instruction{
			Address:  0x16009,
			Mnemonic: "jmp",
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x17000, Size: disasm.Size64},
			},
			Length: 5,
		}
		result, err := lifter.LiftInstruction(insn)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := result[0].(*Jump); !ok {
			t.Errorf("expected Jump, got %T", result[0])
		}
	})

	t.Run("je produces Branch", func(t *testing.T) {
		lifter := NewLifter()
		insn := &disasm.Instruction{
			Address:  0x1600e,
			Mnemonic: "je",
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x17000, Size: disasm.Size64},
			},
			Length: 2,
		}
		result, err := lifter.LiftInstruction(insn)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := result[0].(*Branch); !ok {
			t.Errorf("expected Branch, got %T", result[0])
		}
	})

	t.Run("call produces Call", func(t *testing.T) {
		lifter := NewLifter()
		insn := &disasm.Instruction{
			Address:  0x16010,
			Mnemonic: "call",
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x18000, Size: disasm.Size64},
			},
			Length: 5,
		}
		result, err := lifter.LiftInstruction(insn)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// last instruction must be Call
		last := result[len(result)-1]
		if _, ok := last.(*Call); !ok {
			t.Errorf("expected Call as last instruction, got %T", last)
		}
	})

	t.Run("ret produces Return", func(t *testing.T) {
		lifter := NewLifter()
		insn := &disasm.Instruction{
			Address:  0x16015,
			Mnemonic: "ret",
			Operands: []disasm.Operand{},
			Length:   1,
		}
		result, err := lifter.LiftInstruction(insn)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		last := result[len(result)-1]
		if _, ok := last.(*Return); !ok {
			t.Errorf("expected Return as last instruction, got %T", last)
		}
	})
}

// ============================================================================
// Source location traceability
// ============================================================================

// TestLifterSourceLocation verifies that all emitted instructions carry the
// correct source location (virtual address + mnemonic string).
func TestLifterSourceLocation(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x401000,
		Mnemonic: "add",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
		},
		Length: 3,
	}
	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, ir := range result {
		loc := ir.Location()
		if loc.Address != Address(0x401000) {
			t.Errorf("[%d] expected address 0x401000, got 0x%x", i, loc.Address)
		}
		if loc.Instruction == "" {
			t.Errorf("[%d] instruction string must not be empty", i)
		}
	}
}

// ============================================================================
// Benchmarks
// ============================================================================

// BenchmarkLiftAdd benchmarks the hot path: lifting a register-register add.
func BenchmarkLiftAdd(b *testing.B) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x1000,
		Mnemonic: "add",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
		},
		Length: 3,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = lifter.LiftInstruction(insn)
	}
}

// BenchmarkLiftMov benchmarks mov reg,[mem] which exercises memory address translation.
func BenchmarkLiftMov(b *testing.B) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x1000,
		Mnemonic: "mov",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.MemoryOperand{Base: "rbx", Index: "rcx", Scale: 4, Disp: 0x10, Size: disasm.Size64},
		},
		Length: 4,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = lifter.LiftInstruction(insn)
	}
}

// BenchmarkLiftJcc benchmarks conditional jump lifting including condition expression build.
func BenchmarkLiftJcc(b *testing.B) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x1000,
		Mnemonic: "jle",
		Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x2000, Size: disasm.Size64},
		},
		Length: 2,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = lifter.LiftInstruction(insn)
	}
}
