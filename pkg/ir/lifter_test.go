package ir

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestLifterArithmetic tests lifting of arithmetic operations.
func TestLifterArithmetic(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantOps int // expected number of ir instructions
		wantErr bool
	}{
		{
			name: "add rax, rbx",
			insn: &disasm.Instruction{
				Address:  0x1000,
				Mnemonic: "add",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 1, // assign + 5 flag assignments
			wantErr: false,
		},
		{
			name: "sub rcx, 0x10",
			insn: &disasm.Instruction{
				Address:  0x1003,
				Mnemonic: "sub",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rcx", Size: disasm.Size64},
					disasm.ImmediateOperand{Value: 0x10, Size: disasm.Size64},
				},
				Length: 4,
			},
			wantOps: 1, // assign + 5 flag assignments
			wantErr: false,
		},
		{
			name: "inc rdx",
			insn: &disasm.Instruction{
				Address:  0x1007,
				Mnemonic: "inc",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rdx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 1, // assign + 5 flag assignments
			wantErr: false,
		},
		{
			name: "dec rsi",
			insn: &disasm.Instruction{
				Address:  0x100a,
				Mnemonic: "dec",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rsi", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 1, // assign + 5 flag assignments
			wantErr: false,
		},
		{
			name: "neg rdi",
			insn: &disasm.Instruction{
				Address:  0x100d,
				Mnemonic: "neg",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rdi", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 1, // assign + 5 flag assignments
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
				t.Errorf("LiftInstruction() got %d ops, want %d ops", len(result), tt.wantOps)
				for i, op := range result {
					t.Logf("  [%d] %s", i, op.String())
				}
			}
		})
	}
}

// TestLifterLogical tests lifting of logical operations.
func TestLifterLogical(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantOps int
		wantErr bool
	}{
		{
			name: "and rax, rbx",
			insn: &disasm.Instruction{
				Address:  0x2000,
				Mnemonic: "and",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 1, // assign + 5 flag assignments
			wantErr: false,
		},
		{
			name: "or rcx, rdx",
			insn: &disasm.Instruction{
				Address:  0x2003,
				Mnemonic: "or",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rcx", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rdx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 1,
			wantErr: false,
		},
		{
			name: "xor rsi, rsi",
			insn: &disasm.Instruction{
				Address:  0x2006,
				Mnemonic: "xor",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rsi", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rsi", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 1,
			wantErr: false,
		},
		{
			name: "not rdi",
			insn: &disasm.Instruction{
				Address:  0x2009,
				Mnemonic: "not",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rdi", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 1, // not does not affect flags
			wantErr: false,
		},
		{
			name: "test rax, rax",
			insn: &disasm.Instruction{
				Address:  0x200c,
				Mnemonic: "test",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 0, // 5 flag assignments (no result stored)
			wantErr: false,
		},
		{
			name: "cmp rax, rbx",
			insn: &disasm.Instruction{
				Address:  0x200f,
				Mnemonic: "cmp",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 0, // 5 flag assignments (no result stored)
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
				t.Errorf("LiftInstruction() got %d ops, want %d ops", len(result), tt.wantOps)
			}
		})
	}
}

// TestLifterMemory tests lifting of memory operations.
func TestLifterMemory(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantOps int
		wantErr bool
	}{
		{
			name: "mov rax, rbx",
			insn: &disasm.Instruction{
				Address:  0x3000,
				Mnemonic: "mov",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 1, // single assign
			wantErr: false,
		},
		{
			name: "mov rax, [rbx]",
			insn: &disasm.Instruction{
				Address:  0x3003,
				Mnemonic: "mov",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.MemoryOperand{
						Base: "rbx",
						Size: disasm.Size64,
					},
				},
				Length: 3,
			},
			wantOps: 2, // load + assign
			wantErr: false,
		},
		{
			name: "mov [rax], rbx",
			insn: &disasm.Instruction{
				Address:  0x3006,
				Mnemonic: "mov",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{
						Base: "rax",
						Size: disasm.Size64,
					},
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantOps: 1, // store
			wantErr: false,
		},
		{
			name: "lea rax, [rbx + rcx*4 + 0x10]",
			insn: &disasm.Instruction{
				Address:  0x3009,
				Mnemonic: "lea",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.MemoryOperand{
						Base:  "rbx",
						Index: "rcx",
						Scale: 4,
						Disp:  0x10,
						Size:  disasm.Size64,
					},
				},
				Length: 4,
			},
			wantOps: 1, // single assign (address computation)
			wantErr: false,
		},
		{
			name: "push rax",
			insn: &disasm.Instruction{
				Address:  0x300d,
				Mnemonic: "push",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				},
				Length: 1,
			},
			wantOps: 2, // rsp -= 8, store
			wantErr: false,
		},
		{
			name: "pop rax",
			insn: &disasm.Instruction{
				Address:  0x300e,
				Mnemonic: "pop",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				},
				Length: 1,
			},
			wantOps: 3, // load, rsp += 8, assign
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
				t.Errorf("LiftInstruction() got %d ops, want %d ops", len(result), tt.wantOps)
				for i, op := range result {
					t.Logf("  [%d] %s", i, op.String())
				}
			}
		})
	}
}

// TestLifterControlFlow tests lifting of control flow operations.
//
//nolint:dupl // test struct repetition
func TestLifterControlFlow(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantOps int
		wantErr bool
	}{
		{
			name: "jmp 0x4100",
			insn: &disasm.Instruction{
				Address:  0x4000,
				Mnemonic: "jmp",
				Operands: []disasm.Operand{
					disasm.ImmediateOperand{Value: 0x4100, Size: disasm.Size64},
				},
				Length: 5,
			},
			wantOps: 1, // jump
			wantErr: false,
		},
		{
			name: "je 0x4100",
			insn: &disasm.Instruction{
				Address:  0x4005,
				Mnemonic: "je",
				Operands: []disasm.Operand{
					disasm.ImmediateOperand{Value: 0x4100, Size: disasm.Size64},
				},
				Length: 2,
			},
			wantOps: 1, // branch
			wantErr: false,
		},
		{
			name: "jne 0x4100",
			insn: &disasm.Instruction{
				Address:  0x4007,
				Mnemonic: "jne",
				Operands: []disasm.Operand{
					disasm.ImmediateOperand{Value: 0x4100, Size: disasm.Size64},
				},
				Length: 2,
			},
			wantOps: 1, // branch
			wantErr: false,
		},
		{
			name: "call 0x5000",
			insn: &disasm.Instruction{
				Address:  0x4009,
				Mnemonic: "call",
				Operands: []disasm.Operand{
					disasm.ImmediateOperand{Value: 0x5000, Size: disasm.Size64},
				},
				Length: 5,
			},
			wantOps: 1, // single abstract Call node (rsp manipulation suppressed)
			wantErr: false,
		},
		{
			name: "ret",
			insn: &disasm.Instruction{
				Address:  0x400e,
				Mnemonic: "ret",
				Operands: []disasm.Operand{},
				Length:   1,
			},
			wantOps: 1, // single abstract Return node (rsp manipulation suppressed)
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
				t.Errorf("LiftInstruction() got %d ops, want %d ops", len(result), tt.wantOps)
				for i, op := range result {
					t.Logf("  [%d] %s", i, op.String())
				}
			}
		})
	}
}

// TestLifterShift tests lifting of shift operations.
func TestLifterShift(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantOps int
		wantErr bool
	}{
		{
			name: "shl rax, 1",
			insn: &disasm.Instruction{
				Address:  0x5000,
				Mnemonic: "shl",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.ImmediateOperand{Value: 1, Size: disasm.Size8},
				},
				Length: 3,
			},
			wantOps: 1, // assign + 5 flag assignments
			wantErr: false,
		},
		{
			name: "shr rbx, cl",
			insn: &disasm.Instruction{
				Address:  0x5003,
				Mnemonic: "shr",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "cl", Size: disasm.Size8},
				},
				Length: 3,
			},
			wantOps: 1, // assign + 5 flag assignments
			wantErr: false,
		},
		{
			name: "sar rcx, 4",
			insn: &disasm.Instruction{
				Address:  0x5006,
				Mnemonic: "sar",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rcx", Size: disasm.Size64},
					disasm.ImmediateOperand{Value: 4, Size: disasm.Size8},
				},
				Length: 4,
			},
			wantOps: 1, // assign + 5 flag assignments
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
				t.Errorf("LiftInstruction() got %d ops, want %d ops", len(result), tt.wantOps)
			}
		})
	}
}

// TestLifterUnsupported tests that unsupported instructions are handled gracefully.
// unknown mnemonics produce an empty ir block (no error) to preserve control flow.
func TestLifterUnsupported(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantErr bool
	}{
		{
			name: "unsupported instruction returns empty block",
			insn: &disasm.Instruction{
				Address:  0x6000,
				Mnemonic: "foobar",
				Operands: []disasm.Operand{},
				Length:   1,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifter := NewLifter()
			result, err := lifter.LiftInstruction(tt.insn)

			if (err != nil) != tt.wantErr {
				t.Errorf("LiftInstruction() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && len(result) != 0 {
				t.Errorf("LiftInstruction() returned %d instructions for unknown mnemonic, want 0", len(result))
			}
		})
	}
}
