package ir

import (
	"strings"
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

func TestLifterSubRegisterAliasing_32BitZeroExtend(t *testing.T) {
	tests := []struct {
		name       string
		insn       *disasm.Instruction
		wantParent string
		wantZext   bool
	}{
		{
			name: "mov eax, ebx zeros upper 32 bits of rax",
			insn: &disasm.Instruction{
				Address:  0x1000,
				Mnemonic: "mov",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "eax", Size: disasm.Size32},
					disasm.RegisterOperand{Name: "ebx", Size: disasm.Size32},
				},
				Length: 2,
			},
			wantParent: "rax",
			wantZext:   true,
		},
		{
			name: "mov ecx, 0x42 zeros upper 32 bits of rcx",
			insn: &disasm.Instruction{
				Address:  0x1005,
				Mnemonic: "mov",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "ecx", Size: disasm.Size32},
					disasm.ImmediateOperand{Value: 0x42, Size: disasm.Size32},
				},
				Length: 5,
			},
			wantParent: "rcx",
			wantZext:   true,
		},
		{
			name: "mov r8d, edx zeros upper 32 bits of r8",
			insn: &disasm.Instruction{
				Address:  0x100a,
				Mnemonic: "mov",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "r8d", Size: disasm.Size32},
					disasm.RegisterOperand{Name: "edx", Size: disasm.Size32},
				},
				Length: 3,
			},
			wantParent: "r8",
			wantZext:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifter := NewLifter()
			result, err := lifter.LiftInstruction(tt.insn)
			if err != nil {
				t.Fatalf("LiftInstruction() error = %v", err)
			}

			foundZext := false
			foundParentAssign := false
			for _, instr := range result {
				assign, ok := AsAssign(instr)
				if !ok {
					continue
				}
				if assign.Dest.Name == tt.wantParent {
					foundParentAssign = true
					if _, isZext := assign.Source.(ZeroExtend); isZext {
						foundZext = true
					}
				}
			}

			if tt.wantZext && !foundZext {
				t.Errorf("expected ZeroExtend to parent %q, not found in IR", tt.wantParent)
				for i, op := range result {
					t.Logf("  [%d] %s", i, op.String())
				}
			}
			if !foundParentAssign {
				t.Errorf("expected assignment to parent register %q, not found", tt.wantParent)
				for i, op := range result {
					t.Logf("  [%d] %s", i, op.String())
				}
			}
		})
	}
}

func TestLifterSubRegisterAliasing_8BitInsert(t *testing.T) {
	tests := []struct {
		name       string
		insn       *disasm.Instruction
		wantParent string
		wantOffset uint8
	}{
		{
			name: "mov al, 0xFF preserves upper bits of rax via insert",
			insn: &disasm.Instruction{
				Address:  0x2000,
				Mnemonic: "mov",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "al", Size: disasm.Size8},
					disasm.ImmediateOperand{Value: 0xFF, Size: disasm.Size8},
				},
				Length: 2,
			},
			wantParent: "rax",
			wantOffset: 0,
		},
		{
			name: "mov ah, 0x42 preserves bits 0-7 and 16-63 of rax",
			insn: &disasm.Instruction{
				Address:  0x2002,
				Mnemonic: "mov",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "ah", Size: disasm.Size8},
					disasm.ImmediateOperand{Value: 0x42, Size: disasm.Size8},
				},
				Length: 2,
			},
			wantParent: "rax",
			wantOffset: 1,
		},
		{
			name: "mov bl, cl preserves upper bits of rbx",
			insn: &disasm.Instruction{
				Address:  0x2004,
				Mnemonic: "mov",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "bl", Size: disasm.Size8},
					disasm.RegisterOperand{Name: "cl", Size: disasm.Size8},
				},
				Length: 2,
			},
			wantParent: "rbx",
			wantOffset: 0,
		},
		{
			name: "mov sil, 0x10 preserves upper bits of rsi",
			insn: &disasm.Instruction{
				Address:  0x2006,
				Mnemonic: "mov",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "sil", Size: disasm.Size8},
					disasm.ImmediateOperand{Value: 0x10, Size: disasm.Size8},
				},
				Length: 3,
			},
			wantParent: "rsi",
			wantOffset: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifter := NewLifter()
			result, err := lifter.LiftInstruction(tt.insn)
			if err != nil {
				t.Fatalf("LiftInstruction() error = %v", err)
			}

			foundInsert := false
			for _, instr := range result {
				assign, ok := AsAssign(instr)
				if !ok {
					continue
				}
				if assign.Dest.Name == tt.wantParent {
					ins, isInsert := assign.Source.(Insert)
					if isInsert {
						foundInsert = true
						if ins.Offset != tt.wantOffset {
							t.Errorf("Insert offset = %d, want %d", ins.Offset, tt.wantOffset)
						}
						if ins.Dest.Name != tt.wantParent {
							t.Errorf("Insert dest = %q, want %q", ins.Dest.Name, tt.wantParent)
						}
					}
				}
			}

			if !foundInsert {
				t.Errorf("expected Insert into parent %q with offset %d, not found", tt.wantParent, tt.wantOffset)
				for i, op := range result {
					t.Logf("  [%d] %s", i, op.String())
				}
			}
		})
	}
}

func TestLifterSubRegisterAliasing_16BitInsert(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x3000,
		Mnemonic: "mov",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "ax", Size: disasm.Size16},
			disasm.ImmediateOperand{Value: 0x1234, Size: disasm.Size16},
		},
		Length: 4,
	}

	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	foundInsert := false
	for _, instr := range result {
		assign, ok := AsAssign(instr)
		if !ok {
			continue
		}
		if assign.Dest.Name == "rax" {
			ins, isInsert := assign.Source.(Insert)
			if isInsert {
				foundInsert = true
				if ins.Offset != 0 {
					t.Errorf("Insert offset = %d, want 0", ins.Offset)
				}
				if ins.Size != Size2 {
					t.Errorf("Insert size = %d, want %d", ins.Size, Size2)
				}
			}
		}
	}

	if !foundInsert {
		t.Error("expected Insert into rax for 16-bit ax write, not found")
		for i, op := range result {
			t.Logf("  [%d] %s", i, op.String())
		}
	}
}

func TestLifterSubRegisterAliasing_64BitDirect(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x4000,
		Mnemonic: "mov",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
		},
		Length: 3,
	}

	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 IR instruction, got %d", len(result))
	}

	assign, ok := AsAssign(result[0])
	if !ok {
		t.Fatalf("expected Assign, got %T", result[0])
	}

	if assign.Dest.Name != "rax" {
		t.Errorf("dest = %q, want rax", assign.Dest.Name)
	}

	if _, isZext := assign.Source.(ZeroExtend); isZext {
		t.Error("64-bit write should NOT produce ZeroExtend")
	}
	if _, isInsert := assign.Source.(Insert); isInsert {
		t.Error("64-bit write should NOT produce Insert")
	}
}

func TestLifterMemoryAddressCalculation(t *testing.T) {
	tests := []struct {
		name     string
		insn     *disasm.Instruction
		wantAddr string
	}{
		{
			name: "lea rax, [rbx] base only",
			insn: &disasm.Instruction{
				Address:  0x5000,
				Mnemonic: "lea",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.MemoryOperand{Base: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantAddr: "rbx",
		},
		{
			name: "lea rax, [rbx + 0x10] base + displacement",
			insn: &disasm.Instruction{
				Address:  0x5003,
				Mnemonic: "lea",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.MemoryOperand{Base: "rbx", Disp: 0x10, Size: disasm.Size64},
				},
				Length: 4,
			},
			wantAddr: "(rbx + 16)",
		},
		{
			name: "lea rax, [rbx + rcx*4] base + index*scale",
			insn: &disasm.Instruction{
				Address:  0x5007,
				Mnemonic: "lea",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.MemoryOperand{Base: "rbx", Index: "rcx", Scale: 4, Size: disasm.Size64},
				},
				Length: 4,
			},
			wantAddr: "(rbx + (rcx * 4))",
		},
		{
			name: "lea rax, [rbx + rcx*8 + 0x20] full SIB",
			insn: &disasm.Instruction{
				Address:  0x500b,
				Mnemonic: "lea",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.MemoryOperand{Base: "rbx", Index: "rcx", Scale: 8, Disp: 0x20, Size: disasm.Size64},
				},
				Length: 5,
			},
			wantAddr: "((rbx + (rcx * 8)) + 32)",
		},
		{
			name: "lea rax, [rcx*2] index*scale only",
			insn: &disasm.Instruction{
				Address:  0x5010,
				Mnemonic: "lea",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.MemoryOperand{Index: "rcx", Scale: 2, Size: disasm.Size64},
				},
				Length: 4,
			},
			wantAddr: "(rcx * 2)",
		},
		{
			name: "lea rax, [rcx*1] index*1 no multiply",
			insn: &disasm.Instruction{
				Address:  0x5014,
				Mnemonic: "lea",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.MemoryOperand{Index: "rcx", Scale: 1, Size: disasm.Size64},
				},
				Length: 3,
			},
			wantAddr: "rcx",
		},
		{
			name: "lea rax, [0x401000] displacement only",
			insn: &disasm.Instruction{
				Address:  0x5018,
				Mnemonic: "lea",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.MemoryOperand{Disp: 0x401000, Size: disasm.Size64},
				},
				Length: 7,
			},
			wantAddr: "4198400",
		},
		{
			name: "lea rax, [rbx - 0x8] negative displacement",
			insn: &disasm.Instruction{
				Address:  0x501f,
				Mnemonic: "lea",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.MemoryOperand{Base: "rbx", Disp: -8, Size: disasm.Size64},
				},
				Length: 4,
			},
			wantAddr: "(rbx + -8)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifter := NewLifter()
			result, err := lifter.LiftInstruction(tt.insn)
			if err != nil {
				t.Fatalf("LiftInstruction() error = %v", err)
			}

			if len(result) != 1 {
				t.Fatalf("expected 1 IR instruction, got %d", len(result))
			}

			assign, ok := AsAssign(result[0])
			if !ok {
				t.Fatalf("expected Assign, got %T", result[0])
			}

			gotAddr := assign.Source.String()
			if gotAddr != tt.wantAddr {
				t.Errorf("address expression = %q, want %q", gotAddr, tt.wantAddr)
			}
		})
	}
}

func TestLifterMemoryLoadAddress(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x6000,
		Mnemonic: "mov",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.MemoryOperand{Base: "rbp", Disp: -0x18, Size: disasm.Size64},
		},
		Length: 4,
	}

	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	if len(result) < 1 {
		t.Fatal("expected at least 1 IR instruction")
	}

	load, ok := AsLoad(result[0])
	if !ok {
		t.Fatalf("expected Load as first instruction, got %T", result[0])
	}

	addrStr := load.Address.String()
	if !strings.Contains(addrStr, "rbp") {
		t.Errorf("load address should reference rbp, got %q", addrStr)
	}
	if !strings.Contains(addrStr, "-24") {
		t.Errorf("load address should contain displacement -24, got %q", addrStr)
	}
	if load.Size != Size8 {
		t.Errorf("load size = %d, want %d", load.Size, Size8)
	}
}

func TestLifterMemoryStoreAddress(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x6010,
		Mnemonic: "mov",
		Operands: []disasm.Operand{
			disasm.MemoryOperand{Base: "rsp", Disp: 0x10, Size: disasm.Size32},
			disasm.RegisterOperand{Name: "eax", Size: disasm.Size32},
		},
		Length: 4,
	}

	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 IR instruction, got %d", len(result))
	}

	store, ok := AsStore(result[0])
	if !ok {
		t.Fatalf("expected Store, got %T", result[0])
	}

	addrStr := store.Address.String()
	if !strings.Contains(addrStr, "rsp") {
		t.Errorf("store address should reference rsp, got %q", addrStr)
	}
	if !strings.Contains(addrStr, "16") {
		t.Errorf("store address should contain displacement 16, got %q", addrStr)
	}
	if store.Size != Size4 {
		t.Errorf("store size = %d, want %d", store.Size, Size4)
	}
}

func TestLifterImplicitOperands_Push(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x7000,
		Mnemonic: "push",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
		},
		Length: 1,
	}

	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("push should produce 2 IR instructions (rsp decrement + store), got %d", len(result))
		for i, op := range result {
			t.Logf("  [%d] %s", i, op.String())
		}
	}

	rspAssign, ok := AsAssign(result[0])
	if !ok {
		t.Fatalf("first instruction should be Assign (rsp decrement), got %T", result[0])
	}
	if rspAssign.Dest.Name != "rsp" {
		t.Errorf("first instruction dest = %q, want rsp", rspAssign.Dest.Name)
	}

	binOp, ok := rspAssign.Source.(BinaryOp)
	if !ok {
		t.Fatalf("rsp decrement source should be BinaryOp, got %T", rspAssign.Source)
	}
	if binOp.Op != BinOpSub {
		t.Errorf("rsp operation = %v, want Sub", binOp.Op)
	}

	store, ok := AsStore(result[1])
	if !ok {
		t.Fatalf("second instruction should be Store, got %T", result[1])
	}

	storeAddrStr := store.Address.String()
	if !strings.Contains(storeAddrStr, "rsp") {
		t.Errorf("store address should reference rsp, got %q", storeAddrStr)
	}
	if store.Size != Size8 {
		t.Errorf("store size = %d, want %d (64-bit push)", store.Size, Size8)
	}
}

func TestLifterImplicitOperands_Pop(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x7001,
		Mnemonic: "pop",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
		},
		Length: 1,
	}

	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	if len(result) != 3 {
		t.Fatalf("pop should produce 3 IR instructions (load + rsp increment + assign), got %d", len(result))
		for i, op := range result {
			t.Logf("  [%d] %s", i, op.String())
		}
	}

	load, ok := AsLoad(result[0])
	if !ok {
		t.Fatalf("first instruction should be Load, got %T", result[0])
	}
	loadAddrStr := load.Address.String()
	if !strings.Contains(loadAddrStr, "rsp") {
		t.Errorf("load address should reference rsp, got %q", loadAddrStr)
	}
	if load.Size != Size8 {
		t.Errorf("load size = %d, want %d", load.Size, Size8)
	}

	rspAssign, ok := AsAssign(result[1])
	if !ok {
		t.Fatalf("second instruction should be Assign (rsp increment), got %T", result[1])
	}
	if rspAssign.Dest.Name != "rsp" {
		t.Errorf("second instruction dest = %q, want rsp", rspAssign.Dest.Name)
	}
	binOp, ok := rspAssign.Source.(BinaryOp)
	if !ok {
		t.Fatalf("rsp increment source should be BinaryOp, got %T", rspAssign.Source)
	}
	if binOp.Op != BinOpAdd {
		t.Errorf("rsp operation = %v, want Add", binOp.Op)
	}

	destAssign, ok := AsAssign(result[2])
	if !ok {
		t.Fatalf("third instruction should be Assign (dest = loaded value), got %T", result[2])
	}
	if destAssign.Dest.Name != "rbx" {
		t.Errorf("third instruction dest = %q, want rbx", destAssign.Dest.Name)
	}
}

func TestLifterImplicitOperands_Call(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x7010,
		Mnemonic: "call",
		Operands: []disasm.Operand{
			disasm.ImmediateOperand{Value: 0x401000, Size: disasm.Size64},
		},
		Length: 5,
	}

	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("call should produce 1 abstract Call node (rsp manipulation suppressed), got %d", len(result))
	}

	callInstr, ok := result[0].(*Call)
	if !ok {
		t.Fatalf("expected *Call, got %T", result[0])
	}

	if callInstr.Dest != nil {
		t.Error("Call.Dest should be nil (populated by ABI analyzer)")
	}
	if callInstr.Args != nil {
		t.Error("Call.Args should be nil (populated by ABI analyzer)")
	}
}

func TestLifterImplicitOperands_Ret(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x7020,
		Mnemonic: "ret",
		Operands: []disasm.Operand{},
		Length:   1,
	}

	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("ret should produce 1 abstract Return node, got %d", len(result))
	}

	retInstr, ok := result[0].(*Return)
	if !ok {
		t.Fatalf("expected *Return, got %T", result[0])
	}

	if retInstr.Value != nil {
		t.Error("Return.Value should be nil (populated by ABI analyzer)")
	}
}

func TestLifterImplicitOperands_Leave(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x7030,
		Mnemonic: "leave",
		Operands: []disasm.Operand{},
		Length:   1,
	}

	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	if len(result) != 4 {
		t.Fatalf("leave should produce 4 IR instructions (rsp=rbp, load [rsp], rbp=loaded, rsp+=8), got %d", len(result))
		for i, op := range result {
			t.Logf("  [%d] %s", i, op.String())
		}
	}

	rspFromRbp, ok := AsAssign(result[0])
	if !ok {
		t.Fatalf("first instruction should be Assign, got %T", result[0])
	}
	if rspFromRbp.Dest.Name != "rsp" {
		t.Errorf("first instruction dest = %q, want rsp", rspFromRbp.Dest.Name)
	}
	srcVar, ok := rspFromRbp.Source.(VariableExpr)
	if !ok {
		t.Fatalf("rsp source should be VariableExpr, got %T", rspFromRbp.Source)
	}
	if srcVar.Var.Name != "rbp" {
		t.Errorf("rsp source = %q, want rbp", srcVar.Var.Name)
	}

	_, ok = AsLoad(result[1])
	if !ok {
		t.Fatalf("second instruction should be Load, got %T", result[1])
	}

	rbpAssign, ok := AsAssign(result[2])
	if !ok {
		t.Fatalf("third instruction should be Assign, got %T", result[2])
	}
	if rbpAssign.Dest.Name != "rbp" {
		t.Errorf("third instruction dest = %q, want rbp", rbpAssign.Dest.Name)
	}

	rspInc, ok := AsAssign(result[3])
	if !ok {
		t.Fatalf("fourth instruction should be Assign, got %T", result[3])
	}
	if rspInc.Dest.Name != "rsp" {
		t.Errorf("fourth instruction dest = %q, want rsp", rspInc.Dest.Name)
	}
}

func TestLifterImplicitOperands_Mul(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x8000,
		Mnemonic: "mul",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
		},
		Length: 3,
	}

	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	foundRaxAssign := false
	foundRdxAssign := false
	for _, instr := range result {
		assign, ok := AsAssign(instr)
		if !ok {
			continue
		}
		switch assign.Dest.Name {
		case "rax":
			foundRaxAssign = true
			binOp, ok := assign.Source.(BinaryOp)
			if !ok {
				t.Errorf("rax source should be BinaryOp, got %T", assign.Source)
				continue
			}
			if binOp.Op != BinOpMul {
				t.Errorf("rax operation = %v, want Mul", binOp.Op)
			}
		case "rdx":
			foundRdxAssign = true
		}
	}

	if !foundRaxAssign {
		t.Error("mul should produce implicit assignment to rax (low result)")
	}
	if !foundRdxAssign {
		t.Error("mul should produce implicit assignment to rdx (high result)")
	}
}

func TestLifterImplicitOperands_Div(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x8010,
		Mnemonic: "div",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rcx", Size: disasm.Size64},
		},
		Length: 3,
	}

	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	foundRaxAssign := false
	foundRdxAssign := false
	for _, instr := range result {
		assign, ok := AsAssign(instr)
		if !ok {
			continue
		}
		switch assign.Dest.Name {
		case "rax":
			foundRaxAssign = true
			binOp, ok := assign.Source.(BinaryOp)
			if !ok {
				t.Errorf("rax source should be BinaryOp, got %T", assign.Source)
				continue
			}
			if binOp.Op != BinOpUDiv {
				t.Errorf("rax operation = %v, want UDiv", binOp.Op)
			}
		case "rdx":
			foundRdxAssign = true
			binOp, ok := assign.Source.(BinaryOp)
			if !ok {
				t.Errorf("rdx source should be BinaryOp, got %T", assign.Source)
				continue
			}
			if binOp.Op != BinOpUMod {
				t.Errorf("rdx operation = %v, want UMod", binOp.Op)
			}
		}
	}

	if !foundRaxAssign {
		t.Error("div should produce implicit assignment to rax (quotient)")
	}
	if !foundRdxAssign {
		t.Error("div should produce implicit assignment to rdx (remainder)")
	}
}

func TestLifterImplicitOperands_Cdqe(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x8020,
		Mnemonic: "cdqe",
		Operands: []disasm.Operand{},
		Length:   1,
	}

	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("cdqe should produce 1 IR instruction, got %d", len(result))
	}

	assign, ok := AsAssign(result[0])
	if !ok {
		t.Fatalf("expected Assign, got %T", result[0])
	}
	if assign.Dest.Name != "rax" {
		t.Errorf("dest = %q, want rax", assign.Dest.Name)
	}

	cast, ok := assign.Source.(Cast)
	if !ok {
		t.Fatalf("source should be Cast, got %T", assign.Source)
	}
	targetInt, ok := cast.TargetType.(IntType)
	if !ok {
		t.Fatalf("cast target should be IntType, got %T", cast.TargetType)
	}
	if targetInt.Width != Size8 {
		t.Errorf("cast target width = %d, want %d", targetInt.Width, Size8)
	}
	if !targetInt.Signed {
		t.Error("cdqe cast should be signed extension")
	}
}

func TestLifterImplicitOperands_Cqo(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x8030,
		Mnemonic: "cqo",
		Operands: []disasm.Operand{},
		Length:   2,
	}

	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("cqo should produce 1 IR instruction, got %d", len(result))
	}

	assign, ok := AsAssign(result[0])
	if !ok {
		t.Fatalf("expected Assign, got %T", result[0])
	}
	if assign.Dest.Name != "rdx" {
		t.Errorf("dest = %q, want rdx", assign.Dest.Name)
	}

	binOp, ok := assign.Source.(BinaryOp)
	if !ok {
		t.Fatalf("source should be BinaryOp (sar), got %T", assign.Source)
	}
	if binOp.Op != BinOpSar {
		t.Errorf("operation = %v, want Sar", binOp.Op)
	}
}

func TestLifterSemanticEquivalence_AddSubIdentity(t *testing.T) {
	lifter := NewLifter()

	addInsn := &disasm.Instruction{
		Address:  0x9000,
		Mnemonic: "add",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.ImmediateOperand{Value: 0, Size: disasm.Size64},
		},
		Length: 3,
	}

	result, err := lifter.LiftInstruction(addInsn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	if len(result) < 1 {
		t.Fatal("expected at least 1 IR instruction")
	}

	assign, ok := AsAssign(result[0])
	if !ok {
		t.Fatalf("expected Assign, got %T", result[0])
	}

	binOp, ok := assign.Source.(BinaryOp)
	if !ok {
		t.Fatalf("source should be BinaryOp, got %T", assign.Source)
	}

	if binOp.Op != BinOpAdd {
		t.Errorf("operation = %v, want Add", binOp.Op)
	}

	rightConst, ok := binOp.Right.(ConstantExpr)
	if !ok {
		t.Fatalf("right operand should be ConstantExpr, got %T", binOp.Right)
	}
	intConst, ok := rightConst.Value.(IntConstant)
	if !ok {
		t.Fatalf("constant should be IntConstant, got %T", rightConst.Value)
	}
	if intConst.Value != 0 {
		t.Errorf("add 0 should have constant 0, got %d", intConst.Value)
	}
}

func TestLifterSemanticEquivalence_XorSelfIsZero(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0x9010,
		Mnemonic: "xor",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
		},
		Length: 3,
	}

	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	if len(result) < 1 {
		t.Fatal("expected at least 1 IR instruction")
	}

	assign, ok := AsAssign(result[0])
	if !ok {
		t.Fatalf("expected Assign, got %T", result[0])
	}

	binOp, ok := assign.Source.(BinaryOp)
	if !ok {
		t.Fatalf("source should be BinaryOp, got %T", assign.Source)
	}

	if binOp.Op != BinOpXor {
		t.Errorf("operation = %v, want Xor", binOp.Op)
	}

	leftVar, ok := binOp.Left.(VariableExpr)
	if !ok {
		t.Fatalf("left should be VariableExpr, got %T", binOp.Left)
	}
	rightVar, ok := binOp.Right.(VariableExpr)
	if !ok {
		t.Fatalf("right should be VariableExpr, got %T", binOp.Right)
	}

	if leftVar.Var.Name != rightVar.Var.Name {
		t.Errorf("xor self: left=%q right=%q, should be same register", leftVar.Var.Name, rightVar.Var.Name)
	}
}

func TestLifterSemanticEquivalence_ArithmeticOperators(t *testing.T) {
	tests := []struct {
		mnemonic string
		wantOp   BinaryOperator
	}{
		{"add", BinOpAdd},
		{"sub", BinOpSub},
		{"and", BinOpAnd},
		{"or", BinOpOr},
		{"xor", BinOpXor},
		{"shl", BinOpShl},
		{"shr", BinOpShr},
		{"sar", BinOpSar},
	}

	for _, tt := range tests {
		t.Run(tt.mnemonic, func(t *testing.T) {
			lifter := NewLifter()
			insn := &disasm.Instruction{
				Address:  0xA000,
				Mnemonic: tt.mnemonic,
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			}

			result, err := lifter.LiftInstruction(insn)
			if err != nil {
				t.Fatalf("LiftInstruction() error = %v", err)
			}

			if len(result) < 1 {
				t.Fatal("expected at least 1 IR instruction")
			}

			assign, ok := AsAssign(result[0])
			if !ok {
				t.Fatalf("expected Assign, got %T", result[0])
			}

			binOp, ok := assign.Source.(BinaryOp)
			if !ok {
				t.Fatalf("source should be BinaryOp, got %T", assign.Source)
			}

			if binOp.Op != tt.wantOp {
				t.Errorf("operation = %v, want %v", binOp.Op, tt.wantOp)
			}
		})
	}
}

func TestLifterSemanticEquivalence_UnaryOperators(t *testing.T) {
	tests := []struct {
		mnemonic string
		wantOp   UnaryOperator
	}{
		{"neg", UnOpNeg},
		{"not", UnOpNot},
	}

	for _, tt := range tests {
		t.Run(tt.mnemonic, func(t *testing.T) {
			lifter := NewLifter()
			insn := &disasm.Instruction{
				Address:  0xA100,
				Mnemonic: tt.mnemonic,
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				},
				Length: 3,
			}

			result, err := lifter.LiftInstruction(insn)
			if err != nil {
				t.Fatalf("LiftInstruction() error = %v", err)
			}

			if len(result) < 1 {
				t.Fatal("expected at least 1 IR instruction")
			}

			assign, ok := AsAssign(result[0])
			if !ok {
				t.Fatalf("expected Assign, got %T", result[0])
			}

			unaryOp, ok := assign.Source.(UnaryOp)
			if !ok {
				t.Fatalf("source should be UnaryOp, got %T", assign.Source)
			}

			if unaryOp.Op != tt.wantOp {
				t.Errorf("operation = %v, want %v", unaryOp.Op, tt.wantOp)
			}
		})
	}
}

func TestLifterSemanticEquivalence_IncDecAreAddSub(t *testing.T) {
	tests := []struct {
		mnemonic string
		wantOp   BinaryOperator
	}{
		{"inc", BinOpAdd},
		{"dec", BinOpSub},
	}

	for _, tt := range tests {
		t.Run(tt.mnemonic, func(t *testing.T) {
			lifter := NewLifter()
			insn := &disasm.Instruction{
				Address:  0xA200,
				Mnemonic: tt.mnemonic,
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rcx", Size: disasm.Size64},
				},
				Length: 3,
			}

			result, err := lifter.LiftInstruction(insn)
			if err != nil {
				t.Fatalf("LiftInstruction() error = %v", err)
			}

			if len(result) < 1 {
				t.Fatal("expected at least 1 IR instruction")
			}

			assign, ok := AsAssign(result[0])
			if !ok {
				t.Fatalf("expected Assign, got %T", result[0])
			}

			binOp, ok := assign.Source.(BinaryOp)
			if !ok {
				t.Fatalf("source should be BinaryOp, got %T", assign.Source)
			}

			if binOp.Op != tt.wantOp {
				t.Errorf("operation = %v, want %v", binOp.Op, tt.wantOp)
			}

			rightConst, ok := binOp.Right.(ConstantExpr)
			if !ok {
				t.Fatalf("right operand should be ConstantExpr, got %T", binOp.Right)
			}
			intConst, ok := rightConst.Value.(IntConstant)
			if !ok {
				t.Fatalf("constant should be IntConstant, got %T", rightConst.Value)
			}
			if intConst.Value != 1 {
				t.Errorf("inc/dec should use constant 1, got %d", intConst.Value)
			}
		})
	}
}

func TestLifterSemanticEquivalence_CmpTestNoResult(t *testing.T) {
	tests := []struct {
		mnemonic string
	}{
		{"cmp"},
		{"test"},
	}

	for _, tt := range tests {
		t.Run(tt.mnemonic, func(t *testing.T) {
			lifter := NewLifter()
			insn := &disasm.Instruction{
				Address:  0xA300,
				Mnemonic: tt.mnemonic,
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			}

			result, err := lifter.LiftInstruction(insn)
			if err != nil {
				t.Fatalf("LiftInstruction() error = %v", err)
			}

			for _, instr := range result {
				if assign, ok := AsAssign(instr); ok {
					if assign.Dest.Name == "rax" || assign.Dest.Name == "rbx" {
						t.Errorf("%s should not modify operand registers, found assignment to %q", tt.mnemonic, assign.Dest.Name)
					}
				}
				if _, ok := AsStore(instr); ok {
					t.Errorf("%s should not produce Store instructions", tt.mnemonic)
				}
			}
		})
	}
}

func TestLifterSemanticEquivalence_MemoryOperandArithmetic(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0xB000,
		Mnemonic: "add",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.MemoryOperand{Base: "rbp", Disp: -0x10, Size: disasm.Size64},
		},
		Length: 4,
	}

	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	if len(result) < 2 {
		t.Fatalf("add with memory source should produce at least 2 instructions (load + assign), got %d", len(result))
	}

	load, ok := AsLoad(result[0])
	if !ok {
		t.Fatalf("first instruction should be Load, got %T", result[0])
	}
	if load.Size != Size8 {
		t.Errorf("load size = %d, want %d", load.Size, Size8)
	}

	assign, ok := AsAssign(result[1])
	if !ok {
		t.Fatalf("second instruction should be Assign, got %T", result[1])
	}
	if assign.Dest.Name != "rax" {
		t.Errorf("assign dest = %q, want rax", assign.Dest.Name)
	}
}

func TestLifterSemanticEquivalence_StoreToMemory(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0xB010,
		Mnemonic: "add",
		Operands: []disasm.Operand{
			disasm.MemoryOperand{Base: "rbp", Disp: -0x8, Size: disasm.Size32},
			disasm.ImmediateOperand{Value: 1, Size: disasm.Size32},
		},
		Length: 4,
	}

	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	foundLoad := false
	foundStore := false
	for _, instr := range result {
		if _, ok := AsLoad(instr); ok {
			foundLoad = true
		}
		if _, ok := AsStore(instr); ok {
			foundStore = true
		}
	}

	if !foundLoad {
		t.Error("add [mem], imm should load from memory first")
	}
	if !foundStore {
		t.Error("add [mem], imm should store result back to memory")
	}
}

func TestLifterSourceLocationTraceability(t *testing.T) {
	lifter := NewLifter()
	insn := &disasm.Instruction{
		Address:  0xC000,
		Mnemonic: "mov",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.ImmediateOperand{Value: 42, Size: disasm.Size64},
		},
		Length: 7,
	}

	result, err := lifter.LiftInstruction(insn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	if len(result) < 1 {
		t.Fatal("expected at least 1 IR instruction")
	}

	loc := result[0].Location()
	if loc.Address != 0xC000 {
		t.Errorf("location address = 0x%x, want 0xC000", loc.Address)
	}
	if !strings.Contains(loc.Instruction, "mov") {
		t.Errorf("location instruction = %q, should contain 'mov'", loc.Instruction)
	}
}

func TestLifterLazyFlags(t *testing.T) {
	lifter := NewLifter()

	addInsn := &disasm.Instruction{
		Address:  0xD000,
		Mnemonic: "add",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
		},
		Length: 3,
	}

	_, err := lifter.LiftInstruction(addInsn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	lf := lifter.GetCurrentLazyFlags()
	if lf == nil {
		t.Fatal("lazy flags should be set after arithmetic instruction")
	}
	if lf.Operation != FlagOpArithmetic {
		t.Errorf("lazy flags operation = %v, want FlagOpArithmetic", lf.Operation)
	}

	lifter.ClearLazyFlags()
	if lifter.GetCurrentLazyFlags() != nil {
		t.Error("lazy flags should be nil after ClearLazyFlags()")
	}

	movInsn := &disasm.Instruction{
		Address:  0xD010,
		Mnemonic: "mov",
		Operands: []disasm.Operand{
			disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
		},
		Length: 3,
	}

	_, err = lifter.LiftInstruction(movInsn)
	if err != nil {
		t.Fatalf("LiftInstruction() error = %v", err)
	}

	if lifter.GetCurrentLazyFlags() != nil {
		t.Error("mov should not set lazy flags")
	}
}

func TestLifterErrorHandling(t *testing.T) {
	tests := []struct {
		name    string
		insn    *disasm.Instruction
		wantErr bool
	}{
		{
			name: "add with 0 operands",
			insn: &disasm.Instruction{
				Address: 0xE000, Mnemonic: "add", Operands: []disasm.Operand{}, Length: 1,
			},
			wantErr: true,
		},
		{
			name: "add with 1 operand",
			insn: &disasm.Instruction{
				Address: 0xE001, Mnemonic: "add",
				Operands: []disasm.Operand{disasm.RegisterOperand{Name: "rax", Size: disasm.Size64}},
				Length:   2,
			},
			wantErr: true,
		},
		{
			name: "push with 0 operands",
			insn: &disasm.Instruction{
				Address: 0xE002, Mnemonic: "push", Operands: []disasm.Operand{}, Length: 1,
			},
			wantErr: true,
		},
		{
			name: "pop with 0 operands",
			insn: &disasm.Instruction{
				Address: 0xE003, Mnemonic: "pop", Operands: []disasm.Operand{}, Length: 1,
			},
			wantErr: true,
		},
		{
			name: "lea with non-memory source",
			insn: &disasm.Instruction{
				Address: 0xE004, Mnemonic: "lea",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
					disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantErr: true,
		},
		{
			name: "mov mem to mem",
			insn: &disasm.Instruction{
				Address: 0xE005, Mnemonic: "mov",
				Operands: []disasm.Operand{
					disasm.MemoryOperand{Base: "rax", Size: disasm.Size64},
					disasm.MemoryOperand{Base: "rbx", Size: disasm.Size64},
				},
				Length: 3,
			},
			wantErr: true,
		},
		{
			name: "jmp indirect register",
			insn: &disasm.Instruction{
				Address: 0xE006, Mnemonic: "jmp",
				Operands: []disasm.Operand{
					disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				},
				Length: 2,
			},
			wantErr: true,
		},
		{
			name: "jcc non-immediate target",
			insn: &disasm.Instruction{
				Address: 0xE007, Mnemonic: "je",
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
