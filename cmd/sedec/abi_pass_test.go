package main

import (
	"testing"

	binfmt "github.com/zarazaex69/sedec/pkg/binary"
	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// makeConstExpr builds an ir.ConstantExpr holding an unsigned 64-bit address.
func makeConstExpr(addr uint64) ir.Expression {
	return ir.ConstantExpr{
		Value: ir.IntConstant{
			Value:  int64(addr),
			Width:  ir.Size8,
			Signed: false,
		},
	}
}

// makeVarExpr builds an ir.VariableExpr with the given name.
func makeVarExpr(name string) ir.Expression {
	return ir.VariableExpr{
		Var: ir.Variable{
			Name: name,
			Type: ir.IntType{Width: ir.Size8, Signed: false},
		},
	}
}

// TestResolveCallTarget verifies the five canonical cases for resolveCallTarget.
func TestResolveCallTarget(t *testing.T) {
	t.Run("case1_gotplt_and_symbols_printf", func(t *testing.T) {
		db := binfmt.NewGroundTruthDatabase()
		db.GOTPLT[0x401090] = 0x401090
		db.SymbolsByAddress[0x401090] = "printf"

		result := resolveCallTarget(makeConstExpr(0x401090), db)
		varExpr, ok := result.(ir.VariableExpr)
		if !ok {
			t.Fatalf("case1: expected ir.VariableExpr, got %T(%s)", result, result.String())
		}
		if varExpr.Var.Name != "printf" {
			t.Errorf("case1: expected Name=%q, got %q", "printf", varExpr.Var.Name)
		}
	})

	t.Run("case2_symbols_only_stack_chk_fail", func(t *testing.T) {
		db := binfmt.NewGroundTruthDatabase()
		db.SymbolsByAddress[0x401060] = "__stack_chk_fail"

		result := resolveCallTarget(makeConstExpr(0x401060), db)
		varExpr, ok := result.(ir.VariableExpr)
		if !ok {
			t.Fatalf("case2: expected ir.VariableExpr, got %T(%s)", result, result.String())
		}
		if varExpr.Var.Name != "__stack_chk_fail" {
			t.Errorf("case2: expected Name=%q, got %q", "__stack_chk_fail", varExpr.Var.Name)
		}
	})

	t.Run("case3_unknown_address_unchanged", func(t *testing.T) {
		db := binfmt.NewGroundTruthDatabase()
		result := resolveCallTarget(makeConstExpr(0xdeadbeef), db)

		constExpr, ok := result.(ir.ConstantExpr)
		if !ok {
			t.Fatalf("case3: expected ir.ConstantExpr, got %T(%s)", result, result.String())
		}
		intConst, ok := constExpr.Value.(ir.IntConstant)
		if !ok {
			t.Fatalf("case3: expected ir.IntConstant inside ConstantExpr")
		}
		// #nosec G115 — intentional conversion for address comparison
		if uint64(intConst.Value) != 0xdeadbeef {
			t.Errorf("case3: expected address 0xdeadbeef, got 0x%x", uint64(intConst.Value))
		}
	})

	t.Run("case4_indirect_call_register_unchanged", func(t *testing.T) {
		db := binfmt.NewGroundTruthDatabase()
		db.SymbolsByAddress[0x401090] = "printf"

		result := resolveCallTarget(makeVarExpr("rax"), db)
		varExpr, ok := result.(ir.VariableExpr)
		if !ok {
			t.Fatalf("case4: expected ir.VariableExpr, got %T(%s)", result, result.String())
		}
		if varExpr.Var.Name != "rax" {
			t.Errorf("case4: expected Name=%q (unchanged), got %q", "rax", varExpr.Var.Name)
		}
	})

	t.Run("case5_nil_database_unchanged", func(t *testing.T) {
		result := resolveCallTarget(makeConstExpr(0x401090), nil)

		constExpr, ok := result.(ir.ConstantExpr)
		if !ok {
			t.Fatalf("case5: expected ir.ConstantExpr, got %T(%s)", result, result.String())
		}
		intConst, ok := constExpr.Value.(ir.IntConstant)
		if !ok {
			t.Fatalf("case5: expected ir.IntConstant inside ConstantExpr")
		}
		// #nosec G115 — intentional conversion for address comparison
		if uint64(intConst.Value) != 0x401090 {
			t.Errorf("case5: expected address 0x401090, got 0x%x", uint64(intConst.Value))
		}
	})
}

// makeRegOp builds a disasm.RegisterOperand with the given name.
func makeRegOp(name string) disasm.RegisterOperand {
	return disasm.RegisterOperand{Name: name, Size: disasm.Size64}
}

// makeImmOp builds a disasm.ImmediateOperand with the given value.
func makeImmOp(val int64) disasm.ImmediateOperand {
	return disasm.ImmediateOperand{Value: val, Size: disasm.Size64}
}

// makeInsn builds a minimal disasm.Instruction for testing.
func makeInsn(addr disasm.Address, mnemonic string, ops ...disasm.Operand) *disasm.Instruction {
	return &disasm.Instruction{
		Address:  addr,
		Mnemonic: mnemonic,
		Operands: ops,
		Length:   4,
	}
}

// makeIRAssign builds a pointer-receiver ir.Assign at the given address.
func makeIRAssign(addr ir.Address, name string) *ir.Assign {
	return &ir.Assign{
		Dest:   ir.Variable{Name: name, Type: ir.IntType{Width: ir.Size8}},
		Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size8}},
	}
}

// setAssignAddr patches the Loc.Address on a *ir.Assign via the exported baseInstruction.
// ir.Assign embeds baseInstruction which has an exported Loc field.
func setAssignAddr(a *ir.Assign, addr ir.Address) {
	a.Loc.Address = addr
}

// TestMarkFrameArtifacts verifies that collectFrameArtifactAddresses correctly
// identifies frame prologue/epilogue instructions and that markFrameArtifacts
// sets IsFrameArtifact on the corresponding ir instructions.
func TestMarkFrameArtifacts(t *testing.T) {
	const (
		addrPushRbp   disasm.Address = 0x1000
		addrMovRbpRsp disasm.Address = 0x1001
		addrSubRsp    disasm.Address = 0x1004
		addrXorEax    disasm.Address = 0x1008
		addrPopRbp    disasm.Address = 0x100b
		addrRet       disasm.Address = 0x100c
	)

	rawInsns := []*disasm.Instruction{
		makeInsn(addrPushRbp, "push", makeRegOp("rbp")),
		makeInsn(addrMovRbpRsp, "mov", makeRegOp("rbp"), makeRegOp("rsp")),
		makeInsn(addrSubRsp, "sub", makeRegOp("rsp"), makeImmOp(0x20)),
		makeInsn(addrXorEax, "xor", makeRegOp("eax"), makeRegOp("eax")),
		makeInsn(addrPopRbp, "pop", makeRegOp("rbp")),
		makeInsn(addrRet, "ret"),
	}

	// build ir instructions with matching addresses
	aPushRbp := makeIRAssign(0, "rsp_push")
	setAssignAddr(aPushRbp, ir.Address(addrPushRbp))

	aMovRbpRsp := makeIRAssign(0, "rbp_mov")
	setAssignAddr(aMovRbpRsp, ir.Address(addrMovRbpRsp))

	aSubRsp := makeIRAssign(0, "rsp_sub")
	setAssignAddr(aSubRsp, ir.Address(addrSubRsp))

	aXorEax := makeIRAssign(0, "eax_xor")
	setAssignAddr(aXorEax, ir.Address(addrXorEax))

	aPopRbp := makeIRAssign(0, "rbp_pop")
	setAssignAddr(aPopRbp, ir.Address(addrPopRbp))

	aRet := makeIRAssign(0, "ret_instr")
	setAssignAddr(aRet, ir.Address(addrRet))

	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			aPushRbp, aMovRbpRsp, aSubRsp, aXorEax, aPopRbp, aRet,
		},
	}

	irFunc := &ir.Function{
		Name:       "test_func",
		EntryBlock: 0,
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
	}

	// collect frame artifact addresses
	frameAddrs := collectFrameArtifactAddresses(rawInsns, nil, nil)

	// verify expected addresses are in the set
	for _, addr := range []disasm.Address{addrPushRbp, addrMovRbpRsp, addrSubRsp, addrPopRbp} {
		if !frameAddrs[addr] {
			t.Errorf("expected address 0x%x to be a frame artifact", addr)
		}
	}
	// non-frame instructions must not be in the set
	for _, addr := range []disasm.Address{addrXorEax, addrRet} {
		if frameAddrs[addr] {
			t.Errorf("address 0x%x should NOT be a frame artifact", addr)
		}
	}

	// apply markFrameArtifacts and verify IsFrameArtifact flags
	markFrameArtifacts(irFunc, frameAddrs)

	frameExpected := map[disasm.Address]bool{
		addrPushRbp:   true,
		addrMovRbpRsp: true,
		addrSubRsp:    true,
		addrXorEax:    false,
		addrPopRbp:    true,
		addrRet:       false,
	}

	for _, instr := range block.Instructions {
		loc := instr.Location()
		addr := disasm.Address(loc.Address)
		expected, known := frameExpected[addr]
		if !known {
			continue
		}
		if loc.IsFrameArtifact != expected {
			t.Errorf("addr 0x%x: IsFrameArtifact=%v, want %v", addr, loc.IsFrameArtifact, expected)
		}
	}
}
