// package main — property-based test for defect 6:
// call targets that correspond to known symbols must be resolved to symbol names,
// not left as raw numeric address literals in the generated c output.
//
// **Validates: Requirements 2.11, 2.12**
//
// property 6 (bug condition): for all ir.Call nodes whose Target is a ConstantExpr
// containing an address present in GroundTruthDatabase.SymbolsByAddress (or GOTPLT),
// after applying the abi pass the Target MUST be an ir.VariableExpr whose Name equals
// the resolved symbol name.
//
// this test MUST FAIL on unfixed code — failure confirms the bug exists.
// the bug: applyABIPass(irFunc, rawInsns) does not accept a GroundTruthDatabase
// parameter and therefore never consults the GOT/PLT resolution map.
// the ir.Call.Target remains a ConstantExpr{Value: IntConstant{Value: 0x401090}}
// instead of being replaced with VariableExpr{Var: Variable{Name: "printf"}}.
//
// documented counterexample (from running on unfixed code):
// call target remains ConstantExpr{4198544} instead of VariableExpr{Name:"printf"} —
// the numeric address 0x401090 (4198544 decimal) is emitted verbatim as a c expression,
// producing "4198544(arg0, arg1);" which is syntactically invalid c and completely
// unreadable as decompiler output.
package main

import (
	"fmt"
	"testing"

	binfmt "github.com/zarazaex69/sedec/pkg/binary"
	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
	"pgregory.net/rapid"
)

// buildCallTargetIRFunction constructs a minimal ir.Function containing a single
// basic block with one ir.Call instruction whose Target is a ConstantExpr
// holding the given numeric address.
//
// this mirrors what the ir lifter produces for a "call 0x401090" instruction:
// the target address is encoded as an integer constant because the lifter
// does not have access to the symbol table at lift time.
func buildCallTargetIRFunction(callTargetAddr uint64) *ir.Function {
	// the call target is a raw numeric address — this is what the lifter emits
	targetExpr := ir.ConstantExpr{
		Value: ir.IntConstant{
			Value:  int64(callTargetAddr),
			Width:  ir.Size8,
			Signed: false,
		},
	}

	callInstr := ir.Call{
		Target: targetExpr,
		Args:   nil,
		Dest:   nil,
	}

	block := &ir.BasicBlock{
		ID:           0,
		Instructions: []ir.IRInstruction{callInstr},
		Predecessors: nil,
		Successors:   nil,
	}

	return &ir.Function{
		Name: "test_func",
		Signature: ir.FunctionType{
			ReturnType: ir.VoidType{},
			Parameters: nil,
		},
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		EntryBlock: 0,
		Variables:  nil,
	}
}

// buildGroundTruthDB constructs a GroundTruthDatabase with a single address→symbol mapping.
// this simulates the PLT/GOT resolution table extracted from the ELF binary.
func buildGroundTruthDB(addr uint64, symbolName string) *binfmt.GroundTruthDatabase {
	db := binfmt.NewGroundTruthDatabase()
	bAddr := binfmt.Address(addr)
	db.SymbolsByAddress[bAddr] = symbolName
	db.SymbolsByName[symbolName] = bAddr
	// also register in GOTPLT to cover the plt stub resolution path
	db.GOTPLT[bAddr] = bAddr
	return db
}

// buildCallRawInsns constructs a minimal raw instruction slice representing
// a "call <addr>" instruction at address 0x401000.
// the raw instruction stream is required by applyABIPass for abi analysis.
func buildCallRawInsns(callTargetAddr uint64) []*disasm.Instruction {
	return []*disasm.Instruction{
		{
			Mnemonic: "call",
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: int64(callTargetAddr)},
			},
			Address: 0x401000,
			Bytes:   []byte{0xe8, 0x00, 0x00, 0x00, 0x00},
			Length:  5,
		},
	}
}

// extractCallTarget walks the ir.Function and returns the Target expression
// of the first ir.Call instruction found, or nil if none exists.
func extractCallTarget(fn *ir.Function) ir.Expression {
	for _, block := range fn.Blocks {
		for _, instr := range block.Instructions {
			if callNode, ok := ir.AsCall(instr); ok {
				return callNode.Target
			}
		}
	}
	return nil
}

// isVariableExprWithName reports whether expr is an ir.VariableExpr whose
// variable name equals the expected symbol name.
func isVariableExprWithName(expr ir.Expression, expectedName string) bool {
	varExpr, ok := expr.(ir.VariableExpr)
	if !ok {
		return false
	}
	return varExpr.Var.Name == expectedName
}

// isConstantExprWithAddr reports whether expr is an ir.ConstantExpr whose
// integer value equals the given address.
func isConstantExprWithAddr(expr ir.Expression, addr uint64) bool {
	constExpr, ok := expr.(ir.ConstantExpr)
	if !ok {
		return false
	}
	intConst, ok := constExpr.Value.(ir.IntConstant)
	if !ok {
		return false
	}
	// #nosec G115 — intentional conversion for address comparison
	return uint64(intConst.Value) == addr
}

// TestProperty6_BugCondition_ConcreteCallToPrintf is the deterministic concrete test.
// it constructs an ir.Call targeting address 0x401090 (the printf PLT stub),
// registers "printf" in the GroundTruthDatabase at that address,
// calls applyABIPass (which does NOT accept a database on unfixed code),
// and asserts that the call target has been resolved to VariableExpr{Name:"printf"}.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// applyABIPass does not accept a GroundTruthDatabase parameter and therefore
// cannot resolve the numeric address to a symbol name.
// the call target remains ConstantExpr{4198544} (0x401090 in decimal).
//
// documented counterexample:
// call target remains ConstantExpr{4198544} instead of VariableExpr{Name:"printf"}
func TestProperty6_BugCondition_ConcreteCallToPrintf(t *testing.T) {
	const printfAddr = uint64(0x401090) // 4198544 decimal — typical printf PLT stub address

	irFunc := buildCallTargetIRFunction(printfAddr)
	rawInsns := buildCallRawInsns(printfAddr)

	// construct the ground truth database with printf at the plt stub address
	db := buildGroundTruthDB(printfAddr, "printf")

	// call applyABIPass with the ground truth database
	applyABIPass(irFunc, rawInsns, db)

	// extract the call target after the abi pass
	target := extractCallTarget(irFunc)
	if target == nil {
		t.Fatal("no ir.Call instruction found in function after applyABIPass")
	}

	// assert: target must be VariableExpr{Name:"printf"} — FAILS on unfixed code
	if !isVariableExprWithName(target, "printf") {
		// document the counterexample precisely
		var counterexampleDesc string
		if isConstantExprWithAddr(target, printfAddr) {
			counterexampleDesc = fmt.Sprintf(
				"call target remains ConstantExpr{%d} instead of VariableExpr{Name:\"printf\"}",
				printfAddr,
			)
		} else {
			counterexampleDesc = fmt.Sprintf(
				"call target is %T(%s) instead of VariableExpr{Name:\"printf\"}",
				target, target.String(),
			)
		}
		t.Errorf(
			"bug confirmed: %s\n"+
				"applyABIPass does not accept a GroundTruthDatabase parameter and therefore\n"+
				"cannot resolve numeric address 0x%x to symbol name \"printf\".\n"+
				"the generated c output would emit \"%d(...)\" instead of \"printf(...)\".",
			counterexampleDesc, printfAddr, printfAddr,
		)
	}
}

// TestProperty6_BugCondition_ConcreteCallToStackChkFail tests resolution of
// __stack_chk_fail — another common PLT stub in linux binaries.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// same root cause: applyABIPass does not consult the GroundTruthDatabase.
func TestProperty6_BugCondition_ConcreteCallToStackChkFail(t *testing.T) {
	const stackChkAddr = uint64(0x401030) // typical __stack_chk_fail PLT stub address

	irFunc := buildCallTargetIRFunction(stackChkAddr)
	rawInsns := buildCallRawInsns(stackChkAddr)

	db := buildGroundTruthDB(stackChkAddr, "__stack_chk_fail")

	applyABIPass(irFunc, rawInsns, db)

	target := extractCallTarget(irFunc)
	if target == nil {
		t.Fatal("no ir.Call instruction found in function after applyABIPass")
	}

	if !isVariableExprWithName(target, "__stack_chk_fail") {
		var counterexampleDesc string
		if isConstantExprWithAddr(target, stackChkAddr) {
			counterexampleDesc = fmt.Sprintf(
				"call target remains ConstantExpr{%d} instead of VariableExpr{Name:\"__stack_chk_fail\"}",
				stackChkAddr,
			)
		} else {
			counterexampleDesc = fmt.Sprintf(
				"call target is %T(%s) instead of VariableExpr{Name:\"__stack_chk_fail\"}",
				target, target.String(),
			)
		}
		t.Errorf(
			"bug confirmed: %s\n"+
				"applyABIPass does not accept a GroundTruthDatabase parameter and therefore\n"+
				"cannot resolve numeric address 0x%x to symbol name \"__stack_chk_fail\".",
			counterexampleDesc, stackChkAddr,
		)
	}
}

// symbolNameGenerator is a rapid generator that produces realistic c-legal symbol names
// such as those found in linux elf binaries: printf, malloc, __stack_chk_fail, etc.
func symbolNameGenerator() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		// draw a prefix: either a letter, underscore, or double-underscore (glibc internal)
		prefixes := []string{
			"_", "__", "fn_", "sub_", "sym_",
			"printf", "malloc", "free", "exit", "abort",
			"memcpy", "memset", "strlen", "strcmp", "strcpy",
			"open", "close", "read", "write", "mmap",
			"__stack_chk_fail", "__libc_start_main", "__cxa_finalize",
		}
		idx := rapid.IntRange(0, len(prefixes)-1).Draw(t, "prefixIdx")
		base := prefixes[idx]

		// optionally append a numeric suffix to create unique names
		appendSuffix := rapid.IntRange(0, 3).Draw(t, "appendSuffix")
		if appendSuffix > 0 {
			suffix := rapid.IntRange(0, 999).Draw(t, "suffix")
			return fmt.Sprintf("%s_%d", base, suffix)
		}
		return base
	})
}

// pltAddressGenerator is a rapid generator that produces realistic PLT stub addresses.
// PLT stubs in x86-64 ELF binaries are typically 16 bytes apart starting from 0x401020.
func pltAddressGenerator() *rapid.Generator[uint64] {
	return rapid.Custom(func(t *rapid.T) uint64 {
		// plt base address: 0x401020 is typical for small linux binaries
		const pltBase = uint64(0x401020)
		const pltEntrySize = uint64(16) // each plt stub is 16 bytes
		// generate 0–63 plt entries (covers typical binary sizes)
		entryIdx := rapid.Uint64Range(0, 63).Draw(t, "pltEntryIdx")
		return pltBase + entryIdx*pltEntrySize
	})
}

// TestProperty6_BugCondition_RapidCallTargetResolution is the property-based test
// using pgregory.net/rapid to generate random address→symbol mappings and verify
// that applyABIPass resolves call targets to symbol names.
//
// **Validates: Requirements 2.11, 2.12**
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// rapid will immediately find a counterexample because applyABIPass never
// resolves any call target regardless of the address or symbol name.
//
// documented counterexample (from running on unfixed code):
// addr=0x401090 symName="printf":
// call target remains ConstantExpr{4198544} instead of VariableExpr{Name:"printf"} —
// applyABIPass does not accept a GroundTruthDatabase parameter and therefore
// cannot perform any address-to-symbol resolution.
func TestProperty6_BugCondition_RapidCallTargetResolution(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// generate a random PLT address and corresponding symbol name
		callTargetAddr := pltAddressGenerator().Draw(rt, "callTargetAddr")
		symbolName := symbolNameGenerator().Draw(rt, "symbolName")

		irFunc := buildCallTargetIRFunction(callTargetAddr)
		rawInsns := buildCallRawInsns(callTargetAddr)

		// build the ground truth database with the generated address→symbol mapping
		db := buildGroundTruthDB(callTargetAddr, symbolName)

		// call applyABIPass with the ground truth database
		applyABIPass(irFunc, rawInsns, db)

		// extract the call target after the abi pass
		target := extractCallTarget(irFunc)
		if target == nil {
			// applyABIPass may have removed the call instruction entirely — still a bug
			// if the call was to a known symbol, it should appear as a named call
			rt.Errorf(
				"counterexample: addr=0x%x symName=%q\n"+
					"call instruction disappeared from ir after applyABIPass — expected VariableExpr{Name:%q}",
				callTargetAddr, symbolName, symbolName,
			)
			return
		}

		// property: target must be VariableExpr with the correct symbol name
		if !isVariableExprWithName(target, symbolName) {
			var counterexampleDesc string
			if isConstantExprWithAddr(target, callTargetAddr) {
				counterexampleDesc = fmt.Sprintf(
					"call target remains ConstantExpr{%d} instead of VariableExpr{Name:%q}",
					callTargetAddr, symbolName,
				)
			} else {
				counterexampleDesc = fmt.Sprintf(
					"call target is %T(%s) instead of VariableExpr{Name:%q}",
					target, target.String(), symbolName,
				)
			}
			rt.Errorf(
				"counterexample: addr=0x%x symName=%q\n%s\n"+
					"applyABIPass does not accept a GroundTruthDatabase parameter and therefore\n"+
					"cannot resolve numeric address 0x%x to symbol name %q.",
				callTargetAddr, symbolName, counterexampleDesc, callTargetAddr, symbolName,
			)
		}
	})
}

// ============================================================================
// preservation 6: call targets not in database are left unchanged
// ============================================================================

// TestPreservation6_UnknownCallTargetUnchanged verifies that ir.Call nodes whose
// target address is NOT in any database map have their target expression left
// unchanged after applyABIPass.
//
// **Validates: Requirements 3.11, 3.12**
//
// this is the preservation guarantee for fix 6: the call target resolution must
// not modify call targets that are not in the GroundTruthDatabase.
// indirect calls through registers (e.g., call rax) and calls to unknown addresses
// must be left unchanged.
//
// EXPECTED OUTCOME: PASS on both unfixed and fixed code.
// the unfixed applyABIPass never modifies any call target (it has no database),
// so all call targets are trivially preserved. the fixed version must also
// preserve targets not in the database.
func TestPreservation6_UnknownCallTargetUnchanged(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// generate a call target address that is NOT in any database
		// use addresses in a range that is unlikely to collide with plt stubs
		callTargetAddr := rapid.Uint64Range(0x600000, 0x6fffff).Draw(rt, "callTargetAddr")

		irFunc := buildCallTargetIRFunction(callTargetAddr)
		rawInsns := buildCallRawInsns(callTargetAddr)

		// record the original target expression before applyABIPass
		originalTarget := extractCallTarget(irFunc)
		if originalTarget == nil {
			// no call instruction — skip
			return
		}

		// call applyABIPass with an empty database — unknown address must remain unchanged
		applyABIPass(irFunc, rawInsns, binfmt.NewGroundTruthDatabase())

		// extract the target after the pass
		resultTarget := extractCallTarget(irFunc)
		if resultTarget == nil {
			// call instruction was removed — this is a preservation violation
			rt.Errorf(
				"preservation violated: call to unknown addr 0x%x was removed by applyABIPass",
				callTargetAddr,
			)
			return
		}

		// preservation property: target must still be a ConstantExpr with the same address
		// (the unfixed code never resolves anything, so this always passes on unfixed code)
		if !isConstantExprWithAddr(resultTarget, callTargetAddr) {
			rt.Errorf(
				"preservation violated: call target for unknown addr 0x%x was modified\n"+
					"original: ConstantExpr{%d}\n"+
					"result: %T(%s)",
				callTargetAddr, callTargetAddr, resultTarget, resultTarget.String(),
			)
		}
	})
}

// TestPreservation6_ConcreteUnknownAddressUnchanged tests the concrete case:
// a call to address 0x600000 (not in any database) must remain unchanged.
//
// EXPECTED OUTCOME: PASS on both unfixed and fixed code.
func TestPreservation6_ConcreteUnknownAddressUnchanged(t *testing.T) {
	const unknownAddr = uint64(0x600000)

	irFunc := buildCallTargetIRFunction(unknownAddr)
	rawInsns := buildCallRawInsns(unknownAddr)

	applyABIPass(irFunc, rawInsns, binfmt.NewGroundTruthDatabase())

	target := extractCallTarget(irFunc)
	if target == nil {
		t.Fatal("call instruction disappeared after applyABIPass")
	}

	if !isConstantExprWithAddr(target, unknownAddr) {
		t.Errorf(
			"preservation violated: call target for unknown addr 0x%x was modified to %T(%s)",
			unknownAddr, target, target.String(),
		)
	}
}
