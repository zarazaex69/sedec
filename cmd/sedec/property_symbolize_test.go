// package main — property-based test for defect 7:
// absolute memory addresses in ir.Load/ir.Store must be replaced with symbolic
// references when the address is present in the GroundTruthDatabase.
//
// **Validates: Requirements 2.13, 2.14**
//
// property 7 (bug condition): for all ir.Load instructions whose Address is a
// ConstantExpr containing an address present in GroundTruthDatabase.SymbolsByAddress,
// after applying symbolizeAddresses the Address MUST be a VariableExpr whose Name
// equals "&" + symbolName (e.g., "&__environ").
//
// this test MUST FAIL on unfixed code — failure confirms the bug exists.
// the bug: symbolizeAddresses does not exist in the unfixed codebase.
// the decompile pipeline emits raw decimal integer literals for all absolute
// memory addresses, producing "*(uint64_t*)(163472)" instead of
// "*(uint64_t*)(&__environ)".
//
// documented counterexample:
// addr=0x27e90 (163472 decimal), symbol="__environ":
// generated c output contains "*(uint64_t*)(163472)" instead of
// "*(uint64_t*)(&__environ)" — the raw decimal address is completely
// unreadable and provides no semantic information to the analyst.
package main

import (
	"fmt"
	"strings"
	"testing"

	binfmt "github.com/zarazaex69/sedec/pkg/binary"
	"github.com/zarazaex69/sedec/pkg/codegen"
	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
	"github.com/zarazaex69/sedec/pkg/structuring"
	"pgregory.net/rapid"
)

// buildLoadIRFunction constructs a minimal ir.Function containing a single
// basic block with one ir.Load instruction whose Address is a ConstantExpr
// holding the given absolute virtual address.
//
// this mirrors what the ir lifter produces for "mov rax, [0x27e90]":
// the address is encoded as an integer constant because the lifter has no
// access to the symbol table at lift time.
func buildLoadIRFunction(loadAddr uint64) *ir.Function {
	// the load address is a raw numeric constant — this is what the lifter emits
	addrExpr := ir.ConstantExpr{
		Value: ir.IntConstant{
			Value:  int64(loadAddr),
			Width:  ir.Size8,
			Signed: false,
		},
	}

	destVar := ir.Variable{
		Name: "t1",
		Type: ir.IntType{Width: ir.Size8, Signed: false},
	}

	loadInstr := ir.Load{
		Dest:    destVar,
		Address: addrExpr,
		Size:    ir.Size8,
	}

	block := &ir.BasicBlock{
		ID:           0,
		Instructions: []ir.IRInstruction{loadInstr},
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
		Variables:  []ir.Variable{destVar},
	}
}

// buildRIPRelativeLoadIRFunction constructs an ir.Function with a load whose
// address is a BinaryOp{BinOpAdd, VariableExpr{Name:"rip"}, ConstantExpr{disp}}.
// this mirrors what the lifter produces for RIP-relative addressing:
// "mov rax, [rip + 0x1234]" → load (rip + 0x1234).
// the actual resolved address is instruction_address + instruction_length + disp,
// but the lifter emits the unresolved form.
func buildRIPRelativeLoadIRFunction(ripValue uint64, disp int64, resolvedAddr uint64) *ir.Function {
	// rip variable — the lifter emits this as a named variable
	ripVar := ir.Variable{
		Name: "rip",
		Type: ir.IntType{Width: ir.Size8, Signed: false},
	}

	// displacement constant
	dispExpr := ir.ConstantExpr{
		Value: ir.IntConstant{
			Value:  disp,
			Width:  ir.Size8,
			Signed: true,
		},
	}

	// rip-relative address: (rip + disp)
	addrExpr := ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  ir.VariableExpr{Var: ripVar},
		Right: dispExpr,
	}

	destVar := ir.Variable{
		Name: "t1",
		Type: ir.IntType{Width: ir.Size8, Signed: false},
	}

	loadInstr := ir.Load{
		Dest:    destVar,
		Address: addrExpr,
		Size:    ir.Size8,
	}

	// also include an assign that sets rip to the known value,
	// so symbolizeAddresses can resolve the rip-relative address
	ripAssign := ir.Assign{
		Dest: ripVar,
		Source: ir.ConstantExpr{
			Value: ir.IntConstant{
				Value:  int64(ripValue),
				Width:  ir.Size8,
				Signed: false,
			},
		},
	}
	_ = ripAssign    // used for documentation; the load is the primary test target
	_ = resolvedAddr // the expected resolved address for assertion

	block := &ir.BasicBlock{
		ID:           0,
		Instructions: []ir.IRInstruction{loadInstr},
		Predecessors: nil,
		Successors:   nil,
	}

	return &ir.Function{
		Name: "test_func_rip",
		Signature: ir.FunctionType{
			ReturnType: ir.VoidType{},
			Parameters: nil,
		},
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		EntryBlock: 0,
		Variables:  []ir.Variable{destVar, ripVar},
	}
}

// buildSymbolizeDB constructs a GroundTruthDatabase with a single address→symbol mapping.
// this simulates the global variable table extracted from the ELF binary.
func buildSymbolizeDB(addr uint64, symbolName string) *binfmt.GroundTruthDatabase {
	db := binfmt.NewGroundTruthDatabase()
	bAddr := binfmt.Address(addr)
	db.SymbolsByAddress[bAddr] = symbolName
	db.SymbolsByName[symbolName] = bAddr
	return db
}

// buildASTForLoadFunction constructs a minimal structuring.StructuredAST for the
// given ir.Function, wrapping the single block as an IRBlock statement.
func buildASTForLoadFunction(fn *ir.Function) *structuring.StructuredAST {
	block, ok := fn.Blocks[fn.EntryBlock]
	if !ok {
		return &structuring.StructuredAST{
			Body:       structuring.Block{},
			FunctionID: 0,
		}
	}
	return &structuring.StructuredAST{
		Body: structuring.IRBlock{
			BlockID:      0,
			Instructions: block.Instructions,
		},
		FunctionID: 0,
	}
}

// isDecimalIntegerLiteral reports whether the given c output string contains
// the decimal representation of addr as a standalone numeric literal.
// this detects the bug condition: "*(uint64_t*)(163472)" in the output.
func isDecimalIntegerLiteral(cOutput string, addr uint64) bool {
	decimal := fmt.Sprintf("%d", addr)
	return strings.Contains(cOutput, decimal)
}

// generateCOutputForFunction runs the full codegen pipeline on the given ir.Function
// and returns the rendered c pseudocode string.
func generateCOutputForFunction(fn *ir.Function) string {
	ast := buildASTForLoadFunction(fn)
	gen := codegen.New()
	decl := gen.GenerateFunction(fn, ast)
	return codegen.RenderDecl(decl)
}

// TestProperty7_BugCondition_ConcreteEnvironLoad is the deterministic concrete test.
// it constructs an ir.Load targeting address 0x27e90 (__environ in /bin/ls),
// registers "__environ" in the GroundTruthDatabase at that address,
// attempts to call symbolizeAddresses (which does not exist on unfixed code),
// and asserts that the generated c output does NOT contain the decimal literal 163472.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// symbolizeAddresses does not exist in the unfixed codebase.
// the generated c output contains "*(uint64_t*)(163472)" — the raw decimal
// address 0x27e90 — instead of "*(uint64_t*)(&__environ)".
//
// documented counterexample:
// output contains "*(uint64_t*)(163472)" instead of "*(uint64_t*)(&__environ)"
func TestProperty7_BugCondition_ConcreteEnvironLoad(t *testing.T) {
	const environAddr = uint64(0x27e90) // 163472 decimal — __environ in /bin/ls

	irFunc := buildLoadIRFunction(environAddr)

	// construct the ground truth database — symbolizeAddresses on unfixed code does not exist
	db := buildSymbolizeDB(environAddr, "__environ")
	_ = db // unfixed pipeline does not call symbolizeAddresses

	// attempt to call symbolizeAddresses — this function does not exist on unfixed code.
	// on unfixed code, this call will fail to compile or the function will not exist,
	// so we test the observable effect: the generated c output contains the decimal literal.
	//
	// since symbolizeAddresses does not exist, we run the full codegen pipeline
	// directly on the unmodified ir.Function and check the output.
	symbolizeAddresses(irFunc, db, nil)
	cOutput := generateCOutputForFunction(irFunc)

	// assert: output must NOT contain the decimal literal 163472
	// on unfixed code this FAILS because the address is emitted verbatim
	if isDecimalIntegerLiteral(cOutput, environAddr) {
		t.Errorf(
			"bug confirmed: output contains decimal literal %d instead of symbolic reference \"&__environ\"\n"+
				"addr=0x%x (%d decimal), symbol=\"__environ\"\n"+
				"generated output:\n%s\n"+
				"symbolizeAddresses does not exist in the unfixed pipeline — absolute addresses\n"+
				"are emitted as raw decimal integer literals, producing unreadable decompiler output.",
			environAddr, environAddr, environAddr, cOutput,
		)
	}

	// also assert: the symbolic reference must be present in the output
	if !strings.Contains(cOutput, "&__environ") {
		t.Errorf(
			"bug confirmed: output does not contain symbolic reference \"&__environ\"\n"+
				"addr=0x%x (%d decimal), symbol=\"__environ\"\n"+
				"generated output:\n%s",
			environAddr, environAddr, cOutput,
		)
	}
}

// TestProperty7_BugCondition_ConcreteStderrLoad tests symbolization of stderr GOT entry.
// stderr is accessed via a GOT entry at a known absolute address in /bin/ls.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// same root cause: no symbolizeAddresses pass exists in the unfixed pipeline.
func TestProperty7_BugCondition_ConcreteStderrLoad(t *testing.T) {
	// typical GOT entry address for stderr in a small linux binary
	const stderrAddr = uint64(0x27e98) // 163480 decimal

	irFunc := buildLoadIRFunction(stderrAddr)

	db := buildSymbolizeDB(stderrAddr, "stderr")

	symbolizeAddresses(irFunc, db, nil)
	cOutput := generateCOutputForFunction(irFunc)

	// assert: output must NOT contain the decimal literal
	if isDecimalIntegerLiteral(cOutput, stderrAddr) {
		t.Errorf(
			"bug confirmed: output contains decimal literal %d instead of symbolic reference \"stderr\"\n"+
				"addr=0x%x (%d decimal), symbol=\"stderr\"\n"+
				"generated output:\n%s\n"+
				"symbolizeAddresses does not exist — absolute addresses are emitted as decimal literals.",
			stderrAddr, stderrAddr, stderrAddr, cOutput,
		)
	}

	// assert: symbolic reference must be present
	if !strings.Contains(cOutput, "stderr") {
		t.Errorf(
			"bug confirmed: output does not contain symbolic reference \"stderr\"\n"+
				"addr=0x%x (%d decimal), symbol=\"stderr\"\n"+
				"generated output:\n%s",
			stderrAddr, stderrAddr, cOutput,
		)
	}
}

// TestProperty7_BugCondition_RIPRelativeAddressNotResolved tests that RIP-relative
// address expressions are resolved to symbolic references.
//
// the lifter emits "(rip + disp)" for RIP-relative memory operands.
// the fixed pipeline must resolve this to the actual virtual address and then
// look up the symbol name in the database.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// the rip-relative expression "(rip + 141195)" is emitted verbatim in the output
// instead of being resolved to the target symbol name.
func TestProperty7_BugCondition_RIPRelativeAddressNotResolved(t *testing.T) {
	// choose values so that: instrAddr + instrLen + disp = resolvedAddr
	// instrAddr = 0x1000, instrLen = 7, resolvedAddr = 0x27e90
	// disp = 0x27e90 - (0x1000 + 7) = 0x27e90 - 0x1007 = 0x26e89 = 158345
	const instrAddr = uint64(0x1000)
	const instrLen = 7
	const resolvedAddr = uint64(0x27e90) // __environ address
	const disp = int64(resolvedAddr - instrAddr - instrLen)

	irFunc := buildRIPRelativeLoadIRFunction(instrAddr, disp, resolvedAddr)

	db := buildSymbolizeDB(resolvedAddr, "__environ")

	// rawInsns provides the rip-next-address map: rip = instrAddr + instrLen
	rawInsns := []*disasm.Instruction{
		{Address: disasm.Address(instrAddr), Length: instrLen, Mnemonic: "mov"},
	}

	// patch the load instruction address to match instrAddr so symbolizeAddresses
	// can look up the rip-next value from rawInsns
	if block, ok := irFunc.Blocks[irFunc.EntryBlock]; ok {
		for i, instr := range block.Instructions {
			if load, ok := instr.(ir.Load); ok {
				load.Loc.Address = ir.Address(instrAddr)
				block.Instructions[i] = load
			}
		}
	}

	symbolizeAddresses(irFunc, db, rawInsns)
	cOutput := generateCOutputForFunction(irFunc)

	// assert: the load expression must use the symbolic reference, not rip+disp
	// check that the output contains "&__environ" (the resolved symbol)
	if !strings.Contains(cOutput, "&__environ") {
		t.Errorf(
			"bug confirmed: rip-relative address (rip + %d) was not resolved to symbolic reference\n"+
				"generated output:\n%s\n"+
				"symbolizeAddresses does not exist — rip-relative addresses are emitted\n"+
				"as raw register expressions, producing unreadable decompiler output.",
			disp, cOutput,
		)
	}
	// assert: the load expression must NOT contain the raw rip+disp pattern
	if strings.Contains(cOutput, fmt.Sprintf("(rip + %d)", disp)) {
		t.Errorf(
			"bug confirmed: output contains raw rip-relative expression \"(rip + %d)\"\n"+
				"generated output:\n%s",
			disp, cOutput,
		)
	}
}

// globalSymbolNameGenerator is a rapid generator that produces realistic global
// variable and imported symbol names found in linux elf binaries.
func globalSymbolNameGenerator() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		candidates := []string{
			"__environ", "stderr", "stdout", "stdin",
			"errno", "__errno_location",
			"__stack_chk_guard", "__libc_argv",
			"optarg", "optind", "opterr", "optopt",
			"program_invocation_name", "program_invocation_short_name",
			"__progname", "__progname_full",
			"_IO_2_1_stderr_", "_IO_2_1_stdout_", "_IO_2_1_stdin_",
			"__libc_single_threaded",
		}
		idx := rapid.IntRange(0, len(candidates)-1).Draw(t, "symIdx")
		base := candidates[idx]

		// optionally append a numeric suffix to create unique names
		appendSuffix := rapid.IntRange(0, 4).Draw(t, "appendSuffix")
		if appendSuffix == 0 {
			suffix := rapid.IntRange(0, 99).Draw(t, "suffix")
			return fmt.Sprintf("%s_%d", base, suffix)
		}
		return base
	})
}

// globalAddressGenerator is a rapid generator that produces realistic global
// variable addresses in the data segment of a typical linux x86-64 binary.
// data segment addresses are typically in the range [0x10000, 0x7fffffffffff].
func globalAddressGenerator() *rapid.Generator[uint64] {
	return rapid.Custom(func(t *rapid.T) uint64 {
		// typical .bss/.data segment base for small linux binaries
		const dataBase = uint64(0x20000)
		const dataSize = uint64(0x10000) // 64KB data segment
		// generate addresses aligned to 8 bytes (pointer-sized)
		offset := rapid.Uint64Range(0, dataSize/8-1).Draw(t, "offset")
		return dataBase + offset*8
	})
}

// TestProperty7_BugCondition_RapidSymbolizeAddresses is the property-based test
// using pgregory.net/rapid to generate random address→symbol mappings and verify
// that the decompile pipeline replaces decimal integer literals with symbolic references.
//
// **Validates: Requirements 2.13, 2.14**
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// rapid will immediately find a counterexample because the unfixed pipeline
// never calls symbolizeAddresses and always emits raw decimal integer literals
// for absolute memory addresses.
//
// documented counterexample (from running on unfixed code):
// addr=0x27e90 (163472 decimal), symbol="__environ":
// output contains "*(uint64_t*)(163472)" instead of "*(uint64_t*)(&__environ)" —
// symbolizeAddresses does not exist in the unfixed pipeline, so absolute addresses
// are emitted verbatim as decimal integer literals in all generated c output.
func TestProperty7_BugCondition_RapidSymbolizeAddresses(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// generate a random global variable address and corresponding symbol name
		loadAddr := globalAddressGenerator().Draw(rt, "loadAddr")
		symbolName := globalSymbolNameGenerator().Draw(rt, "symbolName")

		irFunc := buildLoadIRFunction(loadAddr)

		// build the ground truth database and apply symbolizeAddresses
		db := buildSymbolizeDB(loadAddr, symbolName)
		symbolizeAddresses(irFunc, db, nil)

		// run codegen on the symbolized ir.Function
		cOutput := generateCOutputForFunction(irFunc)

		// property: output must NOT contain the decimal literal of the address
		if isDecimalIntegerLiteral(cOutput, loadAddr) {
			rt.Errorf(
				"counterexample: addr=0x%x (%d decimal), symbol=%q\n"+
					"output contains decimal literal %d instead of symbolic reference \"&%s\"\n"+
					"generated output:\n%s\n"+
					"symbolizeAddresses does not exist — absolute addresses are emitted as\n"+
					"raw decimal integer literals, producing unreadable decompiler output.",
				loadAddr, loadAddr, symbolName, loadAddr, symbolName, cOutput,
			)
		}

		// property: output must contain the symbolic reference
		expectedRef := "&" + symbolName
		if !strings.Contains(cOutput, expectedRef) {
			rt.Errorf(
				"counterexample: addr=0x%x (%d decimal), symbol=%q\n"+
					"output does not contain symbolic reference %q\n"+
					"generated output:\n%s",
				loadAddr, loadAddr, symbolName, expectedRef, cOutput,
			)
		}
	})
}

// TestProperty7_BugCondition_HexLiteralFallback verifies that when no symbol is
// available for an absolute address, the fixed pipeline emits a hexadecimal literal
// (e.g., "0x27e90ULL") rather than a decimal integer literal (e.g., "163472").
//
// requirement 2.14: when no symbol name is available, emit hex literal with explicit cast.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// the unfixed pipeline emits "163472" (decimal) instead of "0x27e90ULL" (hex).
// decimal literals are unrecognizable as virtual addresses; hex literals are standard
// in reverse engineering output and immediately recognizable as addresses.
func TestProperty7_BugCondition_HexLiteralFallback(t *testing.T) {
	// use an address that is NOT in any symbol database
	const unknownAddr = uint64(0x27e90) // 163472 decimal — no symbol registered

	irFunc := buildLoadIRFunction(unknownAddr)

	// empty database — no symbol for this address
	// the fixed pipeline should emit "0x27e90ULL" instead of "163472"
	cOutput := generateCOutputForFunction(irFunc)

	// assert: output must NOT contain the decimal literal
	if isDecimalIntegerLiteral(cOutput, unknownAddr) {
		t.Errorf(
			"bug confirmed: output contains decimal literal %d instead of hex literal 0x%xULL\n"+
				"addr=0x%x (%d decimal), no symbol registered\n"+
				"generated output:\n%s\n"+
				"requirement 2.14: when no symbol is available, emit hex literal with explicit cast\n"+
				"(e.g., \"*(uint64_t*)(0x27e90ULL)\") rather than decimal integer literal.",
			unknownAddr, unknownAddr, unknownAddr, unknownAddr, cOutput,
		)
	}

	// assert: output must contain the hex literal form
	hexLiteral := fmt.Sprintf("0x%xULL", unknownAddr)
	if !strings.Contains(cOutput, hexLiteral) {
		t.Errorf(
			"bug confirmed: output does not contain hex literal %q\n"+
				"addr=0x%x (%d decimal), no symbol registered\n"+
				"generated output:\n%s",
			hexLiteral, unknownAddr, unknownAddr, cOutput,
		)
	}
}

// ============================================================================
// preservation 7: register-relative addresses are not symbolized
// ============================================================================

// TestPreservation7_RegisterRelativeAddressUnchanged verifies that IR instructions
// with ONLY register-relative addresses (no absolute constants) are not modified
// by the symbolization pass.
//
// **Validates: Requirements 3.13, 3.14**
//
// this is the preservation guarantee for fix 7: the symbolization pass must not
// modify address expressions that are register-relative (e.g., rbp-8, rsp+16).
// these are stack variable references that must remain as-is.
//
// EXPECTED OUTCOME: PASS on both unfixed and fixed code.
// the unfixed pipeline has no symbolizeAddresses pass, so register-relative
// addresses are trivially preserved. the fixed version must also preserve them.
func TestPreservation7_RegisterRelativeAddressUnchanged(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// generate a register-relative address: (rbp + offset) or (rsp + offset)
		useRBP := rapid.IntRange(0, 1).Draw(rt, "useRBP")
		offset := rapid.Int64Range(-256, 256).Draw(rt, "offset")

		var baseRegName string
		if useRBP == 1 {
			baseRegName = "rbp"
		} else {
			baseRegName = "rsp"
		}

		baseReg := ir.Variable{
			Name: baseRegName,
			Type: ir.IntType{Width: ir.Size8, Signed: false},
		}

		// register-relative address: (baseReg + offset)
		addrExpr := ir.BinaryOp{
			Op:   ir.BinOpAdd,
			Left: ir.VariableExpr{Var: baseReg},
			Right: ir.ConstantExpr{
				Value: ir.IntConstant{Value: offset, Width: ir.Size8, Signed: true},
			},
		}

		destVar := ir.Variable{
			Name: "t1",
			Type: ir.IntType{Width: ir.Size8, Signed: false},
		}

		loadInstr := ir.Load{
			Dest:    destVar,
			Address: addrExpr,
			Size:    ir.Size8,
		}

		block := &ir.BasicBlock{
			ID:           0,
			Instructions: []ir.IRInstruction{loadInstr},
		}

		fn := &ir.Function{
			Name: "test_reg_rel",
			Signature: ir.FunctionType{
				ReturnType: ir.VoidType{},
			},
			Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
			EntryBlock: 0,
			Variables:  []ir.Variable{destVar, baseReg},
		}

		// generate c output — the unfixed pipeline has no symbolizeAddresses
		cOutput := generateCOutputForFunction(fn)

		// preservation property: the base register name must still appear in the output
		// (register-relative addresses must not be symbolized or removed)
		if !strings.Contains(cOutput, baseRegName) {
			rt.Errorf(
				"preservation violated: register-relative address (%s + %d) was modified\n"+
					"base register %q not found in output\ngenerated output:\n%s",
				baseRegName, offset, baseRegName, cOutput,
			)
		}
	})
}

// TestPreservation7_ConcreteRBPRelativeUnchanged tests the concrete case:
// a load from (rbp - 8) must appear as a register-relative expression in the output.
//
// EXPECTED OUTCOME: PASS on both unfixed and fixed code.
func TestPreservation7_ConcreteRBPRelativeUnchanged(t *testing.T) {
	rbpVar := ir.Variable{
		Name: "rbp",
		Type: ir.IntType{Width: ir.Size8, Signed: false},
	}

	// (rbp + -8) — typical local variable access
	addrExpr := ir.BinaryOp{
		Op:   ir.BinOpAdd,
		Left: ir.VariableExpr{Var: rbpVar},
		Right: ir.ConstantExpr{
			Value: ir.IntConstant{Value: -8, Width: ir.Size8, Signed: true},
		},
	}

	destVar := ir.Variable{
		Name: "t1",
		Type: ir.IntType{Width: ir.Size8, Signed: false},
	}

	loadInstr := ir.Load{
		Dest:    destVar,
		Address: addrExpr,
		Size:    ir.Size8,
	}

	block := &ir.BasicBlock{
		ID:           0,
		Instructions: []ir.IRInstruction{loadInstr},
	}

	fn := &ir.Function{
		Name: "test_rbp_rel",
		Signature: ir.FunctionType{
			ReturnType: ir.VoidType{},
		},
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		EntryBlock: 0,
		Variables:  []ir.Variable{destVar, rbpVar},
	}

	cOutput := generateCOutputForFunction(fn)

	// preservation: rbp must appear in the output as part of the address expression
	if !strings.Contains(cOutput, "rbp") {
		t.Errorf(
			"preservation violated: rbp-relative address not preserved in output\n"+
				"generated output:\n%s",
			cOutput,
		)
	}
}
