//nolint:godot // cli test file
package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	binfmt "github.com/zarazaex69/sedec/pkg/binary"
	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// cIdentRegex is the canonical c identifier pattern used in sanitize tests.
var cIdentRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// TestSanitizeFunctionName verifies all sanitization rules and the preservation guarantee.
func TestSanitizeFunctionName(t *testing.T) {
	cases := []struct {
		name     string
		addr     uint64
		expected string
	}{
		// rule 2: leading dot replaced with underscore → valid identifier
		{name: ".init", addr: 0, expected: "_init"},
		// rule 2: leading dot + underscore body
		{name: ".init_func0", addr: 0, expected: "_init_func0"},
		// rule 1 + rule 2: '@' stripped, remainder is valid
		{name: "error@plt", addr: 0, expected: "error_plt"},
		// rule 1: version suffix stripped, remainder is already valid
		{name: "printf@GLIBC_2.2.5", addr: 0, expected: "printf"},
		// rule 3: starts with digit → prepend "fn_"
		{name: "12767", addr: 0, expected: "fn_12767"},
		// preservation: already valid, returned unchanged
		{name: "main", addr: 0, expected: "main"},
		// preservation: already valid with double underscore prefix
		{name: "__libc_start_main", addr: 0, expected: "__libc_start_main"},
		// rule 2: hyphen and dot replaced with underscore
		{name: "__cxa_finalize-2.17", addr: 0, expected: "__cxa_finalize_2_17"},
		// rule 2: leading dot replaced
		{name: ".text_func3", addr: 0, expected: "_text_func3"},
		// rule 4: empty string → sub_XXXXXXXX using addr
		{name: "", addr: 0x401000, expected: "sub_00401000"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name+"_"+tc.expected, func(t *testing.T) {
			got := sanitizeFunctionName(tc.name, tc.addr)
			if got != tc.expected {
				t.Errorf("sanitizeFunctionName(%q, 0x%x) = %q, want %q",
					tc.name, tc.addr, got, tc.expected)
			}
			// all outputs must be valid c identifiers
			if !cIdentRegex.MatchString(got) {
				t.Errorf("sanitizeFunctionName(%q, 0x%x) = %q: not a valid c identifier",
					tc.name, tc.addr, got)
			}
		})
	}
}

func TestDecompile_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := run([]string{"decompile", "--help"}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stderr.String()
	if !strings.Contains(output, "usage: sedec decompile") {
		t.Errorf("expected decompile usage, got: %s", output)
	}
	if !strings.Contains(output, "--function") {
		t.Errorf("expected --function flag in help, got: %s", output)
	}
	if !strings.Contains(output, "--output") {
		t.Errorf("expected --output flag in help, got: %s", output)
	}
}

func TestDecompile_NoInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	stdin := bytes.NewReader([]byte{})

	err := run([]string{"decompile"}, stdin, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for no input")
	}

	if !strings.Contains(err.Error(), "no input provided") {
		t.Errorf("expected 'no input provided' error, got: %v", err)
	}
}

func TestDecompile_TooManyArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := run([]string{"decompile", "file1", "file2"}, nil, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for too many arguments")
	}

	if !strings.Contains(err.Error(), "too many arguments") {
		t.Errorf("expected 'too many arguments' error, got: %v", err)
	}
}

func TestDecompile_FileNotFound(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := run([]string{"decompile", "/nonexistent/file/that/does/not/exist"}, nil, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}

	if !strings.Contains(err.Error(), "file not found") && !strings.Contains(err.Error(), "no such file") {
		t.Errorf("expected 'file not found' error, got: %v", err)
	}
}

func TestDecompile_InvalidBinary(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// random bytes that are not a valid binary
	stdin := bytes.NewReader([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03})

	err := run([]string{"decompile"}, stdin, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for invalid binary")
	}

	// should fail at binary parsing stage, not panic
	if !strings.Contains(err.Error(), "failed to parse binary") &&
		!strings.Contains(err.Error(), "unsupported binary format") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestDecompile_RegisteredInRouter(t *testing.T) {
	// verify that 'decompile' is a recognized command (not 'unknown command')
	var stdout, stderr bytes.Buffer
	stdin := bytes.NewReader([]byte{})

	err := run([]string{"decompile"}, stdin, &stdout, &stderr)
	// should fail with no-input error, not unknown-command error
	if err != nil && strings.Contains(err.Error(), "unknown command") {
		t.Errorf("decompile command not registered in router: %v", err)
	}
}

func TestDecompile_HelpInMainUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := run([]string{"--help"}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "decompile") {
		t.Errorf("expected 'decompile' in main help output, got: %s", output)
	}
}

// TestSymbolizeAddresses verifies the six canonical cases for symbolizeAddresses.
func TestSymbolizeAddresses(t *testing.T) {
	// helper: build a minimal ir.Function with a single Load instruction
	makeLoadFunc := func(addr ir.Address) (*ir.Function, *ir.Load) {
		load := &ir.Load{
			Dest:    ir.Variable{Name: "t0", Type: ir.IntType{Width: ir.Size8}},
			Address: ir.ConstantExpr{Value: ir.IntConstant{Value: int64(addr), Width: ir.Size8}},
			Size:    ir.Size8,
		}
		load.Loc.Address = 0x1000
		block := &ir.BasicBlock{
			ID:           0,
			Instructions: []ir.IRInstruction{load},
		}
		fn := &ir.Function{
			Name:       "test",
			EntryBlock: 0,
			Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		}
		return fn, load
	}

	t.Run("case1_load_address_symbolized", func(t *testing.T) {
		// ir.Load with address 0x27e90 → db has __environ at that address
		fn, load := makeLoadFunc(0x27e90)
		db := binfmt.NewGroundTruthDatabase()
		db.SymbolsByAddress[0x27e90] = "__environ"

		symbolizeAddresses(fn, db, nil)

		varExpr, ok := load.Address.(ir.VariableExpr)
		if !ok {
			t.Fatalf("case1: expected VariableExpr, got %T", load.Address)
		}
		if varExpr.Var.Name != "&__environ" {
			t.Errorf("case1: expected &__environ, got %q", varExpr.Var.Name)
		}
	})

	t.Run("case2_store_address_via_imports", func(t *testing.T) {
		// ir.Store with address 0x601020 → db.Imports has stderr
		store := &ir.Store{
			Address: ir.ConstantExpr{Value: ir.IntConstant{Value: 0x601020, Width: ir.Size8}},
			Value:   ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size8}},
			Size:    ir.Size8,
		}
		store.Loc.Address = 0x1000
		block := &ir.BasicBlock{
			ID:           0,
			Instructions: []ir.IRInstruction{store},
		}
		fn := &ir.Function{
			Name:       "test",
			EntryBlock: 0,
			Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		}
		db := binfmt.NewGroundTruthDatabase()
		db.Imports[0x601020] = &binfmt.Import{Name: "stderr"}

		symbolizeAddresses(fn, db, nil)

		varExpr, ok := store.Address.(ir.VariableExpr)
		if !ok {
			t.Fatalf("case2: expected VariableExpr, got %T", store.Address)
		}
		if varExpr.Var.Name != "&stderr" {
			t.Errorf("case2: expected &stderr, got %q", varExpr.Var.Name)
		}
	})

	t.Run("case3_rip_relative_resolved", func(t *testing.T) {
		// rip-relative: instrAddr=0x1000, instrLen=7, disp=0x100
		// rip = 0x1007, target = 0x1107 → db has "global_var" at 0x1107
		const instrAddr disasm.Address = 0x1000
		const instrLen = 7
		const disp int64 = 0x100
		const targetAddr = uint64(instrAddr) + instrLen + uint64(disp)

		ripExpr := ir.BinaryOp{
			Op:    ir.BinOpAdd,
			Left:  ir.VariableExpr{Var: ir.Variable{Name: "rip", Type: ir.IntType{Width: ir.Size8}}},
			Right: ir.ConstantExpr{Value: ir.IntConstant{Value: disp, Width: ir.Size8}},
		}
		load := &ir.Load{
			Dest:    ir.Variable{Name: "t0", Type: ir.IntType{Width: ir.Size8}},
			Address: ripExpr,
			Size:    ir.Size8,
		}
		load.Loc.Address = ir.Address(instrAddr)
		block := &ir.BasicBlock{
			ID:           0,
			Instructions: []ir.IRInstruction{load},
		}
		fn := &ir.Function{
			Name:       "test",
			EntryBlock: 0,
			Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		}
		db := binfmt.NewGroundTruthDatabase()
		db.SymbolsByAddress[binfmt.Address(targetAddr)] = "global_var"

		rawInsns := []*disasm.Instruction{
			{Address: instrAddr, Length: instrLen, Mnemonic: "mov"},
		}
		symbolizeAddresses(fn, db, rawInsns)

		varExpr, ok := load.Address.(ir.VariableExpr)
		if !ok {
			t.Fatalf("case3: expected VariableExpr, got %T", load.Address)
		}
		if varExpr.Var.Name != "&global_var" {
			t.Errorf("case3: expected &global_var, got %q", varExpr.Var.Name)
		}
	})

	t.Run("case4_small_constant_unchanged", func(t *testing.T) {
		// constant 0x1234 (≤ 0xffff) must not be symbolized
		fn, load := makeLoadFunc(0x1234)
		db := binfmt.NewGroundTruthDatabase()
		db.SymbolsByAddress[0x1234] = "some_sym"

		symbolizeAddresses(fn, db, nil)

		// address must remain a ConstantExpr
		if _, ok := load.Address.(ir.ConstantExpr); !ok {
			t.Errorf("case4: small constant should remain ConstantExpr, got %T", load.Address)
		}
	})

	t.Run("case5_unknown_large_constant_unchanged", func(t *testing.T) {
		// large constant not in db → expression unchanged
		fn, load := makeLoadFunc(0xdeadbeef)
		db := binfmt.NewGroundTruthDatabase()

		symbolizeAddresses(fn, db, nil)

		if _, ok := load.Address.(ir.ConstantExpr); !ok {
			t.Errorf("case5: unknown address should remain ConstantExpr, got %T", load.Address)
		}
	})

	t.Run("case6_nil_database_unchanged", func(t *testing.T) {
		// nil database → no changes
		fn, load := makeLoadFunc(0x27e90)
		origAddr := load.Address

		symbolizeAddresses(fn, nil, nil)

		if load.Address != origAddr {
			t.Errorf("case6: nil db should leave address unchanged")
		}
	})
}
