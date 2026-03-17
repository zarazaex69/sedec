// package main — property-based test for defect 5:
// function names derived from elf section names or symbol names must be valid c identifiers.
//
// **Validates: Requirements 2.9, 2.10**
//
// property 5 (bug condition): for all function chunks produced by splitOnRetBoundaries
// or splitSectionIntoFunctions, every chunk.name must match /^[a-zA-Z_][a-zA-Z0-9_]*$/.
//
// this test MUST FAIL on unfixed code — failure confirms the bug exists.
// the bug: splitOnRetBoundaries builds names as fmt.Sprintf("%s_func%d", sectionName, idx)
// without sanitizing sectionName, so ".init" produces ".init_func0" which begins with a dot
// and is not a valid c identifier.
//
// documented counterexample (from running on unfixed code):
// chunk name ".init_func0" does not match /^[a-zA-Z_][a-zA-Z0-9_]*$/ —
// the leading dot makes it syntactically invalid as a c function name,
// producing output like "void .init_func0(){" which no c compiler accepts.
package main

import (
	"regexp"
	"testing"

	binfmt "github.com/zarazaex69/sedec/pkg/binary"
	"github.com/zarazaex69/sedec/pkg/disasm"
	"pgregory.net/rapid"
)

// cIdentifierRegex is the canonical c identifier pattern.
// a valid c identifier starts with a letter or underscore,
// followed by zero or more letters, digits, or underscores.
var cIdentifierRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// isValidCIdentifier reports whether s is a valid c identifier.
func isValidCIdentifier(s string) bool {
	return cIdentifierRegex.MatchString(s)
}

// makeRetInstruction builds a minimal ret instruction at the given address.
// used to create instruction slices that trigger chunk boundaries in splitOnRetBoundaries.
func makeRetInstruction(addr disasm.Address) *disasm.Instruction {
	return &disasm.Instruction{
		Mnemonic: "ret",
		Operands: nil,
		Address:  addr,
		Bytes:    []byte{0xc3},
		Length:   1,
	}
}

// makeNopInstruction builds a minimal nop instruction at the given address.
func makeNopInstruction(addr disasm.Address) *disasm.Instruction {
	return &disasm.Instruction{
		Mnemonic: "nop",
		Operands: nil,
		Address:  addr,
		Bytes:    []byte{0x90},
		Length:   1,
	}
}

// makeTwoChunkInstructions builds a minimal instruction slice that produces
// exactly two chunks when passed to splitOnRetBoundaries:
// [nop, ret, nop, ret] at consecutive addresses starting from baseAddr.
func makeTwoChunkInstructions(baseAddr disasm.Address) []*disasm.Instruction {
	return []*disasm.Instruction{
		makeNopInstruction(baseAddr),
		makeRetInstruction(baseAddr + 1),
		makeNopInstruction(baseAddr + 2),
		makeRetInstruction(baseAddr + 3),
	}
}

// TestProperty5_BugCondition_DotInitSectionName is the deterministic concrete test.
// it calls splitOnRetBoundaries with sectionName = ".init" and asserts that
// all resulting chunk names are valid c identifiers.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// the bug produces ".init_func0" and ".init_func1" which begin with a dot
// and do not match /^[a-zA-Z_][a-zA-Z0-9_]*$/.
//
// documented counterexample:
// chunk name ".init_func0" does not match /^[a-zA-Z_][a-zA-Z0-9_]*$/
func TestProperty5_BugCondition_DotInitSectionName(t *testing.T) {
	instrs := makeTwoChunkInstructions(0x1000)
	chunks := splitOnRetBoundaries(instrs, ".init")

	if len(chunks) == 0 {
		t.Fatal("splitOnRetBoundaries returned no chunks for non-empty instruction slice")
	}

	for _, chunk := range chunks {
		if !isValidCIdentifier(chunk.name) {
			t.Errorf(
				"bug confirmed: chunk name %q does not match /^[a-zA-Z_][a-zA-Z0-9_]*$/\n"+
					"counterexample: sectionName=\".init\" produces invalid c identifier %q",
				chunk.name, chunk.name,
			)
		}
	}
}

// TestProperty5_BugCondition_AtSignSectionName tests that section names containing
// '@' (common in elf versioned symbols) produce valid c identifiers.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// "@plt_func0" begins with '@' which is not a valid c identifier start character.
func TestProperty5_BugCondition_AtSignSectionName(t *testing.T) {
	instrs := makeTwoChunkInstructions(0x2000)
	chunks := splitOnRetBoundaries(instrs, "@plt")

	for _, chunk := range chunks {
		if !isValidCIdentifier(chunk.name) {
			t.Errorf(
				"bug confirmed: chunk name %q does not match /^[a-zA-Z_][a-zA-Z0-9_]*$/\n"+
					"counterexample: sectionName=\"@plt\" produces invalid c identifier %q",
				chunk.name, chunk.name,
			)
		}
	}
}

// TestProperty5_BugCondition_NumericSectionName tests that section names starting
// with a digit produce valid c identifiers.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// "12767_func0" begins with a digit which is not valid in c.
func TestProperty5_BugCondition_NumericSectionName(t *testing.T) {
	instrs := makeTwoChunkInstructions(0x3000)
	chunks := splitOnRetBoundaries(instrs, "12767")

	for _, chunk := range chunks {
		if !isValidCIdentifier(chunk.name) {
			t.Errorf(
				"bug confirmed: chunk name %q does not match /^[a-zA-Z_][a-zA-Z0-9_]*$/\n"+
					"counterexample: sectionName=\"12767\" produces invalid c identifier %q",
				chunk.name, chunk.name,
			)
		}
	}
}

// TestProperty5_BugCondition_HyphenSectionName tests that section names containing
// hyphens (e.g., ".gnu.version-r") produce valid c identifiers.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// ".gnu-version_func0" contains a dot and hyphen, both invalid in c identifiers.
func TestProperty5_BugCondition_HyphenSectionName(t *testing.T) {
	instrs := makeTwoChunkInstructions(0x4000)
	chunks := splitOnRetBoundaries(instrs, ".gnu-version")

	for _, chunk := range chunks {
		if !isValidCIdentifier(chunk.name) {
			t.Errorf(
				"bug confirmed: chunk name %q does not match /^[a-zA-Z_][a-zA-Z0-9_]*$/\n"+
					"counterexample: sectionName=\".gnu-version\" produces invalid c identifier %q",
				chunk.name, chunk.name,
			)
		}
	}
}

// TestProperty5_BugCondition_SymbolWithAtSign tests splitSectionIntoFunctions
// with symbol names containing '@' (e.g., "printf@GLIBC_2.2.5").
// these are versioned dynamic symbol names common in linux elf binaries.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// "printf@GLIBC_2.2.5" contains '@' and '.' which are invalid in c identifiers.
func TestProperty5_BugCondition_SymbolWithAtSign(t *testing.T) {
	baseAddr := disasm.Address(0x401000)
	instrs := []*disasm.Instruction{
		makeNopInstruction(baseAddr),
		makeNopInstruction(baseAddr + 1),
		makeRetInstruction(baseAddr + 2),
	}

	// symbol with versioned name — common in glibc-linked binaries
	symbols := []*binfmt.Symbol{
		{
			Name:    "printf@GLIBC_2.2.5",
			Address: binfmt.Address(baseAddr),
			Type:    binfmt.SymbolTypeFunction,
			Size:    3,
		},
	}

	chunks := splitSectionIntoFunctions(instrs, symbols, ".text")

	for _, chunk := range chunks {
		if !isValidCIdentifier(chunk.name) {
			t.Errorf(
				"bug confirmed: chunk name %q does not match /^[a-zA-Z_][a-zA-Z0-9_]*$/\n"+
					"counterexample: symbol name \"printf@GLIBC_2.2.5\" produces invalid c identifier %q",
				chunk.name, chunk.name,
			)
		}
	}
}

// TestProperty5_BugCondition_NumericOnlySymbolName tests splitSectionIntoFunctions
// with a numeric-only symbol name (e.g., "12767").
// numeric-only names appear in stripped binaries where addresses are used as names.
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// "12767" begins with a digit and is not a valid c identifier.
func TestProperty5_BugCondition_NumericOnlySymbolName(t *testing.T) {
	baseAddr := disasm.Address(0x402000)
	instrs := []*disasm.Instruction{
		makeNopInstruction(baseAddr),
		makeRetInstruction(baseAddr + 1),
	}

	symbols := []*binfmt.Symbol{
		{
			Name:    "12767",
			Address: binfmt.Address(baseAddr),
			Type:    binfmt.SymbolTypeFunction,
			Size:    2,
		},
	}

	chunks := splitSectionIntoFunctions(instrs, symbols, ".text")

	for _, chunk := range chunks {
		if !isValidCIdentifier(chunk.name) {
			t.Errorf(
				"bug confirmed: chunk name %q does not match /^[a-zA-Z_][a-zA-Z0-9_]*$/\n"+
					"counterexample: symbol name \"12767\" produces invalid c identifier %q",
				chunk.name, chunk.name,
			)
		}
	}
}

// elfSectionNameGenerator is a rapid generator that produces random elf section names,
// including names that start with '.', '@', '-', digits, and other invalid c identifier chars.
// this covers the full space of real-world elf section names encountered in linux binaries.
func elfSectionNameGenerator() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		// draw a prefix character that is likely to be invalid in c identifiers
		prefixChars := []string{
			".", "@", "-", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
			"$", "#", "!", "+", "=", "[", "]", "{", "}", "|", "\\", "/", "?",
			"<", ">", ",", ";", ":", "'", "\"", "`", "~", "^", "&", "*", "(",
			")", "%",
		}
		// 70% chance of invalid prefix, 30% chance of valid prefix
		useInvalidPrefix := rapid.IntRange(0, 9).Draw(t, "useInvalidPrefix") < 7
		var prefix string
		if useInvalidPrefix {
			idx := rapid.IntRange(0, len(prefixChars)-1).Draw(t, "prefixIdx")
			prefix = prefixChars[idx]
		} else {
			// valid c identifier start: letter or underscore
			validStarts := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
			idx := rapid.IntRange(0, len(validStarts)-1).Draw(t, "validStartIdx")
			prefix = string(validStarts[idx])
		}

		// draw 1–12 additional characters from a mixed set
		bodyLen := rapid.IntRange(1, 12).Draw(t, "bodyLen")
		bodyChars := "abcdefghijklmnopqrstuvwxyz0123456789_.-@$"
		body := make([]byte, bodyLen)
		for i := range body {
			idx := rapid.IntRange(0, len(bodyChars)-1).Draw(t, "bodyChar")
			body[i] = bodyChars[idx]
		}

		return prefix + string(body)
	})
}

// TestProperty5_BugCondition_RapidSectionNames is the property-based test using
// pgregory.net/rapid to generate random elf section names and assert that all
// resulting chunk names from splitOnRetBoundaries are valid c identifiers.
//
// **Validates: Requirements 2.9, 2.10**
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// rapid will quickly find a counterexample with a section name starting with '.'
// (e.g., ".text", ".init", ".plt") and demonstrate that the resulting chunk name
// does not match /^[a-zA-Z_][a-zA-Z0-9_]*$/.
//
// documented counterexample (from running on unfixed code):
// sectionName=".init" → chunk name ".init_func0" does not match
// /^[a-zA-Z_][a-zA-Z0-9_]*$/ — the leading dot is syntactically invalid in c.
func TestProperty5_BugCondition_RapidSectionNames(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		sectionName := elfSectionNameGenerator().Draw(rt, "sectionName")

		// build a minimal instruction slice: one nop + one ret = one chunk
		baseAddr := disasm.Address(0x1000)
		instrs := []*disasm.Instruction{
			makeNopInstruction(baseAddr),
			makeRetInstruction(baseAddr + 1),
		}

		chunks := splitOnRetBoundaries(instrs, sectionName)
		if len(chunks) == 0 {
			// no chunks produced — nothing to validate
			return
		}

		for _, chunk := range chunks {
			if !isValidCIdentifier(chunk.name) {
				rt.Errorf(
					"counterexample: sectionName=%q produces invalid c identifier %q\n"+
						"chunk name does not match /^[a-zA-Z_][a-zA-Z0-9_]*$/",
					sectionName, chunk.name,
				)
			}
		}
	})
}

// TestProperty5_BugCondition_RapidSymbolNames is the property-based test using
// pgregory.net/rapid to generate random symbol names containing '@', '.', '-',
// digits, and other invalid c identifier characters, and assert that all resulting
// chunk names from splitSectionIntoFunctions are valid c identifiers.
//
// **Validates: Requirements 2.9, 2.10**
//
// EXPECTED OUTCOME ON UNFIXED CODE: FAIL
// rapid will find counterexamples like "printf@GLIBC_2.2.5" or ".hidden_func"
// where the raw symbol name is used verbatim as the c function name.
func TestProperty5_BugCondition_RapidSymbolNames(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// generate a symbol name that contains at least one invalid c identifier character
		invalidChars := []byte{'@', '.', '-', '$', '#', '!', '+', '=', '/', '\\', '?', '<', '>', ',', ';', ':', '\'', '"', '`', '~', '^', '&', '*', '(', ')', '%', '[', ']', '{', '}', '|'}
		baseChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

		// build a symbol name: 1–8 base chars + one invalid char + 1–8 base chars
		prefixLen := rapid.IntRange(0, 8).Draw(rt, "prefixLen")
		prefix := make([]byte, prefixLen)
		for i := range prefix {
			idx := rapid.IntRange(0, len(baseChars)-1).Draw(rt, "prefixChar")
			prefix[i] = baseChars[idx]
		}

		invalidIdx := rapid.IntRange(0, len(invalidChars)-1).Draw(rt, "invalidCharIdx")
		invalidChar := invalidChars[invalidIdx]

		suffixLen := rapid.IntRange(1, 8).Draw(rt, "suffixLen")
		suffix := make([]byte, suffixLen)
		for i := range suffix {
			idx := rapid.IntRange(0, len(baseChars)-1).Draw(rt, "suffixChar")
			suffix[i] = baseChars[idx]
		}

		symName := string(prefix) + string(invalidChar) + string(suffix)

		baseAddr := disasm.Address(0x401000)
		instrs := []*disasm.Instruction{
			makeNopInstruction(baseAddr),
			makeRetInstruction(baseAddr + 1),
		}

		symbols := []*binfmt.Symbol{
			{
				Name:    symName,
				Address: binfmt.Address(baseAddr),
				Type:    binfmt.SymbolTypeFunction,
				Size:    2,
			},
		}

		chunks := splitSectionIntoFunctions(instrs, symbols, ".text")
		if len(chunks) == 0 {
			return
		}

		for _, chunk := range chunks {
			if !isValidCIdentifier(chunk.name) {
				rt.Errorf(
					"counterexample: symbol name %q produces invalid c identifier %q\n"+
						"chunk name does not match /^[a-zA-Z_][a-zA-Z0-9_]*$/",
					symName, chunk.name,
				)
			}
		}
	})
}

// ============================================================================
// preservation 5: already-valid c identifiers are used verbatim
// ============================================================================

// TestPreservation5_ValidIdentifiersUnchanged verifies that function names that
// already match /^[a-zA-Z_][a-zA-Z0-9_]*$/ are returned unchanged by
// sanitizeFunctionName and used verbatim in splitSectionIntoFunctions.
//
// **Validates: Requirements 3.9, 3.10**
//
// this is the preservation guarantee for fix 5: the sanitization function must
// not modify names that are already valid c identifiers.
// names like "main", "printf", "__libc_start_main" must pass through unchanged.
//
// EXPECTED OUTCOME: PASS on both unfixed and fixed code.
// the sanitizeFunctionName function has an explicit preservation check:
// if name already matches /^[a-zA-Z_][a-zA-Z0-9_]*$/, return it unchanged.
func TestPreservation5_ValidIdentifiersUnchanged(t *testing.T) {
	// concrete cases from the design doc
	validNames := []string{
		"main",
		"printf",
		"__libc_start_main",
		"_start",
		"__cxa_finalize",
		"malloc",
		"free",
		"exit",
		"abort",
		"strlen",
		"strcmp",
		"memcpy",
		"__stack_chk_fail",
		"_IO_2_1_stderr_",
		"fn_test",
		"sub_00401000",
		"a",
		"_",
		"A",
		"Z",
		"z",
		"_0",
		"a0",
	}

	for _, name := range validNames {
		result := sanitizeFunctionName(name, 0)
		if result != name {
			t.Errorf(
				"preservation violated: valid identifier %q was modified to %q — "+
					"sanitizeFunctionName must return valid identifiers unchanged",
				name, result,
			)
		}
	}
}

// TestPreservation5_RapidValidIdentifiersUnchanged is the property-based test
// using pgregory.net/rapid to generate random valid c identifiers and verify
// that sanitizeFunctionName returns them unchanged.
//
// **Validates: Requirements 3.9, 3.10**
//
// EXPECTED OUTCOME: PASS on both unfixed and fixed code.
func TestPreservation5_RapidValidIdentifiersUnchanged(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// generate a valid c identifier: starts with letter or underscore,
		// followed by letters, digits, or underscores
		name := validCIdentifierGenerator().Draw(rt, "validName")

		result := sanitizeFunctionName(name, 0)
		if result != name {
			rt.Errorf(
				"preservation violated: valid identifier %q was modified to %q\n"+
					"sanitizeFunctionName must return valid c identifiers unchanged",
				name, result,
			)
		}
	})
}

// validCIdentifierGenerator produces random strings matching /^[a-zA-Z_][a-zA-Z0-9_]*$/.
func validCIdentifierGenerator() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		// first character: letter or underscore
		firstChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
		firstIdx := rapid.IntRange(0, len(firstChars)-1).Draw(t, "firstChar")
		first := string(firstChars[firstIdx])

		// body: 0–15 letters, digits, or underscores
		bodyLen := rapid.IntRange(0, 15).Draw(t, "bodyLen")
		bodyChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
		body := make([]byte, bodyLen)
		for i := range body {
			idx := rapid.IntRange(0, len(bodyChars)-1).Draw(t, "bodyChar")
			body[i] = bodyChars[idx]
		}

		return first + string(body)
	})
}

// TestPreservation5_ValidSymbolNamesUnchangedInSplitSection verifies that
// splitSectionIntoFunctions uses valid symbol names verbatim without modification.
//
// **Validates: Requirements 3.9, 3.10**
//
// EXPECTED OUTCOME: PASS on both unfixed and fixed code.
func TestPreservation5_ValidSymbolNamesUnchangedInSplitSection(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// generate a valid c identifier as symbol name
		symName := validCIdentifierGenerator().Draw(rt, "symName")

		baseAddr := disasm.Address(0x401000)
		instrs := []*disasm.Instruction{
			makeNopInstruction(baseAddr),
			makeRetInstruction(baseAddr + 1),
		}

		symbols := []*binfmt.Symbol{
			{
				Name:    symName,
				Address: binfmt.Address(baseAddr),
				Type:    binfmt.SymbolTypeFunction,
				Size:    2,
			},
		}

		chunks := splitSectionIntoFunctions(instrs, symbols, ".text")
		if len(chunks) == 0 {
			// no chunks produced — skip
			return
		}

		for _, chunk := range chunks {
			if chunk.name != symName {
				rt.Errorf(
					"preservation violated: valid symbol name %q was modified to %q\n"+
						"splitSectionIntoFunctions must use valid c identifiers verbatim",
					symName, chunk.name,
				)
			}
		}
	})
}
