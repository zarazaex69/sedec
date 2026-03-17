//nolint:godot // cli test file
package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
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
