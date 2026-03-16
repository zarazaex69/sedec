//nolint:godot // cli test file
package main

import (
	"bytes"
	"strings"
	"testing"
)

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
