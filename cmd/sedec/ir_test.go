package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunIR_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := runIR([]string{"--help"}, &bytes.Buffer{}, &stdout, &stderr)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	output := stderr.String()
	if !strings.Contains(output, "usage: sedec ir") {
		t.Errorf("expected usage message in stderr, got: %s", output)
	}
	if !strings.Contains(output, "--ssa") {
		t.Errorf("expected --ssa flag in help, got: %s", output)
	}
}

func TestRunIR_NoInput(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := runIR([]string{}, &bytes.Buffer{}, &stdout, &stderr)

	if err == nil {
		t.Fatal("expected error for no input, got nil")
	}

	if !strings.Contains(err.Error(), "no input provided") {
		t.Errorf("expected 'no input provided' error, got: %v", err)
	}
}

func TestRunIR_InvalidBinary(t *testing.T) {
	var stdout, stderr bytes.Buffer
	invalidData := []byte("not a valid binary")

	err := runIR([]string{}, bytes.NewReader(invalidData), &stdout, &stderr)

	if err == nil {
		t.Fatal("expected error for invalid binary, got nil")
	}

	if !strings.Contains(err.Error(), "failed to parse binary") {
		t.Errorf("expected 'failed to parse binary' error, got: %v", err)
	}
}

func TestRunIR_TooManyArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := runIR([]string{"file1", "file2"}, &bytes.Buffer{}, &stdout, &stderr)

	if err == nil {
		t.Fatal("expected error for too many arguments, got nil")
	}

	if !strings.Contains(err.Error(), "too many arguments") {
		t.Errorf("expected 'too many arguments' error, got: %v", err)
	}
}

func TestRunIR_FileNotFound(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := runIR([]string{"nonexistent_file_xyz.bin"}, &bytes.Buffer{}, &stdout, &stderr)

	if err == nil {
		t.Fatal("expected error for file not found, got nil")
	}

	if !strings.Contains(err.Error(), "file not found") {
		t.Errorf("expected 'file not found' error, got: %v", err)
	}
}

func TestRunIR_SSAFlag(t *testing.T) {
	// test that ssa flag is parsed correctly
	var stdout, stderr bytes.Buffer

	// this will fail at binary parsing stage, but we can verify flag parsing
	err := runIR([]string{"--ssa"}, &bytes.Buffer{}, &stdout, &stderr)

	if err == nil {
		t.Fatal("expected error (no input), got nil")
	}

	// verify error is about input, not flag parsing
	if !strings.Contains(err.Error(), "no input provided") {
		t.Errorf("expected 'no input provided' error after flag parsing, got: %v", err)
	}
}

func TestRunIR_OutputFlag(t *testing.T) {
	// test that output flag is parsed correctly
	var stdout, stderr bytes.Buffer

	// this will fail at binary parsing stage, but we can verify flag parsing
	err := runIR([]string{"--output", "test.ir"}, &bytes.Buffer{}, &stdout, &stderr)

	if err == nil {
		t.Fatal("expected error (no input), got nil")
	}

	// verify error is about input, not flag parsing
	if !strings.Contains(err.Error(), "no input provided") {
		t.Errorf("expected 'no input provided' error after flag parsing, got: %v", err)
	}
}

func TestRunIR_FunctionFlag(t *testing.T) {
	// test that function flag is parsed correctly
	var stdout, stderr bytes.Buffer

	// this will fail at binary parsing stage, but we can verify flag parsing
	err := runIR([]string{"--function", "main"}, &bytes.Buffer{}, &stdout, &stderr)

	if err == nil {
		t.Fatal("expected error (no input), got nil")
	}

	// verify error is about input, not flag parsing
	if !strings.Contains(err.Error(), "no input provided") {
		t.Errorf("expected 'no input provided' error after flag parsing, got: %v", err)
	}
}
