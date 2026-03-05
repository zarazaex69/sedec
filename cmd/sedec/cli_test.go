package main

import (
	"bytes"
	"strings"
	"testing"
)

// cli unit tests - test command line parsing and argument handling
// integration tests with real binaries are in separate test files

func TestCLI_Version(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"long flag", []string{"--version"}},
		{"short flag", []string{"-version"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			err := run(tt.args, nil, &stdout, &stderr)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			output := stdout.String()
			if !strings.Contains(output, "sedec version") {
				t.Errorf("expected version output, got: %s", output)
			}
			if !strings.Contains(output, version) {
				t.Errorf("expected version %s in output, got: %s", version, output)
			}
		})
	}
}

func TestCLI_Help(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"long flag", []string{"--help"}},
		{"short flag", []string{"-help"}},
		{"help command", []string{"help"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			err := run(tt.args, nil, &stdout, &stderr)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			output := stdout.String()
			if !strings.Contains(output, "usage:") {
				t.Errorf("expected usage information, got: %s", output)
			}
			if !strings.Contains(output, "commands:") {
				t.Errorf("expected commands section, got: %s", output)
			}
			if !strings.Contains(output, "disasm") {
				t.Errorf("expected disasm command in help, got: %s", output)
			}
		})
	}
}

func TestCLI_NoArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := run([]string{}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stderr.String()
	if !strings.Contains(output, "usage:") {
		t.Errorf("expected usage information on stderr, got: %s", output)
	}
}

func TestCLI_UnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := run([]string{"unknown"}, nil, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for unknown command")
	}

	if !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("expected 'unknown command' error, got: %v", err)
	}

	output := stderr.String()
	if !strings.Contains(output, "unknown command") {
		t.Errorf("expected error message on stderr, got: %s", output)
	}
}

func TestCLI_DisasmHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := run([]string{"disasm", "--help"}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stderr.String()
	if !strings.Contains(output, "usage: sedec disasm") {
		t.Errorf("expected disasm usage, got: %s", output)
	}
	if !strings.Contains(output, "--function") {
		t.Errorf("expected --function flag in help, got: %s", output)
	}
	if !strings.Contains(output, "--output") {
		t.Errorf("expected --output flag in help, got: %s", output)
	}
	if !strings.Contains(output, "--format") {
		t.Errorf("expected --format flag in help, got: %s", output)
	}
}

func TestCLI_DisasmInvalidFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	stdin := bytes.NewReader([]byte{0x90, 0xc3}) // nop; ret

	err := run([]string{"disasm", "--format", "invalid"}, stdin, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for invalid format")
	}

	if !strings.Contains(err.Error(), "invalid format") {
		t.Errorf("expected 'invalid format' error, got: %v", err)
	}
}

func TestCLI_DisasmNoInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	stdin := bytes.NewReader([]byte{}) // empty stdin

	err := run([]string{"disasm"}, stdin, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for no input")
	}

	if !strings.Contains(err.Error(), "no input provided") {
		t.Errorf("expected 'no input provided' error, got: %v", err)
	}
}

func TestCLI_DisasmTooManyArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := run([]string{"disasm", "file1", "file2"}, nil, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for too many arguments")
	}

	if !strings.Contains(err.Error(), "too many arguments") {
		t.Errorf("expected 'too many arguments' error, got: %v", err)
	}
}

func TestCLI_DisasmFileNotFound(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := run([]string{"disasm", "/nonexistent/file/that/does/not/exist"}, nil, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}

	if !strings.Contains(err.Error(), "file not found") && !strings.Contains(err.Error(), "no such file") {
		t.Errorf("expected 'file not found' error, got: %v", err)
	}
}
