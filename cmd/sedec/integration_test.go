package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// integration tests with real binaries
// these tests require gcc to be installed

func TestIntegration_DisasmRealBinary(t *testing.T) {
	// check if gcc is available
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not available, skipping integration test")
	}

	// create temporary directory
	tmpDir := t.TempDir()

	// create simple c program
	cFile := filepath.Join(tmpDir, "test.c")
	if err := os.WriteFile(cFile, []byte("int main() { return 42; }"), 0o644); err != nil {
		t.Fatalf("failed to create test.c: %v", err)
	}

	// compile it
	binaryFile := filepath.Join(tmpDir, "test")
	cmd := exec.Command("gcc", "-o", binaryFile, cFile)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile test binary: %v", err)
	}

	// test disassembly
	var stdout, stderr bytes.Buffer
	err := run([]string{"disasm", binaryFile}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("disasm failed: %v\nstderr: %s", err, stderr.String())
	}

	output := stdout.String()

	// verify output contains expected elements
	if !strings.Contains(output, "sedec disassembly output") {
		t.Errorf("missing header")
	}
	if !strings.Contains(output, "format: ELF") {
		t.Errorf("missing format")
	}
	if !strings.Contains(output, "architecture: x86_64") {
		t.Errorf("missing architecture")
	}
	if !strings.Contains(output, "0x") {
		t.Errorf("missing addresses")
	}
}

func TestIntegration_DisasmMainFunction(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not available, skipping integration test")
	}

	tmpDir := t.TempDir()
	cFile := filepath.Join(tmpDir, "test.c")
	if err := os.WriteFile(cFile, []byte("int main() { return 42; }"), 0o644); err != nil {
		t.Fatalf("failed to create test.c: %v", err)
	}

	binaryFile := filepath.Join(tmpDir, "test")
	cmd := exec.Command("gcc", "-o", binaryFile, cFile)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile: %v", err)
	}

	// disassemble main function
	var stdout, stderr bytes.Buffer
	err := run([]string{"disasm", "--function", "main", binaryFile}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("disasm failed: %v\nstderr: %s", err, stderr.String())
	}

	output := stdout.String()

	// verify function-specific output
	if !strings.Contains(output, "function: main") {
		t.Errorf("missing function name")
	}
	if !strings.Contains(output, "address:") {
		t.Errorf("missing function address")
	}

	// verify we got assembly instructions
	if !strings.Contains(output, "push") || !strings.Contains(output, "ret") {
		t.Errorf("missing expected instructions")
	}

	// verify return value 42 (0x2a) is in the code
	if !strings.Contains(output, "0x2a") {
		t.Errorf("missing return value 0x2a (42)")
	}
}

func TestIntegration_DisasmByAddress(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not available, skipping integration test")
	}

	tmpDir := t.TempDir()
	cFile := filepath.Join(tmpDir, "test.c")
	if err := os.WriteFile(cFile, []byte("int main() { return 42; }"), 0o644); err != nil {
		t.Fatalf("failed to create test.c: %v", err)
	}

	binaryFile := filepath.Join(tmpDir, "test")
	cmd := exec.Command("gcc", "-o", binaryFile, cFile)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile: %v", err)
	}

	// first, get main address
	var stdout1, stderr1 bytes.Buffer
	err := run([]string{"disasm", "--function", "main", binaryFile}, nil, &stdout1, &stderr1)
	if err != nil {
		t.Fatalf("first disasm failed: %v", err)
	}

	// extract address from output
	output1 := stdout1.String()
	lines := strings.Split(output1, "\n")
	var mainAddr string
	for _, line := range lines {
		if strings.Contains(line, "address:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				mainAddr = parts[len(parts)-1]
				break
			}
		}
	}

	if mainAddr == "" {
		t.Fatal("could not extract main address")
	}

	// now disassemble by address
	var stdout2, stderr2 bytes.Buffer
	err = run([]string{"disasm", "--function", mainAddr, binaryFile}, nil, &stdout2, &stderr2)
	if err != nil {
		t.Fatalf("disasm by address failed: %v", err)
	}

	output2 := stdout2.String()

	// verify we got the same function
	if !strings.Contains(output2, mainAddr) {
		t.Errorf("missing address %s in output", mainAddr)
	}
	if !strings.Contains(output2, "0x2a") {
		t.Errorf("missing return value in disassembly by address")
	}
}

func TestIntegration_DisasmToFile(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not available, skipping integration test")
	}

	tmpDir := t.TempDir()
	cFile := filepath.Join(tmpDir, "test.c")
	if err := os.WriteFile(cFile, []byte("int main() { return 42; }"), 0o644); err != nil {
		t.Fatalf("failed to create test.c: %v", err)
	}

	binaryFile := filepath.Join(tmpDir, "test")
	cmd := exec.Command("gcc", "-o", binaryFile, cFile)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile: %v", err)
	}

	outputFile := filepath.Join(tmpDir, "output.asm")

	// disassemble to file
	var stdout, stderr bytes.Buffer
	err := run([]string{"disasm", "--function", "main", "--output", outputFile, binaryFile}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("disasm failed: %v", err)
	}

	// verify stdout is empty (output went to file)
	if stdout.Len() > 0 {
		t.Errorf("expected empty stdout, got: %s", stdout.String())
	}

	// verify output file exists and has content
	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	output := string(content)
	if !strings.Contains(output, "function: main") {
		t.Errorf("output file missing function name")
	}
	if !strings.Contains(output, "0x2a") {
		t.Errorf("output file missing return value")
	}
}

func TestIntegration_DisasmFromStdin(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not available, skipping integration test")
	}

	tmpDir := t.TempDir()
	cFile := filepath.Join(tmpDir, "test.c")
	if err := os.WriteFile(cFile, []byte("int main() { return 42; }"), 0o644); err != nil {
		t.Fatalf("failed to create test.c: %v", err)
	}

	binaryFile := filepath.Join(tmpDir, "test")
	cmd := exec.Command("gcc", "-o", binaryFile, cFile)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile: %v", err)
	}

	// read binary into memory
	binaryData, err := os.ReadFile(binaryFile)
	if err != nil {
		t.Fatalf("failed to read binary: %v", err)
	}

	// disassemble from stdin
	var stdout, stderr bytes.Buffer
	stdin := bytes.NewReader(binaryData)
	err = run([]string{"disasm", "--function", "main"}, stdin, &stdout, &stderr)
	if err != nil {
		t.Fatalf("disasm from stdin failed: %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "function: main") {
		t.Errorf("missing function name")
	}
	if !strings.Contains(output, "0x2a") {
		t.Errorf("missing return value")
	}
}

func TestIntegration_DisasmIntelSyntax(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not available, skipping integration test")
	}

	tmpDir := t.TempDir()
	cFile := filepath.Join(tmpDir, "test.c")
	if err := os.WriteFile(cFile, []byte("int main() { return 42; }"), 0o644); err != nil {
		t.Fatalf("failed to create test.c: %v", err)
	}

	binaryFile := filepath.Join(tmpDir, "test")
	cmd := exec.Command("gcc", "-o", binaryFile, cFile)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile: %v", err)
	}

	// disassemble with intel syntax
	var stdout, stderr bytes.Buffer
	err := run([]string{"disasm", "--format", "intel", "--function", "main", binaryFile}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("disasm failed: %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "syntax: intel") {
		t.Errorf("missing intel syntax marker")
	}
}

func TestIntegration_DisasmComplexProgram(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not available, skipping integration test")
	}

	tmpDir := t.TempDir()
	cFile := filepath.Join(tmpDir, "test.c")

	// more complex program with multiple functions
	code := `
int add(int a, int b) {
    return a + b;
}

int main() {
    int x = 10;
    int y = 32;
    return add(x, y);
}
`
	if err := os.WriteFile(cFile, []byte(code), 0o644); err != nil {
		t.Fatalf("failed to create test.c: %v", err)
	}

	binaryFile := filepath.Join(tmpDir, "test")
	cmd := exec.Command("gcc", "-o", binaryFile, cFile)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile: %v", err)
	}

	// disassemble main
	var stdout1, stderr1 bytes.Buffer
	err := run([]string{"disasm", "--function", "main", binaryFile}, nil, &stdout1, &stderr1)
	if err != nil {
		t.Fatalf("disasm main failed: %v", err)
	}

	output1 := stdout1.String()
	if !strings.Contains(output1, "function: main") {
		t.Errorf("missing main function")
	}

	// disassemble add function
	var stdout2, stderr2 bytes.Buffer
	err = run([]string{"disasm", "--function", "add", binaryFile}, nil, &stdout2, &stderr2)
	if err != nil {
		t.Fatalf("disasm add failed: %v", err)
	}

	output2 := stdout2.String()
	if !strings.Contains(output2, "function: add") {
		t.Errorf("missing add function")
	}
}
