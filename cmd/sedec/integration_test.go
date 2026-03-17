package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	//nolint:gosec // G306: test code creates temporary files
	if err := os.WriteFile(cFile, []byte("int main() { return 42; }"), 0o644); err != nil {
		t.Fatalf("failed to create test.c: %v", err)
	}

	// compile it
	binaryFile := filepath.Join(tmpDir, "test")
	//nolint:gosec,noctx // test code runs gcc with controlled arguments
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
	//nolint:gosec // G306: test code creates temporary files
	if err := os.WriteFile(cFile, []byte("int main() { return 42; }"), 0o644); err != nil {
		t.Fatalf("failed to create test.c: %v", err)
	}

	binaryFile := filepath.Join(tmpDir, "test")
	//nolint:gosec,noctx // test code runs gcc with controlled arguments
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
	//nolint:gosec // G306: test code creates temporary files
	if err := os.WriteFile(cFile, []byte("int main() { return 42; }"), 0o644); err != nil {
		t.Fatalf("failed to create test.c: %v", err)
	}

	binaryFile := filepath.Join(tmpDir, "test")
	//nolint:gosec,noctx // test code runs gcc with controlled arguments
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
	//nolint:gosec // G306: test code creates temporary files
	if err := os.WriteFile(cFile, []byte("int main() { return 42; }"), 0o644); err != nil {
		t.Fatalf("failed to create test.c: %v", err)
	}

	binaryFile := filepath.Join(tmpDir, "test")
	//nolint:gosec,noctx // test code runs gcc with controlled arguments
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
	//nolint:gosec // G304: test code reads test files
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
	//nolint:gosec // G306: test code creates temporary files
	if err := os.WriteFile(cFile, []byte("int main() { return 42; }"), 0o644); err != nil {
		t.Fatalf("failed to create test.c: %v", err)
	}

	binaryFile := filepath.Join(tmpDir, "test")
	//nolint:gosec,noctx // test code runs gcc with controlled arguments
	cmd := exec.Command("gcc", "-o", binaryFile, cFile)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile: %v", err)
	}

	// read binary into memory
	//nolint:gosec // G304: test code reads test files
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
	//nolint:gosec // G306: test code creates temporary files
	if err := os.WriteFile(cFile, []byte("int main() { return 42; }"), 0o644); err != nil {
		t.Fatalf("failed to create test.c: %v", err)
	}

	binaryFile := filepath.Join(tmpDir, "test")
	//nolint:gosec,noctx // test code runs gcc with controlled arguments
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
	//nolint:gosec // G306: test code creates temporary files
	if err := os.WriteFile(cFile, []byte(code), 0o644); err != nil {
		t.Fatalf("failed to create test.c: %v", err)
	}

	binaryFile := filepath.Join(tmpDir, "test")
	//nolint:gosec,noctx // test code runs gcc with controlled arguments
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

// compileTestDecompilerBinary compiles examples/test_decompiler.c and returns
// the path to the resulting binary. it skips the test if gcc is unavailable or
// the source file cannot be found.
func compileTestDecompilerBinary(t *testing.T) string {
	t.Helper()

	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not available, skipping integration test")
	}

	// the test package is in cmd/sedec, so walk up two levels to reach the workspace root
	srcFile := filepath.Join("..", "..", "examples", "test_decompiler.c")
	if _, err := os.Stat(srcFile); err != nil {
		t.Skipf("examples/test_decompiler.c not found at %s: %v", srcFile, err)
	}

	binaryPath := filepath.Join(t.TempDir(), "test_decompiler")
	//nolint:gosec,noctx // test code runs gcc with controlled arguments
	compileCmd := exec.Command("gcc", "-O0", "-g", "-o", binaryPath, srcFile)
	if out, err := compileCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile test_decompiler.c: %v\n%s", err, out)
	}

	return binaryPath
}

// decompileSingleFunc runs the decompiler on a single function from the given
// binary and returns the output string. it fails the test on any error.
func decompileSingleFunc(t *testing.T, binaryPath, funcName string) string {
	t.Helper()

	var outBuf, errBuf bytes.Buffer
	if err := runDecompile([]string{"--function", funcName, binaryPath}, nil, &outBuf, &errBuf); err != nil {
		t.Fatalf("runDecompile --function %s failed: %v\nstderr: %s", funcName, err, errBuf.String())
	}

	output := outBuf.String()
	if output == "" {
		t.Fatalf("decompiler produced empty output for function %s", funcName)
	}

	return output
}

// checkNoDuplicateConsecutiveLines asserts that no function body in the output
// contains the same non-empty statement on two consecutive lines.
func checkNoDuplicateConsecutiveLines(t *testing.T, output string) {
	t.Helper()

	lines := strings.Split(output, "\n")
	inBody := false
	var prev string
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasSuffix(trimmed, "{") {
			inBody = true
			prev = ""
			continue
		}
		if trimmed == "}" {
			inBody = false
			prev = ""
			continue
		}
		if !inBody || trimmed == "" {
			continue
		}
		if trimmed == prev {
			t.Errorf("duplicate consecutive line %q at line %d", trimmed, i+1)
			return
		}
		prev = trimmed
	}
}

// stripCComments removes c-style block comments (/* ... */) from the output
// so that register names inside disassembly annotations are not false positives.
func stripCComments(s string) string {
	commentPattern := regexp.MustCompile(`/\*[^*]*\*+(?:[^/*][^*]*\*+)*/`)
	return commentPattern.ReplaceAllString(s, "")
}

// checkNoRawRegisterNames asserts that no x86-64 register name appears as a
// standalone c identifier token in the output (excluding comments).
func checkNoRawRegisterNames(t *testing.T, output string) {
	t.Helper()

	// strip comments so that disassembly annotations like
	// "/* 0x116d: mov [rbp - 0x4], edi */" do not cause false positives
	stripped := stripCComments(output)

	registerPattern := regexp.MustCompile(
		`\b(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15)\b`)
	if loc := registerPattern.FindStringIndex(stripped); loc != nil {
		ctxStart := max(loc[0]-40, 0)
		ctxEnd := min(loc[1]+40, len(stripped))
		t.Errorf("raw register name found in output near: %q", stripped[ctxStart:ctxEnd])
	}
}

// checkNoFrameArtifacts asserts that no stack frame prologue/epilogue artifacts
// appear in the output.
func checkNoFrameArtifacts(t *testing.T, output string) {
	t.Helper()

	frameArtifacts := []string{
		"rsp = (rsp - 8U)",
		"rbp = rsp",
		"*(uint64_t*)(rsp) = rbp",
	}
	for _, artifact := range frameArtifacts {
		if strings.Contains(output, artifact) {
			t.Errorf("frame artifact found in output: %q", artifact)
		}
	}
}

// TestDecompileRealBinary_OutputQuality validates all eight output-quality fixes
// against a real ELF binary compiled from examples/test_decompiler.c.
// each sub-test decompiles a specific function using --function to avoid hangs
// on functions with complex switch-like cfgs.
//
// Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10, 2.15, 2.16
func TestDecompileRealBinary_OutputQuality(t *testing.T) {
	binaryPath := compileTestDecompilerBinary(t)

	// ------------------------------------------------------------------ //
	// fix 1: no function body contains the same statement sequence more   //
	// than once (no duplicate consecutive lines within a function body).  //
	// test classify_int which has if/else chains that exercise the        //
	// structuring engine's convergence logic.                             //
	// ------------------------------------------------------------------ //
	t.Run("Fix1_NoDuplicateConsecutiveLines", func(t *testing.T) {
		output := decompileSingleFunc(t, binaryPath, "classify_int")
		checkNoDuplicateConsecutiveLines(t, output)
	})

	// ------------------------------------------------------------------ //
	// fix 2: main() must not have double arg0 / double arg1 in its        //
	// signature -- main takes no parameters (or int argc, char **argv).   //
	// ------------------------------------------------------------------ //
	t.Run("Fix2_NoDoubleArgsInMainSignature", func(t *testing.T) {
		output := decompileSingleFunc(t, binaryPath, "main")
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, "main") && strings.Contains(line, "(") {
				if strings.Contains(line, "double arg0") || strings.Contains(line, "double arg1") {
					t.Errorf("Fix 2 violation: main signature contains double parameter: %q", line)
				}
			}
		}
	})

	// ------------------------------------------------------------------ //
	// fix 3: no raw x86-64 register names appear as standalone c tokens.  //
	// test add and max -- simple functions where register names should     //
	// have been replaced by the variable-naming pass.                      //
	// ------------------------------------------------------------------ //
	t.Run("Fix3_NoRawRegisterNames_add", func(t *testing.T) {
		output := decompileSingleFunc(t, binaryPath, "add")
		checkNoRawRegisterNames(t, output)
	})

	t.Run("Fix3_NoRawRegisterNames_max", func(t *testing.T) {
		output := decompileSingleFunc(t, binaryPath, "max")
		checkNoRawRegisterNames(t, output)
	})

	// ------------------------------------------------------------------ //
	// fix 4: no non-whitespace content after return before closing brace. //
	// test abs_val which has an early return via ternary.                  //
	// ------------------------------------------------------------------ //
	t.Run("Fix4_NoDeadCodeAfterReturn", func(t *testing.T) {
		output := decompileSingleFunc(t, binaryPath, "abs_val")
		// strip comments to avoid false positives from annotation text
		stripped := stripCComments(output)
		// check that no non-whitespace statement follows a return in the same scope.
		// the pattern looks for a return statement followed by a non-empty, non-brace line.
		deadCodePattern := regexp.MustCompile(`(?m)return[^;]*;\s*$\n\s*[^}\s\n]`)
		if deadCodePattern.MatchString(stripped) {
			loc := deadCodePattern.FindStringIndex(stripped)
			ctxEnd := min(loc[1]+20, len(stripped))
			t.Errorf("Fix 4 violation: dead code after return statement near: %q",
				stripped[loc[0]:ctxEnd])
		}
	})

	// ------------------------------------------------------------------ //
	// fix 5: every function name matches a valid c identifier pattern.    //
	// check across multiple decompiled functions.                         //
	// ------------------------------------------------------------------ //
	t.Run("Fix5_ValidFunctionNames", func(t *testing.T) {
		funcNamePattern := regexp.MustCompile(`(?m)^(?:void|int|uint\w*|char|double|float|\w+)\s+(\w+)\s*\(`)
		validIdentifier := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

		// decompile several functions and check all emitted function names
		for _, fn := range []string{"add", "max", "abs_val", "classify_int"} {
			output := decompileSingleFunc(t, binaryPath, fn)
			for _, m := range funcNamePattern.FindAllStringSubmatch(output, -1) {
				if len(m) < 2 {
					continue
				}
				name := strings.TrimSpace(m[1])
				if name == "" {
					continue
				}
				if !validIdentifier.MatchString(name) {
					t.Errorf("Fix 5 violation: invalid C identifier %q in function %s output (match: %q)",
						name, fn, m[0])
				}
			}
		}
	})

	// ------------------------------------------------------------------ //
	// fix 8: no stack frame prologue/epilogue artifacts in output.        //
	// test add -- a simple function whose prologue/epilogue should be     //
	// fully suppressed.                                                   //
	// ------------------------------------------------------------------ //
	t.Run("Fix8_NoFrameArtifacts", func(t *testing.T) {
		output := decompileSingleFunc(t, binaryPath, "add")
		checkNoFrameArtifacts(t, output)
	})
}

// TestDecompileRealBinary_SymbolResolution validates that call targets are
// resolved to symbol names (fix 6) and that large decimal integer literals
// do not appear as memory addresses (fix 7).
//
// Validates: Requirements 2.11, 2.12, 2.13, 2.14
func TestDecompileRealBinary_SymbolResolution(t *testing.T) {
	binaryPath := compileTestDecompilerBinary(t)

	// decompile main which calls printf and many other functions
	output := decompileSingleFunc(t, binaryPath, "main")

	// ------------------------------------------------------------------ //
	// fix 6: output must contain resolved symbol names for call targets,  //
	// not raw numeric addresses. main calls many local functions which     //
	// should be resolved via the symbol table.                             //
	// ------------------------------------------------------------------ //
	t.Run("Fix6_ResolvedCallTargets", func(t *testing.T) {
		// main calls local functions like add, sub, mul -- at least some must
		// appear as resolved symbol names rather than raw numeric addresses.
		resolvedCalls := []string{"add(", "sub(", "mul(", "max(", "fib("}
		foundResolved := 0
		for _, sym := range resolvedCalls {
			if strings.Contains(output, sym) {
				foundResolved++
			}
		}
		if foundResolved == 0 {
			t.Errorf("Fix 6 violation: no resolved call targets found in main output")
		}

		// no raw numeric address with 6+ digits followed by '(' (unresolved call target
		// pattern for non-pie binaries where addresses are large)
		rawCallPattern := regexp.MustCompile(`\b\d{6,}\s*\(`)
		if loc := rawCallPattern.FindStringIndex(output); loc != nil {
			ctxEnd := min(loc[1]+30, len(output))
			t.Errorf("Fix 6 violation: raw numeric call target found near: %q", output[loc[0]:ctxEnd])
		}
	})

	// ------------------------------------------------------------------ //
	// fix 7: output must not contain large decimal integer literals used   //
	// as memory addresses in dereference expressions.                     //
	// ------------------------------------------------------------------ //
	t.Run("Fix7_NoLargeDecimalAddresses", func(t *testing.T) {
		// pattern: *(uintN_t*)(LARGE_DECIMAL) where the decimal has 6+ digits
		largeAddrPattern := regexp.MustCompile(`\*\(uint\d+_t\*\)\(\d{6,}\)`)
		if loc := largeAddrPattern.FindStringIndex(output); loc != nil {
			ctxEnd := min(loc[1]+20, len(output))
			t.Errorf("Fix 7 violation: large decimal address in dereference near: %q",
				output[loc[0]:ctxEnd])
		}
	})
}
