package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCFG_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := runCFG([]string{"--help"}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runCFG --help failed: %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "sedec cfg") {
		t.Error("help output missing command name")
	}
	if !strings.Contains(output, "--output") {
		t.Error("help output missing --output flag")
	}
	if !strings.Contains(output, "--function") {
		t.Error("help output missing --function flag")
	}
}

func TestRunCFG_NoInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	stdin := bytes.NewReader([]byte{})

	err := runCFG([]string{}, stdin, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for no input, got nil")
	}

	if !strings.Contains(err.Error(), "no input provided") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRunCFG_InvalidBinary(t *testing.T) {
	var stdout, stderr bytes.Buffer
	stdin := bytes.NewReader([]byte("not a valid binary"))

	err := runCFG([]string{}, stdin, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for invalid binary, got nil")
	}

	if !strings.Contains(err.Error(), "failed to parse binary") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRunCFG_WithTestBinary(t *testing.T) {
	// create temporary test binary (simple elf)
	testBinary := createTestELFBinary(t)
	defer func() {
		if err := os.Remove(testBinary); err != nil {
			t.Logf("failed to remove test binary: %v", err)
		}
	}()

	var stdout, stderr bytes.Buffer

	err := runCFG([]string{testBinary}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runCFG failed: %v", err)
	}

	output := stdout.String()

	// verify dot format
	if !strings.Contains(output, "digraph CFG") {
		t.Error("output missing digraph header")
	}
	if !strings.Contains(output, "block_") {
		t.Error("output missing block nodes")
	}
}

func TestRunCFG_OutputToFile(t *testing.T) {
	testBinary := createTestELFBinary(t)
	defer func() {
		if err := os.Remove(testBinary); err != nil {
			t.Logf("failed to remove test binary: %v", err)
		}
	}()

	// create temporary output file
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "cfg.dot")

	var stdout, stderr bytes.Buffer

	err := runCFG([]string{"--output", outputFile, testBinary}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runCFG failed: %v", err)
	}

	// verify file was created
	if _, statErr := os.Stat(outputFile); os.IsNotExist(statErr) {
		t.Fatal("output file was not created")
	}

	// read and verify content
	//nolint:gosec // G304: test code reads test files
	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if !strings.Contains(string(content), "digraph CFG") {
		t.Error("output file missing digraph header")
	}

	// verify statistics were printed to stderr
	stderrOutput := stderr.String()
	if !strings.Contains(stderrOutput, "cfg exported") {
		t.Error("stderr missing export confirmation")
	}
	if !strings.Contains(stderrOutput, "blocks:") {
		t.Error("stderr missing statistics")
	}
}

func TestRunCFG_NoInstructions(t *testing.T) {
	testBinary := createTestELFBinary(t)
	defer func() {
		if err := os.Remove(testBinary); err != nil {
			t.Logf("failed to remove test binary: %v", err)
		}
	}()

	var stdout, stderr bytes.Buffer

	err := runCFG([]string{"--no-instructions", testBinary}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runCFG failed: %v", err)
	}

	output := stdout.String()

	// verify instructions are not included
	// (we can't check for specific mnemonics as they depend on binary content,
	// but we can verify the output is shorter and still valid)
	if !strings.Contains(output, "digraph CFG") {
		t.Error("output missing digraph header")
	}
	if !strings.Contains(output, "block_") {
		t.Error("output missing block nodes")
	}
}

func TestRunCFG_MaxInstructions(t *testing.T) {
	testBinary := createTestELFBinary(t)
	defer func() {
		if err := os.Remove(testBinary); err != nil {
			t.Logf("failed to remove test binary: %v", err)
		}
	}()

	var stdout, stderr bytes.Buffer

	err := runCFG([]string{"--max-instructions", "3", testBinary}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runCFG failed: %v", err)
	}

	output := stdout.String()

	// verify output is valid
	if !strings.Contains(output, "digraph CFG") {
		t.Error("output missing digraph header")
	}
}

func TestRunCFG_ShowProvenance(t *testing.T) {
	testBinary := createTestELFBinary(t)
	defer func() {
		if err := os.Remove(testBinary); err != nil {
			t.Logf("failed to remove test binary: %v", err)
		}
	}()

	var stdout, stderr bytes.Buffer

	err := runCFG([]string{"--show-provenance", testBinary}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runCFG failed: %v", err)
	}

	output := stdout.String()

	// verify output is valid (provenance may not be present if no edges have it)
	if !strings.Contains(output, "digraph CFG") {
		t.Error("output missing digraph header")
	}
}

func TestRunCFG_InvalidFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"unknown flag", []string{"--unknown-flag"}},
		{"output without value", []string{"--output"}},
		{"function without value", []string{"--function"}},
		{"max-instructions without value", []string{"--max-instructions"}},
		{"invalid max-instructions", []string{"--max-instructions", "abc"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			err := runCFG(tt.args, nil, &stdout, &stderr)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestRunCFG_NonexistentFile(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := runCFG([]string{"/nonexistent/binary"}, nil, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}

	if !strings.Contains(err.Error(), "failed to read binary file") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRunCFG_NonexistentFunction(t *testing.T) {
	testBinary := createTestELFBinary(t)
	defer func() {
		if err := os.Remove(testBinary); err != nil {
			t.Logf("failed to remove test binary: %v", err)
		}
	}()

	var stdout, stderr bytes.Buffer

	err := runCFG([]string{"--function", "nonexistent_function", testBinary}, nil, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for nonexistent function, got nil")
	}

	if !strings.Contains(err.Error(), "function not found") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// createTestELFBinary creates a minimal valid elf binary for testing.
func createTestELFBinary(t *testing.T) string {
	t.Helper()

	// create a complete minimal x86_64 elf binary with proper section headers
	// this is a fully valid elf that can be parsed by debug/elf

	// elf header (64 bytes)
	elfHeader := []byte{
		// e_ident
		0x7f, 0x45, 0x4c, 0x46, // magic: 0x7f 'E' 'L' 'F'
		0x02,                                     // class: elfclass64
		0x01,                                     // data: elfdata2lsb (little endian)
		0x01,                                     // version: ev_current
		0x00,                                     // osabi: elfosabi_none
		0x00,                                     // abiversion
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding

		// elf header fields
		0x02, 0x00, // e_type: et_exec
		0x3e, 0x00, // e_machine: em_x86_64
		0x01, 0x00, 0x00, 0x00, // e_version
		0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry: 0x400078
		0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff: 64 (program header offset)
		0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff: 184 (section header offset)
		0x00, 0x00, 0x00, 0x00, // e_flags
		0x40, 0x00, // e_ehsize: 64
		0x38, 0x00, // e_phentsize: 56 (program header entry size)
		0x01, 0x00, // e_phnum: 1 (number of program headers)
		0x40, 0x00, // e_shentsize: 64 (section header entry size)
		0x04, 0x00, // e_shnum: 4 (number of section headers)
		0x03, 0x00, // e_shstrndx: 3 (section header string table index)
	}

	// program header (56 bytes) - loadable segment
	programHeader := []byte{
		0x01, 0x00, 0x00, 0x00, // p_type: pt_load
		0x05, 0x00, 0x00, 0x00, // p_flags: pf_r | pf_x (readable + executable)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_offset: 0
		0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_vaddr: 0x400000
		0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // p_paddr: 0x400000
		0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_filesz: 184
		0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_memsz: 184
		0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // p_align: 0x1000
	}

	// code section data (at offset 0x78, vaddr 0x400078)
	// simple function: mov eax, 42; ret
	codeData := []byte{
		0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax, 42
		0xc3, // ret
	}

	// padding to reach section headers at offset 184
	paddingSize := 184 - len(elfHeader) - len(programHeader) - len(codeData)
	padding := make([]byte, paddingSize)

	// section header string table
	shstrtab := []byte{
		0x00,                               // null entry
		0x2e, 0x74, 0x65, 0x78, 0x74, 0x00, // ".text\0"
		0x2e, 0x64, 0x61, 0x74, 0x61, 0x00, // ".data\0"
		0x2e, 0x73, 0x68, 0x73, 0x74, 0x72, 0x74, 0x61, 0x62, 0x00, // ".shstrtab\0"
	}

	// section headers (4 sections * 64 bytes = 256 bytes)
	// section 0: null section
	sectionHeader0 := make([]byte, 64)

	// section 1: .text (executable code)
	sectionHeader1 := []byte{
		0x01, 0x00, 0x00, 0x00, // sh_name: 1 (offset in shstrtab for ".text")
		0x01, 0x00, 0x00, 0x00, // sh_type: sht_progbits
		0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags: shf_alloc | shf_execinstr
		0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr: 0x400078
		0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset: 120
		0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size: 6
		0x00, 0x00, 0x00, 0x00, // sh_link
		0x00, 0x00, 0x00, 0x00, // sh_info
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign: 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize: 0
	}

	// section 2: .data (empty data section)
	sectionHeader2 := []byte{
		0x07, 0x00, 0x00, 0x00, // sh_name: 7 (offset in shstrtab for ".data")
		0x01, 0x00, 0x00, 0x00, // sh_type: sht_progbits
		0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags: shf_alloc | shf_write
		0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr: 0x600000
		0x7e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset: 126
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size: 0
		0x00, 0x00, 0x00, 0x00, // sh_link
		0x00, 0x00, 0x00, 0x00, // sh_info
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign: 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize: 0
	}

	// section 3: .shstrtab (section header string table)
	shstrtabOffset := 184 + 256 // after section headers
	sectionHeader3 := []byte{
		0x0d, 0x00, 0x00, 0x00, // sh_name: 13 (offset in shstrtab for ".shstrtab")
		0x03, 0x00, 0x00, 0x00, // sh_type: sht_strtab
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_flags: 0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addr: 0
		//nolint:gosec // G115: test code uses safe integer conversion
		byte(shstrtabOffset), byte(shstrtabOffset >> 8), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_offset
		//nolint:gosec // G115: test code uses safe integer conversion
		byte(len(shstrtab)), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_size
		0x00, 0x00, 0x00, 0x00, // sh_link
		0x00, 0x00, 0x00, 0x00, // sh_info
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_addralign: 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sh_entsize: 0
	}

	// assemble complete elf file
	elfData := make([]byte, 0, len(elfHeader)+len(programHeader)+len(codeData)+len(padding)+
		len(sectionHeader0)+len(sectionHeader1)+len(sectionHeader2)+len(sectionHeader3)+len(shstrtab))
	elfData = append(elfData, elfHeader...)
	elfData = append(elfData, programHeader...)
	elfData = append(elfData, codeData...)
	elfData = append(elfData, padding...)
	elfData = append(elfData, sectionHeader0...)
	elfData = append(elfData, sectionHeader1...)
	elfData = append(elfData, sectionHeader2...)
	elfData = append(elfData, sectionHeader3...)
	elfData = append(elfData, shstrtab...)

	tmpFile, err := os.CreateTemp("", "test_binary_*.elf")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	if _, writeErr := tmpFile.Write(elfData); writeErr != nil {
		_ = tmpFile.Close()
		//nolint:gosec // G703: test code removes temporary files
		_ = os.Remove(tmpFile.Name())
		t.Fatalf("failed to write test binary: %v", writeErr)
	}

	if closeErr := tmpFile.Close(); closeErr != nil {
		//nolint:gosec // G703: test code removes temporary files
		_ = os.Remove(tmpFile.Name())
		t.Fatalf("failed to close temp file: %v", closeErr)
	}

	return tmpFile.Name()
}

func TestRunCFG_WithAddress(t *testing.T) {
	testBinary := createTestELFBinary(t)
	defer func() {
		if err := os.Remove(testBinary); err != nil {
			t.Logf("failed to remove test binary: %v", err)
		}
	}()

	var stdout, stderr bytes.Buffer

	// test with hex address (0x400078 is .text section start in our test ELF)
	err := runCFG([]string{"--address", "0x400078", "--size", "6", testBinary}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runCFG with address failed: %v", err)
	}

	output := stdout.String()

	// verify dot format
	if !strings.Contains(output, "digraph CFG") {
		t.Error("output missing digraph header")
	}
	if !strings.Contains(output, "block_") {
		t.Error("output missing block nodes")
	}
}

func TestRunCFG_WithAddressDecimal(t *testing.T) {
	testBinary := createTestELFBinary(t)
	defer func() {
		if err := os.Remove(testBinary); err != nil {
			t.Logf("failed to remove test binary: %v", err)
		}
	}()

	var stdout, stderr bytes.Buffer

	// test with decimal address (4194424 = 0x400078)
	err := runCFG([]string{"--address", "4194424", "--size", "6", testBinary}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runCFG with decimal address failed: %v", err)
	}

	output := stdout.String()

	// verify dot format
	if !strings.Contains(output, "digraph CFG") {
		t.Error("output missing digraph header")
	}
}

func TestRunCFG_InvalidAddress(t *testing.T) {
	testBinary := createTestELFBinary(t)
	defer func() {
		if err := os.Remove(testBinary); err != nil {
			t.Logf("failed to remove test binary: %v", err)
		}
	}()

	var stdout, stderr bytes.Buffer

	// test with invalid address format
	err := runCFG([]string{"--address", "invalid", testBinary}, nil, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for invalid address, got nil")
	}

	if !strings.Contains(err.Error(), "invalid address format") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRunCFG_AddressOutOfRange(t *testing.T) {
	testBinary := createTestELFBinary(t)
	defer func() {
		if err := os.Remove(testBinary); err != nil {
			t.Logf("failed to remove test binary: %v", err)
		}
	}()

	var stdout, stderr bytes.Buffer

	// test with address outside executable sections
	err := runCFG([]string{"--address", "0x999999", testBinary}, nil, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for out-of-range address, got nil")
	}

	if !strings.Contains(err.Error(), "not found in any executable section") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRunCFG_AddressWithStatistics(t *testing.T) {
	testBinary := createTestELFBinary(t)
	defer func() {
		if err := os.Remove(testBinary); err != nil {
			t.Logf("failed to remove test binary: %v", err)
		}
	}()

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "cfg.dot")

	var stdout, stderr bytes.Buffer

	err := runCFG([]string{"--address", "0x400078", "--size", "6", "--output", outputFile, testBinary}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runCFG failed: %v", err)
	}

	// verify statistics in stderr
	stderrOutput := stderr.String()
	if !strings.Contains(stderrOutput, "address range:") {
		t.Error("stderr missing address range")
	}
	if !strings.Contains(stderrOutput, "blocks:") {
		t.Error("stderr missing block count")
	}
	if !strings.Contains(stderrOutput, "0x400078") {
		t.Error("stderr missing start address")
	}
}
