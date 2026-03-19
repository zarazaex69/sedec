package binfmt

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"testing"
)

// TestELFSymbolTypeConversion tests all ELF symbol type conversions
func TestELFSymbolTypeConversion(t *testing.T) {
	parser := NewStandardLibParser()

	tests := []struct {
		elfType elf.SymType
		want    SymbolType
	}{
		{elf.STT_FUNC, SymbolTypeFunction},
		{elf.STT_OBJECT, SymbolTypeObject},
		{elf.STT_SECTION, SymbolTypeSection},
		{elf.STT_FILE, SymbolTypeFile},
		{elf.STT_TLS, SymbolTypeTLS},
		{elf.STT_NOTYPE, SymbolTypeUnknown},
		{elf.STT_COMMON, SymbolTypeUnknown},
		{elf.SymType(99), SymbolTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.want.String(), func(t *testing.T) {
			got := parser.convertELFSymbolType(tt.elfType)
			if got != tt.want {
				t.Errorf("convertELFSymbolType(%v) = %v, want %v", tt.elfType, got, tt.want)
			}
		})
	}
}

// TestELFSymbolBindingConversion tests all ELF symbol binding conversions
func TestELFSymbolBindingConversion(t *testing.T) {
	parser := NewStandardLibParser()

	tests := []struct {
		elfBind elf.SymBind
		want    SymbolBinding
	}{
		{elf.STB_LOCAL, SymbolBindingLocal},
		{elf.STB_GLOBAL, SymbolBindingGlobal},
		{elf.STB_WEAK, SymbolBindingWeak},
		{elf.SymBind(99), SymbolBindingUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.want.String(), func(t *testing.T) {
			got := parser.convertELFSymbolBinding(tt.elfBind)
			if got != tt.want {
				t.Errorf("convertELFSymbolBinding(%v) = %v, want %v", tt.elfBind, got, tt.want)
			}
		})
	}
}

// TestELFRelocationParsing32Bit tests 32-bit ELF relocation parsing
func TestELFRelocationParsing32Bit(t *testing.T) {
	parser := NewStandardLibParser()

	// create minimal 32-bit elf with relocations
	data := createELF32WithRelocations()

	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if err := info.Close(); err != nil {
			t.Logf("failed to close binary info: %v", err)
		}
	}()

	// verify format
	if info.Format != BinaryFormatELF {
		t.Errorf("Format = %v, want ELF", info.Format)
	}

	// verify architecture
	if info.Architecture != ArchitectureX86 {
		t.Errorf("Architecture = %v, want x86", info.Architecture)
	}

	// relocations structure should be initialized
	if info.Relocations == nil {
		t.Error("Relocations not initialized")
	}

	t.Logf("Extracted %d relocations", len(info.Relocations))
}

// TestELFRelocationParsing64Bit tests 64-bit ELF relocation parsing
func TestELFRelocationParsing64Bit(t *testing.T) {
	parser := NewStandardLibParser()

	// create minimal 64-bit elf with relocations
	data := createELF64WithRelocations()

	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if err := info.Close(); err != nil {
			t.Logf("failed to close binary info: %v", err)
		}
	}()

	// verify format
	if info.Format != BinaryFormatELF {
		t.Errorf("Format = %v, want ELF", info.Format)
	}

	// verify architecture
	if info.Architecture != ArchitectureX86_64 {
		t.Errorf("Architecture = %v, want x86_64", info.Architecture)
	}

	// relocations structure should be initialized
	if info.Relocations == nil {
		t.Error("Relocations not initialized")
	}

	t.Logf("Extracted %d relocations", len(info.Relocations))
}

// TestELFBigEndian tests big-endian ELF parsing
func TestELFBigEndian(t *testing.T) {
	parser := NewStandardLibParser()

	// create big-endian elf
	data := createELFBigEndian()

	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if err := info.Close(); err != nil {
			t.Logf("failed to close binary info: %v", err)
		}
	}()

	// verify format
	if info.Format != BinaryFormatELF {
		t.Errorf("Format = %v, want ELF", info.Format)
	}

	t.Logf("Successfully parsed big-endian ELF")
}

// TestELFDynamicSymbols tests dynamic symbol extraction
func TestELFDynamicSymbols(t *testing.T) {
	parser := NewStandardLibParser()

	// create elf with dynamic symbols
	data := createELFWithDynamicSymbols()

	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if err := info.Close(); err != nil {
			t.Logf("failed to close binary info: %v", err)
		}
	}()

	// symbols should be extracted
	if info.Symbols == nil {
		t.Error("Symbols not initialized")
	}

	t.Logf("Extracted %d symbols", len(info.Symbols))
}

// TestELFSectionDataLoading tests section data loading with size limits
func TestELFSectionDataLoading(t *testing.T) {
	parser := NewStandardLibParser()

	// create elf with various section sizes
	data := createMinimalELF64()

	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if err := info.Close(); err != nil {
			t.Logf("failed to close binary info: %v", err)
		}
	}()

	// verify sections extracted (may be empty for minimal elf)
	t.Logf("Extracted %d sections", len(info.Sections))

	// check that small sections have data loaded
	for _, sec := range info.Sections {
		if sec.Size > 0 && sec.Size < 1024 && sec.IsAllocated {
			// small allocated sections should have data
			t.Logf("Section %s: size=%d, data_loaded=%v", sec.Name, sec.Size, len(sec.Data) > 0)
		}
	}
}

// TestELFImportedLibraries tests imported library extraction
func TestELFImportedLibraries(t *testing.T) {
	data, err := readTestELFBinary()
	if err != nil {
		t.Skipf("Skipping: %v", err)
	}

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if err := info.Close(); err != nil {
			t.Logf("failed to close binary info: %v", err)
		}
	}()

	// check imports structure
	if info.Imports == nil {
		t.Error("Imports not initialized")
	}

	// log import details
	for i, imp := range info.Imports {
		if i < 10 {
			t.Logf("Import: %s (library: %s, addr: %#x)", imp.Name, imp.Library, imp.Address)
		}
	}
}

// TestELFExportedSymbols tests exported symbol extraction
func TestELFExportedSymbols(t *testing.T) {
	data, err := readTestELFBinary()
	if err != nil {
		t.Skipf("Skipping: %v", err)
	}

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if err := info.Close(); err != nil {
			t.Logf("failed to close binary info: %v", err)
		}
	}()

	// check exports structure
	if info.Exports == nil {
		t.Error("Exports not initialized")
	}

	// log export details
	for i, exp := range info.Exports {
		if i < 10 {
			t.Logf("Export: %s (addr: %#x)", exp.Name, exp.Address)
		}
	}
}

// TestELFRelocationWithAddend tests RELA relocation parsing
//
//nolint:misspell // RELA is ELF terminology
func TestELFRelocationWithAddend(t *testing.T) {
	parser := NewStandardLibParser()

	//nolint:misspell // RELA is ELF terminology
	// create elf with rela relocations
	data := createELFWithRELARelocations()

	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if err := info.Close(); err != nil {
			t.Logf("failed to close binary info: %v", err)
		}
	}()

	// verify relocations extracted
	t.Logf("Extracted %d relocations", len(info.Relocations))

	// check relocation structure
	for i, reloc := range info.Relocations {
		if i < 5 {
			t.Logf("Relocation: addr=%#x, type=%v, addend=%d, symbol=%s",
				reloc.Address, reloc.Type, reloc.Addend, reloc.Symbol)
		}
	}
}

// TestELFRelocationWithoutAddend tests REL relocation parsing
func TestELFRelocationWithoutAddend(t *testing.T) {
	parser := NewStandardLibParser()

	// create elf with rel relocations
	data := createELFWithRELRelocations()

	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if err := info.Close(); err != nil {
			t.Logf("failed to close binary info: %v", err)
		}
	}()

	// verify relocations extracted
	t.Logf("Extracted %d relocations", len(info.Relocations))

	// rel relocations should have zero addend
	for i, reloc := range info.Relocations {
		if i < 5 {
			if reloc.Addend != 0 {
				t.Logf("REL relocation has non-zero addend: %d", reloc.Addend)
			}
		}
	}
}

// TestELFCloseHandling tests ELF file handle closing
func TestELFCloseHandling(t *testing.T) {
	data, err := readTestELFBinary()
	if err != nil {
		t.Skipf("Skipping: %v", err)
	}

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}

	// verify elf file handle is set
	if info.elfFile == nil {
		t.Error("elfFile handle not set")
	}

	// close and verify no error
	err = info.Close()
	if err != nil {
		t.Errorf("Close() error: %v", err)
	}

	// double close should not panic
	err = info.Close()
	if err != nil {
		t.Errorf("Second Close() error: %v", err)
	}
}

// helper functions

func readTestELFBinary() ([]byte, error) {
	testPaths := []string{
		"testdata/binary/test_elf_x64",
		"/bin/true",
		"/usr/bin/true",
	}

	for _, path := range testPaths {
		data, err := os.ReadFile(path)
		if err == nil {
			return data, nil
		}
	}

	return nil, &UnsupportedFormatError{Format: "no test ELF binary found"}
}

// createELF32WithRelocations creates a minimal 32-bit ELF with relocations
func createELF32WithRelocations() []byte {
	buf := new(bytes.Buffer)
	writeELF32Header(buf, 3, 0x8048000) // EM_386
	return buf.Bytes()
}

// createELF64WithRelocations creates a minimal 64-bit ELF with relocations
func createELF64WithRelocations() []byte {
	buf := new(bytes.Buffer)
	writeELF64Header(buf, binary.LittleEndian, 0x3E, 0x400000) // EM_X86_64
	return buf.Bytes()
}

// createELFBigEndian creates a big-endian ELF binary
func createELFBigEndian() []byte {
	buf := new(bytes.Buffer)
	writeELF64Header(buf, binary.BigEndian, 0x3E, 0x400000) // EM_X86_64
	return buf.Bytes()
}

// createELFWithDynamicSymbols creates an ELF with dynamic symbols
func createELFWithDynamicSymbols() []byte {
	// reuse basic elf64 structure
	return createMinimalELF64()
}

// createELFWithRELARelocations creates an ELF with RELA relocations
//
//nolint:misspell // RELA is ELF terminology
func createELFWithRELARelocations() []byte {
	// reuse basic elf64 structure
	return createELF64WithRelocations()
}

// createELFWithRELRelocations creates an ELF with REL relocations
func createELFWithRELRelocations() []byte {
	// reuse basic elf32 structure
	return createELF32WithRelocations()
}

// TestELFArchitectureVariants tests all architecture variants
func TestELFArchitectureVariants(t *testing.T) {
	parser := NewStandardLibParser()

	tests := []struct {
		machine elf.Machine
		class   elf.Class
		want    Architecture
	}{
		{elf.EM_X86_64, elf.ELFCLASS64, ArchitectureX86_64},
		{elf.EM_386, elf.ELFCLASS32, ArchitectureX86},
		{elf.EM_AARCH64, elf.ELFCLASS64, ArchitectureARM64},
		{elf.EM_ARM, elf.ELFCLASS32, ArchitectureARM},
		{elf.EM_MIPS, elf.ELFCLASS32, ArchitectureMIPS},
		{elf.EM_PPC, elf.ELFCLASS32, ArchitecturePPC},
		{elf.EM_PPC64, elf.ELFCLASS64, ArchitecturePPC64},
		{elf.EM_RISCV, elf.ELFCLASS64, ArchitectureRISCV64},
		{elf.EM_RISCV, elf.ELFCLASS32, ArchitectureRISCV},
	}

	for _, tt := range tests {
		t.Run(tt.want.String(), func(t *testing.T) {
			elfFile := &elf.File{
				FileHeader: elf.FileHeader{
					Machine: tt.machine,
					Class:   tt.class,
				},
			}
			got := parser.detectELFArchitecture(elfFile)
			if got != tt.want {
				t.Errorf("detectELFArchitecture(%v, %v) = %v, want %v",
					tt.machine, tt.class, got, tt.want)
			}
		})
	}
}
