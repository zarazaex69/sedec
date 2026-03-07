package binfmt

import (
	"os"
	"testing"
)

// TestWithRealPEBinary tests parser with real PE binary from testdata
func TestWithRealPEBinary(t *testing.T) {
	data, err := os.ReadFile("testdata/binary/test_pe_x64.exe")
	if err != nil {
		t.Skipf("Skipping: real PE binary not found: %v", err)
	}

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if closeErr := info.Close(); closeErr != nil {
			t.Logf("failed to close info: %v", closeErr)
		}
	}()

	// verify format detection
	if info.Format != BinaryFormatPE {
		t.Errorf("Format = %v, want PE", info.Format)
	}

	// verify architecture detection
	if info.Architecture != ArchitectureX86_64 {
		t.Errorf("Architecture = %v, want x86_64", info.Architecture)
	}

	// verify entry point is set
	if info.EntryPoint == 0 {
		t.Error("EntryPoint is zero")
	}

	// verify base address is set
	if info.BaseAddress == 0 {
		t.Error("BaseAddress is zero")
	}

	// verify sections extracted
	if len(info.Sections) == 0 {
		t.Fatal("No sections extracted")
	}

	t.Logf("Extracted %d sections", len(info.Sections))

	// verify .text section exists and has correct properties
	var textSection *Section
	for _, sec := range info.Sections {
		if sec.Name == ".text" {
			textSection = sec
			break
		}
	}
	if textSection != nil {
		if !textSection.IsExecutable {
			t.Error(".text section should be executable")
		}
		if textSection.Size == 0 {
			t.Error(".text section has zero size")
		}
		if len(textSection.Data) == 0 {
			t.Error(".text section data not loaded")
		}
	}

	// verify symbols extracted (pe may have limited symbols)
	t.Logf("Extracted %d symbols", len(info.Symbols))

	// verify ground truth database populated
	if info.GroundTruthDB == nil {
		t.Fatal("GroundTruthDB is nil")
	}

	// verify imports structure
	if info.Imports == nil {
		t.Error("Imports not initialized")
	}
	t.Logf("Extracted %d imports", len(info.Imports))

	// verify exports structure
	if info.Exports == nil {
		t.Error("Exports not initialized")
	}
	t.Logf("Extracted %d exports", len(info.Exports))

	// verify relocations structure
	if info.Relocations == nil {
		t.Error("Relocations not initialized")
	}
	t.Logf("Extracted %d relocations", len(info.Relocations))
}

// TestPESectionProperties tests PE section property extraction
func TestPESectionProperties(t *testing.T) {
	data, err := os.ReadFile("testdata/binary/test_pe_x64.exe")
	if err != nil {
		t.Skipf("Skipping: %v", err)
	}

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if closeErr := info.Close(); closeErr != nil {
			t.Logf("failed to close info: %v", closeErr)
		}
	}()

	// build section map
	sectionMap := make(map[string]*Section)
	for _, sec := range info.Sections {
		sectionMap[sec.Name] = sec
	}

	// test common pe sections
	sectionTests := []struct {
		name       string
		executable bool
		writable   bool
		allocated  bool
	}{
		{".text", true, false, true},
		{".rdata", false, false, true},
		{".data", false, true, true},
	}

	for _, tt := range sectionTests {
		t.Run(tt.name, func(t *testing.T) {
			sec, exists := sectionMap[tt.name]
			if !exists {
				t.Skipf("Section %s not found", tt.name)
			}

			if sec.IsExecutable != tt.executable {
				t.Errorf("%s IsExecutable = %v, want %v", tt.name, sec.IsExecutable, tt.executable)
			}
			if sec.IsWritable != tt.writable {
				t.Errorf("%s IsWritable = %v, want %v", tt.name, sec.IsWritable, tt.writable)
			}
			if sec.IsAllocated != tt.allocated {
				t.Errorf("%s IsAllocated = %v, want %v", tt.name, sec.IsAllocated, tt.allocated)
			}

			// verify section has address and size
			if sec.Address == 0 {
				t.Errorf("%s has zero address", tt.name)
			}
			if sec.Size == 0 {
				t.Errorf("%s has zero size", tt.name)
			}
		})
	}
}

// TestPESymbolExtraction tests PE symbol extraction
func TestPESymbolExtraction(t *testing.T) {
	data, err := os.ReadFile("testdata/binary/test_pe_x64.exe")
	if err != nil {
		t.Skipf("Skipping: %v", err)
	}

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if closeErr := info.Close(); closeErr != nil {
			t.Logf("failed to close info: %v", closeErr)
		}
	}()

	// pe binaries may have limited symbols in coff table
	// but we should still test the extraction logic
	t.Logf("Total symbols: %d", len(info.Symbols))

	// verify symbol structure
	for i, sym := range info.Symbols {
		if sym.Name == "" {
			t.Errorf("Symbol %d has empty name", i)
		}
		// verify type is set
		if sym.Type == SymbolTypeUnknown {
			t.Logf("Symbol %s has unknown type (may be normal for PE)", sym.Name)
		}
		// verify binding is set (pe always uses global)
		if sym.Binding != SymbolBindingGlobal {
			t.Errorf("Symbol %s binding = %v, want Global", sym.Name, sym.Binding)
		}
	}
}

// TestPEImportExtraction tests PE import extraction
func TestPEImportExtraction(t *testing.T) {
	data, err := os.ReadFile("testdata/binary/test_pe_x64.exe")
	if err != nil {
		t.Skipf("Skipping: %v", err)
	}

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if closeErr := info.Close(); closeErr != nil {
			t.Logf("failed to close info: %v", closeErr)
		}
	}()

	// pe binaries typically have imports
	if len(info.Imports) == 0 {
		t.Log("No imports found (may be statically linked)")
	}

	// verify import structure
	for i, imp := range info.Imports {
		if imp.Name == "" {
			t.Errorf("Import %d has empty name", i)
		}
		t.Logf("Import: %s (library: %s)", imp.Name, imp.Library)
	}

	// verify imports are in ground truth database
	for _, imp := range info.Imports {
		if imp.Name != "" && imp.Address != 0 {
			if _, exists := info.GroundTruthDB.Imports[imp.Address]; !exists {
				t.Errorf("Import %s not in GroundTruthDB", imp.Name)
			}
		}
	}
}

// TestPEExportExtraction tests PE export extraction
func TestPEExportExtraction(t *testing.T) {
	data, err := os.ReadFile("testdata/binary/test_pe_x64.exe")
	if err != nil {
		t.Skipf("Skipping: %v", err)
	}

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if closeErr := info.Close(); closeErr != nil {
			t.Logf("failed to close info: %v", closeErr)
		}
	}()

	// exe files typically don't have exports (dlls do)
	t.Logf("Exports: %d", len(info.Exports))

	// verify export structure if any exist
	for i, exp := range info.Exports {
		if exp.Name == "" {
			t.Errorf("Export %d has empty name", i)
		}
		if exp.Address == 0 {
			t.Errorf("Export %s has zero address", exp.Name)
		}
		t.Logf("Export: %s at %#x (ordinal: %d)", exp.Name, exp.Address, exp.Ordinal)
	}

	// verify exports are in ground truth database
	for _, exp := range info.Exports {
		if exp.Name != "" && exp.Address != 0 {
			if _, exists := info.GroundTruthDB.Exports[exp.Address]; !exists {
				t.Errorf("Export %s not in GroundTruthDB", exp.Name)
			}
		}
	}
}

// TestPERelocationExtraction tests PE relocation extraction
func TestPERelocationExtraction(t *testing.T) {
	data, err := os.ReadFile("testdata/binary/test_pe_x64.exe")
	if err != nil {
		t.Skipf("Skipping: %v", err)
	}

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if closeErr := info.Close(); closeErr != nil {
			t.Logf("failed to close info: %v", closeErr)
		}
	}()

	// pe binaries may have relocations in .reloc section
	t.Logf("Relocations: %d", len(info.Relocations))

	// verify relocation structure
	for i, reloc := range info.Relocations {
		if reloc.Address == 0 {
			t.Errorf("Relocation %d has zero address", i)
		}
		if reloc.Type == RelocationTypeUnknown {
			t.Errorf("Relocation %d has unknown type", i)
		}
		// pe base relocations typically don't have symbol names
		if i < 5 {
			t.Logf("Relocation: addr=%#x type=%v", reloc.Address, reloc.Type)
		}
	}

	// verify relocations are in ground truth database
	for _, reloc := range info.Relocations {
		if _, exists := info.GroundTruthDB.Relocations[reloc.Address]; !exists {
			t.Errorf("Relocation at %#x not in GroundTruthDB", reloc.Address)
		}
	}
}

// TestPEGroundTruthDatabase tests ground truth database for PE
func TestPEGroundTruthDatabase(t *testing.T) {
	data, err := os.ReadFile("testdata/binary/test_pe_x64.exe")
	if err != nil {
		t.Skipf("Skipping: %v", err)
	}

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if closeErr := info.Close(); closeErr != nil {
			t.Logf("failed to close info: %v", closeErr)
		}
	}()

	db := info.GroundTruthDB

	// verify all maps are initialized
	if db.Relocations == nil {
		t.Error("Relocations map not initialized")
	}
	if db.Imports == nil {
		t.Error("Imports map not initialized")
	}
	if db.Exports == nil {
		t.Error("Exports map not initialized")
	}
	if db.GOTPLT == nil {
		t.Error("GOTPLT map not initialized")
	}
	if db.SymbolsByAddress == nil {
		t.Error("SymbolsByAddress map not initialized")
	}
	if db.SymbolsByName == nil {
		t.Error("SymbolsByName map not initialized")
	}

	t.Logf("GroundTruthDB stats:")
	t.Logf("  Relocations: %d", len(db.Relocations))
	t.Logf("  Imports: %d", len(db.Imports))
	t.Logf("  Exports: %d", len(db.Exports))
	t.Logf("  GOTPLT: %d", len(db.GOTPLT))
	t.Logf("  SymbolsByAddress: %d", len(db.SymbolsByAddress))
	t.Logf("  SymbolsByName: %d", len(db.SymbolsByName))
}

// TestPEOptionalHeader32 tests PE32 (32-bit) parsing
func TestPEOptionalHeader32(t *testing.T) {
	// this test verifies the pe32 code path in parsePE
	// we create a minimal pe32 binary
	parser := NewStandardLibParser()

	// create minimal pe32 binary
	data := createMinimalPE32()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if closeErr := info.Close(); closeErr != nil {
			t.Logf("failed to close info: %v", closeErr)
		}
	}()

	// verify format
	if info.Format != BinaryFormatPE {
		t.Errorf("Format = %v, want PE", info.Format)
	}

	// verify architecture
	if info.Architecture != ArchitectureX86 {
		t.Errorf("Architecture = %v, want x86", info.Architecture)
	}

	// verify entry point and base address are extracted from optional header 32
	if info.EntryPoint == 0 {
		t.Error("EntryPoint not set")
	}
	if info.BaseAddress == 0 {
		t.Error("BaseAddress not set")
	}
}

// TestPEWithSections tests PE parsing with actual sections
func TestPEWithSections(t *testing.T) {
	data, err := os.ReadFile("testdata/binary/test_pe_x64.exe")
	if err != nil {
		t.Skipf("Skipping: %v", err)
	}

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() {
		if closeErr := info.Close(); closeErr != nil {
			t.Logf("failed to close info: %v", closeErr)
		}
	}()

	// verify we have sections
	if len(info.Sections) == 0 {
		t.Fatal("No sections extracted")
	}

	// verify each section has required fields
	for _, sec := range info.Sections {
		if sec.Name == "" {
			t.Error("Section has empty name")
		}
		if sec.Size == 0 {
			t.Logf("Section %s has zero size (may be bss)", sec.Name)
		}
		// verify flags are set
		if sec.Flags == 0 {
			t.Errorf("Section %s has zero flags", sec.Name)
		}
		// verify type is set
		if sec.Type == 0 {
			t.Errorf("Section %s has zero type", sec.Name)
		}
	}
}

// TestPECloseHandling tests PE file handle closing
func TestPECloseHandling(t *testing.T) {
	data, err := os.ReadFile("testdata/binary/test_pe_x64.exe")
	if err != nil {
		t.Skipf("Skipping: %v", err)
	}

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}

	// verify pe file handle is set
	if info.peFile == nil {
		t.Error("peFile handle not set")
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
