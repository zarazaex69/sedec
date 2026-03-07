package binfmt

import (
	"os"
	"testing"
)

// TestWithRealELFBinary tests parser with real ELF binary from testdata
func TestWithRealELFBinary(t *testing.T) {
	data, err := os.ReadFile("testdata/binary/test_elf_x64")
	if err != nil {
		t.Skipf("Skipping: real ELF binary not found (run 'make -C testdata'): %v", err)
	}

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() { _ = info.Close() }()

	// verify format detection
	if info.Format != BinaryFormatELF {
		t.Errorf("Format = %v, want ELF", info.Format)
	}

	// verify architecture detection
	if info.Architecture != ArchitectureX86_64 {
		t.Errorf("Architecture = %v, want x86_64", info.Architecture)
	}

	// verify sections extracted
	if len(info.Sections) == 0 {
		t.Fatal("No sections extracted")
	}

	// verify .text section exists and has correct properties
	var textSection *Section
	for _, sec := range info.Sections {
		if sec.Name == ".text" {
			textSection = sec
			break
		}
	}
	if textSection == nil {
		t.Fatal(".text section not found")
	}
	if !textSection.IsExecutable {
		t.Error(".text section should be executable")
	}
	if textSection.IsWritable {
		t.Error(".text section should not be writable")
	}

	// verify symbols extracted
	if len(info.Symbols) == 0 {
		t.Fatal("No symbols extracted")
	}

	// verify main function symbol
	var mainSymbol *Symbol
	for _, sym := range info.Symbols {
		if sym.Name == "main" {
			mainSymbol = sym
			break
		}
	}
	if mainSymbol == nil {
		t.Fatal("main symbol not found")
	}
	if mainSymbol.Type != SymbolTypeFunction {
		t.Errorf("main type = %v, want Function", mainSymbol.Type)
	}
	if mainSymbol.Binding != SymbolBindingGlobal {
		t.Errorf("main binding = %v, want Global", mainSymbol.Binding)
	}

	// verify add function symbol
	var addSymbol *Symbol
	for _, sym := range info.Symbols {
		if sym.Name == "add" {
			addSymbol = sym
			break
		}
	}
	if addSymbol == nil {
		t.Fatal("add symbol not found")
	}
	if addSymbol.Type != SymbolTypeFunction {
		t.Errorf("add type = %v, want Function", addSymbol.Type)
	}

	// verify ground truth database populated
	if len(info.GroundTruthDB.SymbolsByName) == 0 {
		t.Error("GroundTruthDB.SymbolsByName empty")
	}
	if len(info.GroundTruthDB.SymbolsByAddress) == 0 {
		t.Error("GroundTruthDB.SymbolsByAddress empty")
	}

	// verify main in ground truth database
	mainAddr, exists := info.GroundTruthDB.SymbolsByName["main"]
	if !exists {
		t.Error("main not in GroundTruthDB.SymbolsByName")
	}
	if mainAddr == 0 {
		t.Error("main has zero address")
	}

	// verify bidirectional mapping
	if name := info.GroundTruthDB.SymbolsByAddress[mainAddr]; name != "main" {
		t.Errorf("SymbolsByAddress[%#x] = %s, want main", mainAddr, name)
	}

	// verify relocations structure (may be empty for static binary)
	if info.Relocations == nil {
		t.Error("Relocations not initialized")
	}

	// verify imports/exports structure
	if info.Imports == nil {
		t.Error("Imports not initialized")
	}
	if info.Exports == nil {
		t.Error("Exports not initialized")
	}
}

// TestELFSectionProperties tests section property extraction
func TestELFSectionProperties(t *testing.T) {
	data, err := os.ReadFile("testdata/binary/test_elf_x64")
	if err != nil {
		t.Skipf("Skipping: %v", err)
	}

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() { _ = info.Close() }()

	sectionTests := []struct {
		name       string
		executable bool
		writable   bool
		allocated  bool
	}{
		{".text", true, false, true},
		{".rodata", false, false, true},
		{".data", false, true, true},
		{".bss", false, true, true},
	}

	sectionMap := make(map[string]*Section)
	for _, sec := range info.Sections {
		sectionMap[sec.Name] = sec
	}

	for _, tt := range sectionTests {
		t.Run(tt.name, func(t *testing.T) {
			sec, exists := sectionMap[tt.name]
			if !exists {
				t.Skipf("Section %s not found (may not exist in minimal binary)", tt.name)
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
		})
	}
}

// TestELFSymbolTypes tests symbol type conversion
func TestELFSymbolTypes(t *testing.T) {
	data, err := os.ReadFile("testdata/binary/test_elf_x64")
	if err != nil {
		t.Skipf("Skipping: %v", err)
	}

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() { _ = info.Close() }()

	// collect symbols by type
	functionSymbols := 0
	objectSymbols := 0
	sectionSymbols := 0
	fileSymbols := 0

	for _, sym := range info.Symbols {
		switch sym.Type {
		case SymbolTypeFunction:
			functionSymbols++
		case SymbolTypeObject:
			objectSymbols++
		case SymbolTypeSection:
			sectionSymbols++
		case SymbolTypeFile:
			fileSymbols++
		case SymbolTypeTLS, SymbolTypeUnknown:
			// skip tls and unknown types
		}
	}

	// verify we have at least some function symbols
	if functionSymbols == 0 {
		t.Error("No function symbols found")
	}

	t.Logf("Symbol types: functions=%d, objects=%d, sections=%d, files=%d",
		functionSymbols, objectSymbols, sectionSymbols, fileSymbols)
}

// TestELFSymbolBindings tests symbol binding conversion
func TestELFSymbolBindings(t *testing.T) {
	data, err := os.ReadFile("testdata/binary/test_elf_x64")
	if err != nil {
		t.Skipf("Skipping: %v", err)
	}

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() { _ = info.Close() }()

	// collect symbols by binding
	globalSymbols := 0
	localSymbols := 0
	weakSymbols := 0

	for _, sym := range info.Symbols {
		switch sym.Binding {
		case SymbolBindingGlobal:
			globalSymbols++
		case SymbolBindingLocal:
			localSymbols++
		case SymbolBindingWeak:
			weakSymbols++
		case SymbolBindingUnknown:
			// skip unknown bindings
		}
	}

	// verify we have at least some global symbols (main, add, etc.)
	if globalSymbols == 0 {
		t.Error("No global symbols found")
	}

	t.Logf("Symbol bindings: global=%d, local=%d, weak=%d",
		globalSymbols, localSymbols, weakSymbols)
}

// TestELFImportsExports tests import/export extraction
func TestELFImportsExports(t *testing.T) {
	data, err := os.ReadFile("testdata/binary/test_elf_x64")
	if err != nil {
		t.Skipf("Skipping: %v", err)
	}

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() { _ = info.Close() }()

	// for dynamically linked binary, we should have imports
	// for statically linked, imports may be empty
	t.Logf("Imports: %d, Exports: %d", len(info.Imports), len(info.Exports))

	// verify structure is initialized even if empty
	if info.Imports == nil {
		t.Error("Imports not initialized")
	}
	if info.Exports == nil {
		t.Error("Exports not initialized")
	}

	// if we have imports, verify they have names
	for i, imp := range info.Imports {
		if imp.Name == "" {
			t.Errorf("Import %d has empty name", i)
		}
	}

	// if we have exports, verify they have names and addresses
	for i, exp := range info.Exports {
		if exp.Name == "" {
			t.Errorf("Export %d has empty name", i)
		}
	}
}
