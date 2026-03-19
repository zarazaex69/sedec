package binfmt

import (
	"debug/elf"
	"os"
	"testing"
)

func TestParseELFFullPipeline(t *testing.T) {
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

	if info.Format != BinaryFormatELF {
		t.Fatalf("Format = %v, want ELF", info.Format)
	}
	if info.Architecture != ArchitectureX86_64 {
		t.Fatalf("Architecture = %v, want x86_64", info.Architecture)
	}
	if info.EntryPoint == 0 {
		t.Error("EntryPoint is zero")
	}
	if info.elfFile == nil {
		t.Fatal("elfFile handle not stored")
	}

	if len(info.Sections) == 0 {
		t.Fatal("no sections extracted")
	}
	var hasText, hasData bool
	for _, sec := range info.Sections {
		if sec.Name == ".text" {
			hasText = true
			if !sec.IsExecutable {
				t.Error(".text not executable")
			}
			if !sec.IsAllocated {
				t.Error(".text not allocated")
			}
			if len(sec.Data) == 0 {
				t.Error(".text has no data")
			}
		}
		if sec.Name == ".data" {
			hasData = true
			if !sec.IsWritable {
				t.Error(".data not writable")
			}
		}
	}
	if !hasText {
		t.Error(".text section missing")
	}
	if !hasData {
		t.Error(".data section missing")
	}
}

func TestParseELFSymbolExtraction(t *testing.T) {
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

	if len(info.Symbols) == 0 {
		t.Fatal("no symbols extracted")
	}

	symMap := make(map[string]*Symbol)
	for _, sym := range info.Symbols {
		symMap[sym.Name] = sym
	}

	mainSym, ok := symMap["main"]
	if !ok {
		t.Fatal("main symbol not found")
	}
	if mainSym.Type != SymbolTypeFunction {
		t.Errorf("main type = %v, want Function", mainSym.Type)
	}
	if mainSym.Address == 0 {
		t.Error("main address is zero")
	}
	if mainSym.Section == "" {
		t.Error("main has no section")
	}

	addSym, ok := symMap["add"]
	if !ok {
		t.Fatal("add symbol not found")
	}
	if addSym.Type != SymbolTypeFunction {
		t.Errorf("add type = %v, want Function", addSym.Type)
	}

	globalData, ok := symMap["global_data"]
	if !ok {
		t.Fatal("global_data symbol not found")
	}
	if globalData.Type != SymbolTypeObject {
		t.Errorf("global_data type = %v, want Object", globalData.Type)
	}
}

func TestParseELFRelocations(t *testing.T) {
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

	if len(info.Relocations) == 0 {
		t.Fatal("no relocations extracted from dynamically linked binary")
	}

	var hasJumpSlot, hasGlobDat bool
	for _, reloc := range info.Relocations {
		if reloc.Address == 0 {
			t.Error("relocation with zero address")
		}
		switch reloc.Type {
		case RelocationTypeJumpSlot:
			hasJumpSlot = true
			if reloc.Symbol == "" {
				t.Error("jump slot relocation without symbol name")
			}
		case RelocationTypeGlobDat:
			hasGlobDat = true
		}
	}

	if !hasJumpSlot {
		t.Error("no JUMP_SLOT relocations found in dynamically linked binary")
	}
	if !hasGlobDat {
		t.Error("no GLOB_DAT relocations found in dynamically linked binary")
	}
}

func TestParseELFImportsExports(t *testing.T) {
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

	if len(info.Imports) == 0 {
		t.Fatal("no imports from dynamically linked binary")
	}

	importNames := make(map[string]bool)
	for _, imp := range info.Imports {
		if imp.Name == "" {
			t.Error("import with empty name")
		}
		importNames[imp.Name] = true
	}

	if !importNames["printf"] {
		t.Error("printf not found in imports")
	}
}

func TestParseELFGroundTruthDB(t *testing.T) {
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

	db := info.GroundTruthDB
	if db == nil {
		t.Fatal("GroundTruthDB is nil")
	}

	if len(db.Relocations) == 0 {
		t.Error("GroundTruthDB.Relocations empty")
	}
	if len(db.Imports) == 0 {
		t.Error("GroundTruthDB.Imports empty")
	}
	if len(db.SymbolsByAddress) == 0 {
		t.Error("GroundTruthDB.SymbolsByAddress empty")
	}
	if len(db.SymbolsByName) == 0 {
		t.Error("GroundTruthDB.SymbolsByName empty")
	}

	mainAddr, ok := db.SymbolsByName["main"]
	if !ok {
		t.Fatal("main not in SymbolsByName")
	}
	if mainAddr == 0 {
		t.Error("main address is zero in GroundTruthDB")
	}

	name, ok := db.SymbolsByAddress[mainAddr]
	if !ok {
		t.Fatal("main address not in SymbolsByAddress")
	}
	if name != "main" {
		t.Errorf("SymbolsByAddress[main] = %s, want main", name)
	}

	if len(db.GOTPLT) == 0 {
		t.Log("GOTPLT empty (may be expected for some binaries)")
	}
}

func TestELFSymbolBindingLOOS(t *testing.T) {
	parser := NewStandardLibParser()

	osBind := parser.convertELFSymbolBinding(elf.STB_LOOS)
	if osBind != SymbolBindingUnknown {
		t.Errorf("STB_LOOS binding = %v, want Unknown", osBind)
	}

	hiosBind := parser.convertELFSymbolBinding(elf.STB_HIOS)
	if hiosBind != SymbolBindingUnknown {
		t.Errorf("STB_HIOS binding = %v, want Unknown", hiosBind)
	}

	loprocBind := parser.convertELFSymbolBinding(elf.STB_LOPROC)
	if loprocBind != SymbolBindingUnknown {
		t.Errorf("STB_LOPROC binding = %v, want Unknown", loprocBind)
	}

	hiprocBind := parser.convertELFSymbolBinding(elf.STB_HIPROC)
	if hiprocBind != SymbolBindingUnknown {
		t.Errorf("STB_HIPROC binding = %v, want Unknown", hiprocBind)
	}
}
