package binfmt

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"errors"
	"testing"
)

func TestParseMachORelocationInfo_LittleEndian(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64},
		ByteOrder:  binary.LittleEndian,
		Symtab: &macho.Symtab{
			Syms: []macho.Symbol{
				{Name: "_printf", Type: 0x01, Sect: 0, Value: 0},
				{Name: "_main", Type: 0x0F, Sect: 1, Value: 0x1000},
			},
		},
	}
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], 0x2000)
	binary.LittleEndian.PutUint32(data[4:8], 1)
	reloc := parser.parseMachORelocationInfo(data, machoFile, true)
	if reloc == nil {
		t.Fatal("returned nil")
	}
	if reloc.Address != Address(0x2000) {
		t.Errorf("Address = %#x, want 0x2000", reloc.Address)
	}
	if reloc.Symbol != "_main" {
		t.Errorf("Symbol = %q, want _main", reloc.Symbol)
	}
}

func TestParseMachORelocationInfo_BigEndian(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuPpc},
		ByteOrder:  binary.BigEndian,
	}
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], 0x3000)
	binary.BigEndian.PutUint32(data[4:8], 0)
	reloc := parser.parseMachORelocationInfo(data, machoFile, false)
	if reloc == nil {
		t.Fatal("returned nil")
	}
	if reloc.Address != Address(0x3000) {
		t.Errorf("Address = %#x, want 0x3000", reloc.Address)
	}
}

func TestParseMachORelocationInfo_TooShort(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64},
		ByteOrder:  binary.LittleEndian,
	}
	reloc := parser.parseMachORelocationInfo(make([]byte, 4), machoFile, true)
	if reloc != nil {
		t.Error("expected nil for data shorter than 8 bytes")
	}
}

func TestParseMachORelocationInfo_NoSymtab(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64},
		ByteOrder:  binary.LittleEndian,
	}
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], 0x1000)
	binary.LittleEndian.PutUint32(data[4:8], 5)
	reloc := parser.parseMachORelocationInfo(data, machoFile, true)
	if reloc == nil {
		t.Fatal("returned nil")
	}
	if reloc.Symbol != "" {
		t.Errorf("Symbol = %q, want empty", reloc.Symbol)
	}
}

func TestParseMachORelocationInfo_SymIdxOutOfRange(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64},
		ByteOrder:  binary.LittleEndian,
		Symtab:     &macho.Symtab{Syms: []macho.Symbol{{Name: "_only"}}},
	}
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], 0x1000)
	binary.LittleEndian.PutUint32(data[4:8], 999)
	reloc := parser.parseMachORelocationInfo(data, machoFile, false)
	if reloc == nil {
		t.Fatal("returned nil")
	}
	if reloc.Symbol != "" {
		t.Errorf("Symbol = %q, want empty (out of range)", reloc.Symbol)
	}
}

func TestExtractMachOExternalRelocations_WithEntries(t *testing.T) {
	parser := NewStandardLibParser()
	entry := make([]byte, 8)
	binary.LittleEndian.PutUint32(entry[0:4], 0x5000)
	data := make([]byte, 40+8)
	copy(data[40:], entry)
	machoFile := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64},
		ByteOrder:  binary.LittleEndian,
	}
	dysymtab := &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Nextrel: 1, Extreloff: 40}}
	relocs := parser.extractMachOExternalRelocations(machoFile, dysymtab, data)
	if len(relocs) != 1 {
		t.Fatalf("len = %d, want 1", len(relocs))
	}
	if relocs[0].Address != Address(0x5000) {
		t.Errorf("Address = %#x, want 0x5000", relocs[0].Address)
	}
}

func TestExtractMachOExternalRelocations_ZeroCount(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	dysymtab := &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Nextrel: 0}}
	relocs := parser.extractMachOExternalRelocations(machoFile, dysymtab, nil)
	if len(relocs) != 0 {
		t.Errorf("len = %d, want 0", len(relocs))
	}
}

func TestExtractMachOExternalRelocations_BoundsExceeded(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	dysymtab := &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Nextrel: 100, Extreloff: 0}}
	relocs := parser.extractMachOExternalRelocations(machoFile, dysymtab, make([]byte, 10))
	if len(relocs) != 0 {
		t.Errorf("len = %d, want 0", len(relocs))
	}
}

func TestExtractMachOLocalRelocations_WithEntries(t *testing.T) {
	parser := NewStandardLibParser()
	entry := make([]byte, 8)
	binary.LittleEndian.PutUint32(entry[0:4], 0x6000)
	data := make([]byte, 40+8)
	copy(data[40:], entry)
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	dysymtab := &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Nlocrel: 1, Locreloff: 40}}
	relocs := parser.extractMachOLocalRelocations(machoFile, dysymtab, data)
	if len(relocs) != 1 {
		t.Fatalf("len = %d, want 1", len(relocs))
	}
	if relocs[0].Address != Address(0x6000) {
		t.Errorf("Address = %#x, want 0x6000", relocs[0].Address)
	}
}

func TestExtractMachOLocalRelocations_ZeroCount(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	dysymtab := &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Nlocrel: 0}}
	relocs := parser.extractMachOLocalRelocations(machoFile, dysymtab, nil)
	if len(relocs) != 0 {
		t.Errorf("len = %d, want 0", len(relocs))
	}
}

func TestExtractMachOLocalRelocations_BoundsExceeded(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	dysymtab := &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Nlocrel: 50, Locreloff: 0}}
	relocs := parser.extractMachOLocalRelocations(machoFile, dysymtab, make([]byte, 8))
	if len(relocs) != 0 {
		t.Errorf("len = %d, want 0", len(relocs))
	}
}

func TestExtractMachOIndirectSymbols_ZeroCount(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	dysymtab := &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Nindirectsyms: 0}}
	relocs := parser.extractMachOIndirectSymbols(machoFile, dysymtab, nil)
	if len(relocs) != 0 {
		t.Errorf("len = %d, want 0", len(relocs))
	}
}

func TestExtractMachOIndirectSymbols_BoundsExceeded(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	dysymtab := &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Nindirectsyms: 100, Indirectsymoff: 0}}
	relocs := parser.extractMachOIndirectSymbols(machoFile, dysymtab, make([]byte, 10))
	if len(relocs) != 0 {
		t.Errorf("len = %d, want 0", len(relocs))
	}
}

func TestExtractMachOIndirectSymbols_WithData(t *testing.T) {
	parser := NewStandardLibParser()
	indirectData := make([]byte, 8)
	binary.LittleEndian.PutUint32(indirectData[0:4], 0)
	binary.LittleEndian.PutUint32(indirectData[4:8], 1)
	data := make([]byte, 64+8)
	copy(data[64:], indirectData)
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	dysymtab := &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{Nindirectsyms: 2, Indirectsymoff: 64}}
	relocs := parser.extractMachOIndirectSymbols(machoFile, dysymtab, data)
	if relocs == nil {
		t.Fatal("returned nil")
	}
}

func TestParseMachOBindInfo_ZeroSize(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	dyldInfo := &dyldInfoCmd{BindSize: 0}
	imports := parser.parseMachOBindInfo(machoFile, nil, dyldInfo, nil)
	if len(imports) != 0 {
		t.Errorf("len = %d, want 0", len(imports))
	}
}

func TestParseMachOBindInfo_BoundsExceeded(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	dyldInfo := &dyldInfoCmd{BindOff: 0, BindSize: 1000}
	imports := parser.parseMachOBindInfo(machoFile, make([]byte, 10), dyldInfo, nil)
	if len(imports) != 0 {
		t.Errorf("len = %d, want 0", len(imports))
	}
}

func TestParseMachOBindInfo_ValidData(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	data := make([]byte, 96)
	dyldInfo := &dyldInfoCmd{BindOff: 64, BindSize: 32}
	imports := parser.parseMachOBindInfo(machoFile, data, dyldInfo, map[uint32]string{1: "libSystem.B.dylib"})
	if imports == nil {
		t.Fatal("returned nil")
	}
}

func TestParseMachOExportTrie_ZeroSize(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	dyldInfo := &dyldInfoCmd{ExportSize: 0}
	exports := parser.parseMachOExportTrie(machoFile, nil, dyldInfo)
	if len(exports) != 0 {
		t.Errorf("len = %d, want 0", len(exports))
	}
}

func TestParseMachOExportTrie_BoundsExceeded(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	dyldInfo := &dyldInfoCmd{ExportOff: 0, ExportSize: 500}
	exports := parser.parseMachOExportTrie(machoFile, make([]byte, 10), dyldInfo)
	if len(exports) != 0 {
		t.Errorf("len = %d, want 0", len(exports))
	}
}

func TestParseMachOExportTrie_ValidData(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	data := make([]byte, 48)
	dyldInfo := &dyldInfoCmd{ExportOff: 32, ExportSize: 16}
	exports := parser.parseMachOExportTrie(machoFile, data, dyldInfo)
	if exports == nil {
		t.Fatal("returned nil")
	}
}

func TestReadPointerValue_64bit(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, 0xDEADBEEFCAFEBABE)
	val := parser.readPointerValue(data, 0, 8, machoFile)
	if val != 0xDEADBEEFCAFEBABE {
		t.Errorf("val = %#x, want 0xDEADBEEFCAFEBABE", val)
	}
}

func TestReadPointerValue_32bit(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.Cpu386}, ByteOrder: binary.LittleEndian}
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, 0xDEADBEEF)
	val := parser.readPointerValue(data, 0, 4, machoFile)
	if val != 0xDEADBEEF {
		t.Errorf("val = %#x, want 0xDEADBEEF", val)
	}
}

func TestReadPointerValue_BigEndian(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuPpc64}, ByteOrder: binary.BigEndian}
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, 0x0000000100001000)
	val := parser.readPointerValue(data, 0, 8, machoFile)
	if val != 0x0000000100001000 {
		t.Errorf("val = %#x, want 0x0000000100001000", val)
	}
}

func TestReadPointerValue_WithOffset(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	data := make([]byte, 24)
	binary.LittleEndian.PutUint64(data[8:16], 0xAAAABBBBCCCCDDDD)
	val := parser.readPointerValue(data, 8, 8, machoFile)
	if val != 0xAAAABBBBCCCCDDDD {
		t.Errorf("val = %#x, want 0xAAAABBBBCCCCDDDD", val)
	}
}

func TestResolveSymbolPointer_WithRelocation(t *testing.T) {
	parser := NewStandardLibParser()
	db := NewGroundTruthDatabase()
	db.Relocations[Address(0x4000)] = &Relocation{Address: Address(0x4000), Symbol: "_printf", Type: RelocationTypeGOT}
	db.SymbolsByName["_printf"] = Address(0x1000)
	parser.resolveSymbolPointer(Address(0x4000), db)
	if targetAddr, exists := db.GOTPLT[Address(0x4000)]; !exists || targetAddr != Address(0x1000) {
		t.Errorf("GOTPLT[0x4000] = %#x, want 0x1000", targetAddr)
	}
}

func TestResolveSymbolPointer_NoRelocation(t *testing.T) {
	parser := NewStandardLibParser()
	db := NewGroundTruthDatabase()
	parser.resolveSymbolPointer(Address(0x4000), db)
	if len(db.GOTPLT) != 0 {
		t.Error("GOTPLT should be empty")
	}
}

func TestResolveSymbolPointer_EmptySymbol(t *testing.T) {
	parser := NewStandardLibParser()
	db := NewGroundTruthDatabase()
	db.Relocations[Address(0x4000)] = &Relocation{Address: Address(0x4000), Symbol: ""}
	parser.resolveSymbolPointer(Address(0x4000), db)
	if len(db.GOTPLT) != 0 {
		t.Error("GOTPLT should be empty for empty symbol")
	}
}

func TestResolveSymbolPointer_SymbolNotFound(t *testing.T) {
	parser := NewStandardLibParser()
	db := NewGroundTruthDatabase()
	db.Relocations[Address(0x4000)] = &Relocation{Address: Address(0x4000), Symbol: "_nonexistent"}
	parser.resolveSymbolPointer(Address(0x4000), db)
	if len(db.GOTPLT) != 0 {
		t.Error("GOTPLT should be empty when symbol not in SymbolsByName")
	}
}

func TestReadSymbolPointerSection_ZeroSize(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	sec := &macho.Section{SectionHeader: macho.SectionHeader{Size: 0, Flags: 0x07}}
	data, ptrSize := parser.readSymbolPointerSection(sec, machoFile)
	if data != nil {
		t.Error("expected nil data for zero-size section")
	}
	if ptrSize != 0 {
		t.Errorf("ptrSize = %d, want 0", ptrSize)
	}
}

func TestReadSymbolPointerSection_Oversized(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	sec := &macho.Section{SectionHeader: macho.SectionHeader{Size: 200 * 1024 * 1024, Flags: 0x07}}
	data, ptrSize := parser.readSymbolPointerSection(sec, machoFile)
	if data != nil {
		t.Error("expected nil data for oversized section")
	}
	if ptrSize != 0 {
		t.Errorf("ptrSize = %d, want 0", ptrSize)
	}
}

func TestIsSymbolPointerSection_AllTypes(t *testing.T) {
	parser := NewStandardLibParser()
	tests := []struct {
		flags uint32
		want  bool
	}{
		{0x06, true},
		{0x07, true},
		{0x08, false},
		{0x00, false},
		{0x01, false},
		{0xFF, false},
	}
	for _, tt := range tests {
		sec := &macho.Section{SectionHeader: macho.SectionHeader{Flags: tt.flags}}
		got := parser.isSymbolPointerSection(sec)
		if got != tt.want {
			t.Errorf("isSymbolPointerSection(flags=%#x) = %v, want %v", tt.flags, got, tt.want)
		}
	}
}

func TestBuildMachOGroundTruthDB_Full(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	info := &BinaryInfo{
		Format: BinaryFormatMachO, Architecture: ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(), machoFile: machoFile,
		Relocations: []*Relocation{
			{Address: Address(0x2000), Symbol: "_puts", Type: RelocationTypeGOT},
			{Address: Address(0x2008), Symbol: "_exit", Type: RelocationTypePLT},
		},
		Imports: []*Import{{Name: "_puts", Address: Address(0x5000), Library: "libSystem.B.dylib"}},
		Exports: []*Export{{Name: "_main", Address: Address(0x1000)}},
		Symbols: []*Symbol{
			{Name: "_main", Address: Address(0x1000), Type: SymbolTypeFunction},
			{Name: "_helper", Address: Address(0x1100), Type: SymbolTypeFunction},
		},
	}
	parser.buildMachOGroundTruthDB(info, machoFile, nil)
	db := info.GroundTruthDB
	if len(db.Relocations) != 2 {
		t.Errorf("Relocations = %d, want 2", len(db.Relocations))
	}
	if _, exists := db.Imports[Address(0x5000)]; !exists {
		t.Error("_puts not in Imports")
	}
	if _, exists := db.Exports[Address(0x1000)]; !exists {
		t.Error("_main not in Exports")
	}
	if addr := db.SymbolsByName["_main"]; addr != Address(0x1000) {
		t.Errorf("SymbolsByName[_main] = %#x, want 0x1000", addr)
	}
	if name := db.SymbolsByAddress[Address(0x1100)]; name != "_helper" {
		t.Errorf("SymbolsByAddress[0x1100] = %q, want _helper", name)
	}
}

func TestBuildMachOGroundTruthDB_GOTPLTResolution(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	info := &BinaryInfo{
		Format: BinaryFormatMachO, Architecture: ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(), machoFile: machoFile,
		Relocations: []*Relocation{{Address: Address(0x3000), Symbol: "_malloc", Type: RelocationTypeGOT}},
		Imports:     []*Import{{Name: "_malloc", Address: Address(0x7000)}},
		Symbols:     []*Symbol{}, Exports: []*Export{},
	}
	parser.buildMachOGroundTruthDB(info, machoFile, nil)
	if targetAddr, exists := info.GroundTruthDB.GOTPLT[Address(0x3000)]; !exists || targetAddr != Address(0x7000) {
		t.Errorf("GOTPLT[0x3000] = %#x, want 0x7000", targetAddr)
	}
}

func TestBuildMachOGroundTruthDB_SymbolPrecedence(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	info := &BinaryInfo{
		Format: BinaryFormatMachO, Architecture: ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(), machoFile: machoFile,
		Relocations: []*Relocation{},
		Imports:     []*Import{{Name: "_shared", Address: Address(0x5000)}},
		Exports:     []*Export{},
		Symbols:     []*Symbol{{Name: "_shared", Address: Address(0x9000)}},
	}
	parser.buildMachOGroundTruthDB(info, machoFile, nil)
	if addr := info.GroundTruthDB.SymbolsByName["_shared"]; addr != Address(0x5000) {
		t.Errorf("SymbolsByName[_shared] = %#x, want 0x5000 (imports take precedence)", addr)
	}
}

func TestBuildMachOGroundTruthDB_EmptySymbolSkipped(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	info := &BinaryInfo{
		Format: BinaryFormatMachO, Architecture: ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(), machoFile: machoFile,
		Relocations: []*Relocation{}, Imports: []*Import{}, Exports: []*Export{},
		Symbols: []*Symbol{{Name: "", Address: Address(0x1000)}, {Name: "_valid", Address: Address(0)}},
	}
	parser.buildMachOGroundTruthDB(info, machoFile, nil)
	if len(info.GroundTruthDB.SymbolsByAddress) != 0 {
		t.Errorf("SymbolsByAddress should be empty, got %d", len(info.GroundTruthDB.SymbolsByAddress))
	}
}

func TestExtractMachOSymbolsFromSymtab_NilSymtab(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}}
	symbols := parser.extractMachOSymbolsFromSymtab(machoFile)
	if len(symbols) != 0 {
		t.Errorf("len = %d, want 0 for nil symtab", len(symbols))
	}
}

func TestExtractMachOSymbolsFromSymtab_StabsFiltered(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64},
		Symtab: &macho.Symtab{Syms: []macho.Symbol{
			{Name: "stab_debug", Type: 0xE0, Sect: 1, Value: 0x1000},
			{Name: "_real_func", Type: 0x0F, Sect: 1, Value: 0x2000},
			{Name: "another_stab", Type: 0x20, Sect: 1, Value: 0x3000},
		}},
	}
	symbols := parser.extractMachOSymbolsFromSymtab(machoFile)
	if len(symbols) != 1 {
		t.Fatalf("len = %d, want 1", len(symbols))
	}
	if symbols[0].Name != "_real_func" {
		t.Errorf("Name = %q, want _real_func", symbols[0].Name)
	}
}

func TestExtractMachOSymbolsFromSymtab_UndefinedExternals(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64},
		Symtab:     &macho.Symtab{Syms: []macho.Symbol{{Name: "_printf", Type: 0x01, Sect: 0, Value: 0}}},
	}
	symbols := parser.extractMachOSymbolsFromSymtab(machoFile)
	if len(symbols) != 1 {
		t.Fatalf("len = %d, want 1", len(symbols))
	}
	if symbols[0].Binding != SymbolBindingGlobal {
		t.Errorf("Binding = %v, want Global", symbols[0].Binding)
	}
}

func TestExtractMachOSymbolsFromSymtab_ZeroValueDefinedSkipped(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64},
		Symtab:     &macho.Symtab{Syms: []macho.Symbol{{Name: "_zero", Type: 0x0E, Sect: 1, Value: 0}}},
	}
	symbols := parser.extractMachOSymbolsFromSymtab(machoFile)
	if len(symbols) != 0 {
		t.Errorf("len = %d, want 0 (zero value + non-zero sect skipped)", len(symbols))
	}
}

func TestExtractMachOSymbolsFromSymtab_SectionName(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64},
		Symtab:     &macho.Symtab{Syms: []macho.Symbol{{Name: "_main", Type: 0x0F, Sect: 1, Value: 0x1000}}},
		Sections:   []*macho.Section{{SectionHeader: macho.SectionHeader{Name: "__text", Seg: "__TEXT"}}},
	}
	symbols := parser.extractMachOSymbolsFromSymtab(machoFile)
	if len(symbols) != 1 {
		t.Fatalf("len = %d, want 1", len(symbols))
	}
	if symbols[0].Section != "__TEXT.__text" {
		t.Errorf("Section = %q, want __TEXT.__text", symbols[0].Section)
	}
}

func TestExtractMachOSymbolsFromSymtab_WeakBinding(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64},
		Symtab:     &macho.Symtab{Syms: []macho.Symbol{{Name: "_weak", Type: 0x0F, Sect: 1, Desc: 0x0080, Value: 0x2000}}},
		Sections:   []*macho.Section{{SectionHeader: macho.SectionHeader{Name: "__text", Seg: "__TEXT"}}},
	}
	symbols := parser.extractMachOSymbolsFromSymtab(machoFile)
	if len(symbols) != 1 {
		t.Fatalf("len = %d, want 1", len(symbols))
	}
	if symbols[0].Binding != SymbolBindingWeak {
		t.Errorf("Binding = %v, want Weak", symbols[0].Binding)
	}
}

func TestExtractMachOSymbolsFromSymtab_LocalBinding(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64},
		Symtab:     &macho.Symtab{Syms: []macho.Symbol{{Name: "_local", Type: 0x0E, Sect: 1, Value: 0x3000}}},
		Sections:   []*macho.Section{{SectionHeader: macho.SectionHeader{Name: "__text", Seg: "__TEXT"}}},
	}
	symbols := parser.extractMachOSymbolsFromSymtab(machoFile)
	if len(symbols) != 1 {
		t.Fatalf("len = %d, want 1", len(symbols))
	}
	if symbols[0].Binding != SymbolBindingLocal {
		t.Errorf("Binding = %v, want Local", symbols[0].Binding)
	}
}

func TestExtractPERelocations_NoRelocSection(t *testing.T) {
	parser := NewStandardLibParser()
	data := createMinimalPE64()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() { _ = info.Close() }()
	if len(info.Relocations) != 0 {
		t.Errorf("len(Relocations) = %d, want 0", len(info.Relocations))
	}
}

func TestParseFatMachO_ZeroArchitectures(t *testing.T) {
	parser := NewStandardLibParser()
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], machoMagicFat)
	binary.BigEndian.PutUint32(data[4:8], 0)
	_, err := parser.Parse(data)
	if err == nil {
		t.Fatal("expected error for zero architectures")
	}
}

func TestParseFatMachO_ArchExceedsFileSize(t *testing.T) {
	parser := NewStandardLibParser()
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, uint32(machoMagicFat))
	_ = binary.Write(buf, binary.BigEndian, uint32(1))
	_ = binary.Write(buf, binary.BigEndian, uint32(0x01000007))
	_ = binary.Write(buf, binary.BigEndian, uint32(3))
	_ = binary.Write(buf, binary.BigEndian, uint32(1000))
	_ = binary.Write(buf, binary.BigEndian, uint32(5000))
	_ = binary.Write(buf, binary.BigEndian, uint32(12))
	_, err := parser.Parse(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for arch exceeding file size")
	}
}

func TestParseFatMachO_TruncatedFatArch(t *testing.T) {
	parser := NewStandardLibParser()
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, uint32(machoMagicFat))
	_ = binary.Write(buf, binary.BigEndian, uint32(1))
	_, err := parser.parseFatMachO(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for truncated fat_arch")
	}
}

func TestParseDispatch_UnknownFormat(t *testing.T) {
	parser := NewStandardLibParser()
	_, err := parser.Parse([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
	var magicErr *InvalidMagicError
	if !errors.As(err, &magicErr) {
		t.Errorf("expected InvalidMagicError, got %T", err)
	}
}

func TestParseDispatch_TooShort(t *testing.T) {
	parser := NewStandardLibParser()
	_, err := parser.Parse([]byte{0x7F})
	if err == nil {
		t.Fatal("expected error for short data")
	}
	var truncErr *TruncatedFileError
	if errors.As(err, &truncErr) {
		if truncErr.Expected != 4 {
			t.Errorf("Expected = %d, want 4", truncErr.Expected)
		}
	} else {
		t.Errorf("expected TruncatedFileError, got %T", err)
	}
}

func TestParseDispatch_EmptyData(t *testing.T) {
	parser := NewStandardLibParser()
	_, err := parser.Parse(nil)
	if err == nil {
		t.Fatal("expected error for nil data")
	}
}

func TestParseDispatch_MalformedELF(t *testing.T) {
	parser := NewStandardLibParser()
	_, err := parser.Parse([]byte{0x7F, 'E', 'L', 'F', 0xFF, 0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for malformed ELF")
	}
}

func TestParseDispatch_MalformedPE(t *testing.T) {
	parser := NewStandardLibParser()
	_, err := parser.Parse([]byte{'M', 'Z', 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for malformed PE")
	}
}

func TestParseDispatch_MalformedMachO(t *testing.T) {
	parser := NewStandardLibParser()
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], 0xFEEDFACF)
	data[4] = 0xFF
	_, err := parser.Parse(data)
	if err == nil {
		t.Fatal("expected error for malformed Mach-O")
	}
}

func TestDetectFormat_AllMachOMagics(t *testing.T) {
	parser := NewStandardLibParser()
	magics := []uint32{machoMagic32, machoMagic64, machoMagicFat, machoMagic32Rev, machoMagic64Rev}
	for _, magic := range magics {
		data := make([]byte, 4)
		data[0] = byte(magic >> 24)
		data[1] = byte(magic >> 16)
		data[2] = byte(magic >> 8)
		data[3] = byte(magic)
		format := parser.detectFormat(data)
		if format != BinaryFormatMachO {
			t.Errorf("detectFormat(%#x) = %v, want MachO", magic, format)
		}
	}
}

func TestProcessSymbolPointers_EmptyData(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	sec := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x3000, Size: 16}}
	db := NewGroundTruthDatabase()
	parser.processSymbolPointers(sec, make([]byte, 16), 8, machoFile, db)
	if len(db.GOTPLT) != 0 {
		t.Errorf("GOTPLT should be empty for zero-value pointers, got %d", len(db.GOTPLT))
	}
}

func TestProcessSymbolPointers_WithRelocations(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	sec := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x3000, Size: 16}}
	data := make([]byte, 16)
	binary.LittleEndian.PutUint64(data[0:8], 0x1000)
	binary.LittleEndian.PutUint64(data[8:16], 0x2000)
	db := NewGroundTruthDatabase()
	db.Relocations[Address(0x3000)] = &Relocation{Address: Address(0x3000), Symbol: "_func1", Type: RelocationTypeGOT}
	db.SymbolsByName["_func1"] = Address(0x8000)
	parser.processSymbolPointers(sec, data, 8, machoFile, db)
	if targetAddr, exists := db.GOTPLT[Address(0x3000)]; !exists || targetAddr != Address(0x8000) {
		t.Errorf("GOTPLT[0x3000] = %#x, want 0x8000", targetAddr)
	}
}

func TestProcessSymbolPointers_DataTooShort(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	sec := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x3000, Size: 24}}
	data := make([]byte, 12)
	binary.LittleEndian.PutUint64(data[0:8], 0x1000)
	db := NewGroundTruthDatabase()
	parser.processSymbolPointers(sec, data, 8, machoFile, db)
}

func TestProcessSymbolPointers_32bit(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.Cpu386}, ByteOrder: binary.LittleEndian}
	sec := &macho.Section{SectionHeader: macho.SectionHeader{Addr: 0x3000, Size: 8}}
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], 0x1000)
	binary.LittleEndian.PutUint32(data[4:8], 0x2000)
	db := NewGroundTruthDatabase()
	db.Relocations[Address(0x3000)] = &Relocation{Address: Address(0x3000), Symbol: "_func32", Type: RelocationTypeGOT}
	db.SymbolsByName["_func32"] = Address(0x5000)
	parser.processSymbolPointers(sec, data, 4, machoFile, db)
	if targetAddr, exists := db.GOTPLT[Address(0x3000)]; !exists || targetAddr != Address(0x5000) {
		t.Errorf("GOTPLT[0x3000] = %#x, want 0x5000", targetAddr)
	}
}

func TestExtractMachODynamicRelocations_NoDysymtab(t *testing.T) {
	parser := NewStandardLibParser()
	machoFile := &macho.File{FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64}, ByteOrder: binary.LittleEndian}
	relocs := parser.extractMachODynamicRelocations(machoFile, nil)
	if relocs == nil {
		t.Fatal("returned nil")
	}
}

func TestExtractMachODynamicRelocations_WithDysymtab(t *testing.T) {
	parser := NewStandardLibParser()
	extEntry := make([]byte, 8)
	binary.LittleEndian.PutUint32(extEntry[0:4], 0xA000)
	locEntry := make([]byte, 8)
	binary.LittleEndian.PutUint32(locEntry[0:4], 0xB000)
	data := make([]byte, 128)
	copy(data[64:72], extEntry)
	copy(data[80:88], locEntry)
	dysymtab := &macho.Dysymtab{DysymtabCmd: macho.DysymtabCmd{
		Nextrel: 1, Extreloff: 64, Nlocrel: 1, Locreloff: 80,
	}}
	machoFile := &macho.File{
		FileHeader: macho.FileHeader{Cpu: macho.CpuAmd64},
		ByteOrder:  binary.LittleEndian,
		Loads:      []macho.Load{dysymtab},
	}
	relocs := parser.extractMachODynamicRelocations(machoFile, data)
	if len(relocs) < 2 {
		t.Fatalf("len = %d, want >= 2", len(relocs))
	}
}

func TestGroundTruthDB_GOTPLTResolution(t *testing.T) {
	parser := NewStandardLibParser()
	info := &BinaryInfo{
		Format: BinaryFormatELF, GroundTruthDB: NewGroundTruthDatabase(),
		Relocations: []*Relocation{
			{Address: Address(0x601000), Symbol: "printf", Type: RelocationTypeJumpSlot},
			{Address: Address(0x601008), Symbol: "malloc", Type: RelocationTypeGOT},
			{Address: Address(0x601010), Symbol: "free", Type: RelocationTypePLT},
			{Address: Address(0x601018), Symbol: "exit", Type: RelocationTypeAbsolute},
		},
		Imports: []*Import{
			{Name: "printf", Address: Address(0x400100)},
			{Name: "malloc", Address: Address(0x400200)},
			{Name: "free", Address: Address(0x400300)},
		},
		Exports: []*Export{}, Symbols: []*Symbol{},
	}
	parser.buildGroundTruthDB(info)
	db := info.GroundTruthDB
	if _, exists := db.GOTPLT[Address(0x601000)]; !exists {
		t.Error("GOTPLT missing for JumpSlot (printf)")
	}
	if _, exists := db.GOTPLT[Address(0x601008)]; !exists {
		t.Error("GOTPLT missing for GOT (malloc)")
	}
	if _, exists := db.GOTPLT[Address(0x601010)]; !exists {
		t.Error("GOTPLT missing for PLT (free)")
	}
	if _, exists := db.GOTPLT[Address(0x601018)]; exists {
		t.Error("GOTPLT should not contain Absolute (exit)")
	}
}

func TestGroundTruthDB_ImportExportPrecedence(t *testing.T) {
	parser := NewStandardLibParser()
	info := &BinaryInfo{
		Format: BinaryFormatELF, GroundTruthDB: NewGroundTruthDatabase(),
		Relocations: []*Relocation{},
		Imports:     []*Import{{Name: "shared_sym", Address: Address(0x1000)}},
		Exports:     []*Export{{Name: "shared_sym", Address: Address(0x2000)}},
		Symbols:     []*Symbol{{Name: "shared_sym", Address: Address(0x3000)}},
	}
	parser.buildGroundTruthDB(info)
	if addr := info.GroundTruthDB.SymbolsByName["shared_sym"]; addr == Address(0x3000) {
		t.Error("Symbols should not override imports/exports")
	}
}

func TestErrorTypes_Messages(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"InvalidMagic", &InvalidMagicError{Magic: []byte{0xDE, 0xAD}}, "invalid magic number: 0xdead"},
		{"UnsupportedFormat", &UnsupportedFormatError{Format: "WASM"}, "unsupported binary format: WASM"},
		{"InvalidOffset", &InvalidOffsetError{Offset: 0x1234, Reason: "beyond section"}, "invalid offset 0x1234: beyond section"},
		{"TruncatedFile", &TruncatedFileError{Expected: 64, Actual: 10}, "truncated file: expected at least 64 bytes, got 10"},
		{"CorruptedSection", &CorruptedSectionError{Section: ".text", Reason: "invalid alignment"}, "corrupted section .text: invalid alignment"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}
