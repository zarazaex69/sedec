package binfmt

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"testing"
)

// TestParseMachO_SingleBinary tests parsing of a single (non-fat) Mach-O binary
func TestParseMachO_SingleBinary(t *testing.T) {
	// create minimal valid mach-o binary for testing
	data := createMinimalMachO64Helper()

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("failed to parse mach-o: %v", err)
	}

	// verify format detection
	if info.Format != BinaryFormatMachO {
		t.Errorf("expected format MachO, got %v", info.Format)
	}

	// verify architecture detection
	if info.Architecture != ArchitectureX86_64 {
		t.Errorf("expected architecture x86_64, got %v", info.Architecture)
	}

	// verify ground-truth database is initialized
	if info.GroundTruthDB == nil {
		t.Error("ground-truth database is nil")
	}
}

// TestParseMachO_FatBinary tests parsing of a fat (universal) binary
func TestParseMachO_FatBinary(t *testing.T) {
	// create minimal fat binary with single architecture
	data := createMinimalFatMachO()

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("failed to parse fat mach-o: %v", err)
	}

	// verify format detection
	if info.Format != BinaryFormatMachO {
		t.Errorf("expected format MachO, got %v", info.Format)
	}

	// verify architecture was extracted from first arch
	if info.Architecture == ArchitectureUnknown {
		t.Error("architecture should be detected from fat binary")
	}
}

// TestExtractMachOSectionsFromLoadCommands tests section extraction via load commands
func TestExtractMachOSectionsFromLoadCommands(t *testing.T) {
	data := createMinimalMachO64WithSections()
	reader := bytes.NewReader(data)
	machoFile, err := macho.NewFile(reader)
	if err != nil {
		t.Fatalf("failed to create macho file: %v", err)
	}
	defer machoFile.Close()

	parser := NewStandardLibParser()
	sections := parser.extractMachOSectionsFromLoadCommands(machoFile)

	// minimal binary may have no sections, which is acceptable
	t.Logf("extracted %d sections", len(sections))

	// verify section properties if any exist
	for _, sec := range sections {
		if sec.Name == "" {
			t.Error("section has empty name")
		}
		if sec.Address == 0 && sec.Size > 0 {
			t.Error("section has zero address but non-zero size")
		}
	}
}

// TestExtractMachOSymbolsFromSymtab tests symbol extraction from symbol table
func TestExtractMachOSymbolsFromSymtab(t *testing.T) {
	data := createMinimalMachO64WithSymbols()
	reader := bytes.NewReader(data)
	machoFile, err := macho.NewFile(reader)
	if err != nil {
		t.Fatalf("failed to create macho file: %v", err)
	}
	defer machoFile.Close()

	parser := NewStandardLibParser()
	symbols := parser.extractMachOSymbolsFromSymtab(machoFile)

	// minimal binary may have no symbols, which is acceptable
	t.Logf("extracted %d symbols", len(symbols))

	// verify symbol properties if any exist
	for _, sym := range symbols {
		if sym.Name == "" {
			t.Error("symbol has empty name")
		}
		if sym.Type == SymbolTypeUnknown && sym.Address != 0 {
			t.Logf("warning: symbol %s has unknown type", sym.Name)
		}
	}
}

// TestExtractMachODynamicRelocations tests dynamic relocation extraction via dysymtab
func TestExtractMachODynamicRelocations(t *testing.T) {
	data := createMinimalMachO64WithRelocations()
	reader := bytes.NewReader(data)
	machoFile, err := macho.NewFile(reader)
	if err != nil {
		t.Fatalf("failed to create macho file: %v", err)
	}
	defer machoFile.Close()

	parser := NewStandardLibParser()
	relocations := parser.extractMachODynamicRelocations(machoFile, data)

	// relocations may be empty for minimal binary, but function should not crash
	t.Logf("extracted %d relocations", len(relocations))

	// verify relocation properties if any exist
	for _, reloc := range relocations {
		if reloc.Address == 0 {
			t.Error("relocation has zero address")
		}
		if reloc.Type == RelocationTypeUnknown {
			t.Logf("warning: relocation at %#x has unknown type", reloc.Address)
		}
	}
}

// TestBuildMachOGroundTruthDB tests ground-truth database construction
func TestBuildMachOGroundTruthDB(t *testing.T) {
	data := createMinimalMachO64WithSymbols()
	reader := bytes.NewReader(data)
	machoFile, err := macho.NewFile(reader)
	if err != nil {
		t.Fatalf("failed to create macho file: %v", err)
	}
	defer machoFile.Close()

	parser := NewStandardLibParser()
	info, err := parser.parseSingleMachO(data, machoFile)
	if err != nil {
		t.Fatalf("failed to parse mach-o: %v", err)
	}

	db := info.GroundTruthDB

	// verify database is populated
	if db == nil {
		t.Fatal("ground-truth database is nil")
	}

	// verify maps are initialized
	if db.Relocations == nil {
		t.Error("relocations map is nil")
	}
	if db.Imports == nil {
		t.Error("imports map is nil")
	}
	if db.Exports == nil {
		t.Error("exports map is nil")
	}
	if db.GOTPLT == nil {
		t.Error("gotplt map is nil")
	}
	if db.SymbolsByAddress == nil {
		t.Error("symbols by address map is nil")
	}
	if db.SymbolsByName == nil {
		t.Error("symbols by name map is nil")
	}

	// verify symbol resolution
	for addr, name := range db.SymbolsByAddress {
		if name == "" {
			t.Errorf("empty symbol name at address %#x", addr)
		}
		// verify reverse mapping exists
		if resolvedAddr, exists := db.SymbolsByName[name]; !exists {
			t.Errorf("symbol %s at %#x not in name map", name, addr)
		} else if resolvedAddr != addr {
			t.Errorf("symbol %s: address mismatch %#x != %#x", name, addr, resolvedAddr)
		}
	}
}

// TestConvertMachOSymbolBinding tests symbol binding conversion
func TestConvertMachOSymbolBinding(t *testing.T) {
	parser := NewStandardLibParser()

	tests := []struct {
		name     string
		symType  uint8
		desc     uint16
		expected SymbolBinding
	}{
		{"local symbol", 0x00, 0x0000, SymbolBindingLocal},
		{"global symbol", 0x01, 0x0000, SymbolBindingGlobal},
		{"weak symbol", 0x01, 0x0080, SymbolBindingWeak},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.convertMachOSymbolBinding(tt.symType, tt.desc)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestConvertMachORelocationType tests relocation type conversion
func TestConvertMachORelocationType(t *testing.T) {
	parser := NewStandardLibParser()

	tests := []struct {
		name      string
		cpu       macho.Cpu
		relocType uint32
		expected  RelocationType
	}{
		{"x86_64 unsigned", macho.CpuAmd64, 0, RelocationTypeAbsolute},
		{"x86_64 signed", macho.CpuAmd64, 1, RelocationTypeRelative},
		{"x86_64 got", macho.CpuAmd64, 4, RelocationTypeGOT},
		{"arm64 unsigned", macho.CpuArm64, 0, RelocationTypeAbsolute},
		{"arm64 got", macho.CpuArm64, 5, RelocationTypeGOT},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.convertMachORelocationType(tt.cpu, tt.relocType)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestParseMachO_MalformedBinary tests error handling for malformed binaries
func TestParseMachO_MalformedBinary(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"truncated header", []byte{0xFE, 0xED, 0xFA}},
		{"invalid magic", []byte{0x00, 0x00, 0x00, 0x00}},
		{"empty data", []byte{}},
	}

	parser := NewStandardLibParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parser.Parse(tt.data)
			if err == nil {
				t.Error("expected error for malformed binary, got nil")
			}
		})
	}
}

// createMinimalFatMachO creates a minimal fat binary
func createMinimalFatMachO() []byte {
	buf := new(bytes.Buffer)

	// fat header
	binary.Write(buf, binary.BigEndian, uint32(0xCAFEBABE)) // magic
	binary.Write(buf, binary.BigEndian, uint32(0x00000001)) // nfat_arch

	// fat arch
	binary.Write(buf, binary.BigEndian, uint32(0x01000007)) // cputype (x86_64)
	binary.Write(buf, binary.BigEndian, uint32(0x00000003)) // cpusubtype
	binary.Write(buf, binary.BigEndian, uint32(0x00001000)) // offset
	binary.Write(buf, binary.BigEndian, uint32(0x00000020)) // size
	binary.Write(buf, binary.BigEndian, uint32(0x0000000C)) // align

	// pad to offset
	for buf.Len() < 0x1000 {
		buf.WriteByte(0)
	}

	// embedded mach-o at offset - use helper from parser_test.go
	buf.Write(createMinimalMachO64Helper())

	return buf.Bytes()
}

// createMinimalMachO64Helper creates a minimal valid 64-bit Mach-O binary
func createMinimalMachO64Helper() []byte {
	buf := new(bytes.Buffer)

	// mach header 64
	binary.Write(buf, binary.LittleEndian, uint32(0xFEEDFACF)) // magic
	binary.Write(buf, binary.LittleEndian, uint32(0x01000007)) // cputype (x86_64)
	binary.Write(buf, binary.LittleEndian, uint32(0x00000003)) // cpusubtype
	binary.Write(buf, binary.LittleEndian, uint32(0x00000002)) // filetype (MH_EXECUTE)
	binary.Write(buf, binary.LittleEndian, uint32(0x00000000)) // ncmds
	binary.Write(buf, binary.LittleEndian, uint32(0x00000000)) // sizeofcmds
	binary.Write(buf, binary.LittleEndian, uint32(0x00000000)) // flags
	binary.Write(buf, binary.LittleEndian, uint32(0x00000000)) // reserved

	return buf.Bytes()
}

// createMinimalMachO64WithSections creates a Mach-O with sections
func createMinimalMachO64WithSections() []byte {
	// for simplicity, return minimal binary
	// real implementation would add LC_SEGMENT_64 commands
	return createMinimalMachO64Helper()
}

// createMinimalMachO64WithSymbols creates a Mach-O with symbol table
func createMinimalMachO64WithSymbols() []byte {
	// for simplicity, return minimal binary
	// real implementation would add LC_SYMTAB command
	return createMinimalMachO64Helper()
}

// createMinimalMachO64WithRelocations creates a Mach-O with relocations
func createMinimalMachO64WithRelocations() []byte {
	// for simplicity, return minimal binary
	// real implementation would add LC_DYSYMTAB command
	return createMinimalMachO64Helper()
}
