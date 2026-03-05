package binfmt

import (
	"debug/pe"
	"encoding/binary"
	"testing"
)

// TestDetectPEArchitecture verifies architecture detection from PE machine type
func TestDetectPEArchitecture(t *testing.T) {
	tests := []struct {
		name     string
		machine  uint16
		expected Architecture
	}{
		{
			name:     "x86_64",
			machine:  pe.IMAGE_FILE_MACHINE_AMD64,
			expected: ArchitectureX86_64,
		},
		{
			name:     "x86",
			machine:  pe.IMAGE_FILE_MACHINE_I386,
			expected: ArchitectureX86,
		},
		{
			name:     "arm64",
			machine:  pe.IMAGE_FILE_MACHINE_ARM64,
			expected: ArchitectureARM64,
		},
		{
			name:     "arm",
			machine:  pe.IMAGE_FILE_MACHINE_ARM,
			expected: ArchitectureARM,
		},
		{
			name:     "unknown",
			machine:  0xFFFF,
			expected: ArchitectureUnknown,
		},
	}

	parser := NewStandardLibParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// create minimal pe file structure
			peFile := &pe.File{
				FileHeader: pe.FileHeader{
					Machine: tt.machine,
				},
			}

			arch := parser.detectPEArchitecture(peFile)
			if arch != tt.expected {
				t.Errorf("detectPEArchitecture() = %v, want %v", arch, tt.expected)
			}
		})
	}
}

// TestExtractPESections verifies section extraction from PE file
func TestExtractPESections(t *testing.T) {
	parser := NewStandardLibParser()

	// create pe file with test sections
	peFile := &pe.File{
		Sections: []*pe.Section{
			{
				SectionHeader: pe.SectionHeader{
					Name:            ".text",
					VirtualAddress:  0x1000,
					VirtualSize:     0x2000,
					Offset:          0x400,
					Characteristics: pe.IMAGE_SCN_CNT_CODE | pe.IMAGE_SCN_MEM_EXECUTE | pe.IMAGE_SCN_MEM_READ,
				},
			},
			{
				SectionHeader: pe.SectionHeader{
					Name:            ".data",
					VirtualAddress:  0x3000,
					VirtualSize:     0x1000,
					Offset:          0x2400,
					Characteristics: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE,
				},
			},
			{
				SectionHeader: pe.SectionHeader{
					Name:            ".rdata",
					VirtualAddress:  0x4000,
					VirtualSize:     0x800,
					Offset:          0x3400,
					Characteristics: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ,
				},
			},
		},
	}

	sections := parser.extractPESections(peFile)

	if len(sections) != 3 {
		t.Fatalf("expected 3 sections, got %d", len(sections))
	}

	// verify .text section
	if sections[0].Name != ".text" {
		t.Errorf("section[0].Name = %s, want .text", sections[0].Name)
	}
	if sections[0].Address != 0x1000 {
		t.Errorf("section[0].Address = %#x, want 0x1000", sections[0].Address)
	}
	if !sections[0].IsExecutable {
		t.Error("section[0] should be executable")
	}
	if sections[0].IsWritable {
		t.Error("section[0] should not be writable")
	}

	// verify .data section
	if sections[1].Name != ".data" {
		t.Errorf("section[1].Name = %s, want .data", sections[1].Name)
	}
	if !sections[1].IsWritable {
		t.Error("section[1] should be writable")
	}

	// verify .rdata section
	if sections[2].Name != ".rdata" {
		t.Errorf("section[2].Name = %s, want .rdata", sections[2].Name)
	}
	if sections[2].IsWritable {
		t.Error("section[2] should not be writable")
	}
}

// TestExtractPESymbols verifies symbol extraction from COFF symbol table
func TestExtractPESymbols(t *testing.T) {
	parser := NewStandardLibParser()

	// create pe file with test symbols
	peFile := &pe.File{
		Symbols: []*pe.Symbol{
			{
				Name:          "main",
				Value:         0x1000,
				SectionNumber: 1,
				StorageClass:  2, // IMAGE_SYM_CLASS_EXTERNAL
			},
			{
				Name:          "data_var",
				Value:         0x3000,
				SectionNumber: 2,
				StorageClass:  3, // IMAGE_SYM_CLASS_STATIC
			},
		},
		Sections: []*pe.Section{
			{
				SectionHeader: pe.SectionHeader{
					Name: ".text",
				},
			},
			{
				SectionHeader: pe.SectionHeader{
					Name: ".data",
				},
			},
		},
	}

	symbols := parser.extractPESymbols(peFile)

	if len(symbols) != 2 {
		t.Fatalf("expected 2 symbols, got %d", len(symbols))
	}

	// verify main symbol
	if symbols[0].Name != "main" {
		t.Errorf("symbols[0].Name = %s, want main", symbols[0].Name)
	}
	if symbols[0].Address != 0x1000 {
		t.Errorf("symbols[0].Address = %#x, want 0x1000", symbols[0].Address)
	}
	if symbols[0].Type != SymbolTypeFunction {
		t.Errorf("symbols[0].Type = %v, want SymbolTypeFunction", symbols[0].Type)
	}
	if symbols[0].Section != ".text" {
		t.Errorf("symbols[0].Section = %s, want .text", symbols[0].Section)
	}

	// verify data_var symbol
	if symbols[1].Name != "data_var" {
		t.Errorf("symbols[1].Name = %s, want data_var", symbols[1].Name)
	}
	if symbols[1].Type != SymbolTypeObject {
		t.Errorf("symbols[1].Type = %v, want SymbolTypeObject", symbols[1].Type)
	}
}

// TestConvertPESymbolType verifies PE storage class to symbol type conversion
func TestConvertPESymbolType(t *testing.T) {
	tests := []struct {
		name         string
		storageClass uint8
		expected     SymbolType
	}{
		{"external", 2, SymbolTypeFunction},
		{"static", 3, SymbolTypeObject},
		{"section", 103, SymbolTypeSection},
		{"file", 104, SymbolTypeFile},
		{"unknown", 255, SymbolTypeUnknown},
	}

	parser := NewStandardLibParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.convertPESymbolType(tt.storageClass)
			if result != tt.expected {
				t.Errorf("convertPESymbolType(%d) = %v, want %v", tt.storageClass, result, tt.expected)
			}
		})
	}
}

// TestParsePERelocationData verifies base relocation parsing from raw data
func TestParsePERelocationData(t *testing.T) {
	parser := NewStandardLibParser()

	// create relocation data
	// block 1: page rva = 0x1000, block size = 16 (header 8 + 4 entries * 2)
	relocData := make([]byte, 32)
	binary.LittleEndian.PutUint32(relocData[0:4], 0x1000)   // page rva
	binary.LittleEndian.PutUint32(relocData[4:8], 16)       // block size
	binary.LittleEndian.PutUint16(relocData[8:10], 0x3010)  // type 3 (highlow), offset 0x010
	binary.LittleEndian.PutUint16(relocData[10:12], 0x3020) // type 3 (highlow), offset 0x020
	binary.LittleEndian.PutUint16(relocData[12:14], 0xA030) // type 10 (dir64), offset 0x030
	binary.LittleEndian.PutUint16(relocData[14:16], 0x0040) // type 0 (padding), offset 0x040

	// block 2: page rva = 0x2000, block size = 12 (header 8 + 2 entries * 2)
	binary.LittleEndian.PutUint32(relocData[16:20], 0x2000) // page rva
	binary.LittleEndian.PutUint32(relocData[20:24], 12)     // block size
	binary.LittleEndian.PutUint16(relocData[24:26], 0x3100) // type 3 (highlow), offset 0x100
	binary.LittleEndian.PutUint16(relocData[26:28], 0xA200) // type 10 (dir64), offset 0x200

	relocations := parser.parsePERelocationData(relocData)

	// should extract 5 relocations (3 from block 1, 2 from block 2)
	// type 0 (padding) should be skipped
	if len(relocations) != 5 {
		t.Fatalf("expected 5 relocations, got %d", len(relocations))
	}

	// verify relocation addresses
	expectedAddrs := []Address{0x1010, 0x1020, 0x1030, 0x2100, 0x2200}
	for i, expected := range expectedAddrs {
		if relocations[i].Address != expected {
			t.Errorf("relocations[%d].Address = %#x, want %#x", i, relocations[i].Address, expected)
		}
		if relocations[i].Type != RelocationTypeAbsolute {
			t.Errorf("relocations[%d].Type = %v, want RelocationTypeAbsolute", i, relocations[i].Type)
		}
	}
}

// TestParsePEExportDirectory verifies export directory parsing
func TestParsePEExportDirectory(t *testing.T) {
	parser := NewStandardLibParser()

	// create export directory data (40 bytes)
	data := make([]byte, 40)
	binary.LittleEndian.PutUint32(data[20:24], 10)     // number of functions
	binary.LittleEndian.PutUint32(data[24:28], 8)      // number of names
	binary.LittleEndian.PutUint32(data[28:32], 0x5000) // address of functions
	binary.LittleEndian.PutUint32(data[32:36], 0x5100) // address of names
	binary.LittleEndian.PutUint32(data[36:40], 0x5200) // address of name ordinals

	exportDir := parser.parsePEExportDirectory(data)

	if exportDir.numberOfFunctions != 10 {
		t.Errorf("numberOfFunctions = %d, want 10", exportDir.numberOfFunctions)
	}
	if exportDir.numberOfNames != 8 {
		t.Errorf("numberOfNames = %d, want 8", exportDir.numberOfNames)
	}
	if exportDir.addressOfFunctions != 0x5000 {
		t.Errorf("addressOfFunctions = %#x, want 0x5000", exportDir.addressOfFunctions)
	}
	if exportDir.addressOfNames != 0x5100 {
		t.Errorf("addressOfNames = %#x, want 0x5100", exportDir.addressOfNames)
	}
	if exportDir.addressOfNameOrdinals != 0x5200 {
		t.Errorf("addressOfNameOrdinals = %#x, want 0x5200", exportDir.addressOfNameOrdinals)
	}
}

// TestGetPEExportDirectory verifies export directory RVA extraction
func TestGetPEExportDirectory(t *testing.T) {
	parser := NewStandardLibParser()

	tests := []struct {
		optHeader    interface{}
		name         string
		expectedRVA  uint32
		expectedSize uint32
	}{
		{
			name: "pe32",
			optHeader: &pe.OptionalHeader32{
				DataDirectory: [16]pe.DataDirectory{
					{VirtualAddress: 0x3000, Size: 0x100},
				},
			},
			expectedRVA:  0x3000,
			expectedSize: 0x100,
		},
		{
			name: "pe64",
			optHeader: &pe.OptionalHeader64{
				DataDirectory: [16]pe.DataDirectory{
					{VirtualAddress: 0x4000, Size: 0x200},
				},
			},
			expectedRVA:  0x4000,
			expectedSize: 0x200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peFile := &pe.File{
				OptionalHeader: tt.optHeader,
			}

			rva, size := parser.getPEExportDirectory(peFile)
			if rva != tt.expectedRVA {
				t.Errorf("rva = %#x, want %#x", rva, tt.expectedRVA)
			}
			if size != tt.expectedSize {
				t.Errorf("size = %#x, want %#x", size, tt.expectedSize)
			}
		})
	}
}

// TestParsePE_Integration verifies full PE parsing integration
func TestParsePE_Integration(t *testing.T) {
	// create minimal valid pe binary
	peData := createMinimalPEBinary(t)

	parser := NewStandardLibParser()
	info, err := parser.Parse(peData)

	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if info.Format != BinaryFormatPE {
		t.Errorf("Format = %v, want BinaryFormatPE", info.Format)
	}

	if info.Architecture != ArchitectureX86_64 {
		t.Errorf("Architecture = %v, want ArchitectureX86_64", info.Architecture)
	}

	if info.GroundTruthDB == nil {
		t.Fatal("GroundTruthDB is nil")
	}

	// verify ground truth database is initialized
	if info.GroundTruthDB.Relocations == nil {
		t.Error("GroundTruthDB.Relocations is nil")
	}
	if info.GroundTruthDB.Imports == nil {
		t.Error("GroundTruthDB.Imports is nil")
	}
	if info.GroundTruthDB.Exports == nil {
		t.Error("GroundTruthDB.Exports is nil")
	}
}

// createMinimalPEBinary creates a minimal valid PE binary for testing
func createMinimalPEBinary(t *testing.T) []byte {
	t.Helper()

	// preallocate with exact size
	const totalSize = 64 + 4 + 20 + 240 + 40 + (0x400 - 368) + 0x200
	result := make([]byte, 0, totalSize)

	// dos header (64 bytes)
	dosHeader := make([]byte, 64)
	dosHeader[0] = 'M' // pe magic
	dosHeader[1] = 'Z'
	binary.LittleEndian.PutUint32(dosHeader[60:64], 64) // e_lfanew (pe header offset)
	result = append(result, dosHeader...)

	// pe signature (4 bytes)
	peSignature := []byte{'P', 'E', 0, 0}
	result = append(result, peSignature...)

	// coff header (20 bytes)
	coffHeader := make([]byte, 20)
	binary.LittleEndian.PutUint16(coffHeader[0:2], pe.IMAGE_FILE_MACHINE_AMD64) // machine
	binary.LittleEndian.PutUint16(coffHeader[2:4], 1)                           // number of sections
	binary.LittleEndian.PutUint16(coffHeader[16:18], 240)                       // size of optional header
	result = append(result, coffHeader...)

	// optional header (240 bytes for pe64)
	optHeader := make([]byte, 240)
	binary.LittleEndian.PutUint16(optHeader[0:2], 0x20b)      // magic (pe32+)
	binary.LittleEndian.PutUint32(optHeader[16:20], 0x1000)   // address of entry point
	binary.LittleEndian.PutUint64(optHeader[24:32], 0x400000) // image base
	binary.LittleEndian.PutUint32(optHeader[32:36], 0x1000)   // section alignment
	binary.LittleEndian.PutUint32(optHeader[36:40], 0x200)    // file alignment
	binary.LittleEndian.PutUint32(optHeader[56:60], 0x2000)   // size of image
	binary.LittleEndian.PutUint32(optHeader[60:64], 0x400)    // size of headers
	binary.LittleEndian.PutUint16(optHeader[68:70], 3)        // subsystem (console)
	binary.LittleEndian.PutUint32(optHeader[108:112], 16)     // number of rva and sizes
	result = append(result, optHeader...)

	// section header (40 bytes)
	sectionHeader := make([]byte, 40)
	copy(sectionHeader[0:6], ".text\x00")
	binary.LittleEndian.PutUint32(sectionHeader[8:12], 0x100)   // virtual size
	binary.LittleEndian.PutUint32(sectionHeader[12:16], 0x1000) // virtual address
	binary.LittleEndian.PutUint32(sectionHeader[16:20], 0x200)  // size of raw data
	binary.LittleEndian.PutUint32(sectionHeader[20:24], 0x400)  // pointer to raw data
	binary.LittleEndian.PutUint32(sectionHeader[36:40], pe.IMAGE_SCN_CNT_CODE|pe.IMAGE_SCN_MEM_EXECUTE|pe.IMAGE_SCN_MEM_READ)
	result = append(result, sectionHeader...)

	// add padding to reach section data offset
	padding := make([]byte, 0x400-len(result))
	result = append(result, padding...)

	// add section data (512 bytes of zeros)
	sectionData := make([]byte, 0x200)
	result = append(result, sectionData...)

	return result
}

// BenchmarkParsePE benchmarks PE parsing performance
func BenchmarkParsePE(b *testing.B) {
	peData := createMinimalPEBinary(&testing.T{})
	parser := NewStandardLibParser()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parser.Parse(peData)
		if err != nil {
			b.Fatalf("Parse() error = %v", err)
		}
	}
}
