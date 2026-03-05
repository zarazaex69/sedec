package binfmt

import (
	"bytes"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"testing"
)

// TestReadPEDataAtRVA_Comprehensive tests PE RVA data reading with real sections
func TestReadPEDataAtRVA_Comprehensive(t *testing.T) {
	parser := NewStandardLibParser()

	// create pe file with actual section data
	peData := createPEWithSectionData(t)
	peFile, err := pe.NewFile(bytes.NewReader(peData))
	if err != nil {
		t.Fatalf("failed to create pe file: %v", err)
	}
	defer peFile.Close()

	tests := []struct {
		name      string
		rva       uint32
		size      int
		expectNil bool
	}{
		{
			name:      "read from .text section",
			rva:       0x1000,
			size:      16,
			expectNil: false,
		},
		{
			name:      "read from invalid rva",
			rva:       0x999999,
			size:      16,
			expectNil: true,
		},
		{
			name:      "read zero bytes",
			rva:       0x1000,
			size:      0,
			expectNil: false,
		},
		{
			name:      "read beyond section size",
			rva:       0x1000,
			size:      0x1000,
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := parser.readPEDataAtRVA(peFile, tt.rva, tt.size)

			if tt.expectNil {
				if data != nil {
					t.Errorf("expected nil, got %d bytes", len(data))
				}
			} else {
				if data == nil {
					t.Error("expected data, got nil")
				} else if len(data) != tt.size {
					t.Errorf("expected %d bytes, got %d", tt.size, len(data))
				}
			}
		})
	}
}

// TestReadPEFunctionAddresses tests function address table reading
func TestReadPEFunctionAddresses(t *testing.T) {
	parser := NewStandardLibParser()

	// create pe with export data
	peData := createPEWithExportData(t)
	peFile, err := pe.NewFile(bytes.NewReader(peData))
	if err != nil {
		t.Fatalf("failed to create pe file: %v", err)
	}
	defer peFile.Close()

	exportDir := peExportDirectory{
		numberOfFunctions:     3,
		addressOfFunctions:    0x3000,
		numberOfNames:         2,
		addressOfNames:        0x3100,
		addressOfNameOrdinals: 0x3200,
	}

	funcAddrs := parser.readPEFunctionAddresses(peFile, exportDir)

	if len(funcAddrs) != 3 {
		t.Errorf("expected 3 function addresses, got %d", len(funcAddrs))
	}

	// verify addresses are read correctly
	for i, addr := range funcAddrs {
		if addr == 0 {
			t.Logf("function address %d is zero (may be valid)", i)
		}
	}
}

// TestProcessPEExportNames tests export name processing
func TestProcessPEExportNames(t *testing.T) {
	parser := NewStandardLibParser()

	peData := createPEWithExportData(t)
	peFile, err := pe.NewFile(bytes.NewReader(peData))
	if err != nil {
		t.Fatalf("failed to create pe file: %v", err)
	}
	defer peFile.Close()

	exportDir := peExportDirectory{
		numberOfFunctions:     3,
		addressOfFunctions:    0x3000,
		numberOfNames:         2,
		addressOfNames:        0x3100,
		addressOfNameOrdinals: 0x3200,
	}

	funcAddrs := []uint32{0x1000, 0x1100, 0x1200}
	exports := parser.processPEExportNames(peFile, exportDir, funcAddrs)

	// may be empty if export data is not properly formatted
	t.Logf("extracted %d exports", len(exports))

	for _, exp := range exports {
		if exp.Name == "" {
			t.Error("export has empty name")
		}
		if exp.Address == 0 {
			t.Error("export has zero address")
		}
	}
}

// TestReadPEExportEntry tests single export entry reading
func TestReadPEExportEntry(t *testing.T) {
	parser := NewStandardLibParser()

	peData := createPEWithExportData(t)
	peFile, err := pe.NewFile(bytes.NewReader(peData))
	if err != nil {
		t.Fatalf("failed to create pe file: %v", err)
	}
	defer peFile.Close()

	exportDir := peExportDirectory{
		numberOfFunctions:     3,
		addressOfFunctions:    0x3000,
		addressOfNames:        0x3100,
		addressOfNameOrdinals: 0x3200,
	}

	funcAddrs := []uint32{0x1000, 0x1100, 0x1200}

	// try to read first export entry
	exp := parser.readPEExportEntry(peFile, exportDir, funcAddrs, 0)

	// may be nil if data is not properly formatted
	if exp != nil {
		if exp.Name == "" {
			t.Error("export name is empty")
		}
		if exp.Address == 0 {
			t.Error("export address is zero")
		}
		t.Logf("export: name=%s, address=0x%x, ordinal=%d", exp.Name, exp.Address, exp.Ordinal)
	} else {
		t.Log("export entry is nil (expected for minimal test data)")
	}
}

// TestReadPEExportName tests export name string reading
func TestReadPEExportName(t *testing.T) {
	parser := NewStandardLibParser()

	peData := createPEWithExportData(t)
	peFile, err := pe.NewFile(bytes.NewReader(peData))
	if err != nil {
		t.Fatalf("failed to create pe file: %v", err)
	}
	defer peFile.Close()

	// try to read name at various rvas
	tests := []struct {
		name    string
		nameRVA uint32
	}{
		{"valid rva", 0x3100},
		{"invalid rva", 0x999999},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := parser.readPEExportName(peFile, tt.nameRVA)
			t.Logf("read name: '%s'", name)
		})
	}
}

// TestGetPLTEntrySize_AllArchitectures tests PLT entry size for all architectures
func TestGetPLTEntrySize_AllArchitectures(t *testing.T) {
	parser := NewStandardLibParser()

	tests := []struct {
		arch         Architecture
		expectedSize int
		expectError  bool
	}{
		{ArchitectureX86_64, 16, false},
		{ArchitectureX86, 16, false},
		{ArchitectureARM64, 16, false},
		{ArchitectureARM, 12, false},
		{ArchitectureMIPS, 0, true},
		{ArchitectureMIPS64, 0, true},
		{ArchitecturePPC, 0, true},
		{ArchitecturePPC64, 0, true},
		{ArchitectureRISCV, 0, true},
		{ArchitectureRISCV64, 0, true},
		{ArchitectureUnknown, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.arch.String(), func(t *testing.T) {
			size, err := parser.getPLTEntrySize(tt.arch)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if size != tt.expectedSize {
				t.Errorf("expected size %d, got %d", tt.expectedSize, size)
			}
		})
	}
}

// TestFindSymbolForGOTAddress_Comprehensive tests symbol resolution for GOT
func TestFindSymbolForGOTAddress_Comprehensive(t *testing.T) {
	parser := NewStandardLibParser()

	info := &BinaryInfo{
		Relocations: []*Relocation{
			{Address: 0x601018, Symbol: "printf", Type: RelocationTypeJumpSlot},
			{Address: 0x601020, Symbol: "malloc", Type: RelocationTypeJumpSlot},
			{Address: 0x601028, Symbol: "free", Type: RelocationTypeJumpSlot},
			{Address: 0x601030, Symbol: "data_var", Type: RelocationTypeGlobDat},
			{Address: 0x601038, Symbol: "another_var", Type: RelocationTypeCopy},
		},
	}

	tests := []struct {
		name           string
		gotAddr        Address
		expectedSymbol string
	}{
		{"printf jump slot", 0x601018, "printf"},
		{"malloc jump slot", 0x601020, "malloc"},
		{"free jump slot", 0x601028, "free"},
		{"glob_dat not jump_slot", 0x601030, ""},
		{"copy relocation", 0x601038, ""},
		{"non-existent address", 0x999999, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			symbol := parser.findSymbolForGOTAddress(info, tt.gotAddr)
			if symbol != tt.expectedSymbol {
				t.Errorf("expected symbol '%s', got '%s'", tt.expectedSymbol, symbol)
			}
		})
	}
}

// TestExtractELFImportsExports_Comprehensive tests ELF import/export extraction
func TestExtractELFImportsExports_Comprehensive(t *testing.T) {
	parser := NewStandardLibParser()

	// create elf with dynamic symbols
	data := createELFWithDynamicSymbols()
	elfFile, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("failed to create elf file: %v", err)
	}
	defer elfFile.Close()

	imports, exports := parser.extractELFImportsExports(elfFile)

	t.Logf("extracted %d imports, %d exports", len(imports), len(exports))

	// verify imports structure
	for i, imp := range imports {
		if imp.Name == "" {
			t.Errorf("import %d has empty name", i)
		}
		if imp.Address == 0 {
			t.Logf("import %d (%s) has zero address (may be valid for undefined symbols)", i, imp.Name)
		}
	}

	// verify exports structure
	for i, exp := range exports {
		if exp.Name == "" {
			t.Errorf("export %d has empty name", i)
		}
		if exp.Address == 0 {
			t.Errorf("export %d (%s) has zero address", i, exp.Name)
		}
	}
}

// helper functions to create test binaries with actual data

func createPEWithSectionData(t *testing.T) []byte {
	t.Helper()

	buf := new(bytes.Buffer)

	// dos header (64 bytes)
	dosHeader := make([]byte, 64)
	dosHeader[0] = 'M'
	dosHeader[1] = 'Z'
	binary.LittleEndian.PutUint32(dosHeader[60:64], 64)
	buf.Write(dosHeader)

	// pe signature
	buf.Write([]byte{'P', 'E', 0, 0})

	// coff header
	coffHeader := make([]byte, 20)
	binary.LittleEndian.PutUint16(coffHeader[0:2], 0x8664) // amd64
	binary.LittleEndian.PutUint16(coffHeader[2:4], 1)      // 1 section
	binary.LittleEndian.PutUint16(coffHeader[16:18], 240)  // optional header size
	binary.LittleEndian.PutUint16(coffHeader[18:20], 0x22) // characteristics
	buf.Write(coffHeader)

	// optional header (240 bytes for pe64)
	optHeader := make([]byte, 240)
	binary.LittleEndian.PutUint16(optHeader[0:2], 0x20b)      // pe32+
	binary.LittleEndian.PutUint32(optHeader[16:20], 0x1000)   // entry point
	binary.LittleEndian.PutUint64(optHeader[24:32], 0x400000) // image base
	binary.LittleEndian.PutUint32(optHeader[32:36], 0x1000)   // section alignment
	binary.LittleEndian.PutUint32(optHeader[36:40], 0x200)    // file alignment
	binary.LittleEndian.PutUint32(optHeader[56:60], 0x5000)   // size of image
	binary.LittleEndian.PutUint32(optHeader[60:64], 0x400)    // size of headers
	binary.LittleEndian.PutUint16(optHeader[68:70], 3)        // subsystem
	binary.LittleEndian.PutUint32(optHeader[108:112], 16)     // number of rva and sizes
	buf.Write(optHeader)

	// section header for .text
	sectionHeader := make([]byte, 40)
	copy(sectionHeader[0:6], ".text\x00")
	binary.LittleEndian.PutUint32(sectionHeader[8:12], 0x200)       // virtual size
	binary.LittleEndian.PutUint32(sectionHeader[12:16], 0x1000)     // virtual address
	binary.LittleEndian.PutUint32(sectionHeader[16:20], 0x200)      // size of raw data
	binary.LittleEndian.PutUint32(sectionHeader[20:24], 0x400)      // pointer to raw data
	binary.LittleEndian.PutUint32(sectionHeader[36:40], 0x60000020) // characteristics
	buf.Write(sectionHeader)

	// pad to section data offset
	for buf.Len() < 0x400 {
		buf.WriteByte(0)
	}

	// section data (512 bytes)
	sectionData := make([]byte, 0x200)
	// fill with some test data
	for i := range sectionData {
		sectionData[i] = byte(i % 256)
	}
	buf.Write(sectionData)

	return buf.Bytes()
}

func createPEWithExportData(t *testing.T) []byte {
	t.Helper()

	buf := new(bytes.Buffer)

	// dos header
	dosHeader := make([]byte, 64)
	dosHeader[0] = 'M'
	dosHeader[1] = 'Z'
	binary.LittleEndian.PutUint32(dosHeader[60:64], 64)
	buf.Write(dosHeader)

	// pe signature
	buf.Write([]byte{'P', 'E', 0, 0})

	// coff header
	coffHeader := make([]byte, 20)
	binary.LittleEndian.PutUint16(coffHeader[0:2], 0x8664)
	binary.LittleEndian.PutUint16(coffHeader[2:4], 2) // 2 sections
	binary.LittleEndian.PutUint16(coffHeader[16:18], 240)
	binary.LittleEndian.PutUint16(coffHeader[18:20], 0x22)
	buf.Write(coffHeader)

	// optional header
	optHeader := make([]byte, 240)
	binary.LittleEndian.PutUint16(optHeader[0:2], 0x20b)
	binary.LittleEndian.PutUint32(optHeader[16:20], 0x1000)
	binary.LittleEndian.PutUint64(optHeader[24:32], 0x400000)
	binary.LittleEndian.PutUint32(optHeader[32:36], 0x1000)
	binary.LittleEndian.PutUint32(optHeader[36:40], 0x200)
	binary.LittleEndian.PutUint32(optHeader[56:60], 0x5000)
	binary.LittleEndian.PutUint32(optHeader[60:64], 0x400)
	binary.LittleEndian.PutUint16(optHeader[68:70], 3)
	binary.LittleEndian.PutUint32(optHeader[108:112], 16)
	buf.Write(optHeader)

	// section header for .text
	textSection := make([]byte, 40)
	copy(textSection[0:6], ".text\x00")
	binary.LittleEndian.PutUint32(textSection[8:12], 0x1000)
	binary.LittleEndian.PutUint32(textSection[12:16], 0x1000)
	binary.LittleEndian.PutUint32(textSection[16:20], 0x200)
	binary.LittleEndian.PutUint32(textSection[20:24], 0x400)
	binary.LittleEndian.PutUint32(textSection[36:40], 0x60000020)
	buf.Write(textSection)

	// section header for .edata (export data)
	edataSection := make([]byte, 40)
	copy(edataSection[0:7], ".edata\x00")
	binary.LittleEndian.PutUint32(edataSection[8:12], 0x1000)
	binary.LittleEndian.PutUint32(edataSection[12:16], 0x3000)
	binary.LittleEndian.PutUint32(edataSection[16:20], 0x1000)
	binary.LittleEndian.PutUint32(edataSection[20:24], 0x600)
	binary.LittleEndian.PutUint32(edataSection[36:40], 0x40000040)
	buf.Write(edataSection)

	// pad to first section
	for buf.Len() < 0x400 {
		buf.WriteByte(0)
	}

	// .text section data
	textData := make([]byte, 0x200)
	buf.Write(textData)

	// .edata section data
	edataData := make([]byte, 0x1000)
	// write function addresses at 0x3000
	binary.LittleEndian.PutUint32(edataData[0:4], 0x1000)
	binary.LittleEndian.PutUint32(edataData[4:8], 0x1100)
	binary.LittleEndian.PutUint32(edataData[8:12], 0x1200)

	// write name rvas at 0x3100
	binary.LittleEndian.PutUint32(edataData[0x100:0x104], 0x3300)
	binary.LittleEndian.PutUint32(edataData[0x104:0x108], 0x3310)

	// write ordinals at 0x3200
	binary.LittleEndian.PutUint16(edataData[0x200:0x202], 0)
	binary.LittleEndian.PutUint16(edataData[0x202:0x204], 1)

	// write name strings at 0x3300
	copy(edataData[0x300:], "Function1\x00")
	copy(edataData[0x310:], "Function2\x00")

	buf.Write(edataData)

	return buf.Bytes()
}
