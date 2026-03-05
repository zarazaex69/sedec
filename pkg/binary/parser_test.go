package binfmt

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"testing"
)

// TestStandardLibParser_DetectFormat tests format detection for ELF, PE, and Mach-O
func TestStandardLibParser_DetectFormat(t *testing.T) {
	parser := NewStandardLibParser()

	tests := []struct {
		name           string
		data           []byte
		expectedFormat BinaryFormat
		shouldError    bool
	}{
		{
			name:           "ELF 64-bit",
			data:           createMinimalELF64(),
			expectedFormat: BinaryFormatELF,
			shouldError:    false,
		},
		{
			name:           "PE 64-bit",
			data:           createMinimalPE64(),
			expectedFormat: BinaryFormatPE,
			shouldError:    false,
		},
		{
			name:           "Mach-O 64-bit",
			data:           createMinimalMachO64(),
			expectedFormat: BinaryFormatMachO,
			shouldError:    false,
		},
		{
			name:           "Invalid magic",
			data:           []byte{0x00, 0x00, 0x00, 0x00},
			expectedFormat: BinaryFormatUnknown,
			shouldError:    true,
		},
		{
			name:           "Truncated file",
			data:           []byte{0x7F, 0x45}, // incomplete ELF magic
			expectedFormat: BinaryFormatUnknown,
			shouldError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format := parser.detectFormat(tt.data)

			if format != tt.expectedFormat {
				t.Errorf("detectFormat() = %v, want %v", format, tt.expectedFormat)
			}

			// test full parse
			info, err := parser.Parse(tt.data)
			if !tt.shouldError {
				if err != nil {
					t.Errorf("Parse() unexpected error: %v", err)
				}
				if info == nil {
					t.Error("Parse() returned nil info")
					return
				}
				if info.Format != tt.expectedFormat {
					t.Errorf("Parse() format = %v, want %v", info.Format, tt.expectedFormat)
				}
				// verify ground truth database is initialized
				if info.GroundTruthDB == nil {
					t.Error("Parse() GroundTruthDB is nil")
				}
				// cleanup
				info.Close()
				return
			}
			if err == nil {
				t.Error("Parse() expected error, got nil")
			}
		})
	}
}

// TestStandardLibParser_ErrorHandling tests error handling for malformed binaries
func TestStandardLibParser_ErrorHandling(t *testing.T) {
	parser := NewStandardLibParser()

	tests := []struct {
		name        string
		errorType   string
		data        []byte
		expectError bool
	}{
		{
			name:        "Empty data",
			data:        []byte{},
			expectError: true,
			errorType:   "truncated",
		},
		{
			name:        "Invalid magic number",
			data:        []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00},
			expectError: true,
			errorType:   "invalid magic",
		},
		{
			name:        "Corrupted ELF",
			data:        append([]byte{0x7F, 'E', 'L', 'F'}, make([]byte, 60)...),
			expectError: true,
			errorType:   "parse error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := parser.Parse(tt.data)

			if !tt.expectError && err != nil {
				t.Errorf("Parse() unexpected error: %v", err)
			}

			if tt.expectError && err == nil {
				t.Error("Parse() expected error, got nil")
			}

			if err != nil {
				// verify error is descriptive (not panic)
				if err.Error() == "" {
					t.Error("Parse() error message is empty")
				}
			}

			if info != nil {
				info.Close()
			}
		})
	}
}

// TestGroundTruthDatabase tests ground truth database construction
func TestGroundTruthDatabase(t *testing.T) {
	db := NewGroundTruthDatabase()

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

	// test adding entries
	testAddr := Address(0x1000)
	testSymbol := "test_func"

	db.SymbolsByAddress[testAddr] = testSymbol
	db.SymbolsByName[testSymbol] = testAddr

	if db.SymbolsByAddress[testAddr] != testSymbol {
		t.Error("Failed to store symbol by address")
	}
	if db.SymbolsByName[testSymbol] != testAddr {
		t.Error("Failed to store symbol by name")
	}
}

// TestBinaryInfo_Close tests resource cleanup
func TestBinaryInfo_Close(t *testing.T) {
	parser := NewStandardLibParser()

	// test with elf
	elfData := createMinimalELF64()
	info, err := parser.Parse(elfData)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	err = info.Close()
	if err != nil {
		t.Errorf("Close() error: %v", err)
	}

	// test with nil info
	var nilInfo *BinaryInfo
	err = nilInfo.Close()
	if err != nil {
		t.Errorf("Close() on nil should not error: %v", err)
	}
}

// createMinimalELF64 creates a minimal valid ELF64 binary for testing
func createMinimalELF64() []byte {
	buf := new(bytes.Buffer)

	// elf header (64 bytes)
	buf.Write([]byte{0x7F, 'E', 'L', 'F'}) // magic
	buf.WriteByte(2)                       // 64-bit
	buf.WriteByte(1)                       // little endian
	buf.WriteByte(1)                       // elf version
	buf.WriteByte(0)                       // system v abi
	buf.Write(make([]byte, 8))             // padding

	binary.Write(buf, binary.LittleEndian, uint16(2))        // e_type: ET_EXEC
	binary.Write(buf, binary.LittleEndian, uint16(0x3E))     // e_machine: EM_X86_64
	binary.Write(buf, binary.LittleEndian, uint32(1))        // e_version
	binary.Write(buf, binary.LittleEndian, uint64(0x400000)) // e_entry
	binary.Write(buf, binary.LittleEndian, uint64(64))       // e_phoff
	binary.Write(buf, binary.LittleEndian, uint64(0))        // e_shoff
	binary.Write(buf, binary.LittleEndian, uint32(0))        // e_flags
	binary.Write(buf, binary.LittleEndian, uint16(64))       // e_ehsize
	binary.Write(buf, binary.LittleEndian, uint16(56))       // e_phentsize
	binary.Write(buf, binary.LittleEndian, uint16(0))        // e_phnum
	binary.Write(buf, binary.LittleEndian, uint16(64))       // e_shentsize
	binary.Write(buf, binary.LittleEndian, uint16(0))        // e_shnum
	binary.Write(buf, binary.LittleEndian, uint16(0))        // e_shstrndx

	return buf.Bytes()
}

// createMinimalPE64 creates a minimal valid PE64 binary for testing
func createMinimalPE64() []byte {
	buf := new(bytes.Buffer)

	// dos header (64 bytes)
	buf.Write([]byte{'M', 'Z'})                        // magic
	buf.Write(make([]byte, 58))                        // dos header padding
	binary.Write(buf, binary.LittleEndian, uint32(64)) // e_lfanew (pe header offset)

	// pe signature (4 bytes)
	buf.Write([]byte{'P', 'E', 0, 0})

	// coff header (20 bytes)
	binary.Write(buf, binary.LittleEndian, uint16(0x8664)) // machine: AMD64
	binary.Write(buf, binary.LittleEndian, uint16(0))      // number of sections
	binary.Write(buf, binary.LittleEndian, uint32(0))      // timestamp
	binary.Write(buf, binary.LittleEndian, uint32(0))      // symbol table pointer
	binary.Write(buf, binary.LittleEndian, uint32(0))      // number of symbols
	binary.Write(buf, binary.LittleEndian, uint16(240))    // optional header size
	binary.Write(buf, binary.LittleEndian, uint16(0x22))   // characteristics

	// optional header (pe64) - 240 bytes
	binary.Write(buf, binary.LittleEndian, uint16(0x20B))       // magic: PE32+
	binary.Write(buf, binary.LittleEndian, uint8(14))           // major linker version
	binary.Write(buf, binary.LittleEndian, uint8(0))            // minor linker version
	binary.Write(buf, binary.LittleEndian, uint32(0))           // size of code
	binary.Write(buf, binary.LittleEndian, uint32(0))           // size of initialized data
	binary.Write(buf, binary.LittleEndian, uint32(0))           // size of uninitialized data
	binary.Write(buf, binary.LittleEndian, uint32(0x1000))      // address of entry point
	binary.Write(buf, binary.LittleEndian, uint32(0x1000))      // base of code
	binary.Write(buf, binary.LittleEndian, uint64(0x140000000)) // image base
	binary.Write(buf, binary.LittleEndian, uint32(0x1000))      // section alignment
	binary.Write(buf, binary.LittleEndian, uint32(0x200))       // file alignment
	binary.Write(buf, binary.LittleEndian, uint16(6))           // major os version
	binary.Write(buf, binary.LittleEndian, uint16(0))           // minor os version
	binary.Write(buf, binary.LittleEndian, uint16(0))           // major image version
	binary.Write(buf, binary.LittleEndian, uint16(0))           // minor image version
	binary.Write(buf, binary.LittleEndian, uint16(6))           // major subsystem version
	binary.Write(buf, binary.LittleEndian, uint16(0))           // minor subsystem version
	binary.Write(buf, binary.LittleEndian, uint32(0))           // win32 version value
	binary.Write(buf, binary.LittleEndian, uint32(0x2000))      // size of image
	binary.Write(buf, binary.LittleEndian, uint32(0x200))       // size of headers
	binary.Write(buf, binary.LittleEndian, uint32(0))           // checksum
	binary.Write(buf, binary.LittleEndian, uint16(3))           // subsystem: console
	binary.Write(buf, binary.LittleEndian, uint16(0))           // dll characteristics
	binary.Write(buf, binary.LittleEndian, uint64(0x100000))    // size of stack reserve
	binary.Write(buf, binary.LittleEndian, uint64(0x1000))      // size of stack commit
	binary.Write(buf, binary.LittleEndian, uint64(0x100000))    // size of heap reserve
	binary.Write(buf, binary.LittleEndian, uint64(0x1000))      // size of heap commit
	binary.Write(buf, binary.LittleEndian, uint32(0))           // loader flags
	binary.Write(buf, binary.LittleEndian, uint32(16))          // number of rva and sizes

	// data directories (16 * 8 = 128 bytes)
	for i := 0; i < 16; i++ {
		binary.Write(buf, binary.LittleEndian, uint32(0)) // virtual address
		binary.Write(buf, binary.LittleEndian, uint32(0)) // size
	}

	return buf.Bytes()
}

// createMinimalMachO64 creates a minimal valid Mach-O 64-bit binary for testing
func createMinimalMachO64() []byte {
	buf := new(bytes.Buffer)

	// mach header 64
	binary.Write(buf, binary.LittleEndian, uint32(0xFEEDFACF)) // magic
	binary.Write(buf, binary.LittleEndian, uint32(0x01000007)) // cpu type: x86_64
	binary.Write(buf, binary.LittleEndian, uint32(3))          // cpu subtype
	binary.Write(buf, binary.LittleEndian, uint32(2))          // file type: MH_EXECUTE
	binary.Write(buf, binary.LittleEndian, uint32(0))          // number of load commands
	binary.Write(buf, binary.LittleEndian, uint32(0))          // size of load commands
	binary.Write(buf, binary.LittleEndian, uint32(0))          // flags
	binary.Write(buf, binary.LittleEndian, uint32(0))          // reserved

	return buf.Bytes()
}

// createMinimalPE32 creates a minimal valid PE32 binary for testing
func createMinimalPE32() []byte {
	buf := new(bytes.Buffer)

	// dos header (64 bytes)
	buf.Write([]byte{'M', 'Z'})                        // magic
	buf.Write(make([]byte, 58))                        // dos header padding
	binary.Write(buf, binary.LittleEndian, uint32(64)) // e_lfanew (pe header offset)

	// pe signature (4 bytes)
	buf.Write([]byte{'P', 'E', 0, 0})

	// coff header (20 bytes)
	binary.Write(buf, binary.LittleEndian, uint16(0x14c)) // machine: I386
	binary.Write(buf, binary.LittleEndian, uint16(0))     // number of sections
	binary.Write(buf, binary.LittleEndian, uint32(0))     // timestamp
	binary.Write(buf, binary.LittleEndian, uint32(0))     // symbol table pointer
	binary.Write(buf, binary.LittleEndian, uint32(0))     // number of symbols
	binary.Write(buf, binary.LittleEndian, uint16(224))   // optional header size
	binary.Write(buf, binary.LittleEndian, uint16(0x102)) // characteristics

	// optional header (pe32) - 224 bytes
	binary.Write(buf, binary.LittleEndian, uint16(0x10B))    // magic: PE32
	binary.Write(buf, binary.LittleEndian, uint8(14))        // major linker version
	binary.Write(buf, binary.LittleEndian, uint8(0))         // minor linker version
	binary.Write(buf, binary.LittleEndian, uint32(0))        // size of code
	binary.Write(buf, binary.LittleEndian, uint32(0))        // size of initialized data
	binary.Write(buf, binary.LittleEndian, uint32(0))        // size of uninitialized data
	binary.Write(buf, binary.LittleEndian, uint32(0x1000))   // address of entry point
	binary.Write(buf, binary.LittleEndian, uint32(0x1000))   // base of code
	binary.Write(buf, binary.LittleEndian, uint32(0x2000))   // base of data
	binary.Write(buf, binary.LittleEndian, uint32(0x400000)) // image base
	binary.Write(buf, binary.LittleEndian, uint32(0x1000))   // section alignment
	binary.Write(buf, binary.LittleEndian, uint32(0x200))    // file alignment
	binary.Write(buf, binary.LittleEndian, uint16(6))        // major os version
	binary.Write(buf, binary.LittleEndian, uint16(0))        // minor os version
	binary.Write(buf, binary.LittleEndian, uint16(0))        // major image version
	binary.Write(buf, binary.LittleEndian, uint16(0))        // minor image version
	binary.Write(buf, binary.LittleEndian, uint16(6))        // major subsystem version
	binary.Write(buf, binary.LittleEndian, uint16(0))        // minor subsystem version
	binary.Write(buf, binary.LittleEndian, uint32(0))        // win32 version value
	binary.Write(buf, binary.LittleEndian, uint32(0x2000))   // size of image
	binary.Write(buf, binary.LittleEndian, uint32(0x200))    // size of headers
	binary.Write(buf, binary.LittleEndian, uint32(0))        // checksum
	binary.Write(buf, binary.LittleEndian, uint16(3))        // subsystem: console
	binary.Write(buf, binary.LittleEndian, uint16(0))        // dll characteristics
	binary.Write(buf, binary.LittleEndian, uint32(0x100000)) // size of stack reserve
	binary.Write(buf, binary.LittleEndian, uint32(0x1000))   // size of stack commit
	binary.Write(buf, binary.LittleEndian, uint32(0x100000)) // size of heap reserve
	binary.Write(buf, binary.LittleEndian, uint32(0x1000))   // size of heap commit
	binary.Write(buf, binary.LittleEndian, uint32(0))        // loader flags
	binary.Write(buf, binary.LittleEndian, uint32(16))       // number of rva and sizes

	// data directories (16 * 8 = 128 bytes)
	for i := 0; i < 16; i++ {
		binary.Write(buf, binary.LittleEndian, uint32(0)) // virtual address
		binary.Write(buf, binary.LittleEndian, uint32(0)) // size
	}

	return buf.Bytes()
}

// TestArchitectureDetection tests architecture detection for all formats
func TestArchitectureDetection(t *testing.T) {
	parser := NewStandardLibParser()

	tests := []struct {
		name         string
		data         []byte
		expectedArch Architecture
	}{
		{
			name:         "ELF x86_64",
			data:         createMinimalELF64(),
			expectedArch: ArchitectureX86_64,
		},
		{
			name:         "PE x86_64",
			data:         createMinimalPE64(),
			expectedArch: ArchitectureX86_64,
		},
		{
			name:         "Mach-O x86_64",
			data:         createMinimalMachO64(),
			expectedArch: ArchitectureX86_64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := parser.Parse(tt.data)
			if err != nil {
				t.Fatalf("Parse() error: %v", err)
			}
			defer info.Close()

			if info.Architecture != tt.expectedArch {
				t.Errorf("Architecture = %v, want %v", info.Architecture, tt.expectedArch)
			}
		})
	}
}

// TestBinaryInfoFields tests that all BinaryInfo fields are populated
func TestBinaryInfoFields(t *testing.T) {
	parser := NewStandardLibParser()
	data := createMinimalELF64()

	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	defer info.Close()

	// verify all required fields
	if info.Format == BinaryFormatUnknown {
		t.Error("Format not set")
	}
	if info.Architecture == ArchitectureUnknown {
		t.Error("Architecture not set")
	}
	if info.GroundTruthDB == nil {
		t.Error("GroundTruthDB not initialized")
	}
	if info.Sections == nil {
		t.Error("Sections not initialized")
	}
	if info.Symbols == nil {
		t.Error("Symbols not initialized")
	}
	if info.Relocations == nil {
		t.Error("Relocations not initialized")
	}
}

// TestELFParsing tests ELF-specific parsing functionality
func TestELFParsing(t *testing.T) {
	parser := NewStandardLibParser()
	data := createMinimalELF64()

	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	defer info.Close()

	// verify format
	if info.Format != BinaryFormatELF {
		t.Errorf("Format = %v, want %v", info.Format, BinaryFormatELF)
	}

	// verify architecture
	if info.Architecture != ArchitectureX86_64 {
		t.Errorf("Architecture = %v, want %v", info.Architecture, ArchitectureX86_64)
	}

	// verify entry point
	if info.EntryPoint != 0x400000 {
		t.Errorf("EntryPoint = %#x, want 0x400000", info.EntryPoint)
	}

	// verify sections initialized
	if info.Sections == nil {
		t.Error("Sections not initialized")
	}

	// verify symbols initialized
	if info.Symbols == nil {
		t.Error("Symbols not initialized")
	}

	// verify relocations initialized
	if info.Relocations == nil {
		t.Error("Relocations not initialized")
	}
}

// TestPEParsing tests PE-specific parsing functionality
func TestPEParsing(t *testing.T) {
	parser := NewStandardLibParser()
	data := createMinimalPE64()

	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	defer info.Close()

	// verify format
	if info.Format != BinaryFormatPE {
		t.Errorf("Format = %v, want %v", info.Format, BinaryFormatPE)
	}

	// verify architecture
	if info.Architecture != ArchitectureX86_64 {
		t.Errorf("Architecture = %v, want %v", info.Architecture, ArchitectureX86_64)
	}

	// verify entry point
	if info.EntryPoint != 0x1000 {
		t.Errorf("EntryPoint = %#x, want 0x1000", info.EntryPoint)
	}

	// verify base address
	if info.BaseAddress != 0x140000000 {
		t.Errorf("BaseAddress = %#x, want 0x140000000", info.BaseAddress)
	}

	// verify sections initialized
	if info.Sections == nil {
		t.Error("Sections not initialized")
	}

	// verify imports initialized
	if info.Imports == nil {
		t.Error("Imports not initialized")
	}

	// verify exports initialized
	if info.Exports == nil {
		t.Error("Exports not initialized")
	}
}

// TestMachOParsing tests Mach-O-specific parsing functionality
func TestMachOParsing(t *testing.T) {
	parser := NewStandardLibParser()
	data := createMinimalMachO64()

	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	defer info.Close()

	// verify format
	if info.Format != BinaryFormatMachO {
		t.Errorf("Format = %v, want %v", info.Format, BinaryFormatMachO)
	}

	// verify architecture
	if info.Architecture != ArchitectureX86_64 {
		t.Errorf("Architecture = %v, want %v", info.Architecture, ArchitectureX86_64)
	}

	// verify sections initialized
	if info.Sections == nil {
		t.Error("Sections not initialized")
	}

	// verify symbols initialized
	if info.Symbols == nil {
		t.Error("Symbols not initialized")
	}
}

// TestSymbolTypes tests symbol type conversions
func TestSymbolTypes(t *testing.T) {
	tests := []struct {
		want    string
		symType SymbolType
	}{
		{"Function", SymbolTypeFunction},
		{"Object", SymbolTypeObject},
		{"Section", SymbolTypeSection},
		{"File", SymbolTypeFile},
		{"TLS", SymbolTypeTLS},
		{"Unknown", SymbolTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.symType.String()
			if got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSymbolBindings tests symbol binding conversions
func TestSymbolBindings(t *testing.T) {
	tests := []struct {
		want    string
		binding SymbolBinding
	}{
		{"Local", SymbolBindingLocal},
		{"Global", SymbolBindingGlobal},
		{"Weak", SymbolBindingWeak},
		{"Unknown", SymbolBindingUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.binding.String()
			if got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRelocationTypes tests relocation type conversions
func TestRelocationTypes(t *testing.T) {
	tests := []struct {
		want      string
		relocType RelocationType
	}{
		{"Absolute", RelocationTypeAbsolute},
		{"Relative", RelocationTypeRelative},
		{"PLT", RelocationTypePLT},
		{"GOT", RelocationTypeGOT},
		{"Copy", RelocationTypeCopy},
		{"JumpSlot", RelocationTypeJumpSlot},
		{"GlobDat", RelocationTypeGlobDat},
		{"Unknown", RelocationTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.relocType.String()
			if got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBinaryFormats tests binary format conversions
func TestBinaryFormats(t *testing.T) {
	tests := []struct {
		want   string
		format BinaryFormat
	}{
		{"ELF", BinaryFormatELF},
		{"PE", BinaryFormatPE},
		{"Mach-O", BinaryFormatMachO},
		{"Unknown", BinaryFormatUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.format.String()
			if got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestArchitectures tests architecture conversions
func TestArchitectures(t *testing.T) {
	tests := []struct {
		want string
		arch Architecture
	}{
		{"x86_64", ArchitectureX86_64},
		{"x86", ArchitectureX86},
		{"ARM64", ArchitectureARM64},
		{"ARM", ArchitectureARM},
		{"MIPS", ArchitectureMIPS},
		{"MIPS64", ArchitectureMIPS64},
		{"PowerPC", ArchitecturePPC},
		{"PowerPC64", ArchitecturePPC64},
		{"RISC-V", ArchitectureRISCV},
		{"RISC-V64", ArchitectureRISCV64},
		{"Unknown", ArchitectureUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.arch.String()
			if got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestErrorTypes tests custom error types
func TestErrorTypes(t *testing.T) {
	t.Run("InvalidMagicError", func(t *testing.T) {
		err := &InvalidMagicError{Magic: []byte{0xFF, 0xFF, 0xFF, 0xFF}}
		if err.Error() == "" {
			t.Error("Error() returned empty string")
		}
	})

	t.Run("UnsupportedFormatError", func(t *testing.T) {
		err := &UnsupportedFormatError{Format: "test"}
		if err.Error() == "" {
			t.Error("Error() returned empty string")
		}
	})

	t.Run("InvalidOffsetError", func(t *testing.T) {
		err := &InvalidOffsetError{Offset: 0x1000, Reason: "test"}
		if err.Error() == "" {
			t.Error("Error() returned empty string")
		}
	})

	t.Run("TruncatedFileError", func(t *testing.T) {
		err := &TruncatedFileError{Expected: 100, Actual: 50}
		if err.Error() == "" {
			t.Error("Error() returned empty string")
		}
	})

	t.Run("CorruptedSectionError", func(t *testing.T) {
		err := &CorruptedSectionError{Section: ".text", Reason: "test"}
		if err.Error() == "" {
			t.Error("Error() returned empty string")
		}
	})
}

// TestGroundTruthDatabasePopulation tests database population from parsed data
func TestGroundTruthDatabasePopulation(t *testing.T) {
	parser := NewStandardLibParser()

	// create binary info with test data
	info := &BinaryInfo{
		Format:        BinaryFormatELF,
		Architecture:  ArchitectureX86_64,
		EntryPoint:    0x1000,
		GroundTruthDB: NewGroundTruthDatabase(),
		Symbols: []*Symbol{
			{Name: "main", Address: 0x1000, Type: SymbolTypeFunction},
			{Name: "data", Address: 0x2000, Type: SymbolTypeObject},
		},
		Relocations: []*Relocation{
			{Address: 0x3000, Symbol: "printf", Type: RelocationTypePLT},
		},
		Imports: []*Import{
			{Name: "printf", Address: 0x4000, Library: "libc.so"},
		},
		Exports: []*Export{
			{Name: "exported_func", Address: 0x5000},
		},
	}

	// build ground truth database
	parser.buildGroundTruthDB(info)

	// verify symbols by address
	if name, exists := info.GroundTruthDB.SymbolsByAddress[0x1000]; !exists || name != "main" {
		t.Error("Symbol 'main' not found in SymbolsByAddress")
	}

	// verify symbols by name
	if addr, exists := info.GroundTruthDB.SymbolsByName["main"]; !exists || addr != 0x1000 {
		t.Error("Symbol 'main' not found in SymbolsByName")
	}

	// verify relocations
	if _, exists := info.GroundTruthDB.Relocations[0x3000]; !exists {
		t.Error("Relocation at 0x3000 not found")
	}

	// verify imports
	if imp, exists := info.GroundTruthDB.Imports[0x4000]; !exists || imp.Name != "printf" {
		t.Error("Import 'printf' not found")
	}

	// verify exports
	if exp, exists := info.GroundTruthDB.Exports[0x5000]; !exists || exp.Name != "exported_func" {
		t.Error("Export 'exported_func' not found")
	}
}

// TestDetectFormatEdgeCases tests edge cases in format detection
func TestDetectFormatEdgeCases(t *testing.T) {
	parser := NewStandardLibParser()

	tests := []struct {
		name string
		data []byte
		want BinaryFormat
	}{
		{
			name: "Too short",
			data: []byte{0x7F, 0x45},
			want: BinaryFormatUnknown,
		},
		{
			name: "Mach-O 32-bit big endian",
			data: []byte{0xFE, 0xED, 0xFA, 0xCE},
			want: BinaryFormatMachO,
		},
		{
			name: "Mach-O fat binary",
			data: []byte{0xCA, 0xFE, 0xBA, 0xBE},
			want: BinaryFormatMachO,
		},
		{
			name: "Random bytes",
			data: []byte{0x12, 0x34, 0x56, 0x78},
			want: BinaryFormatUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parser.detectFormat(tt.data)
			if got != tt.want {
				t.Errorf("detectFormat() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPESymbolTypeConversion tests PE symbol type conversion
func TestPESymbolTypeConversion(t *testing.T) {
	parser := NewStandardLibParser()

	tests := []struct {
		storageClass uint8
		want         SymbolType
	}{
		{2, SymbolTypeFunction},  // IMAGE_SYM_CLASS_EXTERNAL
		{3, SymbolTypeObject},    // IMAGE_SYM_CLASS_STATIC
		{103, SymbolTypeSection}, // IMAGE_SYM_CLASS_SECTION
		{104, SymbolTypeFile},    // IMAGE_SYM_CLASS_FILE
		{255, SymbolTypeUnknown}, // unknown
	}

	for _, tt := range tests {
		t.Run(tt.want.String(), func(t *testing.T) {
			got := parser.convertPESymbolType(tt.storageClass)
			if got != tt.want {
				t.Errorf("convertPESymbolType(%d) = %v, want %v", tt.storageClass, got, tt.want)
			}
		})
	}
}

// TestMachOSymbolTypeConversion tests Mach-O symbol type conversion
func TestMachOSymbolTypeConversion(t *testing.T) {
	parser := NewStandardLibParser()

	tests := []struct {
		name    string
		symType uint8
		want    SymbolType
	}{
		{"N_SECT", 0x0E, SymbolTypeFunction},
		{"N_UNDF", 0x00, SymbolTypeUnknown},
		{"N_ABS", 0x02, SymbolTypeObject},
		{"Unknown", 0x04, SymbolTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parser.convertMachOSymbolType(tt.symType)
			if got != tt.want {
				t.Errorf("convertMachOSymbolType(%#x) = %v, want %v", tt.symType, got, tt.want)
			}
		})
	}
}

// TestMachORelocationParsing tests Mach-O relocation parsing
func TestMachORelocationParsing(t *testing.T) {
	parser := NewStandardLibParser()

	// create minimal mach-o file for testing
	data := createMinimalMachO64()
	machoFile, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Failed to create Mach-O file: %v", err)
	}
	defer machoFile.Close()

	// create fake relocation data (8 bytes)
	relocData := make([]byte, 8)
	binary.LittleEndian.PutUint32(relocData[0:4], 0x1000)     // address
	binary.LittleEndian.PutUint32(relocData[4:8], 0x00000001) // value with type

	// create fake section
	sec := &macho.Section{
		SectionHeader: macho.SectionHeader{
			Addr: 0x100000000,
		},
	}

	// test parsing
	reloc := parser.parseMachORelocation(relocData, machoFile, sec)
	if reloc == nil {
		t.Fatal("parseMachORelocation returned nil")
	}

	// verify relocation structure
	if reloc.Address == 0 {
		t.Error("Relocation address is zero")
	}
	if reloc.Type == RelocationTypeUnknown {
		t.Error("Relocation type is unknown")
	}
}

// TestMachORelocationTypeConversion tests Mach-O relocation type conversion
func TestMachORelocationTypeConversion(t *testing.T) {
	parser := NewStandardLibParser()

	// test x86_64 relocation types
	x64Tests := []struct {
		relocType uint32
		want      RelocationType
	}{
		{0, RelocationTypeAbsolute}, // X86_64_RELOC_UNSIGNED
		{1, RelocationTypeRelative}, // X86_64_RELOC_SIGNED
		{2, RelocationTypeGOT},      // X86_64_RELOC_BRANCH
		{3, RelocationTypeGOT},      // X86_64_RELOC_GOT_LOAD
		{4, RelocationTypeGOT},      // X86_64_RELOC_GOT
		{99, RelocationTypeUnknown}, // unknown
	}

	for _, tt := range x64Tests {
		t.Run("x86_64", func(t *testing.T) {
			got := parser.convertMachORelocationType(macho.CpuAmd64, tt.relocType)
			if got != tt.want {
				t.Errorf("convertMachORelocationType(x86_64, %d) = %v, want %v", tt.relocType, got, tt.want)
			}
		})
	}

	// test arm64 relocation types
	arm64Tests := []struct {
		relocType uint32
		want      RelocationType
	}{
		{0, RelocationTypeAbsolute}, // ARM64_RELOC_UNSIGNED
		{1, RelocationTypeRelative}, // ARM64_RELOC_SUBTRACTOR
		{2, RelocationTypeRelative}, // ARM64_RELOC_BRANCH26
		{3, RelocationTypeRelative}, // ARM64_RELOC_PAGE21
		{4, RelocationTypeRelative}, // ARM64_RELOC_PAGEOFF12
		{5, RelocationTypeGOT},      // ARM64_RELOC_GOT_LOAD_PAGE21
		{99, RelocationTypeUnknown}, // unknown
	}

	for _, tt := range arm64Tests {
		t.Run("arm64", func(t *testing.T) {
			got := parser.convertMachORelocationType(macho.CpuArm64, tt.relocType)
			if got != tt.want {
				t.Errorf("convertMachORelocationType(arm64, %d) = %v, want %v", tt.relocType, got, tt.want)
			}
		})
	}

	// test unknown architecture
	got := parser.convertMachORelocationType(macho.Cpu(999), 0)
	if got != RelocationTypeUnknown {
		t.Errorf("convertMachORelocationType(unknown, 0) = %v, want Unknown", got)
	}
}
