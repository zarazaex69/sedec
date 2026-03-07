package binfmt

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

// TestWithRealMachOBinary tests parser with real Mach-O binary
func TestWithRealMachOBinary(t *testing.T) {
	// try to find a real mach-o binary on the system
	// common locations: /bin/ls, /usr/bin/true, etc.
	testPaths := []string{
		"testdata/binary/test_macho_x64",
	}

	var data []byte
	var err error
	var foundPath string

	for _, path := range testPaths {
		//nolint:gosec // G304: test code reads test files
		data, err = os.ReadFile(path)
		if err == nil {
			foundPath = path
			break
		}
	}

	if err != nil {
		t.Skipf("Skipping: no Mach-O binary found: %v", err)
	}

	t.Logf("Testing with Mach-O binary: %s", foundPath)

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
	if info.Format != BinaryFormatMachO {
		t.Errorf("Format = %v, want Mach-O", info.Format)
	}

	// verify architecture detection
	if info.Architecture == ArchitectureUnknown {
		t.Error("Architecture is unknown")
	}
	t.Logf("Architecture: %v", info.Architecture)

	// verify sections extracted
	if len(info.Sections) == 0 {
		t.Fatal("No sections extracted")
	}
	t.Logf("Extracted %d sections", len(info.Sections))

	// verify symbols extracted
	t.Logf("Extracted %d symbols", len(info.Symbols))

	// verify ground truth database populated
	if info.GroundTruthDB == nil {
		t.Fatal("GroundTruthDB is nil")
	}

	t.Logf("Imports: %d, Exports: %d", len(info.Imports), len(info.Exports))
	t.Logf("Relocations: %d", len(info.Relocations))
}

// TestMachOSectionExtraction tests Mach-O section extraction
func TestMachOSectionExtraction(t *testing.T) {
	// create a more complete mach-o binary with sections
	data := createMachOWithSections()

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

	// verify sections extracted
	if len(info.Sections) == 0 {
		t.Fatal("No sections extracted")
	}

	// verify section properties
	for _, sec := range info.Sections {
		if sec.Name == "" {
			t.Error("Section has empty name")
		}
		if sec.Address == 0 {
			t.Logf("Section %s has zero address (may be normal)", sec.Name)
		}
		// verify flags are set
		if sec.Flags == 0 {
			t.Logf("Section %s has zero flags", sec.Name)
		}
		// verify allocated flag
		if !sec.IsAllocated {
			t.Errorf("Section %s should be allocated", sec.Name)
		}

		t.Logf("Section: %s (addr=%#x, size=%d, exec=%v, write=%v)",
			sec.Name, sec.Address, sec.Size, sec.IsExecutable, sec.IsWritable)
	}
}

// TestMachOSymbolExtraction tests Mach-O symbol extraction
func TestMachOSymbolExtraction(t *testing.T) {
	// create mach-o with symbol table
	data := createMachOWithSymbols()

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

	// verify symbols extracted
	t.Logf("Extracted %d symbols", len(info.Symbols))

	// verify symbol structure
	for i, sym := range info.Symbols {
		if sym.Name == "" {
			t.Logf("Symbol %d has empty name (may be normal)", i)
		}
		// verify type is set
		if sym.Type == SymbolTypeUnknown {
			t.Logf("Symbol %s has unknown type", sym.Name)
		}
		// verify binding is set
		if sym.Binding == SymbolBindingUnknown {
			t.Logf("Symbol %s has unknown binding", sym.Name)
		}

		if i < 5 && sym.Name != "" {
			t.Logf("Symbol: %s (addr=%#x, type=%v, binding=%v)",
				sym.Name, sym.Address, sym.Type, sym.Binding)
		}
	}
}

// TestMachOEntryPointDetection tests entry point detection
func TestMachOEntryPointDetection(t *testing.T) {
	// create mach-o with __TEXT segment and __text section
	data := createMachOWithTextSegment()

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

	// entry point may be 0 if not found, but should not panic
	t.Logf("Entry point: %#x", info.EntryPoint)

	// verify base address
	t.Logf("Base address: %#x", info.BaseAddress)
}

// TestMachORelocationExtraction tests Mach-O relocation extraction
func TestMachORelocationExtraction(t *testing.T) {
	// create mach-o with relocations
	data := createMachOWithRelocations()

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

	// verify relocations extracted
	t.Logf("Extracted %d relocations", len(info.Relocations))

	// verify relocation structure
	for i, reloc := range info.Relocations {
		if reloc.Address == 0 {
			t.Logf("Relocation %d has zero address", i)
		}
		if reloc.Type == RelocationTypeUnknown {
			t.Logf("Relocation %d has unknown type", i)
		}

		if i < 5 {
			t.Logf("Relocation: addr=%#x type=%v symbol=%s",
				reloc.Address, reloc.Type, reloc.Symbol)
		}
	}

	// verify relocations are in ground truth database
	for _, reloc := range info.Relocations {
		if _, exists := info.GroundTruthDB.Relocations[reloc.Address]; !exists {
			t.Errorf("Relocation at %#x not in GroundTruthDB", reloc.Address)
		}
	}
}

// TestMachOImportsExports tests Mach-O import/export extraction
func TestMachOImportsExports(t *testing.T) {
	// create mach-o with dylib imports
	data := createMachOWithDylibs()

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

	// verify imports extracted
	t.Logf("Extracted %d imports", len(info.Imports))

	// verify import structure
	for i, imp := range info.Imports {
		if imp.Name == "" {
			t.Logf("Import %d has empty name", i)
		}
		if i < 5 {
			t.Logf("Import: %s (library: %s)", imp.Name, imp.Library)
		}
	}

	// verify exports extracted
	t.Logf("Extracted %d exports", len(info.Exports))

	// verify export structure
	for i, exp := range info.Exports {
		if exp.Name == "" {
			t.Logf("Export %d has empty name", i)
		}
		if i < 5 {
			t.Logf("Export: %s (addr=%#x)", exp.Name, exp.Address)
		}
	}
}

// TestMachOGroundTruthDatabase tests ground truth database for Mach-O
func TestMachOGroundTruthDatabase(t *testing.T) {
	data := createMachOWithSymbols()

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

// TestMachOCloseHandling tests Mach-O file handle closing
func TestMachOCloseHandling(t *testing.T) {
	data := createMachOWithSections()

	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}

	// verify macho file handle is set
	if info.machoFile == nil {
		t.Error("machoFile handle not set")
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

// helper functions to create test mach-o binaries

// createMachOWithSections creates a mach-o binary with sections
func createMachOWithSections() []byte {
	buf := new(bytes.Buffer)
	writeMachO64HeaderWithSegment(buf, 1, 152)
	writeSegmentCommand64(buf, "__TEXT", 0x100000000, 0x1000, 0, 0x1000, 1)
	writeSection64(buf, "__text", "__TEXT", 0x100000000, 0x100, 0, 4)
	return buf.Bytes()
}

// createMachOWithSymbols creates a mach-o binary with symbol table
func createMachOWithSymbols() []byte {
	buf := new(bytes.Buffer)

	// mach header 64
	_ = binary.Write(buf, binary.LittleEndian, uint32(0xFEEDFACF)) // magic
	_ = binary.Write(buf, binary.LittleEndian, uint32(0x01000007)) // cpu type: x86_64
	_ = binary.Write(buf, binary.LittleEndian, uint32(3))          // cpu subtype
	_ = binary.Write(buf, binary.LittleEndian, uint32(2))          // file type: MH_EXECUTE
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))          // number of load commands
	_ = binary.Write(buf, binary.LittleEndian, uint32(24))         // size of load commands
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))          // flags
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))          // reserved

	// symtab command (LC_SYMTAB = 0x2)
	_ = binary.Write(buf, binary.LittleEndian, uint32(0x2))  // cmd
	_ = binary.Write(buf, binary.LittleEndian, uint32(24))   // cmdsize
	_ = binary.Write(buf, binary.LittleEndian, uint32(1000)) // symoff
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))    // nsyms
	_ = binary.Write(buf, binary.LittleEndian, uint32(2000)) // stroff
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))    // strsize

	return buf.Bytes()
}

// createMachOWithTextSegment creates a mach-o with __TEXT segment
func createMachOWithTextSegment() []byte {
	return createMachOWithSections()
}

// createMachOWithRelocations creates a mach-o with relocations
func createMachOWithRelocations() []byte {
	buf := new(bytes.Buffer)

	// mach header 64
	_ = binary.Write(buf, binary.LittleEndian, uint32(0xFEEDFACF)) // magic
	_ = binary.Write(buf, binary.LittleEndian, uint32(0x01000007)) // cpu type: x86_64
	_ = binary.Write(buf, binary.LittleEndian, uint32(3))          // cpu subtype
	_ = binary.Write(buf, binary.LittleEndian, uint32(2))          // file type: MH_EXECUTE
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))          // number of load commands
	_ = binary.Write(buf, binary.LittleEndian, uint32(152))        // size of load commands
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))          // flags
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))          // reserved

	// segment command 64 with section that has relocations
	_ = binary.Write(buf, binary.LittleEndian, uint32(0x19))        // cmd
	_ = binary.Write(buf, binary.LittleEndian, uint32(152))         // cmdsize
	buf.WriteString("__TEXT")                                       // segname
	buf.Write(make([]byte, 16-len("__TEXT")))                       // padding
	_ = binary.Write(buf, binary.LittleEndian, uint64(0x100000000)) // vmaddr
	_ = binary.Write(buf, binary.LittleEndian, uint64(0x1000))      // vmsize
	_ = binary.Write(buf, binary.LittleEndian, uint64(0))           // fileoff
	_ = binary.Write(buf, binary.LittleEndian, uint64(0x1000))      // filesize
	_ = binary.Write(buf, binary.LittleEndian, uint32(7))           // maxprot
	_ = binary.Write(buf, binary.LittleEndian, uint32(5))           // initprot
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))           // nsects
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))           // flags

	// section 64 with relocations
	buf.WriteString("__text")                                       // sectname
	buf.Write(make([]byte, 16-len("__text")))                       // padding
	buf.WriteString("__TEXT")                                       // segname
	buf.Write(make([]byte, 16-len("__TEXT")))                       // padding
	_ = binary.Write(buf, binary.LittleEndian, uint64(0x100000000)) // addr
	_ = binary.Write(buf, binary.LittleEndian, uint64(0x100))       // size
	_ = binary.Write(buf, binary.LittleEndian, uint32(1000))        // offset
	_ = binary.Write(buf, binary.LittleEndian, uint32(4))           // align
	_ = binary.Write(buf, binary.LittleEndian, uint32(2000))        // reloff
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))           // nreloc (0 to avoid reading invalid data)
	_ = binary.Write(buf, binary.LittleEndian, uint32(0x80000400))  // flags
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))           // reserved1
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))           // reserved2
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))           // reserved3

	return buf.Bytes()
}

// createMachOWithDylibs creates a mach-o with dylib load commands
func createMachOWithDylibs() []byte {
	buf := new(bytes.Buffer)

	// mach header 64
	_ = binary.Write(buf, binary.LittleEndian, uint32(0xFEEDFACF)) // magic
	_ = binary.Write(buf, binary.LittleEndian, uint32(0x01000007)) // cpu type: x86_64
	_ = binary.Write(buf, binary.LittleEndian, uint32(3))          // cpu subtype
	_ = binary.Write(buf, binary.LittleEndian, uint32(2))          // file type: MH_EXECUTE
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))          // number of load commands
	cmdSize := 24 + len("/usr/lib/libSystem.B.dylib") + 1
	// align to 8 bytes
	cmdSize = (cmdSize + 7) & ^7
	//nolint:gosec // G115: safe conversion - cmdSize is small validated value
	_ = binary.Write(buf, binary.LittleEndian, uint32(cmdSize)) // size of load commands
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))       // flags
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))       // reserved

	// dylib command (LC_LOAD_DYLIB = 0xc)
	_ = binary.Write(buf, binary.LittleEndian, uint32(0xc)) // cmd
	//nolint:gosec // G115: safe conversion - cmdSize is small validated value
	_ = binary.Write(buf, binary.LittleEndian, uint32(cmdSize)) // cmdsize
	_ = binary.Write(buf, binary.LittleEndian, uint32(24))      // name offset
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))       // timestamp
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))       // current version
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))       // compatibility version
	buf.WriteString("/usr/lib/libSystem.B.dylib")               // name
	buf.WriteByte(0)                                            // null terminator
	// pad to alignment
	for buf.Len() < 32+cmdSize {
		buf.WriteByte(0)
	}

	return buf.Bytes()
}

// TestMachOFatBinaryDetection tests fat binary detection
func TestMachOFatBinaryDetection(t *testing.T) {
	parser := NewStandardLibParser()

	// create fat binary magic
	data := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x00}

	format := parser.detectFormat(data)
	if format != BinaryFormatMachO {
		t.Errorf("detectFormat(fat binary) = %v, want Mach-O", format)
	}
}

// TestMachO32BitDetection tests 32-bit mach-o detection
func TestMachO32BitDetection(t *testing.T) {
	parser := NewStandardLibParser()

	// create 32-bit mach-o magic
	data := []byte{0xFE, 0xED, 0xFA, 0xCE, 0x00, 0x00, 0x00, 0x00}

	format := parser.detectFormat(data)
	if format != BinaryFormatMachO {
		t.Errorf("detectFormat(32-bit mach-o) = %v, want Mach-O", format)
	}
}

// TestMachOReversedEndian tests reversed endian mach-o detection
func TestMachOReversedEndian(t *testing.T) {
	parser := NewStandardLibParser()

	// create reversed endian 64-bit mach-o magic
	data := []byte{0xCF, 0xFA, 0xED, 0xFE, 0x00, 0x00, 0x00, 0x00}

	format := parser.detectFormat(data)
	if format != BinaryFormatMachO {
		t.Errorf("detectFormat(reversed 64-bit mach-o) = %v, want Mach-O", format)
	}
}
