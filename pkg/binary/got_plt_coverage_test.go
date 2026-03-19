package binfmt

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"testing"
)

func TestResolveGOTEntries_MachO(t *testing.T) {
	parser := NewStandardLibParser()

	info := &BinaryInfo{
		Format:        BinaryFormatMachO,
		Architecture:  ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(),
	}

	info.Relocations = []*Relocation{
		{Address: 0x100002000, Symbol: "printf", Type: RelocationTypeGOT},
		{Address: 0x100002008, Symbol: "malloc", Type: RelocationTypeGOT},
		{Address: 0x100002010, Symbol: "free", Type: RelocationTypeAbsolute},
	}

	info.GroundTruthDB.SymbolsByName["printf"] = 0x100001000
	info.GroundTruthDB.SymbolsByName["malloc"] = 0x100001100

	entries, err := parser.resolveMachOGOT(info, make(map[Address]*GOTEntry))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if e := entries[0x100002000]; e == nil || e.TargetSymbol != "printf" || e.TargetAddress != 0x100001000 {
		t.Errorf("printf entry invalid: %+v", e)
	}
	if e := entries[0x100002008]; e == nil || e.TargetSymbol != "malloc" || e.TargetAddress != 0x100001100 {
		t.Errorf("malloc entry invalid: %+v", e)
	}
}

func TestResolvePLTStubs_PE(t *testing.T) {
	parser := NewStandardLibParser()

	info := &BinaryInfo{
		Format:        BinaryFormatPE,
		Architecture:  ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(),
	}

	info.Imports = []*Import{
		{Name: "CreateFileW", Library: "kernel32.dll", Address: 0x140001000},
		{Name: "ReadFile", Library: "kernel32.dll", Address: 0x140001008},
	}

	entries, err := parser.ResolvePLTStubs(info)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	e := entries[0x140001000]
	if e == nil || e.TargetSymbol != "CreateFileW" {
		t.Errorf("CreateFileW entry invalid: %+v", e)
	}
	if e.GOTAddress != e.Address {
		t.Errorf("PE IAT: GOTAddress should equal Address, got 0x%x vs 0x%x", e.GOTAddress, e.Address)
	}
}

func TestResolvePLTStubs_NilInfo(t *testing.T) {
	parser := NewStandardLibParser()
	_, err := parser.ResolvePLTStubs(nil)
	if err == nil {
		t.Fatal("expected error for nil info")
	}
}

func TestResolvePLTStubs_UnsupportedFormat(t *testing.T) {
	parser := NewStandardLibParser()
	info := &BinaryInfo{Format: BinaryFormatUnknown}
	_, err := parser.ResolvePLTStubs(info)
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestResolveGOTEntries_UnsupportedFormat(t *testing.T) {
	parser := NewStandardLibParser()
	info := &BinaryInfo{Format: BinaryFormatUnknown}
	_, err := parser.ResolveGOTEntries(info)
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestCalculateBaseAddress_UnsupportedFormat(t *testing.T) {
	parser := NewStandardLibParser()
	info := &BinaryInfo{Format: BinaryFormatUnknown}
	_, err := parser.CalculateBaseAddress(info)
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestCalculateBaseAddress_MachO(t *testing.T) {
	parser := NewStandardLibParser()

	machoData := buildMinimalMachO64(t)
	machoFile, err := macho.NewFile(bytes.NewReader(machoData))
	if err != nil {
		t.Fatalf("failed to create macho file: %v", err)
	}

	info := &BinaryInfo{
		Format:    BinaryFormatMachO,
		machoFile: machoFile,
	}

	addr, err := parser.CalculateBaseAddress(info)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if addr != 0x100000000 {
		t.Errorf("expected base 0x100000000, got 0x%x", addr)
	}
}

func TestCalculateBaseAddress_MachO_NilFile(t *testing.T) {
	parser := NewStandardLibParser()
	info := &BinaryInfo{
		Format:    BinaryFormatMachO,
		machoFile: nil,
	}
	_, err := parser.CalculateBaseAddress(info)
	if err == nil {
		t.Fatal("expected error for nil macho file")
	}
}

func TestCreateRelativeGOTEntry_NegativeAddend(t *testing.T) {
	parser := NewStandardLibParser()

	info := &BinaryInfo{
		Format:        BinaryFormatELF,
		Architecture:  ArchitectureX86_64,
		BaseAddress:   0x555555554000,
		GroundTruthDB: NewGroundTruthDatabase(),
		elfFile:       createMinimalELFFile(t),
	}

	reloc := &Relocation{
		Address: 0x601000,
		Type:    RelocationTypeRelative,
		Addend:  -0x100,
	}

	entry := parser.createRelativeGOTEntry(info, reloc)
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}

	expected := Address(0x555555554000 - 0x100)
	if entry.TargetAddress != expected {
		t.Errorf("expected target 0x%x, got 0x%x", expected, entry.TargetAddress)
	}
}

func TestCreateRelativeGOTEntry_ZeroBaseAddress(t *testing.T) {
	parser := NewStandardLibParser()

	elfFile := createELFWithPTLoad(t, 0x400000)

	info := &BinaryInfo{
		Format:        BinaryFormatELF,
		Architecture:  ArchitectureX86_64,
		BaseAddress:   0,
		GroundTruthDB: NewGroundTruthDatabase(),
		elfFile:       elfFile,
	}

	reloc := &Relocation{
		Address: 0x601000,
		Type:    RelocationTypeRelative,
		Addend:  0x1000,
	}

	entry := parser.createRelativeGOTEntry(info, reloc)
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}

	expected := Address(0x400000 + 0x1000)
	if entry.TargetAddress != expected {
		t.Errorf("expected target 0x%x, got 0x%x", expected, entry.TargetAddress)
	}
}

func TestCreateGOTEntryFromRelocation_AllTypes(t *testing.T) {
	parser := NewStandardLibParser()

	info := &BinaryInfo{
		Format:        BinaryFormatELF,
		Architecture:  ArchitectureX86_64,
		BaseAddress:   0x400000,
		GroundTruthDB: NewGroundTruthDatabase(),
		elfFile:       createMinimalELFFile(t),
	}

	tests := []struct {
		name      string
		reloc     *Relocation
		expectNil bool
	}{
		{"GOT type", &Relocation{Address: 0x601000, Symbol: "sym", Type: RelocationTypeGOT}, false},
		{"GlobDat type", &Relocation{Address: 0x601008, Symbol: "sym", Type: RelocationTypeGlobDat}, false},
		{"JumpSlot type", &Relocation{Address: 0x601010, Symbol: "sym", Type: RelocationTypeJumpSlot}, false},
		{"Relative type", &Relocation{Address: 0x601018, Type: RelocationTypeRelative, Addend: 0x100}, false},
		{"Absolute type", &Relocation{Address: 0x601020, Type: RelocationTypeAbsolute}, true},
		{"PLT type", &Relocation{Address: 0x601028, Type: RelocationTypePLT}, true},
		{"Copy type", &Relocation{Address: 0x601030, Type: RelocationTypeCopy}, true},
		{"Unknown type", &Relocation{Address: 0x601038, Type: RelocationTypeUnknown}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := parser.createGOTEntryFromRelocation(info, tt.reloc)
			if tt.expectNil && entry != nil {
				t.Errorf("expected nil entry for %s", tt.name)
			}
			if !tt.expectNil && entry == nil {
				t.Errorf("expected non-nil entry for %s", tt.name)
			}
		})
	}
}

func TestParseELFPLTEntry_X86(t *testing.T) {
	parser := NewStandardLibParser()

	info := &BinaryInfo{Architecture: ArchitectureX86}

	data := []byte{
		0xff, 0x25, 0x18, 0x10, 0x60, 0x00,
		0x68, 0x00, 0x00, 0x00, 0x00,
		0xe9, 0xe0, 0xff, 0xff, 0xff,
	}

	gotAddr, err := parser.parseELFPLTEntry(info, data, 0x400410)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := Address(0x601018)
	if gotAddr != expected {
		t.Errorf("expected got address 0x%x, got 0x%x", expected, gotAddr)
	}
}

func TestParseELFPLTEntry_UnsupportedArch(t *testing.T) {
	parser := NewStandardLibParser()

	info := &BinaryInfo{Architecture: ArchitectureMIPS}
	data := make([]byte, 16)

	_, err := parser.parseELFPLTEntry(info, data, 0x400410)
	if err == nil {
		t.Fatal("expected error for unsupported architecture")
	}
}

func TestParseELFPLTEntry_NegativeRIPOffset(t *testing.T) {
	parser := NewStandardLibParser()

	info := &BinaryInfo{Architecture: ArchitectureX86_64}

	data := []byte{
		0xff, 0x25,
		0x00, 0x00, 0x00, 0x80,
		0x68, 0x00, 0x00, 0x00, 0x00,
		0xe9, 0xe0, 0xff, 0xff, 0xff,
	}

	gotAddr, err := parser.parseELFPLTEntry(info, data, 0x7FFFFFFF00000000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ripOffset := int64(0x80000000) | ^int64(0xFFFFFFFF)
	expected := Address(uint64(0x7FFFFFFF00000000) + 6 - uint64(-ripOffset))
	if gotAddr != expected {
		t.Errorf("expected got address 0x%x, got 0x%x", expected, gotAddr)
	}
}

func TestParseMachOStub_Valid(t *testing.T) {
	parser := NewStandardLibParser()

	info := &BinaryInfo{Architecture: ArchitectureX86_64}

	data := []byte{
		0xff, 0x25, 0x10, 0x20, 0x00, 0x00,
	}

	gotAddr, err := parser.parseMachOStub(info, data, 0x100001000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := Address(0x100001000 + 6 + 0x2010)
	if gotAddr != expected {
		t.Errorf("expected 0x%x, got 0x%x", expected, gotAddr)
	}
}

func TestParseMachOStub_TooShort(t *testing.T) {
	parser := NewStandardLibParser()
	info := &BinaryInfo{Architecture: ArchitectureX86_64}

	_, err := parser.parseMachOStub(info, []byte{0xff}, 0x100001000)
	if err == nil {
		t.Fatal("expected error for short stub")
	}
}

func TestParseMachOStub_InvalidOpcode(t *testing.T) {
	parser := NewStandardLibParser()
	info := &BinaryInfo{Architecture: ArchitectureX86_64}

	data := []byte{0x90, 0x90, 0x10, 0x20, 0x00, 0x00}
	_, err := parser.parseMachOStub(info, data, 0x100001000)
	if err == nil {
		t.Fatal("expected error for invalid opcode")
	}
}

func TestParseMachOStub_UnsupportedArch(t *testing.T) {
	parser := NewStandardLibParser()
	info := &BinaryInfo{Architecture: ArchitectureARM}

	data := make([]byte, 12)
	_, err := parser.parseMachOStub(info, data, 0x100001000)
	if err == nil {
		t.Fatal("expected error for unsupported arch")
	}
}

func TestParseMachOStub_NegativeOffset(t *testing.T) {
	parser := NewStandardLibParser()
	info := &BinaryInfo{Architecture: ArchitectureX86_64}

	data := []byte{
		0xff, 0x25,
		0x00, 0x00, 0x00, 0x80,
	}

	gotAddr, err := parser.parseMachOStub(info, data, 0x7FFFFFFF00000000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ripOffset := int64(0x80000000) | ^int64(0xFFFFFFFF)
	expected := Address(uint64(0x7FFFFFFF00000000) + 6 - uint64(-ripOffset))
	if gotAddr != expected {
		t.Errorf("expected 0x%x, got 0x%x", expected, gotAddr)
	}
}

func TestParseELFGOTSection_64bit(t *testing.T) {
	parser := NewStandardLibParser()

	gotData := make([]byte, 24)
	binary.LittleEndian.PutUint64(gotData[0:8], 0)
	binary.LittleEndian.PutUint64(gotData[8:16], 0x400500)
	binary.LittleEndian.PutUint64(gotData[16:24], 0x400600)

	elfFile := createELFWithGOTSection(t, gotData, 0x601000)

	info := &BinaryInfo{
		Format:        BinaryFormatELF,
		Architecture:  ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(),
		elfFile:       elfFile,
	}

	info.GroundTruthDB.SymbolsByAddress[0x400500] = "printf"

	var gotSection *elf.Section
	for _, s := range elfFile.Sections {
		if s.Name == ".got" {
			gotSection = s
			break
		}
	}
	if gotSection == nil {
		t.Fatal(".got section not found in synthetic elf")
	}

	gotEntries := make(map[Address]*GOTEntry)
	err := parser.parseELFGOTSection(info, gotSection, gotEntries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(gotEntries) != 2 {
		t.Fatalf("expected 2 entries (null skipped), got %d", len(gotEntries))
	}

	e := gotEntries[Address(0x601008)]
	if e == nil {
		t.Fatal("entry at 0x601008 not found")
	}
	if e.TargetAddress != 0x400500 {
		t.Errorf("expected target 0x400500, got 0x%x", e.TargetAddress)
	}
	if e.TargetSymbol != "printf" {
		t.Errorf("expected symbol 'printf', got '%s'", e.TargetSymbol)
	}
}

func TestParseELFGOTSection_SkipsExistingEntries(t *testing.T) {
	parser := NewStandardLibParser()

	gotData := make([]byte, 8)
	binary.LittleEndian.PutUint64(gotData[0:8], 0x400500)

	elfFile := createELFWithGOTSection(t, gotData, 0x601000)

	info := &BinaryInfo{
		Format:        BinaryFormatELF,
		Architecture:  ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(),
		elfFile:       elfFile,
	}

	var gotSection *elf.Section
	for _, s := range elfFile.Sections {
		if s.Name == ".got" {
			gotSection = s
			break
		}
	}
	if gotSection == nil {
		t.Fatal(".got section not found")
	}

	existing := &GOTEntry{Address: 0x601000, TargetSymbol: "existing"}
	gotEntries := map[Address]*GOTEntry{0x601000: existing}

	err := parser.parseELFGOTSection(info, gotSection, gotEntries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotEntries[0x601000].TargetSymbol != "existing" {
		t.Error("existing entry was overwritten")
	}
}

func TestResolveMachOPLT_WithStubs(t *testing.T) {
	parser := NewStandardLibParser()

	machoData := buildMinimalMachO64(t)
	machoFile, err := macho.NewFile(bytes.NewReader(machoData))
	if err != nil {
		t.Fatalf("failed to create macho: %v", err)
	}

	stubData := []byte{
		0xff, 0x25, 0x10, 0x20, 0x00, 0x00,
		0xff, 0x25, 0x14, 0x20, 0x00, 0x00,
	}

	info := &BinaryInfo{
		Format:        BinaryFormatMachO,
		Architecture:  ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(),
		machoFile:     machoFile,
		Sections: []*Section{
			{
				Name:    "__stubs",
				Address: 0x100001000,
				Data:    stubData,
				Size:    uint64(len(stubData)),
			},
		},
		Relocations: []*Relocation{
			{Address: Address(0x100001000 + 6 + 0x2010), Symbol: "printf", Type: RelocationTypeGOT},
		},
	}

	entries, err := parser.resolveMachOPLT(info, make(map[Address]*PLTEntry))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestResolveMachOPLT_NilMachoFile(t *testing.T) {
	parser := NewStandardLibParser()

	info := &BinaryInfo{
		Format:        BinaryFormatMachO,
		Architecture:  ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(),
		machoFile:     nil,
	}

	entries, err := parser.resolveMachOPLT(info, make(map[Address]*PLTEntry))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for nil macho, got %d", len(entries))
	}
}

func TestResolveMachOPLT_NoStubsSection(t *testing.T) {
	parser := NewStandardLibParser()

	machoData := buildMinimalMachO64(t)
	machoFile, err := macho.NewFile(bytes.NewReader(machoData))
	if err != nil {
		t.Fatalf("failed to create macho: %v", err)
	}

	info := &BinaryInfo{
		Format:        BinaryFormatMachO,
		Architecture:  ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(),
		machoFile:     machoFile,
		Sections:      []*Section{},
	}

	entries, err := parser.resolveMachOPLT(info, make(map[Address]*PLTEntry))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestResolveMachOPLT_UnsupportedArch(t *testing.T) {
	parser := NewStandardLibParser()

	machoData := buildMinimalMachO64(t)
	machoFile, err := macho.NewFile(bytes.NewReader(machoData))
	if err != nil {
		t.Fatalf("failed to create macho: %v", err)
	}

	info := &BinaryInfo{
		Format:        BinaryFormatMachO,
		Architecture:  ArchitectureMIPS,
		GroundTruthDB: NewGroundTruthDatabase(),
		machoFile:     machoFile,
		Sections: []*Section{
			{Name: "__stubs", Address: 0x100001000, Data: make([]byte, 12), Size: 12},
		},
	}

	entries, err := parser.resolveMachOPLT(info, make(map[Address]*PLTEntry))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for unsupported arch, got %d", len(entries))
	}
}

func TestResolveELFGOT_NilELFFile(t *testing.T) {
	parser := NewStandardLibParser()

	info := &BinaryInfo{
		Format:        BinaryFormatELF,
		Architecture:  ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(),
		elfFile:       nil,
	}

	_, err := parser.resolveELFGOT(info, make(map[Address]*GOTEntry))
	if err == nil {
		t.Fatal("expected error for nil elf file")
	}
}

func TestResolveELFPLT_NilELFFile(t *testing.T) {
	parser := NewStandardLibParser()

	info := &BinaryInfo{
		Format:        BinaryFormatELF,
		Architecture:  ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(),
		elfFile:       nil,
	}

	_, err := parser.resolveELFPLT(info, make(map[Address]*PLTEntry))
	if err == nil {
		t.Fatal("expected error for nil elf file")
	}
}

func TestCalculateELFBaseAddress_NilELFFile(t *testing.T) {
	parser := NewStandardLibParser()

	info := &BinaryInfo{
		Format:  BinaryFormatELF,
		elfFile: nil,
	}

	_, err := parser.calculateELFBaseAddress(info)
	if err == nil {
		t.Fatal("expected error for nil elf file")
	}
}

func TestCalculateELFBaseAddress_NoPTLoad(t *testing.T) {
	parser := NewStandardLibParser()

	elfFile := createMinimalELFFile(t)

	info := &BinaryInfo{
		Format:  BinaryFormatELF,
		elfFile: elfFile,
	}

	addr, err := parser.calculateELFBaseAddress(info)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if addr != 0 {
		t.Errorf("expected 0 for dyn elf without pt_load, got 0x%x", addr)
	}
}

func buildMinimalMachO64(t *testing.T) []byte {
	t.Helper()

	buf := new(bytes.Buffer)

	cmdSize := uint32(72)
	writeMachO64HeaderWithSegment(buf, 1, cmdSize)

	_ = binary.Write(buf, binary.LittleEndian, uint32(0x19))
	_ = binary.Write(buf, binary.LittleEndian, cmdSize)

	segName := [16]byte{}
	copy(segName[:], "__TEXT")
	buf.Write(segName[:])

	_ = binary.Write(buf, binary.LittleEndian, uint64(0x100000000))
	_ = binary.Write(buf, binary.LittleEndian, uint64(0x1000))
	_ = binary.Write(buf, binary.LittleEndian, uint64(0))
	_ = binary.Write(buf, binary.LittleEndian, uint64(0x1000))
	_ = binary.Write(buf, binary.LittleEndian, uint32(5))
	_ = binary.Write(buf, binary.LittleEndian, uint32(5))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))

	for buf.Len() < 0x1000 {
		buf.WriteByte(0)
	}

	return buf.Bytes()
}

func createELFWithGOTSection(t *testing.T, gotData []byte, gotAddr uint64) *elf.File {
	t.Helper()

	buf := new(bytes.Buffer)

	shstrtabContent := []byte("\x00.got\x00.shstrtab\x00")
	gotNameIdx := uint32(1)
	shstrtabNameIdx := uint32(6)

	ehdrSize := 64
	shentSize := 64
	shnum := 3
	shoff := ehdrSize
	sectionDataStart := ehdrSize + shentSize*shnum

	gotOffset := sectionDataStart
	shstrtabOffset := gotOffset + len(gotData)

	buf.Write([]byte{0x7f, 'E', 'L', 'F'})
	buf.WriteByte(2)
	buf.WriteByte(1)
	buf.WriteByte(1)
	buf.Write(make([]byte, 9))

	_ = binary.Write(buf, binary.LittleEndian, uint16(elf.ET_DYN))
	_ = binary.Write(buf, binary.LittleEndian, uint16(elf.EM_X86_64))
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(buf, binary.LittleEndian, uint64(0x400000))
	_ = binary.Write(buf, binary.LittleEndian, uint64(0))
	_ = binary.Write(buf, binary.LittleEndian, uint64(shoff))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, uint16(64))
	_ = binary.Write(buf, binary.LittleEndian, uint16(56))
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(buf, binary.LittleEndian, uint16(shentSize))
	_ = binary.Write(buf, binary.LittleEndian, uint16(shnum))
	_ = binary.Write(buf, binary.LittleEndian, uint16(2))

	writeGOTShdr64(buf, 0, uint32(elf.SHT_NULL), 0, 0, 0)
	writeGOTShdr64(buf, gotNameIdx, uint32(elf.SHT_PROGBITS), gotAddr, uint64(gotOffset), uint64(len(gotData)))
	writeGOTShdr64(buf, shstrtabNameIdx, uint32(elf.SHT_STRTAB), 0, uint64(shstrtabOffset), uint64(len(shstrtabContent)))

	buf.Write(gotData)
	buf.Write(shstrtabContent)

	elfFile, err := elf.NewFile(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("failed to create elf with .got section: %v", err)
	}

	return elfFile
}

func writeGOTShdr64(buf *bytes.Buffer, nameIdx, shType uint32, addr, offset, size uint64) {
	_ = binary.Write(buf, binary.LittleEndian, nameIdx)
	_ = binary.Write(buf, binary.LittleEndian, shType)
	_ = binary.Write(buf, binary.LittleEndian, uint64(0))
	_ = binary.Write(buf, binary.LittleEndian, addr)
	_ = binary.Write(buf, binary.LittleEndian, offset)
	_ = binary.Write(buf, binary.LittleEndian, size)
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, uint64(0))
	_ = binary.Write(buf, binary.LittleEndian, uint64(0))
}

func createELFWithNamedSection(t *testing.T, name string, data []byte, addr uint64) *elf.File {
	t.Helper()

	buf := new(bytes.Buffer)

	shstrtab := []byte("\x00")
	nameIdx := uint32(len(shstrtab))
	shstrtab = append(shstrtab, []byte(name)...)
	shstrtab = append(shstrtab, 0)
	shstrtabNameIdx := uint32(len(shstrtab))
	shstrtab = append(shstrtab, []byte(".shstrtab")...)
	shstrtab = append(shstrtab, 0)

	ehdrSize := 64
	shentSize := 64
	shnum := 3
	shoff := ehdrSize
	sectionDataStart := ehdrSize + shentSize*shnum

	dataOffset := sectionDataStart
	shstrtabOffset := dataOffset + len(data)

	buf.Write([]byte{0x7f, 'E', 'L', 'F'})
	buf.WriteByte(2)
	buf.WriteByte(1)
	buf.WriteByte(1)
	buf.Write(make([]byte, 9))

	_ = binary.Write(buf, binary.LittleEndian, uint16(elf.ET_DYN))
	_ = binary.Write(buf, binary.LittleEndian, uint16(elf.EM_X86_64))
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(buf, binary.LittleEndian, uint64(0x400000))
	_ = binary.Write(buf, binary.LittleEndian, uint64(0))
	_ = binary.Write(buf, binary.LittleEndian, uint64(shoff))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, uint16(64))
	_ = binary.Write(buf, binary.LittleEndian, uint16(56))
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(buf, binary.LittleEndian, uint16(shentSize))
	_ = binary.Write(buf, binary.LittleEndian, uint16(shnum))
	_ = binary.Write(buf, binary.LittleEndian, uint16(2))

	writeGOTShdr64(buf, 0, uint32(elf.SHT_NULL), 0, 0, 0)
	writeGOTShdr64(buf, nameIdx, uint32(elf.SHT_PROGBITS), addr, uint64(dataOffset), uint64(len(data)))
	writeGOTShdr64(buf, shstrtabNameIdx, uint32(elf.SHT_STRTAB), 0, uint64(shstrtabOffset), uint64(len(shstrtab)))

	buf.Write(data)
	buf.Write(shstrtab)

	elfFile, err := elf.NewFile(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("failed to create elf with %s section: %v", name, err)
	}

	return elfFile
}

func TestProcessELFPLTSection_WithEntries(t *testing.T) {
	parser := NewStandardLibParser()

	pltData := []byte{
		0xff, 0x35, 0x02, 0x10, 0x20, 0x00,
		0xff, 0x25, 0x04, 0x10, 0x20, 0x00,
		0x0f, 0x1f, 0x40, 0x00,
		0xff, 0x25, 0x02, 0x10, 0x20, 0x00,
		0x68, 0x00, 0x00, 0x00, 0x00,
		0xe9, 0xe0, 0xff, 0xff, 0xff,
	}

	elfFile := createELFWithNamedSection(t, ".plt", pltData, 0x400400)

	info := &BinaryInfo{
		Format:        BinaryFormatELF,
		Architecture:  ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(),
		elfFile:       elfFile,
		Relocations: []*Relocation{
			{Address: 0x601018, Symbol: "printf", Type: RelocationTypeJumpSlot},
		},
	}

	info.GroundTruthDB.GOTPLT[0x601018] = 0x400500

	var pltSection *elf.Section
	for _, s := range elfFile.Sections {
		if s.Name == ".plt" {
			pltSection = s
			break
		}
	}
	if pltSection == nil {
		t.Fatal(".plt section not found")
	}

	pltEntries := make(map[Address]*PLTEntry)
	err := parser.processELFPLTSection(info, pltSection, pltEntries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(pltEntries) != 1 {
		t.Errorf("expected 1 plt entry (skipping resolver), got %d", len(pltEntries))
	}
}

func TestProcessELFPLTSection_UnsupportedArch(t *testing.T) {
	parser := NewStandardLibParser()

	pltData := make([]byte, 32)
	elfFile := createELFWithNamedSection(t, ".plt", pltData, 0x400400)

	info := &BinaryInfo{
		Format:        BinaryFormatELF,
		Architecture:  ArchitectureMIPS,
		GroundTruthDB: NewGroundTruthDatabase(),
		elfFile:       elfFile,
	}

	var pltSection *elf.Section
	for _, s := range elfFile.Sections {
		if s.Name == ".plt" {
			pltSection = s
			break
		}
	}
	if pltSection == nil {
		t.Fatal(".plt section not found")
	}

	pltEntries := make(map[Address]*PLTEntry)
	err := parser.processELFPLTSection(info, pltSection, pltEntries)
	if err == nil {
		t.Fatal("expected error for unsupported architecture")
	}
}

func TestParseELFPLTGotSection(t *testing.T) {
	parser := NewStandardLibParser()

	entry := []byte{
		0xff, 0x25, 0x10, 0x20, 0x00, 0x00,
		0x66, 0x90,
	}

	elfFile := createELFWithNamedSection(t, ".plt.got", entry, 0x400500)

	info := &BinaryInfo{
		Format:        BinaryFormatELF,
		Architecture:  ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(),
		elfFile:       elfFile,
		Relocations: []*Relocation{
			{Address: Address(0x400500 + 6 + 0x2010), Symbol: "puts", Type: RelocationTypeGlobDat},
		},
	}

	var pltGotSection *elf.Section
	for _, s := range elfFile.Sections {
		if s.Name == ".plt.got" {
			pltGotSection = s
			break
		}
	}
	if pltGotSection == nil {
		t.Fatal(".plt.got section not found")
	}

	pltEntries := make(map[Address]*PLTEntry)
	err := parser.parseELFPLTGotSection(info, pltGotSection, pltEntries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(pltEntries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(pltEntries))
	}
}

func TestFindELFGOTSections(t *testing.T) {
	parser := NewStandardLibParser()

	elfFile := createMinimalELFFile(t)

	got, gotPlt := parser.findELFGOTSections(elfFile)
	if got != nil {
		t.Error("expected nil .got section for minimal elf")
	}
	if gotPlt != nil {
		t.Error("expected nil .got.plt section for minimal elf")
	}
}

func TestFindELFPLTSections(t *testing.T) {
	parser := NewStandardLibParser()

	elfFile := createMinimalELFFile(t)

	plt, pltGot := parser.findELFPLTSections(elfFile)
	if plt != nil {
		t.Error("expected nil .plt section for minimal elf")
	}
	if pltGot != nil {
		t.Error("expected nil .plt.got section for minimal elf")
	}
}

func TestGetPLTEntrySize(t *testing.T) {
	parser := NewStandardLibParser()

	tests := []struct {
		arch     Architecture
		expected int
		wantErr  bool
	}{
		{ArchitectureX86_64, 16, false},
		{ArchitectureX86, 16, false},
		{ArchitectureARM64, 16, false},
		{ArchitectureARM, 12, false},
		{ArchitectureMIPS, 0, true},
		{ArchitecturePPC, 0, true},
		{ArchitectureRISCV, 0, true},
		{ArchitectureUnknown, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.arch.String(), func(t *testing.T) {
			size, err := parser.getPLTEntrySize(tt.arch)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if size != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, size)
			}
		})
	}
}

func TestResolveELFGOT_WithGOTSections(t *testing.T) {
	parser := NewStandardLibParser()

	gotData := make([]byte, 16)
	binary.LittleEndian.PutUint64(gotData[0:8], 0x400500)
	binary.LittleEndian.PutUint64(gotData[8:16], 0x400600)

	elfFile := createELFWithTwoSections(t, ".got", gotData, 0x601000, ".got.plt", gotData, 0x602000)

	info := &BinaryInfo{
		Format:        BinaryFormatELF,
		Architecture:  ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(),
		elfFile:       elfFile,
		Relocations:   []*Relocation{},
	}

	entries, err := parser.resolveELFGOT(info, make(map[Address]*GOTEntry))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) < 2 {
		t.Errorf("expected at least 2 entries, got %d", len(entries))
	}
}

func TestResolveELFPLT_WithPLTSections(t *testing.T) {
	parser := NewStandardLibParser()

	pltData := []byte{
		0xff, 0x35, 0x02, 0x10, 0x20, 0x00,
		0xff, 0x25, 0x04, 0x10, 0x20, 0x00,
		0x0f, 0x1f, 0x40, 0x00,
		0xff, 0x25, 0x02, 0x10, 0x20, 0x00,
		0x68, 0x00, 0x00, 0x00, 0x00,
		0xe9, 0xe0, 0xff, 0xff, 0xff,
	}

	pltGotEntry := []byte{
		0xff, 0x25, 0x10, 0x20, 0x00, 0x00,
		0x66, 0x90,
	}

	elfFile := createELFWithTwoSections(t, ".plt", pltData, 0x400400, ".plt.got", pltGotEntry, 0x400500)

	info := &BinaryInfo{
		Format:        BinaryFormatELF,
		Architecture:  ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(),
		elfFile:       elfFile,
		Relocations:   []*Relocation{},
	}

	entries, err := parser.resolveELFPLT(info, make(map[Address]*PLTEntry))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) < 1 {
		t.Errorf("expected at least 1 entry, got %d", len(entries))
	}
}

func createELFWithTwoSections(t *testing.T, name1 string, data1 []byte, addr1 uint64, name2 string, data2 []byte, addr2 uint64) *elf.File {
	t.Helper()

	buf := new(bytes.Buffer)

	shstrtab := []byte("\x00")
	name1Idx := uint32(len(shstrtab))
	shstrtab = append(shstrtab, []byte(name1)...)
	shstrtab = append(shstrtab, 0)
	name2Idx := uint32(len(shstrtab))
	shstrtab = append(shstrtab, []byte(name2)...)
	shstrtab = append(shstrtab, 0)
	shstrtabNameIdx := uint32(len(shstrtab))
	shstrtab = append(shstrtab, []byte(".shstrtab")...)
	shstrtab = append(shstrtab, 0)

	ehdrSize := 64
	shentSize := 64
	shnum := 4
	shoff := ehdrSize
	sectionDataStart := ehdrSize + shentSize*shnum

	data1Offset := sectionDataStart
	data2Offset := data1Offset + len(data1)
	shstrtabOffset := data2Offset + len(data2)

	buf.Write([]byte{0x7f, 'E', 'L', 'F'})
	buf.WriteByte(2)
	buf.WriteByte(1)
	buf.WriteByte(1)
	buf.Write(make([]byte, 9))

	_ = binary.Write(buf, binary.LittleEndian, uint16(elf.ET_DYN))
	_ = binary.Write(buf, binary.LittleEndian, uint16(elf.EM_X86_64))
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(buf, binary.LittleEndian, uint64(0x400000))
	_ = binary.Write(buf, binary.LittleEndian, uint64(0))
	_ = binary.Write(buf, binary.LittleEndian, uint64(shoff))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, uint16(64))
	_ = binary.Write(buf, binary.LittleEndian, uint16(56))
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(buf, binary.LittleEndian, uint16(shentSize))
	_ = binary.Write(buf, binary.LittleEndian, uint16(shnum))
	_ = binary.Write(buf, binary.LittleEndian, uint16(3))

	writeGOTShdr64(buf, 0, uint32(elf.SHT_NULL), 0, 0, 0)
	writeGOTShdr64(buf, name1Idx, uint32(elf.SHT_PROGBITS), addr1, uint64(data1Offset), uint64(len(data1)))
	writeGOTShdr64(buf, name2Idx, uint32(elf.SHT_PROGBITS), addr2, uint64(data2Offset), uint64(len(data2)))
	writeGOTShdr64(buf, shstrtabNameIdx, uint32(elf.SHT_STRTAB), 0, uint64(shstrtabOffset), uint64(len(shstrtab)))

	buf.Write(data1)
	buf.Write(data2)
	buf.Write(shstrtab)

	elfFile, err := elf.NewFile(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("failed to create elf with sections %s and %s: %v", name1, name2, err)
	}

	return elfFile
}
