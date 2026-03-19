package binfmt

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func appendStr(base []byte, s string) []byte {
	return append(base, []byte(s)...)
}

func buildELF64WithRELA(endian binary.ByteOrder) []byte {
	var buf bytes.Buffer

	strtab := appendStr([]byte{0}, ".rela.dyn\x00.strtab\x00.dynsym\x00.dynstr\x00")
	dynstrData := appendStr([]byte{0}, "puts\x00printf\x00")

	relaName := uint32(1)
	strtabName := uint32(11)
	dynsymName := uint32(19)
	dynstrName := uint32(27)

	var dynsymData bytes.Buffer
	dynsymData.Write(make([]byte, 24))
	writeDynsym64(&dynsymData, endian, 1, 0x12)
	writeDynsym64(&dynsymData, endian, 6, 0x12)

	var relaData bytes.Buffer
	writeRela64(&relaData, endian, 0x601000, 1, 7, 0)
	writeRela64(&relaData, endian, 0x601008, 2, 7, 0)

	dataStart := uint64(64)
	strtabOff := dataStart
	strtabSize := uint64(len(strtab))
	dynstrOff := strtabOff + strtabSize
	dynstrSize := uint64(len(dynstrData))
	dynsymOff := dynstrOff + dynstrSize
	dynsymSize := uint64(dynsymData.Len())
	relaOff := dynsymOff + dynsymSize
	relaSize := uint64(relaData.Len())
	shoff := relaOff + relaSize

	writeELF64Hdr(&buf, endian, 0x3E, 0x400000, shoff, 5, 1)

	buf.Write(strtab)
	buf.Write(dynstrData)
	buf.Write(dynsymData.Bytes())
	buf.Write(relaData.Bytes())

	writeShdr64(&buf, endian, 0, 0, 0, 0, 0, 0, 0)
	writeShdr64(&buf, endian, strtabName, 3, strtabOff, strtabSize, 0, 0, 1)
	writeShdr64(&buf, endian, dynstrName, 3, dynstrOff, dynstrSize, 0, 0, 1)
	writeShdr64(&buf, endian, dynsymName, 11, dynsymOff, dynsymSize, 2, 1, 8)
	writeShdr64(&buf, endian, relaName, 4, relaOff, relaSize, 3, 0, 8)

	return buf.Bytes()
}

func buildELF64WithREL(endian binary.ByteOrder) []byte {
	var buf bytes.Buffer

	strtab := appendStr([]byte{0}, ".rel.dyn\x00.strtab\x00.dynsym\x00.dynstr\x00")
	dynstrData := appendStr([]byte{0}, "malloc\x00free\x00")

	relName := uint32(1)
	strtabName := uint32(10)
	dynsymName := uint32(18)
	dynstrName := uint32(26)

	var dynsymData bytes.Buffer
	dynsymData.Write(make([]byte, 24))
	writeDynsym64(&dynsymData, endian, 1, 0x12)
	writeDynsym64(&dynsymData, endian, 8, 0x12)

	var relData bytes.Buffer
	writeRel64(&relData, endian, 0x601020, 1, 6)
	writeRel64(&relData, endian, 0x601028, 2, 6)

	dataStart := uint64(64)
	strtabOff := dataStart
	strtabSize := uint64(len(strtab))
	dynstrOff := strtabOff + strtabSize
	dynstrSize := uint64(len(dynstrData))
	dynsymOff := dynstrOff + dynstrSize
	dynsymSize := uint64(dynsymData.Len())
	relOff := dynsymOff + dynsymSize
	relSize := uint64(relData.Len())
	shoff := relOff + relSize

	writeELF64Hdr(&buf, endian, 0x3E, 0x400000, shoff, 5, 1)

	buf.Write(strtab)
	buf.Write(dynstrData)
	buf.Write(dynsymData.Bytes())
	buf.Write(relData.Bytes())

	writeShdr64(&buf, endian, 0, 0, 0, 0, 0, 0, 0)
	writeShdr64(&buf, endian, strtabName, 3, strtabOff, strtabSize, 0, 0, 1)
	writeShdr64(&buf, endian, dynstrName, 3, dynstrOff, dynstrSize, 0, 0, 1)
	writeShdr64(&buf, endian, dynsymName, 11, dynsymOff, dynsymSize, 2, 1, 8)
	writeShdr64(&buf, endian, relName, 9, relOff, relSize, 3, 0, 8)

	return buf.Bytes()
}

func buildELF32WithRELA() []byte {
	var buf bytes.Buffer
	endian := binary.LittleEndian

	strtab := appendStr([]byte{0}, ".rela.dyn\x00.strtab\x00.dynsym\x00.dynstr\x00")
	dynstrData := appendStr([]byte{0}, "exit\x00")

	relaName := uint32(1)
	strtabName := uint32(11)
	dynsymName := uint32(19)
	dynstrName := uint32(27)

	var dynsymData bytes.Buffer
	dynsymData.Write(make([]byte, 16))
	writeDynsym32(&dynsymData, endian, 1, 0x12)

	var relaData bytes.Buffer
	writeRela32(&relaData, endian, 0x08049000, 1, 7, 0)

	ehdrSize := uint32(52)
	strtabOff := ehdrSize
	strtabSize := uint32(len(strtab))
	dynstrOff := strtabOff + strtabSize
	dynstrSize := uint32(len(dynstrData))
	dynsymOff := dynstrOff + dynstrSize
	dynsymSize := uint32(dynsymData.Len())
	relaOff := dynsymOff + dynsymSize
	relaSize := uint32(relaData.Len())
	shoff := relaOff + relaSize

	writeELF32Hdr(&buf, 3, 0x08048000, shoff, 5, 1)

	buf.Write(strtab)
	buf.Write(dynstrData)
	buf.Write(dynsymData.Bytes())
	buf.Write(relaData.Bytes())

	writeShdr32(&buf, endian, 0, 0, 0, 0, 0, 0, 0)
	writeShdr32(&buf, endian, strtabName, 3, strtabOff, strtabSize, 0, 0, 1)
	writeShdr32(&buf, endian, dynstrName, 3, dynstrOff, dynstrSize, 0, 0, 1)
	writeShdr32(&buf, endian, dynsymName, 11, dynsymOff, dynsymSize, 2, 1, 4)
	writeShdr32(&buf, endian, relaName, 4, relaOff, relaSize, 3, 0, 4)

	return buf.Bytes()
}

func buildELF32WithREL() []byte {
	var buf bytes.Buffer
	endian := binary.LittleEndian

	strtab := appendStr([]byte{0}, ".rel.dyn\x00.strtab\x00.dynsym\x00.dynstr\x00")
	dynstrData := appendStr([]byte{0}, "write\x00")

	relName := uint32(1)
	strtabName := uint32(10)
	dynsymName := uint32(18)
	dynstrName := uint32(26)

	var dynsymData bytes.Buffer
	dynsymData.Write(make([]byte, 16))
	writeDynsym32(&dynsymData, endian, 1, 0x12)

	var relData bytes.Buffer
	writeRel32(&relData, endian, 0x08049010, 1, 7)

	ehdrSize := uint32(52)
	strtabOff := ehdrSize
	strtabSize := uint32(len(strtab))
	dynstrOff := strtabOff + strtabSize
	dynstrSize := uint32(len(dynstrData))
	dynsymOff := dynstrOff + dynstrSize
	dynsymSize := uint32(dynsymData.Len())
	relOff := dynsymOff + dynsymSize
	relSize := uint32(relData.Len())
	shoff := relOff + relSize

	writeELF32Hdr(&buf, 3, 0x08048000, shoff, 5, 1)

	buf.Write(strtab)
	buf.Write(dynstrData)
	buf.Write(dynsymData.Bytes())
	buf.Write(relData.Bytes())

	writeShdr32(&buf, endian, 0, 0, 0, 0, 0, 0, 0)
	writeShdr32(&buf, endian, strtabName, 3, strtabOff, strtabSize, 0, 0, 1)
	writeShdr32(&buf, endian, dynstrName, 3, dynstrOff, dynstrSize, 0, 0, 1)
	writeShdr32(&buf, endian, dynsymName, 11, dynsymOff, dynsymSize, 2, 1, 4)
	writeShdr32(&buf, endian, relName, 9, relOff, relSize, 3, 0, 4)

	return buf.Bytes()
}

func writeELF64Hdr(buf *bytes.Buffer, endian binary.ByteOrder, machine uint16, entry, shoff uint64, shnum, shstrndx uint16) {
	buf.Write([]byte{0x7F, 'E', 'L', 'F'})
	buf.WriteByte(2)
	if endian == binary.LittleEndian {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(2)
	}
	buf.WriteByte(1)
	buf.WriteByte(0)
	buf.Write(make([]byte, 8))
	_ = binary.Write(buf, endian, uint16(2))
	_ = binary.Write(buf, endian, machine)
	_ = binary.Write(buf, endian, uint32(1))
	_ = binary.Write(buf, endian, entry)
	_ = binary.Write(buf, endian, uint64(0))
	_ = binary.Write(buf, endian, shoff)
	_ = binary.Write(buf, endian, uint32(0))
	_ = binary.Write(buf, endian, uint16(64))
	_ = binary.Write(buf, endian, uint16(56))
	_ = binary.Write(buf, endian, uint16(0))
	_ = binary.Write(buf, endian, uint16(64))
	_ = binary.Write(buf, endian, shnum)
	_ = binary.Write(buf, endian, shstrndx)
}

func writeELF32Hdr(buf *bytes.Buffer, machine uint16, entry, shoff uint32, shnum, shstrndx uint16) {
	endian := binary.LittleEndian
	buf.Write([]byte{0x7F, 'E', 'L', 'F'})
	buf.WriteByte(1)
	buf.WriteByte(1)
	buf.WriteByte(1)
	buf.WriteByte(0)
	buf.Write(make([]byte, 8))
	_ = binary.Write(buf, endian, uint16(2))
	_ = binary.Write(buf, endian, machine)
	_ = binary.Write(buf, endian, uint32(1))
	_ = binary.Write(buf, endian, entry)
	_ = binary.Write(buf, endian, uint32(0))
	_ = binary.Write(buf, endian, shoff)
	_ = binary.Write(buf, endian, uint32(0))
	_ = binary.Write(buf, endian, uint16(52))
	_ = binary.Write(buf, endian, uint16(32))
	_ = binary.Write(buf, endian, uint16(0))
	_ = binary.Write(buf, endian, uint16(40))
	_ = binary.Write(buf, endian, shnum)
	_ = binary.Write(buf, endian, shstrndx)
}

func writeDynsym64(buf *bytes.Buffer, endian binary.ByteOrder, nameIdx uint32, info uint8) { //nolint:unparam
	_ = binary.Write(buf, endian, nameIdx)
	buf.WriteByte(info)
	buf.WriteByte(0)
	_ = binary.Write(buf, endian, uint16(0))
	_ = binary.Write(buf, endian, uint64(0))
	_ = binary.Write(buf, endian, uint64(0))
}

func writeDynsym32(buf *bytes.Buffer, endian binary.ByteOrder, nameIdx uint32, info uint8) {
	_ = binary.Write(buf, endian, nameIdx)
	_ = binary.Write(buf, endian, uint32(0))
	_ = binary.Write(buf, endian, uint32(0))
	buf.WriteByte(info)
	buf.WriteByte(0)
	_ = binary.Write(buf, endian, uint16(0))
}

func writeRela64(buf *bytes.Buffer, endian binary.ByteOrder, offset uint64, symIdx, relocType uint32, addend int64) {
	_ = binary.Write(buf, endian, offset)
	_ = binary.Write(buf, endian, (uint64(symIdx)<<32)|uint64(relocType))
	_ = binary.Write(buf, endian, addend)
}

func writeRel64(buf *bytes.Buffer, endian binary.ByteOrder, offset uint64, symIdx, relocType uint32) {
	_ = binary.Write(buf, endian, offset)
	_ = binary.Write(buf, endian, (uint64(symIdx)<<32)|uint64(relocType))
}

func writeRela32(buf *bytes.Buffer, endian binary.ByteOrder, offset uint32, symIdx, relocType uint8, addend int32) {
	_ = binary.Write(buf, endian, offset)
	_ = binary.Write(buf, endian, (uint32(symIdx)<<8)|uint32(relocType))
	_ = binary.Write(buf, endian, addend)
}

func writeRel32(buf *bytes.Buffer, endian binary.ByteOrder, offset uint32, symIdx, relocType uint8) {
	_ = binary.Write(buf, endian, offset)
	_ = binary.Write(buf, endian, (uint32(symIdx)<<8)|uint32(relocType))
}

func writeShdr64(buf *bytes.Buffer, endian binary.ByteOrder, name, shtype uint32, offset, size uint64, link, info uint32, entsize uint64) {
	_ = binary.Write(buf, endian, name)
	_ = binary.Write(buf, endian, shtype)
	_ = binary.Write(buf, endian, uint64(0))
	_ = binary.Write(buf, endian, uint64(0))
	_ = binary.Write(buf, endian, offset)
	_ = binary.Write(buf, endian, size)
	_ = binary.Write(buf, endian, link)
	_ = binary.Write(buf, endian, info)
	_ = binary.Write(buf, endian, uint64(0))
	_ = binary.Write(buf, endian, entsize)
}

func writeShdr32(buf *bytes.Buffer, endian binary.ByteOrder, name, shtype, offset, size, link, info, entsize uint32) {
	_ = binary.Write(buf, endian, name)
	_ = binary.Write(buf, endian, shtype)
	_ = binary.Write(buf, endian, uint32(0))
	_ = binary.Write(buf, endian, uint32(0))
	_ = binary.Write(buf, endian, offset)
	_ = binary.Write(buf, endian, size)
	_ = binary.Write(buf, endian, link)
	_ = binary.Write(buf, endian, info)
	_ = binary.Write(buf, endian, uint32(0))
	_ = binary.Write(buf, endian, entsize)
}

func TestSyntheticELF64RELA(t *testing.T) {
	data := buildELF64WithRELA(binary.LittleEndian)
	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() { _ = info.Close() }()

	if info.Format != BinaryFormatELF {
		t.Fatalf("Format = %v, want ELF", info.Format)
	}
	if len(info.Relocations) != 2 {
		t.Fatalf("got %d relocations, want 2", len(info.Relocations))
	}

	r0 := info.Relocations[0]
	if r0.Address != 0x601000 {
		t.Errorf("reloc[0].Address = %#x, want 0x601000", r0.Address)
	}
	if r0.Type != RelocationTypeJumpSlot {
		t.Errorf("reloc[0].Type = %v, want JumpSlot", r0.Type)
	}
	if r0.Symbol != "puts" {
		t.Errorf("reloc[0].Symbol = %q, want puts", r0.Symbol)
	}

	r1 := info.Relocations[1]
	if r1.Address != 0x601008 {
		t.Errorf("reloc[1].Address = %#x, want 0x601008", r1.Address)
	}
	if r1.Symbol != "printf" {
		t.Errorf("reloc[1].Symbol = %q, want printf", r1.Symbol)
	}
}

func TestSyntheticELF64REL(t *testing.T) {
	data := buildELF64WithREL(binary.LittleEndian)
	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() { _ = info.Close() }()

	if len(info.Relocations) != 2 {
		t.Fatalf("got %d relocations, want 2", len(info.Relocations))
	}

	r0 := info.Relocations[0]
	if r0.Address != 0x601020 {
		t.Errorf("reloc[0].Address = %#x, want 0x601020", r0.Address)
	}
	if r0.Type != RelocationTypeGlobDat {
		t.Errorf("reloc[0].Type = %v, want GlobDat", r0.Type)
	}
	if r0.Addend != 0 {
		t.Errorf("REL reloc should have zero addend, got %d", r0.Addend)
	}
}

func TestSyntheticELF64RELABigEndian(t *testing.T) {
	data := buildELF64WithRELA(binary.BigEndian)
	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() { _ = info.Close() }()

	if len(info.Relocations) != 2 {
		t.Fatalf("got %d relocations, want 2", len(info.Relocations))
	}

	r0 := info.Relocations[0]
	if r0.Address != 0x601000 {
		t.Errorf("reloc[0].Address = %#x, want 0x601000", r0.Address)
	}
	if r0.Type != RelocationTypeJumpSlot {
		t.Errorf("reloc[0].Type = %v, want JumpSlot", r0.Type)
	}
}

func TestSyntheticELF32RELA(t *testing.T) {
	data := buildELF32WithRELA()
	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() { _ = info.Close() }()

	if info.Architecture != ArchitectureX86 {
		t.Errorf("Architecture = %v, want x86", info.Architecture)
	}
	if len(info.Relocations) != 1 {
		t.Fatalf("got %d relocations, want 1", len(info.Relocations))
	}

	r0 := info.Relocations[0]
	if r0.Address != 0x08049000 {
		t.Errorf("reloc[0].Address = %#x, want 0x08049000", r0.Address)
	}
}

func TestSyntheticELF32REL(t *testing.T) {
	data := buildELF32WithREL()
	parser := NewStandardLibParser()
	info, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	defer func() { _ = info.Close() }()

	if info.Architecture != ArchitectureX86 {
		t.Errorf("Architecture = %v, want x86", info.Architecture)
	}
	if len(info.Relocations) != 1 {
		t.Fatalf("got %d relocations, want 1", len(info.Relocations))
	}

	r0 := info.Relocations[0]
	if r0.Address != 0x08049010 {
		t.Errorf("reloc[0].Address = %#x, want 0x08049010", r0.Address)
	}
	if r0.Addend != 0 {
		t.Errorf("REL reloc should have zero addend, got %d", r0.Addend)
	}
}
