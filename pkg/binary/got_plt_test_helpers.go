package binfmt

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"
)

const (
	testSymbolPrintf = "printf"
	testSymbolMalloc = "malloc"
)

// writeELFHeader writes a minimal elf64 header to buffer.
func writeELFHeader(buf *bytes.Buffer, elfType elf.Type) {
	// elf header
	buf.Write([]byte{0x7f, 'E', 'L', 'F'}) // magic
	buf.WriteByte(2)                       // 64-bit
	buf.WriteByte(1)                       // little endian
	buf.WriteByte(1)                       // elf version
	buf.Write(make([]byte, 9))             // padding

	// write minimal elf64 header
	_ = binary.Write(buf, binary.LittleEndian, uint16(elfType))       // type
	_ = binary.Write(buf, binary.LittleEndian, uint16(elf.EM_X86_64)) // machine
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))             // version
	_ = binary.Write(buf, binary.LittleEndian, uint64(0x400000))      // entry
	_ = binary.Write(buf, binary.LittleEndian, uint64(64))            // phoff
	_ = binary.Write(buf, binary.LittleEndian, uint64(0))             // shoff
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))             // flags
	_ = binary.Write(buf, binary.LittleEndian, uint16(64))            // ehsize
	_ = binary.Write(buf, binary.LittleEndian, uint16(56))            // phentsize
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))             // phnum
	_ = binary.Write(buf, binary.LittleEndian, uint16(64))            // shentsize
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))             // shnum
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))             // shstrndx
}

// createMinimalELFFile creates a minimal valid elf file for testing.
func createMinimalELFFile(t *testing.T) *elf.File {
	t.Helper()
	buf := new(bytes.Buffer)
	writeELFHeader(buf, elf.ET_DYN)

	elfFile, err := elf.NewFile(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("failed to create minimal elf: %v", err)
	}

	return elfFile
}

// createELFWithPTLoad creates an elf file with pt_load segment.
func createELFWithPTLoad(t *testing.T, vaddr uint64) *elf.File {
	t.Helper()

	buf := new(bytes.Buffer)

	// elf header
	buf.Write([]byte{0x7f, 'E', 'L', 'F'})
	buf.WriteByte(2)
	buf.WriteByte(1)
	buf.WriteByte(1)
	buf.Write(make([]byte, 9))

	_ = binary.Write(buf, binary.LittleEndian, uint16(elf.ET_DYN))
	_ = binary.Write(buf, binary.LittleEndian, uint16(elf.EM_X86_64))
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))
	_ = binary.Write(buf, binary.LittleEndian, vaddr)
	_ = binary.Write(buf, binary.LittleEndian, uint64(64)) // phoff
	_ = binary.Write(buf, binary.LittleEndian, uint64(0))  // shoff
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(buf, binary.LittleEndian, uint16(64))
	_ = binary.Write(buf, binary.LittleEndian, uint16(56))
	_ = binary.Write(buf, binary.LittleEndian, uint16(1)) // phnum
	_ = binary.Write(buf, binary.LittleEndian, uint16(64))
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))

	// program header (pt_load)
	_ = binary.Write(buf, binary.LittleEndian, uint32(elf.PT_LOAD)) // type
	_ = binary.Write(buf, binary.LittleEndian, uint32(5))           // flags (r-x)
	_ = binary.Write(buf, binary.LittleEndian, uint64(0))           // offset
	_ = binary.Write(buf, binary.LittleEndian, vaddr)               // vaddr
	_ = binary.Write(buf, binary.LittleEndian, vaddr)               // paddr
	_ = binary.Write(buf, binary.LittleEndian, uint64(0x1000))      // filesz
	_ = binary.Write(buf, binary.LittleEndian, uint64(0x1000))      // memsz
	_ = binary.Write(buf, binary.LittleEndian, uint64(0x1000))      // align

	elfFile, err := elf.NewFile(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("failed to create elf with pt_load: %v", err)
	}

	return elfFile
}

// createNonPIEELF creates a non-pie elf file (et_exec).
func createNonPIEELF(t *testing.T) *elf.File {
	t.Helper()
	buf := new(bytes.Buffer)
	writeELFHeader(buf, elf.ET_EXEC)

	elfFile, err := elf.NewFile(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("failed to create non-pie elf: %v", err)
	}

	return elfFile
}
