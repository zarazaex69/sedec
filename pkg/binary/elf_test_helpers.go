package binfmt

import (
	"bytes"
	"encoding/binary"
)

// writeELF64Header writes a minimal 64-bit ELF header to buffer.
func writeELF64Header(buf *bytes.Buffer, endian binary.ByteOrder, machine uint16, entry uint64) {
	// elf magic and identification
	buf.Write([]byte{0x7F, 'E', 'L', 'F'}) // magic
	buf.WriteByte(2)                       // 64-bit
	if endian == binary.LittleEndian {
		buf.WriteByte(1) // little endian
	} else {
		buf.WriteByte(2) // big endian
	}
	buf.WriteByte(1)           // elf version
	buf.WriteByte(0)           // system v abi
	buf.Write(make([]byte, 8)) // padding

	// elf header fields
	_ = binary.Write(buf, endian, uint16(2))  // e_type: ET_EXEC
	_ = binary.Write(buf, endian, machine)    // e_machine
	_ = binary.Write(buf, endian, uint32(1))  // e_version
	_ = binary.Write(buf, endian, entry)      // e_entry
	_ = binary.Write(buf, endian, uint64(64)) // e_phoff
	_ = binary.Write(buf, endian, uint64(0))  // e_shoff
	_ = binary.Write(buf, endian, uint32(0))  // e_flags
	_ = binary.Write(buf, endian, uint16(64)) // e_ehsize
	_ = binary.Write(buf, endian, uint16(56)) // e_phentsize
	_ = binary.Write(buf, endian, uint16(0))  // e_phnum
	_ = binary.Write(buf, endian, uint16(64)) // e_shentsize
	_ = binary.Write(buf, endian, uint16(0))  // e_shnum
	_ = binary.Write(buf, endian, uint16(0))  // e_shstrndx
}

// writeELF32Header writes a minimal 32-bit ELF header to buffer.
func writeELF32Header(buf *bytes.Buffer, machine uint16, entry uint32) {
	// elf magic and identification
	buf.Write([]byte{0x7F, 'E', 'L', 'F'}) // magic
	buf.WriteByte(1)                       // 32-bit
	buf.WriteByte(1)                       // little endian
	buf.WriteByte(1)                       // elf version
	buf.WriteByte(0)                       // system v abi
	buf.Write(make([]byte, 8))             // padding

	// elf header fields
	_ = binary.Write(buf, binary.LittleEndian, uint16(2))  // e_type: ET_EXEC
	_ = binary.Write(buf, binary.LittleEndian, machine)    // e_machine
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))  // e_version
	_ = binary.Write(buf, binary.LittleEndian, entry)      // e_entry
	_ = binary.Write(buf, binary.LittleEndian, uint32(52)) // e_phoff
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))  // e_shoff
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))  // e_flags
	_ = binary.Write(buf, binary.LittleEndian, uint16(52)) // e_ehsize
	_ = binary.Write(buf, binary.LittleEndian, uint16(32)) // e_phentsize
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))  // e_phnum
	_ = binary.Write(buf, binary.LittleEndian, uint16(40)) // e_shentsize
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))  // e_shnum
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))  // e_shstrndx
}
