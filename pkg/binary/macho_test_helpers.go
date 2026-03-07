package binfmt

import (
	"bytes"
	"encoding/binary"
)

// writeMachO64HeaderWithSegment writes a minimal Mach-O 64-bit header with one segment.
func writeMachO64HeaderWithSegment(buf *bytes.Buffer, ncmds, sizeofcmds uint32) {
	// mach header 64
	_ = binary.Write(buf, binary.LittleEndian, uint32(0xFEEDFACF)) // magic
	_ = binary.Write(buf, binary.LittleEndian, uint32(0x01000007)) // cpu type: x86_64
	_ = binary.Write(buf, binary.LittleEndian, uint32(3))          // cpu subtype
	_ = binary.Write(buf, binary.LittleEndian, uint32(2))          // file type: MH_EXECUTE
	_ = binary.Write(buf, binary.LittleEndian, ncmds)              // number of load commands
	_ = binary.Write(buf, binary.LittleEndian, sizeofcmds)         // size of load commands
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))          // flags
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))          // reserved
}

// writeSegmentCommand64 writes a LC_SEGMENT_64 command with one section.
func writeSegmentCommand64(buf *bytes.Buffer, segname string, vmaddr, vmsize, fileoff, filesize uint64, nsects uint32) {
	// segment command 64 (LC_SEGMENT_64 = 0x19)
	_ = binary.Write(buf, binary.LittleEndian, uint32(0x19)) // cmd
	_ = binary.Write(buf, binary.LittleEndian, uint32(152))  // cmdsize
	buf.WriteString(segname)                                 // segname
	buf.Write(make([]byte, 16-len(segname)))                 // padding
	_ = binary.Write(buf, binary.LittleEndian, vmaddr)       // vmaddr
	_ = binary.Write(buf, binary.LittleEndian, vmsize)       // vmsize
	_ = binary.Write(buf, binary.LittleEndian, fileoff)      // fileoff
	_ = binary.Write(buf, binary.LittleEndian, filesize)     // filesize
	_ = binary.Write(buf, binary.LittleEndian, uint32(7))    // maxprot
	_ = binary.Write(buf, binary.LittleEndian, uint32(5))    // initprot
	_ = binary.Write(buf, binary.LittleEndian, nsects)       // nsects
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))    // flags
}

// writeSection64 writes a section_64 structure.
func writeSection64(buf *bytes.Buffer, sectname, segname string, addr, size uint64, offset, align uint32) {
	buf.WriteString(sectname)                                      // sectname
	buf.Write(make([]byte, 16-len(sectname)))                      // padding
	buf.WriteString(segname)                                       // segname
	buf.Write(make([]byte, 16-len(segname)))                       // padding
	_ = binary.Write(buf, binary.LittleEndian, addr)               // addr
	_ = binary.Write(buf, binary.LittleEndian, size)               // size
	_ = binary.Write(buf, binary.LittleEndian, offset)             // offset
	_ = binary.Write(buf, binary.LittleEndian, align)              // align
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))          // reloff
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))          // nreloc
	_ = binary.Write(buf, binary.LittleEndian, uint32(0x80000400)) // flags (S_ATTR_PURE_INSTRUCTIONS)
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))          // reserved1
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))          // reserved2
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))          // reserved3
}
