package binfmt

import (
	"debug/macho"
	"encoding/binary"
)

// detectMachOArchitecture determines the architecture from Mach-O file
func (p *StandardLibParser) detectMachOArchitecture(machoFile *macho.File) Architecture {
	switch machoFile.Cpu {
	case macho.CpuAmd64:
		return ArchitectureX86_64
	case macho.Cpu386:
		return ArchitectureX86
	case macho.CpuArm64:
		return ArchitectureARM64
	case macho.CpuArm:
		return ArchitectureARM
	case macho.CpuPpc:
		return ArchitecturePPC
	case macho.CpuPpc64:
		return ArchitecturePPC64
	default:
		return ArchitectureUnknown
	}
}

// findMachOEntryPoint finds the entry point from LC_MAIN or LC_UNIXTHREAD
func (p *StandardLibParser) findMachOEntryPoint(machoFile *macho.File) Address {
	// try to find LC_MAIN command (modern mach-o)
	for _, load := range machoFile.Loads {
		if cmd, ok := load.(*macho.Segment); ok {
			// check for __TEXT segment which contains entry point
			if cmd.Name == "__TEXT" {
				// entry point is typically at start of __text section
				for _, sec := range machoFile.Sections {
					if sec.Seg == "__TEXT" && sec.Name == "__text" {
						return Address(sec.Addr)
					}
				}
			}
		}
	}

	// fallback: return 0 if not found
	return 0
}

// extractMachOSections extracts all sections from Mach-O file
func (p *StandardLibParser) extractMachOSections(machoFile *macho.File) []*Section {
	sections := make([]*Section, 0, len(machoFile.Sections))

	for _, sec := range machoFile.Sections {
		section := &Section{
			Name:    sec.Name,
			Address: Address(sec.Addr),
			Size:    sec.Size,
			Offset:  uint64(sec.Offset),
			Flags:   uint64(sec.Flags),
			Type:    sec.Flags,
		}

		// determine section properties from flags
		// mach-o section types
		sectionType := sec.Flags & 0xFF
		section.IsExecutable = (sec.Flags&0x80000000) != 0 || // S_ATTR_PURE_INSTRUCTIONS
			sectionType == 0 // S_REGULAR in __TEXT

		section.IsWritable = sec.Seg == "__DATA" || sec.Seg == "__BSS"
		section.IsAllocated = true // all mach-o sections are allocated

		// read section data if size is reasonable
		if sec.Size > 0 && sec.Size < 100*1024*1024 {
			data, err := sec.Data()
			if err == nil {
				section.Data = data
			}
		}

		sections = append(sections, section)
	}

	return sections
}

// extractMachOSymbols extracts symbols from symbol table
func (p *StandardLibParser) extractMachOSymbols(machoFile *macho.File) []*Symbol {
	symbols := make([]*Symbol, 0, 256)

	if machoFile.Symtab == nil {
		return symbols
	}

	for _, sym := range machoFile.Symtab.Syms {
		symbol := &Symbol{
			Name:    sym.Name,
			Address: Address(sym.Value),
			Type:    p.convertMachOSymbolType(sym.Type),
			Binding: SymbolBindingGlobal, // simplified
		}

		// get section name if valid section number
		if int(sym.Sect) > 0 && int(sym.Sect) <= len(machoFile.Sections) {
			symbol.Section = machoFile.Sections[sym.Sect-1].Name
		}

		symbols = append(symbols, symbol)
	}

	return symbols
}

// convertMachOSymbolType converts Mach-O symbol type to our type
func (p *StandardLibParser) convertMachOSymbolType(symType uint8) SymbolType {
	// mach-o symbol type is in lower 4 bits
	nType := symType & 0x0E

	switch nType {
	case 0x0E: // N_SECT - defined in section
		return SymbolTypeFunction
	case 0x00: // N_UNDF - undefined
		return SymbolTypeUnknown
	case 0x02: // N_ABS - absolute
		return SymbolTypeObject
	default:
		return SymbolTypeUnknown
	}
}

// extractMachORelocations extracts relocations from sections
func (p *StandardLibParser) extractMachORelocations(machoFile *macho.File) []*Relocation {
	relocations := make([]*Relocation, 0, 256)

	// iterate through sections and extract relocations
	for _, sec := range machoFile.Sections {
		if sec.Nreloc == 0 {
			continue
		}

		// read relocation entries
		// each relocation entry is 8 bytes
		relocData := make([]byte, sec.Nreloc*8)
		_, err := sec.ReadAt(relocData, int64(sec.Reloff))
		if err != nil {
			continue
		}

		// parse relocation entries
		for i := uint32(0); i < sec.Nreloc; i++ {
			offset := i * 8
			reloc := p.parseMachORelocation(relocData[offset:offset+8], machoFile, sec)
			if reloc != nil {
				relocations = append(relocations, reloc)
			}
		}
	}

	return relocations
}

// parseMachORelocation parses a single Mach-O relocation entry
func (p *StandardLibParser) parseMachORelocation(data []byte, machoFile *macho.File,
	sec *macho.Section) *Relocation {
	// parse relocation info structure
	var addr uint32
	var value uint32
	if machoFile.ByteOrder == binary.LittleEndian {
		addr = binary.LittleEndian.Uint32(data[0:4])
		value = binary.LittleEndian.Uint32(data[4:8])
	} else {
		addr = binary.BigEndian.Uint32(data[0:4])
		value = binary.BigEndian.Uint32(data[4:8])
	}

	// extract fields from value
	symnum := value & 0x00FFFFFF
	pcrel := (value & 0x01000000) != 0
	length := (value >> 25) & 3
	extern := (value & 0x08000000) != 0
	relocType := (value >> 28) & 0xF

	_ = length // used for size calculation
	_ = pcrel  // used for pc-relative relocations
	_ = extern // indicates if symbol is external

	reloc := &Relocation{
		Address:   Address(sec.Addr + uint64(addr)),
		Type:      p.convertMachORelocationType(machoFile.Cpu, relocType),
		SymbolIdx: symnum,
	}

	// resolve symbol name if available
	if machoFile.Symtab != nil && int(symnum) < len(machoFile.Symtab.Syms) {
		reloc.Symbol = machoFile.Symtab.Syms[symnum].Name
	}

	return reloc
}

// convertMachORelocationType converts Mach-O relocation type to our type
func (p *StandardLibParser) convertMachORelocationType(cpu macho.Cpu, relocType uint32) RelocationType {
	// x86_64 relocation types
	if cpu == macho.CpuAmd64 {
		switch relocType {
		case 0: // X86_64_RELOC_UNSIGNED
			return RelocationTypeAbsolute
		case 1: // X86_64_RELOC_SIGNED
			return RelocationTypeRelative
		case 2, 3: // X86_64_RELOC_BRANCH, X86_64_RELOC_GOT_LOAD
			return RelocationTypeGOT
		case 4: // X86_64_RELOC_GOT
			return RelocationTypeGOT
		}
	}

	// arm64 relocation types
	if cpu == macho.CpuArm64 {
		switch relocType {
		case 0: // ARM64_RELOC_UNSIGNED
			return RelocationTypeAbsolute
		case 1: // ARM64_RELOC_SUBTRACTOR
			return RelocationTypeRelative
		case 2, 3: // ARM64_RELOC_BRANCH26, ARM64_RELOC_PAGE21
			return RelocationTypeRelative
		case 4: // ARM64_RELOC_PAGEOFF12
			return RelocationTypeRelative
		case 5: // ARM64_RELOC_GOT_LOAD_PAGE21
			return RelocationTypeGOT
		}
	}

	return RelocationTypeUnknown
}

// extractMachOImportsExports extracts imported and exported symbols from dyld info
func (p *StandardLibParser) extractMachOImportsExports(machoFile *macho.File) ([]*Import, []*Export) {
	imports := make([]*Import, 0, 64)
	exports := make([]*Export, 0, 64)

	// extract from symbol table
	if machoFile.Symtab != nil {
		for _, sym := range machoFile.Symtab.Syms {
			// undefined symbols are imports
			if sym.Sect == 0 && sym.Name != "" {
				imp := &Import{
					Name:    sym.Name,
					Address: Address(sym.Value),
				}
				imports = append(imports, imp)
			}

			// defined external symbols are exports
			if sym.Sect > 0 && sym.Name != "" && (sym.Type&0x01) != 0 {
				exp := &Export{
					Name:    sym.Name,
					Address: Address(sym.Value),
				}
				exports = append(exports, exp)
			}
		}
	}

	// extract imported libraries
	for _, load := range machoFile.Loads {
		if dylib, ok := load.(*macho.Dylib); ok {
			// create import entry for each dylib
			// note: this is simplified, real implementation would parse dyld info
			imp := &Import{
				Name:    dylib.Name,
				Library: dylib.Name,
			}
			imports = append(imports, imp)
		}
	}

	return imports, exports
}
