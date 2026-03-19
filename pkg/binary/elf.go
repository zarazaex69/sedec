package binfmt

import (
	"debug/elf"
	"encoding/binary"
)

// detectELFArchitecture determines the architecture from ELF file.
func (p *StandardLibParser) detectELFArchitecture(elfFile *elf.File) Architecture {
	switch elfFile.Machine {
	case elf.EM_X86_64:
		return ArchitectureX86_64
	case elf.EM_386:
		return ArchitectureX86
	case elf.EM_AARCH64:
		return ArchitectureARM64
	case elf.EM_ARM:
		return ArchitectureARM
	case elf.EM_MIPS:
		return ArchitectureMIPS
	case elf.EM_PPC:
		return ArchitecturePPC
	case elf.EM_PPC64:
		return ArchitecturePPC64
	case elf.EM_RISCV:
		// distinguish between 32 and 64 bit by class
		if elfFile.Class == elf.ELFCLASS64 {
			return ArchitectureRISCV64
		}
		return ArchitectureRISCV
	default:
		// all other architectures are unsupported
		return ArchitectureUnknown
	}
}

// extractELFSections extracts all sections from ELF file.
func (p *StandardLibParser) extractELFSections(elfFile *elf.File) []*Section {
	sections := make([]*Section, 0, len(elfFile.Sections))

	for _, sec := range elfFile.Sections {
		section := &Section{
			Name:    sec.Name,
			Address: Address(sec.Addr),
			Size:    sec.Size,
			Offset:  sec.Offset,
			Flags:   uint64(sec.Flags),
			Type:    uint32(sec.Type),
		}

		// determine section properties from flags
		section.IsExecutable = (sec.Flags & elf.SHF_EXECINSTR) != 0
		section.IsWritable = (sec.Flags & elf.SHF_WRITE) != 0
		section.IsAllocated = (sec.Flags & elf.SHF_ALLOC) != 0

		// read section data if allocated and size is reasonable
		if section.IsAllocated && sec.Size > 0 && sec.Size < 100*1024*1024 {
			data, err := sec.Data()
			if err == nil {
				section.Data = data
			}
		}

		sections = append(sections, section)
	}

	return sections
}

// extractELFSymbols extracts both static and dynamic symbols.
func (p *StandardLibParser) extractELFSymbols(elfFile *elf.File) []*Symbol {
	symbols := make([]*Symbol, 0, 256)

	// extract static symbols
	staticSyms, err := elfFile.Symbols()
	if err == nil {
		for i := range staticSyms {
			symbols = append(symbols, p.convertELFSymbol(&staticSyms[i], elfFile))
		}
	}

	// extract dynamic symbols
	dynSyms, err := elfFile.DynamicSymbols()
	if err == nil {
		for i := range dynSyms {
			symbols = append(symbols, p.convertELFSymbol(&dynSyms[i], elfFile))
		}
	}

	return symbols
}

// convertELFSymbol converts elf.Symbol to our Symbol type.
func (p *StandardLibParser) convertELFSymbol(sym *elf.Symbol, elfFile *elf.File) *Symbol {
	symbol := &Symbol{
		Name:    sym.Name,
		Address: Address(sym.Value),
		Size:    sym.Size,
		Type:    p.convertELFSymbolType(elf.ST_TYPE(sym.Info)),
		Binding: p.convertELFSymbolBinding(elf.ST_BIND(sym.Info)),
	}

	// get section name if valid section index
	if int(sym.Section) < len(elfFile.Sections) && sym.Section != elf.SHN_UNDEF {
		symbol.Section = elfFile.Sections[sym.Section].Name
	}

	return symbol
}

// convertELFSymbolType converts ELF symbol type to our type.
func (p *StandardLibParser) convertELFSymbolType(st elf.SymType) SymbolType {
	switch st {
	case elf.STT_FUNC:
		return SymbolTypeFunction
	case elf.STT_OBJECT:
		return SymbolTypeObject
	case elf.STT_SECTION:
		return SymbolTypeSection
	case elf.STT_FILE:
		return SymbolTypeFile
	case elf.STT_TLS:
		return SymbolTypeTLS
	case elf.STT_NOTYPE, elf.STT_COMMON, elf.STT_GNU_IFUNC, elf.STT_HIOS,
		elf.STT_LOPROC, elf.STT_HIPROC, elf.STT_RELC, elf.STT_SRELC:
		return SymbolTypeUnknown
	default:
		return SymbolTypeUnknown
	}
}

// convertELFSymbolBinding converts ELF symbol binding to our type.
func (p *StandardLibParser) convertELFSymbolBinding(sb elf.SymBind) SymbolBinding {
	switch sb {
	case elf.STB_LOCAL:
		return SymbolBindingLocal
	case elf.STB_GLOBAL:
		return SymbolBindingGlobal
	case elf.STB_WEAK:
		return SymbolBindingWeak
	case elf.STB_LOOS, elf.STB_HIOS, elf.STB_LOPROC, elf.STB_HIPROC:
		return SymbolBindingUnknown
	default:
		return SymbolBindingUnknown
	}
}

// extractELFRelocations extracts relocations from SHT_RELA and SHT_REL sections
//
//nolint:misspell // RELA is ELF terminology
func (p *StandardLibParser) extractELFRelocations(elfFile *elf.File) []*Relocation {
	relocations := make([]*Relocation, 0, 256)

	// get dynamic symbols for relocation symbol resolution
	dynSyms, dynErr := elfFile.DynamicSymbols()
	if dynErr != nil {
		dynSyms = []elf.Symbol{} // fallback to empty slice
	}

	for _, sec := range elfFile.Sections {
		if sec.Type != elf.SHT_RELA && sec.Type != elf.SHT_REL { //nolint:misspell // RELA is ELF terminology
			continue
		}

		data, err := sec.Data()
		if err != nil {
			continue
		}

		// determine entry size based on class and type
		var entrySize int
		//nolint:misspell,nestif // RELA is ELF terminology, complexity is acceptable
		if sec.Type == elf.SHT_RELA {
			if elfFile.Class == elf.ELFCLASS64 {
				entrySize = 24 // sizeof(Elf64_Rela)
			} else {
				entrySize = 12 // sizeof(Elf32_Rela)
			}
		} else {
			if elfFile.Class == elf.ELFCLASS64 {
				entrySize = 16 // sizeof(Elf64_Rel)
			} else {
				entrySize = 8 // sizeof(Elf32_Rel)
			}
		}

		// parse relocation entries
		for i := 0; i+entrySize <= len(data); i += entrySize {
			reloc := p.parseELFRelocation(data[i:i+entrySize], elfFile, sec.Type, dynSyms)
			if reloc != nil {
				relocations = append(relocations, reloc)
			}
		}
	}

	return relocations
}

// parseELFRelocation parses a single relocation entry.
func (p *StandardLibParser) parseELFRelocation(data []byte, elfFile *elf.File,
	secType elf.SectionType, dynSyms []elf.Symbol) *Relocation {
	var offset, info uint64
	var addend int64
	var byteOrder binary.ByteOrder
	// determine byte order
	if elfFile.Data == elf.ELFDATA2LSB {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}
	// parse based on class and section type
	if elfFile.Class == elf.ELFCLASS64 {
		offset = byteOrder.Uint64(data[0:8])
		info = byteOrder.Uint64(data[8:16])
		if secType == elf.SHT_RELA { //nolint:misspell // RELA is ELF terminology
			addend = int64(byteOrder.Uint64(data[16:24])) //nolint:gosec // intentional conversion
		}
	} else {
		offset = uint64(byteOrder.Uint32(data[0:4]))
		info = uint64(byteOrder.Uint32(data[4:8]))
		if secType == elf.SHT_RELA { //nolint:misspell // RELA is ELF terminology
			addend = int64(int32(byteOrder.Uint32(data[8:12]))) //nolint:gosec // intentional conversion
		}
	}

	// extract symbol index and relocation type
	var symIdx uint32
	var relocType uint32
	if elfFile.Class == elf.ELFCLASS64 {
		// elf64 relocation info encoding: high 32 bits = symbol index, low 32 bits = type
		symIdx = uint32(info >> 32)
		relocType = uint32(info & 0xffffffff)
	} else {
		symIdx = uint32(info >> 8) //nolint:gosec // safe conversion, info is from uint32
		relocType = uint32(info & 0xff)
	}

	reloc := &Relocation{
		Address:   Address(offset),
		Type:      p.convertELFRelocationType(elfFile.Machine, relocType),
		Addend:    addend,
		SymbolIdx: symIdx,
	}

	// resolve symbol name
	if symIdx > 0 && int(symIdx-1) < len(dynSyms) {
		reloc.Symbol = dynSyms[symIdx-1].Name
	}

	return reloc
}

// convertELFRelocationType converts ELF relocation type to our type.
func (p *StandardLibParser) convertELFRelocationType(machine elf.Machine, relocType uint32) RelocationType {
	// x86_64 relocation types (using raw constants as some may not be in older go versions)
	if machine == elf.EM_X86_64 {
		switch relocType {
		case 1, 10, 11: // R_X86_64_64, R_X86_64_32, R_X86_64_32S
			return RelocationTypeAbsolute
		case 2, 4: // R_X86_64_PC32, R_X86_64_PLT32
			return RelocationTypeRelative
		case 7: // R_X86_64_JUMP_SLOT
			return RelocationTypeJumpSlot
		case 6: // R_X86_64_GLOB_DAT
			return RelocationTypeGlobDat
		case 5: // R_X86_64_COPY
			return RelocationTypeCopy
		case 9: // R_X86_64_GOTPCREL
			return RelocationTypeGOT
		}
	}

	// aarch64 relocation types
	if machine == elf.EM_AARCH64 {
		switch relocType {
		case 257, 258: // R_AARCH64_ABS64, R_AARCH64_ABS32
			return RelocationTypeAbsolute
		case 261, 262: // R_AARCH64_PREL64, R_AARCH64_PREL32
			return RelocationTypeRelative
		case 1026: // R_AARCH64_JUMP_SLOT
			return RelocationTypeJumpSlot
		case 1025: // R_AARCH64_GLOB_DAT
			return RelocationTypeGlobDat
		case 1024: // R_AARCH64_COPY
			return RelocationTypeCopy
		}
	}

	return RelocationTypeUnknown
}

// extractELFImportsExports extracts imported and exported symbols.
func (p *StandardLibParser) extractELFImportsExports(elfFile *elf.File) ([]*Import, []*Export) {
	imports := make([]*Import, 0, 64)
	exports := make([]*Export, 0, 64)

	// extract dynamic symbols
	dynSyms, err := elfFile.DynamicSymbols()
	if err != nil {
		return imports, exports
	}

	// extract imported libraries
	importedLibs, err := elfFile.ImportedLibraries()
	if err != nil {
		importedLibs = []string{}
	}

	for _, sym := range dynSyms {
		// undefined symbols are imports
		if sym.Section == elf.SHN_UNDEF && sym.Name != "" {
			imp := &Import{
				Name:    sym.Name,
				Address: Address(sym.Value),
			}
			// try to match with imported library
			if len(importedLibs) > 0 {
				imp.Library = importedLibs[0] // simplified: would need version info
			}
			imports = append(imports, imp)
		}

		// defined global/weak symbols are exports
		bind := elf.ST_BIND(sym.Info)
		if sym.Section != elf.SHN_UNDEF && sym.Name != "" &&
			(bind == elf.STB_GLOBAL || bind == elf.STB_WEAK) {
			exp := &Export{
				Name:    sym.Name,
				Address: Address(sym.Value),
			}
			exports = append(exports, exp)
		}
	}

	return imports, exports
}
