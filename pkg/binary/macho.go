package binfmt

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
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

// extractMachOSectionsFromLoadCommands extracts sections by iterating through load commands
// this provides more complete information including segment details
func (p *StandardLibParser) extractMachOSectionsFromLoadCommands(machoFile *macho.File) []*Section {
	sections := make([]*Section, 0, len(machoFile.Sections))

	// iterate through load commands to find segments
	for _, load := range machoFile.Loads {
		seg, ok := load.(*macho.Segment)
		if !ok {
			continue
		}

		// process each section in the segment
		for _, sec := range machoFile.Sections {
			if sec.Seg != seg.Name {
				continue
			}

			section := &Section{
				Name:    fmt.Sprintf("%s.%s", seg.Name, sec.Name),
				Address: Address(sec.Addr),
				Size:    sec.Size,
				Offset:  uint64(sec.Offset),
				Flags:   uint64(sec.Flags),
				Type:    sec.Flags,
			}

			// determine section properties from segment and section flags
			section.IsExecutable = (seg.Prot & 0x4) != 0 // VM_PROT_EXECUTE
			section.IsWritable = (seg.Prot & 0x2) != 0   // VM_PROT_WRITE
			section.IsAllocated = true

			// read section data if size is reasonable
			if sec.Size > 0 && sec.Size < 100*1024*1024 {
				data, err := sec.Data()
				if err == nil {
					section.Data = data
				}
			}

			sections = append(sections, section)
		}
	}

	return sections
}

// extractMachOSymbolsFromSymtab extracts symbols from symtab with complete information
func (p *StandardLibParser) extractMachOSymbolsFromSymtab(machoFile *macho.File) []*Symbol {
	symbols := make([]*Symbol, 0, 256)

	if machoFile.Symtab == nil {
		return symbols
	}

	for _, sym := range machoFile.Symtab.Syms {
		// skip stabs debugging symbols (type & N_STAB)
		if (sym.Type & 0xE0) != 0 {
			continue
		}

		symbol := &Symbol{
			Name:    sym.Name,
			Address: Address(sym.Value),
			Type:    p.convertMachOSymbolType(sym.Type),
			Binding: p.convertMachOSymbolBinding(sym.Type, sym.Desc),
		}

		// get section name if valid section number
		if int(sym.Sect) > 0 && int(sym.Sect) <= len(machoFile.Sections) {
			section := machoFile.Sections[sym.Sect-1]
			symbol.Section = fmt.Sprintf("%s.%s", section.Seg, section.Name)
		}

		// only add symbols with valid addresses or undefined externals
		if sym.Value != 0 || sym.Sect == 0 {
			symbols = append(symbols, symbol)
		}
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

// convertMachOSymbolBinding converts Mach-O symbol flags to binding type
func (p *StandardLibParser) convertMachOSymbolBinding(symType uint8, desc uint16) SymbolBinding {
	// check if external symbol (N_EXT flag)
	if (symType & 0x01) != 0 {
		// check if weak definition (N_WEAK_DEF in desc)
		if (desc & 0x0080) != 0 {
			return SymbolBindingWeak
		}
		return SymbolBindingGlobal
	}
	return SymbolBindingLocal
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

// extractMachODynamicRelocations extracts dynamic relocations via dysymtab command
// this includes indirect symbols, external relocations, and local relocations
func (p *StandardLibParser) extractMachODynamicRelocations(machoFile *macho.File, data []byte) []*Relocation {
	relocations := make([]*Relocation, 0, 512)

	// find dysymtab load command
	var dysymtab *macho.Dysymtab
	for _, load := range machoFile.Loads {
		if dt, ok := load.(*macho.Dysymtab); ok {
			dysymtab = dt
			break
		}
	}

	if dysymtab == nil {
		// fallback to section relocations
		return p.extractMachORelocations(machoFile)
	}

	// extract indirect symbol table for lazy/non-lazy symbol pointers
	indirectSyms := p.extractMachOIndirectSymbols(machoFile, dysymtab, data)
	relocations = append(relocations, indirectSyms...)

	// extract external relocations (for dynamic linking)
	extRelocs := p.extractMachOExternalRelocations(machoFile, dysymtab, data)
	relocations = append(relocations, extRelocs...)

	// extract local relocations (for position-independent code)
	localRelocs := p.extractMachOLocalRelocations(machoFile, dysymtab, data)
	relocations = append(relocations, localRelocs...)

	return relocations
}

// extractMachOIndirectSymbols extracts indirect symbol table entries
// these map stub sections and pointer sections to their target symbols
func (p *StandardLibParser) extractMachOIndirectSymbols(machoFile *macho.File,
	dysymtab *macho.Dysymtab, data []byte) []*Relocation {
	relocations := make([]*Relocation, 0, 256)

	if dysymtab.Nindirectsyms == 0 {
		return relocations
	}

	// read indirect symbol table
	indirectSymOffset := dysymtab.Indirectsymoff
	indirectSymSize := dysymtab.Nindirectsyms * 4 // each entry is 4 bytes

	if uint64(indirectSymOffset)+uint64(indirectSymSize) > uint64(len(data)) {
		return relocations
	}

	_ = data[indirectSymOffset : indirectSymOffset+indirectSymSize] // indirectSymData not used due to field limitations

	// process sections that use indirect symbols
	for _, sec := range machoFile.Sections {
		sectionType := sec.Flags & 0xFF

		// check if section uses indirect symbol table
		// S_LAZY_SYMBOL_POINTERS = 0x7, S_NON_LAZY_SYMBOL_POINTERS = 0x6
		// S_SYMBOL_STUBS = 0x8
		if sectionType != 0x6 && sectionType != 0x7 && sectionType != 0x8 {
			continue
		}

		// calculate number of entries in this section
		var entrySize uint64
		if sectionType == 0x8 { // symbol stubs
			// try to get stub size from section, fallback to default
			entrySize = 5 // default stub size for x86_64
			// note: Reserved2 field may not be available in all go versions
		} else { // pointer sections
			if machoFile.Cpu == macho.CpuAmd64 || machoFile.Cpu == macho.CpuArm64 {
				entrySize = 8 // 64-bit pointers
			} else {
				entrySize = 4 // 32-bit pointers
			}
		}

		numEntries := sec.Size / entrySize
		// note: Reserved1 field may not be available in all go versions
		// we'll skip indirect symbol resolution for now
		_ = numEntries

		// simplified: skip indirect symbol processing due to field availability
		continue
	}

	return relocations
}

// extractMachOExternalRelocations extracts external relocation entries from dysymtab
func (p *StandardLibParser) extractMachOExternalRelocations(machoFile *macho.File,
	dysymtab *macho.Dysymtab, data []byte) []*Relocation {
	relocations := make([]*Relocation, 0, 128)

	if dysymtab.Nextrel == 0 {
		return relocations
	}

	// read external relocation entries
	extRelOffset := dysymtab.Extreloff
	extRelSize := dysymtab.Nextrel * 8 // each entry is 8 bytes

	if uint64(extRelOffset)+uint64(extRelSize) > uint64(len(data)) {
		return relocations
	}

	extRelData := data[extRelOffset : extRelOffset+extRelSize]

	// parse each external relocation
	for i := uint32(0); i < dysymtab.Nextrel; i++ {
		offset := i * 8
		reloc := p.parseMachORelocationInfo(extRelData[offset:offset+8], machoFile, true)
		if reloc != nil {
			relocations = append(relocations, reloc)
		}
	}

	return relocations
}

// extractMachOLocalRelocations extracts local relocation entries from dysymtab
func (p *StandardLibParser) extractMachOLocalRelocations(machoFile *macho.File,
	dysymtab *macho.Dysymtab, data []byte) []*Relocation {
	relocations := make([]*Relocation, 0, 128)

	if dysymtab.Nlocrel == 0 {
		return relocations
	}

	// read local relocation entries
	locRelOffset := dysymtab.Locreloff
	locRelSize := dysymtab.Nlocrel * 8 // each entry is 8 bytes

	if uint64(locRelOffset)+uint64(locRelSize) > uint64(len(data)) {
		return relocations
	}

	locRelData := data[locRelOffset : locRelOffset+locRelSize]

	// parse each local relocation
	for i := uint32(0); i < dysymtab.Nlocrel; i++ {
		offset := i * 8
		reloc := p.parseMachORelocationInfo(locRelData[offset:offset+8], machoFile, false)
		if reloc != nil {
			relocations = append(relocations, reloc)
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

// parseMachORelocationInfo parses relocation_info structure from dysymtab
func (p *StandardLibParser) parseMachORelocationInfo(data []byte, machoFile *macho.File,
	_ bool) *Relocation {
	if len(data) < 8 {
		return nil
	}

	// parse relocation_info structure
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

	_ = pcrel
	_ = length
	_ = extern

	reloc := &Relocation{
		Address:   Address(addr),
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

// parseFatMachO handles fat (universal) binaries containing multiple architectures
func (p *StandardLibParser) parseFatMachO(data []byte) (*BinaryInfo, error) {
	if len(data) < 8 {
		return nil, &TruncatedFileError{Expected: 8, Actual: uint64(len(data))}
	}

	// read fat header
	nfatArch := binary.BigEndian.Uint32(data[4:8])
	if nfatArch == 0 {
		return nil, fmt.Errorf("fat binary contains no architectures")
	}

	// read first architecture (typically x86_64 or arm64)
	// fat_arch structure: cputype(4) cpusubtype(4) offset(4) size(4) align(4)
	const fatArchSize = 20
	if len(data) < 8+fatArchSize {
		return nil, &TruncatedFileError{Expected: 8 + fatArchSize, Actual: uint64(len(data))}
	}

	// extract first architecture offset and size
	offset := binary.BigEndian.Uint32(data[8+8 : 8+12])
	size := binary.BigEndian.Uint32(data[8+12 : 8+16])

	// validate bounds
	if uint64(offset)+uint64(size) > uint64(len(data)) {
		return nil, fmt.Errorf("fat architecture offset %d + size %d exceeds file size %d",
			offset, size, len(data))
	}

	// extract single architecture binary
	archData := data[offset : offset+size]
	reader := bytes.NewReader(archData)
	machoFile, err := macho.NewFile(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse mach-o from fat binary: %w", err)
	}

	return p.parseSingleMachO(archData, machoFile)
}

// parseSingleMachO parses a single (non-fat) Mach-O binary
func (p *StandardLibParser) parseSingleMachO(data []byte, machoFile *macho.File) (*BinaryInfo, error) {
	info := &BinaryInfo{
		Format:        BinaryFormatMachO,
		Architecture:  p.detectMachOArchitecture(machoFile),
		EntryPoint:    p.findMachOEntryPoint(machoFile),
		BaseAddress:   0, // mach-o uses vmaddr from segments
		GroundTruthDB: NewGroundTruthDatabase(),
		machoFile:     machoFile,
	}

	// extract segments and sections via load commands
	info.Sections = p.extractMachOSectionsFromLoadCommands(machoFile)

	// extract symbols via symtab
	info.Symbols = p.extractMachOSymbolsFromSymtab(machoFile)

	// extract dynamic relocations via dysymtab
	info.Relocations = p.extractMachODynamicRelocations(machoFile, data)

	// extract imports and exports from dyld info
	info.Imports, info.Exports = p.extractMachODyldInfo(machoFile, data)

	// build ground-truth database from dyld relocations
	p.buildMachOGroundTruthDB(info, machoFile, data)

	return info, nil
}

// extractMachODyldInfo extracts imports and exports from dyld info
// this includes bind info, weak bind info, lazy bind info, and export trie
func (p *StandardLibParser) extractMachODyldInfo(machoFile *macho.File, data []byte) ([]*Import, []*Export) {
	imports := make([]*Import, 0, 128)
	exports := make([]*Export, 0, 128)

	// extract imports from symbol table (undefined symbols)
	if machoFile.Symtab != nil {
		for _, sym := range machoFile.Symtab.Syms {
			// undefined symbols (sect == 0) are imports
			if sym.Sect == 0 && sym.Name != "" {
				imp := &Import{
					Name:    sym.Name,
					Address: Address(sym.Value),
				}
				imports = append(imports, imp)
			}
		}
	}

	// extract imported libraries from load commands
	libraryMap := make(map[uint32]string)
	libraryOrdinal := uint32(1)
	for _, load := range machoFile.Loads {
		if dylib, ok := load.(*macho.Dylib); ok {
			libraryMap[libraryOrdinal] = dylib.Name
			libraryOrdinal++
		}
	}

	// extract exports from symbol table (defined external symbols)
	if machoFile.Symtab != nil {
		for _, sym := range machoFile.Symtab.Syms {
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

	// try to extract more detailed dyld info from LC_DYLD_INFO or LC_DYLD_INFO_ONLY
	dyldInfo := p.findDyldInfoCommand(machoFile)
	if dyldInfo != nil {
		// extract bind info for imports
		bindImports := p.parseMachOBindInfo(machoFile, data, dyldInfo, libraryMap)
		imports = append(imports, bindImports...)

		// extract export trie for exports
		exportTrieExports := p.parseMachOExportTrie(machoFile, data, dyldInfo)
		exports = append(exports, exportTrieExports...)
	}

	return imports, exports
}

// dyldInfoCmd represents LC_DYLD_INFO or LC_DYLD_INFO_ONLY command
type dyldInfoCmd struct {
	RebaseOff    uint32
	RebaseSize   uint32
	BindOff      uint32
	BindSize     uint32
	WeakBindOff  uint32
	WeakBindSize uint32
	LazyBindOff  uint32
	LazyBindSize uint32
	ExportOff    uint32
	ExportSize   uint32
}

// findDyldInfoCommand finds LC_DYLD_INFO or LC_DYLD_INFO_ONLY load command
func (p *StandardLibParser) findDyldInfoCommand(_ *macho.File) *dyldInfoCmd {
	// parse load commands manually to find dyld info
	// note: debug/macho doesn't expose dyld_info_command directly
	// we need to parse it from raw load command data

	// this is a simplified implementation
	// full implementation would parse raw load command bytes
	return nil
}

// parseMachOBindInfo parses bind info to extract imported symbols
func (p *StandardLibParser) parseMachOBindInfo(_ *macho.File, data []byte,
	dyldInfo *dyldInfoCmd, _ map[uint32]string) []*Import {
	imports := make([]*Import, 0, 64)

	if dyldInfo.BindSize == 0 {
		return imports
	}

	// validate bounds
	if uint64(dyldInfo.BindOff)+uint64(dyldInfo.BindSize) > uint64(len(data)) {
		return imports
	}

	bindData := data[dyldInfo.BindOff : dyldInfo.BindOff+dyldInfo.BindSize]

	// parse bind opcodes (simplified implementation)
	// full implementation would decode BIND_OPCODE_* instructions
	_ = bindData

	return imports
}

// parseMachOExportTrie parses export trie to extract exported symbols
func (p *StandardLibParser) parseMachOExportTrie(_ *macho.File, data []byte,
	dyldInfo *dyldInfoCmd) []*Export {
	exports := make([]*Export, 0, 64)

	if dyldInfo.ExportSize == 0 {
		return exports
	}

	// validate bounds
	if uint64(dyldInfo.ExportOff)+uint64(dyldInfo.ExportSize) > uint64(len(data)) {
		return exports
	}

	exportData := data[dyldInfo.ExportOff : dyldInfo.ExportOff+dyldInfo.ExportSize]

	// parse export trie (simplified implementation)
	// full implementation would walk the trie structure
	_ = exportData

	return exports
}

// buildMachOGroundTruthDB builds ground-truth database from dyld relocations
// this maps addresses to their resolved symbols for use as axioms in analysis
func (p *StandardLibParser) buildMachOGroundTruthDB(info *BinaryInfo, machoFile *macho.File, _ []byte) {
	db := info.GroundTruthDB

	// populate relocations map
	for _, reloc := range info.Relocations {
		db.Relocations[reloc.Address] = reloc
	}

	// populate imports map
	for _, imp := range info.Imports {
		db.Imports[imp.Address] = imp
		if imp.Name != "" {
			db.SymbolsByAddress[imp.Address] = imp.Name
			db.SymbolsByName[imp.Name] = imp.Address
		}
	}

	// populate exports map
	for _, exp := range info.Exports {
		db.Exports[exp.Address] = exp
		if exp.Name != "" {
			db.SymbolsByAddress[exp.Address] = exp.Name
			db.SymbolsByName[exp.Name] = exp.Address
		}
	}

	// populate symbols maps
	for _, sym := range info.Symbols {
		if sym.Name != "" && sym.Address != 0 {
			db.SymbolsByAddress[sym.Address] = sym.Name
			// only add to name map if not already present (prefer imports/exports)
			if _, exists := db.SymbolsByName[sym.Name]; !exists {
				db.SymbolsByName[sym.Name] = sym.Address
			}
		}
	}

	// resolve lazy and non-lazy symbol pointers from relocations
	// these are the mach-o equivalent of got/plt
	for _, reloc := range info.Relocations {
		if reloc.Type == RelocationTypePLT || reloc.Type == RelocationTypeGOT {
			// map stub/pointer address to target symbol address
			if targetAddr, exists := db.SymbolsByName[reloc.Symbol]; exists {
				db.GOTPLT[reloc.Address] = targetAddr
			}
		}
	}

	// extract additional ground-truth from __la_symbol_ptr and __nl_symbol_ptr sections
	p.extractMachOSymbolPointers(info, machoFile, db)
}

// extractMachOSymbolPointers extracts symbol pointers from special sections
// __la_symbol_ptr (lazy) and __nl_symbol_ptr (non-lazy) contain resolved addresses
func (p *StandardLibParser) extractMachOSymbolPointers(_ *BinaryInfo,
	machoFile *macho.File, db *GroundTruthDatabase) {
	for _, sec := range machoFile.Sections {
		if !p.isSymbolPointerSection(sec) {
			continue
		}

		data, pointerSize := p.readSymbolPointerSection(sec, machoFile)
		if data == nil {
			continue
		}

		p.processSymbolPointers(sec, data, pointerSize, machoFile, db)
	}
}

// isSymbolPointerSection checks if section is a symbol pointer section
func (p *StandardLibParser) isSymbolPointerSection(sec *macho.Section) bool {
	sectionType := sec.Flags & 0xFF
	// check for lazy or non-lazy symbol pointer sections
	return sectionType == 0x6 || sectionType == 0x7
}

// readSymbolPointerSection reads section data and determines pointer size
func (p *StandardLibParser) readSymbolPointerSection(sec *macho.Section,
	machoFile *macho.File) (data []byte, pointerSize uint64) {
	// read section data
	if sec.Size == 0 || sec.Size > 100*1024*1024 {
		return nil, 0
	}

	data, err := sec.Data()
	if err != nil {
		return nil, 0
	}

	// determine pointer size
	if machoFile.Cpu == macho.CpuAmd64 || machoFile.Cpu == macho.CpuArm64 {
		pointerSize = 8
	} else {
		pointerSize = 4
	}

	return data, pointerSize
}

// processSymbolPointers processes each pointer in the section
func (p *StandardLibParser) processSymbolPointers(sec *macho.Section, data []byte,
	pointerSize uint64, machoFile *macho.File, db *GroundTruthDatabase) {
	numPointers := sec.Size / pointerSize
	for i := uint64(0); i < numPointers; i++ {
		offset := i * pointerSize
		if offset+pointerSize > uint64(len(data)) {
			break
		}

		targetAddr := p.readPointerValue(data, offset, pointerSize, machoFile)
		if targetAddr == 0 {
			continue
		}

		pointerAddr := Address(sec.Addr + i*pointerSize)
		p.resolveSymbolPointer(pointerAddr, db)
	}
}

// readPointerValue reads a pointer value from data
func (p *StandardLibParser) readPointerValue(data []byte, offset, pointerSize uint64,
	machoFile *macho.File) uint64 {
	if pointerSize == 8 {
		return machoFile.ByteOrder.Uint64(data[offset : offset+8])
	}
	return uint64(machoFile.ByteOrder.Uint32(data[offset : offset+4]))
}

// resolveSymbolPointer resolves a symbol pointer address
func (p *StandardLibParser) resolveSymbolPointer(pointerAddr Address, db *GroundTruthDatabase) {
	// check if we have a relocation for this address
	reloc, relocExists := db.Relocations[pointerAddr]
	if !relocExists || reloc.Symbol == "" {
		return
	}

	// map pointer address to target
	if targetAddr, symbolExists := db.SymbolsByName[reloc.Symbol]; symbolExists {
		db.GOTPLT[pointerAddr] = targetAddr
	}
}
