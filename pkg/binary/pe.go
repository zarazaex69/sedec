package binfmt

import (
	"debug/pe"
	"encoding/binary"
)

// detectPEArchitecture determines the architecture from PE file
func (p *StandardLibParser) detectPEArchitecture(peFile *pe.File) Architecture {
	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return ArchitectureX86_64
	case pe.IMAGE_FILE_MACHINE_I386:
		return ArchitectureX86
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return ArchitectureARM64
	case pe.IMAGE_FILE_MACHINE_ARM, pe.IMAGE_FILE_MACHINE_ARMNT:
		return ArchitectureARM
	default:
		return ArchitectureUnknown
	}
}

// extractPESections extracts all sections from PE file
func (p *StandardLibParser) extractPESections(peFile *pe.File) []*Section {
	sections := make([]*Section, 0, len(peFile.Sections))

	for _, sec := range peFile.Sections {
		section := &Section{
			Name:    sec.Name,
			Address: Address(sec.VirtualAddress),
			Size:    uint64(sec.VirtualSize),
			Offset:  uint64(sec.Offset),
			Flags:   uint64(sec.Characteristics),
			Type:    sec.Characteristics,
		}

		// determine section properties from characteristics
		section.IsExecutable = (sec.Characteristics & pe.IMAGE_SCN_MEM_EXECUTE) != 0
		section.IsWritable = (sec.Characteristics & pe.IMAGE_SCN_MEM_WRITE) != 0
		section.IsAllocated = (sec.Characteristics & pe.IMAGE_SCN_MEM_READ) != 0

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

// extractPESymbols extracts symbols from COFF symbol table
func (p *StandardLibParser) extractPESymbols(peFile *pe.File) []*Symbol {
	symbols := make([]*Symbol, 0, len(peFile.Symbols))

	for _, sym := range peFile.Symbols {
		symbol := &Symbol{
			Name:    sym.Name,
			Address: Address(sym.Value),
			Type:    p.convertPESymbolType(sym.StorageClass),
			Binding: SymbolBindingGlobal, // pe doesn't have binding concept
		}

		// get section name if valid section number
		if int(sym.SectionNumber) > 0 && int(sym.SectionNumber) <= len(peFile.Sections) {
			symbol.Section = peFile.Sections[sym.SectionNumber-1].Name
		}

		symbols = append(symbols, symbol)
	}

	return symbols
}

// convertPESymbolType converts PE storage class to our symbol type
func (p *StandardLibParser) convertPESymbolType(storageClass uint8) SymbolType {
	switch storageClass {
	case 2: // IMAGE_SYM_CLASS_EXTERNAL
		return SymbolTypeFunction
	case 3: // IMAGE_SYM_CLASS_STATIC
		return SymbolTypeObject
	case 103: // IMAGE_SYM_CLASS_SECTION
		return SymbolTypeSection
	case 104: // IMAGE_SYM_CLASS_FILE
		return SymbolTypeFile
	default:
		return SymbolTypeUnknown
	}
}

// extractPEImports extracts imported symbols from import directory
func (p *StandardLibParser) extractPEImports(peFile *pe.File) []*Import {
	imports := make([]*Import, 0, 128)

	// get imported symbols (returns []string in newer go versions)
	importedSymbols, err := peFile.ImportedSymbols()
	if err != nil {
		return imports
	}

	// importedSymbols is []string
	for _, sym := range importedSymbols {
		imp := &Import{
			Name:    sym,
			Address: 0, // will be resolved at runtime by loader
		}
		imports = append(imports, imp)
	}

	return imports
}

// extractPEExports extracts exported symbols from export directory
func (p *StandardLibParser) extractPEExports(peFile *pe.File) []*Export {
	exports := make([]*Export, 0, 64)

	// get export directory location
	exportDirRVA, exportDirSize := p.getPEExportDirectory(peFile)
	if exportDirRVA == 0 || exportDirSize == 0 {
		return exports
	}

	// read export directory data
	exportData := p.readPEDataAtRVA(peFile, exportDirRVA, 40)
	if len(exportData) < 40 {
		return exports
	}

	// parse export directory structure
	exportDir := p.parsePEExportDirectory(exportData)

	// read function addresses
	funcAddrs := p.readPEFunctionAddresses(peFile, exportDir)

	// read and process exported names
	return p.processPEExportNames(peFile, exportDir, funcAddrs)
}

// getPEExportDirectory retrieves export directory RVA and size from optional header
func (p *StandardLibParser) getPEExportDirectory(peFile *pe.File) (rva, size uint32) {
	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 0 {
			return oh.DataDirectory[0].VirtualAddress, oh.DataDirectory[0].Size
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 0 {
			return oh.DataDirectory[0].VirtualAddress, oh.DataDirectory[0].Size
		}
	}
	return 0, 0
}

// peExportDirectory holds parsed export directory fields
type peExportDirectory struct {
	numberOfFunctions     uint32
	numberOfNames         uint32
	addressOfFunctions    uint32
	addressOfNames        uint32
	addressOfNameOrdinals uint32
}

// parsePEExportDirectory parses export directory structure from raw data
func (p *StandardLibParser) parsePEExportDirectory(data []byte) peExportDirectory {
	return peExportDirectory{
		numberOfFunctions:     binary.LittleEndian.Uint32(data[20:24]),
		numberOfNames:         binary.LittleEndian.Uint32(data[24:28]),
		addressOfFunctions:    binary.LittleEndian.Uint32(data[28:32]),
		addressOfNames:        binary.LittleEndian.Uint32(data[32:36]),
		addressOfNameOrdinals: binary.LittleEndian.Uint32(data[36:40]),
	}
}

// readPEDataAtRVA reads data at specified RVA from PE file sections
func (p *StandardLibParser) readPEDataAtRVA(peFile *pe.File, rva uint32, size int) []byte {
	for _, sec := range peFile.Sections {
		if rva >= sec.VirtualAddress && rva < sec.VirtualAddress+sec.VirtualSize {
			offset := rva - sec.VirtualAddress
			data, err := sec.Data()
			if err == nil && len(data) >= int(offset)+size {
				return data[offset : offset+uint32(size)] //nolint:gosec // size is controlled
			}
		}
	}
	return nil
}

// readPEFunctionAddresses reads function address table from export directory
func (p *StandardLibParser) readPEFunctionAddresses(peFile *pe.File, exportDir peExportDirectory) []uint32 {
	funcAddrs := make([]uint32, exportDir.numberOfFunctions)
	funcData := p.readPEDataAtRVA(peFile, exportDir.addressOfFunctions, int(exportDir.numberOfFunctions*4))
	if funcData != nil {
		for i := uint32(0); i < exportDir.numberOfFunctions; i++ {
			funcAddrs[i] = binary.LittleEndian.Uint32(funcData[i*4:])
		}
	}
	return funcAddrs
}

// processPEExportNames reads and processes exported function names
func (p *StandardLibParser) processPEExportNames(peFile *pe.File, exportDir peExportDirectory, funcAddrs []uint32) []*Export {
	exports := make([]*Export, 0, exportDir.numberOfNames)

	for i := uint32(0); i < exportDir.numberOfNames; i++ {
		exp := p.readPEExportEntry(peFile, exportDir, funcAddrs, i)
		if exp != nil {
			exports = append(exports, exp)
		}
	}

	return exports
}

// readPEExportEntry reads a single export entry by index
func (p *StandardLibParser) readPEExportEntry(peFile *pe.File, exportDir peExportDirectory, funcAddrs []uint32, index uint32) *Export {
	// read name rva
	nameRVAData := p.readPEDataAtRVA(peFile, exportDir.addressOfNames+index*4, 4)
	if nameRVAData == nil {
		return nil
	}
	nameRVA := binary.LittleEndian.Uint32(nameRVAData)

	// read ordinal
	ordinalData := p.readPEDataAtRVA(peFile, exportDir.addressOfNameOrdinals+index*2, 2)
	if ordinalData == nil {
		return nil
	}
	ordinal := binary.LittleEndian.Uint16(ordinalData)

	// read name string
	name := p.readPEExportName(peFile, nameRVA)
	if name == "" {
		return nil
	}

	// create export entry
	if int(ordinal) < len(funcAddrs) {
		return &Export{
			Name:    name,
			Address: Address(funcAddrs[ordinal]),
			Ordinal: uint32(ordinal),
		}
	}

	return nil
}

// readPEExportName reads null-terminated export name string at RVA
func (p *StandardLibParser) readPEExportName(peFile *pe.File, nameRVA uint32) string {
	nameData := p.readPEDataAtRVA(peFile, nameRVA, 256)
	if nameData == nil {
		return ""
	}

	var name string
	for j := 0; j < len(nameData) && nameData[j] != 0; j++ {
		name += string(nameData[j])
	}
	return name
}

// extractPERelocations extracts base relocations from .reloc section
func (p *StandardLibParser) extractPERelocations(peFile *pe.File, _ []byte) []*Relocation {
	relocations := make([]*Relocation, 0, 256)

	// find .reloc section
	var relocSection *pe.Section
	for _, sec := range peFile.Sections {
		if sec.Name == ".reloc" {
			relocSection = sec
			break
		}
	}

	if relocSection == nil {
		return relocations
	}

	// read relocation data
	relocData, err := relocSection.Data()
	if err != nil {
		return relocations
	}

	// parse base relocation blocks
	offset := 0
	for offset+8 <= len(relocData) {
		// read block header
		pageRVA := binary.LittleEndian.Uint32(relocData[offset : offset+4])
		blockSize := binary.LittleEndian.Uint32(relocData[offset+4 : offset+8])

		if blockSize < 8 || offset+int(blockSize) > len(relocData) {
			break
		}

		// parse relocation entries in this block
		entryOffset := offset + 8
		numEntries := (blockSize - 8) / 2
		for i := uint32(0); i < numEntries; i++ {
			if entryOffset+2 > len(relocData) {
				break
			}

			entry := binary.LittleEndian.Uint16(relocData[entryOffset : entryOffset+2])
			relocType := entry >> 12
			relocOffset := entry & 0x0FFF

			// only process absolute relocations
			if relocType == 3 || relocType == 10 { // IMAGE_REL_BASED_HIGHLOW or DIR64
				reloc := &Relocation{
					Address: Address(pageRVA + uint32(relocOffset)),
					Type:    RelocationTypeAbsolute,
					Addend:  0,
				}
				relocations = append(relocations, reloc)
			}

			entryOffset += 2
		}

		offset += int(blockSize)
	}

	return relocations
}
