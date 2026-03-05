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

	// pe package doesn't provide direct export access
	// we need to parse export directory manually
	var exportDirRVA, exportDirSize uint32

	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 0 {
			exportDirRVA = oh.DataDirectory[0].VirtualAddress
			exportDirSize = oh.DataDirectory[0].Size
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 0 {
			exportDirRVA = oh.DataDirectory[0].VirtualAddress
			exportDirSize = oh.DataDirectory[0].Size
		}
	}

	// if no export directory, return empty
	if exportDirRVA == 0 || exportDirSize == 0 {
		return exports
	}

	// find section containing export directory
	var exportData []byte
	for _, sec := range peFile.Sections {
		if exportDirRVA >= sec.VirtualAddress &&
			exportDirRVA < sec.VirtualAddress+sec.VirtualSize {
			offset := exportDirRVA - sec.VirtualAddress
			data, err := sec.Data()
			if err == nil && uint32(len(data)) > offset {
				exportData = data[offset:]
				break
			}
		}
	}

	if len(exportData) < 40 {
		return exports
	}

	// parse export directory structure
	numberOfFunctions := binary.LittleEndian.Uint32(exportData[20:24])
	numberOfNames := binary.LittleEndian.Uint32(exportData[24:28])
	addressOfFunctions := binary.LittleEndian.Uint32(exportData[28:32])
	addressOfNames := binary.LittleEndian.Uint32(exportData[32:36])
	addressOfNameOrdinals := binary.LittleEndian.Uint32(exportData[36:40])

	// helper to read data at rva
	readAtRVA := func(rva uint32, size int) []byte {
		for _, sec := range peFile.Sections {
			if rva >= sec.VirtualAddress &&
				rva < sec.VirtualAddress+sec.VirtualSize {
				offset := rva - sec.VirtualAddress
				data, err := sec.Data()
				if err == nil && uint32(len(data)) >= offset+uint32(size) {
					return data[offset : offset+uint32(size)]
				}
			}
		}
		return nil
	}

	// read function addresses
	funcAddrs := make([]uint32, numberOfFunctions)
	funcData := readAtRVA(addressOfFunctions, int(numberOfFunctions*4))
	if funcData != nil {
		for i := uint32(0); i < numberOfFunctions; i++ {
			funcAddrs[i] = binary.LittleEndian.Uint32(funcData[i*4:])
		}
	}

	// read name pointers and ordinals
	for i := uint32(0); i < numberOfNames; i++ {
		// read name rva
		nameRVAData := readAtRVA(addressOfNames+i*4, 4)
		if nameRVAData == nil {
			continue
		}
		nameRVA := binary.LittleEndian.Uint32(nameRVAData)

		// read ordinal
		ordinalData := readAtRVA(addressOfNameOrdinals+i*2, 2)
		if ordinalData == nil {
			continue
		}
		ordinal := binary.LittleEndian.Uint16(ordinalData)

		// read name string
		nameData := readAtRVA(nameRVA, 256)
		if nameData == nil {
			continue
		}
		var name string
		for j := 0; j < len(nameData) && nameData[j] != 0; j++ {
			name += string(nameData[j])
		}

		// create export entry
		if uint32(ordinal) < numberOfFunctions {
			exp := &Export{
				Name:    name,
				Address: Address(funcAddrs[ordinal]),
				Ordinal: uint32(ordinal),
			}
			exports = append(exports, exp)
		}
	}

	return exports
}

// extractPERelocations extracts base relocations from .reloc section
func (p *StandardLibParser) extractPERelocations(peFile *pe.File, data []byte) []*Relocation {
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
