package binfmt

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
)

// magic number constants for binary format detection
const (
	// ELF magic: 0x7F 'E' 'L' 'F'
	elfMagic0 = 0x7F
	elfMagic1 = 'E'
	elfMagic2 = 'L'
	elfMagic3 = 'F'

	// PE magic: 'M' 'Z'
	peMagic0 = 'M'
	peMagic1 = 'Z'

	// Mach-O magic numbers
	machoMagic32    = 0xFEEDFACE // 32-bit mach-o
	machoMagic64    = 0xFEEDFACF // 64-bit mach-o
	machoMagicFat   = 0xCAFEBABE // fat binary (big endian)
	machoMagic32Rev = 0xCEFAEDFE // 32-bit reversed
	machoMagic64Rev = 0xCFFAEDFE // 64-bit reversed
)

// BinaryParser defines the interface for parsing binary files
type BinaryParser interface {
	Parse(data []byte) (*BinaryInfo, error)
}

// StandardLibParser implements BinaryParser using Go's standard library
type StandardLibParser struct{}

// NewStandardLibParser creates a new standard library parser
func NewStandardLibParser() *StandardLibParser {
	return &StandardLibParser{}
}

// Parse detects the binary format and delegates to the appropriate parser
func (p *StandardLibParser) Parse(data []byte) (*BinaryInfo, error) {
	if len(data) < 4 {
		return nil, &TruncatedFileError{Expected: 4, Actual: uint64(len(data))}
	}

	// detect format by magic number
	format := p.detectFormat(data)

	switch format {
	case BinaryFormatELF:
		return p.parseELF(data)
	case BinaryFormatPE:
		return p.parsePE(data)
	case BinaryFormatMachO:
		return p.parseMachO(data)
	default:
		return nil, &InvalidMagicError{Magic: data[:4]}
	}
}

// detectFormat identifies the binary format from magic numbers
func (p *StandardLibParser) detectFormat(data []byte) BinaryFormat {
	if len(data) < 4 {
		return BinaryFormatUnknown
	}

	// check elf magic: 0x7F 'E' 'L' 'F'
	if data[0] == elfMagic0 && data[1] == elfMagic1 &&
		data[2] == elfMagic2 && data[3] == elfMagic3 {
		return BinaryFormatELF
	}

	// check pe magic: 'M' 'Z'
	if data[0] == peMagic0 && data[1] == peMagic1 {
		return BinaryFormatPE
	}

	// check mach-o magic (32-bit and 64-bit, both endianness)
	if len(data) >= 4 {
		magic := uint32(data[0])<<24 | uint32(data[1])<<16 |
			uint32(data[2])<<8 | uint32(data[3])

		switch magic {
		case machoMagic32, machoMagic64, machoMagicFat,
			machoMagic32Rev, machoMagic64Rev:
			return BinaryFormatMachO
		}
	}

	return BinaryFormatUnknown
}

// parseELF parses an ELF binary using debug/elf
func (p *StandardLibParser) parseELF(data []byte) (*BinaryInfo, error) {
	reader := bytes.NewReader(data)
	elfFile, err := elf.NewFile(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ELF: %w", err)
	}

	info := &BinaryInfo{
		Format:        BinaryFormatELF,
		Architecture:  p.detectELFArchitecture(elfFile),
		EntryPoint:    Address(elfFile.Entry),
		BaseAddress:   0, // will be computed for pie/pic
		GroundTruthDB: NewGroundTruthDatabase(),
		elfFile:       elfFile,
	}

	// extract sections
	info.Sections = p.extractELFSections(elfFile)

	// extract symbols (both static and dynamic)
	info.Symbols = p.extractELFSymbols(elfFile)

	// extract relocations
	info.Relocations = p.extractELFRelocations(elfFile)

	// extract imports and exports
	info.Imports, info.Exports = p.extractELFImportsExports(elfFile)

	// build ground-truth database
	p.buildGroundTruthDB(info)

	return info, nil
}

// parsePE parses a PE binary using debug/pe
func (p *StandardLibParser) parsePE(data []byte) (*BinaryInfo, error) {
	reader := bytes.NewReader(data)
	peFile, err := pe.NewFile(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PE: %w", err)
	}

	info := &BinaryInfo{
		Format:        BinaryFormatPE,
		Architecture:  p.detectPEArchitecture(peFile),
		GroundTruthDB: NewGroundTruthDatabase(),
		peFile:        peFile,
	}

	// extract entry point and base address
	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		info.EntryPoint = Address(oh.AddressOfEntryPoint)
		info.BaseAddress = Address(oh.ImageBase)
	case *pe.OptionalHeader64:
		info.EntryPoint = Address(oh.AddressOfEntryPoint)
		info.BaseAddress = Address(oh.ImageBase)
	}

	// extract sections
	info.Sections = p.extractPESections(peFile)

	// extract symbols
	info.Symbols = p.extractPESymbols(peFile)

	// extract imports and exports
	info.Imports = p.extractPEImports(peFile)
	info.Exports = p.extractPEExports(peFile)

	// extract relocations
	info.Relocations = p.extractPERelocations(peFile, data)

	// build ground-truth database
	p.buildGroundTruthDB(info)

	return info, nil
}

// parseMachO parses a Mach-O binary using debug/macho
func (p *StandardLibParser) parseMachO(data []byte) (*BinaryInfo, error) {
	reader := bytes.NewReader(data)
	machoFile, err := macho.NewFile(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Mach-O: %w", err)
	}

	info := &BinaryInfo{
		Format:        BinaryFormatMachO,
		Architecture:  p.detectMachOArchitecture(machoFile),
		EntryPoint:    p.findMachOEntryPoint(machoFile),
		BaseAddress:   0, // mach-o uses vmaddr from segments
		GroundTruthDB: NewGroundTruthDatabase(),
		machoFile:     machoFile,
	}

	// extract sections
	info.Sections = p.extractMachOSections(machoFile)

	// extract symbols
	info.Symbols = p.extractMachOSymbols(machoFile)

	// extract relocations
	info.Relocations = p.extractMachORelocations(machoFile)

	// extract imports and exports (dyld info)
	info.Imports, info.Exports = p.extractMachOImportsExports(machoFile)

	// build ground-truth database
	p.buildGroundTruthDB(info)

	return info, nil
}

// buildGroundTruthDB populates the ground-truth database from extracted data
func (p *StandardLibParser) buildGroundTruthDB(info *BinaryInfo) {
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

	// resolve got/plt entries from relocations
	for _, reloc := range info.Relocations {
		if reloc.Type == RelocationTypePLT || reloc.Type == RelocationTypeGOT ||
			reloc.Type == RelocationTypeJumpSlot {
			// map plt/got address to target symbol address
			if targetAddr, exists := db.SymbolsByName[reloc.Symbol]; exists {
				db.GOTPLT[reloc.Address] = targetAddr
			}
		}
	}
}
