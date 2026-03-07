package binfmt

import (
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// mach-o segment names.
	segmentNameText = "__TEXT"
)

var (
	// errBinaryInfoNil indicates binary info is nil.
	errBinaryInfoNil = errors.New("binary info is nil")
	// errUnsupportedBinaryFormat indicates unsupported binary format.
	errUnsupportedBinaryFormat = errors.New("unsupported binary format")
	// errELFFileNil indicates elf file is nil.
	errELFFileNil = errors.New("elf file is nil")
	// errUnknownELFClass indicates unknown elf class.
	errUnknownELFClass = errors.New("unknown elf class")
	// errUnsupportedArchitecture indicates unsupported architecture.
	errUnsupportedArchitecture = errors.New("unsupported architecture for plt resolution")
	// errPLTEntryTooShort indicates plt entry too short.
	errPLTEntryTooShort = errors.New("plt entry too short")
	// errInvalidPLTEntry indicates invalid plt entry.
	errInvalidPLTEntry = errors.New("invalid plt entry: expected jmp instruction")
	// errMachOFileNil indicates mach-o file is nil.
	errMachOFileNil = errors.New("mach-o file is nil")
	// errStubTooShort indicates stub too short.
	errStubTooShort = errors.New("stub too short")
	// errInvalidStub indicates invalid stub.
	errInvalidStub = errors.New("invalid stub: expected jmp instruction")
)

// GOTEntry represents a Global Offset Table entry.
// fields ordered for optimal memory alignment.
type GOTEntry struct {
	TargetSymbol  string         // 16 bytes (pointer + length)
	Address       Address        // 8 bytes
	TargetAddress Address        // 8 bytes
	RelocType     RelocationType // 4 bytes
	// total: 36 bytes (with padding: 40 bytes)
}

// PLTEntry represents a Procedure Linkage Table stub.
// fields ordered for optimal memory alignment.
type PLTEntry struct {
	TargetSymbol  string  // 16 bytes (pointer + length)
	Address       Address // 8 bytes
	GOTAddress    Address // 8 bytes
	TargetAddress Address // 8 bytes
	// total: 40 bytes
}

// ResolveGOTEntries resolves Global Offset Table entries from relocations.
// This function performs O(1) lookup by building a map of GOT addresses to their resolved targets.
// It handles both static and dynamic relocations, including R_X86_64_GLOB_DAT and R_X86_64_RELATIVE.
//
// For PIE/PIC binaries, addresses are computed relative to the base address.
// The function returns a map for constant-time address resolution during analysis.
func (p *StandardLibParser) ResolveGOTEntries(info *BinaryInfo) (map[Address]*GOTEntry, error) {
	if info == nil {
		return nil, errBinaryInfoNil
	}

	gotEntries := make(map[Address]*GOTEntry)

	switch info.Format {
	case BinaryFormatELF:
		return p.resolveELFGOT(info, gotEntries)
	case BinaryFormatPE:
		return p.resolvePEGOT(info, gotEntries)
	case BinaryFormatMachO:
		return p.resolveMachOGOT(info, gotEntries)
	case BinaryFormatUnknown:
		return nil, fmt.Errorf("%w: %v", errUnsupportedBinaryFormat, info.Format)
	default:
		return nil, fmt.Errorf("%w: %v", errUnsupportedBinaryFormat, info.Format)
	}
}

// ResolvePLTStubs resolves Procedure Linkage Table stubs to their target functions.
// PLT stubs are small code sequences that jump through GOT entries for lazy binding.
// This function identifies PLT entries and maps them to their corresponding GOT entries
// and ultimate target symbols.
//
// For x86_64, PLT entries follow a standard pattern:
//
//	jmp *GOT[n](%rip)
//	push $index
//	jmp PLT[0]
//
// The function returns a map for O(1) lookup during control flow analysis.
func (p *StandardLibParser) ResolvePLTStubs(info *BinaryInfo) (map[Address]*PLTEntry, error) {
	if info == nil {
		return nil, errBinaryInfoNil
	}

	pltEntries := make(map[Address]*PLTEntry)

	switch info.Format {
	case BinaryFormatELF:
		return p.resolveELFPLT(info, pltEntries)
	case BinaryFormatPE:
		// pe uses iat (import address table) instead of plt
		return p.resolvePEIAT(info, pltEntries)
	case BinaryFormatMachO:
		return p.resolveMachOPLT(info, pltEntries)
	case BinaryFormatUnknown:
		return nil, fmt.Errorf("%w: %v", errUnsupportedBinaryFormat, info.Format)
	default:
		return nil, fmt.Errorf("%w: %v", errUnsupportedBinaryFormat, info.Format)
	}
}

// CalculateBaseAddress computes the base address for PIE/PIC binaries.
// For position-independent executables, the actual runtime base address differs
// from the link-time base address. This function determines the correct base
// by analyzing PT_LOAD segments and their virtual addresses.
//
// For ELF: finds the lowest PT_LOAD segment virtual address.
// For PE: uses ImageBase from optional header.
// For Mach-O: uses __TEXT segment virtual address.
func (p *StandardLibParser) CalculateBaseAddress(info *BinaryInfo) (Address, error) {
	if info == nil {
		return 0, errBinaryInfoNil
	}

	switch info.Format {
	case BinaryFormatELF:
		return p.calculateELFBaseAddress(info)
	case BinaryFormatPE:
		// pe base address is already set in info.BaseAddress during parsing
		return info.BaseAddress, nil
	case BinaryFormatMachO:
		return p.calculateMachOBaseAddress(info)
	case BinaryFormatUnknown:
		return 0, fmt.Errorf("%w: %v", errUnsupportedBinaryFormat, info.Format)
	default:
		return 0, fmt.Errorf("%w: %v", errUnsupportedBinaryFormat, info.Format)
	}
}

// resolveELFGOT resolves GOT entries for ELF binaries.
func (p *StandardLibParser) resolveELFGOT(info *BinaryInfo, gotEntries map[Address]*GOTEntry) (map[Address]*GOTEntry, error) {
	if info.elfFile == nil {
		return nil, errELFFileNil
	}

	// find .got and .got.plt sections
	gotSection, gotPltSection := p.findELFGOTSections(info.elfFile)

	// process relocations to resolve got entries
	p.processELFRelocations(info, gotEntries)

	// parse got section data for additional entries
	if gotSection != nil {
		if err := p.parseELFGOTSection(info, gotSection, gotEntries); err != nil {
			return gotEntries, fmt.Errorf("failed to parse .got section: %w", err)
		}
	}

	if gotPltSection != nil {
		if err := p.parseELFGOTSection(info, gotPltSection, gotEntries); err != nil {
			return gotEntries, fmt.Errorf("failed to parse .got.plt section: %w", err)
		}
	}

	return gotEntries, nil
}

// findELFGOTSections finds .got and .got.plt sections.
func (p *StandardLibParser) findELFGOTSections(elfFile *elf.File) (gotSection, gotPltSection *elf.Section) {
	for _, section := range elfFile.Sections {
		switch section.Name {
		case ".got":
			gotSection = section
		case ".got.plt":
			gotPltSection = section
		}
	}
	return gotSection, gotPltSection
}

// processELFRelocations processes relocations and creates GOT entries.
func (p *StandardLibParser) processELFRelocations(info *BinaryInfo, gotEntries map[Address]*GOTEntry) {
	for _, reloc := range info.Relocations {
		entry := p.createGOTEntryFromRelocation(info, reloc)
		if entry != nil {
			gotEntries[entry.Address] = entry
			// update ground-truth database
			if entry.TargetAddress != 0 {
				info.GroundTruthDB.GOTPLT[entry.Address] = entry.TargetAddress
			}
		}
	}
}

// createGOTEntryFromRelocation creates a GOT entry from a relocation.
func (p *StandardLibParser) createGOTEntryFromRelocation(info *BinaryInfo, reloc *Relocation) *GOTEntry {
	switch reloc.Type {
	case RelocationTypeGOT, RelocationTypeGlobDat:
		return p.createGlobalDataGOTEntry(info, reloc)
	case RelocationTypeJumpSlot:
		return p.createJumpSlotGOTEntry(info, reloc)
	case RelocationTypeRelative:
		return p.createRelativeGOTEntry(info, reloc)
	case RelocationTypeUnknown, RelocationTypeAbsolute, RelocationTypePLT, RelocationTypeCopy:
		return nil
	default:
		return nil
	}
}

// createGlobalDataGOTEntry creates GOT entry for global data.
func (p *StandardLibParser) createGlobalDataGOTEntry(info *BinaryInfo, reloc *Relocation) *GOTEntry {
	entry := &GOTEntry{
		Address:      reloc.Address,
		TargetSymbol: reloc.Symbol,
		RelocType:    reloc.Type,
	}
	// resolve target address from symbol table
	if targetAddr, exists := info.GroundTruthDB.SymbolsByName[reloc.Symbol]; exists {
		entry.TargetAddress = targetAddr
	}
	return entry
}

// createJumpSlotGOTEntry creates GOT entry for PLT stub.
func (p *StandardLibParser) createJumpSlotGOTEntry(info *BinaryInfo, reloc *Relocation) *GOTEntry {
	entry := &GOTEntry{
		Address:      reloc.Address,
		TargetSymbol: reloc.Symbol,
		RelocType:    reloc.Type,
	}
	// resolve target address from symbol table
	if targetAddr, exists := info.GroundTruthDB.SymbolsByName[reloc.Symbol]; exists {
		entry.TargetAddress = targetAddr
	}
	return entry
}

// createRelativeGOTEntry creates GOT entry for relative relocation.
func (p *StandardLibParser) createRelativeGOTEntry(info *BinaryInfo, reloc *Relocation) *GOTEntry {
	// for pie/pic binaries, use info.BaseAddress if set, otherwise calculate
	baseAddr := info.BaseAddress
	if baseAddr == 0 {
		var err error
		baseAddr, err = p.calculateELFBaseAddress(info)
		if err != nil {
			return nil
		}
	}

	// safe conversion: addend is signed offset, base is unsigned address
	var targetAddr Address
	if reloc.Addend >= 0 {
		targetAddr = Address(uint64(baseAddr) + uint64(reloc.Addend))
	} else {
		// handle negative addend
		targetAddr = Address(uint64(baseAddr) - uint64(-reloc.Addend))
	}

	return &GOTEntry{
		Address:       reloc.Address,
		TargetAddress: targetAddr,
		TargetSymbol:  "", // relative relocations don't have symbols
		RelocType:     reloc.Type,
	}
}

// parseELFGOTSection parses a GOT section and extracts entries.
func (p *StandardLibParser) parseELFGOTSection(info *BinaryInfo, section *elf.Section, gotEntries map[Address]*GOTEntry) error {
	data, err := section.Data()
	if err != nil {
		return fmt.Errorf("failed to read section data: %w", err)
	}

	// determine pointer size based on architecture
	var pointerSize int
	switch info.elfFile.Class {
	case elf.ELFCLASS64:
		pointerSize = 8
	case elf.ELFCLASS32:
		pointerSize = 4
	case elf.ELFCLASSNONE:
		return fmt.Errorf("%w: %v", errUnknownELFClass, info.elfFile.Class)
	default:
		return fmt.Errorf("%w: %v", errUnknownELFClass, info.elfFile.Class)
	}

	// iterate through got entries
	for offset := 0; offset+pointerSize <= len(data); offset += pointerSize {
		entryAddr := Address(section.Addr + uint64(offset))

		// skip if already resolved via relocations
		if _, exists := gotEntries[entryAddr]; exists {
			continue
		}

		// read pointer value
		var targetAddr Address
		switch pointerSize {
		case 8:
			targetAddr = Address(info.elfFile.ByteOrder.Uint64(data[offset : offset+8]))
		case 4:
			targetAddr = Address(info.elfFile.ByteOrder.Uint32(data[offset : offset+4]))
		}

		// skip null entries
		if targetAddr == 0 {
			continue
		}

		// create got entry
		entry := &GOTEntry{
			Address:       entryAddr,
			TargetAddress: targetAddr,
			TargetSymbol:  "", // will be resolved if symbol exists
			RelocType:     RelocationTypeGOT,
		}

		// try to resolve symbol name
		if symName, exists := info.GroundTruthDB.SymbolsByAddress[targetAddr]; exists {
			entry.TargetSymbol = symName
		}

		gotEntries[entryAddr] = entry
	}

	return nil
}

// resolveELFPLT resolves PLT stubs for ELF binaries.
func (p *StandardLibParser) resolveELFPLT(info *BinaryInfo, pltEntries map[Address]*PLTEntry) (map[Address]*PLTEntry, error) {
	if info.elfFile == nil {
		return nil, errELFFileNil
	}

	// find .plt and .plt.got sections
	pltSection, pltGotSection := p.findELFPLTSections(info.elfFile)

	if pltSection == nil {
		// no plt section, return empty map (not an error)
		return pltEntries, nil
	}

	// process main plt section
	if err := p.processELFPLTSection(info, pltSection, pltEntries); err != nil {
		return nil, err
	}

	// process .plt.got section if present
	if pltGotSection != nil {
		if parseErr := p.parseELFPLTGotSection(info, pltGotSection, pltEntries); parseErr != nil {
			return pltEntries, fmt.Errorf("failed to parse .plt.got section: %w", parseErr)
		}
	}

	return pltEntries, nil
}

// findELFPLTSections finds .plt and .plt.got sections.
func (p *StandardLibParser) findELFPLTSections(elfFile *elf.File) (pltSection, pltGotSection *elf.Section) {
	for _, section := range elfFile.Sections {
		switch section.Name {
		case ".plt":
			pltSection = section
		case ".plt.got":
			pltGotSection = section
		}
	}
	return pltSection, pltGotSection
}

// processELFPLTSection processes main PLT section.
func (p *StandardLibParser) processELFPLTSection(info *BinaryInfo, pltSection *elf.Section, pltEntries map[Address]*PLTEntry) error {
	// read plt section data
	pltData, err := pltSection.Data()
	if err != nil {
		return fmt.Errorf("failed to read .plt section: %w", err)
	}

	// get plt entry size for architecture
	pltEntrySize, err := p.getPLTEntrySize(info.Architecture)
	if err != nil {
		return err
	}

	// first entry is plt[0] (resolver stub), skip it
	pltBaseAddr := Address(pltSection.Addr)

	// iterate through plt entries (skip first entry which is resolver stub)
	for offset := pltEntrySize; offset+pltEntrySize <= len(pltData); offset += pltEntrySize {
		// offset is always positive in this loop (starts at pltEntrySize > 0)
		//nolint:gosec // G115: safe conversion - offset validated by loop bounds
		offsetAddr := uint64(offset)
		pltAddr := pltBaseAddr + Address(offsetAddr)
		entry := p.parseSinglePLTEntry(info, pltData[offset:offset+pltEntrySize], pltAddr)
		if entry != nil {
			pltEntries[pltAddr] = entry
			// update ground-truth database
			if entry.TargetSymbol != "" {
				info.GroundTruthDB.SymbolsByAddress[pltAddr] = entry.TargetSymbol + "@plt"
			}
		}
	}

	return nil
}

// getPLTEntrySize returns PLT entry size for architecture.
func (p *StandardLibParser) getPLTEntrySize(arch Architecture) (int, error) {
	switch arch {
	case ArchitectureX86_64, ArchitectureX86, ArchitectureARM64:
		return 16, nil
	case ArchitectureARM:
		return 12, nil
	case ArchitectureUnknown, ArchitectureMIPS, ArchitectureMIPS64,
		ArchitecturePPC, ArchitecturePPC64, ArchitectureRISCV, ArchitectureRISCV64:
		return 0, fmt.Errorf("%w: %v", errUnsupportedArchitecture, arch)
	default:
		return 0, fmt.Errorf("%w: %v", errUnsupportedArchitecture, arch)
	}
}

// parseSinglePLTEntry parses a single PLT entry and creates PLTEntry.
func (p *StandardLibParser) parseSinglePLTEntry(info *BinaryInfo, data []byte, pltAddr Address) *PLTEntry {
	// parse plt entry to extract got address
	gotAddress, parseErr := p.parseELFPLTEntry(info, data, pltAddr)
	if parseErr != nil {
		return nil
	}

	// resolve target from got entry
	targetAddr := info.GroundTruthDB.GOTPLT[gotAddress]

	// find symbol name from relocations
	targetSymbol := p.findSymbolForGOTAddress(info, gotAddress)

	return &PLTEntry{
		Address:       pltAddr,
		GOTAddress:    gotAddress,
		TargetAddress: targetAddr,
		TargetSymbol:  targetSymbol,
	}
}

// findSymbolForGOTAddress finds symbol name for GOT address.
func (p *StandardLibParser) findSymbolForGOTAddress(info *BinaryInfo, gotAddress Address) string {
	for _, reloc := range info.Relocations {
		if reloc.Address == gotAddress && reloc.Type == RelocationTypeJumpSlot {
			return reloc.Symbol
		}
	}
	return ""
}

// parseELFPLTEntry extracts the GOT address from a PLT entry.
func (p *StandardLibParser) parseELFPLTEntry(info *BinaryInfo, data []byte, pltAddr Address) (Address, error) {
	if len(data) < 6 {
		return 0, errPLTEntryTooShort
	}

	switch info.Architecture {
	case ArchitectureX86_64:
		// x86_64 plt entry format:
		// jmp *GOT[n](%rip)  ; ff 25 xx xx xx xx
		// push $index        ; 68 xx xx xx xx
		// jmp PLT[0]         ; e9 xx xx xx xx

		// check for jmp instruction (0xff 0x25)
		if data[0] != 0xff || data[1] != 0x25 {
			return 0, errInvalidPLTEntry
		}

		// extract rip-relative offset (little endian)
		// safe conversion: reading 4 bytes as signed 32-bit offset
		offsetBytes := binary.LittleEndian.Uint32(data[2:6])
		// explicit sign extension from uint32 to int64
		var ripOffset int64
		if offsetBytes&0x80000000 != 0 {
			// negative offset: sign extend
			ripOffset = int64(offsetBytes) | ^0xFFFFFFFF
		} else {
			// positive offset
			ripOffset = int64(offsetBytes)
		}

		// calculate got address: plt_addr + 6 (instruction length) + rip_offset
		// safe: pltAddr is uint64, ripOffset is int64
		var gotAddr Address
		if ripOffset >= 0 {
			gotAddr = Address(uint64(pltAddr) + 6 + uint64(ripOffset))
		} else {
			gotAddr = Address(uint64(pltAddr) + 6 - uint64(-ripOffset))
		}

		return gotAddr, nil

	case ArchitectureX86:
		// x86 plt entry format:
		// jmp *GOT[n]  ; ff 25 xx xx xx xx
		// push $index  ; 68 xx xx xx xx
		// jmp PLT[0]   ; e9 xx xx xx xx

		if data[0] != 0xff || data[1] != 0x25 {
			return 0, errInvalidPLTEntry
		}

		// extract absolute got address (little endian)
		gotAddr := Address(binary.LittleEndian.Uint32(data[2:6]))

		return gotAddr, nil

	case ArchitectureUnknown, ArchitectureARM64, ArchitectureARM,
		ArchitectureMIPS, ArchitectureMIPS64, ArchitecturePPC, ArchitecturePPC64,
		ArchitectureRISCV, ArchitectureRISCV64:
		return 0, fmt.Errorf("%w: %v", errUnsupportedArchitecture, info.Architecture)
	default:
		return 0, fmt.Errorf("%w: %v", errUnsupportedArchitecture, info.Architecture)
	}
}

// parseELFPLTGotSection parses .plt.got section (used for non-lazy binding).
func (p *StandardLibParser) parseELFPLTGotSection(info *BinaryInfo, section *elf.Section, pltEntries map[Address]*PLTEntry) error {
	data, err := section.Data()
	if err != nil {
		return fmt.Errorf("failed to read section data: %w", err)
	}

	// .plt.got entries are typically 8 bytes on x86_64
	entrySize := 8
	if info.Architecture == ArchitectureX86 {
		entrySize = 8
	}

	baseAddr := Address(section.Addr)

	for offset := 0; offset+entrySize <= len(data); offset += entrySize {
		pltAddr := Address(uint64(baseAddr) + uint64(offset))

		// parse entry to extract got address
		gotAddress, parseErr := p.parseELFPLTEntry(info, data[offset:offset+entrySize], pltAddr)
		if parseErr != nil {
			continue
		}

		// resolve target from got
		var targetAddr Address
		var targetSymbol string

		if gotEntry, exists := info.GroundTruthDB.GOTPLT[gotAddress]; exists {
			targetAddr = gotEntry
		}

		// find symbol name
		for _, reloc := range info.Relocations {
			if reloc.Address == gotAddress {
				targetSymbol = reloc.Symbol
				break
			}
		}

		entry := &PLTEntry{
			Address:       pltAddr,
			GOTAddress:    gotAddress,
			TargetAddress: targetAddr,
			TargetSymbol:  targetSymbol,
		}

		pltEntries[pltAddr] = entry
	}

	return nil
}

// calculateELFBaseAddress computes base address for ELF PIE/PIC binaries.
func (p *StandardLibParser) calculateELFBaseAddress(info *BinaryInfo) (Address, error) {
	if info.elfFile == nil {
		return 0, errELFFileNil
	}

	// check if this is a pie/pic binary
	if info.elfFile.Type != elf.ET_DYN {
		// not pie/pic, base address is 0
		return 0, nil
	}

	// find lowest pt_load segment virtual address
	minVAddr := ^uint64(0) // max uint64

	for _, prog := range info.elfFile.Progs {
		if prog.Type == elf.PT_LOAD {
			if prog.Vaddr < minVAddr {
				minVAddr = prog.Vaddr
			}
		}
	}

	if minVAddr == ^uint64(0) {
		// no pt_load segments found
		return 0, nil
	}

	// for pie binaries, base address is typically the lowest load address
	// aligned to page boundary (usually 0x0 or 0x400000)
	return Address(minVAddr), nil
}

// resolvePEGOT resolves GOT-equivalent entries for PE binaries (IAT).
func (p *StandardLibParser) resolvePEGOT(info *BinaryInfo, gotEntries map[Address]*GOTEntry) (map[Address]*GOTEntry, error) {
	// pe uses import address table (iat) instead of got
	// iat entries are resolved during import parsing
	for _, imp := range info.Imports {
		entry := &GOTEntry{
			Address:      imp.Address,
			TargetSymbol: imp.Name,
			RelocType:    RelocationTypeGOT,
		}

		// target address is the iat entry itself for pe
		entry.TargetAddress = imp.Address

		gotEntries[imp.Address] = entry
	}

	return gotEntries, nil
}

// resolvePEIAT resolves Import Address Table for PE binaries.
func (p *StandardLibParser) resolvePEIAT(info *BinaryInfo, pltEntries map[Address]*PLTEntry) (map[Address]*PLTEntry, error) {
	// pe doesn't have plt stubs like elf
	// instead, calls go directly through iat
	// we create pseudo-plt entries for consistency
	for _, imp := range info.Imports {
		entry := &PLTEntry{
			Address:       imp.Address,
			GOTAddress:    imp.Address, // iat entry is both plt and got
			TargetAddress: imp.Address,
			TargetSymbol:  imp.Name,
		}

		pltEntries[imp.Address] = entry
	}

	return pltEntries, nil
}

// resolveMachOGOT resolves GOT entries for Mach-O binaries.
func (p *StandardLibParser) resolveMachOGOT(info *BinaryInfo, gotEntries map[Address]*GOTEntry) (map[Address]*GOTEntry, error) {
	// mach-o uses __DATA.__got and __DATA.__la_symbol_ptr sections
	// resolve from relocations
	for _, reloc := range info.Relocations {
		if reloc.Type == RelocationTypeGOT {
			entry := &GOTEntry{
				Address:      reloc.Address,
				TargetSymbol: reloc.Symbol,
				RelocType:    reloc.Type,
			}

			// resolve target address
			if targetAddr, exists := info.GroundTruthDB.SymbolsByName[reloc.Symbol]; exists {
				entry.TargetAddress = targetAddr
			}

			gotEntries[entry.Address] = entry
		}
	}

	return gotEntries, nil
}

// resolveMachOPLT resolves PLT-equivalent stubs for Mach-O binaries.
func (p *StandardLibParser) resolveMachOPLT(info *BinaryInfo, pltEntries map[Address]*PLTEntry) (map[Address]*PLTEntry, error) {
	// mach-o uses __TEXT.__stubs section for lazy binding
	if info.machoFile == nil {
		return pltEntries, nil
	}

	// find __TEXT.__stubs section
	var stubsSection *Section
	for _, section := range info.Sections {
		if section.Name == "__stubs" {
			stubsSection = section
			break
		}
	}

	if stubsSection == nil {
		return pltEntries, nil
	}

	// stub size varies by architecture
	var stubSize int
	switch info.Architecture {
	case ArchitectureX86_64:
		stubSize = 6 // jmp *addr(%rip)
	case ArchitectureARM64:
		stubSize = 12 // 3 instructions
	case ArchitectureUnknown, ArchitectureX86, ArchitectureARM,
		ArchitectureMIPS, ArchitectureMIPS64, ArchitecturePPC, ArchitecturePPC64,
		ArchitectureRISCV, ArchitectureRISCV64:
		return pltEntries, nil
	default:
		return pltEntries, nil
	}

	// iterate through stubs
	for offset := 0; offset+stubSize <= len(stubsSection.Data); offset += stubSize {
		stubAddr := Address(uint64(stubsSection.Address) + uint64(offset))

		// parse stub to extract got address
		gotAddr, err := p.parseMachOStub(info, stubsSection.Data[offset:offset+stubSize], stubAddr)
		if err != nil {
			continue
		}

		// resolve target
		var targetAddr Address
		var targetSymbol string

		if gotEntry, exists := info.GroundTruthDB.GOTPLT[gotAddr]; exists {
			targetAddr = gotEntry
		}

		// find symbol from relocations
		for _, reloc := range info.Relocations {
			if reloc.Address == gotAddr {
				targetSymbol = reloc.Symbol
				break
			}
		}

		entry := &PLTEntry{
			Address:       stubAddr,
			GOTAddress:    gotAddr,
			TargetAddress: targetAddr,
			TargetSymbol:  targetSymbol,
		}

		pltEntries[stubAddr] = entry
	}

	return pltEntries, nil
}

// parseMachOStub extracts GOT address from Mach-O stub.
func (p *StandardLibParser) parseMachOStub(info *BinaryInfo, data []byte, stubAddr Address) (Address, error) {
	if len(data) < 6 {
		return 0, errStubTooShort
	}

	switch info.Architecture {
	case ArchitectureX86_64:
		// x86_64 stub: jmp *addr(%rip)  ; ff 25 xx xx xx xx
		if data[0] != 0xff || data[1] != 0x25 {
			return 0, errInvalidStub
		}

		// extract rip-relative offset with safe sign extension
		offsetBytes := binary.LittleEndian.Uint32(data[2:6])
		// explicit sign extension from uint32 to int64
		var ripOffset int64
		if offsetBytes&0x80000000 != 0 {
			// negative offset: sign extend
			ripOffset = int64(offsetBytes) | ^0xFFFFFFFF
		} else {
			// positive offset
			ripOffset = int64(offsetBytes)
		}

		// calculate got address with safe arithmetic
		var gotAddr Address
		if ripOffset >= 0 {
			gotAddr = Address(uint64(stubAddr) + 6 + uint64(ripOffset))
		} else {
			gotAddr = Address(uint64(stubAddr) + 6 - uint64(-ripOffset))
		}

		return gotAddr, nil

	case ArchitectureUnknown, ArchitectureX86, ArchitectureARM64, ArchitectureARM,
		ArchitectureMIPS, ArchitectureMIPS64, ArchitecturePPC, ArchitecturePPC64,
		ArchitectureRISCV, ArchitectureRISCV64:
		return 0, fmt.Errorf("%w: %v", errUnsupportedArchitecture, info.Architecture)
	default:
		return 0, fmt.Errorf("%w: %v", errUnsupportedArchitecture, info.Architecture)
	}
}

// calculateMachOBaseAddress computes base address for Mach-O binaries.
func (p *StandardLibParser) calculateMachOBaseAddress(info *BinaryInfo) (Address, error) {
	if info.machoFile == nil {
		return 0, errMachOFileNil
	}

	// find __TEXT segment
	for _, load := range info.machoFile.Loads {
		if seg, ok := load.(*macho.Segment); ok {
			if seg.Name == segmentNameText {
				return Address(seg.Addr), nil
			}
		}
	}

	// default to 0 if __TEXT not found
	return 0, nil
}
