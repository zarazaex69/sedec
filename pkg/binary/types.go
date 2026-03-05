package binfmt

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
)

// Address represents a virtual address in the binary
type Address uint64

// BinaryFormat represents the executable file format
type BinaryFormat int

const (
	BinaryFormatUnknown BinaryFormat = iota
	BinaryFormatELF
	BinaryFormatPE
	BinaryFormatMachO
)

func (f BinaryFormat) String() string {
	switch f {
	case BinaryFormatELF:
		return "ELF"
	case BinaryFormatPE:
		return "PE"
	case BinaryFormatMachO:
		return "Mach-O"
	default:
		return "Unknown"
	}
}

// Architecture represents the target CPU architecture
type Architecture int

const (
	ArchitectureUnknown Architecture = iota
	ArchitectureX86_64
	ArchitectureX86
	ArchitectureARM64
	ArchitectureARM
	ArchitectureMIPS
	ArchitectureMIPS64
	ArchitecturePPC
	ArchitecturePPC64
	ArchitectureRISCV
	ArchitectureRISCV64
)

func (a Architecture) String() string {
	switch a {
	case ArchitectureX86_64:
		return "x86_64"
	case ArchitectureX86:
		return "x86"
	case ArchitectureARM64:
		return "ARM64"
	case ArchitectureARM:
		return "ARM"
	case ArchitectureMIPS:
		return "MIPS"
	case ArchitectureMIPS64:
		return "MIPS64"
	case ArchitecturePPC:
		return "PowerPC"
	case ArchitecturePPC64:
		return "PowerPC64"
	case ArchitectureRISCV:
		return "RISC-V"
	case ArchitectureRISCV64:
		return "RISC-V64"
	default:
		return "Unknown"
	}
}

// Section represents a section in the binary
type Section struct {
	Name         string
	Address      Address
	Size         uint64
	Offset       uint64
	Flags        uint64
	Type         uint32
	Data         []byte
	IsExecutable bool
	IsWritable   bool
	IsAllocated  bool
}

// Symbol represents a symbol in the binary
type Symbol struct {
	Name    string
	Address Address
	Size    uint64
	Type    SymbolType
	Binding SymbolBinding
	Section string
}

// SymbolType represents the type of a symbol
type SymbolType int

const (
	SymbolTypeUnknown SymbolType = iota
	SymbolTypeFunction
	SymbolTypeObject
	SymbolTypeSection
	SymbolTypeFile
	SymbolTypeTLS
)

func (t SymbolType) String() string {
	switch t {
	case SymbolTypeFunction:
		return "Function"
	case SymbolTypeObject:
		return "Object"
	case SymbolTypeSection:
		return "Section"
	case SymbolTypeFile:
		return "File"
	case SymbolTypeTLS:
		return "TLS"
	default:
		return "Unknown"
	}
}

// SymbolBinding represents the binding of a symbol
type SymbolBinding int

const (
	SymbolBindingUnknown SymbolBinding = iota
	SymbolBindingLocal
	SymbolBindingGlobal
	SymbolBindingWeak
)

func (b SymbolBinding) String() string {
	switch b {
	case SymbolBindingLocal:
		return "Local"
	case SymbolBindingGlobal:
		return "Global"
	case SymbolBindingWeak:
		return "Weak"
	default:
		return "Unknown"
	}
}

// Relocation represents a relocation entry
type Relocation struct {
	Address   Address
	Symbol    string
	Type      RelocationType
	Addend    int64
	SymbolIdx uint32
}

// RelocationType represents the type of relocation
type RelocationType int

const (
	RelocationTypeUnknown RelocationType = iota
	RelocationTypeAbsolute
	RelocationTypeRelative
	RelocationTypePLT
	RelocationTypeGOT
	RelocationTypeCopy
	RelocationTypeJumpSlot
	RelocationTypeGlobDat
)

func (t RelocationType) String() string {
	switch t {
	case RelocationTypeAbsolute:
		return "Absolute"
	case RelocationTypeRelative:
		return "Relative"
	case RelocationTypePLT:
		return "PLT"
	case RelocationTypeGOT:
		return "GOT"
	case RelocationTypeCopy:
		return "Copy"
	case RelocationTypeJumpSlot:
		return "JumpSlot"
	case RelocationTypeGlobDat:
		return "GlobDat"
	default:
		return "Unknown"
	}
}

// Import represents an imported symbol
type Import struct {
	Name    string
	Address Address
	Library string
}

// Export represents an exported symbol
type Export struct {
	Name    string
	Address Address
	Ordinal uint32
}

// GroundTruthDatabase stores statically resolved addresses
// from relocation tables, import tables, and export tables.
// This serves as ground-truth axioms before expensive symbolic analysis.
type GroundTruthDatabase struct {
	// Relocations maps addresses to their relocation entries
	Relocations map[Address]*Relocation

	// Imports maps addresses to imported symbols
	Imports map[Address]*Import

	// Exports maps addresses to exported symbols
	Exports map[Address]*Export

	// GOTPLT maps GOT/PLT addresses to their resolved targets
	GOTPLT map[Address]Address

	// SymbolsByAddress maps addresses to symbol names
	SymbolsByAddress map[Address]string

	// SymbolsByName maps symbol names to addresses
	SymbolsByName map[string]Address
}

// NewGroundTruthDatabase creates a new empty ground-truth database
func NewGroundTruthDatabase() *GroundTruthDatabase {
	return &GroundTruthDatabase{
		Relocations:      make(map[Address]*Relocation),
		Imports:          make(map[Address]*Import),
		Exports:          make(map[Address]*Export),
		GOTPLT:           make(map[Address]Address),
		SymbolsByAddress: make(map[Address]string),
		SymbolsByName:    make(map[string]Address),
	}
}

// BinaryInfo contains all extracted information from a binary
type BinaryInfo struct {
	Format        BinaryFormat
	Architecture  Architecture
	EntryPoint    Address
	BaseAddress   Address
	Sections      []*Section
	Symbols       []*Symbol
	Relocations   []*Relocation
	Imports       []*Import
	Exports       []*Export
	GroundTruthDB *GroundTruthDatabase

	// raw file handles for format-specific operations
	elfFile   *elf.File
	peFile    *pe.File
	machoFile *macho.File
}

// Close releases resources associated with the binary
func (bi *BinaryInfo) Close() error {
	if bi == nil {
		return nil
	}
	if bi.elfFile != nil {
		return bi.elfFile.Close()
	}
	if bi.peFile != nil {
		return bi.peFile.Close()
	}
	if bi.machoFile != nil {
		return bi.machoFile.Close()
	}
	return nil
}
