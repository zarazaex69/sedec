package binfmt

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
)

const unknownStr = "Unknown"

// Address represents a virtual address in the binary
type Address uint64

// BinaryFormat represents the executable file format
type BinaryFormat int

const (
	// BinaryFormatUnknown represents an unknown or unsupported binary format
	BinaryFormatUnknown BinaryFormat = iota
	// BinaryFormatELF represents the ELF (Executable and Linkable Format)
	BinaryFormatELF
	// BinaryFormatPE represents the PE (Portable Executable) format
	BinaryFormatPE
	// BinaryFormatMachO represents the Mach-O (Mach Object) format
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
	case BinaryFormatUnknown:
		return unknownStr
	default:
		return unknownStr
	}
}

// Architecture represents the target CPU architecture
type Architecture int

const (
	// ArchitectureUnknown represents an unknown or unsupported architecture
	ArchitectureUnknown Architecture = iota
	// ArchitectureX86_64 represents the x86-64 (AMD64) architecture
	ArchitectureX86_64
	// ArchitectureX86 represents the x86 (i386) architecture
	ArchitectureX86
	// ArchitectureARM64 represents the ARM64 (AArch64) architecture
	ArchitectureARM64
	// ArchitectureARM represents the ARM architecture
	ArchitectureARM
	// ArchitectureMIPS represents the MIPS architecture
	ArchitectureMIPS
	// ArchitectureMIPS64 represents the MIPS64 architecture
	ArchitectureMIPS64
	// ArchitecturePPC represents the PowerPC architecture
	ArchitecturePPC
	// ArchitecturePPC64 represents the PowerPC64 architecture
	ArchitecturePPC64
	// ArchitectureRISCV represents the RISC-V 32-bit architecture
	ArchitectureRISCV
	// ArchitectureRISCV64 represents the RISC-V 64-bit architecture
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
	case ArchitectureUnknown:
		return unknownStr
	default:
		return unknownStr
	}
}

// Section represents a section in the binary
type Section struct {
	Name         string
	Data         []byte
	Address      Address
	Size         uint64
	Offset       uint64
	Flags        uint64
	Type         uint32
	IsExecutable bool
	IsWritable   bool
	IsAllocated  bool
}

// Symbol represents a symbol in the binary
type Symbol struct {
	Name    string
	Section string
	Address Address
	Size    uint64
	Type    SymbolType
	Binding SymbolBinding
}

// SymbolType represents the type of a symbol
type SymbolType int

const (
	// SymbolTypeUnknown represents an unknown symbol type
	SymbolTypeUnknown SymbolType = iota
	// SymbolTypeFunction represents a function symbol
	SymbolTypeFunction
	// SymbolTypeObject represents a data object symbol
	SymbolTypeObject
	// SymbolTypeSection represents a section symbol
	SymbolTypeSection
	// SymbolTypeFile represents a file symbol
	SymbolTypeFile
	// SymbolTypeTLS represents a thread-local storage symbol
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
	case SymbolTypeUnknown:
		return unknownStr
	default:
		return unknownStr
	}
}

// SymbolBinding represents the binding of a symbol
type SymbolBinding int

const (
	// SymbolBindingUnknown represents an unknown symbol binding
	SymbolBindingUnknown SymbolBinding = iota
	// SymbolBindingLocal represents a local symbol binding
	SymbolBindingLocal
	// SymbolBindingGlobal represents a global symbol binding
	SymbolBindingGlobal
	// SymbolBindingWeak represents a weak symbol binding
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
	case SymbolBindingUnknown:
		return unknownStr
	default:
		return unknownStr
	}
}

// Relocation represents a relocation entry
type Relocation struct {
	Symbol    string
	Address   Address
	Type      RelocationType
	Addend    int64
	SymbolIdx uint32
}

// RelocationType represents the type of relocation
type RelocationType int

const (
	// RelocationTypeUnknown represents an unknown relocation type
	RelocationTypeUnknown RelocationType = iota
	// RelocationTypeAbsolute represents an absolute relocation
	RelocationTypeAbsolute
	// RelocationTypeRelative represents a relative relocation
	RelocationTypeRelative
	// RelocationTypePLT represents a PLT (Procedure Linkage Table) relocation
	RelocationTypePLT
	// RelocationTypeGOT represents a GOT (Global Offset Table) relocation
	RelocationTypeGOT
	// RelocationTypeCopy represents a copy relocation
	RelocationTypeCopy
	// RelocationTypeJumpSlot represents a jump slot relocation
	RelocationTypeJumpSlot
	// RelocationTypeGlobDat represents a global data relocation
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
	case RelocationTypeUnknown:
		return unknownStr
	default:
		return unknownStr
	}
}

// Import represents an imported symbol
type Import struct {
	Name    string
	Library string
	Address Address
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
	GroundTruthDB *GroundTruthDatabase
	elfFile       *elf.File
	peFile        *pe.File
	machoFile     *macho.File
	Sections      []*Section
	Symbols       []*Symbol
	Relocations   []*Relocation
	Imports       []*Import
	Exports       []*Export
	EntryPoint    Address
	BaseAddress   Address
	Format        BinaryFormat
	Architecture  Architecture
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
