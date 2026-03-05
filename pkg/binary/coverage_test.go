package binfmt

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"testing"
)

// TestELFArchitectureDetection tests all ELF architecture variants
func TestELFArchitectureDetection(t *testing.T) {
	parser := NewStandardLibParser()

	tests := []struct {
		machine elf.Machine
		class   elf.Class
		want    Architecture
	}{
		{elf.EM_X86_64, elf.ELFCLASS64, ArchitectureX86_64},
		{elf.EM_386, elf.ELFCLASS32, ArchitectureX86},
		{elf.EM_AARCH64, elf.ELFCLASS64, ArchitectureARM64},
		{elf.EM_ARM, elf.ELFCLASS32, ArchitectureARM},
		{elf.EM_MIPS, elf.ELFCLASS32, ArchitectureMIPS},
		{elf.EM_PPC, elf.ELFCLASS32, ArchitecturePPC},
		{elf.EM_PPC64, elf.ELFCLASS64, ArchitecturePPC64},
		{elf.EM_RISCV, elf.ELFCLASS64, ArchitectureRISCV64},
		{elf.EM_RISCV, elf.ELFCLASS32, ArchitectureRISCV},
		{elf.Machine(999), elf.ELFCLASS64, ArchitectureUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.want.String(), func(t *testing.T) {
			elfFile := &elf.File{
				FileHeader: elf.FileHeader{
					Machine: tt.machine,
					Class:   tt.class,
				},
			}
			got := parser.detectELFArchitecture(elfFile)
			if got != tt.want {
				t.Errorf("detectELFArchitecture(%v, %v) = %v, want %v", tt.machine, tt.class, got, tt.want)
			}
		})
	}
}

// TestELFRelocationTypeConversion tests all ELF relocation type conversions
func TestELFRelocationTypeConversion(t *testing.T) {
	parser := NewStandardLibParser()

	// x86_64 relocations
	x64Tests := []struct {
		relocType uint32
		want      RelocationType
	}{
		{1, RelocationTypeAbsolute},  // R_X86_64_64
		{10, RelocationTypeAbsolute}, // R_X86_64_32
		{11, RelocationTypeAbsolute}, // R_X86_64_32S
		{2, RelocationTypeRelative},  // R_X86_64_PC32
		{4, RelocationTypeRelative},  // R_X86_64_PLT32
		{7, RelocationTypeJumpSlot},  // R_X86_64_JUMP_SLOT
		{6, RelocationTypeGlobDat},   // R_X86_64_GLOB_DAT
		{5, RelocationTypeCopy},      // R_X86_64_COPY
		{9, RelocationTypeGOT},       // R_X86_64_GOTPCREL
		{999, RelocationTypeUnknown}, // unknown
	}

	for _, tt := range x64Tests {
		got := parser.convertELFRelocationType(elf.EM_X86_64, tt.relocType)
		if got != tt.want {
			t.Errorf("convertELFRelocationType(x86_64, %d) = %v, want %v", tt.relocType, got, tt.want)
		}
	}

	// aarch64 relocations
	arm64Tests := []struct {
		relocType uint32
		want      RelocationType
	}{
		{257, RelocationTypeAbsolute},  // R_AARCH64_ABS64
		{258, RelocationTypeAbsolute},  // R_AARCH64_ABS32
		{261, RelocationTypeRelative},  // R_AARCH64_PREL64
		{262, RelocationTypeRelative},  // R_AARCH64_PREL32
		{1026, RelocationTypeJumpSlot}, // R_AARCH64_JUMP_SLOT
		{1025, RelocationTypeGlobDat},  // R_AARCH64_GLOB_DAT
		{1024, RelocationTypeCopy},     // R_AARCH64_COPY
		{9999, RelocationTypeUnknown},  // unknown
	}

	for _, tt := range arm64Tests {
		got := parser.convertELFRelocationType(elf.EM_AARCH64, tt.relocType)
		if got != tt.want {
			t.Errorf("convertELFRelocationType(aarch64, %d) = %v, want %v", tt.relocType, got, tt.want)
		}
	}

	// unknown architecture
	got := parser.convertELFRelocationType(elf.Machine(999), 0)
	if got != RelocationTypeUnknown {
		t.Errorf("convertELFRelocationType(unknown, 0) = %v, want Unknown", got)
	}
}

// TestMachOArchitectureDetection tests all Mach-O architecture variants
func TestMachOArchitectureDetection(t *testing.T) {
	parser := NewStandardLibParser()

	tests := []struct {
		cpu  macho.Cpu
		want Architecture
	}{
		{macho.CpuAmd64, ArchitectureX86_64},
		{macho.Cpu386, ArchitectureX86},
		{macho.CpuArm64, ArchitectureARM64},
		{macho.CpuArm, ArchitectureARM},
		{macho.CpuPpc, ArchitecturePPC},
		{macho.CpuPpc64, ArchitecturePPC64},
		{macho.Cpu(999), ArchitectureUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.want.String(), func(t *testing.T) {
			machoFile := &macho.File{
				FileHeader: macho.FileHeader{
					Cpu: tt.cpu,
				},
			}
			got := parser.detectMachOArchitecture(machoFile)
			if got != tt.want {
				t.Errorf("detectMachOArchitecture(%v) = %v, want %v", tt.cpu, got, tt.want)
			}
		})
	}
}

// TestPEArchitectureDetection tests all PE architecture variants
func TestPEArchitectureDetection(t *testing.T) {
	parser := NewStandardLibParser()

	tests := []struct {
		machine uint16
		want    Architecture
	}{
		{0x8664, ArchitectureX86_64},  // IMAGE_FILE_MACHINE_AMD64
		{0x14c, ArchitectureX86},      // IMAGE_FILE_MACHINE_I386
		{0xaa64, ArchitectureARM64},   // IMAGE_FILE_MACHINE_ARM64
		{0x1c0, ArchitectureARM},      // IMAGE_FILE_MACHINE_ARM
		{0x1c4, ArchitectureARM},      // IMAGE_FILE_MACHINE_ARMNT
		{0x9999, ArchitectureUnknown}, // unknown
	}

	for _, tt := range tests {
		t.Run(tt.want.String(), func(t *testing.T) {
			peFile := &pe.File{
				FileHeader: pe.FileHeader{
					Machine: tt.machine,
				},
			}
			got := parser.detectPEArchitecture(peFile)
			if got != tt.want {
				t.Errorf("detectPEArchitecture(%#x) = %v, want %v", tt.machine, got, tt.want)
			}
		})
	}
}

// TestAllStringMethods tests String() methods for all types
func TestAllStringMethods(t *testing.T) {
	// test all architectures
	architectures := []Architecture{
		ArchitectureX86_64,
		ArchitectureX86,
		ArchitectureARM64,
		ArchitectureARM,
		ArchitectureMIPS,
		ArchitectureMIPS64,
		ArchitecturePPC,
		ArchitecturePPC64,
		ArchitectureRISCV,
		ArchitectureRISCV64,
		ArchitectureUnknown,
	}
	for _, arch := range architectures {
		if arch.String() == "" {
			t.Errorf("Architecture %d has empty string", arch)
		}
	}

	// test all binary formats
	formats := []BinaryFormat{
		BinaryFormatELF,
		BinaryFormatPE,
		BinaryFormatMachO,
		BinaryFormatUnknown,
	}
	for _, format := range formats {
		if format.String() == "" {
			t.Errorf("BinaryFormat %d has empty string", format)
		}
	}

	// test all symbol types
	symbolTypes := []SymbolType{
		SymbolTypeFunction,
		SymbolTypeObject,
		SymbolTypeSection,
		SymbolTypeFile,
		SymbolTypeTLS,
		SymbolTypeUnknown,
	}
	for _, st := range symbolTypes {
		if st.String() == "" {
			t.Errorf("SymbolType %d has empty string", st)
		}
	}

	// test all symbol bindings
	bindings := []SymbolBinding{
		SymbolBindingLocal,
		SymbolBindingGlobal,
		SymbolBindingWeak,
		SymbolBindingUnknown,
	}
	for _, binding := range bindings {
		if binding.String() == "" {
			t.Errorf("SymbolBinding %d has empty string", binding)
		}
	}

	// test all relocation types
	relocTypes := []RelocationType{
		RelocationTypeAbsolute,
		RelocationTypeRelative,
		RelocationTypePLT,
		RelocationTypeGOT,
		RelocationTypeCopy,
		RelocationTypeJumpSlot,
		RelocationTypeGlobDat,
		RelocationTypeUnknown,
	}
	for _, rt := range relocTypes {
		if rt.String() == "" {
			t.Errorf("RelocationType %d has empty string", rt)
		}
	}
}
