package binfmt

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"
)

// TestResolveGOTEntries_ELF tests GOT resolution for ELF binaries
func TestResolveGOTEntries_ELF(t *testing.T) {
	//nolint:govet // fieldalignment: test struct, performance not critical
	tests := []struct {
		name          string
		setupBinary   func() *BinaryInfo
		expectedCount int
		validateEntry func(*testing.T, map[Address]*GOTEntry)
	}{
		{
			name: "resolve got entries with relocations",
			setupBinary: func() *BinaryInfo {
				// create minimal elf binary with got relocations
				info := &BinaryInfo{
					Format:        BinaryFormatELF,
					Architecture:  ArchitectureX86_64,
					GroundTruthDB: NewGroundTruthDatabase(),
				}

				// add relocations
				info.Relocations = []*Relocation{
					{
						Address:   0x601018,
						Symbol:    "printf",
						Type:      RelocationTypeJumpSlot,
						Addend:    0,
						SymbolIdx: 1,
					},
					{
						Address:   0x601020,
						Symbol:    "malloc",
						Type:      RelocationTypeGlobDat,
						Addend:    0,
						SymbolIdx: 2,
					},
				}

				// add symbols
				info.GroundTruthDB.SymbolsByName["printf"] = 0x400500
				info.GroundTruthDB.SymbolsByName["malloc"] = 0x400600

				// create minimal elf file
				info.elfFile = createMinimalELFFile(t)

				return info
			},
			expectedCount: 2,
			validateEntry: func(t *testing.T, entries map[Address]*GOTEntry) {
				// validate printf entry
				printfEntry, exists := entries[0x601018]
				if !exists {
					t.Fatal("printf got entry not found")
				}
				if printfEntry.TargetSymbol != "printf" {
					t.Errorf("expected symbol 'printf', got '%s'", printfEntry.TargetSymbol)
				}
				if printfEntry.TargetAddress != 0x400500 {
					t.Errorf("expected target address 0x400500, got 0x%x", printfEntry.TargetAddress)
				}

				// validate malloc entry
				mallocEntry, exists := entries[0x601020]
				if !exists {
					t.Fatal("malloc got entry not found")
				}
				if mallocEntry.TargetSymbol != "malloc" {
					t.Errorf("expected symbol 'malloc', got '%s'", mallocEntry.TargetSymbol)
				}
				if mallocEntry.TargetAddress != 0x400600 {
					t.Errorf("expected target address 0x400600, got 0x%x", mallocEntry.TargetAddress)
				}
			},
		},
		{
			name: "resolve relative relocations for pie",
			setupBinary: func() *BinaryInfo {
				info := &BinaryInfo{
					Format:        BinaryFormatELF,
					Architecture:  ArchitectureX86_64,
					BaseAddress:   0x555555554000,
					GroundTruthDB: NewGroundTruthDatabase(),
				}

				// add relative relocation
				info.Relocations = []*Relocation{
					{
						Address:   0x601000,
						Symbol:    "",
						Type:      RelocationTypeRelative,
						Addend:    0x1234,
						SymbolIdx: 0,
					},
				}

				info.elfFile = createMinimalELFFile(t)

				return info
			},
			expectedCount: 1,
			validateEntry: func(t *testing.T, entries map[Address]*GOTEntry) {
				entry, exists := entries[0x601000]
				if !exists {
					t.Fatal("relative relocation entry not found")
				}
				// target should be base + addend
				expectedTarget := Address(0x555555554000 + 0x1234)
				if entry.TargetAddress != expectedTarget {
					t.Errorf("expected target 0x%x, got 0x%x", expectedTarget, entry.TargetAddress)
				}
			},
		},
		{
			name: "handle nil binary info",
			setupBinary: func() *BinaryInfo {
				return nil
			},
			expectedCount: 0,
			validateEntry: func(_ *testing.T, _ map[Address]*GOTEntry) {
				// should return error, entries will be nil
			},
		},
	}

	parser := NewStandardLibParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := tt.setupBinary()
			entries, err := parser.ResolveGOTEntries(info)

			if info == nil {
				if err == nil {
					t.Fatal("expected error for nil binary info")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(entries) != tt.expectedCount {
				t.Errorf("expected %d entries, got %d", tt.expectedCount, len(entries))
			}

			if tt.validateEntry != nil {
				tt.validateEntry(t, entries)
			}
		})
	}
}

// TestResolvePLTStubs_ELF tests PLT resolution for ELF binaries
func TestResolvePLTStubs_ELF(t *testing.T) {
	//nolint:govet // fieldalignment: test struct, performance not critical
	tests := []struct {
		name          string
		setupBinary   func() *BinaryInfo
		expectedCount int
		validateEntry func(*testing.T, map[Address]*PLTEntry)
	}{
		{
			name: "handle binary without plt section",
			setupBinary: func() *BinaryInfo {
				info := &BinaryInfo{
					Format:        BinaryFormatELF,
					Architecture:  ArchitectureX86_64,
					GroundTruthDB: NewGroundTruthDatabase(),
				}

				// create elf without plt
				info.elfFile = createMinimalELFFile(t)

				return info
			},
			expectedCount: 0,
			validateEntry: func(_ *testing.T, _ map[Address]*PLTEntry) {
				// should return empty map, not error
			},
		},
	}

	parser := NewStandardLibParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := tt.setupBinary()
			entries, err := parser.ResolvePLTStubs(info)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(entries) != tt.expectedCount {
				t.Errorf("expected %d entries, got %d", tt.expectedCount, len(entries))
			}

			if tt.validateEntry != nil {
				tt.validateEntry(t, entries)
			}
		})
	}
}

// TestCalculateBaseAddress tests base address calculation for PIE/PIC binaries
func TestCalculateBaseAddress(t *testing.T) {
	//nolint:govet // fieldalignment: test struct, performance not critical
	tests := []struct {
		name         string
		setupBinary  func() *BinaryInfo
		expectedAddr Address
		expectError  bool
	}{
		{
			name: "elf pie binary with pt_load segments",
			setupBinary: func() *BinaryInfo {
				info := &BinaryInfo{
					Format:       BinaryFormatELF,
					Architecture: ArchitectureX86_64,
				}

				// create elf with pt_load segments
				info.elfFile = createELFWithPTLoad(t, 0x400000)

				return info
			},
			expectedAddr: 0x400000,
			expectError:  false,
		},
		{
			name: "elf non-pie binary",
			setupBinary: func() *BinaryInfo {
				info := &BinaryInfo{
					Format:       BinaryFormatELF,
					Architecture: ArchitectureX86_64,
				}

				// create non-pie elf (et_exec)
				info.elfFile = createNonPIEELF(t)

				return info
			},
			expectedAddr: 0,
			expectError:  false,
		},
		{
			name: "pe binary with image base",
			setupBinary: func() *BinaryInfo {
				info := &BinaryInfo{
					Format:       BinaryFormatPE,
					Architecture: ArchitectureX86_64,
					BaseAddress:  0x140000000,
				}

				return info
			},
			expectedAddr: 0x140000000,
			expectError:  false,
		},
		{
			name: "nil binary info",
			setupBinary: func() *BinaryInfo {
				return nil
			},
			expectedAddr: 0,
			expectError:  true,
		},
	}

	parser := NewStandardLibParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := tt.setupBinary()
			addr, err := parser.CalculateBaseAddress(info)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if addr != tt.expectedAddr {
				t.Errorf("expected base address 0x%x, got 0x%x", tt.expectedAddr, addr)
			}
		})
	}
}

// TestParseELFPLTEntry tests PLT entry parsing for x86_64
func TestParseELFPLTEntry(t *testing.T) {
	tests := []struct {
		name        string
		pltData     []byte
		pltAddr     Address
		expectedGOT Address
		expectError bool
	}{
		{
			name: "valid x86_64 plt entry",
			pltData: []byte{
				0xff, 0x25, 0x02, 0x10, 0x20, 0x00, // jmp *0x201002(%rip)
				0x68, 0x00, 0x00, 0x00, 0x00, // push $0
				0xe9, 0xe0, 0xff, 0xff, 0xff, // jmp plt[0]
			},
			pltAddr:     0x400410,
			expectedGOT: 0x400410 + 6 + 0x201002, // plt_addr + instr_len + rip_offset
			expectError: false,
		},
		{
			name: "invalid opcode",
			pltData: []byte{
				0x90, 0x90, 0x02, 0x10, 0x20, 0x00, // nop nop ...
			},
			pltAddr:     0x400410,
			expectedGOT: 0,
			expectError: true,
		},
		{
			name:        "truncated plt entry",
			pltData:     []byte{0xff, 0x25},
			pltAddr:     0x400410,
			expectedGOT: 0,
			expectError: true,
		},
	}

	parser := NewStandardLibParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &BinaryInfo{
				Architecture: ArchitectureX86_64,
			}

			gotAddr, err := parser.parseELFPLTEntry(info, tt.pltData, tt.pltAddr)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if gotAddr != tt.expectedGOT {
				t.Errorf("expected got address 0x%x, got 0x%x", tt.expectedGOT, gotAddr)
			}
		})
	}
}

// TestGOTPLTIntegration tests end-to-end GOT/PLT resolution
func TestGOTPLTIntegration(t *testing.T) {
	parser := NewStandardLibParser()

	// create complete binary info with got
	info := &BinaryInfo{
		Format:        BinaryFormatELF,
		Architecture:  ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(),
	}

	// add symbols
	info.Symbols = []*Symbol{
		{Name: "printf", Address: 0x400500, Type: SymbolTypeFunction},
		{Name: "malloc", Address: 0x400600, Type: SymbolTypeFunction},
	}

	// add relocations
	info.Relocations = []*Relocation{
		{Address: 0x601018, Symbol: "printf", Type: RelocationTypeJumpSlot},
		{Address: 0x601020, Symbol: "malloc", Type: RelocationTypeJumpSlot},
	}

	// populate ground truth db
	info.GroundTruthDB.SymbolsByName["printf"] = 0x400500
	info.GroundTruthDB.SymbolsByName["malloc"] = 0x400600

	// create minimal elf
	info.elfFile = createMinimalELFFile(t)

	// resolve got entries
	gotEntries, err := parser.ResolveGOTEntries(info)
	if err != nil {
		t.Fatalf("failed to resolve got entries: %v", err)
	}

	// verify got entries
	if len(gotEntries) < 2 {
		t.Errorf("expected at least 2 got entries, got %d", len(gotEntries))
	}

	// verify ground truth db was updated
	if len(info.GroundTruthDB.GOTPLT) < 2 {
		t.Errorf("expected ground truth db to have at least 2 got/plt mappings, got %d",
			len(info.GroundTruthDB.GOTPLT))
	}

	// verify o(1) lookup works
	if targetAddr, exists := info.GroundTruthDB.GOTPLT[0x601018]; !exists {
		t.Error("got entry 0x601018 not in ground truth db")
	} else if targetAddr != 0x400500 {
		t.Errorf("expected target 0x400500, got 0x%x", targetAddr)
	}
}

// TestResolveGOTEntries_PE tests GOT resolution for PE binaries (IAT)
func TestResolveGOTEntries_PE(t *testing.T) {
	parser := NewStandardLibParser()

	info := &BinaryInfo{
		Format:        BinaryFormatPE,
		Architecture:  ArchitectureX86_64,
		GroundTruthDB: NewGroundTruthDatabase(),
	}

	// add imports (pe uses iat instead of got)
	info.Imports = []*Import{
		{Name: "printf", Library: "msvcrt.dll", Address: 0x140001000},
		{Name: "malloc", Library: "msvcrt.dll", Address: 0x140001008},
	}

	entries, err := parser.ResolveGOTEntries(info)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}

	// verify printf entry
	printfEntry, exists := entries[0x140001000]
	if !exists {
		t.Fatal("printf iat entry not found")
	}
	if printfEntry.TargetSymbol != "printf" {
		t.Errorf("expected symbol 'printf', got '%s'", printfEntry.TargetSymbol)
	}
}

// Helper functions for creating test ELF files

func createMinimalELFFile(t *testing.T) *elf.File {
	t.Helper()

	// create minimal valid elf header
	buf := new(bytes.Buffer)

	// elf header
	buf.Write([]byte{0x7f, 'E', 'L', 'F'}) // magic
	buf.WriteByte(2)                       // 64-bit
	buf.WriteByte(1)                       // little endian
	buf.WriteByte(1)                       // elf version
	buf.Write(make([]byte, 9))             // padding

	// write minimal elf64 header
	binary.Write(buf, binary.LittleEndian, uint16(elf.ET_DYN))    // type
	binary.Write(buf, binary.LittleEndian, uint16(elf.EM_X86_64)) // machine
	binary.Write(buf, binary.LittleEndian, uint32(1))             // version
	binary.Write(buf, binary.LittleEndian, uint64(0x400000))      // entry
	binary.Write(buf, binary.LittleEndian, uint64(64))            // phoff
	binary.Write(buf, binary.LittleEndian, uint64(0))             // shoff
	binary.Write(buf, binary.LittleEndian, uint32(0))             // flags
	binary.Write(buf, binary.LittleEndian, uint16(64))            // ehsize
	binary.Write(buf, binary.LittleEndian, uint16(56))            // phentsize
	binary.Write(buf, binary.LittleEndian, uint16(0))             // phnum
	binary.Write(buf, binary.LittleEndian, uint16(64))            // shentsize
	binary.Write(buf, binary.LittleEndian, uint16(0))             // shnum
	binary.Write(buf, binary.LittleEndian, uint16(0))             // shstrndx

	elfFile, err := elf.NewFile(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("failed to create minimal elf: %v", err)
	}

	return elfFile
}

func createELFWithPTLoad(t *testing.T, vaddr uint64) *elf.File {
	t.Helper()

	buf := new(bytes.Buffer)

	// elf header
	buf.Write([]byte{0x7f, 'E', 'L', 'F'})
	buf.WriteByte(2)
	buf.WriteByte(1)
	buf.WriteByte(1)
	buf.Write(make([]byte, 9))

	binary.Write(buf, binary.LittleEndian, uint16(elf.ET_DYN))
	binary.Write(buf, binary.LittleEndian, uint16(elf.EM_X86_64))
	binary.Write(buf, binary.LittleEndian, uint32(1))
	binary.Write(buf, binary.LittleEndian, vaddr)
	binary.Write(buf, binary.LittleEndian, uint64(64)) // phoff
	binary.Write(buf, binary.LittleEndian, uint64(0))  // shoff
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint16(64))
	binary.Write(buf, binary.LittleEndian, uint16(56))
	binary.Write(buf, binary.LittleEndian, uint16(1)) // phnum
	binary.Write(buf, binary.LittleEndian, uint16(64))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))

	// program header (pt_load)
	binary.Write(buf, binary.LittleEndian, uint32(elf.PT_LOAD)) // type
	binary.Write(buf, binary.LittleEndian, uint32(5))           // flags (r-x)
	binary.Write(buf, binary.LittleEndian, uint64(0))           // offset
	binary.Write(buf, binary.LittleEndian, vaddr)               // vaddr
	binary.Write(buf, binary.LittleEndian, vaddr)               // paddr
	binary.Write(buf, binary.LittleEndian, uint64(0x1000))      // filesz
	binary.Write(buf, binary.LittleEndian, uint64(0x1000))      // memsz
	binary.Write(buf, binary.LittleEndian, uint64(0x1000))      // align

	elfFile, err := elf.NewFile(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("failed to create elf with pt_load: %v", err)
	}

	return elfFile
}

func createNonPIEELF(t *testing.T) *elf.File {
	t.Helper()

	buf := new(bytes.Buffer)

	// elf header with et_exec type
	buf.Write([]byte{0x7f, 'E', 'L', 'F'})
	buf.WriteByte(2)
	buf.WriteByte(1)
	buf.WriteByte(1)
	buf.Write(make([]byte, 9))

	binary.Write(buf, binary.LittleEndian, uint16(elf.ET_EXEC)) // et_exec (not pie)
	binary.Write(buf, binary.LittleEndian, uint16(elf.EM_X86_64))
	binary.Write(buf, binary.LittleEndian, uint32(1))
	binary.Write(buf, binary.LittleEndian, uint64(0x400000))
	binary.Write(buf, binary.LittleEndian, uint64(64))
	binary.Write(buf, binary.LittleEndian, uint64(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint16(64))
	binary.Write(buf, binary.LittleEndian, uint16(56))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(64))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))

	elfFile, err := elf.NewFile(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("failed to create non-pie elf: %v", err)
	}

	return elfFile
}
