# makefile for building test binaries

.PHONY: all clean elf pe macho

all: elf pe macho

# build elf binary for linux x86_64
elf: test_elf.c
	gcc -o test_elf_x64 test_elf.c -O0 -g

# build pe binary for windows x86_64 using zig
pe: test_pe.c
	zig cc -target x86_64-windows -o test_pe_x64.exe test_pe.c -O0

# build mach-o binary for macos x86_64 using zig
macho: test_elf.c
	zig cc -target x86_64-macos -o test_macho_x64 test_elf.c -O0

clean:
	rm -f test_elf_x64 test_pe_x64.exe test_macho_x64
