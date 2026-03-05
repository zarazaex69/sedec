# makefile for building test binaries

.PHONY: all clean elf pe macho

all: elf pe

# build elf binary for linux x86_64
elf: test_elf.c
	gcc -o test_elf_x64 test_elf.c -static -O0 -g
	strip -s test_elf_x64 -o test_elf_x64_stripped

# build pe binary for windows x86_64 (requires mingw-w64)
pe: test_pe.c
	x86_64-w64-mingw32-gcc -o test_pe_x64.exe test_pe.c -static -O0 -g
	x86_64-w64-mingw32-strip -s test_pe_x64.exe -o test_pe_x64_stripped.exe

# build mach-o binary for macos x86_64 (only works on macos)
macho: test_elf.c
	clang -o test_macho_x64 test_elf.c -O0 -g
	strip test_macho_x64 -o test_macho_x64_stripped

clean:
	rm -f test_elf_x64 test_elf_x64_stripped
	rm -f test_pe_x64.exe test_pe_x64_stripped.exe
	rm -f test_macho_x64 test_macho_x64_stripped
