# makefile for building test binaries
# binaries are placed in binary/ subdirectory to avoid git tracking

BINARY_DIR = binary

.PHONY: all clean elf pe macho

all: elf pe macho

# build elf binary for linux x86_64
elf: test_elf.c
	@mkdir -p $(BINARY_DIR)
	gcc -o $(BINARY_DIR)/test_elf_x64 test_elf.c -O0 -g

# build pe binary for windows x86_64 using zig
pe: test_pe.c
	@mkdir -p $(BINARY_DIR)
	zig cc -target x86_64-windows -o $(BINARY_DIR)/test_pe_x64.exe test_pe.c -O0

# build mach-o binary for macos x86_64 using zig
macho: test_elf.c
	@mkdir -p $(BINARY_DIR)
	zig cc -target x86_64-macos -o $(BINARY_DIR)/test_macho_x64 test_elf.c -O0

clean:
	rm -rf $(BINARY_DIR)
