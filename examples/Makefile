CC      = zig cc
CFLAGS_DBG = -O0 -g -fno-omit-frame-pointer -Wall -Wextra
CFLAGS_OPT = -O2 -fno-omit-frame-pointer -Wall -Wextra
SEDEC   = ../sedec

BINARY_DBG = test_decompiler_dbg
BINARY_OPT = test_decompiler_opt

.PHONY: all build run clean disasm cfg ir decompile

all: build

build:
	$(CC) $(CFLAGS_DBG) -o $(BINARY_DBG) test_decompiler.c
	$(CC) $(CFLAGS_OPT) -o $(BINARY_OPT) test_decompiler.c

# run the binary to get expected output for comparison
run: build
	./$(BINARY_DBG)

# disassemble both binaries
disasm: build
	$(SEDEC) disasm $(BINARY_DBG)  > out_disasm_dbg.txt
	$(SEDEC) disasm $(BINARY_OPT) > out_disasm_opt.txt

# export cfg as dot graphs
cfg: build
	$(SEDEC) cfg --output out_cfg_dbg.dot  $(BINARY_DBG)
	$(SEDEC) cfg --output out_cfg_opt.dot  $(BINARY_OPT)

# lift to ir (plain and ssa)
ir: build
	$(SEDEC) ir              $(BINARY_DBG)  > out_ir_dbg.txt
	$(SEDEC) ir --ssa        $(BINARY_DBG)  > out_ir_ssa_dbg.txt
	$(SEDEC) ir              $(BINARY_OPT) > out_ir_opt.txt
	$(SEDEC) ir --ssa        $(BINARY_OPT) > out_ir_ssa_opt.txt

# full decompilation
decompile: build
	$(SEDEC) decompile $(BINARY_DBG)  > out_decompile_dbg.txt
	$(SEDEC) decompile $(BINARY_OPT) > out_decompile_opt.txt

# run all pipeline stages
all_stages: disasm cfg ir decompile

clean:
	rm -f $(BINARY_DBG) $(BINARY_OPT)
	rm -f out_*.txt out_*.dot
