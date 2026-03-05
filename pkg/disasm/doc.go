// Package disasm provides x86_64 disassembly using gapstone (Capstone Engine Go bindings).
// It decodes variable-length instructions, handles all ISA extensions (SSE, AVX, AVX2, AVX-512),
// and provides accurate instruction boundary detection.
package disasm
