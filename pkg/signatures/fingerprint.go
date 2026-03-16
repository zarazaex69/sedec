package signatures

import (
	"strings"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// mnemonics whose relative offset operand must be wildcarded.
// the offset is always the last 1-4 bytes of the instruction encoding.
var relativeJumpMnemonics = map[string]bool{
	"jmp": true,
	"je":  true, "jne": true,
	"jz": true, "jnz": true,
	"jl": true, "jle": true,
	"jg": true, "jge": true,
	"jb": true, "jbe": true,
	"ja": true, "jae": true,
	"js": true, "jns": true,
	"jo": true, "jno": true,
	"jp": true, "jnp": true,
	"jcxz": true, "jecxz": true, "jrcxz": true,
	"loop": true, "loope": true, "loopne": true,
}

// ComputeFingerprint builds a wildcard-masked byte fingerprint for a function.
//
// masking rules applied in order:
//  1. CALL rel32 (opcode E8): mask the 4-byte relative offset (bytes 1-4).
//  2. Short Jcc / JMP rel8 (opcode 7x, EB): mask the 1-byte offset (byte 1).
//  3. Near Jcc / JMP rel32 (opcode 0F 8x, E9): mask the 4-byte offset.
//  4. MOV r/m, imm32/64 with an immediate that looks like a code/data address:
//     mask the last 4 or 8 bytes of the instruction.
func ComputeFingerprint(instrs []*disasm.Instruction, imageBase uint64) *FunctionFingerprint {
	if len(instrs) == 0 {
		return &FunctionFingerprint{
			Pattern:    []WildcardByte{},
			ByteLength: 0,
		}
	}

	// collect all raw bytes and build a mask bitmap
	totalBytes := 0
	for _, ins := range instrs {
		totalBytes += len(ins.Bytes)
	}

	pattern := make([]WildcardByte, 0, totalBytes)

	for _, ins := range instrs {
		raw := ins.Bytes
		if len(raw) == 0 {
			continue
		}

		masked := buildMaskedBytes(ins, raw, imageBase)
		pattern = append(pattern, masked...)
	}

	addr := disasm.Address(0)
	if len(instrs) > 0 {
		addr = instrs[0].Address
	}

	return &FunctionFingerprint{
		Pattern:    pattern,
		Address:    addr,
		ByteLength: len(pattern),
	}
}

// buildMaskedBytes applies wildcard masking to a single instruction's bytes.
func buildMaskedBytes(ins *disasm.Instruction, raw []byte, imageBase uint64) []WildcardByte {
	n := len(raw)
	result := make([]WildcardByte, n)
	for i, b := range raw {
		result[i] = WildcardByte{Value: b, IsWild: false}
	}

	mnem := strings.ToLower(ins.Mnemonic)

	switch {
	case mnem == "call" && n >= 5 && raw[0] == 0xE8:
		// CALL rel32: mask bytes 1-4
		maskRange(result, 1, 5)

	case mnem == "call" && n >= 2 && raw[0] == 0xFF:
		// CALL r/m64 (indirect): no masking needed, target is register/memory

	case isRelativeJump(mnem) && n >= 2 && isShortJumpOpcode(raw[0]):
		// short Jcc / JMP rel8: mask byte 1
		maskRange(result, 1, 2)

	case isRelativeJump(mnem) && n >= 6 && raw[0] == 0x0F && isNearJccSecondByte(raw[1]):
		// near Jcc rel32 (0F 8x): mask bytes 2-5
		maskRange(result, 2, 6)

	case isRelativeJump(mnem) && n >= 5 && raw[0] == 0xE9:
		// JMP rel32: mask bytes 1-4
		maskRange(result, 1, 5)

	case isMovWithAddressImmediate(ins, raw, imageBase):
		// MOV with absolute address immediate: mask last 4 or 8 bytes
		immSize := detectImmediateSize(ins)
		if immSize > 0 && immSize <= n {
			maskRange(result, n-immSize, n)
		}

	case mnem == "lea" && n >= 7:
		// LEA with RIP-relative displacement: mask last 4 bytes (disp32)
		maskRange(result, n-4, n)
	}

	return result
}

// maskRange sets IsWild=true for bytes in [start, end).
func maskRange(pattern []WildcardByte, start, end int) {
	if start < 0 {
		start = 0
	}
	if end > len(pattern) {
		end = len(pattern)
	}
	for i := start; i < end; i++ {
		pattern[i].IsWild = true
	}
}

// isRelativeJump returns true if the mnemonic is a relative branch.
func isRelativeJump(mnem string) bool {
	return relativeJumpMnemonics[mnem]
}

// isShortJumpOpcode returns true for single-byte short branch opcodes.
func isShortJumpOpcode(b byte) bool {
	// EB = JMP rel8; 70-7F = Jcc rel8
	return b == 0xEB || (b >= 0x70 && b <= 0x7F)
}

// isNearJccSecondByte returns true for the second byte of a near Jcc (0F 8x).
func isNearJccSecondByte(b byte) bool {
	return b >= 0x80 && b <= 0x8F
}

// isMovWithAddressImmediate heuristically detects MOV instructions that embed
// an absolute address as an immediate operand.
func isMovWithAddressImmediate(ins *disasm.Instruction, raw []byte, imageBase uint64) bool {
	mnem := strings.ToLower(ins.Mnemonic)
	if mnem != "mov" && mnem != "movabs" {
		return false
	}

	// look for an immediate operand whose value is in the plausible address range
	for _, op := range ins.Operands {
		imm, ok := op.(disasm.ImmediateOperand)
		if !ok {
			continue
		}
		// treat values >= imageBase as potential addresses
		// #nosec G115 - intentional conversion for address comparison
		if imageBase > 0 && uint64(imm.Value) >= imageBase {
			return true
		}
		// fallback: values >= 0x1000 that are 4/8-byte aligned look like addresses
		// #nosec G115 - intentional conversion for address comparison
		if uint64(imm.Value) >= 0x1000 && len(raw) >= 5 {
			return true
		}
	}
	return false
}

// detectImmediateSize returns the byte size of the immediate operand in the instruction.
func detectImmediateSize(ins *disasm.Instruction) int {
	for _, op := range ins.Operands {
		imm, ok := op.(disasm.ImmediateOperand)
		if !ok {
			continue
		}
		return int(imm.Size)
	}
	return 0
}

// FingerprintSimilarity computes the Jaccard similarity between two fingerprints.
//
// only non-wildcard bytes at matching positions are compared; positions where
// either pattern has a wildcard are excluded from both numerator and denominator.
func FingerprintSimilarity(a, b *FunctionFingerprint) float64 {
	if a == nil || b == nil {
		return 0.0
	}

	minLen := len(a.Pattern)
	if len(b.Pattern) < minLen {
		minLen = len(b.Pattern)
	}
	maxLen := len(a.Pattern)
	if len(b.Pattern) > maxLen {
		maxLen = len(b.Pattern)
	}

	if maxLen == 0 {
		return 1.0
	}

	matched := 0
	compared := 0

	for i := 0; i < minLen; i++ {
		wa := a.Pattern[i].IsWild
		wb := b.Pattern[i].IsWild

		// skip positions where either side is a wildcard
		if wa || wb {
			continue
		}

		compared++
		if a.Pattern[i].Value == b.Pattern[i].Value {
			matched++
		}
	}

	// length difference penalty: extra bytes in the longer pattern count as mismatches
	lengthPenalty := maxLen - minLen

	denominator := compared + lengthPenalty
	if denominator == 0 {
		// all bytes were wildcards; treat as identical
		return 1.0
	}

	return float64(matched) / float64(denominator)
}
