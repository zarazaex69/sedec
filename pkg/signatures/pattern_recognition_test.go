package signatures

import (
	"testing"

	binfmt "github.com/zarazaex69/sedec/pkg/binary"
	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/disasm"
)

func mkInstr(addr uint64, mnem string, raw []byte) *disasm.Instruction {
	return &disasm.Instruction{
		Address:  disasm.Address(addr),
		Mnemonic: mnem,
		Bytes:    raw,
	}
}

func mkInstrWithOps(addr uint64, mnem string, raw []byte, ops []disasm.Operand) *disasm.Instruction {
	return &disasm.Instruction{
		Address:  disasm.Address(addr),
		Mnemonic: mnem,
		Bytes:    raw,
		Operands: ops,
	}
}

// ---------------------------------------------------------------------------
// Fingerprint: masking edge cases
// ---------------------------------------------------------------------------

func TestFingerprint_LEAMasking(t *testing.T) {
	instrs := []*disasm.Instruction{
		mkInstr(0x1000, "lea", []byte{0x48, 0x8D, 0x05, 0x10, 0x20, 0x30, 0x40}),
	}
	fp := ComputeFingerprint(instrs, 0x400000)
	if fp == nil {
		t.Fatal("expected non-nil fingerprint")
	}
	if len(fp.Pattern) != 7 {
		t.Fatalf("expected 7 bytes, got %d", len(fp.Pattern))
	}
	for i := 3; i < 7; i++ {
		if !fp.Pattern[i].IsWild {
			t.Errorf("byte %d should be wildcarded for LEA RIP-relative", i)
		}
	}
}

func TestFingerprint_NearJccMasking(t *testing.T) {
	instrs := []*disasm.Instruction{
		mkInstr(0x1000, "je", []byte{0x0F, 0x84, 0x10, 0x20, 0x30, 0x40}),
	}
	fp := ComputeFingerprint(instrs, 0)
	if fp == nil {
		t.Fatal("expected non-nil fingerprint")
	}
	if len(fp.Pattern) != 6 {
		t.Fatalf("expected 6 bytes, got %d", len(fp.Pattern))
	}
	if fp.Pattern[0].IsWild || fp.Pattern[1].IsWild {
		t.Error("opcode bytes should not be wildcarded")
	}
	for i := 2; i < 6; i++ {
		if !fp.Pattern[i].IsWild {
			t.Errorf("byte %d should be wildcarded for near Jcc", i)
		}
	}
}

func TestFingerprint_JmpRel32Masking(t *testing.T) {
	instrs := []*disasm.Instruction{
		mkInstr(0x1000, "jmp", []byte{0xE9, 0x10, 0x20, 0x30, 0x40}),
	}
	fp := ComputeFingerprint(instrs, 0)
	if fp == nil {
		t.Fatal("expected non-nil fingerprint")
	}
	if fp.Pattern[0].IsWild {
		t.Error("opcode byte should not be wildcarded")
	}
	for i := 1; i < 5; i++ {
		if !fp.Pattern[i].IsWild {
			t.Errorf("byte %d should be wildcarded for JMP rel32", i)
		}
	}
}

func TestFingerprint_IndirectCallNotMasked(t *testing.T) {
	instrs := []*disasm.Instruction{
		mkInstr(0x1000, "call", []byte{0xFF, 0xD0}),
	}
	fp := ComputeFingerprint(instrs, 0)
	if fp == nil {
		t.Fatal("expected non-nil fingerprint")
	}
	for i := range fp.Pattern {
		if fp.Pattern[i].IsWild {
			t.Errorf("byte %d should not be wildcarded for indirect call", i)
		}
	}
}

func TestFingerprint_MovWithAddressImmediate(t *testing.T) {
	instrs := []*disasm.Instruction{
		mkInstrWithOps(0x1000, "mov", []byte{0x48, 0xB8, 0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00},
			[]disasm.Operand{
				disasm.ImmediateOperand{Value: 0x401000, Size: disasm.Size64},
			}),
	}
	fp := ComputeFingerprint(instrs, 0x400000)
	if fp == nil {
		t.Fatal("expected non-nil fingerprint")
	}
	wildcardCount := 0
	for _, b := range fp.Pattern {
		if b.IsWild {
			wildcardCount++
		}
	}
	if wildcardCount == 0 {
		t.Error("expected some wildcarded bytes for MOV with address immediate")
	}
}

func TestFingerprint_EmptyInstructionBytes(t *testing.T) {
	instrs := []*disasm.Instruction{
		mkInstr(0x1000, "nop", nil),
		mkInstr(0x1001, "ret", []byte{0xC3}),
	}
	fp := ComputeFingerprint(instrs, 0)
	if fp == nil {
		t.Fatal("expected non-nil fingerprint")
	}
	if len(fp.Pattern) != 1 {
		t.Errorf("expected 1 byte (empty instruction skipped), got %d", len(fp.Pattern))
	}
}

// ---------------------------------------------------------------------------
// Signature Matching: comprehensive tests
// ---------------------------------------------------------------------------

func buildTestSignatureDB() *SignatureDB {
	db := NewSignatureDB()

	memcpyFP := &FunctionFingerprint{
		Pattern: []WildcardByte{
			{Value: 0x48, IsWild: false},
			{Value: 0x89, IsWild: false},
			{Value: 0xF8, IsWild: false},
			{Value: 0x48, IsWild: false},
			{Value: 0x89, IsWild: false},
			{Value: 0xD1, IsWild: false},
		},
		ByteLength: 6,
	}
	memcpyCFG := &CFGHash{
		BlockCount:         3,
		EdgeCount:          4,
		LoopCount:          1,
		DominatorTreeDepth: 2,
		DegreeSequence: []DegreeEntry{
			{InDegree: 0, OutDegree: 2},
			{InDegree: 2, OutDegree: 1},
			{InDegree: 1, OutDegree: 0},
		},
		Hash64: 0xDEADBEEF,
	}
	db.Add(&Signature{
		Name:        "memcpy",
		Library:     "libc-2.35",
		Fingerprint: memcpyFP,
		CFGHash:     memcpyCFG,
		Format:      SignatureFormatNative,
	})

	memsetFP := &FunctionFingerprint{
		Pattern: []WildcardByte{
			{Value: 0x48, IsWild: false},
			{Value: 0x89, IsWild: false},
			{Value: 0xF8, IsWild: false},
			{Value: 0x88, IsWild: false},
			{Value: 0x30, IsWild: false},
		},
		ByteLength: 5,
	}
	db.Add(&Signature{
		Name:        "memset",
		Library:     "libc-2.35",
		Fingerprint: memsetFP,
		Format:      SignatureFormatNative,
	})

	db.Add(&Signature{
		Name:    "strlen",
		Library: "libc-2.35",
		Fingerprint: &FunctionFingerprint{
			Pattern: []WildcardByte{
				{Value: 0x31, IsWild: false},
				{Value: 0xC0, IsWild: false},
			},
			ByteLength: 2,
		},
		Format: SignatureFormatNative,
	})

	return db
}

func TestMatchSignatures_PartialByteMatch(t *testing.T) {
	db := buildTestSignatureDB()

	queryInstrs := []*disasm.Instruction{
		mkInstr(0x1000, "mov", []byte{0x48, 0x89, 0xF8}),
		mkInstr(0x1003, "mov", []byte{0x48, 0x89, 0xD1}),
	}

	input := &MatchInput{
		Instructions: queryInstrs,
		Address:      0x1000,
	}

	results := MatchSignatures(input, db)
	if len(results) == 0 {
		t.Fatal("expected at least 1 result")
	}
	if results[0].Confidence <= 0 {
		t.Error("expected positive confidence")
	}
	if results[0].Confidence > 1.0 {
		t.Error("confidence should not exceed 1.0")
	}
}

func TestMatchSignatures_WithCFG(t *testing.T) {
	db := buildTestSignatureDB()

	queryInstrs := []*disasm.Instruction{
		mkInstr(0x1000, "mov", []byte{0x48, 0x89, 0xF8}),
		mkInstr(0x1003, "mov", []byte{0x48, 0x89, 0xD1}),
	}

	queryCFG := buildSimpleCFG(3)

	input := &MatchInput{
		Instructions: queryInstrs,
		FunctionCFG:  queryCFG,
		Address:      0x1000,
	}

	results := MatchSignatures(input, db)
	if len(results) == 0 {
		t.Fatal("expected at least 1 result")
	}
	if results[0].CFGSimilarity <= 0 {
		t.Error("expected positive CFG similarity")
	}
}

func TestMatchSignatures_WithGroundTruth(t *testing.T) {
	db := buildTestSignatureDB()

	queryInstrs := []*disasm.Instruction{
		mkInstr(0x1000, "mov", []byte{0x48, 0x89, 0xF8}),
		mkInstr(0x1003, "mov", []byte{0x48, 0x89, 0xD1}),
	}

	gt := &binfmt.GroundTruthDatabase{
		SymbolsByAddress: map[binfmt.Address]string{
			binfmt.Address(0x1000): "memcpy",
		},
	}

	input := &MatchInput{
		Instructions: queryInstrs,
		Address:      0x1000,
		GroundTruth:  gt,
	}

	results := MatchSignatures(input, db)
	if len(results) == 0 {
		t.Fatal("expected at least 1 result")
	}

	found := false
	for _, r := range results {
		if r.Signature.Name == "memcpy" && r.NameHint == "memcpy" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected memcpy match with name hint boost")
	}
}

func TestMatchSignatures_NoInstructions(t *testing.T) {
	db := buildTestSignatureDB()

	input := &MatchInput{
		Instructions: nil,
		Address:      0x1000,
	}

	results := MatchSignatures(input, db)
	for _, r := range results {
		if r.ByteSimilarity < 0 || r.ByteSimilarity > 1.0 {
			t.Errorf("byte similarity out of range: %f", r.ByteSimilarity)
		}
	}
}

func TestMatchSignatures_NoCFG(t *testing.T) {
	db := buildTestSignatureDB()

	queryInstrs := []*disasm.Instruction{
		mkInstr(0x1000, "xor", []byte{0x31, 0xC0}),
	}

	input := &MatchInput{
		Instructions: queryInstrs,
		Address:      0x1000,
	}

	results := MatchSignatures(input, db)
	for _, r := range results {
		if r.CFGSimilarity != 0.5 {
			t.Errorf("expected neutral CFG similarity (0.5), got %f", r.CFGSimilarity)
		}
	}
}

func TestTopMatch_WithResults(t *testing.T) {
	db := buildTestSignatureDB()

	queryInstrs := []*disasm.Instruction{
		mkInstr(0x1000, "mov", []byte{0x48, 0x89, 0xF8}),
		mkInstr(0x1003, "mov", []byte{0x48, 0x89, 0xD1}),
	}

	input := &MatchInput{
		Instructions: queryInstrs,
		Address:      0x1000,
	}

	result := TopMatch(input, db)
	if result == nil {
		t.Fatal("expected non-nil top match")
	}
	if result.Confidence <= 0 {
		t.Error("expected positive confidence for top match")
	}
}

func TestMatchByName_ExistingName(t *testing.T) {
	db := buildTestSignatureDB()

	queryInstrs := []*disasm.Instruction{
		mkInstr(0x1000, "mov", []byte{0x48, 0x89, 0xF8}),
	}

	input := &MatchInput{
		Instructions: queryInstrs,
		Address:      0x1000,
	}

	results := MatchByName(input, db, "memcpy")
	if len(results) == 0 {
		t.Fatal("expected results for memcpy name lookup")
	}
	if results[0].Signature.Name != "memcpy" {
		t.Errorf("expected memcpy, got %s", results[0].Signature.Name)
	}
}

func TestMatchByName_NonExistingName(t *testing.T) {
	db := buildTestSignatureDB()

	input := &MatchInput{
		Instructions: []*disasm.Instruction{
			mkInstr(0x1000, "nop", []byte{0x90}),
		},
		Address: 0x1000,
	}

	results := MatchByName(input, db, "nonexistent_function")
	if len(results) != 0 {
		t.Errorf("expected 0 results for nonexistent name, got %d", len(results))
	}
}

func TestMatchSignatures_MaxCandidatesCap(t *testing.T) {
	db := NewSignatureDB()
	for i := 0; i < 32; i++ {
		db.Add(&Signature{
			Name:    "func",
			Library: "lib",
			Fingerprint: &FunctionFingerprint{
				Pattern: []WildcardByte{
					{Value: 0x90, IsWild: false},
				},
				ByteLength: 1,
			},
			Format: SignatureFormatNative,
		})
	}

	input := &MatchInput{
		Instructions: []*disasm.Instruction{
			mkInstr(0x1000, "nop", []byte{0x90}),
		},
		Address: 0x1000,
	}

	results := MatchSignatures(input, db)
	if len(results) > maxCandidates {
		t.Errorf("expected at most %d candidates, got %d", maxCandidates, len(results))
	}
}

// ---------------------------------------------------------------------------
// CFG Hash: additional coverage
// ---------------------------------------------------------------------------

func TestCFGHash_MultipleLoops(t *testing.T) {
	c := cfg.NewCFG()
	c.AddBlock(&cfg.BasicBlock{ID: 0, Successors: []cfg.BlockID{1, 3}})
	c.AddBlock(&cfg.BasicBlock{ID: 1, Successors: []cfg.BlockID{2}})
	c.AddBlock(&cfg.BasicBlock{ID: 2, Successors: []cfg.BlockID{1, 3}})
	c.AddBlock(&cfg.BasicBlock{ID: 3, Successors: []cfg.BlockID{4}})
	c.AddBlock(&cfg.BasicBlock{ID: 4, Successors: []cfg.BlockID{3, 5}})
	c.AddBlock(&cfg.BasicBlock{ID: 5})
	c.Entry = 0
	c.Exits = []cfg.BlockID{5}

	c.AddEdge(0, 1, cfg.EdgeTypeConditional)
	c.AddEdge(0, 3, cfg.EdgeTypeFallthrough)
	c.AddEdge(1, 2, cfg.EdgeTypeUnconditional)
	c.AddEdge(2, 1, cfg.EdgeTypeConditional)
	c.AddEdge(2, 3, cfg.EdgeTypeFallthrough)
	c.AddEdge(3, 4, cfg.EdgeTypeUnconditional)
	c.AddEdge(4, 3, cfg.EdgeTypeConditional)
	c.AddEdge(4, 5, cfg.EdgeTypeFallthrough)

	hash := ComputeCFGHash(c)
	if hash == nil {
		t.Fatal("expected non-nil hash")
	}
	if hash.BlockCount != 6 {
		t.Errorf("expected 6 blocks, got %d", hash.BlockCount)
	}
	if hash.LoopCount < 1 {
		t.Errorf("expected at least 1 loop, got %d", hash.LoopCount)
	}
}

func TestCFGHash_SingleBlock(t *testing.T) {
	c := cfg.NewCFG()
	c.AddBlock(&cfg.BasicBlock{ID: 0})
	c.Entry = 0
	c.Exits = []cfg.BlockID{0}

	hash := ComputeCFGHash(c)
	if hash == nil {
		t.Fatal("expected non-nil hash")
	}
	if hash.BlockCount != 1 {
		t.Errorf("expected 1 block, got %d", hash.BlockCount)
	}
	if hash.EdgeCount != 0 {
		t.Errorf("expected 0 edges, got %d", hash.EdgeCount)
	}
	if hash.LoopCount != 0 {
		t.Errorf("expected 0 loops, got %d", hash.LoopCount)
	}
}

func TestCFGHashSimilarity_VeryDifferent(t *testing.T) {
	a := &CFGHash{
		BlockCount:         2,
		EdgeCount:          1,
		LoopCount:          0,
		DominatorTreeDepth: 1,
		DegreeSequence: []DegreeEntry{
			{InDegree: 0, OutDegree: 1},
			{InDegree: 1, OutDegree: 0},
		},
		Hash64: 0x1111,
	}
	b := &CFGHash{
		BlockCount:         100,
		EdgeCount:          200,
		LoopCount:          10,
		DominatorTreeDepth: 15,
		DegreeSequence: []DegreeEntry{
			{InDegree: 0, OutDegree: 5},
			{InDegree: 5, OutDegree: 3},
		},
		Hash64: 0x2222,
	}

	sim := CFGHashSimilarity(a, b)
	if sim < 0 || sim > 1.0 {
		t.Errorf("similarity out of range: %f", sim)
	}
	if sim > 0.5 {
		t.Errorf("expected low similarity for very different CFGs, got %f", sim)
	}
}

func TestFingerprintSimilarity_PartialMatch(t *testing.T) {
	a := &FunctionFingerprint{
		Pattern: []WildcardByte{
			{Value: 0x48, IsWild: false},
			{Value: 0x89, IsWild: false},
			{Value: 0xF8, IsWild: false},
			{Value: 0x00, IsWild: false},
		},
		ByteLength: 4,
	}
	b := &FunctionFingerprint{
		Pattern: []WildcardByte{
			{Value: 0x48, IsWild: false},
			{Value: 0x89, IsWild: false},
			{Value: 0xFF, IsWild: false},
			{Value: 0xFF, IsWild: false},
		},
		ByteLength: 4,
	}

	sim := FingerprintSimilarity(a, b)
	if sim < 0 || sim > 1.0 {
		t.Errorf("similarity out of range: %f", sim)
	}
	if sim != 0.5 {
		t.Errorf("expected 0.5 similarity (2/4 match), got %f", sim)
	}
}

func TestFingerprintSimilarity_WithWildcards(t *testing.T) {
	a := &FunctionFingerprint{
		Pattern: []WildcardByte{
			{Value: 0x48, IsWild: false},
			{Value: 0x00, IsWild: true},
			{Value: 0xF8, IsWild: false},
		},
		ByteLength: 3,
	}
	b := &FunctionFingerprint{
		Pattern: []WildcardByte{
			{Value: 0x48, IsWild: false},
			{Value: 0xFF, IsWild: false},
			{Value: 0xF8, IsWild: false},
		},
		ByteLength: 3,
	}

	sim := FingerprintSimilarity(a, b)
	if sim != 1.0 {
		t.Errorf("expected 1.0 (wildcards excluded, remaining match), got %f", sim)
	}
}

func TestFingerprintSimilarity_DifferentLengths(t *testing.T) {
	a := &FunctionFingerprint{
		Pattern: []WildcardByte{
			{Value: 0x48, IsWild: false},
			{Value: 0x89, IsWild: false},
		},
		ByteLength: 2,
	}
	b := &FunctionFingerprint{
		Pattern: []WildcardByte{
			{Value: 0x48, IsWild: false},
			{Value: 0x89, IsWild: false},
			{Value: 0xF8, IsWild: false},
			{Value: 0xC3, IsWild: false},
		},
		ByteLength: 4,
	}

	sim := FingerprintSimilarity(a, b)
	if sim >= 1.0 {
		t.Errorf("expected < 1.0 due to length penalty, got %f", sim)
	}
	if sim <= 0 {
		t.Errorf("expected > 0 due to partial match, got %f", sim)
	}
}

// ---------------------------------------------------------------------------
// SignatureDB: additional coverage
// ---------------------------------------------------------------------------

func TestSignatureDB_Size(t *testing.T) {
	db := NewSignatureDB()
	if db.Size() != 0 {
		t.Errorf("expected 0, got %d", db.Size())
	}
	db.Add(&Signature{Name: "test", Library: "lib"})
	if db.Size() != 1 {
		t.Errorf("expected 1, got %d", db.Size())
	}
}

func TestSignatureDB_LookupByName_Empty(t *testing.T) {
	db := NewSignatureDB()
	results := db.LookupByName("nonexistent")
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestSignatureDB_MultipleSameName(t *testing.T) {
	db := NewSignatureDB()
	db.Add(&Signature{Name: "memcpy", Library: "libc-2.31"})
	db.Add(&Signature{Name: "memcpy", Library: "libc-2.35"})
	db.Add(&Signature{Name: "memcpy", Library: "musl-1.2"})

	results := db.LookupByName("memcpy")
	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}
}

func TestSignatureFormat_String(t *testing.T) {
	tests := []struct {
		f    SignatureFormat
		want string
	}{
		{SignatureFormatFLIRT, "FLIRT"},
		{SignatureFormatFID, "FID"},
		{SignatureFormatNative, "Native"},
		{SignatureFormatUnknown, "Unknown"},
		{SignatureFormat(99), "Unknown"},
	}
	for _, tt := range tests {
		got := tt.f.String()
		if got != tt.want {
			t.Errorf("SignatureFormat(%d).String() = %q, want %q", tt.f, got, tt.want)
		}
	}
}

func TestMatchResult_String(t *testing.T) {
	mr := &MatchResult{
		Signature: &Signature{
			Name:    "memcpy",
			Library: "libc-2.35",
		},
		Confidence:     0.85,
		ByteSimilarity: 0.9,
		CFGSimilarity:  0.7,
	}
	s := mr.String()
	if s == "" {
		t.Error("String() returned empty string")
	}
}
