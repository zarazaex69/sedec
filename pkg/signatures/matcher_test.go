package signatures

import (
	"strings"
	"testing"

	binfmt "github.com/zarazaex69/sedec/pkg/binary"
	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/disasm"
)

// ============================================================================
// helpers
// ============================================================================

// makeInstr builds a minimal disasm.Instruction with the given bytes and mnemonic.
func makeInstr(addr uint64, mnem string, bytes []byte) *disasm.Instruction {
	return &disasm.Instruction{
		Address:  disasm.Address(addr),
		Mnemonic: mnem,
		Bytes:    bytes,
		Length:   len(bytes),
	}
}

// makeCallInstr builds a CALL rel32 instruction (E8 xx xx xx xx).
func makeCallInstr(addr uint64, rel int32) *disasm.Instruction {
	b := make([]byte, 5)
	b[0] = 0xE8
	b[1] = byte(rel)
	b[2] = byte(rel >> 8)
	b[3] = byte(rel >> 16)
	b[4] = byte(rel >> 24)
	return &disasm.Instruction{
		Address:  disasm.Address(addr),
		Mnemonic: "call",
		Bytes:    b,
		Length:   5,
	}
}

// makeJmpRel32 builds a JMP rel32 instruction (E9 xx xx xx xx).
func makeJmpRel32(addr uint64, rel int32) *disasm.Instruction {
	b := make([]byte, 5)
	b[0] = 0xE9
	b[1] = byte(rel)
	b[2] = byte(rel >> 8)
	b[3] = byte(rel >> 16)
	b[4] = byte(rel >> 24)
	return &disasm.Instruction{
		Address:  disasm.Address(addr),
		Mnemonic: "jmp",
		Bytes:    b,
		Length:   5,
	}
}

// makeJccShort builds a short Jcc rel8 instruction (7x xx).
func makeJccShort(addr uint64, opcode byte, rel int8) *disasm.Instruction {
	return &disasm.Instruction{
		Address:  disasm.Address(addr),
		Mnemonic: "je",
		Bytes:    []byte{opcode, byte(rel)},
		Length:   2,
	}
}

// buildSimpleCFG creates a minimal CFG with the given number of blocks
// arranged in a linear chain.
func buildSimpleCFG(blockCount int) *cfg.CFG {
	graph := cfg.NewCFG()
	for i := 0; i < blockCount; i++ {
		id := cfg.BlockID(i)
		block := &cfg.BasicBlock{
			ID:           id,
			StartAddress: disasm.Address(uint64(i) * 0x10),
			EndAddress:   disasm.Address(uint64(i)*0x10 + 0x0F),
		}
		graph.AddBlock(block)
	}
	graph.Entry = 0
	for i := 0; i < blockCount-1; i++ {
		graph.AddEdge(cfg.BlockID(i), cfg.BlockID(i+1), cfg.EdgeTypeFallthrough)
	}
	return graph
}

// buildLoopCFG creates a CFG with a single back-edge (loop).
func buildLoopCFG() *cfg.CFG {
	graph := cfg.NewCFG()
	for i := 0; i < 3; i++ {
		id := cfg.BlockID(i)
		block := &cfg.BasicBlock{
			ID:           id,
			StartAddress: disasm.Address(uint64(i) * 0x10),
			EndAddress:   disasm.Address(uint64(i)*0x10 + 0x0F),
		}
		graph.AddBlock(block)
	}
	graph.Entry = 0
	graph.AddEdge(0, 1, cfg.EdgeTypeFallthrough)
	graph.AddEdge(1, 2, cfg.EdgeTypeConditional)
	graph.AddEdge(2, 1, cfg.EdgeTypeConditional) // back-edge
	return graph
}

// ============================================================================
// fingerprint tests
// ============================================================================

func TestComputeFingerprint_Empty(t *testing.T) {
	fp := ComputeFingerprint(nil, 0)
	if fp == nil {
		t.Fatal("expected non-nil fingerprint for nil input")
	}
	if len(fp.Pattern) != 0 {
		t.Errorf("expected empty pattern, got %d bytes", len(fp.Pattern))
	}
}

func TestComputeFingerprint_CallMasked(t *testing.T) {
	// CALL rel32: bytes 1-4 must be wildcarded
	instr := makeCallInstr(0x1000, 0x12345678)
	fp := ComputeFingerprint([]*disasm.Instruction{instr}, 0)

	if len(fp.Pattern) != 5 {
		t.Fatalf("expected 5 bytes, got %d", len(fp.Pattern))
	}
	if fp.Pattern[0].IsWild {
		t.Error("opcode byte should not be wildcarded")
	}
	for i := 1; i <= 4; i++ {
		if !fp.Pattern[i].IsWild {
			t.Errorf("byte %d of CALL rel32 should be wildcarded", i)
		}
	}
}

func TestComputeFingerprint_JmpRel32Masked(t *testing.T) {
	instr := makeJmpRel32(0x1000, 0x00AABBCC)
	fp := ComputeFingerprint([]*disasm.Instruction{instr}, 0)

	if len(fp.Pattern) != 5 {
		t.Fatalf("expected 5 bytes, got %d", len(fp.Pattern))
	}
	if fp.Pattern[0].IsWild {
		t.Error("E9 opcode should not be wildcarded")
	}
	for i := 1; i <= 4; i++ {
		if !fp.Pattern[i].IsWild {
			t.Errorf("byte %d of JMP rel32 should be wildcarded", i)
		}
	}
}

func TestComputeFingerprint_ShortJccMasked(t *testing.T) {
	instr := makeJccShort(0x1000, 0x74, 0x10) // JE rel8
	fp := ComputeFingerprint([]*disasm.Instruction{instr}, 0)

	if len(fp.Pattern) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(fp.Pattern))
	}
	if fp.Pattern[0].IsWild {
		t.Error("opcode byte should not be wildcarded")
	}
	if !fp.Pattern[1].IsWild {
		t.Error("rel8 offset should be wildcarded")
	}
}

func TestComputeFingerprint_NopNotMasked(t *testing.T) {
	instr := makeInstr(0x1000, "nop", []byte{0x90})
	fp := ComputeFingerprint([]*disasm.Instruction{instr}, 0)

	if len(fp.Pattern) != 1 {
		t.Fatalf("expected 1 byte, got %d", len(fp.Pattern))
	}
	if fp.Pattern[0].IsWild {
		t.Error("NOP byte should not be wildcarded")
	}
	if fp.Pattern[0].Value != 0x90 {
		t.Errorf("expected 0x90, got 0x%02x", fp.Pattern[0].Value)
	}
}

func TestComputeFingerprint_MultipleInstructions(t *testing.T) {
	instrs := []*disasm.Instruction{
		makeInstr(0x1000, "push", []byte{0x55}),
		makeInstr(0x1001, "mov", []byte{0x48, 0x89, 0xE5}),
		makeCallInstr(0x1004, 0x100),
		makeInstr(0x1009, "pop", []byte{0x5D}),
		makeInstr(0x100A, "ret", []byte{0xC3}),
	}
	fp := ComputeFingerprint(instrs, 0)

	// total: 1 + 3 + 5 + 1 + 1 = 11 bytes
	if len(fp.Pattern) != 11 {
		t.Fatalf("expected 11 bytes, got %d", len(fp.Pattern))
	}

	// bytes 5-8 (CALL rel32 offset) must be wildcarded; byte 4 is the 0xE8 opcode
	if fp.Pattern[4].IsWild {
		t.Error("byte 4 (CALL opcode 0xE8) should not be wildcarded")
	}
	for i := 5; i <= 8; i++ {
		if !fp.Pattern[i].IsWild {
			t.Errorf("byte %d should be wildcarded (CALL rel32 offset)", i)
		}
	}
}

// ============================================================================
// fingerprint similarity tests
// ============================================================================

func TestFingerprintSimilarity_Identical(t *testing.T) {
	instrs := []*disasm.Instruction{
		makeInstr(0x1000, "push", []byte{0x55}),
		makeInstr(0x1001, "ret", []byte{0xC3}),
	}
	fp := ComputeFingerprint(instrs, 0)
	sim := FingerprintSimilarity(fp, fp)
	if sim != 1.0 {
		t.Errorf("identical fingerprints should have similarity 1.0, got %f", sim)
	}
}

func TestFingerprintSimilarity_TotallyDifferent(t *testing.T) {
	fp1 := &FunctionFingerprint{
		Pattern: []WildcardByte{{Value: 0x55}, {Value: 0x48}, {Value: 0x89}},
	}
	fp2 := &FunctionFingerprint{
		Pattern: []WildcardByte{{Value: 0xAA}, {Value: 0xBB}, {Value: 0xCC}},
	}
	sim := FingerprintSimilarity(fp1, fp2)
	if sim != 0.0 {
		t.Errorf("completely different fingerprints should have similarity 0.0, got %f", sim)
	}
}

func TestFingerprintSimilarity_AllWildcards(t *testing.T) {
	fp1 := &FunctionFingerprint{
		Pattern: []WildcardByte{{IsWild: true}, {IsWild: true}},
	}
	fp2 := &FunctionFingerprint{
		Pattern: []WildcardByte{{IsWild: true}, {IsWild: true}},
	}
	sim := FingerprintSimilarity(fp1, fp2)
	// all wildcards → treated as identical
	if sim != 1.0 {
		t.Errorf("all-wildcard fingerprints should have similarity 1.0, got %f", sim)
	}
}

func TestFingerprintSimilarity_NilInputs(t *testing.T) {
	fp := &FunctionFingerprint{Pattern: []WildcardByte{{Value: 0x55}}}
	if FingerprintSimilarity(nil, fp) != 0.0 {
		t.Error("nil left should return 0.0")
	}
	if FingerprintSimilarity(fp, nil) != 0.0 {
		t.Error("nil right should return 0.0")
	}
	if FingerprintSimilarity(nil, nil) != 0.0 {
		t.Error("both nil should return 0.0")
	}
}

// ============================================================================
// CFG hash tests
// ============================================================================

func TestComputeCFGHash_Nil(t *testing.T) {
	h := ComputeCFGHash(nil)
	if h == nil {
		t.Fatal("expected non-nil hash for nil CFG")
	}
	if h.BlockCount != 0 || h.EdgeCount != 0 {
		t.Error("nil CFG should produce zero-valued hash")
	}
}

func TestComputeCFGHash_Linear(t *testing.T) {
	graph := buildSimpleCFG(4)
	h := ComputeCFGHash(graph)

	if h.BlockCount != 4 {
		t.Errorf("expected 4 blocks, got %d", h.BlockCount)
	}
	if h.EdgeCount != 3 {
		t.Errorf("expected 3 edges, got %d", h.EdgeCount)
	}
	if h.LoopCount != 0 {
		t.Errorf("linear CFG should have 0 loops, got %d", h.LoopCount)
	}
}

func TestComputeCFGHash_Loop(t *testing.T) {
	graph := buildLoopCFG()
	h := ComputeCFGHash(graph)

	if h.BlockCount != 3 {
		t.Errorf("expected 3 blocks, got %d", h.BlockCount)
	}
	if h.LoopCount == 0 {
		t.Error("loop CFG should have at least 1 loop")
	}
}

func TestComputeCFGHash_Deterministic(t *testing.T) {
	graph := buildSimpleCFG(5)
	h1 := ComputeCFGHash(graph)
	h2 := ComputeCFGHash(graph)

	if h1.Hash64 != h2.Hash64 {
		t.Error("CFG hash must be deterministic")
	}
}

func TestCFGHashSimilarity_Identical(t *testing.T) {
	graph := buildSimpleCFG(4)
	h := ComputeCFGHash(graph)
	sim := CFGHashSimilarity(h, h)
	if sim != 1.0 {
		t.Errorf("identical hashes should have similarity 1.0, got %f", sim)
	}
}

func TestCFGHashSimilarity_NilInputs(t *testing.T) {
	h := ComputeCFGHash(buildSimpleCFG(3))
	if CFGHashSimilarity(nil, h) != 0.0 {
		t.Error("nil left should return 0.0")
	}
	if CFGHashSimilarity(h, nil) != 0.0 {
		t.Error("nil right should return 0.0")
	}
}

func TestCFGHashSimilarity_DifferentSizes(t *testing.T) {
	h1 := ComputeCFGHash(buildSimpleCFG(2))
	h2 := ComputeCFGHash(buildSimpleCFG(10))
	sim := CFGHashSimilarity(h1, h2)
	if sim < 0.0 || sim > 1.0 {
		t.Errorf("similarity must be in [0,1], got %f", sim)
	}
	if sim >= 1.0 {
		t.Error("very different CFGs should not have similarity 1.0")
	}
}

// ============================================================================
// signature database tests
// ============================================================================

func TestSignatureDB_AddAndLookup(t *testing.T) {
	db := NewSignatureDB()
	sig := &Signature{
		Name:    "memcpy",
		Library: "libc",
		Format:  SignatureFormatNative,
		Fingerprint: &FunctionFingerprint{
			Pattern:    []WildcardByte{{Value: 0x55}},
			ByteLength: 1,
		},
	}
	db.Add(sig)

	if db.Size() != 1 {
		t.Errorf("expected size 1, got %d", db.Size())
	}

	results := db.LookupByName("memcpy")
	if len(results) != 1 {
		t.Errorf("expected 1 result for 'memcpy', got %d", len(results))
	}

	empty := db.LookupByName("nonexistent")
	if len(empty) != 0 {
		t.Errorf("expected 0 results for unknown name, got %d", len(empty))
	}
}

func TestSignatureDB_MultipleCollisions(t *testing.T) {
	db := NewSignatureDB()
	for i := 0; i < 3; i++ {
		db.Add(&Signature{
			Name:    "memcpy",
			Library: "libc",
			Format:  SignatureFormatNative,
		})
	}

	results := db.LookupByName("memcpy")
	if len(results) != 3 {
		t.Errorf("expected 3 collision entries, got %d", len(results))
	}
}

// ============================================================================
// MatchSignatures tests
// ============================================================================

func buildTestDB() *SignatureDB {
	db := NewSignatureDB()

	// memcpy: push rbp; mov rbp,rsp; ret
	memcpyInstrs := []*disasm.Instruction{
		makeInstr(0, "push", []byte{0x55}),
		makeInstr(1, "mov", []byte{0x48, 0x89, 0xE5}),
		makeInstr(4, "ret", []byte{0xC3}),
	}
	db.Add(&Signature{
		Name:        "memcpy",
		Library:     "libc-2.35",
		Format:      SignatureFormatNative,
		Fingerprint: ComputeFingerprint(memcpyInstrs, 0),
		CFGHash:     ComputeCFGHash(buildSimpleCFG(1)),
	})

	// strlen: different bytes
	strlenInstrs := []*disasm.Instruction{
		makeInstr(0, "xor", []byte{0x31, 0xC0}),
		makeInstr(2, "ret", []byte{0xC3}),
	}
	db.Add(&Signature{
		Name:        "strlen",
		Library:     "libc-2.35",
		Format:      SignatureFormatNative,
		Fingerprint: ComputeFingerprint(strlenInstrs, 0),
		CFGHash:     ComputeCFGHash(buildSimpleCFG(1)),
	})

	return db
}

func TestMatchSignatures_ExactMatch(t *testing.T) {
	db := buildTestDB()

	// query with the exact same bytes as memcpy
	queryInstrs := []*disasm.Instruction{
		makeInstr(0x4000, "push", []byte{0x55}),
		makeInstr(0x4001, "mov", []byte{0x48, 0x89, 0xE5}),
		makeInstr(0x4004, "ret", []byte{0xC3}),
	}

	input := &MatchInput{
		Instructions: queryInstrs,
		FunctionCFG:  buildSimpleCFG(1),
		Address:      0x4000,
	}

	results := MatchSignatures(input, db)
	if len(results) == 0 {
		t.Fatal("expected at least one match")
	}

	top := results[0]
	if top.Signature.Name != "memcpy" {
		t.Errorf("expected top match 'memcpy', got %q", top.Signature.Name)
	}
	if top.Confidence < 0.8 {
		t.Errorf("expected high confidence for exact match, got %f", top.Confidence)
	}
}

func TestMatchSignatures_EmptyDB(t *testing.T) {
	db := NewSignatureDB()
	input := &MatchInput{
		Instructions: []*disasm.Instruction{makeInstr(0, "ret", []byte{0xC3})},
	}
	results := MatchSignatures(input, db)
	if results == nil {
		t.Error("MatchSignatures must return non-nil slice")
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty DB, got %d", len(results))
	}
}

func TestMatchSignatures_NilDB(t *testing.T) {
	input := &MatchInput{
		Instructions: []*disasm.Instruction{makeInstr(0, "ret", []byte{0xC3})},
	}
	results := MatchSignatures(input, nil)
	if results == nil {
		t.Error("MatchSignatures must return non-nil slice for nil DB")
	}
}

func TestMatchSignatures_ConfidenceRange(t *testing.T) {
	db := buildTestDB()
	input := &MatchInput{
		Instructions: []*disasm.Instruction{
			makeInstr(0, "push", []byte{0x55}),
			makeInstr(1, "ret", []byte{0xC3}),
		},
		FunctionCFG: buildSimpleCFG(1),
	}

	results := MatchSignatures(input, db)
	for _, r := range results {
		if r.Confidence < 0.0 || r.Confidence > 1.0 {
			t.Errorf("confidence %f out of [0,1] range", r.Confidence)
		}
	}
}

func TestMatchSignatures_SortedByConfidence(t *testing.T) {
	db := buildTestDB()
	input := &MatchInput{
		Instructions: []*disasm.Instruction{
			makeInstr(0, "push", []byte{0x55}),
			makeInstr(1, "mov", []byte{0x48, 0x89, 0xE5}),
			makeInstr(4, "ret", []byte{0xC3}),
		},
		FunctionCFG: buildSimpleCFG(1),
	}

	results := MatchSignatures(input, db)
	for i := 1; i < len(results); i++ {
		if results[i].Confidence > results[i-1].Confidence {
			t.Errorf("results not sorted: results[%d].Confidence=%f > results[%d].Confidence=%f",
				i, results[i].Confidence, i-1, results[i-1].Confidence)
		}
	}
}

func TestMatchSignatures_CollisionReporting(t *testing.T) {
	// req 16.13: when multiple signatures share the same name, all are returned
	db := NewSignatureDB()
	for i := 0; i < 3; i++ {
		db.Add(&Signature{
			Name:    "memcpy",
			Library: "libc",
			Format:  SignatureFormatNative,
			Fingerprint: &FunctionFingerprint{
				Pattern:    []WildcardByte{{Value: 0x55}},
				ByteLength: 1,
			},
		})
	}

	input := &MatchInput{
		Instructions: []*disasm.Instruction{makeInstr(0, "push", []byte{0x55})},
	}

	results := MatchSignatures(input, db)
	if len(results) < 3 {
		t.Errorf("expected at least 3 collision candidates, got %d", len(results))
	}
}

func TestMatchSignatures_NameHintBoost(t *testing.T) {
	db := buildTestDB()

	gt := binfmt.NewGroundTruthDatabase()
	gt.SymbolsByAddress[0x4000] = "memcpy"

	input := &MatchInput{
		Instructions: []*disasm.Instruction{
			makeInstr(0x4000, "push", []byte{0x55}),
			makeInstr(0x4001, "ret", []byte{0xC3}),
		},
		Address:     0x4000,
		GroundTruth: gt,
	}

	results := MatchSignatures(input, db)
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}

	// memcpy should be ranked first due to name hint
	if results[0].Signature.Name != "memcpy" {
		t.Errorf("expected 'memcpy' as top result with name hint, got %q", results[0].Signature.Name)
	}
	if results[0].NameHint != "memcpy" {
		t.Errorf("expected NameHint='memcpy', got %q", results[0].NameHint)
	}
}

func TestTopMatch_NoResults(t *testing.T) {
	db := NewSignatureDB()
	input := &MatchInput{
		Instructions: []*disasm.Instruction{makeInstr(0, "ret", []byte{0xC3})},
	}
	result := TopMatch(input, db)
	if result != nil {
		t.Error("expected nil for empty DB")
	}
}

func TestMatchByName(t *testing.T) {
	db := buildTestDB()
	input := &MatchInput{
		Instructions: []*disasm.Instruction{
			makeInstr(0, "push", []byte{0x55}),
			makeInstr(1, "mov", []byte{0x48, 0x89, 0xE5}),
			makeInstr(4, "ret", []byte{0xC3}),
		},
	}

	results := MatchByName(input, db, "memcpy")
	if len(results) == 0 {
		t.Fatal("expected at least one result for 'memcpy'")
	}
	for _, r := range results {
		if r.Signature.Name != "memcpy" {
			t.Errorf("MatchByName returned non-memcpy result: %q", r.Signature.Name)
		}
	}
}

// ============================================================================
// FLIRT PAT parsing tests
// ============================================================================

func TestParseFLIRTPattern_Valid(t *testing.T) {
	tests := []struct {
		input    string
		wantLen  int
		wantWild []int // indices that should be wildcards
	}{
		{"5548..E5C3", 5, []int{2}},
		{"....C3", 3, []int{0, 1}},
		{"5548", 2, nil},
	}

	for _, tc := range tests {
		pattern, err := parseFLIRTPattern(tc.input)
		if err != nil {
			t.Errorf("parseFLIRTPattern(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if len(pattern) != tc.wantLen {
			t.Errorf("parseFLIRTPattern(%q): got %d bytes, want %d", tc.input, len(pattern), tc.wantLen)
		}
		wildSet := make(map[int]bool)
		for _, i := range tc.wantWild {
			wildSet[i] = true
		}
		for i, wb := range pattern {
			if wildSet[i] && !wb.IsWild {
				t.Errorf("parseFLIRTPattern(%q): byte %d should be wild", tc.input, i)
			}
			if !wildSet[i] && wb.IsWild {
				t.Errorf("parseFLIRTPattern(%q): byte %d should not be wild", tc.input, i)
			}
		}
	}
}

func TestParseFLIRTPattern_Invalid(t *testing.T) {
	_, err := parseFLIRTPattern("5") // odd length
	if err == nil {
		t.Error("expected error for odd-length pattern")
	}

	_, err = parseFLIRTPattern("GG") // invalid hex
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

// ============================================================================
// FingerprintString test
// ============================================================================

func TestFingerprintString(t *testing.T) {
	fp := &FunctionFingerprint{
		Pattern: []WildcardByte{
			{Value: 0x55},
			{IsWild: true},
			{Value: 0xC3},
		},
	}
	s := fp.String()
	expected := "55 ?? c3"
	if s != expected {
		t.Errorf("expected %q, got %q", expected, s)
	}
}

// ============================================================================
// MatchResult.String test
// ============================================================================

func TestMatchResultString(t *testing.T) {
	mr := &MatchResult{
		Signature: &Signature{
			Name:    "memcpy",
			Library: "libc",
		},
		Confidence:     0.95,
		ByteSimilarity: 0.98,
		CFGSimilarity:  0.90,
	}
	s := mr.String()
	if s == "" {
		t.Error("MatchResult.String() should not be empty")
	}
}

// ============================================================================
// db.go coverage tests
// ============================================================================

func TestLoadNativeJSON_RoundTrip(t *testing.T) {
	import_strings := `[
		{"name":"memcpy","library":"libc","version":"2.35","format":"Native",
		 "address":4096,"byte_len":3,
		 "pattern":[{"v":85},{"v":72},{"v":197}],
		 "cfg_hash":{"blocks":1,"edges":0,"loops":0,"dom_depth":0,"hash64":12345,"degree_seq":[{"in":0,"out":0}]}}
	]`

	db, err := loadNativeJSON(strings.NewReader(import_strings))
	if err != nil {
		t.Fatalf("loadNativeJSON: %v", err)
	}
	if db.Size() != 1 {
		t.Fatalf("expected 1 signature, got %d", db.Size())
	}
	sig := db.Signatures[0]
	if sig.Name != "memcpy" {
		t.Errorf("expected name 'memcpy', got %q", sig.Name)
	}
	if sig.Fingerprint == nil {
		t.Fatal("expected non-nil fingerprint")
	}
	if len(sig.Fingerprint.Pattern) != 3 {
		t.Errorf("expected 3 pattern bytes, got %d", len(sig.Fingerprint.Pattern))
	}
	if sig.CFGHash == nil {
		t.Fatal("expected non-nil CFGHash")
	}
	if sig.CFGHash.BlockCount != 1 {
		t.Errorf("expected BlockCount=1, got %d", sig.CFGHash.BlockCount)
	}
}

func TestLoadNativeJSON_InvalidJSON(t *testing.T) {
	_, err := loadNativeJSON(strings.NewReader("{invalid"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadFLIRT_ValidPAT(t *testing.T) {
	pat := "5548E5C3 04 1234 0004 :0000 memcpy\n---\n"
	db, err := loadFLIRT(strings.NewReader(pat), "test.pat")
	if err != nil {
		t.Fatalf("loadFLIRT: %v", err)
	}
	if db.Size() != 1 {
		t.Fatalf("expected 1 signature, got %d", db.Size())
	}
	if db.Signatures[0].Name != "memcpy" {
		t.Errorf("expected name 'memcpy', got %q", db.Signatures[0].Name)
	}
}

func TestLoadFLIRT_SkipsComments(t *testing.T) {
	pat := "; this is a comment\n# another comment\n5548C3 04 1234 0003 :0000 strlen\n"
	db, err := loadFLIRT(strings.NewReader(pat), "test.pat")
	if err != nil {
		t.Fatalf("loadFLIRT: %v", err)
	}
	if db.Size() != 1 {
		t.Errorf("expected 1 signature (comments skipped), got %d", db.Size())
	}
}

func TestLoadFLIRT_MalformedLineSkipped(t *testing.T) {
	// malformed line should be skipped, not cause error
	pat := "ZZZZ 04 1234 0004 :0000 bad\n5548C3 04 1234 0003 :0000 good\n"
	db, err := loadFLIRT(strings.NewReader(pat), "test.pat")
	if err != nil {
		t.Fatalf("loadFLIRT: %v", err)
	}
	if db.Size() != 1 {
		t.Errorf("expected 1 valid signature, got %d", db.Size())
	}
}

func TestLoadFID_ValidJSON(t *testing.T) {
	fidJSON := `[{"full_hash":9999,"specific_hash":8888,"name":"printf","library_name":"libc","library_version":"2.35","domain_path":"/libc/printf"}]`
	db, err := loadFID(strings.NewReader(fidJSON), "test.fidb")
	if err != nil {
		t.Fatalf("loadFID: %v", err)
	}
	if db.Size() != 1 {
		t.Fatalf("expected 1 signature, got %d", db.Size())
	}
	sig := db.Signatures[0]
	if sig.Name != "printf" {
		t.Errorf("expected name 'printf', got %q", sig.Name)
	}
	if sig.Format != SignatureFormatFID {
		t.Errorf("expected FID format, got %v", sig.Format)
	}
	if sig.CFGHash == nil || sig.CFGHash.Hash64 != 9999 {
		t.Errorf("expected Hash64=9999, got %v", sig.CFGHash)
	}
}

func TestLoadFID_InvalidJSON(t *testing.T) {
	_, err := loadFID(strings.NewReader("{bad"), "test.fidb")
	if err == nil {
		t.Error("expected error for invalid FID JSON")
	}
}

func TestSignatureFormatString(t *testing.T) {
	cases := []struct {
		f    SignatureFormat
		want string
	}{
		{SignatureFormatFLIRT, "FLIRT"},
		{SignatureFormatFID, "FID"},
		{SignatureFormatNative, "Native"},
		{SignatureFormatUnknown, "Unknown"},
		{SignatureFormat(99), "Unknown"},
	}
	for _, tc := range cases {
		if got := tc.f.String(); got != tc.want {
			t.Errorf("SignatureFormat(%d).String() = %q, want %q", tc.f, got, tc.want)
		}
	}
}

func TestSaveToFile_EmptyDB(t *testing.T) {
	db := NewSignatureDB()
	err := SaveToFile(db, "/tmp/test_empty.json")
	if err == nil {
		t.Error("expected error for empty DB")
	}
}
