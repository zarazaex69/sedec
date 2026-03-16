package signatures

// **Validates: Requirements 16.4, 16.5, 16.6, 16.7, 16.13**

import (
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/disasm"
)

// genLinearCFG generates a linear CFG with 1-8 blocks.
func genLinearCFG() gopter.Gen {
	return gen.IntRange(1, 8).Map(func(n int) *cfg.CFG {
		return buildSimpleCFG(n)
	})
}

// genInstruction generates a single disasm.Instruction with random bytes.
func genInstruction() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		n := int(params.NextUint64()%8) + 1
		bs := make([]byte, n)
		for i := range bs {
			bs[i] = byte(params.NextUint64())
		}
		instr := &disasm.Instruction{
			Address:  0x1000,
			Mnemonic: "nop",
			Bytes:    bs,
			Length:   n,
		}
		return gopter.NewGenResult(instr, gopter.NoShrinker)
	}
}

// genSignatureDB generates a SignatureDB with 1-8 signatures.
func genSignatureDB() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		n := int(params.NextUint64()%8) + 1
		db := NewSignatureDB()
		for i := 0; i < n; i++ {
			pat := make([]WildcardByte, 4)
			for j := range pat {
				pat[j] = WildcardByte{Value: byte(params.NextUint64())}
			}
			db.Add(&Signature{
				Name:    "func" + string(rune('A'+i%26)),
				Library: "testlib",
				Format:  SignatureFormatNative,
				Fingerprint: &FunctionFingerprint{
					Pattern:    pat,
					ByteLength: 4,
				},
				CFGHash: ComputeCFGHash(buildSimpleCFG(i + 1)),
			})
		}
		return gopter.NewGenResult(db, gopter.NoShrinker)
	}
}

// genFingerprintPair generates two FunctionFingerprint values of the same length.
func genFingerprintPair() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		n := int(params.NextUint64()%8) + 1
		pat1 := make([]WildcardByte, n)
		pat2 := make([]WildcardByte, n)
		for i := 0; i < n; i++ {
			pat1[i] = WildcardByte{Value: byte(params.NextUint64())}
			pat2[i] = WildcardByte{Value: byte(params.NextUint64())}
		}
		pair := [2]*FunctionFingerprint{
			{Pattern: pat1, ByteLength: n},
			{Pattern: pat2, ByteLength: n},
		}
		return gopter.NewGenResult(pair, gopter.NoShrinker)
	}
}

// genByteSlice generates a non-empty byte slice of length 1-16.
func genByteSlice() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		n := int(params.NextUint64()%16) + 1
		bs := make([]byte, n)
		for i := range bs {
			bs[i] = byte(params.NextUint64())
		}
		return gopter.NewGenResult(bs, gopter.NoShrinker)
	}
}

// TestProperty16_4_MatchSignaturesNonNil verifies MatchSignatures always returns non-nil.
// **Validates: Requirements 16.4**
func TestProperty16_4_MatchSignaturesNonNil(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("MatchSignatures always returns non-nil slice", prop.ForAll(
		func(db *SignatureDB) bool {
			input := &MatchInput{
				Instructions: []*disasm.Instruction{makeInstr(0x1000, "nop", []byte{0x90})},
			}
			return MatchSignatures(input, db) != nil
		},
		genSignatureDB(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestProperty16_7_ConfidenceInRange verifies confidence scores are in [0.0, 1.0].
// **Validates: Requirements 16.7**
func TestProperty16_7_ConfidenceInRange(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("all confidence scores are in [0.0, 1.0]", prop.ForAll(
		func(db *SignatureDB) bool {
			input := &MatchInput{
				Instructions: []*disasm.Instruction{
					makeInstr(0x1000, "push", []byte{0x55}),
					makeInstr(0x1001, "ret", []byte{0xC3}),
				},
				FunctionCFG: buildSimpleCFG(1),
			}
			for _, r := range MatchSignatures(input, db) {
				if r.Confidence < 0.0 || r.Confidence > 1.0 {
					return false
				}
			}
			return true
		},
		genSignatureDB(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestProperty16_7_ResultsSorted verifies results are sorted by confidence descending.
// **Validates: Requirements 16.7**
func TestProperty16_7_ResultsSorted(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("MatchSignatures results are sorted by confidence descending", prop.ForAll(
		func(db *SignatureDB) bool {
			input := &MatchInput{
				Instructions: []*disasm.Instruction{
					makeInstr(0x1000, "push", []byte{0x55}),
					makeInstr(0x1001, "ret", []byte{0xC3}),
				},
			}
			results := MatchSignatures(input, db)
			for i := 1; i < len(results); i++ {
				if results[i].Confidence > results[i-1].Confidence {
					return false
				}
			}
			return true
		},
		genSignatureDB(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestProperty16_13_CollisionHandling verifies all collision candidates are returned.
// **Validates: Requirements 16.13**
func TestProperty16_13_CollisionHandling(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("all collision candidates are returned", prop.ForAll(
		func(n int) bool {
			db := NewSignatureDB()
			for i := 0; i < n; i++ {
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
				Instructions: []*disasm.Instruction{makeInstr(0x1000, "push", []byte{0x55})},
			}
			results := MatchSignatures(input, db)
			count := 0
			for _, r := range results {
				if r.Signature.Name == "memcpy" {
					count++
				}
			}
			expected := n
			if expected > maxCandidates {
				expected = maxCandidates
			}
			return count == expected
		},
		gen.IntRange(1, maxCandidates),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestPropertyFingerprintSimilaritySymmetric verifies FingerprintSimilarity is symmetric.
// **Validates: Requirements 16.4**
func TestPropertyFingerprintSimilaritySymmetric(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 200
	properties := gopter.NewProperties(params)

	properties.Property("FingerprintSimilarity is symmetric", prop.ForAll(
		func(pair [2]*FunctionFingerprint) bool {
			a, b := pair[0], pair[1]
			simAB := FingerprintSimilarity(a, b)
			simBA := FingerprintSimilarity(b, a)
			diff := simAB - simBA
			if diff < 0 {
				diff = -diff
			}
			return diff < 1e-9
		},
		genFingerprintPair(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestPropertyFingerprintSimilarityReflexive verifies FingerprintSimilarity(x,x)==1.0.
// **Validates: Requirements 16.4**
func TestPropertyFingerprintSimilarityReflexive(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 200
	properties := gopter.NewProperties(params)

	properties.Property("FingerprintSimilarity(x, x) == 1.0", prop.ForAll(
		func(bs []byte) bool {
			if len(bs) == 0 {
				return true
			}
			pat := make([]WildcardByte, len(bs))
			for i, b := range bs {
				pat[i] = WildcardByte{Value: b}
			}
			fp := &FunctionFingerprint{Pattern: pat, ByteLength: len(pat)}
			return FingerprintSimilarity(fp, fp) == 1.0
		},
		genByteSlice(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestPropertyCFGHashSimilarityReflexive verifies CFGHashSimilarity(x,x)==1.0.
// **Validates: Requirements 16.4**
func TestPropertyCFGHashSimilarityReflexive(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("CFGHashSimilarity(x, x) == 1.0", prop.ForAll(
		func(graph *cfg.CFG) bool {
			h := ComputeCFGHash(graph)
			return CFGHashSimilarity(h, h) == 1.0
		},
		genLinearCFG(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestPropertyCFGHashSimilarityRange verifies CFGHashSimilarity is in [0,1].
// **Validates: Requirements 16.4**
func TestPropertyCFGHashSimilarityRange(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("CFGHashSimilarity is in [0.0, 1.0]", prop.ForAll(
		func(n1, n2 int) bool {
			h1 := ComputeCFGHash(buildSimpleCFG(n1))
			h2 := ComputeCFGHash(buildSimpleCFG(n2))
			sim := CFGHashSimilarity(h1, h2)
			return sim >= 0.0 && sim <= 1.0
		},
		gen.IntRange(1, 10),
		gen.IntRange(1, 10),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestPropertyFingerprintDeterministic verifies ComputeFingerprint is deterministic.
// **Validates: Requirements 16.4**
func TestPropertyFingerprintDeterministic(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("ComputeFingerprint is deterministic", prop.ForAll(
		func(instr *disasm.Instruction) bool {
			fp1 := ComputeFingerprint([]*disasm.Instruction{instr}, 0)
			fp2 := ComputeFingerprint([]*disasm.Instruction{instr}, 0)
			if len(fp1.Pattern) != len(fp2.Pattern) {
				return false
			}
			for i := range fp1.Pattern {
				if fp1.Pattern[i] != fp2.Pattern[i] {
					return false
				}
			}
			return true
		},
		genInstruction(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestProperty16_5_16_6_FormatStrings verifies FLIRT and FID format strings.
// **Validates: Requirements 16.5, 16.6**
func TestProperty16_5_16_6_FormatStrings(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 50
	properties := gopter.NewProperties(params)

	properties.Property("FLIRT format string round-trips correctly", prop.ForAll(
		func(_ bool) bool { return parseFormatString("FLIRT") == SignatureFormatFLIRT },
		gen.Bool(),
	))

	properties.Property("FID format string round-trips correctly", prop.ForAll(
		func(_ bool) bool { return parseFormatString("FID") == SignatureFormatFID },
		gen.Bool(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestPropertyDBAddIncreasesSize verifies Add increases DB size by exactly 1.
// **Validates: Requirements 16.4**
func TestPropertyDBAddIncreasesSize(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("Add increases DB size by exactly 1", prop.ForAll(
		func(n int) bool {
			db := NewSignatureDB()
			for i := 0; i < n; i++ {
				before := db.Size()
				db.Add(&Signature{Name: "f", Library: "lib", Format: SignatureFormatNative})
				if db.Size() != before+1 {
					return false
				}
			}
			return true
		},
		gen.IntRange(1, 20),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
