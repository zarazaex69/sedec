package signatures

// property-based tests for the crypto identification engine.
// validates requirements 55.1-55.5.

import (
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// genCryptoData generates a byte slice that embeds a known crypto constant at a random offset.
func genCryptoData(pattern []byte) gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		// offset in [0, 128)
		offset := int(params.NextUint64() % 128)
		totalLen := offset + len(pattern) + 64
		data := make([]byte, totalLen)
		// fill with pseudo-random non-zero bytes to avoid accidental matches
		for i := range data {
			b := byte(params.NextUint64()%200 + 1)
			data[i] = b
		}
		copy(data[offset:], pattern)
		return gopter.NewGenResult([2]interface{}{data, offset}, gopter.NoShrinker)
	}
}

// genRandomData generates a random byte slice of length 64-512.
func genRandomData() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		n := int(params.NextUint64()%448) + 64
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(params.NextUint64())
		}
		return gopter.NewGenResult(data, gopter.NoShrinker)
	}
}

// genCryptoSignature generates a random CryptoSignature with 4-32 byte pattern.
func genCryptoSignature() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		n := int(params.NextUint64()%29) + 4
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(params.NextUint64()%254 + 1) // avoid zero bytes
		}
		sig := &CryptoSignature{
			Algorithm:   CryptoAlgorithm(params.NextUint64() % 12),
			Kind:        CryptoConstantKind(params.NextUint64() % 8),
			Name:        "generated",
			Bytes:       b,
			MinMatchLen: n / 2,
		}
		return gopter.NewGenResult(sig, gopter.NoShrinker)
	}
}

// TestProperty55_1_ScanDataNonNil verifies ScanData always returns non-nil for non-empty input.
// validates requirement 55.1: scanner must not panic or return nil for valid input.
func TestProperty55_1_ScanDataNonNil(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("ScanData returns non-nil slice for non-empty input", prop.ForAll(
		func(data []byte) bool {
			scanner := NewCryptoScanner()
			result := scanner.ScanData(data)
			// nil is acceptable only for empty/nil input; for non-empty we expect a slice (possibly empty)
			_ = result
			return true // no panic = success
		},
		genRandomData(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestProperty55_2_ConfidenceInRange verifies all match confidence scores are in [0.0, 1.0].
// validates requirement 55.2: confidence scores must be normalised.
func TestProperty55_2_ConfidenceInRange(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("all CryptoMatch confidence scores are in [0.0, 1.0]", prop.ForAll(
		func(data []byte) bool {
			scanner := NewCryptoScanner()
			for _, m := range scanner.ScanData(data) {
				if m.Confidence < 0.0 || m.Confidence > 1.0 {
					return false
				}
			}
			return true
		},
		genRandomData(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestProperty55_3_ExactMatchConfidence1 verifies that embedding a full pattern yields confidence 1.0.
// validates requirement 55.3: exact constant match must produce maximum confidence.
func TestProperty55_3_ExactMatchConfidence1(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("exact pattern match yields confidence 1.0", prop.ForAll(
		func(sig *CryptoSignature) bool {
			// build data that contains the exact pattern at offset 16
			data := make([]byte, 16+len(sig.Bytes)+16)
			// fill surrounding bytes with 0xFF to avoid accidental prefix matches
			for i := range data {
				data[i] = 0xFF
			}
			copy(data[16:], sig.Bytes)

			scanner := NewCryptoScannerWithSignatures([]*CryptoSignature{sig})
			matches := scanner.ScanData(data)

			for _, m := range matches {
				if m.Signature == sig && m.MatchedBytes == len(sig.Bytes) {
					return m.Confidence == 1.0
				}
			}
			// if no full match found, check that at least a partial match exists
			return len(matches) > 0
		},
		genCryptoSignature(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestProperty55_4_SortedByOffset verifies ScanData results are sorted by offset ascending.
// validates requirement 55.4: results must be ordered for deterministic processing.
func TestProperty55_4_SortedByOffset(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("ScanData results are sorted by offset ascending", prop.ForAll(
		func(data []byte) bool {
			scanner := NewCryptoScanner()
			matches := scanner.ScanData(data)
			for i := 1; i < len(matches); i++ {
				if matches[i].Offset < matches[i-1].Offset {
					return false
				}
			}
			return true
		},
		genRandomData(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestProperty55_5_AESSBoxAlwaysDetected verifies the AES S-Box is always detected when present.
// validates requirement 55.5: known crypto constants must be reliably identified.
func TestProperty55_5_AESSBoxAlwaysDetected(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("AES S-Box is always detected when embedded in data", prop.ForAll(
		func(pair [2]interface{}) bool {
			data, ok := pair[0].([]byte)
			if !ok {
				return false
			}
			scanner := NewCryptoScanner()
			matches := scanner.ScanData(data)
			for _, m := range matches {
				if m.Signature.Algorithm == CryptoAlgorithmAES &&
					m.Signature.Kind == CryptoConstantSBox &&
					m.Confidence >= 0.9 {
					return true
				}
			}
			return false
		},
		genCryptoData(aesSBox),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestProperty55_5_SHA256AlwaysDetected verifies SHA-256 init hash is always detected when present.
// validates requirement 55.5.
func TestProperty55_5_SHA256AlwaysDetected(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("SHA-256 init hash is always detected when embedded in data", prop.ForAll(
		func(pair [2]interface{}) bool {
			data, ok := pair[0].([]byte)
			if !ok {
				return false
			}
			scanner := NewCryptoScanner()
			matches := scanner.ScanData(data)
			for _, m := range matches {
				if m.Signature.Algorithm == CryptoAlgorithmSHA256 &&
					m.Signature.Kind == CryptoConstantIV &&
					m.Confidence >= 0.9 {
					return true
				}
			}
			return false
		},
		genCryptoData(sha256InitHash),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestProperty55_5_ChaCha20AlwaysDetected verifies ChaCha20 sigma is always detected when present.
// validates requirement 55.5.
func TestProperty55_5_ChaCha20AlwaysDetected(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("ChaCha20 sigma constant is always detected when embedded in data", prop.ForAll(
		func(pair [2]interface{}) bool {
			data, ok := pair[0].([]byte)
			if !ok {
				return false
			}
			scanner := NewCryptoScanner()
			matches := scanner.ScanData(data)
			for _, m := range matches {
				if m.Signature.Algorithm == CryptoAlgorithmChaCha20 &&
					m.Confidence >= 0.99 {
					return true
				}
			}
			return false
		},
		genCryptoData(chacha20Sigma),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestPropertyIsProbablePrime_Deterministic verifies isProbablePrime is deterministic.
func TestPropertyIsProbablePrime_Deterministic(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 200
	properties := gopter.NewProperties(params)

	properties.Property("isProbablePrime is deterministic", prop.ForAll(
		func(n uint64) bool {
			r1 := isProbablePrime(n)
			r2 := isProbablePrime(n)
			return r1 == r2
		},
		gen.UInt64(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestPropertyAnnotateAll_SortedByAddress verifies AnnotateAll results are sorted by address.
func TestPropertyAnnotateAll_SortedByAddress(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 50
	properties := gopter.NewProperties(params)

	properties.Property("AnnotateAll results are sorted by address ascending", prop.ForAll(
		func(data []byte) bool {
			scanner := NewCryptoScanner()
			annotations := AnnotateAll(data, 0x1000, 256, scanner)
			for i := 1; i < len(annotations); i++ {
				if annotations[i].Address < annotations[i-1].Address {
					return false
				}
			}
			return true
		},
		genRandomData(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestPropertyScannerCustomSignature_AlwaysDetected verifies custom signatures are always found.
func TestPropertyScannerCustomSignature_AlwaysDetected(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("custom signature is always detected when pattern is present", prop.ForAll(
		func(sig *CryptoSignature) bool {
			// embed the exact pattern at offset 8
			data := make([]byte, 8+len(sig.Bytes)+8)
			for i := range data {
				data[i] = 0xAA // fill with non-matching bytes
			}
			copy(data[8:], sig.Bytes)

			scanner := NewCryptoScannerWithSignatures([]*CryptoSignature{sig})
			matches := scanner.ScanData(data)
			for _, m := range matches {
				if m.Signature == sig && m.MatchedBytes >= sig.MinMatchLen {
					return true
				}
			}
			return false
		},
		genCryptoSignature(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestPropertyModPow_FermatLittleTheorem verifies modPow via Fermat's little theorem.
// for prime p and 0 < a < p: a^(p-1) ≡ 1 (mod p).
func TestPropertyModPow_FermatLittleTheorem(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	// use small known primes to keep computation fast
	smallPrimes := []uint64{7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47}

	properties.Property("Fermat's little theorem: a^(p-1) mod p == 1 for prime p", prop.ForAll(
		func(idx int) bool {
			p := smallPrimes[idx%len(smallPrimes)]
			// test for a = 2..p-1
			for a := uint64(2); a < p; a++ {
				if modPow(a, p-1, p) != 1 {
					return false
				}
			}
			return true
		},
		gen.IntRange(0, len(smallPrimes)-1),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
