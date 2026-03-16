package signatures

import (
	"encoding/binary"
	"testing"
)

// ============================================================================
// CryptoAlgorithm.String tests
// ============================================================================

func TestCryptoAlgorithmString(t *testing.T) {
	cases := []struct {
		algo CryptoAlgorithm
		want string
	}{
		{CryptoAlgorithmAES, "AES"},
		{CryptoAlgorithmDES, "DES"},
		{CryptoAlgorithmTripleDES, "3DES"},
		{CryptoAlgorithmRSA, "RSA"},
		{CryptoAlgorithmSHA1, "SHA-1"},
		{CryptoAlgorithmSHA256, "SHA-256"},
		{CryptoAlgorithmSHA512, "SHA-512"},
		{CryptoAlgorithmMD5, "MD5"},
		{CryptoAlgorithmRC4, "RC4"},
		{CryptoAlgorithmChaCha20, "ChaCha20"},
		{CryptoAlgorithmBlowfish, "Blowfish"},
		{CryptoAlgorithmCRC32, "CRC32"},
		{CryptoAlgorithmUnknown, "Unknown"},
		{CryptoAlgorithm(999), "Unknown"},
	}
	for _, tc := range cases {
		if got := tc.algo.String(); got != tc.want {
			t.Errorf("CryptoAlgorithm(%d).String() = %q, want %q", tc.algo, got, tc.want)
		}
	}
}

// ============================================================================
// CryptoConstantKind.String tests
// ============================================================================

func TestCryptoConstantKindString(t *testing.T) {
	cases := []struct {
		kind CryptoConstantKind
		want string
	}{
		{CryptoConstantSBox, "S-Box"},
		{CryptoConstantInvSBox, "Inverse S-Box"},
		{CryptoConstantRoundConstant, "Round Constant"},
		{CryptoConstantIV, "Initialization Vector"},
		{CryptoConstantPrimeModulus, "Prime Modulus"},
		{CryptoConstantSigmaConstant, "Sigma Constant"},
		{CryptoConstantMagicNumber, "Magic Number"},
		{CryptoConstantLookupTable, "Lookup Table"},
		{CryptoConstantKind(999), "Unknown"},
	}
	for _, tc := range cases {
		if got := tc.kind.String(); got != tc.want {
			t.Errorf("CryptoConstantKind(%d).String() = %q, want %q", tc.kind, got, tc.want)
		}
	}
}

// ============================================================================
// AES S-Box detection
// ============================================================================

func TestScanData_AESSBox_Detected(t *testing.T) {
	scanner := NewCryptoScanner()

	// embed the full aes s-box in a data buffer with padding
	data := make([]byte, 512)
	copy(data[64:], aesSBox)

	matches := scanner.ScanData(data)
	if len(matches) == 0 {
		t.Fatal("expected at least one match for AES S-Box")
	}

	found := false
	for _, m := range matches {
		if m.Signature.Algorithm == CryptoAlgorithmAES && m.Signature.Kind == CryptoConstantSBox {
			found = true
			if m.Offset != 64 {
				t.Errorf("expected offset 64, got %d", m.Offset)
			}
			if m.Confidence < 0.9 {
				t.Errorf("expected high confidence for full s-box match, got %f", m.Confidence)
			}
		}
	}
	if !found {
		t.Error("AES S-Box not detected in data")
	}
}

func TestScanData_AESInvSBox_Detected(t *testing.T) {
	scanner := NewCryptoScanner()

	data := make([]byte, 512)
	copy(data[128:], aesInvSBox)

	matches := scanner.ScanData(data)
	found := false
	for _, m := range matches {
		if m.Signature.Algorithm == CryptoAlgorithmAES && m.Signature.Kind == CryptoConstantInvSBox {
			found = true
			if m.Offset != 128 {
				t.Errorf("expected offset 128, got %d", m.Offset)
			}
		}
	}
	if !found {
		t.Error("AES Inverse S-Box not detected")
	}
}

func TestScanData_AESRcon_Detected(t *testing.T) {
	scanner := NewCryptoScanner()

	data := make([]byte, 64)
	copy(data[4:], aesRcon)

	matches := scanner.ScanData(data)
	found := false
	for _, m := range matches {
		if m.Signature.Algorithm == CryptoAlgorithmAES && m.Signature.Kind == CryptoConstantRoundConstant {
			found = true
		}
	}
	if !found {
		t.Error("AES Rcon not detected")
	}
}

// ============================================================================
// SHA constants detection
// ============================================================================

func TestScanData_SHA256InitHash_Detected(t *testing.T) {
	scanner := NewCryptoScanner()

	data := make([]byte, 256)
	copy(data[32:], sha256InitHash)

	matches := scanner.ScanData(data)
	found := false
	for _, m := range matches {
		if m.Signature.Algorithm == CryptoAlgorithmSHA256 && m.Signature.Kind == CryptoConstantIV {
			found = true
			if m.Offset != 32 {
				t.Errorf("expected offset 32, got %d", m.Offset)
			}
		}
	}
	if !found {
		t.Error("SHA-256 initial hash values not detected")
	}
}

func TestScanData_SHA1InitHash_Detected(t *testing.T) {
	scanner := NewCryptoScanner()

	data := make([]byte, 128)
	copy(data[0:], sha1InitHash)

	matches := scanner.ScanData(data)
	found := false
	for _, m := range matches {
		if m.Signature.Algorithm == CryptoAlgorithmSHA1 {
			found = true
		}
	}
	if !found {
		t.Error("SHA-1 initial hash values not detected")
	}
}

func TestScanData_SHA512InitHash_Detected(t *testing.T) {
	scanner := NewCryptoScanner()

	data := make([]byte, 256)
	copy(data[0:], sha512InitHash)

	matches := scanner.ScanData(data)
	found := false
	for _, m := range matches {
		if m.Signature.Algorithm == CryptoAlgorithmSHA512 {
			found = true
		}
	}
	if !found {
		t.Error("SHA-512 initial hash values not detected")
	}
}

// ============================================================================
// MD5 constants detection
// ============================================================================

func TestScanData_MD5InitHash_Detected(t *testing.T) {
	scanner := NewCryptoScanner()

	data := make([]byte, 128)
	copy(data[16:], md5InitHash)

	matches := scanner.ScanData(data)
	found := false
	for _, m := range matches {
		if m.Signature.Algorithm == CryptoAlgorithmMD5 && m.Signature.Kind == CryptoConstantIV {
			found = true
		}
	}
	if !found {
		t.Error("MD5 initial hash values not detected")
	}
}

// ============================================================================
// ChaCha20 sigma constant detection
// ============================================================================

func TestScanData_ChaCha20Sigma_Detected(t *testing.T) {
	scanner := NewCryptoScanner()

	data := make([]byte, 64)
	copy(data[8:], chacha20Sigma)

	matches := scanner.ScanData(data)
	found := false
	for _, m := range matches {
		if m.Signature.Algorithm == CryptoAlgorithmChaCha20 {
			found = true
			if m.Confidence < 0.99 {
				t.Errorf("expected near-perfect confidence for exact sigma match, got %f", m.Confidence)
			}
		}
	}
	if !found {
		t.Error("ChaCha20 sigma constant not detected")
	}
}

// ============================================================================
// CRC32 detection
// ============================================================================

func TestScanData_CRC32Poly_Detected(t *testing.T) {
	scanner := NewCryptoScanner()

	data := make([]byte, 32)
	binary.LittleEndian.PutUint32(data[4:], 0xEDB88320)

	matches := scanner.ScanData(data)
	found := false
	for _, m := range matches {
		if m.Signature.Algorithm == CryptoAlgorithmCRC32 && m.Signature.Kind == CryptoConstantMagicNumber {
			found = true
		}
	}
	if !found {
		t.Error("CRC32 polynomial not detected")
	}
}

// ============================================================================
// empty / nil input handling
// ============================================================================

func TestScanData_EmptyData(t *testing.T) {
	scanner := NewCryptoScanner()
	matches := scanner.ScanData(nil)
	if matches != nil {
		t.Error("expected nil for nil input")
	}
	matches = scanner.ScanData([]byte{})
	if matches != nil {
		t.Error("expected nil for empty input")
	}
}

func TestScanData_NoMatch(t *testing.T) {
	scanner := NewCryptoScanner()
	// all-zero data should not match any crypto constant
	data := make([]byte, 512)
	matches := scanner.ScanData(data)
	// zero data may match some patterns; verify confidence is low
	for _, m := range matches {
		if m.Confidence > 0.5 {
			t.Errorf("unexpected high-confidence match in zero data: %s conf=%f", m.Signature.Name, m.Confidence)
		}
	}
}

// ============================================================================
// custom signature
// ============================================================================

func TestAddSignature_CustomPattern(t *testing.T) {
	scanner := NewCryptoScannerWithSignatures(nil)
	custom := &CryptoSignature{
		Algorithm:   CryptoAlgorithmUnknown,
		Kind:        CryptoConstantMagicNumber,
		Name:        "Custom Test Pattern",
		Bytes:       []byte{0xDE, 0xAD, 0xBE, 0xEF},
		MinMatchLen: 4,
	}
	scanner.AddSignature(custom)

	data := []byte{0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00}
	matches := scanner.ScanData(data)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Offset != 2 {
		t.Errorf("expected offset 2, got %d", matches[0].Offset)
	}
	if matches[0].Confidence != 1.0 {
		t.Errorf("expected confidence 1.0, got %f", matches[0].Confidence)
	}
}

// ============================================================================
// prime detection
// ============================================================================

func TestIsProbablePrime_KnownPrimes(t *testing.T) {
	primes := []uint64{2, 3, 5, 7, 11, 13, 17, 19, 23, 65537, 1000003, 15485863}
	for _, p := range primes {
		if !isProbablePrime(p) {
			t.Errorf("isProbablePrime(%d) = false, want true", p)
		}
	}
}

func TestIsProbablePrime_KnownComposites(t *testing.T) {
	composites := []uint64{0, 1, 4, 6, 8, 9, 10, 15, 100, 1000000}
	for _, c := range composites {
		if isProbablePrime(c) {
			t.Errorf("isProbablePrime(%d) = true, want false", c)
		}
	}
}

func TestDetectPrimeModuli_FindsPrimes(t *testing.T) {
	data := make([]byte, 32)
	// embed prime 1000003 at offset 0
	binary.LittleEndian.PutUint32(data[0:], 1000003)
	// embed composite at offset 4
	binary.LittleEndian.PutUint32(data[4:], 1000000)

	results := DetectPrimeModuli(data)
	found := false
	for _, r := range results {
		if r.Value == 1000003 && r.Size == 4 {
			found = true
		}
		if r.Value == 1000000 {
			t.Error("composite 1000000 should not be detected as prime")
		}
	}
	if !found {
		t.Error("prime 1000003 not detected")
	}
}

func TestDetectPrimeModuli_EmptyData(t *testing.T) {
	results := DetectPrimeModuli(nil)
	if len(results) != 0 {
		t.Errorf("expected 0 results for nil data, got %d", len(results))
	}
}

// ============================================================================
// modPow / modMul correctness
// ============================================================================

func TestModPow(t *testing.T) {
	cases := []struct {
		base, exp, mod, want uint64
	}{
		{2, 10, 1000, 24},
		{3, 0, 7, 1},
		{5, 1, 13, 5},
		{2, 64, 1000000007, 582344008},
	}
	for _, tc := range cases {
		got := modPow(tc.base, tc.exp, tc.mod)
		if got != tc.want {
			t.Errorf("modPow(%d,%d,%d) = %d, want %d", tc.base, tc.exp, tc.mod, got, tc.want)
		}
	}
}

// ============================================================================
// AnnotateFunction
// ============================================================================

func TestAnnotateFunction_AES(t *testing.T) {
	scanner := NewCryptoScanner()

	// build a fake section with aes s-box at offset 100
	section := make([]byte, 512)
	copy(section[100:], aesSBox)

	ann := AnnotateFunction(0x1000, section, 100, 300, scanner)
	if ann == nil {
		t.Fatal("expected non-nil annotation for AES S-Box data")
	}
	if len(ann.Algorithms) == 0 {
		t.Error("expected at least one algorithm in annotation")
	}
	found := false
	for _, a := range ann.Algorithms {
		if a == CryptoAlgorithmAES {
			found = true
		}
	}
	if !found {
		t.Error("AES not in annotation algorithms")
	}
	if ann.FunctionName == "" {
		t.Error("expected non-empty function name suggestion")
	}
}

func TestAnnotateFunction_NoMatch(t *testing.T) {
	scanner := NewCryptoScanner()
	section := make([]byte, 64)
	ann := AnnotateFunction(0x1000, section, 0, 64, scanner)
	if ann != nil {
		// zero data may produce low-confidence matches; verify
		for _, m := range ann.Matches {
			if m.Confidence > 0.5 {
				t.Errorf("unexpected high-confidence match in zero section: %s", m.Signature.Name)
			}
		}
	}
}

// ============================================================================
// AnnotateAll
// ============================================================================

func TestAnnotateAll_MultipleAlgorithms(t *testing.T) {
	scanner := NewCryptoScanner()

	section := make([]byte, 1024)
	// place aes s-box at offset 0
	copy(section[0:], aesSBox)
	// place sha-256 init hash at offset 512
	copy(section[512:], sha256InitHash)

	annotations := AnnotateAll(section, 0x4000, 256, scanner)
	if len(annotations) == 0 {
		t.Fatal("expected at least one annotation")
	}

	foundAES := false
	foundSHA := false
	for _, ann := range annotations {
		for _, a := range ann.Algorithms {
			if a == CryptoAlgorithmAES {
				foundAES = true
			}
			if a == CryptoAlgorithmSHA256 {
				foundSHA = true
			}
		}
	}
	if !foundAES {
		t.Error("AES not found in annotations")
	}
	if !foundSHA {
		t.Error("SHA-256 not found in annotations")
	}
}

func TestAnnotateAll_EmptySection(t *testing.T) {
	scanner := NewCryptoScanner()
	annotations := AnnotateAll(nil, 0, 256, scanner)
	if annotations != nil {
		t.Error("expected nil for nil section data")
	}
}

func TestAnnotateAll_SortedByAddress(t *testing.T) {
	scanner := NewCryptoScanner()

	section := make([]byte, 1024)
	copy(section[0:], aesSBox)
	copy(section[512:], sha256InitHash)

	annotations := AnnotateAll(section, 0x1000, 256, scanner)
	for i := 1; i < len(annotations); i++ {
		if annotations[i].Address < annotations[i-1].Address {
			t.Errorf("annotations not sorted by address: [%d]=%#x > [%d]=%#x",
				i-1, annotations[i-1].Address, i, annotations[i].Address)
		}
	}
}

// ============================================================================
// reverseUint32Endian
// ============================================================================

func TestReverseUint32Endian(t *testing.T) {
	input := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	want := []byte{0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05}
	got := reverseUint32Endian(input)
	if !bytesEqual(got, want) {
		t.Errorf("reverseUint32Endian: got %v, want %v", got, want)
	}
}

// ============================================================================
// countPrefixMatch
// ============================================================================

func TestCountPrefixMatch(t *testing.T) {
	cases := []struct {
		data, pattern []byte
		want          int
	}{
		{[]byte{1, 2, 3, 4}, []byte{1, 2, 3, 4}, 4},
		{[]byte{1, 2, 3, 4}, []byte{1, 2, 9, 9}, 2},
		{[]byte{1, 2}, []byte{1, 2, 3, 4}, 2},
		{[]byte{9, 9, 9}, []byte{1, 2, 3}, 0},
		{nil, []byte{1}, 0},
	}
	for _, tc := range cases {
		got := countPrefixMatch(tc.data, tc.pattern)
		if got != tc.want {
			t.Errorf("countPrefixMatch(%v, %v) = %d, want %d", tc.data, tc.pattern, got, tc.want)
		}
	}
}

// ============================================================================
// builtin signature database integrity
// ============================================================================

func TestBuiltinSignatures_NonEmpty(t *testing.T) {
	if len(builtinCryptoSignatures) == 0 {
		t.Fatal("builtin crypto signature database must not be empty")
	}
}

func TestBuiltinSignatures_AllHaveBytes(t *testing.T) {
	for _, sig := range builtinCryptoSignatures {
		if len(sig.Bytes) == 0 {
			t.Errorf("signature %q has empty Bytes", sig.Name)
		}
		if sig.MinMatchLen <= 0 {
			t.Errorf("signature %q has non-positive MinMatchLen", sig.Name)
		}
		if sig.MinMatchLen > len(sig.Bytes) {
			t.Errorf("signature %q: MinMatchLen=%d > len(Bytes)=%d", sig.Name, sig.MinMatchLen, len(sig.Bytes))
		}
		if sig.Name == "" {
			t.Errorf("signature with algorithm %v has empty Name", sig.Algorithm)
		}
	}
}

func TestBuiltinSignatures_CoverAllAlgorithms(t *testing.T) {
	covered := make(map[CryptoAlgorithm]bool)
	for _, sig := range builtinCryptoSignatures {
		covered[sig.Algorithm] = true
	}
	required := []CryptoAlgorithm{
		CryptoAlgorithmAES,
		CryptoAlgorithmDES,
		CryptoAlgorithmSHA1,
		CryptoAlgorithmSHA256,
		CryptoAlgorithmSHA512,
		CryptoAlgorithmMD5,
		CryptoAlgorithmChaCha20,
		CryptoAlgorithmBlowfish,
		CryptoAlgorithmCRC32,
		CryptoAlgorithmRSA,
	}
	for _, algo := range required {
		if !covered[algo] {
			t.Errorf("algorithm %s not covered in builtin signatures", algo)
		}
	}
}
