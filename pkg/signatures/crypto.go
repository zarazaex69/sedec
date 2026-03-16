package signatures

import (
	"encoding/binary"
	"sort"
)

// unknownStr is the fallback string for unrecognised enum values.
const unknownStr = "Unknown"

// CryptoAlgorithm identifies a cryptographic algorithm family.
type CryptoAlgorithm int

// Supported cryptographic algorithm identifiers.
const (
	CryptoAlgorithmUnknown   CryptoAlgorithm = iota // unknown or unidentified algorithm
	CryptoAlgorithmAES                              // advanced encryption standard
	CryptoAlgorithmDES                              // data encryption standard
	CryptoAlgorithmTripleDES                        // 3des / tdea
	CryptoAlgorithmRSA                              // rsa public-key cryptography
	CryptoAlgorithmSHA1                             // sha-1 hash function
	CryptoAlgorithmSHA256                           // sha-256 hash function
	CryptoAlgorithmSHA512                           // sha-512 hash function
	CryptoAlgorithmMD5                              // md5 message digest
	CryptoAlgorithmRC4                              // rc4 stream cipher
	CryptoAlgorithmChaCha20                         // chacha20 stream cipher
	CryptoAlgorithmBlowfish                         // blowfish block cipher
	CryptoAlgorithmCRC32                            // crc32 checksum (often confused with crypto)
)

// String returns the human-readable name of the algorithm.
func (a CryptoAlgorithm) String() string {
	switch a {
	case CryptoAlgorithmAES:
		return "AES"
	case CryptoAlgorithmDES:
		return "DES"
	case CryptoAlgorithmTripleDES:
		return "3DES"
	case CryptoAlgorithmRSA:
		return "RSA"
	case CryptoAlgorithmSHA1:
		return "SHA-1"
	case CryptoAlgorithmSHA256:
		return "SHA-256"
	case CryptoAlgorithmSHA512:
		return "SHA-512"
	case CryptoAlgorithmMD5:
		return "MD5"
	case CryptoAlgorithmRC4:
		return "RC4"
	case CryptoAlgorithmChaCha20:
		return "ChaCha20"
	case CryptoAlgorithmBlowfish:
		return "Blowfish"
	case CryptoAlgorithmCRC32:
		return "CRC32"
	default:
		return unknownStr
	}
}

// CryptoConstantKind classifies the type of cryptographic constant.
type CryptoConstantKind int

// Supported cryptographic constant kind identifiers.
const (
	CryptoConstantSBox          CryptoConstantKind = iota // substitution box
	CryptoConstantInvSBox                                 // inverse substitution box
	CryptoConstantRoundConstant                           // round constants (rcon)
	CryptoConstantIV                                      // initialization vector
	CryptoConstantPrimeModulus                            // prime modulus for rsa/dh
	CryptoConstantSigmaConstant                           // sigma constants (sha, chacha20)
	CryptoConstantMagicNumber                             // algorithm-specific magic values
	CryptoConstantLookupTable                             // general lookup table
)

// String returns the human-readable kind name.
func (k CryptoConstantKind) String() string {
	switch k {
	case CryptoConstantSBox:
		return "S-Box"
	case CryptoConstantInvSBox:
		return "Inverse S-Box"
	case CryptoConstantRoundConstant:
		return "Round Constant"
	case CryptoConstantIV:
		return "Initialization Vector"
	case CryptoConstantPrimeModulus:
		return "Prime Modulus"
	case CryptoConstantSigmaConstant:
		return "Sigma Constant"
	case CryptoConstantMagicNumber:
		return "Magic Number"
	case CryptoConstantLookupTable:
		return "Lookup Table"
	default:
		return unknownStr
	}
}

// CryptoSignature describes a known cryptographic constant pattern.
type CryptoSignature struct {
	// Algorithm is the cryptographic algorithm this constant belongs to.
	Algorithm CryptoAlgorithm
	// Kind classifies the type of constant.
	Kind CryptoConstantKind
	// Name is a human-readable description (e.g. "AES S-Box").
	Name string
	// Bytes is the raw byte sequence to search for.
	Bytes []byte
	// MinMatchLen is the minimum number of bytes that must match (for partial matches).
	MinMatchLen int
}

// CryptoMatch represents a detected cryptographic constant in binary data.
type CryptoMatch struct {
	// Signature is the matched crypto signature entry.
	Signature *CryptoSignature
	// Offset is the byte offset within the scanned data where the match was found.
	Offset uint64
	// MatchedBytes is the number of bytes that matched.
	MatchedBytes int
	// Confidence is a score in [0.0, 1.0].
	Confidence float64
}

// CryptoAnnotation annotates a function or address with identified crypto algorithms.
type CryptoAnnotation struct {
	// Address is the function or data address.
	Address uint64
	// Algorithms is the deduplicated list of identified algorithms.
	Algorithms []CryptoAlgorithm
	// Matches contains all individual constant matches found.
	Matches []CryptoMatch
	// FunctionName is the suggested name for the function (e.g. "aes_encrypt").
	FunctionName string
}

// ============================================================================
// aes constants
// ============================================================================

// aes forward s-box (fips 197, figure 7)
var aesSBox = []byte{ //nolint:dupl // aes s-box and inverse s-box are structurally similar byte tables by design
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

// aes inverse s-box (fips 197, figure 14)
var aesInvSBox = []byte{ //nolint:dupl // aes s-box and inverse s-box are structurally similar byte tables by design
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
}

// aes round constants (rcon) for key schedule (fips 197, section 5.2)
var aesRcon = []byte{
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
}

// ============================================================================
// des constants
// ============================================================================

// des initial permutation table (ip) - 64 entries
var desIPTable = []byte{
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
}

// des s-box 1 (first 16 entries are sufficient for identification)
var desSBox1 = []byte{
	14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
	0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
	4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
	15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
}

// ============================================================================
// sha constants
// ============================================================================

// sha-1 initial hash values (fips 180-4, section 5.3.1) as little-endian bytes
var sha1InitHash = func() []byte {
	vals := []uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}
	b := make([]byte, len(vals)*4)
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[i*4:], v)
	}
	return b
}()

// sha-256 initial hash values (fips 180-4, section 5.3.3) as little-endian bytes
var sha256InitHash = func() []byte {
	vals := []uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
	b := make([]byte, len(vals)*4)
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[i*4:], v)
	}
	return b
}()

// sha-256 round constants k[0..7] (first 8 of 64) as little-endian bytes
var sha256RoundConst = func() []byte {
	vals := []uint32{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	}
	b := make([]byte, len(vals)*4)
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[i*4:], v)
	}
	return b
}()

// sha-512 initial hash values (fips 180-4, section 5.3.5) as little-endian bytes
var sha512InitHash = func() []byte {
	vals := []uint64{
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
		0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f,
		0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
	}
	b := make([]byte, len(vals)*8)
	for i, v := range vals {
		binary.LittleEndian.PutUint64(b[i*8:], v)
	}
	return b
}()

// ============================================================================
// md5 constants
// ============================================================================

// md5 initial hash values (rfc 1321, section 3.3) as little-endian bytes
var md5InitHash = func() []byte {
	vals := []uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}
	b := make([]byte, len(vals)*4)
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[i*4:], v)
	}
	return b
}()

// md5 t-table constants t[0..7] (rfc 1321, section 3.4) as little-endian bytes
var md5TTable = func() []byte {
	vals := []uint32{
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	}
	b := make([]byte, len(vals)*4)
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[i*4:], v)
	}
	return b
}()

// ============================================================================
// chacha20 constants
// ============================================================================

// chacha20 sigma constant "expand 32-byte k" (rfc 8439, section 2.1)
var chacha20Sigma = []byte("expand 32-byte k")

// chacha20 tau constant "expand 16-byte k"
var chacha20Tau = []byte("expand 16-byte k")

// ============================================================================
// blowfish constants
// ============================================================================

// blowfish p-array initial values (first 8 of 18) as little-endian bytes
var blowfishPArray = func() []byte {
	vals := []uint32{
		0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
		0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
	}
	b := make([]byte, len(vals)*4)
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[i*4:], v)
	}
	return b
}()

// ============================================================================
// crc32 constants
// ============================================================================

// crc32 polynomial 0xEDB88320 (reflected form of 0x04C11DB7) as little-endian
var crc32Poly = func() []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, 0xEDB88320)
	return b
}()

// first 8 entries of the standard crc32 lookup table as little-endian bytes
var crc32Table = func() []byte {
	vals := []uint32{
		0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
		0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	}
	b := make([]byte, len(vals)*4)
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[i*4:], v)
	}
	return b
}()

// ============================================================================
// rsa / prime detection constants
// ============================================================================

// rsaPublicExponents contains the two most common RSA public exponents.
// these are 4-byte little-endian representations.
var rsaPublicExponents = [][]byte{
	{0x01, 0x00, 0x01, 0x00}, // 65537 = 0x10001
	{0x11, 0x00, 0x00, 0x00}, // 17 = 0x11
}

// ============================================================================
// crypto signature database
// ============================================================================

// builtinCryptoSignatures is the built-in database of cryptographic constants.
// each entry specifies the algorithm, kind, name, byte pattern, and minimum match length.
var builtinCryptoSignatures = []*CryptoSignature{
	// aes forward s-box (full 256 bytes)
	{
		Algorithm:   CryptoAlgorithmAES,
		Kind:        CryptoConstantSBox,
		Name:        "AES S-Box",
		Bytes:       aesSBox,
		MinMatchLen: 16,
	},
	// aes inverse s-box (full 256 bytes)
	{
		Algorithm:   CryptoAlgorithmAES,
		Kind:        CryptoConstantInvSBox,
		Name:        "AES Inverse S-Box",
		Bytes:       aesInvSBox,
		MinMatchLen: 16,
	},
	// aes round constants
	{
		Algorithm:   CryptoAlgorithmAES,
		Kind:        CryptoConstantRoundConstant,
		Name:        "AES Round Constants (Rcon)",
		Bytes:       aesRcon,
		MinMatchLen: 8,
	},
	// des initial permutation table
	{
		Algorithm:   CryptoAlgorithmDES,
		Kind:        CryptoConstantLookupTable,
		Name:        "DES Initial Permutation Table",
		Bytes:       desIPTable,
		MinMatchLen: 32,
	},
	// des s-box 1
	{
		Algorithm:   CryptoAlgorithmDES,
		Kind:        CryptoConstantSBox,
		Name:        "DES S-Box 1",
		Bytes:       desSBox1,
		MinMatchLen: 32,
	},
	// sha-1 initial hash values
	{
		Algorithm:   CryptoAlgorithmSHA1,
		Kind:        CryptoConstantIV,
		Name:        "SHA-1 Initial Hash Values",
		Bytes:       sha1InitHash,
		MinMatchLen: 16,
	},
	// sha-256 initial hash values
	{
		Algorithm:   CryptoAlgorithmSHA256,
		Kind:        CryptoConstantIV,
		Name:        "SHA-256 Initial Hash Values",
		Bytes:       sha256InitHash,
		MinMatchLen: 16,
	},
	// sha-256 round constants
	{
		Algorithm:   CryptoAlgorithmSHA256,
		Kind:        CryptoConstantRoundConstant,
		Name:        "SHA-256 Round Constants",
		Bytes:       sha256RoundConst,
		MinMatchLen: 16,
	},
	// sha-512 initial hash values
	{
		Algorithm:   CryptoAlgorithmSHA512,
		Kind:        CryptoConstantIV,
		Name:        "SHA-512 Initial Hash Values",
		Bytes:       sha512InitHash,
		MinMatchLen: 32,
	},
	// md5 initial hash values
	{
		Algorithm:   CryptoAlgorithmMD5,
		Kind:        CryptoConstantIV,
		Name:        "MD5 Initial Hash Values",
		Bytes:       md5InitHash,
		MinMatchLen: 12,
	},
	// md5 t-table constants
	{
		Algorithm:   CryptoAlgorithmMD5,
		Kind:        CryptoConstantRoundConstant,
		Name:        "MD5 T-Table Constants",
		Bytes:       md5TTable,
		MinMatchLen: 16,
	},
	// chacha20 sigma constant
	{
		Algorithm:   CryptoAlgorithmChaCha20,
		Kind:        CryptoConstantSigmaConstant,
		Name:        "ChaCha20 Sigma Constant",
		Bytes:       chacha20Sigma,
		MinMatchLen: 16,
	},
	// chacha20 tau constant
	{
		Algorithm:   CryptoAlgorithmChaCha20,
		Kind:        CryptoConstantSigmaConstant,
		Name:        "ChaCha20 Tau Constant",
		Bytes:       chacha20Tau,
		MinMatchLen: 16,
	},
	// blowfish p-array
	{
		Algorithm:   CryptoAlgorithmBlowfish,
		Kind:        CryptoConstantRoundConstant,
		Name:        "Blowfish P-Array",
		Bytes:       blowfishPArray,
		MinMatchLen: 16,
	},
	// crc32 polynomial
	{
		Algorithm:   CryptoAlgorithmCRC32,
		Kind:        CryptoConstantMagicNumber,
		Name:        "CRC32 Polynomial (0xEDB88320)",
		Bytes:       crc32Poly,
		MinMatchLen: 4,
	},
	// crc32 lookup table
	{
		Algorithm:   CryptoAlgorithmCRC32,
		Kind:        CryptoConstantLookupTable,
		Name:        "CRC32 Lookup Table",
		Bytes:       crc32Table,
		MinMatchLen: 16,
	},
	// rsa public exponent 65537
	{
		Algorithm:   CryptoAlgorithmRSA,
		Kind:        CryptoConstantPrimeModulus,
		Name:        "RSA Public Exponent 65537",
		Bytes:       rsaPublicExponents[0],
		MinMatchLen: 4,
	},
}

// ============================================================================
// crypto scanner
// ============================================================================

// CryptoScanner scans binary data for cryptographic constants.
type CryptoScanner struct {
	// signatures is the database of known crypto constants.
	signatures []*CryptoSignature
	// bigEndian controls whether to also search for big-endian variants of multi-byte constants.
	bigEndian bool
}

// NewCryptoScanner creates a scanner with the built-in signature database.
func NewCryptoScanner() *CryptoScanner {
	return &CryptoScanner{
		signatures: builtinCryptoSignatures,
		bigEndian:  true,
	}
}

// NewCryptoScannerWithSignatures creates a scanner with a custom signature set.
func NewCryptoScannerWithSignatures(sigs []*CryptoSignature) *CryptoScanner {
	return &CryptoScanner{
		signatures: sigs,
		bigEndian:  true,
	}
}

// AddSignature appends a custom signature to the scanner's database.
func (s *CryptoScanner) AddSignature(sig *CryptoSignature) {
	s.signatures = append(s.signatures, sig)
}

// ScanData searches raw binary data for all known cryptographic constants.
// it returns all matches found, sorted by offset ascending.
func (s *CryptoScanner) ScanData(data []byte) []CryptoMatch {
	if len(data) == 0 {
		return nil
	}

	var matches []CryptoMatch

	for _, sig := range s.signatures {
		if len(sig.Bytes) == 0 {
			continue
		}
		found := s.searchPattern(data, sig)
		matches = append(matches, found...)

		// also search big-endian variant for multi-byte integer constants
		if s.bigEndian && len(sig.Bytes) >= 4 && len(sig.Bytes)%4 == 0 {
			beVariant := reverseUint32Endian(sig.Bytes)
			if !bytesEqual(beVariant, sig.Bytes) {
				beFound := s.searchPatternVariant(data, sig, beVariant)
				matches = append(matches, beFound...)
			}
		}
	}

	// sort by offset ascending, then by confidence descending
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Offset != matches[j].Offset {
			return matches[i].Offset < matches[j].Offset
		}
		return matches[i].Confidence > matches[j].Confidence
	})

	return matches
}

// searchPattern finds all occurrences of sig.Bytes in data using a sliding window.
func (s *CryptoScanner) searchPattern(data []byte, sig *CryptoSignature) []CryptoMatch {
	return s.searchPatternVariant(data, sig, sig.Bytes)
}

// searchPatternVariant finds all occurrences of pattern in data.
func (s *CryptoScanner) searchPatternVariant(data []byte, sig *CryptoSignature, pattern []byte) []CryptoMatch {
	patLen := len(pattern)
	minMatch := sig.MinMatchLen
	if minMatch <= 0 {
		minMatch = patLen
	}
	if minMatch > patLen {
		minMatch = patLen
	}

	var matches []CryptoMatch
	dataLen := len(data)

	for i := 0; i <= dataLen-minMatch; i++ {
		matchLen := countPrefixMatch(data[i:], pattern)
		if matchLen >= minMatch {
			confidence := float64(matchLen) / float64(patLen)
			if confidence > 1.0 {
				confidence = 1.0
			}
			matches = append(matches, CryptoMatch{
				Signature:    sig,
				Offset:       uint64(i),
				MatchedBytes: matchLen,
				Confidence:   confidence,
			})
			// skip past the matched region to avoid overlapping matches
			i += matchLen - 1
		}
	}

	return matches
}

// countPrefixMatch returns the number of bytes that match at the start of data vs pattern.
func countPrefixMatch(data, pattern []byte) int {
	n := len(pattern)
	if len(data) < n {
		n = len(data)
	}
	for i := 0; i < n; i++ {
		if data[i] != pattern[i] {
			return i
		}
	}
	return n
}

// reverseUint32Endian returns a copy of b with each 4-byte word byte-swapped.
// b must have length divisible by 4.
func reverseUint32Endian(b []byte) []byte {
	result := make([]byte, len(b))
	for i := 0; i+3 < len(b); i += 4 {
		result[i+0] = b[i+3]
		result[i+1] = b[i+2]
		result[i+2] = b[i+1]
		result[i+3] = b[i+0]
	}
	return result
}

// bytesEqual returns true if a and b have identical contents.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ============================================================================
// prime number detection
// ============================================================================

// isProbablePrime performs a deterministic Miller-Rabin primality test for
// values up to 3,215,031,751 using the witnesses {2, 3, 5, 7}.
// for larger values it uses a probabilistic test with the same witnesses.
func isProbablePrime(n uint64) bool {
	if n < 2 {
		return false
	}
	// small primes fast path
	smallPrimes := []uint64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}
	for _, p := range smallPrimes {
		if n == p {
			return true
		}
		if n%p == 0 {
			return false
		}
	}

	// write n-1 as 2^r * d
	d := n - 1
	r := uint64(0)
	for d%2 == 0 {
		d /= 2
		r++
	}

	// miller-rabin witnesses sufficient for n < 3,215,031,751
	witnesses := []uint64{2, 3, 5, 7}
	for _, a := range witnesses {
		if a >= n {
			continue
		}
		x := modPow(a, d, n)
		if x == 1 || x == n-1 {
			continue
		}
		composite := true
		for i := uint64(0); i < r-1; i++ {
			x = modMul(x, x, n)
			if x == n-1 {
				composite = false
				break
			}
		}
		if composite {
			return false
		}
	}
	return true
}

// modPow computes base^exp mod m using fast exponentiation.
func modPow(base, exp, m uint64) uint64 {
	if m == 1 {
		return 0
	}
	result := uint64(1)
	base %= m
	for exp > 0 {
		if exp%2 == 1 {
			result = modMul(result, base, m)
		}
		exp /= 2
		base = modMul(base, base, m)
	}
	return result
}

// modMul computes (a * b) mod m without overflow using 128-bit arithmetic via
// the russian peasant multiplication algorithm.
func modMul(a, b, m uint64) uint64 {
	result := uint64(0)
	a %= m
	for b > 0 {
		if b%2 == 1 {
			result = (result + a) % m
		}
		a = (a * 2) % m
		b /= 2
	}
	return result
}

// DetectPrimeModuli scans data for large prime numbers that may be RSA/DH moduli.
// it extracts 4-byte and 8-byte little-endian integers and tests primality.
// returns the offsets and values of detected primes.
func DetectPrimeModuli(data []byte) []PrimeMatch {
	var results []PrimeMatch

	// scan 4-byte primes (common in 32-bit rsa, dh parameters)
	for i := 0; i+4 <= len(data); i += 4 {
		v := binary.LittleEndian.Uint32(data[i:])
		// filter: must be > 2^16 to be interesting as a crypto prime
		if v > 65536 && isProbablePrime(uint64(v)) {
			results = append(results, PrimeMatch{
				Offset: uint64(i),
				Value:  uint64(v),
				Size:   4,
			})
		}
	}

	// scan 8-byte primes (common in 64-bit rsa, ecdh)
	for i := 0; i+8 <= len(data); i += 8 {
		v := binary.LittleEndian.Uint64(data[i:])
		// filter: must be > 2^32 to be interesting as a 64-bit crypto prime
		if v > (1<<32) && isProbablePrime(v) {
			results = append(results, PrimeMatch{
				Offset: uint64(i),
				Value:  v,
				Size:   8,
			})
		}
	}

	return results
}

// PrimeMatch represents a detected prime number in binary data.
type PrimeMatch struct {
	// Offset is the byte offset within the scanned data.
	Offset uint64
	// Value is the prime number value.
	Value uint64
	// Size is the byte size of the integer (4 or 8).
	Size int
}

// ============================================================================
// modular arithmetic pattern detection
// ============================================================================

// ModularArithmeticPattern describes a detected modular arithmetic pattern.
type ModularArithmeticPattern struct {
	// Offset is the byte offset of the modulus constant.
	Offset uint64
	// Modulus is the detected modulus value.
	Modulus uint64
	// IsPrime indicates whether the modulus is prime.
	IsPrime bool
	// Algorithm is the likely algorithm (RSA, DH, EC).
	Algorithm CryptoAlgorithm
}

// wellKnownModuli maps known cryptographic moduli to their algorithms.
// these are partial values (first 8 bytes) of well-known prime moduli.
var wellKnownModuli = map[uint64]CryptoAlgorithm{
	// diffie-hellman group 1 (rfc 2409) modulus first 8 bytes le
	0xFFFFFFFFFFFFFFFF: CryptoAlgorithmRSA,
	// nist p-256 prime first 8 bytes le: 0xFFFFFFFFFFFFFFFF
	// rsa common test modulus patterns
	0xFFFFFFFFFFFFFFC5: CryptoAlgorithmRSA,
}

// DetectModularArithmetic scans data for known modular arithmetic patterns.
func DetectModularArithmetic(data []byte) []ModularArithmeticPattern {
	var results []ModularArithmeticPattern

	for i := 0; i+8 <= len(data); i += 4 {
		v := binary.LittleEndian.Uint64(data[i:])
		if algo, ok := wellKnownModuli[v]; ok {
			results = append(results, ModularArithmeticPattern{
				Offset:    uint64(i),
				Modulus:   v,
				IsPrime:   isProbablePrime(v),
				Algorithm: algo,
			})
		}
	}

	return results
}

// ============================================================================
// function annotation
// ============================================================================

// suggestedFunctionNames maps algorithm to a canonical function name prefix.
var suggestedFunctionNames = map[CryptoAlgorithm]string{
	CryptoAlgorithmAES:       "aes",
	CryptoAlgorithmDES:       "des",
	CryptoAlgorithmTripleDES: "des3",
	CryptoAlgorithmRSA:       "rsa",
	CryptoAlgorithmSHA1:      "sha1",
	CryptoAlgorithmSHA256:    "sha256",
	CryptoAlgorithmSHA512:    "sha512",
	CryptoAlgorithmMD5:       "md5",
	CryptoAlgorithmRC4:       "rc4",
	CryptoAlgorithmChaCha20:  "chacha20",
	CryptoAlgorithmBlowfish:  "blowfish",
	CryptoAlgorithmCRC32:     "crc32",
}

// AnnotateFunction produces a CryptoAnnotation for a function given the
// raw bytes of its containing section and the function's offset within it.
// scanRadius controls how many bytes around the function are scanned.
func AnnotateFunction(addr uint64, sectionData []byte, funcOffset int, scanRadius int, scanner *CryptoScanner) *CryptoAnnotation {
	if scanner == nil {
		scanner = NewCryptoScanner()
	}

	// determine scan window
	start := funcOffset - scanRadius
	if start < 0 {
		start = 0
	}
	end := funcOffset + scanRadius
	if end > len(sectionData) {
		end = len(sectionData)
	}

	window := sectionData[start:end]
	matches := scanner.ScanData(window)

	if len(matches) == 0 {
		return nil
	}

	// adjust offsets back to absolute addresses
	baseOffset := uint64(start)
	for i := range matches {
		matches[i].Offset += baseOffset
	}

	// deduplicate algorithms
	algoSet := make(map[CryptoAlgorithm]struct{})
	for _, m := range matches {
		algoSet[m.Signature.Algorithm] = struct{}{}
	}

	algos := make([]CryptoAlgorithm, 0, len(algoSet))
	for a := range algoSet {
		algos = append(algos, a)
	}
	sort.Slice(algos, func(i, j int) bool {
		return algos[i] < algos[j]
	})

	// pick the highest-confidence algorithm for naming
	bestAlgo := CryptoAlgorithmUnknown
	bestConf := 0.0
	for _, m := range matches {
		if m.Confidence > bestConf {
			bestConf = m.Confidence
			bestAlgo = m.Signature.Algorithm
		}
	}

	funcName := ""
	if prefix, ok := suggestedFunctionNames[bestAlgo]; ok {
		funcName = prefix + "_func"
	}

	return &CryptoAnnotation{
		Address:      addr,
		Algorithms:   algos,
		Matches:      matches,
		FunctionName: funcName,
	}
}

// AnnotateAll scans an entire binary section and returns annotations for
// all regions where cryptographic constants are detected.
// regionSize controls the granularity of annotation regions.
func AnnotateAll(sectionData []byte, baseAddr uint64, regionSize int, scanner *CryptoScanner) []*CryptoAnnotation {
	if scanner == nil {
		scanner = NewCryptoScanner()
	}
	if regionSize <= 0 {
		regionSize = 256
	}

	matches := scanner.ScanData(sectionData)
	if len(matches) == 0 {
		return nil
	}

	// group matches by region
	regionMap := make(map[uint64][]CryptoMatch)
	for _, m := range matches {
		regionKey := (m.Offset / uint64(regionSize)) * uint64(regionSize)
		regionMap[regionKey] = append(regionMap[regionKey], m)
	}

	annotations := make([]*CryptoAnnotation, 0, len(regionMap))
	for regionOffset, regionMatches := range regionMap {
		algoSet := make(map[CryptoAlgorithm]struct{})
		for _, m := range regionMatches {
			algoSet[m.Signature.Algorithm] = struct{}{}
		}

		algos := make([]CryptoAlgorithm, 0, len(algoSet))
		for a := range algoSet {
			algos = append(algos, a)
		}
		sort.Slice(algos, func(i, j int) bool {
			return algos[i] < algos[j]
		})

		bestAlgo := CryptoAlgorithmUnknown
		bestConf := 0.0
		for _, m := range regionMatches {
			if m.Confidence > bestConf {
				bestConf = m.Confidence
				bestAlgo = m.Signature.Algorithm
			}
		}

		funcName := ""
		if prefix, ok := suggestedFunctionNames[bestAlgo]; ok {
			funcName = prefix + "_func"
		}

		annotations = append(annotations, &CryptoAnnotation{
			Address:      baseAddr + regionOffset,
			Algorithms:   algos,
			Matches:      regionMatches,
			FunctionName: funcName,
		})
	}

	// sort by address ascending
	sort.Slice(annotations, func(i, j int) bool {
		return annotations[i].Address < annotations[j].Address
	})

	return annotations
}
