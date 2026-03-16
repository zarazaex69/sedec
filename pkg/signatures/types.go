package signatures

import (
	"fmt"

	binfmt "github.com/zarazaex69/sedec/pkg/binary"
	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/disasm"
)

// SignatureFormat identifies the on-disk format of a signature database.
type SignatureFormat int

const (
	// SignatureFormatUnknown is an unrecognised format.
	SignatureFormatUnknown SignatureFormat = iota
	// SignatureFormatFLIRT represents IDA FLIRT .sig / .pat files.
	SignatureFormatFLIRT
	// SignatureFormatFID represents Ghidra FID .fidb files.
	SignatureFormatFID
	// SignatureFormatNative is the sedec-native JSON/binary format.
	SignatureFormatNative
)

func (f SignatureFormat) String() string {
	switch f {
	case SignatureFormatFLIRT:
		return "FLIRT"
	case SignatureFormatFID:
		return "FID"
	case SignatureFormatNative:
		return "Native"
	default:
		return "Unknown"
	}
}

// WildcardByte represents a single byte in a masked fingerprint pattern.
// IsWild == true means the byte is masked out (relocatable / address-dependent).
type WildcardByte struct {
	Value  byte
	IsWild bool
}

// FunctionFingerprint is the byte-level signature of a function with
// relocatable bytes replaced by wildcards.
type FunctionFingerprint struct {
	// Pattern holds the masked byte sequence.
	Pattern []WildcardByte
	// Address is the start address of the function in the source binary.
	Address disasm.Address
	// ByteLength is the total number of bytes (including wildcards).
	ByteLength int
}

// String returns a human-readable hex pattern (wildcards shown as "??").
func (fp *FunctionFingerprint) String() string {
	buf := make([]byte, 0, len(fp.Pattern)*3)
	for i, b := range fp.Pattern {
		if i > 0 {
			buf = append(buf, ' ')
		}
		if b.IsWild {
			buf = append(buf, '?', '?')
		} else {
			buf = append(buf, hexNibble(b.Value>>4), hexNibble(b.Value&0xf))
		}
	}
	return string(buf)
}

func hexNibble(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + n - 10
}

// DegreeEntry captures the in/out degree of a single basic block.
type DegreeEntry struct {
	InDegree  int
	OutDegree int
}

// CFGHash is a structural hash of a control-flow graph that is
// independent of absolute addresses.
type CFGHash struct {
	// DegreeSequence is the sorted list of (in, out) degree pairs.
	DegreeSequence []DegreeEntry
	// BlockCount is the number of basic blocks.
	BlockCount int
	// EdgeCount is the number of CFG edges.
	EdgeCount int
	// LoopCount is the number of natural loops.
	LoopCount int
	// DominatorTreeDepth is the maximum depth of the dominator tree.
	DominatorTreeDepth int
	// Hash64 is a 64-bit summary hash derived from the above fields.
	Hash64 uint64
}

// Signature represents a single library function signature entry.
type Signature struct {
	// Fingerprint is the byte-level masked pattern.
	Fingerprint *FunctionFingerprint
	// CFGHash is the structural CFG hash.
	CFGHash *CFGHash
	// Name is the canonical function name (e.g. "memcpy").
	Name string
	// Library is the originating library name (e.g. "libc-2.35").
	Library string
	// Version is the library version string.
	Version string
	// Format is the source format this signature was loaded from.
	Format SignatureFormat
}

// MatchResult represents a single candidate match returned by MatchSignatures.
type MatchResult struct {
	// Signature is the matched library signature.
	Signature *Signature
	// Confidence is a score in [0.0, 1.0] combining byte and CFG similarity.
	Confidence float64
	// ByteSimilarity is the Jaccard similarity of the byte patterns.
	ByteSimilarity float64
	// CFGSimilarity is the structural similarity of the CFG hashes.
	CFGSimilarity float64
	// NameHint is a symbol name from the ground-truth DB if available.
	NameHint string
}

// String returns a human-readable description of the match.
func (mr *MatchResult) String() string {
	return fmt.Sprintf("%s@%s (conf=%.3f byte=%.3f cfg=%.3f)",
		mr.Signature.Name, mr.Signature.Library,
		mr.Confidence, mr.ByteSimilarity, mr.CFGSimilarity)
}

// MatchInput bundles all data needed to match a single function.
type MatchInput struct {
	// Instructions is the flat list of disassembled instructions for the function.
	Instructions []*disasm.Instruction
	// FunctionCFG is the control-flow graph of the function (may be nil).
	FunctionCFG *cfg.CFG
	// Address is the start address of the function.
	Address disasm.Address
	// GroundTruth is the binary's ground-truth database for symbol hints.
	GroundTruth *binfmt.GroundTruthDatabase
}

// SignatureDB is the in-memory signature database.
type SignatureDB struct {
	// Signatures holds all loaded signatures.
	Signatures []*Signature
	// byName is a secondary index: name → list of signatures.
	byName map[string][]*Signature
	// Format is the format of the last loaded file.
	Format SignatureFormat
}

// NewSignatureDB creates an empty signature database.
func NewSignatureDB() *SignatureDB {
	return &SignatureDB{
		Signatures: make([]*Signature, 0),
		byName:     make(map[string][]*Signature),
	}
}

// Add inserts a signature into the database and updates the name index.
func (db *SignatureDB) Add(sig *Signature) {
	db.Signatures = append(db.Signatures, sig)
	db.byName[sig.Name] = append(db.byName[sig.Name], sig)
}

// LookupByName returns all signatures with the given function name.
func (db *SignatureDB) LookupByName(name string) []*Signature {
	return db.byName[name]
}

// Size returns the number of signatures in the database.
func (db *SignatureDB) Size() int {
	return len(db.Signatures)
}

// matchWeights controls how byte and CFG similarity are combined.
type matchWeights struct {
	byteWeight float64
	cfgWeight  float64
	nameWeight float64
}

// defaultWeights are the production-tuned combination weights.
var defaultWeights = matchWeights{
	byteWeight: 0.55,
	cfgWeight:  0.35,
	nameWeight: 0.10,
}
