package signatures

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	// errUnknownFormat is returned when the file extension is not recognised.
	errUnknownFormat = errors.New("unknown signature file format")
	// errEmptyDatabase is returned when the database has no signatures.
	errEmptyDatabase = errors.New("signature database is empty")
	// errInvalidPatLine is returned when a .pat line cannot be parsed.
	errInvalidPatLine = errors.New("invalid .pat line")
	// errOddLengthPattern is returned when a hex pattern has an odd number of characters.
	errOddLengthPattern = errors.New("odd-length pattern")
	// errInvalidHexByte is returned when a hex byte string is not exactly 2 characters.
	errInvalidHexByte = errors.New("invalid hex byte")
	// errInvalidHexChar is returned when a character is not a valid hex digit.
	errInvalidHexChar = errors.New("invalid hex char")
)

const (
	// sigFormatFLIRT is the string representation of the FLIRT format.
	sigFormatFLIRT = "FLIRT"
	// sigFormatFID is the string representation of the FID format.
	sigFormatFID = "FID"
	// sigFormatNative is the string representation of the native format.
	sigFormatNative = "Native"
)

// LoadFromFile loads signatures from a file, auto-detecting the format from
// the file extension:
//   - .sig  → FLIRT binary (parsed as FLIRT PAT text for simplicity)
//   - .pat  → FLIRT PAT text
//   - .fidb → FID binary (parsed as FID JSON for simplicity)
//   - .json → sedec native JSON
func LoadFromFile(path string) (*SignatureDB, error) {
	ext := strings.ToLower(filepath.Ext(path))

	f, err := os.Open(path) //#nosec G304 - path is caller-controlled
	if err != nil {
		return nil, fmt.Errorf("open signature file %q: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // close on read-only file; error is irrelevant

	switch ext {
	case ".pat", ".sig":
		return loadFLIRT(f, path)
	case ".fidb":
		return loadFID(f, path)
	case ".json":
		return loadNativeJSON(f)
	default:
		return nil, fmt.Errorf("%w: %q", errUnknownFormat, ext)
	}
}

// SaveToFile serialises the database to a file in the native JSON format.
func SaveToFile(db *SignatureDB, path string) error {
	if db.Size() == 0 {
		return errEmptyDatabase
	}

	f, err := os.Create(path) //#nosec G304 - path is caller-controlled
	if err != nil {
		return fmt.Errorf("create signature file %q: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // close on write; encoder already flushed

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")

	records := make([]nativeRecord, 0, db.Size())
	for _, sig := range db.Signatures {
		records = append(records, sigToRecord(sig))
	}

	if err := enc.Encode(records); err != nil {
		return fmt.Errorf("encode signatures: %w", err)
	}
	return nil
}

// ============================================================================
// native JSON format
// ============================================================================

// nativeRecord is the JSON-serialisable representation of a Signature.
type nativeRecord struct {
	Pattern []wildcardByteRecord `json:"pattern"`
	CFGHash *cfgHashRecord       `json:"cfg_hash,omitempty"`
	Name    string               `json:"name"`
	Library string               `json:"library"`
	Version string               `json:"version"`
	Format  string               `json:"format"`
	Address uint64               `json:"address"`
	ByteLen int                  `json:"byte_len"`
}

type wildcardByteRecord struct {
	Value  byte `json:"v"`
	IsWild bool `json:"w,omitempty"`
}

type cfgHashRecord struct {
	DegreeSequence []degreeRecord `json:"degree_seq"`
	Hash64         uint64         `json:"hash64"`
	BlockCount     int            `json:"blocks"`
	EdgeCount      int            `json:"edges"`
	LoopCount      int            `json:"loops"`
	DomDepth       int            `json:"dom_depth"`
}

type degreeRecord struct {
	In  int `json:"in"`
	Out int `json:"out"`
}

func sigToRecord(sig *Signature) nativeRecord {
	r := nativeRecord{
		Name:    sig.Name,
		Library: sig.Library,
		Version: sig.Version,
		Format:  sig.Format.String(),
	}

	if sig.Fingerprint != nil {
		r.Address = uint64(sig.Fingerprint.Address)
		r.ByteLen = sig.Fingerprint.ByteLength
		r.Pattern = make([]wildcardByteRecord, len(sig.Fingerprint.Pattern))
		for i, wb := range sig.Fingerprint.Pattern {
			r.Pattern[i] = wildcardByteRecord(wb)
		}
	}

	if sig.CFGHash != nil {
		ch := sig.CFGHash
		cr := &cfgHashRecord{
			Hash64:     ch.Hash64,
			BlockCount: ch.BlockCount,
			EdgeCount:  ch.EdgeCount,
			LoopCount:  ch.LoopCount,
			DomDepth:   ch.DominatorTreeDepth,
		}
		cr.DegreeSequence = make([]degreeRecord, len(ch.DegreeSequence))
		for i, d := range ch.DegreeSequence {
			cr.DegreeSequence[i] = degreeRecord{In: d.InDegree, Out: d.OutDegree}
		}
		r.CFGHash = cr
	}

	return r
}

func recordToSig(r nativeRecord) *Signature {
	sig := &Signature{
		Name:    r.Name,
		Library: r.Library,
		Version: r.Version,
		Format:  parseFormatString(r.Format),
	}

	if len(r.Pattern) > 0 {
		pattern := make([]WildcardByte, len(r.Pattern))
		for i, wb := range r.Pattern {
			pattern[i] = WildcardByte(wb)
		}
		sig.Fingerprint = &FunctionFingerprint{
			Pattern:    pattern,
			Address:    0,
			ByteLength: r.ByteLen,
		}
	}

	if r.CFGHash != nil {
		ch := r.CFGHash
		degSeq := make([]DegreeEntry, len(ch.DegreeSequence))
		for i, d := range ch.DegreeSequence {
			degSeq[i] = DegreeEntry{InDegree: d.In, OutDegree: d.Out}
		}
		sig.CFGHash = &CFGHash{
			Hash64:             ch.Hash64,
			BlockCount:         ch.BlockCount,
			EdgeCount:          ch.EdgeCount,
			LoopCount:          ch.LoopCount,
			DominatorTreeDepth: ch.DomDepth,
			DegreeSequence:     degSeq,
		}
	}

	return sig
}

func parseFormatString(s string) SignatureFormat {
	switch s {
	case sigFormatFLIRT:
		return SignatureFormatFLIRT
	case sigFormatFID:
		return SignatureFormatFID
	case sigFormatNative:
		return SignatureFormatNative
	default:
		return SignatureFormatUnknown
	}
}

func loadNativeJSON(r io.Reader) (*SignatureDB, error) {
	var records []nativeRecord
	if err := json.NewDecoder(r).Decode(&records); err != nil {
		return nil, fmt.Errorf("decode native JSON: %w", err)
	}

	db := NewSignatureDB()
	db.Format = SignatureFormatNative
	for _, rec := range records {
		db.Add(recordToSig(rec))
	}
	return db, nil
}

// ============================================================================
// FLIRT PAT text format
//
// each non-comment line has the form:
//   <hex-pattern> <crc-len> <crc16> <total-len> :<offset> <name> [:<offset> <name> ...]
//
// wildcards are represented as ".." in the hex pattern.
// we parse the hex pattern and the first name/offset pair.
// ============================================================================

func loadFLIRT(r io.Reader, path string) (*SignatureDB, error) {
	db := NewSignatureDB()
	db.Format = SignatureFormatFLIRT

	scanner := bufio.NewScanner(r)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		// end-of-file marker in FLIRT PAT
		if line == "---" {
			break
		}

		sig, err := parseFLIRTLine(line)
		if err != nil {
			// skip malformed lines with a warning; do not abort
			continue
		}
		db.Add(sig)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read FLIRT file %q: %w", path, err)
	}

	return db, nil
}

// parseFLIRTLine parses a single FLIRT PAT text line.
//
// format: <hex-pattern> <crc-len> <crc16> <total-len> :<offset> <name> ...
func parseFLIRTLine(line string) (*Signature, error) {
	fields := strings.Fields(line)
	// minimum: pattern crc-len crc16 total-len :offset name
	if len(fields) < 6 {
		return nil, fmt.Errorf("%w: too few fields", errInvalidPatLine)
	}

	hexPat := fields[0]
	pattern, err := parseFLIRTPattern(hexPat)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidPatLine, err)
	}

	// find the first ":offset name" pair
	name := ""
	for i := 4; i+1 < len(fields); i++ {
		if strings.HasPrefix(fields[i], ":") {
			name = fields[i+1]
			break
		}
	}
	if name == "" && len(fields) >= 6 {
		name = fields[5]
	}

	sig := &Signature{
		Name:    name,
		Library: "",
		Format:  SignatureFormatFLIRT,
		Fingerprint: &FunctionFingerprint{
			Pattern:    pattern,
			ByteLength: len(pattern),
		},
	}
	return sig, nil
}

// parseFLIRTPattern converts a FLIRT hex pattern string to []WildcardByte.
// ".." represents a wildcard byte; hex pairs represent literal bytes.
func parseFLIRTPattern(s string) ([]WildcardByte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("%w: %q", errOddLengthPattern, s)
	}

	result := make([]WildcardByte, 0, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		pair := s[i : i+2]
		if pair == ".." {
			result = append(result, WildcardByte{IsWild: true})
			continue
		}
		b, err := parseHexByte(pair)
		if err != nil {
			return nil, err
		}
		result = append(result, WildcardByte{Value: b})
	}
	return result, nil
}

func parseHexByte(s string) (byte, error) {
	if len(s) != 2 {
		return 0, fmt.Errorf("%w: %q", errInvalidHexByte, s)
	}
	hi, err := hexVal(s[0])
	if err != nil {
		return 0, err
	}
	lo, err := hexVal(s[1])
	if err != nil {
		return 0, err
	}
	return hi<<4 | lo, nil
}

func hexVal(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("%w: %q", errInvalidHexChar, c)
	}
}

// ============================================================================
// FID JSON format (Ghidra FID .fidb conceptual representation)
//
// we model .fidb as a JSON array of FID records for portability.
// a real .fidb is a SQLite database; this implementation handles the
// JSON export format that Ghidra's FidDb.exportToJson() produces.
// ============================================================================

// fidRecord is the JSON representation of a single FID entry.
type fidRecord struct {
	FullHash       uint64 `json:"full_hash"`
	SpecificHash   uint64 `json:"specific_hash"`
	Name           string `json:"name"`
	LibraryName    string `json:"library_name"`
	LibraryVersion string `json:"library_version"`
	DomainPath     string `json:"domain_path"`
}

func loadFID(r io.Reader, path string) (*SignatureDB, error) {
	var records []fidRecord
	if err := json.NewDecoder(r).Decode(&records); err != nil {
		return nil, fmt.Errorf("decode FID file %q: %w", path, err)
	}

	db := NewSignatureDB()
	db.Format = SignatureFormatFID

	for _, rec := range records {
		sig := &Signature{
			Name:    rec.Name,
			Library: rec.LibraryName,
			Version: rec.LibraryVersion,
			Format:  SignatureFormatFID,
			// FID stores only hashes, not raw byte patterns
			CFGHash: &CFGHash{
				Hash64: rec.FullHash,
			},
		}
		db.Add(sig)
	}

	return db, nil
}
