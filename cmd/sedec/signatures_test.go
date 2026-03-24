package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zarazaex69/sedec/pkg/signatures"
)

// ============================================================================
// helpers
// ============================================================================

// nativeRecord mirrors the unexported type in db.go for test fixture creation.
type nativeRecord struct {
	Pattern []wildcardByteRecord `json:"pattern"`
	Name    string               `json:"name"`
	Library string               `json:"library"`
	Version string               `json:"version"`
	Format  string               `json:"format"`
	ByteLen int                  `json:"byte_len"`
	Address uint64               `json:"address"`
}

type wildcardByteRecord struct {
	Value  byte `json:"v"`
	IsWild bool `json:"w,omitempty"`
}

// writeNativeDB writes a minimal native JSON signature database to a temp file.
func writeNativeDB(t *testing.T, sigs []nativeRecord) string {
	t.Helper()
	data, err := json.Marshal(sigs)
	if err != nil {
		t.Fatalf("marshal native db: %v", err)
	}
	f, err := os.CreateTemp(t.TempDir(), "*.json")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

// writePATFile writes a minimal FLIRT .pat file to a temp file.
func writePATFile(t *testing.T, lines []string) string {
	t.Helper()
	content := strings.Join(lines, "\n") + "\n---\n"
	f, err := os.CreateTemp(t.TempDir(), "*.pat")
	if err != nil {
		t.Fatalf("create temp pat file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write pat file: %v", err)
	}
	f.Close()
	return f.Name()
}

// ============================================================================
// runSignatures dispatch tests
// ============================================================================

func TestRunSignatures_NoArgs_ReturnsError(t *testing.T) {
	var out, errOut bytes.Buffer
	err := runSignatures(nil, nil, &out, &errOut)
	if err == nil {
		t.Fatal("expected error for no args, got nil")
	}
}

func TestRunSignatures_Help_NoError(t *testing.T) {
	var out, errOut bytes.Buffer
	err := runSignatures([]string{"--help"}, nil, &out, &errOut)
	if err != nil {
		t.Fatalf("expected nil error for --help, got: %v", err)
	}
	if !strings.Contains(out.String(), "subcommands") {
		t.Error("help output should mention subcommands")
	}
}

func TestRunSignatures_UnknownSubcommand_ReturnsError(t *testing.T) {
	var out, errOut bytes.Buffer
	err := runSignatures([]string{"nonexistent"}, nil, &out, &errOut)
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

// ============================================================================
// list subcommand tests
// ============================================================================

func TestSigList_NoDBPath_ReturnsError(t *testing.T) {
	var out, errOut bytes.Buffer
	err := runSigList(nil, &out, &errOut)
	if err == nil {
		t.Fatal("expected error when no db path provided")
	}
}

func TestSigList_ValidDB_PrintsSignatures(t *testing.T) {
	sigs := []nativeRecord{
		{Name: "memcpy", Library: "libc", Version: "2.35", Format: "Native",
			Pattern: []wildcardByteRecord{{Value: 0x55}, {Value: 0x48}}, ByteLen: 2},
		{Name: "memset", Library: "libc", Version: "2.35", Format: "Native",
			Pattern: []wildcardByteRecord{{Value: 0x31}}, ByteLen: 1},
	}
	dbPath := writeNativeDB(t, sigs)

	var out, errOut bytes.Buffer
	err := runSigList([]string{dbPath}, &out, &errOut)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "memcpy") {
		t.Error("output should contain 'memcpy'")
	}
	if !strings.Contains(output, "memset") {
		t.Error("output should contain 'memset'")
	}
	if !strings.Contains(output, "total signatures: 2") {
		t.Errorf("output should show total count, got:\n%s", output)
	}
}

func TestSigList_FilterByName(t *testing.T) {
	sigs := []nativeRecord{
		{Name: "memcpy", Library: "libc", Format: "Native",
			Pattern: []wildcardByteRecord{{Value: 0x55}}, ByteLen: 1},
		{Name: "strlen", Library: "libc", Format: "Native",
			Pattern: []wildcardByteRecord{{Value: 0x48}}, ByteLen: 1},
	}
	dbPath := writeNativeDB(t, sigs)

	var out, errOut bytes.Buffer
	err := runSigList([]string{"--filter", "mem", dbPath}, &out, &errOut)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "memcpy") {
		t.Error("filtered output should contain 'memcpy'")
	}
	if strings.Contains(output, "strlen") {
		t.Error("filtered output should not contain 'strlen'")
	}
}

func TestSigList_Limit(t *testing.T) {
	sigs := make([]nativeRecord, 5)
	for i := range sigs {
		sigs[i] = nativeRecord{
			Name: strings.Repeat("f", i+1), Library: "lib", Format: "Native",
			Pattern: []wildcardByteRecord{{Value: byte(i)}}, ByteLen: 1,
		}
	}
	dbPath := writeNativeDB(t, sigs)

	var out, errOut bytes.Buffer
	err := runSigList([]string{"--limit", "2", dbPath}, &out, &errOut)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// count lines with actual signature data (non-header lines)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	dataLines := 0
	for _, l := range lines {
		// skip header lines (format:, total:, separator, empty)
		if strings.HasPrefix(l, "f") {
			dataLines++
		}
	}
	if dataLines > 2 {
		t.Errorf("expected at most 2 data lines with --limit 2, got %d", dataLines)
	}
}

func TestSigList_NonexistentFile_ReturnsError(t *testing.T) {
	var out, errOut bytes.Buffer
	err := runSigList([]string{"/nonexistent/path/db.json"}, &out, &errOut)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

// ============================================================================
// import subcommand tests
// ============================================================================

func TestSigImport_NoInput_ReturnsError(t *testing.T) {
	var out, errOut bytes.Buffer
	err := runSigImport(nil, &out, &errOut)
	if err == nil {
		t.Fatal("expected error when no input provided")
	}
}

func TestSigImport_NoOutput_ReturnsError(t *testing.T) {
	patPath := writePATFile(t, []string{
		"5548..e8........ 04 1234 0010 :0000 memcpy",
	})
	var out, errOut bytes.Buffer
	err := runSigImport([]string{"--import-flirt", patPath}, &out, &errOut)
	if err == nil {
		t.Fatal("expected error when no output path provided")
	}
}

func TestSigImport_FLIRT_CreatesDB(t *testing.T) {
	patPath := writePATFile(t, []string{
		"5548..e8........ 04 1234 0010 :0000 memcpy",
		"4831c0c3........ 02 5678 0008 :0000 strlen",
	})
	outPath := filepath.Join(t.TempDir(), "out.json")

	var out, errOut bytes.Buffer
	err := runSigImport([]string{"--import-flirt", patPath, "--output", outPath}, &out, &errOut)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// verify output file exists and contains signatures
	data, readErr := os.ReadFile(outPath)
	if readErr != nil {
		t.Fatalf("output file not created: %v", readErr)
	}
	if !strings.Contains(string(data), "memcpy") {
		t.Error("output db should contain 'memcpy'")
	}
	if !strings.Contains(out.String(), "imported") {
		t.Error("stdout should report import count")
	}
}

func TestSigImport_FID_CreatesDB(t *testing.T) {
	// write a minimal FID JSON file
	fidContent := `[{"full_hash":12345,"specific_hash":67890,"name":"malloc","library_name":"libc","library_version":"2.35","domain_path":"/libc/malloc"}]`
	fidFile, err := os.CreateTemp(t.TempDir(), "*.fidb")
	if err != nil {
		t.Fatalf("create fidb: %v", err)
	}
	if _, err := fidFile.WriteString(fidContent); err != nil {
		t.Fatalf("write fidb: %v", err)
	}
	fidFile.Close()

	outPath := filepath.Join(t.TempDir(), "out.json")
	var out, errOut bytes.Buffer
	err = runSigImport([]string{"--import-fid", fidFile.Name(), "--output", outPath}, &out, &errOut)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, readErr := os.ReadFile(outPath)
	if readErr != nil {
		t.Fatalf("output file not created: %v", readErr)
	}
	if !strings.Contains(string(data), "malloc") {
		t.Error("output db should contain 'malloc'")
	}
}

func TestSigImport_Merge_CombinesSignatures(t *testing.T) {
	// create initial db
	initial := []nativeRecord{
		{Name: "existing_func", Library: "lib", Format: "Native",
			Pattern: []wildcardByteRecord{{Value: 0x55}}, ByteLen: 1},
	}
	outPath := writeNativeDB(t, initial)

	// import additional FLIRT signatures with merge
	patPath := writePATFile(t, []string{
		"5548..e8........ 04 1234 0010 :0000 new_func",
	})

	var out, errOut bytes.Buffer
	err := runSigImport([]string{"--import-flirt", patPath, "--merge", "--output", outPath}, &out, &errOut)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// reload and verify both signatures present
	data, _ := os.ReadFile(outPath)
	if !strings.Contains(string(data), "existing_func") {
		t.Error("merged db should contain original 'existing_func'")
	}
	if !strings.Contains(string(data), "new_func") {
		t.Error("merged db should contain imported 'new_func'")
	}
	_ = errOut
}

// ============================================================================
// export subcommand tests
// ============================================================================

func TestSigExport_NoDBPath_ReturnsError(t *testing.T) {
	var out, errOut bytes.Buffer
	err := runSigExport(nil, &out, &errOut)
	if err == nil {
		t.Fatal("expected error when no db path provided")
	}
}

func TestSigExport_NoOutputPath_ReturnsError(t *testing.T) {
	sigs := []nativeRecord{
		{Name: "memcpy", Library: "libc", Format: "Native",
			Pattern: []wildcardByteRecord{{Value: 0x55}}, ByteLen: 1},
	}
	dbPath := writeNativeDB(t, sigs)

	var out, errOut bytes.Buffer
	err := runSigExport([]string{dbPath}, &out, &errOut)
	if err == nil {
		t.Fatal("expected error when no output path provided")
	}
}

func TestSigExport_ValidDB_WritesFile(t *testing.T) {
	sigs := []nativeRecord{
		{Name: "memcpy", Library: "libc", Format: "Native",
			Pattern: []wildcardByteRecord{{Value: 0x55}}, ByteLen: 1},
	}
	dbPath := writeNativeDB(t, sigs)
	outPath := filepath.Join(t.TempDir(), "exported.json")

	var out, errOut bytes.Buffer
	err := runSigExport([]string{"--output", outPath, dbPath}, &out, &errOut)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, readErr := os.ReadFile(outPath)
	if readErr != nil {
		t.Fatalf("output file not created: %v", readErr)
	}
	if !strings.Contains(string(data), "memcpy") {
		t.Error("exported file should contain 'memcpy'")
	}
	if !strings.Contains(out.String(), "exported") {
		t.Error("stdout should report export count")
	}
}

func TestSigExport_WithFilter(t *testing.T) {
	sigs := []nativeRecord{
		{Name: "memcpy", Library: "libc", Format: "Native",
			Pattern: []wildcardByteRecord{{Value: 0x55}}, ByteLen: 1},
		{Name: "strlen", Library: "libc", Format: "Native",
			Pattern: []wildcardByteRecord{{Value: 0x48}}, ByteLen: 1},
	}
	dbPath := writeNativeDB(t, sigs)
	outPath := filepath.Join(t.TempDir(), "filtered.json")

	var out, errOut bytes.Buffer
	err := runSigExport([]string{"--filter", "mem", "--output", outPath, dbPath}, &out, &errOut)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(outPath)
	if !strings.Contains(string(data), "memcpy") {
		t.Error("filtered export should contain 'memcpy'")
	}
	if strings.Contains(string(data), "strlen") {
		t.Error("filtered export should not contain 'strlen'")
	}
	_ = errOut
}

// ===========================================================================

// validate subcommand tests
// ============================================================================

func TestSigValidate_NoDBPath_ReturnsError(t *testing.T) {
	var out, errOut bytes.Buffer
	err := runSigValidate(nil, &out, &errOut)
	if err == nil {
		t.Fatal("expected error when no db path provided")
	}
}

func TestSigValidate_ValidDB_PassesValidation(t *testing.T) {
	sigs := []nativeRecord{
		{Name: "memcpy", Library: "libc", Format: "Native",
			Pattern: []wildcardByteRecord{{Value: 0x55}, {Value: 0x48}}, ByteLen: 2},
	}
	dbPath := writeNativeDB(t, sigs)

	var out, errOut bytes.Buffer
	err := runSigValidate([]string{dbPath}, &out, &errOut)
	if err != nil {
		t.Fatalf("unexpected error for valid db: %v", err)
	}
	if !strings.Contains(out.String(), "validation passed") {
		t.Errorf("expected 'validation passed' in output, got:\n%s", out.String())
	}
}

func TestSigValidate_EmptyNameSignature_ReportsIssue(t *testing.T) {
	sigs := []nativeRecord{
		{Name: "", Library: "libc", Format: "Native",
			Pattern: []wildcardByteRecord{{Value: 0x55}}, ByteLen: 1},
	}
	dbPath := writeNativeDB(t, sigs)

	var out, errOut bytes.Buffer
	// without --strict, should not return error but report issue
	err := runSigValidate([]string{dbPath}, &out, &errOut)
	if err != nil {
		t.Fatalf("non-strict validate should not return error: %v", err)
	}
	if !strings.Contains(out.String(), "issues found") {
		t.Errorf("expected issues in output, got:\n%s", out.String())
	}
}

func TestSigValidate_StrictMode_ReturnsErrorOnIssues(t *testing.T) {
	sigs := []nativeRecord{
		{Name: "", Library: "libc", Format: "Native",
			Pattern: []wildcardByteRecord{{Value: 0x55}}, ByteLen: 1},
	}
	dbPath := writeNativeDB(t, sigs)

	var out, errOut bytes.Buffer
	err := runSigValidate([]string{"--strict", dbPath}, &out, &errOut)
	if err == nil {
		t.Fatal("strict mode should return error when issues found")
	}
}

func TestSigValidate_NonexistentFile_ReturnsError(t *testing.T) {
	var out, errOut bytes.Buffer
	err := runSigValidate([]string{"/nonexistent/db.json"}, &out, &errOut)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

// ============================================================================
// integration: full CLI dispatch
// ============================================================================

func TestRunCLI_SignaturesHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{"signatures", "--help"}, nil, &out, &errOut)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), "subcommands") {
		t.Error("help output should mention subcommands")
	}
}

func TestRunCLI_SignaturesList_Integration(t *testing.T) {
	sigs := []nativeRecord{
		{Name: "printf", Library: "libc", Format: "Native",
			Pattern: []wildcardByteRecord{{Value: 0x55}}, ByteLen: 1},
	}
	dbPath := writeNativeDB(t, sigs)

	var out, errOut bytes.Buffer
	err := run([]string{"signatures", "list", dbPath}, nil, &out, &errOut)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), "printf") {
		t.Error("output should contain 'printf'")
	}
}

// ============================================================================
// additional coverage tests
// ============================================================================

func TestSigImport_AutoDetectPAT(t *testing.T) {
	patPath := writePATFile(t, []string{
		"5548..e8........ 04 1234 0010 :0000 auto_detect_func",
	})
	outPath := filepath.Join(t.TempDir(), "out.json")

	var out, errOut bytes.Buffer
	err := runSigImport([]string{"--output", outPath, patPath}, &out, &errOut)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := os.ReadFile(outPath)
	if !strings.Contains(string(data), "auto_detect_func") {
		t.Error("auto-detected PAT import should contain 'auto_detect_func'")
	}
}

func TestSigImport_AutoDetectFIDB(t *testing.T) {
	fidContent := `[{"full_hash":111,"specific_hash":222,"name":"auto_fid","library_name":"lib","library_version":"1.0","domain_path":"/lib"}]`
	fidFile, err := os.CreateTemp(t.TempDir(), "*.fidb")
	if err != nil {
		t.Fatalf("create fidb: %v", err)
	}
	fidFile.WriteString(fidContent)
	fidFile.Close()

	outPath := filepath.Join(t.TempDir(), "out.json")
	var out, errOut bytes.Buffer
	err = runSigImport([]string{"--output", outPath, fidFile.Name()}, &out, &errOut)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := os.ReadFile(outPath)
	if !strings.Contains(string(data), "auto_fid") {
		t.Error("auto-detected FIDB import should contain 'auto_fid'")
	}
}

func TestSigImport_UnknownExtension_ReturnsError(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "*.xyz")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	tmpFile.WriteString("garbage")
	tmpFile.Close()

	outPath := filepath.Join(t.TempDir(), "out.json")
	var out, errOut bytes.Buffer
	err = runSigImport([]string{"--output", outPath, tmpFile.Name()}, &out, &errOut)
	if err == nil {
		t.Fatal("expected error for unknown extension")
	}
}

func TestSigImport_InvalidFLIRT_ReturnsError(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "*.pat")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	tmpFile.WriteString("---\n")
	tmpFile.Close()

	outPath := filepath.Join(t.TempDir(), "out.json")
	var out, errOut bytes.Buffer
	err = runSigImport([]string{"--import-flirt", tmpFile.Name(), "--output", outPath}, &out, &errOut)
	if err == nil {
		t.Fatal("expected error for empty FLIRT import")
	}
}

func TestSigImport_InvalidFID_ReturnsError(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "*.fidb")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	tmpFile.WriteString("not json")
	tmpFile.Close()

	outPath := filepath.Join(t.TempDir(), "out.json")
	var out, errOut bytes.Buffer
	err = runSigImport([]string{"--import-fid", tmpFile.Name(), "--output", outPath}, &out, &errOut)
	if err == nil {
		t.Fatal("expected error for invalid FID file")
	}
}

func TestSigImport_BothFLIRTAndFID(t *testing.T) {
	patPath := writePATFile(t, []string{
		"5548..e8........ 04 1234 0010 :0000 from_flirt",
	})
	fidContent := `[{"full_hash":111,"specific_hash":222,"name":"from_fid","library_name":"lib","library_version":"1.0","domain_path":"/lib"}]`
	fidFile, err := os.CreateTemp(t.TempDir(), "*.fidb")
	if err != nil {
		t.Fatalf("create fidb: %v", err)
	}
	fidFile.WriteString(fidContent)
	fidFile.Close()

	outPath := filepath.Join(t.TempDir(), "out.json")
	var out, errOut bytes.Buffer
	err = runSigImport([]string{
		"--import-flirt", patPath,
		"--import-fid", fidFile.Name(),
		"--output", outPath,
	}, &out, &errOut)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := os.ReadFile(outPath)
	content := string(data)
	if !strings.Contains(content, "from_flirt") {
		t.Error("combined import should contain 'from_flirt'")
	}
	if !strings.Contains(content, "from_fid") {
		t.Error("combined import should contain 'from_fid'")
	}
}

func TestSigValidate_NoFingerprintNoCFGHash_ReportsIssue(t *testing.T) {
	sigs := []nativeRecord{
		{Name: "broken_sig", Library: "lib", Format: "Native", ByteLen: 0},
	}
	dbPath := writeNativeDB(t, sigs)

	var out, errOut bytes.Buffer
	err := runSigValidate([]string{dbPath}, &out, &errOut)
	if err != nil {
		t.Fatalf("non-strict validate should not error: %v", err)
	}
	if !strings.Contains(out.String(), "no fingerprint and no cfg hash") {
		t.Errorf("expected fingerprint/cfg hash issue, got:\n%s", out.String())
	}
}

func TestSigValidate_EmptyPattern_ReportsIssue(t *testing.T) {
	sigs := []nativeRecord{
		{Name: "empty_pat", Library: "lib", Format: "Native",
			Pattern: []wildcardByteRecord{}, ByteLen: 0},
	}
	dbPath := writeNativeDB(t, sigs)

	var out, errOut bytes.Buffer
	err := runSigValidate([]string{dbPath}, &out, &errOut)
	if err != nil {
		t.Fatalf("non-strict validate should not error: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "issues found") {
		t.Errorf("expected issues for empty pattern, got:\n%s", output)
	}
}

func TestSigExport_EmptyAfterFilter_ReturnsError(t *testing.T) {
	sigs := []nativeRecord{
		{Name: "memcpy", Library: "libc", Format: "Native",
			Pattern: []wildcardByteRecord{{Value: 0x55}}, ByteLen: 1},
	}
	dbPath := writeNativeDB(t, sigs)
	outPath := filepath.Join(t.TempDir(), "filtered.json")

	var out, errOut bytes.Buffer
	err := runSigExport([]string{"--filter", "nonexistent_name", "--output", outPath, dbPath}, &out, &errOut)
	if err == nil {
		t.Fatal("expected error when filter produces empty db")
	}
}

func TestSigExport_NonexistentFile_ReturnsError(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "out.json")
	var out, errOut bytes.Buffer
	err := runSigExport([]string{"--output", outPath, "/nonexistent/db.json"}, &out, &errOut)
	if err == nil {
		t.Fatal("expected error for nonexistent source file")
	}
}

func TestFingerprintSimilarity_BothNil(t *testing.T) {
	if s := FingerprintSimilarity(nil, nil); s != 0.0 {
		t.Errorf("expected 0.0 for nil inputs, got %f", s)
	}
}

func TestFingerprintSimilarity_EmptyPattern(t *testing.T) {
	a := &signatures.FunctionFingerprint{Pattern: []signatures.WildcardByte{}}
	b := &signatures.FunctionFingerprint{Pattern: []signatures.WildcardByte{{Value: 0x55}}}
	if s := FingerprintSimilarity(a, b); s != 0.0 {
		t.Errorf("expected 0.0 for empty pattern, got %f", s)
	}
}

func TestFingerprintSimilarity_IdenticalPatterns(t *testing.T) {
	pat := []signatures.WildcardByte{{Value: 0x55}, {Value: 0x48}, {Value: 0x89}}
	a := &signatures.FunctionFingerprint{Pattern: pat}
	b := &signatures.FunctionFingerprint{Pattern: pat}
	s := FingerprintSimilarity(a, b)
	if s != 1.0 {
		t.Errorf("expected 1.0 for identical patterns, got %f", s)
	}
}

func TestFingerprintSimilarity_WildcardMatch(t *testing.T) {
	a := &signatures.FunctionFingerprint{Pattern: []signatures.WildcardByte{
		{Value: 0x55}, {IsWild: true}, {Value: 0x89},
	}}
	b := &signatures.FunctionFingerprint{Pattern: []signatures.WildcardByte{
		{Value: 0x55}, {Value: 0xFF}, {Value: 0x89},
	}}
	s := FingerprintSimilarity(a, b)
	if s != 1.0 {
		t.Errorf("expected 1.0 with wildcard match, got %f", s)
	}
}

func TestFingerprintSimilarity_DifferentLengths(t *testing.T) {
	a := &signatures.FunctionFingerprint{Pattern: []signatures.WildcardByte{
		{Value: 0x55}, {Value: 0x48},
	}}
	b := &signatures.FunctionFingerprint{Pattern: []signatures.WildcardByte{
		{Value: 0x55}, {Value: 0x48}, {Value: 0x89}, {Value: 0xE5},
	}}
	s := FingerprintSimilarity(a, b)
	if s < 0.0 || s > 1.0 {
		t.Errorf("similarity out of range: %f", s)
	}
	if s != 0.5 {
		t.Errorf("expected 0.5 for 2/4 match, got %f", s)
	}
}

func TestCFGHashSimilarity_BothNil(t *testing.T) {
	if s := CFGHashSimilarity(nil, nil); s != 0.0 {
		t.Errorf("expected 0.0 for nil inputs, got %f", s)
	}
}

func TestCFGHashSimilarity_IdenticalHash(t *testing.T) {
	a := &signatures.CFGHash{Hash64: 12345, BlockCount: 10, EdgeCount: 15}
	b := &signatures.CFGHash{Hash64: 12345, BlockCount: 10, EdgeCount: 15}
	s := CFGHashSimilarity(a, b)
	if s != 1.0 {
		t.Errorf("expected 1.0 for identical hashes, got %f", s)
	}
}

func TestCFGHashSimilarity_DifferentHash_SimilarBlocks(t *testing.T) {
	a := &signatures.CFGHash{Hash64: 111, BlockCount: 10, EdgeCount: 15}
	b := &signatures.CFGHash{Hash64: 222, BlockCount: 12, EdgeCount: 18}
	s := CFGHashSimilarity(a, b)
	if s <= 0.0 || s >= 1.0 {
		t.Errorf("expected partial similarity, got %f", s)
	}
}

func TestCFGHashSimilarity_ZeroBlocks(t *testing.T) {
	a := &signatures.CFGHash{Hash64: 111, BlockCount: 0}
	b := &signatures.CFGHash{Hash64: 222, BlockCount: 0}
	s := CFGHashSimilarity(a, b)
	if s != 0.0 {
		t.Errorf("expected 0.0 for zero block counts, got %f", s)
	}
}

func TestRunSignatures_HelpVariants(t *testing.T) {
	variants := []string{"-help", "-h", "help"}
	for _, v := range variants {
		var out, errOut bytes.Buffer
		err := runSignatures([]string{v}, nil, &out, &errOut)
		if err != nil {
			t.Errorf("expected nil error for %q, got: %v", v, err)
		}
	}
}

func TestSigList_HelpFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	err := runSigList([]string{"--help"}, &out, &errOut)
	if err != nil {
		t.Fatalf("expected nil for --help, got: %v", err)
	}
}

func TestSigImport_HelpFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	err := runSigImport([]string{"--help"}, &out, &errOut)
	if err != nil {
		t.Fatalf("expected nil for --help, got: %v", err)
	}
}

func TestSigExport_HelpFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	err := runSigExport([]string{"--help"}, &out, &errOut)
	if err != nil {
		t.Fatalf("expected nil for --help, got: %v", err)
	}
}

func TestSigValidate_HelpFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	err := runSigValidate([]string{"--help"}, &out, &errOut)
	if err != nil {
		t.Fatalf("expected nil for --help, got: %v", err)
	}
}

func TestSigValidate_InvalidByteLength_ReportsIssue(t *testing.T) {
	raw := `[{"name":"bad_len","library":"lib","format":"Native","pattern":[{"v":85}],"byte_len":-1}]`
	f, err := os.CreateTemp(t.TempDir(), "*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(raw); err != nil {
		t.Fatal(err)
	}
	f.Close()

	var out, errOut bytes.Buffer
	err = runSigValidate([]string{f.Name()}, &out, &errOut)
	if err != nil {
		t.Fatalf("non-strict validate should not error: %v", err)
	}
	if !strings.Contains(out.String(), "invalid byte length") {
		t.Errorf("expected invalid byte length issue, got:\n%s", out.String())
	}
}

func TestSigValidate_NegativeBlockCount_ReportsIssue(t *testing.T) {
	raw := `[{"name":"neg_blocks","library":"lib","format":"Native","pattern":[],"byte_len":0,"cfg_hash":{"blocks":-1,"edges":5,"hash64":1}}]`
	f, err := os.CreateTemp(t.TempDir(), "*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(raw); err != nil {
		t.Fatal(err)
	}
	f.Close()

	var out, errOut bytes.Buffer
	err = runSigValidate([]string{f.Name()}, &out, &errOut)
	if err != nil {
		t.Fatalf("non-strict validate should not error: %v", err)
	}
	if !strings.Contains(out.String(), "negative block count") {
		t.Errorf("expected negative block count issue, got:\n%s", out.String())
	}
}

func TestSigValidate_NegativeEdgeCount_ReportsIssue(t *testing.T) {
	raw := `[{"name":"neg_edges","library":"lib","format":"Native","pattern":[],"byte_len":0,"cfg_hash":{"blocks":5,"edges":-3,"hash64":2}}]`
	f, err := os.CreateTemp(t.TempDir(), "*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(raw); err != nil {
		t.Fatal(err)
	}
	f.Close()

	var out, errOut bytes.Buffer
	err = runSigValidate([]string{f.Name()}, &out, &errOut)
	if err != nil {
		t.Fatalf("non-strict validate should not error: %v", err)
	}
	if !strings.Contains(out.String(), "negative edge count") {
		t.Errorf("expected negative edge count issue, got:\n%s", out.String())
	}
}
