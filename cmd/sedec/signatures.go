//nolint:godot // cli tool with many error messages
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/zarazaex69/sedec/pkg/signatures"
)

var (
	// errSigNoSubcommand indicates no subcommand was provided.
	errSigNoSubcommand = errors.New("no subcommand provided")
	// errSigUnknownSubcommand indicates unknown subcommand.
	errSigUnknownSubcommand = errors.New("unknown subcommand")
	// errSigNoDBPath indicates no database path was provided.
	errSigNoDBPath = errors.New("no database path provided")
	// errSigNoInputPath indicates no input path was provided.
	errSigNoInputPath = errors.New("no input path provided")
	// errSigNoOutputPath indicates no output path was provided.
	errSigNoOutputPath = errors.New("no output path provided")
	// errSigEmptyDB indicates the database is empty after import.
	errSigEmptyDB = errors.New("database is empty: no signatures were loaded")
	// errSigValidationFailed indicates validation found issues.
	errSigValidationFailed = errors.New("validation failed")
)

// runSignatures dispatches the signatures subcommand.
func runSignatures(args []string, _ io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printSignaturesUsage(stdout)
		return errSigNoSubcommand
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "list":
		return runSigList(subArgs, stdout, stderr)
	case "import":
		return runSigImport(subArgs, stdout, stderr)
	case "export":
		return runSigExport(subArgs, stdout, stderr)
	case "validate":
		return runSigValidate(subArgs, stdout, stderr)
	case "--help", "-help", "-h", "help":
		printSignaturesUsage(stdout)
		return nil
	default:
		//nolint:errcheck // error output is informational
		fmt.Fprintf(stderr, "unknown subcommand: %s\n\n", sub)
		printSignaturesUsage(stderr)
		return fmt.Errorf("%w: %s", errSigUnknownSubcommand, sub)
	}
}

// ============================================================================
// list subcommand
// ============================================================================

// sigListConfig holds configuration for signatures list subcommand.
type sigListConfig struct {
	format string
	filter string
	limit  int
}

// runSigList lists all signatures in a database file.
func runSigList(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("signatures list", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := &sigListConfig{}
	fs.StringVar(&cfg.format, "format", "table", "output format: table or json")
	fs.StringVar(&cfg.filter, "filter", "", "filter signatures by name substring")
	fs.IntVar(&cfg.limit, "limit", 0, "maximum number of signatures to display (0 = all)")

	fs.Usage = func() {
		//nolint:errcheck // usage output is informational
		fmt.Fprint(stderr, "usage: sedec signatures list [options] <db-file>\n\nlist all signatures in a database file.\n")
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		return errSigNoDBPath
	}
	dbPath := remaining[0]

	db, err := signatures.LoadFromFile(dbPath)
	if err != nil {
		return fmt.Errorf("failed to load signature database %q: %w", dbPath, err)
	}

	return printSigList(db, cfg, stdout)
}

// printSigList prints the signature list to output.
func printSigList(db *signatures.SignatureDB, cfg *sigListConfig, out io.Writer) error {
	sigs := db.Signatures

	// apply name filter
	if cfg.filter != "" {
		filtered := sigs[:0]
		for _, s := range sigs {
			if strings.Contains(s.Name, cfg.filter) {
				filtered = append(filtered, s)
			}
		}
		sigs = filtered
	}

	// apply limit
	if cfg.limit > 0 && len(sigs) > cfg.limit {
		sigs = sigs[:cfg.limit]
	}

	if _, err := fmt.Fprintf(out, "database format: %s\n", db.Format); err != nil {
		return fmt.Errorf("write error: %w", err)
	}
	if _, err := fmt.Fprintf(out, "total signatures: %d\n\n", len(sigs)); err != nil {
		return fmt.Errorf("write error: %w", err)
	}

	if len(sigs) == 0 {
		_, _ = fmt.Fprintln(out, "no signatures found")
		return nil
	}

	// table header
	if _, err := fmt.Fprintf(out, "%-40s %-30s %-10s %-8s\n", "name", "library", "version", "format"); err != nil {
		return fmt.Errorf("write error: %w", err)
	}
	if _, err := fmt.Fprintf(out, "%s\n", strings.Repeat("-", 92)); err != nil {
		return fmt.Errorf("write error: %w", err)
	}

	for _, s := range sigs {
		name := s.Name
		if len(name) > 40 {
			name = name[:37] + "..."
		}
		lib := s.Library
		if len(lib) > 30 {
			lib = lib[:27] + "..."
		}
		if _, err := fmt.Fprintf(out, "%-40s %-30s %-10s %-8s\n", name, lib, s.Version, s.Format); err != nil {
			return fmt.Errorf("write error: %w", err)
		}
	}

	return nil
}

// ============================================================================
// import subcommand
// ============================================================================

// sigImportConfig holds configuration for signatures import subcommand.
type sigImportConfig struct {
	output      string
	importFLIRT string
	importFID   string
	merge       bool
}

// runSigImport imports signatures from FLIRT or FID files into a native database.
func runSigImport(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("signatures import", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := &sigImportConfig{}
	fs.StringVar(&cfg.output, "output", "", "output database file path (native JSON format)")
	fs.StringVar(&cfg.importFLIRT, "import-flirt", "", "path to FLIRT .pat or .sig file to import")
	fs.StringVar(&cfg.importFID, "import-fid", "", "path to FID .fidb file to import")
	fs.BoolVar(&cfg.merge, "merge", false, "merge with existing database at output path")

	fs.Usage = func() {
		//nolint:errcheck // usage output is informational
		fmt.Fprint(stderr, "usage: sedec signatures import [options]\n\nimport signatures from FLIRT or FID files.\n")
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	// at least one import source required
	if cfg.importFLIRT == "" && cfg.importFID == "" {
		// check positional argument as generic input
		remaining := fs.Args()
		if len(remaining) == 0 {
			return errSigNoInputPath
		}
		// auto-detect format from extension
		cfg.importFLIRT = ""
		cfg.importFID = ""
		for _, p := range remaining {
			ext := strings.ToLower(p[max(0, len(p)-5):])
			switch {
			case strings.HasSuffix(ext, ".pat") || strings.HasSuffix(ext, ".sig"):
				cfg.importFLIRT = p
			case strings.HasSuffix(ext, ".fidb"):
				cfg.importFID = p
			}
		}
		if cfg.importFLIRT == "" && cfg.importFID == "" {
			return errSigNoInputPath
		}
	}

	if cfg.output == "" {
		return errSigNoOutputPath
	}

	return executeSigImport(cfg, stdout, stderr)
}

// max returns the larger of two ints.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// executeSigImport performs the actual import operation.
func executeSigImport(cfg *sigImportConfig, stdout, stderr io.Writer) error {
	// start with empty or existing database
	merged := signatures.NewSignatureDB()

	if cfg.merge {
		if existing, err := signatures.LoadFromFile(cfg.output); err == nil {
			for _, s := range existing.Signatures {
				merged.Add(s)
			}
			//nolint:errcheck // informational output
			fmt.Fprintf(stdout, "merged with existing database: %d signatures\n", existing.Size())
		}
	}

	// import FLIRT
	if cfg.importFLIRT != "" {
		db, err := signatures.LoadFromFile(cfg.importFLIRT)
		if err != nil {
			return fmt.Errorf("failed to import FLIRT file %q: %w", cfg.importFLIRT, err)
		}
		for _, s := range db.Signatures {
			merged.Add(s)
		}
		//nolint:errcheck // informational output
		fmt.Fprintf(stdout, "imported %d signatures from FLIRT file: %s\n", db.Size(), cfg.importFLIRT)
	}

	// import FID
	if cfg.importFID != "" {
		db, err := signatures.LoadFromFile(cfg.importFID)
		if err != nil {
			return fmt.Errorf("failed to import FID file %q: %w", cfg.importFID, err)
		}
		for _, s := range db.Signatures {
			merged.Add(s)
		}
		//nolint:errcheck // informational output
		fmt.Fprintf(stdout, "imported %d signatures from FID file: %s\n", db.Size(), cfg.importFID)
	}

	if merged.Size() == 0 {
		return errSigEmptyDB
	}

	if err := signatures.SaveToFile(merged, cfg.output); err != nil {
		return fmt.Errorf("failed to save database to %q: %w", cfg.output, err)
	}

	//nolint:errcheck // informational output
	fmt.Fprintf(stdout, "saved %d signatures to %s\n", merged.Size(), cfg.output)

	_ = stderr
	return nil
}

// ============================================================================
// export subcommand
// ============================================================================

// sigExportConfig holds configuration for signatures export subcommand.
type sigExportConfig struct {
	output string
	filter string
}

// runSigExport exports a signature database to native JSON format.
func runSigExport(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("signatures export", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := &sigExportConfig{}
	fs.StringVar(&cfg.output, "output", "", "output file path (native JSON format)")
	fs.StringVar(&cfg.filter, "filter", "", "export only signatures matching name substring")

	fs.Usage = func() {
		//nolint:errcheck // usage output is informational
		fmt.Fprint(stderr, "usage: sedec signatures export [options] <db-file>\n\nexport signature database to native JSON format.\n")
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		return errSigNoDBPath
	}
	dbPath := remaining[0]

	if cfg.output == "" {
		return errSigNoOutputPath
	}

	db, err := signatures.LoadFromFile(dbPath)
	if err != nil {
		return fmt.Errorf("failed to load signature database %q: %w", dbPath, err)
	}

	// apply filter if specified
	if cfg.filter != "" {
		filtered := signatures.NewSignatureDB()
		for _, s := range db.Signatures {
			if strings.Contains(s.Name, cfg.filter) {
				filtered.Add(s)
			}
		}
		db = filtered
	}

	if db.Size() == 0 {
		return errSigEmptyDB
	}

	if err := signatures.SaveToFile(db, cfg.output); err != nil {
		return fmt.Errorf("failed to export database to %q: %w", cfg.output, err)
	}

	//nolint:errcheck // informational output
	fmt.Fprintf(stdout, "exported %d signatures to %s\n", db.Size(), cfg.output)
	return nil
}

// ============================================================================
// validate subcommand
// ============================================================================

// sigValidateConfig holds configuration for signatures validate subcommand.
type sigValidateConfig struct {
	strict bool
}

// validationIssue represents a single validation problem found in a signature.
type validationIssue struct {
	index   int
	name    string
	problem string
}

// runSigValidate validates the integrity of a signature database.
func runSigValidate(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("signatures validate", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := &sigValidateConfig{}
	fs.BoolVar(&cfg.strict, "strict", false, "treat warnings as errors")

	fs.Usage = func() {
		//nolint:errcheck // usage output is informational
		fmt.Fprint(stderr, "usage: sedec signatures validate [options] <db-file>\n\nvalidate the integrity of a signature database.\n")
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		return errSigNoDBPath
	}
	dbPath := remaining[0]

	db, err := signatures.LoadFromFile(dbPath)
	if err != nil {
		return fmt.Errorf("failed to load signature database %q: %w", dbPath, err)
	}

	issues := validateDB(db)

	if _, writeErr := fmt.Fprintf(stdout, "database: %s\n", dbPath); writeErr != nil {
		return fmt.Errorf("write error: %w", writeErr)
	}
	if _, writeErr := fmt.Fprintf(stdout, "format: %s\n", db.Format); writeErr != nil {
		return fmt.Errorf("write error: %w", writeErr)
	}
	if _, writeErr := fmt.Fprintf(stdout, "total signatures: %d\n", db.Size()); writeErr != nil {
		return fmt.Errorf("write error: %w", writeErr)
	}

	if len(issues) == 0 {
		if _, writeErr := fmt.Fprintln(stdout, "validation passed: no issues found"); writeErr != nil {
			return fmt.Errorf("write error: %w", writeErr)
		}
		return nil
	}

	if _, writeErr := fmt.Fprintf(stdout, "issues found: %d\n\n", len(issues)); writeErr != nil {
		return fmt.Errorf("write error: %w", writeErr)
	}

	for _, issue := range issues {
		if _, writeErr := fmt.Fprintf(stdout, "  [%d] %s: %s\n", issue.index, issue.name, issue.problem); writeErr != nil {
			return fmt.Errorf("write error: %w", writeErr)
		}
	}

	if cfg.strict {
		return fmt.Errorf("%w: %d issues in %s", errSigValidationFailed, len(issues), dbPath)
	}

	//nolint:errcheck // informational output
	fmt.Fprintf(stderr, "warning: %d validation issues found (use --strict to treat as error)\n", len(issues))
	return nil
}

// validateDB checks all signatures in the database for integrity issues.
func validateDB(db *signatures.SignatureDB) []validationIssue {
	var issues []validationIssue

	for i, sig := range db.Signatures {
		// check for empty name
		if sig.Name == "" {
			issues = append(issues, validationIssue{
				index:   i,
				name:    fmt.Sprintf("<unnamed#%d>", i),
				problem: "empty function name",
			})
		}

		// check for missing fingerprint and cfg hash (at least one required)
		if sig.Fingerprint == nil && sig.CFGHash == nil {
			issues = append(issues, validationIssue{
				index:   i,
				name:    sig.Name,
				problem: "no fingerprint and no cfg hash: signature cannot match anything",
			})
		}

		// check fingerprint integrity
		if sig.Fingerprint != nil {
			if len(sig.Fingerprint.Pattern) == 0 {
				issues = append(issues, validationIssue{
					index:   i,
					name:    sig.Name,
					problem: "fingerprint has empty pattern",
				})
			}
			if sig.Fingerprint.ByteLength <= 0 {
				issues = append(issues, validationIssue{
					index:   i,
					name:    sig.Name,
					problem: fmt.Sprintf("invalid byte length: %d", sig.Fingerprint.ByteLength),
				})
			}
		}

		// check cfg hash integrity
		if sig.CFGHash != nil {
			if sig.CFGHash.BlockCount < 0 {
				issues = append(issues, validationIssue{
					index:   i,
					name:    sig.Name,
					problem: fmt.Sprintf("negative block count: %d", sig.CFGHash.BlockCount),
				})
			}
			if sig.CFGHash.EdgeCount < 0 {
				issues = append(issues, validationIssue{
					index:   i,
					name:    sig.Name,
					problem: fmt.Sprintf("negative edge count: %d", sig.CFGHash.EdgeCount),
				})
			}
		}
	}

	return issues
}

// ============================================================================
// usage
// ============================================================================

// printSignaturesUsage prints help for the signatures command.
func printSignaturesUsage(w io.Writer) {
	//nolint:errcheck // usage output is informational
	fmt.Fprint(w, `usage: sedec signatures <subcommand> [options]

manage and inspect signature databases for library function recognition.

subcommands:
  list      list signatures in a database file
  import    import signatures from FLIRT or FID files
  export    export a database to native JSON format
  validate  validate the integrity of a database

examples:
  # list all signatures in a database
  sedec signatures list libc.json

  # list with name filter
  sedec signatures list --filter mem libc.json

  # import from FLIRT .pat file
  sedec signatures import --import-flirt libc.pat --output libc.json

  # import from Ghidra FID .fidb file
  sedec signatures import --import-fid libc.fidb --output libc.json

  # import both and merge
  sedec signatures import --import-flirt libc.pat --import-fid libc.fidb --output merged.json

  # merge into existing database
  sedec signatures import --import-flirt extra.pat --merge --output libc.json

  # export with filter
  sedec signatures export --filter mem --output mem_funcs.json libc.json

  # validate database integrity
  sedec signatures validate libc.json

  # validate with strict mode (exit non-zero on warnings)
  sedec signatures validate --strict libc.json

run 'sedec signatures <subcommand> --help' for subcommand-specific options.
`)
}

// FingerprintSimilarity computes Jaccard similarity between two fingerprints.
// exposed here for use in validate output; the real implementation is in pkg/signatures.
func FingerprintSimilarity(a, b *signatures.FunctionFingerprint) float64 {
	if a == nil || b == nil || len(a.Pattern) == 0 || len(b.Pattern) == 0 {
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
	matches := 0
	for i := 0; i < minLen; i++ {
		if a.Pattern[i].IsWild || b.Pattern[i].IsWild {
			matches++ // wildcards always match
			continue
		}
		if a.Pattern[i].Value == b.Pattern[i].Value {
			matches++
		}
	}
	return float64(matches) / float64(maxLen)
}

// CFGHashSimilarity computes structural similarity between two CFG hashes.
func CFGHashSimilarity(a, b *signatures.CFGHash) float64 {
	if a == nil || b == nil {
		return 0.0
	}
	if a.Hash64 == b.Hash64 {
		return 1.0
	}
	// partial similarity based on block/edge counts
	blockSim := 0.0
	if a.BlockCount > 0 && b.BlockCount > 0 {
		diff := a.BlockCount - b.BlockCount
		if diff < 0 {
			diff = -diff
		}
		maxBlocks := a.BlockCount
		if b.BlockCount > maxBlocks {
			maxBlocks = b.BlockCount
		}
		blockSim = 1.0 - float64(diff)/float64(maxBlocks)
	}
	return blockSim * 0.5
}

// ensure unused import is used (os is used in runSigExport via os.Create indirectly through SaveToFile)
var _ = os.Stderr
