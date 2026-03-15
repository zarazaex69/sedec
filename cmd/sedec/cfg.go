// Package main implements the sedec command-line tool for binary analysis and decompilation.
//
//nolint:godot // CLI tool with many error messages
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	binfmt "github.com/zarazaex69/sedec/pkg/binary"
	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/disasm"
)

const (
	// helpFlagLong is the long form help flag.
	helpFlagLong = "--help"
	// helpFlagShort is the short form help flag.
	helpFlagShort = "-help"
	// helpFlagShortest is the shortest form help flag.
	helpFlagShortest = "-h"
	// flag constants for cfg command
	flagOutput         = "--output"
	flagOutputShort    = "-o"
	flagFunction       = "--function"
	flagFunctionShort  = "-f"
	flagAddress        = "--address"
	flagAddressShort   = "-a"
	flagNoInstructions = "--no-instructions"
	flagNoAddresses    = "--no-addresses"
	flagNoMetadata     = "--no-metadata"
	flagNoEdgeLabels   = "--no-edge-labels"
	flagShowProvenance = "--show-provenance"
)

var (
	// errUnknownStringFlag indicates an unknown string flag was provided.
	errUnknownStringFlag = errors.New("unknown string flag")
	// errFlagRequiresArgument indicates a flag requires an argument.
	errFlagRequiresArgument = errors.New("flag requires an argument")
	// errUnknownFlag indicates an unknown flag was provided.
	errUnknownFlag = errors.New("unknown flag")
	// errMultipleBinaryPaths indicates multiple binary paths were specified.
	errMultipleBinaryPaths = errors.New("multiple binary paths specified")
	// errNoInput indicates no input was provided.
	errNoInput = errors.New("no input provided (use binary path or pipe to stdin)")
	// errNoInstructions indicates no instructions were disassembled.
	errNoInstructions = errors.New("no instructions disassembled")
	// errInvalidAddressFormat indicates invalid address format.
	errInvalidAddressFormat = errors.New("invalid address format (use 0x1234 or decimal)")
	// errAddressNotFound indicates address not found in executable section.
	errAddressNotFound = errors.New("address not found in any executable section")
	// errFunctionNotFound indicates function not found.
	errFunctionNotFound = errors.New("function not found")
	// errFunctionAddressNotFound indicates function address not found in executable section.
	errFunctionAddressNotFound = errors.New("function address not found in any executable section")
	// errNoExecutableSection indicates no executable section found.
	errNoExecutableSection = errors.New("no executable section found in binary")
)

// cfgFlags holds command-line flags for cfg command.
type cfgFlags struct {
	output              string
	function            string
	address             string
	size                uint64
	includeInstructions bool
	includeAddresses    bool
	includeMetadata     bool
	showEdgeLabels      bool
	showProvenance      bool
	maxInstructions     int
}

// runCFG executes the cfg subcommand
func runCFG(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags, binaryPath, err := parseCFGFlags(args, stdout)
	if err != nil {
		return err
	}

	// check if help was printed (only when explicitly requested with --help flag)
	// this is detected by checking if args contained help flag
	for _, arg := range args {
		if arg == helpFlagLong || arg == helpFlagShort || arg == helpFlagShortest {
			return nil
		}
	}

	binaryData, err := readBinaryInput(binaryPath, stdin)
	if err != nil {
		return err
	}

	binaryInfo, err := parseBinary(binaryData)
	if err != nil {
		return err
	}

	disassembler, err := createDisassembler()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := disassembler.Close(); closeErr != nil {
			_, _ = fmt.Fprintf(stderr, "warning: failed to close disassembler: %v\n", closeErr)
		}
	}()

	instructions, startAddr, endAddr, err := disassembleCode(disassembler, binaryInfo, flags)
	if err != nil {
		return err
	}

	controlFlowGraph, err := buildCFG(instructions)
	if err != nil {
		return err
	}

	return exportCFG(controlFlowGraph, flags, startAddr, endAddr, stdout, stderr)
}

// parseCFGFlags parses command-line flags for cfg command
func parseCFGFlags(args []string, stdout io.Writer) (flags cfgFlags, binaryPath string, err error) {
	flags = cfgFlags{
		output:              "",
		function:            "",
		address:             "",
		size:                0,
		includeInstructions: true,
		includeAddresses:    true,
		includeMetadata:     true,
		showEdgeLabels:      true,
		showProvenance:      false,
		maxInstructions:     10,
	}

	binaryPath, err = parseArguments(args, &flags, stdout)
	return flags, binaryPath, err
}

// parseArguments processes command-line arguments and updates flags
func parseArguments(args []string, flags *cfgFlags, stdout io.Writer) (string, error) {
	var binaryPath string

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case helpFlagLong, helpFlagShort, helpFlagShortest:
			printCFGUsage(stdout)
			return "", nil

		case flagOutput, flagOutputShort, flagFunction, flagFunctionShort, flagAddress, flagAddressShort:
			nextArg, err := getNextArgument(args, i, arg)
			if err != nil {
				return "", err
			}
			i++
			if setErr := setStringFlag(flags, arg, nextArg); setErr != nil {
				return "", setErr
			}

		case "--size", "-s":
			nextArg, err := getNextArgument(args, i, "--size")
			if err != nil {
				return "", err
			}
			i++
			if _, scanErr := fmt.Sscanf(nextArg, "%d", &flags.size); scanErr != nil {
				return "", fmt.Errorf("invalid --size value: %w", scanErr)
			}

		case "--max-instructions":
			nextArg, err := getNextArgument(args, i, "--max-instructions")
			if err != nil {
				return "", err
			}
			i++
			var maxInstr int
			if _, scanErr := fmt.Sscanf(nextArg, "%d", &maxInstr); scanErr != nil {
				return "", fmt.Errorf("invalid --max-instructions value: %w", scanErr)
			}
			flags.maxInstructions = maxInstr

		case flagNoInstructions, flagNoAddresses, flagNoMetadata, flagNoEdgeLabels, flagShowProvenance:
			setBooleanFlag(flags, arg)

		default:
			path, err := handlePositionalArgument(arg, binaryPath)
			if err != nil {
				return "", err
			}
			binaryPath = path
		}
	}

	return binaryPath, nil
}

// setStringFlag sets string flag values based on flag name
func setStringFlag(flags *cfgFlags, flagName, value string) error {
	switch flagName {
	case flagOutput, flagOutputShort:
		flags.output = value
	case flagFunction, flagFunctionShort:
		flags.function = value
	case flagAddress, flagAddressShort:
		flags.address = value
	default:
		return fmt.Errorf("%w: %s", errUnknownStringFlag, flagName)
	}
	return nil
}

// setBooleanFlag sets boolean flag values based on flag name
func setBooleanFlag(flags *cfgFlags, flagName string) {
	switch flagName {
	case flagNoInstructions:
		flags.includeInstructions = false
	case flagNoAddresses:
		flags.includeAddresses = false
	case flagNoMetadata:
		flags.includeMetadata = false
	case flagNoEdgeLabels:
		flags.showEdgeLabels = false
	case flagShowProvenance:
		flags.showProvenance = true
	}
}

// getNextArgument retrieves the next argument for a flag
func getNextArgument(args []string, currentIndex int, flagName string) (string, error) {
	if currentIndex+1 >= len(args) {
		return "", fmt.Errorf("%w: %s", errFlagRequiresArgument, flagName)
	}
	return args[currentIndex+1], nil
}

// handlePositionalArgument processes non-flag arguments
func handlePositionalArgument(arg, currentPath string) (string, error) {
	if arg[0] == '-' {
		return "", fmt.Errorf("%w: %s", errUnknownFlag, arg)
	}
	if currentPath != "" {
		return "", errMultipleBinaryPaths
	}
	return arg, nil
}

// readBinaryInput reads binary data from file or stdin
func readBinaryInput(binaryPath string, stdin io.Reader) ([]byte, error) {
	if binaryPath == "" {
		// read from stdin
		binaryData, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("failed to read from stdin: %w", err)
		}
		if len(binaryData) == 0 {
			return nil, errNoInput
		}
		return binaryData, nil
	}

	// read from file
	//nolint:gosec // G703: file path from user input is expected
	binaryData, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read binary file: %w", err)
	}
	return binaryData, nil
}

// parseBinary parses binary data into binary info structure
func parseBinary(binaryData []byte) (*binfmt.BinaryInfo, error) {
	parser := binfmt.NewStandardLibParser()
	binaryInfo, err := parser.Parse(binaryData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse binary: %w", err)
	}
	return binaryInfo, nil
}

// createDisassembler creates and initializes disassembler
func createDisassembler() (*disasm.Disassembler, error) {
	disassembler, err := disasm.NewDisassembler()
	if err != nil {
		return nil, fmt.Errorf("failed to create disassembler: %w", err)
	}
	return disassembler, nil
}

// disassembleCode disassembles code based on flags
func disassembleCode(disassembler *disasm.Disassembler, binaryInfo *binfmt.BinaryInfo, flags cfgFlags) (instructions []*disasm.Instruction, startAddr, endAddr disasm.Address, err error) {
	var codeBytes []byte

	switch {
	case flags.address != "":
		startAddr, endAddr, codeBytes, err = extractCodeByAddress(binaryInfo, flags)
	case flags.function != "":
		startAddr, endAddr, codeBytes, err = extractCodeByFunction(binaryInfo, flags)
	default:
		startAddr, endAddr, codeBytes, err = extractCodeFromFirstSection(binaryInfo)
	}

	if err != nil {
		return nil, 0, 0, err
	}

	// disassemble instructions
	instructions, err = disassembler.DisassembleBytes(codeBytes, startAddr)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to disassemble: %w", err)
	}

	if len(instructions) == 0 {
		return nil, 0, 0, errNoInstructions
	}

	return instructions, startAddr, endAddr, nil
}

// extractCodeByAddress extracts code bytes at specified address
func extractCodeByAddress(binaryInfo *binfmt.BinaryInfo, flags cfgFlags) (startAddr, endAddr disasm.Address, codeBytes []byte, err error) {
	// parse address (hex format: 0x1234 or 1234)
	var addr uint64
	if _, scanErr := fmt.Sscanf(flags.address, "0x%x", &addr); scanErr != nil {
		if _, decScanErr := fmt.Sscanf(flags.address, "%d", &addr); decScanErr != nil {
			return 0, 0, nil, fmt.Errorf("%w: %s", errInvalidAddressFormat, flags.address)
		}
	}
	startAddr = disasm.Address(addr)

	// determine size
	if flags.size > 0 {
		endAddr = startAddr + disasm.Address(flags.size)
	} else {
		// default: analyze 1KB
		endAddr = startAddr + 1024
	}

	// find section containing this address
	containingSection := findExecutableSection(binaryInfo, startAddr)
	if containingSection == nil {
		return 0, 0, nil, fmt.Errorf("%w: 0x%x", errAddressNotFound, startAddr)
	}

	codeBytes, actualEndAddr := extractBytesFromSection(containingSection, startAddr, endAddr)
	return startAddr, actualEndAddr, codeBytes, nil
}

// extractCodeByFunction extracts code bytes for specified function
func extractCodeByFunction(binaryInfo *binfmt.BinaryInfo, flags cfgFlags) (startAddr, endAddr disasm.Address, codeBytes []byte, err error) {
	// find function by name
	found := false
	for _, sym := range binaryInfo.Symbols {
		if sym.Name == flags.function {
			startAddr = disasm.Address(sym.Address)
			endAddr = disasm.Address(sym.Address) + disasm.Address(sym.Size)
			found = true
			break
		}
	}
	if !found {
		return 0, 0, nil, fmt.Errorf("%w: %s", errFunctionNotFound, flags.function)
	}

	// find section containing this function
	containingSection := findExecutableSection(binaryInfo, startAddr)
	if containingSection == nil {
		return 0, 0, nil, fmt.Errorf("%w: 0x%x", errFunctionAddressNotFound, startAddr)
	}

	codeBytes, actualEndAddr := extractBytesFromSection(containingSection, startAddr, endAddr)
	return startAddr, actualEndAddr, codeBytes, nil
}

// extractCodeFromFirstSection extracts code from first executable section
func extractCodeFromFirstSection(binaryInfo *binfmt.BinaryInfo) (startAddr, endAddr disasm.Address, codeBytes []byte, err error) {
	// no function specified - use first executable section
	var execSection *binfmt.Section
	for i := range binaryInfo.Sections {
		if binaryInfo.Sections[i].IsExecutable {
			execSection = binaryInfo.Sections[i]
			break
		}
	}

	if execSection == nil {
		return 0, 0, nil, errNoExecutableSection
	}

	startAddr = disasm.Address(execSection.Address)
	endAddr = disasm.Address(execSection.Address) + disasm.Address(len(execSection.Data))
	codeBytes = execSection.Data
	return startAddr, endAddr, codeBytes, nil
}

// findExecutableSection finds executable section containing given address
func findExecutableSection(binaryInfo *binfmt.BinaryInfo, addr disasm.Address) *binfmt.Section {
	for i := range binaryInfo.Sections {
		sec := binaryInfo.Sections[i]
		if !sec.IsExecutable {
			continue
		}
		secStart := disasm.Address(sec.Address)
		secEnd := disasm.Address(sec.Address) + disasm.Address(len(sec.Data))
		if addr >= secStart && addr < secEnd {
			return sec
		}
	}
	return nil
}

// extractBytesFromSection extracts bytes from section within address range
func extractBytesFromSection(section *binfmt.Section, startAddr, endAddr disasm.Address) ([]byte, disasm.Address) {
	// calculate offset within section
	offset := startAddr - disasm.Address(section.Address)
	length := endAddr - startAddr

	if offset >= disasm.Address(len(section.Data)) {
		return nil, startAddr
	}

	if offset+length > disasm.Address(len(section.Data)) {
		length = disasm.Address(len(section.Data)) - offset
		endAddr = startAddr + length
	}

	return section.Data[offset : offset+length], endAddr
}

// buildCFG builds control flow graph from instructions
func buildCFG(instructions []*disasm.Instruction) (*cfg.CFG, error) {
	builder := cfg.NewCFGBuilder()
	controlFlowGraph, err := builder.Build(instructions)
	if err != nil {
		return nil, fmt.Errorf("failed to build cfg: %w", err)
	}
	return controlFlowGraph, nil
}

// exportCFG exports control flow graph to dot format
func exportCFG(controlFlowGraph *cfg.CFG, flags cfgFlags, startAddr, endAddr disasm.Address, stdout, stderr io.Writer) error {
	// prepare dot export options
	dotOpts := &cfg.DotExportOptions{
		IncludeInstructions: flags.includeInstructions,
		IncludeAddresses:    flags.includeAddresses,
		IncludeMetadata:     flags.includeMetadata,
		ShowEdgeLabels:      flags.showEdgeLabels,
		ShowProvenance:      flags.showProvenance,
		MaxInstructionsShow: flags.maxInstructions,
	}

	// determine output destination
	var output io.Writer
	if flags.output == "" {
		output = stdout
	} else {
		file, createErr := os.Create(flags.output)
		if createErr != nil {
			return fmt.Errorf("failed to create output file: %w", createErr)
		}
		defer func() {
			if closeErr := file.Close(); closeErr != nil {
				_, _ = fmt.Fprintf(stderr, "warning: failed to close output file: %v\n", closeErr)
			}
		}()
		output = file
	}

	// export to dot format
	if exportErr := controlFlowGraph.ExportToDOT(output, dotOpts); exportErr != nil {
		return fmt.Errorf("failed to export cfg to dot: %w", exportErr)
	}

	// print statistics to stderr if output is file
	if flags.output != "" {
		printStatistics(stderr, flags.output, startAddr, endAddr, controlFlowGraph)
	}

	return nil
}

// printStatistics prints cfg statistics to stderr
//

func printStatistics(stderr io.Writer, outputFile string, startAddr, endAddr disasm.Address, controlFlowGraph *cfg.CFG) {
	_, _ = fmt.Fprintf(stderr, "cfg exported to %s\n", outputFile)
	_, _ = fmt.Fprintf(stderr, "address range: 0x%x - 0x%x (%d bytes)\n",
		startAddr, endAddr, endAddr-startAddr)
	_, _ = fmt.Fprintf(stderr, "blocks: %d, edges: %d, unresolved jumps: %d\n",
		controlFlowGraph.BlockCount(),
		controlFlowGraph.EdgeCount(),
		controlFlowGraph.UnresolvedIndirectJumpCount())
}

// printCFGUsage displays help information for cfg command
func printCFGUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `sedec cfg - export control flow graph in dot format

usage:
  sedec cfg [options] [binary]
  sedec cfg --help

options:
  --output, -o <file>        write output to file (default: stdout)
  --function, -f <name>      analyze specific function by name
  --address, -a <addr>       analyze code at specific address (hex: 0x1234 or decimal)
  --size, -s <bytes>         number of bytes to analyze from address (default: 1024)
  --no-instructions          exclude instruction listings from nodes
  --no-addresses             exclude virtual addresses from labels
  --no-metadata              exclude block metadata (instruction counts, entry/exit markers)
  --no-edge-labels           exclude edge type labels
  --show-provenance          show edge provenance information (analysis pass, confidence)
  --max-instructions <n>     maximum instructions to show per block (default: 10, 0 = all)
  --help, -h                 print this help message

output format:
  the command generates graphviz dot format output that can be visualized using:
    dot -Tpng cfg.dot -o cfg.png
    dot -Tsvg cfg.dot -o cfg.svg
    xdot cfg.dot  (interactive viewer)

examples:
  # export entire binary cfg to file
  sedec cfg --output cfg.dot /bin/ls

  # export specific function
  sedec cfg --function main --output main.dot /bin/ls

  # analyze code at specific address (for stripped binaries)
  sedec cfg --address 0x1234 --size 512 --output cfg.dot /bin/cat

  # analyze entry point
  sedec cfg --address 0x2000 /bin/cat > cfg.dot

  # minimal output (no instructions, no metadata)
  sedec cfg --no-instructions --no-metadata /bin/ls > cfg.dot

  # show all instructions per block
  sedec cfg --max-instructions 0 /bin/ls > cfg.dot

  # read from stdin and visualize immediately
  cat /bin/ls | sedec cfg | dot -Tpng > cfg.png

  # show edge provenance for debugging
  sedec cfg --show-provenance --output cfg.dot /bin/ls

visualization:
  install graphviz to visualize dot files:
    ubuntu/debian: sudo apt-get install graphviz
    macos: brew install graphviz
    fedora: sudo dnf install graphviz

node colors:
  - light green: entry block
  - light coral: exit block
  - light blue: regular block
  - orange diamond: unresolved indirect jump

edge colors:
  - black: fallthrough
  - blue: unconditional jump
  - green: conditional branch
  - purple: function call
  - red: return
  - orange: indirect jump
`)
}
