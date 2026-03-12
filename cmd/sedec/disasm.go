//nolint:godot // CLI tool with many error messages
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	binfmt "github.com/zarazaex69/sedec/pkg/binary"
	"github.com/zarazaex69/sedec/pkg/disasm"
)

var (
	// errInvalidFormat indicates invalid assembly format
	errInvalidFormat = errors.New("invalid format (supported: att, intel)")
	// errNoInputProvided indicates no input was provided
	errNoInputProvided = errors.New("no input provided (stdin is empty and no file specified)")
	// errFileNotFound indicates file not found
	errFileNotFound = errors.New("file not found")
	// errTooManyArguments indicates too many arguments
	errTooManyArguments = errors.New("too many arguments (expected 0 or 1)")
	// errDisasmFunctionNotFound indicates function not found
	errDisasmFunctionNotFound = errors.New("function not found (not a valid name or hex address)")
	// errAddressNotInSection indicates address not found in any section
	errAddressNotInSection = errors.New("address not found in any section")
	// errAddressExceedsBounds indicates address exceeds section bounds
	errAddressExceedsBounds = errors.New("address exceeds section bounds")
	// errNoExecutableSections indicates no executable sections found
	errNoExecutableSections = errors.New("no executable sections found in binary")
)

// disasmConfig holds configuration for disasm subcommand
type disasmConfig struct {
	function string
	output   string
	format   string
}

// runDisasm executes the disasm subcommand
func runDisasm(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	// create flagset for disasm subcommand
	fs := flag.NewFlagSet("disasm", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := &disasmConfig{}

	// define flags
	fs.StringVar(&cfg.function, "function", "", "disassemble specific function by name or address (hex: 0x1234)")
	fs.StringVar(&cfg.output, "output", "", "output file path (default: stdout)")
	fs.StringVar(&cfg.format, "format", "att", "assembly syntax format: att or intel (default: att)")

	// custom usage function
	fs.Usage = func() {
		// usage output to stderr - ignore errors as this is informational
		//nolint:errcheck // usage output is informational, errors are non-critical
		fmt.Fprint(stderr, `usage: sedec disasm [options] [binary]

disassemble binary executable to assembly output.

options:
  --function <name|addr>    disassemble specific function by name or address
                            address format: 0x1234 (hexadecimal)
                            example: --function main
                            example: --function 0x401000

  --output <file>           write output to file instead of stdout
                            example: --output output.asm

  --format <fmt>            assembly syntax format (default: att)
                            supported: att, intel
                            example: --format intel

arguments:
  binary                    path to binary file to disassemble
                            if omitted, reads from stdin for pipeline composition

examples:
  # disassemble entire binary
  sedec disasm /bin/ls

  # disassemble specific function
  sedec disasm --function main /bin/ls

  # output to file with intel syntax
  sedec disasm --format intel --output out.asm /bin/ls

  # read from stdin (pipeline composition)
  cat /bin/ls | sedec disasm

  # disassemble function at specific address
  sedec disasm --function 0x401000 /bin/ls
`)
	}

	// parse flags
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	// validate format flag
	if cfg.format != "att" && cfg.format != "intel" {
		return fmt.Errorf("%w: %s", errInvalidFormat, cfg.format)
	}

	// determine input source: file or stdin
	var inputData []byte
	var err error

	remainingArgs := fs.Args()

	switch {
	case len(remainingArgs) == 0:
		// read from stdin
		inputData, err = io.ReadAll(stdin)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
		if len(inputData) == 0 {
			return errNoInputProvided
		}
	case len(remainingArgs) == 1:
		// read from file
		binaryPath := remainingArgs[0]
		//nolint:gosec // G304: file path is user-provided CLI argument, expected behavior for disassembler tool
		inputData, err = os.ReadFile(binaryPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("%w: %s", errFileNotFound, binaryPath)
			}
			return fmt.Errorf("failed to read file %s: %w", binaryPath, err)
		}
	default:
		return fmt.Errorf("%w, got %d", errTooManyArguments, len(remainingArgs))
	}

	// determine output destination
	var output io.Writer
	var outputFile *os.File

	if cfg.output != "" {
		outputFile, err = os.Create(cfg.output)
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", cfg.output, err)
		}
		defer func() {
			if closeErr := outputFile.Close(); closeErr != nil {
				err = closeErr
			}
		}()
		output = outputFile
	} else {
		output = stdout
	}

	// execute disassembly
	return executeDisasm(inputData, cfg, output, stderr)
}

// executeDisasm performs the actual disassembly operation
func executeDisasm(data []byte, cfg *disasmConfig, output, stderr io.Writer) error {
	// parse binary format
	parser := binfmt.NewStandardLibParser()
	binaryInfo, err := parser.Parse(data)
	if err != nil {
		return fmt.Errorf("failed to parse binary: %w", err)
	}

	// create disassembler
	disassembler, err := disasm.NewDisassembler()
	if err != nil {
		return fmt.Errorf("failed to initialize disassembler: %w", err)
	}
	defer func() {
		if closeErr := disassembler.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	// print binary information header
	if _, writeErr := fmt.Fprintf(output, "; sedec disassembly output\n"); writeErr != nil {
		return fmt.Errorf("failed to write output: %w", writeErr)
	}

	if _, writeErr := fmt.Fprintf(output, "; format: %s\n", binaryInfo.Format); writeErr != nil {
		return fmt.Errorf("failed to write output: %w", writeErr)
	}

	if _, writeErr := fmt.Fprintf(output, "; architecture: %s\n", binaryInfo.Architecture); writeErr != nil {
		return fmt.Errorf("failed to write output: %w", writeErr)
	}

	if _, writeErr := fmt.Fprintf(output, "; entry point: 0x%x\n", binaryInfo.EntryPoint); writeErr != nil {
		return fmt.Errorf("failed to write output: %w", writeErr)
	}
	if _, writeErr := fmt.Fprintf(output, "; syntax: %s\n", cfg.format); writeErr != nil {
		return fmt.Errorf("failed to write output: %w", writeErr)
	}
	if _, writeErr := fmt.Fprintf(output, "\n"); writeErr != nil {
		return fmt.Errorf("failed to write output: %w", writeErr)
	}

	// if specific function requested, disassemble only that function
	if cfg.function != "" {
		return disassembleFunction(binaryInfo, disassembler, cfg.function, cfg.format, output, stderr)
	}

	// otherwise, disassemble all executable sections
	return disassembleAllSections(binaryInfo, disassembler, cfg.format, output, stderr)
}

// functionTarget represents a resolved function target
type functionTarget struct {
	name    string
	address disasm.Address
}

// resolveFunctionTarget resolves function specification to address and name
func resolveFunctionTarget(binaryInfo *binfmt.BinaryInfo, functionSpec string) (*functionTarget, error) {
	// try to find function by name first
	if target := findFunctionByName(binaryInfo, functionSpec); target != nil {
		return target, nil
	}

	// if not found by name, try parsing as hex address
	return parseFunctionAddress(functionSpec)
}

// findFunctionByName searches for function in symbol table
func findFunctionByName(binaryInfo *binfmt.BinaryInfo, name string) *functionTarget {
	for _, sym := range binaryInfo.Symbols {
		if sym.Name == name && sym.Type == binfmt.SymbolTypeFunction {
			return &functionTarget{
				address: disasm.Address(sym.Address),
				name:    sym.Name,
			}
		}
	}
	return nil
}

// parseFunctionAddress parses hex address from string
func parseFunctionAddress(spec string) (*functionTarget, error) {
	var addr uint64
	_, err := fmt.Sscanf(spec, "0x%x", &addr)
	if err != nil {
		// try without 0x prefix
		_, err = fmt.Sscanf(spec, "%x", &addr)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", errDisasmFunctionNotFound, spec)
		}
	}
	return &functionTarget{
		address: disasm.Address(addr),
		name:    fmt.Sprintf("sub_%x", addr),
	}, nil
}

// findSectionForAddress finds section containing given address
func findSectionForAddress(binaryInfo *binfmt.BinaryInfo, address disasm.Address) (*binfmt.Section, error) {
	for _, section := range binaryInfo.Sections {
		if section.Address <= binfmt.Address(address) &&
			binfmt.Address(address) < section.Address+binfmt.Address(section.Size) {
			return section, nil
		}
	}
	return nil, fmt.Errorf("%w: 0x%x", errAddressNotInSection, address)
}

// calculateSectionOffset calculates offset within section and validates bounds
func calculateSectionOffset(section *binfmt.Section, address disasm.Address) (uint64, error) {
	offset := uint64(address) - uint64(section.Address)
	if offset >= uint64(len(section.Data)) {
		return 0, fmt.Errorf("%w: 0x%x", errAddressExceedsBounds, address)
	}
	return offset, nil
}

// writeFunctionHeader writes function information header to output
func writeFunctionHeader(output io.Writer, functionName string, address disasm.Address) error {
	if _, writeErr := fmt.Fprintf(output, "; function: %s\n", functionName); writeErr != nil {
		return fmt.Errorf("failed to write output: %w", writeErr)
	}

	if _, writeErr := fmt.Fprintf(output, "; address: 0x%x\n", address); writeErr != nil {
		return fmt.Errorf("failed to write output: %w", writeErr)
	}
	if _, writeErr := fmt.Fprintf(output, "\n"); writeErr != nil {
		return fmt.Errorf("failed to write output: %w", writeErr)
	}
	return nil
}

// disassembleFunction disassembles a specific function by name or address
//
// disassembleFunction disassembles a specific function by name or address
func disassembleFunction(binaryInfo *binfmt.BinaryInfo, disassembler *disasm.Disassembler, functionSpec, format string, output, _ io.Writer) error {
	// resolve function target (name or address)
	target, err := resolveFunctionTarget(binaryInfo, functionSpec)
	if err != nil {
		return err
	}

	// find section containing target address
	section, err := findSectionForAddress(binaryInfo, target.address)
	if err != nil {
		return err
	}

	// calculate offset within section
	offset, err := calculateSectionOffset(section, target.address)
	if err != nil {
		return err
	}

	// write function header
	if writeErr := writeFunctionHeader(output, target.name, target.address); writeErr != nil {
		return writeErr
	}

	// disassemble function
	instructions, err := disassembler.DisassembleFunction(section.Data[offset:], target.address)
	if err != nil {
		return fmt.Errorf("failed to disassemble function %s: %w", target.name, err)
	}

	// print instructions
	return printInstructions(instructions, format, output)
}

// disassembleAllSections disassembles all executable sections
func disassembleAllSections(binaryInfo *binfmt.BinaryInfo, disassembler *disasm.Disassembler, format string, output, stderr io.Writer) error {
	executableSections := 0

	for _, section := range binaryInfo.Sections {
		// only disassemble executable sections
		if !section.IsExecutable {
			continue
		}

		executableSections++

		if _, writeErr := fmt.Fprintf(output, "; section: %s\n", section.Name); writeErr != nil {
			return fmt.Errorf("failed to write output: %w", writeErr)
		}

		if _, writeErr := fmt.Fprintf(output, "; address: 0x%x\n", section.Address); writeErr != nil {
			return fmt.Errorf("failed to write output: %w", writeErr)
		}

		if _, writeErr := fmt.Fprintf(output, "; size: %d bytes\n", section.Size); writeErr != nil {
			return fmt.Errorf("failed to write output: %w", writeErr)
		}
		if _, writeErr := fmt.Fprintf(output, "\n"); writeErr != nil {
			return fmt.Errorf("failed to write output: %w", writeErr)
		}

		// disassemble section
		instructions, err := disassembler.DisassembleBytes(section.Data, disasm.Address(section.Address))
		if err != nil {
			// log warning but continue with other sections
			//nolint:errcheck // warning output is informational, section name is from trusted parser
			fmt.Fprintf(stderr, "warning: failed to disassemble section %s: %v\n", section.Name, err)
			continue
		}

		// print instructions
		if printErr := printInstructions(instructions, format, output); printErr != nil {
			return printErr
		}

		if _, writeErr := fmt.Fprintf(output, "\n"); writeErr != nil {
			return fmt.Errorf("failed to write output: %w", writeErr)
		}
	}

	if executableSections == 0 {
		return errNoExecutableSections
	}

	return nil
}

// printInstructions formats and prints disassembled instructions
func printInstructions(instructions []*disasm.Instruction, format string, output io.Writer) error {
	for _, instr := range instructions {
		// format address
		addrStr := fmt.Sprintf("0x%016x", instr.Address)

		// format bytes (hex representation)
		bytesStr := ""
		for _, b := range instr.Bytes {
			bytesStr += fmt.Sprintf("%02x ", b)
		}
		// pad to consistent width (max 15 bytes for x86_64)
		for len(bytesStr) < 45 {
			bytesStr += " "
		}

		// format instruction
		instrStr := formatInstruction(instr, format)

		// print line: address | bytes | instruction

		if _, writeErr := fmt.Fprintf(output, "%s  %s  %s\n", addrStr, bytesStr, instrStr); writeErr != nil {
			return fmt.Errorf("failed to write output: %w", writeErr)
		}
	}

	return nil
}

// formatInstruction formats instruction based on syntax format
func formatInstruction(instr *disasm.Instruction, _ string) string {
	// for now, both att and intel use the same basic format
	// in future, this can be extended to handle syntax differences
	// (operand order, register prefixes, etc.)

	if len(instr.Operands) == 0 {
		return instr.Mnemonic
	}

	operandsStr := ""
	for i, operand := range instr.Operands {
		if i > 0 {
			operandsStr += ", "
		}
		operandsStr += operand.String()
	}

	return fmt.Sprintf("%s %s", instr.Mnemonic, operandsStr)
}
