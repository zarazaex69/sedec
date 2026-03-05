package main

import (
	"fmt"
	"io"
	"os"

	binfmt "github.com/zarazaex69/sedec/pkg/binary"
	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/disasm"
)

// cfgFlags holds command-line flags for cfg command
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
	flags := cfgFlags{
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

	// parse flags
	var binaryPath string
	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "--help", "-help", "-h":
			printCFGUsage(stdout)
			return nil

		case "--output", "-o":
			if i+1 >= len(args) {
				return fmt.Errorf("--output requires an argument")
			}
			i++
			flags.output = args[i]

		case "--function", "-f":
			if i+1 >= len(args) {
				return fmt.Errorf("--function requires an argument")
			}
			i++
			flags.function = args[i]

		case "--address", "-a":
			if i+1 >= len(args) {
				return fmt.Errorf("--address requires an argument")
			}
			i++
			flags.address = args[i]

		case "--size", "-s":
			if i+1 >= len(args) {
				return fmt.Errorf("--size requires an argument")
			}
			i++
			if _, err := fmt.Sscanf(args[i], "%d", &flags.size); err != nil {
				return fmt.Errorf("invalid --size value: %v", err)
			}

		case "--no-instructions":
			flags.includeInstructions = false

		case "--no-addresses":
			flags.includeAddresses = false

		case "--no-metadata":
			flags.includeMetadata = false

		case "--no-edge-labels":
			flags.showEdgeLabels = false

		case "--show-provenance":
			flags.showProvenance = true

		case "--max-instructions":
			if i+1 >= len(args) {
				return fmt.Errorf("--max-instructions requires an argument")
			}
			i++
			var maxInstr int
			if _, err := fmt.Sscanf(args[i], "%d", &maxInstr); err != nil {
				return fmt.Errorf("invalid --max-instructions value: %v", err)
			}
			flags.maxInstructions = maxInstr

		default:
			if arg[0] == '-' {
				return fmt.Errorf("unknown flag: %s", arg)
			}
			if binaryPath != "" {
				return fmt.Errorf("multiple binary paths specified")
			}
			binaryPath = arg
		}
	}

	// read binary data
	var binaryData []byte
	var err error

	if binaryPath == "" {
		// read from stdin
		binaryData, err = io.ReadAll(stdin)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
		if len(binaryData) == 0 {
			return fmt.Errorf("no input provided (use binary path or pipe to stdin)")
		}
	} else {
		// read from file
		binaryData, err = os.ReadFile(binaryPath)
		if err != nil {
			return fmt.Errorf("failed to read binary file: %w", err)
		}
	}

	// parse binary
	parser := binfmt.NewStandardLibParser()
	binaryInfo, err := parser.Parse(binaryData)
	if err != nil {
		return fmt.Errorf("failed to parse binary: %w", err)
	}

	// disassemble
	disassembler, err := disasm.NewDisassembler()
	if err != nil {
		return fmt.Errorf("failed to create disassembler: %w", err)
	}
	defer disassembler.Close()

	// determine disassembly range
	var startAddr, endAddr disasm.Address
	var codeBytes []byte

	if flags.address != "" {
		// parse address (hex format: 0x1234 or 1234)
		var addr uint64
		if _, err := fmt.Sscanf(flags.address, "0x%x", &addr); err != nil {
			if _, err := fmt.Sscanf(flags.address, "%d", &addr); err != nil {
				return fmt.Errorf("invalid address format: %s (use 0x1234 or decimal)", flags.address)
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
		var containingSection *binfmt.Section
		for i := range binaryInfo.Sections {
			sec := binaryInfo.Sections[i]
			if !sec.IsExecutable {
				continue
			}
			secStart := disasm.Address(sec.Address)
			secEnd := disasm.Address(sec.Address) + disasm.Address(len(sec.Data))
			if startAddr >= secStart && startAddr < secEnd {
				containingSection = sec
				break
			}
		}

		if containingSection == nil {
			return fmt.Errorf("address 0x%x not found in any executable section", startAddr)
		}

		// calculate offset within section
		offset := startAddr - disasm.Address(containingSection.Address)
		length := endAddr - startAddr

		if offset < 0 || offset >= disasm.Address(len(containingSection.Data)) {
			return fmt.Errorf("invalid address offset: 0x%x", offset)
		}

		if offset+length > disasm.Address(len(containingSection.Data)) {
			length = disasm.Address(len(containingSection.Data)) - offset
			endAddr = startAddr + length
		}

		codeBytes = containingSection.Data[offset : offset+length]

	} else if flags.function != "" {
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
			return fmt.Errorf("function not found: %s", flags.function)
		}

		// find section containing this function
		var containingSection *binfmt.Section
		for i := range binaryInfo.Sections {
			sec := binaryInfo.Sections[i]
			if !sec.IsExecutable {
				continue
			}
			secStart := disasm.Address(sec.Address)
			secEnd := disasm.Address(sec.Address) + disasm.Address(len(sec.Data))
			if startAddr >= secStart && startAddr < secEnd {
				containingSection = sec
				break
			}
		}

		if containingSection == nil {
			return fmt.Errorf("function address 0x%x not found in any executable section", startAddr)
		}

		// calculate offset within section
		offset := startAddr - disasm.Address(containingSection.Address)
		length := endAddr - startAddr

		if offset < 0 || offset >= disasm.Address(len(containingSection.Data)) {
			return fmt.Errorf("invalid function offset: 0x%x", offset)
		}

		if offset+length > disasm.Address(len(containingSection.Data)) {
			length = disasm.Address(len(containingSection.Data)) - offset
		}

		codeBytes = containingSection.Data[offset : offset+length]
	} else {
		// no function specified - use first executable section
		var execSection *binfmt.Section
		for i := range binaryInfo.Sections {
			if binaryInfo.Sections[i].IsExecutable {
				execSection = binaryInfo.Sections[i]
				break
			}
		}

		if execSection == nil {
			return fmt.Errorf("no executable section found in binary")
		}

		startAddr = disasm.Address(execSection.Address)
		endAddr = disasm.Address(execSection.Address) + disasm.Address(len(execSection.Data))
		codeBytes = execSection.Data
	}

	// disassemble instructions
	instructions, err := disassembler.DisassembleBytes(codeBytes, startAddr)
	if err != nil {
		return fmt.Errorf("failed to disassemble: %w", err)
	}

	if len(instructions) == 0 {
		return fmt.Errorf("no instructions disassembled")
	}

	// build cfg
	builder := cfg.NewCFGBuilder()
	controlFlowGraph, err := builder.Build(instructions)
	if err != nil {
		return fmt.Errorf("failed to build cfg: %w", err)
	}

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
		file, err := os.Create(flags.output)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer file.Close()
		output = file
	}

	// export to dot format
	if err := controlFlowGraph.ExportToDOT(output, dotOpts); err != nil {
		return fmt.Errorf("failed to export cfg to dot: %w", err)
	}

	// print statistics to stderr if output is file
	if flags.output != "" {
		fmt.Fprintf(stderr, "cfg exported to %s\n", flags.output)
		fmt.Fprintf(stderr, "address range: 0x%x - 0x%x (%d bytes)\n",
			startAddr, endAddr, endAddr-startAddr)
		fmt.Fprintf(stderr, "blocks: %d, edges: %d, unresolved jumps: %d\n",
			controlFlowGraph.BlockCount(),
			controlFlowGraph.EdgeCount(),
			controlFlowGraph.UnresolvedIndirectJumpCount())
	}

	return nil
}

// printCFGUsage displays help information for cfg command
func printCFGUsage(w io.Writer) {
	//nolint:errcheck // usage output is informational
	fmt.Fprintf(w, `sedec cfg - export control flow graph in dot format

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
