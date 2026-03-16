//nolint:godot // cli tool with many error messages
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	binfmt "github.com/zarazaex69/sedec/pkg/binary"
	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
	"github.com/zarazaex69/sedec/pkg/ssa"
)

var (
	// errIRNoInputProvided indicates no input was provided
	errIRNoInputProvided = errors.New("no input provided (stdin is empty and no file specified)")
	// errIRFileNotFound indicates file not found
	errIRFileNotFound = errors.New("file not found")
	// errIRTooManyArguments indicates too many arguments
	errIRTooManyArguments = errors.New("too many arguments (expected 0 or 1)")
	// errIRNoExecutableSections indicates no executable sections found
	errIRNoExecutableSections = errors.New("no executable sections found in binary")
)

// irConfig holds configuration for ir subcommand
type irConfig struct {
	function string
	output   string
	ssa      bool
}

// runIR executes the ir subcommand
func runIR(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	// create flagset for ir subcommand
	fs := flag.NewFlagSet("ir", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := &irConfig{}

	// define flags
	fs.StringVar(&cfg.function, "function", "", "lift specific function by name or address (hex: 0x1234)")
	fs.StringVar(&cfg.output, "output", "", "output file path (default: stdout)")
	fs.BoolVar(&cfg.ssa, "ssa", false, "output ssa form (default: false)")

	// custom usage function
	fs.Usage = func() {
		// usage output to stderr - ignore errors as this is informational
		//nolint:errcheck // usage output is informational, errors are non-critical
		fmt.Fprint(stderr, `usage: sedec ir [options] [binary]

lift binary executable to intermediate representation (ir).

options:
  --function <name|addr>    lift specific function by name or address
                            address format: 0x1234 (hexadecimal)
                            example: --function main
                            example: --function 0x401000

  --output <file>           write output to file instead of stdout
                            example: --output output.ir

  --ssa                     output ssa form (static single assignment)
                            default: false
                            example: --ssa

arguments:
  binary                    path to binary file to lift
                            if omitted, reads from stdin for pipeline composition

examples:
  # lift entire binary to ir
  sedec ir /bin/ls

  # lift specific function
  sedec ir --function main /bin/ls

  # output ssa form to file
  sedec ir --ssa --output out.ir /bin/ls

  # read from stdin (pipeline composition)
  cat /bin/ls | sedec ir

  # lift function at specific address
  sedec ir --function 0x401000 /bin/ls
`)
	}

	// parse flags
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
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
			return errIRNoInputProvided
		}
	case len(remainingArgs) == 1:
		// read from file
		binaryPath := remainingArgs[0]
		//nolint:gosec // G304: file path is user-provided cli argument, expected behavior for decompiler tool
		inputData, err = os.ReadFile(binaryPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("%w: %s", errIRFileNotFound, binaryPath)
			}
			return fmt.Errorf("failed to read file %s: %w", binaryPath, err)
		}
	default:
		return fmt.Errorf("%w, got %d", errIRTooManyArguments, len(remainingArgs))
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

	// execute ir lifting
	return executeIR(inputData, cfg, output, stderr)
}

// executeIR performs the actual ir lifting operation
func executeIR(data []byte, cfg *irConfig, output, stderr io.Writer) error {
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
	if _, writeErr := fmt.Fprintf(output, "; sedec ir output\n"); writeErr != nil {
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
	if cfg.ssa {
		if _, writeErr := fmt.Fprintf(output, "; form: ssa\n"); writeErr != nil {
			return fmt.Errorf("failed to write output: %w", writeErr)
		}
	} else {
		if _, writeErr := fmt.Fprintf(output, "; form: ir\n"); writeErr != nil {
			return fmt.Errorf("failed to write output: %w", writeErr)
		}
	}
	if _, writeErr := fmt.Fprintf(output, "\n"); writeErr != nil {
		return fmt.Errorf("failed to write output: %w", writeErr)
	}

	// if specific function requested, lift only that function
	if cfg.function != "" {
		return liftFunction(binaryInfo, disassembler, cfg.function, cfg.ssa, output, stderr)
	}

	// otherwise, lift all executable sections
	return liftAllSections(binaryInfo, disassembler, cfg.ssa, output, stderr)
}

// liftFunction lifts a specific function by name or address to ir
func liftFunction(binaryInfo *binfmt.BinaryInfo, disassembler *disasm.Disassembler, functionSpec string, ssaForm bool, output, _ io.Writer) error {
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

	// disassemble function
	instructions, err := disassembler.DisassembleFunction(section.Data[offset:], target.address)
	if err != nil {
		return fmt.Errorf("failed to disassemble function %s: %w", target.name, err)
	}

	// lift to ir
	function, cfgBuilder, err := liftInstructionsToIR(target.name, instructions)
	if err != nil {
		return fmt.Errorf("failed to lift function %s to ir: %w", target.name, err)
	}

	// optionally transform to ssa
	if ssaForm {
		if err := transformToSSA(function, cfgBuilder); err != nil {
			return fmt.Errorf("failed to transform function %s to ssa: %w", target.name, err)
		}
	}

	// print ir
	return printIRFunction(function, output)
}

// liftAllSections lifts all executable sections to ir
func liftAllSections(binaryInfo *binfmt.BinaryInfo, disassembler *disasm.Disassembler, ssaForm bool, output, stderr io.Writer) error {
	executableSections := 0

	for _, section := range binaryInfo.Sections {
		// only lift executable sections
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

		// lift to ir (use section name as function name)
		function, cfgBuilder, err := liftInstructionsToIR(section.Name, instructions)
		if err != nil {
			// log warning but continue with other sections
			//nolint:errcheck // warning output is informational, section name is from trusted parser
			fmt.Fprintf(stderr, "warning: failed to lift section %s to ir: %v\n", section.Name, err)
			continue
		}

		// optionally transform to ssa
		if ssaForm {
			if err := transformToSSA(function, cfgBuilder); err != nil {
				// log warning but continue with other sections
				//nolint:errcheck // warning output is informational, section name is from trusted parser
				fmt.Fprintf(stderr, "warning: failed to transform section %s to ssa: %v\n", section.Name, err)
				continue
			}
		}

		// print ir
		if printErr := printIRFunction(function, output); printErr != nil {
			return printErr
		}

		if _, writeErr := fmt.Fprintf(output, "\n"); writeErr != nil {
			return fmt.Errorf("failed to write output: %w", writeErr)
		}
	}

	if executableSections == 0 {
		return errIRNoExecutableSections
	}

	return nil
}

// liftInstructionsToIR lifts disassembled instructions to ir representation
func liftInstructionsToIR(functionName string, instructions []*disasm.Instruction) (*ir.Function, *cfg.Builder, error) {
	// create ir lifter
	lifter := ir.NewLifter()

	// lift each instruction to ir
	var allIRInstructions []ir.IRInstruction
	for _, instr := range instructions {
		irInstrs, err := lifter.LiftInstruction(instr)
		if err != nil {
			// skip unsupported instructions with warning
			// in production, this would be logged
			continue
		}
		allIRInstructions = append(allIRInstructions, irInstrs...)
	}

	// build cfg from instructions
	cfgBuilder := cfg.NewCFGBuilder()
	cfgGraph, err := cfgBuilder.Build(instructions)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build cfg: %w", err)
	}

	// create ir function structure
	function := &ir.Function{
		Name: functionName,
		Signature: ir.FunctionType{
			ReturnType: ir.VoidType{},
			Parameters: []ir.Type{},
			Variadic:   false,
		},
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
		EntryBlock: ir.BlockID(cfgGraph.Entry),
		Variables:  []ir.Variable{},
	}

	// organize ir instructions into basic blocks
	// for simplicity, create one block per cfg block
	for blockID, cfgBlock := range cfgGraph.Blocks {
		irBlock := &ir.BasicBlock{
			ID:           ir.BlockID(blockID),
			Instructions: []ir.IRInstruction{},
			Predecessors: []ir.BlockID{},
			Successors:   []ir.BlockID{},
		}

		// map cfg block instructions to ir instructions
		// this is simplified - in production, would need proper instruction-to-block mapping
		startAddr := cfgBlock.StartAddress
		endAddr := cfgBlock.EndAddress

		for _, irInstr := range allIRInstructions {
			// check if instruction belongs to this block based on source location.
			// endAddr is the address of the last instruction (inclusive), so use <=.
			if loc := irInstr.Location(); loc.Address >= ir.Address(startAddr) && loc.Address <= ir.Address(endAddr) {
				irBlock.Instructions = append(irBlock.Instructions, irInstr)
			}
		}

		// convert predecessors and successors
		for _, pred := range cfgBlock.Predecessors {
			irBlock.Predecessors = append(irBlock.Predecessors, ir.BlockID(pred))
		}
		for _, succ := range cfgBlock.Successors {
			irBlock.Successors = append(irBlock.Successors, ir.BlockID(succ))
		}

		function.Blocks[ir.BlockID(blockID)] = irBlock
	}

	// fix branch targets: lifter stores virtual addresses as BlockID,
	// but structuring engine expects the sequential cfg.BlockID assigned by the builder.
	resolveIRBranchTargets(function, cfgBuilder)

	return function, cfgBuilder, nil
}

// resolveIRBranchTargets rewrites Branch.TrueTarget and Branch.FalseTarget from
// virtual addresses (as emitted by the lifter) to the sequential cfg.BlockID values
// assigned by the cfg builder.
func resolveIRBranchTargets(fn *ir.Function, builder *cfg.Builder) {
	for _, irBlock := range fn.Blocks {
		for i, instr := range irBlock.Instructions {
			b, ok := ir.AsBranch(instr)
			if !ok {
				continue
			}
			// translate true target address to cfg block id
			if id, found := builder.BlockIDForAddress(disasm.Address(b.TrueTarget)); found {
				b.TrueTarget = ir.BlockID(id)
			}
			// translate false target address to cfg block id
			if id, found := builder.BlockIDForAddress(disasm.Address(b.FalseTarget)); found {
				b.FalseTarget = ir.BlockID(id)
			}
			irBlock.Instructions[i] = &b
		}
	}
}

// transformToSSA transforms ir function to ssa form
func transformToSSA(function *ir.Function, cfgBuilder *cfg.Builder) error {
	// compute dominator tree using the same builder that built the cfg
	domTree, err := cfgBuilder.ComputeDominators()
	if err != nil {
		return fmt.Errorf("failed to compute dominators: %w", err)
	}

	// note: we need to get cfg from somewhere
	// since Build() returns it, we should have saved it earlier
	// for now, create a minimal cfg structure from function blocks
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = cfg.BlockID(function.EntryBlock)

	// add blocks from ir function to cfg
	for blockID, irBlock := range function.Blocks {
		cfgBlock := &cfg.BasicBlock{
			ID:           cfg.BlockID(blockID),
			Predecessors: make([]cfg.BlockID, len(irBlock.Predecessors)),
			Successors:   make([]cfg.BlockID, len(irBlock.Successors)),
		}

		for i, pred := range irBlock.Predecessors {
			cfgBlock.Predecessors[i] = cfg.BlockID(pred)
		}
		for i, succ := range irBlock.Successors {
			cfgBlock.Successors[i] = cfg.BlockID(succ)
		}

		cfgGraph.AddBlock(cfgBlock)
	}

	// create ssa transformer
	transformer := ssa.NewTransformer(function, cfgGraph, domTree)

	// perform ssa transformation
	if err := transformer.TransformToSSA(); err != nil {
		return fmt.Errorf("ssa transformation failed: %w", err)
	}

	return nil
}

// printIRFunction prints ir function using ir printer
func printIRFunction(function *ir.Function, output io.Writer) error {
	printer := ir.NewPrinter(output)
	if err := printer.PrintFunction(function); err != nil {
		return fmt.Errorf("failed to print ir: %w", err)
	}
	return nil
}
