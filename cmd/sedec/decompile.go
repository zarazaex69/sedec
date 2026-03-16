//nolint:godot // cli tool with many error messages
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/zarazaex69/sedec/pkg/analysis"
	binfmt "github.com/zarazaex69/sedec/pkg/binary"
	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/codegen"
	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
	"github.com/zarazaex69/sedec/pkg/structuring"
)

var (
	// errDecompileNoInputProvided indicates no input was provided
	errDecompileNoInputProvided = errors.New("no input provided (stdin is empty and no file specified)")
	// errDecompileFileNotFound indicates file not found
	errDecompileFileNotFound = errors.New("file not found")
	// errDecompileTooManyArguments indicates too many arguments
	errDecompileTooManyArguments = errors.New("too many arguments (expected 0 or 1)")
	// errDecompileNoExecutableSections indicates no executable sections found
	errDecompileNoExecutableSections = errors.New("no executable sections found in binary")
)

// decompileConfig holds configuration for decompile subcommand
type decompileConfig struct {
	function string
	output   string
}

// runDecompile executes the decompile subcommand
func runDecompile(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("decompile", flag.ContinueOnError)
	fs.SetOutput(stderr)

	dcfg := &decompileConfig{}

	fs.StringVar(&dcfg.function, "function", "", "decompile specific function by name or address (hex: 0x1234)")
	fs.StringVar(&dcfg.output, "output", "", "output file path (default: stdout)")

	fs.Usage = func() {
		//nolint:errcheck // usage output is informational, errors are non-critical
		fmt.Fprint(stderr, `usage: sedec decompile [options] [binary]

decompile binary executable to c pseudocode.

options:
  --function <name|addr>    decompile specific function by name or address
                            address format: 0x1234 (hexadecimal)
                            example: --function main
                            example: --function 0x401000

  --output <file>           write output to file instead of stdout
                            example: --output output.c

arguments:
  binary                    path to binary file to decompile
                            if omitted, reads from stdin for pipeline composition

examples:
  # decompile entire binary
  sedec decompile /bin/ls

  # decompile specific function
  sedec decompile --function main /bin/ls

  # output to file
  sedec decompile --output output.c /bin/ls

  # read from stdin (pipeline composition)
  cat /bin/ls | sedec decompile

  # decompile function at specific address
  sedec decompile --function 0x401000 /bin/ls
`)
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	var inputData []byte
	var err error

	remainingArgs := fs.Args()

	switch {
	case len(remainingArgs) == 0:
		inputData, err = io.ReadAll(stdin)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
		if len(inputData) == 0 {
			return errDecompileNoInputProvided
		}
	case len(remainingArgs) == 1:
		binaryPath := remainingArgs[0]
		//nolint:gosec // G304: file path is user-provided cli argument, expected behavior for decompiler tool
		inputData, err = os.ReadFile(binaryPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("%w: %s", errDecompileFileNotFound, binaryPath)
			}
			return fmt.Errorf("failed to read file %s: %w", binaryPath, err)
		}
	default:
		return fmt.Errorf("%w, got %d", errDecompileTooManyArguments, len(remainingArgs))
	}

	var output io.Writer
	var outputFile *os.File

	if dcfg.output != "" {
		outputFile, err = os.Create(dcfg.output)
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", dcfg.output, err)
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

	return executeDecompile(inputData, dcfg, output, stderr)
}

// executeDecompile performs the full decompilation pipeline
func executeDecompile(data []byte, dcfg *decompileConfig, output, stderr io.Writer) error {
	// parse binary
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

	// write c file header
	if _, writeErr := fmt.Fprintf(output, "// sedec decompile output\n"); writeErr != nil {
		return fmt.Errorf("failed to write output: %w", writeErr)
	}
	if _, writeErr := fmt.Fprintf(output, "// format: %s  arch: %s  entry: 0x%x\n\n",
		binaryInfo.Format, binaryInfo.Architecture, binaryInfo.EntryPoint); writeErr != nil {
		return fmt.Errorf("failed to write output: %w", writeErr)
	}
	if _, writeErr := fmt.Fprintf(output, "#include <stdint.h>\n#include <stddef.h>\n\n"); writeErr != nil {
		return fmt.Errorf("failed to write output: %w", writeErr)
	}

	if dcfg.function != "" {
		return decompileFunction(binaryInfo, disassembler, dcfg.function, output, stderr)
	}

	return decompileAllSections(binaryInfo, disassembler, output, stderr)
}

// decompileFunction decompiles a single function identified by name or address
func decompileFunction(
	binaryInfo *binfmt.BinaryInfo,
	disassembler *disasm.Disassembler,
	functionSpec string,
	output, _ io.Writer,
) error {
	target, err := resolveFunctionTarget(binaryInfo, functionSpec)
	if err != nil {
		return err
	}

	section, err := findSectionForAddress(binaryInfo, target.address)
	if err != nil {
		return err
	}

	offset, err := calculateSectionOffset(section, target.address)
	if err != nil {
		return err
	}

	instructions, err := disassembler.DisassembleFunction(section.Data[offset:], target.address)
	if err != nil {
		return fmt.Errorf("failed to disassemble function %s: %w", target.name, err)
	}

	// trim instructions to function boundary: stop after the first ret/retn
	instructions = trimToFunctionBoundary(instructions)

	cCode, err := decompileInstructions(target.name, instructions)
	if err != nil {
		return fmt.Errorf("failed to decompile function %s: %w", target.name, err)
	}

	if _, writeErr := fmt.Fprint(output, cCode); writeErr != nil {
		return fmt.Errorf("failed to write output: %w", writeErr)
	}
	return nil
}

// decompileAllSections decompiles all executable sections
func decompileAllSections(
	binaryInfo *binfmt.BinaryInfo,
	disassembler *disasm.Disassembler,
	output, stderr io.Writer,
) error {
	executableSections := 0

	for _, section := range binaryInfo.Sections {
		if !section.IsExecutable {
			continue
		}
		executableSections++

		instructions, err := disassembler.DisassembleBytes(section.Data, disasm.Address(section.Address))
		if err != nil {
			//nolint:errcheck // warning output is informational
			fmt.Fprintf(stderr, "warning: failed to disassemble section %s: %v\n", section.Name, err)
			continue
		}

		cCode, err := decompileInstructions(section.Name, instructions)
		if err != nil {
			//nolint:errcheck // warning output is informational
			fmt.Fprintf(stderr, "warning: failed to decompile section %s: %v\n", section.Name, err)
			continue
		}

		if _, writeErr := fmt.Fprint(output, cCode); writeErr != nil {
			return fmt.Errorf("failed to write output: %w", writeErr)
		}
		if _, writeErr := fmt.Fprint(output, "\n"); writeErr != nil {
			return fmt.Errorf("failed to write output: %w", writeErr)
		}
	}

	if executableSections == 0 {
		return errDecompileNoExecutableSections
	}

	return nil
}

// decompileInstructions runs the full pipeline: lift → cfg → domtree → loops → structure → codegen
func decompileInstructions(functionName string, instructions []*disasm.Instruction) (string, error) {
	// lift instructions to ir; cfgBuilder retains the built cfg internally
	irFunc, cfgBuilder, err := liftInstructionsToIR(functionName, instructions)
	if err != nil {
		return "", fmt.Errorf("ir lifting failed: %w", err)
	}

	// compute dominator tree (lengauer-tarjan via gonum)
	domTree, err := cfgBuilder.ComputeDominators()
	if err != nil {
		return "", fmt.Errorf("dominator tree computation failed: %w", err)
	}

	// detect natural loops (back-edge analysis + tarjan scc)
	loopInfo, err := cfgBuilder.DetectLoops()
	if err != nil {
		return "", fmt.Errorf("loop detection failed: %w", err)
	}

	// reconstruct cfg graph from ir function block topology for analysis and structuring
	cfgGraph := buildCFGFromIRFunction(irFunc)

	// recompute dominator tree for the reconstructed cfg (block ids are preserved)
	irDomTree, err := cfg.ComputeDominatorsForCFG(cfgGraph)
	if err != nil {
		// fall back to original dominator tree if recomputation fails
		irDomTree = domTree
	}

	// run constant folding: simplifies xor reg,reg → 0, and other constant expressions
	if _, cfErr := analysis.FoldConstants(irFunc); cfErr != nil {
		_ = cfErr
	}

	// run dead code elimination: removes dead assignments (xor reg,reg after folding, etc.)
	if _, dceErr := analysis.EliminateDeadCode(irFunc, cfgGraph, irDomTree); dceErr != nil {
		_ = dceErr
	}

	// build ir block map: cfg.BlockID → []ir.IRInstruction
	irBlockMap := buildIRBlockMap(irFunc)

	// run phoenix/dream structuring algorithm
	engine, err := structuring.New(cfgGraph, domTree, loopInfo, irBlockMap)
	if err != nil {
		return "", fmt.Errorf("structuring engine init failed: %w", err)
	}

	ast, err := engine.Structure()
	if err != nil {
		return "", fmt.Errorf("structuring failed: %w", err)
	}

	// apply expression condensation: inline single-use temps, merge nested ifs,
	// de morgan simplification, early-return hoisting
	ast = structuring.CondenseExpressions(ast)

	// generate c pseudocode with scope minimization and traceability annotations
	gen := codegen.NewTraceableGenerator()
	decl, _ := gen.GenerateWithTraceability(irFunc, ast)
	return codegen.RenderDecl(decl), nil
}

// buildCFGFromIRFunction reconstructs a cfg.CFG from the ir.Function block topology.
// this is needed because the structuring engine requires a cfg.CFG, while liftInstructionsToIR
// returns an ir.Function whose blocks carry the same predecessor/successor information.
func buildCFGFromIRFunction(fn *ir.Function) *cfg.CFG {
	cfgGraph := cfg.NewCFG()
	cfgGraph.Entry = cfg.BlockID(fn.EntryBlock)

	for blockID, irBlock := range fn.Blocks {
		block := &cfg.BasicBlock{
			ID:           cfg.BlockID(blockID),
			Predecessors: make([]cfg.BlockID, len(irBlock.Predecessors)),
			Successors:   make([]cfg.BlockID, len(irBlock.Successors)),
		}
		for i, pred := range irBlock.Predecessors {
			block.Predecessors[i] = cfg.BlockID(pred)
		}
		for i, succ := range irBlock.Successors {
			block.Successors[i] = cfg.BlockID(succ)
		}
		cfgGraph.AddBlock(block)
	}

	return cfgGraph
}

// buildIRBlockMap constructs the IRBlockMap required by the structuring engine.
// maps each cfg.BlockID to the slice of ir.IRInstruction in that block.
func buildIRBlockMap(fn *ir.Function) structuring.IRBlockMap {
	m := make(structuring.IRBlockMap, len(fn.Blocks))
	for blockID, irBlock := range fn.Blocks {
		m[cfg.BlockID(blockID)] = irBlock.Instructions
	}
	return m
}

// trimToFunctionBoundary limits instructions to a single function by stopping
// after the last ret/retn that is reachable without crossing another function entry.
// this prevents the lifter from processing instructions from subsequent functions.
func trimToFunctionBoundary(instructions []*disasm.Instruction) []*disasm.Instruction {
	for i, instr := range instructions {
		m := strings.ToLower(instr.Mnemonic)
		if m == "ret" || m == "retn" {
			return instructions[:i+1]
		}
	}
	return instructions
}
