//nolint:godot // cli tool with many error messages
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/zarazaex69/sedec/pkg/abi"
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

// validCIdentifierRegex matches strings that are already valid c identifiers.
// a valid c identifier starts with a letter or underscore, followed by letters, digits, or underscores.
var validCIdentifierRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// invalidCIdentifierCharRegex matches any character that is not valid in a c identifier.
var invalidCIdentifierCharRegex = regexp.MustCompile(`[^a-zA-Z0-9_]`)

// sanitizeFunctionName converts an arbitrary string into a valid c identifier.
//
// rules applied in order:
//  1. if name already matches /^[a-zA-Z_][a-zA-Z0-9_]*$/, return it unchanged (preservation guarantee)
//  2. strip elf version suffix: remove everything from '@' when followed by an uppercase letter
//     (e.g., printf@GLIBC_2.2.5 → printf, but error@plt → error_plt via rule 3)
//  3. replace all characters not in [a-zA-Z0-9_] with '_'
//  4. if the result begins with a digit or is empty, prepend "fn_"
//  5. if the result is still empty after all transformations, use fmt.Sprintf("sub_%08x", addr)
func sanitizeFunctionName(name string, addr uint64) string {
	// preservation guarantee: already-valid identifiers are returned unchanged
	if validCIdentifierRegex.MatchString(name) {
		return name
	}

	// rule 1: strip elf version suffix — only when '@' is followed by an uppercase letter
	// (e.g., @GLIBC_2.2.5, @CXXABI_1.3, @GCC_3.0) — these are elf symbol versioning suffixes
	// names like "error@plt" are not version suffixes; '@' is replaced by '_' in rule 2
	if idx := strings.IndexByte(name, '@'); idx >= 0 && idx+1 < len(name) {
		next := name[idx+1]
		if next >= 'A' && next <= 'Z' {
			name = name[:idx]
		}
	}

	// rule 2: replace all non-[a-zA-Z0-9_] characters with '_'
	name = invalidCIdentifierCharRegex.ReplaceAllString(name, "_")

	// rule 3: if result begins with a digit or is empty, prepend "fn_"
	if len(name) == 0 || (name[0] >= '0' && name[0] <= '9') {
		name = "fn_" + name
	}

	// rule 4: if still empty (e.g., original was all invalid chars stripped to nothing), use address
	if name == "" || name == "fn_" {
		return fmt.Sprintf("sub_%08x", addr)
	}

	return name
}

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

	// trim instructions to function boundary using symbol size when available
	instructions = trimFunctionInstructions(instructions, target.address, binaryInfo.Symbols)

	// sanitize the function name to ensure it is a valid c identifier
	safeFuncName := sanitizeFunctionName(target.name, uint64(target.address))

	cCode, err := decompileInstructions(safeFuncName, instructions, binaryInfo.GroundTruthDB)
	if err != nil {
		return fmt.Errorf("failed to decompile function %s: %w", target.name, err)
	}

	if _, writeErr := fmt.Fprint(output, cCode); writeErr != nil {
		return fmt.Errorf("failed to write output: %w", writeErr)
	}
	return nil
}

// funcChunk is a named slice of instructions representing one function.
type funcChunk struct {
	name         string
	instructions []*disasm.Instruction
}

// decompileAllSections decompiles all executable sections.
// functions are split by symbol table when available, then decompiled in parallel.
func decompileAllSections(
	binaryInfo *binfmt.BinaryInfo,
	disassembler *disasm.Disassembler,
	output, stderr io.Writer,
) error {
	executableSections := 0

	// collect all function chunks across all executable sections
	var allChunks []funcChunk

	for _, section := range binaryInfo.Sections {
		if !section.IsExecutable {
			continue
		}
		executableSections++

		// disassemble the whole section once
		instructions, err := disassembler.DisassembleBytes(section.Data, disasm.Address(section.Address))
		if err != nil {
			//nolint:errcheck // warning output is informational
			fmt.Fprintf(stderr, "warning: failed to disassemble section %s: %v\n", section.Name, err)
			continue
		}

		// split into per-function chunks using symbol table, falling back to ret-boundary heuristic
		chunks := splitSectionIntoFunctions(instructions, binaryInfo.Symbols, section.Name)
		allChunks = append(allChunks, chunks...)
	}

	if executableSections == 0 {
		return errDecompileNoExecutableSections
	}

	if len(allChunks) == 0 {
		return nil
	}

	// decompile all chunks in parallel using a bounded worker pool
	type result struct {
		index int
		code  string
		err   error
	}

	workers := runtime.NumCPU()
	if workers > len(allChunks) {
		workers = len(allChunks)
	}

	jobs := make(chan int, len(allChunks))
	results := make([]result, len(allChunks))

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				chunk := allChunks[idx]
				code, err := decompileInstructions(chunk.name, chunk.instructions, binaryInfo.GroundTruthDB)
				results[idx] = result{index: idx, code: code, err: err}
			}
		}()
	}

	for i := range allChunks {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	// write results in original order to preserve deterministic output
	for i, r := range results {
		if r.err != nil {
			//nolint:errcheck // warning output is informational
			fmt.Fprintf(stderr, "warning: failed to decompile %s: %v\n", allChunks[i].name, r.err)
			continue
		}
		if _, writeErr := fmt.Fprint(output, r.code); writeErr != nil {
			return fmt.Errorf("failed to write output: %w", writeErr)
		}
		if _, writeErr := fmt.Fprint(output, "\n"); writeErr != nil {
			return fmt.Errorf("failed to write output: %w", writeErr)
		}
	}

	return nil
}

// splitSectionIntoFunctions partitions a flat instruction slice into per-function chunks.
// strategy:
//  1. collect function-type symbols that fall within the instruction address range
//  2. sort them by address and use them as function start boundaries
//  3. if no symbols are available, fall back to splitting on ret instructions
func splitSectionIntoFunctions(
	instructions []*disasm.Instruction,
	symbols []*binfmt.Symbol,
	sectionName string,
) []funcChunk {
	if len(instructions) == 0 {
		return nil
	}

	sectionStart := instructions[0].Address
	sectionEnd := instructions[len(instructions)-1].Address

	// build address → index map for O(1) lookup
	addrToIdx := make(map[disasm.Address]int, len(instructions))
	for i, instr := range instructions {
		addrToIdx[instr.Address] = i
	}

	// collect function symbols within this section's address range
	type funcSym struct {
		name string
		addr disasm.Address
	}
	var funcSyms []funcSym
	for _, sym := range symbols {
		if sym.Type != binfmt.SymbolTypeFunction {
			continue
		}
		addr := disasm.Address(sym.Address)
		if addr < sectionStart || addr > sectionEnd {
			continue
		}
		if _, ok := addrToIdx[addr]; !ok {
			continue
		}
		funcSyms = append(funcSyms, funcSym{name: sym.Name, addr: addr})
	}

	// sort by address ascending
	sort.Slice(funcSyms, func(i, j int) bool {
		return funcSyms[i].addr < funcSyms[j].addr
	})

	// if we have symbol information, split by symbol boundaries
	if len(funcSyms) > 0 {
		chunks := make([]funcChunk, 0, len(funcSyms))
		for i, sym := range funcSyms {
			startIdx := addrToIdx[sym.addr]
			endIdx := len(instructions)
			if i+1 < len(funcSyms) {
				if nextIdx, ok := addrToIdx[funcSyms[i+1].addr]; ok {
					endIdx = nextIdx
				}
			}
			if startIdx >= endIdx {
				continue
			}
			chunks = append(chunks, funcChunk{
				name:         sanitizeFunctionName(sym.name, uint64(sym.addr)),
				instructions: instructions[startIdx:endIdx],
			})
		}
		if len(chunks) > 0 {
			return chunks
		}
	}

	// fallback: split on ret instruction boundaries
	return splitOnRetBoundaries(instructions, sectionName)
}

// splitOnRetBoundaries splits instructions into chunks at each ret/retn instruction.
// used when no symbol table is available (stripped binaries).
func splitOnRetBoundaries(instructions []*disasm.Instruction, sectionName string) []funcChunk {
	var chunks []funcChunk
	start := 0
	chunkIdx := 0

	// sanitize the section name once; all chunk names share the same base
	safeName := sanitizeFunctionName(sectionName, 0)

	for i, instr := range instructions {
		m := strings.ToLower(instr.Mnemonic)
		if m == "ret" || m == "retn" {
			if i >= start {
				name := fmt.Sprintf("%s_func%d", safeName, chunkIdx)
				chunks = append(chunks, funcChunk{
					name:         name,
					instructions: instructions[start : i+1],
				})
				chunkIdx++
			}
			start = i + 1
		}
	}

	// trailing instructions after last ret (if any)
	if start < len(instructions) {
		name := fmt.Sprintf("%s_func%d", safeName, chunkIdx)
		chunks = append(chunks, funcChunk{
			name:         name,
			instructions: instructions[start:],
		})
	}

	return chunks
}

// symbolizeAddresses replaces absolute constant addresses in ir expressions with
// symbolic references from the ground-truth database.
//
// two patterns are resolved:
//  1. ir.ConstantExpr with Value > 0xffff that matches a symbol address →
//     replaced with ir.VariableExpr{Name: "&symbolName"}
//  2. ir.BinaryOp{Add, VariableExpr{"rip"}, ConstantExpr{disp}} where
//     rip+disp resolves to a symbol → replaced with ir.VariableExpr{Name: "&symbolName"}
//
// the pass walks Load.Address, Store.Address, Store.Value, and Assign.Source expressions.
// call targets are already resolved by applyABIPass (Fix 6) and are not touched here.
func symbolizeAddresses(irFunc *ir.Function, db *binfmt.GroundTruthDatabase, rawInsns []*disasm.Instruction) {
	if db == nil {
		return
	}

	// build rip-next-address map: for each instruction, rip = address + length
	ripNextAddr := make(map[ir.Address]uint64, len(rawInsns))
	for _, insn := range rawInsns {
		ripNextAddr[ir.Address(insn.Address)] = uint64(insn.Address) + uint64(insn.Length)
	}

	for _, block := range irFunc.Blocks {
		for i, instr := range block.Instructions {
			instrAddr := ir.Address(instr.Location().Address)
			switch typed := instr.(type) {
			case *ir.Load:
				typed.Address = symbolizeExpr(typed.Address, instrAddr, db, ripNextAddr)
			case ir.Load:
				newAddr := symbolizeExpr(typed.Address, instrAddr, db, ripNextAddr)
				if newAddr != typed.Address {
					updated := typed
					updated.Address = newAddr
					block.Instructions[i] = updated
				}
			case *ir.Store:
				typed.Address = symbolizeExpr(typed.Address, instrAddr, db, ripNextAddr)
				typed.Value = symbolizeExpr(typed.Value, instrAddr, db, ripNextAddr)
			case ir.Store:
				newAddr := symbolizeExpr(typed.Address, instrAddr, db, ripNextAddr)
				newVal := symbolizeExpr(typed.Value, instrAddr, db, ripNextAddr)
				if newAddr != typed.Address || newVal != typed.Value {
					updated := typed
					updated.Address = newAddr
					updated.Value = newVal
					block.Instructions[i] = updated
				}
			case *ir.Assign:
				typed.Source = symbolizeExpr(typed.Source, instrAddr, db, ripNextAddr)
			case ir.Assign:
				newSrc := symbolizeExpr(typed.Source, instrAddr, db, ripNextAddr)
				if newSrc != typed.Source {
					updated := typed
					updated.Source = newSrc
					block.Instructions[i] = updated
				}
			}
		}
	}
}

// symbolizeExpr recursively walks expr and replaces absolute address constants
// with symbolic references from the ground-truth database.
func symbolizeExpr(
	expr ir.Expression,
	instrAddr ir.Address,
	db *binfmt.GroundTruthDatabase,
	ripNextAddr map[ir.Address]uint64,
) ir.Expression {
	if expr == nil {
		return expr
	}

	switch e := expr.(type) {
	case ir.ConstantExpr:
		intConst, ok := e.Value.(ir.IntConstant)
		if !ok {
			return expr
		}
		// only symbolize large constants (> 0xffff) to avoid false positives
		// #nosec G115 — intentional conversion: addresses are unsigned
		addr := uint64(intConst.Value)
		if addr <= 0xffff {
			return expr
		}
		bAddr := binfmt.Address(addr)
		if name, ok := db.SymbolsByAddress[bAddr]; ok && name != "" {
			return ir.VariableExpr{Var: ir.Variable{
				Name: "&" + name,
				Type: ir.PointerType{Pointee: ir.VoidType{}},
			}}
		}
		if imp, ok := db.Imports[bAddr]; ok && imp != nil && imp.Name != "" {
			return ir.VariableExpr{Var: ir.Variable{
				Name: "&" + imp.Name,
				Type: ir.PointerType{Pointee: ir.VoidType{}},
			}}
		}
		return expr

	case ir.BinaryOp:
		// detect rip-relative pattern: rip + disp
		if e.Op == ir.BinOpAdd {
			if leftVar, ok := e.Left.(ir.VariableExpr); ok {
				if leftVar.Var.Name == "rip" {
					if rightConst, ok := e.Right.(ir.ConstantExpr); ok {
						if disp, ok := rightConst.Value.(ir.IntConstant); ok {
							if ripNext, exists := ripNextAddr[instrAddr]; exists {
								// #nosec G115 — intentional conversion
								targetAddr := binfmt.Address(ripNext + uint64(disp.Value))
								if name, ok := db.SymbolsByAddress[targetAddr]; ok && name != "" {
									return ir.VariableExpr{Var: ir.Variable{
										Name: "&" + name,
										Type: ir.PointerType{Pointee: ir.VoidType{}},
									}}
								}
								if imp, ok := db.Imports[targetAddr]; ok && imp != nil && imp.Name != "" {
									return ir.VariableExpr{Var: ir.Variable{
										Name: "&" + imp.Name,
										Type: ir.PointerType{Pointee: ir.VoidType{}},
									}}
								}
							}
						}
					}
				}
			}
		}
		// recurse into both operands
		newLeft := symbolizeExpr(e.Left, instrAddr, db, ripNextAddr)
		newRight := symbolizeExpr(e.Right, instrAddr, db, ripNextAddr)
		if newLeft == e.Left && newRight == e.Right {
			return expr
		}
		return ir.BinaryOp{Op: e.Op, Left: newLeft, Right: newRight}

	case ir.UnaryOp:
		newOperand := symbolizeExpr(e.Operand, instrAddr, db, ripNextAddr)
		if newOperand == e.Operand {
			return expr
		}
		return ir.UnaryOp{Op: e.Op, Operand: newOperand}

	case ir.Cast:
		newInner := symbolizeExpr(e.Expr, instrAddr, db, ripNextAddr)
		if newInner == e.Expr {
			return expr
		}
		return ir.Cast{Expr: newInner, TargetType: e.TargetType}

	case ir.LoadExpr:
		newAddr := symbolizeExpr(e.Address, instrAddr, db, ripNextAddr)
		if newAddr == e.Address {
			return expr
		}
		return ir.LoadExpr{Address: newAddr, Size: e.Size}

	default:
		return expr
	}
}

// renameRegisterVariables replaces raw x86-64 register names in irFunc with
// human-readable c variable names.
//
// step 1: map parameter registers to argN names from funcABI.
// step 2: assign synthetic var_N names to all other register-named variables.
// step 3: walk all ir instructions and rename every variable occurrence.
// step 4: rebuild irFunc.Variables with the renamed names.
func renameRegisterVariables(irFunc *ir.Function, funcABI *abi.FunctionABI) {
	// step 1: build register → parameter name map from abi analysis
	regToName := make(map[string]string)
	for _, param := range funcABI.Parameters {
		if param.Location != abi.ParameterLocationRegister || param.Register == "" {
			continue
		}
		argName := fmt.Sprintf("arg%d", param.Index)
		canonical := strings.ToLower(param.Register)
		regToName[canonical] = argName
		// also map all sub-register aliases to the same arg name
		for alias, canon := range buildAliasMap() {
			if canon == canonical {
				regToName[alias] = argName
			}
		}
	}

	// step 2: synthetic name counter and lazy assignment map.
	// use canonical (64-bit) register names as keys so that sub-register aliases
	// (eax, ax, al) map to the same synthetic variable as their parent (rax).
	syntheticNames := make(map[string]string)
	aliasMap := buildAliasMap()
	varCounter := 0

	// renameVar maps a single variable to its renamed form.
	// parameter registers → argN; other registers → var_N; non-registers → unchanged.
	renameVar := func(v ir.Variable) ir.Variable {
		lower := strings.ToLower(v.Name)
		if !x86_64RegisterNames[lower] {
			return v
		}
		if name, ok := regToName[lower]; ok {
			return ir.Variable{Name: name, Type: v.Type, Version: v.Version}
		}
		// canonicalize to 64-bit form so eax/ax/al all share the same synthetic name as rax
		canonical := lower
		if canon, ok := aliasMap[lower]; ok {
			canonical = canon
		}
		if name, ok := syntheticNames[canonical]; ok {
			return ir.Variable{Name: name, Type: v.Type, Version: v.Version}
		}
		name := fmt.Sprintf("var_%d", varCounter)
		varCounter++
		syntheticNames[canonical] = name
		return ir.Variable{Name: name, Type: v.Type, Version: v.Version}
	}

	// renameExpr recursively renames all variable references in an expression.
	var renameExpr func(expr ir.Expression) ir.Expression
	renameExpr = func(expr ir.Expression) ir.Expression {
		if expr == nil {
			return expr
		}
		switch e := expr.(type) {
		case ir.VariableExpr:
			return ir.VariableExpr{Var: renameVar(e.Var)}
		case *ir.VariableExpr:
			return ir.VariableExpr{Var: renameVar(e.Var)}
		case ir.BinaryOp:
			return ir.BinaryOp{Op: e.Op, Left: renameExpr(e.Left), Right: renameExpr(e.Right)}
		case *ir.BinaryOp:
			return ir.BinaryOp{Op: e.Op, Left: renameExpr(e.Left), Right: renameExpr(e.Right)}
		case ir.UnaryOp:
			return ir.UnaryOp{Op: e.Op, Operand: renameExpr(e.Operand)}
		case *ir.UnaryOp:
			return ir.UnaryOp{Op: e.Op, Operand: renameExpr(e.Operand)}
		case ir.Cast:
			return ir.Cast{Expr: renameExpr(e.Expr), TargetType: e.TargetType}
		case *ir.Cast:
			return ir.Cast{Expr: renameExpr(e.Expr), TargetType: e.TargetType}
		case ir.LoadExpr:
			return ir.LoadExpr{Address: renameExpr(e.Address), Size: e.Size}
		case *ir.LoadExpr:
			return ir.LoadExpr{Address: renameExpr(e.Address), Size: e.Size}
		default:
			return expr
		}
	}

	// renameInstr renames all variable references in a single ir instruction.
	renameInstr := func(instr ir.IRInstruction) ir.IRInstruction {
		switch typed := instr.(type) {
		case *ir.Assign:
			typed.Dest = renameVar(typed.Dest)
			typed.Source = renameExpr(typed.Source)
		case ir.Assign:
			updated := typed
			updated.Dest = renameVar(typed.Dest)
			updated.Source = renameExpr(typed.Source)
			return updated
		case *ir.Load:
			typed.Dest = renameVar(typed.Dest)
			typed.Address = renameExpr(typed.Address)
		case ir.Load:
			updated := typed
			updated.Dest = renameVar(typed.Dest)
			updated.Address = renameExpr(typed.Address)
			return updated
		case *ir.Store:
			typed.Address = renameExpr(typed.Address)
			typed.Value = renameExpr(typed.Value)
		case ir.Store:
			updated := typed
			updated.Address = renameExpr(typed.Address)
			updated.Value = renameExpr(typed.Value)
			return updated
		case *ir.Call:
			if typed.Dest != nil {
				renamed := renameVar(*typed.Dest)
				typed.Dest = &renamed
			}
			typed.Target = renameExpr(typed.Target)
			for i, arg := range typed.Args {
				typed.Args[i] = renameVar(arg)
			}
			for i, argExpr := range typed.ArgExprs {
				typed.ArgExprs[i] = renameExpr(argExpr)
			}
		case ir.Call:
			updated := typed
			if typed.Dest != nil {
				renamed := renameVar(*typed.Dest)
				updated.Dest = &renamed
			}
			updated.Target = renameExpr(typed.Target)
			newArgs := make([]ir.Variable, len(typed.Args))
			for i, arg := range typed.Args {
				newArgs[i] = renameVar(arg)
			}
			updated.Args = newArgs
			newArgExprs := make([]ir.Expression, len(typed.ArgExprs))
			for i, argExpr := range typed.ArgExprs {
				newArgExprs[i] = renameExpr(argExpr)
			}
			updated.ArgExprs = newArgExprs
			return updated
		case *ir.Return:
			if typed.Value != nil {
				renamed := renameVar(*typed.Value)
				typed.Value = &renamed
			}
		case ir.Return:
			updated := typed
			if typed.Value != nil {
				renamed := renameVar(*typed.Value)
				updated.Value = &renamed
			}
			return updated
		case *ir.Phi:
			typed.Dest = renameVar(typed.Dest)
			for i, src := range typed.Sources {
				typed.Sources[i].Var = renameVar(src.Var)
			}
		case ir.Phi:
			updated := typed
			updated.Dest = renameVar(typed.Dest)
			newSrcs := make([]ir.PhiSource, len(typed.Sources))
			for i, src := range typed.Sources {
				newSrcs[i] = ir.PhiSource{Block: src.Block, Var: renameVar(src.Var)}
			}
			updated.Sources = newSrcs
			return updated
		case *ir.Branch:
			typed.Condition = renameExpr(typed.Condition)
		case ir.Branch:
			updated := typed
			updated.Condition = renameExpr(typed.Condition)
			return updated
		}
		return instr
	}

	// step 3: walk all blocks and rename every instruction
	for _, block := range irFunc.Blocks {
		for i, instr := range block.Instructions {
			block.Instructions[i] = renameInstr(instr)
		}
	}

	// step 4: rebuild irFunc.Variables with renamed names
	seen := make(map[string]bool)
	newVars := make([]ir.Variable, 0, len(irFunc.Variables))
	for _, v := range irFunc.Variables {
		renamed := renameVar(v)
		if !seen[renamed.Name] {
			seen[renamed.Name] = true
			newVars = append(newVars, renamed)
		}
	}
	irFunc.Variables = newVars
}

// buildAliasMap returns a map from every x86-64 register alias to its 64-bit canonical name.
// used by renameRegisterVariables to map sub-register aliases to the same parameter name.
func buildAliasMap() map[string]string {
	m := make(map[string]string, 128)
	groups := [][]string{
		{"rax", "eax", "ax", "al", "ah"},
		{"rbx", "ebx", "bx", "bl", "bh"},
		{"rcx", "ecx", "cx", "cl", "ch"},
		{"rdx", "edx", "dx", "dl", "dh"},
		{"rsi", "esi", "si", "sil"},
		{"rdi", "edi", "di", "dil"},
		{"rbp", "ebp", "bp", "bpl"},
		{"rsp", "esp", "sp", "spl"},
		{"r8", "r8d", "r8w", "r8b"},
		{"r9", "r9d", "r9w", "r9b"},
		{"r10", "r10d", "r10w", "r10b"},
		{"r11", "r11d", "r11w", "r11b"},
		{"r12", "r12d", "r12w", "r12b"},
		{"r13", "r13d", "r13w", "r13b"},
		{"r14", "r14d", "r14w", "r14b"},
		{"r15", "r15d", "r15w", "r15b"},
	}
	for _, group := range groups {
		canonical := group[0]
		for _, alias := range group {
			m[alias] = canonical
		}
	}
	return m
}

// decompileInstructions runs the full pipeline: lift → cfg → domtree → loops → abi → structure → codegen
func decompileInstructions(functionName string, instructions []*disasm.Instruction, db *binfmt.GroundTruthDatabase) (string, error) {
	// lift instructions to ir; cfgBuilder retains the built cfg internally
	irFunc, cfgBuilder, err := liftInstructionsToIR(functionName, instructions)
	if err != nil {
		return "", fmt.Errorf("ir lifting failed: %w", err)
	}

	// run abi analysis pass: populates Call.Args, sets function signature,
	// and infers return types from register usage at call sites.
	funcABI := applyABIPass(irFunc, instructions, db)

	// replace absolute address constants with symbolic references from the database
	symbolizeAddresses(irFunc, db, instructions)

	// recover stack variables: replace rbp-relative memory accesses with named locals.
	// must run before register renaming so rbp is still identifiable.
	analysis.RecoverStackVariables(irFunc)

	// rename raw x86-64 register variables to human-readable c names (arg0, var_0, etc.)
	if funcABI != nil {
		renameRegisterVariables(irFunc, funcABI)
	}

	// propagate return values: trace last assignment to return register and
	// substitute the actual expression into Return instructions.
	analysis.PropagateReturnValues(irFunc)

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

	// recover high-level conditions: collapse flag-based expressions (zf, sf, of)
	// into relational operators (<=, >, <, >=, ==, !=).
	// must run after constant folding so that of=false is already simplified.
	analysis.RecoverConditions(irFunc)

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

	// recover high-level conditions in the structured ast: the structuring engine
	// copies branch conditions from ir into ast nodes, so we must also recover
	// conditions at the ast level (if/while/for condition expressions).
	analysis.RecoverASTConditions(ast)

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

// trimFunctionInstructions trims instructions to the precise function boundary.
// strategy:
//  1. if a symbol with a non-zero size exists for funcAddr, use size as hard limit
//  2. otherwise find the next function symbol address and stop before it
//  3. fallback: stop after the last ret before the next function starts
func trimFunctionInstructions(instructions []*disasm.Instruction, funcAddr disasm.Address, symbols []*binfmt.Symbol) []*disasm.Instruction {
	if len(instructions) == 0 {
		return instructions
	}

	// find the symbol for this function address
	var funcSize uint64
	var nextFuncAddr disasm.Address

	for _, sym := range symbols {
		if sym.Type != binfmt.SymbolTypeFunction {
			continue
		}
		if disasm.Address(sym.Address) == funcAddr && sym.Size > 0 {
			funcSize = sym.Size
			break
		}
	}

	if funcSize > 0 {
		// hard limit: include only instructions within [funcAddr, funcAddr+funcSize)
		end := funcAddr + disasm.Address(funcSize)
		for i, instr := range instructions {
			if instr.Address >= end {
				return instructions[:i]
			}
		}
		return instructions
	}

	// find the next function symbol after funcAddr
	nextFuncAddr = 0
	for _, sym := range symbols {
		if sym.Type != binfmt.SymbolTypeFunction {
			continue
		}
		addr := disasm.Address(sym.Address)
		if addr <= funcAddr {
			continue
		}
		if nextFuncAddr == 0 || addr < nextFuncAddr {
			nextFuncAddr = addr
		}
	}

	if nextFuncAddr > 0 {
		// stop before the next function starts; also stop after last ret before that boundary
		lastRet := -1
		for i, instr := range instructions {
			if instr.Address >= nextFuncAddr {
				// stop here regardless
				if lastRet >= 0 {
					return instructions[:lastRet+1]
				}
				return instructions[:i]
			}
			m := strings.ToLower(instr.Mnemonic)
			if m == "ret" || m == "retn" {
				lastRet = i
			}
		}
		if lastRet >= 0 {
			return instructions[:lastRet+1]
		}
	}

	// final fallback: first ret
	return trimToFunctionBoundary(instructions)
}
