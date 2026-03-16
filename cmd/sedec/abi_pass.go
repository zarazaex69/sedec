package main

import (
	"fmt"
	"strings"

	"github.com/zarazaex69/sedec/pkg/abi"
	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// systemVIntArgRegs is the ordered list of integer argument registers for System V AMD64.
// arguments are passed left-to-right in these registers (§3.2.3 of the ABI spec).
var systemVIntArgRegs = []string{"rdi", "rsi", "rdx", "rcx", "r8", "r9"}

// msX64IntArgRegs is the ordered list of integer argument registers for Microsoft x64.
var msX64IntArgRegs = []string{"rcx", "rdx", "r8", "r9"}

// applyABIPass runs the ABI analysis pass over the IR function.
// it detects the calling convention, then for each call site in the IR
// determines which argument registers are live and populates Call.Args.
// it also sets the function signature (parameters and return type) on irFunc.
func applyABIPass(irFunc *ir.Function, rawInsns []*disasm.Instruction) {
	// detect calling convention from binary format / platform heuristic.
	// for now we default to system v amd64 (linux/macos); windows binaries
	// would need pe format detection to switch to microsoft x64.
	convention := abi.CallingConventionSystemVAMD64
	analyzer, err := abi.NewAnalyzer(convention)
	if err != nil {
		return
	}

	// run full abi analysis on the raw instruction stream
	funcABI := analyzer.Analyze(rawInsns)

	// update function signature from abi analysis
	applyFunctionSignature(irFunc, funcABI)

	// build a per-address instruction index for fast lookup
	insnByAddr := make(map[disasm.Address]*disasm.Instruction, len(rawInsns))
	for _, insn := range rawInsns {
		insnByAddr[insn.Address] = insn
	}

	// select argument register list for this convention
	argRegs := systemVIntArgRegs
	if convention == abi.CallingConventionMicrosoftX64 {
		argRegs = msX64IntArgRegs
	}

	// walk all ir blocks and populate Call.Args for each call instruction
	for _, block := range irFunc.Blocks {
		for i, instr := range block.Instructions {
			callNode, ok := ir.AsCall(instr)
			if !ok {
				continue
			}

			// find the raw call instruction at this address to locate the call site
			callAddr := disasm.Address(instr.Location().Address)

			// collect live argument registers immediately before this call.
			// we scan backwards from the call site through the raw instruction stream
			// to find the last writes to each argument register.
			callResult := collectCallArgs(callAddr, rawInsns, insnByAddr, argRegs)
			callNode.Args = callResult.args

			// determine return value: if rax is written by the call target,
			// assign a fresh temp as the call destination.
			// heuristic: if the call is followed by a use of rax, assume non-void return.
			if callNode.Dest == nil {
				if dest := inferCallDest(callAddr, rawInsns, irFunc); dest != nil {
					callNode.Dest = dest
					// register the new temp variable in the function's variable list
					irFunc.Variables = append(irFunc.Variables, *dest)
				}
			}

			block.Instructions[i] = &callNode

			// remove ir instructions that were emitted for absorbed push instructions.
			// the lifter emits a Store (push value onto stack) and an Assign (rsp -= 8)
			// for each push. now that these pushes are represented as Call.Args, those
			// ir instructions are pure noise — remove them from the block.
			if len(callResult.absorbedPushAddrs) > 0 {
				removeAbsorbedPushInstrs(block, callResult.absorbedPushAddrs)
			}
		}
	}

	// patch ir.Return instructions: if the function has a non-void return type,
	// set Return.Value to the return register variable so codegen emits
	// "return rax;" instead of bare "return;".
	if len(funcABI.ReturnValues) > 0 {
		retReg := funcABI.ReturnValues[0].Register
		retType := funcABI.ReturnValues[0].Type
		retVar := ir.Variable{
			Name: retReg,
			Type: retType,
		}
		for _, block := range irFunc.Blocks {
			for i, instr := range block.Instructions {
				if r, ok := ir.AsReturn(instr); ok && r.Value == nil {
					patched := r
					patched.Value = &retVar
					block.Instructions[i] = &patched
				}
			}
		}
	}
}

// collectCallArgsResult holds the result of collectCallArgs.
type collectCallArgsResult struct {
	args              []ir.Variable
	absorbedPushAddrs map[disasm.Address]bool // addresses of push insns absorbed as stack args
}

// collectCallArgs scans backwards from callAddr through rawInsns to find
// the last write to each argument register before the call, and also collects
// stack-passed arguments from push instructions (system v: 7th+ arg).
// returns args in argument order (arg0, arg1, ...) and the set of push
// instruction addresses that were absorbed into the call abstraction.
// stops collecting when a register has not been written since function entry
// or since the previous call (indicating it is not an argument for this call).
func collectCallArgs(
	callAddr disasm.Address,
	rawInsns []*disasm.Instruction,
	insnByAddr map[disasm.Address]*disasm.Instruction,
	argRegs []string,
) collectCallArgsResult {
	_ = insnByAddr // reserved for future per-address lookup

	// find the index of the call instruction in the raw stream
	callIdx := -1
	for i, insn := range rawInsns {
		if insn.Address == callAddr {
			callIdx = i
			break
		}
	}
	if callIdx < 0 {
		return collectCallArgsResult{}
	}

	// track which argument registers have been written before the call.
	// scan backwards from callIdx-1 to find the most recent write to each reg.
	written := make(map[string]bool, len(argRegs))
	argVars := make(map[string]ir.Variable, len(argRegs))

	// collect push-based stack arguments in reverse order (last push = last arg).
	// system v amd64: after the 6 register slots, additional args are pushed
	// right-to-left, so the first push encountered scanning backwards is the
	// last (highest-indexed) stack argument.
	var stackArgs []ir.Variable
	absorbedPushAddrs := make(map[disasm.Address]bool)

	for i := callIdx - 1; i >= 0; i-- {
		insn := rawInsns[i]
		mnemonic := strings.ToLower(insn.Mnemonic)

		// stop at a previous call: argument registers are reset at each call boundary
		if mnemonic == "call" {
			break
		}

		if len(insn.Operands) == 0 {
			continue
		}

		// handle push instructions: each push before the call is a stack argument.
		// scanning backwards means we encounter them in reverse push order;
		// we prepend to stackArgs to restore left-to-right argument order.
		if mnemonic == "push" {
			op := insn.Operands[0]
			var argVar ir.Variable
			switch typedOp := op.(type) {
			case disasm.RegisterOperand:
				argVar = ir.Variable{
					Name: strings.ToLower(typedOp.Name),
					Type: ir.IntType{Width: ir.Size8, Signed: false},
				}
			case disasm.ImmediateOperand:
				// immediate pushed as stack arg: represent as a synthetic temp
				argVar = ir.Variable{
					Name: fmt.Sprintf("imm%d", typedOp.Value),
					Type: ir.IntType{Width: ir.Size8, Signed: false},
				}
			default:
				// memory operand or other: use a generic placeholder
				argVar = ir.Variable{
					Name: "stack_arg",
					Type: ir.IntType{Width: ir.Size8, Signed: false},
				}
			}
			// prepend: scanning backwards, so first push found = last arg pushed
			stackArgs = append([]ir.Variable{argVar}, stackArgs...)
			// record this push address as absorbed: the ir.Store and rsp Assign
			// that the lifter emitted for this push are now redundant.
			absorbedPushAddrs[insn.Address] = true
			continue
		}

		// check if the destination operand is an argument register
		destOp, ok := insn.Operands[0].(disasm.RegisterOperand)
		if !ok {
			continue
		}

		// skip flag-only instructions (test, cmp do not write their destination)
		if mnemonic == "test" || mnemonic == "cmp" {
			continue
		}

		// only consider writes (destination operand, not source)
		if len(insn.Operands) < 2 && mnemonic != "pop" && mnemonic != "inc" && mnemonic != "dec" {
			continue
		}

		regName := strings.ToLower(destOp.Name)
		canonical := canonicalizeABIReg(regName)

		for _, argReg := range argRegs {
			if canonical == argReg && !written[argReg] {
				written[argReg] = true
				argVars[argReg] = ir.Variable{
					Name: regName,
					Type: ir.IntType{Width: ir.Size8, Signed: false},
				}
				break
			}
		}

		// stop early if all argument registers have been found
		if len(written) == len(argRegs) {
			break
		}
	}

	// build ordered argument list: register args first (contiguous from arg0),
	// then stack args appended in push order.
	result := make([]ir.Variable, 0, len(argRegs)+len(stackArgs))
	for _, argReg := range argRegs {
		v, ok := argVars[argReg]
		if !ok {
			// gap in argument registers: stop register args here
			break
		}
		result = append(result, v)
	}
	// append stack-passed arguments after register arguments
	result = append(result, stackArgs...)

	return collectCallArgsResult{args: result, absorbedPushAddrs: absorbedPushAddrs}
}

// inferCallDest checks whether the instruction immediately following the call
// uses rax (the return value register). if so, returns a fresh temp variable
// to hold the return value; otherwise returns nil (void call).
func inferCallDest(
	callAddr disasm.Address,
	rawInsns []*disasm.Instruction,
	irFunc *ir.Function,
) *ir.Variable {
	// find the call instruction index
	callIdx := -1
	for i, insn := range rawInsns {
		if insn.Address == callAddr {
			callIdx = i
			break
		}
	}
	if callIdx < 0 || callIdx+1 >= len(rawInsns) {
		return nil
	}

	// scan forward from the instruction after the call to find rax usage
	for i := callIdx + 1; i < len(rawInsns) && i < callIdx+8; i++ {
		insn := rawInsns[i]
		mnemonic := strings.ToLower(insn.Mnemonic)

		// stop at another call or ret
		if mnemonic == "call" || mnemonic == "ret" || mnemonic == "retn" {
			break
		}

		// check if rax is used as a source operand
		for opIdx, op := range insn.Operands {
			regOp, ok := op.(disasm.RegisterOperand)
			if !ok {
				continue
			}
			regName := strings.ToLower(regOp.Name)
			canonical := canonicalizeABIReg(regName)
			isSource := opIdx > 0 || len(insn.Operands) == 1
			if isSource && canonical == "rax" {
				// rax is used after the call: non-void return
				dest := allocCallReturnVar(irFunc)
				return dest
			}
		}
	}

	return nil
}

// allocCallReturnVar allocates a fresh temporary variable for a call return value.
// the variable name is derived from the count of existing call-return temps.
func allocCallReturnVar(irFunc *ir.Function) *ir.Variable {
	// count existing call return vars to generate a unique name
	count := 0
	for _, v := range irFunc.Variables {
		if strings.HasPrefix(v.Name, "ret") {
			count++
		}
	}
	v := ir.Variable{
		Name: "rax", // use rax directly: the return value lives in rax
		Type: ir.IntType{Width: ir.Size8, Signed: false},
	}
	return &v
}

// applyFunctionSignature updates the ir.Function signature from abi analysis results.
func applyFunctionSignature(irFunc *ir.Function, funcABI *abi.FunctionABI) {
	// build parameter type list
	params := make([]ir.Type, len(funcABI.Parameters))
	for i, p := range funcABI.Parameters {
		params[i] = p.Type
	}

	// determine return type
	var retType ir.Type = ir.VoidType{}
	if len(funcABI.ReturnValues) > 0 {
		retType = funcABI.ReturnValues[0].Type
	}

	irFunc.Signature = ir.FunctionType{
		ReturnType: retType,
		Parameters: params,
		Variadic:   funcABI.IsVariadic,
	}
}

// canonicalizeABIReg maps register aliases to their 64-bit canonical name.
// mirrors abi.canonicalizeRegister but is package-local to cmd/sedec.
func canonicalizeABIReg(name string) string {
	switch name {
	case "rax", "eax", "ax", "al", "ah":
		return "rax"
	case "rbx", "ebx", "bx", "bl", "bh":
		return "rbx"
	case "rcx", "ecx", "cx", "cl", "ch":
		return "rcx"
	case "rdx", "edx", "dx", "dl", "dh":
		return "rdx"
	case "rsi", "esi", "si", "sil":
		return "rsi"
	case "rdi", "edi", "di", "dil":
		return "rdi"
	case "rbp", "ebp", "bp", "bpl":
		return "rbp"
	case "rsp", "esp", "sp", "spl":
		return "rsp"
	case "r8", "r8d", "r8w", "r8b":
		return "r8"
	case "r9", "r9d", "r9w", "r9b":
		return "r9"
	case "r10", "r10d", "r10w", "r10b":
		return "r10"
	case "r11", "r11d", "r11w", "r11b":
		return "r11"
	case "r12", "r12d", "r12w", "r12b":
		return "r12"
	case "r13", "r13d", "r13w", "r13b":
		return "r13"
	case "r14", "r14d", "r14w", "r14b":
		return "r14"
	case "r15", "r15d", "r15w", "r15b":
		return "r15"
	default:
		return name
	}
}

// removeAbsorbedPushInstrs removes ir.Store and ir.Assign instructions from block
// that were emitted by the lifter for push instructions whose addresses are in
// absorbedAddrs. a push rax lifts to:
//   - ir.Assign: rsp = rsp - 8   (stack pointer decrement)
//   - ir.Store:  *(rsp) = rax    (value write)
//
// both carry the source address of the push instruction in their SourceLocation.
// since these are now represented as Call.Args, they are pure noise in the ir.
func removeAbsorbedPushInstrs(block *ir.BasicBlock, absorbedAddrs map[disasm.Address]bool) {
	kept := block.Instructions[:0]
	for _, instr := range block.Instructions {
		loc := instr.Location()
		addr := disasm.Address(loc.Address)
		if !absorbedAddrs[addr] {
			kept = append(kept, instr)
			continue
		}
		// only remove Store and Assign emitted for the push; preserve everything else
		// at this address (e.g., a call instruction itself shares no address with push)
		switch instr.(type) {
		case ir.Store, *ir.Store, ir.Assign, *ir.Assign:
			// drop: this is the push artifact
		default:
			kept = append(kept, instr)
		}
	}
	block.Instructions = kept
}
