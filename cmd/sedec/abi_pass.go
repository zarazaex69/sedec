package main

import (
	"fmt"
	"strings"

	"github.com/zarazaex69/sedec/pkg/abi"
	binfmt "github.com/zarazaex69/sedec/pkg/binary"
	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// x86_64RegisterNames is the complete set of x86-64 register names (lowercase).
// used by the register variable renaming pass to identify variables that must be renamed.
var x86_64RegisterNames = map[string]bool{
	// 64-bit general purpose
	"rax": true, "rbx": true, "rcx": true, "rdx": true,
	"rsi": true, "rdi": true, "rbp": true, "rsp": true,
	"r8": true, "r9": true, "r10": true, "r11": true,
	"r12": true, "r13": true, "r14": true, "r15": true,
	// 32-bit general purpose
	"eax": true, "ebx": true, "ecx": true, "edx": true,
	"esi": true, "edi": true, "ebp": true, "esp": true,
	"r8d": true, "r9d": true, "r10d": true, "r11d": true,
	"r12d": true, "r13d": true, "r14d": true, "r15d": true,
	// 16-bit general purpose
	"ax": true, "bx": true, "cx": true, "dx": true,
	"si": true, "di": true, "bp": true, "sp": true,
	"r8w": true, "r9w": true, "r10w": true, "r11w": true,
	"r12w": true, "r13w": true, "r14w": true, "r15w": true,
	// 8-bit general purpose
	"al": true, "ah": true, "bl": true, "bh": true,
	"cl": true, "ch": true, "dl": true, "dh": true,
	"sil": true, "dil": true, "bpl": true, "spl": true,
	"r8b": true, "r9b": true, "r10b": true, "r11b": true,
	"r12b": true, "r13b": true, "r14b": true, "r15b": true,
	// xmm registers (128-bit sse/avx)
	"xmm0": true, "xmm1": true, "xmm2": true, "xmm3": true,
	"xmm4": true, "xmm5": true, "xmm6": true, "xmm7": true,
	"xmm8": true, "xmm9": true, "xmm10": true, "xmm11": true,
	"xmm12": true, "xmm13": true, "xmm14": true, "xmm15": true,
	// instruction pointer and flags
	"rip": true, "eip": true, "rflags": true, "eflags": true,
}

// systemVIntArgRegs is the ordered list of integer argument registers for System V AMD64.
// arguments are passed left-to-right in these registers (§3.2.3 of the ABI spec).
var systemVIntArgRegs = []string{"rdi", "rsi", "rdx", "rcx", "r8", "r9"}

// msX64IntArgRegs is the ordered list of integer argument registers for Microsoft x64.
var msX64IntArgRegs = []string{"rcx", "rdx", "r8", "r9"}

// applyABIPass runs the ABI analysis pass over the IR function.
// it detects the calling convention, then for each call site in the IR
// determines which argument registers are live and populates Call.Args.
// it also sets the function signature (parameters and return type) on irFunc.
// db is the ground-truth database used to resolve call target addresses to symbol names;
// it may be nil (e.g., in unit tests), in which case no resolution is performed.
// returns the FunctionABI result for use by downstream passes (e.g., renameRegisterVariables).
func applyABIPass(irFunc *ir.Function, rawInsns []*disasm.Instruction, db *binfmt.GroundTruthDatabase) *abi.FunctionABI {
	// detect calling convention from binary format / platform heuristic.
	// for now we default to system v amd64 (linux/macos); windows binaries
	// would need pe format detection to switch to microsoft x64.
	convention := abi.CallingConventionSystemVAMD64
	analyzer, err := abi.NewAnalyzer(convention)
	if err != nil {
		return nil
	}

	// run full abi analysis on the raw instruction stream
	funcABI := analyzer.Analyze(rawInsns)

	// mark frame prologue/epilogue instructions as artifacts so codegen suppresses them
	frameAddrs := collectFrameArtifactAddresses(rawInsns, funcABI.Frame, funcABI.CalleeSavedRegs)
	markFrameArtifacts(irFunc, frameAddrs)

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

			// resolve call target: replace numeric address constants with symbol names
			// using the ground-truth database (got/plt, symbol table, imports).
			callNode.Target = resolveCallTarget(callNode.Target, db)

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

	return funcABI
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

// collectFrameArtifactAddresses identifies the addresses of frame prologue/epilogue
// instructions in rawInsns. it returns a set of addresses that should be marked
// as frame artifacts in the ir so the code generator can suppress them.
//
// identified patterns:
//   - push rbp  (frame pointer save)
//   - mov rbp, rsp  (frame pointer establishment)
//   - sub rsp, N  (first stack allocation after mov rbp,rsp — not alloca)
//   - pop rbp  (frame pointer restore)
//   - leave  (equivalent to mov rsp,rbp; pop rbp)
//
// additionally, callee-saved register spill/restore sites from funcABI are included.
func collectFrameArtifactAddresses(
	rawInsns []*disasm.Instruction,
	frame *abi.StackFrame,
	calleeSaved []abi.CalleeSavedRegisterStatus,
) map[disasm.Address]bool {
	addrs := make(map[disasm.Address]bool)

	// track whether we have seen "mov rbp, rsp" to gate the sub rsp detection
	seenMovRbpRsp := false
	// track whether we have already absorbed the first sub rsp (frame allocation)
	absorbedSubRsp := false

	for _, insn := range rawInsns {
		m := strings.ToLower(insn.Mnemonic)

		switch m {
		case "push":
			// push rbp — frame pointer save
			if len(insn.Operands) == 1 {
				if reg, ok := insn.Operands[0].(disasm.RegisterOperand); ok {
					if strings.ToLower(reg.Name) == "rbp" {
						addrs[insn.Address] = true
					}
				}
			}

		case "mov":
			// mov rbp, rsp — frame pointer establishment
			if len(insn.Operands) == 2 {
				dest, destOk := insn.Operands[0].(disasm.RegisterOperand)
				src, srcOk := insn.Operands[1].(disasm.RegisterOperand)
				if destOk && srcOk &&
					strings.ToLower(dest.Name) == "rbp" &&
					strings.ToLower(src.Name) == "rsp" {
					addrs[insn.Address] = true
					seenMovRbpRsp = true
					absorbedSubRsp = false // reset for this function
				}
			}

		case "sub":
			// sub rsp, N — first stack allocation after mov rbp,rsp is the frame artifact
			if seenMovRbpRsp && !absorbedSubRsp && len(insn.Operands) == 2 {
				dest, destOk := insn.Operands[0].(disasm.RegisterOperand)
				_, immOk := insn.Operands[1].(disasm.ImmediateOperand)
				if destOk && immOk && strings.ToLower(dest.Name) == "rsp" {
					addrs[insn.Address] = true
					absorbedSubRsp = true
				}
			}

		case "pop":
			// pop rbp — frame pointer restore
			if len(insn.Operands) == 1 {
				if reg, ok := insn.Operands[0].(disasm.RegisterOperand); ok {
					if strings.ToLower(reg.Name) == "rbp" {
						addrs[insn.Address] = true
					}
				}
			}

		case "leave":
			// leave = mov rsp,rbp; pop rbp
			addrs[insn.Address] = true
		}
	}

	// include callee-saved register spill/restore sites from abi analysis
	for _, cs := range calleeSaved {
		if cs.SaveSite != 0 {
			addrs[cs.SaveSite] = true
		}
		if cs.RestoreSite != 0 {
			addrs[cs.RestoreSite] = true
		}
	}

	// frame parameter is reserved for future use (e.g., alloca detection)
	_ = frame

	return addrs
}

// markFrameArtifacts walks all ir instructions in irFunc and sets IsFrameArtifact = true
// on every instruction whose source address is in frameAddrs.
// only pointer-receiver instruction types are handled because the lifter emits pointers.
func markFrameArtifacts(irFunc *ir.Function, frameAddrs map[disasm.Address]bool) {
	if len(frameAddrs) == 0 {
		return
	}

	for _, block := range irFunc.Blocks {
		for _, instr := range block.Instructions {
			loc := instr.Location()
			if !frameAddrs[disasm.Address(loc.Address)] {
				continue
			}
			// set IsFrameArtifact on the concrete pointer type via type switch
			switch typed := instr.(type) {
			case *ir.Assign:
				typed.Loc.IsFrameArtifact = true
			case *ir.Store:
				typed.Loc.IsFrameArtifact = true
			case *ir.Load:
				typed.Loc.IsFrameArtifact = true
			case *ir.Call:
				typed.Loc.IsFrameArtifact = true
			case *ir.Return:
				typed.Loc.IsFrameArtifact = true
			case *ir.Branch:
				typed.Loc.IsFrameArtifact = true
			case *ir.Jump:
				typed.Loc.IsFrameArtifact = true
			case *ir.Phi:
				typed.Loc.IsFrameArtifact = true
			}
		}
	}
}

// resolveCallTarget attempts to replace a numeric call target address with the
// corresponding symbol name from the ground-truth database.
//
// resolution priority order:
//  1. db.GOTPLT — plt stub addresses (highest priority: these are the canonical import stubs)
//  2. db.SymbolsByAddress — static symbol table entries
//  3. db.Imports — dynamic import table entries
//
// if db is nil, or if target is not a ConstantExpr with an IntConstant, or if the
// address is not found in any map, the original target expression is returned unchanged.
// indirect calls through registers (e.g., call rax) are left unchanged because they
// are VariableExpr nodes, not ConstantExpr nodes.
func resolveCallTarget(target ir.Expression, db *binfmt.GroundTruthDatabase) ir.Expression {
	if db == nil {
		return target
	}

	// only direct calls with a constant address can be resolved
	constExpr, ok := target.(ir.ConstantExpr)
	if !ok {
		return target
	}
	intConst, ok := constExpr.Value.(ir.IntConstant)
	if !ok {
		return target
	}

	// #nosec G115 — intentional conversion: addresses are unsigned 64-bit values
	addr := binfmt.Address(uint64(intConst.Value))

	// priority 1: got/plt map — plt stub addresses resolve to imported symbol names
	if _, inGOTPLT := db.GOTPLT[addr]; inGOTPLT {
		if name, ok := db.SymbolsByAddress[addr]; ok && name != "" {
			return ir.VariableExpr{
				Var: ir.Variable{
					Name: name,
					Type: ir.PointerType{Pointee: ir.VoidType{}},
				},
			}
		}
	}

	// priority 2: static symbol table
	if name, ok := db.SymbolsByAddress[addr]; ok && name != "" {
		return ir.VariableExpr{
			Var: ir.Variable{
				Name: name,
				Type: ir.PointerType{Pointee: ir.VoidType{}},
			},
		}
	}

	// priority 3: dynamic import table
	if imp, ok := db.Imports[addr]; ok && imp != nil && imp.Name != "" {
		return ir.VariableExpr{
			Var: ir.Variable{
				Name: imp.Name,
				Type: ir.PointerType{Pointee: ir.VoidType{}},
			},
		}
	}

	// address not found in any map — leave target unchanged
	return target
}
