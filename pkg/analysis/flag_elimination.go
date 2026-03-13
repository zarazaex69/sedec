package analysis

import (
	"fmt"
	"strings"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// flagSet is a bitmask of cpu flags using ir.CPUFlag constants.
// bit 0 = ZF, bit 1 = SF, bit 2 = CF, bit 3 = OF, bit 4 = PF, bit 5 = AF.
type flagSet uint8

const (
	flagBitZF flagSet = 1 << iota
	flagBitSF
	flagBitCF
	flagBitOF
	flagBitPF
	flagBitAF
	flagBitAll flagSet = flagBitZF | flagBitSF | flagBitCF | flagBitOF | flagBitPF | flagBitAF
)

// cpuFlagToBit converts ir.CPUFlag to its bitmask position.
func cpuFlagToBit(f ir.CPUFlag) flagSet {
	switch f {
	case ir.FlagZF:
		return flagBitZF
	case ir.FlagSF:
		return flagBitSF
	case ir.FlagCF:
		return flagBitCF
	case ir.FlagOF:
		return flagBitOF
	case ir.FlagPF:
		return flagBitPF
	case ir.FlagAF:
		return flagBitAF
	default:
		return 0
	}
}

// flagsFromSlice converts a slice of ir.CPUFlag to a flagSet bitmask.
func flagsFromSlice(flags []ir.CPUFlag) flagSet {
	var s flagSet
	for _, f := range flags {
		s |= cpuFlagToBit(f)
	}
	return s
}

// flagsConsumedByMnemonic returns the set of flags consumed by a given mnemonic.
// this is the authoritative consumer map for all flag-reading instructions.
func flagsConsumedByMnemonic(mnemonic string) flagSet {
	m := strings.ToLower(mnemonic)

	// conditional jumps — delegate to ir.GetRequiredFlags for consistency
	if ir.IsConditionalJump(m) {
		return flagsFromSlice(ir.GetRequiredFlags(m))
	}

	// conditional moves: cmovcc — same flag requirements as corresponding jcc
	if strings.HasPrefix(m, "cmov") {
		suffix := m[4:]
		return flagsFromSlice(ir.GetRequiredFlags("j" + suffix))
	}

	// set byte on condition: setcc — same flag requirements as corresponding jcc
	if strings.HasPrefix(m, "set") {
		suffix := m[3:]
		return flagsFromSlice(ir.GetRequiredFlags("j" + suffix))
	}

	// lahf reads ZF, SF, AF, PF, CF (stores them into AH)
	if m == "lahf" {
		return flagBitZF | flagBitSF | flagBitAF | flagBitPF | flagBitCF
	}

	// pushf/pushfq saves all flags to stack
	if m == "pushf" || m == "pushfq" {
		return flagBitAll
	}

	// sahf writes SF, ZF, AF, PF, CF from AH — it is a flag producer, not consumer
	// popf/popfq restores all flags — also a producer
	// clc/stc/cmc modify CF — producers
	// cld/std modify DF — not tracked
	// cli/sti modify IF — not tracked

	return 0
}

// LazyFlagAssignment represents a lazy flag computation attached to an IR instruction.
// in the current IR, lazy flags are tracked via the Lifter's currentLazyFlags field
// and stored as metadata. for analysis purposes we model them as assignments to
// synthetic flag variables named "__flags_<blockID>_<instrIdx>".
type LazyFlagAssignment struct {
	BlockID  ir.BlockID
	InstrIdx int
	Flags    *ir.LazyFlags // the lazy flags structure
}

// FlagProducerInfo records a flag-producing instruction and which flags it produces.
type FlagProducerInfo struct {
	Point         ProgramPoint
	ProducedFlags flagSet // all flags this instruction can produce
}

// EliminationResult holds statistics from flag elimination analysis.
type EliminationResult struct {
	// TotalFlags is the number of flag-producing instructions before elimination.
	TotalFlags int
	// EliminatedFlags is the number of flag-producing instructions eliminated.
	EliminatedFlags int
	// EliminationRate is EliminatedFlags / TotalFlags (0.0 to 1.0).
	EliminationRate float64
	// NeededFlags maps each surviving flag producer to the specific flags required.
	// key: ProgramPoint of the producer, value: bitmask of flags actually needed.
	NeededFlags map[ProgramPoint]flagSet
	// EliminatedPoints is the set of program points whose flag computations were eliminated.
	EliminatedPoints []ProgramPoint
}

// FlagEliminator performs backward data flow analysis on cpu flags.
// it determines which flag computations are live (consumed before overwrite)
// and eliminates those that are dead (overwritten before any consumer).
//
// the analysis models flags as a separate domain from regular variables:
//   - flag producers: arithmetic/logical instructions that set flags (add, sub, cmp, test, etc.)
//   - flag consumers: conditional branches and flag-reading instructions (jcc, cmovcc, setcc, lahf, pushf)
//   - flag killers: any flag producer also kills the previous flag state
//
// backward data flow equations (per block B):
//
//	FlagLiveOut(B) = union of FlagLiveIn(S) for all successors S
//	FlagLiveIn(B)  = FlagUse(B) union (FlagLiveOut(B) - FlagDef(B))
//
// where FlagUse(B) = flags consumed in B before any redefinition in B
// and   FlagDef(B) = flags defined (and thus killed) in B
type FlagEliminator struct {
	function *ir.Function
	cfgGraph *cfg.CFG
	domTree  *cfg.DominatorTree

	// producers maps each program point to the flags it produces.
	// populated during the scan phase before analysis.
	producers map[ProgramPoint]flagSet

	// consumers maps each program point to the flags it consumes.
	// populated during the scan phase before analysis.
	consumers map[ProgramPoint]flagSet

	// blockFlagLiveIn maps each block to the set of flags live at block entry.
	blockFlagLiveIn map[ir.BlockID]flagSet

	// blockFlagLiveOut maps each block to the set of flags live at block exit.
	blockFlagLiveOut map[ir.BlockID]flagSet

	// pointFlagLiveOut maps each program point to flags live after that instruction.
	pointFlagLiveOut map[ProgramPoint]flagSet
}

// NewFlagEliminator creates a new flag eliminator for the given function.
func NewFlagEliminator(
	function *ir.Function,
	cfgGraph *cfg.CFG,
	domTree *cfg.DominatorTree,
) *FlagEliminator {
	return &FlagEliminator{
		function:         function,
		cfgGraph:         cfgGraph,
		domTree:          domTree,
		producers:        make(map[ProgramPoint]flagSet),
		consumers:        make(map[ProgramPoint]flagSet),
		blockFlagLiveIn:  make(map[ir.BlockID]flagSet),
		blockFlagLiveOut: make(map[ir.BlockID]flagSet),
		pointFlagLiveOut: make(map[ProgramPoint]flagSet),
	}
}

// Analyze performs the complete flag elimination analysis.
// it scans the function for flag producers and consumers, runs backward
// data flow to compute flag liveness, then determines which producers
// can be eliminated.
func (e *FlagEliminator) Analyze() (*EliminationResult, error) {
	if e.function == nil {
		return nil, fmt.Errorf("flag elimination: function is nil")
	}
	if len(e.function.Blocks) == 0 {
		return nil, fmt.Errorf("flag elimination: function %q has no blocks", e.function.Name)
	}

	// phase 1: scan all instructions to identify producers and consumers
	e.scanInstructions()

	// phase 2: backward data flow to compute flag liveness
	e.computeFlagLiveness()

	// phase 3: determine which producers are dead and build result
	return e.buildResult(), nil
}

// scanInstructions scans all instructions to populate producers and consumers maps.
// a producer is any instruction that sets cpu flags (arithmetic, logical, shift, cmp, test).
// a consumer is any instruction that reads cpu flags (jcc, cmovcc, setcc, lahf, pushf).
func (e *FlagEliminator) scanInstructions() {
	for blockID, block := range e.function.Blocks {
		for instrIdx, instr := range block.Instructions {
			point := ProgramPoint{BlockID: blockID, InstrIdx: instrIdx}

			// check if this instruction consumes flags
			consumed := e.flagsConsumedByInstruction(instr)
			if consumed != 0 {
				e.consumers[point] = consumed
			}

			// check if this instruction produces flags
			produced := e.flagsProducedByInstruction(instr)
			if produced != 0 {
				e.producers[point] = produced
			}
		}
	}
}

// flagsConsumedByInstruction returns the set of flags consumed by an instruction.
// it inspects the source location mnemonic to determine flag consumption.
func (e *FlagEliminator) flagsConsumedByInstruction(instr ir.IRInstruction) flagSet {
	loc := instr.Location()
	if loc.Instruction == "" {
		return 0
	}

	// extract mnemonic from source location (format: "mnemonic operands")
	mnemonic := extractMnemonic(loc.Instruction)
	return flagsConsumedByMnemonic(mnemonic)
}

// flagsProducedByInstruction returns the set of flags produced by an instruction.
// flag producers are arithmetic/logical/shift operations and cmp/test.
// in the IR, these are Assign instructions whose source is a BinaryOp or UnaryOp
// that corresponds to a flag-setting x86 instruction.
func (e *FlagEliminator) flagsProducedByInstruction(instr ir.IRInstruction) flagSet {
	loc := instr.Location()
	if loc.Instruction == "" {
		return 0
	}

	mnemonic := extractMnemonic(loc.Instruction)
	return flagsProducedByMnemonic(mnemonic)
}

// flagsProducedByMnemonic returns the set of flags that a given mnemonic produces.
// all arithmetic and logical instructions produce the full set of flags (ZF, SF, CF, OF, PF, AF).
// the data flow analysis will then determine which subset is actually consumed.
func flagsProducedByMnemonic(mnemonic string) flagSet {
	m := strings.ToLower(mnemonic)

	// arithmetic operations: set ZF, SF, CF, OF, PF, AF
	switch m {
	case "add", "sub", "adc", "sbb", "neg", "inc", "dec", "cmp":
		return flagBitAll

	// logical operations: set ZF, SF, PF; clear CF, OF; AF undefined
	case "and", "or", "xor", "test":
		return flagBitZF | flagBitSF | flagBitCF | flagBitOF | flagBitPF

	// shift operations: set CF, ZF, SF, PF; OF defined for 1-bit shifts
	case "shl", "sal", "shr", "sar", "rol", "ror":
		return flagBitCF | flagBitZF | flagBitSF | flagBitPF | flagBitOF

	// multiply: sets CF, OF; ZF, SF, PF, AF undefined
	case "mul", "imul":
		return flagBitCF | flagBitOF

	// div/idiv: all flags undefined — model as producing all to be conservative
	case "div", "idiv":
		return flagBitAll

	// sahf writes SF, ZF, AF, PF, CF from AH
	case "sahf":
		return flagBitSF | flagBitZF | flagBitAF | flagBitPF | flagBitCF

	// popf/popfq restores all flags
	case "popf", "popfq":
		return flagBitAll

	// clc clears CF
	case "clc":
		return flagBitCF

	// stc sets CF
	case "stc":
		return flagBitCF

	// cmc complements CF
	case "cmc":
		return flagBitCF

	default:
		return 0
	}
}

// extractMnemonic extracts the mnemonic from an instruction string.
// instruction strings have the format "mnemonic operand1, operand2, ..."
// or just "mnemonic" for zero-operand instructions.
func extractMnemonic(instruction string) string {
	instruction = strings.TrimSpace(instruction)
	if instruction == "" {
		return ""
	}
	// find first space or end of string
	idx := strings.IndexByte(instruction, ' ')
	if idx < 0 {
		return instruction
	}
	return instruction[:idx]
}

// computeFlagLiveness performs iterative backward data flow analysis on flags.
// initializes all flag live sets to 0 (no flags live at function exit).
// iterates in postorder (successors before predecessors) until fixed point.
func (e *FlagEliminator) computeFlagLiveness() {
	rpo := e.reversePostOrder()

	// initialize all block flag live sets to 0
	for _, blockID := range rpo {
		e.blockFlagLiveIn[blockID] = 0
		e.blockFlagLiveOut[blockID] = 0
	}

	// iterative backward fixed-point computation
	changed := true
	for changed {
		changed = false
		// iterate in reverse of rpo = postorder (successors before predecessors)
		for i := len(rpo) - 1; i >= 0; i-- {
			blockID := rpo[i]
			block, exists := e.function.Blocks[blockID]
			if !exists {
				continue
			}

			// FlagLiveOut(B) = union of FlagLiveIn(S) for all successors S
			var newLiveOut flagSet
			for _, succID := range block.Successors {
				newLiveOut |= e.blockFlagLiveIn[succID]
			}

			// compute FlagUse(B) and FlagDef(B) for this block
			useB, defB := e.computeBlockFlagUseDef(block)

			// FlagLiveIn(B) = FlagUse(B) | (FlagLiveOut(B) & ~FlagDef(B))
			newLiveIn := useB | (newLiveOut &^ defB)

			if newLiveIn != e.blockFlagLiveIn[blockID] {
				e.blockFlagLiveIn[blockID] = newLiveIn
				changed = true
			}
			e.blockFlagLiveOut[blockID] = newLiveOut
		}
	}

	// propagate block-level results to per-instruction program points
	e.computeInstructionFlagLiveness(rpo)
}

// computeBlockFlagUseDef computes the upward-exposed flag use set and flag def set for a block.
// FlagUse(B): flags consumed in B before any redefinition in B (upward-exposed uses).
// FlagDef(B): flags defined (produced/killed) in B.
// scanned in forward order: uses before defs.
func (e *FlagEliminator) computeBlockFlagUseDef(block *ir.BasicBlock) (use flagSet, def flagSet) {
	for instrIdx := range block.Instructions {
		point := ProgramPoint{BlockID: block.ID, InstrIdx: instrIdx}

		// flags consumed at this point that are not yet defined in this block
		if consumed, ok := e.consumers[point]; ok {
			// only upward-exposed: flags consumed before being redefined in this block
			use |= consumed &^ def
		}

		// flags produced (defined/killed) at this point
		if produced, ok := e.producers[point]; ok {
			def |= produced
		}
	}
	return use, def
}

// computeInstructionFlagLiveness propagates block-level flag liveness to per-instruction
// program points by scanning each block backward from its live-out set.
func (e *FlagEliminator) computeInstructionFlagLiveness(rpo []ir.BlockID) {
	for _, blockID := range rpo {
		block, exists := e.function.Blocks[blockID]
		if !exists {
			continue
		}

		n := len(block.Instructions)
		if n == 0 {
			continue
		}

		// start from block live-out
		currentLive := e.blockFlagLiveOut[blockID]

		// scan instructions in reverse order
		for i := n - 1; i >= 0; i-- {
			point := ProgramPoint{BlockID: blockID, InstrIdx: i}

			// live-out for this instruction is the current live set
			e.pointFlagLiveOut[point] = currentLive

			// compute live-in for this instruction:
			// if this instruction consumes flags, add them to live set
			if consumed, ok := e.consumers[point]; ok {
				currentLive |= consumed
			}

			// if this instruction produces flags, kill the produced flags
			// (flags produced here are no longer live before this instruction)
			if produced, ok := e.producers[point]; ok {
				currentLive &^= produced
			}
		}
	}
}

// buildResult constructs the EliminationResult from the computed liveness information.
// a flag producer at point P is dead if none of its produced flags are live after P.
// a flag producer is live if at least one of its produced flags is live after P.
func (e *FlagEliminator) buildResult() *EliminationResult {
	result := &EliminationResult{
		NeededFlags:      make(map[ProgramPoint]flagSet),
		EliminatedPoints: make([]ProgramPoint, 0),
	}

	for point, produced := range e.producers {
		result.TotalFlags++

		liveOut := e.pointFlagLiveOut[point]
		// flags that are both produced and live after this point
		neededFlags := produced & liveOut

		if neededFlags == 0 {
			// no produced flag is consumed before overwrite — eliminate
			result.EliminatedFlags++
			result.EliminatedPoints = append(result.EliminatedPoints, point)
		} else {
			// at least one flag is needed — record which specific flags are required
			result.NeededFlags[point] = neededFlags
		}
	}

	if result.TotalFlags > 0 {
		result.EliminationRate = float64(result.EliminatedFlags) / float64(result.TotalFlags)
	} else {
		// no flag producers means 100% elimination (nothing to eliminate)
		result.EliminationRate = 1.0
	}

	return result
}

// reversePostOrder computes a reverse postorder traversal of the cfg.
// identical to the one in LiveVarsAnalyzer — reused here for consistency.
func (e *FlagEliminator) reversePostOrder() []ir.BlockID {
	visited := make(map[ir.BlockID]bool)
	postOrder := make([]ir.BlockID, 0, len(e.function.Blocks))

	var dfs func(ir.BlockID)
	dfs = func(blockID ir.BlockID) {
		if visited[blockID] {
			return
		}
		visited[blockID] = true

		block, exists := e.function.Blocks[blockID]
		if !exists {
			return
		}

		for _, succID := range block.Successors {
			dfs(succID)
		}

		postOrder = append(postOrder, blockID)
	}

	dfs(e.function.EntryBlock)

	// visit any unreachable blocks
	for blockID := range e.function.Blocks {
		if !visited[blockID] {
			dfs(blockID)
		}
	}

	// reverse to get reverse postorder
	rpo := make([]ir.BlockID, len(postOrder))
	for i, id := range postOrder {
		rpo[len(postOrder)-1-i] = id
	}
	return rpo
}

// EliminateFlags is the top-level entry point for flag elimination analysis.
// it creates a FlagEliminator and runs the complete analysis.
func EliminateFlags(
	function *ir.Function,
	cfgGraph *cfg.CFG,
	domTree *cfg.DominatorTree,
) (*EliminationResult, error) {
	eliminator := NewFlagEliminator(function, cfgGraph, domTree)
	return eliminator.Analyze()
}

// GetNeededFlagsAt returns the specific flags needed at a given program point.
// returns 0 if the producer at that point is dead (all flags eliminated).
func (r *EliminationResult) GetNeededFlagsAt(point ProgramPoint) flagSet {
	return r.NeededFlags[point]
}

// IsProducerEliminated reports whether the flag producer at the given point is dead.
func (r *EliminationResult) IsProducerEliminated(point ProgramPoint) bool {
	for _, p := range r.EliminatedPoints {
		if p == point {
			return true
		}
	}
	return false
}

// GetNeededCPUFlags returns the slice of ir.CPUFlag values needed at a program point.
// this is used by the IR lifter for selective materialization.
func (r *EliminationResult) GetNeededCPUFlags(point ProgramPoint) []ir.CPUFlag {
	bits := r.NeededFlags[point]
	if bits == 0 {
		return nil
	}

	flags := make([]ir.CPUFlag, 0, 6)
	if bits&flagBitZF != 0 {
		flags = append(flags, ir.FlagZF)
	}
	if bits&flagBitSF != 0 {
		flags = append(flags, ir.FlagSF)
	}
	if bits&flagBitCF != 0 {
		flags = append(flags, ir.FlagCF)
	}
	if bits&flagBitOF != 0 {
		flags = append(flags, ir.FlagOF)
	}
	if bits&flagBitPF != 0 {
		flags = append(flags, ir.FlagPF)
	}
	if bits&flagBitAF != 0 {
		flags = append(flags, ir.FlagAF)
	}
	return flags
}
