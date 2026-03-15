package cfg

import (
	"errors"
	"fmt"
	"sort"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

var (
	// errEmptyInstructionList indicates empty instruction list.
	errEmptyInstructionList = errors.New("cannot build cfg from empty instruction list")
	// errJumpSiteNotFound indicates jump site address not found.
	errJumpSiteNotFound = errors.New("jump site address not found in any block")
	// errTargetNotFound indicates target address not found.
	errTargetNotFound = errors.New("target address not found in any block")
	// errIndirectJumpNotFound indicates indirect jump not found in unresolved list.
	errIndirectJumpNotFound = errors.New("indirect jump not found in unresolved list")
)

// Builder constructs control flow graphs from disassembled instructions.
type Builder struct {
	cfg           *CFG
	dominatorTree *DominatorTree // cached dominator tree for loop detection

	// maps instruction address to block id for quick lookup.
	addressToBlock map[disasm.Address]BlockID

	// tracks which addresses are block leaders (start of basic blocks).
	blockLeaders map[disasm.Address]bool

	// tracks unresolved indirect jumps for later resolution (deprecated - use cfg.UnresolvedIndirectJumps).
	unresolvedIndirectJumps map[disasm.Address]bool
	instructions            []*disasm.Instruction
	nextBlockID             BlockID

	// incremental update tracking.
	incrementalMode bool // whether builder is in incremental update mode
}

// NewCFGBuilder creates a new CFG builder.
func NewCFGBuilder() *Builder {
	return &Builder{
		cfg:                     NewCFG(),
		nextBlockID:             0,
		addressToBlock:          make(map[disasm.Address]BlockID),
		blockLeaders:            make(map[disasm.Address]bool),
		unresolvedIndirectJumps: make(map[disasm.Address]bool),
		incrementalMode:         false,
	}
}

// Build constructs a control flow graph from disassembled instructions.
// This is the main entry point for CFG construction.
func (b *Builder) Build(instructions []*disasm.Instruction) (*CFG, error) {
	if len(instructions) == 0 {
		return nil, errEmptyInstructionList
	}

	b.instructions = instructions

	// phase 1: identify block leaders (basic block boundaries)
	b.identifyBlockLeaders()

	// phase 2: create basic blocks from identified leaders
	b.createBasicBlocks()

	// phase 3: update block IDs in unresolved indirect jump structures
	b.updateUnresolvedIndirectJumpBlocks()

	// phase 4: build control flow edges between blocks
	b.buildControlFlowEdges()

	// phase 5: identify entry and exit blocks
	b.identifyEntryAndExits()

	return b.cfg, nil
}

// identifyBlockLeaders determines which instruction addresses start basic blocks
// A basic block leader is:
// 1. The first instruction in the function
// 2. Any instruction that is the target of a jump or branch
// 3. Any instruction immediately following a branch or jump.
func (b *Builder) identifyBlockLeaders() {
	if len(b.instructions) == 0 {
		return
	}

	// first instruction is always a block leader
	b.blockLeaders[b.instructions[0].Address] = true

	for i, instr := range b.instructions {
		mnemonic := instr.Mnemonic

		// check if this is a control flow instruction
		switch {
		case isUnconditionalJump(mnemonic):
			// target of jump is a block leader
			if target := extractJumpTarget(instr); target != 0 {
				b.blockLeaders[target] = true
			} else {
				// indirect jump - mark as unresolved and create tracking structure
				b.unresolvedIndirectJumps[instr.Address] = true
				b.registerUnresolvedIndirectJump(instr, IndirectJumpUnknown)
			}

			// instruction after unconditional jump is a block leader (if exists)
			if i+1 < len(b.instructions) {
				b.blockLeaders[b.instructions[i+1].Address] = true
			}
		case isConditionalBranch(mnemonic):
			// target of branch is a block leader
			if target := extractJumpTarget(instr); target != 0 {
				b.blockLeaders[target] = true
			}

			// instruction after conditional branch is a block leader (fall-through path)
			if i+1 < len(b.instructions) {
				b.blockLeaders[b.instructions[i+1].Address] = true
			}
		case isReturn(mnemonic):
			// instruction after return is a block leader (if exists)
			if i+1 < len(b.instructions) {
				b.blockLeaders[b.instructions[i+1].Address] = true
			}
		case isCall(mnemonic):
			// instruction after call is a block leader (return point)
			if i+1 < len(b.instructions) {
				b.blockLeaders[b.instructions[i+1].Address] = true
			}
		}
	}
}

// createBasicBlocks creates basic block structures from identified leaders.
func (b *Builder) createBasicBlocks() {
	if len(b.instructions) == 0 {
		return
	}

	// collect and sort leader addresses for sequential processing
	leaderAddresses := make([]disasm.Address, 0, len(b.blockLeaders))
	for addr := range b.blockLeaders {
		leaderAddresses = append(leaderAddresses, addr)
	}
	sort.Slice(leaderAddresses, func(i, j int) bool {
		return leaderAddresses[i] < leaderAddresses[j]
	})

	// create basic blocks between consecutive leaders
	for i := 0; i < len(leaderAddresses); i++ {
		startAddr := leaderAddresses[i]

		// determine end address (next leader or end of instructions)
		var endAddr disasm.Address
		if i+1 < len(leaderAddresses) {
			endAddr = leaderAddresses[i+1]
		} else {
			// last block extends to end of instruction list
			lastInstr := b.instructions[len(b.instructions)-1]
			//nolint:gosec // instruction length is small, overflow impossible
			endAddr = lastInstr.Address + disasm.Address(lastInstr.Length)
		}

		// collect instructions for this block
		blockInstructions := b.collectInstructionsInRange(startAddr, endAddr)
		if len(blockInstructions) == 0 {
			continue
		}

		// create basic block
		blockID := b.nextBlockID
		b.nextBlockID++

		block := &BasicBlock{
			ID:           blockID,
			StartAddress: blockInstructions[0].Address,
			EndAddress:   blockInstructions[len(blockInstructions)-1].Address,
			Instructions: blockInstructions,
			Predecessors: make([]BlockID, 0),
			Successors:   make([]BlockID, 0),
		}

		b.cfg.AddBlock(block)

		// map all instruction addresses in this block to block id
		for _, instr := range blockInstructions {
			b.addressToBlock[instr.Address] = blockID
		}
	}
}

// collectInstructionsInRange collects instructions within address range [start, end).
func (b *Builder) collectInstructionsInRange(start, end disasm.Address) []*disasm.Instruction {
	result := make([]*disasm.Instruction, 0)

	for _, instr := range b.instructions {
		if instr.Address >= start && instr.Address < end {
			result = append(result, instr)
		}
	}

	return result
}

// buildControlFlowEdges creates edges between basic blocks based on control flow.
func (b *Builder) buildControlFlowEdges() {
	for _, block := range b.cfg.Blocks {
		if len(block.Instructions) == 0 {
			continue
		}

		// examine last instruction in block to determine successors
		lastInstr := block.Instructions[len(block.Instructions)-1]
		mnemonic := lastInstr.Mnemonic

		switch {
		case isUnconditionalJump(mnemonic):
			// unconditional jump - single successor
			if target := extractJumpTarget(lastInstr); target != 0 {
				if targetBlockID, exists := b.addressToBlock[target]; exists {
					b.cfg.AddEdge(block.ID, targetBlockID, EdgeTypeUnconditional)
				}
			}
			// indirect jump - no edge created yet (will be resolved later)
		case isConditionalBranch(mnemonic):
			// conditional branch - two successors (taken and fall-through)

			// taken branch edge
			if target := extractJumpTarget(lastInstr); target != 0 {
				if targetBlockID, exists := b.addressToBlock[target]; exists {
					b.cfg.AddEdge(block.ID, targetBlockID, EdgeTypeConditional)
				}
			}

			// fall-through edge
			//nolint:gosec // instruction length is small, overflow impossible
			fallThroughAddr := lastInstr.Address + disasm.Address(lastInstr.Length)
			if fallThroughBlockID, exists := b.addressToBlock[fallThroughAddr]; exists {
				b.cfg.AddEdge(block.ID, fallThroughBlockID, EdgeTypeFallthrough)
			}
		case isReturn(mnemonic):
			// return instruction - no successors, mark as exit block
			b.cfg.Exits = append(b.cfg.Exits, block.ID)
		default:
			// regular instruction or call - fall-through to next block
			//nolint:gosec // instruction length is small, overflow impossible
			fallThroughAddr := lastInstr.Address + disasm.Address(lastInstr.Length)
			if fallThroughBlockID, exists := b.addressToBlock[fallThroughAddr]; exists {
				b.cfg.AddEdge(block.ID, fallThroughBlockID, EdgeTypeFallthrough)
			}
		}
	}
}

// identifyEntryAndExits determines entry block and exit blocks.
func (b *Builder) identifyEntryAndExits() {
	if len(b.instructions) == 0 {
		return
	}

	// entry block is the block containing the first instruction
	firstAddr := b.instructions[0].Address
	if entryBlockID, exists := b.addressToBlock[firstAddr]; exists {
		b.cfg.Entry = entryBlockID
	}

	// exit blocks are already identified during edge building (blocks ending with return)
	// no additional work needed here
}

// mnemonic constant for unconditional jump
const mnemonicJmp = "jmp"

// isUnconditionalJump checks if mnemonic is an unconditional jump.
func isUnconditionalJump(mnemonic string) bool {
	return mnemonic == mnemonicJmp
}

// isConditionalBranch checks if mnemonic is a conditional branch.
func isConditionalBranch(mnemonic string) bool {
	// x86_64 conditional jump instructions
	switch mnemonic {
	case "je", "jz", // jump if equal / zero
		"jne", "jnz", // jump if not equal / not zero
		"jg", "jnle", // jump if greater / not less or equal
		"jge", "jnl", // jump if greater or equal / not less
		"jl", "jnge", // jump if less / not greater or equal
		"jle", "jng", // jump if less or equal / not greater
		"ja", "jnbe", // jump if above / not below or equal (unsigned)
		"jae", "jnb", "jnc", // jump if above or equal / not below / not carry (unsigned)
		"jb", "jnae", "jc", // jump if below / not above or equal / carry (unsigned)
		"jbe", "jna", // jump if below or equal / not above (unsigned)
		"jo",        // jump if overflow
		"jno",       // jump if not overflow
		"js",        // jump if sign
		"jns",       // jump if not sign
		"jp", "jpe", // jump if parity / parity even
		"jnp", "jpo", // jump if not parity / parity odd
		"jcxz", "jecxz", "jrcxz": // jump if cx/ecx/rcx is zero
		return true
	default:
		return false
	}
}

// isReturn checks if mnemonic is a return instruction.
func isReturn(mnemonic string) bool {
	switch mnemonic {
	case "ret", "retf", "retn":
		return true
	default:
		return false
	}
}

// isCall checks if mnemonic is a call instruction.
func isCall(mnemonic string) bool {
	switch mnemonic {
	case "call", "callf":
		return true
	default:
		return false
	}
}

// extractJumpTarget extracts the target address from a jump or branch instruction.
// Returns 0 if target cannot be determined (indirect jump).
func extractJumpTarget(instr *disasm.Instruction) disasm.Address {
	if len(instr.Operands) == 0 {
		return 0
	}

	// check first operand for immediate address
	switch op := instr.Operands[0].(type) {
	case disasm.ImmediateOperand:
		// direct jump with immediate address
		if op.Value >= 0 {
			return disasm.Address(op.Value)
		}
		return 0
	case disasm.RegisterOperand:
		// indirect jump through register - cannot determine statically
		return 0
	case disasm.MemoryOperand:
		// indirect jump through memory - cannot determine statically
		return 0
	default:
		return 0
	}
}

// GetUnresolvedIndirectJumps returns addresses of indirect jumps that need resolution.
func (b *Builder) GetUnresolvedIndirectJumps() []disasm.Address {
	result := make([]disasm.Address, 0, len(b.unresolvedIndirectJumps))
	for addr := range b.unresolvedIndirectJumps {
		result = append(result, addr)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i] < result[j]
	})
	return result
}

// AddIndirectTarget adds a resolved indirect jump target to the CFG.
// This is used during cyclic feedback from type inference.
func (b *Builder) AddIndirectTarget(jumpSite, target disasm.Address) error {
	return b.AddIndirectTargetWithProvenance(jumpSite, target, &EdgeProvenance{
		AnalysisPass: "type_inference",
		Confidence:   0.9,
		Metadata:     make(map[string]any),
	})
}

// AddIndirectTargetWithProvenance adds a resolved indirect jump target with provenance tracking.
func (b *Builder) AddIndirectTargetWithProvenance(jumpSite, target disasm.Address, provenance *EdgeProvenance) error {
	// find block containing jump site
	jumpBlockID, exists := b.addressToBlock[jumpSite]
	if !exists {
		return fmt.Errorf("%w: 0x%x", errJumpSiteNotFound, jumpSite)
	}

	// find or create block for target address
	targetBlockID, exists := b.addressToBlock[target]
	if !exists {
		return fmt.Errorf("%w: 0x%x", errTargetNotFound, target)
	}

	// add indirect edge with provenance
	b.cfg.AddEdgeWithProvenance(jumpBlockID, targetBlockID, EdgeTypeIndirect, provenance)

	// update unresolved indirect jump tracking
	if jump, found := b.cfg.GetUnresolvedIndirectJump(jumpSite); found {
		// add to possible targets if not already present
		targetExists := false
		for _, existingTarget := range jump.PossibleTargets {
			if existingTarget == target {
				targetExists = true
				break
			}
		}
		if !targetExists {
			jump.PossibleTargets = append(jump.PossibleTargets, target)
		}
	}

	// remove from legacy unresolved set
	delete(b.unresolvedIndirectJumps, jumpSite)

	return nil
}

// AddIndirectTargets adds multiple resolved targets for an indirect jump (e.g., switch table).
func (b *Builder) AddIndirectTargets(jumpSite disasm.Address, targets []disasm.Address, provenance *EdgeProvenance) error {
	for _, target := range targets {
		if err := b.AddIndirectTargetWithProvenance(jumpSite, target, provenance); err != nil {
			return fmt.Errorf("failed to add target 0x%x: %w", target, err)
		}
	}
	return nil
}

// MarkIndirectJumpResolved marks an indirect jump as fully resolved and removes from unresolved list.
func (b *Builder) MarkIndirectJumpResolved(jumpSite disasm.Address) bool {
	return b.cfg.RemoveUnresolvedIndirectJump(jumpSite)
}

// ClassifyIndirectJump updates the classification of an indirect jump.
func (b *Builder) ClassifyIndirectJump(jumpSite disasm.Address, kind IndirectJumpKind) error {
	jump, found := b.cfg.GetUnresolvedIndirectJump(jumpSite)
	if !found {
		return fmt.Errorf("%w: 0x%x", errIndirectJumpNotFound, jumpSite)
	}
	jump.JumpKind = kind
	return nil
}

// registerUnresolvedIndirectJump creates tracking structure for unresolved indirect jump.
func (b *Builder) registerUnresolvedIndirectJump(instr *disasm.Instruction, kind IndirectJumpKind) {
	// find block containing this instruction (may not exist yet during initial scan)
	blockID, exists := b.addressToBlock[instr.Address]
	if !exists {
		blockID = 0 // will be updated during createBasicBlocks
	}

	jump := &UnresolvedIndirectJump{
		JumpSite:        instr.Address,
		BlockID:         blockID,
		Instruction:     instr,
		PossibleTargets: make([]disasm.Address, 0),
		JumpKind:        kind,
		Metadata:        make(map[string]any),
	}

	b.cfg.AddUnresolvedIndirectJump(jump)
}

// UpdateUnresolvedIndirectJumpBlocks updates block IDs for unresolved jumps after block creation
func (b *Builder) updateUnresolvedIndirectJumpBlocks() {
	for _, jump := range b.cfg.UnresolvedIndirectJumps {
		if blockID, exists := b.addressToBlock[jump.JumpSite]; exists {
			jump.BlockID = blockID
		}
	}
}

// EnableIncrementalMode enables incremental CFG update mode
func (b *Builder) EnableIncrementalMode() {
	b.incrementalMode = true
}

// DisableIncrementalMode disables incremental CFG update mode
func (b *Builder) DisableIncrementalMode() {
	b.incrementalMode = false
}
