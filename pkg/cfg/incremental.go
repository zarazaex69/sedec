package cfg

import (
	"fmt"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// IncrementalUpdate represents a pending CFG update operation
type IncrementalUpdate struct {
	Provenance *EdgeProvenance
	Metadata   map[string]any
	Targets    []disasm.Address
	JumpSite   disasm.Address
	UpdateType UpdateType
}

// UpdateType classifies the type of incremental update
type UpdateType int

const (
	// UpdateTypeAddEdge adds new edge to existing blocks
	UpdateTypeAddEdge UpdateType = iota
	// UpdateTypeAddBlock adds new basic block (discovered code)
	UpdateTypeAddBlock
	// UpdateTypeResolveIndirect resolves indirect jump target
	UpdateTypeResolveIndirect
	// UpdateTypeSplitBlock splits existing block (new branch target discovered)
	UpdateTypeSplitBlock
)

func (u UpdateType) String() string {
	switch u {
	case UpdateTypeAddEdge:
		return "AddEdge"
	case UpdateTypeAddBlock:
		return "AddBlock"
	case UpdateTypeResolveIndirect:
		return "ResolveIndirect"
	case UpdateTypeSplitBlock:
		return "SplitBlock"
	default:
		return "Unknown"
	}
}

// IncrementalUpdateQueue manages pending CFG updates for batch processing
type IncrementalUpdateQueue struct {
	updates []*IncrementalUpdate
}

// NewIncrementalUpdateQueue creates a new update queue
func NewIncrementalUpdateQueue() *IncrementalUpdateQueue {
	return &IncrementalUpdateQueue{
		updates: make([]*IncrementalUpdate, 0),
	}
}

// Enqueue adds an update to the queue
func (q *IncrementalUpdateQueue) Enqueue(update *IncrementalUpdate) {
	q.updates = append(q.updates, update)
}

// Dequeue removes and returns the next update
func (q *IncrementalUpdateQueue) Dequeue() (*IncrementalUpdate, bool) {
	if len(q.updates) == 0 {
		return nil, false
	}
	update := q.updates[0]
	q.updates = q.updates[1:]
	return update, true
}

// Size returns the number of pending updates
func (q *IncrementalUpdateQueue) Size() int {
	return len(q.updates)
}

// Clear removes all pending updates
func (q *IncrementalUpdateQueue) Clear() {
	q.updates = make([]*IncrementalUpdate, 0)
}

// ApplyIncrementalUpdate applies a single incremental update to the CFG
func (b *Builder) ApplyIncrementalUpdate(update *IncrementalUpdate) error {
	switch update.UpdateType {
	case UpdateTypeResolveIndirect:
		return b.applyResolveIndirect(update)
	case UpdateTypeAddEdge:
		return b.applyAddEdge(update)
	case UpdateTypeAddBlock:
		return b.applyAddBlock(update)
	case UpdateTypeSplitBlock:
		return b.applySplitBlock(update)
	default:
		return fmt.Errorf("unknown update type: %v", update.UpdateType)
	}
}

// applyResolveIndirect resolves indirect jump with discovered targets
func (b *Builder) applyResolveIndirect(update *IncrementalUpdate) error {
	if len(update.Targets) == 0 {
		return fmt.Errorf("no targets provided for indirect jump resolution")
	}

	// add all targets
	for _, target := range update.Targets {
		if err := b.AddIndirectTargetWithProvenance(update.JumpSite, target, update.Provenance); err != nil {
			return fmt.Errorf("failed to add target 0x%x: %w", target, err)
		}
	}

	return nil
}

// applyAddEdge adds a new edge between existing blocks
func (b *Builder) applyAddEdge(update *IncrementalUpdate) error {
	if len(update.Targets) != 1 {
		return fmt.Errorf("AddEdge requires exactly one target, got %d", len(update.Targets))
	}

	jumpBlockID, exists := b.addressToBlock[update.JumpSite]
	if !exists {
		return fmt.Errorf("source address 0x%x not found in any block", update.JumpSite)
	}

	targetBlockID, exists := b.addressToBlock[update.Targets[0]]
	if !exists {
		return fmt.Errorf("target address 0x%x not found in any block", update.Targets[0])
	}

	b.cfg.AddEdgeWithProvenance(jumpBlockID, targetBlockID, EdgeTypeIndirect, update.Provenance)
	return nil
}

// applyAddBlock adds a new basic block (for discovered code regions)
func (b *Builder) applyAddBlock(_ *IncrementalUpdate) error {
	// this would require new instructions to be provided
	// placeholder for future implementation when discovering new code
	return fmt.Errorf("AddBlock update type not yet implemented")
}

// applySplitBlock splits an existing block when new branch target is discovered mid-block
func (b *Builder) applySplitBlock(update *IncrementalUpdate) error {
	splitAddr := update.Targets[0]

	block, blockID, err := b.findBlockForSplit(splitAddr)
	if err != nil {
		return err
	}

	// check if split point is already block start (no split needed)
	if block.StartAddress == splitAddr {
		return nil
	}

	splitIndex, err := b.findSplitIndex(block, splitAddr)
	if err != nil {
		return err
	}

	if splitIndex == 0 {
		return nil
	}

	newBlock := b.createSplitBlock(block, splitIndex, blockID)
	b.updateOriginalBlock(block, splitIndex, newBlock.ID)
	b.updateAddressMappings(newBlock)
	b.updateSuccessorPredecessors(newBlock, blockID)
	b.cfg.AddEdge(blockID, newBlock.ID, EdgeTypeFallthrough)
	b.redirectEdgesToNewBlock(newBlock, blockID)

	return nil
}

// findBlockForSplit locates the block containing the split address
func (b *Builder) findBlockForSplit(splitAddr disasm.Address) (*BasicBlock, BlockID, error) {
	blockID, exists := b.addressToBlock[splitAddr]
	if !exists {
		return nil, 0, fmt.Errorf("split address 0x%x not found in any block", splitAddr)
	}

	block, exists := b.cfg.GetBlock(blockID)
	if !exists {
		return nil, 0, fmt.Errorf("block %d not found in cfg", blockID)
	}

	return block, blockID, nil
}

// findSplitIndex finds the instruction index where the split should occur
func (b *Builder) findSplitIndex(block *BasicBlock, splitAddr disasm.Address) (int, error) {
	for i, instr := range block.Instructions {
		if instr.Address == splitAddr {
			return i, nil
		}
	}
	return -1, fmt.Errorf("split address 0x%x not found in block instructions", splitAddr)
}

// createSplitBlock creates a new block from the split point onwards
func (b *Builder) createSplitBlock(originalBlock *BasicBlock, splitIndex int, _ BlockID) *BasicBlock {
	newBlockID := b.nextBlockID
	b.nextBlockID++

	newBlock := &BasicBlock{
		ID:           newBlockID,
		StartAddress: originalBlock.Instructions[splitIndex].Address,
		EndAddress:   originalBlock.EndAddress,
		Instructions: originalBlock.Instructions[splitIndex:],
		Predecessors: make([]BlockID, 0),
		Successors:   originalBlock.Successors,
	}

	b.cfg.AddBlock(newBlock)
	return newBlock
}

// updateOriginalBlock modifies the original block after split
func (b *Builder) updateOriginalBlock(block *BasicBlock, splitIndex int, newBlockID BlockID) {
	block.Instructions = block.Instructions[:splitIndex]
	block.EndAddress = block.Instructions[len(block.Instructions)-1].Address
	block.Successors = []BlockID{newBlockID}
}

// updateAddressMappings updates address-to-block mappings for new block
func (b *Builder) updateAddressMappings(newBlock *BasicBlock) {
	for _, instr := range newBlock.Instructions {
		b.addressToBlock[instr.Address] = newBlock.ID
	}
}

// updateSuccessorPredecessors updates predecessor lists in successor blocks
func (b *Builder) updateSuccessorPredecessors(newBlock *BasicBlock, oldBlockID BlockID) {
	for _, succID := range newBlock.Successors {
		if succBlock, blockExists := b.cfg.GetBlock(succID); blockExists {
			for i, predID := range succBlock.Predecessors {
				if predID == oldBlockID {
					succBlock.Predecessors[i] = newBlock.ID
				}
			}
		}
	}
}

// redirectEdgesToNewBlock redirects edges that should point to the new block
func (b *Builder) redirectEdgesToNewBlock(newBlock *BasicBlock, oldBlockID BlockID) {
	for i, edge := range b.cfg.Edges {
		if edge.To == oldBlockID && edge.From != oldBlockID {
			b.cfg.Edges[i].To = newBlock.ID
			newBlock.Predecessors = append(newBlock.Predecessors, edge.From)
		}
	}
}

// BatchApplyUpdates applies multiple incremental updates efficiently
func (b *Builder) BatchApplyUpdates(updates []*IncrementalUpdate) error {
	b.EnableIncrementalMode()
	defer b.DisableIncrementalMode()

	for i, update := range updates {
		if err := b.ApplyIncrementalUpdate(update); err != nil {
			return fmt.Errorf("failed to apply update %d: %w", i, err)
		}
	}

	return nil
}

// GetIncrementalUpdateStats returns statistics about incremental updates
func (b *Builder) GetIncrementalUpdateStats() *IncrementalUpdateStats {
	resolvedCount := 0
	unresolvedCount := 0

	// count resolved and unresolved indirect jumps
	for _, jump := range b.cfg.UnresolvedIndirectJumps {
		if len(jump.PossibleTargets) > 0 {
			resolvedCount++
		} else {
			unresolvedCount++
		}
	}

	totalCount := resolvedCount + unresolvedCount

	return &IncrementalUpdateStats{
		TotalIndirectJumps:      totalCount,
		ResolvedIndirectJumps:   resolvedCount,
		UnresolvedIndirectJumps: unresolvedCount,
		TotalBlocks:             b.cfg.BlockCount(),
		TotalEdges:              b.cfg.EdgeCount(),
	}
}

// IncrementalUpdateStats contains statistics about CFG updates
type IncrementalUpdateStats struct {
	TotalIndirectJumps      int
	ResolvedIndirectJumps   int
	UnresolvedIndirectJumps int
	TotalBlocks             int
	TotalEdges              int
}

// ResolutionRate returns the percentage of resolved indirect jumps
func (s *IncrementalUpdateStats) ResolutionRate() float64 {
	if s.TotalIndirectJumps == 0 {
		return 1.0
	}
	return float64(s.ResolvedIndirectJumps) / float64(s.TotalIndirectJumps)
}
