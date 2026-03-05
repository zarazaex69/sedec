package cfg

import (
	"fmt"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// IncrementalUpdate represents a pending CFG update operation
type IncrementalUpdate struct {
	UpdateType UpdateType
	JumpSite   disasm.Address
	Targets    []disasm.Address
	Provenance *EdgeProvenance
	Metadata   map[string]any
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
func (b *Builder) applyAddBlock(update *IncrementalUpdate) error {
	// this would require new instructions to be provided
	// placeholder for future implementation when discovering new code
	return fmt.Errorf("AddBlock update type not yet implemented")
}

// applySplitBlock splits an existing block when new branch target is discovered mid-block
func (b *Builder) applySplitBlock(update *IncrementalUpdate) error {
	// find block containing the split point
	splitAddr := update.Targets[0]
	blockID, exists := b.addressToBlock[splitAddr]
	if !exists {
		return fmt.Errorf("split address 0x%x not found in any block", splitAddr)
	}

	block, exists := b.cfg.GetBlock(blockID)
	if !exists {
		return fmt.Errorf("block %d not found in cfg", blockID)
	}

	// check if split point is already block start (no split needed)
	if block.StartAddress == splitAddr {
		return nil // already a block boundary
	}

	// find split point in instructions
	splitIndex := -1
	for i, instr := range block.Instructions {
		if instr.Address == splitAddr {
			splitIndex = i
			break
		}
	}

	if splitIndex == -1 {
		return fmt.Errorf("split address 0x%x not found in block instructions", splitAddr)
	}

	if splitIndex == 0 {
		return nil // already at block start
	}

	// create new block for second half
	newBlockID := b.nextBlockID
	b.nextBlockID++

	newBlock := &BasicBlock{
		ID:           newBlockID,
		StartAddress: block.Instructions[splitIndex].Address,
		EndAddress:   block.EndAddress,
		Instructions: block.Instructions[splitIndex:],
		Predecessors: make([]BlockID, 0),
		Successors:   block.Successors, // inherit successors
	}

	// update original block
	block.Instructions = block.Instructions[:splitIndex]
	block.EndAddress = block.Instructions[len(block.Instructions)-1].Address
	block.Successors = []BlockID{newBlockID} // now only points to new block

	// add new block to cfg
	b.cfg.AddBlock(newBlock)

	// update address mapping for new block instructions
	for _, instr := range newBlock.Instructions {
		b.addressToBlock[instr.Address] = newBlockID
	}

	// update successor blocks' predecessors
	for _, succID := range newBlock.Successors {
		if succBlock, exists := b.cfg.GetBlock(succID); exists {
			// replace old block with new block in predecessors
			for i, predID := range succBlock.Predecessors {
				if predID == blockID {
					succBlock.Predecessors[i] = newBlockID
				}
			}
		}
	}

	// add edge from old block to new block
	b.cfg.AddEdge(blockID, newBlockID, EdgeTypeFallthrough)

	// update edges that pointed to old block
	for i, edge := range b.cfg.Edges {
		if edge.To == blockID && edge.From != blockID {
			// check if this edge should point to new block instead
			// (if target address is in new block range)
			b.cfg.Edges[i].To = newBlockID
			newBlock.Predecessors = append(newBlock.Predecessors, edge.From)
		}
	}

	return nil
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
