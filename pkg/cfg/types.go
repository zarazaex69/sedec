package cfg

import (
	"github.com/zarazaex69/sedec/pkg/disasm"
)

// BlockID uniquely identifies a basic block within a CFG
type BlockID uint64

// BasicBlock represents a sequence of instructions with single entry and exit points
type BasicBlock struct {
	Instructions []*disasm.Instruction // instructions in this block
	Predecessors []BlockID             // blocks that can jump to this block
	Successors   []BlockID             // blocks this block can jump to
	ID           BlockID               // unique identifier for this block
	StartAddress disasm.Address        // virtual address of first instruction
	EndAddress   disasm.Address        // virtual address of last instruction
}

// EdgeType represents the type of control flow edge
type EdgeType int

const (
	// EdgeTypeUnknown represents an unknown edge type
	EdgeTypeUnknown EdgeType = iota
	// EdgeTypeFallthrough represents sequential execution to next block
	EdgeTypeFallthrough
	// EdgeTypeUnconditional represents unconditional jump
	EdgeTypeUnconditional
	// EdgeTypeConditional represents conditional branch (taken)
	EdgeTypeConditional
	// EdgeTypeCall represents function call
	EdgeTypeCall
	// EdgeTypeReturn represents function return
	EdgeTypeReturn
	// EdgeTypeIndirect represents indirect jump (unresolved target)
	EdgeTypeIndirect
)

func (e EdgeType) String() string {
	switch e {
	case EdgeTypeFallthrough:
		return "Fallthrough"
	case EdgeTypeUnconditional:
		return "Unconditional"
	case EdgeTypeConditional:
		return "Conditional"
	case EdgeTypeCall:
		return "Call"
	case EdgeTypeReturn:
		return "Return"
	case EdgeTypeIndirect:
		return "Indirect"
	default:
		return "Unknown"
	}
}

// Edge represents a directed edge in the control flow graph
type Edge struct {
	From BlockID  // source block
	To   BlockID  // destination block
	Type EdgeType // type of control flow edge
}

// CFG represents a control flow graph for a function
type CFG struct {
	Blocks map[BlockID]*BasicBlock // all basic blocks indexed by ID
	Edges  []*Edge                 // all control flow edges
	Exits  []BlockID               // exit block IDs (blocks ending with return)
	Entry  BlockID                 // entry block ID
}

// NewCFG creates a new empty control flow graph
func NewCFG() *CFG {
	return &CFG{
		Blocks: make(map[BlockID]*BasicBlock),
		Edges:  make([]*Edge, 0),
		Exits:  make([]BlockID, 0),
	}
}

// AddBlock adds a basic block to the CFG
func (cfg *CFG) AddBlock(block *BasicBlock) {
	cfg.Blocks[block.ID] = block
}

// AddEdge adds a control flow edge to the CFG
func (cfg *CFG) AddEdge(from, to BlockID, edgeType EdgeType) {
	edge := &Edge{
		From: from,
		To:   to,
		Type: edgeType,
	}
	cfg.Edges = append(cfg.Edges, edge)

	// update predecessor/successor relationships
	if fromBlock, exists := cfg.Blocks[from]; exists {
		fromBlock.Successors = append(fromBlock.Successors, to)
	}
	if toBlock, exists := cfg.Blocks[to]; exists {
		toBlock.Predecessors = append(toBlock.Predecessors, from)
	}
}

// GetBlock retrieves a basic block by ID
func (cfg *CFG) GetBlock(id BlockID) (*BasicBlock, bool) {
	block, exists := cfg.Blocks[id]
	return block, exists
}

// BlockCount returns the number of basic blocks in the CFG
func (cfg *CFG) BlockCount() int {
	return len(cfg.Blocks)
}

// EdgeCount returns the number of edges in the CFG
func (cfg *CFG) EdgeCount() int {
	return len(cfg.Edges)
}
