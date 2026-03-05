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
	From       BlockID         // source block
	To         BlockID         // destination block
	Type       EdgeType        // type of control flow edge
	Provenance *EdgeProvenance // tracks how this edge was discovered (nil for direct edges)
}

// EdgeProvenance tracks the source of edge discovery for debugging and analysis
type EdgeProvenance struct {
	AnalysisPass string         // which analysis pass discovered this edge (e.g., "initial", "type_inference", "vsa")
	Confidence   float64        // confidence level (0.0 to 1.0) for inferred edges
	Metadata     map[string]any // additional metadata about edge discovery
}

// UnresolvedIndirectJump represents an indirect jump that needs resolution
type UnresolvedIndirectJump struct {
	JumpSite        disasm.Address      // address of the indirect jump instruction
	BlockID         BlockID             // block containing the jump
	Instruction     *disasm.Instruction // the actual jump instruction
	PossibleTargets []disasm.Address    // candidate targets discovered so far
	JumpKind        IndirectJumpKind    // classification of indirect jump type
	Metadata        map[string]any      // additional analysis metadata
}

// IndirectJumpKind classifies types of indirect jumps for targeted resolution
type IndirectJumpKind int

const (
	// IndirectJumpUnknown represents unclassified indirect jump
	IndirectJumpUnknown IndirectJumpKind = iota
	// IndirectJumpVTable represents C++ virtual function call through vtable
	IndirectJumpVTable
	// IndirectJumpHandlerTable represents switch jump table or handler array
	IndirectJumpHandlerTable
	// IndirectJumpInterfaceTable represents Go interface method call through itab
	IndirectJumpInterfaceTable
	// IndirectJumpFunctionPointer represents generic function pointer call
	IndirectJumpFunctionPointer
	// IndirectJumpComputedGoto represents computed goto (GCC extension)
	IndirectJumpComputedGoto
)

func (k IndirectJumpKind) String() string {
	switch k {
	case IndirectJumpVTable:
		return "VTable"
	case IndirectJumpHandlerTable:
		return "HandlerTable"
	case IndirectJumpInterfaceTable:
		return "InterfaceTable"
	case IndirectJumpFunctionPointer:
		return "FunctionPointer"
	case IndirectJumpComputedGoto:
		return "ComputedGoto"
	default:
		return "Unknown"
	}
}

// CFG represents a control flow graph for a function
type CFG struct {
	Blocks                  map[BlockID]*BasicBlock   // all basic blocks indexed by ID
	Edges                   []*Edge                   // all control flow edges
	Exits                   []BlockID                 // exit block IDs (blocks ending with return)
	Entry                   BlockID                   // entry block ID
	UnresolvedIndirectJumps []*UnresolvedIndirectJump // indirect jumps awaiting resolution
}

// NewCFG creates a new empty control flow graph
func NewCFG() *CFG {
	return &CFG{
		Blocks:                  make(map[BlockID]*BasicBlock),
		Edges:                   make([]*Edge, 0),
		Exits:                   make([]BlockID, 0),
		UnresolvedIndirectJumps: make([]*UnresolvedIndirectJump, 0),
	}
}

// AddBlock adds a basic block to the CFG
func (cfg *CFG) AddBlock(block *BasicBlock) {
	cfg.Blocks[block.ID] = block
}

// AddEdge adds a control flow edge to the CFG
func (cfg *CFG) AddEdge(from, to BlockID, edgeType EdgeType) {
	cfg.AddEdgeWithProvenance(from, to, edgeType, nil)
}

// AddEdgeWithProvenance adds a control flow edge with provenance tracking
func (cfg *CFG) AddEdgeWithProvenance(from, to BlockID, edgeType EdgeType, provenance *EdgeProvenance) {
	edge := &Edge{
		From:       from,
		To:         to,
		Type:       edgeType,
		Provenance: provenance,
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

// UnresolvedIndirectJumpCount returns the number of unresolved indirect jumps
func (cfg *CFG) UnresolvedIndirectJumpCount() int {
	return len(cfg.UnresolvedIndirectJumps)
}

// AddUnresolvedIndirectJump registers an indirect jump that needs resolution
func (cfg *CFG) AddUnresolvedIndirectJump(jump *UnresolvedIndirectJump) {
	cfg.UnresolvedIndirectJumps = append(cfg.UnresolvedIndirectJumps, jump)
}

// RemoveUnresolvedIndirectJump removes an indirect jump from unresolved list
func (cfg *CFG) RemoveUnresolvedIndirectJump(jumpSite disasm.Address) bool {
	for i, jump := range cfg.UnresolvedIndirectJumps {
		if jump.JumpSite == jumpSite {
			// remove by swapping with last element and truncating
			cfg.UnresolvedIndirectJumps[i] = cfg.UnresolvedIndirectJumps[len(cfg.UnresolvedIndirectJumps)-1]
			cfg.UnresolvedIndirectJumps = cfg.UnresolvedIndirectJumps[:len(cfg.UnresolvedIndirectJumps)-1]
			return true
		}
	}
	return false
}

// GetUnresolvedIndirectJump retrieves unresolved indirect jump by address
func (cfg *CFG) GetUnresolvedIndirectJump(jumpSite disasm.Address) (*UnresolvedIndirectJump, bool) {
	for _, jump := range cfg.UnresolvedIndirectJumps {
		if jump.JumpSite == jumpSite {
			return jump, true
		}
	}
	return nil, false
}
