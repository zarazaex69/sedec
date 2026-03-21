package analysis

import (
	"fmt"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// DCEResult holds statistics from a dead code elimination pass.
type DCEResult struct {
	// RemovedInstructions is the number of dead instructions removed.
	RemovedInstructions int
	// RemovedBlocks is the number of unreachable blocks removed.
	RemovedBlocks int
	// Iterations is the number of fixed-point iterations performed.
	Iterations int
}

// DeadCodeEliminator eliminates dead code from an ir function using live
// variable analysis. it performs two complementary passes:
//
//  1. dead instruction elimination: removes variable definitions whose
//     defined variable is never live after the definition point.
//     side-effecting instructions (stores, calls, returns, branches, jumps)
//     are always preserved regardless of liveness.
//
//  2. unreachable block elimination: removes basic blocks that are not
//     reachable from the entry block via any control flow path.
//
// both passes iterate to a fixed point: removing a dead instruction may
// expose new dead instructions (e.g., the operands of the removed instruction
// may become dead), and removing unreachable blocks may expose new unreachable
// blocks.
type DeadCodeEliminator struct {
	function *ir.Function
	cfgGraph *cfg.CFG
	domTree  *cfg.DominatorTree
}

// NewDeadCodeEliminator creates a new dead code eliminator.
func NewDeadCodeEliminator(
	function *ir.Function,
	cfgGraph *cfg.CFG,
	domTree *cfg.DominatorTree,
) *DeadCodeEliminator {
	return &DeadCodeEliminator{
		function: function,
		cfgGraph: cfgGraph,
		domTree:  domTree,
	}
}

// Eliminate performs dead code elimination to a fixed point.
// the function ir is modified in place.
// returns statistics about what was removed.
func (e *DeadCodeEliminator) Eliminate() (*DCEResult, error) {
	if e.function == nil {
		return nil, fmt.Errorf("dead code elimination: %w", ErrNilFunction)
	}
	if len(e.function.Blocks) == 0 {
		return nil, fmt.Errorf("dead code elimination: function %q: %w", e.function.Name, ErrNoBlocks)
	}

	result := &DCEResult{}

	// iterate to fixed point: each pass may expose new dead code
	for {
		result.Iterations++

		// phase 1: remove unreachable blocks first.
		// unreachable blocks cannot contribute live variables, so removing
		// them before liveness analysis avoids spurious liveness propagation.
		removedBlocks := e.removeUnreachableBlocks()
		result.RemovedBlocks += removedBlocks

		// phase 2: run live variable analysis on the (now pruned) function
		liveAnalyzer := NewLiveVarsAnalyzer(e.function, e.cfgGraph, e.domTree)
		liveResult, err := liveAnalyzer.Compute()
		if err != nil {
			return nil, fmt.Errorf("dead code elimination: liveness analysis failed: %w", err)
		}

		// phase 3: remove dead instructions using liveness information
		removedInstrs := e.removeDeadInstructions(liveResult)
		result.RemovedInstructions += removedInstrs

		// convergence: stop when neither pass removed anything
		if removedBlocks == 0 && removedInstrs == 0 {
			break
		}
	}

	return result, nil
}

// removeUnreachableBlocks removes all basic blocks not reachable from the
// entry block via forward control flow edges. returns the number of blocks removed.
//
// reachability is computed via a simple bfs/dfs from the entry block.
// unreachable blocks are removed from the function's block map, and all
// predecessor/successor references to them are cleaned up.
func (e *DeadCodeEliminator) removeUnreachableBlocks() int {
	reachable := e.computeReachableBlocks()

	var toRemove []ir.BlockID
	for blockID := range e.function.Blocks {
		if !reachable[blockID] {
			toRemove = append(toRemove, blockID)
		}
	}

	if len(toRemove) == 0 {
		return 0
	}

	// build a set for O(1) lookup during cleanup
	removeSet := make(map[ir.BlockID]bool, len(toRemove))
	for _, id := range toRemove {
		removeSet[id] = true
	}

	// remove unreachable blocks from the function
	for _, id := range toRemove {
		delete(e.function.Blocks, id)
	}

	// clean up predecessor/successor lists in remaining blocks.
	// a remaining block may reference an unreachable block as a predecessor
	// (e.g., a conditional branch from an unreachable block).
	for _, block := range e.function.Blocks {
		block.Predecessors = filterBlockIDs(block.Predecessors, removeSet)
		block.Successors = filterBlockIDs(block.Successors, removeSet)
	}

	// clean up phi-node sources that reference removed blocks.
	// a phi-node source from an unreachable predecessor is dead.
	for _, block := range e.function.Blocks {
		for i, instr := range block.Instructions {
			phi, ok := instr.(*ir.Phi)
			if !ok {
				continue
			}
			filtered := phi.Sources[:0]
			for _, src := range phi.Sources {
				if !removeSet[src.Block] {
					filtered = append(filtered, src)
				}
			}
			phi.Sources = filtered
			block.Instructions[i] = phi
		}
	}

	return len(toRemove)
}

// computeReachableBlocks performs a depth-first traversal from the entry block
// and returns the set of all reachable block ids.
func (e *DeadCodeEliminator) computeReachableBlocks() map[ir.BlockID]bool {
	reachable := make(map[ir.BlockID]bool, len(e.function.Blocks))
	stack := []ir.BlockID{e.function.EntryBlock}

	for len(stack) > 0 {
		// pop
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if reachable[id] {
			continue
		}
		reachable[id] = true

		block, exists := e.function.Blocks[id]
		if !exists {
			continue
		}

		for _, succID := range block.Successors {
			if !reachable[succID] {
				stack = append(stack, succID)
			}
		}
	}

	return reachable
}

// removeDeadInstructions removes instructions whose defined variable is dead
// (not live after the instruction) and which have no side effects.
//
// an instruction is dead if ALL of the following hold:
//  1. it defines exactly one variable (assign, load, phi)
//  2. that variable is not live immediately after the instruction
//  3. the instruction has no observable side effects
//
// side-effecting instructions that are ALWAYS preserved:
//   - store: writes to memory (observable side effect)
//   - call: may have arbitrary side effects (I/O, global state, etc.)
//   - return: terminates the function
//   - branch: controls execution flow
//   - jump: controls execution flow
//
// returns the number of instructions removed.
func (e *DeadCodeEliminator) removeDeadInstructions(liveResult *LiveVarsResult) int {
	removed := 0

	for _, block := range e.function.Blocks {
		kept := block.Instructions[:0]
		for idx, instr := range block.Instructions {
			if e.isDeadInstruction(instr, ProgramPoint{BlockID: block.ID, InstrIdx: idx}, liveResult) {
				removed++
			} else {
				kept = append(kept, instr)
			}
		}
		block.Instructions = kept
	}

	return removed
}

// isDeadInstruction reports whether an instruction can be safely removed.
//
// an instruction is dead iff:
//   - it defines a variable (assign, load, phi)
//   - that variable is not live after the instruction
//   - the instruction has no side effects
//
// side-effecting instructions (store, call, return, branch, jump) are never dead.
func (e *DeadCodeEliminator) isDeadInstruction(
	instr ir.IRInstruction,
	point ProgramPoint,
	liveResult *LiveVarsResult,
) bool {
	switch i := instr.(type) {
	case *ir.Store:
		// stores always have side effects: memory write is observable
		return false

	case *ir.Call:
		// calls always have side effects: may modify global state, perform i/o, etc.
		// even void calls (no return value) must be preserved
		return false

	case *ir.Return:
		// returns terminate the function: always preserved
		return false

	case *ir.Branch:
		// branches control execution flow: always preserved
		return false

	case *ir.Jump:
		// jumps control execution flow: always preserved
		return false

	case *ir.Assign:
		liveOut := liveResult.GetLiveOutAt(point)
		return !liveOut.Contains(i.Dest)

	case *ir.Load:
		liveOut := liveResult.GetLiveOutAt(point)
		return !liveOut.Contains(i.Dest)

	case *ir.Phi:
		liveOut := liveResult.GetLiveOutAt(point)
		return !liveOut.Contains(i.Dest)

	case *ir.Intrinsic:
		if i.Dest == nil {
			return false
		}
		liveOut := liveResult.GetLiveOutAt(point)
		return !liveOut.Contains(*i.Dest)

	default:
		return false
	}
}

// filterBlockIDs returns a new slice containing only block ids not in the remove set.
func filterBlockIDs(ids []ir.BlockID, removeSet map[ir.BlockID]bool) []ir.BlockID {
	if len(ids) == 0 {
		return ids
	}
	result := ids[:0]
	for _, id := range ids {
		if !removeSet[id] {
			result = append(result, id)
		}
	}
	return result
}

// EliminateDeadCode is the top-level entry point for dead code elimination.
// it creates a DeadCodeEliminator and runs it to a fixed point.
func EliminateDeadCode(
	function *ir.Function,
	cfgGraph *cfg.CFG,
	domTree *cfg.DominatorTree,
) (*DCEResult, error) {
	eliminator := NewDeadCodeEliminator(function, cfgGraph, domTree)
	return eliminator.Eliminate()
}
