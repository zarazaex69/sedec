package ssa

import (
	"errors"
	"fmt"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

var (
	// errBlockNotFound indicates ir block not found in function
	errBlockNotFound = errors.New("block not found in ir function")
)

// Transformer performs ssa transformation on ir code.
// It implements phi-node placement using dominance frontiers
// and variable renaming to ensure single static assignment property.
type Transformer struct {
	function *ir.Function
	cfg      *cfg.CFG
	domTree  *cfg.DominatorTree
	domFront map[cfg.BlockID][]cfg.BlockID

	// variable definition tracking for phi-node placement
	varDefs map[string][]cfg.BlockID // maps variable name to blocks where it's defined

	// phi-node placement tracking
	phiPlaced map[string]map[cfg.BlockID]bool // tracks where phi-nodes are placed for each variable
}

// NewTransformer creates a new ssa transformer
func NewTransformer(function *ir.Function, cfgGraph *cfg.CFG, domTree *cfg.DominatorTree) *Transformer {
	return &Transformer{
		function:  function,
		cfg:       cfgGraph,
		domTree:   domTree,
		varDefs:   make(map[string][]cfg.BlockID),
		phiPlaced: make(map[string]map[cfg.BlockID]bool),
	}
}

// TransformToSSA performs complete ssa transformation
// this is the main entry point for ssa conversion
func (t *Transformer) TransformToSSA() error {
	// step 1: compute dominance frontiers
	t.domFront = t.domTree.ComputeDominanceFrontiers()

	// step 2: collect variable definitions across all blocks
	t.collectVariableDefinitions()

	// step 3: insert phi-nodes at dominance frontiers
	if err := t.insertPhiNodes(); err != nil {
		return fmt.Errorf("failed to insert phi-nodes: %w", err)
	}

	// step 4: rename variables (will be implemented in task 5.6)
	// if err := t.renameVariables(); err != nil {
	//     return fmt.Errorf("failed to rename variables: %w", err)
	// }

	return nil
}

// collectVariableDefinitions scans all blocks to find where each variable is defined
// a definition is any instruction that assigns to a variable (assign, load, call with return, phi)
func (t *Transformer) collectVariableDefinitions() {
	// iterate through all basic blocks in ir function
	for blockID, block := range t.function.Blocks {
		// convert ir.BlockID to cfg.BlockID for tracking
		cfgBlockID := cfg.BlockID(blockID)

		// scan all instructions in this block
		for _, instr := range block.Instructions {
			// extract defined variable from instruction
			definedVar := t.getDefinedVariable(instr)
			if definedVar == nil {
				continue
			}

			// record this block as a definition site for the variable
			varName := definedVar.Name
			if _, exists := t.varDefs[varName]; !exists {
				t.varDefs[varName] = make([]cfg.BlockID, 0)
			}

			// avoid duplicate entries
			if !t.blockInList(t.varDefs[varName], cfgBlockID) {
				t.varDefs[varName] = append(t.varDefs[varName], cfgBlockID)
			}
		}
	}
}

// getDefinedVariable extracts the variable being defined by an instruction
// returns nil if instruction doesn't define a variable
func (t *Transformer) getDefinedVariable(instr ir.IRInstruction) *ir.Variable {
	switch i := instr.(type) {
	case *ir.Assign:
		return &i.Dest
	case *ir.Load:
		return &i.Dest
	case *ir.Call:
		return i.Dest // may be nil for void calls
	case *ir.Phi:
		return &i.Dest
	default:
		return nil
	}
}

// insertPhiNodes places phi-nodes at dominance frontiers for all variables
// this implements the classic ssa construction algorithm:
// for each variable v with multiple definitions:
//
//	for each definition site d of v:
//	  for each block b in dominance frontier of d:
//	    insert phi-node for v at b (if not already present)
//	    treat phi-node as new definition (iterate until fixed point)
func (t *Transformer) insertPhiNodes() error {
	// process each variable that has definitions
	for varName, defSites := range t.varDefs {
		// skip variables with single definition (no phi-nodes needed)
		if len(defSites) <= 1 {
			continue
		}

		// initialize phi-placement tracking for this variable
		if _, exists := t.phiPlaced[varName]; !exists {
			t.phiPlaced[varName] = make(map[cfg.BlockID]bool)
		}

		// worklist algorithm for iterative phi-node placement
		// phi-nodes themselves are definitions, so we iterate until fixed point
		worklist := make([]cfg.BlockID, 0, len(defSites))
		worklist = append(worklist, defSites...)

		// track blocks already processed to avoid redundant work
		processed := make(map[cfg.BlockID]bool)

		for len(worklist) > 0 {
			// pop block from worklist
			defBlock := worklist[0]
			worklist = worklist[1:]

			// skip if already processed
			if processed[defBlock] {
				continue
			}
			processed[defBlock] = true

			// get dominance frontier for this definition block
			frontier, exists := t.domFront[defBlock]
			if !exists {
				continue
			}

			// for each block in dominance frontier
			for _, frontierBlock := range frontier {
				// check if phi-node already placed at this block
				if t.phiPlaced[varName][frontierBlock] {
					continue
				}

				// place phi-node at frontier block
				if err := t.placePhiNode(varName, frontierBlock); err != nil {
					return fmt.Errorf("failed to place phi-node for %s at block %d: %w",
						varName, frontierBlock, err)
				}

				// mark phi-node as placed
				t.phiPlaced[varName][frontierBlock] = true

				// phi-node is itself a definition, add to worklist
				// this ensures we handle cases where phi-nodes trigger more phi-nodes
				if !processed[frontierBlock] {
					worklist = append(worklist, frontierBlock)
				}
			}
		}
	}

	return nil
}

// placePhiNode inserts a phi-node for the given variable at the specified block
// the phi-node is inserted at the beginning of the block's instruction list
func (t *Transformer) placePhiNode(varName string, blockID cfg.BlockID) error {
	// convert cfg.BlockID to ir.BlockID
	irBlockID := ir.BlockID(blockID)

	// get the ir basic block
	block, exists := t.function.Blocks[irBlockID]
	if !exists {
		return fmt.Errorf("%w: %d", errBlockNotFound, blockID)
	}

	// get the variable's type from existing definitions
	varType := t.getVariableType(varName)
	if varType == nil {
		// fallback to generic pointer type if type unknown
		varType = ir.PointerType{Pointee: ir.VoidType{}}
	}

	// create phi-node with sources from all predecessors
	phiSources := make([]ir.PhiSource, 0, len(block.Predecessors))
	for _, predID := range block.Predecessors {
		phiSources = append(phiSources, ir.PhiSource{
			Block: predID,
			Var: ir.Variable{
				Name:    varName,
				Type:    varType,
				Version: 0, // will be set during variable renaming phase
			},
		})
	}

	// create phi instruction
	phi := &ir.Phi{
		Dest: ir.Variable{
			Name:    varName,
			Type:    varType,
			Version: 0, // will be set during variable renaming phase
		},
		Sources: phiSources,
	}

	// insert phi-node at beginning of block
	// phi-nodes must appear before all other instructions
	block.Instructions = append([]ir.IRInstruction{phi}, block.Instructions...)

	return nil
}

// getVariableType retrieves the type of a variable by scanning its definitions
// returns nil if variable type cannot be determined
func (t *Transformer) getVariableType(varName string) ir.Type {
	// scan all blocks to find a definition of this variable
	for _, block := range t.function.Blocks {
		for _, instr := range block.Instructions {
			definedVar := t.getDefinedVariable(instr)
			if definedVar != nil && definedVar.Name == varName {
				return definedVar.Type
			}
		}
	}

	return nil
}

// blockInList checks if a block id is present in a list
func (t *Transformer) blockInList(list []cfg.BlockID, block cfg.BlockID) bool {
	for _, b := range list {
		if b == block {
			return true
		}
	}
	return false
}

// GetPhiNodeCount returns the total number of phi-nodes placed
// useful for testing and verification
func (t *Transformer) GetPhiNodeCount() int {
	count := 0
	for _, blocks := range t.phiPlaced {
		count += len(blocks)
	}
	return count
}

// GetVariablesWithPhiNodes returns the set of variables that have phi-nodes
func (t *Transformer) GetVariablesWithPhiNodes() []string {
	vars := make([]string, 0, len(t.phiPlaced))
	for varName := range t.phiPlaced {
		vars = append(vars, varName)
	}
	return vars
}

// GetPhiNodeLocations returns the blocks where phi-nodes are placed for a variable
func (t *Transformer) GetPhiNodeLocations(varName string) []cfg.BlockID {
	blocks := make([]cfg.BlockID, 0)
	if phiBlocks, exists := t.phiPlaced[varName]; exists {
		for blockID := range phiBlocks {
			blocks = append(blocks, blockID)
		}
	}
	return blocks
}
