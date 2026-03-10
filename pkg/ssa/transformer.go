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
	// errUnknownInstructionType indicates unknown instruction type encountered
	errUnknownInstructionType = errors.New("unknown instruction type")
	// errInstructionNotDefinition indicates instruction does not define a variable
	errInstructionNotDefinition = errors.New("instruction does not define a variable")
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

	// variable renaming state
	varStacks   map[string]*versionStack // stack of ssa versions for each variable
	varCounters map[string]int           // next version number for each variable
}

// NewTransformer creates a new ssa transformer
func NewTransformer(function *ir.Function, cfgGraph *cfg.CFG, domTree *cfg.DominatorTree) *Transformer {
	return &Transformer{
		function:    function,
		cfg:         cfgGraph,
		domTree:     domTree,
		varDefs:     make(map[string][]cfg.BlockID),
		phiPlaced:   make(map[string]map[cfg.BlockID]bool),
		varStacks:   make(map[string]*versionStack),
		varCounters: make(map[string]int),
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

	// step 4: rename variables with dfs traversal in dominator tree order
	if err := t.renameVariables(); err != nil {
		return fmt.Errorf("failed to rename variables: %w", err)
	}

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

// ============================================================================
// SSA Variable Renaming (Task 5.6)
// ============================================================================

// versionStack maintains a stack of ssa versions for a single variable
// used during dfs traversal for tracking current version in each scope
type versionStack struct {
	versions []int // stack of version numbers
}

// newVersionStack creates a new empty version stack
func newVersionStack() *versionStack {
	return &versionStack{
		versions: make([]int, 0, 8), // preallocate for typical depth
	}
}

// push adds a new version to the stack
func (s *versionStack) push(version int) {
	s.versions = append(s.versions, version)
}

// pop removes and returns the top version from the stack
// returns -1 if stack is empty
func (s *versionStack) pop() int {
	if len(s.versions) == 0 {
		return -1
	}
	top := s.versions[len(s.versions)-1]
	s.versions = s.versions[:len(s.versions)-1]
	return top
}

// top returns the current version without removing it
// returns 0 if stack is empty (uninitialized variable)
func (s *versionStack) top() int {
	if len(s.versions) == 0 {
		return 0
	}
	return s.versions[len(s.versions)-1]
}

// isEmpty checks if the stack is empty
// note: currently unused but kept for api completeness
//
//nolint:unused // kept for api completeness
func (s *versionStack) isEmpty() bool {
	return len(s.versions) == 0
}

// renameVariables performs ssa variable renaming with dfs traversal
// this implements the classic cytron et al. algorithm:
// 1. traverse cfg in dominator tree order (ensures defs before uses)
// 2. for each definition: create new ssa version and push to stack
// 3. for each use: replace with current version from stack top
// 4. for phi-nodes in successors: fill in appropriate version from current block
// 5. recurse to dominated blocks
// 6. pop all versions pushed in this block (backtracking)
func (t *Transformer) renameVariables() error {
	// initialize version stacks and counters for all variables
	t.initializeRenamingState()

	// start dfs from entry block
	entryBlockID := cfg.BlockID(t.function.EntryBlock)
	if err := t.renameBlock(entryBlockID); err != nil {
		return fmt.Errorf("failed to rename variables in entry block: %w", err)
	}

	return nil
}

// initializeRenamingState sets up version stacks and counters
// creates empty stacks for all variables that appear in the function
func (t *Transformer) initializeRenamingState() {
	// collect all variable names from function
	varNames := make(map[string]bool)

	// scan all blocks and instructions
	for _, block := range t.function.Blocks {
		for _, instr := range block.Instructions {
			// collect defined variables
			if definedVar := t.getDefinedVariable(instr); definedVar != nil {
				varNames[definedVar.Name] = true
			}

			// collect used variables
			usedVars := t.getUsedVariables(instr)
			for _, usedVar := range usedVars {
				varNames[usedVar.Name] = true
			}
		}
	}

	// initialize stacks and counters for each variable
	for varName := range varNames {
		t.varStacks[varName] = newVersionStack()
		t.varCounters[varName] = 1 // start from version 1 (0 reserved for uninitialized)
	}
}

// renameBlock performs variable renaming for a single basic block
// this is the core of the dfs traversal algorithm
func (t *Transformer) renameBlock(blockID cfg.BlockID) error {
	// convert to ir block id
	irBlockID := ir.BlockID(blockID)

	// get the ir basic block
	block, exists := t.function.Blocks[irBlockID]
	if !exists {
		return fmt.Errorf("%w: %d", errBlockNotFound, blockID)
	}

	// track how many versions we push for each variable in this block
	// needed for backtracking when we exit the block
	pushedVersions := make(map[string]int)

	// step 1: process all instructions in the block
	for i := range block.Instructions {
		instr := block.Instructions[i]

		// step 1a: rename uses in this instruction (before processing definition)
		if err := t.renameUsesInInstruction(instr); err != nil {
			return fmt.Errorf("failed to rename uses in instruction: %w", err)
		}

		// step 1b: process definition (if any)
		definedVar := t.getDefinedVariable(instr)
		if definedVar != nil {
			// generate new ssa version for this variable
			newVersion := t.newVersion(definedVar.Name)

			// update the instruction with new version
			if err := t.updateDefinitionVersion(instr, newVersion); err != nil {
				return fmt.Errorf("failed to update definition version: %w", err)
			}

			// push new version to stack
			t.varStacks[definedVar.Name].push(newVersion)

			// track for backtracking
			pushedVersions[definedVar.Name]++
		}
	}

	// step 2: fill in phi-node sources in successor blocks
	// for each successor block, update phi-nodes with current versions
	for _, succID := range block.Successors {
		if err := t.fillPhiSources(succID, blockID); err != nil {
			return fmt.Errorf("failed to fill phi sources for successor %d: %w", succID, err)
		}
	}

	// step 3: recurse to blocks dominated by this block
	// process children in dominator tree (not cfg successors)
	children := t.domTree.GetChildren(blockID)
	for _, childID := range children {
		if err := t.renameBlock(childID); err != nil {
			return fmt.Errorf("failed to rename child block %d: %w", childID, err)
		}
	}

	// step 4: backtrack - pop all versions pushed in this block
	for varName, count := range pushedVersions {
		for i := 0; i < count; i++ {
			t.varStacks[varName].pop()
		}
	}

	return nil
}

// newVersion generates a new ssa version number for a variable
func (t *Transformer) newVersion(varName string) int {
	version := t.varCounters[varName]
	t.varCounters[varName]++
	return version
}

// renameUsesInInstruction replaces all variable uses with their current ssa versions
func (t *Transformer) renameUsesInInstruction(instr ir.IRInstruction) error {
	switch i := instr.(type) {
	case *ir.Assign:
		// rename uses in source expression
		t.renameUsesInExpression(i.Source)

	case *ir.Load:
		// rename uses in address expression
		t.renameUsesInExpression(i.Address)

	case *ir.Store:
		// rename uses in both address and value expressions
		t.renameUsesInExpression(i.Address)
		t.renameUsesInExpression(i.Value)

	case *ir.Branch:
		// rename uses in condition expression
		t.renameUsesInExpression(i.Condition)

	case *ir.Call:
		// rename uses in target expression
		t.renameUsesInExpression(i.Target)
		// rename uses in arguments
		for j := range i.Args {
			currentVersion := t.getCurrentVersion(i.Args[j].Name)
			i.Args[j].Version = currentVersion
		}

	case *ir.Return:
		// rename use in return value
		if i.Value != nil {
			currentVersion := t.getCurrentVersion(i.Value.Name)
			i.Value.Version = currentVersion
		}

	case *ir.Phi:
		// phi-node sources are handled separately in fillPhiSources
		// we don't rename them here because they depend on predecessor blocks

	case *ir.Jump:
		// no variables to rename

	default:
		// unknown instruction type - this should not happen
		return fmt.Errorf("%w: %T", errUnknownInstructionType, instr)
	}

	return nil
}

// renameUsesInExpression recursively renames variable uses in an expression
func (t *Transformer) renameUsesInExpression(expr ir.Expression) {
	switch e := expr.(type) {
	case *ir.VariableExpr:
		// replace with current ssa version
		currentVersion := t.getCurrentVersion(e.Var.Name)
		e.Var.Version = currentVersion

	case *ir.BinaryOp:
		// recurse to left and right operands
		t.renameUsesInExpression(e.Left)
		t.renameUsesInExpression(e.Right)

	case *ir.UnaryOp:
		// recurse to operand
		t.renameUsesInExpression(e.Operand)

	case *ir.Cast:
		// recurse to casted expression
		t.renameUsesInExpression(e.Expr)

	case *ir.ConstantExpr:
		// constants don't have variables to rename

	default:
		// unknown expression type - ignore
	}
}

// getCurrentVersion returns the current ssa version for a variable
// returns 0 if variable has no current version (uninitialized)
func (t *Transformer) getCurrentVersion(varName string) int {
	stack, exists := t.varStacks[varName]
	if !exists {
		return 0
	}
	return stack.top()
}

// updateDefinitionVersion updates the version number in a definition instruction
func (t *Transformer) updateDefinitionVersion(instr ir.IRInstruction, version int) error {
	switch i := instr.(type) {
	case *ir.Assign:
		i.Dest.Version = version
	case *ir.Load:
		i.Dest.Version = version
	case *ir.Call:
		if i.Dest != nil {
			i.Dest.Version = version
		}
	case *ir.Phi:
		i.Dest.Version = version
	default:
		return fmt.Errorf("%w: %T", errInstructionNotDefinition, instr)
	}
	return nil
}

// fillPhiSources fills in phi-node sources for a successor block
// for each phi-node in the successor, we set the version corresponding to the current block
func (t *Transformer) fillPhiSources(succID ir.BlockID, currentBlockID cfg.BlockID) error {
	// get successor block
	succBlock, exists := t.function.Blocks[succID]
	if !exists {
		return fmt.Errorf("%w: %d", errBlockNotFound, succID)
	}

	// scan phi-nodes at the beginning of successor block
	for _, instr := range succBlock.Instructions {
		phi, isPhi := instr.(*ir.Phi)
		if !isPhi {
			// phi-nodes are always at the beginning, stop when we hit non-phi
			break
		}

		// find the phi source corresponding to current block
		for j := range phi.Sources {
			if phi.Sources[j].Block == ir.BlockID(currentBlockID) {
				// set the version to current version of this variable
				varName := phi.Sources[j].Var.Name
				currentVersion := t.getCurrentVersion(varName)
				phi.Sources[j].Var.Version = currentVersion
				break
			}
		}
	}

	return nil
}

// getUsedVariables extracts all variables used (not defined) by an instruction
func (t *Transformer) getUsedVariables(instr ir.IRInstruction) []ir.Variable {
	vars := make([]ir.Variable, 0)

	switch i := instr.(type) {
	case *ir.Assign:
		vars = append(vars, t.extractVariablesFromExpression(i.Source)...)

	case *ir.Load:
		vars = append(vars, t.extractVariablesFromExpression(i.Address)...)

	case *ir.Store:
		vars = append(vars, t.extractVariablesFromExpression(i.Address)...)
		vars = append(vars, t.extractVariablesFromExpression(i.Value)...)

	case *ir.Branch:
		vars = append(vars, t.extractVariablesFromExpression(i.Condition)...)

	case *ir.Call:
		vars = append(vars, t.extractVariablesFromExpression(i.Target)...)
		vars = append(vars, i.Args...)

	case *ir.Return:
		if i.Value != nil {
			vars = append(vars, *i.Value)
		}

	case *ir.Phi:
		// phi sources are special - they're filled in during renaming
		for _, src := range i.Sources {
			vars = append(vars, src.Var)
		}
	}

	return vars
}

// extractVariablesFromExpression recursively extracts all variables from an expression
func (t *Transformer) extractVariablesFromExpression(expr ir.Expression) []ir.Variable {
	vars := make([]ir.Variable, 0)

	switch e := expr.(type) {
	case *ir.VariableExpr:
		vars = append(vars, e.Var)

	case *ir.BinaryOp:
		vars = append(vars, t.extractVariablesFromExpression(e.Left)...)
		vars = append(vars, t.extractVariablesFromExpression(e.Right)...)

	case *ir.UnaryOp:
		vars = append(vars, t.extractVariablesFromExpression(e.Operand)...)

	case *ir.Cast:
		vars = append(vars, t.extractVariablesFromExpression(e.Expr)...)

	case *ir.ConstantExpr:
		// no variables in constants
	}

	return vars
}
