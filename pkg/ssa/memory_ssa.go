// Package ssa implements Static Single Assignment form transformation for IR.
// This package provides SSA construction, variable renaming, and Memory SSA
// for precise memory dependency analysis in the sedec decompiler.
package ssa

import (
	"errors"
	"fmt"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// Memory SSA: Extending SSA to Memory Operations
// ============================================================================
//
// Memory SSA extends classical SSA form to track memory state explicitly.
// Instead of treating memory as implicit global state, Memory SSA creates
// explicit def-use chains for memory versions, enabling precise alias analysis
// and optimization of memory operations.
//
// Key concepts:
// - MemoryDef: Represents a write to memory (store, call that modifies memory)
// - MemoryUse: Represents a read from memory (load, call that reads memory)
// - MemoryPhi: Merges memory state at control flow join points
//
// Memory SSA enables:
// - Precise dead store elimination
// - Load-store forwarding
// - Memory dependency analysis
// - Alias-aware optimizations
//
// Algorithm based on:
// "Memory SSA - A Unified Approach for Sparsely Representing Memory Operations"
// by Chow et al., 2005

var (
	// errBlockNotFoundMemSSA indicates block not found during memory ssa construction
	errBlockNotFoundMemSSA = errors.New("block not found in cfg")
)

// MemoryVersion represents a unique version of memory state
// analogous to variable versions in classical ssa
type MemoryVersion struct {
	ID      int        // unique version number
	DefSite ir.BlockID // block where this version is defined
}

func (m MemoryVersion) String() string {
	return fmt.Sprintf("mem_%d", m.ID)
}

// MemoryDef represents a definition of memory state
// created for stores and function calls that may modify memory
type MemoryDef struct {
	Version     MemoryVersion    // new memory version created by this def
	PrevVersion MemoryVersion    // previous memory version (def-use chain)
	Instruction ir.IRInstruction // the instruction that modifies memory
	Block       ir.BlockID       // block containing this def
}

func (m MemoryDef) String() string {
	return fmt.Sprintf("%s = MemoryDef(%s)", m.Version.String(), m.PrevVersion.String())
}

// MemoryUse represents a use of memory state
// created for loads and function calls that may read memory
type MemoryUse struct {
	Version     MemoryVersion    // memory version being read
	Instruction ir.IRInstruction // the instruction that reads memory
	Block       ir.BlockID       // block containing this use
}

func (m MemoryUse) String() string {
	return fmt.Sprintf("MemoryUse(%s)", m.Version.String())
}

// MemoryPhi represents a merge of memory state at control flow join points
// analogous to phi-nodes for variables in classical ssa
type MemoryPhi struct {
	Version MemoryVersion                // new memory version created by this phi
	Sources map[ir.BlockID]MemoryVersion // memory versions from predecessor blocks
	Block   ir.BlockID                   // block containing this phi
}

func (m MemoryPhi) String() string {
	return fmt.Sprintf("%s = MemoryPhi(...)", m.Version.String())
}

// MemorySSAInfo stores all memory ssa information for a function
type MemorySSAInfo struct {
	// memory definitions indexed by block and instruction
	Defs map[ir.BlockID][]*MemoryDef

	// memory uses indexed by block and instruction
	Uses map[ir.BlockID][]*MemoryUse

	// memory phi-nodes indexed by block
	Phis map[ir.BlockID]*MemoryPhi

	// def-use chains: maps memory version to all uses of that version
	DefUseChains map[MemoryVersion][]*MemoryUse

	// use-def chains: maps memory use to its defining memory version
	UseDefChains map[*MemoryUse]MemoryVersion

	// current memory version at end of each block
	BlockExitVersions map[ir.BlockID]MemoryVersion

	// next version number for generating unique memory versions
	nextVersion int
}

// NewMemorySSAInfo creates a new memory ssa information structure
func NewMemorySSAInfo() *MemorySSAInfo {
	return &MemorySSAInfo{
		Defs:              make(map[ir.BlockID][]*MemoryDef),
		Uses:              make(map[ir.BlockID][]*MemoryUse),
		Phis:              make(map[ir.BlockID]*MemoryPhi),
		DefUseChains:      make(map[MemoryVersion][]*MemoryUse),
		UseDefChains:      make(map[*MemoryUse]MemoryVersion),
		BlockExitVersions: make(map[ir.BlockID]MemoryVersion),
		nextVersion:       1, // start from 1, 0 reserved for initial memory state
	}
}

// MemorySSABuilder constructs memory ssa form for a function
type MemorySSABuilder struct {
	function *ir.Function
	cfg      *cfg.CFG
	domTree  *cfg.DominatorTree
	domFront map[cfg.BlockID][]cfg.BlockID

	memInfo *MemorySSAInfo

	// tracking for phi-node placement
	memDefBlocks []cfg.BlockID        // blocks with memory definitions
	phiPlaced    map[cfg.BlockID]bool // tracks where memory phi-nodes are placed
}

// NewMemorySSABuilder creates a new memory ssa builder
func NewMemorySSABuilder(function *ir.Function, cfgGraph *cfg.CFG, domTree *cfg.DominatorTree) *MemorySSABuilder {
	return &MemorySSABuilder{
		function:     function,
		cfg:          cfgGraph,
		domTree:      domTree,
		memInfo:      NewMemorySSAInfo(),
		memDefBlocks: make([]cfg.BlockID, 0),
		phiPlaced:    make(map[cfg.BlockID]bool),
	}
}

// BuildMemorySSA performs complete memory ssa construction
// this is the main entry point for memory ssa conversion
func (b *MemorySSABuilder) BuildMemorySSA() (*MemorySSAInfo, error) {
	// step 1: compute dominance frontiers (reuse from regular ssa)
	b.domFront = b.domTree.ComputeDominanceFrontiers()

	// step 2: identify all memory-modifying instructions and create memory defs/uses
	b.identifyMemoryOperations()

	// step 3: insert memory phi-nodes at dominance frontiers
	if err := b.insertMemoryPhiNodes(); err != nil {
		return nil, fmt.Errorf("failed to insert memory phi-nodes: %w", err)
	}

	// step 4: rename memory versions with dfs traversal
	if err := b.renameMemoryVersions(); err != nil {
		return nil, fmt.Errorf("failed to rename memory versions: %w", err)
	}

	// step 5: build def-use chains
	b.buildDefUseChains()

	return b.memInfo, nil
}

// identifyMemoryOperations scans all instructions to find memory operations
// creates MemoryDef for stores and calls, MemoryUse for loads and calls
func (b *MemorySSABuilder) identifyMemoryOperations() {
	for blockID, block := range b.function.Blocks {
		hasMemoryDef := false

		for _, instr := range block.Instructions {
			switch instr.(type) {
			case *ir.Store:
				// store instruction modifies memory
				memDef := &MemoryDef{
					Version:     MemoryVersion{ID: 0, DefSite: blockID}, // version set during renaming
					PrevVersion: MemoryVersion{ID: 0},                   // set during renaming
					Instruction: instr,
					Block:       blockID,
				}
				b.memInfo.Defs[blockID] = append(b.memInfo.Defs[blockID], memDef)
				hasMemoryDef = true

			case *ir.Load:
				// load instruction reads memory
				memUse := &MemoryUse{
					Version:     MemoryVersion{ID: 0, DefSite: blockID}, // version set during renaming
					Instruction: instr,
					Block:       blockID,
				}
				b.memInfo.Uses[blockID] = append(b.memInfo.Uses[blockID], memUse)

			case *ir.Call:
				// function calls may both read and modify memory
				// conservative approach: assume all calls touch memory
				// (can be refined with alias analysis and function attributes)

				// create memory use (call may read memory)
				memUse := &MemoryUse{
					Version:     MemoryVersion{ID: 0, DefSite: blockID},
					Instruction: instr,
					Block:       blockID,
				}
				b.memInfo.Uses[blockID] = append(b.memInfo.Uses[blockID], memUse)

				// create memory def (call may modify memory)
				memDef := &MemoryDef{
					Version:     MemoryVersion{ID: 0, DefSite: blockID},
					PrevVersion: MemoryVersion{ID: 0},
					Instruction: instr,
					Block:       blockID,
				}
				b.memInfo.Defs[blockID] = append(b.memInfo.Defs[blockID], memDef)
				hasMemoryDef = true
			}
		}

		// track blocks with memory definitions for phi-node placement
		if hasMemoryDef {
			cfgBlockID := cfg.BlockID(blockID)
			b.memDefBlocks = append(b.memDefBlocks, cfgBlockID)
		}
	}
}

// insertMemoryPhiNodes places memory phi-nodes at dominance frontiers
// algorithm identical to regular ssa phi-node placement, but for memory state
func (b *MemorySSABuilder) insertMemoryPhiNodes() error {
	// worklist algorithm for iterative phi-node placement
	worklist := make([]cfg.BlockID, 0, len(b.memDefBlocks))
	worklist = append(worklist, b.memDefBlocks...)

	// track blocks already processed
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
		frontier, exists := b.domFront[defBlock]
		if !exists {
			continue
		}

		// for each block in dominance frontier
		for _, frontierBlock := range frontier {
			// check if memory phi-node already placed
			if b.phiPlaced[frontierBlock] {
				continue
			}

			// place memory phi-node at frontier block
			if err := b.placeMemoryPhiNode(frontierBlock); err != nil {
				return fmt.Errorf("failed to place memory phi-node at block %d: %w",
					frontierBlock, err)
			}

			// mark phi-node as placed
			b.phiPlaced[frontierBlock] = true

			// memory phi-node is itself a definition, add to worklist
			if !processed[frontierBlock] {
				worklist = append(worklist, frontierBlock)
			}
		}
	}

	return nil
}

// placeMemoryPhiNode inserts a memory phi-node at the specified block
func (b *MemorySSABuilder) placeMemoryPhiNode(blockID cfg.BlockID) error {
	// convert cfg.BlockID to ir.BlockID
	irBlockID := ir.BlockID(blockID)

	// get the ir basic block
	block, exists := b.function.Blocks[irBlockID]
	if !exists {
		return fmt.Errorf("%w: %d", errBlockNotFoundMemSSA, blockID)
	}

	// create memory phi-node with sources from all predecessors
	sources := make(map[ir.BlockID]MemoryVersion)
	for _, predID := range block.Predecessors {
		sources[predID] = MemoryVersion{ID: 0} // versions set during renaming
	}

	// create memory phi
	memPhi := &MemoryPhi{
		Version: MemoryVersion{ID: 0, DefSite: irBlockID}, // version set during renaming
		Sources: sources,
		Block:   irBlockID,
	}

	b.memInfo.Phis[irBlockID] = memPhi

	return nil
}

// renameMemoryVersions performs memory version renaming with dfs traversal
// analogous to variable renaming in classical ssa
func (b *MemorySSABuilder) renameMemoryVersions() error {
	// memory version stack for tracking current version during dfs
	memStack := newMemVersionStack()

	// push initial memory version (version 0 = initial state)
	memStack.push(0)

	// start dfs from entry block
	entryBlockID := cfg.BlockID(b.function.EntryBlock)
	if err := b.renameMemoryInBlock(entryBlockID, memStack); err != nil {
		return fmt.Errorf("failed to rename memory in entry block: %w", err)
	}

	return nil
}

// memVersionStack maintains a stack of memory version numbers
// used during dfs traversal for tracking current memory version in each scope
type memVersionStack struct {
	versions []int // stack of version numbers
}

// newMemVersionStack creates a new empty memory version stack
func newMemVersionStack() *memVersionStack {
	return &memVersionStack{
		versions: make([]int, 0, 8), // preallocate for typical depth
	}
}

// push adds a new version to the stack
func (s *memVersionStack) push(version int) {
	s.versions = append(s.versions, version)
}

// pop removes and returns the top version from the stack
// returns -1 if stack is empty
func (s *memVersionStack) pop() int {
	if len(s.versions) == 0 {
		return -1
	}
	top := s.versions[len(s.versions)-1]
	s.versions = s.versions[:len(s.versions)-1]
	return top
}

// top returns the current version without removing it
// returns 0 if stack is empty (uninitialized memory)
func (s *memVersionStack) top() int {
	if len(s.versions) == 0 {
		return 0
	}
	return s.versions[len(s.versions)-1]
}

// renameMemoryInBlock performs memory version renaming for a single block
func (b *MemorySSABuilder) renameMemoryInBlock(blockID cfg.BlockID, memStack *memVersionStack) error {
	// convert to ir block id
	irBlockID := ir.BlockID(blockID)

	// get the ir basic block
	block, exists := b.function.Blocks[irBlockID]
	if !exists {
		return fmt.Errorf("%w: %d", errBlockNotFoundMemSSA, blockID)
	}

	// track how many versions we push (for backtracking)
	pushedCount := 0

	// step 1: process memory phi-node (if present)
	if memPhi, hasPhi := b.memInfo.Phis[irBlockID]; hasPhi {
		// generate new memory version for phi-node
		newVersion := b.newMemoryVersion(irBlockID)
		memPhi.Version = newVersion

		// push new version to stack
		memStack.push(newVersion.ID)
		pushedCount++
	}

	// step 2: process all instructions in the block
	for _, instr := range block.Instructions {
		currentVersion := memStack.top()

		// process memory uses (loads, calls reading memory)
		if uses, hasUses := b.memInfo.Uses[irBlockID]; hasUses {
			for _, memUse := range uses {
				if memUse.Instruction == instr {
					// set memory version for this use
					memUse.Version = MemoryVersion{ID: currentVersion, DefSite: irBlockID}
				}
			}
		}

		// process memory defs (stores, calls modifying memory)
		if defs, hasDefs := b.memInfo.Defs[irBlockID]; hasDefs {
			for _, memDef := range defs {
				if memDef.Instruction == instr {
					// set previous version
					memDef.PrevVersion = MemoryVersion{ID: currentVersion, DefSite: irBlockID}

					// generate new memory version
					newVersion := b.newMemoryVersion(irBlockID)
					memDef.Version = newVersion

					// push new version to stack
					memStack.push(newVersion.ID)
					pushedCount++

					// update current version for subsequent instructions
					currentVersion = newVersion.ID
				}
			}
		}
	}

	// record memory version at block exit
	b.memInfo.BlockExitVersions[irBlockID] = MemoryVersion{
		ID:      memStack.top(),
		DefSite: irBlockID,
	}

	// step 3: fill in memory phi-node sources in successor blocks
	for _, succID := range block.Successors {
		b.fillMemoryPhiSources(succID, irBlockID, memStack.top())
	}

	// step 4: recurse to blocks dominated by this block
	children := b.domTree.GetChildren(blockID)
	for _, childID := range children {
		if err := b.renameMemoryInBlock(childID, memStack); err != nil {
			return fmt.Errorf("failed to rename memory in child block %d: %w", childID, err)
		}
	}

	// step 5: backtrack - pop all versions pushed in this block
	for i := 0; i < pushedCount; i++ {
		memStack.pop()
	}

	return nil
}

// newMemoryVersion generates a new unique memory version
func (b *MemorySSABuilder) newMemoryVersion(defSite ir.BlockID) MemoryVersion {
	version := MemoryVersion{
		ID:      b.memInfo.nextVersion,
		DefSite: defSite,
	}
	b.memInfo.nextVersion++
	return version
}

// fillMemoryPhiSources fills in memory phi-node source for a successor block
func (b *MemorySSABuilder) fillMemoryPhiSources(succID ir.BlockID, currentBlockID ir.BlockID, currentVersion int) {
	// check if successor has memory phi-node
	memPhi, hasPhi := b.memInfo.Phis[succID]
	if !hasPhi {
		return
	}

	// set the memory version for this predecessor
	memPhi.Sources[currentBlockID] = MemoryVersion{
		ID:      currentVersion,
		DefSite: currentBlockID,
	}
}

// buildDefUseChains constructs def-use chains for memory versions
// maps each memory version to all uses of that version
func (b *MemorySSABuilder) buildDefUseChains() {
	// iterate through all memory uses
	for _, uses := range b.memInfo.Uses {
		for _, memUse := range uses {
			// add this use to the def-use chain for its version
			version := memUse.Version
			b.memInfo.DefUseChains[version] = append(b.memInfo.DefUseChains[version], memUse)

			// record use-def chain
			b.memInfo.UseDefChains[memUse] = version
		}
	}
}

// GetMemorySSAInfo returns the constructed memory ssa information
func (b *MemorySSABuilder) GetMemorySSAInfo() *MemorySSAInfo {
	return b.memInfo
}

// ============================================================================
// Memory SSA Query and Analysis Functions
// ============================================================================

// GetMemoryDefForUse returns the memory definition that reaches a given use
func (info *MemorySSAInfo) GetMemoryDefForUse(use *MemoryUse) (MemoryVersion, bool) {
	version, exists := info.UseDefChains[use]
	return version, exists
}

// GetUsesOfMemoryDef returns all uses of a given memory definition
func (info *MemorySSAInfo) GetUsesOfMemoryDef(version MemoryVersion) []*MemoryUse {
	return info.DefUseChains[version]
}

// GetMemoryVersionAtBlockExit returns the memory version at the end of a block
func (info *MemorySSAInfo) GetMemoryVersionAtBlockExit(blockID ir.BlockID) (MemoryVersion, bool) {
	version, exists := info.BlockExitVersions[blockID]
	return version, exists
}

// GetMemoryPhiForBlock returns the memory phi-node for a block (if any)
func (info *MemorySSAInfo) GetMemoryPhiForBlock(blockID ir.BlockID) (*MemoryPhi, bool) {
	phi, exists := info.Phis[blockID]
	return phi, exists
}

// GetMemoryDefsInBlock returns all memory definitions in a block
func (info *MemorySSAInfo) GetMemoryDefsInBlock(blockID ir.BlockID) []*MemoryDef {
	return info.Defs[blockID]
}

// GetMemoryUsesInBlock returns all memory uses in a block
func (info *MemorySSAInfo) GetMemoryUsesInBlock(blockID ir.BlockID) []*MemoryUse {
	return info.Uses[blockID]
}

// GetTotalMemoryDefs returns the total number of memory definitions
func (info *MemorySSAInfo) GetTotalMemoryDefs() int {
	count := 0
	for _, defs := range info.Defs {
		count += len(defs)
	}
	return count
}

// GetTotalMemoryUses returns the total number of memory uses
func (info *MemorySSAInfo) GetTotalMemoryUses() int {
	count := 0
	for _, uses := range info.Uses {
		count += len(uses)
	}
	return count
}

// GetTotalMemoryPhis returns the total number of memory phi-nodes
func (info *MemorySSAInfo) GetTotalMemoryPhis() int {
	return len(info.Phis)
}
