// Package analysis provides data flow analysis algorithms for the sedec decompiler.
package analysis

import (
	"fmt"
	"sort"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// ProgramPoint identifies a specific location within a function's IR.
// it is the combination of a basic block id and an instruction index within that block.
type ProgramPoint struct {
	BlockID  ir.BlockID // basic block containing this point
	InstrIdx int        // index of instruction within the block (0-based)
}

// String returns a human-readable representation of the program point.
func (pp ProgramPoint) String() string {
	return fmt.Sprintf("bb%d:%d", pp.BlockID, pp.InstrIdx)
}

// Definition represents a variable definition at a specific program point.
// in ssa form, each definition is unique (single assignment property).
type Definition struct {
	Point    ProgramPoint // where the definition occurs
	Variable ir.Variable  // the variable being defined (with ssa version)
}

// String returns a human-readable representation of the definition.
func (d Definition) String() string {
	return fmt.Sprintf("%s@%s", d.Variable.String(), d.Point.String())
}

// DefinitionSet is an ordered collection of unique definitions.
// uses sorted slice for deterministic iteration and efficient lookup.
type DefinitionSet struct {
	defs []Definition
}

// NewDefinitionSet creates an empty definition set.
func NewDefinitionSet() *DefinitionSet {
	return &DefinitionSet{defs: make([]Definition, 0)}
}

// NewDefinitionSetFrom creates a definition set from a slice of definitions.
func NewDefinitionSetFrom(defs []Definition) *DefinitionSet {
	ds := &DefinitionSet{defs: make([]Definition, 0, len(defs))}
	for _, d := range defs {
		ds.Add(d)
	}
	return ds
}

// Add inserts a definition into the set. duplicates are ignored.
func (ds *DefinitionSet) Add(d Definition) {
	idx := sort.Search(len(ds.defs), func(i int) bool {
		return defLess(d, ds.defs[i]) || defEqual(d, ds.defs[i])
	})
	if idx < len(ds.defs) && defEqual(ds.defs[idx], d) {
		return // already present
	}
	ds.defs = append(ds.defs, Definition{})
	copy(ds.defs[idx+1:], ds.defs[idx:])
	ds.defs[idx] = d
}

// Contains checks whether a definition exists in the set.
func (ds *DefinitionSet) Contains(d Definition) bool {
	idx := sort.Search(len(ds.defs), func(i int) bool {
		return defLess(d, ds.defs[i]) || defEqual(d, ds.defs[i])
	})
	return idx < len(ds.defs) && defEqual(ds.defs[idx], d)
}

// Remove deletes a definition from the set if present.
func (ds *DefinitionSet) Remove(d Definition) {
	idx := sort.Search(len(ds.defs), func(i int) bool {
		return defLess(d, ds.defs[i]) || defEqual(d, ds.defs[i])
	})
	if idx < len(ds.defs) && defEqual(ds.defs[idx], d) {
		ds.defs = append(ds.defs[:idx], ds.defs[idx+1:]...)
	}
}

// Len returns the number of definitions in the set.
func (ds *DefinitionSet) Len() int {
	return len(ds.defs)
}

// Slice returns a copy of the definitions as a slice.
func (ds *DefinitionSet) Slice() []Definition {
	result := make([]Definition, len(ds.defs))
	copy(result, ds.defs)
	return result
}

// Union returns a new set containing all definitions from both sets.
func (ds *DefinitionSet) Union(other *DefinitionSet) *DefinitionSet {
	result := NewDefinitionSet()
	result.defs = make([]Definition, 0, len(ds.defs)+len(other.defs))
	i, j := 0, 0
	for i < len(ds.defs) && j < len(other.defs) {
		if defEqual(ds.defs[i], other.defs[j]) {
			result.defs = append(result.defs, ds.defs[i])
			i++
			j++
		} else if defLess(ds.defs[i], other.defs[j]) {
			result.defs = append(result.defs, ds.defs[i])
			i++
		} else {
			result.defs = append(result.defs, other.defs[j])
			j++
		}
	}
	for ; i < len(ds.defs); i++ {
		result.defs = append(result.defs, ds.defs[i])
	}
	for ; j < len(other.defs); j++ {
		result.defs = append(result.defs, other.defs[j])
	}
	return result
}

// Equal checks whether two definition sets contain the same definitions.
func (ds *DefinitionSet) Equal(other *DefinitionSet) bool {
	if len(ds.defs) != len(other.defs) {
		return false
	}
	for i := range ds.defs {
		if !defEqual(ds.defs[i], other.defs[i]) {
			return false
		}
	}
	return true
}

// Clone returns a deep copy of the definition set.
func (ds *DefinitionSet) Clone() *DefinitionSet {
	result := &DefinitionSet{defs: make([]Definition, len(ds.defs))}
	copy(result.defs, ds.defs)
	return result
}

// defKey produces a canonical ordering key for a definition.
// ordering: block id ascending, then instruction index ascending, then variable name, then version.
func defLess(a, b Definition) bool {
	if a.Point.BlockID != b.Point.BlockID {
		return a.Point.BlockID < b.Point.BlockID
	}
	if a.Point.InstrIdx != b.Point.InstrIdx {
		return a.Point.InstrIdx < b.Point.InstrIdx
	}
	if a.Variable.Name != b.Variable.Name {
		return a.Variable.Name < b.Variable.Name
	}
	return a.Variable.Version < b.Variable.Version
}

func defEqual(a, b Definition) bool {
	return a.Point.BlockID == b.Point.BlockID &&
		a.Point.InstrIdx == b.Point.InstrIdx &&
		a.Variable.Name == b.Variable.Name &&
		a.Variable.Version == b.Variable.Version
}

// ReachingDefsResult holds the complete result of reaching definitions analysis.
type ReachingDefsResult struct {
	// ReachIn maps each program point to the set of definitions reaching
	// the point immediately before the instruction executes.
	ReachIn map[ProgramPoint]*DefinitionSet

	// ReachOut maps each program point to the set of definitions reaching
	// the point immediately after the instruction executes.
	ReachOut map[ProgramPoint]*DefinitionSet

	// DefSites maps each ssa variable (name_version) to its definition site.
	// in ssa form this is always exactly one point per variable version.
	DefSites map[string]ProgramPoint

	// BlockReachIn maps each block id to the set of definitions reaching
	// the entry of the block (before any instruction in the block).
	BlockReachIn map[ir.BlockID]*DefinitionSet

	// BlockReachOut maps each block id to the set of definitions reaching
	// the exit of the block (after all instructions in the block).
	BlockReachOut map[ir.BlockID]*DefinitionSet
}

// ReachingDefsAnalyzer computes reaching definitions for a function in ssa form.
type ReachingDefsAnalyzer struct {
	function *ir.Function
	cfgGraph *cfg.CFG
	domTree  *cfg.DominatorTree
}

// NewReachingDefsAnalyzer creates a new reaching definitions analyzer.
func NewReachingDefsAnalyzer(
	function *ir.Function,
	cfgGraph *cfg.CFG,
	domTree *cfg.DominatorTree,
) *ReachingDefsAnalyzer {
	return &ReachingDefsAnalyzer{
		function: function,
		cfgGraph: cfgGraph,
		domTree:  domTree,
	}
}

// Compute performs reaching definitions analysis using forward data flow.
// in ssa form, each variable has exactly one definition, so the analysis
// leverages def-use chains for efficient single-pass computation.
//
// the transfer function for a program point p with instruction I is:
//
//	ReachOut(p) = Gen(p) ∪ (ReachIn(p) \ Kill(p))
//
// where:
//
//	Gen(p) = {definition created by I at p}
//	Kill(p) = {definitions of the same base variable killed by I at p}
//
// for ssa form, Kill is always empty (no redefinition of same ssa version),
// so: ReachOut(p) = Gen(p) ∪ ReachIn(p)
//
// block-level equations:
//
//	BlockReachIn(B) = ∪ BlockReachOut(P) for all predecessors P of B
//	BlockReachOut(B) = ReachOut(last instruction in B)
func (a *ReachingDefsAnalyzer) Compute() (*ReachingDefsResult, error) {
	if a.function == nil {
		return nil, fmt.Errorf("function is nil")
	}
	if len(a.function.Blocks) == 0 {
		return nil, fmt.Errorf("function has no blocks")
	}

	result := &ReachingDefsResult{
		ReachIn:       make(map[ProgramPoint]*DefinitionSet),
		ReachOut:      make(map[ProgramPoint]*DefinitionSet),
		DefSites:      make(map[string]ProgramPoint),
		BlockReachIn:  make(map[ir.BlockID]*DefinitionSet),
		BlockReachOut: make(map[ir.BlockID]*DefinitionSet),
	}

	// phase 1: collect all definition sites from ssa form.
	// in ssa, each variable version has exactly one definition point.
	a.collectDefSites(result)

	// phase 2: compute reaching definitions using iterative forward data flow.
	// even though ssa guarantees single definitions, we still need to propagate
	// through the cfg to determine which definitions reach each point.
	a.computeForwardDataFlow(result)

	return result, nil
}

// collectDefSites scans all instructions to build the DefSites map.
// each instruction that defines a variable creates a definition at its program point.
func (a *ReachingDefsAnalyzer) collectDefSites(result *ReachingDefsResult) {
	for blockID, block := range a.function.Blocks {
		for instrIdx, instr := range block.Instructions {
			point := ProgramPoint{BlockID: blockID, InstrIdx: instrIdx}
			if v := extractDefinedVariable(instr); v != nil {
				key := v.String()
				result.DefSites[key] = point
			}
		}
	}
}

// computeForwardDataFlow performs iterative forward data flow analysis.
// processes blocks in reverse postorder (topological order respecting dominance)
// and iterates until reaching a fixed point.
func (a *ReachingDefsAnalyzer) computeForwardDataFlow(result *ReachingDefsResult) {
	// compute reverse postorder for efficient convergence
	rpo := a.reversePostOrder()

	// initialize all block reach-in/out to empty sets
	for _, blockID := range rpo {
		result.BlockReachIn[blockID] = NewDefinitionSet()
		result.BlockReachOut[blockID] = NewDefinitionSet()
	}

	// iterative fixed-point computation
	changed := true
	for changed {
		changed = false
		for _, blockID := range rpo {
			block, exists := a.function.Blocks[blockID]
			if !exists {
				continue
			}

			// compute block reach-in as union of all predecessors' reach-out
			newReachIn := NewDefinitionSet()
			for _, predID := range block.Predecessors {
				if predOut, ok := result.BlockReachOut[predID]; ok {
					newReachIn = newReachIn.Union(predOut)
				}
			}
			result.BlockReachIn[blockID] = newReachIn

			// propagate through each instruction in the block
			currentReach := newReachIn.Clone()
			for instrIdx, instr := range block.Instructions {
				point := ProgramPoint{BlockID: blockID, InstrIdx: instrIdx}

				// reach-in for this instruction is the current reaching set
				result.ReachIn[point] = currentReach.Clone()

				// apply transfer function: gen ∪ (in \ kill)
				currentReach = a.transferFunction(currentReach, instr, point)

				// reach-out for this instruction
				result.ReachOut[point] = currentReach.Clone()
			}

			// check if block reach-out changed
			if !result.BlockReachOut[blockID].Equal(currentReach) {
				result.BlockReachOut[blockID] = currentReach
				changed = true
			}
		}
	}
}

// transferFunction computes the output reaching definitions for a single instruction.
// in ssa form: out = gen(instr) ∪ in
// because ssa variables are never redefined, kill set is empty for ssa versions.
// however, for non-ssa variables (version 0), we kill previous definitions of the same name.
func (a *ReachingDefsAnalyzer) transferFunction(
	reachIn *DefinitionSet,
	instr ir.IRInstruction,
	point ProgramPoint,
) *DefinitionSet {
	result := reachIn.Clone()

	defined := extractDefinedVariable(instr)
	if defined == nil {
		// no definition -- reach-out equals reach-in
		return result
	}

	newDef := Definition{
		Point:    point,
		Variable: *defined,
	}

	// in ssa form (version > 0), each version is unique, so no kill needed.
	// for pre-ssa code (version == 0), kill previous definitions of same base name.
	if defined.Version == 0 {
		a.killDefinitions(result, defined.Name)
	}

	result.Add(newDef)
	return result
}

// killDefinitions removes all definitions of a given base variable name from the set.
// used for non-ssa variables where redefinition kills previous definitions.
func (a *ReachingDefsAnalyzer) killDefinitions(ds *DefinitionSet, varName string) {
	// collect definitions to remove (avoid modifying slice during iteration)
	var toRemove []Definition
	for _, d := range ds.defs {
		if d.Variable.Name == varName {
			toRemove = append(toRemove, d)
		}
	}
	for _, d := range toRemove {
		ds.Remove(d)
	}
}

// reversePostOrder computes a reverse postorder traversal of the cfg.
// this ordering ensures that (in reducible cfgs) all predecessors of a block
// are processed before the block itself, except for loop back-edges.
func (a *ReachingDefsAnalyzer) reversePostOrder() []ir.BlockID {
	visited := make(map[ir.BlockID]bool)
	postOrder := make([]ir.BlockID, 0, len(a.function.Blocks))

	var dfs func(ir.BlockID)
	dfs = func(blockID ir.BlockID) {
		if visited[blockID] {
			return
		}
		visited[blockID] = true

		block, exists := a.function.Blocks[blockID]
		if !exists {
			return
		}

		for _, succID := range block.Successors {
			dfs(succID)
		}

		postOrder = append(postOrder, blockID)
	}

	dfs(a.function.EntryBlock)

	// also visit any unreachable blocks
	for blockID := range a.function.Blocks {
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

// extractDefinedVariable returns the variable defined by an instruction, or nil.
func extractDefinedVariable(instr ir.IRInstruction) *ir.Variable {
	switch inst := instr.(type) {
	case *ir.Assign:
		return &inst.Dest
	case *ir.Load:
		return &inst.Dest
	case *ir.Call:
		return inst.Dest // may be nil for void calls
	case *ir.Phi:
		return &inst.Dest
	default:
		return nil
	}
}

// GetReachingDefsAt returns the set of definitions reaching a specific program point
// (before the instruction at that point executes).
func (r *ReachingDefsResult) GetReachingDefsAt(point ProgramPoint) *DefinitionSet {
	if ds, ok := r.ReachIn[point]; ok {
		return ds
	}
	return NewDefinitionSet()
}

// GetDefinitionsAfter returns the set of definitions available after a specific
// program point (after the instruction at that point executes).
func (r *ReachingDefsResult) GetDefinitionsAfter(point ProgramPoint) *DefinitionSet {
	if ds, ok := r.ReachOut[point]; ok {
		return ds
	}
	return NewDefinitionSet()
}

// GetDefinitionSite returns the program point where a variable was defined.
// in ssa form, this is always exactly one point.
func (r *ReachingDefsResult) GetDefinitionSite(v ir.Variable) (ProgramPoint, bool) {
	point, ok := r.DefSites[v.String()]
	return point, ok
}

// GetReachingDefsForVariable returns all definitions of a specific base variable name
// that reach a given program point.
func (r *ReachingDefsResult) GetReachingDefsForVariable(point ProgramPoint, varName string) []Definition {
	ds := r.GetReachingDefsAt(point)
	var result []Definition
	for _, d := range ds.Slice() {
		if d.Variable.Name == varName {
			result = append(result, d)
		}
	}
	return result
}

// GetBlockReachIn returns the set of definitions reaching the entry of a block.
func (r *ReachingDefsResult) GetBlockReachIn(blockID ir.BlockID) *DefinitionSet {
	if ds, ok := r.BlockReachIn[blockID]; ok {
		return ds
	}
	return NewDefinitionSet()
}

// GetBlockReachOut returns the set of definitions available at the exit of a block.
func (r *ReachingDefsResult) GetBlockReachOut(blockID ir.BlockID) *DefinitionSet {
	if ds, ok := r.BlockReachOut[blockID]; ok {
		return ds
	}
	return NewDefinitionSet()
}
