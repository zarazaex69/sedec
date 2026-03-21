package analysis

import (
	"fmt"
	"sort"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// VarKey is a canonical string key for an ir.Variable (name + version).
// used as map key to avoid struct comparison issues.
type VarKey struct {
	Name    string
	Version int
}

// varKeyOf converts an ir.Variable to a VarKey.
func varKeyOf(v ir.Variable) VarKey {
	return VarKey{Name: v.Name, Version: v.Version}
}

// VarSet is an ordered set of ir.Variable values.
// sorted by (name, version) for deterministic iteration.
type VarSet struct {
	vars []ir.Variable
}

// NewVarSet creates an empty variable set.
func NewVarSet() *VarSet {
	return &VarSet{vars: make([]ir.Variable, 0)}
}

// NewVarSetFrom creates a variable set from a slice.
func NewVarSetFrom(vars []ir.Variable) *VarSet {
	vs := &VarSet{vars: make([]ir.Variable, 0, len(vars))}
	for _, v := range vars {
		vs.Add(v)
	}
	return vs
}

// Add inserts a variable into the set. duplicates are ignored.
func (vs *VarSet) Add(v ir.Variable) {
	idx := sort.Search(len(vs.vars), func(i int) bool {
		return varLess(v, vs.vars[i]) || varEqual(v, vs.vars[i])
	})
	if idx < len(vs.vars) && varEqual(vs.vars[idx], v) {
		return
	}
	vs.vars = append(vs.vars, ir.Variable{})
	copy(vs.vars[idx+1:], vs.vars[idx:])
	vs.vars[idx] = v
}

// Remove deletes a variable from the set if present.
func (vs *VarSet) Remove(v ir.Variable) {
	idx := sort.Search(len(vs.vars), func(i int) bool {
		return varLess(v, vs.vars[i]) || varEqual(v, vs.vars[i])
	})
	if idx < len(vs.vars) && varEqual(vs.vars[idx], v) {
		vs.vars = append(vs.vars[:idx], vs.vars[idx+1:]...)
	}
}

// Contains reports whether v is in the set.
func (vs *VarSet) Contains(v ir.Variable) bool {
	idx := sort.Search(len(vs.vars), func(i int) bool {
		return varLess(v, vs.vars[i]) || varEqual(v, vs.vars[i])
	})
	return idx < len(vs.vars) && varEqual(vs.vars[idx], v)
}

// Len returns the number of variables in the set.
func (vs *VarSet) Len() int {
	return len(vs.vars)
}

// Slice returns a copy of the variables as a slice.
func (vs *VarSet) Slice() []ir.Variable {
	result := make([]ir.Variable, len(vs.vars))
	copy(result, vs.vars)
	return result
}

// Union returns a new set containing all variables from both sets.
func (vs *VarSet) Union(other *VarSet) *VarSet {
	result := &VarSet{vars: make([]ir.Variable, 0, len(vs.vars)+len(other.vars))}
	i, j := 0, 0
	for i < len(vs.vars) && j < len(other.vars) {
		if varEqual(vs.vars[i], other.vars[j]) { //nolint:gocritic // merge-sorted union: if-else chain is intentional
			result.vars = append(result.vars, vs.vars[i])
			i++
			j++
		} else if varLess(vs.vars[i], other.vars[j]) {
			result.vars = append(result.vars, vs.vars[i])
			i++
		} else {
			result.vars = append(result.vars, other.vars[j])
			j++
		}
	}
	for ; i < len(vs.vars); i++ {
		result.vars = append(result.vars, vs.vars[i])
	}
	for ; j < len(other.vars); j++ {
		result.vars = append(result.vars, other.vars[j])
	}
	return result
}

// Difference returns a new set containing variables in vs but not in other.
func (vs *VarSet) Difference(other *VarSet) *VarSet {
	result := NewVarSet()
	for _, v := range vs.vars {
		if !other.Contains(v) {
			result.vars = append(result.vars, v)
		}
	}
	return result
}

// Equal reports whether two sets contain the same variables.
func (vs *VarSet) Equal(other *VarSet) bool {
	if len(vs.vars) != len(other.vars) {
		return false
	}
	for i := range vs.vars {
		if !varEqual(vs.vars[i], other.vars[i]) {
			return false
		}
	}
	return true
}

// Clone returns a deep copy of the set.
func (vs *VarSet) Clone() *VarSet {
	result := &VarSet{vars: make([]ir.Variable, len(vs.vars))}
	copy(result.vars, vs.vars)
	return result
}

// varLess defines the canonical ordering for variables: name asc, version asc.
func varLess(a, b ir.Variable) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return a.Version < b.Version
}

func varEqual(a, b ir.Variable) bool {
	return a.Name == b.Name && a.Version == b.Version
}

// LiveVarsResult holds the complete result of live variable analysis.
type LiveVarsResult struct {
	// LiveIn maps each program point to the set of variables live
	// immediately before the instruction at that point executes.
	LiveIn map[ProgramPoint]*VarSet

	// LiveOut maps each program point to the set of variables live
	// immediately after the instruction at that point executes.
	LiveOut map[ProgramPoint]*VarSet

	// BlockLiveIn maps each block id to the set of variables live
	// at the entry of the block (before any instruction executes).
	BlockLiveIn map[ir.BlockID]*VarSet

	// BlockLiveOut maps each block id to the set of variables live
	// at the exit of the block (after all instructions execute).
	BlockLiveOut map[ir.BlockID]*VarSet
}

// IsLiveAt reports whether variable v is live immediately before the instruction
// at the given program point.
func (r *LiveVarsResult) IsLiveAt(point ProgramPoint, v ir.Variable) bool {
	if vs, ok := r.LiveIn[point]; ok {
		return vs.Contains(v)
	}
	return false
}

// IsLiveAfter reports whether variable v is live immediately after the instruction
// at the given program point.
func (r *LiveVarsResult) IsLiveAfter(point ProgramPoint, v ir.Variable) bool {
	if vs, ok := r.LiveOut[point]; ok {
		return vs.Contains(v)
	}
	return false
}

// GetLiveInAt returns the set of variables live before the instruction at point.
func (r *LiveVarsResult) GetLiveInAt(point ProgramPoint) *VarSet {
	if vs, ok := r.LiveIn[point]; ok {
		return vs
	}
	return NewVarSet()
}

// GetLiveOutAt returns the set of variables live after the instruction at point.
func (r *LiveVarsResult) GetLiveOutAt(point ProgramPoint) *VarSet {
	if vs, ok := r.LiveOut[point]; ok {
		return vs
	}
	return NewVarSet()
}

// GetBlockLiveIn returns the set of variables live at the entry of a block.
func (r *LiveVarsResult) GetBlockLiveIn(blockID ir.BlockID) *VarSet {
	if vs, ok := r.BlockLiveIn[blockID]; ok {
		return vs
	}
	return NewVarSet()
}

// GetBlockLiveOut returns the set of variables live at the exit of a block.
func (r *LiveVarsResult) GetBlockLiveOut(blockID ir.BlockID) *VarSet {
	if vs, ok := r.BlockLiveOut[blockID]; ok {
		return vs
	}
	return NewVarSet()
}

// LiveVarsAnalyzer computes live variable sets using backward data flow analysis.
//
// standard equations (per block B):
//
//	LiveOut(B) = union of LiveIn(S) for all successors S of B
//	LiveIn(B)  = Use(B) union (LiveOut(B) - Def(B))
//
// where:
//
//	Use(B) = variables used in B before any definition in B (upward-exposed uses)
//	Def(B) = variables defined in B
//
// the analysis iterates to a fixed point, processing blocks in postorder
// (reverse of reverse-postorder) so that successors are processed before
// predecessors, which is the natural order for backward analysis.
type LiveVarsAnalyzer struct {
	function *ir.Function
	cfgGraph *cfg.CFG
	domTree  *cfg.DominatorTree
}

// NewLiveVarsAnalyzer creates a new live variable analyzer.
func NewLiveVarsAnalyzer(
	function *ir.Function,
	cfgGraph *cfg.CFG,
	domTree *cfg.DominatorTree,
) *LiveVarsAnalyzer {
	return &LiveVarsAnalyzer{
		function: function,
		cfgGraph: cfgGraph,
		domTree:  domTree,
	}
}

// Compute performs live variable analysis using backward iterative data flow.
//
// the algorithm:
//  1. initialize all BlockLiveIn/BlockLiveOut to empty sets
//  2. iterate in postorder (successors before predecessors) until fixed point:
//     a. BlockLiveOut(B) = union of BlockLiveIn(S) for all successors S
//     b. compute Use(B) and Def(B) for block B
//     c. BlockLiveIn(B) = Use(B) union (BlockLiveOut(B) - Def(B))
//  3. propagate block-level results to per-instruction program points
func (a *LiveVarsAnalyzer) Compute() (*LiveVarsResult, error) {
	if a.function == nil {
		return nil, fmt.Errorf("live variable analysis: %w", ErrNilFunction)
	}
	if len(a.function.Blocks) == 0 {
		return nil, fmt.Errorf("live variable analysis: function %q: %w", a.function.Name, ErrNoBlocks)
	}

	result := &LiveVarsResult{
		LiveIn:       make(map[ProgramPoint]*VarSet),
		LiveOut:      make(map[ProgramPoint]*VarSet),
		BlockLiveIn:  make(map[ir.BlockID]*VarSet),
		BlockLiveOut: make(map[ir.BlockID]*VarSet),
	}

	// compute reverse postorder; postorder is its reverse (used for backward pass)
	rpo := a.reversePostOrder()

	// initialize all block live sets to empty
	for _, blockID := range rpo {
		result.BlockLiveIn[blockID] = NewVarSet()
		result.BlockLiveOut[blockID] = NewVarSet()
	}

	// iterative backward fixed-point computation.
	// process blocks in postorder (reverse of rpo) so successors are
	// visited before predecessors, improving convergence speed.
	changed := true
	for changed {
		changed = false
		// iterate rpo in reverse = postorder
		for i := len(rpo) - 1; i >= 0; i-- {
			blockID := rpo[i]
			block, exists := a.function.Blocks[blockID]
			if !exists {
				continue
			}

			// step 1: LiveOut(B) = union of LiveIn(S) for all successors S
			newLiveOut := NewVarSet()
			for _, succID := range block.Successors {
				if succLiveIn, ok := result.BlockLiveIn[succID]; ok {
					newLiveOut = newLiveOut.Union(succLiveIn)
				}
			}

			// step 2: compute Use(B) and Def(B) for this block
			useB, defB := a.computeUseDefSets(block)

			// step 3: LiveIn(B) = Use(B) union (LiveOut(B) - Def(B))
			newLiveIn := useB.Union(newLiveOut.Difference(defB))

			// check for change in live-in (convergence criterion)
			if !result.BlockLiveIn[blockID].Equal(newLiveIn) {
				result.BlockLiveIn[blockID] = newLiveIn
				changed = true
			}
			result.BlockLiveOut[blockID] = newLiveOut
		}
	}

	// propagate block-level results to per-instruction program points
	a.computeInstructionLiveness(result, rpo)

	return result, nil
}

// computeUseDefSets computes the upward-exposed use set and definition set for a block.
//
// Use(B): variables used in B before any definition in B.
// Def(B): variables defined in B.
//
// computed by scanning instructions in forward order:
//   - for each instruction, add used variables not yet in Def to Use
//   - add defined variable to Def
func (a *LiveVarsAnalyzer) computeUseDefSets(block *ir.BasicBlock) (use *VarSet, def *VarSet) {
	use = NewVarSet()
	def = NewVarSet()

	for _, instr := range block.Instructions {
		// collect uses first (before recording the definition)
		for _, usedVar := range extractUsedVariables(instr) {
			// only upward-exposed uses: not yet defined in this block
			if !def.Contains(usedVar) {
				use.Add(usedVar)
			}
		}

		// record definition
		if definedVar := extractDefinedVariable(instr); definedVar != nil {
			def.Add(*definedVar)
		}
	}

	return use, def
}

// computeInstructionLiveness propagates block-level liveness to per-instruction
// program points by scanning each block backward from its live-out set.
//
// for instruction at index i in block B:
//
//	LiveOut(B, i) = LiveIn(B, i+1)  for i < last
//	LiveOut(B, last) = BlockLiveOut(B)
//	LiveIn(B, i) = Use(instr_i) union (LiveOut(B, i) - Def(instr_i))
func (a *LiveVarsAnalyzer) computeInstructionLiveness(result *LiveVarsResult, rpo []ir.BlockID) {
	for _, blockID := range rpo {
		block, exists := a.function.Blocks[blockID]
		if !exists {
			continue
		}

		n := len(block.Instructions)
		if n == 0 {
			continue
		}

		// current live set starts as block live-out
		currentLive := result.BlockLiveOut[blockID].Clone()

		// scan instructions in reverse order
		for i := n - 1; i >= 0; i-- {
			point := ProgramPoint{BlockID: blockID, InstrIdx: i}
			instr := block.Instructions[i]

			// live-out for this instruction is the current live set
			result.LiveOut[point] = currentLive.Clone()

			// compute live-in for this instruction:
			// LiveIn(p) = Use(instr) union (LiveOut(p) - Def(instr))
			liveIn := currentLive.Clone()

			// remove defined variable (kill)
			if definedVar := extractDefinedVariable(instr); definedVar != nil {
				liveIn.Remove(*definedVar)
			}

			// add used variables (gen)
			for _, usedVar := range extractUsedVariables(instr) {
				liveIn.Add(usedVar)
			}

			result.LiveIn[point] = liveIn
			currentLive = liveIn
		}
	}
}

// reversePostOrder computes a reverse postorder traversal of the cfg.
// identical to the one in ReachingDefsAnalyzer — reused here for consistency.
//
//nolint:dupl // similar to other analyzers
func (a *LiveVarsAnalyzer) reversePostOrder() []ir.BlockID {
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

	// visit any unreachable blocks
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

// extractUsedVariables returns all variables read (used) by an instruction.
// for phi-nodes, all source variables are considered uses.
// the defined variable is NOT included in the use set.
func extractUsedVariables(instr ir.IRInstruction) []ir.Variable {
	var vars []ir.Variable
	switch i := instr.(type) {
	case *ir.Assign:
		vars = append(vars, extractVarsFromExpression(i.Source)...)
	case *ir.Load:
		vars = append(vars, extractVarsFromExpression(i.Address)...)
	case *ir.Store:
		vars = append(vars, extractVarsFromExpression(i.Address)...)
		vars = append(vars, extractVarsFromExpression(i.Value)...)
	case *ir.Branch:
		vars = append(vars, extractVarsFromExpression(i.Condition)...)
	case *ir.Call:
		vars = append(vars, extractVarsFromExpression(i.Target)...)
		vars = append(vars, i.Args...)
	case *ir.Return:
		if i.Value != nil {
			vars = append(vars, *i.Value)
		}
	case *ir.Phi:
		// all phi sources are uses (from their respective predecessor blocks)
		for _, src := range i.Sources {
			vars = append(vars, src.Var)
		}
	case *ir.Jump:
		// no variable uses
	case *ir.Intrinsic:
		for _, arg := range i.Args {
			vars = append(vars, extractVarsFromExpression(arg)...)
		}
	}
	return vars
}

// extractVarsFromExpression recursively collects all variable references in an expression.
func extractVarsFromExpression(expr ir.Expression) []ir.Variable {
	if expr == nil {
		return nil
	}
	var vars []ir.Variable
	switch e := expr.(type) {
	case *ir.VariableExpr:
		vars = append(vars, e.Var)
	case ir.VariableExpr:
		vars = append(vars, e.Var)
	case *ir.BinaryOp:
		vars = append(vars, extractVarsFromExpression(e.Left)...)
		vars = append(vars, extractVarsFromExpression(e.Right)...)
	case ir.BinaryOp:
		vars = append(vars, extractVarsFromExpression(e.Left)...)
		vars = append(vars, extractVarsFromExpression(e.Right)...)
	case *ir.UnaryOp:
		vars = append(vars, extractVarsFromExpression(e.Operand)...)
	case ir.UnaryOp:
		vars = append(vars, extractVarsFromExpression(e.Operand)...)
	case *ir.Cast:
		vars = append(vars, extractVarsFromExpression(e.Expr)...)
	case ir.Cast:
		vars = append(vars, extractVarsFromExpression(e.Expr)...)
	case *ir.ConstantExpr, ir.ConstantExpr:
		// constants have no variable references
	}
	return vars
}
