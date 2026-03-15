package typeinfer

import (
	"fmt"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// Steensgaard's Pointer Analysis
//
// flow-insensitive, context-insensitive, equality-based pointer analysis.
// complexity: O(n α(n)) where α is the inverse Ackermann function.
//
// the algorithm models each program variable as a node in a points-to graph.
// equality constraints (x = y, x = &y, x = *y, *x = y) are solved by
// union-find, collapsing nodes that must point to the same abstract location.
//
// requirements: 45.1, 45.2, 45.3
// ============================================================================

// ptNode is a single node in the Steensgaard points-to graph.
// each node represents an abstract memory location (variable or heap cell).
type ptNode struct {
	// parent is the union-find parent index; self-loop means root.
	parent int

	// rank is used for union-by-rank to keep trees shallow.
	rank int

	// pointsTo is the index of the node that this location points to.
	// -1 means this node is not a pointer (or its target is unknown).
	// after union-find, this field is only meaningful on root nodes.
	pointsTo int

	// name is the canonical name of this abstract location (for diagnostics).
	name string
}

// PointsToSet maps a variable name to the set of abstract locations it may
// point to. the set is represented as a slice of location names.
type PointsToSet map[string][]string

// SteensgaardAnalyzer implements Steensgaard's pointer analysis.
// it maintains a union-find structure over abstract memory locations and
// processes pointer constraints in near-linear time.
//
// requirements: 45.1, 45.2, 45.3
type SteensgaardAnalyzer struct {
	// nodes is the flat array of all abstract location nodes.
	// indices into this slice are stable identifiers.
	nodes []ptNode

	// nameToNode maps a canonical location name to its node index.
	nameToNode map[string]int

	// heapCounter generates unique names for heap allocation sites.
	heapCounter int
}

// NewSteensgaardAnalyzer allocates a fresh analyzer ready to process constraints.
func NewSteensgaardAnalyzer() *SteensgaardAnalyzer {
	return &SteensgaardAnalyzer{
		nodes:      make([]ptNode, 0, 64),
		nameToNode: make(map[string]int, 64),
	}
}

// ============================================================================
// union-find primitives
// ============================================================================

// newNode allocates a fresh self-rooted node and returns its index.
func (a *SteensgaardAnalyzer) newNode(name string) int {
	idx := len(a.nodes)
	a.nodes = append(a.nodes, ptNode{
		parent:   idx, // self-loop = root
		rank:     0,
		pointsTo: -1,
		name:     name,
	})
	return idx
}

// find returns the canonical root index for node i using path compression
// (path halving variant: O(α(n)) amortised, single-pass, no recursion).
func (a *SteensgaardAnalyzer) find(i int) int {
	for a.nodes[i].parent != i {
		// path halving: point i to its grandparent
		grandparent := a.nodes[a.nodes[i].parent].parent
		a.nodes[i].parent = grandparent
		i = grandparent
	}
	return i
}

// union merges the equivalence classes of nodes i and j using union-by-rank.
// it also merges the pointsTo fields: if both roots have targets, those targets
// are recursively unified (Steensgaard's key invariant: each equivalence class
// has at most one points-to target).
// returns the index of the new root.
func (a *SteensgaardAnalyzer) union(i, j int) int {
	ri, rj := a.find(i), a.find(j)
	if ri == rj {
		return ri
	}

	// snapshot pointsTo before modifying parent pointers
	ptI := a.nodes[ri].pointsTo
	ptJ := a.nodes[rj].pointsTo

	var newRoot, oldRoot int
	switch {
	case a.nodes[ri].rank < a.nodes[rj].rank:
		a.nodes[ri].parent = rj
		newRoot, oldRoot = rj, ri
	case a.nodes[ri].rank > a.nodes[rj].rank:
		a.nodes[rj].parent = ri
		newRoot, oldRoot = ri, rj
	default:
		a.nodes[rj].parent = ri
		a.nodes[ri].rank++
		newRoot, oldRoot = ri, rj
	}
	_ = oldRoot

	// merge pointsTo on the new root
	switch {
	case ptI != -1 && ptJ != -1:
		merged := a.union(ptI, ptJ)
		a.nodes[newRoot].pointsTo = merged
	case ptI != -1:
		a.nodes[newRoot].pointsTo = ptI
	case ptJ != -1:
		a.nodes[newRoot].pointsTo = ptJ
	default:
		a.nodes[newRoot].pointsTo = -1
	}

	return newRoot
}

// ============================================================================
// node lookup / creation
// ============================================================================

// nodeFor returns the node index for a named location, creating it if absent.
func (a *SteensgaardAnalyzer) nodeFor(name string) int {
	if idx, ok := a.nameToNode[name]; ok {
		return idx
	}
	idx := a.newNode(name)
	a.nameToNode[name] = idx
	return idx
}

// heapNodeFor returns a unique heap node for an allocation site identified by
// the given label (e.g., function name + instruction address).
func (a *SteensgaardAnalyzer) heapNodeFor(label string) int {
	heapName := fmt.Sprintf("$heap_%s_%d", label, a.heapCounter)
	a.heapCounter++
	return a.nodeFor(heapName)
}

// ============================================================================
// Steensgaard constraint processing
// ============================================================================

// processAddressOf handles: x = &y  (x points to y)
// sets x's points-to target to y's node.
// if x already points to some other node z, unifies y and z (Steensgaard's
// key insight: all locations that x may point to are collapsed into one).
func (a *SteensgaardAnalyzer) processAddressOf(x, y string) {
	xNode := a.nodeFor(x)
	yNode := a.nodeFor(y)

	xRoot := a.find(xNode)
	yRoot := a.find(yNode)

	if a.nodes[xRoot].pointsTo == -1 {
		// x does not yet point to anything: set its target to y
		a.nodes[xRoot].pointsTo = yRoot
	} else {
		// x already points to some node: unify that node with y
		existingTarget := a.find(a.nodes[xRoot].pointsTo)
		newRoot := a.union(existingTarget, yRoot)
		a.nodes[a.find(xRoot)].pointsTo = newRoot
	}
}

// processCopy handles: x = y  (x and y point to the same locations)
// unifies x and y into the same equivalence class. since union() now
// automatically merges pointsTo fields, no additional work is needed.
func (a *SteensgaardAnalyzer) processCopy(x, y string) {
	xNode := a.nodeFor(x)
	yNode := a.nodeFor(y)
	a.union(xNode, yNode)
}

// processLoad handles: x = *y  (x receives the value pointed to by y)
// x's points-to target must be unified with the points-to target of y's target.
func (a *SteensgaardAnalyzer) processLoad(x, y string) {
	xNode := a.nodeFor(x)
	yNode := a.nodeFor(y)

	yRoot := a.find(yNode)
	yTarget := a.nodes[yRoot].pointsTo

	if yTarget == -1 {
		// y does not yet point to anything: create a fresh heap node as y's target
		// and make x point to a fresh node that is y's target's target.
		yTargetNode := a.heapNodeFor(fmt.Sprintf("load_y_%s", y))
		a.nodes[yRoot].pointsTo = yTargetNode

		xTargetNode := a.heapNodeFor(fmt.Sprintf("load_x_%s", x))
		a.nodes[a.find(yTargetNode)].pointsTo = xTargetNode

		xRoot := a.find(xNode)
		if a.nodes[xRoot].pointsTo == -1 {
			a.nodes[xRoot].pointsTo = xTargetNode
		} else {
			merged := a.union(a.nodes[xRoot].pointsTo, xTargetNode)
			a.nodes[a.find(xRoot)].pointsTo = merged
		}
		return
	}

	// y points to yTarget: x must point to the same locations as yTarget
	yTargetRoot := a.find(yTarget)
	xRoot := a.find(xNode)

	xTarget := a.nodes[xRoot].pointsTo
	yTargetTarget := a.nodes[yTargetRoot].pointsTo

	switch {
	case xTarget == -1 && yTargetTarget == -1:
		// neither x nor *y has a target yet: create a shared fresh node
		sharedNode := a.heapNodeFor(fmt.Sprintf("load_shared_%s_%s", x, y))
		a.nodes[xRoot].pointsTo = sharedNode
		a.nodes[yTargetRoot].pointsTo = sharedNode
	case xTarget == -1:
		a.nodes[xRoot].pointsTo = yTargetTarget
	case yTargetTarget == -1:
		a.nodes[yTargetRoot].pointsTo = xTarget
	default:
		merged := a.union(xTarget, yTargetTarget)
		a.nodes[a.find(xRoot)].pointsTo = merged
		a.nodes[a.find(yTargetRoot)].pointsTo = merged
	}
}

// processStore handles: *x = y  (store y through pointer x)
// x's target must be unified with y.
func (a *SteensgaardAnalyzer) processStore(x, y string) {
	xNode := a.nodeFor(x)
	yNode := a.nodeFor(y)

	xRoot := a.find(xNode)
	xTarget := a.nodes[xRoot].pointsTo

	if xTarget == -1 {
		// x does not yet point to anything: create a fresh heap node as x's target
		// and unify it with y.
		freshNode := a.heapNodeFor(fmt.Sprintf("store_%s", x))
		a.nodes[xRoot].pointsTo = freshNode
		xTarget = freshNode
	}

	// unify x's target with y
	xTargetRoot := a.find(xTarget)
	yRoot := a.find(yNode)

	if xTargetRoot != yRoot {
		newRoot := a.union(xTargetRoot, yRoot)
		a.nodes[a.find(xRoot)].pointsTo = newRoot
	}
}

// ============================================================================
// IR traversal
// ============================================================================

// PointerConstraint classifies a single pointer-relevant IR instruction.
type PointerConstraint struct {
	// Kind identifies the constraint type.
	Kind PointerConstraintKind

	// LHS is the left-hand side variable name.
	LHS string

	// RHS is the right-hand side variable name (or address-taken variable).
	RHS string
}

// PointerConstraintKind classifies the four fundamental pointer constraint forms.
type PointerConstraintKind int

const (
	// PtrConstraintAddressOf represents lhs = &rhs.
	PtrConstraintAddressOf PointerConstraintKind = iota

	// PtrConstraintCopy represents lhs = rhs (pointer copy).
	PtrConstraintCopy

	// PtrConstraintLoad represents lhs = *rhs.
	PtrConstraintLoad

	// PtrConstraintStore represents *lhs = rhs.
	PtrConstraintStore
)

// String returns a human-readable name for the constraint kind.
func (k PointerConstraintKind) String() string {
	switch k {
	case PtrConstraintAddressOf:
		return "addr_of"
	case PtrConstraintCopy:
		return "copy"
	case PtrConstraintLoad:
		return "load"
	case PtrConstraintStore:
		return "store"
	default:
		return fmt.Sprintf("unknown(%d)", int(k))
	}
}

// ExtractPointerConstraints traverses an IR function and extracts all
// pointer-relevant constraints for Steensgaard analysis.
//
// the extraction rules are:
//   - Assign{dest, VariableExpr{src}}: copy constraint if either is a pointer
//   - Load{dest, addr}: load constraint (dest = *addr)
//   - Store{addr, value}: store constraint (*addr = value)
//   - Assign{dest, Cast{VariableExpr{src}, PointerType}}: address-of approximation
//   - Call with pointer arguments: copy constraints for each pointer arg
func ExtractPointerConstraints(fn *ir.Function) []PointerConstraint {
	var constraints []PointerConstraint

	blockIDs := sortedBlockIDs(fn)
	for _, bid := range blockIDs {
		block := fn.Blocks[bid]
		for _, instr := range block.Instructions {
			cs := extractFromInstruction(instr)
			constraints = append(constraints, cs...)
		}
	}

	return constraints
}

// extractFromInstruction extracts pointer constraints from a single IR instruction.
func extractFromInstruction(instr ir.IRInstruction) []PointerConstraint {
	switch i := instr.(type) {
	case ir.Assign:
		return extractFromAssign(i)
	case ir.Load:
		return []PointerConstraint{{
			Kind: PtrConstraintLoad,
			LHS:  i.Dest.String(),
			RHS:  exprRootVar(i.Address),
		}}
	case ir.Store:
		return []PointerConstraint{{
			Kind: PtrConstraintStore,
			LHS:  exprRootVar(i.Address),
			RHS:  exprRootVar(i.Value),
		}}
	case ir.Call:
		return extractFromCall(i)
	case ir.Phi:
		return extractFromPhi(i)
	default:
		return nil
	}
}

// extractFromAssign extracts constraints from an assignment instruction.
// handles: copy (x = y), address-of (x = &y via cast), and pointer arithmetic.
func extractFromAssign(a ir.Assign) []PointerConstraint {
	destName := a.Dest.String()

	switch src := a.Source.(type) {
	case ir.VariableExpr:
		// x = y: copy constraint (conservative: always emit, analysis handles non-pointers)
		return []PointerConstraint{{
			Kind: PtrConstraintCopy,
			LHS:  destName,
			RHS:  src.Var.String(),
		}}

	case ir.Cast:
		// x = (T)y: if target type is a pointer, treat as address-of approximation
		if _, isPtr := src.TargetType.(ir.PointerType); isPtr {
			innerVar := exprRootVar(src.Expr)
			if innerVar != "" {
				return []PointerConstraint{{
					Kind: PtrConstraintAddressOf,
					LHS:  destName,
					RHS:  innerVar,
				}}
			}
		}
		// non-pointer cast: copy the inner variable conservatively
		innerVar := exprRootVar(src.Expr)
		if innerVar != "" {
			return []PointerConstraint{{
				Kind: PtrConstraintCopy,
				LHS:  destName,
				RHS:  innerVar,
			}}
		}

	case ir.BinaryOp:
		// pointer arithmetic: x = base + offset → x aliases base
		// only emit if the left operand is a variable (the base pointer)
		baseVar := exprRootVar(src.Left)
		if baseVar != "" {
			return []PointerConstraint{{
				Kind: PtrConstraintCopy,
				LHS:  destName,
				RHS:  baseVar,
			}}
		}
	}

	return nil
}

// extractFromCall extracts copy constraints for pointer arguments passed to a call.
// each argument is conservatively treated as a copy to the callee's parameter.
func extractFromCall(c ir.Call) []PointerConstraint {
	var constraints []PointerConstraint

	// if the call has a return destination, create a synthetic return node
	if c.Dest != nil {
		targetVar := exprRootVar(c.Target)
		if targetVar != "" {
			retNode := fmt.Sprintf("$ret_%s", targetVar)
			constraints = append(constraints, PointerConstraint{
				Kind: PtrConstraintCopy,
				LHS:  c.Dest.String(),
				RHS:  retNode,
			})
		}
	}

	// each argument is a copy to the callee's parameter
	targetVar := exprRootVar(c.Target)
	for idx, arg := range c.Args {
		paramNode := fmt.Sprintf("$param_%s_%d", targetVar, idx)
		constraints = append(constraints, PointerConstraint{
			Kind: PtrConstraintCopy,
			LHS:  paramNode,
			RHS:  arg.String(),
		})
	}

	return constraints
}

// extractFromPhi extracts copy constraints from a phi node.
// each phi source is a copy to the phi destination.
func extractFromPhi(p ir.Phi) []PointerConstraint {
	destName := p.Dest.String()
	constraints := make([]PointerConstraint, 0, len(p.Sources))
	for _, src := range p.Sources {
		constraints = append(constraints, PointerConstraint{
			Kind: PtrConstraintCopy,
			LHS:  destName,
			RHS:  src.Var.String(),
		})
	}
	return constraints
}

// exprRootVar extracts the root variable name from an expression.
// for VariableExpr: returns the variable name.
// for BinaryOp: returns the left operand's root variable (pointer arithmetic base).
// for all others: returns "" (no extractable variable).
func exprRootVar(expr ir.Expression) string {
	if expr == nil {
		return ""
	}
	switch e := expr.(type) {
	case ir.VariableExpr:
		return e.Var.String()
	case ir.BinaryOp:
		return exprRootVar(e.Left)
	case ir.Cast:
		return exprRootVar(e.Expr)
	default:
		return ""
	}
}

// ============================================================================
// main analysis entry point
// ============================================================================

// Analyze runs Steensgaard's pointer analysis on the given IR function.
// it extracts pointer constraints from the IR, processes them through the
// union-find structure, and returns the resulting PointsToSet.
//
// the analysis is flow-insensitive: all constraints are processed without
// regard to program order. this is sound but may over-approximate.
//
// complexity: O(n α(n)) where n is the number of pointer-relevant instructions.
//
// requirements: 45.1, 45.2, 45.3
func (a *SteensgaardAnalyzer) Analyze(fn *ir.Function) PointsToSet {
	constraints := ExtractPointerConstraints(fn)
	return a.AnalyzeConstraints(constraints)
}

// AnalyzeConstraints processes a pre-extracted set of pointer constraints
// and returns the resulting PointsToSet.
// this entry point is useful for testing and for interprocedural analysis
// where constraints are collected across multiple functions.
func (a *SteensgaardAnalyzer) AnalyzeConstraints(constraints []PointerConstraint) PointsToSet {
	// process all constraints through the union-find structure
	for _, c := range constraints {
		switch c.Kind {
		case PtrConstraintAddressOf:
			a.processAddressOf(c.LHS, c.RHS)
		case PtrConstraintCopy:
			a.processCopy(c.LHS, c.RHS)
		case PtrConstraintLoad:
			a.processLoad(c.LHS, c.RHS)
		case PtrConstraintStore:
			a.processStore(c.LHS, c.RHS)
		}
	}

	return a.buildPointsToSet()
}

// buildPointsToSet constructs the final PointsToSet from the union-find structure.
// for each named (non-heap) variable, it resolves the canonical root of its
// points-to target and collects all variable names in that equivalence class.
func (a *SteensgaardAnalyzer) buildPointsToSet() PointsToSet {
	// build a map from root index to all names in that equivalence class
	rootToNames := make(map[int][]string, len(a.nodes))
	for name, idx := range a.nameToNode {
		root := a.find(idx)
		rootToNames[root] = append(rootToNames[root], name)
	}

	result := make(PointsToSet, len(a.nameToNode))

	for name, idx := range a.nameToNode {
		root := a.find(idx)
		// always read pointsTo from the canonical root
		target := a.nodes[root].pointsTo

		if target == -1 {
			// this variable does not point to anything
			result[name] = nil
			continue
		}

		// collect all names in the target's equivalence class
		targetRoot := a.find(target)
		targetNames := rootToNames[targetRoot]

		// sort for deterministic output
		sorted := make([]string, len(targetNames))
		copy(sorted, targetNames)
		sortStrings(sorted)

		result[name] = sorted
	}

	return result
}

// ============================================================================
// interprocedural Steensgaard analysis
// ============================================================================

// AnalyzeProgram runs Steensgaard's analysis across all functions in the program.
// it processes constraints from all functions in a single shared union-find
// structure, which is the standard approach for context-insensitive analysis.
//
// the shared structure means that a pointer passed to a function is unified
// with all other pointers passed to that function at any call site, which is
// the defining characteristic of Steensgaard's equality-based approach.
//
// requirements: 45.1, 45.2, 45.3
func (a *SteensgaardAnalyzer) AnalyzeProgram(functions []*ir.Function) PointsToSet {
	// collect all constraints from all functions
	var allConstraints []PointerConstraint
	for _, fn := range functions {
		cs := ExtractPointerConstraints(fn)
		allConstraints = append(allConstraints, cs...)
	}

	return a.AnalyzeConstraints(allConstraints)
}

// PointsTo returns the set of abstract locations that variable varName may
// point to, according to the current analysis state.
// returns nil if the variable is not a pointer or has not been analyzed.
func (a *SteensgaardAnalyzer) PointsTo(varName string) []string {
	idx, ok := a.nameToNode[varName]
	if !ok {
		return nil
	}

	root := a.find(idx)
	target := a.nodes[root].pointsTo
	if target == -1 {
		return nil
	}

	targetRoot := a.find(target)

	// collect all names in the target's equivalence class
	var names []string
	for name, nodeIdx := range a.nameToNode {
		if a.find(nodeIdx) == targetRoot {
			names = append(names, name)
		}
	}

	sortStrings(names)
	return names
}

// MayAlias returns true if variables a and b may point to the same location.
// two variables may alias if and only if their points-to sets intersect,
// which in Steensgaard's analysis means their points-to targets are in the
// same equivalence class.
func (a *SteensgaardAnalyzer) MayAlias(varA, varB string) bool {
	idxA, okA := a.nameToNode[varA]
	idxB, okB := a.nameToNode[varB]

	if !okA || !okB {
		return false
	}

	rootA := a.find(idxA)
	rootB := a.find(idxB)

	// direct alias: a and b are in the same equivalence class
	if rootA == rootB {
		return true
	}

	// indirect alias: a and b point to the same abstract location
	targetA := a.nodes[rootA].pointsTo
	targetB := a.nodes[rootB].pointsTo

	if targetA == -1 || targetB == -1 {
		return false
	}

	return a.find(targetA) == a.find(targetB)
}

// ============================================================================
// utility
// ============================================================================

// sortStrings sorts a slice of strings in ascending lexicographic order
// using insertion sort (fast for small slices typical in points-to sets).
func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		key := ss[i]
		j := i - 1
		for j >= 0 && ss[j] > key {
			ss[j+1] = ss[j]
			j--
		}
		ss[j+1] = key
	}
}
