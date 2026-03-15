package typeinfer

import (
	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// Andersen's Pointer Analysis
//
// flow-insensitive, context-insensitive, inclusion-based (subset-based) pointer
// analysis. complexity: O(n^3) worst case, O(n^2) in practice for typical code.
//
// unlike Steensgaard's equality-based analysis, Andersen's analysis uses
// inclusion constraints (pts(x) ⊆ pts(y)) rather than equality constraints.
// this produces strictly more precise results at the cost of higher complexity.
//
// the algorithm builds an inclusion constraint graph and computes its transitive
// closure using an online worklist algorithm with SCC (cycle) detection and
// collapsing. cycles in the constraint graph are collapsed into single nodes
// (Lazy Cycle Detection, Hardekopf & Lin 2007) to avoid redundant propagation.
//
// constraint forms:
//   - addr_of:  pts(x) ⊇ {y}          (x = &y)
//   - copy:     pts(x) ⊇ pts(y)        (x = y)
//   - load:     pts(x) ⊇ pts(*y)       (x = *y)  → complex constraint
//   - store:    pts(*x) ⊇ pts(y)       (*x = y)  → complex constraint
//
// requirements: 45.4, 45.5, 45.6, 45.8
// ============================================================================

// andersenNode is a single node in the Andersen constraint graph.
// each node represents an abstract memory location (variable or heap cell).
type andersenNode struct {
	// id is the stable index of this node in AndersenAnalyzer.nodes.
	id int

	// name is the canonical name of this abstract location (for diagnostics).
	name string

	// pointsTo is the current points-to set: set of node indices that this
	// location may point to. represented as a sorted slice for determinism.
	pointsTo []int

	// copyEdges are outgoing copy edges in the constraint graph.
	// if this node has a copy edge to j, then pts(j) ⊇ pts(this).
	copyEdges []int

	// complexLoads are pending load constraints: for each l in complexLoads,
	// whenever o ∈ pts(this), add copy edge pts(l) ⊇ pts(o).
	// encodes: l = *this
	complexLoads []int

	// complexStores are pending store constraints: for each s in complexStores,
	// whenever o ∈ pts(this), add copy edge pts(o) ⊇ pts(s).
	// encodes: *this = s
	complexStores []int

	// union-find parent for SCC collapsing.
	// self-loop means this node is its own representative.
	parent int

	// rank for union-by-rank in SCC collapsing.
	rank int
}

// AndersenPointsToSet maps a variable name to the precise set of abstract
// locations it may point to. more precise than Steensgaard's PointsToSet
// because inclusion constraints are not collapsed into equality classes.
type AndersenPointsToSet map[string][]string

// AndersenAnalyzer implements Andersen's inclusion-based pointer analysis.
// it maintains an explicit constraint graph and propagates points-to sets
// through copy edges using an online worklist algorithm.
//
// requirements: 45.4, 45.5, 45.6, 45.8
type AndersenAnalyzer struct {
	// nodes is the flat array of all abstract location nodes.
	nodes []andersenNode

	// nameToNode maps a canonical location name to its node index.
	nameToNode map[string]int

	// worklist contains node indices whose points-to sets have grown and
	// whose outgoing edges must be re-propagated.
	worklist []int

	// inWorklist tracks which nodes are currently in the worklist to avoid
	// duplicate entries (O(1) membership test).
	inWorklist map[int]bool
}

// NewAndersenAnalyzer allocates a fresh analyzer ready to process constraints.
func NewAndersenAnalyzer() *AndersenAnalyzer {
	return &AndersenAnalyzer{
		nodes:      make([]andersenNode, 0, 64),
		nameToNode: make(map[string]int, 64),
		inWorklist: make(map[int]bool, 64),
	}
}

// ============================================================================
// union-find for SCC collapsing
// ============================================================================

// andersenFind returns the canonical representative index for node i using
// path compression (path halving variant).
func (a *AndersenAnalyzer) andersenFind(i int) int {
	for a.nodes[i].parent != i {
		grandparent := a.nodes[a.nodes[i].parent].parent
		a.nodes[i].parent = grandparent
		i = grandparent
	}
	return i
}

// andersenUnion merges the equivalence classes of nodes i and j.
// the merged node inherits the union of both nodes' points-to sets,
// copy edges, and complex constraints. returns the new representative.
func (a *AndersenAnalyzer) andersenUnion(i, j int) int {
	ri, rj := a.andersenFind(i), a.andersenFind(j)
	if ri == rj {
		return ri
	}

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

	// merge points-to sets: newRoot.pts ∪= oldRoot.pts
	for _, pt := range a.nodes[oldRoot].pointsTo {
		a.addToPointsTo(newRoot, pt)
	}

	// merge copy edges
	for _, dst := range a.nodes[oldRoot].copyEdges {
		a.addCopyEdge(newRoot, dst)
	}

	// merge complex constraints
	for _, l := range a.nodes[oldRoot].complexLoads {
		a.addComplexLoad(newRoot, l)
	}
	for _, s := range a.nodes[oldRoot].complexStores {
		a.addComplexStore(newRoot, s)
	}

	// clear old root's data to avoid double-processing
	a.nodes[oldRoot].pointsTo = nil
	a.nodes[oldRoot].copyEdges = nil
	a.nodes[oldRoot].complexLoads = nil
	a.nodes[oldRoot].complexStores = nil

	return newRoot
}

// ============================================================================
// node management
// ============================================================================

// newAndersenNode allocates a fresh self-rooted node and returns its index.
func (a *AndersenAnalyzer) newAndersenNode(name string) int {
	idx := len(a.nodes)
	a.nodes = append(a.nodes, andersenNode{
		id:     idx,
		name:   name,
		parent: idx, // self-loop = root
	})
	return idx
}

// nodeFor returns the node index for a named location, creating it if absent.
func (a *AndersenAnalyzer) andersenNodeFor(name string) int {
	if idx, ok := a.nameToNode[name]; ok {
		return idx
	}
	idx := a.newAndersenNode(name)
	a.nameToNode[name] = idx
	return idx
}

// addToPointsTo adds target to node's points-to set if not already present.
// returns true if the set grew (new element added).
func (a *AndersenAnalyzer) addToPointsTo(nodeIdx, target int) bool {
	root := a.andersenFind(nodeIdx)
	target = a.andersenFind(target)

	// check for existing membership (linear scan; sets are small in practice)
	for _, existing := range a.nodes[root].pointsTo {
		if a.andersenFind(existing) == target {
			return false
		}
	}
	a.nodes[root].pointsTo = append(a.nodes[root].pointsTo, target)
	return true
}

// addCopyEdge adds a copy edge from src to dst: pts(dst) ⊇ pts(src).
// returns true if the edge is new.
func (a *AndersenAnalyzer) addCopyEdge(src, dst int) bool {
	src = a.andersenFind(src)
	dst = a.andersenFind(dst)
	if src == dst {
		return false
	}
	for _, existing := range a.nodes[src].copyEdges {
		if a.andersenFind(existing) == dst {
			return false
		}
	}
	a.nodes[src].copyEdges = append(a.nodes[src].copyEdges, dst)
	return true
}

// addComplexLoad registers a load constraint: dst = *src.
// whenever a new object o enters pts(src), we add copy edge pts(dst) ⊇ pts(o).
func (a *AndersenAnalyzer) addComplexLoad(src, dst int) {
	src = a.andersenFind(src)
	for _, existing := range a.nodes[src].complexLoads {
		if a.andersenFind(existing) == a.andersenFind(dst) {
			return
		}
	}
	a.nodes[src].complexLoads = append(a.nodes[src].complexLoads, dst)
}

// addComplexStore registers a store constraint: *dst = src.
// whenever a new object o enters pts(dst), we add copy edge pts(o) ⊇ pts(src).
func (a *AndersenAnalyzer) addComplexStore(dst, src int) {
	dst = a.andersenFind(dst)
	for _, existing := range a.nodes[dst].complexStores {
		if a.andersenFind(existing) == a.andersenFind(src) {
			return
		}
	}
	a.nodes[dst].complexStores = append(a.nodes[dst].complexStores, src)
}

// pushWorklist adds nodeIdx to the worklist if not already present.
func (a *AndersenAnalyzer) pushWorklist(nodeIdx int) {
	root := a.andersenFind(nodeIdx)
	if !a.inWorklist[root] {
		a.worklist = append(a.worklist, root)
		a.inWorklist[root] = true
	}
}

// popWorklist removes and returns the last element from the worklist.
func (a *AndersenAnalyzer) popWorklist() int {
	n := len(a.worklist)
	node := a.worklist[n-1]
	a.worklist = a.worklist[:n-1]
	delete(a.inWorklist, node)
	return node
}

// ============================================================================
// constraint processing (initial seeding)
// ============================================================================

// processAndersenAddressOf handles: x = &y → pts(x) ⊇ {y}
func (a *AndersenAnalyzer) processAndersenAddressOf(x, y string) {
	xNode := a.andersenNodeFor(x)
	yNode := a.andersenNodeFor(y)

	if a.addToPointsTo(xNode, yNode) {
		a.pushWorklist(xNode)
	}
}

// processAndersenCopy handles: x = y → pts(x) ⊇ pts(y)
// adds a copy edge from y to x in the constraint graph.
func (a *AndersenAnalyzer) processAndersenCopy(x, y string) {
	xNode := a.andersenNodeFor(x)
	yNode := a.andersenNodeFor(y)

	// copy edge: y → x means pts(x) ⊇ pts(y)
	if a.addCopyEdge(yNode, xNode) {
		// propagate existing pts(y) to pts(x) immediately
		yRoot := a.andersenFind(yNode)
		for _, pt := range a.nodes[yRoot].pointsTo {
			if a.addToPointsTo(xNode, pt) {
				a.pushWorklist(xNode)
			}
		}
	}
}

// processAndersenLoad handles: x = *y → pts(x) ⊇ pts(o) for all o ∈ pts(y)
// registers a complex load constraint that is resolved during propagation.
func (a *AndersenAnalyzer) processAndersenLoad(x, y string) {
	xNode := a.andersenNodeFor(x)
	yNode := a.andersenNodeFor(y)

	// register complex load: whenever o ∈ pts(y), add copy edge o → x
	a.addComplexLoad(yNode, xNode)

	// resolve immediately for any objects already in pts(y)
	yRoot := a.andersenFind(yNode)
	for _, o := range a.nodes[yRoot].pointsTo {
		oRoot := a.andersenFind(o)
		if a.addCopyEdge(oRoot, xNode) {
			// propagate pts(o) to pts(x)
			for _, pt := range a.nodes[oRoot].pointsTo {
				if a.addToPointsTo(xNode, pt) {
					a.pushWorklist(xNode)
				}
			}
		}
	}
}

// processAndersenStore handles: *x = y → pts(o) ⊇ pts(y) for all o ∈ pts(x)
// registers a complex store constraint that is resolved during propagation.
func (a *AndersenAnalyzer) processAndersenStore(x, y string) {
	xNode := a.andersenNodeFor(x)
	yNode := a.andersenNodeFor(y)

	// register complex store: whenever o ∈ pts(x), add copy edge y → o
	a.addComplexStore(xNode, yNode)

	// resolve immediately for any objects already in pts(x)
	xRoot := a.andersenFind(xNode)
	for _, o := range a.nodes[xRoot].pointsTo {
		oRoot := a.andersenFind(o)
		if a.addCopyEdge(yNode, oRoot) {
			// propagate pts(y) to pts(o)
			yRoot := a.andersenFind(yNode)
			for _, pt := range a.nodes[yRoot].pointsTo {
				if a.addToPointsTo(oRoot, pt) {
					a.pushWorklist(oRoot)
				}
			}
		}
	}
}

// ============================================================================
// online propagation with lazy cycle detection (Hardekopf & Lin 2007)
// ============================================================================

// propagate runs the online worklist algorithm to compute the transitive closure
// of the constraint graph. it processes nodes whose points-to sets have grown,
// propagating new objects through copy edges and resolving complex constraints.
//
// lazy cycle detection: when a node n is processed and a copy edge n → m exists
// where pts(n) == pts(m) and m has a copy edge back to n (i.e., they are in a
// cycle), the two nodes are collapsed into a single SCC representative.
// this avoids redundant propagation through cycles.
func (a *AndersenAnalyzer) propagate() {
	for len(a.worklist) > 0 {
		nodeIdx := a.popWorklist()
		root := a.andersenFind(nodeIdx)

		// snapshot the current points-to set and edges to avoid mutation during iteration
		pts := make([]int, len(a.nodes[root].pointsTo))
		copy(pts, a.nodes[root].pointsTo)

		copyEdges := make([]int, len(a.nodes[root].copyEdges))
		copy(copyEdges, a.nodes[root].copyEdges)

		loads := make([]int, len(a.nodes[root].complexLoads))
		copy(loads, a.nodes[root].complexLoads)

		stores := make([]int, len(a.nodes[root].complexStores))
		copy(stores, a.nodes[root].complexStores)

		// resolve complex load constraints: for each o ∈ pts(root), add copy o → l
		for _, o := range pts {
			oRoot := a.andersenFind(o)
			for _, l := range loads {
				lRoot := a.andersenFind(l)
				if a.addCopyEdge(oRoot, lRoot) {
					// propagate pts(o) to pts(l)
					for _, pt := range a.nodes[oRoot].pointsTo {
						if a.addToPointsTo(lRoot, pt) {
							a.pushWorklist(lRoot)
						}
					}
				}
			}
		}

		// resolve complex store constraints: for each o ∈ pts(root), add copy s → o
		for _, o := range pts {
			oRoot := a.andersenFind(o)
			for _, s := range stores {
				sRoot := a.andersenFind(s)
				if a.addCopyEdge(sRoot, oRoot) {
					// propagate pts(s) to pts(o)
					for _, pt := range a.nodes[sRoot].pointsTo {
						if a.addToPointsTo(oRoot, pt) {
							a.pushWorklist(oRoot)
						}
					}
				}
			}
		}

		// propagate pts(root) through copy edges
		for _, dst := range copyEdges {
			dstRoot := a.andersenFind(dst)
			if dstRoot == root {
				continue // self-edge after SCC collapse
			}

			// propagate all objects in pts(root) to pts(dst)
			grew := false
			for _, pt := range pts {
				if a.addToPointsTo(dstRoot, pt) {
					grew = true
				}
			}
			if grew {
				a.pushWorklist(dstRoot)
			}

			// lazy cycle detection: if pts(root) == pts(dst) and there is a
			// back-edge dst → root, collapse them into a single SCC node.
			if a.hasCopyEdge(dstRoot, root) && a.pointsToEqual(root, dstRoot) {
				merged := a.andersenUnion(root, dstRoot)
				// after merge, continue with the new representative
				root = merged
			}
		}
	}
}

// hasCopyEdge returns true if there is a copy edge from src to dst.
func (a *AndersenAnalyzer) hasCopyEdge(src, dst int) bool {
	src = a.andersenFind(src)
	dst = a.andersenFind(dst)
	for _, e := range a.nodes[src].copyEdges {
		if a.andersenFind(e) == dst {
			return true
		}
	}
	return false
}

// pointsToEqual returns true if pts(a) == pts(b) (same set of objects).
func (a *AndersenAnalyzer) pointsToEqual(nodeA, nodeB int) bool {
	ra := a.andersenFind(nodeA)
	rb := a.andersenFind(nodeB)
	if ra == rb {
		return true
	}

	ptsA := a.nodes[ra].pointsTo
	ptsB := a.nodes[rb].pointsTo

	if len(ptsA) != len(ptsB) {
		return false
	}

	// build a set from ptsA and check all of ptsB are in it
	setA := make(map[int]bool, len(ptsA))
	for _, o := range ptsA {
		setA[a.andersenFind(o)] = true
	}
	for _, o := range ptsB {
		if !setA[a.andersenFind(o)] {
			return false
		}
	}
	return true
}

// ============================================================================
// IR traversal and constraint extraction
// ============================================================================

// ExtractAndersenConstraints traverses an IR function and extracts all
// pointer-relevant constraints for Andersen analysis.
// the extraction rules are identical to Steensgaard's ExtractPointerConstraints
// since both analyses consume the same four constraint forms.
func ExtractAndersenConstraints(fn *ir.Function) []PointerConstraint {
	// reuse the same extraction logic as Steensgaard
	return ExtractPointerConstraints(fn)
}

// ============================================================================
// main analysis entry points
// ============================================================================

// AnalyzeConstraints processes a pre-extracted set of pointer constraints
// and returns the resulting AndersenPointsToSet.
// this is the core entry point for both intraprocedural and interprocedural use.
//
// algorithm:
//  1. seed the constraint graph with all addr_of constraints (pts(x) ⊇ {y})
//  2. add copy edges for copy constraints (pts(x) ⊇ pts(y))
//  3. register complex constraints for load/store
//  4. run online propagation with lazy cycle detection to fixed point
//
// requirements: 45.4, 45.5, 45.6
func (a *AndersenAnalyzer) AnalyzeConstraints(constraints []PointerConstraint) AndersenPointsToSet {
	// phase 1: seed addr_of constraints first (they establish ground-truth pts sets)
	for _, c := range constraints {
		if c.Kind == PtrConstraintAddressOf {
			a.processAndersenAddressOf(c.LHS, c.RHS)
		}
	}

	// phase 2: process copy, load, store constraints
	for _, c := range constraints {
		switch c.Kind {
		case PtrConstraintAddressOf:
			// handled in phase 1
		case PtrConstraintCopy:
			a.processAndersenCopy(c.LHS, c.RHS)
		case PtrConstraintLoad:
			a.processAndersenLoad(c.LHS, c.RHS)
		case PtrConstraintStore:
			a.processAndersenStore(c.LHS, c.RHS)
		}
	}

	// phase 3: propagate to fixed point
	a.propagate()

	return a.buildAndersenPointsToSet()
}

// Analyze runs Andersen's pointer analysis on the given IR function.
// it extracts pointer constraints from the IR and returns the precise
// AndersenPointsToSet.
//
// requirements: 45.4, 45.5, 45.6
func (a *AndersenAnalyzer) Analyze(fn *ir.Function) AndersenPointsToSet {
	constraints := ExtractAndersenConstraints(fn)
	return a.AnalyzeConstraints(constraints)
}

// AnalyzeProgram runs Andersen's analysis across all functions in the program.
// all constraints are processed in a single shared constraint graph, which
// provides context-insensitive but inclusion-precise interprocedural results.
//
// requirements: 45.4, 45.5, 45.6
func (a *AndersenAnalyzer) AnalyzeProgram(functions []*ir.Function) AndersenPointsToSet {
	var allConstraints []PointerConstraint
	for _, fn := range functions {
		cs := ExtractAndersenConstraints(fn)
		allConstraints = append(allConstraints, cs...)
	}
	return a.AnalyzeConstraints(allConstraints)
}

// buildAndersenPointsToSet constructs the final AndersenPointsToSet from the
// constraint graph after propagation has reached a fixed point.
func (a *AndersenAnalyzer) buildAndersenPointsToSet() AndersenPointsToSet {
	// build a map from root index to all names in that equivalence class
	rootToNames := make(map[int][]string, len(a.nodes))
	for name, idx := range a.nameToNode {
		root := a.andersenFind(idx)
		rootToNames[root] = append(rootToNames[root], name)
	}

	result := make(AndersenPointsToSet, len(a.nameToNode))

	for name, idx := range a.nameToNode {
		root := a.andersenFind(idx)
		pts := a.nodes[root].pointsTo

		if len(pts) == 0 {
			result[name] = nil
			continue
		}

		// collect all names in the points-to set
		var targetNames []string
		seen := make(map[int]bool, len(pts))
		for _, ptIdx := range pts {
			ptRoot := a.andersenFind(ptIdx)
			if seen[ptRoot] {
				continue
			}
			seen[ptRoot] = true
			names := rootToNames[ptRoot]
			targetNames = append(targetNames, names...)
		}

		sortStrings(targetNames)
		result[name] = targetNames
	}

	return result
}

// ============================================================================
// query API
// ============================================================================

// PointsTo returns the precise set of abstract locations that varName may
// point to, according to the current analysis state.
// returns nil if the variable is not a pointer or has not been analyzed.
func (a *AndersenAnalyzer) PointsTo(varName string) []string {
	idx, ok := a.nameToNode[varName]
	if !ok {
		return nil
	}

	root := a.andersenFind(idx)
	pts := a.nodes[root].pointsTo
	if len(pts) == 0 {
		return nil
	}

	// build a map from root index to all names for result construction
	rootToNames := make(map[int][]string, len(a.nodes))
	for name, nodeIdx := range a.nameToNode {
		r := a.andersenFind(nodeIdx)
		rootToNames[r] = append(rootToNames[r], name)
	}

	var names []string
	seen := make(map[int]bool, len(pts))
	for _, ptIdx := range pts {
		ptRoot := a.andersenFind(ptIdx)
		if seen[ptRoot] {
			continue
		}
		seen[ptRoot] = true
		names = append(names, rootToNames[ptRoot]...)
	}

	sortStrings(names)
	return names
}

// MayAlias returns true if variables varA and varB may point to the same
// abstract location. unlike Steensgaard's MayAlias, this check is precise:
// it only returns true if the points-to sets actually intersect, not merely
// if the variables are in the same equivalence class.
func (a *AndersenAnalyzer) MayAlias(varA, varB string) bool {
	idxA, okA := a.nameToNode[varA]
	idxB, okB := a.nameToNode[varB]
	if !okA || !okB {
		return false
	}

	rootA := a.andersenFind(idxA)
	rootB := a.andersenFind(idxB)

	// direct alias: same representative after SCC collapsing
	if rootA == rootB {
		return true
	}

	// check if pts(a) ∩ pts(b) ≠ ∅
	ptsA := a.nodes[rootA].pointsTo
	ptsB := a.nodes[rootB].pointsTo

	if len(ptsA) == 0 || len(ptsB) == 0 {
		return false
	}

	// build set from smaller pts for O(min(|A|,|B|)) intersection check
	if len(ptsA) > len(ptsB) {
		ptsA, ptsB = ptsB, ptsA
	}

	setA := make(map[int]bool, len(ptsA))
	for _, o := range ptsA {
		setA[a.andersenFind(o)] = true
	}
	for _, o := range ptsB {
		if setA[a.andersenFind(o)] {
			return true
		}
	}
	return false
}

// ============================================================================
// selective application (hot path analysis)
// ============================================================================

// HotPathSelector determines which functions should use the more expensive
// Andersen analysis vs the cheaper Steensgaard analysis.
// a function is considered a "hot path" if it:
//   - contains more than hotPathLoadStoreThreshold load/store instructions
//   - contains indirect calls (function pointer calls)
//   - is in a loop with pointer-heavy operations
//
// requirements: 45.8
type HotPathSelector struct {
	// LoadStoreThreshold is the minimum number of load/store instructions
	// for a function to be considered a hot path. default: 10.
	LoadStoreThreshold int

	// IndirectCallThreshold is the minimum number of indirect calls
	// for a function to be considered a hot path. default: 1.
	IndirectCallThreshold int
}

// DefaultHotPathSelector returns a HotPathSelector with conservative defaults.
func DefaultHotPathSelector() *HotPathSelector {
	return &HotPathSelector{
		LoadStoreThreshold:    10,
		IndirectCallThreshold: 1,
	}
}

// IsHotPath returns true if the given function should use Andersen analysis.
// the decision is based on instruction counts and indirect call presence.
//
// requirements: 45.8
func (s *HotPathSelector) IsHotPath(fn *ir.Function) bool {
	loadStoreCount := 0
	indirectCallCount := 0

	for _, block := range fn.Blocks {
		for _, instr := range block.Instructions {
			switch i := instr.(type) {
			case ir.Load:
				loadStoreCount++
			case ir.Store:
				loadStoreCount++
			case ir.Call:
				// indirect call: target is not a constant (function pointer)
				if _, isConst := i.Target.(ir.ConstantExpr); !isConst {
					if _, isVar := i.Target.(ir.VariableExpr); isVar {
						indirectCallCount++
					}
				}
			}
		}
	}

	return loadStoreCount >= s.LoadStoreThreshold ||
		indirectCallCount >= s.IndirectCallThreshold
}

// SelectiveAnalyze runs Andersen analysis on hot-path functions and
// Steensgaard analysis on the rest, merging results into a unified
// AndersenPointsToSet. this provides a precision/performance trade-off
// suitable for large binaries.
//
// requirements: 45.8
func SelectiveAnalyze(
	functions []*ir.Function,
	selector *HotPathSelector,
) AndersenPointsToSet {
	if selector == nil {
		selector = DefaultHotPathSelector()
	}

	result := make(AndersenPointsToSet)

	// partition functions into hot and cold sets
	var hotFunctions []*ir.Function
	var coldFunctions []*ir.Function

	for _, fn := range functions {
		if selector.IsHotPath(fn) {
			hotFunctions = append(hotFunctions, fn)
		} else {
			coldFunctions = append(coldFunctions, fn)
		}
	}

	// run Andersen on hot functions (precise)
	if len(hotFunctions) > 0 {
		andersenAnalyzer := NewAndersenAnalyzer()
		hotPts := andersenAnalyzer.AnalyzeProgram(hotFunctions)
		for k, v := range hotPts {
			result[k] = v
		}
	}

	// run Steensgaard on cold functions (fast)
	if len(coldFunctions) > 0 {
		steensgaardAnalyzer := NewSteensgaardAnalyzer()
		coldPts := steensgaardAnalyzer.AnalyzeProgram(coldFunctions)
		// convert Steensgaard PointsToSet to AndersenPointsToSet
		for k, v := range coldPts {
			if _, exists := result[k]; !exists {
				result[k] = v
			}
		}
	}

	return result
}
