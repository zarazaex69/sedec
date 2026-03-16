package cfg

import (
	"errors"
	"fmt"

	"gonum.org/v1/gonum/graph/flow"
	"gonum.org/v1/gonum/graph/simple"
)

var (
	// errCFGNotBuilt indicates cfg not built yet
	errCFGNotBuilt = errors.New("cfg not built yet")
	// errCFGHasNoBlocks indicates cfg has no blocks
	errCFGHasNoBlocks = errors.New("cfg has no blocks")
	// errEntryDoesNotDominate indicates entry block does not dominate reachable block
	errEntryDoesNotDominate = errors.New("entry block does not dominate reachable block")
	// errCycleInDominatorTree indicates cycle detected in dominator tree
	errCycleInDominatorTree = errors.New("cycle detected in dominator tree")
	// errChildBlockNoIdom indicates child block has no idom
	errChildBlockNoIdom = errors.New("child block has no idom but listed as child")
	// errChildBlockWrongIdom indicates child block has wrong idom
	errChildBlockWrongIdom = errors.New("child block has wrong idom")
)

// DominatorTree represents the dominator tree structure for a CFG
// it provides immediate dominator relationships and children mappings
type DominatorTree struct {
	Idom     map[BlockID]BlockID   // immediate dominator for each block
	Children map[BlockID][]BlockID // children in dominator tree for each block
	DFSNum   map[BlockID]int       // dfs numbering for each block
	Parent   map[BlockID]BlockID   // parent in dfs spanning tree
	cfg      *CFG                  // reference to original cfg
}

// NewDominatorTree creates an empty dominator tree structure
func NewDominatorTree(cfg *CFG) *DominatorTree {
	return &DominatorTree{
		Idom:     make(map[BlockID]BlockID),
		Children: make(map[BlockID][]BlockID),
		DFSNum:   make(map[BlockID]int),
		Parent:   make(map[BlockID]BlockID),
		cfg:      cfg,
	}
}

// Dominates returns true if block a dominates block b
// a dominates b if all paths from entry to b pass through a
func (dt *DominatorTree) Dominates(a, b BlockID) bool {
	// entry dominates all reachable blocks
	if a == dt.cfg.Entry {
		return true
	}

	// a block dominates itself
	if a == b {
		return true
	}

	// walk up dominator tree from b to entry
	current := b
	for {
		idom, exists := dt.Idom[current]
		if !exists {
			// reached entry or unreachable block
			return false
		}

		if idom == a {
			return true
		}

		if idom == current {
			// reached entry (entry's idom is itself)
			return false
		}

		current = idom
	}
}

// StrictlyDominates returns true if a strictly dominates b (a dominates b and a != b)
func (dt *DominatorTree) StrictlyDominates(a, b BlockID) bool {
	return a != b && dt.Dominates(a, b)
}

// GetImmediateDominator returns the immediate dominator of a block
func (dt *DominatorTree) GetImmediateDominator(block BlockID) (BlockID, bool) {
	idom, exists := dt.Idom[block]
	return idom, exists
}

// GetChildren returns the children of a block in the dominator tree
func (dt *DominatorTree) GetChildren(block BlockID) []BlockID {
	return dt.Children[block]
}

// GetDFSNumber returns the dfs number assigned to a block
func (dt *DominatorTree) GetDFSNumber(block BlockID) (int, bool) {
	num, exists := dt.DFSNum[block]
	return num, exists
}

// ComputeDominators computes the dominator tree for the cfg using lengauer-tarjan algorithm
// this is the main entry point for dominator tree construction
func (b *Builder) ComputeDominators() (*DominatorTree, error) {
	if b.cfg == nil {
		return nil, errCFGNotBuilt
	}
	return ComputeDominatorsForCFG(b.cfg)
}

// ComputeDominatorsForCFG computes the dominator tree for any cfg using lengauer-tarjan algorithm.
// this allows computing dominators without a Builder, e.g. for reconstructed cfgs.
func ComputeDominatorsForCFG(cfgGraph *CFG) (*DominatorTree, error) {
	if cfgGraph == nil {
		return nil, errCFGNotBuilt
	}

	if len(cfgGraph.Blocks) == 0 {
		return nil, errCFGHasNoBlocks
	}

	// create dominator tree structure
	dt := NewDominatorTree(cfgGraph)

	// convert cfg to gonum directed graph
	g := simple.NewDirectedGraph()

	// add all nodes
	for id := range cfgGraph.Blocks {
		//nolint:gosec // G115: safe conversion - blockid range is limited by cfg size
		g.AddNode(simple.Node(int64(id)))
	}

	// add all edges (skip self-loops as gonum doesn't support them)
	for _, edge := range cfgGraph.Edges {
		if edge.From == edge.To {
			continue
		}
		//nolint:gosec // G115: safe conversion - blockid range is limited by cfg size
		g.SetEdge(simple.Edge{
			F: simple.Node(int64(edge.From)),
			T: simple.Node(int64(edge.To)),
		})
	}

	// perform dfs numbering to build spanning tree
	dt.performDFSNumbering(cfgGraph.Entry)

	// compute dominators using gonum's lengauer-tarjan implementation
	//nolint:gosec // G115: safe conversion - blockid range is limited by cfg size
	entryNode := simple.Node(int64(cfgGraph.Entry))
	dominatorTree := flow.Dominators(entryNode, g)

	// extract immediate dominators from gonum result
	for id := range cfgGraph.Blocks {
		if id == cfgGraph.Entry {
			dt.Idom[id] = id
			continue
		}

		//nolint:gosec // G115: safe conversion - blockid range is limited by cfg size
		node := simple.Node(int64(id))
		idomNode := dominatorTree.DominatorOf(node.ID())

		if idomNode == nil {
			continue
		}

		//nolint:gosec // G115: safe conversion - node id comes from our controlled graph
		idomID := BlockID(idomNode.ID())
		dt.Idom[id] = idomID
	}

	// build children mapping from idom relationships
	dt.buildChildrenMapping()

	return dt, nil
}

// performDFSNumbering performs depth-first search to assign dfs numbers
// and build the dfs spanning tree (parent relationships)
func (dt *DominatorTree) performDFSNumbering(entry BlockID) {
	visited := make(map[BlockID]bool)
	dfsCounter := 0

	var dfs func(BlockID)
	dfs = func(current BlockID) {
		if visited[current] {
			return
		}

		visited[current] = true
		dt.DFSNum[current] = dfsCounter
		dfsCounter++

		// visit all successors
		block, exists := dt.cfg.Blocks[current]
		if !exists {
			return
		}

		for _, successor := range block.Successors {
			if !visited[successor] {
				dt.Parent[successor] = current
				dfs(successor)
			}
		}
	}

	// entry has no parent
	dt.Parent[entry] = entry
	dfs(entry)
}

// buildChildrenMapping constructs the children mapping from idom relationships
func (dt *DominatorTree) buildChildrenMapping() {
	// initialize children slices
	for id := range dt.cfg.Blocks {
		dt.Children[id] = make([]BlockID, 0)
	}

	// for each block, add it as child of its immediate dominator
	for block, idom := range dt.Idom {
		if block == idom {
			// skip entry (its own idom)
			continue
		}

		dt.Children[idom] = append(dt.Children[idom], block)
	}
}

// ComputeDominanceFrontiers computes dominance frontiers for all blocks
// dominance frontier of block x is the set of blocks y where:
// - x dominates a predecessor of y
// - x does not strictly dominate y
// this is used for ssa phi-node placement
func (dt *DominatorTree) ComputeDominanceFrontiers() map[BlockID][]BlockID {
	df := make(map[BlockID][]BlockID)

	// initialize empty frontiers
	for id := range dt.cfg.Blocks {
		df[id] = make([]BlockID, 0)
	}

	// for each block y
	for y := range dt.cfg.Blocks {
		block, exists := dt.cfg.Blocks[y]
		if !exists {
			continue
		}

		// if y has multiple predecessors
		if len(block.Predecessors) >= 2 {
			// for each predecessor p of y
			for _, p := range block.Predecessors {
				runner := p

				// walk up dominator tree from p
				for runner != dt.Idom[y] {
					// add y to dominance frontier of runner
					if !contains(df[runner], y) {
						df[runner] = append(df[runner], y)
					}

					// move to immediate dominator
					idom, idomExists := dt.Idom[runner]
					if !idomExists || idom == runner {
						break
					}
					runner = idom
				}
			}
		}
	}

	return df
}

// contains checks if a slice contains a specific block id
func contains(slice []BlockID, item BlockID) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

// VerifyDominatorTree verifies the correctness of the dominator tree
// returns error if any invariant is violated
func (dt *DominatorTree) VerifyDominatorTree() error {
	// verify entry dominates all reachable blocks
	for id := range dt.cfg.Blocks {
		if id == dt.cfg.Entry {
			continue
		}

		if !dt.Dominates(dt.cfg.Entry, id) {
			return fmt.Errorf("%w: entry %d, block %d", errEntryDoesNotDominate, dt.cfg.Entry, id)
		}
	}

	// verify idom relationships are acyclic
	for block := range dt.cfg.Blocks {
		visited := make(map[BlockID]bool)
		current := block

		for {
			if visited[current] {
				return fmt.Errorf("%w: block %d", errCycleInDominatorTree, current)
			}

			visited[current] = true

			idom, exists := dt.Idom[current]
			if !exists {
				break
			}

			if idom == current {
				// reached entry
				break
			}

			current = idom
		}
	}

	// verify children mapping consistency
	for parent, children := range dt.Children {
		for _, child := range children {
			idom, exists := dt.Idom[child]
			if !exists {
				return fmt.Errorf("%w: child %d, parent %d", errChildBlockNoIdom, child, parent)
			}

			if idom != parent {
				return fmt.Errorf("%w: child %d, idom %d, parent %d", errChildBlockWrongIdom, child, idom, parent)
			}
		}
	}

	return nil
}

// GetDominatorTreeDepth returns the maximum depth of the dominator tree
func (dt *DominatorTree) GetDominatorTreeDepth() int {
	maxDepth := 0

	var computeDepth func(BlockID, int)
	computeDepth = func(block BlockID, depth int) {
		if depth > maxDepth {
			maxDepth = depth
		}

		for _, child := range dt.Children[block] {
			computeDepth(child, depth+1)
		}
	}

	computeDepth(dt.cfg.Entry, 0)
	return maxDepth
}

// GetDominatorPath returns the path from block to entry in dominator tree
func (dt *DominatorTree) GetDominatorPath(block BlockID) []BlockID {
	path := make([]BlockID, 0)
	current := block

	for {
		path = append(path, current)

		idom, exists := dt.Idom[current]
		if !exists || idom == current {
			break
		}

		current = idom
	}

	return path
}
