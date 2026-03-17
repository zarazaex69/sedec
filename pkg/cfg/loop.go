package cfg

import (
	"errors"
	"fmt"

	"gonum.org/v1/gonum/graph/simple"
	"gonum.org/v1/gonum/graph/topo"
)

var (
	// errLoopInvalidHeader indicates loop has invalid header block
	errLoopInvalidHeader = errors.New("loop has invalid header block")
	// errLoopHeaderNotDominate indicates loop header does not dominate body block
	errLoopHeaderNotDominate = errors.New("loop header does not dominate body block")
	// errLoopBackEdgeNotToHeader indicates loop has back-edge not targeting header
	errLoopBackEdgeNotToHeader = errors.New("loop has back-edge not targeting header")
	// errLoopInconsistentDepth indicates loop has inconsistent depth
	errLoopInconsistentDepth = errors.New("loop has inconsistent depth")
	// errLoopTopLevelWrongDepth indicates loop is top-level but has wrong depth
	errLoopTopLevelWrongDepth = errors.New("loop is top-level but has wrong depth")
)

// Loop represents a natural loop in the control flow graph
// a natural loop has a single entry point (header) and one or more back-edges
type Loop struct {
	BackEdges     []*Edge   // back-edges that form this loop (target dominates source)
	ExitEdges     []*Edge   // edges leaving the loop to blocks outside
	Body          []BlockID // all blocks in the loop body (including header)
	ExitBlocks    []BlockID // blocks inside loop with edges to outside
	ParentLoop    *Loop     // parent loop if this is nested (nil for top-level)
	NestedLoops   []*Loop   // directly nested child loops
	Header        BlockID   // loop header (entry point, dominates all blocks in loop)
	Depth         int       // nesting depth (0 for outermost loops)
	IsIrreducible bool      // true if loop has multiple entry points (irreducible control flow)
}

// LoopInfo contains all detected loops and their relationships
type LoopInfo struct {
	BlockToLoops map[BlockID][]*Loop // maps each block to loops it belongs to (innermost first)
	Loops        []*Loop             // all detected loops
	cfg          *CFG                // reference to original cfg
	dt           *DominatorTree      // reference to dominator tree
}

// NewLoopInfo creates an empty loop information structure
func NewLoopInfo(cfg *CFG, dt *DominatorTree) *LoopInfo {
	return &LoopInfo{
		Loops:        make([]*Loop, 0),
		BlockToLoops: make(map[BlockID][]*Loop),
		cfg:          cfg,
		dt:           dt,
	}
}

// DetectLoops identifies all natural loops in the cfg using back-edge analysis
// this is the main entry point for loop detection
func (b *Builder) DetectLoops() (*LoopInfo, error) {
	if b.cfg == nil {
		return nil, errCFGNotBuilt
	}

	if b.dominatorTree == nil {
		var err error
		b.dominatorTree, err = b.ComputeDominators()
		if err != nil {
			return nil, fmt.Errorf("failed to compute dominators: %w", err)
		}
	}

	loopInfo := NewLoopInfo(b.cfg, b.dominatorTree)

	// step 1: identify back-edges using dominator tree
	backEdges := loopInfo.identifyBackEdges()

	// step 2: for each back-edge, construct natural loop
	for _, backEdge := range backEdges {
		loop := loopInfo.constructNaturalLoop(backEdge)
		if loop != nil {
			loopInfo.Loops = append(loopInfo.Loops, loop)
		}
	}

	// step 3: detect nested loop structures
	loopInfo.computeLoopNesting()

	// step 4: identify exit edges and exit blocks
	loopInfo.identifyExitEdges()

	// step 5: detect irreducible loops using tarjan's scc
	loopInfo.detectIrreducibleLoops()

	// step 6: build block-to-loops mapping
	loopInfo.buildBlockToLoopsMapping()

	return loopInfo, nil
}

// identifyBackEdges finds all back-edges in the cfg
// a back-edge is an edge (b, h) where h dominates b
// back-edges indicate loops in the control flow
func (li *LoopInfo) identifyBackEdges() []*Edge {
	backEdges := make([]*Edge, 0)

	for _, edge := range li.cfg.Edges {
		// check if target dominates source
		if li.dt.Dominates(edge.To, edge.From) {
			backEdges = append(backEdges, edge)
		}
	}

	return backEdges
}

// constructNaturalLoop constructs a natural loop from a back-edge
// given back-edge (b, h) where h dominates b:
// - h is the loop header
// - loop body consists of h and all blocks that can reach b without going through h
func (li *LoopInfo) constructNaturalLoop(backEdge *Edge) *Loop {
	header := backEdge.To
	tail := backEdge.From

	loop := &Loop{
		Header:        header,
		Body:          make([]BlockID, 0),
		BackEdges:     []*Edge{backEdge},
		ExitEdges:     make([]*Edge, 0),
		ExitBlocks:    make([]BlockID, 0),
		NestedLoops:   make([]*Loop, 0),
		IsIrreducible: false,
	}

	// body includes header
	bodySet := make(map[BlockID]bool)
	bodySet[header] = true

	// if tail != header, find all blocks that can reach tail without going through header
	if tail != header {
		li.findLoopBody(tail, header, bodySet)
	}

	// convert set to slice
	for blockID := range bodySet {
		loop.Body = append(loop.Body, blockID)
	}

	return loop
}

// findLoopBody performs backward traversal from tail to find all blocks in loop body
// stops when reaching header (header is already in body)
func (li *LoopInfo) findLoopBody(tail, header BlockID, bodySet map[BlockID]bool) {
	// worklist for backward traversal
	worklist := []BlockID{tail}
	bodySet[tail] = true

	for len(worklist) > 0 {
		// pop from worklist
		current := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]

		// get predecessors of current block
		block, exists := li.cfg.Blocks[current]
		if !exists {
			continue
		}

		for _, pred := range block.Predecessors {
			// skip if already in body
			if bodySet[pred] {
				continue
			}

			// skip if this is the header (we don't traverse past header)
			if pred == header {
				continue
			}

			// add to body and worklist
			bodySet[pred] = true
			worklist = append(worklist, pred)
		}
	}
}

// computeLoopNesting determines parent-child relationships between loops
// a loop L1 is nested inside loop L2 if L1.header is in L2.body and L1.header != L2.header
func (li *LoopInfo) computeLoopNesting() {
	// for each loop, find its parent loop
	for _, loop := range li.Loops {
		var parentLoop *Loop
		minParentSize := -1

		// find the smallest loop that contains this loop's header
		for _, candidateParent := range li.Loops {
			if candidateParent == loop {
				continue
			}

			// check if loop header is in candidate parent's body
			if li.blockInLoop(loop.Header, candidateParent) {
				// find smallest enclosing loop
				if minParentSize == -1 || len(candidateParent.Body) < minParentSize {
					parentLoop = candidateParent
					minParentSize = len(candidateParent.Body)
				}
			}
		}

		if parentLoop != nil {
			loop.ParentLoop = parentLoop
			parentLoop.NestedLoops = append(parentLoop.NestedLoops, loop)
		}
	}

	// compute nesting depth; use a visited set to break cycles in parent chain
	// (can occur with irreducible loops that share headers)
	for _, loop := range li.Loops {
		depth := 0
		current := loop.ParentLoop
		visited := make(map[*Loop]bool)
		for current != nil && !visited[current] {
			visited[current] = true
			depth++
			current = current.ParentLoop
		}
		loop.Depth = depth
	}
}

// blockInLoop checks if a block is in the loop body
func (li *LoopInfo) blockInLoop(blockID BlockID, loop *Loop) bool {
	for _, bodyBlock := range loop.Body {
		if bodyBlock == blockID {
			return true
		}
	}
	return false
}

// identifyExitEdges finds all edges that leave each loop
// an exit edge is an edge from a block inside the loop to a block outside
func (li *LoopInfo) identifyExitEdges() {
	for _, loop := range li.Loops {
		// create set of blocks in loop for fast lookup
		inLoop := make(map[BlockID]bool)
		for _, blockID := range loop.Body {
			inLoop[blockID] = true
		}

		exitBlockSet := make(map[BlockID]bool)

		// check all edges in cfg
		for _, edge := range li.cfg.Edges {
			// if edge goes from inside loop to outside loop
			if inLoop[edge.From] && !inLoop[edge.To] {
				loop.ExitEdges = append(loop.ExitEdges, edge)
				exitBlockSet[edge.From] = true
			}
		}

		// convert exit block set to slice
		for blockID := range exitBlockSet {
			loop.ExitBlocks = append(loop.ExitBlocks, blockID)
		}
	}
}

// detectIrreducibleLoops uses tarjan's strongly connected components algorithm
// to detect irreducible loops (loops with multiple entry points)
func (li *LoopInfo) detectIrreducibleLoops() {
	// convert cfg to gonum directed graph
	g := simple.NewDirectedGraph()

	// add all nodes
	for id := range li.cfg.Blocks {
		//nolint:gosec // blockid is controlled, overflow impossible in practice
		g.AddNode(simple.Node(int64(id)))
	}

	// add all edges (skip self-loops as gonum doesn't support them in simple graphs)
	for _, edge := range li.cfg.Edges {
		// skip self-loops
		if edge.From == edge.To {
			continue
		}

		g.SetEdge(simple.Edge{
			//nolint:gosec // blockid is controlled, overflow impossible in practice
			F: simple.Node(int64(edge.From)),
			//nolint:gosec // blockid is controlled, overflow impossible in practice
			T: simple.Node(int64(edge.To)),
		})
	}

	// compute strongly connected components using tarjan's algorithm
	sccs := topo.TarjanSCC(g)

	// for each scc with more than one node, check if it's irreducible
	for _, scc := range sccs {
		if len(scc) <= 1 {
			// single node scc - check for self-loop
			if len(scc) == 1 {
				//nolint:gosec // node id from gonum graph, controlled value
				nodeID := BlockID(scc[0].ID())
				if li.hasSelfLoop(nodeID) {
					// self-loop is a reducible single-block loop
					continue
				}
			}
			continue
		}

		// convert scc nodes to block ids
		sccBlocks := make([]BlockID, len(scc))
		for i, node := range scc {
			//nolint:gosec // node id from gonum graph, controlled value
			sccBlocks[i] = BlockID(node.ID())
		}

		// check if this scc corresponds to an irreducible loop
		if li.isIrreducibleSCC(sccBlocks) {
			// mark corresponding loop as irreducible
			li.markLoopAsIrreducible(sccBlocks)
		}
	}
}

// hasSelfLoop checks if a block has an edge to itself
func (li *LoopInfo) hasSelfLoop(blockID BlockID) bool {
	for _, edge := range li.cfg.Edges {
		if edge.From == blockID && edge.To == blockID {
			return true
		}
	}
	return false
}

// isIrreducibleSCC checks if a strongly connected component represents an irreducible loop
// an scc is irreducible if it has multiple entry points (blocks with predecessors outside scc)
func (li *LoopInfo) isIrreducibleSCC(sccBlocks []BlockID) bool {
	// create set for fast lookup
	inSCC := make(map[BlockID]bool)
	for _, blockID := range sccBlocks {
		inSCC[blockID] = true
	}

	entryCount := 0

	// count blocks with predecessors outside scc
	for _, blockID := range sccBlocks {
		block, exists := li.cfg.Blocks[blockID]
		if !exists {
			continue
		}

		hasExternalPredecessor := false
		for _, pred := range block.Predecessors {
			if !inSCC[pred] {
				hasExternalPredecessor = true
				break
			}
		}

		if hasExternalPredecessor {
			entryCount++
		}
	}

	// irreducible if more than one entry point
	return entryCount > 1
}

// markLoopAsIrreducible marks loops containing the given blocks as irreducible
func (li *LoopInfo) markLoopAsIrreducible(sccBlocks []BlockID) {
	for _, loop := range li.Loops {
		// check if loop overlaps with scc
		for _, sccBlock := range sccBlocks {
			if li.blockInLoop(sccBlock, loop) {
				loop.IsIrreducible = true
				break
			}
		}
	}
}

// buildBlockToLoopsMapping creates mapping from each block to all loops it belongs to
// loops are ordered from innermost to outermost
func (li *LoopInfo) buildBlockToLoopsMapping() {
	for blockID := range li.cfg.Blocks {
		loops := make([]*Loop, 0)

		// find all loops containing this block
		for _, loop := range li.Loops {
			if li.blockInLoop(blockID, loop) {
				loops = append(loops, loop)
			}
		}

		// sort loops by depth (innermost first)
		// bubble sort is sufficient for small number of nesting levels
		for i := 0; i < len(loops); i++ {
			for j := i + 1; j < len(loops); j++ {
				if loops[i].Depth < loops[j].Depth {
					loops[i], loops[j] = loops[j], loops[i]
				}
			}
		}

		li.BlockToLoops[blockID] = loops
	}
}

// GetInnermostLoop returns the innermost loop containing the given block
// returns nil if block is not in any loop
func (li *LoopInfo) GetInnermostLoop(blockID BlockID) *Loop {
	loops, exists := li.BlockToLoops[blockID]
	if !exists || len(loops) == 0 {
		return nil
	}
	return loops[0]
}

// GetOutermostLoop returns the outermost loop containing the given block
// returns nil if block is not in any loop
func (li *LoopInfo) GetOutermostLoop(blockID BlockID) *Loop {
	loops, exists := li.BlockToLoops[blockID]
	if !exists || len(loops) == 0 {
		return nil
	}
	return loops[len(loops)-1]
}

// GetLoopDepth returns the nesting depth of the innermost loop containing the block
// returns 0 if block is not in any loop
func (li *LoopInfo) GetLoopDepth(blockID BlockID) int {
	loop := li.GetInnermostLoop(blockID)
	if loop == nil {
		return 0
	}
	return loop.Depth + 1
}

// IsLoopHeader returns true if the block is a loop header
func (li *LoopInfo) IsLoopHeader(blockID BlockID) bool {
	for _, loop := range li.Loops {
		if loop.Header == blockID {
			return true
		}
	}
	return false
}

// GetLoopByHeader returns the loop with the given header block
// returns nil if no loop has this header
func (li *LoopInfo) GetLoopByHeader(header BlockID) *Loop {
	for _, loop := range li.Loops {
		if loop.Header == header {
			return loop
		}
	}
	return nil
}

// GetTopLevelLoops returns all loops that are not nested inside other loops
func (li *LoopInfo) GetTopLevelLoops() []*Loop {
	topLevel := make([]*Loop, 0)
	for _, loop := range li.Loops {
		if loop.ParentLoop == nil {
			topLevel = append(topLevel, loop)
		}
	}
	return topLevel
}

// LoopCount returns the total number of detected loops
func (li *LoopInfo) LoopCount() int {
	return len(li.Loops)
}

// IrreducibleLoopCount returns the number of irreducible loops
func (li *LoopInfo) IrreducibleLoopCount() int {
	count := 0
	for _, loop := range li.Loops {
		if loop.IsIrreducible {
			count++
		}
	}
	return count
}

// MaxLoopDepth returns the maximum nesting depth of all loops
func (li *LoopInfo) MaxLoopDepth() int {
	maxDepth := 0
	for _, loop := range li.Loops {
		if loop.Depth > maxDepth {
			maxDepth = loop.Depth
		}
	}
	return maxDepth
}

// VerifyLoopInfo verifies the correctness of loop detection
// returns error if any invariant is violated
func (li *LoopInfo) VerifyLoopInfo() error {
	// verify each loop has valid header
	for i, loop := range li.Loops {
		if _, exists := li.cfg.Blocks[loop.Header]; !exists {
			return fmt.Errorf("%w: loop %d, header %d", errLoopInvalidHeader, i, loop.Header)
		}

		// verify header dominates all blocks in loop body
		for _, bodyBlock := range loop.Body {
			if bodyBlock == loop.Header {
				continue
			}

			if !li.dt.Dominates(loop.Header, bodyBlock) {
				return fmt.Errorf("%w: loop %d, header %d, body %d", errLoopHeaderNotDominate, i, loop.Header, bodyBlock)
			}
		}

		// verify all back-edges target the header
		for _, backEdge := range loop.BackEdges {
			if backEdge.To != loop.Header {
				return fmt.Errorf("%w: loop %d, edge %d -> %d", errLoopBackEdgeNotToHeader, i, backEdge.From, backEdge.To)
			}
		}

		// verify nesting depth consistency
		if loop.ParentLoop != nil {
			if loop.Depth != loop.ParentLoop.Depth+1 {
				return fmt.Errorf("%w: loop %d, depth %d, parent depth %d", errLoopInconsistentDepth, i, loop.Depth, loop.ParentLoop.Depth)
			}
		} else {
			if loop.Depth != 0 {
				return fmt.Errorf("%w: loop %d, depth %d", errLoopTopLevelWrongDepth, i, loop.Depth)
			}
		}
	}

	return nil
}
