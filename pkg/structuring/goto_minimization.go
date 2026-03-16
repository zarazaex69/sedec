// package structuring - goto minimization pass
// implements node splitting for irreducible → reducible cfg transformation
// and minimal goto insertion for remaining irreducible control flow.
package structuring

import (
	"fmt"
	"sort"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// maxSplitIterations caps the node-splitting loop to prevent exponential blowup.
const maxSplitIterations = 32

// gotoMinimizer implements the goto minimization pass.
// it operates in two phases:
//  1. node splitting: transform irreducible SCCs into reducible ones
//  2. goto insertion: emit goto/label pairs for edges that remain unstructured
type gotoMinimizer struct {
	cfgraph  *cfg.CFG
	dt       *cfg.DominatorTree
	irBlocks IRBlockMap

	// splitCount tracks how many times each original block has been split
	splitCount map[cfg.BlockID]int
	// splitOrigin maps a cloned block id back to the original block id
	splitOrigin map[cfg.BlockID]cfg.BlockID
	// nextBlockID is the next available block id for cloned blocks
	nextBlockID cfg.BlockID
}

// newGotoMinimizer creates a goto minimizer for the given cfg.
func newGotoMinimizer(
	cfgraph *cfg.CFG,
	dt *cfg.DominatorTree,
	irBlocks IRBlockMap,
) *gotoMinimizer {
	// find the maximum existing block id so clones get fresh ids
	var maxID cfg.BlockID
	for id := range cfgraph.Blocks {
		if id > maxID {
			maxID = id
		}
	}

	return &gotoMinimizer{
		cfgraph:     cfgraph,
		dt:          dt,
		irBlocks:    irBlocks,
		splitCount:  make(map[cfg.BlockID]int),
		splitOrigin: make(map[cfg.BlockID]cfg.BlockID),
		nextBlockID: maxID + 1,
	}
}

// Run executes the goto minimization pass and returns the modified AST.
// it first attempts node splitting to reduce irreducible regions, then
// performs tail merging to collapse identical clones, and finally
// inserts minimal goto statements for any remaining irreducible edges.
func (g *gotoMinimizer) Run(ast *StructuredAST) *StructuredAST {
	// phase 1: node splitting for irreducible → reducible transformation
	g.splitIrreducibleRegions()

	// phase 2: tail merging — collapse cloned blocks that are structurally
	// identical back into their originals to prevent block duplication in output.
	// this is the inverse of splitNode: if a clone has exactly one predecessor
	// and its ir content is identical to the original, redirect the predecessor
	// to the original and remove the clone.
	g.mergeIdenticalClones()

	// phase 3: insert goto statements for remaining unstructured edges
	body := g.insertGotos(ast.Body)

	return &StructuredAST{
		Body:       body,
		FunctionID: ast.FunctionID,
	}
}

// mergeIdenticalClones performs tail merging after node splitting.
// for each cloned block (tracked in splitOrigin), if the clone has exactly
// one predecessor and its IR instructions are byte-for-byte identical to the
// original block, the predecessor is redirected to the original and the clone
// is removed from the CFG and irBlocks map.
// this prevents the structuring engine from emitting the same basic block twice.
func (g *gotoMinimizer) mergeIdenticalClones() {
	// collect clone ids in deterministic order
	cloneIDs := make([]cfg.BlockID, 0, len(g.splitOrigin))
	for cloneID := range g.splitOrigin {
		cloneIDs = append(cloneIDs, cloneID)
	}
	sort.Slice(cloneIDs, func(i, j int) bool { return cloneIDs[i] < cloneIDs[j] })

	for _, cloneID := range cloneIDs {
		origID, ok := g.splitOrigin[cloneID]
		if !ok {
			continue
		}

		cloneBlock, cloneExists := g.cfgraph.Blocks[cloneID]
		origBlock, origExists := g.cfgraph.Blocks[origID]
		if !cloneExists || !origExists {
			continue
		}

		// only merge if the clone has exactly one predecessor
		// (multiple predecessors mean it was split for a reason we must preserve)
		if len(cloneBlock.Predecessors) != 1 {
			continue
		}

		// verify ir content is identical
		if !g.irBlocksIdentical(cloneID, origID) {
			continue
		}

		predID := cloneBlock.Predecessors[0]
		predBlock, predExists := g.cfgraph.Blocks[predID]
		if !predExists {
			continue
		}

		// redirect predecessor's successor list: replace cloneID with origID
		for i, succ := range predBlock.Successors {
			if succ == cloneID {
				predBlock.Successors[i] = origID
				break
			}
		}

		// update edge list
		for _, edge := range g.cfgraph.Edges {
			if edge.From == predID && edge.To == cloneID {
				edge.To = origID
				break
			}
		}

		// add predID to origBlock's predecessors if not already present
		alreadyPred := false
		for _, p := range origBlock.Predecessors {
			if p == predID {
				alreadyPred = true
				break
			}
		}
		if !alreadyPred {
			origBlock.Predecessors = append(origBlock.Predecessors, predID)
		}

		// remove clone from cfg and irBlocks
		delete(g.cfgraph.Blocks, cloneID)
		delete(g.irBlocks, cloneID)
		delete(g.splitOrigin, cloneID)

		// remove edges originating from clone
		filtered := g.cfgraph.Edges[:0]
		for _, edge := range g.cfgraph.Edges {
			if edge.From != cloneID {
				filtered = append(filtered, edge)
			}
		}
		g.cfgraph.Edges = filtered
	}
}

// irBlocksIdentical returns true if the IR instruction sequences for two blocks
// are structurally identical (same string representation for each instruction).
func (g *gotoMinimizer) irBlocksIdentical(a, b cfg.BlockID) bool {
	instrsA := g.irBlocks[a]
	instrsB := g.irBlocks[b]
	if len(instrsA) != len(instrsB) {
		return false
	}
	for i := range instrsA {
		if instrsA[i].String() != instrsB[i].String() {
			return false
		}
	}
	return true
}

// ============================================================================
// phase 1: irreducible region detection and node splitting
// ============================================================================

// splitIrreducibleRegions iterates node splitting until the cfg is reducible
// or the iteration limit is reached.
func (g *gotoMinimizer) splitIrreducibleRegions() {
	for iter := 0; iter < maxSplitIterations; iter++ {
		irreducible := g.findIrreducibleSCCs()
		if len(irreducible) == 0 {
			// cfg is now reducible
			return
		}

		// split one node per iteration to avoid exponential blowup
		// pick the node with the most incoming back-edges from different headers
		target := g.chooseSplitTarget(irreducible)
		if target == 0 {
			return
		}

		g.splitNode(target)
	}
}

// findIrreducibleSCCs returns all SCCs that have multiple entry points,
// i.e., nodes in the SCC that are reachable from outside the SCC via
// more than one distinct predecessor not in the SCC.
// an SCC is irreducible if it has more than one entry node.
func (g *gotoMinimizer) findIrreducibleSCCs() [][]cfg.BlockID {
	sccs := g.tarjanSCC()
	var irreducible [][]cfg.BlockID

	for _, scc := range sccs {
		if len(scc) < 2 {
			continue
		}

		sccSet := make(map[cfg.BlockID]bool, len(scc))
		for _, id := range scc {
			sccSet[id] = true
		}

		// count entry nodes: nodes in scc with predecessors outside scc
		entryCount := 0
		for _, id := range scc {
			block, exists := g.cfgraph.Blocks[id]
			if !exists {
				continue
			}
			for _, pred := range block.Predecessors {
				if !sccSet[pred] {
					entryCount++
					break
				}
			}
		}

		if entryCount > 1 {
			irreducible = append(irreducible, scc)
		}
	}

	return irreducible
}

// tarjanSCC computes strongly connected components using Tarjan's algorithm.
// returns SCCs in reverse topological order (leaves first).
func (g *gotoMinimizer) tarjanSCC() [][]cfg.BlockID {
	index := 0
	stack := make([]cfg.BlockID, 0)
	onStack := make(map[cfg.BlockID]bool)
	indices := make(map[cfg.BlockID]int)
	lowlinks := make(map[cfg.BlockID]int)
	var sccs [][]cfg.BlockID

	var strongConnect func(v cfg.BlockID)
	strongConnect = func(v cfg.BlockID) {
		indices[v] = index
		lowlinks[v] = index
		index++
		stack = append(stack, v)
		onStack[v] = true

		block, exists := g.cfgraph.Blocks[v]
		if !exists {
			return
		}

		// visit successors in sorted order for determinism
		succs := make([]cfg.BlockID, len(block.Successors))
		copy(succs, block.Successors)
		sort.Slice(succs, func(i, j int) bool { return succs[i] < succs[j] })

		for _, w := range succs {
			if _, visited := indices[w]; !visited {
				strongConnect(w)
				if lowlinks[w] < lowlinks[v] {
					lowlinks[v] = lowlinks[w]
				}
			} else if onStack[w] {
				if indices[w] < lowlinks[v] {
					lowlinks[v] = indices[w]
				}
			}
		}

		// if v is a root node, pop the scc
		if lowlinks[v] == indices[v] {
			var scc []cfg.BlockID
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				scc = append(scc, w)
				if w == v {
					break
				}
			}
			sccs = append(sccs, scc)
		}
	}

	// visit all blocks in sorted order for determinism
	ids := make([]cfg.BlockID, 0, len(g.cfgraph.Blocks))
	for id := range g.cfgraph.Blocks {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	for _, id := range ids {
		if _, visited := indices[id]; !visited {
			strongConnect(id)
		}
	}

	return sccs
}

// chooseSplitTarget selects the best node to split from the irreducible SCCs.
// it picks the node with the most incoming edges from outside the SCC,
// preferring nodes that have not been split too many times.
func (g *gotoMinimizer) chooseSplitTarget(irreducible [][]cfg.BlockID) cfg.BlockID {
	type candidate struct {
		id         cfg.BlockID
		entryEdges int
		splits     int
	}

	var candidates []candidate

	for _, scc := range irreducible {
		sccSet := make(map[cfg.BlockID]bool, len(scc))
		for _, id := range scc {
			sccSet[id] = true
		}

		for _, id := range scc {
			block, exists := g.cfgraph.Blocks[id]
			if !exists {
				continue
			}

			// count predecessors outside the scc
			externalPreds := 0
			for _, pred := range block.Predecessors {
				if !sccSet[pred] {
					externalPreds++
				}
			}

			if externalPreds > 0 {
				// get the original block id for split count tracking
				origID := g.originalID(id)
				candidates = append(candidates, candidate{
					id:         id,
					entryEdges: externalPreds,
					splits:     g.splitCount[origID],
				})
			}
		}
	}

	if len(candidates) == 0 {
		return 0
	}

	// sort: prefer fewer splits, then more entry edges, then lower id for determinism
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].splits != candidates[j].splits {
			return candidates[i].splits < candidates[j].splits
		}
		if candidates[i].entryEdges != candidates[j].entryEdges {
			return candidates[i].entryEdges > candidates[j].entryEdges
		}
		return candidates[i].id < candidates[j].id
	})

	return candidates[0].id
}

// splitNode duplicates blockID in the cfg. each predecessor of blockID
// that comes from outside the SCC gets its own copy of the block.
// this breaks the multiple-entry property of the irreducible SCC.
func (g *gotoMinimizer) splitNode(blockID cfg.BlockID) {
	block, exists := g.cfgraph.Blocks[blockID]
	if !exists {
		return
	}

	origID := g.originalID(blockID)
	g.splitCount[origID]++

	// create a clone block with a fresh id
	cloneID := g.nextBlockID
	g.nextBlockID++
	g.splitOrigin[cloneID] = origID

	// clone the block: same successors, same ir instructions
	clone := &cfg.BasicBlock{
		ID:           cloneID,
		StartAddress: block.StartAddress,
		EndAddress:   block.EndAddress,
		Instructions: block.Instructions,
		Successors:   make([]cfg.BlockID, len(block.Successors)),
		Predecessors: make([]cfg.BlockID, 0),
	}
	copy(clone.Successors, block.Successors)
	g.cfgraph.Blocks[cloneID] = clone

	// copy ir instructions for the clone
	if instrs, ok := g.irBlocks[blockID]; ok {
		cloned := make([]ir.IRInstruction, len(instrs))
		copy(cloned, instrs)
		g.irBlocks[cloneID] = cloned
	}

	// add clone as predecessor to all successors of the original
	for _, succ := range clone.Successors {
		succBlock, ok := g.cfgraph.Blocks[succ]
		if !ok {
			continue
		}
		succBlock.Predecessors = append(succBlock.Predecessors, cloneID)
	}

	// add clone edges to the cfg edge list
	for _, succ := range clone.Successors {
		g.cfgraph.Edges = append(g.cfgraph.Edges, &cfg.Edge{
			From: cloneID,
			To:   succ,
			Type: cfg.EdgeTypeUnconditional,
		})
	}

	// find external predecessors (outside the scc) and redirect them to the clone
	// we need to determine which scc blockID belongs to
	sccSet := g.sccContaining(blockID)

	externalPreds := make([]cfg.BlockID, 0)
	for _, pred := range block.Predecessors {
		if !sccSet[pred] {
			externalPreds = append(externalPreds, pred)
		}
	}

	// redirect external predecessors to the clone
	for _, pred := range externalPreds {
		predBlock, ok := g.cfgraph.Blocks[pred]
		if !ok {
			continue
		}

		// update successor list of pred: replace blockID with cloneID
		for i, succ := range predBlock.Successors {
			if succ == blockID {
				predBlock.Successors[i] = cloneID
				break
			}
		}

		// update edge list
		for _, edge := range g.cfgraph.Edges {
			if edge.From == pred && edge.To == blockID {
				edge.To = cloneID
				break
			}
		}

		// update predecessor list of original block: remove pred
		newPreds := make([]cfg.BlockID, 0, len(block.Predecessors))
		for _, p := range block.Predecessors {
			if p != pred {
				newPreds = append(newPreds, p)
			}
		}
		block.Predecessors = newPreds

		// add pred to clone's predecessor list
		clone.Predecessors = append(clone.Predecessors, pred)
	}
}

// sccContaining returns the set of block ids in the same SCC as blockID.
func (g *gotoMinimizer) sccContaining(blockID cfg.BlockID) map[cfg.BlockID]bool {
	sccs := g.tarjanSCC()
	for _, scc := range sccs {
		for _, id := range scc {
			if id == blockID {
				set := make(map[cfg.BlockID]bool, len(scc))
				for _, s := range scc {
					set[s] = true
				}
				return set
			}
		}
	}
	return map[cfg.BlockID]bool{blockID: true}
}

// originalID returns the original block id before any splitting.
func (g *gotoMinimizer) originalID(id cfg.BlockID) cfg.BlockID {
	if orig, ok := g.splitOrigin[id]; ok {
		return orig
	}
	return id
}

// ============================================================================
// phase 2: minimal goto insertion
// ============================================================================

// labelFixer walks the structured AST and ensures that every GotoStatement
// has a corresponding LabelStatement prepended to the target IRBlock.
// it does NOT introduce new gotos — it only fixes up labels for gotos that
// the structuring engine already emitted (e.g., from collapseMultiWay).
type labelFixer struct {
	// gotoTargets collects all block ids referenced by GotoStatements
	gotoTargets map[cfg.BlockID]string
	// counter for generating unique label names
	counter int
}

func newLabelFixer() *labelFixer {
	return &labelFixer{
		gotoTargets: make(map[cfg.BlockID]string),
	}
}

func (lf *labelFixer) label(blockID cfg.BlockID) string {
	if l, ok := lf.gotoTargets[blockID]; ok {
		return l
	}
	lf.counter++
	l := fmt.Sprintf("L%d", lf.counter)
	lf.gotoTargets[blockID] = l
	return l
}

// insertGotos ensures all GotoStatement targets have LabelStatements.
// it performs two passes:
//  1. collect all goto targets from the AST
//  2. prepend LabelStatements to the corresponding IRBlock nodes
func (g *gotoMinimizer) insertGotos(stmt Statement) Statement {
	lf := newLabelFixer()
	// pass 1: collect all goto targets
	lf.collectTargets(stmt)
	// pass 2: insert labels at target blocks
	return lf.insertLabels(stmt)
}

// collectTargets walks the AST and registers all GotoStatement targets.
func (lf *labelFixer) collectTargets(stmt Statement) {
	if stmt == nil {
		return
	}
	switch s := stmt.(type) {
	case GotoStatement:
		_ = lf.label(s.Target)
	case Block:
		for _, child := range s.Stmts {
			lf.collectTargets(child)
		}
	case IfStatement:
		lf.collectTargets(s.Then)
		if s.Else != nil {
			lf.collectTargets(s.Else)
		}
	case WhileStatement:
		lf.collectTargets(s.Body)
	case DoWhileStatement:
		lf.collectTargets(s.Body)
	case ForStatement:
		if s.Init != nil {
			lf.collectTargets(s.Init)
		}
		if s.Post != nil {
			lf.collectTargets(s.Post)
		}
		lf.collectTargets(s.Body)
	}
}

// insertLabels walks the AST and prepends LabelStatements to IRBlock nodes
// that are goto targets.
func (lf *labelFixer) insertLabels(stmt Statement) Statement {
	if stmt == nil {
		return nil
	}
	switch s := stmt.(type) {
	case IRBlock:
		if label, ok := lf.gotoTargets[s.BlockID]; ok {
			return Block{Stmts: []Statement{
				LabelStatement{Name: label},
				s,
			}}
		}
		return s

	case Block:
		result := make([]Statement, 0, len(s.Stmts))
		for _, child := range s.Stmts {
			walked := lf.insertLabels(child)
			if walked != nil {
				result = append(result, walked)
			}
		}
		if len(result) == 0 {
			return Block{Stmts: nil}
		}
		if len(result) == 1 {
			return result[0]
		}
		return Block{Stmts: result}

	case IfStatement:
		then := lf.insertLabels(s.Then)
		var els Statement
		if s.Else != nil {
			els = lf.insertLabels(s.Else)
		}
		return IfStatement{Condition: s.Condition, Then: then, Else: els}

	case WhileStatement:
		return WhileStatement{Condition: s.Condition, Body: lf.insertLabels(s.Body)}

	case DoWhileStatement:
		return DoWhileStatement{Body: lf.insertLabels(s.Body), Condition: s.Condition}

	case ForStatement:
		var init, post Statement
		if s.Init != nil {
			init = lf.insertLabels(s.Init)
		}
		if s.Post != nil {
			post = lf.insertLabels(s.Post)
		}
		return ForStatement{
			Init:      init,
			Condition: s.Condition,
			Post:      post,
			Body:      lf.insertLabels(s.Body),
		}

	default:
		return stmt
	}
}

// ============================================================================
// MinimizeGotos is the public entry point for the goto minimization pass.
// it takes a structured AST and returns a new AST with:
//   - irreducible SCCs reduced via node splitting where possible
//   - minimal goto statements inserted for remaining irreducible edges
//
// Requirements: 15.6 (goto-free where possible), 15.7 (minimal gotos for irreducible)
// ============================================================================

// MinimizeGotos applies the goto minimization pass to the given AST.
// cfgraph and irBlocks are used for node splitting analysis.
// dt is the dominator tree used for back-edge detection.
func MinimizeGotos(
	ast *StructuredAST,
	cfgraph *cfg.CFG,
	dt *cfg.DominatorTree,
	irBlocks IRBlockMap,
) *StructuredAST {
	if ast == nil || cfgraph == nil || dt == nil {
		return ast
	}

	minimizer := newGotoMinimizer(cfgraph, dt, irBlocks)
	return minimizer.Run(ast)
}

// CountGotos counts the number of GotoStatement nodes in the AST.
// used for testing that goto count is minimal.
func CountGotos(stmt Statement) int {
	if stmt == nil {
		return 0
	}
	switch s := stmt.(type) {
	case GotoStatement:
		return 1
	case Block:
		count := 0
		for _, child := range s.Stmts {
			count += CountGotos(child)
		}
		return count
	case IfStatement:
		count := CountGotos(s.Then)
		if s.Else != nil {
			count += CountGotos(s.Else)
		}
		return count
	case WhileStatement:
		return CountGotos(s.Body)
	case DoWhileStatement:
		return CountGotos(s.Body)
	case ForStatement:
		count := 0
		if s.Init != nil {
			count += CountGotos(s.Init)
		}
		if s.Post != nil {
			count += CountGotos(s.Post)
		}
		count += CountGotos(s.Body)
		return count
	default:
		return 0
	}
}

// IsReducible checks whether the cfg is reducible (no irreducible SCCs).
// a cfg is reducible if every SCC has at most one entry node.
func IsReducible(cfgraph *cfg.CFG) bool {
	if cfgraph == nil {
		return true
	}
	// use a temporary minimizer just for the reducibility check
	g := newGotoMinimizer(cfgraph, nil, make(IRBlockMap))
	return len(g.findIrreducibleSCCs()) == 0
}
