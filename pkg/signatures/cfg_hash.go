package signatures

import (
	"encoding/binary"
	"sort"

	"github.com/zarazaex69/sedec/pkg/cfg"
)

// ComputeCFGHash derives a structural hash from a control-flow graph.
//
// the hash captures:
//   - number of basic blocks
//   - number of CFG edges
//   - sorted degree sequence (in-degree, out-degree) of every block
//   - number of natural loops (back-edges in the dominator tree)
//   - maximum depth of the dominator tree
//
// all fields are address-independent, so the hash is stable across
// different load addresses of the same binary.
func ComputeCFGHash(graph *cfg.CFG) *CFGHash {
	if graph == nil {
		return &CFGHash{}
	}

	blockCount := graph.BlockCount()
	edgeCount := graph.EdgeCount()

	// build degree sequence
	inDeg := make(map[cfg.BlockID]int, blockCount)
	outDeg := make(map[cfg.BlockID]int, blockCount)

	for id := range graph.Blocks {
		inDeg[id] = 0
		outDeg[id] = 0
	}

	for _, e := range graph.Edges {
		outDeg[e.From]++
		inDeg[e.To]++
	}

	degSeq := make([]DegreeEntry, 0, blockCount)
	for id := range graph.Blocks {
		degSeq = append(degSeq, DegreeEntry{
			InDegree:  inDeg[id],
			OutDegree: outDeg[id],
		})
	}

	// sort for canonical ordering
	sort.Slice(degSeq, func(i, j int) bool {
		if degSeq[i].InDegree != degSeq[j].InDegree {
			return degSeq[i].InDegree < degSeq[j].InDegree
		}
		return degSeq[i].OutDegree < degSeq[j].OutDegree
	})

	// count back-edges (loops) using dominator tree
	loopCount := countLoops(graph)

	// compute dominator tree depth
	domDepth := computeDomTreeDepth(graph)

	h := &CFGHash{
		BlockCount:         blockCount,
		EdgeCount:          edgeCount,
		DegreeSequence:     degSeq,
		LoopCount:          loopCount,
		DominatorTreeDepth: domDepth,
	}
	h.Hash64 = hashCFGFields(h)

	return h
}

// countLoops counts back-edges by checking whether the target of each edge
// dominates its source using a simple reachability check (no full dominator
// tree construction to keep this self-contained and allocation-light).
func countLoops(graph *cfg.CFG) int {
	if len(graph.Blocks) == 0 {
		return 0
	}

	// compute reachability from entry via DFS to assign DFS order numbers
	dfsNum := make(map[cfg.BlockID]int, len(graph.Blocks))
	counter := 0

	var dfs func(id cfg.BlockID)
	dfs = func(id cfg.BlockID) {
		if _, seen := dfsNum[id]; seen {
			return
		}
		dfsNum[id] = counter
		counter++
		block, ok := graph.Blocks[id]
		if !ok {
			return
		}
		for _, succ := range block.Successors {
			dfs(succ)
		}
	}
	dfs(graph.Entry)

	// a back-edge (u → v) exists when v was visited before u in DFS
	// (i.e. dfsNum[v] <= dfsNum[u] and v is an ancestor of u)
	// we use the simpler heuristic: edge (u → v) is a back-edge when
	// dfsNum[v] <= dfsNum[u], which is accurate for reducible CFGs.
	count := 0
	for _, e := range graph.Edges {
		numFrom, okFrom := dfsNum[e.From]
		numTo, okTo := dfsNum[e.To]
		if okFrom && okTo && numTo <= numFrom {
			count++
		}
	}
	return count
}

// computeDomTreeDepth computes the maximum depth of the dominator tree using
// a lightweight iterative fixed-point algorithm (Cooper et al. 2001).
func computeDomTreeDepth(graph *cfg.CFG) int {
	if len(graph.Blocks) == 0 {
		return 0
	}

	// assign RPO numbers
	rpo := computeRPO(graph)
	if len(rpo) == 0 {
		return 0
	}

	// idom[b] = immediate dominator of b (index into rpo slice)
	idom := make([]int, len(rpo))
	for i := range idom {
		idom[i] = -1
	}
	// entry dominates itself
	idom[0] = 0

	rpoIndex := make(map[cfg.BlockID]int, len(rpo))
	for i, id := range rpo {
		rpoIndex[id] = i
	}

	changed := true
	for changed {
		changed = false
		// iterate in RPO order (skip entry at index 0)
		for i := 1; i < len(rpo); i++ {
			blockID := rpo[i]
			block, ok := graph.Blocks[blockID]
			if !ok {
				continue
			}

			newIdom := -1
			for _, pred := range block.Predecessors {
				predIdx, exists := rpoIndex[pred]
				if !exists {
					continue
				}
				if idom[predIdx] == -1 {
					continue
				}
				if newIdom == -1 {
					newIdom = predIdx
				} else {
					newIdom = intersect(idom, newIdom, predIdx)
				}
			}

			if newIdom != -1 && idom[i] != newIdom {
				idom[i] = newIdom
				changed = true
			}
		}
	}

	// compute depth of each node in the dominator tree
	depth := make([]int, len(rpo))
	maxDepth := 0
	for i := 1; i < len(rpo); i++ {
		d := 0
		cur := i
		for cur != 0 && idom[cur] != cur {
			d++
			cur = idom[cur]
			if d > len(rpo) {
				// cycle guard
				break
			}
		}
		depth[i] = d
		if d > maxDepth {
			maxDepth = d
		}
	}

	return maxDepth
}

// intersect finds the common dominator of two nodes in the idom array.
func intersect(idom []int, a, b int) int {
	for a != b {
		for a > b {
			a = idom[a]
		}
		for b > a {
			b = idom[b]
		}
	}
	return a
}

// computeRPO returns blocks in reverse post-order starting from the entry.
func computeRPO(graph *cfg.CFG) []cfg.BlockID {
	visited := make(map[cfg.BlockID]bool, len(graph.Blocks))
	postOrder := make([]cfg.BlockID, 0, len(graph.Blocks))

	var dfs func(id cfg.BlockID)
	dfs = func(id cfg.BlockID) {
		if visited[id] {
			return
		}
		visited[id] = true
		block, ok := graph.Blocks[id]
		if !ok {
			return
		}
		for _, succ := range block.Successors {
			dfs(succ)
		}
		postOrder = append(postOrder, id)
	}
	dfs(graph.Entry)

	// reverse
	for i, j := 0, len(postOrder)-1; i < j; i, j = i+1, j-1 {
		postOrder[i], postOrder[j] = postOrder[j], postOrder[i]
	}
	return postOrder
}

// hashCFGFields computes a 64-bit FNV-1a hash over the structural fields.
func hashCFGFields(h *CFGHash) uint64 {
	const (
		fnvOffset uint64 = 14695981039346656037
		fnvPrime  uint64 = 1099511628211
	)

	hash := fnvOffset

	mix := func(v uint64) {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], v)
		for _, b := range buf {
			hash ^= uint64(b)
			hash *= fnvPrime
		}
	}

	mix(uint64(h.BlockCount))
	mix(uint64(h.EdgeCount))
	mix(uint64(h.LoopCount))
	mix(uint64(h.DominatorTreeDepth))

	for _, d := range h.DegreeSequence {
		mix(uint64(d.InDegree)<<32 | uint64(d.OutDegree))
	}

	return hash
}

// CFGHashSimilarity computes a similarity score in [0.0, 1.0] between two
// CFG hashes. the score is a weighted combination of normalised differences
// in block count, edge count, loop count, and dominator tree depth.
func CFGHashSimilarity(a, b *CFGHash) float64 {
	if a == nil || b == nil {
		return 0.0
	}

	// exact hash match → perfect score
	if a.Hash64 == b.Hash64 {
		return 1.0
	}

	// component-wise similarity using normalised absolute difference
	blockSim := normSim(a.BlockCount, b.BlockCount)
	edgeSim := normSim(a.EdgeCount, b.EdgeCount)
	loopSim := normSim(a.LoopCount, b.LoopCount)
	depthSim := normSim(a.DominatorTreeDepth, b.DominatorTreeDepth)
	degSim := degreeSequenceSimilarity(a.DegreeSequence, b.DegreeSequence)

	// weighted combination
	score := 0.25*blockSim + 0.20*edgeSim + 0.15*loopSim + 0.15*depthSim + 0.25*degSim
	return score
}

// normSim returns 1 - |a-b| / max(a,b,1).
func normSim(a, b int) float64 {
	if a == b {
		return 1.0
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	maxVal := a
	if b > maxVal {
		maxVal = b
	}
	if maxVal == 0 {
		return 1.0
	}
	return 1.0 - float64(diff)/float64(maxVal)
}

// degreeSequenceSimilarity computes the similarity of two sorted degree sequences
// using the longest common subsequence length normalised by the longer sequence.
func degreeSequenceSimilarity(a, b []DegreeEntry) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	if maxLen == 0 {
		return 1.0
	}

	// count matching entries (both sequences are sorted, use two-pointer merge)
	i, j := 0, 0
	matches := 0
	for i < len(a) && j < len(b) {
		ai := a[i]
		bj := b[j]
		if ai.InDegree == bj.InDegree && ai.OutDegree == bj.OutDegree {
			matches++
			i++
			j++
		} else if ai.InDegree < bj.InDegree || (ai.InDegree == bj.InDegree && ai.OutDegree < bj.OutDegree) {
			i++
		} else {
			j++
		}
	}

	return float64(matches) / float64(maxLen)
}
