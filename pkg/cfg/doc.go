// Package cfg provides control flow graph construction and analysis for sedec decompiler.
//
// The package implements sophisticated CFG building with support for:
//   - Basic block identification and edge construction
//   - Indirect jump tracking and resolution
//   - Incremental CFG updates for cyclic feedback with type inference
//   - Dominator tree construction using Lengauer-Tarjan algorithm
//   - Dominance frontier computation for SSA phi-node placement
//   - Loop detection via back-edge analysis
//
// # Architecture
//
// The CFG builder follows a multi-phase approach:
//
//  1. Block Leader Identification: Identifies basic block boundaries at branch targets
//     and after branch instructions
//  2. Basic Block Creation: Groups instructions into basic blocks with single entry/exit
//  3. Edge Construction: Creates directed edges for jumps, branches, and fall-through paths
//  4. Indirect Jump Tracking: Marks unresolved indirect jumps for later resolution
//  5. Dominator Tree Construction: Computes dominator relationships using gonum/graph/flow
//  6. Dominance Frontier Computation: Calculates dominance frontiers for SSA construction
//
// # Dominator Tree Algorithm
//
// The package uses the Lengauer-Tarjan algorithm for dominator tree construction,
// implemented via gonum.org/v1/gonum/graph/flow.Dominators. This provides O(n log n)
// time complexity where n is the number of basic blocks.
//
// Key components:
//   - DFS numbering for spanning tree construction
//   - Semi-dominator computation with path compression
//   - Immediate dominator calculation
//   - Children mapping for tree traversal
//
// # Cyclic Feedback Integration
//
// The CFG builder supports incremental updates through cyclic feedback with type inference:
//
//   - Type_Inferencer discovers function pointer arrays (vtables, handler tables)
//   - CFG_Builder receives discovered targets and adds new edges
//   - Incremental re-analysis updates SSA, VSA, and type constraints
//   - Iteration continues until convergence or max iterations
//
// # Performance Characteristics
//
// Target performance metrics:
//   - Functions < 100 basic blocks: CFG construction < 200ms
//   - Functions < 500 basic blocks: CFG construction < 1s
//   - Dominator tree: O(n log n) complexity
//   - Dominance frontiers: O(n * e) where e is average edges per node
//   - Dominance queries: O(depth) where depth is dominator tree depth
//
// # Example Usage
//
//	// build cfg from disassembled instructions
//	builder := cfg.NewCFGBuilder()
//	cfg, err := builder.Build(instructions)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// compute dominator tree
//	dt, err := builder.ComputeDominators()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// check dominance relationship
//	if dt.Dominates(blockA, blockB) {
//	    fmt.Println("Block A dominates Block B")
//	}
//
//	// compute dominance frontiers for ssa
//	df := dt.ComputeDominanceFrontiers()
//	for block, frontier := range df {
//	    fmt.Printf("DF[%d] = %v\n", block, frontier)
//	}
//
//	// add indirect jump target (cyclic feedback)
//	builder.AddIndirectTarget(jumpSite, target)
//
// # Thread Safety
//
// The CFG builder is not thread-safe. Each function should be analyzed in a separate
// goroutine with its own CFG builder instance. The global state (XREF database, call graph)
// should be protected with sync.Map or sync.RWMutex for concurrent access.
//
// # References
//
//   - Lengauer, T., & Tarjan, R. E. (1979). A fast algorithm for finding dominators
//     in a flowgraph. ACM Transactions on Programming Languages and Systems, 1(1), 121-141.
//   - Cytron, R., Ferrante, J., Rosen, B. K., Wegman, M. N., & Zadeck, F. K. (1991).
//     Efficiently computing static single assignment form and the control dependence graph.
//     ACM Transactions on Programming Languages and Systems, 13(4), 451-490.
//   - Cooper, K. D., Harvey, T. J., & Kennedy, K. (2001). A simple, fast dominance algorithm.
//     Software Practice & Experience, 4(1-10), 1-8.
package cfg
