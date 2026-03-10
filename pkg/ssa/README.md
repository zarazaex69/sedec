# SSA Package

## Overview

The `ssa` package implements Static Single Assignment (SSA) form transformation for the sedec decompiler. SSA is a critical intermediate representation where each variable is assigned exactly once, enabling precise data flow analysis and optimization.

## Key Components

### Transformer

The `Transformer` struct is the main entry point for SSA transformation. It performs:

1. **Phi-node placement** using dominance frontiers (Cytron et al. algorithm)
2. **Variable renaming** to ensure single static assignment property (to be implemented in task 5.6)
3. **Def-use chain construction** for data flow analysis

### Algorithm

The phi-node placement algorithm follows the classic SSA construction approach:

```
For each variable V with multiple definitions:
  For each definition site D of V:
    For each block B in dominance frontier of D:
      Insert phi-node for V at B (if not already present)
      Treat phi-node as new definition (iterate until fixed point)
```

This iterative algorithm ensures that phi-nodes are placed at all merge points where multiple definitions of a variable converge.

## Usage Example

```go
import (
    "github.com/zarazaex69/sedec/pkg/ssa"
    "github.com/zarazaex69/sedec/pkg/ir"
    "github.com/zarazaex69/sedec/pkg/cfg"
)

// assume we have ir function, cfg, and dominator tree
function := &ir.Function{...}
cfgGraph := &cfg.CFG{...}
domTree := &cfg.DominatorTree{...}

// create transformer
transformer := ssa.NewTransformer(function, cfgGraph, domTree)

// perform ssa transformation
err := transformer.TransformToSSA()
if err != nil {
    log.Fatalf("SSA transformation failed: %v", err)
}

// query phi-node placement
phiCount := transformer.GetPhiNodeCount()
varsWithPhi := transformer.GetVariablesWithPhiNodes()
```

## Implementation Details

### Phi-node Placement

Phi-nodes are inserted at dominance frontiers of definition sites. The dominance frontier of a block X is the set of blocks Y where:
- X dominates a predecessor of Y
- X does not strictly dominate Y

This ensures phi-nodes are placed exactly at merge points where control flow from multiple paths converges.

### Iterative Fixed Point

The algorithm iterates until a fixed point is reached because:
1. Phi-nodes themselves are definitions
2. A phi-node at block B may trigger more phi-nodes at B's dominance frontier
3. Iteration continues until no new phi-nodes are added

### Correctness Properties

The implementation guarantees:
- **Completeness**: All variables with multiple definitions get phi-nodes at appropriate merge points
- **Minimality**: No redundant phi-nodes are placed (only at dominance frontiers)
- **Soundness**: SSA property is preserved (each variable has exactly one definition after renaming)

## Testing

The package includes comprehensive unit tests covering:
- Linear code (no phi-nodes needed)
- If-then-else patterns (phi-nodes at merge points)
- While loops (phi-nodes at loop headers)
- Nested loops (phi-nodes at multiple levels)
- Multiple variables (independent phi-node placement)
- Single definitions (no phi-nodes needed)

Run tests with:
```bash
go test -v ./pkg/ssa
go test -cover ./pkg/ssa  # check coverage (target: 80%+)
go test -race ./pkg/ssa   # check for data races
```

## Performance

The phi-node placement algorithm has complexity:
- **Time**: O(N × E) where N is number of variables and E is number of CFG edges
- **Space**: O(N × B) where B is number of basic blocks

For typical functions (< 500 basic blocks), transformation completes in < 500ms as specified in requirements.

## Future Work

Task 5.6 will implement variable renaming to complete the SSA transformation:
- DFS traversal in dominator tree order
- Version numbering for each variable definition
- Phi-node source resolution based on predecessor blocks

## References

- Cytron et al. "Efficiently Computing Static Single Assignment Form and the Control Dependence Graph" (1991)
- Appel, Andrew W. "Modern Compiler Implementation in ML" (1998)
- Cooper, Keith D. "Engineering a Compiler" (2011)
