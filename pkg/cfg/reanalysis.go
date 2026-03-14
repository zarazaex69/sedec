package cfg

import (
	"errors"
	"fmt"
	"sync"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

var (
	// errMaxIterationsReached indicates the feedback loop hit the iteration cap.
	errMaxIterationsReached = errors.New("incremental re-analysis: max iterations reached without convergence")
)

// ReAnalysisPass identifies which analysis passes must be re-run after a CFG update.
type ReAnalysisPass uint32

const (
	// PassDominatorTree re-computes the dominator tree and dominance frontiers.
	PassDominatorTree ReAnalysisPass = 1 << iota
	// PassSSA re-runs SSA transformation (phi-node placement + variable renaming).
	PassSSA
	// PassVSA re-runs Value Set Analysis.
	PassVSA
	// PassReachingDefs re-runs reaching definitions data flow.
	PassReachingDefs
	// PassTypeConstraints signals that type constraint generation must be re-run.
	PassTypeConstraints

	// PassAll is a convenience mask that requests all passes.
	PassAll ReAnalysisPass = PassDominatorTree | PassSSA | PassVSA | PassReachingDefs | PassTypeConstraints
)

func (p ReAnalysisPass) String() string {
	if p == 0 {
		return "None"
	}
	names := []string{}
	if p&PassDominatorTree != 0 {
		names = append(names, "DominatorTree")
	}
	if p&PassSSA != 0 {
		names = append(names, "SSA")
	}
	if p&PassVSA != 0 {
		names = append(names, "VSA")
	}
	if p&PassReachingDefs != 0 {
		names = append(names, "ReachingDefs")
	}
	if p&PassTypeConstraints != 0 {
		names = append(names, "TypeConstraints")
	}
	result := ""
	for i, n := range names {
		if i > 0 {
			result += "|"
		}
		result += n
	}
	return result
}

// ReAnalysisHooks contains callbacks invoked after each incremental update.
// callers register concrete analysis implementations here; nil hooks are skipped.
type ReAnalysisHooks struct {
	// OnDominatorTreeUpdated is called after the dominator tree is recomputed.
	// the new tree is passed so downstream passes can use it immediately.
	OnDominatorTreeUpdated func(tree *DominatorTree)

	// OnSSARequired is called when SSA must be re-run.
	// the implementation should re-transform the ir function using the updated cfg
	// and the freshly computed dominator tree.
	OnSSARequired func(cfgGraph *CFG, domTree *DominatorTree) error

	// OnVSARequired is called when VSA must be re-run.
	// the implementation should re-run value set analysis on the updated ir.
	OnVSARequired func(cfgGraph *CFG, domTree *DominatorTree) error

	// OnReachingDefsRequired is called when reaching definitions must be re-run.
	OnReachingDefsRequired func(cfgGraph *CFG, domTree *DominatorTree) error

	// OnTypeConstraintsRequired is called when type constraint generation must be re-run.
	// this is the signal that feeds back into the type inferencer.
	OnTypeConstraintsRequired func(cfgGraph *CFG) error
}

// ResolutionRecord captures provenance for a single resolved indirect jump.
type ResolutionRecord struct {
	// Provenance describes which analysis pass resolved this jump and with what confidence.
	Provenance *EdgeProvenance
	// Targets are the resolved destination addresses.
	Targets []disasm.Address
	// JumpSite is the address of the indirect jump instruction.
	JumpSite disasm.Address
	// Iteration is the feedback-loop iteration number when this was resolved.
	Iteration int
}

// IncrementalReAnalysisResult summarises the outcome of one or more re-analysis cycles.
type IncrementalReAnalysisResult struct {
	// ResolutionHistory records every indirect jump resolution in order.
	ResolutionHistory []*ResolutionRecord
	// PassesExecuted is the union of all passes that were triggered.
	PassesExecuted ReAnalysisPass
	// Iterations is the number of feedback-loop iterations performed.
	Iterations int
	// Converged is true when no new targets were discovered in the last iteration.
	Converged bool
	// NewEdgesAdded is the total number of new CFG edges added across all iterations.
	NewEdgesAdded int
}

// IncrementalReAnalyzer coordinates incremental re-analysis of a CFG after
// new indirect jump targets are discovered by the type inferencer or VSA.
//
// the workflow is:
//  1. type inferencer discovers a function pointer array (vtable, handler table)
//  2. caller invokes AddResolvedTargets with the jump site and target addresses
//  3. IncrementalReAnalyzer applies the CFG update via the Builder
//  4. it recomputes the dominator tree (always required after structural change)
//  5. it invokes registered hooks for SSA, VSA, reaching defs, type constraints
//  6. convergence is checked: if no new targets were added, the loop terminates
//
// the analyzer is safe for use from a single goroutine. for concurrent use,
// the caller must provide external synchronisation.
type IncrementalReAnalyzer struct {
	mu            sync.Mutex
	builder       *Builder
	hooks         *ReAnalysisHooks
	history       []*ResolutionRecord
	maxIterations int
	iteration     int
	totalNewEdges int
}

// NewIncrementalReAnalyzer creates a new incremental re-analyzer.
//
// builder must be the same Builder instance that constructed the CFG being analysed.
// hooks contains the analysis callbacks; nil hooks are silently skipped.
// maxIterations caps the feedback loop (0 means use the default of 10).
func NewIncrementalReAnalyzer(builder *Builder, hooks *ReAnalysisHooks, maxIterations int) *IncrementalReAnalyzer {
	if maxIterations <= 0 {
		maxIterations = 10
	}
	if hooks == nil {
		hooks = &ReAnalysisHooks{}
	}
	return &IncrementalReAnalyzer{
		builder:       builder,
		hooks:         hooks,
		history:       make([]*ResolutionRecord, 0),
		maxIterations: maxIterations,
	}
}

// AddResolvedTargets applies a single indirect jump resolution and triggers
// incremental re-analysis of all registered passes.
//
// jumpSite is the virtual address of the indirect jump instruction.
// targets are the resolved destination addresses.
// provenance describes which analysis pass produced this resolution.
//
// returns an error if the CFG update fails or if a registered hook returns an error.
// the error does NOT include errMaxIterationsReached; that is only returned by
// RunConvergenceLoop.
func (r *IncrementalReAnalyzer) AddResolvedTargets(
	jumpSite disasm.Address,
	targets []disasm.Address,
	provenance *EdgeProvenance,
) (*IncrementalReAnalysisResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if provenance == nil {
		provenance = &EdgeProvenance{
			AnalysisPass: "unknown",
			Confidence:   0.5,
			Metadata:     make(map[string]any),
		}
	}

	// apply all target edges to the cfg
	newEdges := 0
	for _, target := range targets {
		edgeBefore := r.builder.cfg.EdgeCount()
		if err := r.builder.AddIndirectTargetWithProvenance(jumpSite, target, provenance); err != nil {
			return nil, fmt.Errorf("add resolved target 0x%x → 0x%x: %w", jumpSite, target, err)
		}
		if r.builder.cfg.EdgeCount() > edgeBefore {
			newEdges++
		}
	}

	r.totalNewEdges += newEdges

	// record provenance
	record := &ResolutionRecord{
		JumpSite:   jumpSite,
		Targets:    targets,
		Provenance: provenance,
		Iteration:  r.iteration,
	}
	r.history = append(r.history, record)

	// mark the jump as resolved in the unresolved list
	r.builder.MarkIndirectJumpResolved(jumpSite)

	// determine which passes need to run
	passes := r.requiredPasses(newEdges)

	// execute passes in dependency order
	if err := r.executePasses(passes); err != nil {
		return nil, err
	}

	return &IncrementalReAnalysisResult{
		ResolutionHistory: r.history,
		PassesExecuted:    passes,
		Iterations:        r.iteration,
		Converged:         false,
		NewEdgesAdded:     r.totalNewEdges,
	}, nil
}

// RunConvergenceLoop runs the incremental re-analysis loop until convergence
// or the iteration limit is reached.
//
// resolveFunc is called each iteration with the current set of unresolved
// indirect jumps. it should return a map from jump site address to the
// resolved target addresses (and provenance). returning an empty map signals
// that no new targets were found and the loop should terminate.
//
// this is the top-level entry point for the cyclic feedback loop between
// the type inferencer and the CFG builder.
func (r *IncrementalReAnalyzer) RunConvergenceLoop(
	resolveFunc func(unresolved []*UnresolvedIndirectJump) (map[disasm.Address]*ResolvedTargetSet, error),
) (*IncrementalReAnalysisResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	totalPasses := ReAnalysisPass(0)

	for r.iteration = 0; r.iteration < r.maxIterations; r.iteration++ {
		unresolved := r.builder.cfg.UnresolvedIndirectJumps
		if len(unresolved) == 0 {
			// no unresolved jumps: converged immediately
			return &IncrementalReAnalysisResult{
				ResolutionHistory: r.history,
				PassesExecuted:    totalPasses,
				Iterations:        r.iteration,
				Converged:         true,
				NewEdgesAdded:     r.totalNewEdges,
			}, nil
		}

		// ask the caller to resolve what it can
		resolved, err := resolveFunc(unresolved)
		if err != nil {
			return nil, fmt.Errorf("iteration %d: resolve func: %w", r.iteration, err)
		}

		if len(resolved) == 0 {
			// no new targets discovered: converged
			return &IncrementalReAnalysisResult{
				ResolutionHistory: r.history,
				PassesExecuted:    totalPasses,
				Iterations:        r.iteration + 1,
				Converged:         true,
				NewEdgesAdded:     r.totalNewEdges,
			}, nil
		}

		// apply all resolutions for this iteration
		iterNewEdges := 0
		for jumpSite, rts := range resolved {
			for _, target := range rts.Targets {
				edgeBefore := r.builder.cfg.EdgeCount()
				if err := r.builder.AddIndirectTargetWithProvenance(jumpSite, target, rts.Provenance); err != nil {
					return nil, fmt.Errorf("iteration %d: add target 0x%x → 0x%x: %w",
						r.iteration, jumpSite, target, err)
				}
				if r.builder.cfg.EdgeCount() > edgeBefore {
					iterNewEdges++
				}
			}

			r.builder.MarkIndirectJumpResolved(jumpSite)

			record := &ResolutionRecord{
				JumpSite:   jumpSite,
				Targets:    rts.Targets,
				Provenance: rts.Provenance,
				Iteration:  r.iteration,
			}
			r.history = append(r.history, record)
		}

		r.totalNewEdges += iterNewEdges

		// run required passes
		passes := r.requiredPasses(iterNewEdges)
		totalPasses |= passes

		if err := r.executePasses(passes); err != nil {
			return nil, fmt.Errorf("iteration %d: execute passes: %w", r.iteration, err)
		}
	}

	// hit the iteration cap without convergence
	return &IncrementalReAnalysisResult{
		ResolutionHistory: r.history,
		PassesExecuted:    totalPasses,
		Iterations:        r.maxIterations,
		Converged:         false,
		NewEdgesAdded:     r.totalNewEdges,
	}, errMaxIterationsReached
}

// GetResolutionHistory returns a copy of the resolution history.
func (r *IncrementalReAnalyzer) GetResolutionHistory() []*ResolutionRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]*ResolutionRecord, len(r.history))
	copy(result, r.history)
	return result
}

// GetProvenanceForJump returns the resolution record for a specific jump site,
// or nil if the jump has not been resolved.
func (r *IncrementalReAnalyzer) GetProvenanceForJump(jumpSite disasm.Address) *ResolutionRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	// iterate in reverse to return the most recent resolution
	for i := len(r.history) - 1; i >= 0; i-- {
		if r.history[i].JumpSite == jumpSite {
			return r.history[i]
		}
	}
	return nil
}

// GetStats returns current statistics about the re-analysis state.
func (r *IncrementalReAnalyzer) GetStats() *IncrementalReAnalysisResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	return &IncrementalReAnalysisResult{
		ResolutionHistory: r.history,
		Iterations:        r.iteration,
		NewEdgesAdded:     r.totalNewEdges,
		Converged:         len(r.builder.cfg.UnresolvedIndirectJumps) == 0,
	}
}

// requiredPasses determines which analysis passes must be re-run.
// if new edges were added to the cfg, the dominator tree is structurally
// changed and all downstream passes must be invalidated.
// if no new edges were added (targets were already known), only type
// constraints need refreshing.
func (r *IncrementalReAnalyzer) requiredPasses(newEdges int) ReAnalysisPass {
	if newEdges == 0 {
		// no structural change: only type constraints may need updating
		return PassTypeConstraints
	}
	// structural change: full re-analysis pipeline required
	return PassAll
}

// executePasses runs the registered hooks for the given pass set in
// dependency order: dominator tree → SSA → VSA → reaching defs → type constraints.
func (r *IncrementalReAnalyzer) executePasses(passes ReAnalysisPass) error {
	var newDomTree *DominatorTree

	// step 1: recompute dominator tree (prerequisite for all other passes)
	if passes&PassDominatorTree != 0 {
		newDomTree = NewDominatorTree(r.builder.cfg)
		// cache the updated tree in the builder for subsequent queries
		r.builder.dominatorTree = newDomTree

		if r.hooks.OnDominatorTreeUpdated != nil {
			r.hooks.OnDominatorTreeUpdated(newDomTree)
		}
	} else {
		// use the cached tree if no structural change occurred
		newDomTree = r.builder.dominatorTree
	}

	// step 2: re-run ssa transformation
	if passes&PassSSA != 0 && r.hooks.OnSSARequired != nil {
		if err := r.hooks.OnSSARequired(r.builder.cfg, newDomTree); err != nil {
			return fmt.Errorf("ssa re-analysis: %w", err)
		}
	}

	// step 3: re-run vsa
	if passes&PassVSA != 0 && r.hooks.OnVSARequired != nil {
		if err := r.hooks.OnVSARequired(r.builder.cfg, newDomTree); err != nil {
			return fmt.Errorf("vsa re-analysis: %w", err)
		}
	}

	// step 4: re-run reaching definitions
	if passes&PassReachingDefs != 0 && r.hooks.OnReachingDefsRequired != nil {
		if err := r.hooks.OnReachingDefsRequired(r.builder.cfg, newDomTree); err != nil {
			return fmt.Errorf("reaching defs re-analysis: %w", err)
		}
	}

	// step 5: signal type constraint regeneration
	if passes&PassTypeConstraints != 0 && r.hooks.OnTypeConstraintsRequired != nil {
		if err := r.hooks.OnTypeConstraintsRequired(r.builder.cfg); err != nil {
			return fmt.Errorf("type constraint re-analysis: %w", err)
		}
	}

	return nil
}

// ResolvedTargetSet groups resolved targets with their provenance for a single jump site.
type ResolvedTargetSet struct {
	Provenance *EdgeProvenance
	Targets    []disasm.Address
}

// NewResolvedTargetSet creates a ResolvedTargetSet with the given provenance and targets.
func NewResolvedTargetSet(pass string, confidence float64, targets []disasm.Address) *ResolvedTargetSet {
	return &ResolvedTargetSet{
		Provenance: &EdgeProvenance{
			AnalysisPass: pass,
			Confidence:   confidence,
			Metadata:     make(map[string]any),
		},
		Targets: targets,
	}
}

// ConsistencyCheck verifies that the CFG is internally consistent after
// incremental updates. it checks:
//   - every edge references existing blocks
//   - every block's predecessor/successor lists are symmetric
//   - the entry block exists
//
// returns a list of consistency violations (empty slice means consistent).
func (b *Builder) ConsistencyCheck() []string {
	violations := make([]string, 0)

	// check entry block exists
	if _, exists := b.cfg.Blocks[b.cfg.Entry]; !exists {
		violations = append(violations, fmt.Sprintf("entry block %d does not exist", b.cfg.Entry))
	}

	// check all edges reference existing blocks
	for i, edge := range b.cfg.Edges {
		if _, exists := b.cfg.Blocks[edge.From]; !exists {
			violations = append(violations, fmt.Sprintf("edge[%d]: from block %d does not exist", i, edge.From))
		}
		if _, exists := b.cfg.Blocks[edge.To]; !exists {
			violations = append(violations, fmt.Sprintf("edge[%d]: to block %d does not exist", i, edge.To))
		}
	}

	// check predecessor/successor symmetry
	for blockID, block := range b.cfg.Blocks {
		for _, succID := range block.Successors {
			succBlock, exists := b.cfg.Blocks[succID]
			if !exists {
				violations = append(violations, fmt.Sprintf(
					"block %d successor %d does not exist", blockID, succID))
				continue
			}
			// verify that succBlock has blockID as a predecessor
			found := false
			for _, predID := range succBlock.Predecessors {
				if predID == blockID {
					found = true
					break
				}
			}
			if !found {
				violations = append(violations, fmt.Sprintf(
					"block %d is successor of %d but %d is not in its predecessor list",
					succID, blockID, blockID))
			}
		}
	}

	return violations
}
