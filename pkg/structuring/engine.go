// package structuring implements the Phoenix/DREAM pattern-independent
// control flow structuring algorithm. it recovers high-level constructs
// (if-then-else, while, do-while) from a CFG via bottom-up region collapsing.
package structuring

import (
	"errors"
	"fmt"
	"sort"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

var (
	// errNilCFG indicates a nil cfg was provided
	errNilCFG = errors.New("cfg is nil")
	// errNilDominatorTree indicates a nil dominator tree was provided
	errNilDominatorTree = errors.New("dominator tree is nil")
	// errNilLoopInfo indicates nil loop info was provided
	errNilLoopInfo = errors.New("loop info is nil")
	// errNilIRBlocks indicates nil ir blocks map was provided
	errNilIRBlocks = errors.New("ir blocks map is nil")
)

// IRBlockMap maps each cfg block id to its lifted IR instructions
type IRBlockMap map[cfg.BlockID][]ir.IRInstruction

// Engine implements the Phoenix/DREAM structuring algorithm.
// it operates on a CFG with pre-computed dominator tree and loop info,
// and produces a StructuredAST via bottom-up region collapsing.
type Engine struct {
	cfgraph  *cfg.CFG
	dt       *cfg.DominatorTree
	loopInfo *cfg.LoopInfo
	irBlocks IRBlockMap

	// gotoCounter is used to generate unique goto label names
	gotoCounter int
	// gotoLabels maps block ids that are goto targets to their label names
	gotoLabels map[cfg.BlockID]string
	// inProgress tracks blocks currently being collapsed to detect re-entrancy
	inProgress map[cfg.BlockID]bool
}

// New creates a new structuring engine.
// cfgraph, dt, loopInfo, and irBlocks must all be non-nil.
func New(
	cfgraph *cfg.CFG,
	dt *cfg.DominatorTree,
	loopInfo *cfg.LoopInfo,
	irBlocks IRBlockMap,
) (*Engine, error) {
	if cfgraph == nil {
		return nil, errNilCFG
	}
	if dt == nil {
		return nil, errNilDominatorTree
	}
	if loopInfo == nil {
		return nil, errNilLoopInfo
	}
	if irBlocks == nil {
		return nil, errNilIRBlocks
	}

	return &Engine{
		cfgraph:    cfgraph,
		dt:         dt,
		loopInfo:   loopInfo,
		irBlocks:   irBlocks,
		gotoLabels: make(map[cfg.BlockID]string),
		inProgress: make(map[cfg.BlockID]bool),
	}, nil
}

// Structure applies the Phoenix/DREAM algorithm to the CFG and returns
// a StructuredAST. the algorithm proceeds in three phases:
//
//  1. identify single-entry single-exit regions bottom-up (post-order DFS)
//  2. collapse each region into a single structured node
//  3. recurse until the entire CFG is a single region
func (e *Engine) Structure() (*StructuredAST, error) {
	stmt, err := e.structureCFG(e.cfgraph.Entry)
	if err != nil {
		return nil, fmt.Errorf("structuring failed: %w", err)
	}

	return &StructuredAST{
		Body:       stmt,
		FunctionID: e.cfgraph.Entry,
	}, nil
}

// structureCFG is the main recursive entry point. it processes the subgraph
// rooted at entryBlock and returns the corresponding structured statement.
func (e *Engine) structureCFG(entryBlock cfg.BlockID) (Statement, error) {
	// collect all blocks reachable from entry in post-order (leaves first)
	postOrder := e.postOrderBlocks(entryBlock)

	// process blocks bottom-up: try to collapse regions at each block
	// we iterate until no more collapses are possible (fixed point)
	stmts, err := e.collapseRegions(postOrder)
	if err != nil {
		return nil, err
	}

	if len(stmts) == 1 {
		return stmts[0], nil
	}

	// multiple top-level statements: wrap in a block
	return Block{Stmts: stmts}, nil
}

// postOrderBlocks returns all blocks reachable from start in post-order
// (children before parents). this ensures bottom-up processing.
func (e *Engine) postOrderBlocks(start cfg.BlockID) []cfg.BlockID {
	visited := make(map[cfg.BlockID]bool)
	result := make([]cfg.BlockID, 0, len(e.cfgraph.Blocks))

	var dfs func(cfg.BlockID)
	dfs = func(id cfg.BlockID) {
		if visited[id] {
			return
		}
		visited[id] = true

		block, exists := e.cfgraph.Blocks[id]
		if !exists {
			return
		}

		// visit successors in sorted order for determinism
		succs := make([]cfg.BlockID, len(block.Successors))
		copy(succs, block.Successors)
		sort.Slice(succs, func(i, j int) bool { return succs[i] < succs[j] })

		for _, succ := range succs {
			// skip back-edges to avoid infinite recursion in loops
			if e.isBackEdge(id, succ) {
				continue
			}
			dfs(succ)
		}

		result = append(result, id)
	}

	dfs(start)
	return result
}

// isBackEdge returns true if the edge from->to is a back-edge in the dominator tree.
// a back-edge is one where the target dominates the source.
func (e *Engine) isBackEdge(from, to cfg.BlockID) bool {
	return e.dt.Dominates(to, from)
}

// collapseRegions processes blocks in post-order and collapses identified
// regions into structured statements. returns the list of top-level statements.
func (e *Engine) collapseRegions(postOrder []cfg.BlockID) ([]Statement, error) {
	// collapsed maps each block id to its structured statement once collapsed
	collapsed := make(map[cfg.BlockID]Statement)
	// inlined tracks blocks that have been inlined into a parent statement
	// and must not be emitted as top-level statements by the pre-order pass.
	inlined := make(map[cfg.BlockID]bool)

	// process each block in post-order (bottom-up)
	for _, blockID := range postOrder {
		stmt, err := e.collapseBlockWithInlined(blockID, collapsed, inlined)
		if err != nil {
			return nil, err
		}
		collapsed[blockID] = stmt
	}

	// collect top-level statements in dominator tree pre-order (top-down)
	// to preserve execution order
	preOrder := e.preOrderBlocks(e.cfgraph.Entry)
	seen := make(map[cfg.BlockID]bool)
	result := make([]Statement, 0)

	for _, blockID := range preOrder {
		if seen[blockID] || inlined[blockID] {
			continue
		}
		seen[blockID] = true

		if stmt, ok := collapsed[blockID]; ok && stmt != nil {
			result = append(result, stmt)
		}
	}

	return result, nil
}

// preOrderBlocks returns blocks in dominator tree pre-order (parents before children)
func (e *Engine) preOrderBlocks(start cfg.BlockID) []cfg.BlockID {
	result := make([]cfg.BlockID, 0, len(e.cfgraph.Blocks))
	visited := make(map[cfg.BlockID]bool)

	var dfs func(cfg.BlockID)
	dfs = func(id cfg.BlockID) {
		if visited[id] {
			return
		}
		visited[id] = true
		result = append(result, id)

		// visit dominator tree children in sorted order for determinism
		children := e.dt.GetChildren(id)
		sorted := make([]cfg.BlockID, len(children))
		copy(sorted, children)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

		for _, child := range sorted {
			dfs(child)
		}
	}

	dfs(start)
	return result
}

// collapseBlock determines the structural pattern at blockID and returns
// the corresponding Statement. it uses already-collapsed child statements.
func (e *Engine) collapseBlock(blockID cfg.BlockID, collapsed map[cfg.BlockID]Statement) (Statement, error) {
	return e.collapseBlockWithInlined(blockID, collapsed, nil)
}

// collapseBlockWithInlined is the internal implementation of collapseBlock.
// inlined tracks blocks that have been inlined into a parent statement;
// it may be nil (treated as empty set).
func (e *Engine) collapseBlockWithInlined(blockID cfg.BlockID, collapsed map[cfg.BlockID]Statement, inlined map[cfg.BlockID]bool) (Statement, error) {
	block, exists := e.cfgraph.Blocks[blockID]
	if !exists {
		return nil, fmt.Errorf("block %d not found in cfg", blockID)
	}

	// re-entrancy guard: if we are already collapsing this block (cycle in the
	// non-back-edge subgraph that the dominator check missed), emit a goto.
	if e.inProgress[blockID] {
		label := e.getOrCreateLabel(blockID)
		return GotoStatement{Target: blockID, Label: label}, nil
	}
	e.inProgress[blockID] = true
	defer func() { delete(e.inProgress, blockID) }()

	// check if this block is a loop header
	if e.loopInfo.IsLoopHeader(blockID) {
		return e.collapseLoop(blockID, block, collapsed)
	}

	// check successor count to determine region type
	succs := e.nonBackEdgeSuccessors(blockID)

	switch len(succs) {
	case 0:
		// exit block: emit raw IR block (return statement)
		return e.buildIRBlock(blockID), nil

	case 1:
		// linear region: this block followed by its single successor
		return e.collapseLinear(blockID, succs[0], collapsed)

	case 2:
		// conditional branch: if-then or if-then-else
		return e.collapseConditional(blockID, block, succs, collapsed, inlined)

	default:
		// more than 2 successors: indirect jump or switch (emit as goto targets)
		return e.collapseMultiWay(blockID, succs, collapsed)
	}
}

// nonBackEdgeSuccessors returns successors of blockID excluding back-edges
func (e *Engine) nonBackEdgeSuccessors(blockID cfg.BlockID) []cfg.BlockID {
	block, exists := e.cfgraph.Blocks[blockID]
	if !exists {
		return nil
	}

	result := make([]cfg.BlockID, 0, len(block.Successors))
	for _, succ := range block.Successors {
		if !e.isBackEdge(blockID, succ) {
			result = append(result, succ)
		}
	}

	// sort for determinism
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

// collapseLinear handles a block with a single non-back-edge successor.
// it emits the current block's IR and then the successor's statement.
func (e *Engine) collapseLinear(blockID, succID cfg.BlockID, collapsed map[cfg.BlockID]Statement) (Statement, error) {
	current := e.buildIRBlock(blockID)

	// if successor is already collapsed (dominated by another block), just emit current
	if _, alreadyCollapsed := collapsed[succID]; alreadyCollapsed {
		// successor will be emitted separately in pre-order traversal
		return current, nil
	}

	// guard against re-entrant collapse of the same successor:
	// if succID is not strictly dominated by blockID, it will be handled
	// by the top-level post-order pass — emit a goto instead of inlining.
	if !e.dt.StrictlyDominates(blockID, succID) {
		label := e.getOrCreateLabel(succID)
		return e.mergeSequential(current, GotoStatement{Target: succID, Label: label}), nil
	}

	// successor is dominated by this block: inline it
	succStmt, err := e.collapseBlock(succID, collapsed)
	if err != nil {
		return nil, err
	}
	collapsed[succID] = succStmt

	return e.mergeSequential(current, succStmt), nil
}

// collapseConditional handles a block with exactly two non-back-edge successors.
// it identifies if-then or if-then-else patterns.
func (e *Engine) collapseConditional(
	blockID cfg.BlockID,
	block *cfg.BasicBlock,
	succs []cfg.BlockID,
	collapsed map[cfg.BlockID]Statement,
	inlined map[cfg.BlockID]bool,
) (Statement, error) {
	// extract branch condition from the last IR instruction of this block
	cond := e.extractBranchCondition(blockID)

	// find the branch instruction to determine true/false targets
	trueTarget, falseTarget := e.extractBranchTargets(blockID, succs)

	// find the immediate post-dominator (convergence point)
	// this is the block where both branches merge
	convergence := e.findConvergencePoint(trueTarget, falseTarget)

	// pre-mark branch targets and convergence as inlined so that
	// the pre-order traversal in collapseRegions does not emit them as top-level
	// statements after they have been inlined into the if-statement body.
	if inlined != nil {
		// mark all blocks in the then-branch subtree
		for _, bid := range e.collectBranchBlocks(trueTarget, convergence) {
			inlined[bid] = true
		}
		// mark all blocks in the else-branch subtree
		if falseTarget != convergence {
			for _, bid := range e.collectBranchBlocks(falseTarget, convergence) {
				inlined[bid] = true
			}
		}
		// mark convergence block as inlined (will be emitted after the if-statement)
		if convergence != e.cfgraph.Entry && convergence != blockID {
			inlined[convergence] = true
		}
	}

	// build then-branch: blocks dominated by trueTarget up to convergence
	thenStmt, err := e.buildBranch(trueTarget, convergence, collapsed)
	if err != nil {
		return nil, fmt.Errorf("building then-branch from bb%d: %w", trueTarget, err)
	}

	// build else-branch: blocks dominated by falseTarget up to convergence
	var elseStmt Statement
	if falseTarget != convergence {
		elseStmt, err = e.buildBranch(falseTarget, convergence, collapsed)
		if err != nil {
			return nil, fmt.Errorf("building else-branch from bb%d: %w", falseTarget, err)
		}
	}

	// build the header block IR (without the branch terminator)
	headerIR := e.buildIRBlockWithoutTerminator(blockID)

	ifStmt := IfStatement{
		Condition: cond,
		Then:      thenStmt,
		Else:      elseStmt,
	}

	// update collapsed with the actual built statements
	if thenStmt != nil {
		collapsed[trueTarget] = thenStmt
	}
	if elseStmt != nil {
		collapsed[falseTarget] = elseStmt
	}

	result := e.mergeSequential(headerIR, ifStmt)

	// emit convergence block as a sequential statement after the if-statement.
	// this ensures the convergence block is emitted exactly once, after the
	// closing brace of the if/else, rather than being duplicated by both branches.
	if convergence != e.cfgraph.Entry && convergence != blockID {
		convStmt, convErr := e.collapseBlock(convergence, collapsed)
		if convErr != nil {
			return nil, convErr
		}
		collapsed[convergence] = convStmt
		result = e.mergeSequential(result, convStmt)
	}

	return result, nil
}

// collapseLoop handles a loop header block. it uses loopClassifier to determine
// the loop kind (while/do-while/for/infinite) and builds the corresponding
// loop statement. for-loops are identified via induction variable analysis.
func (e *Engine) collapseLoop(
	headerID cfg.BlockID,
	_ *cfg.BasicBlock,
	collapsed map[cfg.BlockID]Statement,
) (Statement, error) {
	loop := e.loopInfo.GetLoopByHeader(headerID)
	if loop == nil {
		// no loop info: treat as regular block
		return e.buildIRBlock(headerID), nil
	}

	// classify loop kind and extract exit condition
	lc := newLoopClassifier(e.cfgraph, e.dt, e.loopInfo, e.irBlocks)
	kind, exitCond, _ := lc.classifyLoop(loop)

	// build loop body: all blocks in loop body except header
	bodyStmt, err := e.buildLoopBody(loop, headerID, collapsed)
	if err != nil {
		return nil, fmt.Errorf("building loop body for header bb%d: %w", headerID, err)
	}

	// mark all loop body blocks as collapsed
	for _, bodyBlock := range loop.Body {
		if bodyBlock != headerID {
			if _, ok := collapsed[bodyBlock]; !ok {
				collapsed[bodyBlock] = e.buildIRBlock(bodyBlock)
			}
		}
	}

	switch kind {
	case LoopKindFor:
		// recover for-loop: find induction variable and build ForStatement
		iv := lc.findInductionVariable(loop)
		if iv != nil {
			return buildForStatement(iv, exitCond, bodyStmt), nil
		}
		// iv detection failed at this point: fall back to while
		return WhileStatement{Condition: exitCond, Body: bodyStmt}, nil

	case LoopKindDoWhile:
		// do-while: body executes first, condition checked at tail
		return DoWhileStatement{Body: bodyStmt, Condition: exitCond}, nil

	case LoopKindInfinite:
		// infinite loop: while(true)
		return WhileStatement{
			Condition: ir.ConstantExpr{Value: ir.BoolConstant{Value: true}},
			Body:      bodyStmt,
		}, nil

	default:
		// LoopKindWhile: condition at header
		return WhileStatement{Condition: exitCond, Body: bodyStmt}, nil
	}
}

// collapseMultiWay handles blocks with more than 2 successors (switch/indirect jump).
// it emits the block IR and generates goto statements for each target.
func (e *Engine) collapseMultiWay(
	blockID cfg.BlockID,
	succs []cfg.BlockID,
	collapsed map[cfg.BlockID]Statement,
) (Statement, error) {
	stmts := []Statement{e.buildIRBlock(blockID)}

	for _, succ := range succs {
		label := e.getOrCreateLabel(succ)
		stmts = append(stmts, GotoStatement{Target: succ, Label: label})

		// ensure successor has a label statement prepended
		if _, ok := collapsed[succ]; !ok {
			succStmt, err := e.collapseBlock(succ, collapsed)
			if err != nil {
				return nil, err
			}
			collapsed[succ] = Block{Stmts: []Statement{
				LabelStatement{Name: label},
				succStmt,
			}}
		}
	}

	return Block{Stmts: stmts}, nil
}

// buildBranch builds the structured statement for a branch from startID
// up to (but not including) convergenceID.
func (e *Engine) buildBranch(
	startID cfg.BlockID,
	convergenceID cfg.BlockID,
	collapsed map[cfg.BlockID]Statement,
) (Statement, error) {
	if startID == convergenceID {
		// empty branch
		return Block{Stmts: nil}, nil
	}

	// collect all blocks in this branch (dominated by startID, before convergence)
	branchBlocks := e.collectBranchBlocks(startID, convergenceID)

	if len(branchBlocks) == 0 {
		return Block{Stmts: nil}, nil
	}

	// recursively structure the branch subgraph
	stmts := make([]Statement, 0, len(branchBlocks))
	for _, bid := range branchBlocks {
		if stmt, ok := collapsed[bid]; ok {
			stmts = append(stmts, stmt)
			continue
		}

		// only inline blocks that are strictly dominated by startID;
		// others will be emitted by the top-level pass via goto.
		if bid != startID && !e.dt.StrictlyDominates(startID, bid) {
			label := e.getOrCreateLabel(bid)
			stmts = append(stmts, GotoStatement{Target: bid, Label: label})
			continue
		}

		stmt, err := e.collapseBlock(bid, collapsed)
		if err != nil {
			return nil, err
		}
		collapsed[bid] = stmt
		stmts = append(stmts, stmt)
	}

	if len(stmts) == 1 {
		return stmts[0], nil
	}
	return Block{Stmts: stmts}, nil
}

// collectBranchBlocks returns all blocks dominated by startID that are
// reachable before reaching convergenceID, in dominator tree pre-order.
func (e *Engine) collectBranchBlocks(startID, convergenceID cfg.BlockID) []cfg.BlockID {
	result := make([]cfg.BlockID, 0)
	visited := make(map[cfg.BlockID]bool)

	var collect func(cfg.BlockID)
	collect = func(id cfg.BlockID) {
		if visited[id] || id == convergenceID {
			return
		}
		visited[id] = true

		// only include blocks dominated by startID
		if id != startID && !e.dt.StrictlyDominates(startID, id) {
			return
		}

		result = append(result, id)

		block, exists := e.cfgraph.Blocks[id]
		if !exists {
			return
		}

		succs := make([]cfg.BlockID, len(block.Successors))
		copy(succs, block.Successors)
		sort.Slice(succs, func(i, j int) bool { return succs[i] < succs[j] })

		for _, succ := range succs {
			if !e.isBackEdge(id, succ) {
				collect(succ)
			}
		}
	}

	collect(startID)
	return result
}

// buildLoopBody builds the structured statement for the loop body.
// it processes all blocks in the loop except the header.
func (e *Engine) buildLoopBody(
	loop *cfg.Loop,
	headerID cfg.BlockID,
	collapsed map[cfg.BlockID]Statement,
) (Statement, error) {
	// collect body blocks (excluding header) in post-order
	bodyBlocks := make([]cfg.BlockID, 0, len(loop.Body))
	for _, bid := range loop.Body {
		if bid != headerID {
			bodyBlocks = append(bodyBlocks, bid)
		}
	}

	if len(bodyBlocks) == 0 {
		// self-loop: body is just the header IR
		return e.buildIRBlock(headerID), nil
	}

	// sort for determinism
	sort.Slice(bodyBlocks, func(i, j int) bool { return bodyBlocks[i] < bodyBlocks[j] })

	stmts := make([]Statement, 0, len(bodyBlocks))
	for _, bid := range bodyBlocks {
		if stmt, ok := collapsed[bid]; ok {
			stmts = append(stmts, stmt)
			continue
		}

		stmt, err := e.collapseBlock(bid, collapsed)
		if err != nil {
			return nil, err
		}
		collapsed[bid] = stmt
		stmts = append(stmts, stmt)
	}

	if len(stmts) == 1 {
		return stmts[0], nil
	}
	return Block{Stmts: stmts}, nil
}

// findConvergencePoint finds the immediate post-dominator of two blocks.
// this is the first block that both paths must pass through.
// we approximate this by walking up the dominator tree from both sides.
func (e *Engine) findConvergencePoint(a, b cfg.BlockID) cfg.BlockID {
	// collect dominator path from a to entry
	pathA := make(map[cfg.BlockID]bool)
	current := a
	for {
		pathA[current] = true
		idom, exists := e.dt.Idom[current]
		if !exists || idom == current {
			break
		}
		current = idom
	}

	// walk up from b until we hit a block in pathA
	current = b
	for {
		if pathA[current] {
			return current
		}
		idom, exists := e.dt.Idom[current]
		if !exists || idom == current {
			break
		}
		current = idom
	}

	// fallback: return entry block
	return e.cfgraph.Entry
}

// extractBranchCondition extracts the condition expression from the last
// IR instruction of blockID. returns a placeholder if not found.
func (e *Engine) extractBranchCondition(blockID cfg.BlockID) ir.Expression {
	instrs, ok := e.irBlocks[blockID]
	if !ok || len(instrs) == 0 {
		return ir.ConstantExpr{Value: ir.BoolConstant{Value: true}}
	}

	// the last instruction should be a Branch
	last := instrs[len(instrs)-1]
	if branch, ok := ir.AsBranch(last); ok {
		return branch.Condition
	}

	return ir.ConstantExpr{Value: ir.BoolConstant{Value: true}}
}

// extractBranchTargets returns the true and false targets of a conditional branch.
// it uses the IR Branch instruction if available, otherwise falls back to
// the CFG edge ordering.
func (e *Engine) extractBranchTargets(blockID cfg.BlockID, succs []cfg.BlockID) (trueTarget, falseTarget cfg.BlockID) {
	instrs, ok := e.irBlocks[blockID]
	if ok && len(instrs) > 0 {
		last := instrs[len(instrs)-1]
		if branch, ok := ir.AsBranch(last); ok {
			// ir.BlockID and cfg.BlockID are both uint64 - safe cast
			//nolint:gosec // G115: controlled conversion between equivalent uint64 types
			return cfg.BlockID(branch.TrueTarget), cfg.BlockID(branch.FalseTarget)
		}
	}

	// fallback: use sorted successor order
	if len(succs) >= 2 {
		return succs[0], succs[1]
	}
	if len(succs) == 1 {
		return succs[0], succs[0]
	}
	return blockID, blockID
}

// buildIRBlock creates an IRBlock statement for the given block id
func (e *Engine) buildIRBlock(blockID cfg.BlockID) Statement {
	instrs := e.irBlocks[blockID]
	return IRBlock{
		BlockID:      blockID,
		Instructions: instrs,
	}
}

// buildIRBlockWithoutTerminator creates an IRBlock omitting the last
// branch/jump instruction (which is represented structurally)
func (e *Engine) buildIRBlockWithoutTerminator(blockID cfg.BlockID) Statement {
	instrs := e.irBlocks[blockID]
	if len(instrs) == 0 {
		return IRBlock{BlockID: blockID, Instructions: nil}
	}

	// check if last instruction is a branch or jump terminator
	last := instrs[len(instrs)-1]
	switch last.(type) {
	case ir.Branch, ir.Jump, *ir.Branch, *ir.Jump:
		// omit the terminator: it is represented by the structural node
		return IRBlock{
			BlockID:      blockID,
			Instructions: instrs[:len(instrs)-1],
		}
	default:
		return IRBlock{BlockID: blockID, Instructions: instrs}
	}
}

// mergeSequential combines two statements into a sequential block.
// if either is an empty block, returns the other directly.
func (e *Engine) mergeSequential(first, second Statement) Statement {
	// unwrap empty blocks
	if isEmptyBlock(first) {
		return second
	}
	if isEmptyBlock(second) {
		return first
	}

	// flatten nested blocks
	stmts := make([]Statement, 0, 4)
	stmts = appendFlattened(stmts, first)
	stmts = appendFlattened(stmts, second)

	return Block{Stmts: stmts}
}

// appendFlattened appends stmt to stmts, flattening top-level Block nodes
func appendFlattened(stmts []Statement, stmt Statement) []Statement {
	if b, ok := stmt.(Block); ok {
		return append(stmts, b.Stmts...)
	}
	return append(stmts, stmt)
}

// isEmptyBlock returns true if stmt is a Block with no statements
func isEmptyBlock(stmt Statement) bool {
	if b, ok := stmt.(Block); ok {
		return len(b.Stmts) == 0
	}
	return false
}

// getOrCreateLabel returns the goto label for a block, creating one if needed
func (e *Engine) getOrCreateLabel(blockID cfg.BlockID) string {
	if label, ok := e.gotoLabels[blockID]; ok {
		return label
	}
	e.gotoCounter++
	label := fmt.Sprintf("L%d", e.gotoCounter)
	e.gotoLabels[blockID] = label
	return label
}
