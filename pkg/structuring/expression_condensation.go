// package structuring - expression condensation pass
// this file implements condense_expressions: a post-structuring AST simplification
// pass that merges nested ifs, applies de morgan's laws, recognises early-return
// patterns, and inlines single-use temporaries.
package structuring

import (
	"fmt"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// public entry point
// ============================================================================

// CondenseExpressions applies all expression condensation transformations to
// the given StructuredAST and returns a new, simplified AST.
//
// transformations applied (in order):
//  1. merge nested if statements:  if(a){if(b){...}} → if(a&&b){...}
//  2. de morgan simplification:    !(a||b) → !a&&!b, !(a&&b) → !a||!b
//  3. early-return hoisting:       if(cond){return x;} rest → if(!cond) rest; return x;
//  4. single-use temporary inlining: t=expr; use(t) → use(expr)
//  5. tail merging: if(c){S;T} else{S';T} → if(c){S} else{S'} T  (identical tails)
//  6. empty-else normalization:    if(c){S} else {} → if(c){S}
//  7. merge consecutive if-statements with identical bodies: if(A){S} if(B){S} → if(A||B){S}
//  8. redundant branch elimination: if(c){S} S → S  (then-body identical to next stmt)
//  9. second early-return hoisting pass: collapses patterns exposed by passes 6-8
//
// Requirements: 60.4, 60.5, 60.6, 60.7, 60.9, 15.1, 15.7
func CondenseExpressions(ast *StructuredAST) *StructuredAST {
	if ast == nil {
		return nil
	}

	body := ast.Body

	// pass 1: merge nested ifs (if(a){if(b){S}} → if(a&&b){S})
	body = mergeNestedIfs(body)

	// pass 2: apply de morgan's laws to negate-of-logical expressions
	body = applyDeMorgan(body)

	// pass 3: inline single-use temporaries
	// note: hoistEarlyReturns is intentionally deferred to pass 8 so that
	// passes 4-7 (tail merging, empty-else normalization, consecutive-if merging,
	// redundant branch elimination) can operate on the original conditions without
	// interference from condition inversion introduced by early-return hoisting.
	body = inlineSingleUseTemps(body)

	// pass 4: tail merging — hoist identical trailing statements out of if-else branches
	body = mergeTails(body)

	// pass 5: normalize empty else-branches to nil so that pass 6 can merge
	// consecutive ifs that were separated by an empty else after tail hoisting.
	// example: if(c){S} else {} → if(c){S}
	body = normalizeEmptyElse(body)

	// pass 6: merge consecutive if-statements with identical bodies into a
	// single if with a disjunctive condition: if(A){S} if(B){S} → if(A||B){S}.
	// this eliminates tail duplication artifacts produced by the structuring engine
	// when the convergence block is duplicated into multiple branches.
	body = mergeConsecutiveIfs(body)

	// pass 7: eliminate redundant branches where the then-body is identical to
	// the immediately following statement: if(c){S} S → S.
	// this collapses the residual pattern after passes 4-6 where both the
	// conditional and the fall-through path execute the same code.
	body = eliminateRedundantBranches(body)

	// pass 8: hoist early returns to the top of blocks.
	// applied last so that passes 4-7 can operate on unmodified conditions.
	// example: if(cond){return x;} rest → if(!cond) rest; return x;
	body = hoistEarlyReturns(body)

	// pass 9: second early-return hoisting pass — re-apply after passes 6-8
	// have exposed new if(cond){return x;} patterns that were not visible
	// during pass 3 (e.g., after mergeConsecutiveIfs collapses multiple ifs
	// into one, the resulting if may now be eligible for hoisting).
	body = hoistEarlyReturns(body)

	return &StructuredAST{
		Body:       body,
		FunctionID: ast.FunctionID,
	}
}

// ============================================================================
// pass 1: nested if merging
// ============================================================================

// mergeNestedIfs walks the AST and collapses patterns of the form:
//
//	if (a) { if (b) { S } }  →  if (a && b) { S }
//
// the merge is only applied when the outer if has no else branch and the
// inner if (the sole statement in the then-block) also has no else branch.
func mergeNestedIfs(stmt Statement) Statement {
	if stmt == nil {
		return nil
	}

	switch s := stmt.(type) {
	case Block:
		result := make([]Statement, 0, len(s.Stmts))
		for _, child := range s.Stmts {
			result = append(result, mergeNestedIfs(child))
		}
		return Block{Stmts: result}

	case IfStatement:
		// recurse into branches first
		then := mergeNestedIfs(s.Then)
		var els Statement
		if s.Else != nil {
			els = mergeNestedIfs(s.Else)
		}
		merged := IfStatement{Condition: s.Condition, Then: then, Else: els}

		// attempt merge only when there is no else branch
		if merged.Else != nil {
			return merged
		}

		// unwrap single-statement then-block
		inner := singleStatement(merged.Then)
		if inner == nil {
			return merged
		}

		innerIf, ok := inner.(IfStatement)
		if !ok || innerIf.Else != nil {
			// inner statement is not a bare if, or it has an else
			return merged
		}

		// merge: if(a){if(b){S}} → if(a&&b){S}
		combined := ir.BinaryOp{
			Op:    ir.BinOpLogicalAnd,
			Left:  merged.Condition,
			Right: innerIf.Condition,
		}
		return IfStatement{
			Condition: combined,
			Then:      innerIf.Then,
			Else:      nil,
		}

	case WhileStatement:
		return WhileStatement{
			Condition: s.Condition,
			Body:      mergeNestedIfs(s.Body),
		}

	case DoWhileStatement:
		return DoWhileStatement{
			Body:      mergeNestedIfs(s.Body),
			Condition: s.Condition,
		}

	case ForStatement:
		var init, post Statement
		if s.Init != nil {
			init = mergeNestedIfs(s.Init)
		}
		if s.Post != nil {
			post = mergeNestedIfs(s.Post)
		}
		return ForStatement{
			Init:      init,
			Condition: s.Condition,
			Post:      post,
			Body:      mergeNestedIfs(s.Body),
		}

	default:
		return stmt
	}
}

// singleStatement returns the sole Statement inside a Block, or the statement
// itself if it is not a Block. returns nil when the block is empty or contains
// more than one statement.
func singleStatement(stmt Statement) Statement {
	if stmt == nil {
		return nil
	}
	blk, ok := stmt.(Block)
	if !ok {
		return stmt
	}
	// skip empty blocks
	nonEmpty := make([]Statement, 0, len(blk.Stmts))
	for _, s := range blk.Stmts {
		if !isEmptyBlock(s) {
			nonEmpty = append(nonEmpty, s)
		}
	}
	if len(nonEmpty) == 1 {
		return nonEmpty[0]
	}
	return nil
}

// ============================================================================
// pass 2: de morgan simplification
// ============================================================================

// applyDeMorgan walks the AST and rewrites logical-not of compound boolean
// expressions using De Morgan's laws:
//
//	!(a || b)  →  (!a && !b)
//	!(a && b)  →  (!a || !b)
//
// the transformation is applied recursively to all expressions inside
// statements, and also to the conditions of if/while/do-while/for nodes.
func applyDeMorgan(stmt Statement) Statement {
	if stmt == nil {
		return nil
	}

	switch s := stmt.(type) {
	case Block:
		result := make([]Statement, 0, len(s.Stmts))
		for _, child := range s.Stmts {
			result = append(result, applyDeMorgan(child))
		}
		return Block{Stmts: result}

	case IfStatement:
		then := applyDeMorgan(s.Then)
		var els Statement
		if s.Else != nil {
			els = applyDeMorgan(s.Else)
		}
		return IfStatement{
			Condition: deMorganExpr(s.Condition),
			Then:      then,
			Else:      els,
		}

	case WhileStatement:
		return WhileStatement{
			Condition: deMorganExpr(s.Condition),
			Body:      applyDeMorgan(s.Body),
		}

	case DoWhileStatement:
		return DoWhileStatement{
			Body:      applyDeMorgan(s.Body),
			Condition: deMorganExpr(s.Condition),
		}

	case ForStatement:
		var init, post Statement
		if s.Init != nil {
			init = applyDeMorgan(s.Init)
		}
		if s.Post != nil {
			post = applyDeMorgan(s.Post)
		}
		return ForStatement{
			Init:      init,
			Condition: deMorganExpr(s.Condition),
			Post:      post,
			Body:      applyDeMorgan(s.Body),
		}

	default:
		return stmt
	}
}

// deMorganExpr recursively applies De Morgan's laws to an expression.
// it only rewrites UnaryOp{LogicalNot, BinaryOp{LogicalAnd|LogicalOr, ...}}.
func deMorganExpr(expr ir.Expression) ir.Expression {
	if expr == nil {
		return nil
	}

	switch e := expr.(type) {
	case ir.UnaryOp:
		if e.Op != ir.UnOpLogicalNot {
			return ir.UnaryOp{Op: e.Op, Operand: deMorganExpr(e.Operand)}
		}
		// check if operand is a logical binary op
		inner, ok := e.Operand.(ir.BinaryOp)
		if !ok {
			return ir.UnaryOp{Op: e.Op, Operand: deMorganExpr(e.Operand)}
		}

		switch inner.Op {
		case ir.BinOpLogicalOr:
			// !(a || b) → (!a && !b)
			return ir.BinaryOp{
				Op:    ir.BinOpLogicalAnd,
				Left:  deMorganExpr(ir.UnaryOp{Op: ir.UnOpLogicalNot, Operand: inner.Left}),
				Right: deMorganExpr(ir.UnaryOp{Op: ir.UnOpLogicalNot, Operand: inner.Right}),
			}
		case ir.BinOpLogicalAnd:
			// !(a && b) → (!a || !b)
			return ir.BinaryOp{
				Op:    ir.BinOpLogicalOr,
				Left:  deMorganExpr(ir.UnaryOp{Op: ir.UnOpLogicalNot, Operand: inner.Left}),
				Right: deMorganExpr(ir.UnaryOp{Op: ir.UnOpLogicalNot, Operand: inner.Right}),
			}
		default:
			return ir.UnaryOp{Op: e.Op, Operand: deMorganExpr(e.Operand)}
		}

	case ir.BinaryOp:
		return ir.BinaryOp{
			Op:    e.Op,
			Left:  deMorganExpr(e.Left),
			Right: deMorganExpr(e.Right),
		}

	default:
		return expr
	}
}

// ============================================================================
// pass 3: early-return hoisting
// ============================================================================

// hoistEarlyReturns detects the pattern:
//
//	if (cond) { return x; }
//	<rest of block>
//
// and rewrites it to:
//
//	if (!cond) { <rest of block> }
//	return x;
//
// this is only applied when the then-branch is a single return statement and
// the rest of the block is non-empty. the transformation reduces nesting depth
// and makes the early-exit intent explicit.
func hoistEarlyReturns(stmt Statement) Statement {
	if stmt == nil {
		return nil
	}

	switch s := stmt.(type) {
	case Block:
		// first recurse into children
		stmts := make([]Statement, len(s.Stmts))
		for i, child := range s.Stmts {
			stmts[i] = hoistEarlyReturns(child)
		}

		// scan for early-return pattern: if(cond){return x;} followed by more stmts
		result := make([]Statement, 0, len(stmts))
		for i, child := range stmts {
			ifStmt, ok := child.(IfStatement)
			if !ok || ifStmt.Else != nil {
				result = append(result, child)
				continue
			}

			// check that then-branch is a single return
			retStmt := extractSingleReturn(ifStmt.Then)
			if retStmt == nil {
				result = append(result, child)
				continue
			}

			// check that there are remaining statements after this if
			rest := stmts[i+1:]
			if len(rest) == 0 {
				result = append(result, child)
				continue
			}

			// hoist: negate condition, wrap rest in new if, append return
			negated := negateCondition(ifStmt.Condition)
			restBlock := flattenToBlock(rest)
			result = append(result, IfStatement{
				Condition: negated,
				Then:      restBlock,
				Else:      nil,
			})
			result = append(result, *retStmt)
			// skip remaining stmts since they are now inside the new if
			break
		}

		if len(result) == 1 {
			return result[0]
		}
		return Block{Stmts: result}

	case IfStatement:
		then := hoistEarlyReturns(s.Then)
		var els Statement
		if s.Else != nil {
			els = hoistEarlyReturns(s.Else)
		}
		return IfStatement{Condition: s.Condition, Then: then, Else: els}

	case WhileStatement:
		return WhileStatement{Condition: s.Condition, Body: hoistEarlyReturns(s.Body)}

	case DoWhileStatement:
		return DoWhileStatement{Body: hoistEarlyReturns(s.Body), Condition: s.Condition}

	case ForStatement:
		var init, post Statement
		if s.Init != nil {
			init = hoistEarlyReturns(s.Init)
		}
		if s.Post != nil {
			post = hoistEarlyReturns(s.Post)
		}
		return ForStatement{
			Init:      init,
			Condition: s.Condition,
			Post:      post,
			Body:      hoistEarlyReturns(s.Body),
		}

	default:
		return stmt
	}
}

// extractSingleReturn returns a pointer to the ReturnStatement if stmt
// contains exactly one non-empty statement that is a ReturnStatement.
// returns nil otherwise.
func extractSingleReturn(stmt Statement) *ReturnStatement {
	single := singleStatement(stmt)
	if single == nil {
		return nil
	}
	ret, ok := single.(ReturnStatement)
	if !ok {
		return nil
	}
	return &ret
}

// negateCondition wraps an expression in a logical-not, with simple
// double-negation elimination: !(!x) → x.
func negateCondition(expr ir.Expression) ir.Expression {
	// double-negation elimination
	if u, ok := expr.(ir.UnaryOp); ok && u.Op == ir.UnOpLogicalNot {
		return u.Operand
	}
	return ir.UnaryOp{Op: ir.UnOpLogicalNot, Operand: expr}
}

// flattenToBlock wraps a slice of statements into a Block, or returns the
// single statement directly if the slice has exactly one element.
func flattenToBlock(stmts []Statement) Statement {
	if len(stmts) == 1 {
		return stmts[0]
	}
	cp := make([]Statement, len(stmts))
	copy(cp, stmts)
	return Block{Stmts: cp}
}

// ============================================================================
// pass 4: single-use temporary inlining
// ============================================================================

// inlineSingleUseTemps scans each Block for the pattern:
//
//	IRBlock containing: t = <expr>   (single assignment to a fresh variable)
//	followed by any statement that uses t exactly once
//
// and replaces the use of t with <expr> directly, removing the assignment.
// this reduces noise from compiler-generated temporaries in the output.
//
// the pass only inlines when:
//   - the variable is defined exactly once in the block
//   - the variable is used exactly once across all subsequent statements
//   - the defining expression has no side effects (no Call, Load, Store)
func inlineSingleUseTemps(stmt Statement) Statement {
	if stmt == nil {
		return nil
	}

	switch s := stmt.(type) {
	case Block:
		// first recurse into children
		stmts := make([]Statement, len(s.Stmts))
		for i, child := range s.Stmts {
			stmts[i] = inlineSingleUseTemps(child)
		}

		// collect single-definition candidates from IRBlock nodes.
		// candidates are: Assign with pure source, or Load (single memory read)
		// where the Load is the ONLY instruction in its IRBlock (cross-block inline).
		// map: variable name → (defining expression, index of IRBlock in stmts)
		type candidate struct {
			expr     ir.Expression
			blockIdx int
			instrIdx int
		}
		candidates := make(map[string]candidate)
		defCount := make(map[string]int)

		for i, child := range stmts {
			irb, ok := child.(IRBlock)
			if !ok {
				continue
			}
			for j, instr := range irb.Instructions {
				// handle Assign with pure source
				if assign, ok := ir.AsAssign(instr); ok {
					defCount[assign.Dest.Name]++
					if defCount[assign.Dest.Name] == 1 && isPureExpr(assign.Source) {
						candidates[assign.Dest.Name] = candidate{
							expr:     assign.Source,
							blockIdx: i,
							instrIdx: j,
						}
					} else {
						delete(candidates, assign.Dest.Name)
					}
					continue
				}
				// handle Load: inline only when the address is a constant expression.
				// a load from a constant address (e.g. *(uint64_t*)(163016)) is
				// safe to inline at a single use site because the address is
				// statically known and cannot alias any variable.
				// a load from a variable address (e.g. *(uint64_t*)(addr)) must
				// NOT be inlined — the address may change between the load and
				// the use site, and inlining would reorder the memory read.
				if load, ok := ir.AsLoad(instr); ok {
					defCount[load.Dest.Name]++
					if defCount[load.Dest.Name] == 1 && isConstantAddress(load.Address) {
						candidates[load.Dest.Name] = candidate{
							expr:     buildLoadExpr(load),
							blockIdx: i,
							instrIdx: j,
						}
					} else {
						delete(candidates, load.Dest.Name)
					}
				}
			}
		}

		// count uses of each candidate across all subsequent statements
		useCount := make(map[string]int)
		for _, child := range stmts {
			countVarUses(child, useCount)
		}

		// subtract the definition itself from use count (the lhs is not a use)
		// build the inlining substitution map: only inline single-use vars
		subst := make(map[string]ir.Expression)
		for name, cand := range candidates {
			uses := useCount[name]
			// the definition counts as one occurrence in countVarUses (rhs of assign
			// does not reference the dest, so uses here are pure consumer uses)
			if uses == 1 {
				subst[name] = cand.expr
			}
		}

		if len(subst) == 0 {
			return Block{Stmts: stmts}
		}

		// apply substitution: replace uses and remove defining assignments
		result := make([]Statement, 0, len(stmts))
		for i, child := range stmts {
			irb, ok := child.(IRBlock)
			if !ok {
				result = append(result, substituteInStmt(child, subst))
				continue
			}

			// rebuild IRBlock, dropping inlined assignments and loads
			newInstrs := make([]ir.IRInstruction, 0, len(irb.Instructions))
			for _, instr := range irb.Instructions {
				if assign, isAssign := ir.AsAssign(instr); isAssign {
					if _, shouldInline := subst[assign.Dest.Name]; shouldInline {
						continue
					}
				}
				if load, isLoad := ir.AsLoad(instr); isLoad {
					if _, shouldInline := subst[load.Dest.Name]; shouldInline {
						continue
					}
				}
				newInstrs = append(newInstrs, substituteInInstr(instr, subst))
			}

			if len(newInstrs) == 0 {
				// irblock became empty after inlining; check if it was the only content
				_ = i
				continue
			}
			result = append(result, IRBlock{BlockID: irb.BlockID, Instructions: newInstrs})
		}

		// apply substitution to all non-IRBlock statements
		final := make([]Statement, 0, len(result))
		for _, child := range result {
			if _, isIRB := child.(IRBlock); isIRB {
				final = append(final, child)
			} else {
				final = append(final, substituteInStmt(child, subst))
			}
		}

		if len(final) == 1 {
			return final[0]
		}
		return Block{Stmts: final}

	case IfStatement:
		then := inlineSingleUseTemps(s.Then)
		var els Statement
		if s.Else != nil {
			els = inlineSingleUseTemps(s.Else)
		}
		return IfStatement{Condition: s.Condition, Then: then, Else: els}

	case WhileStatement:
		return WhileStatement{Condition: s.Condition, Body: inlineSingleUseTemps(s.Body)}

	case DoWhileStatement:
		return DoWhileStatement{Body: inlineSingleUseTemps(s.Body), Condition: s.Condition}

	case ForStatement:
		var init, post Statement
		if s.Init != nil {
			init = inlineSingleUseTemps(s.Init)
		}
		if s.Post != nil {
			post = inlineSingleUseTemps(s.Post)
		}
		return ForStatement{
			Init:      init,
			Condition: s.Condition,
			Post:      post,
			Body:      inlineSingleUseTemps(s.Body),
		}

	default:
		return stmt
	}
}

// buildLoadExpr constructs a LoadExpr from an ir.Load instruction.
// used by inlineSingleUseTemps to represent an inlined memory dereference.
func buildLoadExpr(load ir.Load) ir.Expression {
	return ir.LoadExpr{Address: load.Address, Size: load.Size}
}

// isConstantAddress returns true when an address expression is fully constant
// (contains no variable references). such loads are safe to inline at a single
// use site because the address cannot alias any variable in the function.
func isConstantAddress(expr ir.Expression) bool {
	if expr == nil {
		return false
	}
	switch e := expr.(type) {
	case ir.ConstantExpr, *ir.ConstantExpr:
		return true
	case ir.BinaryOp:
		return isConstantAddress(e.Left) && isConstantAddress(e.Right)
	case *ir.BinaryOp:
		return isConstantAddress(e.Left) && isConstantAddress(e.Right)
	case ir.UnaryOp:
		return isConstantAddress(e.Operand)
	case *ir.UnaryOp:
		return isConstantAddress(e.Operand)
	case ir.Cast:
		return isConstantAddress(e.Expr)
	case *ir.Cast:
		return isConstantAddress(e.Expr)
	default:
		// VariableExpr and anything else: not a constant address
		return false
	}
}

// isPureExpr returns true when the expression is safe to inline at a single
// use site without changing observable semantics.
//
// policy:
//   - arithmetic, logical, cast, variable, constant: always safe
//   - Load (memory read): safe to inline at a single use site because the
//     value is read exactly once; no write side-effect
//   - Call: never safe (may have side effects, must execute exactly once at
//     the original program point)
func isPureExpr(expr ir.Expression) bool {
	if expr == nil {
		return true
	}
	switch e := expr.(type) {
	case ir.VariableExpr, *ir.VariableExpr,
		ir.ConstantExpr, *ir.ConstantExpr:
		return true
	case ir.BinaryOp:
		return isPureExpr(e.Left) && isPureExpr(e.Right)
	case *ir.BinaryOp:
		return isPureExpr(e.Left) && isPureExpr(e.Right)
	case ir.UnaryOp:
		return isPureExpr(e.Operand)
	case *ir.UnaryOp:
		return isPureExpr(e.Operand)
	case ir.Cast:
		return isPureExpr(e.Expr)
	case *ir.Cast:
		return isPureExpr(e.Expr)
	default:
		// Call and unknown expression types are not pure
		return false
	}
}

// countVarUses walks a Statement and increments useCount for every
// VariableExpr encountered in expressions.
func countVarUses(stmt Statement, useCount map[string]int) {
	if stmt == nil {
		return
	}
	switch s := stmt.(type) {
	case Block:
		for _, child := range s.Stmts {
			countVarUses(child, useCount)
		}
	case IRBlock:
		for _, instr := range s.Instructions {
			countVarUsesInInstr(instr, useCount)
		}
	case IfStatement:
		countVarUsesInExpr(s.Condition, useCount)
		countVarUses(s.Then, useCount)
		if s.Else != nil {
			countVarUses(s.Else, useCount)
		}
	case WhileStatement:
		countVarUsesInExpr(s.Condition, useCount)
		countVarUses(s.Body, useCount)
	case DoWhileStatement:
		countVarUses(s.Body, useCount)
		countVarUsesInExpr(s.Condition, useCount)
	case ForStatement:
		if s.Init != nil {
			countVarUses(s.Init, useCount)
		}
		countVarUsesInExpr(s.Condition, useCount)
		if s.Post != nil {
			countVarUses(s.Post, useCount)
		}
		countVarUses(s.Body, useCount)
	case ReturnStatement:
		if s.Value != nil {
			countVarUsesInExpr(s.Value, useCount)
		}
	}
}

// countVarUsesInInstr counts variable uses in a single IR instruction.
// uses As* helpers to handle both value and pointer receiver variants emitted
// by the lifter (which stores *Call, *Load, *Assign etc. in IRInstruction slices).
func countVarUsesInInstr(instr ir.IRInstruction, useCount map[string]int) {
	if assign, ok := ir.AsAssign(instr); ok {
		// only count uses in the source expression, not the destination
		countVarUsesInExpr(assign.Source, useCount)
		return
	}
	if load, ok := ir.AsLoad(instr); ok {
		countVarUsesInExpr(load.Address, useCount)
		return
	}
	if store, ok := ir.AsStore(instr); ok {
		countVarUsesInExpr(store.Address, useCount)
		countVarUsesInExpr(store.Value, useCount)
		return
	}
	if branch, ok := ir.AsBranch(instr); ok {
		countVarUsesInExpr(branch.Condition, useCount)
		return
	}
	if call, ok := ir.AsCall(instr); ok {
		if call.Target != nil {
			countVarUsesInExpr(call.Target, useCount)
		}
		// if ArgExprs already populated (previous inline pass), count those instead
		if len(call.ArgExprs) == len(call.Args) && len(call.ArgExprs) > 0 {
			for _, e := range call.ArgExprs {
				countVarUsesInExpr(e, useCount)
			}
		} else {
			for _, arg := range call.Args {
				useCount[arg.Name]++
			}
		}
		return
	}
	if ret, ok := ir.AsReturn(instr); ok {
		if ret.Value != nil {
			useCount[ret.Value.Name]++
		}
		return
	}
}

// countVarUsesInExpr counts variable uses in an expression tree.
func countVarUsesInExpr(expr ir.Expression, useCount map[string]int) {
	if expr == nil {
		return
	}
	switch e := expr.(type) {
	case ir.VariableExpr:
		useCount[e.Var.Name]++
	case ir.BinaryOp:
		countVarUsesInExpr(e.Left, useCount)
		countVarUsesInExpr(e.Right, useCount)
	case ir.UnaryOp:
		countVarUsesInExpr(e.Operand, useCount)
	case ir.Cast:
		countVarUsesInExpr(e.Expr, useCount)
	}
}

// substituteInStmt replaces all VariableExpr occurrences matching keys in subst
// with the corresponding replacement expression throughout a Statement tree.
func substituteInStmt(stmt Statement, subst map[string]ir.Expression) Statement {
	if stmt == nil || len(subst) == 0 {
		return stmt
	}
	switch s := stmt.(type) {
	case Block:
		result := make([]Statement, len(s.Stmts))
		for i, child := range s.Stmts {
			result[i] = substituteInStmt(child, subst)
		}
		return Block{Stmts: result}

	case IRBlock:
		newInstrs := make([]ir.IRInstruction, len(s.Instructions))
		for i, instr := range s.Instructions {
			newInstrs[i] = substituteInInstr(instr, subst)
		}
		return IRBlock{BlockID: s.BlockID, Instructions: newInstrs}

	case IfStatement:
		then := substituteInStmt(s.Then, subst)
		var els Statement
		if s.Else != nil {
			els = substituteInStmt(s.Else, subst)
		}
		return IfStatement{
			Condition: substituteInExpr(s.Condition, subst),
			Then:      then,
			Else:      els,
		}

	case WhileStatement:
		return WhileStatement{
			Condition: substituteInExpr(s.Condition, subst),
			Body:      substituteInStmt(s.Body, subst),
		}

	case DoWhileStatement:
		return DoWhileStatement{
			Body:      substituteInStmt(s.Body, subst),
			Condition: substituteInExpr(s.Condition, subst),
		}

	case ForStatement:
		var init, post Statement
		if s.Init != nil {
			init = substituteInStmt(s.Init, subst)
		}
		if s.Post != nil {
			post = substituteInStmt(s.Post, subst)
		}
		return ForStatement{
			Init:      init,
			Condition: substituteInExpr(s.Condition, subst),
			Post:      post,
			Body:      substituteInStmt(s.Body, subst),
		}

	case ReturnStatement:
		if s.Value != nil {
			newVal := substituteInExpr(s.Value, subst)
			return ReturnStatement{Value: newVal}
		}
		return s

	default:
		return stmt
	}
}

// substituteInInstr applies the substitution map to all expressions in an
// IR instruction, returning a new instruction with replaced variable references.
// uses As* helpers to handle both value and pointer receiver variants emitted
// by the lifter (which stores *Call, *Load, *Assign etc. in IRInstruction slices).
func substituteInInstr(instr ir.IRInstruction, subst map[string]ir.Expression) ir.IRInstruction {
	if assign, ok := ir.AsAssign(instr); ok {
		// preserve SourceLocation from the original instruction
		return ir.CloneAssign(assign, substituteInExpr(assign.Source, subst))
	}
	if load, ok := ir.AsLoad(instr); ok {
		return ir.CloneLoad(load, substituteInExpr(load.Address, subst))
	}
	if store, ok := ir.AsStore(instr); ok {
		return ir.CloneStore(store,
			substituteInExpr(store.Address, subst),
			substituteInExpr(store.Value, subst),
		)
	}
	if branch, ok := ir.AsBranch(instr); ok {
		return ir.CloneBranch(branch, substituteInExpr(branch.Condition, subst))
	}
	if call, ok := ir.AsCall(instr); ok {
		// build ArgExprs: for each argument, substitute if it's in subst,
		// otherwise wrap the original variable in a VariableExpr.
		// this populates ArgExprs so codegen can render inlined expressions
		// without changing the ssa variable representation in Args.
		newArgExprs := make([]ir.Expression, len(call.Args))
		anyInlined := false
		for j, arg := range call.Args {
			if replacement, ok := subst[arg.Name]; ok {
				newArgExprs[j] = replacement
				anyInlined = true
			} else if len(call.ArgExprs) == len(call.Args) {
				// preserve existing ArgExprs for args not being substituted
				newArgExprs[j] = substituteInExpr(call.ArgExprs[j], subst)
			} else {
				newArgExprs[j] = ir.VariableExpr{Var: arg}
			}
		}
		// only set ArgExprs when at least one arg was inlined or ArgExprs already existed
		if !anyInlined && len(call.ArgExprs) == 0 {
			newArgExprs = nil
		}
		newArgs := make([]ir.Variable, len(call.Args))
		copy(newArgs, call.Args)
		// preserve SourceLocation so traceability survives condensation
		return ir.CloneCall(call, substituteInExpr(call.Target, subst), newArgs, newArgExprs)
	}
	return instr
}

// substituteInExpr replaces VariableExpr nodes whose variable name is in subst
// with the corresponding replacement expression.
func substituteInExpr(expr ir.Expression, subst map[string]ir.Expression) ir.Expression {
	if expr == nil || len(subst) == 0 {
		return expr
	}
	switch e := expr.(type) {
	case ir.VariableExpr:
		if replacement, ok := subst[e.Var.Name]; ok {
			return replacement
		}
		return e
	case ir.BinaryOp:
		return ir.BinaryOp{
			Op:    e.Op,
			Left:  substituteInExpr(e.Left, subst),
			Right: substituteInExpr(e.Right, subst),
		}
	case ir.UnaryOp:
		return ir.UnaryOp{Op: e.Op, Operand: substituteInExpr(e.Operand, subst)}
	case ir.Cast:
		return ir.Cast{Expr: substituteInExpr(e.Expr, subst), TargetType: e.TargetType}
	case ir.LoadExpr:
		return ir.LoadExpr{Address: substituteInExpr(e.Address, subst), Size: e.Size}
	default:
		return expr
	}
}

// ============================================================================
// pass 5: tail merging
// ============================================================================

// mergeTails walks the AST and hoists identical trailing statements out of
// if-then-else branches. the pattern:
//
//	if (c) { S1; T } else { S2; T }  →  if (c) { S1 } else { S2 } T
//
// where T is a structurally identical suffix shared by both branches.
// this is the inverse of tail duplication: it collapses code that the
// structuring engine emitted twice because the CFG had a shared successor
// that was duplicated into both branches.
//
// additionally handles the asymmetric case produced by the structuring engine
// when the convergence block is only included in one branch:
//
//	Block { if(c) { S1 } else { S2; T }; T }  →  Block { if(c) { S1 } else { S2 }; T }
//
// the transformation is applied recursively bottom-up so that nested
// if-else constructs are also simplified.
func mergeTails(stmt Statement) Statement {
	if stmt == nil {
		return nil
	}

	switch s := stmt.(type) {
	case Block:
		// recurse into children first
		stmts := make([]Statement, len(s.Stmts))
		for i, child := range s.Stmts {
			stmts[i] = mergeTails(child)
		}

		// asymmetric tail merging: scan for the pattern
		//   stmts[i] = IfStatement{Then: S1, Else: Block{...; T}}
		//   stmts[i+1..] = T (identical suffix)
		// and hoist T out of the else branch.
		stmts = mergeAsymmetricTails(stmts)

		return Block{Stmts: stmts}

	case IfStatement:
		// recurse into branches first (bottom-up)
		then := mergeTails(s.Then)
		var els Statement
		if s.Else != nil {
			els = mergeTails(s.Else)
		}

		// only attempt symmetric tail merging when both branches exist
		if els == nil {
			return IfStatement{Condition: s.Condition, Then: then, Else: els}
		}

		// extract statement lists from both branches
		thenStmts := flattenBlock(then)
		elseStmts := flattenBlock(els)

		if len(thenStmts) == 0 || len(elseStmts) == 0 {
			return IfStatement{Condition: s.Condition, Then: then, Else: els}
		}

		// count how many trailing statements are identical in both branches
		sharedCount := 0
		for sharedCount < len(thenStmts) && sharedCount < len(elseStmts) {
			tIdx := len(thenStmts) - 1 - sharedCount
			eIdx := len(elseStmts) - 1 - sharedCount
			if !statementsEqual(thenStmts[tIdx], elseStmts[eIdx]) {
				break
			}
			sharedCount++
		}

		if sharedCount == 0 {
			return IfStatement{Condition: s.Condition, Then: then, Else: els}
		}

		// build trimmed branches (without the shared tail)
		thenTrimmed := thenStmts[:len(thenStmts)-sharedCount]
		elseTrimmed := elseStmts[:len(elseStmts)-sharedCount]
		sharedTail := thenStmts[len(thenStmts)-sharedCount:]

		newIf := IfStatement{
			Condition: s.Condition,
			Then:      blockOrSingle(thenTrimmed),
			Else:      blockOrSingle(elseTrimmed),
		}

		// build result: new if followed by the shared tail
		result := make([]Statement, 0, 1+len(sharedTail))
		result = append(result, newIf)
		result = append(result, sharedTail...)
		return Block{Stmts: result}

	case WhileStatement:
		return WhileStatement{Condition: s.Condition, Body: mergeTails(s.Body)}

	case DoWhileStatement:
		return DoWhileStatement{Body: mergeTails(s.Body), Condition: s.Condition}

	case ForStatement:
		var init, post Statement
		if s.Init != nil {
			init = mergeTails(s.Init)
		}
		if s.Post != nil {
			post = mergeTails(s.Post)
		}
		return ForStatement{
			Init:      init,
			Condition: s.Condition,
			Post:      post,
			Body:      mergeTails(s.Body),
		}

	default:
		return stmt
	}
}

// mergeAsymmetricTails handles the case where the structuring engine duplicated
// the convergence block into only one branch of an if-else. the pattern is:
//
//	stmts[i]   = IfStatement { Then: S1, Else: Block{S2; T1; T2; ...} }
//	stmts[i+1] = T1
//	stmts[i+2] = T2
//	...
//
// or the mirror (tail in Then branch, not Else). it finds the longest suffix
// of the else (or then) branch that matches the subsequent statements in the
// parent block, and hoists that suffix out.
func mergeAsymmetricTails(stmts []Statement) []Statement {
	result := make([]Statement, 0, len(stmts))
	i := 0
	for i < len(stmts) {
		ifStmt, ok := stmts[i].(IfStatement)
		if !ok || ifStmt.Else == nil || i+1 >= len(stmts) {
			result = append(result, stmts[i])
			i++
			continue
		}

		// remaining statements after this if in the parent block
		following := stmts[i+1:]

		// try to hoist from else branch
		if _, newElse, count := hoistMatchingSuffix(ifStmt.Else, following); count > 0 {
			newIf := IfStatement{
				Condition: ifStmt.Condition,
				Then:      ifStmt.Then,
				Else:      newElse,
			}
			result = append(result, newIf)
			// the hoisted statements are the first `count` elements of following;
			// they must appear after the if (deduplicated — keep only the copy
			// from the parent block, not the one inside the branch).
			result = append(result, following[:count]...)
			// skip past the hoisted statements in the parent block
			i += 1 + count
			// append any remaining statements after the hoisted block
			result = append(result, stmts[i:]...)
			return result
		}

		// try to hoist from then branch
		if _, newThen, count := hoistMatchingSuffix(ifStmt.Then, following); count > 0 {
			newIf := IfStatement{
				Condition: ifStmt.Condition,
				Then:      newThen,
				Else:      ifStmt.Else,
			}
			result = append(result, newIf)
			result = append(result, following[:count]...)
			i += 1 + count
			result = append(result, stmts[i:]...)
			return result
		}

		result = append(result, stmts[i])
		i++
	}
	return result
}

// hoistMatchingSuffix checks whether the trailing statements of branchStmt
// match a prefix of following. returns the number of matched statements,
// the trimmed branch (with the matched suffix removed), and the count.
// returns count=0 if no match.
func hoistMatchingSuffix(branchStmt Statement, following []Statement) ([]Statement, Statement, int) {
	branchStmts := flattenBlock(branchStmt)
	if len(branchStmts) == 0 || len(following) == 0 {
		return nil, branchStmt, 0
	}

	// count how many trailing statements of branchStmts match the prefix of following
	maxMatch := len(following)
	if len(branchStmts) < maxMatch {
		maxMatch = len(branchStmts)
	}

	matched := 0
	for matched < maxMatch {
		bIdx := len(branchStmts) - maxMatch + matched
		fIdx := matched
		if !statementsEqual(branchStmts[bIdx], following[fIdx]) {
			break
		}
		matched++
	}

	if matched == 0 {
		return nil, branchStmt, 0
	}

	// trim the matched suffix from the branch
	trimmed := branchStmts[:len(branchStmts)-matched]
	hoisted := branchStmts[len(branchStmts)-matched:]
	return hoisted, blockOrSingle(trimmed), matched
}

// flattenBlock returns the statement list of a Block, or a single-element
// slice containing stmt if it is not a Block.
func flattenBlock(stmt Statement) []Statement {
	if stmt == nil {
		return nil
	}
	if b, ok := stmt.(Block); ok {
		return b.Stmts
	}
	return []Statement{stmt}
}

// blockOrSingle wraps a statement list into a Block, or returns the single
// statement directly. returns an empty Block for an empty list.
func blockOrSingle(stmts []Statement) Statement {
	switch len(stmts) {
	case 0:
		return Block{Stmts: nil}
	case 1:
		return stmts[0]
	default:
		cp := make([]Statement, len(stmts))
		copy(cp, stmts)
		return Block{Stmts: cp}
	}
}

// statementsEqual performs structural equality comparison between two statements.
// it compares the string representation of IR instructions within IRBlock nodes
// and recursively compares composite statements. this is sufficient for the
// tail-merging use case where duplicated blocks originate from the same CFG node.
func statementsEqual(a, b Statement) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	switch sa := a.(type) {
	case IRBlock:
		sb, ok := b.(IRBlock)
		if !ok {
			return false
		}
		if len(sa.Instructions) != len(sb.Instructions) {
			return false
		}
		for i := range sa.Instructions {
			if sa.Instructions[i].String() != sb.Instructions[i].String() {
				return false
			}
		}
		return true

	case ReturnStatement:
		rb, ok := b.(ReturnStatement)
		if !ok {
			return false
		}
		aVal := ""
		bVal := ""
		if sa.Value != nil {
			aVal = sa.Value.String()
		}
		if rb.Value != nil {
			bVal = rb.Value.String()
		}
		return aVal == bVal

	case Block:
		sb, ok := b.(Block)
		if !ok {
			return false
		}
		if len(sa.Stmts) != len(sb.Stmts) {
			return false
		}
		for i := range sa.Stmts {
			if !statementsEqual(sa.Stmts[i], sb.Stmts[i]) {
				return false
			}
		}
		return true

	case IfStatement:
		sb, ok := b.(IfStatement)
		if !ok {
			return false
		}
		if sa.Condition.String() != sb.Condition.String() {
			return false
		}
		return statementsEqual(sa.Then, sb.Then) && statementsEqual(sa.Else, sb.Else)

	default:
		// for other statement types, use string representation as a proxy
		return fmt.Sprintf("%T", a) == fmt.Sprintf("%T", b)
	}
}

// ============================================================================
// pass 6: consecutive if merging
// ============================================================================

// mergeConsecutiveIfs walks the AST and collapses sequences of if-statements
// that share an identical body into a single if with a disjunctive condition:
//
//	if (A) { S }
//	if (B) { S }   →   if (A || B) { S }
//
// the merge is applied repeatedly within each block until no further reduction
// is possible. only if-statements without an else branch are merged; an else
// branch changes the semantics and must not be collapsed.
//
// this eliminates the tail-duplication artifact produced by the structuring
// engine when the convergence block is cloned into multiple branches.
func mergeConsecutiveIfs(stmt Statement) Statement {
	if stmt == nil {
		return nil
	}

	switch s := stmt.(type) {
	case Block:
		// recurse into children first (bottom-up)
		stmts := make([]Statement, len(s.Stmts))
		for i, child := range s.Stmts {
			stmts[i] = mergeConsecutiveIfs(child)
		}
		// repeatedly scan for adjacent if-pairs with identical bodies
		stmts = collapseConsecutiveIfPairs(stmts)
		return Block{Stmts: stmts}

	case IfStatement:
		then := mergeConsecutiveIfs(s.Then)
		var els Statement
		if s.Else != nil {
			els = mergeConsecutiveIfs(s.Else)
		}
		return IfStatement{Condition: s.Condition, Then: then, Else: els}

	case WhileStatement:
		return WhileStatement{Condition: s.Condition, Body: mergeConsecutiveIfs(s.Body)}

	case DoWhileStatement:
		return DoWhileStatement{Body: mergeConsecutiveIfs(s.Body), Condition: s.Condition}

	case ForStatement:
		var init, post Statement
		if s.Init != nil {
			init = mergeConsecutiveIfs(s.Init)
		}
		if s.Post != nil {
			post = mergeConsecutiveIfs(s.Post)
		}
		return ForStatement{
			Init:      init,
			Condition: s.Condition,
			Post:      post,
			Body:      mergeConsecutiveIfs(s.Body),
		}

	default:
		return stmt
	}
}

// collapseConsecutiveIfPairs scans a statement list and merges adjacent
// if-statements (no else) whose bodies are structurally identical.
// the scan is repeated until no further merges are possible, handling
// chains of three or more identical branches.
func collapseConsecutiveIfPairs(stmts []Statement) []Statement {
	changed := true
	for changed {
		changed = false
		result := make([]Statement, 0, len(stmts))
		i := 0
		for i < len(stmts) {
			a, aOk := stmts[i].(IfStatement)
			if !aOk || a.Else != nil || i+1 >= len(stmts) {
				result = append(result, stmts[i])
				i++
				continue
			}
			b, bOk := stmts[i+1].(IfStatement)
			if !bOk || b.Else != nil {
				result = append(result, stmts[i])
				i++
				continue
			}
			// merge only when bodies are structurally identical
			if !statementsEqual(a.Then, b.Then) {
				result = append(result, stmts[i])
				i++
				continue
			}
			// build disjunctive condition: A || B
			merged := IfStatement{
				Condition: ir.BinaryOp{
					Op:    ir.BinOpLogicalOr,
					Left:  a.Condition,
					Right: b.Condition,
				},
				Then: a.Then,
				Else: nil,
			}
			result = append(result, merged)
			i += 2
			changed = true
		}
		stmts = result
	}
	return stmts
}

// ============================================================================
// pass 6: empty-else normalization
// ============================================================================

// normalizeEmptyElse walks the AST and replaces empty else-branches with nil.
// an empty else is a Block with zero non-empty statements.
// this is necessary because mergeAsymmetricTails (in mergeTails) replaces a
// hoisted else-branch with Block{Stmts: nil}, which is structurally non-nil
// but semantically empty. collapseConsecutiveIfPairs checks a.Else != nil to
// decide whether to skip merging, so without this normalization the merge
// would be incorrectly suppressed.
func normalizeEmptyElse(stmt Statement) Statement {
	if stmt == nil {
		return nil
	}

	switch s := stmt.(type) {
	case Block:
		result := make([]Statement, len(s.Stmts))
		for i, child := range s.Stmts {
			result[i] = normalizeEmptyElse(child)
		}
		return Block{Stmts: result}

	case IfStatement:
		then := normalizeEmptyElse(s.Then)
		var els Statement
		if s.Else != nil {
			normalized := normalizeEmptyElse(s.Else)
			if !isEmptyBlock(normalized) {
				els = normalized
			}
			// else: els stays nil — empty else is dropped
		}
		return IfStatement{Condition: s.Condition, Then: then, Else: els}

	case WhileStatement:
		return WhileStatement{Condition: s.Condition, Body: normalizeEmptyElse(s.Body)}

	case DoWhileStatement:
		return DoWhileStatement{Body: normalizeEmptyElse(s.Body), Condition: s.Condition}

	case ForStatement:
		var init, post Statement
		if s.Init != nil {
			init = normalizeEmptyElse(s.Init)
		}
		if s.Post != nil {
			post = normalizeEmptyElse(s.Post)
		}
		return ForStatement{
			Init:      init,
			Condition: s.Condition,
			Post:      post,
			Body:      normalizeEmptyElse(s.Body),
		}

	default:
		return stmt
	}
}

// ============================================================================
// pass 8: redundant branch elimination
// ============================================================================

// eliminateRedundantBranches walks the AST and removes if-statements whose
// then-body is structurally identical to the immediately following statement
// in the parent block. the pattern:
//
//	if (cond) { S }
//	S
//
// is collapsed to just S, because S executes unconditionally regardless of
// the branch outcome. this is the residual artifact produced when:
//  1. mergeTails hoists the convergence block out of the else-branch
//  2. normalizeEmptyElse drops the now-empty else
//  3. mergeConsecutiveIfs merges the resulting bare if with the next if
//  4. the merged if(A||B){S} is followed by the same S from the fall-through
//
// the transformation is only applied when:
//   - the if-statement has no else branch
//   - the then-body is structurally identical to the next statement
//
// after elimination the redundant if is dropped and S appears exactly once.
func eliminateRedundantBranches(stmt Statement) Statement {
	if stmt == nil {
		return nil
	}

	switch s := stmt.(type) {
	case Block:
		// recurse into children first (bottom-up)
		stmts := make([]Statement, len(s.Stmts))
		for i, child := range s.Stmts {
			stmts[i] = eliminateRedundantBranches(child)
		}
		stmts = collapseRedundantIfPairs(stmts)
		return Block{Stmts: stmts}

	case IfStatement:
		then := eliminateRedundantBranches(s.Then)
		var els Statement
		if s.Else != nil {
			els = eliminateRedundantBranches(s.Else)
		}
		return IfStatement{Condition: s.Condition, Then: then, Else: els}

	case WhileStatement:
		return WhileStatement{Condition: s.Condition, Body: eliminateRedundantBranches(s.Body)}

	case DoWhileStatement:
		return DoWhileStatement{Body: eliminateRedundantBranches(s.Body), Condition: s.Condition}

	case ForStatement:
		var init, post Statement
		if s.Init != nil {
			init = eliminateRedundantBranches(s.Init)
		}
		if s.Post != nil {
			post = eliminateRedundantBranches(s.Post)
		}
		return ForStatement{
			Init:      init,
			Condition: s.Condition,
			Post:      post,
			Body:      eliminateRedundantBranches(s.Body),
		}

	default:
		return stmt
	}
}

// collapseRedundantIfPairs scans a statement list and removes if-statements
// (no else) whose then-body is identical to the immediately following statement.
// the if is dropped and the following statement is kept (it executes unconditionally).
func collapseRedundantIfPairs(stmts []Statement) []Statement {
	result := make([]Statement, 0, len(stmts))
	i := 0
	for i < len(stmts) {
		ifStmt, ok := stmts[i].(IfStatement)
		if !ok || ifStmt.Else != nil || i+1 >= len(stmts) {
			result = append(result, stmts[i])
			i++
			continue
		}
		next := stmts[i+1]
		if statementsEqual(ifStmt.Then, next) {
			// then-body is identical to the next statement: drop the if,
			// keep the unconditional statement
			result = append(result, next)
			i += 2
			continue
		}
		result = append(result, stmts[i])
		i++
	}
	return result
}
