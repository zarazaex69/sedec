// package structuring - expression condensation pass
// this file implements condense_expressions: a post-structuring AST simplification
// pass that merges nested ifs, applies de morgan's laws, recognises early-return
// patterns, and inlines single-use temporaries.
package structuring

import (
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
//
// Requirements: 60.4, 60.5, 60.6, 60.7, 60.9
func CondenseExpressions(ast *StructuredAST) *StructuredAST {
	if ast == nil {
		return nil
	}

	body := ast.Body

	// pass 1: merge nested ifs (if(a){if(b){S}} → if(a&&b){S})
	body = mergeNestedIfs(body)

	// pass 2: apply de morgan's laws to negate-of-logical expressions
	body = applyDeMorgan(body)

	// pass 3: hoist early returns to the top of blocks
	body = hoistEarlyReturns(body)

	// pass 4: inline single-use temporaries
	body = inlineSingleUseTemps(body)

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

		// collect single-definition candidates from IRBlock nodes
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
				assign, ok := instr.(ir.Assign)
				if !ok {
					continue
				}
				defCount[assign.Dest.Name]++
				if defCount[assign.Dest.Name] == 1 && isPureExpr(assign.Source) {
					candidates[assign.Dest.Name] = candidate{
						expr:     assign.Source,
						blockIdx: i,
						instrIdx: j,
					}
				} else {
					// multiple definitions: not safe to inline
					delete(candidates, assign.Dest.Name)
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

			// rebuild IRBlock, dropping inlined assignments
			newInstrs := make([]ir.IRInstruction, 0, len(irb.Instructions))
			for _, instr := range irb.Instructions {
				assign, isAssign := instr.(ir.Assign)
				if isAssign {
					if _, shouldInline := subst[assign.Dest.Name]; shouldInline {
						// drop this assignment; its value is inlined at the use site
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

// isPureExpr returns true when the expression has no observable side effects
// (no function calls, no memory loads). only pure arithmetic/logical/variable
// expressions are safe to duplicate at the use site.
func isPureExpr(expr ir.Expression) bool {
	if expr == nil {
		return true
	}
	switch e := expr.(type) {
	case ir.VariableExpr, ir.ConstantExpr:
		return true
	case ir.BinaryOp:
		return isPureExpr(e.Left) && isPureExpr(e.Right)
	case ir.UnaryOp:
		return isPureExpr(e.Operand)
	case ir.Cast:
		return isPureExpr(e.Expr)
	default:
		// Load, Call, and any unknown expression type are not pure
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
func countVarUsesInInstr(instr ir.IRInstruction, useCount map[string]int) {
	switch i := instr.(type) {
	case ir.Assign:
		// only count uses in the source expression, not the destination
		countVarUsesInExpr(i.Source, useCount)
	case ir.Load:
		countVarUsesInExpr(i.Address, useCount)
	case ir.Store:
		countVarUsesInExpr(i.Address, useCount)
		countVarUsesInExpr(i.Value, useCount)
	case ir.Branch:
		countVarUsesInExpr(i.Condition, useCount)
	case ir.Call:
		if i.Target != nil {
			countVarUsesInExpr(i.Target, useCount)
		}
		for _, arg := range i.Args {
			useCount[arg.Name]++
		}
	case ir.Return:
		if i.Value != nil {
			useCount[i.Value.Name]++
		}
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
func substituteInInstr(instr ir.IRInstruction, subst map[string]ir.Expression) ir.IRInstruction {
	switch i := instr.(type) {
	case ir.Assign:
		return ir.Assign{Dest: i.Dest, Source: substituteInExpr(i.Source, subst)}
	case ir.Load:
		return ir.Load{Dest: i.Dest, Address: substituteInExpr(i.Address, subst), Size: i.Size}
	case ir.Store:
		return ir.Store{
			Address: substituteInExpr(i.Address, subst),
			Value:   substituteInExpr(i.Value, subst),
			Size:    i.Size,
		}
	case ir.Branch:
		return ir.Branch{Condition: substituteInExpr(i.Condition, subst), TrueTarget: i.TrueTarget, FalseTarget: i.FalseTarget}
	case ir.Call:
		newArgs := make([]ir.Variable, len(i.Args))
		copy(newArgs, i.Args)
		return ir.Call{Dest: i.Dest, Target: substituteInExpr(i.Target, subst), Args: newArgs}
	default:
		return instr
	}
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
	default:
		return expr
	}
}
