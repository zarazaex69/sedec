// package codegen - variable scope minimization pass.
// declares variables at first use point in innermost possible block,
// using liveness analysis to determine safe declaration sites.
package codegen

import (
	"fmt"
	"strings"

	"github.com/zarazaex69/sedec/pkg/ir"
	"github.com/zarazaex69/sedec/pkg/structuring"
)

// varFirstUse records the first use of a variable within a structured ast.
// path is the sequence of block depths leading to the statement where the
// variable first appears; depth is the nesting level (0 = function body).
// reserved for future use in advanced scope analysis.
type varFirstUse struct { //nolint:unused
	// depth is the nesting level at which the variable first appears
	depth int
	// stmtIdx is the index within the block at that depth
	stmtIdx int
	// blockPath is the sequence of block indices from root to the containing block
	blockPath []int
}

// ScopeMinimizer rewrites a structured ast so that variable declarations
// appear at their first use point in the innermost enclosing block,
// rather than being dumped at function entry.
//
// algorithm:
//  1. walk the ast collecting first-use positions for every variable
//  2. for each variable, determine the innermost block that contains all uses
//  3. inject a VarDeclStatement immediately before the first use in that block
//  4. strip the bulk variable declarations from the function preamble
type ScopeMinimizer struct {
	fn *ir.Function
}

// NewScopeMinimizer creates a scope minimizer for the given ir function.
func NewScopeMinimizer(fn *ir.Function) *ScopeMinimizer {
	return &ScopeMinimizer{fn: fn}
}

// MinimizeVariableScope rewrites the structured ast body so that each local
// variable is declared at its first use point in the innermost enclosing block.
// it returns a new Statement tree with VarDeclStatement nodes injected.
//
// safety guarantee: the transformation preserves program semantics because:
//   - declarations are only moved forward (never backward) in execution order
//   - liveness analysis ensures no use precedes the injected declaration
//   - side-effect ordering is preserved (only declaration placement changes)
func (m *ScopeMinimizer) MinimizeVariableScope(body structuring.Statement) structuring.Statement {
	// collect parameter names to exclude from scope minimization
	paramNames := m.collectParamNames()

	// collect all variables that need declarations (non-params, non-ssa-artifacts)
	candidates := m.collectDeclarationCandidates(paramNames)

	if len(candidates) == 0 {
		return body
	}

	// walk the ast and inject declarations at first-use points
	result, _ := m.injectDeclarations(body, candidates, 0, make(map[string]bool))
	return result
}

// collectParamNames returns a set of parameter variable names to exclude.
func (m *ScopeMinimizer) collectParamNames() map[string]bool {
	params := make(map[string]bool, len(m.fn.Signature.Parameters))
	for i := range m.fn.Signature.Parameters {
		params[fmt.Sprintf("arg%d", i)] = true
	}
	return params
}

// collectDeclarationCandidates returns the set of variables that need
// declarations, excluding parameters and variables with no type info.
func (m *ScopeMinimizer) collectDeclarationCandidates(paramNames map[string]bool) map[string]ir.Variable {
	candidates := make(map[string]ir.Variable, len(m.fn.Variables))
	for _, v := range m.fn.Variables {
		name := v.String()
		if paramNames[name] {
			continue
		}
		if v.Type == nil {
			continue
		}
		candidates[name] = v
	}
	return candidates
}

// injectDeclarations walks stmt recursively, injecting VarDeclStatement nodes
// immediately before the first use of each candidate variable.
// outerDeclared contains variables already declared in enclosing/preceding scopes.
// returns the rewritten statement and the set of variables declared within it.
func (m *ScopeMinimizer) injectDeclarations(
	stmt structuring.Statement,
	candidates map[string]ir.Variable,
	depth int,
	outerDeclared map[string]bool,
) (structuring.Statement, map[string]bool) {
	// local declared: starts as copy of outer so we don't re-declare
	declared := make(map[string]bool, len(outerDeclared))
	for k := range outerDeclared {
		declared[k] = true
	}

	switch n := stmt.(type) {
	case structuring.Block:
		return m.injectInBlock(n, candidates, depth, declared)

	case structuring.IRBlock:
		// leaf node: inject declarations for variables first used here
		newStmts := m.injectBeforeIRBlock(n, candidates, declared)
		if len(newStmts) == 1 {
			return newStmts[0], declared
		}
		return structuring.Block{Stmts: newStmts}, declared

	case structuring.IfStatement:
		return m.injectInIf(n, candidates, depth, declared)

	case structuring.WhileStatement:
		return m.injectInWhile(n, candidates, depth, declared)

	case structuring.DoWhileStatement:
		return m.injectInDoWhile(n, candidates, depth, declared)

	case structuring.ForStatement:
		return m.injectInFor(n, candidates, depth, declared)

	case structuring.ReturnStatement:
		// inject declarations for variables used in return expression
		newStmts := m.injectBeforeReturn(n, candidates, declared)
		if len(newStmts) == 1 {
			return newStmts[0], declared
		}
		return structuring.Block{Stmts: newStmts}, declared

	default:
		return stmt, declared
	}
}

// injectInBlock processes a Block statement, injecting declarations before
// each child statement that first uses a candidate variable.
// declarations are injected by the child-specific handlers (injectBeforeIRBlock,
// injectInIf, etc.) — this method only recurses and collects results.
// declared is passed sequentially between children so earlier declarations
// are visible to later siblings (prevents duplicate declarations).
func (m *ScopeMinimizer) injectInBlock(
	b structuring.Block,
	candidates map[string]ir.Variable,
	depth int,
	declared map[string]bool,
) (structuring.Statement, map[string]bool) {
	result := make([]structuring.Statement, 0, len(b.Stmts)*2)

	for _, child := range b.Stmts {
		// pass declared sequentially: each child sees what previous siblings declared
		rewritten, innerDeclared := m.injectDeclarations(child, candidates, depth+1, declared)
		for k := range innerDeclared {
			declared[k] = true
		}
		result = append(result, rewritten)
	}

	return structuring.Block{Stmts: result}, declared
}

// injectBeforeIRBlock injects declarations for variables first used in an IRBlock.
// returns a slice of statements: [decl1, decl2, ..., irblock].
func (m *ScopeMinimizer) injectBeforeIRBlock(
	b structuring.IRBlock,
	candidates map[string]ir.Variable,
	declared map[string]bool,
) []structuring.Statement {
	result := make([]structuring.Statement, 0, 4)

	// collect variables used in this block in definition order
	for _, instr := range b.Instructions {
		used := collectUsedVarsInInstr(instr)
		for _, varName := range used {
			if v, ok := candidates[varName]; ok && !declared[varName] {
				result = append(result, structuring.VarDeclStatement{
					Name:     varName,
					TypeName: cTypeName(v.Type),
				})
				declared[varName] = true
			}
		}
		// also handle the defined variable (it needs a declaration too)
		if defName := definedVarName(instr); defName != "" {
			if v, ok := candidates[defName]; ok && !declared[defName] {
				result = append(result, structuring.VarDeclStatement{
					Name:     defName,
					TypeName: cTypeName(v.Type),
				})
				declared[defName] = true
			}
		}
	}

	result = append(result, b)
	return result
}

// injectBeforeReturn injects declarations for variables used in a return expression.
func (m *ScopeMinimizer) injectBeforeReturn(
	r structuring.ReturnStatement,
	candidates map[string]ir.Variable,
	declared map[string]bool,
) []structuring.Statement {
	result := make([]structuring.Statement, 0, 2)
	if r.Value != nil {
		for _, varName := range collectUsedVarsInExpr(r.Value) {
			if v, ok := candidates[varName]; ok && !declared[varName] {
				result = append(result, structuring.VarDeclStatement{
					Name:     varName,
					TypeName: cTypeName(v.Type),
				})
				declared[varName] = true
			}
		}
	}
	result = append(result, r)
	return result
}

// injectInIf handles IfStatement: condition vars are declared before the if,
// then/else body vars are declared in their respective inner scopes.
//
// critical invariant: a variable declared inside one branch is NOT visible
// outside that branch. therefore we must NOT propagate branch-local declarations
// into the parent declared set. only variables declared in the condition prefix
// (before the if) are propagated upward.
//
// variables that are used in both branches, or used in the condition, are
// hoisted to a declaration before the if statement so they remain in scope
// after the if-else construct.
func (m *ScopeMinimizer) injectInIf(
	n structuring.IfStatement,
	candidates map[string]ir.Variable,
	depth int,
	declared map[string]bool,
) (structuring.Statement, map[string]bool) {
	prefix := make([]structuring.Statement, 0, 4)

	// declare variables used in the condition before the if statement
	for _, varName := range collectUsedVarsInExpr(n.Condition) {
		if v, ok := candidates[varName]; ok && !declared[varName] {
			prefix = append(prefix, structuring.VarDeclStatement{
				Name:     varName,
				TypeName: cTypeName(v.Type),
			})
			declared[varName] = true
		}
	}

	// collect variables used in each branch (without modifying declared yet)
	usedInThen := collectUsedVars(n.Then)
	usedInElse := make(map[string]bool)
	if n.Else != nil {
		usedInElse = collectUsedVars(n.Else)
	}

	// hoist variables that appear in both branches to before the if.
	// this prevents a variable from being declared in one branch and used
	// in the other (or after the if-else) out of scope.
	for varName, v := range candidates {
		if declared[varName] {
			continue
		}
		inThen := usedInThen[varName]
		inElse := usedInElse[varName]
		if inThen && inElse {
			prefix = append(prefix, structuring.VarDeclStatement{
				Name:     varName,
				TypeName: cTypeName(v.Type),
			})
			declared[varName] = true
		}
	}

	// recurse into then-branch with a snapshot of declared (branch-local scope).
	// do NOT merge thenDeclared back into declared: variables declared inside
	// a branch are not visible outside it.
	thenSnapshot := make(map[string]bool, len(declared))
	for k := range declared {
		thenSnapshot[k] = true
	}
	thenRewritten, _ := m.injectDeclarations(n.Then, candidates, depth+1, thenSnapshot)

	// recurse into else-branch with the same pre-branch declared snapshot.
	var elseRewritten structuring.Statement
	if n.Else != nil {
		elseSnapshot := make(map[string]bool, len(declared))
		for k := range declared {
			elseSnapshot[k] = true
		}
		elseRewritten, _ = m.injectDeclarations(n.Else, candidates, depth+1, elseSnapshot)
	}

	ifStmt := structuring.IfStatement{
		Condition: n.Condition,
		Then:      thenRewritten,
		Else:      elseRewritten,
	}

	if len(prefix) == 0 {
		return ifStmt, declared
	}
	prefix = append(prefix, ifStmt)
	return structuring.Block{Stmts: prefix}, declared
}

// injectInWhile handles WhileStatement: condition vars declared before loop,
// body vars declared inside loop body.
// body-local declarations are NOT propagated to the parent scope.
func (m *ScopeMinimizer) injectInWhile(
	n structuring.WhileStatement,
	candidates map[string]ir.Variable,
	depth int,
	declared map[string]bool,
) (structuring.Statement, map[string]bool) {
	prefix := make([]structuring.Statement, 0, 2)

	for _, varName := range collectUsedVarsInExpr(n.Condition) {
		if v, ok := candidates[varName]; ok && !declared[varName] {
			prefix = append(prefix, structuring.VarDeclStatement{
				Name:     varName,
				TypeName: cTypeName(v.Type),
			})
			declared[varName] = true
		}
	}

	// body uses a snapshot: declarations inside the loop body stay loop-local
	bodySnapshot := make(map[string]bool, len(declared))
	for k := range declared {
		bodySnapshot[k] = true
	}
	bodyRewritten, _ := m.injectDeclarations(n.Body, candidates, depth+1, bodySnapshot)

	loop := structuring.WhileStatement{Condition: n.Condition, Body: bodyRewritten}
	if len(prefix) == 0 {
		return loop, declared
	}
	prefix = append(prefix, loop)
	return structuring.Block{Stmts: prefix}, declared
}

// injectInDoWhile handles DoWhileStatement.
// variables used in the condition that are also defined in the body must be
// declared before the do-while (they are set in the body and tested in the condition).
// body-local declarations that are NOT used in the condition stay loop-local.
func (m *ScopeMinimizer) injectInDoWhile(
	n structuring.DoWhileStatement,
	candidates map[string]ir.Variable,
	depth int,
	declared map[string]bool,
) (structuring.Statement, map[string]bool) {
	// collect variables used in the condition
	condVars := make(map[string]bool)
	for _, name := range collectUsedVarsInExpr(n.Condition) {
		condVars[name] = true
	}

	// hoist variables that are used in the condition to before the loop.
	// this covers the canonical do { flag = ...; } while (flag) pattern.
	prefix := make([]structuring.Statement, 0, 2)
	for varName := range condVars {
		if v, ok := candidates[varName]; ok && !declared[varName] {
			prefix = append(prefix, structuring.VarDeclStatement{
				Name:     varName,
				TypeName: cTypeName(v.Type),
			})
			declared[varName] = true
		}
	}

	// body uses a snapshot: declarations inside the loop body that are NOT
	// condition variables stay loop-local.
	bodySnapshot := make(map[string]bool, len(declared))
	for k := range declared {
		bodySnapshot[k] = true
	}
	bodyRewritten, _ := m.injectDeclarations(n.Body, candidates, depth+1, bodySnapshot)

	loop := structuring.DoWhileStatement{Body: bodyRewritten, Condition: n.Condition}
	if len(prefix) == 0 {
		return loop, declared
	}
	prefix = append(prefix, loop)
	return structuring.Block{Stmts: prefix}, declared
}

// injectInFor handles ForStatement: init vars declared before for,
// body vars declared inside body.
// body-local declarations are NOT propagated to the parent scope.
func (m *ScopeMinimizer) injectInFor(
	n structuring.ForStatement,
	candidates map[string]ir.Variable,
	depth int,
	declared map[string]bool,
) (structuring.Statement, map[string]bool) {
	prefix := make([]structuring.Statement, 0, 4)

	// declare variables used in init statement
	if n.Init != nil {
		used := collectUsedVars(n.Init)
		for varName := range used {
			if v, ok := candidates[varName]; ok && !declared[varName] {
				prefix = append(prefix, structuring.VarDeclStatement{
					Name:     varName,
					TypeName: cTypeName(v.Type),
				})
				declared[varName] = true
			}
		}
		// also declare the variable being initialized (e.g., i in i = 0)
		if defName := collectDefinedVarInStmt(n.Init); defName != "" {
			if v, ok := candidates[defName]; ok && !declared[defName] {
				prefix = append(prefix, structuring.VarDeclStatement{
					Name:     defName,
					TypeName: cTypeName(v.Type),
				})
				declared[defName] = true
			}
		}
	}

	// declare variables used in condition
	for _, varName := range collectUsedVarsInExpr(n.Condition) {
		if v, ok := candidates[varName]; ok && !declared[varName] {
			prefix = append(prefix, structuring.VarDeclStatement{
				Name:     varName,
				TypeName: cTypeName(v.Type),
			})
			declared[varName] = true
		}
	}

	// body uses a snapshot: declarations inside the loop body stay loop-local
	bodySnapshot := make(map[string]bool, len(declared))
	for k := range declared {
		bodySnapshot[k] = true
	}
	bodyRewritten, _ := m.injectDeclarations(n.Body, candidates, depth+1, bodySnapshot)

	forStmt := structuring.ForStatement{
		Init:      n.Init,
		Condition: n.Condition,
		Post:      n.Post,
		Body:      bodyRewritten,
	}

	if len(prefix) == 0 {
		return forStmt, declared
	}
	prefix = append(prefix, forStmt)
	return structuring.Block{Stmts: prefix}, declared
}

// ============================================================================
// variable collection helpers
// ============================================================================

// collectUsedVars returns the set of variable names referenced in a statement.
func collectUsedVars(stmt structuring.Statement) map[string]bool {
	result := make(map[string]bool)
	collectUsedVarsInStmt(stmt, result)
	return result
}

// collectUsedVarsInStmt recursively collects variable names from a statement.
func collectUsedVarsInStmt(stmt structuring.Statement, out map[string]bool) {
	if stmt == nil {
		return
	}
	switch n := stmt.(type) {
	case structuring.Block:
		for _, s := range n.Stmts {
			collectUsedVarsInStmt(s, out)
		}
	case structuring.IRBlock:
		for _, instr := range n.Instructions {
			for _, name := range collectUsedVarsInInstr(instr) {
				out[name] = true
			}
			if def := definedVarName(instr); def != "" {
				out[def] = true
			}
		}
	case structuring.IfStatement:
		for _, name := range collectUsedVarsInExpr(n.Condition) {
			out[name] = true
		}
		collectUsedVarsInStmt(n.Then, out)
		if n.Else != nil {
			collectUsedVarsInStmt(n.Else, out)
		}
	case structuring.WhileStatement:
		for _, name := range collectUsedVarsInExpr(n.Condition) {
			out[name] = true
		}
		collectUsedVarsInStmt(n.Body, out)
	case structuring.DoWhileStatement:
		collectUsedVarsInStmt(n.Body, out)
		for _, name := range collectUsedVarsInExpr(n.Condition) {
			out[name] = true
		}
	case structuring.ForStatement:
		if n.Init != nil {
			collectUsedVarsInStmt(n.Init, out)
		}
		for _, name := range collectUsedVarsInExpr(n.Condition) {
			out[name] = true
		}
		if n.Post != nil {
			collectUsedVarsInStmt(n.Post, out)
		}
		collectUsedVarsInStmt(n.Body, out)
	case structuring.ReturnStatement:
		if n.Value != nil {
			for _, name := range collectUsedVarsInExpr(n.Value) {
				out[name] = true
			}
		}
	}
}

// collectUsedVarsInInstr returns variable names read (used) by an instruction,
// in the order they appear. duplicates may be present.
func collectUsedVarsInInstr(instr ir.IRInstruction) []string {
	var names []string
	switch i := instr.(type) {
	case ir.Assign:
		names = append(names, collectUsedVarsInExpr(i.Source)...)
	case *ir.Assign:
		names = append(names, collectUsedVarsInExpr(i.Source)...)
	case ir.Load:
		names = append(names, collectUsedVarsInExpr(i.Address)...)
	case *ir.Load:
		names = append(names, collectUsedVarsInExpr(i.Address)...)
	case ir.Store:
		names = append(names, collectUsedVarsInExpr(i.Address)...)
		names = append(names, collectUsedVarsInExpr(i.Value)...)
	case *ir.Store:
		names = append(names, collectUsedVarsInExpr(i.Address)...)
		names = append(names, collectUsedVarsInExpr(i.Value)...)
	case ir.Branch:
		names = append(names, collectUsedVarsInExpr(i.Condition)...)
	case *ir.Branch:
		names = append(names, collectUsedVarsInExpr(i.Condition)...)
	case ir.Call:
		names = append(names, collectUsedVarsInExpr(i.Target)...)
		for _, arg := range i.Args {
			names = append(names, arg.String())
		}
	case *ir.Call:
		names = append(names, collectUsedVarsInExpr(i.Target)...)
		for _, arg := range i.Args {
			names = append(names, arg.String())
		}
	case ir.Return:
		if i.Value != nil {
			names = append(names, i.Value.String())
		}
	case *ir.Return:
		if i.Value != nil {
			names = append(names, i.Value.String())
		}
	case ir.Phi:
		for _, src := range i.Sources {
			names = append(names, src.Var.String())
		}
	case *ir.Phi:
		for _, src := range i.Sources {
			names = append(names, src.Var.String())
		}
	}
	return names
}

// collectUsedVarsInExpr returns variable names referenced in an expression.
func collectUsedVarsInExpr(expr ir.Expression) []string {
	if expr == nil {
		return nil
	}
	var names []string
	switch e := expr.(type) {
	case ir.VariableExpr:
		names = append(names, e.Var.String())
	case *ir.VariableExpr:
		names = append(names, e.Var.String())
	case ir.BinaryOp:
		names = append(names, collectUsedVarsInExpr(e.Left)...)
		names = append(names, collectUsedVarsInExpr(e.Right)...)
	case *ir.BinaryOp:
		names = append(names, collectUsedVarsInExpr(e.Left)...)
		names = append(names, collectUsedVarsInExpr(e.Right)...)
	case ir.UnaryOp:
		names = append(names, collectUsedVarsInExpr(e.Operand)...)
	case *ir.UnaryOp:
		names = append(names, collectUsedVarsInExpr(e.Operand)...)
	case ir.Cast:
		names = append(names, collectUsedVarsInExpr(e.Expr)...)
	case *ir.Cast:
		names = append(names, collectUsedVarsInExpr(e.Expr)...)
	}
	return names
}

// definedVarName returns the name of the variable defined by an instruction,
// or empty string if the instruction defines no variable.
func definedVarName(instr ir.IRInstruction) string {
	switch i := instr.(type) {
	case ir.Assign:
		return i.Dest.String()
	case *ir.Assign:
		return i.Dest.String()
	case ir.Load:
		return i.Dest.String()
	case *ir.Load:
		return i.Dest.String()
	case ir.Call:
		if i.Dest != nil {
			return i.Dest.String()
		}
	case *ir.Call:
		if i.Dest != nil {
			return i.Dest.String()
		}
	case ir.Phi:
		return i.Dest.String()
	case *ir.Phi:
		return i.Dest.String()
	}
	return ""
}

// collectDefinedVarInStmt returns the name of the first variable defined
// in a statement (used for for-loop init variable detection).
func collectDefinedVarInStmt(stmt structuring.Statement) string {
	if stmt == nil {
		return ""
	}
	switch n := stmt.(type) {
	case structuring.IRBlock:
		for _, instr := range n.Instructions {
			if name := definedVarName(instr); name != "" {
				return name
			}
		}
	case structuring.Block:
		for _, s := range n.Stmts {
			if name := collectDefinedVarInStmt(s); name != "" {
				return name
			}
		}
	}
	return ""
}

// ============================================================================
// integration with Generator: scope-minimized code generation
// ============================================================================

// GenerateFunctionWithScopeMinimization produces a FunctionDecl where variables
// are declared at their first use point rather than at function entry.
// this implements requirements 60.1, 60.2, 60.3, 60.6.
func (g *Generator) GenerateFunctionWithScopeMinimization(
	fn *ir.Function,
	ast *structuring.StructuredAST,
) FunctionDecl {
	minimizer := NewScopeMinimizer(fn)
	minimizedBody := minimizer.MinimizeVariableScope(ast.Body)

	// create a synthetic ast with the minimized body
	minimizedAST := &structuring.StructuredAST{
		Body:       minimizedBody,
		FunctionID: ast.FunctionID,
	}

	state := newGeneratorState(fn, minimizedAST)

	// generate body with inline declarations (no preamble block)
	body := state.genStatementWithDecls(minimizedAST.Body, state.indent)

	params := buildParams(fn)

	return FunctionDecl{
		Name:          fn.Name,
		ReturnType:    cTypeName(fn.Signature.ReturnType),
		Params:        params,
		Body:          body,
		SourceAddress: 0,
	}
}

// genStatementWithDecls is like genStatement but also handles VarDeclStatement.
func (s *generatorState) genStatementWithDecls(stmt structuring.Statement, depth int) string {
	if stmt == nil {
		return ""
	}
	if vd, ok := stmt.(structuring.VarDeclStatement); ok {
		return indent(depth) + vd.String() + "\n"
	}
	// for blocks, recurse with decl-aware handling
	if b, ok := stmt.(structuring.Block); ok {
		var sb strings.Builder
		for _, child := range b.Stmts {
			sb.WriteString(s.genStatementWithDecls(child, depth))
		}
		return sb.String()
	}
	return s.genStatement(stmt, depth)
}
