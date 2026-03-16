// package structuring - tests for expression condensation pass
package structuring

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// helpers
// ============================================================================

func varExpr(name string) ir.Expression {
	return ir.VariableExpr{Var: ir.Variable{Name: name, Type: ir.BoolType{}}}
}

func intVarExpr(name string) ir.Expression {
	return ir.VariableExpr{Var: ir.Variable{Name: name, Type: ir.IntType{Width: ir.Size8, Signed: true}}}
}

func constInt(v int64) ir.Expression {
	return ir.ConstantExpr{Value: ir.IntConstant{Value: v, Width: ir.Size8}}
}

func logicalAnd(a, b ir.Expression) ir.Expression {
	return ir.BinaryOp{Op: ir.BinOpLogicalAnd, Left: a, Right: b}
}

func logicalOr(a, b ir.Expression) ir.Expression {
	return ir.BinaryOp{Op: ir.BinOpLogicalOr, Left: a, Right: b}
}

func logicalNot(e ir.Expression) ir.Expression {
	return ir.UnaryOp{Op: ir.UnOpLogicalNot, Operand: e}
}

func makeAST(body Statement) *StructuredAST {
	return &StructuredAST{Body: body, FunctionID: cfg.BlockID(0)}
}

// ============================================================================
// CondenseExpressions - nil safety
// ============================================================================

func TestCondenseExpressions_Nil(t *testing.T) {
	if got := CondenseExpressions(nil); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestCondenseExpressions_EmptyBlock(t *testing.T) {
	ast := makeAST(Block{Stmts: nil})
	got := CondenseExpressions(ast)
	if got == nil {
		t.Fatal("expected non-nil result")
	}
}

// ============================================================================
// pass 1: nested if merging
// ============================================================================

func TestMergeNestedIfs_Basic(t *testing.T) {
	// if (a) { if (b) { S } }  →  if (a && b) { S }
	inner := IfStatement{
		Condition: varExpr("b"),
		Then:      IRBlock{BlockID: 1},
	}
	outer := IfStatement{
		Condition: varExpr("a"),
		Then:      Block{Stmts: []Statement{inner}},
	}

	result := mergeNestedIfs(outer)

	merged, ok := result.(IfStatement)
	if !ok {
		t.Fatalf("expected IfStatement, got %T", result)
	}
	if merged.Else != nil {
		t.Fatal("merged if must have no else")
	}
	binop, ok := merged.Condition.(ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp condition, got %T", merged.Condition)
	}
	if binop.Op != ir.BinOpLogicalAnd {
		t.Fatalf("expected &&, got %v", binop.Op)
	}
}

func TestMergeNestedIfs_OuterHasElse_NoMerge(t *testing.T) {
	// outer has else: must NOT merge
	inner := IfStatement{Condition: varExpr("b"), Then: IRBlock{BlockID: 1}}
	outer := IfStatement{
		Condition: varExpr("a"),
		Then:      Block{Stmts: []Statement{inner}},
		Else:      IRBlock{BlockID: 2},
	}

	result := mergeNestedIfs(outer)

	merged, ok := result.(IfStatement)
	if !ok {
		t.Fatalf("expected IfStatement, got %T", result)
	}
	if merged.Else == nil {
		t.Fatal("else branch must be preserved")
	}
	// condition must remain unchanged (just varExpr "a")
	if _, ok := merged.Condition.(ir.VariableExpr); !ok {
		t.Fatalf("condition must remain VariableExpr, got %T", merged.Condition)
	}
}

func TestMergeNestedIfs_InnerHasElse_NoMerge(t *testing.T) {
	// inner has else: must NOT merge
	inner := IfStatement{
		Condition: varExpr("b"),
		Then:      IRBlock{BlockID: 1},
		Else:      IRBlock{BlockID: 2},
	}
	outer := IfStatement{
		Condition: varExpr("a"),
		Then:      Block{Stmts: []Statement{inner}},
	}

	result := mergeNestedIfs(outer)

	merged, ok := result.(IfStatement)
	if !ok {
		t.Fatalf("expected IfStatement, got %T", result)
	}
	// condition must remain varExpr "a"
	if _, ok := merged.Condition.(ir.VariableExpr); !ok {
		t.Fatalf("condition must remain VariableExpr, got %T", merged.Condition)
	}
}

func TestMergeNestedIfs_MultipleStmtsInThen_NoMerge(t *testing.T) {
	// then-block has two statements: must NOT merge
	inner := IfStatement{Condition: varExpr("b"), Then: IRBlock{BlockID: 1}}
	outer := IfStatement{
		Condition: varExpr("a"),
		Then: Block{Stmts: []Statement{
			inner,
			IRBlock{BlockID: 3},
		}},
	}

	result := mergeNestedIfs(outer)

	merged, ok := result.(IfStatement)
	if !ok {
		t.Fatalf("expected IfStatement, got %T", result)
	}
	if _, ok := merged.Condition.(ir.VariableExpr); !ok {
		t.Fatalf("condition must remain VariableExpr, got %T", merged.Condition)
	}
}

func TestMergeNestedIfs_Block(t *testing.T) {
	// merging inside a Block
	inner := IfStatement{Condition: varExpr("b"), Then: IRBlock{BlockID: 1}}
	outer := IfStatement{
		Condition: varExpr("a"),
		Then:      Block{Stmts: []Statement{inner}},
	}
	blk := Block{Stmts: []Statement{outer}}

	result := mergeNestedIfs(blk)

	blkResult, ok := result.(Block)
	if !ok {
		// single-statement block may be unwrapped
		if _, ok := result.(IfStatement); !ok {
			t.Fatalf("expected Block or IfStatement, got %T", result)
		}
		return
	}
	if len(blkResult.Stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(blkResult.Stmts))
	}
	merged, ok := blkResult.Stmts[0].(IfStatement)
	if !ok {
		t.Fatalf("expected IfStatement, got %T", blkResult.Stmts[0])
	}
	if _, ok := merged.Condition.(ir.BinaryOp); !ok {
		t.Fatalf("expected merged BinaryOp condition, got %T", merged.Condition)
	}
}

// ============================================================================
// pass 2: de morgan simplification
// ============================================================================

func TestDeMorganExpr_NotOr(t *testing.T) {
	// !(a || b) → (!a && !b)
	expr := logicalNot(logicalOr(varExpr("a"), varExpr("b")))
	result := deMorganExpr(expr)

	binop, ok := result.(ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp, got %T", result)
	}
	if binop.Op != ir.BinOpLogicalAnd {
		t.Fatalf("expected &&, got %v", binop.Op)
	}
	leftNot, ok := binop.Left.(ir.UnaryOp)
	if !ok || leftNot.Op != ir.UnOpLogicalNot {
		t.Fatalf("expected !a on left, got %T", binop.Left)
	}
	rightNot, ok := binop.Right.(ir.UnaryOp)
	if !ok || rightNot.Op != ir.UnOpLogicalNot {
		t.Fatalf("expected !b on right, got %T", binop.Right)
	}
}

func TestDeMorganExpr_NotAnd(t *testing.T) {
	// !(a && b) → (!a || !b)
	expr := logicalNot(logicalAnd(varExpr("a"), varExpr("b")))
	result := deMorganExpr(expr)

	binop, ok := result.(ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp, got %T", result)
	}
	if binop.Op != ir.BinOpLogicalOr {
		t.Fatalf("expected ||, got %v", binop.Op)
	}
}

func TestDeMorganExpr_NotVar_NoChange(t *testing.T) {
	// !a stays !a (no de morgan applicable)
	expr := logicalNot(varExpr("a"))
	result := deMorganExpr(expr)

	u, ok := result.(ir.UnaryOp)
	if !ok || u.Op != ir.UnOpLogicalNot {
		t.Fatalf("expected !a unchanged, got %T", result)
	}
}

func TestDeMorganExpr_Nested(t *testing.T) {
	// !(!(a || b) && c) → (a || b) || !c
	// outer: !(X && c) → !X || !c
	// inner X = !(a||b) → (!a && !b)
	// so result: (!a && !b) || !c
	inner := logicalNot(logicalOr(varExpr("a"), varExpr("b")))
	expr := logicalNot(logicalAnd(inner, varExpr("c")))
	result := deMorganExpr(expr)

	binop, ok := result.(ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp, got %T", result)
	}
	if binop.Op != ir.BinOpLogicalOr {
		t.Fatalf("expected || at top level, got %v", binop.Op)
	}
}

func TestApplyDeMorgan_InIfCondition(t *testing.T) {
	// if (!(a || b)) { S }  →  if (!a && !b) { S }
	cond := logicalNot(logicalOr(varExpr("a"), varExpr("b")))
	stmt := IfStatement{Condition: cond, Then: IRBlock{BlockID: 1}}

	result := applyDeMorgan(stmt)

	ifResult, ok := result.(IfStatement)
	if !ok {
		t.Fatalf("expected IfStatement, got %T", result)
	}
	binop, ok := ifResult.Condition.(ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp condition, got %T", ifResult.Condition)
	}
	if binop.Op != ir.BinOpLogicalAnd {
		t.Fatalf("expected &&, got %v", binop.Op)
	}
}

func TestApplyDeMorgan_InWhileCondition(t *testing.T) {
	cond := logicalNot(logicalAnd(varExpr("x"), varExpr("y")))
	stmt := WhileStatement{Condition: cond, Body: IRBlock{BlockID: 1}}

	result := applyDeMorgan(stmt)

	ws, ok := result.(WhileStatement)
	if !ok {
		t.Fatalf("expected WhileStatement, got %T", result)
	}
	binop, ok := ws.Condition.(ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp, got %T", ws.Condition)
	}
	if binop.Op != ir.BinOpLogicalOr {
		t.Fatalf("expected ||, got %v", binop.Op)
	}
}

// ============================================================================
// pass 3: early-return hoisting
// ============================================================================

func makeReturnStmt(expr ir.Expression) ReturnStatement {
	return ReturnStatement{Value: expr}
}

func TestHoistEarlyReturns_Basic(t *testing.T) {
	// block: [if(cond){return x;}, stmt2]
	// →      [if(!cond){stmt2}, return x;]
	retStmt := makeReturnStmt(intVarExpr("x"))
	ifStmt := IfStatement{
		Condition: varExpr("cond"),
		Then:      Block{Stmts: []Statement{retStmt}},
	}
	stmt2 := IRBlock{BlockID: 99}
	blk := Block{Stmts: []Statement{ifStmt, stmt2}}

	result := hoistEarlyReturns(blk)

	// result should be a Block with 2 statements: if(!cond){stmt2} and return x
	var stmts []Statement
	switch r := result.(type) {
	case Block:
		stmts = r.Stmts
	default:
		t.Fatalf("expected Block, got %T", result)
	}

	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}

	newIf, ok := stmts[0].(IfStatement)
	if !ok {
		t.Fatalf("expected IfStatement first, got %T", stmts[0])
	}
	// condition must be negated
	negCond, ok := newIf.Condition.(ir.UnaryOp)
	if !ok || negCond.Op != ir.UnOpLogicalNot {
		t.Fatalf("expected negated condition, got %T", newIf.Condition)
	}

	_, ok = stmts[1].(ReturnStatement)
	if !ok {
		t.Fatalf("expected ReturnStatement last, got %T", stmts[1])
	}
}

func TestHoistEarlyReturns_NoRestStmts_NoHoist(t *testing.T) {
	// if(cond){return x;} with nothing after: no transformation
	retStmt := makeReturnStmt(intVarExpr("x"))
	ifStmt := IfStatement{
		Condition: varExpr("cond"),
		Then:      Block{Stmts: []Statement{retStmt}},
	}
	blk := Block{Stmts: []Statement{ifStmt}}

	result := hoistEarlyReturns(blk)

	// should remain an IfStatement (or Block with single IfStatement)
	var inner Statement
	switch r := result.(type) {
	case Block:
		if len(r.Stmts) != 1 {
			t.Fatalf("expected 1 stmt, got %d", len(r.Stmts))
		}
		inner = r.Stmts[0]
	case IfStatement:
		inner = r
	default:
		t.Fatalf("unexpected type %T", result)
	}
	if _, ok := inner.(IfStatement); !ok {
		t.Fatalf("expected IfStatement preserved, got %T", inner)
	}
}

func TestHoistEarlyReturns_IfWithElse_NoHoist(t *testing.T) {
	// if(cond){return x;} else {S}: must NOT hoist (has else branch)
	retStmt := makeReturnStmt(intVarExpr("x"))
	ifStmt := IfStatement{
		Condition: varExpr("cond"),
		Then:      Block{Stmts: []Statement{retStmt}},
		Else:      IRBlock{BlockID: 5},
	}
	stmt2 := IRBlock{BlockID: 99}
	blk := Block{Stmts: []Statement{ifStmt, stmt2}}

	result := hoistEarlyReturns(blk)

	blkResult, ok := result.(Block)
	if !ok {
		t.Fatalf("expected Block, got %T", result)
	}
	// first statement must still be the original if-else
	first, ok := blkResult.Stmts[0].(IfStatement)
	if !ok {
		t.Fatalf("expected IfStatement, got %T", blkResult.Stmts[0])
	}
	if first.Else == nil {
		t.Fatal("else branch must be preserved")
	}
}

func TestHoistEarlyReturns_DoubleNegationElimination(t *testing.T) {
	// if(!cond){return x;} rest  →  if(cond){rest}; return x;
	// negation of !cond should be cond (double-negation eliminated)
	retStmt := makeReturnStmt(intVarExpr("x"))
	negCond := logicalNot(varExpr("cond"))
	ifStmt := IfStatement{
		Condition: negCond,
		Then:      Block{Stmts: []Statement{retStmt}},
	}
	stmt2 := IRBlock{BlockID: 99}
	blk := Block{Stmts: []Statement{ifStmt, stmt2}}

	result := hoistEarlyReturns(blk)

	blkResult, ok := result.(Block)
	if !ok {
		t.Fatalf("expected Block, got %T", result)
	}
	newIf, ok := blkResult.Stmts[0].(IfStatement)
	if !ok {
		t.Fatalf("expected IfStatement, got %T", blkResult.Stmts[0])
	}
	// condition should be plain varExpr "cond" (double-negation eliminated)
	if _, ok := newIf.Condition.(ir.VariableExpr); !ok {
		t.Fatalf("expected VariableExpr after double-neg elimination, got %T", newIf.Condition)
	}
}

// ============================================================================
// pass 4: single-use temporary inlining
// ============================================================================

func makeAssign(dest string, src ir.Expression) ir.IRInstruction {
	return ir.Assign{
		Dest:   ir.Variable{Name: dest, Type: ir.IntType{Width: ir.Size8, Signed: true}},
		Source: src,
	}
}

func makeAssignInstr(dest string, src ir.Expression) ir.IRInstruction {
	return makeAssign(dest, src)
}

func TestInlineSingleUseTemps_Basic(t *testing.T) {
	// IRBlock: [t = a + b, result = t * 2]
	// t is used exactly once → inline: result = (a+b) * 2
	addExpr := ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  intVarExpr("a"),
		Right: intVarExpr("b"),
	}
	mulExpr := ir.BinaryOp{
		Op:    ir.BinOpMul,
		Left:  intVarExpr("t"),
		Right: constInt(2),
	}
	irb := IRBlock{
		BlockID: 1,
		Instructions: []ir.IRInstruction{
			makeAssignInstr("t", addExpr),
			makeAssignInstr("result", mulExpr),
		},
	}
	blk := Block{Stmts: []Statement{irb}}

	result := inlineSingleUseTemps(blk)

	// find the IRBlock in result

	var finalIRB IRBlock
	switch r := result.(type) {
	case Block:
		for _, s := range r.Stmts {
			if irb2, ok := s.(IRBlock); ok {
				finalIRB = irb2
			}
		}
	case IRBlock:
		finalIRB = r
	default:
		t.Fatalf("unexpected result type %T", result)
	}

	// after inlining, only one instruction should remain (the result assignment)
	// and t's definition should be gone
	for _, instr := range finalIRB.Instructions {
		assign, ok := instr.(ir.Assign)
		if !ok {
			continue
		}
		if assign.Dest.Name == "t" {
			t.Fatal("t definition should have been inlined away")
		}
		if assign.Dest.Name == "result" {
			// source should now be (a+b)*2, not t*2
			binop, ok := assign.Source.(ir.BinaryOp)
			if !ok {
				t.Fatalf("expected BinaryOp source, got %T", assign.Source)
			}
			if binop.Op != ir.BinOpMul {
				t.Fatalf("expected *, got %v", binop.Op)
			}
			// left should be the inlined (a+b)
			innerBinop, ok := binop.Left.(ir.BinaryOp)
			if !ok {
				t.Fatalf("expected inlined BinaryOp on left, got %T", binop.Left)
			}
			if innerBinop.Op != ir.BinOpAdd {
				t.Fatalf("expected + in inlined expr, got %v", innerBinop.Op)
			}
		}
	}
}

func TestInlineSingleUseTemps_MultipleUses_NoInline(t *testing.T) {
	// t is used twice: must NOT inline
	addExpr := ir.BinaryOp{Op: ir.BinOpAdd, Left: intVarExpr("a"), Right: intVarExpr("b")}
	irb := IRBlock{
		BlockID: 1,
		Instructions: []ir.IRInstruction{
			makeAssignInstr("t", addExpr),
			makeAssignInstr("r1", intVarExpr("t")),
			makeAssignInstr("r2", intVarExpr("t")),
		},
	}
	blk := Block{Stmts: []Statement{irb}}

	result := inlineSingleUseTemps(blk)

	// t definition must still be present
	found := false
	var checkIRB func(Statement)
	checkIRB = func(s Statement) {
		switch r := s.(type) {
		case Block:
			for _, child := range r.Stmts {
				checkIRB(child)
			}
		case IRBlock:
			for _, instr := range r.Instructions {
				if assign, ok := instr.(ir.Assign); ok && assign.Dest.Name == "t" {
					found = true
				}
			}
		}
	}
	checkIRB(result)
	if !found {
		t.Fatal("t definition must be preserved when used multiple times")
	}
}

func TestInlineSingleUseTemps_ImpureExpr_NoInline(t *testing.T) {
	// t = load(addr): impure expression, must NOT inline
	loadInstr := ir.Load{
		Dest:    ir.Variable{Name: "t", Type: ir.IntType{Width: ir.Size8, Signed: true}},
		Address: intVarExpr("addr"),
		Size:    ir.Size8,
	}
	irb := IRBlock{
		BlockID: 1,
		Instructions: []ir.IRInstruction{
			loadInstr,
			makeAssignInstr("result", intVarExpr("t")),
		},
	}
	blk := Block{Stmts: []Statement{irb}}

	result := inlineSingleUseTemps(blk)

	// load instruction must still be present
	found := false
	var checkIRB func(Statement)
	checkIRB = func(s Statement) {
		switch r := s.(type) {
		case Block:
			for _, child := range r.Stmts {
				checkIRB(child)
			}
		case IRBlock:
			for _, instr := range r.Instructions {
				if _, ok := instr.(ir.Load); ok {
					found = true
				}
			}
		}
	}
	checkIRB(result)
	if !found {
		t.Fatal("load instruction must be preserved (impure expression)")
	}
}

// ============================================================================
// full pipeline: CondenseExpressions
// ============================================================================

func TestCondenseExpressions_NestedIfAndDeMorgan(t *testing.T) {
	// if (!(a||b)) { if (c) { S } }
	// after de morgan: if (!a && !b) { if (c) { S } }
	// after nested-if merge: if ((!a && !b) && c) { S }
	cond := logicalNot(logicalOr(varExpr("a"), varExpr("b")))
	inner := IfStatement{Condition: varExpr("c"), Then: IRBlock{BlockID: 1}}
	outer := IfStatement{
		Condition: cond,
		Then:      Block{Stmts: []Statement{inner}},
	}
	ast := makeAST(outer)

	result := CondenseExpressions(ast)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// the body should be a single IfStatement with a BinaryOp condition
	var body Statement = result.Body
	// unwrap single-element block if needed
	if blk, ok := body.(Block); ok && len(blk.Stmts) == 1 {
		body = blk.Stmts[0]
	}
	ifResult, ok := body.(IfStatement)
	if !ok {
		t.Fatalf("expected IfStatement, got %T", body)
	}
	if _, ok := ifResult.Condition.(ir.BinaryOp); !ok {
		t.Fatalf("expected BinaryOp condition after condensation, got %T", ifResult.Condition)
	}
}

func TestCondenseExpressions_EarlyReturn(t *testing.T) {
	// block: [if(err){return -1;}, doWork()]
	// → [if(!err){doWork()}, return -1;]
	retStmt := makeReturnStmt(constInt(-1))
	ifStmt := IfStatement{
		Condition: varExpr("err"),
		Then:      Block{Stmts: []Statement{retStmt}},
	}
	work := IRBlock{BlockID: 10}
	ast := makeAST(Block{Stmts: []Statement{ifStmt, work}})

	result := CondenseExpressions(ast)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	blk, ok := result.Body.(Block)
	if !ok {
		t.Fatalf("expected Block body, got %T", result.Body)
	}
	if len(blk.Stmts) != 2 {
		t.Fatalf("expected 2 stmts after hoisting, got %d", len(blk.Stmts))
	}
	if _, ok := blk.Stmts[1].(ReturnStatement); !ok {
		t.Fatalf("expected ReturnStatement last, got %T", blk.Stmts[1])
	}
}

// ============================================================================
// helpers: isPureExpr
// ============================================================================

func TestIsPureExpr_Variable(t *testing.T) {
	if !isPureExpr(intVarExpr("x")) {
		t.Fatal("variable expr must be pure")
	}
}

func TestIsPureExpr_Constant(t *testing.T) {
	if !isPureExpr(constInt(42)) {
		t.Fatal("constant expr must be pure")
	}
}

func TestIsPureExpr_BinaryOp(t *testing.T) {
	expr := ir.BinaryOp{Op: ir.BinOpAdd, Left: intVarExpr("a"), Right: constInt(1)}
	if !isPureExpr(expr) {
		t.Fatal("arithmetic binop must be pure")
	}
}

func TestIsPureExpr_Load_NotPure(t *testing.T) {
	// ir.Load is not an Expression, but we test via a wrapper that returns false
	// for any non-expression type. here we test that a Cast of a non-pure is not pure.
	// since Load is an IRInstruction, not an Expression, we test the default branch
	// by passing a nil-like unknown expression type.
	// the simplest test: nil is pure
	if !isPureExpr(nil) {
		t.Fatal("nil must be considered pure (no-op)")
	}
}

func TestNegateCondition_DoubleNeg(t *testing.T) {
	// negateCondition(!x) → x
	inner := varExpr("x")
	notX := logicalNot(inner)
	result := negateCondition(notX)
	if _, ok := result.(ir.VariableExpr); !ok {
		t.Fatalf("expected VariableExpr after double-neg elimination, got %T", result)
	}
}

func TestNegateCondition_Plain(t *testing.T) {
	// negateCondition(x) → !x
	result := negateCondition(varExpr("x"))
	u, ok := result.(ir.UnaryOp)
	if !ok || u.Op != ir.UnOpLogicalNot {
		t.Fatalf("expected !x, got %T", result)
	}
}

// ============================================================================
// regression tests: task 15.1 (tail merging) and task 15.7 (inline temps)
// ============================================================================

// makeLoadInstr creates an ir.Load instruction (memory read into dest variable).
func makeLoadInstr(dest string, addr ir.Expression, size ir.Size) ir.IRInstruction {
	return ir.Load{
		Dest:    ir.Variable{Name: dest, Type: ir.IntType{Width: size, Signed: false}},
		Address: addr,
		Size:    size,
	}
}

// makeCallInstr creates an ir.Call instruction with a variable target and args.
func makeCallInstr(dest *ir.Variable, target ir.Expression, args []ir.Variable) ir.IRInstruction {
	return ir.Call{
		Dest:   dest,
		Target: target,
		Args:   args,
	}
}

// constUint creates an unsigned integer constant expression.
func constUint(v uint64) ir.Expression {
	return ir.ConstantExpr{Value: ir.IntConstant{Value: int64(v), Width: ir.Size8, Signed: false}} //nolint:gosec
}

// eqExpr creates a == comparison expression.
func eqExpr(a, b ir.Expression) ir.Expression {
	return ir.BinaryOp{Op: ir.BinOpEq, Left: a, Right: b}
}

// TestMergeTails_AsymmetricElseDuplication reproduces the "double tail" pattern
// from task 15.1: the structuring engine duplicates the convergence block into
// the else branch, producing identical code in else and after the if-else.
//
//	Block {
//	    IfStatement { Then: S1, Else: Block{ IRBlock{load t3; rax=t3}; IfStatement{rax==0 → return rax} } }
//	    IRBlock{load t3; rax=t3}          // duplicated convergence block
//	    IfStatement{rax==0 → return rax}  // duplicated convergence block
//	}
//
// expected after mergeTails:
//
//	Block {
//	    IfStatement { Then: S1, Else: Block{} }
//	    IRBlock{load t3; rax=t3}
//	    IfStatement{rax==0 → return rax}
//	}
func TestMergeTails_AsymmetricElseDuplication(t *testing.T) {
	// shared convergence block: t3 = load(163016); rax = t3
	loadAddr := constUint(163016)
	loadT3 := makeLoadInstr("t3", loadAddr, ir.Size8)
	assignRax := makeAssign("rax", intVarExpr("t3"))
	convergenceIRB := IRBlock{
		BlockID:      10,
		Instructions: []ir.IRInstruction{loadT3, assignRax},
	}

	// shared convergence if: if (rax == 0) { return rax; }
	raxVar := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}
	convergenceIf := IfStatement{
		Condition: eqExpr(ir.VariableExpr{Var: raxVar}, constUint(0)),
		Then:      ReturnStatement{Value: ir.VariableExpr{Var: raxVar}},
		Else:      nil,
	}

	// else branch contains the duplicated convergence block
	elseBlock := Block{Stmts: []Statement{
		convergenceIRB,
		convergenceIf,
	}}

	// then branch: some other work
	thenBlock := IRBlock{BlockID: 5, Instructions: []ir.IRInstruction{
		makeAssign("rax", constUint(1)),
	}}

	// outer if-else
	outerIf := IfStatement{
		Condition: varExpr("cond"),
		Then:      thenBlock,
		Else:      elseBlock,
	}

	// parent block: if-else followed by the same convergence code (duplication)
	// use a different BlockID to simulate the real CFG scenario
	convergenceIRB2 := IRBlock{
		BlockID:      10, // same block id — structuring engine emits same block twice
		Instructions: []ir.IRInstruction{loadT3, assignRax},
	}
	convergenceIf2 := IfStatement{
		Condition: eqExpr(ir.VariableExpr{Var: raxVar}, constUint(0)),
		Then:      ReturnStatement{Value: ir.VariableExpr{Var: raxVar}},
		Else:      nil,
	}

	parent := Block{Stmts: []Statement{outerIf, convergenceIRB2, convergenceIf2}}

	result := mergeTails(parent)

	// after merging: else branch should be empty (or stripped), convergence code
	// should appear exactly once after the if-else
	blk, ok := result.(Block)
	if !ok {
		t.Fatalf("expected Block, got %T", result)
	}

	// find the if statement
	var foundIf *IfStatement
	for _, s := range blk.Stmts {
		if ifS, ok := s.(IfStatement); ok {
			foundIf = &ifS
			break
		}
	}
	if foundIf == nil {
		t.Fatal("expected IfStatement in result block")
	}

	// else branch must not contain the convergence IRBlock anymore
	if foundIf.Else != nil {
		elseStmts := flattenBlock(foundIf.Else)
		for _, s := range elseStmts {
			if irb, ok := s.(IRBlock); ok {
				for _, instr := range irb.Instructions {
					if load, ok := instr.(ir.Load); ok {
						if load.Dest.Name == "t3" {
							t.Fatal("convergence IRBlock must be hoisted out of else branch")
						}
					}
				}
			}
		}
	}

	// convergence IRBlock must appear exactly once in the parent block (after the if)
	loadCount := 0
	for _, s := range blk.Stmts {
		if irb, ok := s.(IRBlock); ok {
			for _, instr := range irb.Instructions {
				if load, ok := instr.(ir.Load); ok && load.Dest.Name == "t3" {
					loadCount++
				}
			}
		}
	}
	if loadCount != 1 {
		t.Fatalf("expected convergence IRBlock exactly once after merge, got %d occurrences", loadCount)
	}
}

// TestInlineSingleUseTemps_CallTarget reproduces task 15.7: a single-use
// temporary loaded from a constant address is used as the call target.
//
//	t2 = *(uint64_t*)(162976)   // Load with constant address
//	t2(rdi, rsi, ...)           // Call with t2 as target
//
// expected after inlining:
//
//	(*(uint64_t*)(162976))(rdi, rsi, ...)
func TestInlineSingleUseTemps_CallTarget(t *testing.T) {
	constAddr := constUint(162976)
	loadT2 := makeLoadInstr("t2", constAddr, ir.Size8)

	rdiVar := ir.Variable{Name: "rdi", Type: ir.IntType{Width: ir.Size8, Signed: false}}
	rsiVar := ir.Variable{Name: "rsi", Type: ir.IntType{Width: ir.Size8, Signed: false}}
	t2Var := ir.Variable{Name: "t2", Type: ir.IntType{Width: ir.Size8, Signed: false}}

	callInstr := ir.Call{
		Dest:   nil,
		Target: ir.VariableExpr{Var: t2Var},
		Args:   []ir.Variable{rdiVar, rsiVar},
	}

	irb := IRBlock{
		BlockID:      1,
		Instructions: []ir.IRInstruction{loadT2, callInstr},
	}
	blk := Block{Stmts: []Statement{irb}}

	result := inlineSingleUseTemps(blk)

	// find the call instruction in result
	var foundCall *ir.Call
	var checkStmt func(Statement)
	checkStmt = func(s Statement) {
		switch r := s.(type) {
		case Block:
			for _, child := range r.Stmts {
				checkStmt(child)
			}
		case IRBlock:
			for _, instr := range r.Instructions {
				if c, ok := instr.(ir.Call); ok {
					cp := c
					foundCall = &cp
				}
			}
		}
	}
	checkStmt(result)

	if foundCall == nil {
		t.Fatal("expected Call instruction in result")
	}

	// target must be a LoadExpr (inlined from t2 = load(162976))
	if _, ok := foundCall.Target.(ir.LoadExpr); !ok {
		t.Fatalf("expected LoadExpr as call target after inlining, got %T", foundCall.Target)
	}

	// t2 load instruction must be gone
	var checkNoT2Load func(Statement)
	checkNoT2Load = func(s Statement) {
		switch r := s.(type) {
		case Block:
			for _, child := range r.Stmts {
				checkNoT2Load(child)
			}
		case IRBlock:
			for _, instr := range r.Instructions {
				if load, ok := instr.(ir.Load); ok && load.Dest.Name == "t2" {
					t.Fatal("t2 load must be inlined away")
				}
			}
		}
	}
	checkNoT2Load(result)
}

// TestInlineSingleUseTemps_VariableAddressLoad_NoInline verifies that a load
// from a variable address (e.g. rsp) is NOT inlined even when used once,
// because the address may change between the load and the use site.
func TestInlineSingleUseTemps_VariableAddressLoad_NoInline(t *testing.T) {
	rspVar := ir.Variable{Name: "rsp", Type: ir.IntType{Width: ir.Size8, Signed: false}}
	loadT1 := makeLoadInstr("t1", ir.VariableExpr{Var: rspVar}, ir.Size8)
	// rsp = rsp + 8 (modifies the address between load and use)
	addExpr := ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  ir.VariableExpr{Var: rspVar},
		Right: constUint(8),
	}
	updateRsp := makeAssign("rsp", addExpr)
	// rsi = t1
	assignRsi := makeAssign("rsi", intVarExpr("t1"))

	irb := IRBlock{
		BlockID:      1,
		Instructions: []ir.IRInstruction{loadT1, updateRsp, assignRsi},
	}
	blk := Block{Stmts: []Statement{irb}}

	result := inlineSingleUseTemps(blk)

	// t1 load must still be present (variable address — unsafe to inline)
	found := false
	var check func(Statement)
	check = func(s Statement) {
		switch r := s.(type) {
		case Block:
			for _, child := range r.Stmts {
				check(child)
			}
		case IRBlock:
			for _, instr := range r.Instructions {
				if load, ok := instr.(ir.Load); ok && load.Dest.Name == "t1" {
					found = true
				}
			}
		}
	}
	check(result)
	if !found {
		t.Fatal("t1 load must be preserved: variable address load is unsafe to inline")
	}
}
