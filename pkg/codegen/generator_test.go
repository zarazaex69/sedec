package codegen

import (
	"strings"
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
	"github.com/zarazaex69/sedec/pkg/structuring"
)

// ============================================================================
// helpers
// ============================================================================

// makeIntVar creates a signed 64-bit ir variable
func makeIntVar(name string) ir.Variable {
	return ir.Variable{Name: name, Type: ir.IntType{Width: ir.Size8, Signed: true}}
}

// makeUintVar creates an unsigned 32-bit ir variable
func makeUintVar(name string) ir.Variable {
	return ir.Variable{Name: name, Type: ir.IntType{Width: ir.Size4, Signed: false}}
}

// simpleFn builds a minimal ir.Function with the given name, return type, and variables
func simpleFn(name string, ret ir.Type, vars []ir.Variable) *ir.Function {
	sig := ir.FunctionType{ReturnType: ret, Parameters: nil}
	return &ir.Function{
		Name:       name,
		Signature:  sig,
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
		EntryBlock: 0,
		Variables:  vars,
	}
}

// ============================================================================
// cTypeName tests
// ============================================================================

func TestCTypeName_Primitives(t *testing.T) {
	cases := []struct {
		typ  ir.Type
		want string
	}{
		{ir.VoidType{}, "void"},
		{ir.BoolType{}, "int"},
		{ir.IntType{Width: ir.Size1, Signed: true}, "int8_t"},
		{ir.IntType{Width: ir.Size1, Signed: false}, "uint8_t"},
		{ir.IntType{Width: ir.Size2, Signed: true}, "int16_t"},
		{ir.IntType{Width: ir.Size2, Signed: false}, "uint16_t"},
		{ir.IntType{Width: ir.Size4, Signed: true}, "int32_t"},
		{ir.IntType{Width: ir.Size4, Signed: false}, "uint32_t"},
		{ir.IntType{Width: ir.Size8, Signed: true}, "int64_t"},
		{ir.IntType{Width: ir.Size8, Signed: false}, "uint64_t"},
		{ir.FloatType{Width: ir.Size4}, "float"},
		{ir.FloatType{Width: ir.Size8}, "double"},
		{ir.FloatType{Width: ir.Size10}, "long double"},
	}

	for _, tc := range cases {
		got := cTypeName(tc.typ)
		if got != tc.want {
			t.Errorf("cTypeName(%v) = %q, want %q", tc.typ, got, tc.want)
		}
	}
}

func TestCTypeName_Pointer(t *testing.T) {
	pt := ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: true}}
	got := cTypeName(pt)
	if got != "int32_t*" {
		t.Errorf("got %q, want %q", got, "int32_t*")
	}
}

func TestCTypeName_NamedStruct(t *testing.T) {
	st := ir.StructType{Name: "MyStruct"}
	got := cTypeName(st)
	if got != "struct MyStruct" {
		t.Errorf("got %q, want %q", got, "struct MyStruct")
	}
}

func TestCTypeName_Nil(t *testing.T) {
	got := cTypeName(nil)
	if got != "void" {
		t.Errorf("got %q, want %q", got, "void")
	}
}

// ============================================================================
// expression generation tests
// ============================================================================

func TestGenExpression_Variable(t *testing.T) {
	g := New()
	fn := simpleFn("f", ir.VoidType{}, nil)
	ast := &structuring.StructuredAST{Body: structuring.Block{}, FunctionID: 0}
	state := newGeneratorState(fn, ast)
	_ = g

	v := ir.VariableExpr{Var: makeIntVar("x")}
	got := state.genExpression(v)
	if got != "x" {
		t.Errorf("got %q, want %q", got, "x")
	}
}

func TestGenExpression_IntConstant(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	c := ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size8, Signed: true}}
	got := state.genExpression(c)
	if got != "42" {
		t.Errorf("got %q, want %q", got, "42")
	}
}

func TestGenExpression_UnsignedConstant(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	c := ir.ConstantExpr{Value: ir.IntConstant{Value: 100, Width: ir.Size4, Signed: false}}
	got := state.genExpression(c)
	if got != "100U" {
		t.Errorf("got %q, want %q", got, "100U")
	}
}

func TestGenExpression_BinaryOp(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	expr := ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  ir.VariableExpr{Var: makeIntVar("a")},
		Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
	}
	got := state.genExpression(expr)
	if got != "(a + 1)" {
		t.Errorf("got %q, want %q", got, "(a + 1)")
	}
}

func TestGenExpression_UnaryOp(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	expr := ir.UnaryOp{
		Op:      ir.UnOpNeg,
		Operand: ir.VariableExpr{Var: makeIntVar("x")},
	}
	got := state.genExpression(expr)
	if got != "(-x)" {
		t.Errorf("got %q, want %q", got, "(-x)")
	}
}

func TestGenExpression_Cast(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	expr := ir.Cast{
		Expr:       ir.VariableExpr{Var: makeIntVar("x")},
		TargetType: ir.IntType{Width: ir.Size4, Signed: false},
	}
	got := state.genExpression(expr)
	if got != "(uint32_t)(x)" {
		t.Errorf("got %q, want %q", got, "(uint32_t)(x)")
	}
}

func TestGenExpression_NullConstant(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	c := ir.ConstantExpr{Value: ir.NullConstant{PointerType: ir.PointerType{Pointee: ir.VoidType{}}}}
	got := state.genExpression(c)
	if got != "NULL" {
		t.Errorf("got %q, want %q", got, "NULL")
	}
}

// ============================================================================
// ir instruction generation tests
// ============================================================================

func TestGenIRInstruction_Assign(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	instr := ir.Assign{
		Dest:   makeIntVar("v0"),
		Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 7, Width: ir.Size8, Signed: true}},
	}
	got := state.genIRInstruction(instr)
	if got != "v0 = 7;" {
		t.Errorf("got %q, want %q", got, "v0 = 7;")
	}
}

func TestGenIRInstruction_Load(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	instr := ir.Load{
		Dest:    makeIntVar("v1"),
		Address: ir.VariableExpr{Var: makeIntVar("ptr")},
		Size:    ir.Size8,
	}
	got := state.genIRInstruction(instr)
	want := "v1 = *(uint64_t*)(ptr);"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenIRInstruction_Store(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	instr := ir.Store{
		Address: ir.VariableExpr{Var: makeIntVar("ptr")},
		Value:   ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size4, Signed: true}},
		Size:    ir.Size4,
	}
	got := state.genIRInstruction(instr)
	want := "*(uint32_t*)(ptr) = 0;"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenIRInstruction_CallVoid(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	instr := ir.Call{
		Target: ir.VariableExpr{Var: ir.Variable{Name: "foo", Type: ir.FunctionType{ReturnType: ir.VoidType{}}}},
		Args:   []ir.Variable{makeIntVar("a"), makeIntVar("b")},
	}
	got := state.genIRInstruction(instr)
	want := "foo(a, b);"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenIRInstruction_CallWithDest(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	dest := makeIntVar("ret")
	instr := ir.Call{
		Dest:   &dest,
		Target: ir.VariableExpr{Var: ir.Variable{Name: "bar", Type: ir.FunctionType{ReturnType: ir.IntType{Width: ir.Size8, Signed: true}}}},
		Args:   nil,
	}
	got := state.genIRInstruction(instr)
	want := "ret = bar();"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenIRInstruction_ReturnValue(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	v := makeIntVar("x")
	instr := ir.Return{Value: &v}
	got := state.genIRInstruction(instr)
	if got != "return x;" {
		t.Errorf("got %q, want %q", got, "return x;")
	}
}

func TestGenIRInstruction_ReturnVoid(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	instr := ir.Return{}
	got := state.genIRInstruction(instr)
	if got != "return;" {
		t.Errorf("got %q, want %q", got, "return;")
	}
}

func TestGenIRInstruction_JumpSuppressed(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	instr := ir.Jump{Target: 1}
	got := state.genIRInstruction(instr)
	if got != "" {
		t.Errorf("jump should be suppressed, got %q", got)
	}
}

func TestGenIRInstruction_BranchSuppressed(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	instr := ir.Branch{
		Condition:   ir.ConstantExpr{Value: ir.BoolConstant{Value: true}},
		TrueTarget:  1,
		FalseTarget: 2,
	}
	got := state.genIRInstruction(instr)
	if got != "" {
		t.Errorf("branch should be suppressed, got %q", got)
	}
}

// ============================================================================
// statement generation tests
// ============================================================================

func TestGenStatement_IfNoElse(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	stmt := structuring.IfStatement{
		Condition: ir.VariableExpr{Var: makeIntVar("cond")},
		Then: structuring.IRBlock{
			BlockID: 1,
			Instructions: []ir.IRInstruction{
				ir.Return{},
			},
		},
		Else: nil,
	}
	got := state.genStatement(stmt, 0)
	if !strings.Contains(got, "if (cond)") {
		t.Errorf("missing if condition in: %q", got)
	}
	if !strings.Contains(got, "return;") {
		t.Errorf("missing return in then branch: %q", got)
	}
	if strings.Contains(got, "else") {
		t.Errorf("unexpected else in output: %q", got)
	}
}

func TestGenStatement_IfElse(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	v := makeIntVar("x")
	stmt := structuring.IfStatement{
		Condition: ir.VariableExpr{Var: makeIntVar("cond")},
		Then: structuring.ReturnStatement{
			Value: ir.VariableExpr{Var: v},
		},
		Else: structuring.ReturnStatement{
			Value: ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size8, Signed: true}},
		},
	}
	got := state.genStatement(stmt, 0)
	if !strings.Contains(got, "else") {
		t.Errorf("missing else in: %q", got)
	}
}

func TestGenStatement_While(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	stmt := structuring.WhileStatement{
		Condition: ir.VariableExpr{Var: makeIntVar("running")},
		Body:      structuring.Block{Stmts: nil},
	}
	got := state.genStatement(stmt, 0)
	if !strings.Contains(got, "while (running)") {
		t.Errorf("missing while condition in: %q", got)
	}
}

func TestGenStatement_DoWhile(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	stmt := structuring.DoWhileStatement{
		Body:      structuring.Block{Stmts: nil},
		Condition: ir.VariableExpr{Var: makeIntVar("flag")},
	}
	got := state.genStatement(stmt, 0)
	if !strings.Contains(got, "do") || !strings.Contains(got, "while (flag)") {
		t.Errorf("malformed do-while in: %q", got)
	}
}

func TestGenStatement_For(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	stmt := structuring.ForStatement{
		Init: structuring.IRBlock{
			BlockID: 0,
			Instructions: []ir.IRInstruction{
				ir.Assign{
					Dest:   makeIntVar("i"),
					Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size8, Signed: true}},
				},
			},
		},
		Condition: ir.BinaryOp{
			Op:    ir.BinOpLt,
			Left:  ir.VariableExpr{Var: makeIntVar("i")},
			Right: ir.VariableExpr{Var: makeIntVar("n")},
		},
		Post: structuring.IRBlock{
			BlockID: 0,
			Instructions: []ir.IRInstruction{
				ir.Assign{
					Dest: makeIntVar("i"),
					Source: ir.BinaryOp{
						Op:    ir.BinOpAdd,
						Left:  ir.VariableExpr{Var: makeIntVar("i")},
						Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
					},
				},
			},
		},
		Body: structuring.Block{Stmts: nil},
	}
	got := state.genStatement(stmt, 0)
	if !strings.Contains(got, "for (") {
		t.Errorf("missing for keyword in: %q", got)
	}
	if !strings.Contains(got, "(i < n)") {
		t.Errorf("missing loop condition in: %q", got)
	}
}

func TestGenStatement_Goto(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	stmt := structuring.GotoStatement{Target: cfg.BlockID(5), Label: "label_5"}
	got := state.genStatement(stmt, 0)
	if got != "goto label_5;\n" {
		t.Errorf("got %q, want %q", got, "goto label_5;\n")
	}
}

func TestGenStatement_Label(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	stmt := structuring.LabelStatement{Name: "label_5"}
	got := state.genStatement(stmt, 1)
	if !strings.Contains(got, "label_5:") {
		t.Errorf("missing label in: %q", got)
	}
}

func TestGenStatement_Return(t *testing.T) {
	state := newGeneratorState(simpleFn("f", ir.VoidType{}, nil), &structuring.StructuredAST{})
	stmt := structuring.ReturnStatement{
		Value: ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size8, Signed: true}},
	}
	got := state.genStatement(stmt, 0)
	if got != "return 42;\n" {
		t.Errorf("got %q, want %q", got, "return 42;\n")
	}
}

// ============================================================================
// full function generation tests
// ============================================================================

func TestGenerateFunction_VoidNoParams(t *testing.T) {
	g := New()
	fn := simpleFn("my_func", ir.VoidType{}, nil)
	ast := &structuring.StructuredAST{
		Body:       structuring.Block{Stmts: nil},
		FunctionID: 0,
	}
	decl := g.GenerateFunction(fn, ast)
	if decl.Name != "my_func" {
		t.Errorf("name = %q, want %q", decl.Name, "my_func")
	}
	if decl.ReturnType != "void" {
		t.Errorf("return type = %q, want %q", decl.ReturnType, "void")
	}
	if len(decl.Params) != 0 {
		t.Errorf("expected 0 params, got %d", len(decl.Params))
	}
}

func TestGenerateFunction_WithParams(t *testing.T) {
	g := New()
	fn := &ir.Function{
		Name: "add",
		Signature: ir.FunctionType{
			ReturnType: ir.IntType{Width: ir.Size8, Signed: true},
			Parameters: []ir.Type{
				ir.IntType{Width: ir.Size8, Signed: true},
				ir.IntType{Width: ir.Size8, Signed: true},
			},
		},
		Blocks:    make(map[ir.BlockID]*ir.BasicBlock),
		Variables: nil,
	}
	ast := &structuring.StructuredAST{Body: structuring.Block{}, FunctionID: 0}
	decl := g.GenerateFunction(fn, ast)

	if len(decl.Params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(decl.Params))
	}
	if decl.Params[0].Name != "arg0" || decl.Params[1].Name != "arg1" {
		t.Errorf("unexpected param names: %v", decl.Params)
	}
	if decl.Params[0].Type != "int64_t" {
		t.Errorf("param type = %q, want %q", decl.Params[0].Type, "int64_t")
	}
}

func TestGenerate_OutputContainsFunctionSignature(t *testing.T) {
	g := New()
	fn := &ir.Function{
		Name: "compute",
		Signature: ir.FunctionType{
			ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
			Parameters: []ir.Type{ir.IntType{Width: ir.Size4, Signed: true}},
		},
		Blocks:    make(map[ir.BlockID]*ir.BasicBlock),
		Variables: []ir.Variable{makeIntVar("result")},
	}
	ast := &structuring.StructuredAST{
		Body: structuring.ReturnStatement{
			Value: ir.VariableExpr{Var: makeIntVar("result")},
		},
		FunctionID: 0,
	}
	out := g.Generate(fn, ast)

	if !strings.Contains(out, "int32_t compute(") {
		t.Errorf("missing function signature in:\n%s", out)
	}
	if !strings.Contains(out, "return result;") {
		t.Errorf("missing return statement in:\n%s", out)
	}
}

func TestGenerate_VariableDeclarations(t *testing.T) {
	g := New()
	fn := &ir.Function{
		Name: "f",
		Signature: ir.FunctionType{
			ReturnType: ir.VoidType{},
			Parameters: nil,
		},
		Blocks: make(map[ir.BlockID]*ir.BasicBlock),
		Variables: []ir.Variable{
			makeIntVar("v0"),
			makeUintVar("v1"),
		},
	}
	ast := &structuring.StructuredAST{Body: structuring.Block{}, FunctionID: 0}
	out := g.Generate(fn, ast)

	if !strings.Contains(out, "int64_t v0;") {
		t.Errorf("missing v0 declaration in:\n%s", out)
	}
	if !strings.Contains(out, "uint32_t v1;") {
		t.Errorf("missing v1 declaration in:\n%s", out)
	}
}

func TestGenerate_SyntacticallyValid_BracesBalanced(t *testing.T) {
	g := New()
	fn := simpleFn("balanced", ir.VoidType{}, nil)
	ast := &structuring.StructuredAST{
		Body: structuring.IfStatement{
			Condition: ir.VariableExpr{Var: makeIntVar("x")},
			Then: structuring.WhileStatement{
				Condition: ir.VariableExpr{Var: makeIntVar("y")},
				Body:      structuring.Block{},
			},
			Else: nil,
		},
		FunctionID: 0,
	}
	out := g.Generate(fn, ast)

	opens := strings.Count(out, "{")
	closes := strings.Count(out, "}")
	if opens != closes {
		t.Errorf("unbalanced braces: %d open, %d close in:\n%s", opens, closes, out)
	}
}

// ============================================================================
// operator mapping tests
// ============================================================================

func TestCBinaryOp_AllOperators(t *testing.T) {
	cases := []struct {
		op   ir.BinaryOperator
		want string
	}{
		{ir.BinOpAdd, "+"},
		{ir.BinOpSub, "-"},
		{ir.BinOpMul, "*"},
		{ir.BinOpDiv, "/"},
		{ir.BinOpMod, "%"},
		{ir.BinOpAnd, "&"},
		{ir.BinOpOr, "|"},
		{ir.BinOpXor, "^"},
		{ir.BinOpShl, "<<"},
		{ir.BinOpShr, ">>"},
		{ir.BinOpEq, "=="},
		{ir.BinOpNe, "!="},
		{ir.BinOpLt, "<"},
		{ir.BinOpLe, "<="},
		{ir.BinOpGt, ">"},
		{ir.BinOpGe, ">="},
		{ir.BinOpLogicalAnd, "&&"},
		{ir.BinOpLogicalOr, "||"},
	}
	for _, tc := range cases {
		got := cBinaryOp(tc.op)
		if got != tc.want {
			t.Errorf("cBinaryOp(%v) = %q, want %q", tc.op, got, tc.want)
		}
	}
}

func TestCUnaryOp_AllOperators(t *testing.T) {
	cases := []struct {
		op   ir.UnaryOperator
		want string
	}{
		{ir.UnOpNeg, "-"},
		{ir.UnOpNot, "~"},
		{ir.UnOpLogicalNot, "!"},
	}
	for _, tc := range cases {
		got := cUnaryOp(tc.op)
		if got != tc.want {
			t.Errorf("cUnaryOp(%v) = %q, want %q", tc.op, got, tc.want)
		}
	}
}

// ============================================================================
// indent helper test
// ============================================================================

func TestIndent(t *testing.T) {
	if indent(0) != "" {
		t.Error("indent(0) should be empty")
	}
	if indent(1) != "    " {
		t.Errorf("indent(1) = %q, want 4 spaces", indent(1))
	}
	if indent(2) != "        " {
		t.Errorf("indent(2) = %q, want 8 spaces", indent(2))
	}
}

// TestGenIRBlockTruncatesAfterReturn verifies that genIRBlock stops emitting
// instructions after the first ir.Return instruction.
func TestGenIRBlockTruncatesAfterReturn(t *testing.T) {
	retVar := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}
	var1 := ir.Variable{Name: "var1", Type: ir.IntType{Width: ir.Size8, Signed: false}}
	var2 := ir.Variable{Name: "var2", Type: ir.IntType{Width: ir.Size8, Signed: false}}

	retVal := retVar
	irBlock := structuring.IRBlock{
		BlockID: 0,
		Instructions: []ir.IRInstruction{
			// first: a normal assign
			ir.Assign{
				Dest:   var1,
				Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8}},
			},
			// second: return
			ir.Return{Value: &retVal},
			// third: dead assign after return
			ir.Assign{
				Dest:   var2,
				Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 2, Width: ir.Size8}},
			},
		},
	}

	fn := &ir.Function{
		Name:      "test_func",
		Signature: ir.FunctionType{ReturnType: ir.VoidType{}},
		Blocks:    map[ir.BlockID]*ir.BasicBlock{},
	}
	ast := &structuring.StructuredAST{Body: irBlock, FunctionID: 0}
	state := newGeneratorState(fn, ast)

	output := state.genIRBlock(irBlock, 0)

	// must contain the first assign and the return
	if !strings.Contains(output, "var1") {
		t.Errorf("expected var1 assignment in output, got:\n%s", output)
	}
	if !strings.Contains(output, "return") {
		t.Errorf("expected return statement in output, got:\n%s", output)
	}
	// must NOT contain the dead assign after return
	if strings.Contains(output, "var2") {
		t.Errorf("dead code after return: var2 should not appear in output, got:\n%s", output)
	}
}

// TestGenBlockTruncatesAfterReturnStatement verifies that genBlock stops
// emitting sibling statements after a return-containing IRBlock.
func TestGenBlockTruncatesAfterReturnStatement(t *testing.T) {
	retVar := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}
	deadVar := ir.Variable{Name: "dead_var", Type: ir.IntType{Width: ir.Size8, Signed: false}}

	retVal := retVar
	retBlock := structuring.IRBlock{
		BlockID:      0,
		Instructions: []ir.IRInstruction{ir.Return{Value: &retVal}},
	}
	deadBlock := structuring.IRBlock{
		BlockID: 1,
		Instructions: []ir.IRInstruction{
			ir.Assign{
				Dest:   deadVar,
				Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 99, Width: ir.Size8}},
			},
		},
	}

	block := structuring.Block{Stmts: []structuring.Statement{retBlock, deadBlock}}

	fn := &ir.Function{
		Name:      "test_func",
		Signature: ir.FunctionType{ReturnType: ir.VoidType{}},
		Blocks:    map[ir.BlockID]*ir.BasicBlock{},
	}
	ast := &structuring.StructuredAST{Body: block, FunctionID: 0}
	state := newGeneratorState(fn, ast)

	output := state.genBlock(block, 0)

	if !strings.Contains(output, "return") {
		t.Errorf("expected return in output, got:\n%s", output)
	}
	if strings.Contains(output, "dead_var") {
		t.Errorf("dead code after return: dead_var should not appear in output, got:\n%s", output)
	}
}
