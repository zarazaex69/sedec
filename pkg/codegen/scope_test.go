package codegen

import (
	"strings"
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
	"github.com/zarazaex69/sedec/pkg/structuring"
)

// ============================================================================
// helpers
// ============================================================================

// makeVar creates a signed 64-bit variable with the given name.
func makeVar(name string) ir.Variable {
	return ir.Variable{Name: name, Type: ir.IntType{Width: ir.Size8, Signed: true}}
}

// makePtr creates a pointer-to-int64 variable.
func makePtr(name string) ir.Variable {
	return ir.Variable{Name: name, Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size8, Signed: true}}}
}

// fnWith creates an ir.Function with the given local variables.
func fnWith(name string, vars ...ir.Variable) *ir.Function {
	return &ir.Function{
		Name:       name,
		Signature:  ir.FunctionType{ReturnType: ir.VoidType{}},
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
		EntryBlock: 0,
		Variables:  vars,
	}
}

// countDecls counts VarDeclStatement nodes in a statement tree.
func countDecls(stmt structuring.Statement) int {
	if stmt == nil {
		return 0
	}
	count := 0
	if _, ok := stmt.(structuring.VarDeclStatement); ok {
		return 1
	}
	switch n := stmt.(type) {
	case structuring.Block:
		for _, s := range n.Stmts {
			count += countDecls(s)
		}
	case structuring.IfStatement:
		count += countDecls(n.Then)
		if n.Else != nil {
			count += countDecls(n.Else)
		}
	case structuring.WhileStatement:
		count += countDecls(n.Body)
	case structuring.DoWhileStatement:
		count += countDecls(n.Body)
	case structuring.ForStatement:
		count += countDecls(n.Body)
	}
	return count
}

// findDeclDepth returns the nesting depth at which varName is declared.
// depth 0 = top-level block, 1 = inside if/while/for body, etc.
// returns -1 if not found.
func findDeclDepth(stmt structuring.Statement, varName string, depth int) int {
	if stmt == nil {
		return -1
	}
	if vd, ok := stmt.(structuring.VarDeclStatement); ok {
		if vd.Name == varName {
			return depth
		}
		return -1
	}
	switch n := stmt.(type) {
	case structuring.Block:
		for _, s := range n.Stmts {
			if d := findDeclDepth(s, varName, depth); d >= 0 {
				return d
			}
		}
	case structuring.IfStatement:
		if d := findDeclDepth(n.Then, varName, depth+1); d >= 0 {
			return d
		}
		if n.Else != nil {
			if d := findDeclDepth(n.Else, varName, depth+1); d >= 0 {
				return d
			}
		}
	case structuring.WhileStatement:
		return findDeclDepth(n.Body, varName, depth+1)
	case structuring.DoWhileStatement:
		return findDeclDepth(n.Body, varName, depth+1)
	case structuring.ForStatement:
		return findDeclDepth(n.Body, varName, depth+1)
	}
	return -1
}

// ============================================================================
// TestScopeMinimizer_NoVariables: function with no local variables
// ============================================================================

func TestScopeMinimizer_NoVariables(t *testing.T) {
	fn := fnWith("empty")
	body := structuring.Block{Stmts: []structuring.Statement{
		structuring.ReturnStatement{},
	}}
	m := NewScopeMinimizer(fn)
	result := m.MinimizeVariableScope(body)

	if countDecls(result) != 0 {
		t.Errorf("expected 0 declarations for function with no variables, got %d", countDecls(result))
	}
}

// ============================================================================
// TestScopeMinimizer_DeclAtFirstUse: variable declared at first use, not at entry
// ============================================================================

func TestScopeMinimizer_DeclAtFirstUse(t *testing.T) {
	v := makeVar("result")
	fn := fnWith("f", v)

	// body: result = 42; return result;
	body := structuring.Block{Stmts: []structuring.Statement{
		structuring.IRBlock{
			BlockID: 0,
			Instructions: []ir.IRInstruction{
				ir.Assign{
					Dest:   v,
					Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size8, Signed: true}},
				},
			},
		},
		structuring.ReturnStatement{
			Value: ir.VariableExpr{Var: v},
		},
	}}

	m := NewScopeMinimizer(fn)
	result := m.MinimizeVariableScope(body)

	// must have exactly one declaration
	if countDecls(result) != 1 {
		t.Errorf("expected 1 declaration, got %d", countDecls(result))
	}

	// declaration must be at depth 0 (top-level block, not inside any nested scope)
	depth := findDeclDepth(result, "result", 0)
	if depth != 0 {
		t.Errorf("expected declaration at depth 0, got %d", depth)
	}
}

// ============================================================================
// TestScopeMinimizer_InnerScopeDecl: variable used only inside if-body
// ============================================================================

func TestScopeMinimizer_InnerScopeDecl(t *testing.T) {
	cond := makeVar("cond")
	inner := makeVar("inner")
	fn := fnWith("f", cond, inner)

	// body: if (cond) { inner = 1; }
	body := structuring.Block{Stmts: []structuring.Statement{
		structuring.IfStatement{
			Condition: ir.VariableExpr{Var: cond},
			Then: structuring.IRBlock{
				BlockID: 1,
				Instructions: []ir.IRInstruction{
					ir.Assign{
						Dest:   inner,
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
					},
				},
			},
			Else: nil,
		},
	}}

	m := NewScopeMinimizer(fn)
	result := m.MinimizeVariableScope(body)

	// inner must be declared inside the if body (depth >= 1)
	innerDepth := findDeclDepth(result, "inner", 0)
	if innerDepth < 1 {
		t.Errorf("expected 'inner' declared inside if body (depth >= 1), got depth %d", innerDepth)
	}
}

// ============================================================================
// TestScopeMinimizer_ConditionVarDeclaredBeforeIf
// ============================================================================

func TestScopeMinimizer_ConditionVarDeclaredBeforeIf(t *testing.T) {
	cond := makeVar("flag")
	fn := fnWith("f", cond)

	body := structuring.Block{Stmts: []structuring.Statement{
		structuring.IfStatement{
			Condition: ir.VariableExpr{Var: cond},
			Then:      structuring.Block{Stmts: nil},
			Else:      nil,
		},
	}}

	m := NewScopeMinimizer(fn)
	result := m.MinimizeVariableScope(body)

	// flag is used in condition: must be declared at depth 0 (before the if)
	depth := findDeclDepth(result, "flag", 0)
	if depth != 0 {
		t.Errorf("condition variable 'flag' must be declared at depth 0, got %d", depth)
	}
}

// ============================================================================
// TestScopeMinimizer_WhileBodyVar: variable used only inside while body
// ============================================================================

func TestScopeMinimizer_WhileBodyVar(t *testing.T) {
	cond := makeVar("running")
	bodyVar := makeVar("tmp")
	fn := fnWith("f", cond, bodyVar)

	body := structuring.Block{Stmts: []structuring.Statement{
		structuring.WhileStatement{
			Condition: ir.VariableExpr{Var: cond},
			Body: structuring.IRBlock{
				BlockID: 1,
				Instructions: []ir.IRInstruction{
					ir.Assign{
						Dest:   bodyVar,
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size8, Signed: true}},
					},
				},
			},
		},
	}}

	m := NewScopeMinimizer(fn)
	result := m.MinimizeVariableScope(body)

	// tmp is only used inside while body: must be declared at depth >= 1
	tmpDepth := findDeclDepth(result, "tmp", 0)
	if tmpDepth < 1 {
		t.Errorf("expected 'tmp' declared inside while body (depth >= 1), got %d", tmpDepth)
	}
}

// ============================================================================
// TestScopeMinimizer_MultipleVarsCorrectOrder: declarations appear before uses
// ============================================================================

func TestScopeMinimizer_MultipleVarsCorrectOrder(t *testing.T) {
	a := makeVar("a")
	b := makeVar("b")
	fn := fnWith("f", a, b)

	// a = 1; b = a + 2;
	body := structuring.Block{Stmts: []structuring.Statement{
		structuring.IRBlock{
			BlockID: 0,
			Instructions: []ir.IRInstruction{
				ir.Assign{
					Dest:   a,
					Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
				},
				ir.Assign{
					Dest: b,
					Source: ir.BinaryOp{
						Op:    ir.BinOpAdd,
						Left:  ir.VariableExpr{Var: a},
						Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 2, Width: ir.Size8, Signed: true}},
					},
				},
			},
		},
	}}

	m := NewScopeMinimizer(fn)
	result := m.MinimizeVariableScope(body)

	if countDecls(result) != 2 {
		t.Errorf("expected 2 declarations, got %d", countDecls(result))
	}
}

// ============================================================================
// TestScopeMinimizer_ParamsNotDeclared: parameters must not get declarations
// ============================================================================

func TestScopeMinimizer_ParamsNotDeclared(t *testing.T) {
	fn := &ir.Function{
		Name: "f",
		Signature: ir.FunctionType{
			ReturnType: ir.VoidType{},
			Parameters: []ir.Type{ir.IntType{Width: ir.Size8, Signed: true}},
		},
		Blocks:    make(map[ir.BlockID]*ir.BasicBlock),
		Variables: []ir.Variable{makeVar("arg0")},
	}

	body := structuring.Block{Stmts: []structuring.Statement{
		structuring.IRBlock{
			BlockID: 0,
			Instructions: []ir.IRInstruction{
				ir.Return{Value: &fn.Variables[0]},
			},
		},
	}}

	m := NewScopeMinimizer(fn)
	result := m.MinimizeVariableScope(body)

	// arg0 is a parameter: must not be declared
	if countDecls(result) != 0 {
		t.Errorf("parameter 'arg0' must not be declared, got %d declarations", countDecls(result))
	}
}

// ============================================================================
// TestScopeMinimizer_ForLoopVar: induction variable declared before for loop
// ============================================================================

func TestScopeMinimizer_ForLoopVar(t *testing.T) {
	i := makeVar("i")
	n := makeVar("n")
	fn := fnWith("f", i, n)

	body := structuring.Block{Stmts: []structuring.Statement{
		structuring.ForStatement{
			Init: structuring.IRBlock{
				BlockID: 0,
				Instructions: []ir.IRInstruction{
					ir.Assign{
						Dest:   i,
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 0, Width: ir.Size8, Signed: true}},
					},
				},
			},
			Condition: ir.BinaryOp{
				Op:    ir.BinOpLt,
				Left:  ir.VariableExpr{Var: i},
				Right: ir.VariableExpr{Var: n},
			},
			Post: nil,
			Body: structuring.Block{Stmts: nil},
		},
	}}

	m := NewScopeMinimizer(fn)
	result := m.MinimizeVariableScope(body)

	// i and n must be declared before the for loop (depth 0)
	iDepth := findDeclDepth(result, "i", 0)
	nDepth := findDeclDepth(result, "n", 0)
	if iDepth != 0 {
		t.Errorf("induction variable 'i' must be declared at depth 0, got %d", iDepth)
	}
	if nDepth != 0 {
		t.Errorf("loop bound 'n' must be declared at depth 0, got %d", nDepth)
	}
}

// ============================================================================
// TestScopeMinimizer_SemanticsPreserved: generated code contains all variables
// ============================================================================

func TestScopeMinimizer_SemanticsPreserved(t *testing.T) {
	v := makeVar("x")
	fn := fnWith("compute", v)

	body := structuring.Block{Stmts: []structuring.Statement{
		structuring.IRBlock{
			BlockID: 0,
			Instructions: []ir.IRInstruction{
				ir.Assign{
					Dest:   v,
					Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 99, Width: ir.Size8, Signed: true}},
				},
			},
		},
		structuring.ReturnStatement{
			Value: ir.VariableExpr{Var: v},
		},
	}}

	g := New()
	ast := &structuring.StructuredAST{Body: body, FunctionID: 0}
	decl := g.GenerateFunctionWithScopeMinimization(fn, ast)

	// the generated body must contain the declaration and the assignment
	if !strings.Contains(decl.Body, "int64_t x;") {
		t.Errorf("expected 'int64_t x;' declaration in body:\n%s", decl.Body)
	}
	if !strings.Contains(decl.Body, "x = 99;") {
		t.Errorf("expected 'x = 99;' assignment in body:\n%s", decl.Body)
	}
	if !strings.Contains(decl.Body, "return x;") {
		t.Errorf("expected 'return x;' in body:\n%s", decl.Body)
	}
}

// ============================================================================
// TestScopeMinimizer_NoPreambleDump: no bulk variable dump at function start
// ============================================================================

func TestScopeMinimizer_NoPreambleDump(t *testing.T) {
	// create function with 3 variables used in different places
	a := makeVar("a")
	b := makeVar("b")
	c := makeVar("c")
	fn := fnWith("f", a, b, c)

	// a used in block 0, b used in if-body, c used in else-body
	body := structuring.Block{Stmts: []structuring.Statement{
		structuring.IRBlock{
			BlockID: 0,
			Instructions: []ir.IRInstruction{
				ir.Assign{
					Dest:   a,
					Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
				},
			},
		},
		structuring.IfStatement{
			Condition: ir.VariableExpr{Var: a},
			Then: structuring.IRBlock{
				BlockID: 1,
				Instructions: []ir.IRInstruction{
					ir.Assign{
						Dest:   b,
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 2, Width: ir.Size8, Signed: true}},
					},
				},
			},
			Else: structuring.IRBlock{
				BlockID: 2,
				Instructions: []ir.IRInstruction{
					ir.Assign{
						Dest:   c,
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 3, Width: ir.Size8, Signed: true}},
					},
				},
			},
		},
	}}

	g := New()
	ast := &structuring.StructuredAST{Body: body, FunctionID: 0}
	decl := g.GenerateFunctionWithScopeMinimization(fn, ast)

	// b and c must NOT appear in the first 3 lines of the body
	// (they should be declared inside the if/else branches)
	lines := strings.Split(strings.TrimSpace(decl.Body), "\n")
	for i := 0; i < 3 && i < len(lines); i++ {
		if strings.Contains(lines[i], "int64_t b;") {
			t.Errorf("'b' declared too early (line %d): %q", i, lines[i])
		}
		if strings.Contains(lines[i], "int64_t c;") {
			t.Errorf("'c' declared too early (line %d): %q", i, lines[i])
		}
	}
}

// ============================================================================
// TestVarDeclStatement_String: VarDeclStatement renders correctly
// ============================================================================

func TestVarDeclStatement_String(t *testing.T) {
	vd := structuring.VarDeclStatement{Name: "myVar", TypeName: "int32_t"}
	got := vd.String()
	want := "int32_t myVar;"
	if got != want {
		t.Errorf("VarDeclStatement.String() = %q, want %q", got, want)
	}
}

// ============================================================================
// TestScopeMinimizer_DoWhileVar: variable used in do-while condition
// ============================================================================

func TestScopeMinimizer_DoWhileVar(t *testing.T) {
	flag := makeVar("flag")
	fn := fnWith("f", flag)

	body := structuring.Block{Stmts: []structuring.Statement{
		structuring.DoWhileStatement{
			Body: structuring.IRBlock{
				BlockID: 0,
				Instructions: []ir.IRInstruction{
					ir.Assign{
						Dest:   flag,
						Source: ir.ConstantExpr{Value: ir.BoolConstant{Value: false}},
					},
				},
			},
			Condition: ir.VariableExpr{Var: flag},
		},
	}}

	m := NewScopeMinimizer(fn)
	result := m.MinimizeVariableScope(body)

	// flag is used in condition and defined in body: must be declared
	if countDecls(result) != 1 {
		t.Errorf("expected 1 declaration, got %d", countDecls(result))
	}
}
