package analysis

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
	"github.com/zarazaex69/sedec/pkg/structuring"
)

func TestRecoverASTConditions_Nil(t *testing.T) {
	RecoverASTConditions(nil)
}

func TestRecoverASTConditions_NilBody(t *testing.T) {
	ast := &structuring.StructuredAST{}
	RecoverASTConditions(ast)
}

func TestRecoverASTConditions_IfStatement(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	cond := zfExpr(a, b)

	ast := &structuring.StructuredAST{
		Body: structuring.IfStatement{
			Condition: cond,
			Then:      structuring.Block{Stmts: []structuring.Statement{}},
			Else:      nil,
		},
	}

	RecoverASTConditions(ast)

	ifStmt, ok := ast.Body.(structuring.IfStatement)
	if !ok {
		t.Fatal("expected IfStatement")
	}
	binOp, ok := ifStmt.Condition.(ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp condition, got %T", ifStmt.Condition)
	}
	if binOp.Op != ir.BinOpEq {
		t.Errorf("expected BinOpEq, got %v", binOp.Op)
	}
}

func TestRecoverASTConditions_WhileStatement(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	ast := &structuring.StructuredAST{
		Body: structuring.WhileStatement{
			Condition: zfExpr(a, b),
			Body:      structuring.Block{},
		},
	}

	RecoverASTConditions(ast)

	ws, ok := ast.Body.(structuring.WhileStatement)
	if !ok {
		t.Fatal("expected WhileStatement")
	}
	if _, ok := ws.Condition.(ir.BinaryOp); !ok {
		t.Error("expected condition to be recovered")
	}
}

func TestRecoverASTConditions_DoWhileStatement(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	ast := &structuring.StructuredAST{
		Body: structuring.DoWhileStatement{
			Body:      structuring.Block{},
			Condition: zfExpr(a, b),
		},
	}

	RecoverASTConditions(ast)

	dw, ok := ast.Body.(structuring.DoWhileStatement)
	if !ok {
		t.Fatal("expected DoWhileStatement")
	}
	if _, ok := dw.Condition.(ir.BinaryOp); !ok {
		t.Error("expected condition to be recovered")
	}
}

func TestRecoverASTConditions_ForStatement(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	ast := &structuring.StructuredAST{
		Body: structuring.ForStatement{
			Init:      nil,
			Condition: zfExpr(a, b),
			Post:      nil,
			Body:      structuring.Block{},
		},
	}

	RecoverASTConditions(ast)

	fs, ok := ast.Body.(structuring.ForStatement)
	if !ok {
		t.Fatal("expected ForStatement")
	}
	if _, ok := fs.Condition.(ir.BinaryOp); !ok {
		t.Error("expected condition to be recovered")
	}
}

func TestRecoverASTConditions_IRBlock(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	ast := &structuring.StructuredAST{
		Body: structuring.IRBlock{
			BlockID: 0,
			Instructions: []ir.IRInstruction{
				&ir.Branch{Condition: zfExpr(a, b), TrueTarget: 1},
			},
		},
	}

	RecoverASTConditions(ast)
}

func TestRecoverASTConditions_ReturnWithValue(t *testing.T) {
	ast := &structuring.StructuredAST{
		Body: structuring.ReturnStatement{
			Value: ir.VariableExpr{Var: ir.Variable{Name: "x"}},
		},
	}

	RecoverASTConditions(ast)

	rs, ok := ast.Body.(structuring.ReturnStatement)
	if !ok {
		t.Fatal("expected ReturnStatement")
	}
	if rs.Value == nil {
		t.Error("expected non-nil return value")
	}
}

func TestRecoverASTConditions_ReturnWithoutValue(t *testing.T) {
	ast := &structuring.StructuredAST{
		Body: structuring.ReturnStatement{Value: nil},
	}

	RecoverASTConditions(ast)
}

func TestRecoverASTConditions_Block(t *testing.T) {
	a := ir.VariableExpr{Var: ir.Variable{Name: "a"}}
	b := ir.VariableExpr{Var: ir.Variable{Name: "b"}}

	ast := &structuring.StructuredAST{
		Body: structuring.Block{
			Stmts: []structuring.Statement{
				structuring.IfStatement{
					Condition: zfExpr(a, b),
					Then:      structuring.Block{},
				},
				structuring.ReturnStatement{Value: nil},
			},
		},
	}

	RecoverASTConditions(ast)
}
