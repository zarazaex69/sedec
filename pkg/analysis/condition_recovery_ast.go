package analysis

import (
	"github.com/zarazaex69/sedec/pkg/ir"
	"github.com/zarazaex69/sedec/pkg/structuring"
)

// RecoverASTConditions walks the structured ast and applies condition recovery
// to all condition expressions in if/while/do-while/for statements.
// this is necessary because the structuring engine extracts branch conditions
// from ir.Branch instructions and stores them directly in the ast nodes.
func RecoverASTConditions(ast *structuring.StructuredAST) {
	if ast == nil {
		return
	}
	ast.Body = recoverStmtConditions(ast.Body)
}

// recoverStmtConditions recursively walks a statement tree and recovers conditions.
func recoverStmtConditions(stmt structuring.Statement) structuring.Statement {
	if stmt == nil {
		return nil
	}

	switch s := stmt.(type) {
	case structuring.Block:
		newStmts := make([]structuring.Statement, len(s.Stmts))
		for i, child := range s.Stmts {
			newStmts[i] = recoverStmtConditions(child)
		}
		return structuring.Block{Stmts: newStmts}

	case structuring.IfStatement:
		return structuring.IfStatement{
			Condition: recoverExpr(s.Condition),
			Then:      recoverStmtConditions(s.Then),
			Else:      recoverStmtConditions(s.Else),
		}

	case structuring.WhileStatement:
		return structuring.WhileStatement{
			Condition: recoverExpr(s.Condition),
			Body:      recoverStmtConditions(s.Body),
		}

	case structuring.DoWhileStatement:
		return structuring.DoWhileStatement{
			Body:      recoverStmtConditions(s.Body),
			Condition: recoverExpr(s.Condition),
		}

	case structuring.ForStatement:
		return structuring.ForStatement{
			Init:      recoverStmtConditions(s.Init),
			Condition: recoverExpr(s.Condition),
			Post:      recoverStmtConditions(s.Post),
			Body:      recoverStmtConditions(s.Body),
		}

	case structuring.IRBlock:
		newInstrs := make([]ir.IRInstruction, len(s.Instructions))
		for i, instr := range s.Instructions {
			newInstrs[i] = recoverInstrConditions(instr)
		}
		return structuring.IRBlock{
			BlockID:      s.BlockID,
			Instructions: newInstrs,
		}

	case structuring.ReturnStatement:
		if s.Value != nil {
			return structuring.ReturnStatement{Value: recoverExpr(s.Value)}
		}
		return s

	default:
		return stmt
	}
}
