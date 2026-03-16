package structuring

import (
	"fmt"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// StructuredAST is the root of the recovered high-level AST for a function
type StructuredAST struct {
	Body       Statement
	FunctionID cfg.BlockID // entry block id of the original function
}

// Statement is the base interface for all AST statement nodes
type Statement interface {
	isStatement()
	String() string
}

// Block is a sequence of statements (corresponds to a basic block or compound body)
type Block struct {
	Stmts []Statement
}

func (Block) isStatement() {}
func (b Block) String() string {
	s := "{\n"
	for _, stmt := range b.Stmts {
		s += "  " + stmt.String() + "\n"
	}
	s += "}"
	return s
}

// IRBlock holds the raw IR instructions from a single basic block
type IRBlock struct {
	BlockID      cfg.BlockID
	Instructions []ir.IRInstruction
}

func (IRBlock) isStatement() {}
func (b IRBlock) String() string {
	s := fmt.Sprintf("/* bb%d */\n", b.BlockID)
	for _, instr := range b.Instructions {
		s += "  " + instr.String() + ";\n"
	}
	return s
}

// IfStatement represents an if-then-else construct
type IfStatement struct {
	Condition ir.Expression
	Then      Statement
	Else      Statement // nil if no else branch
}

func (IfStatement) isStatement() {}
func (s IfStatement) String() string {
	if s.Else != nil {
		return fmt.Sprintf("if (%s) %s else %s", s.Condition.String(), s.Then.String(), s.Else.String())
	}
	return fmt.Sprintf("if (%s) %s", s.Condition.String(), s.Then.String())
}

// WhileStatement represents a while loop
type WhileStatement struct {
	Condition ir.Expression
	Body      Statement
}

func (WhileStatement) isStatement() {}
func (s WhileStatement) String() string {
	return fmt.Sprintf("while (%s) %s", s.Condition.String(), s.Body.String())
}

// DoWhileStatement represents a do-while loop
type DoWhileStatement struct {
	Body      Statement
	Condition ir.Expression
}

func (DoWhileStatement) isStatement() {}
func (s DoWhileStatement) String() string {
	return fmt.Sprintf("do %s while (%s);", s.Body.String(), s.Condition.String())
}

// GotoStatement represents an unconditional goto for irreducible control flow
type GotoStatement struct {
	Target cfg.BlockID
	Label  string
}

func (GotoStatement) isStatement() {}
func (s GotoStatement) String() string {
	return fmt.Sprintf("goto %s;", s.Label)
}

// LabelStatement marks a target for goto statements
type LabelStatement struct {
	Name string
}

func (LabelStatement) isStatement() {}
func (s LabelStatement) String() string {
	return fmt.Sprintf("%s:", s.Name)
}

// ReturnStatement represents a function return
type ReturnStatement struct {
	Value ir.Expression // nil for void return
}

func (ReturnStatement) isStatement() {}
func (s ReturnStatement) String() string {
	if s.Value != nil {
		return fmt.Sprintf("return %s;", s.Value.String())
	}
	return "return;"
}

// regionKind classifies the structural type of a CFG region
type regionKind int

const (
	// regionLinear is a single-entry single-exit linear sequence
	regionLinear regionKind = iota
	// regionIfThen is a conditional with only a then branch
	regionIfThen
	// regionIfThenElse is a conditional with both branches
	regionIfThenElse
	// regionSelfLoop is a single-block loop (back-edge to itself)
	regionSelfLoop
	// regionWhileLoop is a while-style loop (condition at header)
	regionWhileLoop
	// regionDoWhileLoop is a do-while-style loop (condition at tail)
	regionDoWhileLoop
	// regionIrreducible is irreducible control flow requiring goto
	regionIrreducible
)

// region represents a single-entry single-exit subgraph of the CFG
type region struct {
	entry  cfg.BlockID   // single entry block
	exit   cfg.BlockID   // single exit block (may equal entry for loops)
	blocks []cfg.BlockID // all blocks in this region (including entry and exit)
	kind   regionKind
}
