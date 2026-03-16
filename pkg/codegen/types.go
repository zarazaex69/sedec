// package codegen generates syntactically valid c pseudocode from a structured ast
package codegen

import (
	"github.com/zarazaex69/sedec/pkg/ir"
	"github.com/zarazaex69/sedec/pkg/structuring"
)

// FunctionDecl holds the generated c representation of a single function
type FunctionDecl struct {
	// Name is the function name (may be synthetic like sub_401000)
	Name string
	// ReturnType is the c type string for the return value
	ReturnType string
	// Params is the ordered list of parameter declarations
	Params []ParamDecl
	// Body is the fully rendered c body (without outer braces)
	Body string
	// SourceAddress is the entry point virtual address of the function
	SourceAddress ir.Address
}

// ParamDecl represents a single function parameter
type ParamDecl struct {
	Name string
	Type string
}

// varDecl tracks a local variable that needs a declaration
type varDecl struct {
	name     string
	typeName string
}

// generatorState holds mutable state for a single function generation pass
type generatorState struct {
	// indent tracks current indentation depth
	indent int
	// declaredVars tracks variables already declared to avoid duplicates
	declaredVars map[string]bool
	// pendingDecls accumulates declarations to emit at block entry
	pendingDecls []varDecl
	// irFunc is the ir function being generated (for type lookups)
	irFunc *ir.Function
	// ast is the structured ast produced by the structuring engine
	ast *structuring.StructuredAST
}

func newGeneratorState(fn *ir.Function, ast *structuring.StructuredAST) *generatorState {
	return &generatorState{
		indent:       0,
		declaredVars: make(map[string]bool),
		irFunc:       fn,
		ast:          ast,
	}
}
