package codegen

import (
	"fmt"
	"strings"

	"github.com/zarazaex69/sedec/pkg/ir"
	"github.com/zarazaex69/sedec/pkg/structuring"
)

// Generator converts a structured ast and ir function into c pseudocode
type Generator struct{}

// New creates a new Generator instance
func New() *Generator {
	return &Generator{}
}

// GenerateFunction produces a complete FunctionDecl from an ir function and its structured ast.
// The ir.Function provides type information and the structuring.StructuredAST provides
// the recovered high-level control flow structure.
func (g *Generator) GenerateFunction(fn *ir.Function, ast *structuring.StructuredAST) FunctionDecl {
	state := newGeneratorState(fn, ast)

	// generate body statements
	body := state.genStatement(ast.Body, state.indent)

	// collect variable declarations for all variables used in the function
	// that were not already emitted inline; prepend them to the body
	decls := state.buildVarDeclarations(fn)
	if len(decls) > 0 {
		body = decls + "\n" + body
	}

	// build parameter list from function signature
	params := buildParams(fn)

	return FunctionDecl{
		Name:          fn.Name,
		ReturnType:    cTypeName(fn.Signature.ReturnType),
		Params:        params,
		Body:          body,
		SourceAddress: 0, // caller may set this from binary metadata
	}
}

// Generate renders a complete c translation unit string for a single function.
func (g *Generator) Generate(fn *ir.Function, ast *structuring.StructuredAST) string {
	decl := g.GenerateFunction(fn, ast)
	return renderFunctionDecl(decl)
}

// RenderDecl formats a FunctionDecl as a c function definition string.
// exported so the cli pipeline can render a decl produced by TraceableGenerator.
func RenderDecl(decl FunctionDecl) string {
	return renderFunctionDecl(decl)
}

// renderFunctionDecl formats a FunctionDecl as a c function definition string
func renderFunctionDecl(decl FunctionDecl) string {
	var sb strings.Builder

	// function signature line
	sb.WriteString(decl.ReturnType)
	sb.WriteString(" ")
	sb.WriteString(decl.Name)
	sb.WriteString("(")
	for i, p := range decl.Params {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(p.Type)
		sb.WriteString(" ")
		sb.WriteString(p.Name)
	}
	sb.WriteString(")\n{\n")

	// indent body lines by one level
	for _, line := range strings.Split(decl.Body, "\n") {
		if line == "" {
			sb.WriteString("\n")
			continue
		}
		sb.WriteString("    ")
		sb.WriteString(line)
		sb.WriteString("\n")
	}

	sb.WriteString("}\n")
	return sb.String()
}

// buildParams extracts parameter declarations from the function signature.
// Parameters are named arg0, arg1, ... when no debug info is available.
func buildParams(fn *ir.Function) []ParamDecl {
	params := make([]ParamDecl, 0, len(fn.Signature.Parameters))
	for i, pt := range fn.Signature.Parameters {
		params = append(params, ParamDecl{
			Name: fmt.Sprintf("arg%d", i),
			Type: cTypeName(pt),
		})
	}
	if fn.Signature.Variadic {
		params = append(params, ParamDecl{Name: "...", Type: ""})
	}
	return params
}

// buildVarDeclarations emits c variable declarations for all local variables
// in the function that are not parameters. Variables are grouped by type.
func (s *generatorState) buildVarDeclarations(fn *ir.Function) string {
	// collect unique variable names that are not parameters
	paramNames := make(map[string]bool, len(fn.Signature.Parameters))
	for i := range fn.Signature.Parameters {
		paramNames[fmt.Sprintf("arg%d", i)] = true
	}

	seen := make(map[string]bool)
	var lines []string

	for _, v := range fn.Variables {
		name := v.String()
		if paramNames[name] || seen[name] {
			continue
		}
		seen[name] = true
		typStr := cTypeName(v.Type)
		lines = append(lines, fmt.Sprintf("%s %s;", typStr, name))
	}

	return strings.Join(lines, "\n")
}

// ============================================================================
// Statement generation
// ============================================================================

// genStatement recursively renders a structuring.Statement node into c source.
func (s *generatorState) genStatement(stmt structuring.Statement, depth int) string {
	if stmt == nil {
		return ""
	}

	switch n := stmt.(type) {
	case structuring.Block:
		return s.genBlock(n, depth)
	case structuring.IRBlock:
		return s.genIRBlock(n, depth)
	case structuring.IfStatement:
		return s.genIf(n, depth)
	case structuring.WhileStatement:
		return s.genWhile(n, depth)
	case structuring.DoWhileStatement:
		return s.genDoWhile(n, depth)
	case structuring.ForStatement:
		return s.genFor(n, depth)
	case structuring.GotoStatement:
		return s.genGoto(n, depth)
	case structuring.LabelStatement:
		return s.genLabel(n, depth)
	case structuring.ReturnStatement:
		return s.genReturn(n, depth)
	case structuring.VarDeclStatement:
		// inline variable declaration injected by scope minimizer
		return indent(depth) + n.String() + "\n"
	default:
		// unknown statement type: emit a comment so output remains valid c
		return indent(depth) + "/* unknown statement */\n"
	}
}

func (s *generatorState) genBlock(b structuring.Block, depth int) string {
	var sb strings.Builder
	for _, stmt := range b.Stmts {
		sb.WriteString(s.genStatement(stmt, depth))
	}
	return sb.String()
}

func (s *generatorState) genIRBlock(b structuring.IRBlock, depth int) string {
	var sb strings.Builder
	for _, instr := range b.Instructions {
		line := s.genIRInstruction(instr)
		if line == "" {
			continue
		}
		sb.WriteString(indent(depth))
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	return sb.String()
}

func (s *generatorState) genIf(n structuring.IfStatement, depth int) string {
	var sb strings.Builder
	cond := s.genExpression(n.Condition)
	sb.WriteString(indent(depth))
	sb.WriteString("if (")
	sb.WriteString(cond)
	sb.WriteString(")\n")
	sb.WriteString(indent(depth))
	sb.WriteString("{\n")
	sb.WriteString(s.genStatement(n.Then, depth+1))
	sb.WriteString(indent(depth))
	sb.WriteString("}")
	if n.Else != nil {
		// suppress empty else branches
		elseBody := s.genStatement(n.Else, depth+1)
		if strings.TrimSpace(elseBody) != "" {
			sb.WriteString("\n")
			sb.WriteString(indent(depth))
			sb.WriteString("else\n")
			sb.WriteString(indent(depth))
			sb.WriteString("{\n")
			sb.WriteString(elseBody)
			sb.WriteString(indent(depth))
			sb.WriteString("}")
		}
	}
	sb.WriteString("\n")
	return sb.String()
}

func (s *generatorState) genWhile(n structuring.WhileStatement, depth int) string {
	var sb strings.Builder
	cond := s.genExpression(n.Condition)
	sb.WriteString(indent(depth))
	sb.WriteString("while (")
	sb.WriteString(cond)
	sb.WriteString(")\n")
	sb.WriteString(indent(depth))
	sb.WriteString("{\n")
	sb.WriteString(s.genStatement(n.Body, depth+1))
	sb.WriteString(indent(depth))
	sb.WriteString("}\n")
	return sb.String()
}

func (s *generatorState) genDoWhile(n structuring.DoWhileStatement, depth int) string {
	var sb strings.Builder
	cond := s.genExpression(n.Condition)
	sb.WriteString(indent(depth))
	sb.WriteString("do\n")
	sb.WriteString(indent(depth))
	sb.WriteString("{\n")
	sb.WriteString(s.genStatement(n.Body, depth+1))
	sb.WriteString(indent(depth))
	sb.WriteString("} while (")
	sb.WriteString(cond)
	sb.WriteString(");\n")
	return sb.String()
}

func (s *generatorState) genFor(n structuring.ForStatement, depth int) string {
	var sb strings.Builder

	initStr := ""
	if n.Init != nil {
		// strip trailing newline/semicolon from init statement for inline use
		raw := strings.TrimRight(s.genStatement(n.Init, 0), "\n")
		raw = strings.TrimRight(raw, ";")
		initStr = strings.TrimSpace(raw)
	}

	condStr := s.genExpression(n.Condition)

	postStr := ""
	if n.Post != nil {
		raw := strings.TrimRight(s.genStatement(n.Post, 0), "\n")
		raw = strings.TrimRight(raw, ";")
		postStr = strings.TrimSpace(raw)
	}

	sb.WriteString(indent(depth))
	sb.WriteString("for (")
	sb.WriteString(initStr)
	sb.WriteString("; ")
	sb.WriteString(condStr)
	sb.WriteString("; ")
	sb.WriteString(postStr)
	sb.WriteString(")\n")
	sb.WriteString(indent(depth))
	sb.WriteString("{\n")
	sb.WriteString(s.genStatement(n.Body, depth+1))
	sb.WriteString(indent(depth))
	sb.WriteString("}\n")
	return sb.String()
}

func (s *generatorState) genGoto(n structuring.GotoStatement, depth int) string {
	return indent(depth) + "goto " + n.Label + ";\n"
}

func (s *generatorState) genLabel(n structuring.LabelStatement, depth int) string {
	// labels are dedented by one level in c convention
	d := depth - 1
	if d < 0 {
		d = 0
	}
	return indent(d) + n.Name + ":\n"
}

func (s *generatorState) genReturn(n structuring.ReturnStatement, depth int) string {
	if n.Value != nil {
		return indent(depth) + "return " + s.genExpression(n.Value) + ";\n"
	}
	return indent(depth) + "return;\n"
}

// ============================================================================
// IR instruction → c statement
// ============================================================================

// genIRInstruction converts a single ir instruction to a c statement string (no newline).
// Returns empty string for instructions that should be suppressed (phi nodes, jumps).
// Both value and pointer receivers are handled since the lifter emits pointer types.
func (s *generatorState) genIRInstruction(instr ir.IRInstruction) string {
	// suppress frame prologue/epilogue artifacts (push rbp, mov rbp rsp, sub rsp N, etc.)
	if instr.Location().IsFrameArtifact {
		return ""
	}
	if n, ok := ir.AsAssign(instr); ok {
		return fmt.Sprintf("%s = %s;", n.Dest.String(), s.genExpression(n.Source))
	}
	if n, ok := ir.AsLoad(instr); ok {
		addr := s.genExpression(n.Address)
		return fmt.Sprintf("%s = *(%s*)(%s);", n.Dest.String(), cIntTypeForSize(n.Size), addr)
	}
	if n, ok := ir.AsStore(instr); ok {
		addr := s.genExpression(n.Address)
		val := s.genExpression(n.Value)
		return fmt.Sprintf("*(%s*)(%s) = %s;", cIntTypeForSize(n.Size), addr, val)
	}
	if n, ok := ir.AsCall(instr); ok {
		var args []string
		// prefer inlined argument expressions when the condensation pass populated them
		if len(n.ArgExprs) == len(n.Args) && len(n.ArgExprs) > 0 {
			args = make([]string, 0, len(n.ArgExprs))
			for _, e := range n.ArgExprs {
				args = append(args, s.genExpression(e))
			}
		} else {
			args = make([]string, 0, len(n.Args))
			for _, a := range n.Args {
				args = append(args, a.String())
			}
		}
		callExpr := fmt.Sprintf("%s(%s)", s.genExpression(n.Target), strings.Join(args, ", "))
		if n.Dest != nil {
			return fmt.Sprintf("%s = %s;", n.Dest.String(), callExpr)
		}
		return callExpr + ";"
	}
	if n, ok := ir.AsReturn(instr); ok {
		if n.Value != nil {
			return fmt.Sprintf("return %s;", n.Value.String())
		}
		return "return;"
	}
	if n, ok := ir.AsPhi(instr); ok {
		// phi nodes are an ssa artifact; they should be eliminated before codegen.
		// if they survive, emit a comment so the output remains valid c.
		return fmt.Sprintf("/* phi: %s */", n.Dest.String())
	}
	if ir.IsTerminator(instr) {
		// control flow is handled by the structured ast; suppress raw jumps
		return ""
	}
	return fmt.Sprintf("/* unhandled ir: %s */", instr.String())
}

// ============================================================================
// Expression generation
// ============================================================================

// genExpression converts an ir.Expression to a c expression string
func (s *generatorState) genExpression(expr ir.Expression) string {
	if expr == nil {
		return "0"
	}

	switch e := expr.(type) {
	case ir.VariableExpr:
		return normalizeFlagVar(e.Var.String())
	case *ir.VariableExpr:
		return normalizeFlagVar(e.Var.String())

	case ir.ConstantExpr:
		return genConstant(e.Value)
	case *ir.ConstantExpr:
		return genConstant(e.Value)

	case ir.BinaryOp:
		left := s.genExpression(e.Left)
		right := s.genExpression(e.Right)
		op := cBinaryOp(e.Op)
		return fmt.Sprintf("(%s %s %s)", left, op, right)
	case *ir.BinaryOp:
		left := s.genExpression(e.Left)
		right := s.genExpression(e.Right)
		op := cBinaryOp(e.Op)
		return fmt.Sprintf("(%s %s %s)", left, op, right)

	case ir.UnaryOp:
		operand := s.genExpression(e.Operand)
		op := cUnaryOp(e.Op)
		return fmt.Sprintf("(%s%s)", op, operand)
	case *ir.UnaryOp:
		operand := s.genExpression(e.Operand)
		op := cUnaryOp(e.Op)
		return fmt.Sprintf("(%s%s)", op, operand)

	case ir.Cast:
		inner := s.genExpression(e.Expr)
		return fmt.Sprintf("(%s)(%s)", cTypeName(e.TargetType), inner)
	case *ir.Cast:
		inner := s.genExpression(e.Expr)
		return fmt.Sprintf("(%s)(%s)", cTypeName(e.TargetType), inner)

	case ir.LoadExpr:
		addr := s.genExpression(e.Address)
		return fmt.Sprintf("*(%s*)(%s)", cIntTypeForSize(e.Size), addr)
	case *ir.LoadExpr:
		addr := s.genExpression(e.Address)
		return fmt.Sprintf("*(%s*)(%s)", cIntTypeForSize(e.Size), addr)

	default:
		return "/* unknown expr */"
	}
}

// genConstant renders an ir.Constant as a c literal
func genConstant(c ir.Constant) string {
	switch v := c.(type) {
	case ir.IntConstant:
		if v.Signed {
			return fmt.Sprintf("%d", v.Value)
		}
		// unsigned: use explicit cast to avoid sign ambiguity
		return fmt.Sprintf("%dU", uint64(v.Value)) //nolint:gosec
	case ir.FloatConstant:
		switch v.Width {
		case ir.Size4:
			return fmt.Sprintf("%gf", v.Value)
		default:
			return fmt.Sprintf("%g", v.Value)
		}
	case ir.BoolConstant:
		if v.Value {
			return "1"
		}
		return "0"
	case ir.NullConstant:
		return "NULL"
	default:
		return "0"
	}
}

// ============================================================================
// Type name mapping
// ============================================================================

// cTypeName maps an ir.Type to its canonical c type name
func cTypeName(t ir.Type) string {
	if t == nil {
		return "void"
	}
	switch v := t.(type) {
	case ir.VoidType:
		return "void"
	case ir.BoolType:
		return "int" // c has no bool in c89; use int for maximum compatibility
	case ir.IntType:
		return cIntType(v.Width, v.Signed)
	case ir.FloatType:
		return cFloatType(v.Width)
	case ir.PointerType:
		inner := cTypeName(v.Pointee)
		return inner + "*"
	case ir.ArrayType:
		// c array syntax requires the name between type and brackets;
		// return element type here and let the caller handle brackets
		return cTypeName(v.Element)
	case ir.StructType:
		if v.Name != "" {
			return "struct " + v.Name
		}
		return "struct { /* anonymous */ }"
	case ir.FunctionType:
		// function pointer rendered as void* for simplicity when used as a type
		return "void*"
	default:
		return "void*"
	}
}

// cIntType returns the c integer type for a given width and signedness
func cIntType(width ir.Size, signed bool) string {
	switch width {
	case ir.Size1:
		if signed {
			return "int8_t"
		}
		return "uint8_t"
	case ir.Size2:
		if signed {
			return "int16_t"
		}
		return "uint16_t"
	case ir.Size4:
		if signed {
			return "int32_t"
		}
		return "uint32_t"
	case ir.Size8:
		if signed {
			return "int64_t"
		}
		return "uint64_t"
	default:
		if signed {
			return fmt.Sprintf("int%d_t", width*8)
		}
		return fmt.Sprintf("uint%d_t", width*8)
	}
}

// cIntTypeForSize returns an unsigned integer c type for a memory access size
func cIntTypeForSize(size ir.Size) string {
	return cIntType(size, false)
}

// cFloatType returns the c floating-point type for a given width
func cFloatType(width ir.Size) string {
	switch width {
	case ir.Size4:
		return "float"
	case ir.Size8:
		return "double"
	case ir.Size10:
		return "long double"
	default:
		return "double"
	}
}

// ============================================================================
// Operator mapping
// ============================================================================

// cBinaryOp maps an ir.BinaryOperator to its c operator string
func cBinaryOp(op ir.BinaryOperator) string {
	switch op {
	case ir.BinOpAdd:
		return "+"
	case ir.BinOpSub:
		return "-"
	case ir.BinOpMul:
		return "*"
	case ir.BinOpDiv:
		return "/"
	case ir.BinOpMod:
		return "%"
	case ir.BinOpUDiv:
		// unsigned division: caller must ensure operands are cast to unsigned
		return "/"
	case ir.BinOpUMod:
		return "%"
	case ir.BinOpAnd:
		return "&"
	case ir.BinOpOr:
		return "|"
	case ir.BinOpXor:
		return "^"
	case ir.BinOpShl:
		return "<<"
	case ir.BinOpShr:
		return ">>"
	case ir.BinOpSar:
		// arithmetic right shift: in c this is implementation-defined for signed types;
		// we emit >> and rely on the type cast to convey signedness
		return ">>"
	case ir.BinOpEq:
		return "=="
	case ir.BinOpNe:
		return "!="
	case ir.BinOpLt:
		return "<"
	case ir.BinOpLe:
		return "<="
	case ir.BinOpGt:
		return ">"
	case ir.BinOpGe:
		return ">="
	case ir.BinOpULt:
		return "<"
	case ir.BinOpULe:
		return "<="
	case ir.BinOpUGt:
		return ">"
	case ir.BinOpUGe:
		return ">="
	case ir.BinOpLogicalAnd:
		return "&&"
	case ir.BinOpLogicalOr:
		return "||"
	default:
		return "?"
	}
}

// cUnaryOp maps an ir.UnaryOperator to its c operator string
func cUnaryOp(op ir.UnaryOperator) string {
	switch op {
	case ir.UnOpNeg:
		return "-"
	case ir.UnOpNot:
		return "~"
	case ir.UnOpLogicalNot:
		return "!"
	default:
		return "?"
	}
}

// ============================================================================
// Helpers
// ============================================================================

// indent returns a string of spaces for the given depth (4 spaces per level)
func indent(depth int) string {
	if depth <= 0 {
		return ""
	}
	return strings.Repeat("    ", depth)
}

// normalizeFlagVar rewrites raw cpu flag variable names to readable c expressions.
// x86 flag variables (zf, sf, of, cf, pf) are boolean-valued; when used directly
// as a condition they should render as "(flagvar != 0)" to make the semantics
// explicit and avoid confusion with integer variables.
// if the lazy flag elimination pass has already materialized the flag into a
// proper comparison expression, this function is a no-op for non-flag names.
func normalizeFlagVar(name string) string {
	switch name {
	case "zf", "sf", "of", "cf", "pf", "af", "df", "tf":
		return fmt.Sprintf("(%s != 0)", name)
	default:
		return name
	}
}
