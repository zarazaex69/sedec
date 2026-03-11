package ir

import (
	"fmt"
	"io"
	"strings"
)

// Printer formats IR structures into human-readable text
type Printer struct {
	w      io.Writer
	indent int
	err    error
}

// NewPrinter creates a new IR printer
func NewPrinter(w io.Writer) *Printer {
	return &Printer{
		w:      w,
		indent: 0,
	}
}

// PrintFunction prints a complete function in IR text format
func (pr *Printer) PrintFunction(fn *Function) error {
	// print function header
	pr.printf("func %s", fn.Name)
	pr.printFunctionSignature(fn.Signature)
	pr.println("")

	// print entry block first
	if block, ok := fn.Blocks[fn.EntryBlock]; ok {
		pr.printBasicBlock(block)
	}

	// print remaining blocks
	for id, block := range fn.Blocks {
		if id != fn.EntryBlock {
			pr.printBasicBlock(block)
		}
	}

	return pr.err
}

// printFunctionSignature prints function signature
func (pr *Printer) printFunctionSignature(sig FunctionType) {
	pr.printf("(")
	for i, param := range sig.Parameters {
		if i > 0 {
			pr.printf(", ")
		}
		pr.printf("%s", param.String())
	}
	if sig.Variadic {
		if len(sig.Parameters) > 0 {
			pr.printf(", ")
		}
		pr.printf("...")
	}
	pr.printf(") %s", sig.ReturnType.String())
}

// printBasicBlock prints a basic block with its instructions
func (pr *Printer) printBasicBlock(block *BasicBlock) {
	// print block label
	pr.println("")
	pr.printf("bb%d:", block.ID)

	// add comment with predecessor info if any
	if len(block.Predecessors) > 0 {
		pr.printf("  // preds:")
		for _, pred := range block.Predecessors {
			pr.printf(" bb%d", pred)
		}
	}
	pr.println("")

	// print instructions with indentation
	pr.indent++
	for _, insn := range block.Instructions {
		pr.printInstruction(insn)
	}
	pr.indent--
}

// printInstruction prints a single IR instruction
func (pr *Printer) printInstruction(insn IRInstruction) {
	pr.writeIndent()

	switch i := insn.(type) {
	case *Assign:
		pr.printf("%s = %s", i.Dest.String(), pr.formatExpression(i.Source))
	case *Load:
		pr.printf("%s = load.%d %s", i.Dest.String(), i.Size, pr.formatExpression(i.Address))
	case *Store:
		pr.printf("store.%d %s, %s", i.Size, pr.formatExpression(i.Address), pr.formatExpression(i.Value))
	case *Branch:
		pr.printf("branch %s, bb%d, bb%d", pr.formatExpression(i.Condition), i.TrueTarget, i.FalseTarget)
	case *Jump:
		pr.printf("jump bb%d", i.Target)
	case *Call:
		if i.Dest != nil {
			pr.printf("%s = ", i.Dest.String())
		}
		pr.printf("call %s(", pr.formatExpression(i.Target))
		for j, arg := range i.Args {
			if j > 0 {
				pr.printf(", ")
			}
			pr.printf("%s", arg.String())
		}
		pr.printf(")")
	case *Return:
		if i.Value != nil {
			pr.printf("return %s", i.Value.String())
		} else {
			pr.printf("return")
		}
	case *Phi:
		pr.printf("%s = phi ", i.Dest.String())
		for j, src := range i.Sources {
			if j > 0 {
				pr.printf(", ")
			}
			pr.printf("[bb%d: %s]", src.Block, src.Var.String())
		}
	default:
		pr.printf("// unknown instruction: %T", insn)
	}

	// add source location comment if available
	loc := insn.Location()
	if loc.Address != 0 {
		pr.printf("  // %s", loc.String())
	}

	pr.println("")
}

// formatExpression formats an expression as a string
func (pr *Printer) formatExpression(expr Expression) string {
	switch e := expr.(type) {
	case VariableExpr:
		return e.Var.String()
	case ConstantExpr:
		return e.Value.String()
	case BinaryOp:
		return fmt.Sprintf("(%s %s %s)",
			pr.formatExpression(e.Left),
			e.Op.String(),
			pr.formatExpression(e.Right))
	case UnaryOp:
		return fmt.Sprintf("(%s%s)", e.Op.String(), pr.formatExpression(e.Operand))
	case Cast:
		return fmt.Sprintf("(%s)%s", e.TargetType.String(), pr.formatExpression(e.Expr))
	case Extract:
		return fmt.Sprintf("extract(%s, %d, %d)", pr.formatExpression(VariableExpr{Var: Variable{Name: e.Source.Name, Type: e.Source.Type}}), e.Offset, e.Size)
	case Insert:
		return fmt.Sprintf("insert(%s, %s, %d, %d)", pr.formatExpression(VariableExpr{Var: Variable{Name: e.Dest.Name, Type: e.Dest.Type}}), pr.formatExpression(e.Value), e.Offset, e.Size)
	case ZeroExtend:
		return fmt.Sprintf("zext(%s, %d, %d)", pr.formatExpression(VariableExpr{Var: Variable{Name: e.Source.Name, Type: e.Source.Type}}), e.FromSize, e.ToSize)
	default:
		return fmt.Sprintf("/* unknown expr: %T */", expr)
	}
}

// PrintBasicBlock prints a single basic block (for testing/debugging)
func (pr *Printer) PrintBasicBlock(block *BasicBlock) error {
	pr.printBasicBlock(block)
	return pr.err
}

// PrintInstruction prints a single instruction (for testing/debugging)
func (pr *Printer) PrintInstruction(insn IRInstruction) error {
	pr.printInstruction(insn)
	return pr.err
}

// helper functions

func (pr *Printer) writeIndent() {
	if pr.err != nil {
		return
	}
	for i := 0; i < pr.indent; i++ {
		_, err := pr.w.Write([]byte("  "))
		if err != nil {
			pr.err = err
			return
		}
	}
}

func (pr *Printer) printf(format string, args ...interface{}) {
	if pr.err != nil {
		return
	}
	_, err := fmt.Fprintf(pr.w, format, args...)
	if err != nil {
		pr.err = err
	}
}

func (pr *Printer) println(s string) {
	if pr.err != nil {
		return
	}
	_, err := fmt.Fprintln(pr.w, s)
	if err != nil {
		pr.err = err
	}
}

// PrettyPrint is a convenience function that prints a function to a string
func PrettyPrint(fn *Function) (string, error) {
	var sb strings.Builder
	printer := NewPrinter(&sb)
	if err := printer.PrintFunction(fn); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// PrettyPrintBlock is a convenience function that prints a basic block to a string
func PrettyPrintBlock(block *BasicBlock) (string, error) {
	var sb strings.Builder
	printer := NewPrinter(&sb)
	if err := printer.PrintBasicBlock(block); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// PrettyPrintInstruction is a convenience function that prints an instruction to a string
func PrettyPrintInstruction(insn IRInstruction) (string, error) {
	var sb strings.Builder
	printer := NewPrinter(&sb)
	if err := printer.PrintInstruction(insn); err != nil {
		return "", err
	}
	return strings.TrimSpace(sb.String()), nil
}
