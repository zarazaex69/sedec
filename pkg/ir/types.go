package ir

import "fmt"

// Address represents a virtual address in the binary
type Address uint64

// Size represents the size of a value in bytes
type Size uint8

// Size constants for common data widths
const (
	Size1  Size = 1  // 8-bit
	Size2  Size = 2  // 16-bit
	Size4  Size = 4  // 32-bit
	Size8  Size = 8  // 64-bit
	Size10 Size = 10 // 80-bit (x87 extended precision)
	Size16 Size = 16 // 128-bit (xmm registers)
	Size32 Size = 32 // 256-bit (ymm registers)
	Size64 Size = 64 // 512-bit (zmm registers)
)

// SourceLocation tracks the original assembly address for traceability
type SourceLocation struct {
	Address     Address // virtual address in binary
	Instruction string  // original assembly mnemonic (e.g., "mov rax, rbx")
	Function    string  // function name if known
}

// String returns human-readable source location
func (s SourceLocation) String() string {
	if s.Function != "" {
		return fmt.Sprintf("%s+0x%x: %s", s.Function, s.Address, s.Instruction)
	}
	return fmt.Sprintf("0x%x: %s", s.Address, s.Instruction)
}

// ============================================================================
// Type System
// ============================================================================

// Keywords for types
const (
	KeywordVoid = "void"
	KeywordBool = "bool"
)

// string constants for ir representation
const (
	strStruct   = "struct"
	strEllipsis = "..."
	strTrue     = "true"
	strFalse    = "false"
	strNull     = "null"
	strReturn   = "return"
)

// Type represents the type of a value in IR
type Type interface {
	isType()
	String() string
	Size() Size // size in bytes, 0 for void/function types
}

// VoidType represents the absence of a value
type VoidType struct{}

func (VoidType) isType() {}

func (VoidType) String() string { return KeywordVoid }

// Size returns the size in bytes (0 for void)
func (VoidType) Size() Size { return 0 }

// BoolType represents a boolean value (1 byte)
type BoolType struct{}

func (BoolType) isType() {}

func (BoolType) String() string { return KeywordBool }

// Size returns the size in bytes (1 for bool)
func (BoolType) Size() Size { return Size1 }

// IntType represents an integer value
type IntType struct {
	Width  Size // 1, 2, 4, 8 bytes
	Signed bool
}

func (IntType) isType() {}
func (t IntType) String() string {
	if t.Signed {
		return fmt.Sprintf("i%d", t.Width*8)
	}
	return fmt.Sprintf("u%d", t.Width*8)
}

// Size returns the size in bytes
func (t IntType) Size() Size { return t.Width }

// FloatType represents a floating-point value
type FloatType struct {
	Width Size // 4 (float32), 8 (float64), 10 (x87 extended), 16 (float128)
}

func (FloatType) isType() {}
func (t FloatType) String() string {
	switch t.Width {
	case Size1, Size2:
		// unusual float sizes, use generic format
		return fmt.Sprintf("f%d", t.Width*8)
	case Size4:
		return "f32"
	case Size8:
		return "f64"
	case Size10:
		return "f80"
	case Size16:
		return "f128"
	case Size32:
		return "f256"
	case Size64:
		return "f512"
	default:
		return fmt.Sprintf("f%d", t.Width*8)
	}
}

// Size returns the size in bytes
func (t FloatType) Size() Size { return t.Width }

// PointerType represents a pointer to another type
type PointerType struct {
	Pointee Type
}

func (PointerType) isType() {}
func (t PointerType) String() string {
	return fmt.Sprintf("*%s", t.Pointee.String())
}

// Size returns the size in bytes (8 for 64-bit pointers)
func (PointerType) Size() Size { return Size8 }

// ArrayType represents a fixed-size array
type ArrayType struct {
	Element Type
	Length  uint64
}

func (ArrayType) isType() {}
func (t ArrayType) String() string {
	return fmt.Sprintf("[%d]%s", t.Length, t.Element.String())
}

// Size returns the size in bytes (element size * length, capped at 255)
func (t ArrayType) Size() Size {
	elemSize := t.Element.Size()
	totalSize := uint64(elemSize) * t.Length
	if totalSize > 255 {
		return 255 // cap at max Size value
	}
	return Size(totalSize)
}

// StructField represents a field in a structure
type StructField struct {
	Name   string
	Type   Type
	Offset uint64 // byte offset from struct start
}

// StructType represents a structure with named fields
type StructType struct {
	Name   string
	Fields []StructField
}

func (StructType) isType() {}
func (t StructType) String() string {
	if t.Name != "" {
		return fmt.Sprintf("%s %s", strStruct, t.Name)
	}
	return strStruct
}

// Size returns the size in bytes (computed from last field, capped at 255)
func (t StructType) Size() Size {
	if len(t.Fields) == 0 {
		return 0
	}
	// compute total size from last field
	lastField := t.Fields[len(t.Fields)-1]
	totalSize := lastField.Offset + uint64(lastField.Type.Size())
	if totalSize > 255 {
		return 255
	}
	return Size(totalSize)
}

// FunctionType represents a function signature
type FunctionType struct {
	ReturnType Type
	Parameters []Type
	Variadic   bool
}

func (FunctionType) isType() {}
func (t FunctionType) String() string {
	params := ""
	for i, p := range t.Parameters {
		if i > 0 {
			params += ", "
		}
		params += p.String()
	}
	if t.Variadic {
		if len(t.Parameters) > 0 {
			params += ", "
		}
		params += strEllipsis
	}
	return fmt.Sprintf("func(%s) %s", params, t.ReturnType.String())
}

// Size returns the size in bytes (0 for function types)
func (FunctionType) Size() Size { return 0 }

// ============================================================================
// Variables and Constants
// ============================================================================

// Variable represents a named variable in IR
type Variable struct {
	Name    string
	Type    Type
	Version int // ssa version number, 0 for non-ssa
}

func (v Variable) String() string {
	if v.Version > 0 {
		return fmt.Sprintf("%s_%d", v.Name, v.Version)
	}
	return v.Name
}

// Constant represents a compile-time constant value
type Constant interface {
	isConstant()
	Type() Type
	String() string
}

// IntConstant represents an integer constant
type IntConstant struct {
	Value  int64
	Width  Size
	Signed bool
}

func (IntConstant) isConstant() {}

// Type returns the type of the constant
func (c IntConstant) Type() Type {
	return IntType{Width: c.Width, Signed: c.Signed}
}
func (c IntConstant) String() string {
	if c.Signed {
		return fmt.Sprintf("%d", c.Value)
	}
	// #nosec G115 - intentional conversion for unsigned display
	return fmt.Sprintf("%d", uint64(c.Value))
}

// FloatConstant represents a floating-point constant
type FloatConstant struct {
	Value float64
	Width Size
}

func (FloatConstant) isConstant() {}

// Type returns the type of the constant
func (c FloatConstant) Type() Type {
	return FloatType{Width: c.Width}
}
func (c FloatConstant) String() string {
	return fmt.Sprintf("%f", c.Value)
}

// BoolConstant represents a boolean constant
type BoolConstant struct {
	Value bool
}

func (BoolConstant) isConstant() {}

// Type returns the type of the constant
func (BoolConstant) Type() Type {
	return BoolType{}
}
func (c BoolConstant) String() string {
	if c.Value {
		return strTrue
	}
	return strFalse
}

// NullConstant represents a null pointer
type NullConstant struct {
	PointerType Type
}

func (NullConstant) isConstant() {}

// Type returns the type of the constant
func (c NullConstant) Type() Type {
	return c.PointerType
}
func (NullConstant) String() string {
	return strNull
}

// ============================================================================
// Expressions
// ============================================================================

// Expression represents a value-producing operation
type Expression interface {
	isExpression()
	Type() Type
	String() string
}

// VariableExpr represents a variable reference
type VariableExpr struct {
	Var Variable
}

func (VariableExpr) isExpression() {}

// Type returns the type of the expression
func (e VariableExpr) Type() Type {
	return e.Var.Type
}
func (e VariableExpr) String() string {
	return e.Var.String()
}

// ConstantExpr represents a constant value
type ConstantExpr struct {
	Value Constant
}

func (ConstantExpr) isExpression() {}

// Type returns the type of the expression
func (e ConstantExpr) Type() Type {
	return e.Value.Type()
}
func (e ConstantExpr) String() string {
	return e.Value.String()
}

// BinaryOperator represents a binary operation
type BinaryOperator int

// Binary operators
const (
	// BinOpAdd represents addition
	BinOpAdd BinaryOperator = iota
	// BinOpSub represents subtraction
	BinOpSub
	// BinOpMul represents multiplication
	BinOpMul
	// BinOpDiv represents signed division
	BinOpDiv
	// BinOpMod represents signed modulo
	BinOpMod
	// BinOpUDiv represents unsigned division
	BinOpUDiv
	// BinOpUMod represents unsigned modulo
	BinOpUMod

	// BinOpAnd represents bitwise and
	BinOpAnd
	// BinOpOr represents bitwise or
	BinOpOr
	// BinOpXor represents bitwise xor
	BinOpXor
	// BinOpShl represents left shift
	BinOpShl
	// BinOpShr represents logical right shift
	BinOpShr
	// BinOpSar represents arithmetic right shift
	BinOpSar

	// BinOpEq represents equality comparison
	BinOpEq
	// BinOpNe represents inequality comparison
	BinOpNe
	// BinOpLt represents signed less than
	BinOpLt
	// BinOpLe represents signed less or equal
	BinOpLe
	// BinOpGt represents signed greater than
	BinOpGt
	// BinOpGe represents signed greater or equal
	BinOpGe
	// BinOpULt represents unsigned less than
	BinOpULt
	// BinOpULe represents unsigned less or equal
	BinOpULe
	// BinOpUGt represents unsigned greater than
	BinOpUGt
	// BinOpUGe represents unsigned greater or equal
	BinOpUGe

	// BinOpLogicalAnd represents logical and
	BinOpLogicalAnd
	// BinOpLogicalOr represents logical or
	BinOpLogicalOr
)

func (op BinaryOperator) String() string {
	switch op {
	case BinOpAdd:
		return "+"
	case BinOpSub:
		return "-"
	case BinOpMul:
		return "*"
	case BinOpDiv:
		return "/"
	case BinOpMod:
		return "%"
	case BinOpUDiv:
		return "/u"
	case BinOpUMod:
		return "%u"
	case BinOpAnd:
		return "&"
	case BinOpOr:
		return "|"
	case BinOpXor:
		return "^"
	case BinOpShl:
		return "<<"
	case BinOpShr:
		return ">>"
	case BinOpSar:
		return ">>>"
	case BinOpEq:
		return "=="
	case BinOpNe:
		return "!="
	case BinOpLt:
		return "<"
	case BinOpLe:
		return "<="
	case BinOpGt:
		return ">"
	case BinOpGe:
		return ">="
	case BinOpULt:
		return "<u"
	case BinOpULe:
		return "<=u"
	case BinOpUGt:
		return ">u"
	case BinOpUGe:
		return ">=u"
	case BinOpLogicalAnd:
		return "&&"
	case BinOpLogicalOr:
		return "||"
	default:
		return "?"
	}
}

// BinaryOp represents a binary operation
type BinaryOp struct {
	Op    BinaryOperator
	Left  Expression
	Right Expression
}

func (BinaryOp) isExpression() {}

// Type returns the type of the expression
func (e BinaryOp) Type() Type {
	// comparison and logical ops return bool
	switch e.Op {
	case BinOpEq, BinOpNe, BinOpLt, BinOpLe, BinOpGt, BinOpGe,
		BinOpULt, BinOpULe, BinOpUGt, BinOpUGe,
		BinOpLogicalAnd, BinOpLogicalOr:
		return BoolType{}
	case BinOpAdd, BinOpSub, BinOpMul, BinOpDiv, BinOpMod, BinOpUDiv, BinOpUMod,
		BinOpAnd, BinOpOr, BinOpXor, BinOpShl, BinOpShr, BinOpSar:
		// arithmetic and bitwise ops return left operand type
		return e.Left.Type()
	default:
		return e.Left.Type()
	}
}
func (e BinaryOp) String() string {
	return fmt.Sprintf("(%s %s %s)", e.Left.String(), e.Op.String(), e.Right.String())
}

// UnaryOperator represents a unary operation
type UnaryOperator int

// Unary operators
const (
	// UnOpNeg represents arithmetic negation
	UnOpNeg UnaryOperator = iota
	// UnOpNot represents bitwise not
	UnOpNot
	// UnOpLogicalNot represents logical not
	UnOpLogicalNot
)

func (op UnaryOperator) String() string {
	switch op {
	case UnOpNeg:
		return "-"
	case UnOpNot:
		return "~"
	case UnOpLogicalNot:
		return "!"
	default:
		return "?"
	}
}

// UnaryOp represents a unary operation
type UnaryOp struct {
	Op      UnaryOperator
	Operand Expression
}

func (UnaryOp) isExpression() {}

// Type returns the type of the expression
func (e UnaryOp) Type() Type {
	if e.Op == UnOpLogicalNot {
		return BoolType{}
	}
	return e.Operand.Type()
}
func (e UnaryOp) String() string {
	return fmt.Sprintf("(%s%s)", e.Op.String(), e.Operand.String())
}

// Cast represents a type conversion
type Cast struct {
	Expr       Expression
	TargetType Type
}

func (Cast) isExpression() {}

// Type returns the type of the expression
func (e Cast) Type() Type {
	return e.TargetType
}
func (e Cast) String() string {
	return fmt.Sprintf("(%s)%s", e.TargetType.String(), e.Expr.String())
}

// LoadExpr represents an inlined memory dereference expression.
// it is produced by the expression condensation pass when a single-use
// Load instruction is inlined at its use site.
// example: *(uint64_t*)(rip + 141195)
type LoadExpr struct {
	Address Expression
	Size    Size
}

func (LoadExpr) isExpression() {}

// Type returns a pointer-sized unsigned integer type matching the load size.
func (e LoadExpr) Type() Type {
	return IntType{Width: e.Size, Signed: false}
}

func (e LoadExpr) String() string {
	return fmt.Sprintf("*(uint%d_t*)(%s)", e.Size*8, e.Address.String())
}

// ============================================================================
// IR Instructions
// ============================================================================

// IRInstruction represents a single IR instruction
//
//nolint:revive // IRInstruction is intentional, follows LLVM naming convention
type IRInstruction interface {
	isIRInstruction()
	Location() SourceLocation
	String() string
}

// baseInstruction provides common fields for all instructions
type baseInstruction struct {
	Loc SourceLocation
}

func (b baseInstruction) Location() SourceLocation {
	return b.Loc
}

// Assign represents an assignment: dest = source
type Assign struct {
	baseInstruction
	Dest   Variable
	Source Expression
}

func (Assign) isIRInstruction() {}
func (a Assign) String() string {
	return fmt.Sprintf("%s = %s", a.Dest.String(), a.Source.String())
}

// Load represents a memory load: dest = *address
type Load struct {
	baseInstruction
	Dest    Variable
	Address Expression
	Size    Size
}

func (Load) isIRInstruction() {}
func (l Load) String() string {
	return fmt.Sprintf("%s = load.%d %s", l.Dest.String(), l.Size, l.Address.String())
}

// Store represents a memory store: *address = value
type Store struct {
	baseInstruction
	Address Expression
	Value   Expression
	Size    Size
}

func (Store) isIRInstruction() {}
func (s Store) String() string {
	return fmt.Sprintf("store.%d %s, %s", s.Size, s.Address.String(), s.Value.String())
}

// BlockID represents a basic block identifier
type BlockID uint64

// Branch represents a conditional branch
type Branch struct {
	baseInstruction
	Condition   Expression
	TrueTarget  BlockID
	FalseTarget BlockID
}

func (Branch) isIRInstruction() {}
func (b Branch) String() string {
	return fmt.Sprintf("branch %s, bb%d, bb%d", b.Condition.String(), b.TrueTarget, b.FalseTarget)
}

// Jump represents an unconditional jump
type Jump struct {
	baseInstruction
	Target BlockID
}

func (Jump) isIRInstruction() {}
func (j Jump) String() string {
	return fmt.Sprintf("jump bb%d", j.Target)
}

// Call represents a function call
type Call struct {
	baseInstruction
	Dest   *Variable // nil for void return
	Target Expression
	Args   []Variable
}

func (Call) isIRInstruction() {}
func (c Call) String() string {
	args := ""
	for i, arg := range c.Args {
		if i > 0 {
			args += ", "
		}
		args += arg.String()
	}
	if c.Dest != nil {
		return fmt.Sprintf("%s = call %s(%s)", c.Dest.String(), c.Target.String(), args)
	}
	return fmt.Sprintf("call %s(%s)", c.Target.String(), args)
}

// Return represents a function return
type Return struct {
	baseInstruction
	Value *Variable // nil for void return
}

func (Return) isIRInstruction() {}
func (r Return) String() string {
	if r.Value != nil {
		return fmt.Sprintf("%s %s", strReturn, r.Value.String())
	}
	return strReturn
}

// PhiSource represents a single source in a phi node
type PhiSource struct {
	Block BlockID
	Var   Variable
}

// Phi represents an SSA phi node
type Phi struct {
	baseInstruction
	Dest    Variable
	Sources []PhiSource
}

func (Phi) isIRInstruction() {}
func (p Phi) String() string {
	sources := ""
	for i, src := range p.Sources {
		if i > 0 {
			sources += ", "
		}
		sources += fmt.Sprintf("[bb%d: %s]", src.Block, src.Var.String())
	}
	return fmt.Sprintf("%s = phi %s", p.Dest.String(), sources)
}

// ============================================================================
// Basic Block and Function
// ============================================================================

// BasicBlock represents a sequence of instructions with single entry/exit
type BasicBlock struct {
	ID           BlockID
	Instructions []IRInstruction
	Predecessors []BlockID
	Successors   []BlockID
}

// Function represents a complete function in IR
type Function struct {
	Name       string
	Signature  FunctionType
	Blocks     map[BlockID]*BasicBlock
	EntryBlock BlockID
	Variables  []Variable // all variables used in function
}
