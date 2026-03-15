package ir

import (
	"testing"
)

// ============================================================================
// Type System Tests
// ============================================================================

const (
	strVoid = "void"
	strBool = "bool"
	strAdd  = "add"
)

func TestVoidType(t *testing.T) {
	vt := VoidType{}
	if vt.String() != strVoid {
		t.Errorf("expected 'void', got '%s'", vt.String())
	}
	if vt.Size() != 0 {
		t.Errorf("expected size 0, got %d", vt.Size())
	}
}

func TestBoolType(t *testing.T) {
	bt := BoolType{}
	if bt.String() != strBool {
		t.Errorf("expected 'bool', got '%s'", bt.String())
	}
	if bt.Size() != Size1 {
		t.Errorf("expected size 1, got %d", bt.Size())
	}
}

func TestIntType(t *testing.T) {
	tests := []struct {
		name     string
		intType  IntType
		expected string
		size     Size
	}{
		{"i8", IntType{Width: Size1, Signed: true}, "i8", Size1},
		{"u8", IntType{Width: Size1, Signed: false}, "u8", Size1},
		{"i16", IntType{Width: Size2, Signed: true}, "i16", Size2},
		{"u16", IntType{Width: Size2, Signed: false}, "u16", Size2},
		{"i32", IntType{Width: Size4, Signed: true}, "i32", Size4},
		{"u32", IntType{Width: Size4, Signed: false}, "u32", Size4},
		{"i64", IntType{Width: Size8, Signed: true}, "i64", Size8},
		{"u64", IntType{Width: Size8, Signed: false}, "u64", Size8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.intType.String() != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, tt.intType.String())
			}
			if tt.intType.Size() != tt.size {
				t.Errorf("expected size %d, got %d", tt.size, tt.intType.Size())
			}
		})
	}
}

func TestFloatType(t *testing.T) {
	tests := []struct {
		name      string
		floatType FloatType
		expected  string
		size      Size
	}{
		{"f32", FloatType{Width: Size4}, "f32", Size4},
		{"f64", FloatType{Width: Size8}, "f64", Size8},
		{"f80", FloatType{Width: Size10}, "f80", Size10},
		{"f128", FloatType{Width: Size16}, "f128", Size16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.floatType.String() != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, tt.floatType.String())
			}
			if tt.floatType.Size() != tt.size {
				t.Errorf("expected size %d, got %d", tt.size, tt.floatType.Size())
			}
		})
	}
}

func TestPointerType(t *testing.T) {
	pt := PointerType{Pointee: IntType{Width: Size4, Signed: true}}
	if pt.String() != "*i32" {
		t.Errorf("expected '*i32', got '%s'", pt.String())
	}
	if pt.Size() != Size8 {
		t.Errorf("expected size 8, got %d", pt.Size())
	}

	// nested pointer
	ppt := PointerType{Pointee: PointerType{Pointee: IntType{Width: Size4, Signed: true}}}
	if ppt.String() != "**i32" {
		t.Errorf("expected '**i32', got '%s'", ppt.String())
	}
}

func TestArrayType(t *testing.T) {
	at := ArrayType{
		Element: IntType{Width: Size4, Signed: true},
		Length:  10,
	}
	if at.String() != "[10]i32" {
		t.Errorf("expected '[10]i32', got '%s'", at.String())
	}
	if at.Size() != Size(40) {
		t.Errorf("expected size 40, got %d", at.Size())
	}

	// array of pointers
	apt := ArrayType{
		Element: PointerType{Pointee: IntType{Width: Size4, Signed: true}},
		Length:  5,
	}
	if apt.String() != "[5]*i32" {
		t.Errorf("expected '[5]*i32', got '%s'", apt.String())
	}
	if apt.Size() != Size(40) { // 5 * 8 bytes
		t.Errorf("expected size 40, got %d", apt.Size())
	}
}

func TestStructType(t *testing.T) {
	st := StructType{
		Name: "Point",
		Fields: []StructField{
			{Name: "x", Type: IntType{Width: Size4, Signed: true}, Offset: 0},
			{Name: "y", Type: IntType{Width: Size4, Signed: true}, Offset: 4},
		},
	}
	if st.String() != "struct Point" {
		t.Errorf("expected 'struct Point', got '%s'", st.String())
	}
	if st.Size() != Size(8) {
		t.Errorf("expected size 8, got %d", st.Size())
	}

	// anonymous struct
	ast := StructType{
		Fields: []StructField{
			{Name: "a", Type: IntType{Width: Size8, Signed: true}, Offset: 0},
		},
	}
	if ast.String() != "struct" {
		t.Errorf("expected 'struct', got '%s'", ast.String())
	}
}

func TestFunctionType(t *testing.T) {
	ft := FunctionType{
		ReturnType: IntType{Width: Size4, Signed: true},
		Parameters: []Type{
			IntType{Width: Size4, Signed: true},
			IntType{Width: Size4, Signed: true},
		},
		Variadic: false,
	}
	expected := "func(i32, i32) i32"
	if ft.String() != expected {
		t.Errorf("expected '%s', got '%s'", expected, ft.String())
	}
	if ft.Size() != 0 {
		t.Errorf("expected size 0, got %d", ft.Size())
	}

	// variadic function
	vft := FunctionType{
		ReturnType: VoidType{},
		Parameters: []Type{PointerType{Pointee: IntType{Width: Size1, Signed: false}}},
		Variadic:   true,
	}
	expectedVariadic := "func(*u8, ...) void"
	if vft.String() != expectedVariadic {
		t.Errorf("expected '%s', got '%s'", expectedVariadic, vft.String())
	}
}

// ============================================================================
// Variable and Constant Tests
// ============================================================================

func TestVariable(t *testing.T) {
	// non-ssa variable
	v := Variable{
		Name: "x",
		Type: IntType{Width: Size4, Signed: true},
	}
	if v.String() != "x" {
		t.Errorf("expected 'x', got '%s'", v.String())
	}

	// ssa variable
	vssa := Variable{
		Name:    "x",
		Type:    IntType{Width: Size4, Signed: true},
		Version: 3,
	}
	if vssa.String() != "x_3" {
		t.Errorf("expected 'x_3', got '%s'", vssa.String())
	}
}

func TestIntConstant(t *testing.T) {
	// signed constant
	ic := IntConstant{Value: -42, Width: Size4, Signed: true}
	if ic.String() != "-42" {
		t.Errorf("expected '-42', got '%s'", ic.String())
	}
	expectedType := IntType{Width: Size4, Signed: true}
	if ic.Type() != expectedType {
		t.Errorf("expected type %v, got %v", expectedType, ic.Type())
	}

	// unsigned constant
	uc := IntConstant{Value: 255, Width: Size1, Signed: false}
	if uc.String() != "255" {
		t.Errorf("expected '255', got '%s'", uc.String())
	}
}

func TestFloatConstant(t *testing.T) {
	fc := FloatConstant{Value: 3.14159, Width: Size8}
	if fc.String() != "3.141590" {
		t.Errorf("expected '3.141590', got '%s'", fc.String())
	}
	expectedType := FloatType{Width: Size8}
	if fc.Type() != expectedType {
		t.Errorf("expected type %v, got %v", expectedType, fc.Type())
	}
}

func TestBoolConstant(t *testing.T) {
	trueConst := BoolConstant{Value: true}
	if trueConst.String() != strTrue {
		t.Errorf("expected 'true', got '%s'", trueConst.String())
	}

	falseConst := BoolConstant{Value: false}
	if falseConst.String() != strFalse {
		t.Errorf("expected 'false', got '%s'", falseConst.String())
	}
}

func TestNullConstant(t *testing.T) {
	nc := NullConstant{
		PointerType: PointerType{Pointee: IntType{Width: Size4, Signed: true}},
	}
	if nc.String() != strNull {
		t.Errorf("expected 'null', got '%s'", nc.String())
	}
}

// ============================================================================
// Expression Tests
// ============================================================================

func TestVariableExpr(t *testing.T) {
	v := Variable{Name: "x", Type: IntType{Width: Size4, Signed: true}}
	ve := VariableExpr{Var: v}
	if ve.String() != "x" {
		t.Errorf("expected 'x', got '%s'", ve.String())
	}
	if ve.Type() != v.Type {
		t.Errorf("expected type %v, got %v", v.Type, ve.Type())
	}
}

func TestConstantExpr(t *testing.T) {
	c := IntConstant{Value: 42, Width: Size4, Signed: true}
	ce := ConstantExpr{Value: c}
	if ce.String() != "42" {
		t.Errorf("expected '42', got '%s'", ce.String())
	}
}

func TestBinaryOp(t *testing.T) {
	left := VariableExpr{Var: Variable{Name: "a", Type: IntType{Width: Size4, Signed: true}}}
	right := VariableExpr{Var: Variable{Name: "b", Type: IntType{Width: Size4, Signed: true}}}

	tests := []struct {
		op       BinaryOperator
		expected string
	}{
		{BinOpAdd, "(a + b)"},
		{BinOpSub, "(a - b)"},
		{BinOpMul, "(a * b)"},
		{BinOpDiv, "(a / b)"},
		{BinOpMod, "(a % b)"},
		{BinOpAnd, "(a & b)"},
		{BinOpOr, "(a | b)"},
		{BinOpXor, "(a ^ b)"},
		{BinOpShl, "(a << b)"},
		{BinOpShr, "(a >> b)"},
		{BinOpEq, "(a == b)"},
		{BinOpNe, "(a != b)"},
		{BinOpLt, "(a < b)"},
		{BinOpLe, "(a <= b)"},
		{BinOpGt, "(a > b)"},
		{BinOpGe, "(a >= b)"},
	}

	for _, tt := range tests {
		t.Run(tt.op.String(), func(t *testing.T) {
			binop := BinaryOp{Op: tt.op, Left: left, Right: right}
			if binop.String() != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, binop.String())
			}

			// check type for comparison ops
			switch tt.op {
			case BinOpEq, BinOpNe, BinOpLt, BinOpLe, BinOpGt, BinOpGe,
				BinOpULt, BinOpULe, BinOpUGt, BinOpUGe,
				BinOpLogicalAnd, BinOpLogicalOr:
				if binop.Type() != (BoolType{}) {
					t.Errorf("expected bool type for comparison, got %v", binop.Type())
				}
			case BinOpAdd, BinOpSub, BinOpMul, BinOpDiv, BinOpMod, BinOpUDiv, BinOpUMod,
				BinOpAnd, BinOpOr, BinOpXor, BinOpShl, BinOpShr, BinOpSar:
				if binop.Type() != left.Type() {
					t.Errorf("expected type %v, got %v", left.Type(), binop.Type())
				}
			default:
				t.Errorf("unexpected operator: %v", tt.op)
			}
		})
	}
}

func TestUnaryOp(t *testing.T) {
	operand := VariableExpr{Var: Variable{Name: "x", Type: IntType{Width: Size4, Signed: true}}}

	tests := []struct {
		op       UnaryOperator
		expected string
	}{
		{UnOpNeg, "(-x)"},
		{UnOpNot, "(~x)"},
		{UnOpLogicalNot, "(!x)"},
	}

	for _, tt := range tests {
		t.Run(tt.op.String(), func(t *testing.T) {
			unop := UnaryOp{Op: tt.op, Operand: operand}
			if unop.String() != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, unop.String())
			}

			// check type for logical not
			if tt.op == UnOpLogicalNot {
				if unop.Type() != (BoolType{}) {
					t.Errorf("expected bool type for logical not, got %v", unop.Type())
				}
			} else {
				if unop.Type() != operand.Type() {
					t.Errorf("expected type %v, got %v", operand.Type(), unop.Type())
				}
			}
		})
	}
}

func TestCast(t *testing.T) {
	expr := VariableExpr{Var: Variable{Name: "x", Type: IntType{Width: Size4, Signed: true}}}
	targetType := IntType{Width: Size8, Signed: true}
	cast := Cast{Expr: expr, TargetType: targetType}

	expected := "(i64)x"
	if cast.String() != expected {
		t.Errorf("expected '%s', got '%s'", expected, cast.String())
	}
	if cast.Type() != targetType {
		t.Errorf("expected type %v, got %v", targetType, cast.Type())
	}
}

// ============================================================================
// Instruction Tests
// ============================================================================

func TestAssign(t *testing.T) {
	dest := Variable{Name: "x", Type: IntType{Width: Size4, Signed: true}}
	source := ConstantExpr{Value: IntConstant{Value: 42, Width: Size4, Signed: true}}
	assign := Assign{
		Dest:   dest,
		Source: source,
	}

	expected := "x = 42"
	if assign.String() != expected {
		t.Errorf("expected '%s', got '%s'", expected, assign.String())
	}
}

func TestLoad(t *testing.T) {
	dest := Variable{Name: "x", Type: IntType{Width: Size4, Signed: true}}
	addr := VariableExpr{Var: Variable{Name: "ptr", Type: PointerType{Pointee: IntType{Width: Size4, Signed: true}}}}
	load := Load{
		Dest:    dest,
		Address: addr,
		Size:    Size4,
	}

	expected := "x = load.4 ptr"
	if load.String() != expected {
		t.Errorf("expected '%s', got '%s'", expected, load.String())
	}
}

func TestStore(t *testing.T) {
	addr := VariableExpr{Var: Variable{Name: "ptr", Type: PointerType{Pointee: IntType{Width: Size4, Signed: true}}}}
	value := VariableExpr{Var: Variable{Name: "x", Type: IntType{Width: Size4, Signed: true}}}
	store := Store{
		Address: addr,
		Value:   value,
		Size:    Size4,
	}

	expected := "store.4 ptr, x"
	if store.String() != expected {
		t.Errorf("expected '%s', got '%s'", expected, store.String())
	}
}

func TestBranch(t *testing.T) {
	cond := VariableExpr{Var: Variable{Name: "flag", Type: BoolType{}}}
	branch := Branch{
		Condition:   cond,
		TrueTarget:  1,
		FalseTarget: 2,
	}

	expected := "branch flag, bb1, bb2"
	if branch.String() != expected {
		t.Errorf("expected '%s', got '%s'", expected, branch.String())
	}
}

func TestJump(t *testing.T) {
	jump := Jump{Target: 5}
	expected := "jump bb5"
	if jump.String() != expected {
		t.Errorf("expected '%s', got '%s'", expected, jump.String())
	}
}

func TestCall(t *testing.T) {
	// call with return value
	dest := Variable{Name: "result", Type: IntType{Width: Size4, Signed: true}}
	target := VariableExpr{Var: Variable{Name: "func", Type: FunctionType{}}}
	args := []Variable{
		{Name: "a", Type: IntType{Width: Size4, Signed: true}},
		{Name: "b", Type: IntType{Width: Size4, Signed: true}},
	}
	call := Call{
		Dest:   &dest,
		Target: target,
		Args:   args,
	}

	expected := "result = call func(a, b)"
	if call.String() != expected {
		t.Errorf("expected '%s', got '%s'", expected, call.String())
	}

	// void call
	voidCall := Call{
		Dest:   nil,
		Target: target,
		Args:   args,
	}
	expectedVoid := "call func(a, b)"
	if voidCall.String() != expectedVoid {
		t.Errorf("expected '%s', got '%s'", expectedVoid, voidCall.String())
	}
}

func TestReturn(t *testing.T) {
	// return with value
	value := Variable{Name: "x", Type: IntType{Width: Size4, Signed: true}}
	ret := Return{Value: &value}
	expected := "return x"
	if ret.String() != expected {
		t.Errorf("expected '%s', got '%s'", expected, ret.String())
	}

	// void return
	voidRet := Return{Value: nil}
	expectedVoid := "return"
	if voidRet.String() != expectedVoid {
		t.Errorf("expected '%s', got '%s'", expectedVoid, voidRet.String())
	}
}

func TestPhi(t *testing.T) {
	dest := Variable{Name: "x", Type: IntType{Width: Size4, Signed: true}, Version: 3}
	sources := []PhiSource{
		{Block: 1, Var: Variable{Name: "x", Type: IntType{Width: Size4, Signed: true}, Version: 1}},
		{Block: 2, Var: Variable{Name: "x", Type: IntType{Width: Size4, Signed: true}, Version: 2}},
	}
	phi := Phi{
		Dest:    dest,
		Sources: sources,
	}

	expected := "x_3 = phi [bb1: x_1], [bb2: x_2]"
	if phi.String() != expected {
		t.Errorf("expected '%s', got '%s'", expected, phi.String())
	}
}

// ============================================================================
// Source Location Tests
// ============================================================================

func TestSourceLocation(t *testing.T) {
	// with function name
	loc := SourceLocation{
		Address:     0x401000,
		Instruction: "mov rax, rbx",
		Function:    "main",
	}
	expected := "main+0x401000: mov rax, rbx"
	if loc.String() != expected {
		t.Errorf("expected '%s', got '%s'", expected, loc.String())
	}

	// without function name
	locNoFunc := SourceLocation{
		Address:     0x401000,
		Instruction: "mov rax, rbx",
	}
	expectedNoFunc := "0x401000: mov rax, rbx"
	if locNoFunc.String() != expectedNoFunc {
		t.Errorf("expected '%s', got '%s'", expectedNoFunc, locNoFunc.String())
	}
}

// ============================================================================
// Integration Tests
// ============================================================================

func TestComplexExpression(t *testing.T) {
	// (a + b) * (c - d)
	a := VariableExpr{Var: Variable{Name: "a", Type: IntType{Width: Size4, Signed: true}}}
	b := VariableExpr{Var: Variable{Name: "b", Type: IntType{Width: Size4, Signed: true}}}
	c := VariableExpr{Var: Variable{Name: "c", Type: IntType{Width: Size4, Signed: true}}}
	d := VariableExpr{Var: Variable{Name: "d", Type: IntType{Width: Size4, Signed: true}}}

	add := BinaryOp{Op: BinOpAdd, Left: a, Right: b}
	sub := BinaryOp{Op: BinOpSub, Left: c, Right: d}
	mul := BinaryOp{Op: BinOpMul, Left: add, Right: sub}

	expected := "((a + b) * (c - d))"
	if mul.String() != expected {
		t.Errorf("expected '%s', got '%s'", expected, mul.String())
	}
}

func TestBasicBlockConstruction(t *testing.T) {
	// create a simple basic block with multiple instructions
	block := &BasicBlock{
		ID: 0,
		Instructions: []IRInstruction{
			&Assign{
				Dest:   Variable{Name: "x", Type: IntType{Width: Size4, Signed: true}},
				Source: ConstantExpr{Value: IntConstant{Value: 10, Width: Size4, Signed: true}},
			},
			&Assign{
				Dest:   Variable{Name: "y", Type: IntType{Width: Size4, Signed: true}},
				Source: ConstantExpr{Value: IntConstant{Value: 20, Width: Size4, Signed: true}},
			},
			&Assign{
				Dest: Variable{Name: "z", Type: IntType{Width: Size4, Signed: true}},
				Source: BinaryOp{
					Op:    BinOpAdd,
					Left:  VariableExpr{Var: Variable{Name: "x", Type: IntType{Width: Size4, Signed: true}}},
					Right: VariableExpr{Var: Variable{Name: "y", Type: IntType{Width: Size4, Signed: true}}},
				},
			},
		},
		Predecessors: []BlockID{},
		Successors:   []BlockID{1},
	}

	if len(block.Instructions) != 3 {
		t.Errorf("expected 3 instructions, got %d", len(block.Instructions))
	}
	if block.ID != 0 {
		t.Errorf("expected block id 0, got %d", block.ID)
	}
}

func TestFunctionConstruction(t *testing.T) {
	// create a simple function: int add(int a, int b) { return a + b; }
	fn := &Function{
		Name: "add",
		Signature: FunctionType{
			ReturnType: IntType{Width: Size4, Signed: true},
			Parameters: []Type{
				IntType{Width: Size4, Signed: true},
				IntType{Width: Size4, Signed: true},
			},
		},
		Blocks:     make(map[BlockID]*BasicBlock),
		EntryBlock: 0,
		Variables: []Variable{
			{Name: "a", Type: IntType{Width: Size4, Signed: true}},
			{Name: "b", Type: IntType{Width: Size4, Signed: true}},
			{Name: "result", Type: IntType{Width: Size4, Signed: true}},
		},
	}

	block := &BasicBlock{
		ID: 0,
		Instructions: []IRInstruction{
			&Assign{
				Dest: Variable{Name: "result", Type: IntType{Width: Size4, Signed: true}},
				Source: BinaryOp{
					Op:    BinOpAdd,
					Left:  VariableExpr{Var: Variable{Name: "a", Type: IntType{Width: Size4, Signed: true}}},
					Right: VariableExpr{Var: Variable{Name: "b", Type: IntType{Width: Size4, Signed: true}}},
				},
			},
			&Return{
				Value: &Variable{Name: "result", Type: IntType{Width: Size4, Signed: true}},
			},
		},
	}
	fn.Blocks[0] = block

	if fn.Name != strAdd {
		t.Errorf("expected function name 'add', got '%s'", fn.Name)
	}
	if len(fn.Blocks) != 1 {
		t.Errorf("expected 1 block, got %d", len(fn.Blocks))
	}
	if len(fn.Variables) != 3 {
		t.Errorf("expected 3 variables, got %d", len(fn.Variables))
	}
}
