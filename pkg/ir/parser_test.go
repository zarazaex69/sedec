package ir

import (
	"strings"
	"testing"
)

func TestParserBasicFunction(t *testing.T) {
	input := `func test_func(i64, i64) i64

bb0:
  result_1 = (x_1 + y_1)
  return result_1
`

	parser := NewParser(strings.NewReader(input))
	fn, err := parser.ParseFunction()
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if fn.Name != "test_func" {
		t.Errorf("expected function name 'test_func', got '%s'", fn.Name)
	}

	if len(fn.Signature.Parameters) != 2 {
		t.Errorf("expected 2 parameters, got %d", len(fn.Signature.Parameters))
	}

	if len(fn.Blocks) != 1 {
		t.Errorf("expected 1 block, got %d", len(fn.Blocks))
	}

	block := fn.Blocks[fn.EntryBlock]
	if len(block.Instructions) != 2 {
		t.Errorf("expected 2 instructions, got %d", len(block.Instructions))
	}
}

func TestParserWithComments(t *testing.T) {
	input := `// this is a test function
func add(i32, i32) i32  // function signature

bb0:  // entry block
  // compute sum
  sum_1 = (a_1 + b_1)  // add operation
  return sum_1  // return result
`

	parser := NewParser(strings.NewReader(input))
	fn, err := parser.ParseFunction()
	if err != nil {
		t.Fatalf("parse with comments failed: %v", err)
	}

	if fn.Name != "add" {
		t.Errorf("expected function name 'add', got '%s'", fn.Name)
	}

	block := fn.Blocks[fn.EntryBlock]
	if len(block.Instructions) != 2 {
		t.Errorf("expected 2 instructions, got %d", len(block.Instructions))
	}
}

func TestParserAllInstructionTypes(t *testing.T) {
	input := `func test_all(i64, *i64) void

bb0:
  x_1 = (a_1 + 42)
  y_1 = load.8 ptr_1
  store.8 ptr_1, x_1
  branch (x_1 == y_1), bb1, bb2

bb1:
  result_1 = call func_ptr(x_1, y_1)
  jump bb3

bb2:
  z_1 = phi [bb0: x_1], [bb1: result_1]
  return

bb3:
  return
`

	parser := NewParser(strings.NewReader(input))
	fn, err := parser.ParseFunction()
	if err != nil {
		t.Fatalf("parse all instructions failed: %v", err)
	}

	if len(fn.Blocks) != 4 {
		t.Errorf("expected 4 blocks, got %d", len(fn.Blocks))
	}

	// verify bb0 has assign, load, store, branch
	bb0 := fn.Blocks[0]
	if len(bb0.Instructions) != 4 {
		t.Errorf("bb0: expected 4 instructions, got %d", len(bb0.Instructions))
	}

	// verify instruction types
	if _, ok := bb0.Instructions[0].(*Assign); !ok {
		t.Errorf("bb0[0]: expected Assign, got %T", bb0.Instructions[0])
	}
	if _, ok := bb0.Instructions[1].(*Load); !ok {
		t.Errorf("bb0[1]: expected Load, got %T", bb0.Instructions[1])
	}
	if _, ok := bb0.Instructions[2].(*Store); !ok {
		t.Errorf("bb0[2]: expected Store, got %T", bb0.Instructions[2])
	}
	if _, ok := bb0.Instructions[3].(*Branch); !ok {
		t.Errorf("bb0[3]: expected Branch, got %T", bb0.Instructions[3])
	}

	// verify bb1 has call and jump
	bb1 := fn.Blocks[1]
	if len(bb1.Instructions) != 2 {
		t.Errorf("bb1: expected 2 instructions, got %d", len(bb1.Instructions))
	}
	if _, ok := bb1.Instructions[0].(*Call); !ok {
		t.Errorf("bb1[0]: expected Call, got %T", bb1.Instructions[0])
	}
	if _, ok := bb1.Instructions[1].(*Jump); !ok {
		t.Errorf("bb1[1]: expected Jump, got %T", bb1.Instructions[1])
	}

	// verify bb2 has phi and return
	bb2 := fn.Blocks[2]
	if len(bb2.Instructions) != 2 {
		t.Errorf("bb2: expected 2 instructions, got %d", len(bb2.Instructions))
	}
	if phi, ok := bb2.Instructions[0].(*Phi); !ok {
		t.Errorf("bb2[0]: expected Phi, got %T", bb2.Instructions[0])
	} else {
		if len(phi.Sources) != 2 {
			t.Errorf("phi: expected 2 sources, got %d", len(phi.Sources))
		}
	}
}

func TestParserBinaryOperators(t *testing.T) {
	tests := []struct {
		expr string
		op   BinaryOperator
	}{
		{"(a + b)", BinOpAdd},
		{"(a - b)", BinOpSub},
		{"(a * b)", BinOpMul},
		{"(a / b)", BinOpDiv},
		{"(a % b)", BinOpMod},
		{"(a /u b)", BinOpUDiv},
		{"(a %u b)", BinOpUMod},
		{"(a & b)", BinOpAnd},
		{"(a | b)", BinOpOr},
		{"(a ^ b)", BinOpXor},
		{"(a << b)", BinOpShl},
		{"(a >> b)", BinOpShr},
		{"(a >>> b)", BinOpSar},
		{"(a == b)", BinOpEq},
		{"(a != b)", BinOpNe},
		{"(a < b)", BinOpLt},
		{"(a <= b)", BinOpLe},
		{"(a > b)", BinOpGt},
		{"(a >= b)", BinOpGe},
		{"(a <u b)", BinOpULt},
		{"(a <=u b)", BinOpULe},
		{"(a >u b)", BinOpUGt},
		{"(a >=u b)", BinOpUGe},
		{"(a && b)", BinOpLogicalAnd},
		{"(a || b)", BinOpLogicalOr},
	}

	for _, tt := range tests {
		t.Run(tt.op.String(), func(t *testing.T) {
			input := "func test() void\n\nbb0:\n  x = " + tt.expr + "\n  return\n"
			parser := NewParser(strings.NewReader(input))
			fn, err := parser.ParseFunction()
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}

			block := fn.Blocks[fn.EntryBlock]
			assign, ok := block.Instructions[0].(*Assign)
			if !ok {
				t.Fatalf("expected Assign, got %T", block.Instructions[0])
			}

			binop, ok := assign.Source.(BinaryOp)
			if !ok {
				t.Fatalf("expected BinaryOp, got %T", assign.Source)
			}

			if binop.Op != tt.op {
				t.Errorf("expected operator %v, got %v", tt.op, binop.Op)
			}
		})
	}
}

func TestParserUnaryOperators(t *testing.T) {
	tests := []struct {
		expr string
		op   UnaryOperator
	}{
		{"(-a)", UnOpNeg},
		{"(~a)", UnOpNot},
		{"(!a)", UnOpLogicalNot},
	}

	for _, tt := range tests {
		t.Run(tt.op.String(), func(t *testing.T) {
			input := "func test() void\n\nbb0:\n  x = " + tt.expr + "\n  return\n"
			parser := NewParser(strings.NewReader(input))
			fn, err := parser.ParseFunction()
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}

			block := fn.Blocks[fn.EntryBlock]
			assign, ok := block.Instructions[0].(*Assign)
			if !ok {
				t.Fatalf("expected Assign, got %T", block.Instructions[0])
			}

			unop, ok := assign.Source.(UnaryOp)
			if !ok {
				t.Fatalf("expected UnaryOp, got %T", assign.Source)
			}

			if unop.Op != tt.op {
				t.Errorf("expected operator %v, got %v", tt.op, unop.Op)
			}
		})
	}
}

func TestParserTypeCast(t *testing.T) {
	input := `func test() void

bb0:
  x = (i32)y
  p = (*i64)addr
  return
`

	parser := NewParser(strings.NewReader(input))
	fn, err := parser.ParseFunction()
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	block := fn.Blocks[fn.EntryBlock]

	// check first cast
	assign1, ok := block.Instructions[0].(*Assign)
	if !ok {
		t.Fatalf("expected Assign, got %T", block.Instructions[0])
	}

	cast1, ok := assign1.Source.(Cast)
	if !ok {
		t.Fatalf("expected Cast, got %T", assign1.Source)
	}

	if _, ok := cast1.TargetType.(IntType); !ok {
		t.Errorf("expected IntType, got %T", cast1.TargetType)
	}

	// check second cast
	assign2, ok := block.Instructions[1].(*Assign)
	if !ok {
		t.Fatalf("expected Assign, got %T", block.Instructions[1])
	}

	cast2, ok := assign2.Source.(Cast)
	if !ok {
		t.Fatalf("expected Cast, got %T", assign2.Source)
	}

	if _, ok := cast2.TargetType.(PointerType); !ok {
		t.Errorf("expected PointerType, got %T", cast2.TargetType)
	}
}

func TestParserConstants(t *testing.T) {
	input := `func test() void

bb0:
  a = 42
  b = -100
  c = 3.14
  d = true
  e = false
  f = null
  return
`

	parser := NewParser(strings.NewReader(input))
	fn, err := parser.ParseFunction()
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	block := fn.Blocks[fn.EntryBlock]

	// check integer constant
	assign0 := block.Instructions[0].(*Assign)
	constExpr0 := assign0.Source.(ConstantExpr)
	intConst := constExpr0.Value.(IntConstant)
	if intConst.Value != 42 {
		t.Errorf("expected 42, got %d", intConst.Value)
	}

	// check negative integer
	assign1 := block.Instructions[1].(*Assign)
	constExpr1 := assign1.Source.(ConstantExpr)
	intConst1 := constExpr1.Value.(IntConstant)
	if intConst1.Value != -100 {
		t.Errorf("expected -100, got %d", intConst1.Value)
	}

	// check float constant
	assign2 := block.Instructions[2].(*Assign)
	constExpr2 := assign2.Source.(ConstantExpr)
	floatConst := constExpr2.Value.(FloatConstant)
	if floatConst.Value != 3.14 {
		t.Errorf("expected 3.14, got %f", floatConst.Value)
	}

	// check boolean constants
	assign3 := block.Instructions[3].(*Assign)
	constExpr3 := assign3.Source.(ConstantExpr)
	boolConst3 := constExpr3.Value.(BoolConstant)
	if !boolConst3.Value {
		t.Errorf("expected true, got false")
	}

	assign4 := block.Instructions[4].(*Assign)
	constExpr4 := assign4.Source.(ConstantExpr)
	boolConst4 := constExpr4.Value.(BoolConstant)
	if boolConst4.Value {
		t.Errorf("expected false, got true")
	}

	// check null constant
	assign5 := block.Instructions[5].(*Assign)
	constExpr5 := assign5.Source.(ConstantExpr)
	if _, ok := constExpr5.Value.(NullConstant); !ok {
		t.Errorf("expected NullConstant, got %T", constExpr5.Value)
	}
}

func TestPrinterBasicFunction(t *testing.T) {
	fn := &Function{
		Name: "test_func",
		Signature: FunctionType{
			ReturnType: IntType{Width: Size8, Signed: true},
			Parameters: []Type{
				IntType{Width: Size8, Signed: true},
				IntType{Width: Size8, Signed: true},
			},
		},
		Blocks:     make(map[BlockID]*BasicBlock),
		EntryBlock: 0,
	}

	block := &BasicBlock{
		ID: 0,
		Instructions: []IRInstruction{
			&Assign{
				Dest: Variable{Name: "result", Type: IntType{Width: Size8, Signed: true}, Version: 1},
				Source: BinaryOp{
					Op:    BinOpAdd,
					Left:  VariableExpr{Var: Variable{Name: "x", Type: IntType{Width: Size8, Signed: true}, Version: 1}},
					Right: VariableExpr{Var: Variable{Name: "y", Type: IntType{Width: Size8, Signed: true}, Version: 1}},
				},
			},
			&Return{
				Value: &Variable{Name: "result", Type: IntType{Width: Size8, Signed: true}, Version: 1},
			},
		},
	}

	fn.Blocks[0] = block

	output, err := PrettyPrint(fn)
	if err != nil {
		t.Fatalf("print failed: %v", err)
	}

	t.Logf("Output:\n%s", output)

	if !strings.Contains(output, "func test_func") {
		t.Errorf("output missing function name")
	}

	if !strings.Contains(output, "bb0:") {
		t.Errorf("output missing block label")
	}

	if !strings.Contains(output, "result_1 = (x_1 + y_1)") {
		t.Errorf("output missing assignment")
	}

	if !strings.Contains(output, "return result_1") {
		t.Errorf("output missing return")
	}
}

func TestRoundTripSimple(t *testing.T) {
	input := `func add(i64, i64) i64

bb0:
  sum_1 = (a_1 + b_1)
  return sum_1
`

	// parse
	parser := NewParser(strings.NewReader(input))
	fn1, err := parser.ParseFunction()
	if err != nil {
		t.Fatalf("first parse failed: %v", err)
	}

	// print
	output1, err := PrettyPrint(fn1)
	if err != nil {
		t.Fatalf("print failed: %v", err)
	}

	// parse again
	parser2 := NewParser(strings.NewReader(output1))
	fn2, err := parser2.ParseFunction()
	if err != nil {
		t.Fatalf("second parse failed: %v\noutput was:\n%s", err, output1)
	}

	// print again
	output2, err := PrettyPrint(fn2)
	if err != nil {
		t.Fatalf("second print failed: %v", err)
	}

	// compare outputs (should be identical after normalization)
	if normalizeWhitespace(output1) != normalizeWhitespace(output2) {
		t.Errorf("round-trip failed:\nfirst output:\n%s\nsecond output:\n%s", output1, output2)
	}
}

func TestRoundTripComplex(t *testing.T) {
	input := `func complex_func(i64, *i64, f64) i32

bb0:
  x_1 = (a_1 + 42)
  y_1 = load.8 ptr_1
  z_1 = (f_1 * 2.5)
  cond_1 = (x_1 > y_1)
  branch cond_1, bb1, bb2

bb1:
  result_1 = call helper(x_1, y_1)
  store.8 ptr_1, result_1
  jump bb3

bb2:
  neg_1 = (-x_1)
  not_1 = (~y_1)
  result_2 = (neg_1 & not_1)
  jump bb3

bb3:
  final_1 = phi [bb1: result_1], [bb2: result_2]
  cast_1 = (i32)final_1
  return cast_1
`

	// parse
	parser := NewParser(strings.NewReader(input))
	fn1, err := parser.ParseFunction()
	if err != nil {
		t.Fatalf("first parse failed: %v", err)
	}

	// verify structure
	if len(fn1.Blocks) != 4 {
		t.Errorf("expected 4 blocks, got %d", len(fn1.Blocks))
	}

	// print
	output1, err := PrettyPrint(fn1)
	if err != nil {
		t.Fatalf("print failed: %v", err)
	}

	// parse again
	parser2 := NewParser(strings.NewReader(output1))
	fn2, err := parser2.ParseFunction()
	if err != nil {
		t.Fatalf("second parse failed: %v\noutput was:\n%s", err, output1)
	}

	// verify structure preserved
	if len(fn2.Blocks) != 4 {
		t.Errorf("after round-trip: expected 4 blocks, got %d", len(fn2.Blocks))
	}

	// print again
	output2, err := PrettyPrint(fn2)
	if err != nil {
		t.Fatalf("second print failed: %v", err)
	}

	// compare outputs
	if normalizeWhitespace(output1) != normalizeWhitespace(output2) {
		t.Errorf("round-trip failed:\nfirst output:\n%s\nsecond output:\n%s", output1, output2)
	}
}

func TestRoundTripWithAllOperators(t *testing.T) {
	input := `func operators(i64, i64) bool

bb0:
  add_1 = (a_1 + b_1)
  sub_1 = (a_1 - b_1)
  mul_1 = (a_1 * b_1)
  div_1 = (a_1 / b_1)
  mod_1 = (a_1 % b_1)
  udiv_1 = (a_1 /u b_1)
  umod_1 = (a_1 %u b_1)
  and_1 = (a_1 & b_1)
  or_1 = (a_1 | b_1)
  xor_1 = (a_1 ^ b_1)
  shl_1 = (a_1 << b_1)
  shr_1 = (a_1 >> b_1)
  sar_1 = (a_1 >>> b_1)
  eq_1 = (a_1 == b_1)
  ne_1 = (a_1 != b_1)
  lt_1 = (a_1 < b_1)
  le_1 = (a_1 <= b_1)
  gt_1 = (a_1 > b_1)
  ge_1 = (a_1 >= b_1)
  ult_1 = (a_1 <u b_1)
  ule_1 = (a_1 <=u b_1)
  ugt_1 = (a_1 >u b_1)
  uge_1 = (a_1 >=u b_1)
  land_1 = (eq_1 && ne_1)
  lor_1 = (eq_1 || ne_1)
  return lor_1
`

	// parse
	parser := NewParser(strings.NewReader(input))
	fn1, err := parser.ParseFunction()
	if err != nil {
		t.Fatalf("first parse failed: %v", err)
	}

	// print
	output1, err := PrettyPrint(fn1)
	if err != nil {
		t.Fatalf("print failed: %v", err)
	}

	// parse again
	parser2 := NewParser(strings.NewReader(output1))
	fn2, err := parser2.ParseFunction()
	if err != nil {
		t.Fatalf("second parse failed: %v\noutput was:\n%s", err, output1)
	}

	// print again
	output2, err := PrettyPrint(fn2)
	if err != nil {
		t.Fatalf("second print failed: %v", err)
	}

	// compare
	if normalizeWhitespace(output1) != normalizeWhitespace(output2) {
		t.Errorf("round-trip failed")
	}
}

func TestRoundTripWithTypes(t *testing.T) {
	input := `func types_test(*i64, [10]i32, f64) void

bb0:
  ptr_deref_1 = load.8 ptr_1
  arr_elem_1 = load.4 arr_1
  float_val_1 = (f_1 + 1.5)
  cast_ptr_1 = (*i32)ptr_1
  cast_int_1 = (i32)ptr_deref_1
  return
`

	// parse
	parser := NewParser(strings.NewReader(input))
	fn1, err := parser.ParseFunction()
	if err != nil {
		t.Fatalf("first parse failed: %v", err)
	}

	// print
	output1, err := PrettyPrint(fn1)
	if err != nil {
		t.Fatalf("print failed: %v", err)
	}

	// parse again
	parser2 := NewParser(strings.NewReader(output1))
	fn2, err := parser2.ParseFunction()
	if err != nil {
		t.Fatalf("second parse failed: %v\noutput was:\n%s", err, output1)
	}

	// print again
	output2, err := PrettyPrint(fn2)
	if err != nil {
		t.Fatalf("second print failed: %v", err)
	}

	// compare
	if normalizeWhitespace(output1) != normalizeWhitespace(output2) {
		t.Errorf("round-trip failed")
	}
}

func TestParserErrorHandling(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "missing function keyword",
			input: "test() void\n\nbb0:\n  return\n",
		},
		{
			name:  "invalid block label",
			input: "func test() void\n\nblock0:\n  return\n",
		},
		{
			name:  "invalid instruction",
			input: "func test() void\n\nbb0:\n  invalid instruction here\n",
		},
		{
			name:  "malformed assignment",
			input: "func test() void\n\nbb0:\n  x y z\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser(strings.NewReader(tt.input))
			_, err := parser.ParseFunction()
			if err == nil {
				t.Errorf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

// helper function to normalize whitespace for comparison
func normalizeWhitespace(s string) string {
	lines := strings.Split(s, "\n")
	var normalized []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "//") {
			normalized = append(normalized, line)
		}
	}
	return strings.Join(normalized, "\n")
}
