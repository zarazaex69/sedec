package typeinfer

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// makeFunction builds a minimal ir.Function with a single basic block
// containing the provided instructions.
func makeFunction(name string, instrs []ir.IRInstruction) *ir.Function {
	block := &ir.BasicBlock{
		ID:           0,
		Instructions: instrs,
	}
	return &ir.Function{
		Name: name,
		Signature: ir.FunctionType{
			ReturnType: ir.IntType{Width: ir.Size8, Signed: true},
			Parameters: []ir.Type{ir.IntType{Width: ir.Size8, Signed: true}},
		},
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		EntryBlock: 0,
	}
}

// varOf creates an IR variable with the given name and type.
func varOf(name string, t ir.Type) ir.Variable {
	return ir.Variable{Name: name, Type: t}
}

// i64 is a shorthand for a signed 64-bit integer type.
var i64 = ir.IntType{Width: ir.Size8, Signed: true}

// u64 is a shorthand for an unsigned 64-bit integer type.
var u64 = ir.IntType{Width: ir.Size8, Signed: false}

// TestGenerateConstraints_Assign verifies that an assignment emits an equality constraint.
func TestGenerateConstraints_Assign(t *testing.T) {
	dest := varOf("x", i64)
	src := varOf("y", i64)
	assign := ir.Assign{
		Dest:   dest,
		Source: ir.VariableExpr{Var: src},
	}
	fn := makeFunction("f", []ir.IRInstruction{assign})
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()

	if len(cs) == 0 {
		t.Fatal("expected at least one constraint from assign, got none")
	}
	found := false
	for _, c := range cs {
		if c.Kind == ConstraintEquality && c.Left.Name == dest.String() && c.Right.Name == src.String() {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected equality constraint x eq y, got: %v", cs)
	}
}

// TestGenerateConstraints_Load verifies pointer and field constraints from a load.
func TestGenerateConstraints_Load(t *testing.T) {
	dest := varOf("v", i64)
	base := varOf("ptr", ir.PointerType{Pointee: i64})
	// address = ptr + 8
	addr := ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  ir.VariableExpr{Var: base},
		Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 8, Width: ir.Size8, Signed: false}},
	}
	load := ir.Load{Dest: dest, Address: addr, Size: ir.Size8}
	fn := makeFunction("f", []ir.IRInstruction{load})
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()

	hasPtr := false
	hasField := false
	for _, c := range cs {
		if c.Kind == ConstraintPointerTo {
			hasPtr = true
		}
		if c.Kind == ConstraintFieldAccess && c.FieldOffset == 8 {
			hasField = true
		}
	}
	if !hasPtr {
		t.Error("expected ConstraintPointerTo from load, not found")
	}
	if !hasField {
		t.Error("expected ConstraintFieldAccess with offset 8 from load, not found")
	}
}

// TestGenerateConstraints_Store verifies pointer constraint from a store.
func TestGenerateConstraints_Store(t *testing.T) {
	val := varOf("v", i64)
	ptr := varOf("p", ir.PointerType{Pointee: i64})
	store := ir.Store{
		Address: ir.VariableExpr{Var: ptr},
		Value:   ir.VariableExpr{Var: val},
		Size:    ir.Size8,
	}
	fn := makeFunction("f", []ir.IRInstruction{store})
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()

	for _, c := range cs {
		if c.Kind == ConstraintPointerTo {
			return
		}
	}
	t.Error("expected ConstraintPointerTo from store, not found")
}

// TestGenerateConstraints_Branch verifies that branch condition is constrained to bool.
func TestGenerateConstraints_Branch(t *testing.T) {
	cond := varOf("cond", ir.BoolType{})
	branch := ir.Branch{
		Condition:   ir.VariableExpr{Var: cond},
		TrueTarget:  1,
		FalseTarget: 2,
	}
	fn := makeFunction("f", []ir.IRInstruction{branch})
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()

	for _, c := range cs {
		if c.Kind == ConstraintEquality && c.Right.Concrete != nil {
			if _, ok := c.Right.Concrete.(ir.BoolType); ok {
				return
			}
		}
	}
	t.Error("expected bool equality constraint from branch condition, not found")
}

// TestGenerateConstraints_Call verifies return and param constraints from a call.
func TestGenerateConstraints_Call(t *testing.T) {
	dest := varOf("ret", i64)
	arg0 := varOf("a0", i64)
	target := varOf("fn_ptr", ir.FunctionType{
		ReturnType: i64,
		Parameters: []ir.Type{i64},
	})
	call := ir.Call{
		Dest:   &dest,
		Target: ir.VariableExpr{Var: target},
		Args:   []ir.Variable{arg0},
	}
	fn := makeFunction("f", []ir.IRInstruction{call})
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()

	hasRet := false
	hasParam := false
	for _, c := range cs {
		if c.Kind == ConstraintReturnType {
			hasRet = true
		}
		if c.Kind == ConstraintParamType && c.ParamIndex == 0 {
			hasParam = true
		}
	}
	if !hasRet {
		t.Error("expected ConstraintReturnType from call, not found")
	}
	if !hasParam {
		t.Error("expected ConstraintParamType[0] from call, not found")
	}
}

// TestGenerateConstraints_Phi verifies that phi sources are unified with the destination.
func TestGenerateConstraints_Phi(t *testing.T) {
	dest := varOf("x_3", i64)
	src0 := varOf("x_1", i64)
	src1 := varOf("x_2", i64)
	phi := ir.Phi{
		Dest: dest,
		Sources: []ir.PhiSource{
			{Block: 0, Var: src0},
			{Block: 1, Var: src1},
		},
	}
	fn := makeFunction("f", []ir.IRInstruction{phi})
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()

	eqCount := 0
	for _, c := range cs {
		if c.Kind == ConstraintEquality && c.Left.Name == dest.String() {
			eqCount++
		}
	}
	if eqCount < 2 {
		t.Errorf("expected 2 equality constraints from phi (one per source), got %d", eqCount)
	}
}

// TestGenerateConstraints_BinaryOp_Comparison verifies bool result for comparison ops.
func TestGenerateConstraints_BinaryOp_Comparison(t *testing.T) {
	a := varOf("a", i64)
	b := varOf("b", i64)
	dest := varOf("cmp", ir.BoolType{})
	cmpExpr := ir.BinaryOp{
		Op:    ir.BinOpLt,
		Left:  ir.VariableExpr{Var: a},
		Right: ir.VariableExpr{Var: b},
	}
	assign := ir.Assign{Dest: dest, Source: cmpExpr}
	fn := makeFunction("f", []ir.IRInstruction{assign})
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()

	for _, c := range cs {
		if c.Kind == ConstraintEquality && c.Right.Concrete != nil {
			if _, ok := c.Right.Concrete.(ir.BoolType); ok {
				return
			}
		}
	}
	t.Error("expected bool equality constraint from comparison, not found")
}

// TestGenerateConstraints_UnsignedDiv verifies unsigned constraints for udiv.
func TestGenerateConstraints_UnsignedDiv(t *testing.T) {
	a := varOf("a", u64)
	b := varOf("b", u64)
	dest := varOf("q", u64)
	divExpr := ir.BinaryOp{
		Op:    ir.BinOpUDiv,
		Left:  ir.VariableExpr{Var: a},
		Right: ir.VariableExpr{Var: b},
	}
	assign := ir.Assign{Dest: dest, Source: divExpr}
	fn := makeFunction("f", []ir.IRInstruction{assign})
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()

	// at least one constraint must reference a synthetic uint var
	for _, c := range cs {
		if c.Kind == ConstraintEquality && len(c.Right.Name) > 5 && c.Right.Name[:5] == "$uint" {
			return
		}
	}
	t.Error("expected synthetic uint constraint from udiv, not found")
}

// TestGenerateConstraints_Return verifies return value is unified with function return type.
func TestGenerateConstraints_Return(t *testing.T) {
	retVal := varOf("r", i64)
	ret := ir.Return{Value: &retVal}
	fn := makeFunction("f", []ir.IRInstruction{ret})
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()

	for _, c := range cs {
		if c.Kind == ConstraintEquality && c.Right.Name == "$ret_f" {
			return
		}
	}
	t.Error("expected return type equality constraint, not found")
}

// TestGenerateConstraints_Deterministic verifies that two runs produce identical constraints.
func TestGenerateConstraints_Deterministic(t *testing.T) {
	dest := varOf("x", i64)
	src := varOf("y", i64)
	assign := ir.Assign{Dest: dest, Source: ir.VariableExpr{Var: src}}
	fn := makeFunction("f", []ir.IRInstruction{assign})

	cs1 := NewConstraintGenerator(fn).GenerateConstraints()
	cs2 := NewConstraintGenerator(fn).GenerateConstraints()

	if len(cs1) != len(cs2) {
		t.Fatalf("non-deterministic: run1=%d constraints, run2=%d constraints", len(cs1), len(cs2))
	}
	for i := range cs1 {
		if cs1[i].Kind != cs2[i].Kind || cs1[i].Left.Name != cs2[i].Left.Name || cs1[i].Right.Name != cs2[i].Right.Name {
			t.Errorf("constraint %d differs between runs: %v vs %v", i, cs1[i], cs2[i])
		}
	}
}

// TestGenerateConstraints_EmptyFunction verifies no panic on empty function.
func TestGenerateConstraints_EmptyFunction(_ *testing.T) {
	fn := makeFunction("empty", nil)
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()
	// signature seeds may produce constraints; just verify no panic
	_ = cs
}

// TestConstraintKind_String verifies all ConstraintKind values have string representations.
func TestConstraintKind_String(t *testing.T) {
	kinds := []ConstraintKind{
		ConstraintEquality, ConstraintSubtype, ConstraintFieldAccess,
		ConstraintPointerTo, ConstraintArrayElement, ConstraintReturnType, ConstraintParamType,
	}
	for _, k := range kinds {
		s := k.String()
		if s == "" || (len(s) >= 7 && s[:7] == "unknown") {
			t.Errorf("ConstraintKind %d has no proper string representation: %q", k, s)
		}
	}
}

// TestTypeVar_String verifies TypeVar string formatting.
func TestTypeVar_String(t *testing.T) {
	tv := TypeVar{Name: "rax_1"}
	if tv.String() != "rax_1" {
		t.Errorf("expected 'rax_1', got %q", tv.String())
	}
	tv2 := TypeVar{Name: "rax_1", Concrete: i64}
	if tv2.String() != "rax_1:i64" {
		t.Errorf("expected 'rax_1:i64', got %q", tv2.String())
	}
}
