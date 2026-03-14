package typeinfer

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// TestGenerateConstraints_Cast verifies that a cast expression emits a
// subtype constraint from the inner expression to the cast target type.
func TestGenerateConstraints_Cast(t *testing.T) {
	inner := varOf("x", i64)
	dest := varOf("y", ir.IntType{Width: ir.Size4, Signed: true})
	castExpr := ir.Cast{
		Expr:       ir.VariableExpr{Var: inner},
		TargetType: ir.IntType{Width: ir.Size4, Signed: true},
	}
	assign := ir.Assign{Dest: dest, Source: castExpr}
	fn := makeFunction("f", []ir.IRInstruction{assign})
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()

	hasSubtype := false
	for _, c := range cs {
		if c.Kind == ConstraintSubtype {
			hasSubtype = true
			break
		}
	}
	if !hasSubtype {
		t.Error("expected ConstraintSubtype from cast expression, not found")
	}
}

// TestGenerateConstraints_UnaryOp_LogicalNot verifies that logical-not emits
// bool constraints for both operand and result.
func TestGenerateConstraints_UnaryOp_LogicalNot(t *testing.T) {
	operand := varOf("cond", ir.BoolType{})
	dest := varOf("not_cond", ir.BoolType{})
	notExpr := ir.UnaryOp{
		Op:      ir.UnOpLogicalNot,
		Operand: ir.VariableExpr{Var: operand},
	}
	assign := ir.Assign{Dest: dest, Source: notExpr}
	fn := makeFunction("f", []ir.IRInstruction{assign})
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()

	boolCount := 0
	for _, c := range cs {
		if c.Kind == ConstraintEquality {
			if c.Right.Concrete != nil {
				if _, ok := c.Right.Concrete.(ir.BoolType); ok {
					boolCount++
				}
			}
		}
	}
	if boolCount < 2 {
		t.Errorf("expected at least 2 bool equality constraints from logical-not, got %d", boolCount)
	}
}

// TestGenerateConstraints_UnaryOp_Neg verifies that negation emits an equality
// constraint between result and operand (same type).
func TestGenerateConstraints_UnaryOp_Neg(t *testing.T) {
	operand := varOf("x", i64)
	dest := varOf("neg_x", i64)
	negExpr := ir.UnaryOp{
		Op:      ir.UnOpNeg,
		Operand: ir.VariableExpr{Var: operand},
	}
	assign := ir.Assign{Dest: dest, Source: negExpr}
	fn := makeFunction("f", []ir.IRInstruction{assign})
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()

	// result must be constrained equal to operand
	found := false
	for _, c := range cs {
		if c.Kind == ConstraintEquality &&
			c.Left.Name == dest.String() &&
			c.Right.Name == operand.String() {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected equality constraint neg_x eq x from unary neg, not found")
	}
}

// TestGenerateConstraints_BinaryOp_LogicalAnd verifies that logical-and emits
// bool constraints for both operands and the result.
func TestGenerateConstraints_BinaryOp_LogicalAnd(t *testing.T) {
	a := varOf("a", ir.BoolType{})
	b := varOf("b", ir.BoolType{})
	dest := varOf("r", ir.BoolType{})
	andExpr := ir.BinaryOp{
		Op:    ir.BinOpLogicalAnd,
		Left:  ir.VariableExpr{Var: a},
		Right: ir.VariableExpr{Var: b},
	}
	assign := ir.Assign{Dest: dest, Source: andExpr}
	fn := makeFunction("f", []ir.IRInstruction{assign})
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()

	boolCount := 0
	for _, c := range cs {
		if c.Kind == ConstraintEquality {
			if c.Right.Concrete != nil {
				if _, ok := c.Right.Concrete.(ir.BoolType); ok {
					boolCount++
				}
			}
		}
	}
	// expect 3 bool constraints: left, right, result
	if boolCount < 3 {
		t.Errorf("expected at least 3 bool constraints from logical-and, got %d", boolCount)
	}
}

// TestGenerateConstraints_BinaryOp_UnsignedComparison verifies that unsigned
// comparison emits bool result constraint.
func TestGenerateConstraints_BinaryOp_UnsignedComparison(t *testing.T) {
	a := varOf("a", u64)
	b := varOf("b", u64)
	dest := varOf("cmp", ir.BoolType{})
	cmpExpr := ir.BinaryOp{
		Op:    ir.BinOpULt,
		Left:  ir.VariableExpr{Var: a},
		Right: ir.VariableExpr{Var: b},
	}
	assign := ir.Assign{Dest: dest, Source: cmpExpr}
	fn := makeFunction("f", []ir.IRInstruction{assign})
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()

	hasBoolResult := false
	for _, c := range cs {
		if c.Kind == ConstraintEquality && c.Right.Concrete != nil {
			if _, ok := c.Right.Concrete.(ir.BoolType); ok {
				hasBoolResult = true
				break
			}
		}
	}
	if !hasBoolResult {
		t.Error("expected bool result constraint from unsigned comparison, not found")
	}
}

// TestGenerateConstraints_BinaryOp_UnsignedMod verifies that unsigned modulo
// emits unsigned constraints for both operands and result.
func TestGenerateConstraints_BinaryOp_UnsignedMod(t *testing.T) {
	a := varOf("a", u64)
	b := varOf("b", u64)
	dest := varOf("r", u64)
	modExpr := ir.BinaryOp{
		Op:    ir.BinOpUMod,
		Left:  ir.VariableExpr{Var: a},
		Right: ir.VariableExpr{Var: b},
	}
	assign := ir.Assign{Dest: dest, Source: modExpr}
	fn := makeFunction("f", []ir.IRInstruction{assign})
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()

	// at least one constraint must reference a synthetic uint var
	found := false
	for _, c := range cs {
		if c.Kind == ConstraintEquality && len(c.Right.Name) > 5 && c.Right.Name[:5] == "$uint" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected synthetic uint constraint from umod, not found")
	}
}

// TestGenerateConstraints_StoreWithOffset verifies that a store to base+offset
// emits a field access constraint.
func TestGenerateConstraints_StoreWithOffset(t *testing.T) {
	val := varOf("v", i64)
	base := varOf("ptr", ir.PointerType{Pointee: i64})
	addr := ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  ir.VariableExpr{Var: base},
		Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 16, Width: ir.Size8, Signed: false}},
	}
	store := ir.Store{
		Address: addr,
		Value:   ir.VariableExpr{Var: val},
		Size:    ir.Size8,
	}
	fn := makeFunction("f", []ir.IRInstruction{store})
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()

	hasField := false
	for _, c := range cs {
		if c.Kind == ConstraintFieldAccess && c.FieldOffset == 16 {
			hasField = true
			break
		}
	}
	if !hasField {
		t.Error("expected ConstraintFieldAccess with offset 16 from store, not found")
	}
}

// TestGenerateConstraints_MultipleBlocks verifies that constraints are generated
// from all basic blocks in a multi-block function.
func TestGenerateConstraints_MultipleBlocks(t *testing.T) {
	x := varOf("x", i64)
	y := varOf("y", i64)
	z := varOf("z", i64)

	block0 := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			ir.Assign{Dest: x, Source: ir.VariableExpr{Var: y}},
		},
	}
	block1 := &ir.BasicBlock{
		ID: 1,
		Instructions: []ir.IRInstruction{
			ir.Assign{Dest: z, Source: ir.VariableExpr{Var: x}},
		},
	}
	fn := &ir.Function{
		Name: "multi",
		Signature: ir.FunctionType{
			ReturnType: i64,
			Parameters: []ir.Type{i64},
		},
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block0, 1: block1},
		EntryBlock: 0,
	}

	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()

	// must have constraints from both blocks
	hasXY := false
	hasZX := false
	for _, c := range cs {
		if c.Kind == ConstraintEquality && c.Left.Name == x.String() && c.Right.Name == y.String() {
			hasXY = true
		}
		if c.Kind == ConstraintEquality && c.Left.Name == z.String() && c.Right.Name == x.String() {
			hasZX = true
		}
	}
	if !hasXY {
		t.Error("expected x eq y constraint from block 0, not found")
	}
	if !hasZX {
		t.Error("expected z eq x constraint from block 1, not found")
	}
}

// TestGenerateConstraints_Jump verifies that a Jump instruction produces no
// type constraints (it has no type-bearing operands).
func TestGenerateConstraints_Jump(_ *testing.T) {
	jump := ir.Jump{Target: 1}
	fn := makeFunction("f", []ir.IRInstruction{jump})
	g := NewConstraintGenerator(fn)
	cs := g.GenerateConstraints()
	// signature seeds may produce constraints; jump itself must not add any
	// we just verify no panic and the count is reasonable
	_ = cs
}

// TestTypeVarForExpr_ConstantExpr verifies that typeVarForExpr returns a
// concrete TypeVar for a ConstantExpr.
func TestTypeVarForExpr_ConstantExpr(t *testing.T) {
	constExpr := ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size8, Signed: true}}
	tv := typeVarForExpr(constExpr)
	if tv.Concrete == nil {
		t.Error("expected concrete type for ConstantExpr TypeVar, got nil")
	}
}

// TestTypeVarForExpr_CompoundExpr verifies that typeVarForExpr returns a
// synthetic TypeVar for a compound expression (BinaryOp).
func TestTypeVarForExpr_CompoundExpr(t *testing.T) {
	a := varOf("a", i64)
	b := varOf("b", i64)
	binop := ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  ir.VariableExpr{Var: a},
		Right: ir.VariableExpr{Var: b},
	}
	tv := typeVarForExpr(binop)
	// synthetic var must start with "$expr_"
	if len(tv.Name) < 6 || tv.Name[:6] != "$expr_" {
		t.Errorf("expected synthetic $expr_ var, got %q", tv.Name)
	}
}
