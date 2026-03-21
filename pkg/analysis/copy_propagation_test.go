package analysis

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// helpers
// ============================================================================

// copyPropFn builds a minimal single-block function for copy propagation tests.
func copyPropFn(instrs ...ir.IRInstruction) *ir.Function {
	return &ir.Function{
		Name: "test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID:           0,
				Instructions: instrs,
			},
		},
		EntryBlock: 0,
	}
}

// ============================================================================
// simple copy propagation: x = y; use x  ->  use y
// ============================================================================

// TestCopyProp_SimpleCopy verifies that a direct copy is propagated.
// bb0: x_1 = y_1; z_1 = x_1 + 1
// after propagation: z_1 = y_1 + 1
func TestCopyProp_SimpleCopy(t *testing.T) {
	x1 := ssaVar("x", 1)
	y1 := ssaVar("y", 1)
	z1 := ssaVar("z", 1)

	fn := copyPropFn(
		&ir.Assign{Dest: x1, Source: &ir.VariableExpr{Var: y1}},
		&ir.Assign{
			Dest: z1,
			Source: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: x1},
				Right: intConst(1),
			},
		},
	)

	result, err := PropagateCopies(fn, nil, nil)
	if err != nil {
		t.Fatalf("PropagateCopies failed: %v", err)
	}

	if result.CopiesFound != 1 {
		t.Errorf("expected 1 copy found, got %d", result.CopiesFound)
	}
	if result.ReplacedCount < 1 {
		t.Errorf("expected at least 1 replacement, got %d", result.ReplacedCount)
	}

	// verify z_1 = y_1 + 1 (x_1 replaced by y_1)
	assign := fn.Blocks[0].Instructions[1].(*ir.Assign) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	binop, ok := assign.Source.(*ir.BinaryOp)
	if !ok {
		t.Fatalf("expected BinaryOp source, got %T", assign.Source)
	}
	leftVar, ok := binop.Left.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("expected VariableExpr on left, got %T", binop.Left)
	}
	if leftVar.Var.Name != "y" || leftVar.Var.Version != 1 {
		t.Errorf("expected y_1 after propagation, got %s", leftVar.Var.String())
	}
}

// TestCopyProp_CopyInReturn verifies propagation into return value.
// bb0: x_1 = y_1; return x_1  ->  return y_1
func TestCopyProp_CopyInReturn(t *testing.T) {
	x1 := ssaVar("x", 1)
	y1 := ssaVar("y", 1)

	fn := copyPropFn(
		&ir.Assign{Dest: x1, Source: &ir.VariableExpr{Var: y1}},
		&ir.Return{Value: &x1},
	)

	result, err := PropagateCopies(fn, nil, nil)
	if err != nil {
		t.Fatalf("PropagateCopies failed: %v", err)
	}

	if result.ReplacedCount < 1 {
		t.Errorf("expected at least 1 replacement, got %d", result.ReplacedCount)
	}

	ret := fn.Blocks[0].Instructions[1].(*ir.Return) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if ret.Value == nil {
		t.Fatal("return value must not be nil")
	}
	if ret.Value.Name != "y" || ret.Value.Version != 1 {
		t.Errorf("expected return y_1, got %s", ret.Value.String())
	}
}

// ============================================================================
// copy chain propagation: x = y; z = x; use z  ->  use y
// ============================================================================

// TestCopyProp_CopyChain verifies transitive copy propagation.
// bb0: x_1 = y_1; z_1 = x_1; w_1 = z_1 + 2
// after propagation: w_1 = y_1 + 2
func TestCopyProp_CopyChain(t *testing.T) {
	x1 := ssaVar("x", 1)
	y1 := ssaVar("y", 1)
	z1 := ssaVar("z", 1)
	w1 := ssaVar("w", 1)

	fn := copyPropFn(
		&ir.Assign{Dest: x1, Source: &ir.VariableExpr{Var: y1}},
		&ir.Assign{Dest: z1, Source: &ir.VariableExpr{Var: x1}},
		&ir.Assign{
			Dest: w1,
			Source: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: z1},
				Right: intConst(2),
			},
		},
	)

	result, err := PropagateCopies(fn, nil, nil)
	if err != nil {
		t.Fatalf("PropagateCopies failed: %v", err)
	}

	if result.CopiesFound != 2 {
		t.Errorf("expected 2 copies found, got %d", result.CopiesFound)
	}

	// w_1 = z_1 + 2 should become w_1 = y_1 + 2
	assign := fn.Blocks[0].Instructions[2].(*ir.Assign) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	binop := assign.Source.(*ir.BinaryOp)               //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	leftVar := binop.Left.(*ir.VariableExpr)            //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if leftVar.Var.Name != "y" || leftVar.Var.Version != 1 {
		t.Errorf("expected y_1 after chain propagation, got %s", leftVar.Var.String())
	}
}

// TestCopyProp_LongChain verifies propagation through a chain of 4 copies.
// a = b; c = a; d = c; e = d; use e  ->  use b
func TestCopyProp_LongChain(t *testing.T) {
	a := ssaVar("a", 1)
	b := ssaVar("b", 1)
	c := ssaVar("c", 1)
	d := ssaVar("d", 1)
	e := ssaVar("e", 1)
	r := ssaVar("r", 1)

	fn := copyPropFn(
		&ir.Assign{Dest: a, Source: &ir.VariableExpr{Var: b}},
		&ir.Assign{Dest: c, Source: &ir.VariableExpr{Var: a}},
		&ir.Assign{Dest: d, Source: &ir.VariableExpr{Var: c}},
		&ir.Assign{Dest: e, Source: &ir.VariableExpr{Var: d}},
		&ir.Assign{Dest: r, Source: &ir.VariableExpr{Var: e}},
	)

	_, err := PropagateCopies(fn, nil, nil)
	if err != nil {
		t.Fatalf("PropagateCopies failed: %v", err)
	}

	// r = e should become r = b after full chain resolution
	lastAssign := fn.Blocks[0].Instructions[4].(*ir.Assign) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	srcVar, ok := lastAssign.Source.(*ir.VariableExpr)
	if !ok {
		t.Fatalf("expected VariableExpr, got %T", lastAssign.Source)
	}
	if srcVar.Var.Name != "b" || srcVar.Var.Version != 1 {
		t.Errorf("expected b_1 after long chain, got %s", srcVar.Var.String())
	}
}

// ============================================================================
// no propagation through phi-node sources
// ============================================================================

// TestCopyProp_NoPropThroughPhiSources verifies that phi-node inputs are not
// treated as copies. the phi result itself may be propagated if it is a copy,
// but the phi inputs are not copy sources.
//
// bb0: branch cond -> bb1, bb2
// bb1: x_1 = 10; jump bb3
// bb2: x_2 = 20; jump bb3
// bb3: x_3 = phi(x_1 from bb1, x_2 from bb2); z_1 = x_3
//
// x_3 is a phi result, not a copy (phi has two sources).
// z_1 = x_3 IS a copy, so uses of z_1 should be replaced by x_3.
// but x_3 itself must NOT be replaced by x_1 or x_2.
func TestCopyProp_NoPropThroughPhiSources(t *testing.T) {
	x1 := ssaVar("x", 1)
	x2 := ssaVar("x", 2)
	x3 := ssaVar("x", 3)
	z1 := ssaVar("z", 1)
	w1 := ssaVar("w", 1)
	cond := ssaVar("cond", 1)

	fn := &ir.Function{
		Name: "phi_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Branch{
						Condition:   &ir.VariableExpr{Var: cond},
						TrueTarget:  1,
						FalseTarget: 2,
					},
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x1, Source: intConst(10)},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x2, Source: intConst(20)},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			3: {
				ID: 3,
				Instructions: []ir.IRInstruction{
					&ir.Phi{
						Dest: x3,
						Sources: []ir.PhiSource{
							{Block: 1, Var: x1},
							{Block: 2, Var: x2},
						},
					},
					// z_1 = x_3 is a copy; uses of z_1 should become x_3
					&ir.Assign{Dest: z1, Source: &ir.VariableExpr{Var: x3}},
					// w_1 = z_1 + 5; after propagation: w_1 = x_3 + 5
					&ir.Assign{
						Dest: w1,
						Source: &ir.BinaryOp{
							Op:    ir.BinOpAdd,
							Left:  &ir.VariableExpr{Var: z1},
							Right: intConst(5),
						},
					},
				},
				Predecessors: []ir.BlockID{1, 2},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateCopies(fn, nil, nil)
	if err != nil {
		t.Fatalf("PropagateCopies failed: %v", err)
	}

	// z_1 = x_3 is the only copy
	if result.CopiesFound != 1 {
		t.Errorf("expected 1 copy (z_1 = x_3), got %d", result.CopiesFound)
	}

	// w_1 = z_1 + 5 should become w_1 = x_3 + 5
	block3 := fn.Blocks[3]
	wAssign := block3.Instructions[2].(*ir.Assign) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	binop := wAssign.Source.(*ir.BinaryOp)         //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	leftVar := binop.Left.(*ir.VariableExpr)       //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if leftVar.Var.Name != "x" || leftVar.Var.Version != 3 {
		t.Errorf("expected x_3 after propagation of z_1, got %s", leftVar.Var.String())
	}

	// phi sources must NOT be rewritten: x_3 phi sources remain x_1 and x_2
	phi := block3.Instructions[0].(*ir.Phi) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if phi.Sources[0].Var.Name != "x" || phi.Sources[0].Var.Version != 1 {
		t.Errorf("phi source 0 must remain x_1, got %s", phi.Sources[0].Var.String())
	}
	if phi.Sources[1].Var.Name != "x" || phi.Sources[1].Var.Version != 2 {
		t.Errorf("phi source 1 must remain x_2, got %s", phi.Sources[1].Var.String())
	}
}

// ============================================================================
// preservation of side effects
// ============================================================================

// TestCopyProp_PreservesStore verifies that store instructions are preserved
// and their address/value expressions are correctly rewritten.
// bb0: x_1 = y_1; store *x_1, x_1
// after propagation: store *y_1, y_1
func TestCopyProp_PreservesStore(t *testing.T) {
	x1 := ssaVar("x", 1)
	y1 := ssaVar("y", 1)

	fn := copyPropFn(
		&ir.Assign{Dest: x1, Source: &ir.VariableExpr{Var: y1}},
		&ir.Store{
			Address: &ir.VariableExpr{Var: x1},
			Value:   &ir.VariableExpr{Var: x1},
			Size:    ir.Size8,
		},
	)

	result, err := PropagateCopies(fn, nil, nil)
	if err != nil {
		t.Fatalf("PropagateCopies failed: %v", err)
	}

	// store must still be present
	if len(fn.Blocks[0].Instructions) != 2 {
		t.Errorf("expected 2 instructions (copy + store), got %d", len(fn.Blocks[0].Instructions))
	}

	store := fn.Blocks[0].Instructions[1].(*ir.Store) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior

	// address should now be y_1
	addrVar := store.Address.(*ir.VariableExpr) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if addrVar.Var.Name != "y" || addrVar.Var.Version != 1 {
		t.Errorf("expected store address y_1, got %s", addrVar.Var.String())
	}

	// value should now be y_1
	valVar := store.Value.(*ir.VariableExpr) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if valVar.Var.Name != "y" || valVar.Var.Version != 1 {
		t.Errorf("expected store value y_1, got %s", valVar.Var.String())
	}

	if result.ReplacedCount < 2 {
		t.Errorf("expected at least 2 replacements (addr + val), got %d", result.ReplacedCount)
	}
}

// TestCopyProp_PreservesCall verifies that call instructions are preserved
// and their arguments are correctly rewritten.
// bb0: x_1 = y_1; call foo(x_1)
// after propagation: call foo(y_1)
func TestCopyProp_PreservesCall(t *testing.T) {
	x1 := ssaVar("x", 1)
	y1 := ssaVar("y", 1)

	fn := copyPropFn(
		&ir.Assign{Dest: x1, Source: &ir.VariableExpr{Var: y1}},
		&ir.Call{
			Target: ir.VariableExpr{Var: ir.Variable{Name: "foo", Type: ir.FunctionType{}}},
			Args:   []ir.Variable{x1},
		},
	)

	result, err := PropagateCopies(fn, nil, nil)
	if err != nil {
		t.Fatalf("PropagateCopies failed: %v", err)
	}

	// call must still be present
	call := fn.Blocks[0].Instructions[1].(*ir.Call) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if len(call.Args) != 1 {
		t.Fatalf("expected 1 call argument, got %d", len(call.Args))
	}
	if call.Args[0].Name != "y" || call.Args[0].Version != 1 {
		t.Errorf("expected call arg y_1, got %s", call.Args[0].String())
	}

	if result.ReplacedCount < 1 {
		t.Errorf("expected at least 1 replacement, got %d", result.ReplacedCount)
	}
}

// TestCopyProp_NoCopies verifies that a function with no copies is unchanged.
// bb0: x_1 = 1; y_1 = x_1 + 2; return y_1
func TestCopyProp_NoCopies(t *testing.T) {
	x1 := ssaVar("x", 1)
	y1 := ssaVar("y", 1)

	fn := copyPropFn(
		&ir.Assign{Dest: x1, Source: intConst(1)},
		&ir.Assign{
			Dest: y1,
			Source: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: x1},
				Right: intConst(2),
			},
		},
		&ir.Return{Value: &y1},
	)

	result, err := PropagateCopies(fn, nil, nil)
	if err != nil {
		t.Fatalf("PropagateCopies failed: %v", err)
	}

	if result.CopiesFound != 0 {
		t.Errorf("expected 0 copies, got %d", result.CopiesFound)
	}
	if result.ReplacedCount != 0 {
		t.Errorf("expected 0 replacements, got %d", result.ReplacedCount)
	}
}

// TestCopyProp_NilFunction verifies error handling for nil function.
func TestCopyProp_NilFunction(t *testing.T) {
	_, err := PropagateCopies(nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil function")
	}
}

// TestCopyProp_EmptyFunction verifies error handling for function with no blocks.
func TestCopyProp_EmptyFunction(t *testing.T) {
	fn := &ir.Function{
		Name:   "empty",
		Blocks: map[ir.BlockID]*ir.BasicBlock{},
	}
	_, err := PropagateCopies(fn, nil, nil)
	if err == nil {
		t.Fatal("expected error for empty function")
	}
}

// TestCopyProp_CopyDestNotRewritten verifies that the destination of a copy
// instruction is NOT rewritten (only uses are rewritten).
// bb0: x_1 = y_1; x_1 must remain x_1 as destination
func TestCopyProp_CopyDestNotRewritten(t *testing.T) {
	x1 := ssaVar("x", 1)
	y1 := ssaVar("y", 1)

	fn := copyPropFn(
		&ir.Assign{Dest: x1, Source: &ir.VariableExpr{Var: y1}},
	)

	_, err := PropagateCopies(fn, nil, nil)
	if err != nil {
		t.Fatalf("PropagateCopies failed: %v", err)
	}

	// the copy instruction itself: destination must remain x_1
	assign := fn.Blocks[0].Instructions[0].(*ir.Assign) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if assign.Dest.Name != "x" || assign.Dest.Version != 1 {
		t.Errorf("copy destination must not be rewritten, got %s", assign.Dest.String())
	}
}

// TestCopyProp_MultipleUsesReplaced verifies that all uses of a copied variable
// are replaced, not just the first one.
// bb0: x_1 = y_1; z_1 = x_1 + x_1
// after propagation: z_1 = y_1 + y_1 (both uses replaced)
func TestCopyProp_MultipleUsesReplaced(t *testing.T) {
	x1 := ssaVar("x", 1)
	y1 := ssaVar("y", 1)
	z1 := ssaVar("z", 1)

	fn := copyPropFn(
		&ir.Assign{Dest: x1, Source: &ir.VariableExpr{Var: y1}},
		&ir.Assign{
			Dest: z1,
			Source: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: x1},
				Right: &ir.VariableExpr{Var: x1},
			},
		},
	)

	result, err := PropagateCopies(fn, nil, nil)
	if err != nil {
		t.Fatalf("PropagateCopies failed: %v", err)
	}

	// both uses of x_1 in the binary op should be replaced
	if result.ReplacedCount < 2 {
		t.Errorf("expected at least 2 replacements, got %d", result.ReplacedCount)
	}

	assign := fn.Blocks[0].Instructions[1].(*ir.Assign) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	binop := assign.Source.(*ir.BinaryOp)               //nolint:forcetypeassert // test: panicking on wrong type is correct behavior

	leftVar := binop.Left.(*ir.VariableExpr) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if leftVar.Var.Name != "y" || leftVar.Var.Version != 1 {
		t.Errorf("expected left y_1, got %s", leftVar.Var.String())
	}

	rightVar := binop.Right.(*ir.VariableExpr) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if rightVar.Var.Name != "y" || rightVar.Var.Version != 1 {
		t.Errorf("expected right y_1, got %s", rightVar.Var.String())
	}
}

// TestCopyProp_BranchConditionReplaced verifies propagation into branch conditions.
// bb0: x_1 = y_1; branch x_1 -> bb1, bb2
// after propagation: branch y_1 -> bb1, bb2
func TestCopyProp_BranchConditionReplaced(t *testing.T) {
	x1 := ssaVar("x", 1)
	y1 := ssaVar("y", 1)

	fn := &ir.Function{
		Name: "branch_copy",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: x1, Source: &ir.VariableExpr{Var: y1}},
					&ir.Branch{
						Condition:   &ir.VariableExpr{Var: x1},
						TrueTarget:  1,
						FalseTarget: 2,
					},
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID:           1,
				Instructions: []ir.IRInstruction{&ir.Return{}},
				Predecessors: []ir.BlockID{0},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{&ir.Return{}},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}

	result, err := PropagateCopies(fn, nil, nil)
	if err != nil {
		t.Fatalf("PropagateCopies failed: %v", err)
	}

	if result.ReplacedCount < 1 {
		t.Errorf("expected at least 1 replacement, got %d", result.ReplacedCount)
	}

	branch := fn.Blocks[0].Instructions[1].(*ir.Branch) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	condVar := branch.Condition.(*ir.VariableExpr)      //nolint:forcetypeassert // test: panicking on wrong type is correct behavior
	if condVar.Var.Name != "y" || condVar.Var.Version != 1 {
		t.Errorf("expected branch condition y_1, got %s", condVar.Var.String())
	}
}

func TestCopyProp_IntrinsicArgsReplaced(t *testing.T) {
	x1 := ssaVar("x", 1)
	y1 := ssaVar("y", 1)
	z1 := ssaVar("z", 1)

	fn := copyPropFn(
		&ir.Assign{Dest: x1, Source: &ir.VariableExpr{Var: y1}},
		&ir.Intrinsic{
			Dest: &z1,
			Name: "bswap",
			Args: []ir.Expression{&ir.VariableExpr{Var: x1}},
		},
	)

	result, err := PropagateCopies(fn, nil, nil)
	if err != nil {
		t.Fatalf("PropagateCopies failed: %v", err)
	}

	if result.CopiesFound != 1 {
		t.Errorf("expected 1 copy, got %d", result.CopiesFound)
	}
	if result.ReplacedCount < 1 {
		t.Errorf("expected at least 1 replacement, got %d", result.ReplacedCount)
	}

	intr := fn.Blocks[0].Instructions[1].(*ir.Intrinsic) //nolint:forcetypeassert
	argVar := intr.Args[0].(*ir.VariableExpr)            //nolint:forcetypeassert
	if argVar.Var.Name != "y" || argVar.Var.Version != 1 {
		t.Errorf("expected intrinsic arg y_1, got %s", argVar.Var.String())
	}
}

func TestCopyProp_LoadExprAddressReplaced(t *testing.T) {
	x1 := ssaVar("x", 1)
	y1 := ssaVar("y", 1)
	z1 := ssaVar("z", 1)

	fn := copyPropFn(
		&ir.Assign{Dest: x1, Source: &ir.VariableExpr{Var: y1}},
		&ir.Assign{
			Dest: z1,
			Source: &ir.LoadExpr{
				Address: &ir.VariableExpr{Var: x1},
				Size:    ir.Size8,
			},
		},
	)

	result, err := PropagateCopies(fn, nil, nil)
	if err != nil {
		t.Fatalf("PropagateCopies failed: %v", err)
	}

	if result.ReplacedCount < 1 {
		t.Errorf("expected at least 1 replacement, got %d", result.ReplacedCount)
	}

	assign := fn.Blocks[0].Instructions[1].(*ir.Assign) //nolint:forcetypeassert
	loadExpr := assign.Source.(*ir.LoadExpr)            //nolint:forcetypeassert
	addrVar := loadExpr.Address.(*ir.VariableExpr)      //nolint:forcetypeassert
	if addrVar.Var.Name != "y" || addrVar.Var.Version != 1 {
		t.Errorf("expected load address y_1, got %s", addrVar.Var.String())
	}
}
