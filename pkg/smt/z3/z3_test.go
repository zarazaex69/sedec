package z3_test

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/smt/z3"
)

func TestContext_CreateAndClose(t *testing.T) {
	ctx := z3.NewContext()
	if ctx == nil {
		t.Fatal("NewContext returned nil")
	}
	ctx.Close()
	ctx.Close()
}

func TestContext_BoolConst(t *testing.T) {
	ctx := z3.NewContext()
	defer ctx.Close()

	b := ctx.BoolConst("test_var")
	s := b.String()
	if s == "" {
		t.Error("BoolConst String() must not be empty")
	}
}

func TestContext_TrueFalse(t *testing.T) {
	ctx := z3.NewContext()
	defer ctx.Close()

	tr := ctx.True()
	if tr.String() == "" {
		t.Error("True String() must not be empty")
	}
	fl := ctx.False()
	if fl.String() == "" {
		t.Error("False String() must not be empty")
	}
}

func TestContext_Not(t *testing.T) {
	ctx := z3.NewContext()
	defer ctx.Close()

	b := ctx.BoolConst("x")
	nb := ctx.Not(b)
	if nb.String() == "" {
		t.Error("Not String() must not be empty")
	}
}

func TestContext_AndOr(t *testing.T) {
	ctx := z3.NewContext()
	defer ctx.Close()

	a := ctx.BoolConst("a")
	b := ctx.BoolConst("b")

	andExpr := ctx.And(a, b)
	if andExpr.String() == "" {
		t.Error("And String() must not be empty")
	}

	orExpr := ctx.Or(a, b)
	if orExpr.String() == "" {
		t.Error("Or String() must not be empty")
	}
}

func TestContext_Implies(t *testing.T) {
	ctx := z3.NewContext()
	defer ctx.Close()

	a := ctx.BoolConst("a")
	b := ctx.BoolConst("b")
	imp := ctx.Implies(a, b)
	if imp.String() == "" {
		t.Error("Implies String() must not be empty")
	}
}

func TestContext_Eq(t *testing.T) {
	ctx := z3.NewContext()
	defer ctx.Close()

	a := ctx.BoolConst("a")
	b := ctx.BoolConst("b")
	eq := ctx.Eq(a, b)
	if eq.String() == "" {
		t.Error("Eq String() must not be empty")
	}
}

func TestContext_Sorts(t *testing.T) {
	ctx := z3.NewContext()
	defer ctx.Close()

	_ = ctx.BoolSort()
	_ = ctx.IntSort()
	_ = ctx.BitVecSort(64)
}

func TestContext_BitVecOps(t *testing.T) {
	ctx := z3.NewContext()
	defer ctx.Close()

	x := ctx.BitVecConst("x", 64)
	y := ctx.BitVecConst("y", 64)
	v := ctx.BitVecVal(42, 64)

	add := ctx.BVAdd(x, y)
	if add.String() == "" {
		t.Error("BVAdd String() must not be empty")
	}

	sub := ctx.BVSub(x, v)
	if sub.String() == "" {
		t.Error("BVSub String() must not be empty")
	}

	mul := ctx.BVMul(x, y)
	if mul.String() == "" {
		t.Error("BVMul String() must not be empty")
	}

	ult := ctx.BVUlt(x, y)
	if ult.String() == "" {
		t.Error("BVUlt String() must not be empty")
	}

	slt := ctx.BVSlt(x, y)
	if slt.String() == "" {
		t.Error("BVSlt String() must not be empty")
	}
}

func TestOptimize_BasicSolve(t *testing.T) {
	ctx := z3.NewContext()
	defer ctx.Close()

	opt := ctx.NewOptimize()
	defer opt.Close()

	a := ctx.BoolConst("a")
	b := ctx.BoolConst("b")

	opt.Assert(ctx.Or(a, b))
	opt.AssertSoft(a, "100", "group1")
	opt.AssertSoft(b, "50", "group1")

	result := opt.Check()
	if result != z3.CheckSat {
		t.Fatalf("expected sat, got %s", result)
	}

	model := opt.Model()
	if model == nil {
		t.Fatal("model must not be nil after sat")
	}
	defer model.Close()

	aVal, aOk := model.EvalBool(a)
	if !aOk {
		t.Error("expected a to have a value in model")
	}
	if !aVal {
		t.Error("expected a=true (higher weight)")
	}
}

func TestOptimize_String(t *testing.T) {
	ctx := z3.NewContext()
	defer ctx.Close()

	opt := ctx.NewOptimize()
	defer opt.Close()

	a := ctx.BoolConst("a")
	opt.Assert(a)

	s := opt.String()
	if s == "" {
		t.Error("Optimize String() must not be empty")
	}
}

func TestModel_String(t *testing.T) {
	ctx := z3.NewContext()
	defer ctx.Close()

	opt := ctx.NewOptimize()
	defer opt.Close()

	a := ctx.BoolConst("a")
	opt.Assert(a)

	result := opt.Check()
	if result != z3.CheckSat {
		t.Fatalf("expected sat, got %s", result)
	}

	model := opt.Model()
	if model == nil {
		t.Fatal("model must not be nil")
	}
	defer model.Close()

	s := model.String()
	if s == "" {
		t.Error("Model String() must not be empty")
	}
}

func TestModel_EvalBool_Unspecified(t *testing.T) {
	ctx := z3.NewContext()
	defer ctx.Close()

	opt := ctx.NewOptimize()
	defer opt.Close()

	a := ctx.BoolConst("a")
	b := ctx.BoolConst("b")
	opt.Assert(a)

	result := opt.Check()
	if result != z3.CheckSat {
		t.Fatalf("expected sat, got %s", result)
	}

	model := opt.Model()
	if model == nil {
		t.Fatal("model must not be nil")
	}
	defer model.Close()

	_, bOk := model.EvalBool(b)
	_ = bOk
}

func TestCheckResult_String(t *testing.T) {
	cases := []struct {
		r    z3.CheckResult
		want string
	}{
		{z3.CheckSat, "sat"},
		{z3.CheckUnsat, "unsat"},
		{z3.CheckUnknown, "unknown"},
		{z3.CheckResult(42), "unknown"},
	}
	for _, tc := range cases {
		got := tc.r.String()
		if got != tc.want {
			t.Errorf("CheckResult(%d).String() = %q, want %q", int(tc.r), got, tc.want)
		}
	}
}

func TestContext_ContextError(t *testing.T) {
	ctx := z3.NewContext()
	defer ctx.Close()

	err := ctx.ContextError()
	if err != nil {
		t.Errorf("expected no error on fresh context, got %v", err)
	}
}

func TestOptimize_Unsat(t *testing.T) {
	ctx := z3.NewContext()
	defer ctx.Close()

	opt := ctx.NewOptimize()
	defer opt.Close()

	a := ctx.BoolConst("a")
	opt.Assert(a)
	opt.Assert(ctx.Not(a))

	result := opt.Check()
	if result != z3.CheckUnsat {
		t.Fatalf("expected unsat, got %s", result)
	}
}

func TestOptimize_CloseDouble(t *testing.T) {
	ctx := z3.NewContext()
	defer ctx.Close()

	opt := ctx.NewOptimize()
	opt.Close()
	opt.Close()
}

func TestModel_CloseDouble(t *testing.T) {
	ctx := z3.NewContext()
	defer ctx.Close()

	opt := ctx.NewOptimize()
	defer opt.Close()

	a := ctx.BoolConst("a")
	opt.Assert(a)
	_ = opt.Check()

	model := opt.Model()
	if model == nil {
		t.Fatal("model must not be nil")
	}
	model.Close()
	model.Close()
}
