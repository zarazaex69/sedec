// Package z3 provides CGO bindings to the Z3 SMT solver C API.
// It wraps the Z3 C API with type-safe Go interfaces and handles
// memory management via explicit Close() calls on all objects.
//
// Requirements: 11.3, 44.1, 44.2, 44.3, 44.4
//
//nolint:godot // CGO file with C-style comments
package z3

/*
#cgo LDFLAGS: -lz3
#include <z3.h>
#include <stdlib.h>

// helper: create a fresh config with default settings
static inline Z3_config make_default_config(void) {
	Z3_config cfg = Z3_mk_config();
	// set timeout to 5000ms to prevent runaway solves
	Z3_set_param_value(cfg, "timeout", "5000");
	return cfg;
}

// helper: create optimize context (for MaxSMT / weighted objectives)
static inline Z3_optimize make_optimize(Z3_context ctx) {
	return Z3_mk_optimize(ctx);
}

// helper: assert soft constraint with weight and group id
static inline unsigned optimize_assert_soft(
	Z3_context ctx,
	Z3_optimize opt,
	Z3_ast formula,
	const char* weight,
	Z3_symbol group
) {
	return Z3_optimize_assert_soft(ctx, opt, formula, weight, group);
}

// helper: check satisfiability of optimize context
static inline Z3_lbool optimize_check(Z3_context ctx, Z3_optimize opt) {
	return Z3_optimize_check(ctx, opt, 0, NULL);
}

// helper: evaluate ast in model with model_completion=true
static inline bool model_eval_complete(Z3_context ctx, Z3_model m, Z3_ast t, Z3_ast* v) {
	return Z3_model_eval(ctx, m, t, true, v);
}
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

// CheckResult represents the satisfiability result from Z3.
type CheckResult int

const (
	// CheckUnsat means the formula is unsatisfiable.
	CheckUnsat CheckResult = -1
	// CheckUnknown means Z3 could not determine satisfiability (timeout, etc.).
	CheckUnknown CheckResult = 0
	// CheckSat means the formula is satisfiable.
	CheckSat CheckResult = 1
)

// String returns a human-readable name for the check result.
func (r CheckResult) String() string {
	switch r {
	case CheckSat:
		return "sat"
	case CheckUnsat:
		return "unsat"
	default:
		return "unknown"
	}
}

// Context wraps a Z3_context. it is the root object from which all
// Z3 expressions, sorts, and solvers are created.
// a Context must be closed after use to release native memory.
type Context struct {
	ctx C.Z3_context
}

// NewContext creates a new Z3 context with default configuration.
// the caller must call Close() when done.
func NewContext() *Context {
	cfg := C.make_default_config()
	ctx := C.Z3_mk_context(cfg)
	C.Z3_del_config(cfg)

	c := &Context{ctx: ctx}
	// register finalizer as safety net; explicit Close() is preferred
	runtime.SetFinalizer(c, (*Context).Close)
	return c
}

// Close releases the Z3 context and all associated resources.
// calling Close more than once is safe.
func (c *Context) Close() {
	if c.ctx != nil {
		C.Z3_del_context(c.ctx)
		c.ctx = nil
	}
	runtime.SetFinalizer(c, nil)
}

// BoolSort returns the Z3 boolean sort.
func (c *Context) BoolSort() Sort {
	return Sort{sort: C.Z3_mk_bool_sort(c.ctx), ctx: c}
}

// IntSort returns the Z3 integer sort (mathematical integers, not bitvectors).
func (c *Context) IntSort() Sort {
	return Sort{sort: C.Z3_mk_int_sort(c.ctx), ctx: c}
}

// BitVecSort returns the Z3 bitvector sort of the given width in bits.
func (c *Context) BitVecSort(bits uint) Sort {
	return Sort{sort: C.Z3_mk_bv_sort(c.ctx, C.unsigned(bits)), ctx: c}
}

// Sort wraps a Z3_sort.
type Sort struct {
	sort C.Z3_sort
	ctx  *Context
}

// Expr wraps a Z3_ast (expression / formula node).
// all Expr values are immutable and reference-counted by Z3 internally.
type Expr struct {
	ast C.Z3_ast
	ctx *Context
}

// String returns the SMT-LIB2 string representation of the expression.
func (e Expr) String() string {
	return C.GoString(C.Z3_ast_to_string(e.ctx.ctx, e.ast))
}

// ============================================================================
// Boolean expression constructors
// ============================================================================

// BoolConst creates a boolean constant (free variable) with the given name.
func (c *Context) BoolConst(name string) Expr {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	sym := C.Z3_mk_string_symbol(c.ctx, cname)
	sort := C.Z3_mk_bool_sort(c.ctx)
	return Expr{ast: C.Z3_mk_const(c.ctx, sym, sort), ctx: c}
}

// True returns the Z3 boolean literal true.
func (c *Context) True() Expr {
	return Expr{ast: C.Z3_mk_true(c.ctx), ctx: c}
}

// False returns the Z3 boolean literal false.
func (c *Context) False() Expr {
	return Expr{ast: C.Z3_mk_false(c.ctx), ctx: c}
}

// Not returns the logical negation of e.
func (c *Context) Not(e Expr) Expr {
	return Expr{ast: C.Z3_mk_not(c.ctx, e.ast), ctx: c}
}

// And returns the conjunction of all given expressions.
// panics if args is empty (developer error).
func (c *Context) And(args ...Expr) Expr {
	if len(args) == 0 {
		panic("z3.And: at least one argument required")
	}
	cargs := make([]C.Z3_ast, len(args))
	for i, a := range args {
		cargs[i] = a.ast
	}
	return Expr{
		ast: C.Z3_mk_and(c.ctx, C.unsigned(len(cargs)), &cargs[0]),
		ctx: c,
	}
}

// Or returns the disjunction of all given expressions.
// panics if args is empty (developer error).
func (c *Context) Or(args ...Expr) Expr {
	if len(args) == 0 {
		panic("z3.Or: at least one argument required")
	}
	cargs := make([]C.Z3_ast, len(args))
	for i, a := range args {
		cargs[i] = a.ast
	}
	return Expr{
		ast: C.Z3_mk_or(c.ctx, C.unsigned(len(cargs)), &cargs[0]),
		ctx: c,
	}
}

// Implies returns the implication e1 => e2.
func (c *Context) Implies(e1, e2 Expr) Expr {
	return Expr{ast: C.Z3_mk_implies(c.ctx, e1.ast, e2.ast), ctx: c}
}

// Eq returns the equality constraint e1 == e2.
func (c *Context) Eq(e1, e2 Expr) Expr {
	return Expr{ast: C.Z3_mk_eq(c.ctx, e1.ast, e2.ast), ctx: c}
}

// ============================================================================
// Bitvector expression constructors
// ============================================================================

// BitVecConst creates a bitvector constant (free variable) with the given name and width.
func (c *Context) BitVecConst(name string, bits uint) Expr {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	sym := C.Z3_mk_string_symbol(c.ctx, cname)
	sort := C.Z3_mk_bv_sort(c.ctx, C.unsigned(bits))
	return Expr{ast: C.Z3_mk_const(c.ctx, sym, sort), ctx: c}
}

// BitVecVal creates a bitvector literal with the given value and width.
func (c *Context) BitVecVal(val int64, bits uint) Expr {
	sort := C.Z3_mk_bv_sort(c.ctx, C.unsigned(bits))
	return Expr{
		ast: C.Z3_mk_int64(c.ctx, C.int64_t(val), sort),
		ctx: c,
	}
}

// BVAdd returns the bitvector addition e1 + e2.
func (c *Context) BVAdd(e1, e2 Expr) Expr {
	return Expr{ast: C.Z3_mk_bvadd(c.ctx, e1.ast, e2.ast), ctx: c}
}

// BVSub returns the bitvector subtraction e1 - e2.
func (c *Context) BVSub(e1, e2 Expr) Expr {
	return Expr{ast: C.Z3_mk_bvsub(c.ctx, e1.ast, e2.ast), ctx: c}
}

// BVMul returns the bitvector multiplication e1 * e2.
func (c *Context) BVMul(e1, e2 Expr) Expr {
	return Expr{ast: C.Z3_mk_bvmul(c.ctx, e1.ast, e2.ast), ctx: c}
}

// BVUlt returns the unsigned bitvector less-than comparison e1 < e2.
func (c *Context) BVUlt(e1, e2 Expr) Expr {
	return Expr{ast: C.Z3_mk_bvult(c.ctx, e1.ast, e2.ast), ctx: c}
}

// BVSlt returns the signed bitvector less-than comparison e1 < e2.
func (c *Context) BVSlt(e1, e2 Expr) Expr {
	return Expr{ast: C.Z3_mk_bvslt(c.ctx, e1.ast, e2.ast), ctx: c}
}

// ============================================================================
// Optimize (MaxSMT) context
// ============================================================================

// Optimize wraps a Z3_optimize context for weighted MaxSMT solving.
// hard constraints are asserted unconditionally; soft constraints carry
// a weight and a group identifier for objective maximization.
type Optimize struct {
	opt C.Z3_optimize
	ctx *Context
}

// NewOptimize creates a new Z3 optimize context.
// the caller must call Close() when done.
func (c *Context) NewOptimize() *Optimize {
	opt := C.make_optimize(c.ctx)
	C.Z3_optimize_inc_ref(c.ctx, opt)
	o := &Optimize{opt: opt, ctx: c}
	runtime.SetFinalizer(o, (*Optimize).Close)
	return o
}

// Close releases the optimize context.
func (o *Optimize) Close() {
	if o.opt != nil {
		C.Z3_optimize_dec_ref(o.ctx.ctx, o.opt)
		o.opt = nil
	}
	runtime.SetFinalizer(o, nil)
}

// Assert adds a hard constraint to the optimize context.
// hard constraints must be satisfied in any solution.
func (o *Optimize) Assert(formula Expr) {
	C.Z3_optimize_assert(o.ctx.ctx, o.opt, formula.ast)
}

// AssertSoft adds a soft constraint with the given weight (as a decimal string)
// and group identifier. soft constraints are maximized subject to hard constraints.
// weight must be a non-negative decimal string, e.g. "100", "90", "50".
// group is a symbolic name for the objective function (e.g. "type_constraints").
func (o *Optimize) AssertSoft(formula Expr, weight string, group string) uint {
	cweight := C.CString(weight)
	defer C.free(unsafe.Pointer(cweight))

	cgroup := C.CString(group)
	defer C.free(unsafe.Pointer(cgroup))
	sym := C.Z3_mk_string_symbol(o.ctx.ctx, cgroup)

	id := C.optimize_assert_soft(o.ctx.ctx, o.opt, formula.ast, cweight, sym)
	return uint(id)
}

// Check runs the MaxSMT optimization and returns the satisfiability result.
// CheckSat means all hard constraints are satisfiable and the maximum-weight
// subset of soft constraints has been found.
func (o *Optimize) Check() CheckResult {
	result := C.optimize_check(o.ctx.ctx, o.opt)
	return CheckResult(result)
}

// Model returns the satisfying assignment after a successful Check().
// returns nil if Check() did not return CheckSat.
func (o *Optimize) Model() *Model {
	m := C.Z3_optimize_get_model(o.ctx.ctx, o.opt)
	if m == nil {
		return nil
	}
	C.Z3_model_inc_ref(o.ctx.ctx, m)
	model := &Model{model: m, ctx: o.ctx}
	runtime.SetFinalizer(model, (*Model).Close)
	return model
}

// String returns the SMT-LIB2 string representation of the optimize context.
func (o *Optimize) String() string {
	return C.GoString(C.Z3_optimize_to_string(o.ctx.ctx, o.opt))
}

// ============================================================================
// Model (satisfying assignment)
// ============================================================================

// Model wraps a Z3_model representing a satisfying assignment.
type Model struct {
	model C.Z3_model
	ctx   *Context
}

// Close releases the model.
func (m *Model) Close() {
	if m.model != nil {
		C.Z3_model_dec_ref(m.ctx.ctx, m.model)
		m.model = nil
	}
	runtime.SetFinalizer(m, nil)
}

// EvalBool evaluates a boolean expression in the model.
// returns (value, true) if the expression has a definite boolean value,
// or (false, false) if the value is unspecified (don't-care).
func (m *Model) EvalBool(e Expr) (bool, bool) {
	var result C.Z3_ast
	// use c helper to avoid _Bool conversion issues in cgo
	ok := C.model_eval_complete(m.ctx.ctx, m.model, e.ast, &result)
	if !bool(ok) {
		return false, false
	}

	kind := C.Z3_get_bool_value(m.ctx.ctx, result)
	switch kind {
	case C.Z3_L_TRUE:
		return true, true
	case C.Z3_L_FALSE:
		return false, true
	default:
		return false, false
	}
}

// String returns the SMT-LIB2 string representation of the model.
func (m *Model) String() string {
	return C.GoString(C.Z3_model_to_string(m.ctx.ctx, m.model))
}

// ============================================================================
// Error handling
// ============================================================================

// ErrZ3 represents a Z3 API error.
type ErrZ3 struct {
	Code    int
	Message string
}

func (e *ErrZ3) Error() string {
	return fmt.Sprintf("z3 error %d: %s", e.Code, e.Message)
}

// checkError checks the Z3 error code and returns an error if non-OK.
func checkError(ctx C.Z3_context) error {
	code := C.Z3_get_error_code(ctx)
	if code == C.Z3_OK {
		return nil
	}
	msg := C.GoString(C.Z3_get_error_msg(ctx, code))
	return &ErrZ3{Code: int(code), Message: msg}
}

// ContextError returns the last error from the context, or nil if no error.
func (c *Context) ContextError() error {
	return checkError(c.ctx)
}
