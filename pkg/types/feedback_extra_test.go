package typeinfer

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// TestLooksLikeArrayVariable verifies the keyword-based heuristic for
// detecting array-like variable names.
func TestLooksLikeArrayVariable(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"vtable_Foo", true},
		{"vptr_Bar", true},
		{"vtbl_Baz", true},
		{"table_handlers", true},
		{"handlers_list", true},
		{"callbacks_array", true},
		{"itab_Stringer", true},
		{"iface_methods", true},
		{"dispatch_table", true},
		{"jump_targets", true},
		{"plain_int", false},
		{"rax_1", false},
		{"local_var", false},
		{"", false},
	}
	for _, tc := range cases {
		got := looksLikeArrayVariable(tc.name)
		if got != tc.want {
			t.Errorf("looksLikeArrayVariable(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestFunctionPointerAnalyzer_PointerToFuncWithArrayName verifies that a
// pointer-to-function variable with an array-like name is detected as a
// function pointer array.
func TestFunctionPointerAnalyzer_PointerToFuncWithArrayName(t *testing.T) {
	a := NewFunctionPointerAnalyzer()
	sol := &TypeSolution{
		Types: map[string]ir.Type{
			// pointer to function type with array-like name
			"vtable_ptr": ir.PointerType{
				Pointee: ir.FunctionType{ReturnType: ir.VoidType{}},
			},
		},
	}
	arrays := a.DiscoverFunctionPointers(sol)
	if len(arrays) != 1 {
		t.Fatalf("expected 1 array for vtable_ptr, got %d", len(arrays))
	}
	if arrays[0].Kind != ArrayKindVTable {
		t.Errorf("kind = %v, want ArrayKindVTable", arrays[0].Kind)
	}
}

// TestFunctionPointerAnalyzer_PointerToFuncWithNonArrayName verifies that a
// pointer-to-function variable without an array-like name is skipped.
func TestFunctionPointerAnalyzer_PointerToFuncWithNonArrayName(t *testing.T) {
	a := NewFunctionPointerAnalyzer()
	sol := &TypeSolution{
		Types: map[string]ir.Type{
			// pointer to function but name does not suggest array
			"fn_ptr": ir.PointerType{
				Pointee: ir.FunctionType{ReturnType: ir.VoidType{}},
			},
		},
	}
	arrays := a.DiscoverFunctionPointers(sol)
	if len(arrays) != 0 {
		t.Errorf("expected 0 arrays for non-array-named fn_ptr, got %d", len(arrays))
	}
}

// TestFunctionPointerAnalyzer_NilTypeInSolution verifies that nil type entries
// in the solution are skipped without panicking.
func TestFunctionPointerAnalyzer_NilTypeInSolution(t *testing.T) {
	a := NewFunctionPointerAnalyzer()
	sol := &TypeSolution{
		Types: map[string]ir.Type{
			"nil_var":    nil,
			"vtable_foo": ir.ArrayType{Element: ir.FunctionType{ReturnType: ir.VoidType{}}, Length: 3},
		},
	}
	arrays := a.DiscoverFunctionPointers(sol)
	// nil_var must be skipped; vtable_foo must be detected
	if len(arrays) != 1 {
		t.Fatalf("expected 1 array (nil_var skipped), got %d", len(arrays))
	}
}

// TestComputeConfidence_AllKinds verifies confidence values for all ArrayKind
// values when the address is not a known vtable.
func TestComputeConfidence_AllKinds(t *testing.T) {
	a := NewFunctionPointerAnalyzer()

	cases := []struct {
		kind    ArrayKind
		wantMin float64
		wantMax float64
	}{
		{ArrayKindVTable, 0.80, 0.90},
		{ArrayKindInterfaceTable, 0.75, 0.85},
		{ArrayKindHandlerTable, 0.65, 0.75},
		{ArrayKindJumpTable, 0.60, 0.70},
		{ArrayKind(99), 0.45, 0.55}, // unknown kind → default 0.50
	}
	for _, tc := range cases {
		conf := a.computeConfidence(0xDEAD_BEEF, tc.kind)
		if conf < tc.wantMin || conf > tc.wantMax {
			t.Errorf("computeConfidence(kind=%v) = %.2f, want [%.2f, %.2f]",
				tc.kind, conf, tc.wantMin, tc.wantMax)
		}
	}
}

// TestIsFunctionType verifies the isFunctionType helper.
func TestIsFunctionType(t *testing.T) {
	if !isFunctionType(ir.FunctionType{ReturnType: ir.VoidType{}}) {
		t.Error("expected true for FunctionType")
	}
	if isFunctionType(ir.IntType{Width: ir.Size8}) {
		t.Error("expected false for IntType")
	}
	if isFunctionType(nil) {
		t.Error("expected false for nil")
	}
}

// TestIsFunctionPointerType verifies the isFunctionPointerType helper.
func TestIsFunctionPointerType(t *testing.T) {
	fnPtr := ir.PointerType{Pointee: ir.FunctionType{ReturnType: ir.VoidType{}}}
	if !isFunctionPointerType(fnPtr) {
		t.Error("expected true for pointer-to-function")
	}
	intPtr := ir.PointerType{Pointee: ir.IntType{Width: ir.Size8}}
	if isFunctionPointerType(intPtr) {
		t.Error("expected false for pointer-to-int")
	}
	if isFunctionPointerType(nil) {
		t.Error("expected false for nil")
	}
	if isFunctionPointerType(ir.IntType{Width: ir.Size8}) {
		t.Error("expected false for non-pointer type")
	}
}
