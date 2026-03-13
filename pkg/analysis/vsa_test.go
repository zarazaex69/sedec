package analysis

import (
	"math"
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// StridedInterval unit tests
// ============================================================================

func TestStridedInterval_NewSingleton(t *testing.T) {
	si := NewSingleton(42)
	if !si.IsSingleton() {
		t.Fatalf("expected singleton, got %s", si.String())
	}
	if !si.Contains(42) {
		t.Fatalf("singleton must contain its value")
	}
	if si.Contains(43) {
		t.Fatalf("singleton must not contain other values")
	}
	if si.Size() != 1 {
		t.Fatalf("singleton size must be 1, got %d", si.Size())
	}
}

func TestStridedInterval_NewStridedInterval(t *testing.T) {
	// array index: [0, 100, stride=4] — indices 0, 4, 8, ..., 100
	si := NewStridedInterval(4, 0, 100)
	if si.IsEmpty() {
		t.Fatal("expected non-empty interval")
	}
	if !si.Contains(0) || !si.Contains(4) || !si.Contains(100) {
		t.Fatal("interval must contain stride-aligned values")
	}
	if si.Contains(1) || si.Contains(3) || si.Contains(101) {
		t.Fatal("interval must not contain non-stride-aligned or out-of-range values")
	}
	expectedSize := int64(26) // (100-0)/4 + 1
	if si.Size() != expectedSize {
		t.Fatalf("expected size %d, got %d", expectedSize, si.Size())
	}
}

func TestStridedInterval_Empty(t *testing.T) {
	si := NewStridedInterval(1, 10, 5) // lo > hi => empty
	if !si.IsEmpty() {
		t.Fatal("expected empty interval for lo > hi")
	}
	if si.Contains(7) {
		t.Fatal("empty interval must not contain any value")
	}
	if si.Size() != 0 {
		t.Fatalf("empty interval size must be 0, got %d", si.Size())
	}
}

func TestStridedInterval_Top(t *testing.T) {
	si := topStridedInterval
	if !si.IsTop() {
		t.Fatal("expected top interval")
	}
	if !si.Contains(0) || !si.Contains(math.MaxInt64) || !si.Contains(math.MinInt64) {
		t.Fatal("top interval must contain all values")
	}
}

func TestStridedInterval_Join(t *testing.T) {
	tests := []struct {
		name         string
		a            StridedInterval
		b            StridedInterval
		wantLo       int64
		wantHi       int64
		wantContains []int64
	}{
		{
			name:         "disjoint intervals",
			a:            NewStridedInterval(1, 0, 5),
			b:            NewStridedInterval(1, 10, 15),
			wantLo:       0,
			wantHi:       15,
			wantContains: []int64{0, 5, 10, 15},
		},
		{
			name:         "overlapping intervals",
			a:            NewStridedInterval(2, 0, 10),
			b:            NewStridedInterval(2, 4, 14),
			wantLo:       0,
			wantHi:       14,
			wantContains: []int64{0, 2, 4, 14},
		},
		{
			name:         "join with empty",
			a:            emptyStridedInterval,
			b:            NewStridedInterval(1, 5, 10),
			wantLo:       5,
			wantHi:       10,
			wantContains: []int64{5, 7, 10},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.a.Join(tt.b)
			if result.Lo != tt.wantLo {
				t.Errorf("Lo: want %d, got %d", tt.wantLo, result.Lo)
			}
			if result.Hi != tt.wantHi {
				t.Errorf("Hi: want %d, got %d", tt.wantHi, result.Hi)
			}
			for _, v := range tt.wantContains {
				if !result.Contains(v) {
					t.Errorf("join result must contain %d", v)
				}
			}
		})
	}
}

func TestStridedInterval_Meet(t *testing.T) {
	// [0, 10] meet [5, 15] = [5, 10]
	a := NewStridedInterval(1, 0, 10)
	b := NewStridedInterval(1, 5, 15)
	result := a.Meet(b)
	if result.Lo != 5 || result.Hi != 10 {
		t.Errorf("meet [0,10] ∩ [5,15]: want [5,10], got [%d,%d]", result.Lo, result.Hi)
	}

	// disjoint: empty result
	c := NewStridedInterval(1, 0, 4)
	d := NewStridedInterval(1, 6, 10)
	empty := c.Meet(d)
	if !empty.IsEmpty() {
		t.Errorf("meet of disjoint intervals must be empty, got %s", empty.String())
	}
}

func TestStridedInterval_Widen(t *testing.T) {
	// widening: if next extends beyond current, widen to ±inf
	current := NewStridedInterval(1, 0, 10)
	next := NewStridedInterval(1, 0, 20) // hi grew
	widened := current.Widen(next)
	if widened.Hi != math.MaxInt64 {
		t.Errorf("widening should extend Hi to MaxInt64, got %d", widened.Hi)
	}
	if widened.Lo != 0 {
		t.Errorf("widening should preserve Lo when it did not decrease, got %d", widened.Lo)
	}

	// lo decreased: widen lo to MinInt64
	next2 := NewStridedInterval(1, -5, 10)
	widened2 := current.Widen(next2)
	if widened2.Lo != math.MinInt64 {
		t.Errorf("widening should extend Lo to MinInt64, got %d", widened2.Lo)
	}
}

func TestStridedInterval_Add(t *testing.T) {
	// [0, 10] + [5, 15] = [5, 25]
	a := NewStridedInterval(1, 0, 10)
	b := NewStridedInterval(1, 5, 15)
	result := a.Add(b)
	if result.Lo != 5 || result.Hi != 25 {
		t.Errorf("add: want [5,25], got [%d,%d]", result.Lo, result.Hi)
	}
}

func TestStridedInterval_Sub(t *testing.T) {
	// [10, 20] - [1, 5] = [5, 19]
	a := NewStridedInterval(1, 10, 20)
	b := NewStridedInterval(1, 1, 5)
	result := a.Sub(b)
	if result.Lo != 5 || result.Hi != 19 {
		t.Errorf("sub: want [5,19], got [%d,%d]", result.Lo, result.Hi)
	}
}

func TestStridedInterval_Mul(t *testing.T) {
	// [2, 4] * {3} = [6, 12]
	a := NewStridedInterval(1, 2, 4)
	b := NewSingleton(3)
	result := a.Mul(b)
	if result.Lo != 6 || result.Hi != 12 {
		t.Errorf("mul: want [6,12], got [%d,%d]", result.Lo, result.Hi)
	}
}

func TestStridedInterval_Shl(t *testing.T) {
	// [1, 4] << {2} = [4, 16]
	a := NewStridedInterval(1, 1, 4)
	shift := NewSingleton(2)
	result := a.Shl(shift)
	if result.Lo != 4 || result.Hi != 16 {
		t.Errorf("shl: want [4,16], got [%d,%d]", result.Lo, result.Hi)
	}
}

func TestStridedInterval_ArrayIndex(t *testing.T) {
	// typical array index: i in [0, 99], stride=1; address = base + i*4
	// i * 4 should give [0, 396, stride=4]
	i := NewStridedInterval(1, 0, 99)
	four := NewSingleton(4)
	offset := i.Mul(four)
	if offset.Lo != 0 || offset.Hi != 396 {
		t.Errorf("array offset: want [0,396], got [%d,%d]", offset.Lo, offset.Hi)
	}
	// stride should be 4 (every 4th value)
	if offset.Stride != 4 {
		t.Errorf("array offset stride: want 4, got %d", offset.Stride)
	}
}

// ============================================================================
// ValueSet unit tests
// ============================================================================

func TestValueSet_BottomTop(t *testing.T) {
	bottom := NewValueSetBottom()
	if !bottom.IsBottom() {
		t.Fatal("expected bottom")
	}
	if bottom.IsTop() {
		t.Fatal("bottom must not be top")
	}

	top := NewValueSetTop()
	if !top.IsTop() {
		t.Fatal("expected top")
	}
	if top.IsBottom() {
		t.Fatal("top must not be bottom")
	}
}

func TestValueSet_Constant(t *testing.T) {
	vs := NewValueSetConstant(42)
	if vs.IsBottom() || vs.IsTop() {
		t.Fatal("constant value set must not be bottom or top")
	}
	si := vs.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if !si.IsSingleton() || si.Lo != 42 {
		t.Fatalf("expected singleton {42}, got %s", si.String())
	}
}

func TestValueSet_Join(t *testing.T) {
	a := NewValueSetConstant(5)
	b := NewValueSetConstant(10)
	joined := a.Join(b)

	si := joined.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if si.Lo != 5 || si.Hi != 10 {
		t.Errorf("join of {5} and {10}: want [5,10], got %s", si.String())
	}
}

func TestValueSet_JoinWithBottom(t *testing.T) {
	bottom := NewValueSetBottom()
	vs := NewValueSetConstant(7)
	result := bottom.Join(vs)
	si := result.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if !si.IsSingleton() || si.Lo != 7 {
		t.Errorf("join(bottom, {7}) must be {7}, got %s", si.String())
	}
}

func TestValueSet_Equal(t *testing.T) {
	a := NewValueSetConstant(42)
	b := NewValueSetConstant(42)
	if !a.Equal(b) {
		t.Fatal("equal value sets must be equal")
	}

	c := NewValueSetConstant(43)
	if a.Equal(c) {
		t.Fatal("different value sets must not be equal")
	}
}

func TestValueSet_Pointer(t *testing.T) {
	stackRegion := MemoryRegion{Kind: RegionStack, ID: 1}
	vs := NewValueSetPointer(stackRegion, 1, -64, -8)

	si := vs.GetInterval(stackRegion)
	if si.Lo != -64 || si.Hi != -8 {
		t.Errorf("pointer interval: want [-64,-8], got %s", si.String())
	}

	// numeric region should be empty
	numericSI := vs.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if !numericSI.IsEmpty() {
		t.Errorf("pointer value set must have empty numeric region, got %s", numericSI.String())
	}
}

func TestValueSet_Widen(t *testing.T) {
	current := NewValueSetInterval(1, 0, 10)
	next := NewValueSetInterval(1, 0, 20)
	widened := current.Widen(next)

	si := widened.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if si.Hi != math.MaxInt64 {
		t.Errorf("widened Hi must be MaxInt64, got %d", si.Hi)
	}
}

// ============================================================================
// ValueSet arithmetic tests
// ============================================================================

func TestAddValueSets(t *testing.T) {
	a := NewValueSetInterval(1, 0, 10)
	b := NewValueSetInterval(1, 5, 15)
	result := AddValueSets(a, b)
	si := result.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if si.Lo != 5 || si.Hi != 25 {
		t.Errorf("add: want [5,25], got %s", si.String())
	}
}

func TestSubValueSets(t *testing.T) {
	a := NewValueSetInterval(1, 10, 20)
	b := NewValueSetInterval(1, 1, 5)
	result := SubValueSets(a, b)
	si := result.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if si.Lo != 5 || si.Hi != 19 {
		t.Errorf("sub: want [5,19], got %s", si.String())
	}
}

func TestMulValueSets(t *testing.T) {
	a := NewValueSetInterval(1, 2, 4)
	b := NewValueSetConstant(3)
	result := MulValueSets(a, b)
	si := result.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if si.Lo != 6 || si.Hi != 12 {
		t.Errorf("mul: want [6,12], got %s", si.String())
	}
}

func TestAddValueSets_PointerPlusOffset(t *testing.T) {
	// pointer arithmetic: stack_ptr + numeric_offset
	stackRegion := MemoryRegion{Kind: RegionStack, ID: 0}
	ptr := NewValueSetPointer(stackRegion, 1, 0, 0) // base pointer
	offset := NewValueSetConstant(8)                // +8 bytes

	result := AddValueSets(ptr, offset)
	si := result.GetInterval(stackRegion)
	if si.Lo != 8 || si.Hi != 8 {
		t.Errorf("ptr+8: want stack offset {8}, got %s", si.String())
	}
}

func TestAddValueSets_WithBottom(t *testing.T) {
	bottom := NewValueSetBottom()
	vs := NewValueSetConstant(5)
	result := AddValueSets(bottom, vs)
	if !result.IsBottom() {
		t.Fatal("bottom + anything must be bottom")
	}
}

func TestAddValueSets_WithTop(t *testing.T) {
	top := NewValueSetTop()
	vs := NewValueSetConstant(5)
	result := AddValueSets(top, vs)
	if !result.IsTop() {
		t.Fatal("top + anything must be top")
	}
}

// ============================================================================
// VSA Analyzer integration tests
// ============================================================================

// buildVSAFunction constructs a minimal ir.Function for VSA testing.
// the function has a single block with the given instructions.
func buildVSAFunction(name string, instrs []ir.IRInstruction) *ir.Function {
	block := &ir.BasicBlock{
		ID:           0,
		Instructions: instrs,
		Predecessors: nil,
		Successors:   nil,
	}
	return &ir.Function{
		Name:       name,
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		EntryBlock: 0,
	}
}

func TestVSA_Constant(t *testing.T) {
	// x = 42
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: true}}
	instrs := []ir.IRInstruction{
		&ir.Assign{
			Dest:   x,
			Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size8, Signed: true}},
		},
	}

	fn := buildVSAFunction("test_const", instrs)
	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	val, ok := result.IsConstant(x)
	if !ok {
		t.Fatal("x must be a constant")
	}
	if val != 42 {
		t.Errorf("x must be 42, got %d", val)
	}
}

func TestVSA_AddConstants(t *testing.T) {
	// x = 10; y = 20; z = x + y  =>  z in {30}
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: true}}
	y := ir.Variable{Name: "y", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: true}}
	z := ir.Variable{Name: "z", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: true}}

	instrs := []ir.IRInstruction{
		&ir.Assign{
			Dest:   x,
			Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 10, Width: ir.Size8, Signed: true}},
		},
		&ir.Assign{
			Dest:   y,
			Source: &ir.ConstantExpr{Value: ir.IntConstant{Value: 20, Width: ir.Size8, Signed: true}},
		},
		&ir.Assign{
			Dest: z,
			Source: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: x},
				Right: &ir.VariableExpr{Var: y},
			},
		},
	}

	fn := buildVSAFunction("test_add", instrs)
	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	val, ok := result.IsConstant(z)
	if !ok {
		t.Fatal("z must be a constant (10+20=30)")
	}
	if val != 30 {
		t.Errorf("z must be 30, got %d", val)
	}
}

func TestVSA_ArrayIndexPattern(t *testing.T) {
	// model a loop: block 0 (entry) -> block 1 (loop body) -> block 1 (back-edge)
	// block 0: i_init = 0
	// block 1: i = phi(block0: i_init, block1: i_next)
	//          offset = i * 4
	//          i_next = i + 1
	//          if i_next < 100 goto block1 else exit
	//
	// after fixed-point with widening, i should be in [0, MaxInt64] (widened),
	// but offset = i * 4 should be in [0, MaxInt64] as well.
	// the key property we test: offset is a multiple of 4 (stride=4) and Lo=0.
	//
	// for a simpler deterministic test, we directly verify the StridedInterval
	// arithmetic that VSA uses for array index patterns.

	// direct strided interval test: i in [0, 99, stride=1], offset = i * 4
	i := NewStridedInterval(1, 0, 99)
	four := NewSingleton(4)
	offset := i.Mul(four)

	if offset.Lo != 0 {
		t.Errorf("array offset Lo: want 0, got %d", offset.Lo)
	}
	if offset.Hi != 396 {
		t.Errorf("array offset Hi: want 396, got %d", offset.Hi)
	}
	if offset.Stride != 4 {
		t.Errorf("array offset stride: want 4, got %d", offset.Stride)
	}

	// verify all expected values are present
	for idx := int64(0); idx <= 99; idx++ {
		expected := idx * 4
		if !offset.Contains(expected) {
			t.Errorf("offset must contain %d (i=%d)", expected, idx)
			break
		}
	}

	// verify non-multiples of 4 are absent
	if offset.Contains(1) || offset.Contains(2) || offset.Contains(3) {
		t.Error("offset must not contain non-multiples of 4")
	}
}

func TestVSA_ModuloConstraint(t *testing.T) {
	// x = y % 8  =>  x in [0, 7]
	y := ir.Variable{Name: "y", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}

	instrs := []ir.IRInstruction{
		// y is unknown (loaded from memory)
		&ir.Load{
			Dest:    y,
			Address: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x1000, Width: ir.Size8, Signed: false}},
			Size:    ir.Size8,
		},
		&ir.Assign{
			Dest: x,
			Source: &ir.BinaryOp{
				Op:    ir.BinOpMod,
				Left:  &ir.VariableExpr{Var: y},
				Right: &ir.ConstantExpr{Value: ir.IntConstant{Value: 8, Width: ir.Size8, Signed: false}},
			},
		},
	}

	fn := buildVSAFunction("test_modulo", instrs)
	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	xVS := result.GetValueSet(x)
	si := xVS.GetInterval(MemoryRegion{Kind: RegionUnknown})

	if si.Lo != 0 || si.Hi != 7 {
		t.Errorf("x = y %% 8: want [0,7], got %s", si.String())
	}
}

func TestVSA_LoadResultIsTop(t *testing.T) {
	// load from memory: result must be top (unknown)
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size8, Signed: false}}
	instrs := []ir.IRInstruction{
		&ir.Load{
			Dest:    x,
			Address: &ir.ConstantExpr{Value: ir.IntConstant{Value: 0x4000, Width: ir.Size8, Signed: false}},
			Size:    ir.Size8,
		},
	}

	fn := buildVSAFunction("test_load", instrs)
	result, err := PerformVSA(fn, nil, nil)
	if err != nil {
		t.Fatalf("VSA failed: %v", err)
	}

	xVS := result.GetValueSet(x)
	if !xVS.IsTop() {
		t.Errorf("load result must be top, got %s", xVS.String())
	}
}

func TestVSA_EmptyFunction(t *testing.T) {
	fn := &ir.Function{
		Name:       "empty",
		Blocks:     map[ir.BlockID]*ir.BasicBlock{},
		EntryBlock: 0,
	}
	_, err := PerformVSA(fn, nil, nil)
	if err == nil {
		t.Fatal("expected error for empty function")
	}
}

// ============================================================================
// GCD / LCM helper tests
// ============================================================================

func TestGCDInt64(t *testing.T) {
	tests := []struct{ a, b, want int64 }{
		{12, 8, 4},
		{7, 3, 1},
		{0, 5, 5},
		{5, 0, 5},
		{0, 0, 0},
		{100, 25, 25},
	}
	for _, tt := range tests {
		got := gcdInt64(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("gcd(%d,%d): want %d, got %d", tt.a, tt.b, tt.want, got)
		}
	}
}

func TestLCMInt64(t *testing.T) {
	tests := []struct{ a, b, want int64 }{
		{4, 6, 12},
		{3, 5, 15},
		{0, 5, 0},
		{1, 1, 1},
	}
	for _, tt := range tests {
		got := lcmInt64(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("lcm(%d,%d): want %d, got %d", tt.a, tt.b, tt.want, got)
		}
	}
}

func TestAddSaturate(t *testing.T) {
	if addSaturate(math.MaxInt64, 1) != math.MaxInt64 {
		t.Error("addSaturate must saturate at MaxInt64")
	}
	if addSaturate(math.MinInt64, -1) != math.MinInt64 {
		t.Error("addSaturate must saturate at MinInt64")
	}
	if addSaturate(10, 20) != 30 {
		t.Error("addSaturate(10,20) must be 30")
	}
}

func TestMulSaturate(t *testing.T) {
	if mulSaturate(math.MaxInt64, 2) != math.MaxInt64 {
		t.Error("mulSaturate must saturate at MaxInt64")
	}
	if mulSaturate(3, 4) != 12 {
		t.Error("mulSaturate(3,4) must be 12")
	}
}
