package typeinfer

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// helpers
// ============================================================================

// acc builds a MemoryAccess with the given parameters.
func acc(base string, offset int64, size AccessSize, t ir.Type) MemoryAccess {
	return MemoryAccess{
		BaseVar:    base,
		Offset:     offset,
		Size:       size,
		IsWrite:    false,
		AccessType: t,
		Location:   "0x0",
	}
}

// findStruct returns the StructDef with the given name, or nil.
func findStruct(defs []StructDef, name string) *StructDef {
	for i := range defs {
		if defs[i].Name == name {
			return &defs[i]
		}
	}
	return nil
}

// findField returns the StructField at the given offset, or nil.
func findField(def *StructDef, offset int64) *StructField {
	for i := range def.Fields {
		if def.Fields[i].Offset == offset {
			return &def.Fields[i]
		}
	}
	return nil
}

// ============================================================================
// TestASIAnalyzer_SimpleStruct
// ============================================================================

// TestASIAnalyzer_SimpleStruct verifies recovery of a struct with three fields
// at offsets 0, 4, 8 with distinct types.
func TestASIAnalyzer_SimpleStruct(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}
	u8 := ir.IntType{Width: ir.Size1, Signed: false}

	accesses := []MemoryAccess{
		acc("p", 0, AccessSize4, i32),
		acc("p", 4, AccessSize1, u8),
		acc("p", 8, AccessSize8, i64),
	}

	a := NewASIAnalyzer()
	defs := a.InferStructures(accesses)

	if len(defs) != 1 {
		t.Fatalf("expected 1 struct, got %d", len(defs))
	}
	def := &defs[0]
	if len(def.Fields) != 3 {
		t.Fatalf("expected 3 fields, got %d", len(def.Fields))
	}

	// verify field at offset 0
	f0 := findField(def, 0)
	if f0 == nil {
		t.Fatal("field at offset 0 not found")
	}
	if f0.FieldType.String() != i32.String() {
		t.Errorf("field[0]: expected %s, got %s", i32, f0.FieldType)
	}
	if f0.Name != "field_0x00" {
		t.Errorf("field[0] name: expected field_0x00, got %s", f0.Name)
	}

	// verify field at offset 4
	f4 := findField(def, 4)
	if f4 == nil {
		t.Fatal("field at offset 4 not found")
	}
	if f4.FieldType.String() != u8.String() {
		t.Errorf("field[4]: expected %s, got %s", u8, f4.FieldType)
	}

	// verify field at offset 8
	f8 := findField(def, 8)
	if f8 == nil {
		t.Fatal("field at offset 8 not found")
	}
	if f8.FieldType.String() != i64.String() {
		t.Errorf("field[8]: expected %s, got %s", i64, f8.FieldType)
	}
}

// ============================================================================
// TestASIAnalyzer_NestedStruct
// ============================================================================

// TestASIAnalyzer_NestedStruct verifies that a struct whose fields are a
// strict subset of another struct's fields is marked as IsNested=true.
func TestASIAnalyzer_NestedStruct(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	// outer struct: fields at 0, 4, 8, 16
	// inner struct: fields at 0, 4 (subset of outer)
	accesses := []MemoryAccess{
		acc("outer", 0, AccessSize4, i32),
		acc("outer", 4, AccessSize4, i32),
		acc("outer", 8, AccessSize8, i64),
		acc("outer", 16, AccessSize8, i64),
		acc("inner", 0, AccessSize4, i32),
		acc("inner", 4, AccessSize4, i32),
	}

	a := NewASIAnalyzer()
	defs := a.InferStructures(accesses)

	if len(defs) != 2 {
		t.Fatalf("expected 2 structs, got %d", len(defs))
	}

	innerDef := findStruct(defs, "struct_inner")
	if innerDef == nil {
		t.Fatal("struct_inner not found")
	}
	if !innerDef.IsNested {
		t.Error("struct_inner should be marked as nested")
	}

	outerDef := findStruct(defs, "struct_outer")
	if outerDef == nil {
		t.Fatal("struct_outer not found")
	}
	if outerDef.IsNested {
		t.Error("struct_outer should NOT be marked as nested")
	}
}

// ============================================================================
// TestASIAnalyzer_ArrayDetection
// ============================================================================

// TestASIAnalyzer_ArrayDetection verifies that strided accesses (stride=4,
// offsets 0,4,8,12) are recovered as four separate fields with consistent types.
func TestASIAnalyzer_ArrayDetection(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}

	accesses := []MemoryAccess{
		acc("arr", 0, AccessSize4, i32),
		acc("arr", 4, AccessSize4, i32),
		acc("arr", 8, AccessSize4, i32),
		acc("arr", 12, AccessSize4, i32),
	}

	a := NewASIAnalyzer()
	defs := a.InferStructures(accesses)

	if len(defs) != 1 {
		t.Fatalf("expected 1 struct, got %d", len(defs))
	}
	def := &defs[0]
	if len(def.Fields) != 4 {
		t.Fatalf("expected 4 fields for strided access, got %d", len(def.Fields))
	}

	// all fields must have the same type and correct stride
	for i, f := range def.Fields {
		expectedOffset := int64(i * 4)
		if f.Offset != expectedOffset {
			t.Errorf("field[%d]: expected offset %d, got %d", i, expectedOffset, f.Offset)
		}
		if f.FieldType.String() != i32.String() {
			t.Errorf("field[%d]: expected %s, got %s", i, i32, f.FieldType)
		}
		if f.Size != 4 {
			t.Errorf("field[%d]: expected size 4, got %d", i, f.Size)
		}
	}

	// struct size must be 16 (4 fields * 4 bytes, aligned to 4)
	if def.Size != 16 {
		t.Errorf("expected struct size 16, got %d", def.Size)
	}
}

// ============================================================================
// TestASIAnalyzer_MultipleStructs
// ============================================================================

// TestASIAnalyzer_MultipleStructs verifies that accesses from two distinct
// base pointers produce two independent StructDefs.
func TestASIAnalyzer_MultipleStructs(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	accesses := []MemoryAccess{
		acc("node", 0, AccessSize8, i64),  // next pointer
		acc("node", 8, AccessSize4, i32),  // value
		acc("point", 0, AccessSize4, i32), // x
		acc("point", 4, AccessSize4, i32), // y
	}

	a := NewASIAnalyzer()
	defs := a.InferStructures(accesses)

	if len(defs) != 2 {
		t.Fatalf("expected 2 structs, got %d", len(defs))
	}

	nodeDef := findStruct(defs, "struct_node")
	if nodeDef == nil {
		t.Fatal("struct_node not found")
	}
	if len(nodeDef.Fields) != 2 {
		t.Errorf("struct_node: expected 2 fields, got %d", len(nodeDef.Fields))
	}

	pointDef := findStruct(defs, "struct_point")
	if pointDef == nil {
		t.Fatal("struct_point not found")
	}
	if len(pointDef.Fields) != 2 {
		t.Errorf("struct_point: expected 2 fields, got %d", len(pointDef.Fields))
	}
}

// ============================================================================
// TestASIAnalyzer_EmptyAccesses
// ============================================================================

// TestASIAnalyzer_EmptyAccesses verifies that an empty input produces nil output.
func TestASIAnalyzer_EmptyAccesses(t *testing.T) {
	a := NewASIAnalyzer()
	defs := a.InferStructures(nil)
	if defs != nil {
		t.Errorf("expected nil for empty input, got %v", defs)
	}
	defs = a.InferStructures([]MemoryAccess{})
	if defs != nil {
		t.Errorf("expected nil for empty slice, got %v", defs)
	}
}

// ============================================================================
// TestASIAnalyzer_SingleField
// ============================================================================

// TestASIAnalyzer_SingleField verifies that a single access produces a
// one-field struct with correct size and alignment.
func TestASIAnalyzer_SingleField(t *testing.T) {
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	accesses := []MemoryAccess{
		acc("ptr", 0, AccessSize8, i64),
	}

	a := NewASIAnalyzer()
	defs := a.InferStructures(accesses)

	if len(defs) != 1 {
		t.Fatalf("expected 1 struct, got %d", len(defs))
	}
	def := &defs[0]
	if len(def.Fields) != 1 {
		t.Fatalf("expected 1 field, got %d", len(def.Fields))
	}
	if def.Fields[0].FieldType.String() != i64.String() {
		t.Errorf("expected %s, got %s", i64, def.Fields[0].FieldType)
	}
	if def.Size != 8 {
		t.Errorf("expected size 8, got %d", def.Size)
	}
	if def.Alignment != 8 {
		t.Errorf("expected alignment 8, got %d", def.Alignment)
	}
}

// ============================================================================
// TestASIAnalyzer_AlignmentComputation
// ============================================================================

// TestASIAnalyzer_AlignmentComputation verifies that struct alignment equals
// the maximum field alignment and that total size is rounded up accordingly.
func TestASIAnalyzer_AlignmentComputation(t *testing.T) {
	u8 := ir.IntType{Width: ir.Size1, Signed: false}
	i64 := ir.IntType{Width: ir.Size8, Signed: true}

	// fields: u8 at 0 (align=1), i64 at 8 (align=8)
	// max alignment = 8, raw end = 8+8=16, aligned size = 16
	accesses := []MemoryAccess{
		acc("s", 0, AccessSize1, u8),
		acc("s", 8, AccessSize8, i64),
	}

	a := NewASIAnalyzer()
	defs := a.InferStructures(accesses)

	if len(defs) != 1 {
		t.Fatalf("expected 1 struct, got %d", len(defs))
	}
	def := &defs[0]

	if def.Alignment != 8 {
		t.Errorf("expected alignment 8 (max field align), got %d", def.Alignment)
	}
	// size must be aligned to 8: raw end = 16, aligned = 16
	if def.Size != 16 {
		t.Errorf("expected size 16, got %d", def.Size)
	}
}

// ============================================================================
// TestASIAnalyzer_FieldTypeInference
// ============================================================================

// TestASIAnalyzer_FieldTypeInference verifies that when AccessType is nil,
// the field type is synthesised from the access size.
func TestASIAnalyzer_FieldTypeInference(t *testing.T) {
	accesses := []MemoryAccess{
		{BaseVar: "q", Offset: 0, Size: AccessSize4, AccessType: nil, Location: "0x0"},
		{BaseVar: "q", Offset: 4, Size: AccessSize8, AccessType: nil, Location: "0x4"},
		{BaseVar: "q", Offset: 12, Size: AccessSize2, AccessType: nil, Location: "0x8"},
		{BaseVar: "q", Offset: 14, Size: AccessSize1, AccessType: nil, Location: "0xc"},
	}

	a := NewASIAnalyzer()
	defs := a.InferStructures(accesses)

	if len(defs) != 1 {
		t.Fatalf("expected 1 struct, got %d", len(defs))
	}
	def := &defs[0]
	if len(def.Fields) != 4 {
		t.Fatalf("expected 4 fields, got %d", len(def.Fields))
	}

	expected := []struct {
		offset int64
		typ    string
	}{
		{0, "u32"},
		{4, "u64"},
		{12, "u16"},
		{14, "u8"},
	}

	for _, e := range expected {
		f := findField(def, e.offset)
		if f == nil {
			t.Errorf("field at offset %d not found", e.offset)
			continue
		}
		if f.FieldType.String() != e.typ {
			t.Errorf("offset %d: expected type %s, got %s", e.offset, e.typ, f.FieldType)
		}
	}
}

// ============================================================================
// TestASIAnalyzer_DuplicateAccessMerge
// ============================================================================

// TestASIAnalyzer_DuplicateAccessMerge verifies that multiple accesses at the
// same offset are merged into a single field (no duplicates).
func TestASIAnalyzer_DuplicateAccessMerge(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}

	accesses := []MemoryAccess{
		acc("s", 0, AccessSize4, i32),
		acc("s", 0, AccessSize4, i32), // duplicate read
		acc("s", 0, AccessSize4, i32), // another duplicate (write)
	}
	accesses[2].IsWrite = true

	a := NewASIAnalyzer()
	defs := a.InferStructures(accesses)

	if len(defs) != 1 {
		t.Fatalf("expected 1 struct, got %d", len(defs))
	}
	if len(defs[0].Fields) != 1 {
		t.Errorf("expected 1 merged field, got %d", len(defs[0].Fields))
	}
}

// ============================================================================
// TestASIAnalyzer_FieldNameFormat
// ============================================================================

// TestASIAnalyzer_FieldNameFormat verifies the field_0x%02x naming convention.
func TestASIAnalyzer_FieldNameFormat(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}

	accesses := []MemoryAccess{
		acc("s", 0, AccessSize4, i32),
		acc("s", 16, AccessSize4, i32),
		acc("s", 255, AccessSize4, i32),
	}

	a := NewASIAnalyzer()
	defs := a.InferStructures(accesses)

	if len(defs) != 1 {
		t.Fatalf("expected 1 struct, got %d", len(defs))
	}

	names := map[int64]string{
		0:   "field_0x00",
		16:  "field_0x10",
		255: "field_0xff",
	}
	for _, f := range defs[0].Fields {
		expected, ok := names[f.Offset]
		if !ok {
			t.Errorf("unexpected field at offset %d", f.Offset)
			continue
		}
		if f.Name != expected {
			t.Errorf("offset %d: expected name %s, got %s", f.Offset, expected, f.Name)
		}
	}
}

// ============================================================================
// TestASIAnalyzer_StructSize
// ============================================================================

// TestASIAnalyzer_StructSize verifies that struct size = alignUp(max(offset+size), alignment).
func TestASIAnalyzer_StructSize(t *testing.T) {
	i32 := ir.IntType{Width: ir.Size4, Signed: true}

	// fields at 0 (4 bytes) and 4 (4 bytes): raw end=8, align=4, size=8
	accesses := []MemoryAccess{
		acc("s", 0, AccessSize4, i32),
		acc("s", 4, AccessSize4, i32),
	}

	a := NewASIAnalyzer()
	defs := a.InferStructures(accesses)

	if len(defs) != 1 {
		t.Fatalf("expected 1 struct, got %d", len(defs))
	}
	if defs[0].Size != 8 {
		t.Errorf("expected size 8, got %d", defs[0].Size)
	}
	if defs[0].Alignment != 4 {
		t.Errorf("expected alignment 4, got %d", defs[0].Alignment)
	}
}

// ============================================================================
// TestOffsetSignature
// ============================================================================

// TestOffsetSignature verifies that offsetSignature produces a canonical
// comma-separated sorted offset string.
func TestOffsetSignature(t *testing.T) {
	def := StructDef{
		Fields: []StructField{
			{Offset: 8},
			{Offset: 0},
			{Offset: 4},
		},
	}
	sig := offsetSignature(def)
	expected := "0,4,8,"
	if sig != expected {
		t.Errorf("expected %q, got %q", expected, sig)
	}
}

// TestAlignUp verifies edge cases of the alignUp helper.
func TestAlignUp(t *testing.T) {
	cases := []struct {
		v, align, want int64
	}{
		{0, 4, 0},
		{1, 4, 4},
		{4, 4, 4},
		{5, 8, 8},
		{16, 8, 16},
		{17, 8, 24},
		{0, 0, 0}, // zero align: return v unchanged
	}
	for _, c := range cases {
		got := alignUp(c.v, c.align)
		if got != c.want {
			t.Errorf("alignUp(%d,%d): expected %d, got %d", c.v, c.align, c.want, got)
		}
	}
}

// TestDefaultTypeForSize verifies fallback for unusual access sizes.
func TestDefaultTypeForSize(t *testing.T) {
	// unusual size 3 must fall back to u8
	got := defaultTypeForSize(3)
	expected := ir.IntType{Width: ir.Size1, Signed: false}
	if got.String() != expected.String() {
		t.Errorf("defaultTypeForSize(3): expected %s, got %s", expected, got)
	}
	// size 0 also falls back to u8
	got = defaultTypeForSize(0)
	if got.String() != expected.String() {
		t.Errorf("defaultTypeForSize(0): expected %s, got %s", expected, got)
	}
}

// TestAlignmentForSize verifies fallback for unusual field sizes.
func TestAlignmentForSize(t *testing.T) {
	// unusual size 3 must fall back to alignment 1
	got := alignmentForSize(3)
	if got != 1 {
		t.Errorf("alignmentForSize(3): expected 1, got %d", got)
	}
}

// TestASIAnalyzer_ZeroSizeAccess verifies that a zero-size access is treated
// as a 1-byte access without panicking.
func TestASIAnalyzer_ZeroSizeAccess(t *testing.T) {
	accesses := []MemoryAccess{
		{BaseVar: "z", Offset: 0, Size: 0, AccessType: nil, Location: "0x0"},
	}
	a := NewASIAnalyzer()
	defs := a.InferStructures(accesses)
	if len(defs) != 1 {
		t.Fatalf("expected 1 struct, got %d", len(defs))
	}
	if len(defs[0].Fields) != 1 {
		t.Fatalf("expected 1 field, got %d", len(defs[0].Fields))
	}
}
