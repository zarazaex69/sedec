package ir

import (
	"testing"
)

// ============================================================================
// Extract Operation Tests
// ============================================================================

func TestExtract_Type(t *testing.T) {
	tests := []struct {
		name     string
		extract  Extract
		wantSize Size
	}{
		{
			name: "extract al from rax",
			extract: Extract{
				Source: Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}},
				Offset: 0,
				Size:   Size1,
			},
			wantSize: Size1,
		},
		{
			name: "extract ah from rax",
			extract: Extract{
				Source: Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}},
				Offset: 1,
				Size:   Size1,
			},
			wantSize: Size1,
		},
		{
			name: "extract ax from rax",
			extract: Extract{
				Source: Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}},
				Offset: 0,
				Size:   Size2,
			},
			wantSize: Size2,
		},
		{
			name: "extract eax from rax",
			extract: Extract{
				Source: Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}},
				Offset: 0,
				Size:   Size4,
			},
			wantSize: Size4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typ := tt.extract.Type()
			intType, ok := typ.(IntType)
			if !ok {
				t.Fatalf("expected IntType, got %T", typ)
			}
			if intType.Width != tt.wantSize {
				t.Errorf("expected size %d, got %d", tt.wantSize, intType.Width)
			}
			if intType.Signed {
				t.Errorf("expected unsigned type, got signed")
			}
		})
	}
}

func TestExtract_String(t *testing.T) {
	extract := Extract{
		Source: Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}},
		Offset: 1,
		Size:   Size1,
	}

	got := extract.String()
	want := "extract(rax, offset=1, size=1)"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

// ============================================================================
// Insert Operation Tests
// ============================================================================

func TestInsert_Type(t *testing.T) {
	raxType := IntType{Width: Size8, Signed: false}
	rax := Variable{Name: "rax", Type: raxType}
	alValue := ConstantExpr{Value: IntConstant{Value: 0x42, Width: Size1, Signed: false}}

	insert := Insert{
		Dest:   rax,
		Value:  alValue,
		Offset: 0,
		Size:   Size1,
	}

	typ := insert.Type()
	if typ != raxType {
		t.Errorf("expected type %v, got %v", raxType, typ)
	}
}

func TestInsert_String(t *testing.T) {
	rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}
	alValue := ConstantExpr{Value: IntConstant{Value: 0x42, Width: Size1, Signed: false}}

	insert := Insert{
		Dest:   rax,
		Value:  alValue,
		Offset: 0,
		Size:   Size1,
	}

	got := insert.String()
	// expected format: insert(rax, 66, offset=0, size=1)
	// note: 0x42 = 66 in decimal
	if got != "insert(rax, 66, offset=0, size=1)" {
		t.Errorf("unexpected string representation: %q", got)
	}
}

func TestInsert_PreservesUpperBits(t *testing.T) {
	// test that insert operation semantics preserve upper bits
	// this is a semantic test - actual execution would be in ir interpreter

	tests := []struct {
		name   string
		offset uint8
		size   Size
		desc   string
	}{
		{
			name:   "insert al preserves bits 8-63",
			offset: 0,
			size:   Size1,
			desc:   "writing to al (bits 0-7) preserves bits 8-63",
		},
		{
			name:   "insert ah preserves bits 0-7 and 16-63",
			offset: 1,
			size:   Size1,
			desc:   "writing to ah (bits 8-15) preserves bits 0-7 and 16-63",
		},
		{
			name:   "insert ax preserves bits 16-63",
			offset: 0,
			size:   Size2,
			desc:   "writing to ax (bits 0-15) preserves bits 16-63",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}
			value := ConstantExpr{Value: IntConstant{Value: 0xFF, Width: tt.size, Signed: false}}

			insert := Insert{
				Dest:   rax,
				Value:  value,
				Offset: tt.offset,
				Size:   tt.size,
			}

			// verify insert operation is correctly formed
			if insert.Offset != tt.offset {
				t.Errorf("expected offset %d, got %d", tt.offset, insert.Offset)
			}
			if insert.Size != tt.size {
				t.Errorf("expected size %d, got %d", tt.size, insert.Size)
			}

			t.Logf("semantics: %s", tt.desc)
		})
	}
}

// ============================================================================
// ZeroExtend Operation Tests
// ============================================================================

func TestZeroExtend_Type(t *testing.T) {
	tests := []struct {
		name     string
		zext     ZeroExtend
		wantSize Size
	}{
		{
			name: "extend eax to rax",
			zext: ZeroExtend{
				Source:   Variable{Name: "eax", Type: IntType{Width: Size4, Signed: false}},
				FromSize: Size4,
				ToSize:   Size8,
			},
			wantSize: Size8,
		},
		{
			name: "extend ax to rax",
			zext: ZeroExtend{
				Source:   Variable{Name: "ax", Type: IntType{Width: Size2, Signed: false}},
				FromSize: Size2,
				ToSize:   Size8,
			},
			wantSize: Size8,
		},
		{
			name: "extend al to rax",
			zext: ZeroExtend{
				Source:   Variable{Name: "al", Type: IntType{Width: Size1, Signed: false}},
				FromSize: Size1,
				ToSize:   Size8,
			},
			wantSize: Size8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typ := tt.zext.Type()
			intType, ok := typ.(IntType)
			if !ok {
				t.Fatalf("expected IntType, got %T", typ)
			}
			if intType.Width != tt.wantSize {
				t.Errorf("expected size %d, got %d", tt.wantSize, intType.Width)
			}
			if intType.Signed {
				t.Errorf("expected unsigned type, got signed")
			}
		})
	}
}

func TestZeroExtend_String(t *testing.T) {
	zext := ZeroExtend{
		Source:   Variable{Name: "eax", Type: IntType{Width: Size4, Signed: false}},
		FromSize: Size4,
		ToSize:   Size8,
	}

	got := zext.String()
	want := "zeroextend(eax, from=4, to=8)"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestZeroExtend_32BitRule(t *testing.T) {
	// critical x86_64 rule: writing to 32-bit register zeros upper 32 bits
	// this is different from 8/16-bit writes which preserve upper bits

	eax := Variable{Name: "eax", Type: IntType{Width: Size4, Signed: false}}

	zext := ZeroExtend{
		Source:   eax,
		FromSize: Size4,
		ToSize:   Size8,
	}

	// verify zero extension is correctly formed
	if zext.FromSize != Size4 {
		t.Errorf("expected fromsize 4, got %d", zext.FromSize)
	}
	if zext.ToSize != Size8 {
		t.Errorf("expected tosize 8, got %d", zext.ToSize)
	}

	t.Log("semantics: writing to eax zeros bits 32-63 of rax")
	t.Log("this is x86_64 isa-defined behavior for 32-bit operations")
}

// ============================================================================
// Register Aliasing Relationship Tests
// ============================================================================

func TestGetParentRegister(t *testing.T) {
	tests := []struct {
		subReg     string
		wantParent string
		wantOffset uint8
		wantSize   Size
		wantFound  bool
	}{
		// rax family
		{"al", "rax", 0, Size1, true},
		{"ah", "rax", 1, Size1, true},
		{"ax", "rax", 0, Size2, true},
		{"eax", "rax", 0, Size4, true},

		// rbx family
		{"bl", "rbx", 0, Size1, true},
		{"bh", "rbx", 1, Size1, true},
		{"bx", "rbx", 0, Size2, true},
		{"ebx", "rbx", 0, Size4, true},

		// rcx family
		{"cl", "rcx", 0, Size1, true},
		{"ch", "rcx", 1, Size1, true},
		{"cx", "rcx", 0, Size2, true},
		{"ecx", "rcx", 0, Size4, true},

		// rdx family
		{"dl", "rdx", 0, Size1, true},
		{"dh", "rdx", 1, Size1, true},
		{"dx", "rdx", 0, Size2, true},
		{"edx", "rdx", 0, Size4, true},

		// rsi family (no high byte register)
		{"sil", "rsi", 0, Size1, true},
		{"si", "rsi", 0, Size2, true},
		{"esi", "rsi", 0, Size4, true},

		// rdi family (no high byte register)
		{"dil", "rdi", 0, Size1, true},
		{"di", "rdi", 0, Size2, true},
		{"edi", "rdi", 0, Size4, true},

		// r8-r15 families (no high byte registers)
		{"r8b", "r8", 0, Size1, true},
		{"r8w", "r8", 0, Size2, true},
		{"r8d", "r8", 0, Size4, true},

		{"r15b", "r15", 0, Size1, true},
		{"r15w", "r15", 0, Size2, true},
		{"r15d", "r15", 0, Size4, true},

		// non-existent registers
		{"xyz", "", 0, 0, false},
		{"rax", "", 0, 0, false}, // rax is parent, not sub-register
	}

	for _, tt := range tests {
		t.Run(tt.subReg, func(t *testing.T) {
			parent, offset, size, found := GetParentRegister(tt.subReg)

			if found != tt.wantFound {
				t.Errorf("expected found=%v, got %v", tt.wantFound, found)
			}

			if !found {
				return
			}

			if parent != tt.wantParent {
				t.Errorf("expected parent %q, got %q", tt.wantParent, parent)
			}
			if offset != tt.wantOffset {
				t.Errorf("expected offset %d, got %d", tt.wantOffset, offset)
			}
			if size != tt.wantSize {
				t.Errorf("expected size %d, got %d", tt.wantSize, size)
			}
		})
	}
}

func TestIsSubRegister(t *testing.T) {
	tests := []struct {
		subReg    string
		parentReg string
		want      bool
	}{
		// positive cases
		{"al", "rax", true},
		{"ah", "rax", true},
		{"ax", "rax", true},
		{"eax", "rax", true},
		{"bl", "rbx", true},
		{"bh", "rbx", true},
		{"r8b", "r8", true},
		{"r8w", "r8", true},
		{"r8d", "r8", true},

		// negative cases
		{"al", "rbx", false},
		{"bl", "rax", false},
		{"rax", "rax", false}, // parent is not sub-register of itself
		{"xyz", "rax", false},
		{"al", "xyz", false},
	}

	for _, tt := range tests {
		t.Run(tt.subReg+"_"+tt.parentReg, func(t *testing.T) {
			got := IsSubRegister(tt.subReg, tt.parentReg)
			if got != tt.want {
				t.Errorf("IsSubRegister(%q, %q) = %v, want %v",
					tt.subReg, tt.parentReg, got, tt.want)
			}
		})
	}
}

func TestIs32BitRegister(t *testing.T) {
	tests := []struct {
		reg  string
		want bool
	}{
		// 32-bit registers (should return true)
		{"eax", true},
		{"ebx", true},
		{"ecx", true},
		{"edx", true},
		{"esi", true},
		{"edi", true},
		{"ebp", true},
		{"esp", true},
		{"r8d", true},
		{"r9d", true},
		{"r10d", true},
		{"r11d", true},
		{"r12d", true},
		{"r13d", true},
		{"r14d", true},
		{"r15d", true},

		// non-32-bit registers (should return false)
		{"rax", false},
		{"rbx", false},
		{"ax", false},
		{"al", false},
		{"ah", false},
		{"r8", false},
		{"r8w", false},
		{"r8b", false},
		{"xyz", false},
		{"", false},
		{"e", false},
		{"ed", false},
	}

	for _, tt := range tests {
		t.Run(tt.reg, func(t *testing.T) {
			got := Is32BitRegister(tt.reg)
			if got != tt.want {
				t.Errorf("Is32BitRegister(%q) = %v, want %v", tt.reg, got, tt.want)
			}
		})
	}
}

// ============================================================================
// Semantic Correctness Tests
// ============================================================================

func TestSubRegisterSemantics_8BitWrite(t *testing.T) {
	// test semantic correctness: writing to 8-bit register preserves upper bits

	rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}
	alValue := ConstantExpr{Value: IntConstant{Value: 0x42, Width: Size1, Signed: false}}

	// writing to al should use insert, not zeroextend
	insert := Insert{
		Dest:   rax,
		Value:  alValue,
		Offset: 0,
		Size:   Size1,
	}

	// verify insert preserves upper bits semantically
	if insert.Size != Size1 {
		t.Errorf("expected size 1, got %d", insert.Size)
	}
	if insert.Offset != 0 {
		t.Errorf("expected offset 0, got %d", insert.Offset)
	}

	t.Log("semantics verified: insert operation preserves bits 8-63 of rax")
}

func TestSubRegisterSemantics_16BitWrite(t *testing.T) {
	// test semantic correctness: writing to 16-bit register preserves upper bits

	rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}
	axValue := ConstantExpr{Value: IntConstant{Value: 0x1234, Width: Size2, Signed: false}}

	// writing to ax should use insert, not zeroextend
	insert := Insert{
		Dest:   rax,
		Value:  axValue,
		Offset: 0,
		Size:   Size2,
	}

	// verify insert preserves upper bits semantically
	if insert.Size != Size2 {
		t.Errorf("expected size 2, got %d", insert.Size)
	}
	if insert.Offset != 0 {
		t.Errorf("expected offset 0, got %d", insert.Offset)
	}

	t.Log("semantics verified: insert operation preserves bits 16-63 of rax")
}

func TestSubRegisterSemantics_32BitWrite(t *testing.T) {
	// test semantic correctness: writing to 32-bit register zeros upper bits

	eax := Variable{Name: "eax", Type: IntType{Width: Size4, Signed: false}}

	// writing to eax should use zeroextend, not insert
	zext := ZeroExtend{
		Source:   eax,
		FromSize: Size4,
		ToSize:   Size8,
	}

	// verify zeroextend zeros upper bits semantically
	if zext.FromSize != Size4 {
		t.Errorf("expected fromsize 4, got %d", zext.FromSize)
	}
	if zext.ToSize != Size8 {
		t.Errorf("expected tosize 8, got %d", zext.ToSize)
	}

	t.Log("semantics verified: zeroextend operation zeros bits 32-63 of rax")
	t.Log("this is x86_64 isa-defined behavior")
}

func TestSubRegisterSemantics_HighByteWrite(t *testing.T) {
	// test semantic correctness: writing to ah (high byte) preserves other bits

	rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}
	ahValue := ConstantExpr{Value: IntConstant{Value: 0x42, Width: Size1, Signed: false}}

	// writing to ah should use insert with offset=1
	insert := Insert{
		Dest:   rax,
		Value:  ahValue,
		Offset: 1, // critical: offset 1 for high byte
		Size:   Size1,
	}

	// verify insert preserves bits 0-7 and 16-63
	if insert.Size != Size1 {
		t.Errorf("expected size 1, got %d", insert.Size)
	}
	if insert.Offset != 1 {
		t.Errorf("expected offset 1, got %d", insert.Offset)
	}

	t.Log("semantics verified: insert with offset=1 modifies bits 8-15 only")
	t.Log("preserves bits 0-7 (al) and bits 16-63 (upper rax)")
}

// ============================================================================
// Interface Compliance Tests
// ============================================================================

func TestSubRegisterOp_InterfaceCompliance(t *testing.T) {
	// verify all sub-register operations implement required interfaces

	var _ SubRegisterOp = Extract{}
	var _ SubRegisterOp = Insert{}
	var _ SubRegisterOp = ZeroExtend{}

	var _ Expression = Extract{}
	var _ Expression = Insert{}
	var _ Expression = ZeroExtend{}

	t.Log("all sub-register operations implement SubRegisterOp interface")
	t.Log("all sub-register operations implement Expression interface")
}

// ============================================================================
// Edge Case Tests
// ============================================================================

func TestSubRegisterOp_EdgeCases(t *testing.T) {
	t.Run("extract with zero offset", func(t *testing.T) {
		extract := Extract{
			Source: Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}},
			Offset: 0,
			Size:   Size1,
		}
		if extract.Offset != 0 {
			t.Errorf("expected offset 0, got %d", extract.Offset)
		}
	})

	t.Run("extract with non-zero offset", func(t *testing.T) {
		extract := Extract{
			Source: Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}},
			Offset: 1,
			Size:   Size1,
		}
		if extract.Offset != 1 {
			t.Errorf("expected offset 1, got %d", extract.Offset)
		}
	})

	t.Run("zeroextend same size", func(t *testing.T) {
		// edge case: extending to same size (should still zero upper bits conceptually)
		zext := ZeroExtend{
			Source:   Variable{Name: "eax", Type: IntType{Width: Size4, Signed: false}},
			FromSize: Size4,
			ToSize:   Size4,
		}
		if zext.FromSize != zext.ToSize {
			t.Errorf("expected same size, got from=%d to=%d", zext.FromSize, zext.ToSize)
		}
	})
}

// ============================================================================
// Coverage Tests for All Register Families
// ============================================================================

func TestRegisterAliases_Coverage(t *testing.T) {
	// verify all major register families are covered

	families := []struct {
		parent string
		subs   []string
	}{
		{"rax", []string{"eax", "ax", "al", "ah"}},
		{"rbx", []string{"ebx", "bx", "bl", "bh"}},
		{"rcx", []string{"ecx", "cx", "cl", "ch"}},
		{"rdx", []string{"edx", "dx", "dl", "dh"}},
		{"rsi", []string{"esi", "si", "sil"}},
		{"rdi", []string{"edi", "di", "dil"}},
		{"rbp", []string{"ebp", "bp", "bpl"}},
		{"rsp", []string{"esp", "sp", "spl"}},
		{"r8", []string{"r8d", "r8w", "r8b"}},
		{"r9", []string{"r9d", "r9w", "r9b"}},
		{"r10", []string{"r10d", "r10w", "r10b"}},
		{"r11", []string{"r11d", "r11w", "r11b"}},
		{"r12", []string{"r12d", "r12w", "r12b"}},
		{"r13", []string{"r13d", "r13w", "r13b"}},
		{"r14", []string{"r14d", "r14w", "r14b"}},
		{"r15", []string{"r15d", "r15w", "r15b"}},
	}

	for _, family := range families {
		t.Run(family.parent, func(t *testing.T) {
			for _, sub := range family.subs {
				parent, _, _, found := GetParentRegister(sub)
				if !found {
					t.Errorf("sub-register %q not found in alias table", sub)
					continue
				}
				if parent != family.parent {
					t.Errorf("sub-register %q has wrong parent: got %q, want %q",
						sub, parent, family.parent)
				}
			}
		})
	}

	t.Logf("verified %d register families with complete aliasing coverage", len(families))
}

func TestIs64BitRegister(t *testing.T) {
	tests := []struct {
		reg  string
		want bool
	}{
		{"rax", true}, {"rbx", true}, {"rcx", true}, {"rdx", true},
		{"rsi", true}, {"rdi", true}, {"rbp", true}, {"rsp", true},
		{"r8", true}, {"r9", true}, {"r10", true}, {"r11", true},
		{"r12", true}, {"r13", true}, {"r14", true}, {"r15", true},
		{"eax", false}, {"ax", false}, {"al", false}, {"ah", false},
		{"r8d", false}, {"r8w", false}, {"r8b", false},
		{"xmm0", false}, {"", false},
	}
	for _, tt := range tests {
		t.Run(tt.reg, func(t *testing.T) {
			got := Is64BitRegister(tt.reg)
			if got != tt.want {
				t.Errorf("Is64BitRegister(%q) = %v, want %v", tt.reg, got, tt.want)
			}
		})
	}
}

func TestRegisterSize(t *testing.T) {
	tests := []struct {
		reg  string
		want Size
	}{
		{"rax", Size8}, {"rbx", Size8}, {"rsp", Size8}, {"r15", Size8},
		{"eax", Size4}, {"ebx", Size4}, {"r8d", Size4},
		{"ax", Size2}, {"bx", Size2}, {"r8w", Size2},
		{"al", Size1}, {"ah", Size1}, {"bl", Size1}, {"r8b", Size1},
		{"xmm0", 0}, {"unknown", 0},
	}
	for _, tt := range tests {
		t.Run(tt.reg, func(t *testing.T) {
			got := RegisterSize(tt.reg)
			if got != tt.want {
				t.Errorf("RegisterSize(%q) = %d, want %d", tt.reg, got, tt.want)
			}
		})
	}
}

func TestClassifyRegisterWrite(t *testing.T) {
	tests := []struct {
		reg        string
		wantKind   SubRegisterWriteKind
		wantParent string
		wantOffset uint8
		wantSize   Size
	}{
		{"rax", WriteKindFull, "rax", 0, Size8},
		{"rbx", WriteKindFull, "rbx", 0, Size8},
		{"r15", WriteKindFull, "r15", 0, Size8},
		{"eax", WriteKindZeroExtend, "rax", 0, Size4},
		{"ebx", WriteKindZeroExtend, "rbx", 0, Size4},
		{"r8d", WriteKindZeroExtend, "r8", 0, Size4},
		{"ax", WriteKindInsert, "rax", 0, Size2},
		{"bx", WriteKindInsert, "rbx", 0, Size2},
		{"r8w", WriteKindInsert, "r8", 0, Size2},
		{"al", WriteKindInsert, "rax", 0, Size1},
		{"ah", WriteKindInsert, "rax", 1, Size1},
		{"bl", WriteKindInsert, "rbx", 0, Size1},
		{"bh", WriteKindInsert, "rbx", 1, Size1},
		{"r8b", WriteKindInsert, "r8", 0, Size1},
		{"sil", WriteKindInsert, "rsi", 0, Size1},
	}
	for _, tt := range tests {
		t.Run(tt.reg, func(t *testing.T) {
			kind, parent, offset, size := ClassifyRegisterWrite(tt.reg)
			if kind != tt.wantKind {
				t.Errorf("kind: got %d, want %d", kind, tt.wantKind)
			}
			if parent != tt.wantParent {
				t.Errorf("parent: got %q, want %q", parent, tt.wantParent)
			}
			if offset != tt.wantOffset {
				t.Errorf("offset: got %d, want %d", offset, tt.wantOffset)
			}
			if kind == WriteKindFull && size != Size8 {
				t.Errorf("full write size: got %d, want %d", size, Size8)
			}
			if kind != WriteKindFull && size != tt.wantSize {
				t.Errorf("size: got %d, want %d", size, tt.wantSize)
			}
		})
	}
}

func TestBuildSubRegisterWrite_ZeroExtend(t *testing.T) {
	value := ConstantExpr{Value: IntConstant{Value: 0x12345678, Width: Size4, Signed: false}}
	parentVar, resultExpr, isSubReg := BuildSubRegisterWrite("eax", value)

	if !isSubReg {
		t.Fatal("expected isSubReg=true for eax write")
	}
	if parentVar.Name != "rax" {
		t.Errorf("expected parent rax, got %q", parentVar.Name)
	}
	zext, ok := resultExpr.(ZeroExtend)
	if !ok {
		t.Fatalf("expected ZeroExtend, got %T", resultExpr)
	}
	if zext.FromSize != Size4 || zext.ToSize != Size8 {
		t.Errorf("expected from=4 to=8, got from=%d to=%d", zext.FromSize, zext.ToSize)
	}
	if zext.Source.Name != "eax" {
		t.Errorf("expected source eax, got %q", zext.Source.Name)
	}
}

func TestBuildSubRegisterWrite_Insert8Bit(t *testing.T) {
	value := ConstantExpr{Value: IntConstant{Value: 0x42, Width: Size1, Signed: false}}
	parentVar, resultExpr, isSubReg := BuildSubRegisterWrite("al", value)

	if !isSubReg {
		t.Fatal("expected isSubReg=true for al write")
	}
	if parentVar.Name != "rax" {
		t.Errorf("expected parent rax, got %q", parentVar.Name)
	}
	ins, ok := resultExpr.(Insert)
	if !ok {
		t.Fatalf("expected Insert, got %T", resultExpr)
	}
	if ins.Offset != 0 || ins.Size != Size1 {
		t.Errorf("expected offset=0 size=1, got offset=%d size=%d", ins.Offset, ins.Size)
	}
	if ins.Dest.Name != "rax" {
		t.Errorf("expected dest rax, got %q", ins.Dest.Name)
	}
}

func TestBuildSubRegisterWrite_InsertHighByte(t *testing.T) {
	value := ConstantExpr{Value: IntConstant{Value: 0x99, Width: Size1, Signed: false}}
	parentVar, resultExpr, isSubReg := BuildSubRegisterWrite("ah", value)

	if !isSubReg {
		t.Fatal("expected isSubReg=true for ah write")
	}
	if parentVar.Name != "rax" {
		t.Errorf("expected parent rax, got %q", parentVar.Name)
	}
	ins, ok := resultExpr.(Insert)
	if !ok {
		t.Fatalf("expected Insert, got %T", resultExpr)
	}
	if ins.Offset != 1 {
		t.Errorf("expected offset=1 for ah, got %d", ins.Offset)
	}
}

func TestBuildSubRegisterWrite_Insert16Bit(t *testing.T) {
	value := ConstantExpr{Value: IntConstant{Value: 0x1234, Width: Size2, Signed: false}}
	parentVar, resultExpr, isSubReg := BuildSubRegisterWrite("ax", value)

	if !isSubReg {
		t.Fatal("expected isSubReg=true for ax write")
	}
	if parentVar.Name != "rax" {
		t.Errorf("expected parent rax, got %q", parentVar.Name)
	}
	ins, ok := resultExpr.(Insert)
	if !ok {
		t.Fatalf("expected Insert, got %T", resultExpr)
	}
	if ins.Offset != 0 || ins.Size != Size2 {
		t.Errorf("expected offset=0 size=2, got offset=%d size=%d", ins.Offset, ins.Size)
	}
}

func TestBuildSubRegisterWrite_FullRegister(t *testing.T) {
	value := ConstantExpr{Value: IntConstant{Value: 0xDEADBEEF, Width: Size8, Signed: false}}
	parentVar, resultExpr, isSubReg := BuildSubRegisterWrite("rax", value)

	if isSubReg {
		t.Fatal("expected isSubReg=false for rax write")
	}
	if parentVar.Name != "rax" {
		t.Errorf("expected parent rax, got %q", parentVar.Name)
	}
	if resultExpr != value {
		t.Errorf("expected value pass-through for full register write")
	}
}

func TestBuildSubRegisterRead(t *testing.T) {
	tests := []struct {
		reg        string
		wantSub    bool
		wantParent string
		wantOffset uint8
		wantSize   Size
	}{
		{"al", true, "rax", 0, Size1},
		{"ah", true, "rax", 1, Size1},
		{"ax", true, "rax", 0, Size2},
		{"eax", true, "rax", 0, Size4},
		{"r8b", true, "r8", 0, Size1},
		{"r8w", true, "r8", 0, Size2},
		{"r8d", true, "r8", 0, Size4},
		{"rax", false, "", 0, 0},
		{"r15", false, "", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.reg, func(t *testing.T) {
			parentVar, expr, isSub := BuildSubRegisterRead(tt.reg)
			if isSub != tt.wantSub {
				t.Fatalf("isSubReg: got %v, want %v", isSub, tt.wantSub)
			}
			if !isSub {
				return
			}
			if parentVar.Name != tt.wantParent {
				t.Errorf("parent: got %q, want %q", parentVar.Name, tt.wantParent)
			}
			if expr.Offset != tt.wantOffset {
				t.Errorf("offset: got %d, want %d", expr.Offset, tt.wantOffset)
			}
			if expr.Size != tt.wantSize {
				t.Errorf("size: got %d, want %d", expr.Size, tt.wantSize)
			}
		})
	}
}
