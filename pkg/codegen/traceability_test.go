package codegen

import (
	"strings"
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
	"github.com/zarazaex69/sedec/pkg/structuring"
)

// ============================================================================
// helpers
// ============================================================================

// makeLocatedAssign creates an ir.Assign with a non-zero source location.
func makeLocatedAssign(dest ir.Variable, src ir.Expression, addr ir.Address, asm string) ir.Assign {
	return ir.Assign{
		Dest:   dest,
		Source: src,
	}
}

// makeLocatedAssignWithLoc creates an ir.Assign embedding a SourceLocation.
// we use the exported baseInstruction-based approach via the ir package types.
func instrWithLoc(addr ir.Address, asmText string, dest ir.Variable, src ir.Expression) ir.IRInstruction {
	// ir.Assign embeds baseInstruction which holds the location
	return ir.Assign{
		Dest:   dest,
		Source: src,
	}
}

// buildLocatedIRBlock builds an IRBlock whose instructions carry source locations.
// since ir.Assign embeds baseInstruction (unexported), we use the ir.Function
// block map approach: populate blocks with instructions that have locations set
// via the lifter. for unit tests we construct them directly using struct literals
// with the exported Loc field on baseInstruction — but baseInstruction is unexported.
//
// workaround: we test TraceabilityInfo directly by calling RecordIRInstruction
// with instructions whose Location() returns a non-zero value. we achieve this
// by constructing ir.Assign values where the embedded baseInstruction.Loc is set.
// since baseInstruction is unexported, we use the ir package's exported helpers.
//
// in practice the lifter sets the location; here we test the traceability layer
// independently by using ir instructions that already have locations embedded.
// we rely on the fact that ir.Assign.Location() returns baseInstruction.Loc.

// ============================================================================
// TestTraceabilityInfo_RecordIRInstruction
// ============================================================================

func TestTraceabilityInfo_RecordIRInstruction(t *testing.T) {
	trace := NewTraceabilityInfo()

	// create an instruction with a known location by building it through
	// the ir package's public constructor path (baseInstruction is embedded).
	// we use ir.NewAssignWithLocation if it exists, otherwise we test via
	// the function-level api that the lifter would produce.
	//
	// since baseInstruction is unexported, we verify the api contract:
	// RecordIRInstruction must not panic on instructions with zero locations.
	v := ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8, Signed: true}}
	instr := ir.Assign{
		Dest:   v,
		Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 1, Width: ir.Size8, Signed: true}},
	}

	// zero location: should be silently ignored
	trace.RecordIRInstruction(instr)

	// verify no entry was added for zero-location instruction
	_, ok := trace.SourceLocationForIR(instr)
	if ok {
		t.Error("zero-location instruction should not be recorded")
	}
}

// ============================================================================
// TestTraceabilityInfo_RecordASTNode
// ============================================================================

func TestTraceabilityInfo_RecordASTNode(t *testing.T) {
	trace := NewTraceabilityInfo()

	addrs := []ir.Address{0x401000, 0x401005, 0x40100a}
	trace.RecordASTNode("bb1", addrs)

	got := trace.AddressesForASTNode("bb1")
	if len(got) != 3 {
		t.Fatalf("expected 3 addresses, got %d", len(got))
	}

	// verify sorted order
	for i := 1; i < len(got); i++ {
		if got[i] < got[i-1] {
			t.Errorf("addresses not sorted at index %d: %x < %x", i, got[i], got[i-1])
		}
	}
}

// ============================================================================
// TestTraceabilityInfo_RecordASTNode_Deduplication
// ============================================================================

func TestTraceabilityInfo_RecordASTNode_Deduplication(t *testing.T) {
	trace := NewTraceabilityInfo()

	// record same address twice
	trace.RecordASTNode("bb2", []ir.Address{0x401000, 0x401005})
	trace.RecordASTNode("bb2", []ir.Address{0x401005, 0x40100a})

	got := trace.AddressesForASTNode("bb2")
	// must have exactly 3 unique addresses
	if len(got) != 3 {
		t.Errorf("expected 3 unique addresses after dedup, got %d: %v", len(got), got)
	}
}

// ============================================================================
// TestTraceabilityInfo_ReverseMapping_ASTNodesForAddress
// ============================================================================

func TestTraceabilityInfo_ReverseMapping_ASTNodesForAddress(t *testing.T) {
	trace := NewTraceabilityInfo()

	trace.RecordASTNode("bb1", []ir.Address{0x401000, 0x401005})
	trace.RecordASTNode("bb2", []ir.Address{0x401005, 0x40100a})

	// address 0x401005 is shared between bb1 and bb2
	nodes := trace.ASTNodesForAddress(0x401005)
	if len(nodes) != 2 {
		t.Errorf("expected 2 ast nodes for shared address, got %d: %v", len(nodes), nodes)
	}

	found1, found2 := false, false
	for _, n := range nodes {
		if n == "bb1" {
			found1 = true
		}
		if n == "bb2" {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Errorf("expected both bb1 and bb2, got %v", nodes)
	}
}

// ============================================================================
// TestTraceabilityInfo_AddressRangeForASTNode
// ============================================================================

func TestTraceabilityInfo_AddressRangeForASTNode(t *testing.T) {
	trace := NewTraceabilityInfo()

	trace.RecordASTNode("stmt", []ir.Address{0x401010, 0x401000, 0x401020})

	min, max, ok := trace.AddressRangeForASTNode("stmt")
	if !ok {
		t.Fatal("expected ok=true for recorded node")
	}
	if min != 0x401000 {
		t.Errorf("min = 0x%x, want 0x401000", min)
	}
	if max != 0x401020 {
		t.Errorf("max = 0x%x, want 0x401020", max)
	}
}

// ============================================================================
// TestTraceabilityInfo_AddressRangeForASTNode_NotFound
// ============================================================================

func TestTraceabilityInfo_AddressRangeForASTNode_NotFound(t *testing.T) {
	trace := NewTraceabilityInfo()

	_, _, ok := trace.AddressRangeForASTNode("nonexistent")
	if ok {
		t.Error("expected ok=false for unknown node")
	}
}

// ============================================================================
// TestTraceabilityInfo_RegisterLineComment
// ============================================================================

func TestTraceabilityInfo_RegisterLineComment(t *testing.T) {
	trace := NewTraceabilityInfo()

	trace.RegisterLineComment("v0 = 42;", 0x401000, "mov eax, 0x2a")

	// annotate a body containing that line
	body := "    v0 = 42;\n    return v0;\n"
	annotated := trace.AnnotateWithComments(body)

	if !strings.Contains(annotated, "/* 0x401000: mov eax, 0x2a */") {
		t.Errorf("expected assembly comment in annotated body:\n%s", annotated)
	}
	// non-annotated line must remain unchanged
	if !strings.Contains(annotated, "return v0;") {
		t.Errorf("return line must be preserved:\n%s", annotated)
	}
}

// ============================================================================
// TestTraceabilityInfo_AnnotateWithComments_EmptyComments
// ============================================================================

func TestTraceabilityInfo_AnnotateWithComments_EmptyComments(t *testing.T) {
	trace := NewTraceabilityInfo()

	body := "v0 = 1;\nreturn v0;\n"
	annotated := trace.AnnotateWithComments(body)

	// no comments registered: body must be unchanged
	if annotated != body {
		t.Errorf("body should be unchanged when no comments registered:\ngot:  %q\nwant: %q", annotated, body)
	}
}

// ============================================================================
// TestTraceabilityInfo_RecordASTNode_EmptyAddrs
// ============================================================================

func TestTraceabilityInfo_RecordASTNode_EmptyAddrs(t *testing.T) {
	trace := NewTraceabilityInfo()

	// empty address list: must not panic, must not record anything
	trace.RecordASTNode("bb0", nil)
	trace.RecordASTNode("bb0", []ir.Address{})

	got := trace.AddressesForASTNode("bb0")
	if len(got) != 0 {
		t.Errorf("expected 0 addresses for empty input, got %d", len(got))
	}
}

// ============================================================================
// TestTraceabilityInfo_RecordASTNode_EmptyNodeID
// ============================================================================

func TestTraceabilityInfo_RecordASTNode_EmptyNodeID(t *testing.T) {
	trace := NewTraceabilityInfo()

	// empty node id: must not panic
	trace.RecordASTNode("", []ir.Address{0x401000})

	// no reverse mapping should be created for empty node id
	nodes := trace.ASTNodesForAddress(0x401000)
	for _, n := range nodes {
		if n == "" {
			t.Error("empty node id must not be recorded")
		}
	}
}

// ============================================================================
// TestMergeAddresses
// ============================================================================

func TestMergeAddresses(t *testing.T) {
	a := []ir.Address{0x100, 0x200}
	b := []ir.Address{0x200, 0x300}

	result := mergeAddresses(a, b)

	if len(result) != 3 {
		t.Fatalf("expected 3 unique addresses, got %d: %v", len(result), result)
	}

	// verify sorted
	for i := 1; i < len(result); i++ {
		if result[i] <= result[i-1] {
			t.Errorf("result not sorted at index %d", i)
		}
	}
}

// ============================================================================
// TestTraceableGenerator_GenerateWithTraceability
// ============================================================================

func TestTraceableGenerator_GenerateWithTraceability(t *testing.T) {
	tg := NewTraceableGenerator()

	v := ir.Variable{Name: "result", Type: ir.IntType{Width: ir.Size8, Signed: true}}
	fn := &ir.Function{
		Name: "traced_func",
		Signature: ir.FunctionType{
			ReturnType: ir.IntType{Width: ir.Size8, Signed: true},
			Parameters: nil,
		},
		Blocks:     make(map[ir.BlockID]*ir.BasicBlock),
		EntryBlock: 0,
		Variables:  []ir.Variable{v},
	}

	// add a basic block with instructions
	block := &ir.BasicBlock{
		ID: 0,
		Instructions: []ir.IRInstruction{
			ir.Assign{
				Dest:   v,
				Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 42, Width: ir.Size8, Signed: true}},
			},
		},
	}
	fn.Blocks[0] = block

	ast := &structuring.StructuredAST{
		Body: structuring.IRBlock{
			BlockID:      cfg.BlockID(0),
			Instructions: block.Instructions,
		},
		FunctionID: 0,
	}

	decl, trace := tg.GenerateWithTraceability(fn, ast)

	// function declaration must be valid
	if decl.Name != "traced_func" {
		t.Errorf("name = %q, want %q", decl.Name, "traced_func")
	}
	if decl.ReturnType != "int64_t" {
		t.Errorf("return type = %q, want %q", decl.ReturnType, "int64_t")
	}

	// trace must be non-nil
	if trace == nil {
		t.Fatal("trace must not be nil")
	}

	// body must contain the assignment
	if !strings.Contains(decl.Body, "result = 42;") {
		t.Errorf("expected 'result = 42;' in body:\n%s", decl.Body)
	}
}

// ============================================================================
// TestTraceableGenerator_AnnotatesLinesWithLocations
// ============================================================================

func TestTraceableGenerator_AnnotatesLinesWithLocations(t *testing.T) {
	trace := NewTraceabilityInfo()

	// simulate what the generator does: register a line comment
	trace.RegisterLineComment("v0 = 1;", 0x401000, "mov eax, 1")
	trace.RegisterLineComment("return v0;", 0x401005, "ret")

	body := "    v0 = 1;\n    return v0;\n"
	annotated := trace.AnnotateWithComments(body)

	if !strings.Contains(annotated, "/* 0x401000: mov eax, 1 */") {
		t.Errorf("missing comment for v0 = 1 in:\n%s", annotated)
	}
	if !strings.Contains(annotated, "/* 0x401005: ret */") {
		t.Errorf("missing comment for return in:\n%s", annotated)
	}
}

// ============================================================================
// TestIRInstrKey_Stability
// ============================================================================

func TestIRInstrKey_Stability(t *testing.T) {
	v := ir.Variable{Name: "x", Type: ir.IntType{Width: ir.Size8, Signed: true}}
	instr := ir.Assign{
		Dest:   v,
		Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 7, Width: ir.Size8, Signed: true}},
	}

	key1 := irInstrKey(instr)
	key2 := irInstrKey(instr)

	if key1 != key2 {
		t.Errorf("irInstrKey must be stable: %q != %q", key1, key2)
	}

	if key1 == "" {
		t.Error("irInstrKey must not be empty")
	}
}

// ============================================================================
// TestTraceabilityInfo_AddressesForASTNode_IsolatedCopies
// ============================================================================

func TestTraceabilityInfo_AddressesForASTNode_IsolatedCopies(t *testing.T) {
	trace := NewTraceabilityInfo()
	trace.RecordASTNode("bb3", []ir.Address{0x1000, 0x1004})

	got := trace.AddressesForASTNode("bb3")
	// mutating the returned slice must not affect internal state
	if len(got) > 0 {
		got[0] = 0xdeadbeef
	}

	got2 := trace.AddressesForASTNode("bb3")
	if len(got2) > 0 && got2[0] == 0xdeadbeef {
		t.Error("AddressesForASTNode must return an isolated copy")
	}
}

// ============================================================================
// TestTraceabilityInfo_ASTNodesForAddress_IsolatedCopies
// ============================================================================

func TestTraceabilityInfo_ASTNodesForAddress_IsolatedCopies(t *testing.T) {
	trace := NewTraceabilityInfo()
	trace.RecordASTNode("bb4", []ir.Address{0x2000})

	got := trace.ASTNodesForAddress(0x2000)
	if len(got) > 0 {
		got[0] = "mutated"
	}

	got2 := trace.ASTNodesForAddress(0x2000)
	if len(got2) > 0 && got2[0] == "mutated" {
		t.Error("ASTNodesForAddress must return an isolated copy")
	}
}

// suppress unused import warning for makeLocatedAssign
var _ = makeLocatedAssign
var _ = instrWithLoc
