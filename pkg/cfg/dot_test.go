package cfg

import (
	"bytes"
	"strings"
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

func TestExportToDOT_EmptyCFG(t *testing.T) {
	cfg := NewCFG()
	var buf bytes.Buffer

	err := cfg.ExportToDOT(&buf, nil)
	if err != nil {
		t.Fatalf("ExportToDOT failed: %v", err)
	}

	output := buf.String()

	// verify dot structure
	if !strings.Contains(output, "digraph CFG {") {
		t.Error("missing digraph header")
	}
	if !strings.Contains(output, "}") {
		t.Error("missing closing brace")
	}
}

func TestExportToDOT_LinearCode(t *testing.T) {
	// create simple linear cfg: block0 -> block1 -> block2
	cfg := NewCFG()

	block0 := &BasicBlock{
		ID:           0,
		StartAddress: 0x1000,
		EndAddress:   0x1010,
		Instructions: []*disasm.Instruction{
			{Address: 0x1000, Mnemonic: "mov", Operands: []disasm.Operand{
				&disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				&disasm.ImmediateOperand{Value: 42, Size: disasm.Size32},
			}},
			{Address: 0x1007, Mnemonic: "add", Operands: []disasm.Operand{
				&disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				&disasm.ImmediateOperand{Value: 10, Size: disasm.Size32},
			}},
		},
	}

	block1 := &BasicBlock{
		ID:           1,
		StartAddress: 0x1010,
		EndAddress:   0x1020,
		Instructions: []*disasm.Instruction{
			{Address: 0x1010, Mnemonic: "sub", Operands: []disasm.Operand{
				&disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				&disasm.ImmediateOperand{Value: 5, Size: disasm.Size32},
			}},
		},
	}

	block2 := &BasicBlock{
		ID:           2,
		StartAddress: 0x1020,
		EndAddress:   0x1025,
		Instructions: []*disasm.Instruction{
			{Address: 0x1020, Mnemonic: "ret", Operands: []disasm.Operand{}},
		},
	}

	cfg.AddBlock(block0)
	cfg.AddBlock(block1)
	cfg.AddBlock(block2)

	cfg.Entry = 0
	cfg.Exits = []BlockID{2}

	cfg.AddEdge(0, 1, EdgeTypeFallthrough)
	cfg.AddEdge(1, 2, EdgeTypeFallthrough)

	var buf bytes.Buffer
	opts := DefaultDotExportOptions()
	opts.MaxInstructionsShow = 0 // show all instructions

	err := cfg.ExportToDOT(&buf, opts)
	if err != nil {
		t.Fatalf("ExportToDOT failed: %v", err)
	}

	output := buf.String()

	// verify blocks are present
	if !strings.Contains(output, "block_0") {
		t.Error("missing block_0")
	}
	if !strings.Contains(output, "block_1") {
		t.Error("missing block_1")
	}
	if !strings.Contains(output, "block_2") {
		t.Error("missing block_2")
	}

	// verify edges
	if !strings.Contains(output, "block_0 -> block_1") {
		t.Error("missing edge 0->1")
	}
	if !strings.Contains(output, "block_1 -> block_2") {
		t.Error("missing edge 1->2")
	}

	// verify entry/exit markers
	if !strings.Contains(output, "(ENTRY)") {
		t.Error("missing ENTRY marker")
	}
	if !strings.Contains(output, "(EXIT)") {
		t.Error("missing EXIT marker")
	}

	// verify instructions
	if !strings.Contains(output, "mov") {
		t.Error("missing mov instruction")
	}
	if !strings.Contains(output, "add") {
		t.Error("missing add instruction")
	}
	if !strings.Contains(output, "ret") {
		t.Error("missing ret instruction")
	}

	// verify addresses
	if !strings.Contains(output, "0x1000") {
		t.Error("missing address 0x1000")
	}

	// verify metadata
	if !strings.Contains(output, "2 instructions") {
		t.Error("missing instruction count for block 0")
	}
}

func TestExportToDOT_ConditionalBranch(t *testing.T) {
	// create cfg with conditional branch: block0 -> block1 (true) or block2 (false)
	cfg := NewCFG()

	block0 := &BasicBlock{
		ID:           0,
		StartAddress: 0x1000,
		EndAddress:   0x1010,
		Instructions: []*disasm.Instruction{
			{Address: 0x1000, Mnemonic: "cmp", Operands: []disasm.Operand{
				&disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				&disasm.ImmediateOperand{Value: 0, Size: disasm.Size32},
			}},
			{Address: 0x1004, Mnemonic: "je", Operands: []disasm.Operand{
				&disasm.ImmediateOperand{Value: 0x1020, Size: disasm.Size32},
			}},
		},
	}

	block1 := &BasicBlock{
		ID:           1,
		StartAddress: 0x1010,
		EndAddress:   0x1020,
		Instructions: []*disasm.Instruction{
			{Address: 0x1010, Mnemonic: "mov", Operands: []disasm.Operand{
				&disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				&disasm.ImmediateOperand{Value: 1, Size: disasm.Size32},
			}},
		},
	}

	block2 := &BasicBlock{
		ID:           2,
		StartAddress: 0x1020,
		EndAddress:   0x1030,
		Instructions: []*disasm.Instruction{
			{Address: 0x1020, Mnemonic: "mov", Operands: []disasm.Operand{
				&disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64},
				&disasm.ImmediateOperand{Value: 2, Size: disasm.Size32},
			}},
		},
	}

	cfg.AddBlock(block0)
	cfg.AddBlock(block1)
	cfg.AddBlock(block2)

	cfg.Entry = 0

	cfg.AddEdge(0, 1, EdgeTypeFallthrough)
	cfg.AddEdge(0, 2, EdgeTypeConditional)

	var buf bytes.Buffer
	err := cfg.ExportToDOT(&buf, nil)
	if err != nil {
		t.Fatalf("ExportToDOT failed: %v", err)
	}

	output := buf.String()

	// verify conditional edge styling
	if !strings.Contains(output, "Conditional") {
		t.Error("missing Conditional edge label")
	}
	if !strings.Contains(output, "color=green") {
		t.Error("missing green color for conditional edge")
	}

	// verify fallthrough edge
	if !strings.Contains(output, "Fallthrough") {
		t.Error("missing Fallthrough edge label")
	}
}

func TestExportToDOT_UnresolvedIndirectJump(t *testing.T) {
	cfg := NewCFG()

	block0 := &BasicBlock{
		ID:           0,
		StartAddress: 0x1000,
		EndAddress:   0x1010,
		Instructions: []*disasm.Instruction{
			{Address: 0x1000, Mnemonic: "jmp", Operands: []disasm.Operand{
				&disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			}},
		},
	}

	cfg.AddBlock(block0)
	cfg.Entry = 0

	// add unresolved indirect jump
	cfg.AddUnresolvedIndirectJump(&UnresolvedIndirectJump{
		BlockID:  0,
		JumpSite: 0x1000,
		JumpKind: IndirectJumpVTable,
		PossibleTargets: []disasm.Address{
			0x2000,
			0x3000,
		},
	})

	var buf bytes.Buffer
	err := cfg.ExportToDOT(&buf, nil)
	if err != nil {
		t.Fatalf("ExportToDOT failed: %v", err)
	}

	output := buf.String()

	// verify unresolved jump node
	if !strings.Contains(output, "unresolved_0") {
		t.Error("missing unresolved jump node")
	}
	if !strings.Contains(output, "VTable") {
		t.Error("missing VTable jump kind")
	}
	if !strings.Contains(output, "shape=diamond") {
		t.Error("missing diamond shape for unresolved jump")
	}
	if !strings.Contains(output, "fillcolor=orange") {
		t.Error("missing orange color for unresolved jump")
	}

	// verify dashed edge to unresolved node
	if !strings.Contains(output, "style=dashed") {
		t.Error("missing dashed edge style")
	}
}

func TestExportToDOT_WithProvenance(t *testing.T) {
	cfg := NewCFG()

	block0 := &BasicBlock{
		ID:           0,
		StartAddress: 0x1000,
		EndAddress:   0x1010,
	}

	block1 := &BasicBlock{
		ID:           1,
		StartAddress: 0x1010,
		EndAddress:   0x1020,
	}

	cfg.AddBlock(block0)
	cfg.AddBlock(block1)

	cfg.Entry = 0

	// add edge with provenance
	provenance := &EdgeProvenance{
		AnalysisPass: "type_inference",
		Confidence:   0.95,
		Metadata:     map[string]any{"vtable_index": 3},
	}
	cfg.AddEdgeWithProvenance(0, 1, EdgeTypeIndirect, provenance)

	var buf bytes.Buffer
	opts := DefaultDotExportOptions()
	opts.ShowProvenance = true

	err := cfg.ExportToDOT(&buf, opts)
	if err != nil {
		t.Fatalf("ExportToDOT failed: %v", err)
	}

	output := buf.String()

	// verify provenance information
	if !strings.Contains(output, "type_inference") {
		t.Error("missing analysis pass in provenance")
	}
	if !strings.Contains(output, "0.95") {
		t.Error("missing confidence in provenance")
	}
}

func TestExportToDOT_MaxInstructionsLimit(t *testing.T) {
	cfg := NewCFG()

	// create block with many instructions
	instructions := make([]*disasm.Instruction, 20)
	for i := 0; i < 20; i++ {
		instructions[i] = &disasm.Instruction{
			Address:  disasm.Address(0x1000 + uint64(i)*4),
			Mnemonic: "nop",
			Operands: []disasm.Operand{},
		}
	}

	block0 := &BasicBlock{
		ID:           0,
		StartAddress: 0x1000,
		EndAddress:   0x1050,
		Instructions: instructions,
	}

	cfg.AddBlock(block0)
	cfg.Entry = 0

	var buf bytes.Buffer
	opts := DefaultDotExportOptions()
	opts.MaxInstructionsShow = 5

	err := cfg.ExportToDOT(&buf, opts)
	if err != nil {
		t.Fatalf("ExportToDOT failed: %v", err)
	}

	output := buf.String()

	// verify truncation message
	if !strings.Contains(output, "... (15 more)") {
		t.Error("missing truncation message")
	}

	// count nop occurrences (should be limited)
	nopCount := strings.Count(output, "nop")
	if nopCount > 5 {
		t.Errorf("expected at most 5 nop instructions, got %d", nopCount)
	}
}

func TestExportToDOT_NoInstructions(t *testing.T) {
	cfg := NewCFG()

	block0 := &BasicBlock{
		ID:           0,
		StartAddress: 0x1000,
		EndAddress:   0x1010,
		Instructions: []*disasm.Instruction{
			{Address: 0x1000, Mnemonic: "mov", Operands: []disasm.Operand{}},
		},
	}

	cfg.AddBlock(block0)
	cfg.Entry = 0

	var buf bytes.Buffer
	opts := DefaultDotExportOptions()
	opts.IncludeInstructions = false

	err := cfg.ExportToDOT(&buf, opts)
	if err != nil {
		t.Fatalf("ExportToDOT failed: %v", err)
	}

	output := buf.String()

	// verify instructions are not included
	if strings.Contains(output, "mov") {
		t.Error("instructions should not be included when IncludeInstructions=false")
	}

	// verify block still exists
	if !strings.Contains(output, "block_0") {
		t.Error("missing block_0")
	}
}

func TestExportToDOT_EdgeTypes(t *testing.T) {
	cfg := NewCFG()

	// create blocks for testing all edge types
	blocks := make([]*BasicBlock, 7)
	for i := 0; i < 7; i++ {
		blocks[i] = &BasicBlock{
			ID:           BlockID(i),
			StartAddress: disasm.Address(0x1000 + uint64(i)*0x10),
			EndAddress:   disasm.Address(0x1010 + uint64(i)*0x10),
		}
		cfg.AddBlock(blocks[i])
	}

	cfg.Entry = 0

	// add edges of different types
	cfg.AddEdge(0, 1, EdgeTypeFallthrough)
	cfg.AddEdge(1, 2, EdgeTypeUnconditional)
	cfg.AddEdge(2, 3, EdgeTypeConditional)
	cfg.AddEdge(3, 4, EdgeTypeCall)
	cfg.AddEdge(4, 5, EdgeTypeReturn)
	cfg.AddEdge(5, 6, EdgeTypeIndirect)

	var buf bytes.Buffer
	err := cfg.ExportToDOT(&buf, nil)
	if err != nil {
		t.Fatalf("ExportToDOT failed: %v", err)
	}

	output := buf.String()

	// verify all edge types are present
	edgeTypes := []string{
		"Fallthrough",
		"Unconditional",
		"Conditional",
		"Call",
		"Return",
		"Indirect",
	}

	for _, edgeType := range edgeTypes {
		if !strings.Contains(output, edgeType) {
			t.Errorf("missing edge type: %s", edgeType)
		}
	}

	// verify different colors are used
	colors := []string{"black", "blue", "green", "purple", "red", "orange"}
	for _, color := range colors {
		if !strings.Contains(output, color) {
			t.Errorf("missing color: %s", color)
		}
	}
}

func TestEscapeForDOT(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`test`, `test`},
		{`test"quote`, `test\"quote`},
		{`test\backslash`, `test\\backslash`},
		{`test<angle>`, `test\<angle\>`},
		{`test\n newline`, `test\\n newline`},
	}

	for _, tt := range tests {
		result := escapeForDOT(tt.input)
		if result != tt.expected {
			t.Errorf("escapeForDOT(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
