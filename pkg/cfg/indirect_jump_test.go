package cfg

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestIndirectJump_RegisterOperand tests indirect jump through register (jmp rax)
func TestIndirectJump_RegisterOperand(t *testing.T) {
	instructions := []*disasm.Instruction{
		{
			Address:  0x1000,
			Bytes:    []byte{0x48, 0x89, 0xc0}, // mov rax, rax
			Mnemonic: "mov",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			},
			Length: 3,
		},
		{
			Address:  0x1003,
			Bytes:    []byte{0xff, 0xe0}, // jmp rax
			Mnemonic: "jmp",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			},
			Length: 2,
		},
		{
			Address:  0x1005,
			Bytes:    []byte{0xc3}, // ret
			Mnemonic: "ret",
			Operands: []disasm.Operand{},
			Length:   1,
		},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify unresolved indirect jump was registered
	if cfg.UnresolvedIndirectJumpCount() != 1 {
		t.Errorf("expected 1 unresolved indirect jump, got %d", cfg.UnresolvedIndirectJumpCount())
	}

	// verify jump site address
	jump, found := cfg.GetUnresolvedIndirectJump(0x1003)
	if !found {
		t.Fatal("indirect jump at 0x1003 not found in unresolved list")
	}

	if jump.JumpSite != 0x1003 {
		t.Errorf("expected jump site 0x1003, got 0x%x", jump.JumpSite)
	}

	if jump.Instruction.Mnemonic != "jmp" {
		t.Errorf("expected mnemonic 'jmp', got '%s'", jump.Instruction.Mnemonic)
	}

	if jump.JumpKind != IndirectJumpUnknown {
		t.Errorf("expected jump kind Unknown, got %s", jump.JumpKind)
	}

	if len(jump.PossibleTargets) != 0 {
		t.Errorf("expected 0 possible targets initially, got %d", len(jump.PossibleTargets))
	}
}

// TestIndirectJump_MemoryOperand tests indirect jump through memory (jmp [rax+8])
func TestIndirectJump_MemoryOperand(t *testing.T) {
	instructions := []*disasm.Instruction{
		{
			Address:  0x2000,
			Bytes:    []byte{0x48, 0x8b, 0x40, 0x08}, // mov rax, [rax+8]
			Mnemonic: "mov",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
				disasm.MemoryOperand{
					Base: "rax",
					Disp: 8,
					Size: disasm.Size64,
				},
			},
			Length: 4,
		},
		{
			Address:  0x2004,
			Bytes:    []byte{0xff, 0x60, 0x10}, // jmp [rax+0x10]
			Mnemonic: "jmp",
			Operands: []disasm.Operand{
				disasm.MemoryOperand{
					Base: "rax",
					Disp: 0x10,
					Size: disasm.Size64,
				},
			},
			Length: 3,
		},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify unresolved indirect jump was registered
	if cfg.UnresolvedIndirectJumpCount() != 1 {
		t.Errorf("expected 1 unresolved indirect jump, got %d", cfg.UnresolvedIndirectJumpCount())
	}

	jump, found := cfg.GetUnresolvedIndirectJump(0x2004)
	if !found {
		t.Fatal("indirect jump at 0x2004 not found")
	}

	if jump.JumpSite != 0x2004 {
		t.Errorf("expected jump site 0x2004, got 0x%x", jump.JumpSite)
	}
}

// TestAddIndirectTarget tests adding resolved target to indirect jump
func TestAddIndirectTarget(t *testing.T) {
	instructions := []*disasm.Instruction{
		{
			Address:  0x3000,
			Bytes:    []byte{0xff, 0xe0}, // jmp rax
			Mnemonic: "jmp",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			},
			Length: 2,
		},
		{
			Address:  0x3002,
			Bytes:    []byte{0x90}, // nop (target 1)
			Mnemonic: "nop",
			Operands: []disasm.Operand{},
			Length:   1,
		},
		{
			Address:  0x3003,
			Bytes:    []byte{0x90}, // nop (target 2)
			Mnemonic: "nop",
			Operands: []disasm.Operand{},
			Length:   1,
		},
		{
			Address:  0x3004,
			Bytes:    []byte{0xc3}, // ret
			Mnemonic: "ret",
			Operands: []disasm.Operand{},
			Length:   1,
		},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify initial state
	if cfg.UnresolvedIndirectJumpCount() != 1 {
		t.Fatalf("expected 1 unresolved indirect jump, got %d", cfg.UnresolvedIndirectJumpCount())
	}

	initialEdgeCount := cfg.EdgeCount()

	// add first target
	err = builder.AddIndirectTarget(0x3000, 0x3002)
	if err != nil {
		t.Fatalf("failed to add indirect target: %v", err)
	}

	// verify edge was added
	if cfg.EdgeCount() != initialEdgeCount+1 {
		t.Errorf("expected %d edges after adding target, got %d", initialEdgeCount+1, cfg.EdgeCount())
	}

	// verify target was recorded
	jump, found := cfg.GetUnresolvedIndirectJump(0x3000)
	if !found {
		t.Fatal("indirect jump disappeared after adding target")
	}

	if len(jump.PossibleTargets) != 1 {
		t.Errorf("expected 1 possible target, got %d", len(jump.PossibleTargets))
	}

	if jump.PossibleTargets[0] != 0x3002 {
		t.Errorf("expected target 0x3002, got 0x%x", jump.PossibleTargets[0])
	}

	// add second target
	err = builder.AddIndirectTarget(0x3000, 0x3003)
	if err != nil {
		t.Fatalf("failed to add second indirect target: %v", err)
	}

	// verify both targets recorded
	jump, _ = cfg.GetUnresolvedIndirectJump(0x3000)
	if len(jump.PossibleTargets) != 2 {
		t.Errorf("expected 2 possible targets, got %d", len(jump.PossibleTargets))
	}
}

// TestAddIndirectTargets tests adding multiple targets at once (switch table)
func TestAddIndirectTargets(t *testing.T) {
	instructions := []*disasm.Instruction{
		{
			Address:  0x4000,
			Bytes:    []byte{0xff, 0x24, 0xc5}, // jmp [rax*8+table]
			Mnemonic: "jmp",
			Operands: []disasm.Operand{
				disasm.MemoryOperand{
					Base:  "rax",
					Scale: 8,
					Size:  disasm.Size64,
				},
			},
			Length: 3,
		},
		{Address: 0x4003, Mnemonic: "nop", Length: 1, Operands: []disasm.Operand{}}, // case 0
		{Address: 0x4004, Mnemonic: "nop", Length: 1, Operands: []disasm.Operand{}}, // case 1
		{Address: 0x4005, Mnemonic: "nop", Length: 1, Operands: []disasm.Operand{}}, // case 2
		{Address: 0x4006, Mnemonic: "ret", Length: 1, Operands: []disasm.Operand{}},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// add multiple targets (switch table)
	targets := []disasm.Address{0x4003, 0x4004, 0x4005}
	provenance := &EdgeProvenance{
		AnalysisPass: "vsa",
		Confidence:   0.95,
		Metadata: map[string]any{
			"switch_table": true,
			"case_count":   3,
		},
	}

	err = builder.AddIndirectTargets(0x4000, targets, provenance)
	if err != nil {
		t.Fatalf("failed to add indirect targets: %v", err)
	}

	// verify all targets recorded
	jump, found := cfg.GetUnresolvedIndirectJump(0x4000)
	if !found {
		t.Fatal("indirect jump not found after adding targets")
	}

	if len(jump.PossibleTargets) != 3 {
		t.Errorf("expected 3 possible targets, got %d", len(jump.PossibleTargets))
	}

	// verify edges created with correct provenance
	edgeCount := 0
	for _, edge := range cfg.Edges {
		if edge.Type == EdgeTypeIndirect && edge.Provenance != nil {
			if edge.Provenance.AnalysisPass != "vsa" {
				t.Errorf("expected provenance analysis pass 'vsa', got '%s'", edge.Provenance.AnalysisPass)
			}
			if edge.Provenance.Confidence != 0.95 {
				t.Errorf("expected confidence 0.95, got %f", edge.Provenance.Confidence)
			}
			edgeCount++
		}
	}

	if edgeCount != 3 {
		t.Errorf("expected 3 indirect edges with provenance, got %d", edgeCount)
	}
}

// TestClassifyIndirectJump tests jump kind classification
func TestClassifyIndirectJump(t *testing.T) {
	instructions := []*disasm.Instruction{
		{
			Address:  0x5000,
			Bytes:    []byte{0xff, 0x50, 0x08}, // call [rax+8] (vtable call)
			Mnemonic: "call",
			Operands: []disasm.Operand{
				disasm.MemoryOperand{
					Base: "rax",
					Disp: 8,
					Size: disasm.Size64,
				},
			},
			Length: 3,
		},
		{
			Address:  0x5003,
			Bytes:    []byte{0xff, 0xe1}, // jmp rcx (handler table)
			Mnemonic: "jmp",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rcx", Size: disasm.Size64},
			},
			Length: 2,
		},
	}

	builder := NewCFGBuilder()
	_, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// classify second jump as handler table
	err = builder.ClassifyIndirectJump(0x5003, IndirectJumpHandlerTable)
	if err != nil {
		t.Fatalf("failed to classify indirect jump: %v", err)
	}

	// verify classification
	jump, found := builder.cfg.GetUnresolvedIndirectJump(0x5003)
	if !found {
		t.Fatal("indirect jump not found after classification")
	}

	if jump.JumpKind != IndirectJumpHandlerTable {
		t.Errorf("expected jump kind HandlerTable, got %s", jump.JumpKind)
	}
}

// TestMarkIndirectJumpResolved tests removing resolved jump from unresolved list
func TestMarkIndirectJumpResolved(t *testing.T) {
	instructions := []*disasm.Instruction{
		{
			Address:  0x6000,
			Bytes:    []byte{0xff, 0xe0}, // jmp rax
			Mnemonic: "jmp",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			},
			Length: 2,
		},
		{
			Address:  0x6002,
			Bytes:    []byte{0x90}, // nop (target)
			Mnemonic: "nop",
			Operands: []disasm.Operand{},
			Length:   1,
		},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	initialCount := cfg.UnresolvedIndirectJumpCount()
	if initialCount != 1 {
		t.Fatalf("expected 1 unresolved jump initially, got %d", initialCount)
	}

	// add target
	err = builder.AddIndirectTarget(0x6000, 0x6002)
	if err != nil {
		t.Fatalf("failed to add target: %v", err)
	}

	// mark as fully resolved
	removed := builder.MarkIndirectJumpResolved(0x6000)
	if !removed {
		t.Error("expected MarkIndirectJumpResolved to return true")
	}

	// verify removed from unresolved list
	if cfg.UnresolvedIndirectJumpCount() != 0 {
		t.Errorf("expected 0 unresolved jumps after marking resolved, got %d", cfg.UnresolvedIndirectJumpCount())
	}

	// verify cannot find anymore
	_, found := cfg.GetUnresolvedIndirectJump(0x6000)
	if found {
		t.Error("indirect jump should not be found after marking resolved")
	}
}

// TestIndirectJumpKind_String tests string representation of jump kinds
func TestIndirectJumpKind_String(t *testing.T) {
	tests := []struct {
		kind     IndirectJumpKind
		expected string
	}{
		{IndirectJumpUnknown, "Unknown"},
		{IndirectJumpVTable, "VTable"},
		{IndirectJumpHandlerTable, "HandlerTable"},
		{IndirectJumpInterfaceTable, "InterfaceTable"},
		{IndirectJumpFunctionPointer, "FunctionPointer"},
		{IndirectJumpComputedGoto, "ComputedGoto"},
	}

	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.expected {
			t.Errorf("IndirectJumpKind(%d).String() = %s, want %s", tt.kind, got, tt.expected)
		}
	}
}

// TestEdgeProvenance tests edge provenance tracking
func TestEdgeProvenance(t *testing.T) {
	instructions := []*disasm.Instruction{
		{
			Address:  0x7000,
			Bytes:    []byte{0xff, 0xe0}, // jmp rax
			Mnemonic: "jmp",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			},
			Length: 2,
		},
		{
			Address:  0x7002,
			Bytes:    []byte{0x90}, // nop
			Mnemonic: "nop",
			Operands: []disasm.Operand{},
			Length:   1,
		},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// add target with custom provenance
	provenance := &EdgeProvenance{
		AnalysisPass: "custom_analysis",
		Confidence:   0.75,
		Metadata: map[string]any{
			"method":     "pattern_matching",
			"iterations": 5,
		},
	}

	err = builder.AddIndirectTargetWithProvenance(0x7000, 0x7002, provenance)
	if err != nil {
		t.Fatalf("failed to add target with provenance: %v", err)
	}

	// find the indirect edge
	var indirectEdge *Edge
	for _, edge := range cfg.Edges {
		if edge.Type == EdgeTypeIndirect {
			indirectEdge = edge
			break
		}
	}

	if indirectEdge == nil {
		t.Fatal("indirect edge not found")
	}

	if indirectEdge.Provenance == nil {
		t.Fatal("edge provenance is nil")
	}

	if indirectEdge.Provenance.AnalysisPass != "custom_analysis" {
		t.Errorf("expected analysis pass 'custom_analysis', got '%s'", indirectEdge.Provenance.AnalysisPass)
	}

	if indirectEdge.Provenance.Confidence != 0.75 {
		t.Errorf("expected confidence 0.75, got %f", indirectEdge.Provenance.Confidence)
	}

	method, ok := indirectEdge.Provenance.Metadata["method"].(string)
	if !ok || method != "pattern_matching" {
		t.Errorf("expected metadata method 'pattern_matching', got '%v'", method)
	}
}

// TestMultipleIndirectJumps tests handling multiple indirect jumps in same function
func TestMultipleIndirectJumps(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x8000, Mnemonic: "jmp", Operands: []disasm.Operand{disasm.RegisterOperand{Name: "rax", Size: disasm.Size64}}, Length: 2},
		{Address: 0x8002, Mnemonic: "nop", Length: 1, Operands: []disasm.Operand{}},
		{Address: 0x8003, Mnemonic: "jmp", Operands: []disasm.Operand{disasm.RegisterOperand{Name: "rbx", Size: disasm.Size64}}, Length: 2},
		{Address: 0x8005, Mnemonic: "nop", Length: 1, Operands: []disasm.Operand{}},
		{Address: 0x8006, Mnemonic: "jmp", Operands: []disasm.Operand{disasm.RegisterOperand{Name: "rcx", Size: disasm.Size64}}, Length: 2},
		{Address: 0x8008, Mnemonic: "ret", Length: 1, Operands: []disasm.Operand{}},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// verify all three indirect jumps registered
	if cfg.UnresolvedIndirectJumpCount() != 3 {
		t.Errorf("expected 3 unresolved indirect jumps, got %d", cfg.UnresolvedIndirectJumpCount())
	}

	// verify each jump is tracked
	addresses := []disasm.Address{0x8000, 0x8003, 0x8006}
	for _, addr := range addresses {
		_, found := cfg.GetUnresolvedIndirectJump(addr)
		if !found {
			t.Errorf("indirect jump at 0x%x not found", addr)
		}
	}

	// resolve middle jump
	err = builder.AddIndirectTarget(0x8003, 0x8005)
	if err != nil {
		t.Fatalf("failed to add target: %v", err)
	}

	builder.MarkIndirectJumpResolved(0x8003)

	// verify count decreased
	if cfg.UnresolvedIndirectJumpCount() != 2 {
		t.Errorf("expected 2 unresolved jumps after resolving one, got %d", cfg.UnresolvedIndirectJumpCount())
	}

	// verify correct jump was removed
	_, found := cfg.GetUnresolvedIndirectJump(0x8003)
	if found {
		t.Error("resolved jump should not be in unresolved list")
	}

	// verify others still present
	for _, addr := range []disasm.Address{0x8000, 0x8006} {
		_, found := cfg.GetUnresolvedIndirectJump(addr)
		if !found {
			t.Errorf("unresolved jump at 0x%x should still be present", addr)
		}
	}
}
