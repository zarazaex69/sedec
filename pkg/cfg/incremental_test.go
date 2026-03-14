package cfg

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestIncrementalUpdateQueue tests update queue operations
func TestIncrementalUpdateQueue(t *testing.T) {
	queue := NewIncrementalUpdateQueue()

	if queue.Size() != 0 {
		t.Errorf("expected empty queue, got size %d", queue.Size())
	}

	// enqueue updates
	update1 := &IncrementalUpdate{
		UpdateType: UpdateTypeResolveIndirect,
		JumpSite:   0x1000,
		Targets:    []disasm.Address{0x2000},
	}
	update2 := &IncrementalUpdate{
		UpdateType: UpdateTypeAddEdge,
		JumpSite:   0x3000,
		Targets:    []disasm.Address{0x4000},
	}

	queue.Enqueue(update1)
	queue.Enqueue(update2)

	if queue.Size() != 2 {
		t.Errorf("expected queue size 2, got %d", queue.Size())
	}

	// dequeue in fifo order
	dequeued, ok := queue.Dequeue()
	if !ok {
		t.Fatal("expected successful dequeue")
	}
	if dequeued.JumpSite != 0x1000 {
		t.Errorf("expected first update jump site 0x1000, got 0x%x", dequeued.JumpSite)
	}

	if queue.Size() != 1 {
		t.Errorf("expected queue size 1 after dequeue, got %d", queue.Size())
	}

	// clear queue
	queue.Clear()
	if queue.Size() != 0 {
		t.Errorf("expected empty queue after clear, got size %d", queue.Size())
	}

	// dequeue from empty queue
	_, ok = queue.Dequeue()
	if ok {
		t.Error("expected dequeue from empty queue to return false")
	}
}

// TestApplyResolveIndirect tests applying indirect jump resolution update
func TestApplyResolveIndirect(t *testing.T) {
	instructions := []*disasm.Instruction{
		{
			Address:  0x1000,
			Bytes:    []byte{0xff, 0xe0}, // jmp rax
			Mnemonic: "jmp",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			},
			Length: 2,
		},
		{
			Address:  0x1002,
			Bytes:    []byte{0x90}, // nop (target 1)
			Mnemonic: "nop",
			Operands: []disasm.Operand{},
			Length:   1,
		},
		{
			Address:  0x1003,
			Bytes:    []byte{0xc3}, // ret - ends block at 0x1002
			Mnemonic: "ret",
			Operands: []disasm.Operand{},
			Length:   1,
		},
		{
			Address:  0x1004,
			Bytes:    []byte{0x90}, // nop (target 2 - separate block)
			Mnemonic: "nop",
			Operands: []disasm.Operand{},
			Length:   1,
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

	initialEdgeCount := cfg.EdgeCount()

	// create update to resolve indirect jump with two distinct target blocks
	update := &IncrementalUpdate{
		UpdateType: UpdateTypeResolveIndirect,
		JumpSite:   0x1000,
		Targets:    []disasm.Address{0x1002, 0x1004},
		Provenance: &EdgeProvenance{
			AnalysisPass: "type_inference",
			Confidence:   0.9,
		},
	}

	// apply update
	err = builder.ApplyIncrementalUpdate(update)
	if err != nil {
		t.Fatalf("failed to apply update: %v", err)
	}

	// verify edges were added (two distinct target blocks → two new edges)
	if cfg.EdgeCount() != initialEdgeCount+2 {
		t.Errorf("expected %d edges after update, got %d", initialEdgeCount+2, cfg.EdgeCount())
	}

	// verify targets recorded
	jump, found := cfg.GetUnresolvedIndirectJump(0x1000)
	if !found {
		t.Fatal("indirect jump not found after update")
	}

	if len(jump.PossibleTargets) != 2 {
		t.Errorf("expected 2 possible targets, got %d", len(jump.PossibleTargets))
	}
}

// TestApplyAddEdge tests applying add edge update
func TestApplyAddEdge(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x2000, Mnemonic: "nop", Length: 1, Operands: []disasm.Operand{}},
		{Address: 0x2001, Mnemonic: "nop", Length: 1, Operands: []disasm.Operand{}},
		{Address: 0x2002, Mnemonic: "ret", Length: 1, Operands: []disasm.Operand{}},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	initialEdgeCount := cfg.EdgeCount()

	// create update to add edge
	update := &IncrementalUpdate{
		UpdateType: UpdateTypeAddEdge,
		JumpSite:   0x2000,
		Targets:    []disasm.Address{0x2002},
		Provenance: &EdgeProvenance{
			AnalysisPass: "manual",
			Confidence:   1.0,
		},
	}

	// apply update
	err = builder.ApplyIncrementalUpdate(update)
	if err != nil {
		t.Fatalf("failed to apply update: %v", err)
	}

	// verify edge was added
	if cfg.EdgeCount() != initialEdgeCount+1 {
		t.Errorf("expected %d edges after update, got %d", initialEdgeCount+1, cfg.EdgeCount())
	}
}

// TestApplySplitBlock tests splitting a block when new branch target discovered
func TestApplySplitBlock(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x3000, Mnemonic: "nop", Length: 1, Operands: []disasm.Operand{}},
		{Address: 0x3001, Mnemonic: "nop", Length: 1, Operands: []disasm.Operand{}},
		{Address: 0x3002, Mnemonic: "nop", Length: 1, Operands: []disasm.Operand{}}, // split point
		{Address: 0x3003, Mnemonic: "nop", Length: 1, Operands: []disasm.Operand{}},
		{Address: 0x3004, Mnemonic: "ret", Length: 1, Operands: []disasm.Operand{}},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	initialBlockCount := cfg.BlockCount()

	// create update to split block at 0x3002
	update := &IncrementalUpdate{
		UpdateType: UpdateTypeSplitBlock,
		Targets:    []disasm.Address{0x3002},
	}

	// apply update
	err = builder.ApplyIncrementalUpdate(update)
	if err != nil {
		t.Fatalf("failed to apply split block update: %v", err)
	}

	// verify new block was created
	if cfg.BlockCount() != initialBlockCount+1 {
		t.Errorf("expected %d blocks after split, got %d", initialBlockCount+1, cfg.BlockCount())
	}

	// verify split point is now a block start
	blockID, exists := builder.addressToBlock[0x3002]
	if !exists {
		t.Fatal("split address not found in address mapping")
	}

	block, exists := cfg.GetBlock(blockID)
	if !exists {
		t.Fatal("split block not found in cfg")
	}

	if block.StartAddress != 0x3002 {
		t.Errorf("expected new block start at 0x3002, got 0x%x", block.StartAddress)
	}

	if len(block.Instructions) != 3 {
		t.Errorf("expected 3 instructions in new block, got %d", len(block.Instructions))
	}
}

// TestBatchApplyUpdates tests applying multiple updates in batch
func TestBatchApplyUpdates(t *testing.T) {
	instructions := []*disasm.Instruction{
		{
			Address:  0x4000,
			Bytes:    []byte{0xff, 0xe0}, // jmp rax
			Mnemonic: "jmp",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			},
			Length: 2,
		},
		{Address: 0x4002, Mnemonic: "nop", Length: 1, Operands: []disasm.Operand{}},
		{
			Address:  0x4003,
			Bytes:    []byte{0xff, 0xe1}, // jmp rcx
			Mnemonic: "jmp",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rcx", Size: disasm.Size64},
			},
			Length: 2,
		},
		{Address: 0x4005, Mnemonic: "nop", Length: 1, Operands: []disasm.Operand{}},
		{Address: 0x4006, Mnemonic: "ret", Length: 1, Operands: []disasm.Operand{}},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// create batch of updates
	updates := []*IncrementalUpdate{
		{
			UpdateType: UpdateTypeResolveIndirect,
			JumpSite:   0x4000,
			Targets:    []disasm.Address{0x4002},
			Provenance: &EdgeProvenance{AnalysisPass: "vsa", Confidence: 0.85},
		},
		{
			UpdateType: UpdateTypeResolveIndirect,
			JumpSite:   0x4003,
			Targets:    []disasm.Address{0x4005},
			Provenance: &EdgeProvenance{AnalysisPass: "vsa", Confidence: 0.85},
		},
	}

	// apply batch
	err = builder.BatchApplyUpdates(updates)
	if err != nil {
		t.Fatalf("failed to apply batch updates: %v", err)
	}

	// verify both jumps have targets
	jump1, found := cfg.GetUnresolvedIndirectJump(0x4000)
	if !found {
		t.Fatal("first indirect jump not found")
	}
	if len(jump1.PossibleTargets) != 1 {
		t.Errorf("expected 1 target for first jump, got %d", len(jump1.PossibleTargets))
	}

	jump2, found := cfg.GetUnresolvedIndirectJump(0x4003)
	if !found {
		t.Fatal("second indirect jump not found")
	}
	if len(jump2.PossibleTargets) != 1 {
		t.Errorf("expected 1 target for second jump, got %d", len(jump2.PossibleTargets))
	}
}

// TestGetIncrementalUpdateStats tests statistics gathering
func TestGetIncrementalUpdateStats(t *testing.T) {
	instructions := []*disasm.Instruction{
		{
			Address:  0x5000,
			Bytes:    []byte{0xff, 0xe0}, // jmp rax (will be resolved)
			Mnemonic: "jmp",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rax", Size: disasm.Size64},
			},
			Length: 2,
		},
		{Address: 0x5002, Mnemonic: "nop", Length: 1, Operands: []disasm.Operand{}},
		{
			Address:  0x5003,
			Bytes:    []byte{0xff, 0xe1}, // jmp rcx (will remain unresolved)
			Mnemonic: "jmp",
			Operands: []disasm.Operand{
				disasm.RegisterOperand{Name: "rcx", Size: disasm.Size64},
			},
			Length: 2,
		},
		{Address: 0x5005, Mnemonic: "ret", Length: 1, Operands: []disasm.Operand{}},
	}

	builder := NewCFGBuilder()
	_, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	// resolve first jump
	err = builder.AddIndirectTarget(0x5000, 0x5002)
	if err != nil {
		t.Fatalf("failed to add target: %v", err)
	}

	// get stats
	stats := builder.GetIncrementalUpdateStats()

	if stats.TotalIndirectJumps != 2 {
		t.Errorf("expected 2 total indirect jumps, got %d", stats.TotalIndirectJumps)
	}

	if stats.ResolvedIndirectJumps != 1 {
		t.Errorf("expected 1 resolved indirect jump, got %d", stats.ResolvedIndirectJumps)
	}

	if stats.UnresolvedIndirectJumps != 1 {
		t.Errorf("expected 1 unresolved indirect jump, got %d", stats.UnresolvedIndirectJumps)
	}

	resolutionRate := stats.ResolutionRate()
	expectedRate := 0.5
	if resolutionRate != expectedRate {
		t.Errorf("expected resolution rate %.2f, got %.2f", expectedRate, resolutionRate)
	}
}

// TestUpdateType_String tests string representation of update types
func TestUpdateType_String(t *testing.T) {
	tests := []struct {
		expected   string
		updateType UpdateType
	}{
		{"AddEdge", UpdateTypeAddEdge},
		{"AddBlock", UpdateTypeAddBlock},
		{"ResolveIndirect", UpdateTypeResolveIndirect},
		{"SplitBlock", UpdateTypeSplitBlock},
	}

	for _, tt := range tests {
		if got := tt.updateType.String(); got != tt.expected {
			t.Errorf("UpdateType(%d).String() = %s, want %s", tt.updateType, got, tt.expected)
		}
	}
}

// TestApplySplitBlock_AlreadyBlockStart tests splitting at existing block boundary
func TestApplySplitBlock_AlreadyBlockStart(t *testing.T) {
	instructions := []*disasm.Instruction{
		{Address: 0x6000, Mnemonic: "nop", Length: 1, Operands: []disasm.Operand{}},
		{
			Address:  0x6001,
			Mnemonic: "je",
			Operands: []disasm.Operand{
				disasm.ImmediateOperand{Value: 0x6003, Size: disasm.Size32},
			},
			Length: 2,
		},
		{Address: 0x6003, Mnemonic: "nop", Length: 1, Operands: []disasm.Operand{}}, // already block start
		{Address: 0x6004, Mnemonic: "ret", Length: 1, Operands: []disasm.Operand{}},
	}

	builder := NewCFGBuilder()
	cfg, err := builder.Build(instructions)
	if err != nil {
		t.Fatalf("failed to build cfg: %v", err)
	}

	initialBlockCount := cfg.BlockCount()

	// try to split at existing block boundary
	update := &IncrementalUpdate{
		UpdateType: UpdateTypeSplitBlock,
		Targets:    []disasm.Address{0x6003},
	}

	err = builder.ApplyIncrementalUpdate(update)
	if err != nil {
		t.Fatalf("failed to apply split: %v", err)
	}

	// verify no new block was created
	if cfg.BlockCount() != initialBlockCount {
		t.Errorf("expected %d blocks (no split), got %d", initialBlockCount, cfg.BlockCount())
	}
}

// TestIncrementalMode tests enabling/disabling incremental mode
func TestIncrementalMode(t *testing.T) {
	builder := NewCFGBuilder()

	if builder.incrementalMode {
		t.Error("expected incremental mode to be disabled initially")
	}

	builder.EnableIncrementalMode()
	if !builder.incrementalMode {
		t.Error("expected incremental mode to be enabled")
	}

	builder.DisableIncrementalMode()
	if builder.incrementalMode {
		t.Error("expected incremental mode to be disabled")
	}
}

// TestResolutionRate_ZeroJumps tests resolution rate with no indirect jumps
func TestResolutionRate_ZeroJumps(t *testing.T) {
	stats := &IncrementalUpdateStats{
		TotalIndirectJumps:      0,
		ResolvedIndirectJumps:   0,
		UnresolvedIndirectJumps: 0,
	}

	rate := stats.ResolutionRate()
	if rate != 1.0 {
		t.Errorf("expected resolution rate 1.0 for zero jumps, got %.2f", rate)
	}
}
