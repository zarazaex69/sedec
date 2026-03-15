package abi

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// TestStackOffset_Interface verifies that ConcreteOffset and SymbolicOffset
// satisfy the StackOffset interface and return correct base offsets.
func TestStackOffset_Interface(t *testing.T) {
	var c StackOffset = ConcreteOffset{Value: -32}
	if c.BaseOffset() != -32 {
		t.Errorf("ConcreteOffset.BaseOffset(): expected -32, got %d", c.BaseOffset())
	}

	var s StackOffset = SymbolicOffset{Base: -16, VarName: "rax"}
	if s.BaseOffset() != -16 {
		t.Errorf("SymbolicOffset.BaseOffset(): expected -16, got %d", s.BaseOffset())
	}
}

// TestStackOffset_IsStackOffset verifies the type discriminator methods compile and run.
func TestStackOffset_IsStackOffset(t *testing.T) {
	// these calls exercise the isStackOffset() discriminator methods
	c := ConcreteOffset{Value: 0}
	c.isStackOffset()

	s := SymbolicOffset{Base: 0, VarName: "rcx"}
	s.isStackOffset()
}

// TestSymbolicStackTracker_AddInconsistency verifies inconsistency recording.
func TestSymbolicStackTracker_AddInconsistency(t *testing.T) {
	tracker := NewSymbolicStackTracker()

	inc := StackInconsistency{
		Address:  0x1000,
		Expected: ConcreteOffset{Value: -8},
		Observed: ConcreteOffset{Value: -16},
		Message:  "divergent paths",
	}
	tracker.AddInconsistency(inc)

	incs := tracker.Inconsistencies()
	if len(incs) != 1 {
		t.Fatalf("expected 1 inconsistency, got %d", len(incs))
	}
	if incs[0].Address != 0x1000 {
		t.Errorf("inconsistency address: expected 0x1000, got 0x%x", incs[0].Address)
	}
	if incs[0].Message != "divergent paths" {
		t.Errorf("inconsistency message: expected 'divergent paths', got '%s'", incs[0].Message)
	}
}

// TestSymbolicStackTracker_MultipleInconsistencies verifies multiple inconsistencies accumulate.
func TestSymbolicStackTracker_MultipleInconsistencies(t *testing.T) {
	tracker := NewSymbolicStackTracker()
	for i := 0; i < 3; i++ {
		tracker.AddInconsistency(StackInconsistency{
			Address: disasm.Address(0x1000 + uint64(i)*4),
			Message: "test",
		})
	}
	if len(tracker.Inconsistencies()) != 3 {
		t.Errorf("expected 3 inconsistencies, got %d", len(tracker.Inconsistencies()))
	}
}
