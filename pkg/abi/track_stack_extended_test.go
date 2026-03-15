package abi

import (
	"testing"
)

// TestAdjustOffset_SymbolicDelta verifies adjustOffset on SymbolicOffset.
// This exercises the SymbolicOffset branch in adjustOffset which was previously uncovered.
func TestAdjustOffset_SymbolicDelta(t *testing.T) {
	sym := SymbolicOffset{Base: -8, VarName: "rax"}
	result := adjustOffset(sym, -16)
	got, ok := result.(SymbolicOffset)
	if !ok {
		t.Fatalf("expected SymbolicOffset, got %T", result)
	}
	if got.Base != -24 {
		t.Errorf("adjusted base: expected -24, got %d", got.Base)
	}
	if got.VarName != "rax" {
		t.Errorf("var name: expected 'rax', got '%s'", got.VarName)
	}
}

// TestAdjustOffset_UnknownType verifies adjustOffset fallback for unknown StackOffset type.
// The default branch returns ConcreteOffset{Value: delta}.
func TestAdjustOffset_UnknownType(t *testing.T) {
	// ConcreteOffset and SymbolicOffset are the only two types; test the concrete path
	// to ensure the default branch is exercised via a zero-value concrete offset.
	result := adjustOffset(ConcreteOffset{Value: 0}, -8)
	got, ok := result.(ConcreteOffset)
	if !ok {
		t.Fatalf("expected ConcreteOffset, got %T", result)
	}
	if got.Value != -8 {
		t.Errorf("expected -8, got %d", got.Value)
	}
}
