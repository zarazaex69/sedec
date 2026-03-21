package smt_test

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/smt"
	typeinfer "github.com/zarazaex69/sedec/pkg/types"
)

func TestGreedyFallback_NoConflicts(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	cs := []typeinfer.TypeConstraint{
		makeEqConstraint("a", "b", 1.0, "relocation"),
		makeEqConstraint("c", "d", 0.5, "operation"),
		makePtrConstraint("e", "f", 0.3, "heuristic"),
	}

	result := solver.GreedyFallback(cs)
	if result == nil {
		t.Fatal("result must not be nil")
	}
	if len(result.SatisfiedIDs) != 3 {
		t.Errorf("expected 3 satisfied, got %d", len(result.SatisfiedIDs))
	}
	if len(result.UnsatisfiedIDs) != 0 {
		t.Errorf("expected 0 unsatisfied, got %d", len(result.UnsatisfiedIDs))
	}
	expectedMax := 100 + 50 + 30
	if result.MaxPossibleWeight != expectedMax {
		t.Errorf("expected MaxPossibleWeight=%d, got %d", expectedMax, result.MaxPossibleWeight)
	}
	if result.TotalWeight != expectedMax {
		t.Errorf("expected TotalWeight=%d, got %d", expectedMax, result.TotalWeight)
	}
	if result.SatisfactionRate < 0.99 {
		t.Errorf("expected satisfaction rate ~1.0, got %f", result.SatisfactionRate)
	}
}

func TestGreedyFallback_WithConflicts(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	cs := []typeinfer.TypeConstraint{
		makeEqConstraint("a", "b", 1.0, "relocation"),
		makePtrConstraint("a", "b", 0.3, "heuristic"),
	}

	result := solver.GreedyFallback(cs)
	if result == nil {
		t.Fatal("result must not be nil")
	}
	if len(result.SatisfiedIDs) != 1 {
		t.Errorf("expected 1 satisfied, got %d", len(result.SatisfiedIDs))
	}
	if len(result.UnsatisfiedIDs) != 1 {
		t.Errorf("expected 1 unsatisfied, got %d", len(result.UnsatisfiedIDs))
	}
	if result.TotalWeight != 100 {
		t.Errorf("expected TotalWeight=100, got %d", result.TotalWeight)
	}
}

func TestGreedyFallback_Empty(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	result := solver.GreedyFallback(nil)
	if result == nil {
		t.Fatal("result must not be nil")
	}
	if result.SatisfactionRate != 1.0 {
		t.Errorf("expected 1.0 for empty, got %f", result.SatisfactionRate)
	}
}

func TestGreedyFallback_HighConfidenceWins(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	cs := []typeinfer.TypeConstraint{
		makeEqConstraint("x", "y", 0.3, "heuristic"),
		makePtrConstraint("x", "y", 0.9, "debug info"),
		makeFieldConstraint("x", "y", 0, 0.5),
	}

	result := solver.GreedyFallback(cs)
	if result == nil {
		t.Fatal("result must not be nil")
	}
	satisfiedSet := make(map[int]bool, len(result.SatisfiedIDs))
	for _, id := range result.SatisfiedIDs {
		satisfiedSet[id] = true
	}
	if !satisfiedSet[1] {
		t.Error("debug info constraint (index 1, highest confidence) must be satisfied")
	}
}

func TestSanitizeZ3Name_AllBranches(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"abc", "abc"},
		{"ABC", "ABC"},
		{"123", "123"},
		{"a_b", "a_b"},
		{"a$b", "a$b"},
		{"a#b", "a#b"},
		{"a@b", "a@b"},
		{"a.b", "a.b"},
		{"a-b", "a-b"},
		{"a b", "a_b"},
		{"a(b)", "a_b_"},
		{"a+b", "a_b"},
		{"", ""},
		{"hello world!", "hello_world_"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := smt.SanitizeZ3Name(tc.input)
			if got != tc.want {
				t.Errorf("SanitizeZ3Name(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestSolveWithMaxSMT_MixedConstraintKinds(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	cs := []typeinfer.TypeConstraint{
		makeEqConstraint("a", "b", 1.0, "relocation"),
		makePtrConstraint("c", "d", 0.9, "debug"),
		makeFieldConstraint("e", "f", 8, 0.8),
		{
			Kind:       typeinfer.ConstraintSubtype,
			Left:       typeinfer.TypeVar{Name: "g"},
			Right:      typeinfer.TypeVar{Name: "h"},
			Confidence: 0.5,
			Origin:     "widening",
		},
		{
			Kind:       typeinfer.ConstraintArrayElement,
			Left:       typeinfer.TypeVar{Name: "arr"},
			Right:      typeinfer.TypeVar{Name: "elem"},
			Confidence: 0.8,
			Origin:     "strided",
		},
		{
			Kind:       typeinfer.ConstraintReturnType,
			Left:       typeinfer.TypeVar{Name: "fn"},
			Right:      typeinfer.TypeVar{Name: "ret"},
			Confidence: 0.9,
			Origin:     "call",
		},
		{
			Kind:       typeinfer.ConstraintParamType,
			Left:       typeinfer.TypeVar{Name: "fn2"},
			Right:      typeinfer.TypeVar{Name: "arg0"},
			ParamIndex: 0,
			Confidence: 0.8,
			Origin:     "call arg",
		},
	}

	result, err := solver.SolveWithMaxSMT(cs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.SatisfiedIDs) != len(cs) {
		t.Errorf("expected all %d constraints satisfied, got %d",
			len(cs), len(result.SatisfiedIDs))
	}
}

func TestSolveWithMaxSMT_InvalidConstraintKindSkipped(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	cs := []typeinfer.TypeConstraint{
		makeEqConstraint("a", "b", 0.5, "valid"),
		{
			Kind:       typeinfer.ConstraintKind(999),
			Left:       typeinfer.TypeVar{Name: "x"},
			Right:      typeinfer.TypeVar{Name: "y"},
			Confidence: 0.5,
			Origin:     "invalid kind",
		},
	}

	result, err := solver.SolveWithMaxSMT(cs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.SatisfiedIDs) != 1 {
		t.Errorf("expected 1 satisfied (invalid kind skipped), got %d",
			len(result.SatisfiedIDs))
	}
}
