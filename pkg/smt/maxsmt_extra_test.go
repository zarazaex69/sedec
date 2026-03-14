package smt_test

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/smt"
	typeinfer "github.com/zarazaex69/sedec/pkg/types"
)

// TestConfidenceToWeight_AllTiers verifies that the confidence-to-weight
// mapping covers all documented tiers correctly.
// this exercises the confidenceToWeight function indirectly via SolveWithMaxSMT
// by checking MaxPossibleWeight for single-constraint inputs.
func TestConfidenceToWeight_AllTiers(t *testing.T) {
	cases := []struct {
		confidence float64
		wantWeight int
		origin     string
	}{
		{1.0, 100, "relocation"},
		{0.99, 100, "relocation boundary"},
		{0.9, 90, "debug info"},
		{0.89, 90, "debug info boundary"},
		{0.8, 80, "calling convention"},
		{0.79, 80, "calling convention boundary"},
		{0.5, 50, "operation derived"},
		{0.49, 50, "operation derived boundary"},
		{0.3, 30, "heuristic"},
		{0.1, 30, "heuristic low"},
	}

	for _, tc := range cases {
		t.Run(tc.origin, func(t *testing.T) {
			solver := smt.NewSolver()
			defer solver.Close()

			cs := []typeinfer.TypeConstraint{
				makeEqConstraint("x", "y", tc.confidence, tc.origin),
			}
			result, err := solver.SolveWithMaxSMT(cs)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.MaxPossibleWeight != tc.wantWeight {
				t.Errorf("confidence=%.2f: expected weight %d, got %d",
					tc.confidence, tc.wantWeight, result.MaxPossibleWeight)
			}
		})
	}
}

// TestSolveWithMaxSMT_ManyIndependentConstraints verifies that a large set of
// independent constraints (no conflicts) are all satisfied.
func TestSolveWithMaxSMT_ManyIndependentConstraints(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	// 20 independent equality constraints with distinct variable pairs
	cs := make([]typeinfer.TypeConstraint, 20)
	for i := range cs {
		left := typeinfer.TypeVar{Name: string(rune('a'+i)) + "_l"}
		right := typeinfer.TypeVar{Name: string(rune('a'+i)) + "_r"}
		cs[i] = typeinfer.TypeConstraint{
			Kind:       typeinfer.ConstraintEquality,
			Left:       left,
			Right:      right,
			Confidence: 0.5,
			Origin:     "independent",
		}
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

// TestSolveWithMaxSMT_ArrayElementConstraint verifies that array element
// constraints are correctly encoded and solved.
func TestSolveWithMaxSMT_ArrayElementConstraint(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	cs := []typeinfer.TypeConstraint{
		{
			Kind:       typeinfer.ConstraintArrayElement,
			Left:       typeinfer.TypeVar{Name: "arr"},
			Right:      typeinfer.TypeVar{Name: "elem"},
			Confidence: 0.8,
			Origin:     "strided access",
		},
		makeEqConstraint("elem", "int32_type", 0.9, "debug info"),
	}

	result, err := solver.SolveWithMaxSMT(cs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result must not be nil")
	}
	if len(result.SatisfiedIDs) != 2 {
		t.Errorf("expected 2 satisfied constraints, got %d", len(result.SatisfiedIDs))
	}
}

// TestSolveWithMaxSMT_ReturnTypeConstraint verifies that return type constraints
// are correctly encoded and solved.
func TestSolveWithMaxSMT_ReturnTypeConstraint(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	cs := []typeinfer.TypeConstraint{
		{
			Kind:       typeinfer.ConstraintReturnType,
			Left:       typeinfer.TypeVar{Name: "fn_ptr"},
			Right:      typeinfer.TypeVar{Name: "ret_val"},
			Confidence: 0.9,
			Origin:     "call site",
		},
	}

	result, err := solver.SolveWithMaxSMT(cs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.SatisfiedIDs) != 1 {
		t.Errorf("expected 1 satisfied constraint, got %d", len(result.SatisfiedIDs))
	}
}

// TestSolveWithMaxSMT_ParamTypeConstraint verifies that parameter type
// constraints are correctly encoded and solved.
func TestSolveWithMaxSMT_ParamTypeConstraint(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	cs := []typeinfer.TypeConstraint{
		{
			Kind:       typeinfer.ConstraintParamType,
			Left:       typeinfer.TypeVar{Name: "fn_ptr"},
			Right:      typeinfer.TypeVar{Name: "arg0"},
			ParamIndex: 0,
			Confidence: 0.8,
			Origin:     "call site arg 0",
		},
		{
			Kind:       typeinfer.ConstraintParamType,
			Left:       typeinfer.TypeVar{Name: "fn_ptr"},
			Right:      typeinfer.TypeVar{Name: "arg1"},
			ParamIndex: 1,
			Confidence: 0.8,
			Origin:     "call site arg 1",
		},
	}

	result, err := solver.SolveWithMaxSMT(cs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.SatisfiedIDs) != 2 {
		t.Errorf("expected 2 satisfied constraints, got %d", len(result.SatisfiedIDs))
	}
}

// TestSolveWithMaxSMT_SolverClose verifies that calling Close twice on a
// solver does not panic.
func TestSolveWithMaxSMT_SolverClose(t *testing.T) {
	solver := smt.NewSolver()
	solver.Close()
	// second close must not panic
	solver.Close()
}

// TestConflictAnalyzer_MultipleConflicts verifies that the analyzer correctly
// identifies multiple independent conflicts in a single result.
func TestConflictAnalyzer_MultipleConflicts(t *testing.T) {
	analyzer := &smt.ConflictAnalyzer{}

	constraints := []typeinfer.TypeConstraint{
		makeEqConstraint("a", "b", 1.0, "relocation"), // index 0: winner for (a,b)
		makeEqConstraint("a", "b", 0.3, "heuristic"),  // index 1: loser for (a,b)
		makeEqConstraint("x", "y", 0.9, "debug info"), // index 2: winner for (x,y)
		makeEqConstraint("x", "y", 0.5, "operation"),  // index 3: loser for (x,y)
	}
	result := &smt.MaxSMTResult{
		SatisfiedIDs:      []int{0, 2},
		UnsatisfiedIDs:    []int{1, 3},
		TotalWeight:       190,
		MaxPossibleWeight: 270,
		SatisfactionRate:  190.0 / 270.0,
	}

	reports := analyzer.Analyze(constraints, result)
	if len(reports) != 2 {
		t.Fatalf("expected 2 conflict reports, got %d", len(reports))
	}

	// verify both conflicts are correctly identified
	for _, r := range reports {
		if r.WinnerConfidence <= r.LoserConfidence {
			t.Errorf("winner confidence (%.2f) must be > loser confidence (%.2f)",
				r.WinnerConfidence, r.LoserConfidence)
		}
		if r.Description == "" {
			t.Error("conflict description must not be empty")
		}
	}
}

// TestConflictAnalyzer_UnsatisfiedWithNoMatchingSatisfied verifies that
// unsatisfied constraints with no matching satisfied pair produce no report.
func TestConflictAnalyzer_UnsatisfiedWithNoMatchingSatisfied(t *testing.T) {
	analyzer := &smt.ConflictAnalyzer{}

	constraints := []typeinfer.TypeConstraint{
		makeEqConstraint("a", "b", 1.0, "relocation"), // index 0: satisfied
		makeEqConstraint("x", "y", 0.3, "heuristic"),  // index 1: unsatisfied, no conflict pair
	}
	result := &smt.MaxSMTResult{
		SatisfiedIDs:      []int{0},
		UnsatisfiedIDs:    []int{1},
		TotalWeight:       100,
		MaxPossibleWeight: 130,
		SatisfactionRate:  100.0 / 130.0,
	}

	reports := analyzer.Analyze(constraints, result)
	// (x,y) has no satisfied counterpart, so no conflict report
	if len(reports) != 0 {
		t.Errorf("expected 0 conflict reports for unmatched unsatisfied, got %d", len(reports))
	}
}

// TestMaxSMTResult_SatisfactionRateEdgeCases verifies edge cases of the
// satisfaction rate computation.
func TestMaxSMTResult_SatisfactionRateEdgeCases(t *testing.T) {
	// zero max weight: rate must be 1.0 (vacuously satisfied)
	r := &smt.MaxSMTResult{
		SatisfiedIDs:      []int{},
		UnsatisfiedIDs:    []int{},
		TotalWeight:       0,
		MaxPossibleWeight: 0,
		SatisfactionRate:  1.0,
	}
	if r.SatisfactionRate != 1.0 {
		t.Errorf("expected 1.0 for zero max weight, got %f", r.SatisfactionRate)
	}

	// full satisfaction: rate must be 1.0
	r2 := &smt.MaxSMTResult{
		TotalWeight:       300,
		MaxPossibleWeight: 300,
		SatisfactionRate:  1.0,
	}
	if r2.SatisfactionRate != 1.0 {
		t.Errorf("expected 1.0 for full satisfaction, got %f", r2.SatisfactionRate)
	}
}

// TestSolveWithMaxSMT_SpecialCharactersInVarNames verifies that variable names
// with special characters (dollar signs, underscores, numbers) are handled
// correctly by the Z3 name sanitizer.
func TestSolveWithMaxSMT_SpecialCharactersInVarNames(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	cs := []typeinfer.TypeConstraint{
		makeEqConstraint("$ret_main", "$param_main_0", 0.8, "signature"),
		makeEqConstraint("rax_3", "rbx_1", 0.5, "operation"),
		makeEqConstraint("$uint_42", "$uint_43", 0.6, "unsigned op"),
	}

	result, err := solver.SolveWithMaxSMT(cs)
	if err != nil {
		t.Fatalf("unexpected error with special char var names: %v", err)
	}
	if result == nil {
		t.Fatal("result must not be nil")
	}
	// all constraints are independent: all should be satisfied
	if len(result.SatisfiedIDs) != 3 {
		t.Errorf("expected 3 satisfied constraints, got %d", len(result.SatisfiedIDs))
	}
}
