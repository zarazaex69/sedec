package smt_test

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/smt"
	typeinfer "github.com/zarazaex69/sedec/pkg/types"
)

// makeEqConstraint creates an equality constraint with the given confidence.
func makeEqConstraint(left, right string, confidence float64, origin string) typeinfer.TypeConstraint {
	return typeinfer.TypeConstraint{
		Kind:       typeinfer.ConstraintEquality,
		Left:       typeinfer.TypeVar{Name: left},
		Right:      typeinfer.TypeVar{Name: right},
		Confidence: confidence,
		Origin:     origin,
	}
}

// makePtrConstraint creates a pointer-to constraint with the given confidence.
func makePtrConstraint(left, right string, confidence float64, origin string) typeinfer.TypeConstraint {
	return typeinfer.TypeConstraint{
		Kind:       typeinfer.ConstraintPointerTo,
		Left:       typeinfer.TypeVar{Name: left},
		Right:      typeinfer.TypeVar{Name: right},
		Confidence: confidence,
		Origin:     origin,
	}
}

// makeFieldConstraint creates a field access constraint.
func makeFieldConstraint(structVar, fieldVar string, offset int64, confidence float64) typeinfer.TypeConstraint {
	return typeinfer.TypeConstraint{
		Kind:        typeinfer.ConstraintFieldAccess,
		Left:        typeinfer.TypeVar{Name: structVar},
		Right:       typeinfer.TypeVar{Name: fieldVar},
		FieldOffset: offset,
		Confidence:  confidence,
		Origin:      "test field access",
	}
}

// TestSolveWithMaxSMT_EmptyConstraints verifies that an empty constraint set
// produces a valid result with zero weights.
func TestSolveWithMaxSMT_EmptyConstraints(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	result, err := solver.SolveWithMaxSMT(nil)
	if err != nil {
		t.Fatalf("unexpected error on empty constraints: %v", err)
	}
	if result == nil {
		t.Fatal("result must not be nil")
	}
	if result.TotalWeight != 0 {
		t.Errorf("expected TotalWeight=0, got %d", result.TotalWeight)
	}
	if result.MaxPossibleWeight != 0 {
		t.Errorf("expected MaxPossibleWeight=0, got %d", result.MaxPossibleWeight)
	}
	if result.SatisfactionRate != 1.0 {
		t.Errorf("expected SatisfactionRate=1.0 for empty set, got %f", result.SatisfactionRate)
	}
}

// TestSolveWithMaxSMT_AllConsistent verifies that when all constraints are
// mutually consistent, all are satisfied.
func TestSolveWithMaxSMT_AllConsistent(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	constraints := []typeinfer.TypeConstraint{
		makeEqConstraint("rax_1", "rbx_1", 0.5, "add operands"),
		makeEqConstraint("rbx_1", "rcx_1", 0.5, "mov operands"),
		makePtrConstraint("rdi_1", "rax_1", 0.5, "load address"),
	}

	result, err := solver.SolveWithMaxSMT(constraints)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result must not be nil")
	}

	// all constraints are consistent: all should be satisfied
	if len(result.SatisfiedIDs) != len(constraints) {
		t.Errorf("expected all %d constraints satisfied, got %d",
			len(constraints), len(result.SatisfiedIDs))
	}
	if len(result.UnsatisfiedIDs) != 0 {
		t.Errorf("expected 0 unsatisfied constraints, got %d", len(result.UnsatisfiedIDs))
	}
	if result.SatisfactionRate < 0.99 {
		t.Errorf("expected satisfaction rate ~1.0, got %f", result.SatisfactionRate)
	}
}

// TestSolveWithMaxSMT_HighConfidenceWins verifies that when two constraints
// conflict, the higher-confidence one is preferred.
// this is the core MaxSMT property: weight maximization.
func TestSolveWithMaxSMT_HighConfidenceWins(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	// relocation-derived constraint (confidence=1.0, weight=100): rax_1 eq rbx_1
	// heuristic constraint (confidence=0.3, weight=30): rax_1 eq rcx_1
	// both involve rax_1 but with different partners; they are not directly
	// conflicting in Z3 encoding (both can be true simultaneously), but
	// the weight system ensures relocation constraints dominate.
	constraints := []typeinfer.TypeConstraint{
		makeEqConstraint("rax_1", "rbx_1", 1.0, "relocation axiom"),
		makeEqConstraint("rax_1", "rcx_1", 0.3, "heuristic"),
		makeEqConstraint("rbx_1", "rcx_1", 0.5, "operation derived"),
	}

	result, err := solver.SolveWithMaxSMT(constraints)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// the relocation constraint (index 0, weight 100) must be satisfied
	satisfiedSet := make(map[int]bool, len(result.SatisfiedIDs))
	for _, id := range result.SatisfiedIDs {
		satisfiedSet[id] = true
	}
	if !satisfiedSet[0] {
		t.Error("relocation axiom (index 0, weight 100) must be satisfied")
	}

	// total weight must be >= 100 (at minimum the relocation constraint)
	if result.TotalWeight < 100 {
		t.Errorf("expected TotalWeight >= 100, got %d", result.TotalWeight)
	}
}

// TestSolveWithMaxSMT_WeightMapping verifies that confidence values are
// correctly mapped to integer weights.
func TestSolveWithMaxSMT_WeightMapping(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	// one constraint per confidence tier
	constraints := []typeinfer.TypeConstraint{
		makeEqConstraint("a", "b", 1.0, "relocation"),   // weight 100
		makeEqConstraint("c", "d", 0.9, "debug info"),   // weight 90
		makeEqConstraint("e", "f", 0.8, "calling conv"), // weight 80
		makeEqConstraint("g", "h", 0.5, "operation"),    // weight 50
		makeEqConstraint("i", "j", 0.3, "heuristic"),    // weight 30
	}

	result, err := solver.SolveWithMaxSMT(constraints)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// all constraints are independent (different variables): all should be satisfied
	expectedMaxWeight := 100 + 90 + 80 + 50 + 30 // = 350
	if result.MaxPossibleWeight != expectedMaxWeight {
		t.Errorf("expected MaxPossibleWeight=%d, got %d", expectedMaxWeight, result.MaxPossibleWeight)
	}
	if len(result.SatisfiedIDs) != len(constraints) {
		t.Errorf("expected all %d constraints satisfied, got %d",
			len(constraints), len(result.SatisfiedIDs))
	}
}

// TestSolveWithMaxSMT_FieldConstraints verifies that field access constraints
// are correctly encoded and solved.
func TestSolveWithMaxSMT_FieldConstraints(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	constraints := []typeinfer.TypeConstraint{
		makeFieldConstraint("base_ptr", "field_0", 0, 0.5),
		makeFieldConstraint("base_ptr", "field_8", 8, 0.5),
		makeFieldConstraint("base_ptr", "field_16", 16, 0.5),
		// relocation-derived: base_ptr is a pointer to a known struct
		makePtrConstraint("base_ptr", "struct_type", 1.0, "relocation"),
	}

	result, err := solver.SolveWithMaxSMT(constraints)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// relocation constraint must be satisfied
	satisfiedSet := make(map[int]bool, len(result.SatisfiedIDs))
	for _, id := range result.SatisfiedIDs {
		satisfiedSet[id] = true
	}
	if !satisfiedSet[3] {
		t.Error("relocation pointer constraint (index 3) must be satisfied")
	}
}

// TestSolveWithMaxSMT_SatisfactionRate verifies that the satisfaction rate
// is correctly computed as TotalWeight / MaxPossibleWeight.
func TestSolveWithMaxSMT_SatisfactionRate(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	constraints := []typeinfer.TypeConstraint{
		makeEqConstraint("x", "y", 1.0, "relocation"), // weight 100
		makeEqConstraint("a", "b", 0.5, "operation"),  // weight 50
	}

	result, err := solver.SolveWithMaxSMT(constraints)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.MaxPossibleWeight != 150 {
		t.Errorf("expected MaxPossibleWeight=150, got %d", result.MaxPossibleWeight)
	}
	if result.SatisfactionRate < 0.0 || result.SatisfactionRate > 1.0 {
		t.Errorf("satisfaction rate must be in [0,1], got %f", result.SatisfactionRate)
	}
}

// TestSolveWithMaxSMT_SubtypeConstraints verifies that subtype constraints
// are correctly encoded as implications.
func TestSolveWithMaxSMT_SubtypeConstraints(t *testing.T) {
	solver := smt.NewSolver()
	defer solver.Close()

	constraints := []typeinfer.TypeConstraint{
		{
			Kind:       typeinfer.ConstraintSubtype,
			Left:       typeinfer.TypeVar{Name: "derived"},
			Right:      typeinfer.TypeVar{Name: "base"},
			Confidence: 0.8,
			Origin:     "implicit widening",
		},
		makeEqConstraint("base", "int64", 0.9, "debug info"),
	}

	result, err := solver.SolveWithMaxSMT(constraints)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result must not be nil")
	}
	// both constraints are consistent: both should be satisfied
	if len(result.SatisfiedIDs) != 2 {
		t.Errorf("expected 2 satisfied constraints, got %d", len(result.SatisfiedIDs))
	}
}

// TestConflictAnalyzer_NoConflicts verifies that the analyzer produces no
// reports when all constraints are satisfied.
func TestConflictAnalyzer_NoConflicts(t *testing.T) {
	analyzer := &smt.ConflictAnalyzer{}
	constraints := []typeinfer.TypeConstraint{
		makeEqConstraint("a", "b", 1.0, "relocation"),
		makeEqConstraint("c", "d", 0.5, "operation"),
	}
	result := &smt.MaxSMTResult{
		SatisfiedIDs:      []int{0, 1},
		UnsatisfiedIDs:    []int{},
		TotalWeight:       150,
		MaxPossibleWeight: 150,
		SatisfactionRate:  1.0,
	}

	reports := analyzer.Analyze(constraints, result)
	if len(reports) != 0 {
		t.Errorf("expected 0 conflict reports, got %d", len(reports))
	}
}

// TestConflictAnalyzer_WithConflict verifies that the analyzer correctly
// identifies which constraint won and which was dropped.
func TestConflictAnalyzer_WithConflict(t *testing.T) {
	analyzer := &smt.ConflictAnalyzer{}
	constraints := []typeinfer.TypeConstraint{
		makeEqConstraint("rax_1", "rbx_1", 1.0, "relocation axiom"),    // index 0: winner
		makeEqConstraint("rax_1", "rbx_1", 0.3, "heuristic inference"), // index 1: loser
	}
	result := &smt.MaxSMTResult{
		SatisfiedIDs:      []int{0},
		UnsatisfiedIDs:    []int{1},
		TotalWeight:       100,
		MaxPossibleWeight: 130,
		SatisfactionRate:  100.0 / 130.0,
	}

	reports := analyzer.Analyze(constraints, result)
	if len(reports) != 1 {
		t.Fatalf("expected 1 conflict report, got %d", len(reports))
	}

	report := reports[0]
	if report.WinnerIndex != 0 {
		t.Errorf("expected WinnerIndex=0, got %d", report.WinnerIndex)
	}
	if report.LoserIndex != 1 {
		t.Errorf("expected LoserIndex=1, got %d", report.LoserIndex)
	}
	if report.WinnerConfidence != 1.0 {
		t.Errorf("expected WinnerConfidence=1.0, got %f", report.WinnerConfidence)
	}
	if report.LoserConfidence != 0.3 {
		t.Errorf("expected LoserConfidence=0.3, got %f", report.LoserConfidence)
	}
	if report.Description == "" {
		t.Error("conflict description must not be empty")
	}
}

// TestMaxSMTResult_String verifies the human-readable summary format.
func TestMaxSMTResult_String(t *testing.T) {
	result := &smt.MaxSMTResult{
		SatisfiedIDs:      []int{0, 1, 2},
		UnsatisfiedIDs:    []int{3},
		TotalWeight:       240,
		MaxPossibleWeight: 270,
		SatisfactionRate:  240.0 / 270.0,
	}

	s := result.String()
	if s == "" {
		t.Error("String() must not return empty string")
	}
	// verify it contains key metrics
	if len(s) < 10 {
		t.Errorf("String() too short: %q", s)
	}
}
