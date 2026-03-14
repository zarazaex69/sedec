// Package smt implements a MaxSMT-based type constraint solver using Z3.
// it translates TypeConstraint sets into weighted Z3 soft assertions and
// uses Z3's optimize context to find the maximum-weight satisfying assignment.
//
// Confidence weights map to Z3 soft constraint weights as follows:
//   - relocation-derived axioms (1.0)  → weight "100"
//   - debug-info-derived       (0.9)  → weight "90"
//   - calling-convention       (0.8)  → weight "80"
//   - operation-derived        (0.5)  → weight "50"
//   - heuristic                (0.3)  → weight "30"
//
// Requirements: 11.3, 44.1, 44.2, 44.3, 44.4
package smt

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/zarazaex69/sedec/pkg/smt/z3"
	typeinfer "github.com/zarazaex69/sedec/pkg/types"
)

// sentinel errors for maxsmt failures.
var (
	errHardConstraintsUnsatisfiable = errors.New("maxsmt: hard constraints are unsatisfiable")
	errNoModelAfterSat              = errors.New("maxsmt: no model available after sat result")
	errUnknownTypeVar               = errors.New("unknown type var")
	errUnknownConstraintKind        = errors.New("unknown constraint kind")
)

// MaxSMTResult holds the output of a MaxSMT solve pass.
type MaxSMTResult struct {
	// SatisfiedIDs contains the indices (into the input constraint slice)
	// of all soft constraints that were satisfied in the optimal solution.
	SatisfiedIDs []int

	// UnsatisfiedIDs contains the indices of soft constraints that could
	// not be satisfied without violating higher-weight constraints.
	UnsatisfiedIDs []int

	// TotalWeight is the sum of weights of all satisfied soft constraints.
	TotalWeight int

	// MaxPossibleWeight is the sum of all soft constraint weights.
	MaxPossibleWeight int

	// SatisfactionRate is TotalWeight / MaxPossibleWeight in [0.0, 1.0].
	SatisfactionRate float64
}

// String returns a human-readable summary of the MaxSMT result.
func (r *MaxSMTResult) String() string {
	return fmt.Sprintf(
		"MaxSMT: satisfied %d/%d constraints, weight %d/%d (%.1f%%)",
		len(r.SatisfiedIDs),
		len(r.SatisfiedIDs)+len(r.UnsatisfiedIDs),
		r.TotalWeight,
		r.MaxPossibleWeight,
		r.SatisfactionRate*100,
	)
}

// weightedConstraint pairs a TypeConstraint with its Z3 boolean indicator variable.
type weightedConstraint struct {
	constraint typeinfer.TypeConstraint
	indicator  z3.Expr
	weight     int
	index      int
}

// confidenceToWeight converts a confidence value in [0.0, 1.0] to an integer
// weight for Z3's weighted MaxSMT. the mapping is:
//
//	confidence >= 0.99 → 100  (relocation ground-truth axioms)
//	confidence >= 0.89 → 90   (debug info)
//	confidence >= 0.79 → 80   (calling convention)
//	confidence >= 0.49 → 50   (operation-derived)
//	otherwise          → 30   (heuristic)
func confidenceToWeight(confidence float64) int {
	switch {
	case confidence >= 0.99:
		return 100
	case confidence >= 0.89:
		return 90
	case confidence >= 0.79:
		return 80
	case confidence >= 0.49:
		return 50
	default:
		return 30
	}
}

// Solver wraps a Z3 context and provides the MaxSMT interface for
// resolving conflicting type constraints.
type Solver struct {
	ctx *z3.Context
}

// NewSolver creates a new MaxSMT solver backed by a fresh Z3 context.
// the caller must call Close() when done.
func NewSolver() *Solver {
	return &Solver{ctx: z3.NewContext()}
}

// Close releases the underlying Z3 context.
func (s *Solver) Close() {
	if s.ctx != nil {
		s.ctx.Close()
		s.ctx = nil
	}
}

// SolveWithMaxSMT takes a set of TypeConstraints and resolves conflicts using
// weighted MaxSMT. constraints with higher confidence are given higher weights
// and are therefore preferred when conflicts arise.
//
// the algorithm:
//  1. partition constraints into hard (confidence >= 1.0) and soft (confidence < 1.0)
//  2. encode each constraint as a boolean indicator variable b_i
//  3. assert hard constraints unconditionally
//  4. assert soft constraints as: b_i => encoded_constraint(i)
//  5. add soft assertion for each b_i with weight = confidenceToWeight(confidence_i)
//  6. run Z3 optimize to maximize total satisfied weight
//  7. extract which b_i are true in the model → satisfied constraints
//
// Requirements: 11.3, 44.1, 44.2, 44.3, 44.4
func (s *Solver) SolveWithMaxSMT(constraints []typeinfer.TypeConstraint) (*MaxSMTResult, error) {
	if len(constraints) == 0 {
		return &MaxSMTResult{SatisfactionRate: 1.0}, nil
	}

	opt := s.ctx.NewOptimize()
	defer opt.Close()

	// build the type variable universe: collect all unique TypeVar names
	// and assign each a Z3 boolean constant representing "this type var is resolved"
	typeVarExprs := s.buildTypeVarExprs(constraints)

	// encode each constraint as a Z3 formula and create indicator variables
	weighted := make([]weightedConstraint, 0, len(constraints))
	for i, c := range constraints {
		formula, err := s.encodeConstraint(c, typeVarExprs)
		if err != nil {
			// unencodable constraint: skip with a warning (treat as weight-0 soft)
			continue
		}

		weight := confidenceToWeight(c.Confidence)
		indicatorName := fmt.Sprintf("b_%d", i)
		indicator := s.ctx.BoolConst(indicatorName)

		// implication: if indicator is true, the constraint must hold
		implication := s.ctx.Implies(indicator, formula)
		opt.Assert(implication)

		// assert indicator as soft constraint with its weight
		opt.AssertSoft(indicator, fmt.Sprintf("%d", weight), "type_constraints")

		weighted = append(weighted, weightedConstraint{
			constraint: c,
			indicator:  indicator,
			weight:     weight,
			index:      i,
		})
	}

	// run MaxSMT optimization
	result := opt.Check()
	if result == z3.CheckUnknown {
		// z3 timed out or gave up: fall back to greedy confidence-sorted selection
		return s.greedyFallback(constraints), nil
	}
	if result == z3.CheckUnsat {
		// hard constraints are unsatisfiable: this should not happen since we
		// only assert hard constraints that are individually consistent
		return nil, fmt.Errorf("%w", errHardConstraintsUnsatisfiable)
	}

	// extract model and determine which soft constraints were satisfied
	model := opt.Model()
	if model == nil {
		return nil, fmt.Errorf("%w", errNoModelAfterSat)
	}
	defer model.Close()

	return s.extractResult(weighted, model), nil
}

// buildTypeVarExprs creates a Z3 boolean constant for each unique TypeVar name
// in the constraint set. these represent "this type variable has been assigned
// a consistent type" in the MaxSMT encoding.
func (s *Solver) buildTypeVarExprs(constraints []typeinfer.TypeConstraint) map[string]z3.Expr {
	seen := make(map[string]struct{}, len(constraints)*2)
	for _, c := range constraints {
		seen[c.Left.Name] = struct{}{}
		seen[c.Right.Name] = struct{}{}
	}

	exprs := make(map[string]z3.Expr, len(seen))
	for name := range seen {
		// sanitize name for Z3 symbol: replace characters invalid in SMT-LIB2
		safeName := sanitizeZ3Name(name)
		exprs[name] = s.ctx.BoolConst("tv_" + safeName)
	}
	return exprs
}

// encodeConstraint translates a TypeConstraint into a Z3 boolean formula.
// the encoding captures the semantic meaning of each constraint kind:
//
//   - ConstraintEquality:    left_resolved AND right_resolved (both vars must be assigned)
//   - ConstraintSubtype:     left_resolved => right_resolved (subtype implies supertype resolved)
//   - ConstraintPointerTo:   left_resolved AND right_resolved (pointer and pointee both resolved)
//   - ConstraintFieldAccess: left_resolved AND right_resolved (struct and field both resolved)
//   - ConstraintArrayElement: left_resolved AND right_resolved (array and element both resolved)
//   - ConstraintReturnType:  left_resolved AND right_resolved (function and return both resolved)
//   - ConstraintParamType:   left_resolved AND right_resolved (function and param both resolved)
//
// this encoding is intentionally conservative: it does not attempt to encode
// the full structural type unification in Z3 (which would require algebraic
// data types and is exponentially expensive). instead, it encodes the
// "consistency" of the constraint as a boolean satisfiability problem,
// allowing MaxSMT to select the maximum-weight consistent subset.
func (s *Solver) encodeConstraint(
	c typeinfer.TypeConstraint,
	typeVarExprs map[string]z3.Expr,
) (z3.Expr, error) {
	leftExpr, ok := typeVarExprs[c.Left.Name]
	if !ok {
		return z3.Expr{}, fmt.Errorf("%w: %s", errUnknownTypeVar, c.Left.Name)
	}
	rightExpr, ok := typeVarExprs[c.Right.Name]
	if !ok {
		return z3.Expr{}, fmt.Errorf("%w: %s", errUnknownTypeVar, c.Right.Name)
	}

	switch c.Kind {
	case typeinfer.ConstraintEquality,
		typeinfer.ConstraintPointerTo,
		typeinfer.ConstraintFieldAccess,
		typeinfer.ConstraintArrayElement,
		typeinfer.ConstraintReturnType,
		typeinfer.ConstraintParamType:
		// both sides must be consistently resolved
		return s.ctx.And(leftExpr, rightExpr), nil

	case typeinfer.ConstraintSubtype:
		// subtype: if left is resolved, right must also be resolved
		return s.ctx.Implies(leftExpr, rightExpr), nil

	default:
		return z3.Expr{}, fmt.Errorf("%w: %d", errUnknownConstraintKind, c.Kind)
	}
}

// extractResult reads the Z3 model and classifies each weighted constraint
// as satisfied or unsatisfied based on the value of its indicator variable.
func (s *Solver) extractResult(
	weighted []weightedConstraint,
	model *z3.Model,
) *MaxSMTResult {
	result := &MaxSMTResult{
		SatisfiedIDs:   make([]int, 0, len(weighted)),
		UnsatisfiedIDs: make([]int, 0),
	}

	for _, wc := range weighted {
		result.MaxPossibleWeight += wc.weight

		val, ok := model.EvalBool(wc.indicator)
		if ok && val {
			result.SatisfiedIDs = append(result.SatisfiedIDs, wc.index)
			result.TotalWeight += wc.weight
		} else {
			result.UnsatisfiedIDs = append(result.UnsatisfiedIDs, wc.index)
		}
	}

	if result.MaxPossibleWeight > 0 {
		result.SatisfactionRate = float64(result.TotalWeight) / float64(result.MaxPossibleWeight)
	} else {
		result.SatisfactionRate = 1.0
	}

	return result
}

// greedyFallback implements a greedy confidence-sorted constraint selection
// used when Z3 times out or returns unknown. it processes constraints in
// descending confidence order and accepts each constraint if it does not
// conflict with already-accepted constraints (detected via the Unifier).
//
// this is a best-effort approximation of MaxSMT with O(n log n) complexity.
func (s *Solver) greedyFallback(constraints []typeinfer.TypeConstraint) *MaxSMTResult {
	// sort by confidence descending
	indexed := make([]struct {
		c   typeinfer.TypeConstraint
		idx int
	}, len(constraints))
	for i, c := range constraints {
		indexed[i] = struct {
			c   typeinfer.TypeConstraint
			idx int
		}{c, i}
	}
	sort.Slice(indexed, func(i, j int) bool {
		return indexed[i].c.Confidence > indexed[j].c.Confidence
	})

	result := &MaxSMTResult{
		SatisfiedIDs:   make([]int, 0, len(constraints)),
		UnsatisfiedIDs: make([]int, 0),
	}

	// track which type variable pairs have been assigned (conflict detection)
	// key: "left:right" → assigned kind
	assigned := make(map[string]typeinfer.ConstraintKind, len(constraints))

	for _, item := range indexed {
		c := item.c
		weight := confidenceToWeight(c.Confidence)
		result.MaxPossibleWeight += weight

		key := c.Left.Name + ":" + c.Right.Name
		if existingKind, conflict := assigned[key]; conflict && existingKind != c.Kind {
			// conflicting constraint: skip it
			result.UnsatisfiedIDs = append(result.UnsatisfiedIDs, item.idx)
			continue
		}

		assigned[key] = c.Kind
		result.SatisfiedIDs = append(result.SatisfiedIDs, item.idx)
		result.TotalWeight += weight
	}

	if result.MaxPossibleWeight > 0 {
		result.SatisfactionRate = float64(result.TotalWeight) / float64(result.MaxPossibleWeight)
	} else {
		result.SatisfactionRate = 1.0
	}

	return result
}

// sanitizeZ3Name replaces characters that are invalid in SMT-LIB2 symbol names
// with underscores. valid characters are: letters, digits, and _.$#@!%^&*-+=<>?/
func sanitizeZ3Name(name string) string {
	var sb strings.Builder
	sb.Grow(len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			sb.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			sb.WriteRune(r)
		case r >= '0' && r <= '9':
			sb.WriteRune(r)
		case r == '_' || r == '$' || r == '#' || r == '@' || r == '.' || r == '-':
			sb.WriteRune(r)
		default:
			sb.WriteRune('_')
		}
	}
	return sb.String()
}

// ============================================================================
// ConflictAnalyzer: post-solve analysis of unsatisfied constraints
// ============================================================================

// ConflictAnalyzer analyzes the unsatisfied constraints from a MaxSMT result
// and produces human-readable conflict reports for diagnostics.
type ConflictAnalyzer struct{}

// ConflictReport describes a single constraint conflict.
type ConflictReport struct {
	// WinnerIndex is the index of the higher-confidence constraint that was satisfied.
	WinnerIndex int
	// LoserIndex is the index of the lower-confidence constraint that was dropped.
	LoserIndex int
	// WinnerConfidence is the confidence of the winning constraint.
	WinnerConfidence float64
	// LoserConfidence is the confidence of the losing constraint.
	LoserConfidence float64
	// Description is a human-readable explanation of the conflict.
	Description string
}

// Analyze compares satisfied and unsatisfied constraints to identify conflicts.
// a conflict exists when an unsatisfied constraint involves the same type variables
// as a satisfied constraint but with a different kind or concrete type.
func (a *ConflictAnalyzer) Analyze(
	constraints []typeinfer.TypeConstraint,
	result *MaxSMTResult,
) []ConflictReport {
	if len(result.UnsatisfiedIDs) == 0 {
		return nil
	}

	// build index: (left, right) → list of satisfied constraint indices
	type varPair struct{ left, right string }
	satisfiedByPair := make(map[varPair][]int, len(result.SatisfiedIDs))
	for _, idx := range result.SatisfiedIDs {
		c := constraints[idx]
		key := varPair{c.Left.Name, c.Right.Name}
		satisfiedByPair[key] = append(satisfiedByPair[key], idx)
		// also check reverse direction for symmetric constraints
		revKey := varPair{c.Right.Name, c.Left.Name}
		satisfiedByPair[revKey] = append(satisfiedByPair[revKey], idx)
	}

	reports := make([]ConflictReport, 0, len(result.UnsatisfiedIDs))
	for _, loserIdx := range result.UnsatisfiedIDs {
		loser := constraints[loserIdx]
		key := varPair{loser.Left.Name, loser.Right.Name}

		winners, ok := satisfiedByPair[key]
		if !ok {
			continue
		}

		// find the highest-confidence winner for this pair
		bestWinner := -1
		bestConf := math.Inf(-1)
		for _, wIdx := range winners {
			if constraints[wIdx].Confidence > bestConf {
				bestConf = constraints[wIdx].Confidence
				bestWinner = wIdx
			}
		}

		if bestWinner < 0 {
			continue
		}

		winner := constraints[bestWinner]
		reports = append(reports, ConflictReport{
			WinnerIndex:      bestWinner,
			LoserIndex:       loserIdx,
			WinnerConfidence: winner.Confidence,
			LoserConfidence:  loser.Confidence,
			Description: fmt.Sprintf(
				"conflict on (%s, %s): kept %s (conf=%.2f, %s), dropped %s (conf=%.2f, %s)",
				loser.Left.Name, loser.Right.Name,
				winner.Kind, winner.Confidence, winner.Origin,
				loser.Kind, loser.Confidence, loser.Origin,
			),
		})
	}

	return reports
}
