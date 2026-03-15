// Package typeinfer implements type inference using Hindley-Milner unification and MaxSMT.
// This file implements the cyclic feedback loop between Type_Inferencer and CFG_Builder.
// When type inference discovers function pointer arrays (vtables, handler tables, itabs),
// the discovered targets are fed back to CFG_Builder to resolve indirect jumps and expand
// the control flow graph. The loop iterates until convergence or the iteration limit.
//
// Requirements: 11.17, 11.18, 11.19, 11.20, 11.21, 11.22
package typeinfer

import (
	"fmt"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// defaultMaxIterations is the default cap on cyclic feedback iterations.
// prevents infinite loops on pathological inputs (e.g., deeply recursive vtables).
const defaultMaxIterations = 10

// ArrayKind classifies the semantic role of a discovered function pointer array.
// the kind drives how CFG_Builder interprets the resolved targets.
type ArrayKind int

const (
	// ArrayKindVTable represents a C++ virtual function table.
	// each element is a pointer to a virtual method implementation.
	ArrayKindVTable ArrayKind = iota

	// ArrayKindHandlerTable represents a switch jump table or callback array.
	// each element is a pointer to a case handler or registered callback.
	ArrayKindHandlerTable

	// ArrayKindJumpTable represents a compiler-generated computed-goto table.
	// each element is a direct jump target address.
	ArrayKindJumpTable

	// ArrayKindInterfaceTable represents a Go itab (interface method table).
	// each element is a pointer to an interface method implementation.
	ArrayKindInterfaceTable
)

// array kind string constants
const (
	strInterfaceTable = "interface_table"
)

// convergence reason string constants
const (
	strFixedPoint     = "fixed_point"
	strIterationLimit = "iteration_limit"
)

// String returns a human-readable name for the array kind.
func (k ArrayKind) String() string {
	switch k {
	case ArrayKindVTable:
		return "vtable"
	case ArrayKindHandlerTable:
		return "handler_table"
	case ArrayKindJumpTable:
		return "jump_table"
	case ArrayKindInterfaceTable:
		return strInterfaceTable
	default:
		return fmt.Sprintf("unknown_array_kind(%d)", int(k))
	}
}

// FunctionPointerArray describes a discovered array of function pointers.
// it is the primary output of DiscoverFunctionPointers and the primary input
// to CFG_Builder for indirect jump resolution.
type FunctionPointerArray struct {
	// Address is the virtual address of the array in the binary.
	Address ir.Address

	// ElementType is the inferred type of each element (typically a function pointer).
	ElementType ir.Type

	// Elements holds the resolved target addresses extracted from the array.
	// each element corresponds to one indirect jump target.
	Elements []ir.Address

	// Kind classifies the semantic role of this array.
	Kind ArrayKind

	// Confidence is the probability [0.0, 1.0] that this is a genuine function
	// pointer array and not a false positive from type inference.
	Confidence float64

	// Origin describes which analysis pass discovered this array (for provenance).
	Origin string
}

// FeedbackTarget bundles a single resolved indirect jump target with its
// provenance for transmission to CFG_Builder.
type FeedbackTarget struct {
	// JumpSite is the virtual address of the indirect jump instruction.
	JumpSite ir.Address

	// Target is the resolved destination address.
	Target ir.Address

	// Confidence is the confidence level for this resolution.
	Confidence float64

	// AnalysisPass identifies which pass produced this resolution.
	AnalysisPass string
}

// ConvergenceReason describes why the cyclic feedback loop terminated.
type ConvergenceReason int

const (
	// ConvergenceNoNewTargets means no new indirect jump targets were discovered
	// in the last iteration — the loop reached a true fixed point.
	ConvergenceNoNewTargets ConvergenceReason = iota

	// ConvergenceIterationLimit means the loop hit the maximum iteration cap
	// without reaching a fixed point. analysis results are still valid but
	// may be incomplete (some indirect jumps remain unresolved).
	ConvergenceIterationLimit
)

// String returns a human-readable convergence reason.
func (r ConvergenceReason) String() string {
	switch r {
	case ConvergenceNoNewTargets:
		return strFixedPoint
	case ConvergenceIterationLimit:
		return strIterationLimit
	default:
		return fmt.Sprintf("unknown(%d)", int(r))
	}
}

// FeedbackLoopResult summarises the outcome of a complete cyclic feedback run.
type FeedbackLoopResult struct {
	// IterationsRun is the number of iterations actually executed.
	IterationsRun int

	// TotalTargetsResolved is the cumulative count of indirect jump targets
	// added to the CFG across all iterations.
	TotalTargetsResolved int

	// ArraysDiscovered is the total number of function pointer arrays found.
	ArraysDiscovered int

	// Reason explains why the loop terminated.
	Reason ConvergenceReason
}

// String returns a compact summary of the feedback loop result.
func (r *FeedbackLoopResult) String() string {
	return fmt.Sprintf(
		"feedback loop: %d iterations, %d targets resolved, %d arrays, reason=%s",
		r.IterationsRun, r.TotalTargetsResolved, r.ArraysDiscovered, r.Reason,
	)
}

// CFGBuilderAdapter is the interface that CyclicFeedbackLoop requires from
// the CFG builder. it is satisfied by *cfg.Builder.
// using an interface here allows unit tests to inject a mock without
// depending on the full CFG construction machinery.
type CFGBuilderAdapter interface {
	// AddIndirectTargetWithProvenance adds a resolved indirect jump edge to the CFG.
	AddIndirectTargetWithProvenance(jumpSite, target disasm.Address, provenance *cfg.EdgeProvenance) error

	// GetUnresolvedIndirectJumps returns the addresses of all indirect jumps
	// that have not yet been fully resolved.
	GetUnresolvedIndirectJumps() []disasm.Address
}

// FunctionPointerDiscoverer is the interface that CyclicFeedbackLoop uses to
// obtain function pointer arrays from the type inference layer.
// it is satisfied by *FunctionPointerAnalyzer.
type FunctionPointerDiscoverer interface {
	// DiscoverFunctionPointers analyses the current type solution and returns
	// all function pointer arrays found in this iteration.
	DiscoverFunctionPointers(solution *TypeSolution) []FunctionPointerArray
}

// CyclicFeedbackLoop orchestrates the iterative refinement between
// Type_Inferencer and CFG_Builder.
//
// each iteration:
//  1. runs DiscoverFunctionPointers on the current TypeSolution
//  2. sends discovered targets to CFG_Builder via AddIndirectTargetWithProvenance
//  3. checks convergence: if no new targets were added, terminates
//  4. otherwise increments the iteration counter and repeats
//
// the loop is capped at MaxIterations (default: 10) to guarantee termination.
//
// Requirements: 11.17, 11.18, 11.19, 11.20, 11.21, 11.22
type CyclicFeedbackLoop struct {
	// discoverer provides function pointer arrays from type inference.
	discoverer FunctionPointerDiscoverer

	// builder receives resolved indirect jump targets.
	builder CFGBuilderAdapter

	// MaxIterations caps the number of refinement cycles.
	// zero means use defaultMaxIterations.
	MaxIterations int

	// resolvedTargets tracks all (jumpSite, target) pairs already sent to the
	// builder to avoid duplicate edge insertions across iterations.
	resolvedTargets map[resolvedKey]struct{}
}

// resolvedKey is the deduplication key for already-sent (jumpSite, target) pairs.
type resolvedKey struct {
	jumpSite ir.Address
	target   ir.Address
}

// NewCyclicFeedbackLoop creates a CyclicFeedbackLoop with the given discoverer
// and CFG builder adapter. maxIterations <= 0 uses defaultMaxIterations.
func NewCyclicFeedbackLoop(
	discoverer FunctionPointerDiscoverer,
	builder CFGBuilderAdapter,
	maxIterations int,
) *CyclicFeedbackLoop {
	if maxIterations <= 0 {
		maxIterations = defaultMaxIterations
	}
	return &CyclicFeedbackLoop{
		discoverer:      discoverer,
		builder:         builder,
		MaxIterations:   maxIterations,
		resolvedTargets: make(map[resolvedKey]struct{}),
	}
}

// Run executes the cyclic feedback loop starting from the provided TypeSolution.
// it returns a FeedbackLoopResult describing the outcome and an error if any
// individual target insertion fails (non-fatal: the loop continues after logging).
//
// the caller is responsible for re-running intraprocedural analysis (SSA, VSA,
// type constraint generation) after each iteration if needed; this function
// only handles the feedback transmission and convergence check.
func (l *CyclicFeedbackLoop) Run(solution *TypeSolution) (*FeedbackLoopResult, error) {
	result := &FeedbackLoopResult{}
	var lastErr error

	maxIter := l.MaxIterations
	if maxIter <= 0 {
		maxIter = defaultMaxIterations
	}

	for iter := 0; iter < maxIter; iter++ {
		result.IterationsRun++

		// discover function pointer arrays from current type solution
		arrays := l.discoverer.DiscoverFunctionPointers(solution)
		result.ArraysDiscovered += len(arrays)

		// transmit discovered targets to cfg builder
		newTargets := 0
		for _, arr := range arrays {
			for _, jumpSite := range l.jumpSitesForArray(arr) {
				for _, target := range arr.Elements {
					key := resolvedKey{jumpSite: jumpSite, target: target}
					if _, alreadySent := l.resolvedTargets[key]; alreadySent {
						continue
					}

					provenance := &cfg.EdgeProvenance{
						AnalysisPass: fmt.Sprintf("type_inference_iter_%d_%s", iter+1, arr.Kind),
						Confidence:   arr.Confidence,
						Metadata: map[string]any{
							"array_kind":    arr.Kind.String(),
							"array_address": arr.Address,
							"origin":        arr.Origin,
						},
					}

					// convert ir.Address to disasm.Address (both are uint64 aliases)
					if err := l.builder.AddIndirectTargetWithProvenance(
						disasm.Address(jumpSite),
						disasm.Address(target),
						provenance,
					); err != nil {
						// non-fatal: target may not yet be in the cfg (new code region)
						// record the error but continue processing remaining targets
						lastErr = fmt.Errorf("iter %d: add target 0x%x→0x%x: %w",
							iter+1, jumpSite, target, err)
						continue
					}

					l.resolvedTargets[key] = struct{}{}
					newTargets++
					result.TotalTargetsResolved++
				}
			}
		}

		// convergence check: no new targets added in this iteration
		if newTargets == 0 {
			result.Reason = ConvergenceNoNewTargets
			return result, lastErr
		}
	}

	result.Reason = ConvergenceIterationLimit
	return result, lastErr
}

// jumpSitesForArray returns the set of indirect jump sites that should be
// resolved using the targets in the given FunctionPointerArray.
//
// the mapping strategy depends on the array kind:
//   - VTable / InterfaceTable: the array address itself is the call site
//     (virtual dispatch loads from the vtable pointer)
//   - HandlerTable / JumpTable: each element index corresponds to a distinct
//     jump site; we use the array base address as a single representative
//     site because the CFG builder tracks all unresolved jumps by address
//
// in practice, the CFG builder's AddIndirectTargetWithProvenance will match
// the jump site to the correct UnresolvedIndirectJump entry.
func (l *CyclicFeedbackLoop) jumpSitesForArray(arr FunctionPointerArray) []ir.Address {
	// use the array's own address as the canonical jump site.
	// the CFG builder resolves the actual call/jmp instruction that loads
	// from this address via its addressToBlock map.
	return []ir.Address{arr.Address}
}

// ============================================================================
// FunctionPointerAnalyzer - discovers function pointer arrays from TypeSolution
// ============================================================================

// FunctionPointerAnalyzer inspects a TypeSolution to find variables whose
// inferred type is an array of function pointers, then classifies each array
// as a vtable, handler table, jump table, or Go interface table.
//
// Requirements: 11.17, 11.18, 11.19, 11.20
type FunctionPointerAnalyzer struct {
	// minArrayLen is the minimum number of elements required to classify
	// a pointer array as a function pointer array (avoids false positives
	// from single-element pointer variables).
	minArrayLen int

	// knownVTableAddresses is an optional set of addresses pre-identified
	// as vtable bases from relocation data (ground-truth axioms).
	// when an array's address matches a known vtable, confidence is boosted.
	knownVTableAddresses map[ir.Address]struct{}
}

// NewFunctionPointerAnalyzer creates an analyzer with sensible defaults.
// minArrayLen=2 avoids false positives from ordinary function pointers.
func NewFunctionPointerAnalyzer() *FunctionPointerAnalyzer {
	return &FunctionPointerAnalyzer{
		minArrayLen:          2,
		knownVTableAddresses: make(map[ir.Address]struct{}),
	}
}

// RegisterKnownVTable registers an address as a known vtable base from
// relocation data. this boosts confidence for arrays at that address.
func (a *FunctionPointerAnalyzer) RegisterKnownVTable(addr ir.Address) {
	a.knownVTableAddresses[addr] = struct{}{}
}

// DiscoverFunctionPointers satisfies FunctionPointerDiscoverer.
// it scans the TypeSolution for variables whose resolved type is an array
// of function pointers and returns a FunctionPointerArray for each one.
//
// detection heuristics (in priority order):
//  1. type is ir.ArrayType with ir.FunctionType element → function pointer array
//  2. type is ir.PointerType to ir.FunctionType → single function pointer (skip if < minArrayLen)
//  3. type is ir.ArrayType with ir.PointerType{Pointee: ir.FunctionType} element → array of func ptrs
//
// Requirements: 11.17, 11.18, 11.19, 11.20
func (a *FunctionPointerAnalyzer) DiscoverFunctionPointers(solution *TypeSolution) []FunctionPointerArray {
	if solution == nil {
		return nil
	}

	var arrays []FunctionPointerArray

	for varName, t := range solution.Types {
		if t == nil {
			continue
		}

		arr, ok := a.tryExtractFunctionPointerArray(varName, t)
		if !ok {
			continue
		}

		arrays = append(arrays, arr)
	}

	return arrays
}

// tryExtractFunctionPointerArray attempts to interpret a type as a function
// pointer array. returns the array descriptor and true on success.
func (a *FunctionPointerAnalyzer) tryExtractFunctionPointerArray(
	varName string,
	t ir.Type,
) (FunctionPointerArray, bool) {
	switch ct := t.(type) {
	case ir.ArrayType:
		return a.handleArrayType(varName, ct)

	case ir.PointerType:
		// pointer to function type: treat as single-element function pointer array
		// only if the variable name suggests an array (e.g., contains "vtable", "table")
		if isFunctionType(ct.Pointee) {
			if !looksLikeArrayVariable(varName) {
				return FunctionPointerArray{}, false
			}
			return FunctionPointerArray{
				Address:     0, // address unknown from type alone
				ElementType: ct,
				Elements:    nil, // elements resolved by VSA / relocation data
				Kind:        classifyByName(varName),
				Confidence:  0.4,
				Origin:      fmt.Sprintf("ptr_to_func_var %s", varName),
			}, true
		}
		return FunctionPointerArray{}, false

	default:
		return FunctionPointerArray{}, false
	}
}

// handleArrayType processes an ir.ArrayType to determine if it is a function
// pointer array and returns the corresponding FunctionPointerArray.
func (a *FunctionPointerAnalyzer) handleArrayType(
	varName string,
	ct ir.ArrayType,
) (FunctionPointerArray, bool) {
	// check element type: must be a function type or pointer-to-function
	elemIsFuncPtr := isFunctionType(ct.Element) || isFunctionPointerType(ct.Element)
	if !elemIsFuncPtr {
		return FunctionPointerArray{}, false
	}

	// enforce minimum array length to reduce false positives
	if ct.Length > 0 && int(ct.Length) < a.minArrayLen { //nolint:gosec // ct.Length is array length, bounded by practical limits
		return FunctionPointerArray{}, false
	}

	kind := classifyByName(varName)
	confidence := a.computeConfidence(0, kind)

	return FunctionPointerArray{
		Address:     0, // address resolved by caller from VSA / relocation data
		ElementType: ct.Element,
		Elements:    nil, // populated by resolveArrayElements
		Kind:        kind,
		Confidence:  confidence,
		Origin:      fmt.Sprintf("array_type_var %s (len=%d)", varName, ct.Length),
	}, true
}

// computeConfidence returns the confidence score for a discovered array.
// known vtable addresses (from relocation data) receive maximum confidence.
func (a *FunctionPointerAnalyzer) computeConfidence(addr ir.Address, kind ArrayKind) float64 {
	if _, isKnown := a.knownVTableAddresses[addr]; isKnown {
		return 1.0
	}
	switch kind {
	case ArrayKindVTable:
		return 0.85
	case ArrayKindInterfaceTable:
		return 0.80
	case ArrayKindHandlerTable:
		return 0.70
	case ArrayKindJumpTable:
		return 0.65
	default:
		return 0.50
	}
}

// isFunctionType returns true if t is an ir.FunctionType.
func isFunctionType(t ir.Type) bool {
	if t == nil {
		return false
	}
	_, ok := t.(ir.FunctionType)
	return ok
}

// isFunctionPointerType returns true if t is a pointer to a function type.
func isFunctionPointerType(t ir.Type) bool {
	if t == nil {
		return false
	}
	pt, ok := t.(ir.PointerType)
	if !ok {
		return false
	}
	return isFunctionType(pt.Pointee)
}

// looksLikeArrayVariable returns true if the variable name contains keywords
// that suggest it holds an array of function pointers.
func looksLikeArrayVariable(name string) bool {
	keywords := []string{
		"vtable", "vptr", "vtbl",
		"table", "handlers", "callbacks",
		"itab", "iface",
		"dispatch", "jump",
	}
	for _, kw := range keywords {
		if containsSubstring(name, kw) {
			return true
		}
	}
	return false
}

// classifyByName infers the ArrayKind from the variable name using keyword matching.
func classifyByName(name string) ArrayKind {
	switch {
	case containsAny(name, []string{"vtable", "vptr", "vtbl", "vmt"}):
		return ArrayKindVTable
	case containsAny(name, []string{"itab", "iface", "interface"}):
		return ArrayKindInterfaceTable
	case containsAny(name, []string{"jump", "computed", "goto"}):
		return ArrayKindJumpTable
	default:
		return ArrayKindHandlerTable
	}
}

// containsSubstring checks if s contains substr (case-insensitive).
func containsSubstring(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	sLower := toLower(s)
	subLower := toLower(substr)
	for i := 0; i <= len(sLower)-len(subLower); i++ {
		if sLower[i:i+len(subLower)] == subLower {
			return true
		}
	}
	return false
}

// containsAny returns true if s contains any of the given substrings.
func containsAny(s string, substrings []string) bool {
	for _, sub := range substrings {
		if containsSubstring(s, sub) {
			return true
		}
	}
	return false
}

// toLower converts ASCII uppercase letters to lowercase without importing strings.
// avoids a dependency on the strings package for this hot-path utility.
func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
