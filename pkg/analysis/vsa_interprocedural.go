// Package analysis provides data flow analysis algorithms for the sedec decompiler.
package analysis

import (
	"errors"
	"fmt"
	"sync"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// sentinel errors for vsa analysis
var (
	errVSANilResult          = errors.New("vsa: nil result")
	errVSANonPositiveElement = errors.New("vsa: element size must be positive")
	errVSANilFunction        = errors.New("interprocedural vsa: nil function")
)

// ============================================================================
// Interprocedural VSA summary
// ============================================================================

// FunctionSummary captures the abstract input-output behaviour of a function
// for interprocedural VSA.  It is computed once per callee and reused at every
// call site, avoiding re-analysis of the callee body.
type FunctionSummary struct {
	// FunctionName is the callee identifier.
	FunctionName string

	// ParamValueSets maps parameter index → abstract value set at function entry.
	// index 0 is the first parameter.
	ParamValueSets map[int]*ValueSet

	// ReturnValueSet is the abstract value set of the return value.
	// nil means the function returns void or the return value is unknown (top).
	ReturnValueSet *ValueSet

	// ModifiedRegions lists memory regions that the function may write.
	// callers must invalidate these regions after the call.
	ModifiedRegions []MemoryRegion

	// Converged reports whether the summary reached a fixed point.
	Converged bool
}

// FunctionSummaryDB stores per-function summaries for interprocedural analysis.
// it is safe for concurrent reads after the analysis phase completes.
type FunctionSummaryDB struct {
	mu        sync.RWMutex
	summaries map[string]*FunctionSummary
}

// NewFunctionSummaryDB creates an empty summary database.
func NewFunctionSummaryDB() *FunctionSummaryDB {
	return &FunctionSummaryDB{
		summaries: make(map[string]*FunctionSummary),
	}
}

// Store inserts or replaces the summary for a function.
func (db *FunctionSummaryDB) Store(name string, s *FunctionSummary) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.summaries[name] = s
}

// Load retrieves the summary for a function.  Returns nil if not found.
func (db *FunctionSummaryDB) Load(name string) *FunctionSummary {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.summaries[name]
}

// Len returns the number of stored summaries.
func (db *FunctionSummaryDB) Len() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.summaries)
}

// ============================================================================
// Memory access disambiguation
// ============================================================================

// MemoryAccessKind classifies a memory access for disambiguation.
type MemoryAccessKind int

const (
	// MemAccessLoad is a read from memory.
	MemAccessLoad MemoryAccessKind = iota
	// MemAccessStore is a write to memory.
	MemAccessStore
)

// MemoryAccessInfo describes a single memory access with its abstract address.
type MemoryAccessInfo struct {
	// Kind is load or store.
	Kind MemoryAccessKind
	// AddressVS is the abstract value set of the address operand.
	AddressVS *ValueSet
	// Region is the inferred memory region (stack, heap, global, …).
	Region MemoryRegion
	// Size is the access size in bytes (1, 2, 4, 8, …).
	Size int
	// BlockID is the basic block containing this access.
	BlockID ir.BlockID
	// InstrIndex is the position within the block.
	InstrIndex int
}

// DisambiguationResult holds the outcome of memory access disambiguation.
type DisambiguationResult struct {
	// MayAlias reports whether two accesses may refer to the same location.
	MayAlias bool
	// MustAlias reports whether two accesses definitely refer to the same location.
	MustAlias bool
	// Confidence is a value in [0, 1] indicating analysis confidence.
	Confidence float64
}

// DisambiguateMemoryAccesses uses VSA results to determine whether two memory
// accesses may or must alias.
//
// the algorithm:
//  1. extract the abstract address value sets for both accesses.
//  2. if the regions are disjoint (stack vs heap, different stack frames), they
//     cannot alias → NoAlias with confidence 1.0.
//  3. if both addresses are singletons and equal → MustAlias.
//  4. if the strided intervals are disjoint → NoAlias.
//  5. otherwise → MayAlias with confidence proportional to interval overlap.
func DisambiguateMemoryAccesses(a, b *MemoryAccessInfo) DisambiguationResult {
	if a == nil || b == nil {
		return DisambiguationResult{MayAlias: true, Confidence: 0.0}
	}

	vsA := a.AddressVS
	vsB := b.AddressVS

	if vsA == nil || vsA.IsTop() || vsB == nil || vsB.IsTop() {
		// unknown addresses: conservatively may-alias
		return DisambiguationResult{MayAlias: true, Confidence: 0.0}
	}

	if vsA.IsBottom() || vsB.IsBottom() {
		// unreachable access: no alias
		return DisambiguationResult{MayAlias: false, MustAlias: false, Confidence: 1.0}
	}

	// check region disjointness first — cheapest check
	regionsA := vsA.Regions()
	regionsB := vsB.Regions()

	if len(regionsA) > 0 && len(regionsB) > 0 {
		if regionsDisjointSets(regionsA, regionsB) {
			return DisambiguationResult{MayAlias: false, MustAlias: false, Confidence: 1.0}
		}
	}

	// check interval overlap for each shared region
	anyOverlap := false
	mustOverlap := true

	for _, rA := range regionsA {
		siA := vsA.GetInterval(rA)
		if siA.IsEmpty() {
			continue
		}
		for _, rB := range regionsB {
			if rA != rB {
				continue
			}
			siB := vsB.GetInterval(rB)
			if siB.IsEmpty() {
				continue
			}
			// check if the access ranges overlap considering access sizes
			loA, hiA := siA.Lo, siA.Hi+int64(a.Size)-1
			loB, hiB := siB.Lo, siB.Hi+int64(b.Size)-1
			if loA <= hiB && loB <= hiA {
				anyOverlap = true
				// must-alias: both are singletons at the same address
				if siA.IsSingleton() && siB.IsSingleton() && siA.Lo == siB.Lo && a.Size == b.Size {
					return DisambiguationResult{MayAlias: true, MustAlias: true, Confidence: 1.0}
				}
			} else {
				mustOverlap = false
			}
		}
	}

	_ = mustOverlap

	if !anyOverlap {
		return DisambiguationResult{MayAlias: false, MustAlias: false, Confidence: 0.9}
	}

	return DisambiguationResult{MayAlias: true, MustAlias: false, Confidence: 0.5}
}

// regionsDisjointSets reports whether two sets of memory regions are completely
// disjoint (no region in common).
func regionsDisjointSets(a, b []MemoryRegion) bool {
	for _, rA := range a {
		for _, rB := range b {
			if rA == rB {
				return false
			}
			// same kind but different IDs are still disjoint
			if rA.Kind == rB.Kind && rA.ID != rB.ID {
				// different stack frames or heap objects: disjoint
				continue
			}
			if rA.Kind != rB.Kind && rA.Kind != RegionUnknown && rB.Kind != RegionUnknown {
				// different region kinds: disjoint
				continue
			}
			return false
		}
	}
	return true
}

// ============================================================================
// Array bounds inference
// ============================================================================

// ArrayBoundsInfo describes the inferred bounds of an array access.
type ArrayBoundsInfo struct {
	// BaseRegion is the memory region of the array base pointer.
	BaseRegion MemoryRegion
	// BaseOffset is the abstract value set of the base address.
	BaseOffset *ValueSet
	// IndexVS is the abstract value set of the array index.
	IndexVS *ValueSet
	// ElementSize is the size of each array element in bytes.
	ElementSize int64
	// InferredLo is the inferred minimum index (inclusive).
	InferredLo int64
	// InferredHi is the inferred maximum index (inclusive).
	InferredHi int64
	// AllocatedSize is the known allocation size in bytes (0 if unknown).
	AllocatedSize int64
}

// InferArrayBounds extracts array bounds from a VSA result for a given
// array index variable.
//
// the algorithm:
//  1. look up the strided interval for the index variable.
//  2. the lower bound is SI.Lo, the upper bound is SI.Hi.
//  3. if the allocation size is known, verify that Hi * elementSize < allocSize.
func InferArrayBounds(vsaResult *VSAResult, indexVar ir.Variable, elementSize int64) (*ArrayBoundsInfo, error) {
	if vsaResult == nil {
		return nil, errVSANilResult
	}
	if elementSize <= 0 {
		return nil, fmt.Errorf("%w: got %d", errVSANonPositiveElement, elementSize)
	}

	vs := vsaResult.GetValueSet(indexVar)
	if vs.IsTop() || vs.IsBottom() {
		return &ArrayBoundsInfo{
			IndexVS:     vs,
			ElementSize: elementSize,
			InferredLo:  0,
			InferredHi:  -1, // unknown
		}, nil
	}

	// find the tightest interval across all regions
	var tightestSI *StridedInterval
	var bestRegion MemoryRegion

	for _, region := range vs.Regions() {
		si := vs.GetInterval(region)
		if si.IsEmpty() {
			continue
		}
		if tightestSI == nil {
			cp := si
			tightestSI = &cp
			bestRegion = region
		} else {
			span := si.Hi - si.Lo
			bestSpan := tightestSI.Hi - tightestSI.Lo
			if span < bestSpan {
				cp := si
				tightestSI = &cp
				bestRegion = region
			}
		}
	}

	if tightestSI == nil {
		return &ArrayBoundsInfo{
			IndexVS:     vs,
			ElementSize: elementSize,
			InferredLo:  0,
			InferredHi:  -1,
		}, nil
	}

	return &ArrayBoundsInfo{
		BaseRegion:  bestRegion,
		IndexVS:     vs,
		ElementSize: elementSize,
		InferredLo:  tightestSI.Lo,
		InferredHi:  tightestSI.Hi,
	}, nil
}

// ============================================================================
// Buffer overflow detection
// ============================================================================

// BufferOverflowSeverity classifies the severity of a detected overflow.
type BufferOverflowSeverity int

const (
	// OverflowDefinite means the value set provably exceeds the allocation.
	OverflowDefinite BufferOverflowSeverity = iota
	// OverflowPossible means the value set may exceed the allocation.
	OverflowPossible
)

// overflow severity string constants
const (
	strDefinite = "definite"
	strPossible = "possible"
)

// String returns a human-readable severity label.
func (s BufferOverflowSeverity) String() string {
	switch s {
	case OverflowDefinite:
		return strDefinite
	case OverflowPossible:
		return strPossible
	default:
		return unknownRegion
	}
}

// BufferOverflowReport describes a detected buffer overflow.
type BufferOverflowReport struct {
	// Variable is the pointer or index variable involved.
	Variable ir.Variable
	// AccessVS is the abstract value set of the access address.
	AccessVS *ValueSet
	// AllocatedSize is the known allocation size in bytes.
	AllocatedSize int64
	// MaxAccessOffset is the maximum possible access offset.
	MaxAccessOffset int64
	// Severity indicates whether the overflow is definite or possible.
	Severity BufferOverflowSeverity
	// BlockID is the basic block where the overflow occurs.
	BlockID ir.BlockID
	// Message is a human-readable description.
	Message string
}

// BufferOverflowDetector checks VSA results against known allocation sizes to
// detect buffer overflows.
type BufferOverflowDetector struct {
	// AllocationSizes maps memory region → allocation size in bytes.
	// populated from malloc/alloca/stack frame analysis.
	AllocationSizes map[MemoryRegion]int64
}

// NewBufferOverflowDetector creates a detector with the given allocation map.
func NewBufferOverflowDetector(allocSizes map[MemoryRegion]int64) *BufferOverflowDetector {
	if allocSizes == nil {
		allocSizes = make(map[MemoryRegion]int64)
	}
	return &BufferOverflowDetector{AllocationSizes: allocSizes}
}

// CheckAccess tests whether a memory access described by accessVS may overflow
// the allocation for the given region.
//
// returns nil if no overflow is detected or the allocation size is unknown.
func (d *BufferOverflowDetector) CheckAccess(
	v ir.Variable,
	accessVS *ValueSet,
	region MemoryRegion,
	accessSize int,
	blockID ir.BlockID,
) *BufferOverflowReport {
	allocSize, known := d.AllocationSizes[region]
	if !known || allocSize <= 0 {
		return nil
	}

	if accessVS == nil || accessVS.IsBottom() {
		return nil
	}

	if accessVS.IsTop() {
		return &BufferOverflowReport{
			Variable:        v,
			AccessVS:        accessVS,
			AllocatedSize:   allocSize,
			MaxAccessOffset: -1, // unknown
			Severity:        OverflowPossible,
			BlockID:         blockID,
			Message: fmt.Sprintf(
				"variable %s: unknown address range may overflow allocation of %d bytes",
				v.String(), allocSize,
			),
		}
	}

	si := accessVS.GetInterval(region)
	if si.IsEmpty() {
		return nil
	}

	// maximum byte offset accessed = si.Hi + accessSize - 1
	maxOffset := si.Hi + int64(accessSize) - 1

	if maxOffset >= allocSize {
		severity := OverflowPossible
		if si.Lo >= allocSize {
			severity = OverflowDefinite
		}
		return &BufferOverflowReport{
			Variable:        v,
			AccessVS:        accessVS,
			AllocatedSize:   allocSize,
			MaxAccessOffset: maxOffset,
			Severity:        severity,
			BlockID:         blockID,
			Message: fmt.Sprintf(
				"variable %s: access offset [%d, %d] (size %d) may exceed allocation of %d bytes",
				v.String(), si.Lo, si.Hi, accessSize, allocSize,
			),
		}
	}

	return nil
}

// ScanFunction scans all memory accesses in a function for buffer overflows
// using the provided VSA result.
func (d *BufferOverflowDetector) ScanFunction(
	function *ir.Function,
	vsaResult *VSAResult,
) []*BufferOverflowReport {
	if function == nil || vsaResult == nil {
		return nil
	}

	var reports []*BufferOverflowReport

	for blockID, block := range function.Blocks {
		for _, instr := range block.Instructions {
			switch i := instr.(type) {
			case *ir.Load:
				addrVS := evalExpressionForVSA(i.Address, blockID, vsaResult)
				for _, region := range addrVS.Regions() {
					if r := d.CheckAccess(i.Dest, addrVS, region, sizeToBytes(i.Size), blockID); r != nil {
						reports = append(reports, r)
					}
				}
			case *ir.Store:
				addrVS := evalExpressionForVSA(i.Address, blockID, vsaResult)
				// use a synthetic variable name for the store address
				synth := ir.Variable{Name: "store_addr", Version: 0}
				for _, region := range addrVS.Regions() {
					if r := d.CheckAccess(synth, addrVS, region, sizeToBytes(i.Size), blockID); r != nil {
						reports = append(reports, r)
					}
				}
			}
		}
	}

	return reports
}

// evalExpressionForVSA evaluates an expression using the VSA result to obtain
// its abstract value set.  This is a lightweight helper that only handles
// variable lookups and constants; complex expressions return top.
func evalExpressionForVSA(expr ir.Expression, _ ir.BlockID, vsaResult *VSAResult) *ValueSet {
	if expr == nil {
		return NewValueSetTop()
	}
	switch e := expr.(type) {
	case *ir.VariableExpr:
		return vsaResult.GetValueSet(e.Var)
	case ir.VariableExpr:
		return vsaResult.GetValueSet(e.Var)
	case *ir.ConstantExpr:
		if ic, ok := e.Value.(ir.IntConstant); ok {
			return NewValueSetConstant(ic.Value)
		}
		return NewValueSetTop()
	case ir.ConstantExpr:
		if ic, ok := e.Value.(ir.IntConstant); ok {
			return NewValueSetConstant(ic.Value)
		}
		return NewValueSetTop()
	default:
		return NewValueSetTop()
	}
}

// sizeToBytes converts an ir.Size to a byte count.
func sizeToBytes(s ir.Size) int {
	return int(s)
}

// ============================================================================
// Interprocedural VSA analyzer
// ============================================================================

// InterproceduralVSAConfig controls the interprocedural analysis.
type InterproceduralVSAConfig struct {
	// MaxCallDepth limits recursive summary computation.
	MaxCallDepth int
	// WideningThreshold is passed to each per-function VSAAnalyzer.
	WideningThreshold int
	// MaxIterations is the per-function fixed-point iteration limit.
	MaxIterations int
}

// DefaultInterproceduralVSAConfig returns sensible defaults.
func DefaultInterproceduralVSAConfig() InterproceduralVSAConfig {
	return InterproceduralVSAConfig{
		MaxCallDepth:      8,
		WideningThreshold: 3,
		MaxIterations:     100,
	}
}

// InterproceduralVSAAnalyzer performs VSA across multiple functions using
// function summaries to model call effects.
type InterproceduralVSAAnalyzer struct {
	cfg    InterproceduralVSAConfig
	summDB *FunctionSummaryDB
}

// NewInterproceduralVSAAnalyzer creates a new interprocedural VSA analyzer.
func NewInterproceduralVSAAnalyzer(cfg InterproceduralVSAConfig) *InterproceduralVSAAnalyzer {
	return &InterproceduralVSAAnalyzer{
		cfg:    cfg,
		summDB: NewFunctionSummaryDB(),
	}
}

// SummaryDB returns the function summary database populated during analysis.
func (a *InterproceduralVSAAnalyzer) SummaryDB() *FunctionSummaryDB {
	return a.summDB
}

// AnalyzeFunction performs VSA for a single function, applying summaries from
// the database for any callees that have already been analysed.
//
// the caller is responsible for analysing callees before callers (bottom-up
// call graph order) to maximise precision.
func (a *InterproceduralVSAAnalyzer) AnalyzeFunction(
	function *ir.Function,
	cfgGraph *cfg.CFG,
	domTree *cfg.DominatorTree,
) (*VSAResult, error) {
	if function == nil {
		return nil, errVSANilFunction
	}

	// build a per-function analyzer with the configured parameters
	analyzer := NewVSAAnalyzer(function, cfgGraph, domTree)
	analyzer.SetWideningThreshold(a.cfg.WideningThreshold)

	// inject callee summaries into the analyzer so call instructions produce
	// more precise return value sets instead of top
	analyzer.summaryDB = a.summDB

	result, err := analyzer.Compute()
	if err != nil {
		return nil, fmt.Errorf("interprocedural vsa: function %q: %w", function.Name, err)
	}

	// build and store a summary for this function so callers can use it
	summary := a.buildSummary(function, result)
	a.summDB.Store(function.Name, summary)

	return result, nil
}

// buildSummary constructs a FunctionSummary from a completed VSA result.
func (a *InterproceduralVSAAnalyzer) buildSummary(
	function *ir.Function,
	result *VSAResult,
) *FunctionSummary {
	summary := &FunctionSummary{
		FunctionName:   function.Name,
		ParamValueSets: make(map[int]*ValueSet),
		Converged:      true,
	}

	// collect parameter value sets from the entry block state
	entryState, ok := result.BlockValueSets[function.EntryBlock]
	if ok {
		for i, paramType := range function.Signature.Parameters {
			// parameters are modelled as variables named "arg0", "arg1", …
			paramVar := ir.Variable{Name: fmt.Sprintf("arg%d", i), Version: 0, Type: paramType}
			if vs, found := entryState[paramVar.String()]; found {
				summary.ParamValueSets[i] = vs.Clone()
			} else {
				summary.ParamValueSets[i] = NewValueSetTop()
			}
		}
	}

	// collect return value set by joining all return instruction operands
	retVS := NewValueSetBottom()
	for _, block := range function.Blocks {
		for _, instr := range block.Instructions {
			if ret, ok := instr.(*ir.Return); ok && ret.Value != nil {
				vs := result.GetValueSet(*ret.Value)
				retVS = retVS.Join(vs)
			}
		}
	}

	if !retVS.IsBottom() {
		summary.ReturnValueSet = retVS
	}

	// conservatively mark all non-stack regions as potentially modified by stores
	modifiedSet := make(map[MemoryRegion]struct{})
	for _, block := range function.Blocks {
		for _, instr := range block.Instructions {
			if store, ok := instr.(*ir.Store); ok {
				addrVS := evalExpressionForVSA(store.Address, block.ID, result)
				for _, region := range addrVS.Regions() {
					if region.Kind != RegionStack {
						modifiedSet[region] = struct{}{}
					}
				}
			}
		}
	}
	for region := range modifiedSet {
		summary.ModifiedRegions = append(summary.ModifiedRegions, region)
	}

	return summary
}

// ============================================================================
// VSAAnalyzer extension: summary-aware call handling
// ============================================================================

// summaryDB is injected into VSAAnalyzer by InterproceduralVSAAnalyzer.
// it is nil for standalone (intraprocedural) analysis.
//
// we extend VSAAnalyzer with this field via a pointer receiver method that
// overrides the call transfer function when a summary is available.

// transferCallWithSummary applies a callee summary to a call instruction,
// producing a more precise return value set than top.
func transferCallWithSummary(
	call *ir.Call,
	state map[string]*ValueSet,
	result *VSAResult,
	db *FunctionSummaryDB,
) {
	if db == nil || call.Dest == nil {
		if call.Dest != nil {
			state[call.Dest.String()] = NewValueSetTop()
			result.ValueSets[call.Dest.String()] = NewValueSetTop()
		}
		return
	}

	// resolve callee name from the call target expression
	calleeName := resolveCalleeName(call.Target)
	if calleeName == "" {
		state[call.Dest.String()] = NewValueSetTop()
		result.ValueSets[call.Dest.String()] = NewValueSetTop()
		return
	}

	summary := db.Load(calleeName)
	if summary == nil || summary.ReturnValueSet == nil {
		state[call.Dest.String()] = NewValueSetTop()
		result.ValueSets[call.Dest.String()] = NewValueSetTop()
		return
	}

	retVS := summary.ReturnValueSet.Clone()
	state[call.Dest.String()] = retVS
	result.ValueSets[call.Dest.String()] = retVS
}

// resolveCalleeName extracts a function name from a call target expression.
// returns empty string if the target is indirect or unknown.
func resolveCalleeName(target ir.Expression) string {
	if target == nil {
		return ""
	}
	switch t := target.(type) {
	case *ir.VariableExpr:
		return t.Var.Name
	case ir.VariableExpr:
		return t.Var.Name
	default:
		return ""
	}
}

// ============================================================================
// Program-level interprocedural VSA
// ============================================================================

// FunctionInput bundles the artifacts needed to analyse a single function.
type FunctionInput struct {
	Function *ir.Function
	CFG      *cfg.CFG
	DomTree  *cfg.DominatorTree
}

// ProgramVSAResult holds the results of analysing an entire program.
type ProgramVSAResult struct {
	FunctionResults map[string]*VSAResult
	SummaryDB       *FunctionSummaryDB
}

// AnalyzeProgram performs interprocedural VSA over a set of functions in
// bottom-up call graph order.  Functions that appear earlier in the slice are
// analysed first; the caller is responsible for providing a topologically
// sorted order (callees before callers).
//
// If a function fails analysis it is skipped and its summary defaults to top
// for all return values, so callers conservatively lose precision rather than
// aborting the entire program analysis.
func (a *InterproceduralVSAAnalyzer) AnalyzeProgram(
	functions []FunctionInput,
) (*ProgramVSAResult, error) {
	progResult := &ProgramVSAResult{
		FunctionResults: make(map[string]*VSAResult, len(functions)),
		SummaryDB:       a.summDB,
	}

	for _, fi := range functions {
		if fi.Function == nil {
			continue
		}
		result, err := a.AnalyzeFunction(fi.Function, fi.CFG, fi.DomTree)
		if err != nil {
			a.summDB.Store(fi.Function.Name, &FunctionSummary{
				FunctionName:   fi.Function.Name,
				ParamValueSets: make(map[int]*ValueSet),
				ReturnValueSet: NewValueSetTop(),
				Converged:      false,
			})
			continue
		}
		progResult.FunctionResults[fi.Function.Name] = result
	}

	return progResult, nil
}

// ============================================================================
// VSAAnalyzer: summary-aware call handling
// ============================================================================

// transferCallInstruction is the summary-aware replacement for the call case
// in transferInstruction.  It is called from transferInstruction when a Call
// instruction is encountered.
func (a *VSAAnalyzer) transferCallInstruction(
	call *ir.Call,
	state map[string]*ValueSet,
	result *VSAResult,
) {
	transferCallWithSummary(call, state, result, a.summaryDB)
}
