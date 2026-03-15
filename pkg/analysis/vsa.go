// Package analysis provides data flow analysis algorithms for the sedec decompiler.
package analysis

import (
	"fmt"
	"math"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// MemoryRegionKind classifies the abstract memory region a value belongs to.
// vsa partitions memory into disjoint regions to enable precise alias analysis.
type MemoryRegionKind int

const (
	// RegionGlobal represents statically allocated global/static variables.
	RegionGlobal MemoryRegionKind = iota
	// RegionStack represents stack-allocated local variables (rsp/rbp-relative).
	RegionStack
	// RegionHeap represents heap-allocated objects (malloc/new).
	RegionHeap
	// RegionCode represents the code segment (function pointers, vtables).
	RegionCode
	// RegionUnknown represents an unknown or merged memory region.
	RegionUnknown
)

// unknownRegion is the string representation for unknown/unresolvable values.
const unknownRegion = "unknown"

// lattice level string constants shared across analysis package
const (
	strTop    = "top"
	strBottom = "bottom"
)

// String returns a human-readable name for the memory region kind.
func (k MemoryRegionKind) String() string {
	switch k {
	case RegionGlobal:
		return "global"
	case RegionStack:
		return "stack"
	case RegionHeap:
		return "heap"
	case RegionCode:
		return "code"
	case RegionUnknown:
		return unknownRegion
	default:
		return unknownRegion
	}
}

// MemoryRegion identifies a disjoint abstract memory region.
// two values with different regions cannot alias each other.
type MemoryRegion struct {
	Kind MemoryRegionKind
	// ID disambiguates multiple regions of the same kind (e.g., different stack frames).
	ID uint64
}

// String returns a human-readable representation of the memory region.
func (r MemoryRegion) String() string {
	return fmt.Sprintf("%s#%d", r.Kind.String(), r.ID)
}

// StridedInterval represents a set of integer values as a strided interval.
// the set is { base + k*stride | 0 <= k <= (bound-base)/stride } where
// bound = base + stride * count.
//
// mathematical definition:
//
//	SI(stride, lo, hi) = { v | lo <= v <= hi, (v - lo) mod stride == 0 }
//
// special cases:
//   - stride == 0: singleton set { lo } (lo must equal hi)
//   - lo > hi: empty set (represented as EmptyInterval)
//   - lo == MinInt64, hi == MaxInt64, stride == 1: top (all integers)
//
// all arithmetic is performed with 64-bit signed semantics and wraps on overflow.
type StridedInterval struct {
	Stride int64 // step between consecutive values; 0 means singleton
	Lo     int64 // inclusive lower bound
	Hi     int64 // inclusive upper bound
}

// emptyStridedInterval is the canonical empty interval sentinel.
var emptyStridedInterval = StridedInterval{Stride: 1, Lo: 1, Hi: 0}

// topStridedInterval represents the set of all 64-bit integers.
var topStridedInterval = StridedInterval{Stride: 1, Lo: math.MinInt64, Hi: math.MaxInt64}

// NewSingleton creates a strided interval containing exactly one value.
func NewSingleton(v int64) StridedInterval {
	return StridedInterval{Stride: 0, Lo: v, Hi: v}
}

// NewStridedInterval creates a strided interval [lo, hi] with the given stride.
// panics if stride < 0 or if stride == 0 and lo != hi.
func NewStridedInterval(stride, lo, hi int64) StridedInterval {
	if stride < 0 {
		panic(fmt.Sprintf("vsa: negative stride %d", stride))
	}
	if stride == 0 && lo != hi {
		panic(fmt.Sprintf("vsa: stride 0 requires lo == hi, got lo=%d hi=%d", lo, hi))
	}
	if lo > hi {
		return emptyStridedInterval
	}
	return StridedInterval{Stride: stride, Lo: lo, Hi: hi}
}

// IsEmpty reports whether the interval contains no values.
func (si StridedInterval) IsEmpty() bool {
	return si.Lo > si.Hi
}

// IsSingleton reports whether the interval contains exactly one value.
func (si StridedInterval) IsSingleton() bool {
	return !si.IsEmpty() && si.Lo == si.Hi
}

// IsTop reports whether the interval represents all integers.
func (si StridedInterval) IsTop() bool {
	return si.Lo == math.MinInt64 && si.Hi == math.MaxInt64 && si.Stride == 1
}

// Contains reports whether value v is in the strided interval.
func (si StridedInterval) Contains(v int64) bool {
	if si.IsEmpty() {
		return false
	}
	if v < si.Lo || v > si.Hi {
		return false
	}
	if si.Stride == 0 {
		return v == si.Lo
	}
	return (v-si.Lo)%si.Stride == 0
}

// Size returns the number of elements in the strided interval.
// returns 0 for empty, 1 for singleton, math.MaxInt64 for top.
func (si StridedInterval) Size() int64 {
	if si.IsEmpty() {
		return 0
	}
	if si.Stride == 0 {
		return 1
	}
	return (si.Hi-si.Lo)/si.Stride + 1
}

// String returns a human-readable representation of the strided interval.
func (si StridedInterval) String() string {
	if si.IsEmpty() {
		return "empty"
	}
	if si.IsSingleton() {
		return fmt.Sprintf("{%d}", si.Lo)
	}
	if si.IsTop() {
		return strTop
	}
	if si.Stride == 1 {
		return fmt.Sprintf("[%d, %d]", si.Lo, si.Hi)
	}
	return fmt.Sprintf("[%d, %d, stride=%d]", si.Lo, si.Hi, si.Stride)
}

// Join computes the least upper bound (widening join) of two strided intervals.
// the result is the smallest strided interval containing all values from both.
//
// algorithm:
//  1. if either is empty, return the other
//  2. new lo = min(a.Lo, b.Lo), new hi = max(a.Hi, b.Hi)
//  3. new stride = gcd(a.Stride, b.Stride, |a.Lo - b.Lo|)
//     this ensures all values from both intervals are representable
func (si StridedInterval) Join(other StridedInterval) StridedInterval {
	if si.IsEmpty() {
		return other
	}
	if other.IsEmpty() {
		return si
	}

	newLo := si.Lo
	if other.Lo < newLo {
		newLo = other.Lo
	}
	newHi := si.Hi
	if other.Hi > newHi {
		newHi = other.Hi
	}

	// compute gcd of strides and the offset between lower bounds
	newStride := gcdInt64(si.Stride, other.Stride)
	diff := si.Lo - other.Lo
	if diff < 0 {
		diff = -diff
	}
	newStride = gcdInt64(newStride, diff)

	if newStride == 0 {
		newStride = 1
	}

	return StridedInterval{Stride: newStride, Lo: newLo, Hi: newHi}
}

// Meet computes the greatest lower bound (intersection) of two strided intervals.
// returns the empty interval if the intersection is empty.
func (si StridedInterval) Meet(other StridedInterval) StridedInterval {
	if si.IsEmpty() || other.IsEmpty() {
		return emptyStridedInterval
	}

	// intersection bounds
	newLo := si.Lo
	if other.Lo > newLo {
		newLo = other.Lo
	}
	newHi := si.Hi
	if other.Hi < newHi {
		newHi = other.Hi
	}

	if newLo > newHi {
		return emptyStridedInterval
	}

	// stride of intersection is lcm of the two strides
	// (values must satisfy both stride constraints)
	newStride := lcmInt64(si.Stride, other.Stride)
	if newStride == 0 {
		newStride = 1
	}

	// find the first value >= newLo that satisfies both stride constraints
	// for simplicity, use stride 1 if lcm would produce no valid values
	// in the range (conservative over-approximation)
	if newStride > 0 {
		// adjust lo to be aligned to newStride from si.Lo
		offset := (newLo - si.Lo) % newStride
		if offset != 0 {
			newLo += newStride - offset
		}
	}

	if newLo > newHi {
		return emptyStridedInterval
	}

	return StridedInterval{Stride: newStride, Lo: newLo, Hi: newHi}
}

// Widen applies widening to prevent infinite ascending chains in fixed-point iteration.
// if the new interval extends beyond the old one, widen to ±infinity on that side.
// this guarantees termination of the analysis.
func (si StridedInterval) Widen(next StridedInterval) StridedInterval {
	if si.IsEmpty() {
		return next
	}
	if next.IsEmpty() {
		return si
	}

	newLo := si.Lo
	newHi := si.Hi

	// widen lower bound downward if it decreased
	if next.Lo < si.Lo {
		newLo = math.MinInt64
	}
	// widen upper bound upward if it increased
	if next.Hi > si.Hi {
		newHi = math.MaxInt64
	}

	newStride := gcdInt64(si.Stride, next.Stride)
	if newStride == 0 {
		newStride = 1
	}

	return StridedInterval{Stride: newStride, Lo: newLo, Hi: newHi}
}

// ============================================================================
// Arithmetic on Strided Intervals
// ============================================================================

// Add computes the strided interval for (si + other).
// result stride = gcd(si.Stride, other.Stride).
// result bounds = [si.Lo + other.Lo, si.Hi + other.Hi] (with overflow clamping).
func (si StridedInterval) Add(other StridedInterval) StridedInterval {
	if si.IsEmpty() || other.IsEmpty() {
		return emptyStridedInterval
	}

	newLo := addSaturate(si.Lo, other.Lo)
	newHi := addSaturate(si.Hi, other.Hi)
	newStride := gcdInt64(si.Stride, other.Stride)
	if newStride == 0 {
		newStride = 1
	}

	if newLo > newHi {
		return topStridedInterval
	}
	return StridedInterval{Stride: newStride, Lo: newLo, Hi: newHi}
}

// Sub computes the strided interval for (si - other).
// result stride = gcd(si.Stride, other.Stride).
// result bounds = [si.Lo - other.Hi, si.Hi - other.Lo].
func (si StridedInterval) Sub(other StridedInterval) StridedInterval {
	if si.IsEmpty() || other.IsEmpty() {
		return emptyStridedInterval
	}

	newLo := subSaturate(si.Lo, other.Hi)
	newHi := subSaturate(si.Hi, other.Lo)
	newStride := gcdInt64(si.Stride, other.Stride)
	if newStride == 0 {
		newStride = 1
	}

	if newLo > newHi {
		return topStridedInterval
	}
	return StridedInterval{Stride: newStride, Lo: newLo, Hi: newHi}
}

// Mul computes the strided interval for (si * other).
// uses the four-corner method: evaluate all combinations of bounds.
func (si StridedInterval) Mul(other StridedInterval) StridedInterval {
	if si.IsEmpty() || other.IsEmpty() {
		return emptyStridedInterval
	}

	// four-corner method: min/max of all products of bounds
	corners := [4]int64{
		mulSaturate(si.Lo, other.Lo),
		mulSaturate(si.Lo, other.Hi),
		mulSaturate(si.Hi, other.Lo),
		mulSaturate(si.Hi, other.Hi),
	}

	newLo := corners[0]
	newHi := corners[0]
	for _, c := range corners[1:] {
		if c < newLo {
			newLo = c
		}
		if c > newHi {
			newHi = c
		}
	}

	// stride of product: if one operand is a singleton, stride scales
	newStride := int64(1)
	if other.IsSingleton() && si.Stride != 0 {
		newStride = mulSaturateAbs(si.Stride, absInt64(other.Lo))
	} else if si.IsSingleton() && other.Stride != 0 {
		newStride = mulSaturateAbs(other.Stride, absInt64(si.Lo))
	}
	if newStride <= 0 {
		newStride = 1
	}

	return StridedInterval{Stride: newStride, Lo: newLo, Hi: newHi}
}

// Neg computes the strided interval for (-si).
func (si StridedInterval) Neg() StridedInterval {
	if si.IsEmpty() {
		return emptyStridedInterval
	}
	// negate and swap bounds
	newLo := negSaturate(si.Hi)
	newHi := negSaturate(si.Lo)
	return StridedInterval{Stride: si.Stride, Lo: newLo, Hi: newHi}
}

// And computes a conservative over-approximation of (si & other) for bitwise AND.
// result is [0, min(si.Hi, other.Hi)] with stride 1 (sound over-approximation).
func (si StridedInterval) And(other StridedInterval) StridedInterval {
	if si.IsEmpty() || other.IsEmpty() {
		return emptyStridedInterval
	}
	// conservative: result is in [0, min(|a|, |b|)] for non-negative inputs
	// for general signed inputs, use [min(a.Lo,b.Lo,0), max(a.Hi,b.Hi)]
	newLo := int64(0)
	if si.Lo < 0 || other.Lo < 0 {
		newLo = minInt64(si.Lo, other.Lo)
	}
	newHi := minInt64(si.Hi, other.Hi)
	if newHi < 0 {
		newHi = 0
	}
	if newLo > newHi {
		newLo = newHi
	}
	return StridedInterval{Stride: 1, Lo: newLo, Hi: newHi}
}

// Or computes a conservative over-approximation of (si | other) for bitwise OR.
// result is [max(si.Lo, other.Lo), si.Hi | other.Hi] with stride 1.
func (si StridedInterval) Or(other StridedInterval) StridedInterval {
	if si.IsEmpty() || other.IsEmpty() {
		return emptyStridedInterval
	}
	newLo := maxInt64(si.Lo, other.Lo)
	// upper bound: bitwise or of upper bounds (conservative)
	newHi := bitwiseOrUpperBound(si.Hi, other.Hi)
	if newLo > newHi {
		newLo = newHi
	}
	return StridedInterval{Stride: 1, Lo: newLo, Hi: newHi}
}

// Shl computes a conservative over-approximation of (si << shift).
// shift must be a singleton interval representing the shift amount.
func (si StridedInterval) Shl(shift StridedInterval) StridedInterval {
	if si.IsEmpty() || shift.IsEmpty() {
		return emptyStridedInterval
	}
	if !shift.IsSingleton() {
		// non-constant shift: return top (sound over-approximation)
		return topStridedInterval
	}
	s := shift.Lo
	if s < 0 || s >= 64 {
		return topStridedInterval
	}
	newLo := si.Lo << uint(s)
	newHi := si.Hi << uint(s)
	newStride := si.Stride << uint(s)
	if newStride <= 0 {
		newStride = 1
	}
	return StridedInterval{Stride: newStride, Lo: newLo, Hi: newHi}
}

// Shr computes a conservative over-approximation of logical right shift (si >> shift).
func (si StridedInterval) Shr(shift StridedInterval) StridedInterval {
	if si.IsEmpty() || shift.IsEmpty() {
		return emptyStridedInterval
	}
	if !shift.IsSingleton() {
		return topStridedInterval
	}
	s := shift.Lo
	if s < 0 || s >= 64 {
		return topStridedInterval
	}
	// logical right shift: treat as unsigned
	newLo := int64(uint64(si.Lo) >> uint(s)) //nolint:gosec // intentional int64->uint64->int64 for logical shift
	newHi := int64(uint64(si.Hi) >> uint(s)) //nolint:gosec // intentional int64->uint64->int64 for logical shift
	if newLo > newHi {
		newLo, newHi = newHi, newLo
	}
	return StridedInterval{Stride: 1, Lo: newLo, Hi: newHi}
}

// ============================================================================
// ValueSet: abstract value combining region and strided interval
// ============================================================================

// ValueSet is the core abstract domain for Value Set Analysis.
// it represents the set of possible values a variable can hold at runtime.
//
// a ValueSet is a map from MemoryRegion to StridedInterval:
//   - for integer/pointer values: region = RegionUnknown, interval = numeric range
//   - for stack pointers: region = RegionStack, interval = offset range
//   - for global pointers: region = RegionGlobal, interval = address range
//   - for heap pointers: region = RegionHeap, interval = allocation offset range
//
// the "top" ValueSet contains a single entry: (RegionUnknown, topStridedInterval).
// the "bottom" (empty) ValueSet contains no entries.
type ValueSet struct {
	// regions maps each memory region to the strided interval of offsets/values
	// within that region. an empty map means bottom (no possible values).
	regions map[MemoryRegion]StridedInterval
}

// NewValueSetBottom creates the bottom element (empty set, no possible values).
func NewValueSetBottom() *ValueSet {
	return &ValueSet{regions: make(map[MemoryRegion]StridedInterval)}
}

// NewValueSetTop creates the top element (all possible values).
func NewValueSetTop() *ValueSet {
	vs := &ValueSet{regions: make(map[MemoryRegion]StridedInterval, 1)}
	vs.regions[MemoryRegion{Kind: RegionUnknown, ID: 0}] = topStridedInterval
	return vs
}

// NewValueSetConstant creates a ValueSet containing exactly one integer constant.
func NewValueSetConstant(v int64) *ValueSet {
	vs := &ValueSet{regions: make(map[MemoryRegion]StridedInterval, 1)}
	vs.regions[MemoryRegion{Kind: RegionUnknown, ID: 0}] = NewSingleton(v)
	return vs
}

// NewValueSetInterval creates a ValueSet for a numeric range with stride.
func NewValueSetInterval(stride, lo, hi int64) *ValueSet {
	vs := &ValueSet{regions: make(map[MemoryRegion]StridedInterval, 1)}
	vs.regions[MemoryRegion{Kind: RegionUnknown, ID: 0}] = NewStridedInterval(stride, lo, hi)
	return vs
}

// NewValueSetPointer creates a ValueSet for a pointer into a specific memory region.
// the interval represents the range of byte offsets within that region.
func NewValueSetPointer(region MemoryRegion, offsetStride, offsetLo, offsetHi int64) *ValueSet {
	vs := &ValueSet{regions: make(map[MemoryRegion]StridedInterval, 1)}
	vs.regions[region] = NewStridedInterval(offsetStride, offsetLo, offsetHi)
	return vs
}

// IsBottom reports whether the ValueSet is the bottom element (empty).
func (vs *ValueSet) IsBottom() bool {
	return len(vs.regions) == 0
}

// IsTop reports whether the ValueSet is the top element (all values).
func (vs *ValueSet) IsTop() bool {
	if len(vs.regions) != 1 {
		return false
	}
	for region, si := range vs.regions {
		return region.Kind == RegionUnknown && region.ID == 0 && si.IsTop()
	}
	return false
}

// GetInterval returns the strided interval for the given memory region.
// returns the empty interval if the region is not present.
func (vs *ValueSet) GetInterval(region MemoryRegion) StridedInterval {
	if si, ok := vs.regions[region]; ok {
		return si
	}
	return emptyStridedInterval
}

// SetInterval sets the strided interval for the given memory region.
func (vs *ValueSet) SetInterval(region MemoryRegion, si StridedInterval) {
	if si.IsEmpty() {
		delete(vs.regions, region)
		return
	}
	vs.regions[region] = si
}

// Regions returns all memory regions present in this ValueSet.
func (vs *ValueSet) Regions() []MemoryRegion {
	result := make([]MemoryRegion, 0, len(vs.regions))
	for r := range vs.regions {
		result = append(result, r)
	}
	return result
}

// Clone returns a deep copy of the ValueSet.
func (vs *ValueSet) Clone() *ValueSet {
	result := &ValueSet{regions: make(map[MemoryRegion]StridedInterval, len(vs.regions))}
	for r, si := range vs.regions {
		result.regions[r] = si
	}
	return result
}

// Equal reports whether two ValueSets are identical.
func (vs *ValueSet) Equal(other *ValueSet) bool {
	if len(vs.regions) != len(other.regions) {
		return false
	}
	for r, si := range vs.regions {
		otherSI, ok := other.regions[r]
		if !ok {
			return false
		}
		if si.Lo != otherSI.Lo || si.Hi != otherSI.Hi || si.Stride != otherSI.Stride {
			return false
		}
	}
	return true
}

// Join computes the least upper bound of two ValueSets.
// for each region present in either set, joins the corresponding intervals.
func (vs *ValueSet) Join(other *ValueSet) *ValueSet {
	result := &ValueSet{regions: make(map[MemoryRegion]StridedInterval, len(vs.regions)+len(other.regions))}

	// add all regions from vs
	for r, si := range vs.regions {
		result.regions[r] = si
	}

	// join with regions from other
	for r, otherSI := range other.regions {
		if existingSI, ok := result.regions[r]; ok {
			result.regions[r] = existingSI.Join(otherSI)
		} else {
			result.regions[r] = otherSI
		}
	}

	return result
}

// Widen applies widening to prevent infinite ascending chains.
// for each region, widens the interval if it has grown.
func (vs *ValueSet) Widen(next *ValueSet) *ValueSet {
	result := &ValueSet{regions: make(map[MemoryRegion]StridedInterval, len(next.regions))}

	for r, nextSI := range next.regions {
		if currentSI, ok := vs.regions[r]; ok {
			result.regions[r] = currentSI.Widen(nextSI)
		} else {
			result.regions[r] = nextSI
		}
	}

	return result
}

// String returns a human-readable representation of the ValueSet.
func (vs *ValueSet) String() string {
	if vs.IsBottom() {
		return strBottom
	}
	if vs.IsTop() {
		return strTop
	}
	result := "{"
	first := true
	for r, si := range vs.regions {
		if !first {
			result += ", "
		}
		result += fmt.Sprintf("%s: %s", r.String(), si.String())
		first = false
	}
	return result + "}"
}

// ============================================================================
// ValueSet arithmetic: propagation through IR operations
// ============================================================================

// AddValueSets computes the ValueSet for (a + b).
// only numeric (RegionUnknown) intervals are combined; pointer arithmetic
// adds a numeric offset to a pointer region.
func AddValueSets(a, b *ValueSet) *ValueSet {
	if a.IsBottom() || b.IsBottom() {
		return NewValueSetBottom()
	}
	if a.IsTop() || b.IsTop() {
		return NewValueSetTop()
	}

	result := NewValueSetBottom()

	// numeric + numeric
	aSI := a.GetInterval(MemoryRegion{Kind: RegionUnknown})
	bSI := b.GetInterval(MemoryRegion{Kind: RegionUnknown})

	if !aSI.IsEmpty() && !bSI.IsEmpty() {
		result.SetInterval(MemoryRegion{Kind: RegionUnknown}, aSI.Add(bSI))
	}

	// pointer + numeric offset: add numeric b to each pointer region in a
	numericB := b.GetInterval(MemoryRegion{Kind: RegionUnknown})
	for _, r := range a.Regions() {
		if r.Kind == RegionUnknown {
			continue
		}
		ptrSI := a.GetInterval(r)
		if !numericB.IsEmpty() {
			result.SetInterval(r, ptrSI.Add(numericB))
		} else {
			result.SetInterval(r, ptrSI)
		}
	}

	// numeric a + pointer b
	numericA := a.GetInterval(MemoryRegion{Kind: RegionUnknown})
	for _, r := range b.Regions() {
		if r.Kind == RegionUnknown {
			continue
		}
		ptrSI := b.GetInterval(r)
		if !numericA.IsEmpty() {
			existing := result.GetInterval(r)
			result.SetInterval(r, existing.Join(ptrSI.Add(numericA)))
		}
	}

	if result.IsBottom() {
		return NewValueSetTop()
	}
	return result
}

// SubValueSets computes the ValueSet for (a - b).
func SubValueSets(a, b *ValueSet) *ValueSet {
	if a.IsBottom() || b.IsBottom() {
		return NewValueSetBottom()
	}
	if a.IsTop() || b.IsTop() {
		return NewValueSetTop()
	}

	result := NewValueSetBottom()

	aSI := a.GetInterval(MemoryRegion{Kind: RegionUnknown})
	bSI := b.GetInterval(MemoryRegion{Kind: RegionUnknown})

	if !aSI.IsEmpty() && !bSI.IsEmpty() {
		result.SetInterval(MemoryRegion{Kind: RegionUnknown}, aSI.Sub(bSI))
	}

	// pointer - numeric offset
	numericB := b.GetInterval(MemoryRegion{Kind: RegionUnknown})
	for _, r := range a.Regions() {
		if r.Kind == RegionUnknown {
			continue
		}
		ptrSI := a.GetInterval(r)
		if !numericB.IsEmpty() {
			result.SetInterval(r, ptrSI.Sub(numericB))
		} else {
			result.SetInterval(r, ptrSI)
		}
	}

	if result.IsBottom() {
		return NewValueSetTop()
	}
	return result
}

// MulValueSets computes the ValueSet for (a * b).
// only numeric × numeric is precise; pointer × anything returns top.
func MulValueSets(a, b *ValueSet) *ValueSet {
	if a.IsBottom() || b.IsBottom() {
		return NewValueSetBottom()
	}
	if a.IsTop() || b.IsTop() {
		return NewValueSetTop()
	}

	aSI := a.GetInterval(MemoryRegion{Kind: RegionUnknown})
	bSI := b.GetInterval(MemoryRegion{Kind: RegionUnknown})

	if aSI.IsEmpty() || bSI.IsEmpty() {
		// pointer multiplication is unsound — return top
		return NewValueSetTop()
	}

	result := NewValueSetBottom()
	result.SetInterval(MemoryRegion{Kind: RegionUnknown}, aSI.Mul(bSI))
	return result
}

// NegValueSet computes the ValueSet for (-a).
func NegValueSet(a *ValueSet) *ValueSet {
	if a.IsBottom() {
		return NewValueSetBottom()
	}
	if a.IsTop() {
		return NewValueSetTop()
	}

	result := NewValueSetBottom()
	for _, r := range a.Regions() {
		si := a.GetInterval(r)
		result.SetInterval(r, si.Neg())
	}
	return result
}

// AndValueSets computes a conservative ValueSet for (a & b).
func AndValueSets(a, b *ValueSet) *ValueSet {
	if a.IsBottom() || b.IsBottom() {
		return NewValueSetBottom()
	}
	if a.IsTop() || b.IsTop() {
		return NewValueSetTop()
	}

	aSI := a.GetInterval(MemoryRegion{Kind: RegionUnknown})
	bSI := b.GetInterval(MemoryRegion{Kind: RegionUnknown})

	if aSI.IsEmpty() || bSI.IsEmpty() {
		return NewValueSetTop()
	}

	result := NewValueSetBottom()
	result.SetInterval(MemoryRegion{Kind: RegionUnknown}, aSI.And(bSI))
	return result
}

// OrValueSets computes a conservative ValueSet for (a | b).
func OrValueSets(a, b *ValueSet) *ValueSet {
	if a.IsBottom() || b.IsBottom() {
		return NewValueSetBottom()
	}
	if a.IsTop() || b.IsTop() {
		return NewValueSetTop()
	}

	aSI := a.GetInterval(MemoryRegion{Kind: RegionUnknown})
	bSI := b.GetInterval(MemoryRegion{Kind: RegionUnknown})

	if aSI.IsEmpty() || bSI.IsEmpty() {
		return NewValueSetTop()
	}

	result := NewValueSetBottom()
	result.SetInterval(MemoryRegion{Kind: RegionUnknown}, aSI.Or(bSI))
	return result
}

// ShlValueSets computes a conservative ValueSet for (a << b).
func ShlValueSets(a, b *ValueSet) *ValueSet {
	if a.IsBottom() || b.IsBottom() {
		return NewValueSetBottom()
	}
	if a.IsTop() || b.IsTop() {
		return NewValueSetTop()
	}

	aSI := a.GetInterval(MemoryRegion{Kind: RegionUnknown})
	bSI := b.GetInterval(MemoryRegion{Kind: RegionUnknown})

	if aSI.IsEmpty() || bSI.IsEmpty() {
		return NewValueSetTop()
	}

	result := NewValueSetBottom()
	result.SetInterval(MemoryRegion{Kind: RegionUnknown}, aSI.Shl(bSI))
	return result
}

// ShrValueSets computes a conservative ValueSet for logical right shift (a >> b).
func ShrValueSets(a, b *ValueSet) *ValueSet {
	if a.IsBottom() || b.IsBottom() {
		return NewValueSetBottom()
	}
	if a.IsTop() || b.IsTop() {
		return NewValueSetTop()
	}

	aSI := a.GetInterval(MemoryRegion{Kind: RegionUnknown})
	bSI := b.GetInterval(MemoryRegion{Kind: RegionUnknown})

	if aSI.IsEmpty() || bSI.IsEmpty() {
		return NewValueSetTop()
	}

	result := NewValueSetBottom()
	result.SetInterval(MemoryRegion{Kind: RegionUnknown}, aSI.Shr(bSI))
	return result
}

// ============================================================================
// VSA Analyzer: forward data flow over the IR function
// ============================================================================

// VSAResult holds the complete result of Value Set Analysis.
type VSAResult struct {
	// ValueSets maps each variable key (name_version) to its abstract ValueSet
	// at the point immediately after its definition.
	ValueSets map[string]*ValueSet

	// BlockValueSets maps each block id to the abstract state at block entry.
	// the state is a map from variable key to ValueSet.
	BlockValueSets map[ir.BlockID]map[string]*ValueSet
}

// GetValueSet returns the ValueSet for a variable, or top if unknown.
func (r *VSAResult) GetValueSet(v ir.Variable) *ValueSet {
	if vs, ok := r.ValueSets[v.String()]; ok {
		return vs
	}
	return NewValueSetTop()
}

// IsConstant reports whether a variable is known to be a single constant.
func (r *VSAResult) IsConstant(v ir.Variable) (int64, bool) {
	vs := r.GetValueSet(v)
	if vs.IsBottom() || vs.IsTop() {
		return 0, false
	}
	si := vs.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if si.IsSingleton() {
		return si.Lo, true
	}
	return 0, false
}

// VSAAnalyzer performs Value Set Analysis using forward abstract interpretation.
//
// the analysis computes, for each variable, the set of possible values it can
// hold at runtime. it uses strided intervals as the abstract domain and applies
// widening to guarantee termination.
//
// algorithm:
//  1. initialize all variables to bottom (no possible values yet).
//  2. seed the entry block with the initial abstract state.
//  3. process blocks in reverse postorder (forward data flow).
//  4. for each instruction, apply the abstract transfer function.
//  5. at join points (blocks with multiple predecessors), join abstract states.
//  6. apply widening after a configurable number of iterations to ensure termination.
//  7. terminate when the abstract state reaches a fixed point.
type VSAAnalyzer struct {
	function *ir.Function
	cfgGraph *cfg.CFG
	domTree  *cfg.DominatorTree

	// widenAfter is the number of iterations before widening is applied.
	// lower values converge faster but produce less precise results.
	widenAfter int

	// maxIterations is the hard limit on fixed-point iterations.
	maxIterations int

	// summaryDB is an optional interprocedural function summary database.
	// when non-nil, call instructions use callee summaries for return values.
	summaryDB *FunctionSummaryDB
}

// NewVSAAnalyzer creates a new VSA analyzer with default parameters.
func NewVSAAnalyzer(
	function *ir.Function,
	cfgGraph *cfg.CFG,
	domTree *cfg.DominatorTree,
) *VSAAnalyzer {
	return &VSAAnalyzer{
		function:      function,
		cfgGraph:      cfgGraph,
		domTree:       domTree,
		widenAfter:    3,
		maxIterations: 100,
	}
}

// SetWideningThreshold sets the number of iterations before widening is applied.
// must be >= 1. lower values trade precision for faster convergence.
func (a *VSAAnalyzer) SetWideningThreshold(n int) {
	if n < 1 {
		n = 1
	}
	a.widenAfter = n
}

// Compute performs VSA and returns the result.
// the function IR is not modified.
func (a *VSAAnalyzer) Compute() (*VSAResult, error) {
	if a.function == nil {
		return nil, fmt.Errorf("vsa: %w", ErrNilFunction)
	}
	if len(a.function.Blocks) == 0 {
		return nil, fmt.Errorf("vsa: function %q: %w", a.function.Name, ErrNoBlocks)
	}

	result := &VSAResult{
		ValueSets:      make(map[string]*ValueSet),
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	// compute reverse postorder for forward traversal
	rpo := a.reversePostOrder()

	// initialize all block abstract states to bottom
	for _, blockID := range rpo {
		result.BlockValueSets[blockID] = make(map[string]*ValueSet)
	}

	// iterative forward fixed-point computation with widening
	iterCount := make(map[ir.BlockID]int)
	changed := true
	for iteration := 0; changed && iteration < a.maxIterations; iteration++ {
		changed = false

		for _, blockID := range rpo {
			block, exists := a.function.Blocks[blockID]
			if !exists {
				continue
			}

			// compute join of all predecessor abstract states
			joinedState := a.joinPredecessorStates(blockID, block, result)

			// apply widening if this block has been visited enough times
			iterCount[blockID]++
			if iterCount[blockID] > a.widenAfter {
				joinedState = a.widenState(result.BlockValueSets[blockID], joinedState)
			}

			// propagate through each instruction in the block
			newState := a.propagateThroughBlock(block, joinedState, result)

			// check if the block's exit state changed
			if !abstractStatesEqual(result.BlockValueSets[blockID], newState) {
				result.BlockValueSets[blockID] = newState
				changed = true
			}
		}
	}

	// collect final per-variable value sets from block states
	for _, blockID := range rpo {
		for key, vs := range result.BlockValueSets[blockID] {
			if existing, ok := result.ValueSets[key]; ok {
				result.ValueSets[key] = existing.Join(vs)
			} else {
				result.ValueSets[key] = vs.Clone()
			}
		}
	}

	return result, nil
}

// joinPredecessorStates computes the join of all predecessor abstract states
// for a given block. returns an empty state for the entry block.
func (a *VSAAnalyzer) joinPredecessorStates(
	blockID ir.BlockID,
	block *ir.BasicBlock,
	result *VSAResult,
) map[string]*ValueSet {
	joined := make(map[string]*ValueSet)

	if blockID == a.function.EntryBlock {
		// entry block: all parameters are top (unknown inputs)
		return joined
	}

	for _, predID := range block.Predecessors {
		predState, ok := result.BlockValueSets[predID]
		if !ok {
			continue
		}
		for key, vs := range predState {
			if existing, ok := joined[key]; ok {
				joined[key] = existing.Join(vs)
			} else {
				joined[key] = vs.Clone()
			}
		}
	}

	return joined
}

// widenState applies widening between the current state and the new state.
// for each variable, widens the interval if it has grown.
func (a *VSAAnalyzer) widenState(
	current map[string]*ValueSet,
	next map[string]*ValueSet,
) map[string]*ValueSet {
	result := make(map[string]*ValueSet, len(next))
	for key, nextVS := range next {
		if currentVS, ok := current[key]; ok {
			result[key] = currentVS.Widen(nextVS)
		} else {
			result[key] = nextVS.Clone()
		}
	}
	return result
}

// propagateThroughBlock applies the abstract transfer function to each instruction
// in the block, updating the abstract state. returns the exit state.
func (a *VSAAnalyzer) propagateThroughBlock(
	block *ir.BasicBlock,
	entryState map[string]*ValueSet,
	result *VSAResult,
) map[string]*ValueSet {
	state := copyAbstractState(entryState)

	for _, instr := range block.Instructions {
		a.transferInstruction(instr, state, result)
	}

	return state
}

// transferInstruction applies the abstract transfer function for a single instruction.
// updates the abstract state in place.
func (a *VSAAnalyzer) transferInstruction(
	instr ir.IRInstruction,
	state map[string]*ValueSet,
	result *VSAResult,
) {
	switch i := instr.(type) {
	case *ir.Assign:
		vs := a.evalExpression(i.Source, state)
		state[i.Dest.String()] = vs
		result.ValueSets[i.Dest.String()] = vs

	case *ir.Load:
		// load from memory: result is top (unknown memory contents)
		// a more precise analysis would use memory SSA to track memory state
		state[i.Dest.String()] = NewValueSetTop()
		result.ValueSets[i.Dest.String()] = NewValueSetTop()

	case *ir.Call:
		// delegate to summary-aware handler; falls back to top when no summary exists
		a.transferCallInstruction(i, state, result)

	case *ir.Phi:
		// phi-node: join all source value sets
		joined := NewValueSetBottom()
		for _, src := range i.Sources {
			srcVS := a.lookupVar(src.Var, state)
			joined = joined.Join(srcVS)
		}
		state[i.Dest.String()] = joined
		result.ValueSets[i.Dest.String()] = joined

		// store, branch, jump, return: no variable definitions
	}
}

// evalExpression evaluates an expression in the current abstract state.
func (a *VSAAnalyzer) evalExpression(expr ir.Expression, state map[string]*ValueSet) *ValueSet {
	if expr == nil {
		return NewValueSetTop()
	}

	switch e := expr.(type) {
	case *ir.ConstantExpr:
		return a.evalConstant(e.Value)
	case ir.ConstantExpr:
		return a.evalConstant(e.Value)

	case *ir.VariableExpr:
		return a.lookupVar(e.Var, state)
	case ir.VariableExpr:
		return a.lookupVar(e.Var, state)

	case *ir.BinaryOp:
		return a.evalBinaryOp(e.Op, e.Left, e.Right, state)
	case ir.BinaryOp:
		return a.evalBinaryOp(e.Op, e.Left, e.Right, state)

	case *ir.UnaryOp:
		return a.evalUnaryOp(e.Op, e.Operand, state)
	case ir.UnaryOp:
		return a.evalUnaryOp(e.Op, e.Operand, state)

	case *ir.Cast:
		// cast: propagate the inner value set (conservative: ignore width truncation)
		return a.evalExpression(e.Expr, state)
	case ir.Cast:
		return a.evalExpression(e.Expr, state)

	default:
		return NewValueSetTop()
	}
}

// evalConstant converts an IR constant to a ValueSet.
func (a *VSAAnalyzer) evalConstant(c ir.Constant) *ValueSet {
	switch cv := c.(type) {
	case ir.IntConstant:
		return NewValueSetConstant(cv.Value)
	case ir.BoolConstant:
		if cv.Value {
			return NewValueSetConstant(1)
		}
		return NewValueSetConstant(0)
	case ir.FloatConstant:
		// float constants: use integer bits as approximation
		return NewValueSetTop()
	case ir.NullConstant:
		return NewValueSetConstant(0)
	default:
		return NewValueSetTop()
	}
}

// lookupVar returns the ValueSet for a variable from the abstract state.
// returns top if the variable is not yet in the state.
func (a *VSAAnalyzer) lookupVar(v ir.Variable, state map[string]*ValueSet) *ValueSet {
	if vs, ok := state[v.String()]; ok {
		return vs
	}
	return NewValueSetTop()
}

// evalBinaryOp evaluates a binary operation on abstract ValueSets.
func (a *VSAAnalyzer) evalBinaryOp(
	op ir.BinaryOperator,
	left, right ir.Expression,
	state map[string]*ValueSet,
) *ValueSet {
	lVS := a.evalExpression(left, state)
	rVS := a.evalExpression(right, state)

	switch op {
	case ir.BinOpAdd:
		return AddValueSets(lVS, rVS)
	case ir.BinOpSub:
		return SubValueSets(lVS, rVS)
	case ir.BinOpMul:
		return MulValueSets(lVS, rVS)
	case ir.BinOpAnd:
		return AndValueSets(lVS, rVS)
	case ir.BinOpOr:
		return OrValueSets(lVS, rVS)
	case ir.BinOpShl:
		return ShlValueSets(lVS, rVS)
	case ir.BinOpShr, ir.BinOpSar:
		return ShrValueSets(lVS, rVS)
	case ir.BinOpDiv, ir.BinOpUDiv:
		// division: conservative — return top unless divisor is a non-zero singleton
		rSI := rVS.GetInterval(MemoryRegion{Kind: RegionUnknown})
		if rSI.IsSingleton() && rSI.Lo != 0 {
			lSI := lVS.GetInterval(MemoryRegion{Kind: RegionUnknown})
			if !lSI.IsEmpty() {
				newLo := lSI.Lo / rSI.Lo
				newHi := lSI.Hi / rSI.Lo
				if newLo > newHi {
					newLo, newHi = newHi, newLo
				}
				result := NewValueSetBottom()
				result.SetInterval(MemoryRegion{Kind: RegionUnknown}, StridedInterval{Stride: 1, Lo: newLo, Hi: newHi})
				return result
			}
		}
		return NewValueSetTop()
	case ir.BinOpMod, ir.BinOpUMod:
		// modulo: result is in [0, divisor-1] for positive divisor
		rSI := rVS.GetInterval(MemoryRegion{Kind: RegionUnknown})
		if rSI.IsSingleton() && rSI.Lo > 0 {
			result := NewValueSetBottom()
			result.SetInterval(MemoryRegion{Kind: RegionUnknown}, StridedInterval{Stride: 1, Lo: 0, Hi: rSI.Lo - 1})
			return result
		}
		return NewValueSetTop()
	case ir.BinOpXor:
		// xor: conservative top
		return NewValueSetTop()
	case ir.BinOpEq, ir.BinOpNe, ir.BinOpLt, ir.BinOpLe, ir.BinOpGt, ir.BinOpGe,
		ir.BinOpULt, ir.BinOpULe, ir.BinOpUGt, ir.BinOpUGe,
		ir.BinOpLogicalAnd, ir.BinOpLogicalOr:
		// comparison/logical: result is boolean {0, 1}
		return NewValueSetInterval(1, 0, 1)
	default:
		return NewValueSetTop()
	}
}

// evalUnaryOp evaluates a unary operation on an abstract ValueSet.
func (a *VSAAnalyzer) evalUnaryOp(
	op ir.UnaryOperator,
	operand ir.Expression,
	state map[string]*ValueSet,
) *ValueSet {
	vs := a.evalExpression(operand, state)

	switch op {
	case ir.UnOpNeg:
		return NegValueSet(vs)
	case ir.UnOpNot:
		// bitwise not: conservative top
		return NewValueSetTop()
	case ir.UnOpLogicalNot:
		// logical not: result is boolean {0, 1}
		return NewValueSetInterval(1, 0, 1)
	default:
		return NewValueSetTop()
	}
}

// reversePostOrder computes a reverse postorder traversal of the cfg.
//
//nolint:dupl // similar to other analyzers
func (a *VSAAnalyzer) reversePostOrder() []ir.BlockID {
	visited := make(map[ir.BlockID]bool)
	postOrder := make([]ir.BlockID, 0, len(a.function.Blocks))

	var dfs func(ir.BlockID)
	dfs = func(blockID ir.BlockID) {
		if visited[blockID] {
			return
		}
		visited[blockID] = true

		block, exists := a.function.Blocks[blockID]
		if !exists {
			return
		}

		for _, succID := range block.Successors {
			dfs(succID)
		}

		postOrder = append(postOrder, blockID)
	}

	dfs(a.function.EntryBlock)

	for blockID := range a.function.Blocks {
		if !visited[blockID] {
			dfs(blockID)
		}
	}

	rpo := make([]ir.BlockID, len(postOrder))
	for i, id := range postOrder {
		rpo[len(postOrder)-1-i] = id
	}
	return rpo
}

// abstractStatesEqual reports whether two abstract states are identical.
func abstractStatesEqual(a, b map[string]*ValueSet) bool {
	if len(a) != len(b) {
		return false
	}
	for key, vsA := range a {
		vsB, ok := b[key]
		if !ok {
			return false
		}
		if !vsA.Equal(vsB) {
			return false
		}
	}
	return true
}

// copyAbstractState creates a shallow copy of an abstract state map.
func copyAbstractState(state map[string]*ValueSet) map[string]*ValueSet {
	result := make(map[string]*ValueSet, len(state))
	for key, vs := range state {
		result[key] = vs.Clone()
	}
	return result
}

// PerformVSA is the top-level entry point for Value Set Analysis.
func PerformVSA(
	function *ir.Function,
	cfgGraph *cfg.CFG,
	domTree *cfg.DominatorTree,
) (*VSAResult, error) {
	analyzer := NewVSAAnalyzer(function, cfgGraph, domTree)
	return analyzer.Compute()
}

// ============================================================================
// Integer arithmetic helpers with saturation semantics
// ============================================================================

// gcdInt64 computes the greatest common divisor of two non-negative int64 values.
// returns 0 if both inputs are 0.
func gcdInt64(a, b int64) int64 {
	if a < 0 {
		a = -a
	}
	if b < 0 {
		b = -b
	}
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// lcmInt64 computes the least common multiple of two non-negative int64 values.
// returns 0 if either input is 0. saturates to math.MaxInt64 on overflow.
func lcmInt64(a, b int64) int64 {
	if a == 0 || b == 0 {
		return 0
	}
	g := gcdInt64(a, b)
	if g == 0 {
		return 0
	}
	result := a / g
	// check for overflow before multiplying
	if result > math.MaxInt64/b {
		return math.MaxInt64
	}
	return result * b
}

// addSaturate adds two int64 values, saturating at ±math.MaxInt64 on overflow.
func addSaturate(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	if b < 0 && a < math.MinInt64-b {
		return math.MinInt64
	}
	return a + b
}

// subSaturate subtracts b from a, saturating at ±math.MaxInt64 on overflow.
func subSaturate(a, b int64) int64 {
	if b < 0 && a > math.MaxInt64+b {
		return math.MaxInt64
	}
	if b > 0 && a < math.MinInt64+b {
		return math.MinInt64
	}
	return a - b
}

// mulSaturate multiplies two int64 values, saturating at ±math.MaxInt64 on overflow.
func mulSaturate(a, b int64) int64 {
	if a == 0 || b == 0 {
		return 0
	}
	result := a * b
	// check for overflow: if result/a != b, overflow occurred
	if a != 0 && result/a != b {
		if (a > 0) == (b > 0) {
			return math.MaxInt64
		}
		return math.MinInt64
	}
	return result
}

// mulSaturateAbs multiplies two non-negative int64 values, saturating at math.MaxInt64.
func mulSaturateAbs(a, b int64) int64 {
	if a <= 0 || b <= 0 {
		return 0
	}
	if a > math.MaxInt64/b {
		return math.MaxInt64
	}
	return a * b
}

// negSaturate negates an int64, saturating at math.MaxInt64 for math.MinInt64.
func negSaturate(a int64) int64 {
	if a == math.MinInt64 {
		return math.MaxInt64
	}
	return -a
}

// absInt64 returns the absolute value of an int64, saturating at math.MaxInt64.
func absInt64(a int64) int64 {
	if a < 0 {
		return negSaturate(a)
	}
	return a
}

// minInt64 returns the minimum of two int64 values.
func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// maxInt64 returns the maximum of two int64 values.
func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// bitwiseOrUpperBound computes an upper bound for (a | b) using bit manipulation.
// for non-negative a and b: result <= a | b <= (a | b) rounded up to next power of 2 - 1.
func bitwiseOrUpperBound(a, b int64) int64 {
	if a < 0 || b < 0 {
		return math.MaxInt64
	}
	result := a | b
	// round up to next power of 2 minus 1 (fill all lower bits)
	result |= result >> 1
	result |= result >> 2
	result |= result >> 4
	result |= result >> 8
	result |= result >> 16
	result |= result >> 32
	return result
}
