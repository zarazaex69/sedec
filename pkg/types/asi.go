package typeinfer

import (
	"fmt"
	"sort"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// AccessSize encodes the byte width of a single memory access.
type AccessSize int64

const (
	AccessSize1 AccessSize = 1 // 8-bit
	AccessSize2 AccessSize = 2 // 16-bit
	AccessSize4 AccessSize = 4 // 32-bit
	AccessSize8 AccessSize = 8 // 64-bit
)

// MemoryAccess describes a single observed memory access at base+offset.
type MemoryAccess struct {
	BaseVar    string     // name of the base pointer variable
	Offset     int64      // byte offset from base
	Size       AccessSize // access width in bytes
	IsWrite    bool       // true = store, false = load
	AccessType ir.Type    // concrete type observed at this access site
	Location   string     // instruction address for traceability
}

// StructField describes a recovered field within a reconstructed structure.
type StructField struct {
	Offset    int64
	Size      int64
	FieldType ir.Type
	Name      string // generated as field_0x%02x
}

// StructDef describes a fully reconstructed aggregate type.
type StructDef struct {
	Name      string
	Fields    []StructField
	Size      int64
	Alignment int64
	IsNested  bool // true when this struct appears as a field inside another
}

// ASIAnalyzer performs Aggregate Structure Identification over a set of
// observed memory accesses, recovering struct layouts and nested types.
type ASIAnalyzer struct {
	// nestedPatterns maps a canonical offset-signature to the struct name
	// that was already recovered with that pattern, enabling nesting detection.
	nestedPatterns map[string]string
}

// NewASIAnalyzer allocates a fresh ASIAnalyzer ready for use.
func NewASIAnalyzer() *ASIAnalyzer {
	return &ASIAnalyzer{
		nestedPatterns: make(map[string]string),
	}
}

// InferStructures is the primary entry point for ASI.
// It clusters the provided accesses by base variable, recovers one StructDef
// per cluster, detects nesting relationships between clusters, and returns
// the complete slice of recovered structures.
//
// Requirements: 11.9, 11.10, 11.11, 11.12, 11.13
func (a *ASIAnalyzer) InferStructures(accesses []MemoryAccess) []StructDef {
	if len(accesses) == 0 {
		return nil
	}

	// step 1: cluster accesses by base variable
	clusters := a.clusterByBase(accesses)

	// step 2: recover one StructDef per cluster
	defs := make([]StructDef, 0, len(clusters))
	// sort base names for deterministic output
	bases := make([]string, 0, len(clusters))
	for base := range clusters {
		bases = append(bases, base)
	}
	sort.Strings(bases)

	for _, base := range bases {
		def := a.recoverStruct(base, clusters[base])
		defs = append(defs, def)
	}

	// step 3: detect nesting - mark structs whose offset-signature matches
	// a sub-range of another struct's fields
	a.detectNesting(defs)

	return defs
}

// clusterByBase groups accesses into per-base-variable buckets.
func (a *ASIAnalyzer) clusterByBase(accesses []MemoryAccess) map[string][]MemoryAccess {
	clusters := make(map[string][]MemoryAccess, 8)
	for _, acc := range accesses {
		clusters[acc.BaseVar] = append(clusters[acc.BaseVar], acc)
	}
	return clusters
}

// recoverStruct builds a StructDef from the accesses belonging to one cluster.
func (a *ASIAnalyzer) recoverStruct(base string, accesses []MemoryAccess) StructDef {
	// collect unique offsets and pick the best type for each
	type fieldCandidate struct {
		size      int64
		fieldType ir.Type
	}
	byOffset := make(map[int64]fieldCandidate)

	for _, acc := range accesses {
		sz := int64(acc.Size)
		if sz <= 0 {
			sz = 1
		}
		existing, seen := byOffset[acc.Offset]
		if !seen {
			byOffset[acc.Offset] = fieldCandidate{
				size:      sz,
				fieldType: a.resolveFieldType(acc),
			}
			continue
		}
		// prefer larger size and more specific type
		if sz > existing.size {
			existing.size = sz
		}
		if existing.fieldType == nil && acc.AccessType != nil {
			existing.fieldType = a.resolveFieldType(acc)
		}
		byOffset[acc.Offset] = existing
	}

	// sort offsets for deterministic field ordering
	offsets := make([]int64, 0, len(byOffset))
	for off := range byOffset {
		offsets = append(offsets, off)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })

	// build fields
	fields := make([]StructField, 0, len(offsets))
	maxEnd := int64(0)
	maxAlign := int64(1)

	for _, off := range offsets {
		cand := byOffset[off]
		ft := cand.fieldType
		if ft == nil {
			ft = defaultTypeForSize(cand.size)
		}
		fieldAlign := alignmentForSize(cand.size)
		if fieldAlign > maxAlign {
			maxAlign = fieldAlign
		}
		end := off + cand.size
		if end > maxEnd {
			maxEnd = end
		}
		fields = append(fields, StructField{
			Offset:    off,
			Size:      cand.size,
			FieldType: ft,
			Name:      fmt.Sprintf("field_0x%02x", off),
		})
	}

	// align total size up to struct alignment
	structSize := alignUp(maxEnd, maxAlign)

	return StructDef{
		Name:      fmt.Sprintf("struct_%s", base),
		Fields:    fields,
		Size:      structSize,
		Alignment: maxAlign,
		IsNested:  false,
	}
}

// resolveFieldType picks the best ir.Type for a single access.
// if AccessType is set it is used directly; otherwise a type is synthesised
// from the access size.
func (a *ASIAnalyzer) resolveFieldType(acc MemoryAccess) ir.Type {
	if acc.AccessType != nil {
		return acc.AccessType
	}
	return defaultTypeForSize(int64(acc.Size))
}

// defaultTypeForSize returns an unsigned integer type matching the given byte width.
func defaultTypeForSize(size int64) ir.Type {
	switch size {
	case 1:
		return ir.IntType{Width: ir.Size1, Signed: false}
	case 2:
		return ir.IntType{Width: ir.Size2, Signed: false}
	case 4:
		return ir.IntType{Width: ir.Size4, Signed: false}
	case 8:
		return ir.IntType{Width: ir.Size8, Signed: false}
	default:
		// fall back to u8 for unusual sizes
		return ir.IntType{Width: ir.Size1, Signed: false}
	}
}

// alignmentForSize returns the natural alignment for a field of the given size.
func alignmentForSize(size int64) int64 {
	switch size {
	case 1:
		return 1
	case 2:
		return 2
	case 4:
		return 4
	case 8:
		return 8
	default:
		return 1
	}
}

// alignUp rounds v up to the nearest multiple of align (align must be > 0).
func alignUp(v, align int64) int64 {
	if align <= 0 {
		return v
	}
	return (v + align - 1) &^ (align - 1)
}

// offsetSignature produces a canonical string key representing the sorted set
// of field offsets in a StructDef. two structs with identical offset sets
// share the same signature and are candidates for nesting.
func offsetSignature(def StructDef) string {
	offsets := make([]int64, len(def.Fields))
	for i, f := range def.Fields {
		offsets[i] = f.Offset
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	sig := ""
	for _, o := range offsets {
		sig += fmt.Sprintf("%d,", o)
	}
	return sig
}

// detectNesting marks structs as nested when their offset-signature is a
// sub-signature of another struct in the same result set.
// a struct S is considered nested inside T when every offset in S also
// appears in T (S's fields are a subset of T's fields).
func (a *ASIAnalyzer) detectNesting(defs []StructDef) {
	// build offset sets for each def
	type offsetSet = map[int64]struct{}
	sets := make([]offsetSet, len(defs))
	for i, def := range defs {
		s := make(offsetSet, len(def.Fields))
		for _, f := range def.Fields {
			s[f.Offset] = struct{}{}
		}
		sets[i] = s
	}

	for i := range defs {
		if len(sets[i]) == 0 {
			continue
		}
		for j := range defs {
			if i == j {
				continue
			}
			if len(sets[i]) >= len(sets[j]) {
				continue
			}
			// check if every offset in defs[i] is present in defs[j]
			allPresent := true
			for off := range sets[i] {
				if _, ok := sets[j][off]; !ok {
					allPresent = false
					break
				}
			}
			if allPresent {
				defs[i].IsNested = true
				break
			}
		}
	}
}
