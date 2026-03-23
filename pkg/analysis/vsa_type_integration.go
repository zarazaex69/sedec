package analysis

import (
	"fmt"
	"sort"

	"github.com/zarazaex69/sedec/pkg/ir"
	typeinfer "github.com/zarazaex69/sedec/pkg/types"
)

var (
	errVSATypeNilResult   = fmt.Errorf("vsa type integration: nil VSA result")
	errVSATypeNilFunction = fmt.Errorf("vsa type integration: nil function")
)

type MemoryAccessPattern struct {
	BaseVar    ir.Variable
	OffsetVS   *ValueSet
	AccessSize ir.Size
	IsStore    bool
	BlockID    ir.BlockID
}

type StridedAccessGroup struct {
	BaseVar     ir.Variable
	Stride      int64
	MinOffset   int64
	MaxOffset   int64
	ElementSize ir.Size
	Count       int
}

type FieldAccessGroup struct {
	BaseVar ir.Variable
	Offsets []FieldAccess
}

type FieldAccess struct {
	Offset     int64
	AccessSize ir.Size
}

type VSATypeIntegrationResult struct {
	Constraints    []typeinfer.TypeConstraint
	ArrayHints     []StridedAccessGroup
	StructHints    []FieldAccessGroup
	PointerTargets map[string]*ValueSet
}

func GenerateTypeConstraintsFromVSA(
	function *ir.Function,
	vsaResult *VSAResult,
) (*VSATypeIntegrationResult, error) {
	if function == nil {
		return nil, errVSATypeNilFunction
	}
	if vsaResult == nil {
		return nil, errVSATypeNilResult
	}

	result := &VSATypeIntegrationResult{
		PointerTargets: make(map[string]*ValueSet),
	}

	patterns := collectMemoryAccessPatterns(function, vsaResult)
	grouped := groupByBaseVariable(patterns)

	for baseKey, accesses := range grouped {
		stridedGroups := detectStridedAccesses(accesses)
		for _, sg := range stridedGroups {
			result.ArrayHints = append(result.ArrayHints, sg)
			result.Constraints = append(result.Constraints,
				buildArrayConstraints(baseKey, sg)...)
		}

		fieldGroup := detectFieldAccesses(accesses)
		if len(fieldGroup.Offsets) > 1 {
			result.StructHints = append(result.StructHints, fieldGroup)
			result.Constraints = append(result.Constraints,
				buildStructConstraints(baseKey, fieldGroup)...)
		}
	}

	collectPointerTargets(function, vsaResult, result)

	return result, nil
}

func collectMemoryAccessPatterns(
	function *ir.Function,
	vsaResult *VSAResult,
) []MemoryAccessPattern {
	var patterns []MemoryAccessPattern

	blockIDs := sortedFunctionBlockIDs(function)
	for _, blockID := range blockIDs {
		block := function.Blocks[blockID]
		if block == nil {
			continue
		}
		for _, instr := range block.Instructions {
			switch i := instr.(type) {
			case *ir.Load:
				if pat, ok := extractAccessPattern(i.Address, i.Dest, i.Size, false, blockID, vsaResult); ok {
					patterns = append(patterns, pat)
				}
			case *ir.Store:
				synth := ir.Variable{Name: "store_target", Version: 0}
				if pat, ok := extractAccessPattern(i.Address, synth, i.Size, true, blockID, vsaResult); ok {
					patterns = append(patterns, pat)
				}
			}
		}
	}

	return patterns
}

func extractAccessPattern(
	addrExpr ir.Expression,
	dest ir.Variable,
	size ir.Size,
	isStore bool,
	blockID ir.BlockID,
	vsaResult *VSAResult,
) (MemoryAccessPattern, bool) {
	baseVar, offsetVS := decomposeAddress(addrExpr, vsaResult)
	if baseVar.Name == "" {
		return MemoryAccessPattern{}, false
	}

	return MemoryAccessPattern{
		BaseVar:    baseVar,
		OffsetVS:   offsetVS,
		AccessSize: size,
		IsStore:    isStore,
		BlockID:    blockID,
	}, true
}
func decomposeAddress(expr ir.Expression, vsaResult *VSAResult) (ir.Variable, *ValueSet) {
	if expr == nil {
		return ir.Variable{}, nil
	}

	switch e := expr.(type) {
	case *ir.BinaryOp:
		if e.Op == ir.BinOpAdd {
			if varExpr, ok := e.Left.(*ir.VariableExpr); ok {
				offsetVS := evalExprForTypeIntegration(e.Right, vsaResult)
				return varExpr.Var, offsetVS
			}
			if varExpr, ok := e.Right.(*ir.VariableExpr); ok {
				offsetVS := evalExprForTypeIntegration(e.Left, vsaResult)
				return varExpr.Var, offsetVS
			}
		}
	case *ir.VariableExpr:
		return e.Var, NewValueSetConstant(0)
	}

	return ir.Variable{}, nil
}

func evalExprForTypeIntegration(expr ir.Expression, vsaResult *VSAResult) *ValueSet {
	if expr == nil {
		return NewValueSetTop()
	}
	switch e := expr.(type) {
	case *ir.ConstantExpr:
		if ic, ok := e.Value.(ir.IntConstant); ok {
			return NewValueSetConstant(ic.Value)
		}
		return NewValueSetTop()
	case *ir.VariableExpr:
		return vsaResult.GetValueSet(e.Var)
	case *ir.BinaryOp:
		left := evalExprForTypeIntegration(e.Left, vsaResult)
		right := evalExprForTypeIntegration(e.Right, vsaResult)
		switch e.Op {
		case ir.BinOpAdd:
			return AddValueSets(left, right)
		case ir.BinOpMul:
			return MulValueSets(left, right)
		case ir.BinOpShl:
			return ShlValueSets(left, right)
		default:
			return NewValueSetTop()
		}
	default:
		return NewValueSetTop()
	}
}

type accessPatternKey struct {
	name    string
	version int
}

func groupByBaseVariable(patterns []MemoryAccessPattern) map[accessPatternKey][]MemoryAccessPattern {
	groups := make(map[accessPatternKey][]MemoryAccessPattern)
	for _, p := range patterns {
		key := accessPatternKey{name: p.BaseVar.Name, version: p.BaseVar.Version}
		groups[key] = append(groups[key], p)
	}
	return groups
}

func detectStridedAccesses(accesses []MemoryAccessPattern) []StridedAccessGroup {
	var entries []offsetEntry
	for _, a := range accesses {
		if a.OffsetVS == nil || a.OffsetVS.IsTop() || a.OffsetVS.IsBottom() {
			continue
		}
		for _, region := range a.OffsetVS.Regions() {
			si := a.OffsetVS.GetInterval(region)
			if si.IsEmpty() {
				continue
			}
			if si.IsSingleton() {
				entries = append(entries, offsetEntry{offset: si.Lo, accessSize: a.AccessSize})
			} else if si.Stride > 0 {
				return []StridedAccessGroup{{
					BaseVar:     accesses[0].BaseVar,
					Stride:      si.Stride,
					MinOffset:   si.Lo,
					MaxOffset:   si.Hi,
					ElementSize: a.AccessSize,
					Count:       int((si.Hi-si.Lo)/si.Stride) + 1,
				}}
			}
		}
	}

	if len(entries) < 2 {
		return nil
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].offset < entries[j].offset
	})

	return detectStrideFromOffsets(accesses[0].BaseVar, entries)
}

func detectStrideFromOffsets(baseVar ir.Variable, entries []offsetEntry) []StridedAccessGroup {
	if len(entries) < 2 {
		return nil
	}

	diffs := make(map[int64]int)
	for i := 1; i < len(entries); i++ {
		d := entries[i].offset - entries[i-1].offset
		if d > 0 {
			diffs[d]++
		}
	}

	var bestStride int64
	bestCount := 0
	for stride, count := range diffs {
		if count > bestCount {
			bestStride = stride
			bestCount = count
		}
	}

	if bestStride <= 0 || bestCount < 1 {
		return nil
	}

	elemSize := entries[0].accessSize
	if int64(elemSize) > bestStride {
		elemSize = ir.Size(bestStride)
	}

	return []StridedAccessGroup{{
		BaseVar:     baseVar,
		Stride:      bestStride,
		MinOffset:   entries[0].offset,
		MaxOffset:   entries[len(entries)-1].offset,
		ElementSize: elemSize,
		Count:       len(entries),
	}}
}
func detectFieldAccesses(accesses []MemoryAccessPattern) FieldAccessGroup {
	seen := make(map[int64]ir.Size)
	var baseVar ir.Variable

	for _, a := range accesses {
		if baseVar.Name == "" {
			baseVar = a.BaseVar
		}
		if a.OffsetVS == nil || a.OffsetVS.IsTop() || a.OffsetVS.IsBottom() {
			continue
		}
		for _, region := range a.OffsetVS.Regions() {
			si := a.OffsetVS.GetInterval(region)
			if si.IsSingleton() {
				if existing, ok := seen[si.Lo]; !ok || a.AccessSize > existing {
					seen[si.Lo] = a.AccessSize
				}
			}
		}
	}

	var fields []FieldAccess
	for offset, size := range seen {
		fields = append(fields, FieldAccess{Offset: offset, AccessSize: size})
	}
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Offset < fields[j].Offset
	})

	return FieldAccessGroup{
		BaseVar: baseVar,
		Offsets: fields,
	}
}

func buildArrayConstraints(
	key accessPatternKey,
	sg StridedAccessGroup,
) []typeinfer.TypeConstraint {
	baseTV := typeinfer.TypeVar{Name: fmt.Sprintf("%s_%d", key.name, key.version)}

	elemType := sizeToIRType(sg.ElementSize)
	elemTV := typeinfer.TypeVar{
		Name:     fmt.Sprintf("$elem_%s_%d", key.name, key.version),
		Concrete: elemType,
	}

	return []typeinfer.TypeConstraint{
		{
			Kind:       typeinfer.ConstraintPointerTo,
			Left:       baseTV,
			Right:      typeinfer.TypeVar{Name: fmt.Sprintf("$arr_%s_%d", key.name, key.version)},
			Confidence: 0.7,
			Origin:     fmt.Sprintf("vsa: strided access stride=%d count=%d", sg.Stride, sg.Count),
		},
		{
			Kind:       typeinfer.ConstraintArrayElement,
			Left:       typeinfer.TypeVar{Name: fmt.Sprintf("$arr_%s_%d", key.name, key.version)},
			Right:      elemTV,
			Confidence: 0.7,
			Origin:     fmt.Sprintf("vsa: array element size=%d", sg.ElementSize),
		},
	}
}

func buildStructConstraints(
	key accessPatternKey,
	fg FieldAccessGroup,
) []typeinfer.TypeConstraint {
	baseTV := typeinfer.TypeVar{Name: fmt.Sprintf("%s_%d", key.name, key.version)}
	structTV := typeinfer.TypeVar{Name: fmt.Sprintf("$struct_%s_%d", key.name, key.version)}

	constraints := []typeinfer.TypeConstraint{
		{
			Kind:       typeinfer.ConstraintPointerTo,
			Left:       baseTV,
			Right:      structTV,
			Confidence: 0.6,
			Origin:     fmt.Sprintf("vsa: struct with %d fields", len(fg.Offsets)),
		},
	}

	for _, field := range fg.Offsets {
		fieldType := sizeToIRType(field.AccessSize)
		fieldTV := typeinfer.TypeVar{
			Name:     fmt.Sprintf("$field_%s_%d_off%d", key.name, key.version, field.Offset),
			Concrete: fieldType,
		}
		constraints = append(constraints, typeinfer.TypeConstraint{
			Kind:        typeinfer.ConstraintFieldAccess,
			Left:        structTV,
			Right:       fieldTV,
			FieldOffset: field.Offset,
			Confidence:  0.6,
			Origin:      fmt.Sprintf("vsa: field at offset %d size %d", field.Offset, field.AccessSize),
		})
	}

	return constraints
}

func sizeToIRType(s ir.Size) ir.Type {
	switch s {
	case ir.Size1:
		return ir.IntType{Width: ir.Size1, Signed: false}
	case ir.Size2:
		return ir.IntType{Width: ir.Size2, Signed: false}
	case ir.Size4:
		return ir.IntType{Width: ir.Size4, Signed: true}
	case ir.Size8:
		return ir.IntType{Width: ir.Size8, Signed: true}
	default:
		return ir.IntType{Width: s, Signed: false}
	}
}

func collectPointerTargets(
	function *ir.Function,
	vsaResult *VSAResult,
	result *VSATypeIntegrationResult,
) {
	for varKey, vs := range vsaResult.ValueSets {
		if vs == nil || vs.IsTop() || vs.IsBottom() {
			continue
		}
		hasPointerRegion := false
		for _, region := range vs.Regions() {
			if region.Kind == RegionHeap || region.Kind == RegionGlobal {
				hasPointerRegion = true
				break
			}
		}
		if hasPointerRegion {
			result.PointerTargets[varKey] = vs
		}
	}
}

func sortedFunctionBlockIDs(function *ir.Function) []ir.BlockID {
	ids := make([]ir.BlockID, 0, len(function.Blocks))
	for id := range function.Blocks {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return ids[i] < ids[j]
	})
	return ids
}

type offsetEntry struct {
	offset     int64
	accessSize ir.Size
}
