package idiom

// memcpy_memset.go recognizes compiler-generated memcpy and memset patterns.
//
// compilers inline memcpy/memset for small, constant-size copies/fills.
// the inlined forms vary by size and alignment:
//
// memset(dst, val, N) patterns:
//   - N=1:  store byte [dst], val
//   - N=2:  store word [dst], val | (val << 8)
//   - N=4:  store dword [dst], val * 0x01010101
//   - N=8:  store qword [dst], val * 0x0101010101010101
//   - N=16: two qword stores (or XMM store for val=0)
//   - N>16: rep stosb / rep stosd loop
//
// memcpy(dst, src, N) patterns:
//   - N=1:  t = load byte [src]; store byte [dst], t
//   - N=2:  t = load word [src]; store word [dst], t
//   - N=4:  t = load dword [src]; store dword [dst], t
//   - N=8:  t = load qword [src]; store qword [dst], t
//   - N=16: two load/store pairs (or XMM load+store)
//   - N>16: rep movsb / rep movsd loop
//
// detection strategy:
//   1. scan for consecutive load/store pairs with matching sizes and sequential offsets
//   2. scan for consecutive stores with identical values (memset)
//   3. verify total byte count matches a power-of-2 or common size
//   4. replace with a single Call instruction to memcpy/memset

import (
	"errors"
	"fmt"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ErrNilBlockMM is returned when a nil block is passed to memcpy/memset detection.
var ErrNilBlockMM = errors.New("memcpy/memset detection: nil block")

// MemPatternKind identifies whether the pattern is memcpy or memset.
type MemPatternKind int

const (
	// MemPatternMemset represents a memset pattern.
	MemPatternMemset MemPatternKind = iota
	// MemPatternMemcpy represents a memcpy pattern.
	MemPatternMemcpy
)

const (
	memsetName = "memset"
	memcpyName = "memcpy"
)

func (k MemPatternKind) String() string {
	if k == MemPatternMemset {
		return memsetName
	}
	return memcpyName
}

// MemPatternMatch describes a recognized memcpy or memset pattern.
type MemPatternMatch struct {
	// StartIdx is the index of the first instruction in the pattern.
	StartIdx int
	// EndIdx is the index of the last instruction in the pattern.
	EndIdx int
	// Kind is memcpy or memset.
	Kind MemPatternKind
	// DstBase is the destination base pointer variable.
	DstBase ir.Variable
	// SrcBase is the source base pointer variable (memcpy only).
	SrcBase ir.Variable
	// FillValue is the fill value expression (memset only).
	FillValue ir.Expression
	// ByteCount is the total number of bytes copied or filled.
	ByteCount int64
}

// String returns a human-readable description of the match.
func (m *MemPatternMatch) String() string {
	switch m.Kind {
	case MemPatternMemset:
		return fmt.Sprintf("memset(%s, %s, %d)  [instrs %d..%d]",
			m.DstBase.String(), m.FillValue, m.ByteCount, m.StartIdx, m.EndIdx)
	default:
		return fmt.Sprintf("memcpy(%s, %s, %d)  [instrs %d..%d]",
			m.DstBase.String(), m.SrcBase.String(), m.ByteCount, m.StartIdx, m.EndIdx)
	}
}

// minMemPatternBytes is the minimum byte count to recognize as a pattern.
// single-byte stores are too common to be meaningful.
const minMemPatternBytes = 2

// maxMemPatternInstructions is the maximum number of instructions to scan
// for a single pattern. beyond this, the compiler would use rep movs/stos.
const maxMemPatternInstructions = 32

// RecognizeMemPatterns scans a basic block for memcpy and memset patterns
// and returns all detected matches.
func RecognizeMemPatterns(block *ir.BasicBlock) ([]*MemPatternMatch, error) {
	if block == nil {
		return nil, ErrNilBlockMM
	}

	var matches []*MemPatternMatch
	consumed := make(map[int]bool)

	for i := 0; i < len(block.Instructions); i++ {
		if consumed[i] {
			continue
		}

		// try memset first (stores only)
		if m := tryMatchMemset(block.Instructions, i, consumed); m != nil {
			for j := m.StartIdx; j <= m.EndIdx; j++ {
				consumed[j] = true
			}
			matches = append(matches, m)
			i = m.EndIdx
			continue
		}

		// try memcpy (load/store pairs)
		if m := tryMatchMemcpy(block.Instructions, i, consumed); m != nil {
			for j := m.StartIdx; j <= m.EndIdx; j++ {
				consumed[j] = true
			}
			matches = append(matches, m)
			i = m.EndIdx
			continue
		}
	}

	return matches, nil
}

// tryMatchMemset detects a sequence of stores to consecutive addresses with
// the same value, indicating an inlined memset.
//
// pattern:
//
//	store [base + 0], val, size
//	store [base + size], val, size
//	store [base + 2*size], val, size
//	...
func tryMatchMemset(instrs []ir.IRInstruction, startIdx int, consumed map[int]bool) *MemPatternMatch {
	// first instruction must be a store
	s0, ok := instrs[startIdx].(*ir.Store)
	if !ok {
		return nil
	}

	// extract base pointer and initial offset from the address expression
	base0, offset0, hasBase := extractBaseAndOffset(s0.Address)
	if !hasBase {
		return nil
	}

	fillValue := s0.Value
	storeSize := int64(s0.Size)
	if storeSize == 0 {
		return nil
	}

	totalBytes := storeSize
	endIdx := startIdx

	// scan forward for consecutive stores with the same base, value, and stride
	for j := startIdx + 1; j < len(instrs) && j-startIdx < maxMemPatternInstructions; j++ {
		if consumed[j] {
			break
		}
		sj, ok := instrs[j].(*ir.Store)
		if !ok {
			break
		}

		baseJ, offsetJ, hasBaseJ := extractBaseAndOffset(sj.Address)
		if !hasBaseJ {
			break
		}

		// base pointer must be the same variable
		if baseJ.Name != base0.Name || baseJ.Version != base0.Version {
			break
		}

		// offset must be exactly base0 + totalBytes
		if offsetJ != offset0+totalBytes {
			break
		}

		// store size must match
		if int64(sj.Size) != storeSize {
			break
		}

		// fill value must be structurally identical
		if !expressionEqual(sj.Value, fillValue) {
			break
		}

		totalBytes += storeSize
		endIdx = j
	}

	if totalBytes < minMemPatternBytes {
		return nil
	}

	return &MemPatternMatch{
		StartIdx:  startIdx,
		EndIdx:    endIdx,
		Kind:      MemPatternMemset,
		DstBase:   base0,
		FillValue: fillValue,
		ByteCount: totalBytes,
	}
}

// tryMatchMemcpy detects a sequence of load/store pairs from consecutive source
// addresses to consecutive destination addresses, indicating an inlined memcpy.
//
// pattern:
//
//	t0 = load [src + 0], size
//	store [dst + 0], t0, size
//	t1 = load [src + size], size
//	store [dst + size], t1, size
//	...
//
// loadStorePair holds a matched load/store pair with extracted address info.
type loadStorePair struct {
	srcBase   ir.Variable
	srcOffset int64
	dstBase   ir.Variable
	dstOffset int64
	size      int64
}

// extractLoadStorePair validates that instrs[i] is a load and instrs[i+1] is a store
// of the loaded value, and extracts their base/offset addresses.
func extractLoadStorePair(instrs []ir.IRInstruction, i int) (loadStorePair, bool) {
	l, ok := instrs[i].(*ir.Load)
	if !ok {
		return loadStorePair{}, false
	}
	s, ok := instrs[i+1].(*ir.Store)
	if !ok {
		return loadStorePair{}, false
	}
	sv, svIsVar := extractVar(s.Value)
	if !svIsVar || sv.Name != l.Dest.Name || sv.Version != l.Dest.Version {
		return loadStorePair{}, false
	}
	srcBase, srcOffset, hasSrc := extractBaseAndOffset(l.Address)
	dstBase, dstOffset, hasDst := extractBaseAndOffset(s.Address)
	if !hasSrc || !hasDst {
		return loadStorePair{}, false
	}
	lSize := int64(l.Size)
	if lSize == 0 || int64(s.Size) != lSize {
		return loadStorePair{}, false
	}
	return loadStorePair{srcBase, srcOffset, dstBase, dstOffset, lSize}, true
}

func tryMatchMemcpy(instrs []ir.IRInstruction, startIdx int, consumed map[int]bool) *MemPatternMatch {
	if startIdx+1 >= len(instrs) {
		return nil
	}

	p0, ok := extractLoadStorePair(instrs, startIdx)
	if !ok {
		return nil
	}

	totalBytes := p0.size
	endIdx := startIdx + 1

	// scan forward for more load/store pairs
	for j := startIdx + 2; j+1 < len(instrs) && j-startIdx < maxMemPatternInstructions; j += 2 {
		if consumed[j] || consumed[j+1] {
			break
		}

		pj, ok := extractLoadStorePair(instrs, j)
		if !ok {
			break
		}

		// base pointers must match
		if pj.srcBase.Name != p0.srcBase.Name || pj.srcBase.Version != p0.srcBase.Version {
			break
		}
		if pj.dstBase.Name != p0.dstBase.Name || pj.dstBase.Version != p0.dstBase.Version {
			break
		}

		// offsets must be sequential
		if pj.srcOffset != p0.srcOffset+totalBytes || pj.dstOffset != p0.dstOffset+totalBytes {
			break
		}

		// sizes must match
		if pj.size != p0.size {
			break
		}

		totalBytes += p0.size
		endIdx = j + 1
	}

	if totalBytes < minMemPatternBytes {
		return nil
	}

	return &MemPatternMatch{
		StartIdx:  startIdx,
		EndIdx:    endIdx,
		Kind:      MemPatternMemcpy,
		DstBase:   p0.dstBase,
		SrcBase:   p0.srcBase,
		ByteCount: totalBytes,
	}
}

// extractBaseAndOffset extracts the base variable and constant offset from
// an address expression. handles the following forms:
//
//	var              → (var, 0)
//	var + const      → (var, const)
//	var - const      → (var, -const)
//	const + var      → (var, const)
func extractBaseAndOffset(addr ir.Expression) (base ir.Variable, offset int64, ok bool) {
	// simple variable: base = var, offset = 0
	if v, isVar := extractVar(addr); isVar {
		return v, 0, true
	}

	// binary expression: var ± const
	binop, isBinop := addr.(*ir.BinaryOp)
	if !isBinop {
		return ir.Variable{}, 0, false
	}

	switch binop.Op {
	case ir.BinOpAdd:
		if lv, lvIsVar := extractVar(binop.Left); lvIsVar {
			if rc, rcIsConst := extractIntConst(binop.Right); rcIsConst {
				return lv, int64(rc), true //nolint:gosec // safe: uint64->int64 offset cast
			}
		}
		if rv, rvIsVar := extractVar(binop.Right); rvIsVar {
			if lc, lcIsConst := extractIntConst(binop.Left); lcIsConst {
				return rv, int64(lc), true //nolint:gosec // safe: uint64->int64 offset cast
			}
		}
	case ir.BinOpSub:
		if lv, lvIsVar := extractVar(binop.Left); lvIsVar {
			if rc, rcIsConst := extractIntConst(binop.Right); rcIsConst {
				return lv, -int64(rc), true //nolint:gosec // safe: uint64->int64 offset cast
			}
		}
	default:
		// non-add/sub operators cannot form a base+offset address
	}

	return ir.Variable{}, 0, false
}

// expressionEqual performs structural equality comparison of two IR expressions.
// used to verify that memset fill values are identical across stores.
func expressionEqual(a, b ir.Expression) bool {
	switch ea := a.(type) {
	case *ir.ConstantExpr:
		eb, ok := b.(*ir.ConstantExpr)
		if !ok {
			return false
		}
		switch ca := ea.Value.(type) {
		case ir.IntConstant:
			cb, ok := eb.Value.(ir.IntConstant)
			return ok && ca.Value == cb.Value && ca.Width == cb.Width
		case ir.BoolConstant:
			cb, ok := eb.Value.(ir.BoolConstant)
			return ok && ca.Value == cb.Value
		default:
			return false
		}
	case *ir.VariableExpr:
		eb, ok := b.(*ir.VariableExpr)
		if !ok {
			return false
		}
		return ea.Var.Name == eb.Var.Name && ea.Var.Version == eb.Var.Version
	case *ir.BinaryOp:
		eb, ok := b.(*ir.BinaryOp)
		if !ok {
			return false
		}
		return ea.Op == eb.Op &&
			expressionEqual(ea.Left, eb.Left) &&
			expressionEqual(ea.Right, eb.Right)
	case *ir.UnaryOp:
		eb, ok := b.(*ir.UnaryOp)
		if !ok {
			return false
		}
		return ea.Op == eb.Op && expressionEqual(ea.Operand, eb.Operand)
	default:
		return false
	}
}

// RecognizeMemPatternsInFunction applies memcpy/memset recognition to every
// basic block in a function.
func RecognizeMemPatternsInFunction(fn *ir.Function) ([]*MemPatternMatch, error) {
	if fn == nil {
		return nil, ErrNilFunction
	}
	var all []*MemPatternMatch
	for _, block := range fn.Blocks {
		m, err := RecognizeMemPatterns(block)
		if err != nil {
			return nil, fmt.Errorf("memcpy/memset recognition: block %d: %w", block.ID, err)
		}
		all = append(all, m...)
	}
	return all, nil
}
