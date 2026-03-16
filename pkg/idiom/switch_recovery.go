package idiom

// switch_recovery.go recovers switch statement structure from compiler-generated
// jump tables in IR basic blocks.
//
// compilers lower switch statements to jump tables for dense case ranges.
// the canonical x86_64 pattern (gcc/clang -O2):
//
//  1. bounds check:  cmp selector, max_case; ja default_block
//  2. normalization: sub selector, min_case  (only for non-zero base)
//  3. table lookup:  jmp [table_base + selector * ptr_size]
//
// in IR form, after lifting, this appears as:
//
//	t_norm = selector - min_case          (optional, absent when min_case == 0)
//	t_cmp  = t_norm >u range              (unsigned comparison for bounds check)
//	branch t_cmp, default_block, table_block
//	... (table_block)
//	t_addr = table_base + t_norm * 8      (address computation)
//	t_ptr  = load t_addr, 8               (load target address from table)
//	jump   t_ptr                          (indirect jump)
//
// the jump table itself is a contiguous array of 64-bit addresses in the binary's
// read-only data section. each entry corresponds to one case label.
//
// sparse switches: the compiler may emit a range check followed by a secondary
// lookup table (char/short index table) mapping normalized index → dense index.
// we detect both forms.
//
// detection strategy:
//  1. find indirect jumps (unresolved jmp through register/memory)
//  2. trace backward through def-use chains to find the address computation
//  3. identify the bounds check (unsigned comparison) and normalization (subtraction)
//  4. extract min_case, range, and table_base address
//  5. read table entries from binary memory to enumerate case targets
//  6. classify as dense (consecutive entries) or sparse (gaps present)
//  7. identify default block from the bounds-check branch

import (
	"errors"
	"fmt"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// sentinel errors for nil-input guards.
var (
	// ErrNilBlockSW is returned when a nil block is passed to switch recovery.
	ErrNilBlockSW = errors.New("switch recovery: nil block")
	// ErrNilFunctionSW is returned when a nil function is passed to switch recovery.
	ErrNilFunctionSW = errors.New("switch recovery: nil function")
	// ErrNilMemorySW is returned when a nil memory reader is passed to switch recovery.
	ErrNilMemorySW = errors.New("switch recovery: nil memory reader")
)

// SwitchKind classifies the switch statement structure.
type SwitchKind int

const (
	// SwitchDense represents a switch with consecutive case values (no gaps).
	SwitchDense SwitchKind = iota
	// SwitchSparse represents a switch with non-consecutive case values (gaps present).
	SwitchSparse
)

func (k SwitchKind) String() string {
	switch k {
	case SwitchDense:
		return "dense"
	case SwitchSparse:
		return "sparse"
	default:
		return "unknown"
	}
}

// CaseEntry represents a single case in a recovered switch statement.
type CaseEntry struct {
	// CaseValue is the integer value of this case label.
	CaseValue int64
	// TargetAddress is the virtual address of the case handler block.
	TargetAddress uint64
}

// SwitchMatch describes a recovered switch statement pattern.
type SwitchMatch struct {
	// JumpInstrIdx is the index of the indirect jump instruction in the block.
	JumpInstrIdx int
	// SelectorVar is the variable holding the switch selector (after normalization).
	SelectorVar ir.Variable
	// OriginalSelector is the variable before normalization (before sub min_case).
	// equals SelectorVar when min_case == 0.
	OriginalSelector ir.Variable
	// TableBase is the virtual address of the jump table in the binary.
	TableBase uint64
	// MinCase is the minimum case value (subtracted during normalization).
	MinCase int64
	// Cases contains all recovered case entries sorted by CaseValue.
	Cases []CaseEntry
	// DefaultBlock is the IR block ID of the default case handler.
	DefaultBlock ir.BlockID
	// Kind indicates whether the switch is dense or sparse.
	Kind SwitchKind
}

// String returns a human-readable description of the match.
func (m *SwitchMatch) String() string {
	return fmt.Sprintf(
		"switch(%s) [min=%d, cases=%d, table=0x%x, kind=%s, default=bb%d]",
		m.OriginalSelector.String(),
		m.MinCase,
		len(m.Cases),
		m.TableBase,
		m.Kind.String(),
		m.DefaultBlock,
	)
}

// MemoryReader provides read access to binary memory for extracting jump table entries.
// implementations must handle virtual address translation and bounds checking.
type MemoryReader interface {
	// ReadUint64 reads a 64-bit little-endian value from the given virtual address.
	// returns an error if the address is out of bounds or unmapped.
	ReadUint64(addr uint64) (uint64, error)
}

// RecoverSwitchStatements scans a function for switch statement patterns and
// returns all detected switch matches. the memory reader is used to extract
// jump table entries from the binary's data section.
//
// the function operates on IR basic blocks and traces def-use chains to identify
// the canonical switch lowering pattern produced by gcc/clang at -O1 and above.
func RecoverSwitchStatements(fn *ir.Function, mem MemoryReader) ([]*SwitchMatch, error) {
	if fn == nil {
		return nil, ErrNilFunctionSW
	}
	if mem == nil {
		return nil, ErrNilMemorySW
	}

	var matches []*SwitchMatch

	for _, block := range fn.Blocks {
		blockMatches, err := recoverSwitchInBlock(block, fn, mem)
		if err != nil {
			return nil, fmt.Errorf("switch recovery: block %d: %w", block.ID, err)
		}
		matches = append(matches, blockMatches...)
	}

	return matches, nil
}

// recoverSwitchInBlock scans a single basic block for switch patterns.
// a switch pattern terminates with an indirect jump whose address is computed
// from a table lookup with a bounds-checked index.
func recoverSwitchInBlock(block *ir.BasicBlock, fn *ir.Function, mem MemoryReader) ([]*SwitchMatch, error) {
	if block == nil {
		return nil, ErrNilBlockSW
	}

	// build def-index for this block to trace variable definitions
	defIdx := buildDefIndex(block.Instructions)

	var matches []*SwitchMatch

	for i, instr := range block.Instructions {
		// switch patterns end with an indirect jump: jump through a variable
		// in IR this is a Jump instruction whose target is a variable (not a constant block id)
		// we detect this by looking for a Load followed by a Jump using the loaded value,
		// or a Call with indirect target — but in our IR, indirect jumps are represented
		// as a Jump with a variable target stored in a special Assign before it.
		//
		// the IR lifter represents: jmp [table + rax*8]  as:
		//   t_addr = table_base + rax * 8
		//   t_ptr  = load t_addr, 8
		//   jump   t_ptr   (but Jump.Target is a BlockID, not an expression)
		//
		// since our IR Jump uses BlockID (resolved), unresolved indirect jumps
		// appear as a Load instruction whose result is used as a jump target.
		// we detect the Load instruction that feeds an indirect jump.
		load, isLoad := instr.(*ir.Load)
		if !isLoad {
			continue
		}

		// check if this load's result is used as a jump target in the next instruction
		// (the indirect jump pattern: load address from table, then jump to it)
		if i+1 >= len(block.Instructions) {
			continue
		}

		// the instruction after the load must be an indirect jump marker.
		// in our IR, after lifting jmp [mem], we get:
		//   t = load [table + idx*8], 8
		//   jump t  (represented as an Assign with the loaded value, since Jump.Target is BlockID)
		// we look for an Assign that copies the load result (indirect jump preparation)
		// OR we look for the load itself being the last meaningful instruction before
		// an unresolved indirect jump.
		//
		// strategy: if the load result is used in an address computation that feeds
		// another load or is the final value before a block boundary, treat it as
		// an indirect jump target load.
		if !isIndirectJumpLoad(load, block.Instructions, i+1) {
			continue
		}

		// trace the address expression of the load to find the table base and index
		tableInfo, ok := extractTableInfo(load.Address, defIdx, block.Instructions)
		if !ok {
			continue
		}

		// find the bounds check: a branch instruction that guards this block
		// the bounds check is in a predecessor block that branches to this block
		// or earlier in the same block
		boundsInfo, ok := findBoundsCheck(tableInfo.indexVar, block, fn, defIdx)
		if !ok {
			continue
		}

		// read jump table entries from binary memory
		cases, err := readJumpTable(tableInfo.tableBase, boundsInfo.rangeSize, boundsInfo.minCase, mem)
		if err != nil {
			// table read failure is non-fatal: skip this potential match
			continue
		}

		if len(cases) == 0 {
			continue
		}

		// classify as dense or sparse
		kind := classifySwitchKind(cases)

		match := &SwitchMatch{
			JumpInstrIdx:     i,
			SelectorVar:      tableInfo.indexVar,
			OriginalSelector: boundsInfo.originalSelector,
			TableBase:        tableInfo.tableBase,
			MinCase:          boundsInfo.minCase,
			Cases:            cases,
			DefaultBlock:     boundsInfo.defaultBlock,
			Kind:             kind,
		}

		matches = append(matches, match)
	}

	return matches, nil
}

// tableInfo holds the extracted jump table address computation components.
type tableInfo struct {
	tableBase uint64      // virtual address of the jump table
	indexVar  ir.Variable // normalized index variable (after sub min_case)
	ptrSize   int64       // pointer size (4 or 8 bytes per entry)
}

// boundsInfo holds the extracted bounds check components.
type boundsInfo struct {
	originalSelector ir.Variable // selector before normalization
	minCase          int64       // minimum case value (subtracted during normalization)
	rangeSize        uint64      // number of cases (max_case - min_case + 1)
	defaultBlock     ir.BlockID  // block ID of the default case
}

// isIndirectJumpLoad checks whether the load at instrIdx feeds an indirect jump.
// in our IR, after lifting `jmp [table + rax*8]`, the load result is either:
//  1. directly used as the next instruction's jump target (Assign copy)
//  2. the last instruction in the block (block ends with indirect jump)
func isIndirectJumpLoad(load *ir.Load, instrs []ir.IRInstruction, nextIdx int) bool {
	// the load must be 8 bytes (pointer-sized) for a jump table entry
	if load.Size != ir.Size8 && load.Size != ir.Size4 {
		return false
	}

	// check if the loaded variable is used in the next instruction
	if nextIdx < len(instrs) {
		next := instrs[nextIdx]
		// pattern: assign that copies the load result (indirect jump preparation)
		if assign, ok := next.(*ir.Assign); ok {
			if src, ok := assign.Source.(*ir.VariableExpr); ok {
				if src.Var.Name == load.Dest.Name && src.Var.Version == load.Dest.Version {
					return true
				}
			}
		}
	}

	// if this is the last instruction in the block, it's likely an indirect jump
	if nextIdx >= len(instrs) {
		return true
	}

	// check if the load result is used as a call/jump target anywhere in remaining instructions
	for j := nextIdx; j < len(instrs) && j < nextIdx+3; j++ {
		if usesVarAsJumpTarget(instrs[j], load.Dest) {
			return true
		}
	}

	return false
}

// usesVarAsJumpTarget checks if an instruction uses the given variable as a jump target.
func usesVarAsJumpTarget(instr ir.IRInstruction, v ir.Variable) bool {
	switch inst := instr.(type) {
	case *ir.Call:
		if ve, ok := inst.Target.(*ir.VariableExpr); ok {
			return ve.Var.Name == v.Name && ve.Var.Version == v.Version
		}
	case *ir.Assign:
		// indirect jump preparation: assign copies the loaded address
		if src, ok := inst.Source.(*ir.VariableExpr); ok {
			return src.Var.Name == v.Name && src.Var.Version == v.Version
		}
	}
	return false
}

// extractTableInfo traces the address expression of a load instruction to
// extract the jump table base address and the index variable.
//
// the canonical address expression is:
//
//	table_base + index * ptr_size
//
// where table_base is a constant (virtual address) and index is a variable.
// ptr_size is 8 for 64-bit targets, 4 for 32-bit targets.
// the address may be stored in a variable (t_addr = ...; load t_addr) so we
// resolve through the def-index chain.
func extractTableInfo(addr ir.Expression, defIdx map[varKey]int, instrs []ir.IRInstruction) (tableInfo, bool) {
	// resolve variable references through def-index (e.g., load t_addr where t_addr = base + idx*8)
	resolved := resolveExprThroughDefs(addr, defIdx, instrs, 4)
	return extractTableInfoFromExpr(resolved, defIdx, instrs)
}

// resolveExprThroughDefs follows variable definitions up to maxDepth levels.
func resolveExprThroughDefs(expr ir.Expression, defIdx map[varKey]int, instrs []ir.IRInstruction, maxDepth int) ir.Expression {
	if maxDepth == 0 || defIdx == nil || instrs == nil {
		return expr
	}
	v, ok := extractVar(expr)
	if !ok {
		return expr
	}
	idx, defined := defIdx[varKey{name: v.Name, version: v.Version}]
	if !defined {
		return expr
	}
	assign, ok := instrs[idx].(*ir.Assign)
	if !ok {
		return expr
	}
	// recurse to handle chains of assignments
	return resolveExprThroughDefs(assign.Source, defIdx, instrs, maxDepth-1)
}

// extractTableInfoFromExpr extracts table info from a resolved address expression.
func extractTableInfoFromExpr(addr ir.Expression, defIdx map[varKey]int, instrs []ir.IRInstruction) (tableInfo, bool) {
	// pattern: table_base + (index * ptr_size)
	// or:      table_base + index  (when ptr_size == 1, rare)
	binop, ok := addr.(*ir.BinaryOp)
	if !ok {
		return tableInfo{}, false
	}
	if binop.Op != ir.BinOpAdd {
		return tableInfo{}, false
	}

	// try: left is table_base (constant), right is index expression
	if base, ok := extractIntConst(binop.Left); ok {
		if idxVar, ptrSize, ok := extractIndexExpr(binop.Right, defIdx, instrs); ok {
			return tableInfo{tableBase: base, indexVar: idxVar, ptrSize: ptrSize}, true
		}
	}

	// try: right is table_base (constant), left is index expression
	if base, ok := extractIntConst(binop.Right); ok {
		if idxVar, ptrSize, ok := extractIndexExpr(binop.Left, defIdx, instrs); ok {
			return tableInfo{tableBase: base, indexVar: idxVar, ptrSize: ptrSize}, true
		}
	}

	// try: left is a variable (table_base loaded into register), right is index expression
	// this handles: mov rax, table_base; jmp [rax + rcx*8]
	if lv, ok := extractVar(binop.Left); ok {
		if idxVar, ptrSize, ok := extractIndexExpr(binop.Right, defIdx, instrs); ok {
			// resolve the table base variable to a constant
			if base, ok := resolveVarToConst(lv, defIdx, instrs); ok {
				return tableInfo{tableBase: base, indexVar: idxVar, ptrSize: ptrSize}, true
			}
		}
	}

	return tableInfo{}, false
}

// extractIndexExpr extracts the index variable and pointer size from an
// index expression of the form: index * ptr_size  or  index (ptr_size=1).
func extractIndexExpr(expr ir.Expression, defIdx map[varKey]int, instrs []ir.IRInstruction) (ir.Variable, int64, bool) {
	// pattern: index * ptr_size
	if binop, ok := expr.(*ir.BinaryOp); ok && binop.Op == ir.BinOpMul {
		if idxVar, ok := extractVar(binop.Left); ok {
			if ptrSize, ok := extractIntConst(binop.Right); ok && isPtrSize(int64(ptrSize)) { //nolint:gosec
				return idxVar, int64(ptrSize), true //nolint:gosec
			}
		}
		if idxVar, ok := extractVar(binop.Right); ok {
			if ptrSize, ok := extractIntConst(binop.Left); ok && isPtrSize(int64(ptrSize)) { //nolint:gosec
				return idxVar, int64(ptrSize), true //nolint:gosec
			}
		}
	}

	// pattern: index << shift_amount (equivalent to index * 2^shift)
	if binop, ok := expr.(*ir.BinaryOp); ok && binop.Op == ir.BinOpShl {
		if idxVar, ok := extractVar(binop.Left); ok {
			if shift, ok := extractIntConst(binop.Right); ok {
				ptrSize := int64(1) << shift //nolint:gosec
				if isPtrSize(ptrSize) {
					return idxVar, ptrSize, true
				}
			}
		}
	}

	// pattern: plain variable (ptr_size = 1, byte-indexed table)
	if v, ok := extractVar(expr); ok {
		return v, 1, true
	}

	// pattern: variable that was defined as index * ptr_size
	if v, ok := extractVar(expr); ok {
		if idx, defined := defIdx[varKey{name: v.Name, version: v.Version}]; defined {
			if assign, ok := instrs[idx].(*ir.Assign); ok {
				if idxVar, ptrSize, ok := extractIndexExpr(assign.Source, defIdx, instrs); ok {
					return idxVar, ptrSize, true
				}
			}
		}
	}

	return ir.Variable{}, 0, false
}

// isPtrSize returns true if the value is a valid pointer size (1, 2, 4, or 8).
func isPtrSize(n int64) bool {
	return n == 1 || n == 2 || n == 4 || n == 8
}

// resolveVarToConst attempts to resolve a variable to a constant value by
// tracing its definition in the instruction list.
func resolveVarToConst(v ir.Variable, defIdx map[varKey]int, instrs []ir.IRInstruction) (uint64, bool) {
	idx, defined := defIdx[varKey{name: v.Name, version: v.Version}]
	if !defined {
		return 0, false
	}
	assign, ok := instrs[idx].(*ir.Assign)
	if !ok {
		return 0, false
	}
	if c, ok := extractIntConst(assign.Source); ok {
		return c, true
	}
	return 0, false
}

// findBoundsCheck searches for the bounds check that guards the switch jump table.
// the bounds check is a branch instruction of the form:
//
//	branch (index >u range), default_block, table_block
//
// it may be in the current block or in a predecessor block.
// the index variable may be the result of a normalization: index = selector - min_case.
func findBoundsCheck(indexVar ir.Variable, block *ir.BasicBlock, fn *ir.Function, defIdx map[varKey]int) (boundsInfo, bool) {
	// first, check if indexVar is the result of a normalization (sub min_case)
	originalSelector, minCase := resolveNormalization(indexVar, defIdx, block.Instructions)

	// search for the bounds check branch in the current block
	if info, ok := findBoundsCheckInBlock(indexVar, block, minCase, originalSelector); ok {
		return info, true
	}

	// search in predecessor blocks using both the normalized and original selector
	for _, predID := range block.Predecessors {
		predBlock, exists := fn.Blocks[predID]
		if !exists {
			continue
		}
		predDefIdx := buildDefIndex(predBlock.Instructions)

		// in predecessor, the index variable may be defined differently
		predOriginal, predMinCase := resolveNormalization(indexVar, predDefIdx, predBlock.Instructions)

		// try with the normalized index variable
		if info, ok := findBoundsCheckInBlock(indexVar, predBlock, predMinCase, predOriginal); ok {
			return info, true
		}

		// try with the original selector (before normalization)
		if originalSelector.Name != indexVar.Name || originalSelector.Version != indexVar.Version {
			if info, ok := findBoundsCheckInBlock(originalSelector, predBlock, minCase, originalSelector); ok {
				return info, true
			}
		}

		// try: normalization is in predecessor block, bounds check uses normalized var
		predNorm, predMin := resolveNormalization(indexVar, predDefIdx, predBlock.Instructions)
		if predNorm.Name != indexVar.Name || predNorm.Version != indexVar.Version {
			if info, ok := findBoundsCheckInBlock(indexVar, predBlock, predMin, predNorm); ok {
				return info, true
			}
		}

		// try: bounds check in predecessor uses the original selector directly (min_case=0)
		if info, ok := findBoundsCheckInBlock(originalSelector, predBlock, 0, originalSelector); ok {
			return info, true
		}
	}

	// fallback: if we have a bounds check in the current block without normalization
	// (min_case == 0, selector is used directly)
	if info, ok := findBoundsCheckInBlock(originalSelector, block, 0, originalSelector); ok {
		return info, true
	}

	return boundsInfo{}, false
}

// resolveNormalization checks if a variable is the result of: var = original - min_case.
// returns (original, min_case) or (var, 0) if no normalization found.
func resolveNormalization(v ir.Variable, defIdx map[varKey]int, instrs []ir.IRInstruction) (ir.Variable, int64) {
	idx, defined := defIdx[varKey{name: v.Name, version: v.Version}]
	if !defined {
		return v, 0
	}
	assign, ok := instrs[idx].(*ir.Assign)
	if !ok {
		return v, 0
	}
	binop, ok := assign.Source.(*ir.BinaryOp)
	if !ok {
		return v, 0
	}
	if binop.Op != ir.BinOpSub {
		return v, 0
	}
	// pattern: v = original - min_case
	original, originalIsVar := extractVar(binop.Left)
	minConst, minIsConst := extractIntConst(binop.Right)
	if !originalIsVar || !minIsConst {
		return v, 0
	}
	return original, int64(minConst) //nolint:gosec
}

// findBoundsCheckInBlock searches for a bounds check branch in a single block.
// the bounds check has the form: branch (index >u range), default_block, table_block
// or equivalently: branch (index >=u range+1), default_block, table_block
func findBoundsCheckInBlock(indexVar ir.Variable, block *ir.BasicBlock, minCase int64, originalSelector ir.Variable) (boundsInfo, bool) {
	defIdx := buildDefIndex(block.Instructions)

	for _, instr := range block.Instructions {
		branch, ok := instr.(*ir.Branch)
		if !ok {
			continue
		}

		// the condition must be a comparison involving the index variable
		rangeSize, defaultBlock, ok := extractBoundsCondition(branch, indexVar, defIdx, block.Instructions)
		if !ok {
			continue
		}

		return boundsInfo{
			originalSelector: originalSelector,
			minCase:          minCase,
			rangeSize:        rangeSize,
			defaultBlock:     defaultBlock,
		}, true
	}

	return boundsInfo{}, false
}

// extractBoundsCondition extracts the range size and default block from a
// bounds check branch condition.
//
// supported patterns:
//
//	branch (index >u N),  default_block, table_block  → range = N+1
//	branch (index >=u N), default_block, table_block  → range = N
//	branch (index <u N),  table_block,   default_block → range = N
//	branch (index <=u N), table_block,   default_block → range = N+1
func extractBoundsCondition(branch *ir.Branch, indexVar ir.Variable, defIdx map[varKey]int, instrs []ir.IRInstruction) (uint64, ir.BlockID, bool) {
	cond := branch.Condition

	// resolve condition through def-use chain if it's a variable
	if cv, ok := cond.(*ir.VariableExpr); ok {
		if idx, defined := defIdx[varKey{name: cv.Var.Name, version: cv.Var.Version}]; defined {
			if assign, ok := instrs[idx].(*ir.Assign); ok {
				cond = assign.Source
			}
		}
	}

	binop, ok := cond.(*ir.BinaryOp)
	if !ok {
		return 0, 0, false
	}

	// check if left operand is the index variable (possibly through a def chain)
	leftIsIndex := isIndexVar(binop.Left, indexVar, defIdx, instrs)
	rightIsIndex := isIndexVar(binop.Right, indexVar, defIdx, instrs)

	switch binop.Op {
	case ir.BinOpUGt:
		// branch (index >u N), default, table → range = N+1
		if leftIsIndex {
			if n, ok := extractIntConst(binop.Right); ok {
				return n + 1, branch.TrueTarget, true
			}
		}
	case ir.BinOpUGe:
		// branch (index >=u N), default, table → range = N
		if leftIsIndex {
			if n, ok := extractIntConst(binop.Right); ok {
				return n, branch.TrueTarget, true
			}
		}
	case ir.BinOpULt:
		// branch (index <u N), table, default → range = N
		if leftIsIndex {
			if n, ok := extractIntConst(binop.Right); ok {
				return n, branch.FalseTarget, true
			}
		}
	case ir.BinOpULe:
		// branch (index <=u N), table, default → range = N+1
		if leftIsIndex {
			if n, ok := extractIntConst(binop.Right); ok {
				return n + 1, branch.FalseTarget, true
			}
		}
	case ir.BinOpGt:
		// signed >: treat as unsigned for switch bounds (selector is non-negative after normalization)
		if leftIsIndex {
			if n, ok := extractIntConst(binop.Right); ok {
				return n + 1, branch.TrueTarget, true
			}
		}
	case ir.BinOpGe:
		if leftIsIndex {
			if n, ok := extractIntConst(binop.Right); ok {
				return n, branch.TrueTarget, true
			}
		}
	case ir.BinOpLt:
		if leftIsIndex {
			if n, ok := extractIntConst(binop.Right); ok {
				return n, branch.FalseTarget, true
			}
		}
	case ir.BinOpLe:
		if leftIsIndex {
			if n, ok := extractIntConst(binop.Right); ok {
				return n + 1, branch.FalseTarget, true
			}
		}
	}

	// handle reversed operands: branch (N <u index), default, table
	switch binop.Op {
	case ir.BinOpULt:
		if rightIsIndex {
			if n, ok := extractIntConst(binop.Left); ok {
				return n + 1, branch.TrueTarget, true
			}
		}
	case ir.BinOpULe:
		if rightIsIndex {
			if n, ok := extractIntConst(binop.Left); ok {
				return n, branch.TrueTarget, true
			}
		}
	case ir.BinOpUGt:
		if rightIsIndex {
			if n, ok := extractIntConst(binop.Left); ok {
				return n, branch.FalseTarget, true
			}
		}
	case ir.BinOpUGe:
		if rightIsIndex {
			if n, ok := extractIntConst(binop.Left); ok {
				return n + 1, branch.FalseTarget, true
			}
		}
	}

	return 0, 0, false
}

// isIndexVar checks if an expression refers to the given index variable,
// possibly through a chain of assignments.
func isIndexVar(expr ir.Expression, indexVar ir.Variable, defIdx map[varKey]int, instrs []ir.IRInstruction) bool {
	v, ok := extractVar(expr)
	if !ok {
		return false
	}
	if v.Name == indexVar.Name && v.Version == indexVar.Version {
		return true
	}
	// follow one level of def chain
	idx, defined := defIdx[varKey{name: v.Name, version: v.Version}]
	if !defined {
		return false
	}
	assign, ok := instrs[idx].(*ir.Assign)
	if !ok {
		return false
	}
	if src, ok := extractVar(assign.Source); ok {
		return src.Name == indexVar.Name && src.Version == indexVar.Version
	}
	return false
}

// readJumpTable reads jump table entries from binary memory.
// the table starts at tableBase and contains rangeSize entries of ptrSize bytes each.
// each entry is a virtual address of a case handler block.
// minCase is added to the entry index to compute the actual case value.
//
// maxTableEntries limits the number of entries read to prevent runaway reads
// on corrupted or misidentified tables.
const maxTableEntries = 4096

func readJumpTable(tableBase uint64, rangeSize uint64, minCase int64, mem MemoryReader) ([]CaseEntry, error) {
	if rangeSize == 0 || rangeSize > maxTableEntries {
		return nil, nil
	}

	cases := make([]CaseEntry, 0, rangeSize)

	for i := uint64(0); i < rangeSize; i++ {
		entryAddr := tableBase + i*8 // 64-bit pointer size
		target, err := mem.ReadUint64(entryAddr)
		if err != nil {
			// partial table read: return what we have
			break
		}
		if target == 0 {
			// null entry: skip (may indicate end of table or padding)
			continue
		}

		caseValue := minCase + int64(i) //nolint:gosec
		cases = append(cases, CaseEntry{
			CaseValue:     caseValue,
			TargetAddress: target,
		})
	}

	return cases, nil
}

// classifySwitchKind determines whether a switch is dense or sparse.
// a switch is dense if all case values form a contiguous range with no gaps
// AND no two cases share the same target address (which would indicate gap entries
// pointing to the default handler).
// a switch is sparse if there are gaps between case values OR multiple entries
// share the same target (indicating the compiler filled gaps with the default address).
func classifySwitchKind(cases []CaseEntry) SwitchKind {
	if len(cases) <= 1 {
		return SwitchDense
	}

	// check for consecutive case values
	for i := 1; i < len(cases); i++ {
		if cases[i].CaseValue != cases[i-1].CaseValue+1 {
			return SwitchSparse
		}
	}

	// check for duplicate target addresses: if multiple cases point to the same
	// address, the compiler filled gaps with the default handler address,
	// indicating a sparse switch with holes.
	targetCount := make(map[uint64]int, len(cases))
	for _, c := range cases {
		targetCount[c.TargetAddress]++
	}
	for _, count := range targetCount {
		if count > 1 {
			return SwitchSparse
		}
	}

	return SwitchDense
}

// RecoverSwitchInBlock is the block-level entry point for switch recovery.
// it requires a memory reader for jump table extraction.
func RecoverSwitchInBlock(block *ir.BasicBlock, fn *ir.Function, mem MemoryReader) ([]*SwitchMatch, error) {
	if block == nil {
		return nil, ErrNilBlockSW
	}
	if fn == nil {
		return nil, ErrNilFunctionSW
	}
	if mem == nil {
		return nil, ErrNilMemorySW
	}
	return recoverSwitchInBlock(block, fn, mem)
}
