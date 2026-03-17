package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// RecoverStackVariables scans all ir instructions for frame-pointer-relative
// memory accesses (rbp + offset patterns) and replaces them with named local
// variables. this eliminates raw pointer arithmetic like *(uint32_t*)((var_0 + -4))
// and produces clean variable references like local_4.
//
// the pass operates in two phases:
//  1. scan: collect all unique rbp-relative offsets and their access sizes
//  2. rewrite: replace Load/Store with frame-relative addresses into Assign
//     instructions using named local variables
//
// only negative rbp offsets are treated as locals (positive offsets are
// caller frame / return address / arguments passed on stack).
func RecoverStackVariables(fn *ir.Function) {
	// phase 1: collect all frame-relative access sites
	slots := collectFrameSlots(fn)
	if len(slots) == 0 {
		return
	}

	// assign names to each slot
	assignSlotNames(slots, fn)

	// phase 2: rewrite Load/Store instructions that use frame-relative addresses
	for _, block := range fn.Blocks {
		for i, instr := range block.Instructions {
			block.Instructions[i] = rewriteFrameInstr(instr, slots)
		}
	}

	// register new local variables in the function
	for _, slot := range slots {
		fn.Variables = append(fn.Variables, ir.Variable{
			Name: slot.name,
			Type: slot.varType,
		})
	}
}

// frameSlot represents a single stack frame slot identified by its rbp offset.
type frameSlot struct {
	offset  int64   // rbp-relative offset (negative for locals)
	size    ir.Size // access size in bytes
	name    string  // assigned variable name
	varType ir.Type // inferred type
}

// collectFrameSlots scans all instructions for rbp-relative memory patterns.
func collectFrameSlots(fn *ir.Function) map[int64]*frameSlot {
	slots := make(map[int64]*frameSlot)

	for _, block := range fn.Blocks {
		for _, instr := range block.Instructions {
			if instr.Location().IsFrameArtifact {
				continue
			}
			switch typed := instr.(type) {
			case *ir.Load:
				if offset, ok := extractFrameOffset(typed.Address); ok && offset < 0 {
					recordSlot(slots, offset, typed.Size)
				}
			case ir.Load:
				if offset, ok := extractFrameOffset(typed.Address); ok && offset < 0 {
					recordSlot(slots, offset, typed.Size)
				}
			case *ir.Store:
				if offset, ok := extractFrameOffset(typed.Address); ok && offset < 0 {
					recordSlot(slots, offset, typed.Size)
				}
			case ir.Store:
				if offset, ok := extractFrameOffset(typed.Address); ok && offset < 0 {
					recordSlot(slots, offset, typed.Size)
				}
			}
		}
	}

	return slots
}

// recordSlot adds or updates a frame slot entry.
func recordSlot(slots map[int64]*frameSlot, offset int64, size ir.Size) {
	if size == 0 {
		size = ir.Size4
	}
	if _, exists := slots[offset]; !exists {
		slots[offset] = &frameSlot{
			offset:  offset,
			size:    size,
			varType: ir.IntType{Width: size, Signed: false},
		}
	}
}

// extractFrameOffset checks if expr is a rbp-relative address pattern:
//   - rbp + constant (where rbp may have been renamed to var_N)
//   - the pattern is: VariableExpr{rbp/ebp} + ConstantExpr{offset}
//
// returns the offset and true if matched.
func extractFrameOffset(expr ir.Expression) (int64, bool) {
	add, ok := expr.(ir.BinaryOp)
	if !ok || add.Op != ir.BinOpAdd {
		return 0, false
	}

	// left should be a variable that is rbp
	varExpr, ok := add.Left.(ir.VariableExpr)
	if !ok {
		return 0, false
	}
	if !isFramePointerVar(varExpr.Var.Name) {
		return 0, false
	}

	// right should be a constant offset
	constExpr, ok := add.Right.(ir.ConstantExpr)
	if !ok {
		return 0, false
	}
	intConst, ok := constExpr.Value.(ir.IntConstant)
	if !ok {
		return 0, false
	}

	return intConst.Value, true
}

// isFramePointerVar checks if a variable name refers to the frame pointer.
func isFramePointerVar(name string) bool {
	lower := strings.ToLower(name)
	return lower == "rbp" || lower == "ebp"
}

// assignSlotNames assigns human-readable names to frame slots.
func assignSlotNames(slots map[int64]*frameSlot, fn *ir.Function) {
	// sort offsets for deterministic naming (highest offset first = closest to rbp)
	offsets := make([]int64, 0, len(slots))
	for offset := range slots {
		offsets = append(offsets, offset)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] > offsets[j] })

	// check existing variable names to avoid collisions
	existing := make(map[string]bool)
	for _, v := range fn.Variables {
		existing[v.Name] = true
	}

	for _, offset := range offsets {
		slot := slots[offset]
		absOff := -offset
		name := fmt.Sprintf("local_%x", absOff)
		for existing[name] {
			name = name + "_"
		}
		slot.name = name
		existing[name] = true
	}
}

// rewriteFrameInstr replaces Load/Store with frame-relative addresses.
// Load from frame slot -> Assign from local variable.
// Store to frame slot -> Assign to local variable.
func rewriteFrameInstr(instr ir.IRInstruction, slots map[int64]*frameSlot) ir.IRInstruction {
	if instr.Location().IsFrameArtifact {
		return instr
	}

	switch typed := instr.(type) {
	case *ir.Load:
		if offset, ok := extractFrameOffset(typed.Address); ok {
			if slot, exists := slots[offset]; exists && slot.name != "" {
				// load from frame slot -> assign from local variable
				return &ir.Assign{
					Dest:   typed.Dest,
					Source: ir.VariableExpr{Var: ir.Variable{Name: slot.name, Type: slot.varType}},
				}
			}
		}
	case ir.Load:
		if offset, ok := extractFrameOffset(typed.Address); ok {
			if slot, exists := slots[offset]; exists && slot.name != "" {
				return ir.Assign{
					Dest:   typed.Dest,
					Source: ir.VariableExpr{Var: ir.Variable{Name: slot.name, Type: slot.varType}},
				}
			}
		}
	case *ir.Store:
		if offset, ok := extractFrameOffset(typed.Address); ok {
			if slot, exists := slots[offset]; exists && slot.name != "" {
				// store to frame slot -> assign to local variable
				return &ir.Assign{
					Dest:   ir.Variable{Name: slot.name, Type: slot.varType},
					Source: typed.Value,
				}
			}
		}
	case ir.Store:
		if offset, ok := extractFrameOffset(typed.Address); ok {
			if slot, exists := slots[offset]; exists && slot.name != "" {
				return ir.Assign{
					Dest:   ir.Variable{Name: slot.name, Type: slot.varType},
					Source: typed.Value,
				}
			}
		}
	}
	return instr
}
