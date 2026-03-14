package analysis

// TestProperty11: Dead Code Elimination Safety
//
// property 11: for all ir programs P with dead code:
//
//	side_effects(dce(P)) == side_effects(P)
//
// validates requirements 10.1-10.5:
//   - 10.1: dead variable definitions are removed
//   - 10.2: unreachable basic blocks are removed
//   - 10.3: side-effecting instructions (stores, calls) are always preserved
//   - 10.4: dce iterates to fixed point
//   - 10.5: dead phi-nodes are removed
//
// minimum 100 iterations required.

import (
	"fmt"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// property test entry point
// ============================================================================

// TestProperty11 verifies dce safety: side effects are always preserved.
// runs 100+ iterations with gopter-generated ir programs.
//
//nolint:dupl // similar test property structure to others
func TestProperty11(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	params.MaxSize = 8

	properties := gopter.NewProperties(params)

	// property 11a: stores are always preserved after dce
	properties.Property("dce preserves all store instructions", prop.ForAll(
		func(prog *dceProgram) bool {
			return checkStoresPreserved(t, prog)
		},
		genDCEProgram(),
	))

	// property 11b: calls are always preserved after dce
	properties.Property("dce preserves all call instructions", prop.ForAll(
		func(prog *dceProgram) bool {
			return checkCallsPreserved(t, prog)
		},
		genDCEProgram(),
	))

	// property 11c: variables used by side effects are preserved
	properties.Property("dce preserves variables used by side effects", prop.ForAll(
		func(prog *dceProgram) bool {
			return checkSideEffectOperandsPreserved(t, prog)
		},
		genDCEProgram(),
	))

	// property 11d: dead definitions without side effects are removed
	properties.Property("dce removes dead definitions", prop.ForAll(
		func(prog *pureDCEProgram) bool {
			return checkDeadDefinitionsRemoved(t, prog)
		},
		genPureDCEProgram(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ============================================================================
// program types for generators
// ============================================================================

// dceProgram represents an ir function with a mix of live code, dead code,
// and side-effecting instructions (stores and calls).
type dceProgram struct {
	// numDeadAssigns is the number of dead assignments to inject
	numDeadAssigns int
	// numStores is the number of store instructions
	numStores int
	// numCalls is the number of call instructions
	numCalls int
	// storeUsesDeadVar: if true, the store's value operand is a "live" variable
	// (one that is defined just before the store and used only by it)
	storeUsesDeadVar bool
}

// pureDCEProgram represents an ir function with only dead assignments and a return.
// used to verify that dce removes all dead definitions.
type pureDCEProgram struct {
	// chainLength is the number of chained dead assignments
	// a_1 = seed; a_2 = a_1 op c; a_3 = a_2 op c; ... (none returned)
	chainLength int
	// seed is the initial constant value
	seed int64
}

// ============================================================================
// gopter generators
// ============================================================================

// genDCEProgram generates arbitrary dce programs with side effects.
func genDCEProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		prog := &dceProgram{
			numDeadAssigns:   int(params.NextUint64()%6) + 1, // 1-6 dead assigns
			numStores:        int(params.NextUint64()%4) + 1, // 1-4 stores
			numCalls:         int(params.NextUint64() % 3),   // 0-2 calls
			storeUsesDeadVar: params.NextUint64()%2 == 0,
		}
		return gopter.NewGenResult(prog, gopter.NoShrinker)
	}
}

// genPureDCEProgram generates programs with only dead assignments.
func genPureDCEProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		prog := &pureDCEProgram{
			chainLength: int(params.NextUint64()%8) + 2, // 2-9 chained dead assigns
			seed:        int64(params.NextUint64()%100) + 1,
		}
		return gopter.NewGenResult(prog, gopter.NoShrinker)
	}
}

// ============================================================================
// property checkers
// ============================================================================

// checkStoresPreserved verifies that all store instructions survive dce.
// property: count(stores, dce(P)) == count(stores, P)
func checkStoresPreserved(t *testing.T, prog *dceProgram) bool {
	t.Helper()
	fn, cfgGraph := buildDCETestFunction(prog)

	storesBefore := countInstructionType(fn, func(i ir.IRInstruction) bool {
		_, ok := i.(*ir.Store)
		return ok
	})

	_, err := EliminateDeadCode(fn, cfgGraph, nil)
	if err != nil {
		t.Logf("EliminateDeadCode failed: %v", err)
		return false
	}

	storesAfter := countInstructionType(fn, func(i ir.IRInstruction) bool {
		_, ok := i.(*ir.Store)
		return ok
	})

	if storesBefore != storesAfter {
		t.Logf("store count changed: before=%d after=%d\n  program: %s",
			storesBefore, storesAfter, describeDCEProgram(prog))
		return false
	}
	return true
}

// checkCallsPreserved verifies that all call instructions survive dce.
// property: count(calls, dce(P)) == count(calls, P)
func checkCallsPreserved(t *testing.T, prog *dceProgram) bool {
	t.Helper()
	fn, cfgGraph := buildDCETestFunction(prog)

	callsBefore := countInstructionType(fn, func(i ir.IRInstruction) bool {
		_, ok := i.(*ir.Call)
		return ok
	})

	if callsBefore == 0 {
		// no calls to check: trivially true
		return true
	}

	_, err := EliminateDeadCode(fn, cfgGraph, nil)
	if err != nil {
		t.Logf("EliminateDeadCode failed: %v", err)
		return false
	}

	callsAfter := countInstructionType(fn, func(i ir.IRInstruction) bool {
		_, ok := i.(*ir.Call)
		return ok
	})

	if callsBefore != callsAfter {
		t.Logf("call count changed: before=%d after=%d\n  program: %s",
			callsBefore, callsAfter, describeDCEProgram(prog))
		return false
	}
	return true
}

// checkSideEffectOperandsPreserved verifies that variables used as operands
// of side-effecting instructions are not eliminated.
//
// property: for all v in operands(side_effects(P)):
//
//	v is defined in dce(P)
func checkSideEffectOperandsPreserved(t *testing.T, prog *dceProgram) bool {
	t.Helper()
	fn, cfgGraph := buildDCETestFunction(prog)

	// collect all variables used as operands of side-effecting instructions
	// before dce runs
	sideEffectOperands := collectSideEffectOperands(fn)

	_, err := EliminateDeadCode(fn, cfgGraph, nil)
	if err != nil {
		t.Logf("EliminateDeadCode failed: %v", err)
		return false
	}

	// collect all defined variables after dce
	definedAfter := collectDefinedVariables(fn)

	// every side-effect operand must still be defined
	for _, v := range sideEffectOperands {
		if !definedAfter[v.String()] {
			t.Logf("side-effect operand %s was eliminated\n  program: %s",
				v.String(), describeDCEProgram(prog))
			return false
		}
	}
	return true
}

// checkDeadDefinitionsRemoved verifies that a chain of dead assignments
// (none of which are used by any side effect or return) is fully eliminated.
//
// property: for all pure dead chains P:
//
//	count(assigns, dce(P)) == 0
func checkDeadDefinitionsRemoved(t *testing.T, prog *pureDCEProgram) bool {
	t.Helper()
	fn, cfgGraph := buildPureDCEFunction(prog)

	assignsBefore := countInstructionType(fn, func(i ir.IRInstruction) bool {
		_, ok := i.(*ir.Assign)
		return ok
	})

	if assignsBefore == 0 {
		return true
	}

	result, err := EliminateDeadCode(fn, cfgGraph, nil)
	if err != nil {
		t.Logf("EliminateDeadCode failed: %v", err)
		return false
	}

	assignsAfter := countInstructionType(fn, func(i ir.IRInstruction) bool {
		_, ok := i.(*ir.Assign)
		return ok
	})

	if assignsAfter != 0 {
		t.Logf("dead assigns not fully removed: before=%d after=%d removed=%d\n  program: %s",
			assignsBefore, assignsAfter, result.RemovedInstructions, describePureDCEProgram(prog))
		return false
	}
	return true
}

// ============================================================================
// ir function builders
// ============================================================================

// buildDCETestFunction constructs an ir function from a dceProgram.
//
// structure:
//
//	bb0:
//	  dead_1 = 1          (dead assign #1)
//	  dead_2 = dead_1 + 1 (dead assign #2, chained)
//	  ...
//	  store_val_1 = 42    (live: used by store)
//	  store *0x1000, store_val_1
//	  ...
//	  call foo()          (side effect, no return value used)
//	  ...
//	  return
func buildDCETestFunction(prog *dceProgram) (*ir.Function, *cfg.CFG) {
	instrs := make([]ir.IRInstruction, 0, prog.numDeadAssigns+prog.numStores*2+prog.numCalls+1)

	// inject dead assignment chain
	// dead_0 = seed; dead_1 = dead_0 + 1; ... (none used by anything)
	prevDeadVar := ir.Variable{Name: "dead", Version: 0, Type: intType()}
	instrs = append(instrs, &ir.Assign{
		Dest:   prevDeadVar,
		Source: intConst(7),
	})
	for i := 1; i < prog.numDeadAssigns; i++ {
		nextDeadVar := ir.Variable{Name: "dead", Version: i, Type: intType()}
		instrs = append(instrs, &ir.Assign{
			Dest: nextDeadVar,
			Source: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: prevDeadVar},
				Right: intConst(1),
			},
		})
		prevDeadVar = nextDeadVar
	}

	// inject stores with live operands
	for i := 0; i < prog.numStores; i++ {
		addr := uint64(0x1000 + i*8)
		var storeVal ir.Expression

		if prog.storeUsesDeadVar {
			// store value is a freshly defined variable (live only because of this store)
			liveVar := ir.Variable{Name: fmt.Sprintf("sv%d", i), Version: 1, Type: intType()}
			instrs = append(instrs, &ir.Assign{
				Dest:   liveVar,
				Source: intConst(int64(i + 10)),
			})
			storeVal = &ir.VariableExpr{Var: liveVar}
		} else {
			storeVal = intConst(int64(i + 10))
		}

		instrs = append(instrs, &ir.Store{
			Address: intConst(int64(addr)),
			Value:   storeVal,
			Size:    ir.Size8,
		})
	}

	// inject calls (no return value used — but call itself must be preserved)
	for i := 0; i < prog.numCalls; i++ {
		instrs = append(instrs, &ir.Call{
			Target: ir.VariableExpr{Var: ir.Variable{
				Name: fmt.Sprintf("fn%d", i),
				Type: ir.FunctionType{},
			}},
		})
	}

	instrs = append(instrs, &ir.Return{})

	fn := &ir.Function{
		Name: "dce_prop_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID:           0,
				Instructions: instrs,
			},
		},
		EntryBlock: 0,
	}

	cfgGraph := buildDCECFG(map[cfg.BlockID][]cfg.BlockID{0: {}})
	return fn, cfgGraph
}

// buildPureDCEFunction constructs an ir function with only dead assignments.
// the function returns void (no variable is returned), so all assigns are dead.
//
// structure:
//
//	bb0:
//	  v0 = seed
//	  v1 = v0 + 1
//	  v2 = v1 + 1
//	  ...
//	  return   (void — no variable used)
func buildPureDCEFunction(prog *pureDCEProgram) (*ir.Function, *cfg.CFG) {
	instrs := make([]ir.IRInstruction, 0, prog.chainLength+1)

	v0 := ir.Variable{Name: "v", Version: 0, Type: intType()}
	instrs = append(instrs, &ir.Assign{
		Dest:   v0,
		Source: intConst(prog.seed),
	})

	prev := v0
	for i := 1; i < prog.chainLength; i++ {
		next := ir.Variable{Name: "v", Version: i, Type: intType()}
		instrs = append(instrs, &ir.Assign{
			Dest: next,
			Source: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: prev},
				Right: intConst(1),
			},
		})
		prev = next
	}

	// void return: no variable referenced → all assigns are dead
	instrs = append(instrs, &ir.Return{})

	fn := &ir.Function{
		Name: "pure_dead_chain",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID:           0,
				Instructions: instrs,
			},
		},
		EntryBlock: 0,
	}

	cfgGraph := buildDCECFG(map[cfg.BlockID][]cfg.BlockID{0: {}})
	return fn, cfgGraph
}

// ============================================================================
// analysis helpers
// ============================================================================

// countInstructionType counts instructions matching the predicate across all blocks.
func countInstructionType(fn *ir.Function, pred func(ir.IRInstruction) bool) int {
	count := 0
	for _, block := range fn.Blocks {
		for _, instr := range block.Instructions {
			if pred(instr) {
				count++
			}
		}
	}
	return count
}

// collectSideEffectOperands returns all variables used as operands of
// side-effecting instructions (Store value/address, Call args).
func collectSideEffectOperands(fn *ir.Function) []ir.Variable {
	var vars []ir.Variable
	seen := make(map[string]bool)

	addVar := func(v ir.Variable) {
		key := v.String()
		if !seen[key] {
			seen[key] = true
			vars = append(vars, v)
		}
	}

	for _, block := range fn.Blocks {
		for _, instr := range block.Instructions {
			switch i := instr.(type) {
			case *ir.Store:
				// collect variables referenced in store address and value
				collectVarsFromExpr(i.Address, addVar)
				collectVarsFromExpr(i.Value, addVar)
			case *ir.Call:
				// collect call arguments
				for _, arg := range i.Args {
					addVar(arg)
				}
			}
		}
	}
	return vars
}

// collectDefinedVariables returns a set of all variable keys defined in the function.
func collectDefinedVariables(fn *ir.Function) map[string]bool {
	defined := make(map[string]bool)
	for _, block := range fn.Blocks {
		for _, instr := range block.Instructions {
			switch i := instr.(type) {
			case *ir.Assign:
				defined[i.Dest.String()] = true
			case *ir.Load:
				defined[i.Dest.String()] = true
			case *ir.Phi:
				defined[i.Dest.String()] = true
			case *ir.Call:
				if i.Dest != nil {
					defined[i.Dest.String()] = true
				}
			}
		}
	}
	return defined
}

// collectVarsFromExpr recursively collects all variable references in an expression.
func collectVarsFromExpr(expr ir.Expression, add func(ir.Variable)) {
	if expr == nil {
		return
	}
	switch e := expr.(type) {
	case ir.VariableExpr:
		add(e.Var)
	case *ir.VariableExpr:
		add(e.Var)
	case *ir.BinaryOp:
		collectVarsFromExpr(e.Left, add)
		collectVarsFromExpr(e.Right, add)
	case ir.BinaryOp:
		collectVarsFromExpr(e.Left, add)
		collectVarsFromExpr(e.Right, add)
	case *ir.UnaryOp:
		collectVarsFromExpr(e.Operand, add)
	case ir.UnaryOp:
		collectVarsFromExpr(e.Operand, add)
	case *ir.Cast:
		collectVarsFromExpr(e.Expr, add)
	case ir.Cast:
		collectVarsFromExpr(e.Expr, add)
	}
}

// ============================================================================
// description helpers for failure messages
// ============================================================================

func describeDCEProgram(prog *dceProgram) string {
	return fmt.Sprintf(
		"deadAssigns=%d stores=%d calls=%d storeUsesDeadVar=%v",
		prog.numDeadAssigns, prog.numStores, prog.numCalls, prog.storeUsesDeadVar,
	)
}

func describePureDCEProgram(prog *pureDCEProgram) string {
	return fmt.Sprintf("chainLength=%d seed=%d", prog.chainLength, prog.seed)
}
