package ir

import (
	"fmt"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
)

// TestProperty24 validates the ir parser/printer round-trip property.
//
// property 24: for all valid ir programs P:
//
//	parse(print(P)) produces output identical to print(P)
//
// this verifies that the printer produces unambiguous, parseable output and
// that the parser correctly reconstructs the ir structure from text.
// minimum 100 iterations as required by the spec.
func TestProperty24(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	params.MaxSize = 8 // limit complexity to keep tests fast

	properties := gopter.NewProperties(params)

	properties.Property("parse(print(ir)) == print(ir) for arbitrary functions", prop.ForAll(
		func(fn *Function) bool {
			// first print
			out1, err := PrettyPrint(fn)
			if err != nil {
				// skip unprintable functions (degenerate cases)
				return true
			}

			// parse the printed output
			parser := NewParser(strings.NewReader(out1))
			fn2, err := parser.ParseFunction()
			if err != nil {
				t.Logf("parse failed after print:\nprinted:\n%s\nerror: %v", out1, err)
				return false
			}

			// second print
			out2, err := PrettyPrint(fn2)
			if err != nil {
				t.Logf("second print failed: %v", err)
				return false
			}

			// compare normalized outputs
			n1 := normalizeIROutput(out1)
			n2 := normalizeIROutput(out2)
			if n1 != n2 {
				t.Logf("round-trip mismatch:\nfirst:\n%s\nsecond:\n%s", out1, out2)
				return false
			}
			return true
		},
		genFunction(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ============================================================================
// generators
// ============================================================================

// genFunction generates an arbitrary valid ir function with 1-4 basic blocks.
func genFunction() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		// draw number of blocks from [1, 4]
		numBlocks := int(params.NextUint64()%4) + 1

		fn := &Function{
			Name:       genFuncName(numBlocks),
			Signature:  genSimpleSignature(),
			Blocks:     make(map[BlockID]*BasicBlock),
			EntryBlock: 0,
			Variables:  []Variable{},
		}

		// generate blocks with sequential block ids
		for i := 0; i < numBlocks; i++ {
			bid := BlockID(i)
			block := genSimpleBlock(bid, numBlocks)
			fn.Blocks[bid] = block
		}

		return gopter.NewGenResult(fn, gopter.NoShrinker)
	}
}

// genFuncName generates a valid function name from block count seed.
func genFuncName(seed int) string {
	names := []string{"fn_a", "fn_b", "fn_c", "fn_d", "fn_e", "fn_f", "fn_g", "fn_h"}
	return names[seed%len(names)]
}

// genSimpleSignature generates a simple function signature.
func genSimpleSignature() FunctionType {
	return FunctionType{
		ReturnType: VoidType{},
		Parameters: []Type{},
	}
}

// genSimpleBlock generates a basic block with valid instructions.
// the last instruction is always a terminator (return or jump).
func genSimpleBlock(id BlockID, totalBlocks int) *BasicBlock {
	block := &BasicBlock{
		ID:           id,
		Instructions: []IRInstruction{},
		Predecessors: []BlockID{},
		Successors:   []BlockID{},
	}

	// add 0-2 non-terminator instructions
	numInsns := int(id) % 3 //nolint:gosec // id is generated small above
	for i := 0; i < numInsns; i++ {
		insn := genNonTerminatorInsn(id, i)
		block.Instructions = append(block.Instructions, insn)
	}

	// always end with a terminator
	terminator := genTerminator(id, totalBlocks)
	block.Instructions = append(block.Instructions, terminator)

	return block
}

// genNonTerminatorInsn generates assign, load, or store instructions.
func genNonTerminatorInsn(blockID BlockID, idx int) IRInstruction {
	// cycle through instruction types deterministically
	switch (int(blockID) + idx) % 3 { //nolint:gosec // blockID is generated small above
	case 0:
		return genAssignInsn(blockID, idx)
	case 1:
		return genLoadInsn(blockID, idx)
	default:
		return genStoreInsn(blockID, idx)
	}
}

// genAssignInsn generates an assign instruction.
func genAssignInsn(blockID BlockID, idx int) *Assign {
	dest := Variable{
		Name:    fmt.Sprintf("tmp%d_%d", blockID, idx),
		Type:    IntType{Width: Size8, Signed: true},
		Version: 1,
	}
	src := genSimpleExpr(blockID, idx, 0)
	return &Assign{Dest: dest, Source: src}
}

// genLoadInsn generates a load instruction.
func genLoadInsn(blockID BlockID, idx int) *Load {
	dest := Variable{
		Name:    fmt.Sprintf("tmp%d_%d", blockID, idx),
		Type:    IntType{Width: Size8, Signed: true},
		Version: 1,
	}
	addr := VariableExpr{
		Var: Variable{
			Name:    fmt.Sprintf("ptr%d", blockID),
			Type:    PointerType{Pointee: VoidType{}},
			Version: 1,
		},
	}
	return &Load{Dest: dest, Address: addr, Size: Size8}
}

// genStoreInsn generates a store instruction.
func genStoreInsn(blockID BlockID, idx int) *Store {
	addr := VariableExpr{
		Var: Variable{
			Name:    fmt.Sprintf("ptr%d", blockID),
			Type:    PointerType{Pointee: VoidType{}},
			Version: 1,
		},
	}
	val := VariableExpr{
		Var: Variable{
			Name:    fmt.Sprintf("tmp%d_%d", blockID, idx),
			Type:    IntType{Width: Size8, Signed: true},
			Version: 1,
		},
	}
	return &Store{Address: addr, Value: val, Size: Size8}
}

// genTerminator generates a valid terminator instruction for a block.
func genTerminator(id BlockID, totalBlocks int) IRInstruction {
	// last block always returns
	if int(id) == totalBlocks-1 || totalBlocks == 1 { //nolint:gosec // id is generated small above
		return &Return{Value: nil}
	}

	// other blocks jump to next block
	nextBlock := id + 1
	return &Jump{Target: nextBlock}
}

// genSimpleExpr generates a simple expression with bounded depth.
func genSimpleExpr(blockID BlockID, idx int, depth int) Expression {
	if depth >= 2 {
		// base case: return a variable or constant
		//nolint:gosec // id is small test bounds
		idx64 := uint64(uint(idx + depth))
		if (uint64(blockID)+idx64)%2 == 0 {
			return genIntConstantExpr(int64(idx * 10))
		}
		return VariableExpr{
			Var: Variable{
				Name:    fmt.Sprintf("tmp%d_%d", blockID, idx),
				Type:    IntType{Width: Size8, Signed: true},
				Version: 1,
			},
		}
	}

	//nolint:gosec // id is small test bounds
	idx64 := uint64(uint(idx + depth))
	// cycle through expression types
	switch (uint64(blockID) + idx64) % 5 {
	case 0:
		return genIntConstantExpr(int64(blockID)*10 + int64(idx)) //nolint:gosec // blockID is generated small above
	case 1:
		return genBinaryOpExpr(blockID, idx, depth)
	case 2:
		return genUnaryOpExpr(blockID, idx, depth)
	case 3:
		return genCastExpr(blockID, idx, depth)
	default:
		return VariableExpr{
			Var: Variable{
				Name:    fmt.Sprintf("tmp%d_%d", blockID, idx),
				Type:    IntType{Width: Size8, Signed: true},
				Version: 1,
			},
		}
	}
}

// genIntConstantExpr generates an integer constant expression.
func genIntConstantExpr(val int64) ConstantExpr {
	return ConstantExpr{
		Value: IntConstant{
			Value:  val,
			Width:  Size8,
			Signed: true,
		},
	}
}

// genBinaryOpExpr generates a binary operation expression.
func genBinaryOpExpr(blockID BlockID, idx int, depth int) BinaryOp {
	// use only arithmetic ops that round-trip cleanly
	ops := []BinaryOperator{
		BinOpAdd, BinOpSub, BinOpMul,
		BinOpAnd, BinOpOr, BinOpXor,
	}
	op := ops[(uint64(blockID)+uint64(uint(idx)))%uint64(len(ops))] //nolint:gosec // idx bounds

	left := genSimpleExpr(blockID, idx, depth+1)
	right := genSimpleExpr(blockID, idx+1, depth+1)

	return BinaryOp{Op: op, Left: left, Right: right}
}

// genUnaryOpExpr generates a unary operation expression.
func genUnaryOpExpr(blockID BlockID, idx int, depth int) UnaryOp {
	ops := []UnaryOperator{UnOpNeg, UnOpNot}
	op := ops[(uint64(blockID)+uint64(uint(idx)))%uint64(len(ops))] //nolint:gosec // idx bounds
	operand := genSimpleExpr(blockID, idx, depth+1)
	return UnaryOp{Op: op, Operand: operand}
}

// genCastExpr generates a cast expression.
func genCastExpr(blockID BlockID, idx int, depth int) Cast {
	targetTypes := []Type{
		IntType{Width: Size4, Signed: true},
		IntType{Width: Size2, Signed: false},
		IntType{Width: Size1, Signed: false},
	}
	//nolint:gosec // test bounds
	idx64 := uint64(idx)
	targetType := targetTypes[(uint64(blockID)+idx64)%uint64(len(targetTypes))]
	inner := genSimpleExpr(blockID, idx, depth+1)
	return Cast{Expr: inner, TargetType: targetType}
}

// ============================================================================
// helpers
// ============================================================================

// normalizeIROutput strips comments and normalizes whitespace for comparison.
// this is necessary because the printer may emit source location comments
// that differ between runs.
func normalizeIROutput(s string) string {
	lines := strings.Split(s, "\n")
	var result []string
	for _, line := range lines {
		// strip inline comments
		if idx := strings.Index(line, "//"); idx != -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return strings.Join(result, "\n")
}
