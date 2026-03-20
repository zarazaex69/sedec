package ir

import (
	"fmt"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
)

func TestProperty24(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	params.MaxSize = 8

	properties := gopter.NewProperties(params)

	properties.Property("parse(print(ir)) == print(ir) for arbitrary functions", prop.ForAll(
		func(fn *Function) bool {
			out1, err := PrettyPrint(fn)
			if err != nil {
				return true
			}

			parser := NewParser(strings.NewReader(out1))
			fn2, err := parser.ParseFunction()
			if err != nil {
				t.Logf("parse failed after print:\nprinted:\n%s\nerror: %v", out1, err)
				return false
			}

			out2, err := PrettyPrint(fn2)
			if err != nil {
				t.Logf("second print failed: %v", err)
				return false
			}

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

func genFunction() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		rng := params.Rng
		numBlocks := int(rng.Int63()%4) + 1

		fn := &Function{
			Name:       genFuncName(rng.Int63()),
			Signature:  genRandSignature(rng.Int63()),
			Blocks:     make(map[BlockID]*BasicBlock),
			EntryBlock: 0,
		}

		for i := range numBlocks {
			bid := BlockID(i)
			fn.Blocks[bid] = genRandBlock(bid, numBlocks, rng.Int63())
		}

		return gopter.NewGenResult(fn, gopter.NoShrinker)
	}
}

func genFuncName(seed int64) string {
	names := []string{"fn_a", "fn_b", "fn_c", "fn_d", "fn_e", "fn_f", "fn_g", "fn_h"}
	idx := seed % int64(len(names))
	if idx < 0 {
		idx = -idx
	}
	return names[idx]
}

func genRandSignature(seed int64) FunctionType {
	if seed < 0 {
		seed = -seed
	}
	paramTypes := []Type{
		IntType{Width: Size8, Signed: true},
		IntType{Width: Size4, Signed: false},
		IntType{Width: Size2, Signed: true},
	}
	retTypes := []Type{
		VoidType{},
		IntType{Width: Size8, Signed: true},
		IntType{Width: Size4, Signed: false},
	}
	numParams := int(seed % 3)
	params := make([]Type, 0, numParams)
	for i := range numParams {
		params = append(params, paramTypes[(int(seed)+i)%len(paramTypes)])
	}
	return FunctionType{
		ReturnType: retTypes[seed%int64(len(retTypes))],
		Parameters: params,
	}
}

func genRandBlock(id BlockID, totalBlocks int, seed int64) *BasicBlock {
	if seed < 0 {
		seed = -seed
	}
	block := &BasicBlock{
		ID:           id,
		Instructions: []IRInstruction{},
	}

	numInsns := int(seed % 4)
	for i := range numInsns {
		block.Instructions = append(block.Instructions, genRandNonTerminator(id, i, totalBlocks, seed+int64(i*7)))
	}

	block.Instructions = append(block.Instructions, genRandTerminator(id, totalBlocks, seed))
	return block
}

func genRandNonTerminator(blockID BlockID, idx int, totalBlocks int, seed int64) IRInstruction {
	if seed < 0 {
		seed = -seed
	}
	switch seed % 6 {
	case 0:
		return genAssignInsn(blockID, idx)
	case 1:
		return genLoadInsn(blockID, idx)
	case 2:
		return genStoreInsn(blockID, idx)
	case 3:
		return genCallInsn(blockID, idx, seed)
	case 4:
		return genPhiInsn(blockID, idx, totalBlocks, seed)
	default:
		return genAssignInsn(blockID, idx)
	}
}

func genAssignInsn(blockID BlockID, idx int) *Assign {
	return &Assign{
		Dest: Variable{
			Name:    fmt.Sprintf("tmp%d_%d", blockID, idx),
			Type:    IntType{Width: Size8, Signed: true},
			Version: 1,
		},
		Source: genSimpleExpr(blockID, idx, 0),
	}
}

func genLoadInsn(blockID BlockID, idx int) *Load {
	return &Load{
		Dest: Variable{
			Name:    fmt.Sprintf("tmp%d_%d", blockID, idx),
			Type:    IntType{Width: Size8, Signed: true},
			Version: 1,
		},
		Address: VariableExpr{
			Var: Variable{
				Name:    fmt.Sprintf("ptr%d", blockID),
				Type:    PointerType{Pointee: VoidType{}},
				Version: 1,
			},
		},
		Size: Size8,
	}
}

func genStoreInsn(blockID BlockID, idx int) *Store {
	return &Store{
		Address: VariableExpr{
			Var: Variable{
				Name:    fmt.Sprintf("ptr%d", blockID),
				Type:    PointerType{Pointee: VoidType{}},
				Version: 1,
			},
		},
		Value: VariableExpr{
			Var: Variable{
				Name:    fmt.Sprintf("tmp%d_%d", blockID, idx),
				Type:    IntType{Width: Size8, Signed: true},
				Version: 1,
			},
		},
		Size: Size8,
	}
}

func genCallInsn(blockID BlockID, idx int, seed int64) *Call {
	if seed < 0 {
		seed = -seed
	}
	call := &Call{
		Target: VariableExpr{
			Var: Variable{
				Name: fmt.Sprintf("callee%d", blockID),
				Type: IntType{Width: Size8, Signed: true},
			},
		},
		Args: []Variable{
			{
				Name:    fmt.Sprintf("tmp%d_%d", blockID, idx),
				Type:    IntType{Width: Size8, Signed: true},
				Version: 1,
			},
		},
	}
	if seed%2 == 0 {
		dest := Variable{
			Name:    fmt.Sprintf("ret%d_%d", blockID, idx),
			Type:    IntType{Width: Size8, Signed: true},
			Version: 1,
		}
		call.Dest = &dest
	}
	return call
}

func genPhiInsn(blockID BlockID, idx int, totalBlocks int, seed int64) *Phi {
	if seed < 0 {
		seed = -seed
	}
	numSources := 2
	if totalBlocks < 2 {
		numSources = 1
	}
	sources := make([]PhiSource, 0, numSources)
	for i := range numSources {
		srcBlock := BlockID(i)
		sources = append(sources, PhiSource{
			Block: srcBlock,
			Var: Variable{
				Name:    fmt.Sprintf("tmp%d_%d", srcBlock, idx),
				Type:    IntType{Width: Size8, Signed: true},
				Version: int(seed%3) + 1,
			},
		})
	}
	return &Phi{
		Dest: Variable{
			Name:    fmt.Sprintf("tmp%d_%d", blockID, idx),
			Type:    IntType{Width: Size8, Signed: true},
			Version: int(seed%3) + 2,
		},
		Sources: sources,
	}
}

func genRandTerminator(id BlockID, totalBlocks int, seed int64) IRInstruction {
	if seed < 0 {
		seed = -seed
	}
	isLast := int(id) == totalBlocks-1 || totalBlocks == 1

	if isLast {
		if seed%2 == 0 {
			return &Return{Value: nil}
		}
		retVar := Variable{
			Name:    fmt.Sprintf("tmp%d", id),
			Type:    IntType{Width: Size8, Signed: true},
			Version: 1,
		}
		return &Return{Value: &retVar}
	}

	switch seed % 3 {
	case 0:
		return &Jump{Target: id + 1}
	case 1:
		trueTarget := id + 1
		falseTarget := BlockID(totalBlocks - 1)
		if falseTarget == id {
			falseTarget = 0
		}
		return &Branch{
			Condition:   genSimpleExpr(id, 0, 1),
			TrueTarget:  trueTarget,
			FalseTarget: falseTarget,
		}
	default:
		return &Jump{Target: id + 1}
	}
}

func genSimpleExpr(blockID BlockID, idx int, depth int) Expression {
	if depth >= 2 {
		idx64 := uint64(uint(idx + depth)) //nolint:gosec
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

	idx64 := uint64(uint(idx + depth)) //nolint:gosec
	switch (uint64(blockID) + idx64) % 5 {
	case 0:
		return genIntConstantExpr(int64(blockID)*10 + int64(idx)) //nolint:gosec
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

func genIntConstantExpr(val int64) ConstantExpr {
	return ConstantExpr{
		Value: IntConstant{
			Value:  val,
			Width:  Size8,
			Signed: true,
		},
	}
}

func genBinaryOpExpr(blockID BlockID, idx int, depth int) BinaryOp {
	ops := []BinaryOperator{
		BinOpAdd, BinOpSub, BinOpMul, BinOpDiv, BinOpMod,
		BinOpAnd, BinOpOr, BinOpXor,
		BinOpShl, BinOpShr, BinOpSar,
		BinOpUDiv, BinOpUMod,
	}
	op := ops[(uint64(blockID)+uint64(uint(idx)))%uint64(len(ops))] //nolint:gosec
	left := genSimpleExpr(blockID, idx, depth+1)
	right := genSimpleExpr(blockID, idx+1, depth+1)
	return BinaryOp{Op: op, Left: left, Right: right}
}

func genUnaryOpExpr(blockID BlockID, idx int, depth int) UnaryOp {
	ops := []UnaryOperator{UnOpNeg, UnOpNot, UnOpLogicalNot}
	op := ops[(uint64(blockID)+uint64(uint(idx)))%uint64(len(ops))] //nolint:gosec
	operand := genSimpleExpr(blockID, idx, depth+1)
	return UnaryOp{Op: op, Operand: operand}
}

func genCastExpr(blockID BlockID, idx int, depth int) Cast {
	targetTypes := []Type{
		IntType{Width: Size4, Signed: true},
		IntType{Width: Size2, Signed: false},
		IntType{Width: Size1, Signed: false},
	}
	idx64 := uint64(idx)                                                        //nolint:gosec
	targetType := targetTypes[(uint64(blockID)+idx64)%uint64(len(targetTypes))] //nolint:gosec
	inner := genSimpleExpr(blockID, idx, depth+1)
	return Cast{Expr: inner, TargetType: targetType}
}

func normalizeIROutput(s string) string {
	lines := strings.Split(s, "\n")
	var result []string
	for _, line := range lines {
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
