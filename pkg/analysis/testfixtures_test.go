package analysis

import "github.com/zarazaex69/sedec/pkg/ir"

// makeIfThenElseFunction builds a diamond-shaped ir.Function for shared test use.
// structure:
//
//	bb0: cond_1 = 1; branch cond_1 -> bb1/bb2
//	bb1: x_1 = 10; jump bb3
//	bb2: x_2 = 20; jump bb3
//	bb3: x_3 = phi(x_1, x_2); return x_3
func makeIfThenElseFunction() *ir.Function {
	return &ir.Function{
		Name: "if_then_else",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("cond", 1), Source: intConst(1)},
					&ir.Branch{
						Condition:   varExpr("cond", 1),
						TrueTarget:  1,
						FalseTarget: 2,
					},
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("x", 1), Source: intConst(10)},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("x", 2), Source: intConst(20)},
					&ir.Jump{Target: 3},
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3},
			},
			3: {
				ID: 3,
				Instructions: []ir.IRInstruction{
					&ir.Phi{
						Dest: ssaVar("x", 3),
						Sources: []ir.PhiSource{
							{Block: 1, Var: ssaVar("x", 1)},
							{Block: 2, Var: ssaVar("x", 2)},
						},
					},
					&ir.Return{Value: &ir.Variable{Name: "x", Type: intType(), Version: 3}},
				},
				Predecessors: []ir.BlockID{1, 2},
			},
		},
		EntryBlock: 0,
	}
}

// makeWhileLoopFunction builds a loop-shaped ir.Function for shared test use.
// structure:
//
//	bb0: i_1 = 0
//	bb1: i_2 = phi(i_1, i_3); branch i_2 < 10 -> bb2/bb3
//	bb2: i_3 = i_2 + 1; jump bb1
//	bb3: return i_2
func makeWhileLoopFunction() *ir.Function {
	return &ir.Function{
		Name: "while_loop",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("i", 1), Source: intConst(0)},
				},
				Successors: []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Phi{
						Dest: ssaVar("i", 2),
						Sources: []ir.PhiSource{
							{Block: 0, Var: ssaVar("i", 1)},
							{Block: 2, Var: ssaVar("i", 3)},
						},
					},
					&ir.Branch{
						Condition: ir.BinaryOp{
							Op:    ir.BinOpLt,
							Left:  varExpr("i", 2),
							Right: intConst(10),
						},
						TrueTarget:  2,
						FalseTarget: 3,
					},
				},
				Predecessors: []ir.BlockID{0, 2},
				Successors:   []ir.BlockID{2, 3},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest: ssaVar("i", 3),
						Source: ir.BinaryOp{
							Op:    ir.BinOpAdd,
							Left:  varExpr("i", 2),
							Right: intConst(1),
						},
					},
					&ir.Jump{Target: 1},
				},
				Predecessors: []ir.BlockID{1},
				Successors:   []ir.BlockID{1},
			},
			3: {
				ID: 3,
				Instructions: []ir.IRInstruction{
					&ir.Return{Value: &ir.Variable{Name: "i", Type: intType(), Version: 2}},
				},
				Predecessors: []ir.BlockID{1},
			},
		},
		EntryBlock: 0,
	}
}

// makeMultiVarFunction builds a two-block ir.Function with multiple variables.
// structure:
//
//	bb0: x_1 = 1; y_1 = 2
//	bb1: z_1 = x_1 + y_1; return z_1
func makeMultiVarFunction() *ir.Function {
	return &ir.Function{
		Name: "multi_var",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: ssaVar("x", 1), Source: intConst(1)},
					&ir.Assign{Dest: ssaVar("y", 1), Source: intConst(2)},
				},
				Successors: []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest: ssaVar("z", 1),
						Source: ir.BinaryOp{
							Op:    ir.BinOpAdd,
							Left:  varExpr("x", 1),
							Right: varExpr("y", 1),
						},
					},
					&ir.Return{Value: &ir.Variable{Name: "z", Type: intType(), Version: 1}},
				},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}
}
