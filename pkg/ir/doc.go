// Package ir defines the Intermediate Representation for platform-independent analysis.
// It provides three-address code with explicit operands, typed values, memory operations,
// control flow instructions, and support for SSA phi-nodes.
// Package ir provides the Intermediate Representation (IR) for the sedec decompiler.
//
// The IR is a platform-independent, typed, three-address code representation that serves
// as the foundation for all analysis and optimization passes. It abstracts away
// architecture-specific details while preserving semantic information necessary for
// accurate decompilation.
//
// # Design Principles
//
// 1. Platform Independence: IR abstracts x86_64/ARM64/MIPS specifics into uniform operations
// 2. Strong Typing: Every expression and variable has an explicit type for inference
// 3. SSA Support: Phi nodes enable Static Single Assignment form for precise data flow
// 4. Traceability: Source location metadata links IR back to original assembly
// 5. Serializability: Human-readable text format for debugging and inspection
//
// # Type System
//
// The IR type system includes:
//   - Primitive types: Void, Bool, Int (signed/unsigned, 8/16/32/64-bit), Float (32/64/80/128-bit)
//   - Composite types: Pointer, Array, Struct
//   - Function types: Complete signatures with parameters and return types
//
// # Instruction Set
//
// IR instructions follow three-address code format:
//   - Assign: dest = source
//   - Load: dest = *address (explicit memory read)
//   - Store: *address = value (explicit memory write)
//   - Branch: conditional control flow
//   - Jump: unconditional control flow
//   - Call: function invocation
//   - Return: function exit
//   - Phi: SSA merge point for multiple definitions
//
// # Expression System
//
// Expressions are typed, composable value producers:
//   - Variable references
//   - Constants (integer, float, bool, null)
//   - Binary operations (arithmetic, bitwise, comparison, logical)
//   - Unary operations (negation, bitwise not, logical not)
//   - Type casts
//
// # Usage Example
//
//	// create a simple function: int add(int a, int b) { return a + b; }
//	fn := &ir.Function{
//		Name: "add",
//		Signature: ir.FunctionType{
//			ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
//			Parameters: []ir.Type{
//				ir.IntType{Width: ir.Size4, Signed: true},
//				ir.IntType{Width: ir.Size4, Signed: true},
//			},
//		},
//		Blocks: make(map[ir.BlockID]*ir.BasicBlock),
//		EntryBlock: 0,
//	}
//
//	// create basic block with addition
//	block := &ir.BasicBlock{
//		ID: 0,
//		Instructions: []ir.IRInstruction{
//			&ir.Assign{
//				Dest: ir.Variable{Name: "result", Type: ir.IntType{Width: ir.Size4, Signed: true}},
//				Source: &ir.BinaryOp{
//					Op: ir.BinOpAdd,
//					Left: &ir.VariableExpr{Var: ir.Variable{Name: "a", Type: ir.IntType{Width: ir.Size4, Signed: true}}},
//					Right: &ir.VariableExpr{Var: ir.Variable{Name: "b", Type: ir.IntType{Width: ir.Size4, Signed: true}}},
//				},
//			},
//			&ir.Return{
//				Value: &ir.Variable{Name: "result", Type: ir.IntType{Width: ir.Size4, Signed: true}},
//			},
//		},
//	}
//	fn.Blocks[0] = block
package ir
