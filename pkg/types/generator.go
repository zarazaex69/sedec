package typeinfer

import (
	"fmt"
	"sync/atomic"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// syntheticCounter generates unique ids for synthetic type variables.
var syntheticCounter atomic.Int64

// newSyntheticVar creates a fresh synthetic type variable with the given prefix.
func newSyntheticVar(prefix string) TypeVar {
	id := syntheticCounter.Add(1)
	return TypeVar{Name: fmt.Sprintf("$%s_%d", prefix, id)}
}

// typeVarForVariable returns the canonical TypeVar for an IR variable.
func typeVarForVariable(v ir.Variable) TypeVar {
	tv := TypeVar{Name: v.String()}
	if v.Type != nil {
		tv.Concrete = v.Type
	}
	return tv
}

// typeVarForExpr returns the TypeVar for an expression.
// for VariableExpr it delegates to typeVarForVariable.
// for ConstantExpr it returns a concrete TypeVar.
// for compound expressions it returns a fresh synthetic var.
func typeVarForExpr(expr ir.Expression) TypeVar {
	switch e := expr.(type) {
	case ir.VariableExpr:
		return typeVarForVariable(e.Var)
	case ir.ConstantExpr:
		return TypeVar{Name: fmt.Sprintf("$const_%s", e.String()), Concrete: e.Type()}
	default:
		return newSyntheticVar("expr")
	}
}

// ConstraintGenerator traverses an IR function and emits TypeConstraints
// for every instruction it encounters. it is the entry point for task 9.1.
type ConstraintGenerator struct {
	fn          *ir.Function
	constraints []TypeConstraint
}

// NewConstraintGenerator creates a generator for the given IR function.
func NewConstraintGenerator(fn *ir.Function) *ConstraintGenerator {
	return &ConstraintGenerator{fn: fn}
}

// GenerateConstraints traverses every basic block and instruction in the function
// and returns the complete set of type constraints.
// Requirements: 11.1
func (g *ConstraintGenerator) GenerateConstraints() []TypeConstraint {
	g.constraints = make([]TypeConstraint, 0, len(g.fn.Variables)*2)

	// seed concrete types from the function signature
	g.seedSignatureConstraints()

	// visit blocks in a deterministic order (sorted by block id)
	blockIDs := sortedBlockIDs(g.fn)
	for _, bid := range blockIDs {
		block := g.fn.Blocks[bid]
		for _, instr := range block.Instructions {
			g.visitInstruction(instr)
		}
	}

	return g.constraints
}

// seedSignatureConstraints emits constraints derived from the known function signature.
// parameter types and return type are treated as high-confidence axioms (0.8).
func (g *ConstraintGenerator) seedSignatureConstraints() {
	sig := g.fn.Signature
	if sig.ReturnType == nil {
		return
	}
	retTV := TypeVar{Name: "$ret_" + g.fn.Name, Concrete: sig.ReturnType}
	for i, paramType := range sig.Parameters {
		paramTV := TypeVar{
			Name:     fmt.Sprintf("$param_%s_%d", g.fn.Name, i),
			Concrete: paramType,
		}
		g.emit(TypeConstraint{
			Kind:       ConstraintEquality,
			Left:       paramTV,
			Right:      paramTV,
			Confidence: 0.8,
			Origin:     fmt.Sprintf("function signature param %d", i),
		})
		_ = retTV // used below when return instructions are visited
	}
}

// visitInstruction dispatches to the appropriate constraint-generation method
// based on the dynamic type of the IR instruction.
func (g *ConstraintGenerator) visitInstruction(instr ir.IRInstruction) {
	switch i := instr.(type) {
	case ir.Assign:
		g.visitAssign(i)
	case ir.Load:
		g.visitLoad(i)
	case ir.Store:
		g.visitStore(i)
	case ir.Branch:
		g.visitBranch(i)
	case ir.Call:
		g.visitCall(i)
	case ir.Return:
		g.visitReturn(i)
	case ir.Phi:
		g.visitPhi(i)
	case ir.Intrinsic:
		g.visitIntrinsic(i)
	case ir.Jump:
	}
}

// visitAssign emits: type(dest) eq type(source)
// if source is a cast, also emits a subtype constraint from the original expression.
func (g *ConstraintGenerator) visitAssign(a ir.Assign) {
	destTV := typeVarForVariable(a.Dest)
	srcTV := typeVarForExpr(a.Source)

	g.emit(TypeConstraint{
		Kind:       ConstraintEquality,
		Left:       destTV,
		Right:      srcTV,
		Confidence: 0.5,
		Origin:     fmt.Sprintf("assign at %s", a.Location()),
	})

	// if the source is a cast, the original expression is a subtype of the target
	if cast, ok := a.Source.(ir.Cast); ok {
		innerTV := typeVarForExpr(cast.Expr)
		castTV := TypeVar{Name: destTV.Name + "$cast", Concrete: cast.TargetType}
		g.emit(TypeConstraint{
			Kind:       ConstraintSubtype,
			Left:       innerTV,
			Right:      castTV,
			Confidence: 0.5,
			Origin:     fmt.Sprintf("cast at %s", a.Location()),
		})
	}

	// propagate constraints from the expression tree
	g.visitExpression(a.Source, destTV, a.Location().String())
}

// visitLoad emits:
//   - type(address) eq ptr(type(dest))   [ConstraintPointerTo]
//   - type(dest) has concrete width from load size
func (g *ConstraintGenerator) visitLoad(l ir.Load) {
	destTV := typeVarForVariable(l.Dest)
	addrTV := typeVarForExpr(l.Address)

	// the address expression must be a pointer to the loaded type
	g.emit(TypeConstraint{
		Kind:       ConstraintPointerTo,
		Left:       addrTV,
		Right:      destTV,
		Confidence: 0.5,
		Origin:     fmt.Sprintf("load at %s", l.Location()),
	})

	// if the load size is known, constrain dest to an integer of that width
	if l.Size > 0 {
		sizedTV := TypeVar{
			Name:     destTV.Name + "$sized",
			Concrete: ir.IntType{Width: l.Size, Signed: false},
		}
		g.emit(TypeConstraint{
			Kind:       ConstraintEquality,
			Left:       destTV,
			Right:      sizedTV,
			Confidence: 0.4,
			Origin:     fmt.Sprintf("load size %d at %s", l.Size, l.Location()),
		})
	}

	// if the address is a binary add (base + const_offset), emit a field constraint
	if binop, ok := l.Address.(ir.BinaryOp); ok && binop.Op == ir.BinOpAdd {
		if constExpr, ok := binop.Right.(ir.ConstantExpr); ok {
			if intConst, ok := constExpr.Value.(ir.IntConstant); ok {
				baseTV := typeVarForExpr(binop.Left)
				g.emit(TypeConstraint{
					Kind:        ConstraintFieldAccess,
					Left:        baseTV,
					Right:       destTV,
					FieldOffset: intConst.Value,
					Confidence:  0.5,
					Origin:      fmt.Sprintf("load field offset %d at %s", intConst.Value, l.Location()),
				})
			}
		}
	}
}

// visitStore emits:
//   - type(address) eq ptr(type(value))  [ConstraintPointerTo]
//   - field constraint when address is base+offset
func (g *ConstraintGenerator) visitStore(s ir.Store) {
	valTV := typeVarForExpr(s.Value)
	addrTV := typeVarForExpr(s.Address)

	g.emit(TypeConstraint{
		Kind:       ConstraintPointerTo,
		Left:       addrTV,
		Right:      valTV,
		Confidence: 0.5,
		Origin:     fmt.Sprintf("store at %s", s.Location()),
	})

	// field access from base+const_offset pattern
	if binop, ok := s.Address.(ir.BinaryOp); ok && binop.Op == ir.BinOpAdd {
		if constExpr, ok := binop.Right.(ir.ConstantExpr); ok {
			if intConst, ok := constExpr.Value.(ir.IntConstant); ok {
				baseTV := typeVarForExpr(binop.Left)
				g.emit(TypeConstraint{
					Kind:        ConstraintFieldAccess,
					Left:        baseTV,
					Right:       valTV,
					FieldOffset: intConst.Value,
					Confidence:  0.5,
					Origin:      fmt.Sprintf("store field offset %d at %s", intConst.Value, s.Location()),
				})
			}
		}
	}
}

// visitBranch emits: type(condition) eq bool
func (g *ConstraintGenerator) visitBranch(b ir.Branch) {
	condTV := typeVarForExpr(b.Condition)
	boolTV := TypeVar{Name: "$bool", Concrete: ir.BoolType{}}
	g.emit(TypeConstraint{
		Kind:       ConstraintEquality,
		Left:       condTV,
		Right:      boolTV,
		Confidence: 0.9,
		Origin:     fmt.Sprintf("branch condition at %s", b.Location()),
	})
}

// visitCall emits:
//   - type(dest) eq return_type(target)   [ConstraintReturnType]
//   - type(arg_i) eq param_type_i(target) [ConstraintParamType]
func (g *ConstraintGenerator) visitCall(c ir.Call) {
	targetTV := typeVarForExpr(c.Target)

	// return value constraint
	if c.Dest != nil {
		destTV := typeVarForVariable(*c.Dest)
		g.emit(TypeConstraint{
			Kind:       ConstraintReturnType,
			Left:       targetTV,
			Right:      destTV,
			Confidence: 0.5,
			Origin:     fmt.Sprintf("call return at %s", c.Location()),
		})
	}

	// argument constraints
	for idx, arg := range c.Args {
		argTV := typeVarForVariable(arg)
		g.emit(TypeConstraint{
			Kind:       ConstraintParamType,
			Left:       targetTV,
			Right:      argTV,
			ParamIndex: idx,
			Confidence: 0.5,
			Origin:     fmt.Sprintf("call arg %d at %s", idx, c.Location()),
		})
	}
}

// visitReturn emits: type(value) eq return_type(function)
func (g *ConstraintGenerator) visitReturn(r ir.Return) {
	if r.Value == nil {
		return
	}
	retValTV := typeVarForVariable(*r.Value)
	retTV := TypeVar{Name: "$ret_" + g.fn.Name, Concrete: g.fn.Signature.ReturnType}
	g.emit(TypeConstraint{
		Kind:       ConstraintEquality,
		Left:       retValTV,
		Right:      retTV,
		Confidence: 0.8,
		Origin:     fmt.Sprintf("return at %s", r.Location()),
	})
}

// visitPhi emits: type(dest) eq type(src_i) for every phi source.
// all sources and the destination must unify to the same type.
func (g *ConstraintGenerator) visitPhi(p ir.Phi) {
	destTV := typeVarForVariable(p.Dest)
	for _, src := range p.Sources {
		srcTV := typeVarForVariable(src.Var)
		g.emit(TypeConstraint{
			Kind:       ConstraintEquality,
			Left:       destTV,
			Right:      srcTV,
			Confidence: 0.5,
			Origin:     fmt.Sprintf("phi source bb%d at %s", src.Block, p.Location()),
		})
	}
}

// visitExpression recursively emits constraints for compound expressions.
// parentTV is the type variable of the expression's consumer (used for equality).
func (g *ConstraintGenerator) visitExpression(expr ir.Expression, parentTV TypeVar, origin string) {
	switch e := expr.(type) {
	case ir.BinaryOp:
		g.visitBinaryOp(e, parentTV, origin)
	case ir.UnaryOp:
		g.visitUnaryOp(e, parentTV, origin)
	case ir.Cast:
		// cast already handled in visitAssign; nothing extra needed here
	case ir.VariableExpr, ir.ConstantExpr:
		// leaf nodes: equality already emitted by the caller
	}
}

// visitBinaryOp emits constraints for a binary operation.
// arithmetic/bitwise ops: type(left) eq type(right) eq type(result)
// comparison ops:         type(left) eq type(right), type(result) eq bool
// unsigned ops:           type(left) eq type(right) eq unsigned int
func (g *ConstraintGenerator) visitBinaryOp(e ir.BinaryOp, resultTV TypeVar, origin string) {
	leftTV := typeVarForExpr(e.Left)
	rightTV := typeVarForExpr(e.Right)

	switch e.Op {
	case ir.BinOpEq, ir.BinOpNe,
		ir.BinOpLt, ir.BinOpLe, ir.BinOpGt, ir.BinOpGe:
		// signed comparison: operands must have equal types
		g.emit(TypeConstraint{
			Kind: ConstraintEquality, Left: leftTV, Right: rightTV,
			Confidence: 0.5, Origin: origin + " cmp operands",
		})
		// result is bool
		boolTV := TypeVar{Name: "$bool", Concrete: ir.BoolType{}}
		g.emit(TypeConstraint{
			Kind: ConstraintEquality, Left: resultTV, Right: boolTV,
			Confidence: 0.9, Origin: origin + " cmp result",
		})

	case ir.BinOpULt, ir.BinOpULe, ir.BinOpUGt, ir.BinOpUGe:
		// unsigned comparison: operands must be unsigned integers
		g.emit(TypeConstraint{
			Kind: ConstraintEquality, Left: leftTV, Right: rightTV,
			Confidence: 0.5, Origin: origin + " ucmp operands",
		})
		boolTV := TypeVar{Name: "$bool", Concrete: ir.BoolType{}}
		g.emit(TypeConstraint{
			Kind: ConstraintEquality, Left: resultTV, Right: boolTV,
			Confidence: 0.9, Origin: origin + " ucmp result",
		})

	case ir.BinOpUDiv, ir.BinOpUMod:
		// unsigned arithmetic: both operands and result are unsigned
		unsignedTV := newSyntheticVar("uint")
		g.emit(TypeConstraint{
			Kind: ConstraintEquality, Left: leftTV, Right: unsignedTV,
			Confidence: 0.6, Origin: origin + " udiv left",
		})
		g.emit(TypeConstraint{
			Kind: ConstraintEquality, Left: rightTV, Right: unsignedTV,
			Confidence: 0.6, Origin: origin + " udiv right",
		})
		g.emit(TypeConstraint{
			Kind: ConstraintEquality, Left: resultTV, Right: unsignedTV,
			Confidence: 0.6, Origin: origin + " udiv result",
		})

	case ir.BinOpLogicalAnd, ir.BinOpLogicalOr:
		// logical ops: operands and result are bool
		boolTV := TypeVar{Name: "$bool", Concrete: ir.BoolType{}}
		g.emit(TypeConstraint{
			Kind: ConstraintEquality, Left: leftTV, Right: boolTV,
			Confidence: 0.9, Origin: origin + " logical left",
		})
		g.emit(TypeConstraint{
			Kind: ConstraintEquality, Left: rightTV, Right: boolTV,
			Confidence: 0.9, Origin: origin + " logical right",
		})
		g.emit(TypeConstraint{
			Kind: ConstraintEquality, Left: resultTV, Right: boolTV,
			Confidence: 0.9, Origin: origin + " logical result",
		})

	case ir.BinOpAdd, ir.BinOpSub, ir.BinOpMul, ir.BinOpDiv, ir.BinOpMod,
		ir.BinOpAnd, ir.BinOpOr, ir.BinOpXor, ir.BinOpShl, ir.BinOpShr, ir.BinOpSar:
		// arithmetic and bitwise: all three must have the same type
		g.emit(TypeConstraint{
			Kind: ConstraintEquality, Left: leftTV, Right: rightTV,
			Confidence: 0.5, Origin: origin + " arith operands",
		})
		g.emit(TypeConstraint{
			Kind: ConstraintEquality, Left: resultTV, Right: leftTV,
			Confidence: 0.5, Origin: origin + " arith result",
		})

	default:
		// arithmetic and bitwise: all three must have the same type
		g.emit(TypeConstraint{
			Kind: ConstraintEquality, Left: leftTV, Right: rightTV,
			Confidence: 0.5, Origin: origin + " arith operands",
		})
		g.emit(TypeConstraint{
			Kind: ConstraintEquality, Left: resultTV, Right: leftTV,
			Confidence: 0.5, Origin: origin + " arith result",
		})
	}

	// recurse into sub-expressions
	g.visitExpression(e.Left, leftTV, origin)
	g.visitExpression(e.Right, rightTV, origin)
}

// visitUnaryOp emits constraints for a unary operation.
func (g *ConstraintGenerator) visitUnaryOp(e ir.UnaryOp, resultTV TypeVar, origin string) {
	operandTV := typeVarForExpr(e.Operand)

	if e.Op == ir.UnOpLogicalNot {
		boolTV := TypeVar{Name: "$bool", Concrete: ir.BoolType{}}
		g.emit(TypeConstraint{
			Kind: ConstraintEquality, Left: operandTV, Right: boolTV,
			Confidence: 0.9, Origin: origin + " lnot operand",
		})
		g.emit(TypeConstraint{
			Kind: ConstraintEquality, Left: resultTV, Right: boolTV,
			Confidence: 0.9, Origin: origin + " lnot result",
		})
	} else {
		// neg / bitwise-not: result has same type as operand
		g.emit(TypeConstraint{
			Kind: ConstraintEquality, Left: resultTV, Right: operandTV,
			Confidence: 0.5, Origin: origin + " unary result",
		})
	}

	g.visitExpression(e.Operand, operandTV, origin)
}

func (g *ConstraintGenerator) visitIntrinsic(i ir.Intrinsic) {
	if i.Dest == nil {
		return
	}
	destTV := typeVarForVariable(*i.Dest)
	for idx, arg := range i.Args {
		argTV := typeVarForExpr(arg)
		g.emit(TypeConstraint{
			Kind:       ConstraintParamType,
			Left:       destTV,
			Right:      argTV,
			ParamIndex: idx,
			Confidence: 0.3,
			Origin:     fmt.Sprintf("intrinsic %s arg %d at %s", i.Name, idx, i.Location()),
		})
	}
}

// emit appends a constraint to the internal list.
func (g *ConstraintGenerator) emit(c TypeConstraint) {
	g.constraints = append(g.constraints, c)
}

// sortedBlockIDs returns the block IDs of the function in ascending order
// to guarantee deterministic constraint generation across runs.
func sortedBlockIDs(fn *ir.Function) []ir.BlockID {
	ids := make([]ir.BlockID, 0, len(fn.Blocks))
	for id := range fn.Blocks {
		ids = append(ids, id)
	}
	// insertion sort is fine for typical function sizes (< 500 blocks)
	for i := 1; i < len(ids); i++ {
		key := ids[i]
		j := i - 1
		for j >= 0 && ids[j] > key {
			ids[j+1] = ids[j]
			j--
		}
		ids[j+1] = key
	}
	return ids
}
