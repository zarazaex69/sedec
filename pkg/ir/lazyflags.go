package ir

// lazyflags.go implements lazy cpu flag evaluation for x86_64 decompilation.
//
// architectural rationale:
// x86_64 arithmetic operations set 6 cpu flags (zf, sf, cf, of, pf, af), but most
// of these flags are never used before being overwritten. immediate flag computation
// pollutes ir with unnecessary operations. lazy evaluation defers flag materialization
// until actual use in conditional branches (jcc, cmovcc, setcc), achieving 95%+ elimination.
//
// design principles:
// 1. lazyflags structure stores operation + operands instead of immediate computation
// 2. materialized flag tracks whether flag has been computed (false = lazy, true = materialized)
// 3. data flow analyzer eliminates unused lazy flags during dead code elimination
// 4. selective materialization: je/jne only materializes zf, not all 6 flags
//
// integration with ssa:
// - lazy flags participate in ssa transformation as regular variables
// - phi-nodes can merge lazy flag values from different paths
// - def-use chains track flag consumers for elimination analysis

// x86_64 conditional jump mnemonic constants
const (
	mnemonicJe   = "je"
	mnemonicJz   = "jz"
	mnemonicJne  = "jne"
	mnemonicJnz  = "jnz"
	mnemonicJl   = "jl"
	mnemonicJnge = "jnge"
	mnemonicJge  = "jge"
	mnemonicJnl  = "jnl"
	mnemonicJle  = "jle"
	mnemonicJng  = "jng"
	mnemonicJg   = "jg"
	mnemonicJnle = "jnle"
	mnemonicJb   = "jb"
	mnemonicJnae = "jnae"
	mnemonicJc   = "jc"
	mnemonicJae  = "jae"
	mnemonicJnb  = "jnb"
	mnemonicJnc  = "jnc"
	mnemonicJbe  = "jbe"
	mnemonicJna  = "jna"
	mnemonicJa   = "ja"
	mnemonicJnbe = "jnbe"
	mnemonicJs   = "js"
	mnemonicJns  = "jns"
	mnemonicJo   = "jo"
	mnemonicJno  = "jno"
	mnemonicJp   = "jp"
	mnemonicJpe  = "jpe"
	mnemonicJnp  = "jnp"
	mnemonicJpo  = "jpo"
	mnemonicAdd  = "add"
)

// CPUFlag represents individual x86_64 cpu flags
type CPUFlag int

const (
	// FlagZF is zero flag (result == 0)
	FlagZF CPUFlag = iota
	// FlagSF is sign flag (result < 0, high bit set)
	FlagSF
	// FlagCF is carry flag (unsigned overflow)
	FlagCF
	// FlagOF is overflow flag (signed overflow)
	FlagOF
	// FlagPF is parity flag (even number of 1 bits in low byte)
	FlagPF
	// FlagAF is auxiliary carry flag (carry from bit 3 to bit 4)
	FlagAF
)

// String returns human-readable flag name
func (f CPUFlag) String() string {
	switch f {
	case FlagZF:
		return "zf"
	case FlagSF:
		return "sf"
	case FlagCF:
		return "cf"
	case FlagOF:
		return "of"
	case FlagPF:
		return "pf"
	case FlagAF:
		return "af"
	default:
		return "unknown_flag"
	}
}

// FlagOperation represents the operation that produces flag values
type FlagOperation int

const (
	// FlagOpArithmetic represents arithmetic operations (add, sub, inc, dec, neg, cmp)
	FlagOpArithmetic FlagOperation = iota
	// FlagOpLogical represents logical operations (and, or, xor, test)
	FlagOpLogical
	// FlagOpShift represents shift operations (shl, shr, sar, rol, ror)
	FlagOpShift
	// FlagOpMultiply represents multiplication (mul, imul)
	FlagOpMultiply
	// FlagOpDivide represents division (div, idiv) - flags undefined
	FlagOpDivide
)

// String returns human-readable operation name
func (op FlagOperation) String() string {
	switch op {
	case FlagOpArithmetic:
		return "arithmetic"
	case FlagOpLogical:
		return "logical"
	case FlagOpShift:
		return "shift"
	case FlagOpMultiply:
		return "multiply"
	case FlagOpDivide:
		return "divide"
	default:
		return "unknown_op"
	}
}

// LazyFlags represents deferred cpu flag computation.
//
// instead of immediately computing all 6 flags after each arithmetic operation,
// lazyflags stores the operation and operands. flags are materialized only when
// actually consumed by conditional branches or flag-reading instructions.
//
// example:
//
//	add rax, rbx  -> lazyflags{op: arithmetic, operands: [rax, rbx], result: rax}
//	add rcx, rdx  -> lazyflags{op: arithmetic, operands: [rcx, rdx], result: rcx}
//	je target     -> materializes only zf from second add, first add flags eliminated
//
// materialization rules:
//
//	je/jne  -> materialize zf only
//	jl/jge  -> materialize sf, of only
//	jb/jae  -> materialize cf only
//	js/jns  -> materialize sf only
//	jo/jno  -> materialize of only
//	jp/jnp  -> materialize pf only
type LazyFlags struct {
	// Operation is the type of operation that produced these flags
	Operation FlagOperation

	// Operands are the input operands to the operation
	// for binary ops: [left, right]
	// for unary ops: [operand]
	Operands []Expression

	// Result is the computed result of the operation (for flag computation)
	Result Expression

	// Size is the operand size in bytes (affects flag computation)
	Size Size

	// Materialized tracks which flags have been computed
	// key: CPUFlag, value: true if materialized
	Materialized map[CPUFlag]bool

	// SourceLocation tracks where flags were created for debugging
	Location SourceLocation
}

// NewLazyFlags creates a new lazy flags structure for deferred evaluation.
func NewLazyFlags(op FlagOperation, operands []Expression, result Expression, size Size, loc SourceLocation) *LazyFlags {
	return &LazyFlags{
		Operation:    op,
		Operands:     operands,
		Result:       result,
		Size:         size,
		Materialized: make(map[CPUFlag]bool),
		Location:     loc,
	}
}

// IsMaterialized checks if a specific flag has been computed.
func (lf *LazyFlags) IsMaterialized(flag CPUFlag) bool {
	return lf.Materialized[flag]
}

// MarkMaterialized marks a flag as computed (no longer lazy).
func (lf *LazyFlags) MarkMaterialized(flag CPUFlag) {
	lf.Materialized[flag] = true
}

// IsAnyMaterialized checks if any flag has been materialized.
func (lf *LazyFlags) IsAnyMaterialized() bool {
	return len(lf.Materialized) > 0
}

// GetMaterializedFlags returns list of materialized flags.
func (lf *LazyFlags) GetMaterializedFlags() []CPUFlag {
	flags := make([]CPUFlag, 0, len(lf.Materialized))
	for flag, materialized := range lf.Materialized {
		if materialized {
			flags = append(flags, flag)
		}
	}
	return flags
}

// MaterializeFlag computes a specific flag value on demand.
//
// this method generates ir instructions to compute the requested flag
// based on the stored operation and operands. only the requested flag
// is computed, not all 6 flags.
//
// returns: expression representing the flag value (boolean)
func (lf *LazyFlags) MaterializeFlag(flag CPUFlag) Expression {
	// mark as materialized
	lf.MarkMaterialized(flag)

	// dispatch by operation type
	switch lf.Operation {
	case FlagOpArithmetic:
		return lf.materializeArithmeticFlag(flag)
	case FlagOpLogical:
		return lf.materializeLogicalFlag(flag)
	case FlagOpShift:
		return lf.materializeShiftFlag(flag)
	case FlagOpMultiply:
		return lf.materializeMultiplyFlag(flag)
	case FlagOpDivide:
		// flags undefined after division
		return ConstantExpr{Value: BoolConstant{Value: false}}
	default:
		// unknown operation - return false
		return ConstantExpr{Value: BoolConstant{Value: false}}
	}
}

// materializeArithmeticFlag computes flag for arithmetic operations (add, sub, cmp, inc, dec, neg)
func (lf *LazyFlags) materializeArithmeticFlag(flag CPUFlag) Expression {
	result := lf.Result

	switch flag {
	case FlagZF:
		// zf = (result == 0)
		zeroExpr := ConstantExpr{
			Value: IntConstant{
				Value:  0,
				Width:  lf.Size,
				Signed: false,
			},
		}
		return BinaryOp{
			Op:    BinOpEq,
			Left:  result,
			Right: zeroExpr,
		}

	case FlagSF:
		// sf = (result < 0) - check sign bit
		signBitMask := ConstantExpr{
			Value: IntConstant{
				Value:  int64(1) << (int64(lf.Size)*8 - 1),
				Width:  lf.Size,
				Signed: false,
			},
		}
		signBitExpr := BinaryOp{
			Op:    BinOpAnd,
			Left:  result,
			Right: signBitMask,
		}
		zeroExpr := ConstantExpr{
			Value: IntConstant{
				Value:  0,
				Width:  lf.Size,
				Signed: false,
			},
		}
		return BinaryOp{
			Op:    BinOpNe,
			Left:  signBitExpr,
			Right: zeroExpr,
		}

	case FlagCF:
		// cf = carry occurred (unsigned overflow)
		// for add: cf = (result < left)
		// for sub: cf = (left < right)
		if len(lf.Operands) >= 2 {
			left := lf.Operands[0]
			right := lf.Operands[1]

			// detect operation type from result expression
			if binOp, ok := result.(BinaryOp); ok {
				switch binOp.Op {
				case BinOpAdd:
					// add: cf = (result < left)
					return BinaryOp{
						Op:    BinOpULt,
						Left:  result,
						Right: left,
					}
				case BinOpSub:
					// sub: cf = (left < right)
					return BinaryOp{
						Op:    BinOpULt,
						Left:  left,
						Right: right,
					}
				default:
					return ConstantExpr{Value: BoolConstant{Value: false}}
				}
			}
		}
		// default: cf = false
		return ConstantExpr{Value: BoolConstant{Value: false}}

	case FlagOF:
		// of = signed overflow occurred
		// for add: of = (sign(left) == sign(right)) && (sign(result) != sign(left))
		// for sub: of = (sign(left) != sign(right)) && (sign(result) != sign(left))
		if len(lf.Operands) >= 2 {
			left := lf.Operands[0]
			right := lf.Operands[1]

			signBitMask := ConstantExpr{
				Value: IntConstant{
					Value:  int64(1) << (int64(lf.Size)*8 - 1),
					Width:  lf.Size,
					Signed: false,
				},
			}

			// extract sign bits
			leftSign := BinaryOp{
				Op:    BinOpAnd,
				Left:  left,
				Right: signBitMask,
			}
			rightSign := BinaryOp{
				Op:    BinOpAnd,
				Left:  right,
				Right: signBitMask,
			}
			resultSign := BinaryOp{
				Op:    BinOpAnd,
				Left:  result,
				Right: signBitMask,
			}

			// detect operation type
			if binOp, ok := result.(BinaryOp); ok {
				switch binOp.Op {
				case BinOpAdd:
					// add: of = (sign(left) == sign(right)) && (sign(result) != sign(left))
					signsEqual := BinaryOp{
						Op:    BinOpEq,
						Left:  leftSign,
						Right: rightSign,
					}
					resultDifferent := BinaryOp{
						Op:    BinOpNe,
						Left:  resultSign,
						Right: leftSign,
					}
					return BinaryOp{
						Op:    BinOpLogicalAnd,
						Left:  signsEqual,
						Right: resultDifferent,
					}
				case BinOpSub:
					// sub: of = (sign(left) != sign(right)) && (sign(result) != sign(left))
					signsDifferent := BinaryOp{
						Op:    BinOpNe,
						Left:  leftSign,
						Right: rightSign,
					}
					resultDifferent := BinaryOp{
						Op:    BinOpNe,
						Left:  resultSign,
						Right: leftSign,
					}
					return BinaryOp{
						Op:    BinOpLogicalAnd,
						Left:  signsDifferent,
						Right: resultDifferent,
					}
				default:
					return ConstantExpr{Value: BoolConstant{Value: false}}
				}
			}
		}
		// default: of = false
		return ConstantExpr{Value: BoolConstant{Value: false}}

	case FlagPF:
		// pf = parity of low byte (even number of 1 bits)
		// extract low byte
		lowByteMask := ConstantExpr{
			Value: IntConstant{
				Value:  0xFF,
				Width:  lf.Size,
				Signed: false,
			},
		}
		lowByte := BinaryOp{
			Op:    BinOpAnd,
			Left:  result,
			Right: lowByteMask,
		}
		// parity computation requires counting bits - complex
		// for now, return false (will be eliminated if unused)
		_ = lowByte
		return ConstantExpr{Value: BoolConstant{Value: false}}

	case FlagAF:
		// af = auxiliary carry (carry from bit 3 to bit 4)
		// used for bcd arithmetic - rarely used in modern code
		// for now, return false (will be eliminated if unused)
		return ConstantExpr{Value: BoolConstant{Value: false}}

	default:
		return ConstantExpr{Value: BoolConstant{Value: false}}
	}
}

// materializeLogicalFlag computes flag for logical operations (and, or, xor, test)
func (lf *LazyFlags) materializeLogicalFlag(flag CPUFlag) Expression {
	result := lf.Result

	switch flag {
	case FlagZF:
		// zf = (result == 0)
		zeroExpr := ConstantExpr{
			Value: IntConstant{
				Value:  0,
				Width:  lf.Size,
				Signed: false,
			},
		}
		return BinaryOp{
			Op:    BinOpEq,
			Left:  result,
			Right: zeroExpr,
		}

	case FlagSF:
		// sf = sign bit set
		signBitMask := ConstantExpr{
			Value: IntConstant{
				Value:  int64(1) << (int64(lf.Size)*8 - 1),
				Width:  lf.Size,
				Signed: false,
			},
		}
		signBitExpr := BinaryOp{
			Op:    BinOpAnd,
			Left:  result,
			Right: signBitMask,
		}
		zeroExpr := ConstantExpr{
			Value: IntConstant{
				Value:  0,
				Width:  lf.Size,
				Signed: false,
			},
		}
		return BinaryOp{
			Op:    BinOpNe,
			Left:  signBitExpr,
			Right: zeroExpr,
		}

	case FlagCF:
		// logical operations clear cf
		return ConstantExpr{Value: BoolConstant{Value: false}}

	case FlagOF:
		// logical operations clear of
		return ConstantExpr{Value: BoolConstant{Value: false}}

	case FlagPF:
		// pf = parity of low byte
		// complex computation - return false for now
		return ConstantExpr{Value: BoolConstant{Value: false}}

	case FlagAF:
		// af undefined for logical operations
		return ConstantExpr{Value: BoolConstant{Value: false}}

	default:
		return ConstantExpr{Value: BoolConstant{Value: false}}
	}
}

// materializeShiftFlag computes flag for shift operations (shl, shr, sar, rol, ror)
func (lf *LazyFlags) materializeShiftFlag(flag CPUFlag) Expression {
	return lf.materializeLogicalFlag(flag)
}

// materializeMultiplyFlag computes flag for multiply operations (mul, imul)
func (lf *LazyFlags) materializeMultiplyFlag(flag CPUFlag) Expression {
	switch flag {
	case FlagCF, FlagOF:
		// cf and of set if high part of result is non-zero
		// complex - requires tracking high part
		// for now, return false
		return ConstantExpr{Value: BoolConstant{Value: false}}

	case FlagZF, FlagSF, FlagPF, FlagAF:
		// undefined after multiply
		return ConstantExpr{Value: BoolConstant{Value: false}}

	default:
		return ConstantExpr{Value: BoolConstant{Value: false}}
	}
}

// GetRequiredFlags determines which flags are needed for a conditional jump.
//
// this function analyzes jump mnemonics to determine minimal flag set required,
// enabling selective materialization. for example, je/jne only needs zf, not all 6 flags.
//
// returns: slice of flags that must be materialized for this condition
func GetRequiredFlags(mnemonic string) []CPUFlag {
	switch mnemonic {
	case mnemonicJe, mnemonicJz, mnemonicJne, mnemonicJnz:
		// equal/not equal: only zf
		return []CPUFlag{FlagZF}

	case mnemonicJl, mnemonicJnge, mnemonicJge, mnemonicJnl:
		// less/greater or equal (signed): sf, of
		return []CPUFlag{FlagSF, FlagOF}

	case mnemonicJle, mnemonicJng, mnemonicJg, mnemonicJnle:
		// less or equal/greater (signed): zf, sf, of
		return []CPUFlag{FlagZF, FlagSF, FlagOF}

	case mnemonicJb, mnemonicJnae, mnemonicJc, mnemonicJae, mnemonicJnb, mnemonicJnc:
		// below/above or equal (unsigned): cf
		return []CPUFlag{FlagCF}

	case mnemonicJbe, mnemonicJna, mnemonicJa, mnemonicJnbe:
		// below or equal/above (unsigned): cf, zf
		return []CPUFlag{FlagCF, FlagZF}

	case mnemonicJs, mnemonicJns:
		// sign: sf
		return []CPUFlag{FlagSF}

	case mnemonicJo, mnemonicJno:
		// overflow: of
		return []CPUFlag{FlagOF}

	case mnemonicJp, mnemonicJpe, mnemonicJnp, mnemonicJpo:
		// parity: pf
		return []CPUFlag{FlagPF}

	default:
		// unknown condition - materialize all flags (conservative)
		return []CPUFlag{FlagZF, FlagSF, FlagCF, FlagOF, FlagPF, FlagAF}
	}
}

// IsConditionalJump checks if mnemonic is a conditional jump instruction.
func IsConditionalJump(mnemonic string) bool {
	conditionals := []string{
		"je", "jz", "jne", "jnz",
		"jl", "jnge", "jle", "jng", "jg", "jnle", "jge", "jnl",
		"jb", "jnae", "jc", "jbe", "jna", "ja", "jnbe", "jae", "jnb", "jnc",
		"js", "jns", "jo", "jno", "jp", "jpe", "jnp", "jpo",
	}

	for _, cond := range conditionals {
		if mnemonic == cond {
			return true
		}
	}
	return false
}

// IsFlagReadingInstruction checks if instruction reads cpu flags.
//
// includes: conditional jumps (jcc), conditional moves (cmovcc),
// set byte on condition (setcc), flag manipulation (lahf, sahf, pushf, popf)
func IsFlagReadingInstruction(mnemonic string) bool {
	// conditional jumps
	if IsConditionalJump(mnemonic) {
		return true
	}

	// conditional moves: cmovcc
	if len(mnemonic) >= 4 && mnemonic[:4] == "cmov" {
		return true
	}

	// set byte on condition: setcc
	if len(mnemonic) >= 3 && mnemonic[:3] == "set" {
		return true
	}

	// flag manipulation instructions
	flagInstructions := []string{
		"lahf", "sahf", "pushf", "pushfq", "popf", "popfq",
		"clc", "stc", "cmc", "cld", "std", "cli", "sti",
	}

	for _, instr := range flagInstructions {
		if mnemonic == instr {
			return true
		}
	}

	return false
}
