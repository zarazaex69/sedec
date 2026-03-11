package ir

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
)

// Parser parses serialized IR text format into IR structures
type Parser struct {
	scanner *bufio.Scanner
	line    int
	current string
	err     error
	putback bool // flag to indicate current line should be re-read
}

// NewParser creates a new IR parser from a reader
func NewParser(r io.Reader) *Parser {
	scanner := bufio.NewScanner(r)
	return &Parser{
		scanner: scanner,
		line:    0,
	}
}

// ParseFunction parses a complete function from IR text
func (p *Parser) ParseFunction() (*Function, error) {
	fn := &Function{
		Blocks:    make(map[BlockID]*BasicBlock),
		Variables: []Variable{},
	}

	// skip empty lines and comments at the beginning
	for p.advance() {
		line := p.trimComment(p.current)
		if line != "" {
			break
		}
	}

	if p.err != nil {
		return nil, p.error("expected function declaration")
	}

	if err := p.parseFunctionHeader(fn); err != nil {
		return nil, err
	}

	// parse basic blocks
	for p.advance() {
		line := p.trimComment(p.current)
		if line == "" {
			continue
		}

		// check for basic block label: bb0:
		if strings.HasPrefix(line, "bb") && strings.Contains(line, ":") {
			block, err := p.parseBasicBlock()
			if err != nil {
				return nil, err
			}
			fn.Blocks[block.ID] = block
			if len(fn.Blocks) == 1 {
				fn.EntryBlock = block.ID
			}
		} else if strings.Contains(line, ":") && !strings.Contains(line, "=") {
			// looks like a block label but doesn't start with "bb" — invalid
			return nil, p.errorf("invalid block label: %s", line)
		}
	}

	if p.err != nil {
		return nil, p.err
	}

	return fn, nil
}

// parseFunctionHeader parses function declaration line
func (p *Parser) parseFunctionHeader(fn *Function) error {
	line := p.trimComment(p.current)

	// format: func name(params) returntype
	if !strings.HasPrefix(line, "func ") {
		return p.error("expected 'func' keyword")
	}

	line = strings.TrimPrefix(line, "func ")

	// extract function name
	parenIdx := strings.Index(line, "(")
	if parenIdx == -1 {
		return p.error("expected '(' after function name")
	}

	fn.Name = strings.TrimSpace(line[:parenIdx])
	line = line[parenIdx:]

	// parse signature
	sig, err := p.parseFunctionSignature(line)
	if err != nil {
		return err
	}
	fn.Signature = sig

	return nil
}

// parseFunctionSignature parses function signature from string
func (p *Parser) parseFunctionSignature(s string) (FunctionType, error) {
	// format: (param1, param2, ...) returntype
	closeIdx := strings.Index(s, ")")
	if closeIdx == -1 {
		return FunctionType{}, p.error("expected ')' in function signature")
	}

	paramsStr := strings.TrimSpace(s[1:closeIdx])
	returnStr := strings.TrimSpace(s[closeIdx+1:])

	var params []Type
	var variadic bool

	if paramsStr != "" {
		paramList := strings.Split(paramsStr, ",")
		for _, paramStr := range paramList {
			paramStr = strings.TrimSpace(paramStr)
			if paramStr == "..." {
				variadic = true
				continue
			}
			paramType, err := p.parseType(paramStr)
			if err != nil {
				return FunctionType{}, err
			}
			params = append(params, paramType)
		}
	}

	returnType, err := p.parseType(returnStr)
	if err != nil {
		return FunctionType{}, err
	}

	return FunctionType{
		ReturnType: returnType,
		Parameters: params,
		Variadic:   variadic,
	}, nil
}

// parseBasicBlock parses a basic block and its instructions
func (p *Parser) parseBasicBlock() (*BasicBlock, error) {
	line := p.trimComment(p.current)

	// parse block id from label: bb0:
	if !strings.HasPrefix(line, "bb") {
		return nil, p.error("expected basic block label")
	}

	colonIdx := strings.Index(line, ":")
	if colonIdx == -1 {
		return nil, p.error("expected ':' after block label")
	}

	idStr := strings.TrimSpace(line[2:colonIdx])
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return nil, p.errorf("invalid block id: %v", err)
	}

	block := &BasicBlock{
		ID:           BlockID(id),
		Instructions: []IRInstruction{},
		Predecessors: []BlockID{},
		Successors:   []BlockID{},
	}

	// parse instructions until next block or eof
	for p.advance() {
		nextLine := p.trimComment(p.current)

		if nextLine == "" {
			continue
		}

		// check if next line is a new block - stop parsing this block
		if strings.HasPrefix(nextLine, "bb") && strings.Contains(nextLine, ":") {
			// mark current line to be re-read by ParseFunction
			p.putback = true
			break
		}

		insn, err := p.parseInstruction()
		if err != nil {
			return nil, err
		}
		if insn != nil {
			block.Instructions = append(block.Instructions, insn)
		}
	}

	return block, nil
}

// parseInstruction parses a single IR instruction
func (p *Parser) parseInstruction() (IRInstruction, error) {
	line := p.trimComment(p.current)
	line = strings.TrimSpace(line)

	if line == "" {
		return nil, nil
	}

	// determine instruction type by keywords
	switch {
	case strings.HasPrefix(line, "return"):
		return p.parseReturn(line)
	case strings.HasPrefix(line, "branch "):
		return p.parseBranch(line)
	case strings.HasPrefix(line, "jump "):
		return p.parseJump(line)
	case strings.HasPrefix(line, "call "):
		return p.parseCall(line)
	case strings.Contains(line, "= call "):
		return p.parseCall(line)
	case strings.HasPrefix(line, "store."):
		return p.parseStore(line)
	case strings.Contains(line, "= load."):
		return p.parseLoad(line)
	case strings.Contains(line, "= phi "):
		return p.parsePhi(line)
	case strings.Contains(line, " = "):
		return p.parseAssign(line)
	default:
		return nil, p.errorf("unknown instruction: %s", line)
	}
}

// parseAssign parses assignment instruction: dest = source
func (p *Parser) parseAssign(line string) (*Assign, error) {
	parts := strings.SplitN(line, " = ", 2)
	if len(parts) != 2 {
		return nil, p.error("invalid assignment syntax")
	}

	dest, err := p.parseVariable(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, err
	}

	source, err := p.parseExpression(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, err
	}

	return &Assign{
		Dest:   dest,
		Source: source,
	}, nil
}

// parseLoad parses load instruction: dest = load.size address
func (p *Parser) parseLoad(line string) (*Load, error) {
	parts := strings.SplitN(line, " = ", 2)
	if len(parts) != 2 {
		return nil, p.error("invalid load syntax")
	}

	dest, err := p.parseVariable(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, err
	}

	// parse load.size address
	loadPart := strings.TrimSpace(parts[1])
	if !strings.HasPrefix(loadPart, "load.") {
		return nil, p.error("expected 'load.' prefix")
	}

	loadPart = strings.TrimPrefix(loadPart, "load.")
	spaceIdx := strings.Index(loadPart, " ")
	if spaceIdx == -1 {
		return nil, p.error("expected address after load size")
	}

	sizeStr := loadPart[:spaceIdx]
	size, err := strconv.ParseUint(sizeStr, 10, 8)
	if err != nil {
		return nil, p.errorf("invalid load size: %v", err)
	}

	addrStr := strings.TrimSpace(loadPart[spaceIdx+1:])
	addr, err := p.parseExpression(addrStr)
	if err != nil {
		return nil, err
	}

	return &Load{
		Dest:    dest,
		Address: addr,
		Size:    Size(size),
	}, nil
}

// parseStore parses store instruction: store.size address, value
func (p *Parser) parseStore(line string) (*Store, error) {
	if !strings.HasPrefix(line, "store.") {
		return nil, p.error("expected 'store.' prefix")
	}

	line = strings.TrimPrefix(line, "store.")
	spaceIdx := strings.Index(line, " ")
	if spaceIdx == -1 {
		return nil, p.error("expected address after store size")
	}

	sizeStr := line[:spaceIdx]
	size, err := strconv.ParseUint(sizeStr, 10, 8)
	if err != nil {
		return nil, p.errorf("invalid store size: %v", err)
	}

	rest := strings.TrimSpace(line[spaceIdx+1:])
	parts := strings.SplitN(rest, ",", 2)
	if len(parts) != 2 {
		return nil, p.error("expected comma between address and value")
	}

	addr, err := p.parseExpression(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, err
	}

	value, err := p.parseExpression(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, err
	}

	return &Store{
		Address: addr,
		Value:   value,
		Size:    Size(size),
	}, nil
}

// parseBranch parses branch instruction: branch condition, bb1, bb2
func (p *Parser) parseBranch(line string) (*Branch, error) {
	line = strings.TrimPrefix(line, "branch ")
	parts := strings.Split(line, ",")
	if len(parts) != 3 {
		return nil, p.error("branch requires condition and two targets")
	}

	cond, err := p.parseExpression(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, err
	}

	trueTarget, err := p.parseBlockID(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, err
	}

	falseTarget, err := p.parseBlockID(strings.TrimSpace(parts[2]))
	if err != nil {
		return nil, err
	}

	return &Branch{
		Condition:   cond,
		TrueTarget:  trueTarget,
		FalseTarget: falseTarget,
	}, nil
}

// parseJump parses jump instruction: jump bb0
func (p *Parser) parseJump(line string) (*Jump, error) {
	line = strings.TrimPrefix(line, "jump ")
	target, err := p.parseBlockID(strings.TrimSpace(line))
	if err != nil {
		return nil, err
	}

	return &Jump{
		Target: target,
	}, nil
}

// parseCall parses call instruction: [dest =] call target(args)
func (p *Parser) parseCall(line string) (*Call, error) {
	var dest *Variable

	// check for assignment form
	if strings.Contains(line, " = call ") {
		parts := strings.SplitN(line, " = call ", 2)
		if len(parts) != 2 {
			return nil, p.error("invalid call syntax")
		}

		destVar, err := p.parseVariable(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, err
		}
		dest = &destVar
		line = parts[1]
	} else {
		line = strings.TrimPrefix(line, "call ")
	}

	// parse target(args)
	parenIdx := strings.Index(line, "(")
	if parenIdx == -1 {
		return nil, p.error("expected '(' in call")
	}

	targetStr := strings.TrimSpace(line[:parenIdx])
	target, err := p.parseExpression(targetStr)
	if err != nil {
		return nil, err
	}

	closeIdx := strings.LastIndex(line, ")")
	if closeIdx == -1 {
		return nil, p.error("expected ')' in call")
	}

	argsStr := strings.TrimSpace(line[parenIdx+1 : closeIdx])
	var args []Variable

	if argsStr != "" {
		argList := strings.Split(argsStr, ",")
		for _, argStr := range argList {
			arg, err := p.parseVariable(strings.TrimSpace(argStr))
			if err != nil {
				return nil, err
			}
			args = append(args, arg)
		}
	}

	return &Call{
		Dest:   dest,
		Target: target,
		Args:   args,
	}, nil
}

// parseReturn parses return instruction: return [value]
func (p *Parser) parseReturn(line string) (*Return, error) {
	line = strings.TrimPrefix(line, "return")
	line = strings.TrimSpace(line)

	if line == "" {
		return &Return{Value: nil}, nil
	}

	value, err := p.parseVariable(line)
	if err != nil {
		return nil, err
	}

	return &Return{Value: &value}, nil
}

// parsePhi parses phi instruction: dest = phi [bb0: var0], [bb1: var1], ...
func (p *Parser) parsePhi(line string) (*Phi, error) {
	parts := strings.SplitN(line, " = phi ", 2)
	if len(parts) != 2 {
		return nil, p.error("invalid phi syntax")
	}

	dest, err := p.parseVariable(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, err
	}

	// parse phi sources: [bb0: var0], [bb1: var1]
	sourcesStr := strings.TrimSpace(parts[1])
	var sources []PhiSource

	// split by "], [" to handle multiple sources
	sourceList := strings.Split(sourcesStr, "],")
	for i, srcStr := range sourceList {
		srcStr = strings.TrimSpace(srcStr)

		// remove leading/trailing brackets
		srcStr = strings.TrimPrefix(srcStr, "[")
		if i == len(sourceList)-1 {
			srcStr = strings.TrimSuffix(srcStr, "]")
		}

		// parse bb0: var0
		colonIdx := strings.Index(srcStr, ":")
		if colonIdx == -1 {
			return nil, p.error("expected ':' in phi source")
		}

		blockStr := strings.TrimSpace(srcStr[:colonIdx])
		varStr := strings.TrimSpace(srcStr[colonIdx+1:])

		blockID, err := p.parseBlockID(blockStr)
		if err != nil {
			return nil, err
		}

		varVal, err := p.parseVariable(varStr)
		if err != nil {
			return nil, err
		}

		sources = append(sources, PhiSource{
			Block: blockID,
			Var:   varVal,
		})
	}

	return &Phi{
		Dest:    dest,
		Sources: sources,
	}, nil
}

// parseExpression parses an expression
func (p *Parser) parseExpression(s string) (Expression, error) {
	s = strings.TrimSpace(s)

	// check for type cast: (type)expr — opening paren followed by a type name and closing paren
	// this must be checked before the fully-parenthesized expression branch
	if strings.HasPrefix(s, "(") {
		// find the matching close paren for the opening one
		closeIdx := p.findMatchingParen(s, 0)
		if closeIdx != -1 {
			inner := strings.TrimSpace(s[1:closeIdx])
			rest := strings.TrimSpace(s[closeIdx+1:])

			if rest != "" && p.isTypeName(inner) {
				// it's a cast: (type)expr
				targetType, err := p.parseType(inner)
				if err == nil {
					expr, err := p.parseExpression(rest)
					if err != nil {
						return nil, err
					}
					return Cast{
						Expr:       expr,
						TargetType: targetType,
					}, nil
				}
			}

			// not a cast — if rest is empty, it's a fully-parenthesized expression
			if rest == "" {
				return p.parseExpression(inner)
			}
		}
	}

	// check for binary operations (lowest precedence first)
	// important: check longer operators before shorter ones
	for _, op := range []struct {
		str string
		op  BinaryOperator
	}{
		{"||", BinOpLogicalOr},
		{"&&", BinOpLogicalAnd},
		{"==", BinOpEq},
		{"!=", BinOpNe},
		{"<=u", BinOpULe},
		{">=u", BinOpUGe},
		{"<u", BinOpULt},
		{">u", BinOpUGt},
		{"<=", BinOpLe},
		{">=", BinOpGe},
		{">>>", BinOpSar}, // check >>> before >>
		{"<<", BinOpShl},
		{">>", BinOpShr},
		{"<", BinOpLt},
		{">", BinOpGt},
		{"+", BinOpAdd},
		{"-", BinOpSub},
		{"|", BinOpOr},
		{"^", BinOpXor},
		{"/u", BinOpUDiv},
		{"%u", BinOpUMod},
		{"*", BinOpMul},
		{"/", BinOpDiv},
		{"%", BinOpMod},
		{"&", BinOpAnd},
	} {
		if idx := p.findOperator(s, op.str); idx != -1 {
			left, err := p.parseExpression(s[:idx])
			if err != nil {
				return nil, err
			}
			right, err := p.parseExpression(s[idx+len(op.str):])
			if err != nil {
				return nil, err
			}
			return BinaryOp{
				Op:    op.op,
				Left:  left,
				Right: right,
			}, nil
		}
	}

	// check for unary operations (higher precedence than binary)
	if len(s) > 0 && s[0] == '!' {
		operand, err := p.parseExpression(strings.TrimSpace(s[1:]))
		if err != nil {
			return nil, err
		}
		return UnaryOp{
			Op:      UnOpLogicalNot,
			Operand: operand,
		}, nil
	}
	if len(s) > 0 && s[0] == '~' {
		operand, err := p.parseExpression(strings.TrimSpace(s[1:]))
		if err != nil {
			return nil, err
		}
		return UnaryOp{
			Op:      UnOpNot,
			Operand: operand,
		}, nil
	}
	// unary minus: check it's not a negative number literal
	if len(s) > 0 && s[0] == '-' {
		rest := strings.TrimSpace(s[1:])
		// if rest starts with digit, it's a negative number
		if len(rest) > 0 && unicode.IsDigit(rune(rest[0])) {
			// try to parse as constant
			if constant, err := p.parseConstant(s); err == nil {
				return ConstantExpr{Value: constant}, nil
			}
		} else if len(rest) > 0 {
			// it's unary minus
			operand, err := p.parseExpression(rest)
			if err != nil {
				return nil, err
			}
			return UnaryOp{
				Op:      UnOpNeg,
				Operand: operand,
			}, nil
		}
	}

	// check for constants
	if constant, err := p.parseConstant(s); err == nil {
		return ConstantExpr{Value: constant}, nil
	}

	// must be a variable
	variable, err := p.parseVariable(s)
	if err != nil {
		return nil, err
	}
	return VariableExpr{Var: variable}, nil
}

// parseVariable parses a variable: name or name_version
func (p *Parser) parseVariable(s string) (Variable, error) {
	s = strings.TrimSpace(s)

	// check for ssa version: name_version
	underscoreIdx := strings.LastIndex(s, "_")
	if underscoreIdx != -1 {
		name := s[:underscoreIdx]
		versionStr := s[underscoreIdx+1:]

		version, err := strconv.Atoi(versionStr)
		if err == nil && version > 0 {
			// infer type from name prefix
			typ := p.inferTypeFromName(name)
			return Variable{
				Name:    name,
				Type:    typ,
				Version: version,
			}, nil
		}
	}

	// non-ssa variable
	typ := p.inferTypeFromName(s)
	return Variable{
		Name:    s,
		Type:    typ,
		Version: 0,
	}, nil
}

// parseConstant parses a constant value
func (p *Parser) parseConstant(s string) (Constant, error) {
	s = strings.TrimSpace(s)

	// check for boolean
	if s == "true" {
		return BoolConstant{Value: true}, nil
	}
	if s == "false" {
		return BoolConstant{Value: false}, nil
	}

	// check for null
	if s == "null" {
		return NullConstant{PointerType: PointerType{Pointee: VoidType{}}}, nil
	}

	// check for float (contains decimal point)
	if strings.Contains(s, ".") {
		val, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return nil, err
		}
		return FloatConstant{Value: val, Width: Size8}, nil
	}

	// parse integer
	val, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return nil, err
	}

	// determine width and signedness
	signed := val < 0
	var width Size
	if val >= -128 && val <= 127 {
		width = Size1
	} else if val >= -32768 && val <= 32767 {
		width = Size2
	} else if val >= -2147483648 && val <= 2147483647 {
		width = Size4
	} else {
		width = Size8
	}

	return IntConstant{
		Value:  val,
		Width:  width,
		Signed: signed,
	}, nil
}

// parseType parses a type string
func (p *Parser) parseType(s string) (Type, error) {
	s = strings.TrimSpace(s)

	switch s {
	case "void":
		return VoidType{}, nil
	case "bool":
		return BoolType{}, nil
	}

	// check for integer types: i8, i16, i32, i64, u8, u16, u32, u64
	if strings.HasPrefix(s, "i") || strings.HasPrefix(s, "u") {
		signed := strings.HasPrefix(s, "i")
		widthStr := s[1:]
		width, err := strconv.Atoi(widthStr)
		if err != nil {
			return nil, p.errorf("invalid integer type: %s", s)
		}
		return IntType{
			Width:  Size(width / 8),
			Signed: signed,
		}, nil
	}

	// check for float types: f32, f64, f80, f128
	if strings.HasPrefix(s, "f") {
		widthStr := s[1:]
		width, err := strconv.Atoi(widthStr)
		if err != nil {
			return nil, p.errorf("invalid float type: %s", s)
		}
		return FloatType{Width: Size(width / 8)}, nil
	}

	// check for pointer type: *type
	if strings.HasPrefix(s, "*") {
		pointee, err := p.parseType(s[1:])
		if err != nil {
			return nil, err
		}
		return PointerType{Pointee: pointee}, nil
	}

	// check for array type: [length]type
	if strings.HasPrefix(s, "[") {
		closeIdx := strings.Index(s, "]")
		if closeIdx == -1 {
			return nil, p.error("expected ']' in array type")
		}
		lengthStr := s[1:closeIdx]
		length, err := strconv.ParseUint(lengthStr, 10, 64)
		if err != nil {
			return nil, p.errorf("invalid array length: %v", err)
		}
		elemType, err := p.parseType(s[closeIdx+1:])
		if err != nil {
			return nil, err
		}
		return ArrayType{
			Element: elemType,
			Length:  length,
		}, nil
	}

	// check for struct type
	if strings.HasPrefix(s, "struct") {
		name := strings.TrimSpace(strings.TrimPrefix(s, "struct"))
		return StructType{Name: name}, nil
	}

	// check for function type: func(params) returntype
	if strings.HasPrefix(s, "func(") {
		return p.parseFunctionType(s)
	}

	return nil, p.errorf("unknown type: %s", s)
}

// parseFunctionType parses function type from string
func (p *Parser) parseFunctionType(s string) (FunctionType, error) {
	// reuse function signature parser
	s = strings.TrimPrefix(s, "func")
	return p.parseFunctionSignature(s)
}

// parseBlockID parses a block identifier: bb0
func (p *Parser) parseBlockID(s string) (BlockID, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "bb") {
		return 0, p.error("expected 'bb' prefix for block id")
	}
	idStr := strings.TrimPrefix(s, "bb")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return 0, p.errorf("invalid block id: %v", err)
	}
	return BlockID(id), nil
}

// helper functions

func (p *Parser) advance() bool {
	// check if we need to re-read current line
	if p.putback {
		p.putback = false
		return true
	}

	if p.scanner.Scan() {
		p.current = p.scanner.Text()
		p.line++
		return true
	}
	p.err = p.scanner.Err()
	return false
}

func (p *Parser) trimComment(s string) string {
	if idx := strings.Index(s, "//"); idx != -1 {
		return strings.TrimSpace(s[:idx])
	}
	if idx := strings.Index(s, "#"); idx != -1 {
		return strings.TrimSpace(s[:idx])
	}
	return strings.TrimSpace(s)
}

func (p *Parser) error(msg string) error {
	return fmt.Errorf("line %d: %s", p.line, msg)
}

func (p *Parser) errorf(format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	return fmt.Errorf("line %d: %s", p.line, msg)
}

func (p *Parser) findOperator(s, op string) int {
	// find operator outside of parentheses
	depth := 0
	opLen := len(op)

	for i := 0; i < len(s); i++ {
		if s[i] == '(' {
			depth++
		} else if s[i] == ')' {
			depth--
		} else if depth == 0 && i+opLen <= len(s) && s[i:i+opLen] == op {
			// found potential operator match

			// for operators that can be both unary and binary (-, +),
			// skip if at start of string (unary position)
			if i == 0 && (op == "-" || op == "+") {
				continue
			}

			// check it's not part of a longer operator
			if i+opLen < len(s) {
				next := s[i+opLen]
				// prevent matching < when we want <<
				if op == "<" && next == '<' {
					continue
				}
				// prevent matching > when we want >> or >>>
				if op == ">" && next == '>' {
					continue
				}
				// prevent matching >> when we want >>>
				if op == ">>" && i+opLen < len(s) && next == '>' {
					continue
				}
				// prevent matching = when we want ==
				if op == "=" && next == '=' {
					continue
				}
			}
			return i
		}
	}
	return -1
}

func (p *Parser) isTypeName(s string) bool {
	s = strings.TrimSpace(s)
	// check if string looks like a type name
	return strings.HasPrefix(s, "i") || strings.HasPrefix(s, "u") ||
		strings.HasPrefix(s, "f") || strings.HasPrefix(s, "*") ||
		strings.HasPrefix(s, "[") || s == "void" || s == "bool" ||
		strings.HasPrefix(s, "struct")
}

func (p *Parser) inferTypeFromName(name string) Type {
	// infer type from variable name prefix
	switch {
	case strings.HasPrefix(name, "i") || strings.HasPrefix(name, "tmp"):
		return IntType{Width: Size8, Signed: true}
	case strings.HasPrefix(name, "u"):
		return IntType{Width: Size8, Signed: false}
	case strings.HasPrefix(name, "f"):
		return FloatType{Width: Size8}
	case strings.HasPrefix(name, "p") || strings.HasPrefix(name, "ptr"):
		return PointerType{Pointee: VoidType{}}
	case strings.HasPrefix(name, "b"):
		return BoolType{}
	default:
		return IntType{Width: Size8, Signed: true}
	}
}

// findMatchingParen finds the index of matching closing paren
func (p *Parser) findMatchingParen(s string, start int) int {
	if start >= len(s) || s[start] != '(' {
		return -1
	}

	depth := 0
	for i := start; i < len(s); i++ {
		if s[i] == '(' {
			depth++
		} else if s[i] == ')' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
