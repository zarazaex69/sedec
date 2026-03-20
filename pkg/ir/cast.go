package ir

// AsAssign extracts an Assign from an IRInstruction, handling both value and pointer receivers.
func AsAssign(instr IRInstruction) (Assign, bool) {
	switch v := instr.(type) {
	case Assign:
		return v, true
	case *Assign:
		return *v, true
	}
	return Assign{}, false
}

// AsLoad extracts a Load from an IRInstruction, handling both value and pointer receivers.
func AsLoad(instr IRInstruction) (Load, bool) {
	switch v := instr.(type) {
	case Load:
		return v, true
	case *Load:
		return *v, true
	}
	return Load{}, false
}

// AsStore extracts a Store from an IRInstruction, handling both value and pointer receivers.
func AsStore(instr IRInstruction) (Store, bool) {
	switch v := instr.(type) {
	case Store:
		return v, true
	case *Store:
		return *v, true
	}
	return Store{}, false
}

// AsBranch extracts a Branch from an IRInstruction, handling both value and pointer receivers.
func AsBranch(instr IRInstruction) (Branch, bool) {
	switch v := instr.(type) {
	case Branch:
		return v, true
	case *Branch:
		return *v, true
	}
	return Branch{}, false
}

// AsJump extracts a Jump from an IRInstruction, handling both value and pointer receivers.
func AsJump(instr IRInstruction) (Jump, bool) {
	switch v := instr.(type) {
	case Jump:
		return v, true
	case *Jump:
		return *v, true
	}
	return Jump{}, false
}

// AsCall extracts a Call from an IRInstruction, handling both value and pointer receivers.
func AsCall(instr IRInstruction) (Call, bool) {
	switch v := instr.(type) {
	case Call:
		return v, true
	case *Call:
		return *v, true
	}
	return Call{}, false
}

// AsReturn extracts a Return from an IRInstruction, handling both value and pointer receivers.
func AsReturn(instr IRInstruction) (Return, bool) {
	switch v := instr.(type) {
	case Return:
		return v, true
	case *Return:
		return *v, true
	}
	return Return{}, false
}

// AsPhi extracts a Phi from an IRInstruction, handling both value and pointer receivers.
func AsPhi(instr IRInstruction) (Phi, bool) {
	switch v := instr.(type) {
	case Phi:
		return v, true
	case *Phi:
		return *v, true
	}
	return Phi{}, false
}

// AsIntrinsic extracts an Intrinsic from an IRInstruction, handling both value and pointer receivers.
func AsIntrinsic(instr IRInstruction) (Intrinsic, bool) {
	switch v := instr.(type) {
	case Intrinsic:
		return v, true
	case *Intrinsic:
		return *v, true
	}
	return Intrinsic{}, false
}

// IsTerminator reports whether instr is a branch or jump (control flow terminator).
func IsTerminator(instr IRInstruction) bool {
	switch instr.(type) {
	case Branch, *Branch, Jump, *Jump:
		return true
	}
	return false
}

// ============================================================================
// clone helpers — preserve SourceLocation across condensation passes
// ============================================================================

// CloneAssign returns a new Assign with the same SourceLocation as src but
// with Source replaced by newSource.
func CloneAssign(src Assign, newSource Expression) Assign {
	return Assign{
		baseInstruction: src.baseInstruction,
		Dest:            src.Dest,
		Source:          newSource,
	}
}

// CloneLoad returns a new Load with the same SourceLocation as src but
// with Address replaced by newAddress.
func CloneLoad(src Load, newAddress Expression) Load {
	return Load{
		baseInstruction: src.baseInstruction,
		Dest:            src.Dest,
		Address:         newAddress,
		Size:            src.Size,
	}
}

// CloneStore returns a new Store with the same SourceLocation as src but
// with Address and Value replaced.
func CloneStore(src Store, newAddress, newValue Expression) Store {
	return Store{
		baseInstruction: src.baseInstruction,
		Address:         newAddress,
		Value:           newValue,
		Size:            src.Size,
	}
}

// CloneBranch returns a new Branch with the same SourceLocation as src but
// with Condition replaced by newCond.
func CloneBranch(src Branch, newCond Expression) Branch {
	return Branch{
		baseInstruction: src.baseInstruction,
		Condition:       newCond,
		TrueTarget:      src.TrueTarget,
		FalseTarget:     src.FalseTarget,
	}
}

// CloneCall returns a new Call with the same SourceLocation as src but
// with Target, Args, and ArgExprs replaced.
func CloneCall(src Call, newTarget Expression, newArgs []Variable, newArgExprs []Expression) Call {
	return Call{
		baseInstruction: src.baseInstruction,
		Dest:            src.Dest,
		Target:          newTarget,
		Args:            newArgs,
		ArgExprs:        newArgExprs,
	}
}

// CloneIntrinsic returns a new Intrinsic with the same SourceLocation as src but
// with Args replaced by newArgs.
func CloneIntrinsic(src Intrinsic, newArgs []Expression) Intrinsic {
	return Intrinsic{
		baseInstruction: src.baseInstruction,
		Dest:            src.Dest,
		Name:            src.Name,
		Args:            newArgs,
	}
}
