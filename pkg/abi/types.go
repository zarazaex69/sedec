package abi

import (
	"github.com/zarazaex69/sedec/pkg/disasm"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// CallingConvention identifies the calling convention used by a function
type CallingConvention int

const (
	// CallingConventionUnknown represents an unidentified calling convention
	CallingConventionUnknown CallingConvention = iota
	// CallingConventionSystemVAMD64 is the System V AMD64 ABI (Linux, macOS, BSD)
	CallingConventionSystemVAMD64
	// CallingConventionMicrosoftX64 is the Microsoft x64 calling convention (Windows)
	CallingConventionMicrosoftX64
	// CallingConventionCustom represents a non-standard calling convention
	CallingConventionCustom
)

func (c CallingConvention) String() string {
	switch c {
	case CallingConventionUnknown:
		return unknownStr
	case CallingConventionSystemVAMD64:
		return "SystemV_AMD64"
	case CallingConventionMicrosoftX64:
		return "Microsoft_x64"
	case CallingConventionCustom:
		return "Custom"
	default:
		return unknownStr
	}
}

// ParameterLocation describes where a parameter is passed
type ParameterLocation int

const (
	// ParameterLocationRegister means the parameter is in a register
	ParameterLocationRegister ParameterLocation = iota
	// ParameterLocationStack means the parameter is on the stack
	ParameterLocationStack
)

// Parameter represents a function parameter with its location and type
type Parameter struct {
	Name     string            // inferred or synthetic name (arg0, arg1, ...)
	Type     ir.Type           // inferred type
	Register string            // register name if location is register (e.g., "rdi")
	Location ParameterLocation // register or stack
	// StackOffset is the offset from RSP at call site (only valid for stack params)
	StackOffset int64
	// Index is the zero-based parameter index
	Index int
}

// ReturnValue represents a function return value
type ReturnValue struct {
	Type     ir.Type // inferred type
	Register string  // register holding the return value (rax, rdx, xmm0, etc.)
}

// LocalVariable represents a local variable identified on the stack
type LocalVariable struct {
	Name        string      // synthetic name (local_0, local_8, ...)
	Type        ir.Type     // inferred type
	FrameOffset int64       // offset from frame base (rbp or rsp at entry)
	Size        disasm.Size // size in bytes
}

// SpillSlot represents a register spill slot on the stack
type SpillSlot struct {
	Register    string      // which register was spilled
	FrameOffset int64       // offset from frame base
	Size        disasm.Size // size in bytes
}

// StackFrame describes the complete stack frame layout of a function
type StackFrame struct {
	LocalVariables []LocalVariable // identified local variables
	SpillSlots     []SpillSlot     // register spill slots
	// Size is the total frame size in bytes (distance from entry RSP to lowest RSP)
	Size int64
	// HasFramePointer indicates whether RBP is used as frame pointer
	HasFramePointer bool
	// FramePointerOffset is the offset of saved RBP from entry RSP
	FramePointerOffset int64
}

// CalleeSavedRegisterStatus tracks whether a callee-saved register is properly preserved
type CalleeSavedRegisterStatus struct {
	Register    string         // register name
	Preserved   bool           // true if register is saved and restored correctly
	SaveSite    disasm.Address // address where register is saved (push/mov to stack)
	RestoreSite disasm.Address // address where register is restored
}

// FunctionABI contains the complete ABI analysis result for a function
type FunctionABI struct {
	Convention      CallingConvention
	Parameters      []Parameter
	ReturnValues    []ReturnValue
	Frame           *StackFrame
	CalleeSavedRegs []CalleeSavedRegisterStatus
	// IsVariadic indicates the function accepts variable arguments
	IsVariadic bool
	// IsLeaf indicates the function makes no calls (no stack frame required by ABI)
	IsLeaf bool
}

// StackOffset represents the symbolic RSP offset at a given program point.
// It is either a concrete integer offset or a symbolic expression with a variable component.
type StackOffset interface {
	isStackOffset()
	// BaseOffset returns the statically-known component of the offset
	BaseOffset() int64
}

// ConcreteOffset is a fully-determined RSP offset relative to function entry
type ConcreteOffset struct {
	Value int64
}

func (ConcreteOffset) isStackOffset() {}

// BaseOffset returns the concrete offset value.
func (c ConcreteOffset) BaseOffset() int64 { return c.Value }

// SymbolicOffset is an RSP offset with a dynamic (unknown) component.
// Arises from alloca-style dynamic allocation: sub rsp, rax
type SymbolicOffset struct {
	// Base is the statically-known component
	Base int64
	// VarName is the name of the IR variable representing the dynamic component
	VarName string
}

func (SymbolicOffset) isStackOffset() {}

// BaseOffset returns the statically-known component of the symbolic offset.
func (s SymbolicOffset) BaseOffset() int64 { return s.Base }

// SymbolicStackTracker tracks RSP/RBP offsets throughout a function.
// It maintains a per-instruction map of stack pointer offsets relative to
// the function entry RSP, enabling correct local variable identification.
type SymbolicStackTracker struct {
	// offsetMap maps instruction address to RSP offset at that point
	offsetMap map[disasm.Address]StackOffset
	// rbpOffset is the RSP offset at the point RBP was set as frame pointer.
	// nil means RBP is not used as frame pointer.
	rbpOffset *int64
	// inconsistencies records addresses where stack tracking detected contradictions
	inconsistencies []StackInconsistency
}

// StackInconsistency records a detected contradiction in stack pointer tracking
type StackInconsistency struct {
	Address  disasm.Address
	Expected StackOffset
	Observed StackOffset
	Message  string
}

// NewSymbolicStackTracker creates a tracker initialized with RSP offset = 0 at entry
func NewSymbolicStackTracker() *SymbolicStackTracker {
	return &SymbolicStackTracker{
		offsetMap:       make(map[disasm.Address]StackOffset),
		inconsistencies: make([]StackInconsistency, 0),
	}
}

// SetOffset records the RSP offset at a given instruction address
func (t *SymbolicStackTracker) SetOffset(addr disasm.Address, offset StackOffset) {
	t.offsetMap[addr] = offset
}

// GetOffset retrieves the RSP offset at a given instruction address.
// Returns nil if the address has not been tracked.
func (t *SymbolicStackTracker) GetOffset(addr disasm.Address) (StackOffset, bool) {
	off, ok := t.offsetMap[addr]
	return off, ok
}

// SetFramePointer records that RBP was set as frame pointer at the given RSP offset
func (t *SymbolicStackTracker) SetFramePointer(rspOffset int64) {
	t.rbpOffset = &rspOffset
}

// HasFramePointer returns true if RBP is being used as frame pointer
func (t *SymbolicStackTracker) HasFramePointer() bool {
	return t.rbpOffset != nil
}

// FramePointerRSPOffset returns the RSP offset at which RBP was established as frame pointer
func (t *SymbolicStackTracker) FramePointerRSPOffset() (int64, bool) {
	if t.rbpOffset == nil {
		return 0, false
	}
	return *t.rbpOffset, true
}

// AddInconsistency records a stack tracking inconsistency
func (t *SymbolicStackTracker) AddInconsistency(inc StackInconsistency) {
	t.inconsistencies = append(t.inconsistencies, inc)
}

// Inconsistencies returns all detected stack tracking inconsistencies
func (t *SymbolicStackTracker) Inconsistencies() []StackInconsistency {
	return t.inconsistencies
}
