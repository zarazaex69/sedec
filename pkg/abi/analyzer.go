// Package abi implements calling convention analysis for x86_64 binaries.
// It identifies function parameters, return values, callee-saved register usage,
// and stack frame layouts according to the System V AMD64 ABI and Microsoft x64 ABI.
package abi

import "github.com/zarazaex69/sedec/pkg/disasm"

// Analyzer is the interface for ABI analysis of a function.
// Different implementations handle different calling conventions.
type Analyzer interface {
	// IdentifyCallingConvention returns the calling convention this analyzer implements
	IdentifyCallingConvention() CallingConvention

	// IdentifyParameters extracts function parameters from the instruction sequence.
	// It scans the function prologue to determine which argument registers and
	// stack slots are read before being written (i.e., are inputs to the function).
	IdentifyParameters(insns []*disasm.Instruction) []Parameter

	// IdentifyReturnValues determines what the function returns by scanning
	// backwards from the ret instruction to find writes to return registers.
	IdentifyReturnValues(insns []*disasm.Instruction) []ReturnValue

	// VerifyCalleeSavedRegisters checks whether each callee-saved register
	// is properly saved on entry and restored before return.
	VerifyCalleeSavedRegisters(insns []*disasm.Instruction) []CalleeSavedRegisterStatus

	// TrackStackPointer performs symbolic stack pointer tracking throughout
	// the function, computing RSP offset relative to function entry at each
	// instruction address.
	TrackStackPointer(insns []*disasm.Instruction) *SymbolicStackTracker

	// AnalyzeStackFrame recovers the complete stack frame layout including
	// local variables and register spill slots.
	AnalyzeStackFrame(insns []*disasm.Instruction) *StackFrame

	// Analyze performs complete ABI analysis and returns a FunctionABI
	// containing all recovered calling convention information.
	Analyze(insns []*disasm.Instruction) *FunctionABI
}

// NewAnalyzer creates an ABI analyzer for the given calling convention.
// Returns an error if the convention is not supported.
func NewAnalyzer(convention CallingConvention) (Analyzer, error) {
	switch convention {
	case CallingConventionSystemVAMD64:
		return NewSystemVAnalyzer(), nil
	default:
		return nil, &ErrUnsupportedConvention{Convention: convention}
	}
}

// ErrUnsupportedConvention is returned when an unsupported calling convention is requested
type ErrUnsupportedConvention struct {
	Convention CallingConvention
}

func (e *ErrUnsupportedConvention) Error() string {
	return "unsupported calling convention: " + e.Convention.String()
}
