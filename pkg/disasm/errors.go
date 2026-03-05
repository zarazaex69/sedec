package disasm

import "fmt"

// InvalidOpcodeError represents an error when encountering an invalid opcode
type InvalidOpcodeError struct {
	VA   Address // virtual address where invalid opcode was found
	Byte byte    // the invalid byte
}

func (e InvalidOpcodeError) Error() string {
	return fmt.Sprintf("invalid opcode at 0x%x: byte 0x%02x", e.VA, e.Byte)
}

// InsufficientBytesError represents an error when there are not enough bytes to decode
type InsufficientBytesError struct {
	VA        Address // virtual address where decoding failed
	Available int     // number of bytes available
	Required  int     // number of bytes required
}

func (e InsufficientBytesError) Error() string {
	return fmt.Sprintf("insufficient bytes at 0x%x: have %d, need %d", e.VA, e.Available, e.Required)
}

// EngineInitError represents an error during disassembler engine initialization
type EngineInitError struct {
	Reason string
}

func (e EngineInitError) Error() string {
	return fmt.Sprintf("failed to initialize disassembler engine: %s", e.Reason)
}
