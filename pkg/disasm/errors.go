package disasm

import "fmt"

// ErrInvalidOpcode represents an error when encountering an invalid opcode
type ErrInvalidOpcode struct {
	VA   Address // virtual address where invalid opcode was found
	Byte byte    // the invalid byte
}

func (e ErrInvalidOpcode) Error() string {
	return fmt.Sprintf("invalid opcode at 0x%x: byte 0x%02x", e.VA, e.Byte)
}

// ErrInsufficientBytes represents an error when there are not enough bytes to decode
type ErrInsufficientBytes struct {
	VA        Address // virtual address where decoding failed
	Available int     // number of bytes available
	Required  int     // number of bytes required
}

func (e ErrInsufficientBytes) Error() string {
	return fmt.Sprintf("insufficient bytes at 0x%x: have %d, need %d", e.VA, e.Available, e.Required)
}

// ErrEngineInit represents an error during disassembler engine initialization
type ErrEngineInit struct {
	Reason string
}

func (e ErrEngineInit) Error() string {
	return fmt.Sprintf("failed to initialize disassembler engine: %s", e.Reason)
}
