package binfmt

import "fmt"

// ErrInvalidMagic indicates that the binary has an invalid magic number
type ErrInvalidMagic struct {
	Magic []byte
}

func (e *ErrInvalidMagic) Error() string {
	return fmt.Sprintf("invalid magic number: %#x", e.Magic)
}

// ErrUnsupportedFormat indicates that the binary format is not supported
type ErrUnsupportedFormat struct {
	Format string
}

func (e *ErrUnsupportedFormat) Error() string {
	return fmt.Sprintf("unsupported binary format: %s", e.Format)
}

// ErrInvalidOffset indicates an invalid offset in the binary
type ErrInvalidOffset struct {
	Offset uint64
	Reason string
}

func (e *ErrInvalidOffset) Error() string {
	return fmt.Sprintf("invalid offset %#x: %s", e.Offset, e.Reason)
}

// ErrTruncatedFile indicates that the file is truncated
type ErrTruncatedFile struct {
	Expected uint64
	Actual   uint64
}

func (e *ErrTruncatedFile) Error() string {
	return fmt.Sprintf("truncated file: expected at least %d bytes, got %d", e.Expected, e.Actual)
}

// ErrCorruptedSection indicates a corrupted section
type ErrCorruptedSection struct {
	Section string
	Reason  string
}

func (e *ErrCorruptedSection) Error() string {
	return fmt.Sprintf("corrupted section %s: %s", e.Section, e.Reason)
}
