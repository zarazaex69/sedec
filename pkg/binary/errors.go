package binfmt

import "fmt"

// InvalidMagicError indicates that the binary has an invalid magic number.
type InvalidMagicError struct {
	Magic []byte
}

func (e *InvalidMagicError) Error() string {
	return fmt.Sprintf("invalid magic number: %#x", e.Magic)
}

// UnsupportedFormatError indicates that the binary format is not supported.
type UnsupportedFormatError struct {
	Format string
}

func (e *UnsupportedFormatError) Error() string {
	return fmt.Sprintf("unsupported binary format: %s", e.Format)
}

// InvalidOffsetError indicates an invalid offset in the binary.
type InvalidOffsetError struct {
	Reason string
	Offset uint64
}

func (e *InvalidOffsetError) Error() string {
	return fmt.Sprintf("invalid offset %#x: %s", e.Offset, e.Reason)
}

// TruncatedFileError indicates that the file is truncated.
type TruncatedFileError struct {
	Expected uint64
	Actual   uint64
}

func (e *TruncatedFileError) Error() string {
	return fmt.Sprintf("truncated file: expected at least %d bytes, got %d", e.Expected, e.Actual)
}

// CorruptedSectionError indicates a corrupted section.
type CorruptedSectionError struct {
	Section string
	Reason  string
}

func (e *CorruptedSectionError) Error() string {
	return fmt.Sprintf("corrupted section %s: %s", e.Section, e.Reason)
}
