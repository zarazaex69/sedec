// Package ir provides intermediate representation (IR) for the sedec decompiler.
//
// The IR package implements a platform-independent intermediate representation
// that serves as the foundation for analysis and optimization passes. It includes:
//
// - Type system (integers, floats, pointers, arrays, structs, functions)
// - Expression trees (variables, constants, binary/unary operations, casts)
// - IR instructions (assign, load, store, branch, jump, call, return, phi)
// - Sub-register operations (extract, insert, zero-extend)
// - Lazy CPU flags evaluation for x86_64
// - IR parser and pretty printer with round-trip property
//
// # IR Text Format
//
// The IR can be serialized to and parsed from a human-readable text format:
//
//	func add(i64, i64) i64
//
//	bb0:
//	  sum_1 = (a_1 + b_1)
//	  return sum_1
//
// # Parser and Printer
//
// The package provides a complete parser and pretty printer:
//
//	// Parse IR from text
//	parser := ir.NewParser(strings.NewReader(irText))
//	fn, err := parser.ParseFunction()
//
//	// Print IR to text
//	output, err := ir.PrettyPrint(fn)
//
// # Round-Trip Property
//
// The parser and printer satisfy the round-trip property:
//
//	parse(print(ir)) == ir
//
// This ensures that IR can be reliably serialized, stored, and reconstructed
// without loss of information.
//
// # Comments
//
// The IR text format supports comments using // or # syntax:
//
//	func test() void  // function declaration
//
//	bb0:  // entry block
//	  x = 42  // assignment
//	  return  // void return
//
// Comments are preserved during parsing but not included in the IR structure.
package ir
