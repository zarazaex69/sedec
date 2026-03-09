# Sub-Register Aliasing Model - Usage Guide

## Overview

This document describes the sub-register aliasing model for x86_64 architecture in sedec's IR. The model provides mathematically correct semantics for partial register updates, which is critical for accurate decompilation.

## Background

x86_64 has complex register aliasing where smaller registers share storage with larger registers:

```
RAX (64-bit)
├── EAX (bits 0-31, lower 32 bits)
│   ├── AX (bits 0-15, lower 16 bits)
│   │   ├── AL (bits 0-7, lower 8 bits)
│   │   └── AH (bits 8-15, bits 8-15)
```

### Critical Semantic Rules

1. **32-bit writes zero upper 32 bits**: Writing to EAX zeros bits 32-63 of RAX
2. **8/16-bit writes preserve upper bits**: Writing to AL, AH, or AX preserves upper bits

## Operations

### Extract

Extracts a sub-register from a parent register.

```go
// Extract AL from RAX (bits 0-7)
extract := ir.Extract{
    Source: rax,
    Offset: 0,
    Size:   ir.Size1,
}

// Extract AH from RAX (bits 8-15)
extract := ir.Extract{
    Source: rax,
    Offset: 1,  // offset 1 for high byte
    Size:   ir.Size1,
}

// Extract AX from RAX (bits 0-15)
extract := ir.Extract{
    Source: rax,
    Offset: 0,
    Size:   ir.Size2,
}

// Extract EAX from RAX (bits 0-31)
extract := ir.Extract{
    Source: rax,
    Offset: 0,
    Size:   ir.Size4,
}
```

### Insert

Inserts a value into a sub-register, preserving other bits.

```go
// Write to AL, preserve bits 8-63
insert := ir.Insert{
    Dest:   rax,
    Value:  alValue,
    Offset: 0,
    Size:   ir.Size1,
}

// Write to AH, preserve bits 0-7 and 16-63
insert := ir.Insert{
    Dest:   rax,
    Value:  ahValue,
    Offset: 1,  // CRITICAL: offset 1 for high byte
    Size:   ir.Size1,
}

// Write to AX, preserve bits 16-63
insert := ir.Insert{
    Dest:   rax,
    Value:  axValue,
    Offset: 0,
    Size:   ir.Size2,
}
```

### ZeroExtend

Extends a value to larger size, zeroing upper bits. Used for 32-bit writes.

```go
// Write to EAX, zero bits 32-63 (x86_64 ISA rule)
zext := ir.ZeroExtend{
    Source:   eax,
    FromSize: ir.Size4,
    ToSize:   ir.Size8,
}
```

## Usage Examples

### Example 1: MOV AL, 0x42

```go
// Assembly: mov al, 0x42
// Semantics: Write 0x42 to AL (bits 0-7), preserve bits 8-63

rax := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}
value := ir.ConstantExpr{Value: ir.IntConstant{Value: 0x42, Width: ir.Size1, Signed: false}}

// IR: rax_new = insert(rax_old, 0x42, offset=0, size=1)
insert := ir.Insert{
    Dest:   rax,
    Value:  value,
    Offset: 0,
    Size:   ir.Size1,
}
```

### Example 2: MOV AH, 0x99

```go
// Assembly: mov ah, 0x99
// Semantics: Write 0x99 to AH (bits 8-15), preserve bits 0-7 and 16-63

rax := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}
value := ir.ConstantExpr{Value: ir.IntConstant{Value: 0x99, Width: ir.Size1, Signed: false}}

// IR: rax_new = insert(rax_old, 0x99, offset=1, size=1)
insert := ir.Insert{
    Dest:   rax,
    Value:  value,
    Offset: 1,  // CRITICAL: offset 1 for high byte
    Size:   ir.Size1,
}
```

### Example 3: MOV EAX, 0x12345678

```go
// Assembly: mov eax, 0x12345678
// Semantics: Write 0x12345678 to EAX (bits 0-31), ZERO bits 32-63

eax := ir.Variable{Name: "eax", Type: ir.IntType{Width: ir.Size4, Signed: false}}

// IR: rax_new = zeroextend(0x12345678, from=4, to=8)
zext := ir.ZeroExtend{
    Source:   eax,
    FromSize: ir.Size4,
    ToSize:   ir.Size8,
}
```

### Example 4: Complex Sequence

```go
// Assembly sequence:
//   mov eax, 0x12345678  ; zeros upper 32 bits
//   mov al, 0x42         ; modifies bits 0-7, preserves 8-63
//   mov ah, 0x99         ; modifies bits 8-15, preserves 0-7 and 16-63

rax := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}
eax := ir.Variable{Name: "eax", Type: ir.IntType{Width: ir.Size4, Signed: false}}

// Instruction 1: mov eax, 0x12345678
// Effect: rax = 0x0000000012345678
zext := ir.ZeroExtend{
    Source:   eax,
    FromSize: ir.Size4,
    ToSize:   ir.Size8,
}

// Instruction 2: mov al, 0x42
// Effect: rax = 0x0000000012345642
insert1 := ir.Insert{
    Dest:   rax,
    Value:  ir.ConstantExpr{Value: ir.IntConstant{Value: 0x42, Width: ir.Size1, Signed: false}},
    Offset: 0,
    Size:   ir.Size1,
}

// Instruction 3: mov ah, 0x99
// Effect: rax = 0x0000000012349942
insert2 := ir.Insert{
    Dest:   rax,
    Value:  ir.ConstantExpr{Value: ir.IntConstant{Value: 0x99, Width: ir.Size1, Signed: false}},
    Offset: 1,
    Size:   ir.Size1,
}

// Final value: rax = 0x0000000012349942
```

## SSA Form Integration

Sub-register operations work seamlessly with SSA form:

```go
// Assembly:
//   mov eax, 0x1000    ; rax_1 = zeroextend(0x1000)
//   mov al, 0x42       ; rax_2 = insert(rax_1, 0x42, 0, 1)
//   mov ah, 0x99       ; rax_3 = insert(rax_2, 0x99, 1, 1)

// SSA version 1
rax1 := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}, Version: 1}
eax := ir.Variable{Name: "eax", Type: ir.IntType{Width: ir.Size4, Signed: false}}

zext := ir.ZeroExtend{
    Source:   eax,
    FromSize: ir.Size4,
    ToSize:   ir.Size8,
}

// SSA version 2
rax2 := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}, Version: 2}
insert1 := ir.Insert{
    Dest:   rax1,  // uses rax_1
    Value:  ir.ConstantExpr{Value: ir.IntConstant{Value: 0x42, Width: ir.Size1, Signed: false}},
    Offset: 0,
    Size:   ir.Size1,
}

// SSA version 3
rax3 := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}, Version: 3}
insert2 := ir.Insert{
    Dest:   rax2,  // uses rax_2
    Value:  ir.ConstantExpr{Value: ir.IntConstant{Value: 0x99, Width: ir.Size1, Signed: false}},
    Offset: 1,
    Size:   ir.Size1,
}
```

## Helper Functions

### GetParentRegister

Returns the parent register for a given sub-register:

```go
parent, offset, size, found := ir.GetParentRegister("al")
// parent = "rax", offset = 0, size = 1, found = true

parent, offset, size, found := ir.GetParentRegister("ah")
// parent = "rax", offset = 1, size = 1, found = true

parent, offset, size, found := ir.GetParentRegister("eax")
// parent = "rax", offset = 0, size = 4, found = true
```

### IsSubRegister

Checks if a register is a sub-register of another:

```go
ir.IsSubRegister("al", "rax")   // true
ir.IsSubRegister("eax", "rax")  // true
ir.IsSubRegister("al", "rbx")   // false
```

### Is32BitRegister

Checks if a register is a 32-bit register (critical for zero-extension rule):

```go
ir.Is32BitRegister("eax")   // true
ir.Is32BitRegister("r8d")   // true
ir.Is32BitRegister("ax")    // false
ir.Is32BitRegister("rax")   // false
```

## Optimization Opportunities

### Dead Insert Elimination

```go
// Pattern:
//   mov al, 0x42       ; rax_1 = insert(rax_0, 0x42, 0, 1)
//   mov eax, 0x1000    ; rax_2 = zeroextend(0x1000) - overwrites al

// Optimization: First insert is dead, can be eliminated
// zeroextend overwrites bits 0-31, including al
```

### Extract-Insert Fusion

```go
// Pattern:
//   al = extract(rax, 0, 1)
//   rax = insert(rax, al, 0, 1)

// Optimization: This is a no-op, can be eliminated
```

### Constant Propagation

```go
// Pattern:
//   mov eax, 0x12345678
//   mov bl, al

// Optimization: bl = 0x78 (constant propagation)
// extract(zeroextend(0x12345678), 0, 1) -> 0x78
```

## Common Pitfalls

### Incorrect High Byte Handling

```go
// WRONG: Using offset 0 for AH
insert := ir.Insert{
    Dest:   rax,
    Value:  ahValue,
    Offset: 0,  // WRONG! Should be 1
    Size:   ir.Size1,
}

// RIGHT: Using offset 1 for AH
insert := ir.Insert{
    Dest:   rax,
    Value:  ahValue,
    Offset: 1,  // CORRECT
    Size:   ir.Size1,
}
```

### Confusing Insert and ZeroExtend

```go
// WRONG: Using insert for 32-bit write
insert := ir.Insert{
    Dest:   rax,
    Value:  eaxValue,
    Offset: 0,
    Size:   ir.Size4,
}
// This would preserve bits 32-63, which is INCORRECT for x86_64

// RIGHT: Using zeroextend for 32-bit write
zext := ir.ZeroExtend{
    Source:   eax,
    FromSize: ir.Size4,
    ToSize:   ir.Size8,
}
// This zeros bits 32-63, which is CORRECT for x86_64
```

## Register Families

All x86_64 general-purpose register families are supported:

- RAX family: RAX, EAX, AX, AL, AH
- RBX family: RBX, EBX, BX, BL, BH
- RCX family: RCX, ECX, CX, CL, CH
- RDX family: RDX, EDX, DX, DL, DH
- RSI family: RSI, ESI, SI, SIL (no high byte)
- RDI family: RDI, EDI, DI, DIL (no high byte)
- RBP family: RBP, EBP, BP, BPL (no high byte)
- RSP family: RSP, ESP, SP, SPL (no high byte)
- R8-R15 families: R8-R15, R8D-R15D, R8W-R15W, R8B-R15B (no high byte)

## Testing

Comprehensive tests are provided in `subreg_test.go` and `subreg_integration_test.go`:

```bash
# Run all sub-register tests
go test -v ./pkg/ir -run TestExtract
go test -v ./pkg/ir -run TestInsert
go test -v ./pkg/ir -run TestZeroExtend
go test -v ./pkg/ir -run TestGetParentRegister
go test -v ./pkg/ir -run TestIs32BitRegister
go test -v ./pkg/ir -run TestSubRegisterLifting

# Run all tests with coverage
go test -cover ./pkg/ir
```

## References

- Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 1, Section 3.4.1.1
- AMD64 Architecture Programmer's Manual, Volume 1, Section 3.1.1
- x86_64 ABI Specification, Section 3.2.1
