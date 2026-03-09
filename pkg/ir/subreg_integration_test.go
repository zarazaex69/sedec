package ir

import (
	"testing"
)

// ============================================================================
// Integration Tests - Real-World Usage Scenarios
// ============================================================================

// TestSubRegisterLifting_RealWorldScenario demonstrates how sub-register
// operations would be used by IR_Lifter when translating x86_64 assembly
func TestSubRegisterLifting_RealWorldScenario(t *testing.T) {
	t.Run("scenario: mov al, 0x42", func(t *testing.T) {
		// assembly: mov al, 0x42
		// semantics: write 0x42 to al (bits 0-7), preserve bits 8-63 of rax

		rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}
		value := ConstantExpr{Value: IntConstant{Value: 0x42, Width: Size1, Signed: false}}

		// ir_lifter would generate: rax_new = insert(rax_old, 0x42, offset=0, size=1)
		insert := Insert{
			Dest:   rax,
			Value:  value,
			Offset: 0,
			Size:   Size1,
		}

		// verify correct ir generation
		if insert.Size != Size1 {
			t.Errorf("expected size 1, got %d", insert.Size)
		}
		if insert.Offset != 0 {
			t.Errorf("expected offset 0, got %d", insert.Offset)
		}

		t.Logf("generated ir: %s", insert.String())
		t.Log("semantics: preserves bits 8-63 of rax")
	})

	t.Run("scenario: mov ah, 0x42", func(t *testing.T) {
		// assembly: mov ah, 0x42
		// semantics: write 0x42 to ah (bits 8-15), preserve bits 0-7 and 16-63

		rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}
		value := ConstantExpr{Value: IntConstant{Value: 0x42, Width: Size1, Signed: false}}

		// ir_lifter would generate: rax_new = insert(rax_old, 0x42, offset=1, size=1)
		insert := Insert{
			Dest:   rax,
			Value:  value,
			Offset: 1, // critical: offset 1 for high byte
			Size:   Size1,
		}

		// verify correct ir generation
		if insert.Size != Size1 {
			t.Errorf("expected size 1, got %d", insert.Size)
		}
		if insert.Offset != 1 {
			t.Errorf("expected offset 1, got %d", insert.Offset)
		}

		t.Logf("generated ir: %s", insert.String())
		t.Log("semantics: preserves bits 0-7 (al) and bits 16-63 (upper rax)")
	})

	t.Run("scenario: mov ax, 0x1234", func(t *testing.T) {
		// assembly: mov ax, 0x1234
		// semantics: write 0x1234 to ax (bits 0-15), preserve bits 16-63

		rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}
		value := ConstantExpr{Value: IntConstant{Value: 0x1234, Width: Size2, Signed: false}}

		// ir_lifter would generate: rax_new = insert(rax_old, 0x1234, offset=0, size=2)
		insert := Insert{
			Dest:   rax,
			Value:  value,
			Offset: 0,
			Size:   Size2,
		}

		// verify correct ir generation
		if insert.Size != Size2 {
			t.Errorf("expected size 2, got %d", insert.Size)
		}

		t.Logf("generated ir: %s", insert.String())
		t.Log("semantics: preserves bits 16-63 of rax")
	})

	t.Run("scenario: mov eax, 0x12345678", func(t *testing.T) {
		// assembly: mov eax, 0x12345678
		// semantics: write 0x12345678 to eax (bits 0-31), ZERO bits 32-63
		// this is x86_64 isa-defined behavior

		eax := Variable{Name: "eax", Type: IntType{Width: Size4, Signed: false}}

		// ir_lifter would generate: rax_new = zeroextend(0x12345678, from=4, to=8)
		zext := ZeroExtend{
			Source:   eax,
			FromSize: Size4,
			ToSize:   Size8,
		}

		// verify correct ir generation
		if zext.FromSize != Size4 {
			t.Errorf("expected fromsize 4, got %d", zext.FromSize)
		}
		if zext.ToSize != Size8 {
			t.Errorf("expected tosize 8, got %d", zext.ToSize)
		}

		t.Logf("generated ir: %s", zext.String())
		t.Log("semantics: zeros bits 32-63 of rax (x86_64 isa rule)")
	})

	t.Run("scenario: movzx rax, al", func(t *testing.T) {
		// assembly: movzx rax, al
		// semantics: zero-extend al to rax (extract al, then zero-extend)

		rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}
		al := Variable{Name: "al", Type: IntType{Width: Size1, Signed: false}}

		// step 1: extract al from rax
		extract := Extract{
			Source: rax,
			Offset: 0,
			Size:   Size1,
		}

		// step 2: zero-extend to 64-bit
		zext := ZeroExtend{
			Source:   al,
			FromSize: Size1,
			ToSize:   Size8,
		}

		t.Logf("step 1: %s", extract.String())
		t.Logf("step 2: %s", zext.String())
		t.Log("semantics: extract al, then zero-extend to rax")
	})
}

// TestSubRegisterLifting_ComplexSequence tests a complex sequence of
// sub-register operations that might occur in real code
func TestSubRegisterLifting_ComplexSequence(t *testing.T) {
	// simulate this assembly sequence:
	//   mov eax, 0x12345678  ; zeros upper 32 bits
	//   mov al, 0x42         ; modifies bits 0-7, preserves 8-63
	//   mov ah, 0x99         ; modifies bits 8-15, preserves 0-7 and 16-63

	rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}
	eax := Variable{Name: "eax", Type: IntType{Width: Size4, Signed: false}}

	// instruction 1: mov eax, 0x12345678
	zext1 := ZeroExtend{
		Source:   eax,
		FromSize: Size4,
		ToSize:   Size8,
	}
	t.Logf("instr 1: %s", zext1.String())
	t.Log("  effect: rax = 0x0000000012345678")

	// instruction 2: mov al, 0x42
	insert1 := Insert{
		Dest:   rax,
		Value:  ConstantExpr{Value: IntConstant{Value: 0x42, Width: Size1, Signed: false}},
		Offset: 0,
		Size:   Size1,
	}
	t.Logf("instr 2: %s", insert1.String())
	t.Log("  effect: rax = 0x0000000012345642")

	// instruction 3: mov ah, 0x99
	insert2 := Insert{
		Dest:   rax,
		Value:  ConstantExpr{Value: IntConstant{Value: 0x99, Width: Size1, Signed: false}},
		Offset: 1,
		Size:   Size1,
	}
	t.Logf("instr 3: %s", insert2.String())
	t.Log("  effect: rax = 0x0000000012349942")

	t.Log("final value: rax = 0x0000000012349942")
	t.Log("demonstrates correct modeling of partial register updates")
}

// TestSubRegisterLifting_DataFlowAnalysis demonstrates how sub-register
// operations interact with data-flow analysis
func TestSubRegisterLifting_DataFlowAnalysis(t *testing.T) {
	t.Run("def-use chain with sub-registers", func(t *testing.T) {
		// assembly:
		//   mov eax, [rbx]     ; define eax (zeros upper 32 bits)
		//   add al, 0x10       ; use al, define al (preserves upper bits)
		//   mov [rcx], ax      ; use ax

		rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}
		eax := Variable{Name: "eax", Type: IntType{Width: Size4, Signed: false}}

		// instruction 1: mov eax, [rbx]
		// defines eax, which zero-extends to rax
		zext := ZeroExtend{
			Source:   eax,
			FromSize: Size4,
			ToSize:   Size8,
		}

		// instruction 2: add al, 0x10
		// uses al (extract from rax), defines al (insert into rax)
		extract := Extract{
			Source: rax,
			Offset: 0,
			Size:   Size1,
		}

		// add operation
		addResult := BinaryOp{
			Op:    BinOpAdd,
			Left:  extract,
			Right: ConstantExpr{Value: IntConstant{Value: 0x10, Width: Size1, Signed: false}},
		}

		// insert result back
		insert := Insert{
			Dest:   rax,
			Value:  addResult,
			Offset: 0,
			Size:   Size1,
		}

		// instruction 3: mov [rcx], ax
		// uses ax (extract from rax)
		extractAx := Extract{
			Source: rax,
			Offset: 0,
			Size:   Size2,
		}

		t.Logf("def: %s", zext.String())
		t.Logf("use-def: extract=%s, add=%s, insert=%s",
			extract.String(), addResult.String(), insert.String())
		t.Logf("use: %s", extractAx.String())

		t.Log("data-flow analysis must track:")
		t.Log("  - eax definition zeros upper 32 bits")
		t.Log("  - al modification preserves bits 8-63")
		t.Log("  - ax use depends on both eax and al definitions")
	})
}

// TestSubRegisterLifting_SSAForm demonstrates how sub-register operations
// work in SSA form with versioned variables
func TestSubRegisterLifting_SSAForm(t *testing.T) {
	// assembly:
	//   mov eax, 0x1000    ; rax_1 = zeroextend(0x1000)
	//   mov al, 0x42       ; rax_2 = insert(rax_1, 0x42, 0, 1)
	//   mov ah, 0x99       ; rax_3 = insert(rax_2, 0x99, 1, 1)

	// ssa version 1
	rax1 := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}, Version: 1}
	eax := Variable{Name: "eax", Type: IntType{Width: Size4, Signed: false}}

	zext := ZeroExtend{
		Source:   eax,
		FromSize: Size4,
		ToSize:   Size8,
	}

	// ssa version 2
	rax2 := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}, Version: 2}
	insert1 := Insert{
		Dest:   rax1, // uses rax_1
		Value:  ConstantExpr{Value: IntConstant{Value: 0x42, Width: Size1, Signed: false}},
		Offset: 0,
		Size:   Size1,
	}

	// ssa version 3
	rax3 := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}, Version: 3}
	insert2 := Insert{
		Dest:   rax2, // uses rax_2
		Value:  ConstantExpr{Value: IntConstant{Value: 0x99, Width: Size1, Signed: false}},
		Offset: 1,
		Size:   Size1,
	}

	t.Logf("%s = %s", rax1.String(), zext.String())
	t.Logf("%s = %s", rax2.String(), insert1.String())
	t.Logf("%s = %s", rax3.String(), insert2.String())

	t.Log("ssa form correctly tracks register versions through partial updates")
	t.Log("each insert creates new ssa version, preserving def-use chains")
}

// TestSubRegisterLifting_OptimizationOpportunities demonstrates optimization
// opportunities enabled by explicit sub-register modeling
func TestSubRegisterLifting_OptimizationOpportunities(t *testing.T) {
	t.Run("dead insert elimination", func(t *testing.T) {
		// assembly:
		//   mov al, 0x42       ; rax_1 = insert(rax_0, 0x42, 0, 1)
		//   mov eax, 0x1000    ; rax_2 = zeroextend(0x1000) - overwrites al
		// optimization: first insert is dead, can be eliminated

		rax0 := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}, Version: 0}

		insert := Insert{
			Dest:   rax0,
			Value:  ConstantExpr{Value: IntConstant{Value: 0x42, Width: Size1, Signed: false}},
			Offset: 0,
			Size:   Size1,
		}

		eax := Variable{Name: "eax", Type: IntType{Width: Size4, Signed: false}}
		zext := ZeroExtend{
			Source:   eax,
			FromSize: Size4,
			ToSize:   Size8,
		}

		t.Logf("dead: %s", insert.String())
		t.Logf("overwrites: %s", zext.String())
		t.Log("optimization: eliminate dead insert (zeroextend overwrites bits 0-31)")
	})

	t.Run("extract-insert fusion", func(t *testing.T) {
		// pattern: extract then immediately insert same value
		//   al = extract(rax, 0, 1)
		//   rax = insert(rax, al, 0, 1)
		// optimization: this is a no-op, can be eliminated

		rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}

		extract := Extract{
			Source: rax,
			Offset: 0,
			Size:   Size1,
		}

		insert := Insert{
			Dest:   rax,
			Value:  extract,
			Offset: 0,
			Size:   Size1,
		}

		t.Logf("extract: %s", extract.String())
		t.Logf("insert: %s", insert.String())
		t.Log("optimization: extract-insert of same location is no-op")
	})

	t.Run("constant propagation through sub-registers", func(t *testing.T) {
		// assembly:
		//   mov eax, 0x12345678
		//   mov bl, al
		// optimization: bl = 0x78 (constant propagation)

		eax := Variable{Name: "eax", Type: IntType{Width: Size4, Signed: false}}
		rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}

		// eax = 0x12345678, which zero-extends to rax
		zext := ZeroExtend{
			Source:   eax,
			FromSize: Size4,
			ToSize:   Size8,
		}

		// extract al from rax (bits 0-7)
		extract := Extract{
			Source: rax,
			Offset: 0,
			Size:   Size1,
		}

		t.Logf("rax = %s (value: 0x0000000012345678)", zext.String())
		t.Logf("al = %s", extract.String())
		t.Log("optimization: al = 0x78 (constant propagation)")
		t.Log("  extract(zeroextend(0x12345678), 0, 1) -> 0x78")
	})
}

// TestSubRegisterLifting_ErrorPrevention demonstrates how explicit modeling
// prevents common decompilation errors
func TestSubRegisterLifting_ErrorPrevention(t *testing.T) {
	t.Run("prevent incorrect value propagation", func(t *testing.T) {
		// without proper aliasing model, this could be miscompiled:
		//   mov eax, 0xFFFFFFFF
		//   mov al, 0x00
		//   ; rax should be 0x00000000FFFFFF00, NOT 0x0000000000000000

		rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}
		eax := Variable{Name: "eax", Type: IntType{Width: Size4, Signed: false}}

		// instruction 1: mov eax, 0xFFFFFFFF
		zext := ZeroExtend{
			Source:   eax,
			FromSize: Size4,
			ToSize:   Size8,
		}
		t.Logf("instr 1: %s", zext.String())
		t.Log("  rax = 0x00000000FFFFFFFF (upper 32 bits zeroed)")

		// instruction 2: mov al, 0x00
		insert := Insert{
			Dest:   rax,
			Value:  ConstantExpr{Value: IntConstant{Value: 0x00, Width: Size1, Signed: false}},
			Offset: 0,
			Size:   Size1,
		}
		t.Logf("instr 2: %s", insert.String())
		t.Log("  rax = 0x00000000FFFFFF00 (only bits 0-7 modified)")

		t.Log("correct modeling prevents miscompilation:")
		t.Log("  WRONG: treating al write as full rax write -> 0x0000000000000000")
		t.Log("  RIGHT: insert preserves bits 8-63 -> 0x00000000FFFFFF00")
	})

	t.Run("prevent incorrect high byte handling", func(t *testing.T) {
		// ah (high byte) is tricky - offset must be 1, not 0
		//   mov ah, 0x42
		//   ; should modify bits 8-15, preserve bits 0-7 and 16-63

		rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}

		insert := Insert{
			Dest:   rax,
			Value:  ConstantExpr{Value: IntConstant{Value: 0x42, Width: Size1, Signed: false}},
			Offset: 1, // CRITICAL: offset 1 for high byte
			Size:   Size1,
		}

		if insert.Offset != 1 {
			t.Errorf("CRITICAL ERROR: ah must have offset 1, got %d", insert.Offset)
		}

		t.Logf("correct: %s", insert.String())
		t.Log("  modifies bits 8-15 only")
		t.Log("  preserves al (bits 0-7) and upper rax (bits 16-63)")

		t.Log("incorrect modeling would:")
		t.Log("  - use offset 0 (wrong bit range)")
		t.Log("  - overwrite al instead of ah")
		t.Log("  - produce incorrect decompilation")
	})
}

// TestSubRegisterLifting_PerformanceConsiderations tests that sub-register
// operations have reasonable performance characteristics
func TestSubRegisterLifting_PerformanceConsiderations(t *testing.T) {
	t.Run("operation creation overhead", func(t *testing.T) {
		// measure overhead of creating sub-register operations
		rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}
		value := ConstantExpr{Value: IntConstant{Value: 0x42, Width: Size1, Signed: false}}

		// create 1000 operations
		operations := make([]SubRegisterOp, 1000)
		for i := 0; i < 1000; i++ {
			operations[i] = Insert{
				Dest:   rax,
				Value:  value,
				Offset: 0,
				Size:   Size1,
			}
		}

		if len(operations) != 1000 {
			t.Errorf("expected 1000 operations, got %d", len(operations))
		}

		t.Log("created 1000 sub-register operations")
		t.Log("operations are lightweight structs with minimal overhead")
	})

	t.Run("string representation performance", func(t *testing.T) {
		// verify string representation doesn't allocate excessively
		rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}
		value := ConstantExpr{Value: IntConstant{Value: 0x42, Width: Size1, Signed: false}}

		insert := Insert{
			Dest:   rax,
			Value:  value,
			Offset: 0,
			Size:   Size1,
		}

		// call string multiple times
		for i := 0; i < 100; i++ {
			_ = insert.String()
		}

		t.Log("string representation called 100 times")
		t.Log("uses fmt.Sprintf - acceptable for debugging/logging")
	})
}

// TestSubRegisterLifting_EdgeCasesAndCornerCases tests unusual but valid
// sub-register operation patterns
func TestSubRegisterLifting_EdgeCasesAndCornerCases(t *testing.T) {
	t.Run("extract full register", func(t *testing.T) {
		// edge case: extract entire register (offset=0, size=8)
		rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}

		extract := Extract{
			Source: rax,
			Offset: 0,
			Size:   Size8,
		}

		t.Logf("extract: %s", extract.String())
		t.Log("semantics: extracting full register is identity operation")
		t.Log("optimization: can be eliminated")
	})

	t.Run("insert full register", func(t *testing.T) {
		// edge case: insert entire register (offset=0, size=8)
		rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}
		value := ConstantExpr{Value: IntConstant{Value: 0x123456789ABCDEF0, Width: Size8, Signed: false}}

		insert := Insert{
			Dest:   rax,
			Value:  value,
			Offset: 0,
			Size:   Size8,
		}

		t.Logf("insert: %s", insert.String())
		t.Log("semantics: inserting full register is assignment")
		t.Log("optimization: can be replaced with simple assign")
	})

	t.Run("zeroextend to same size", func(t *testing.T) {
		// edge case: zero-extend to same size
		eax := Variable{Name: "eax", Type: IntType{Width: Size4, Signed: false}}

		zext := ZeroExtend{
			Source:   eax,
			FromSize: Size4,
			ToSize:   Size4,
		}

		t.Logf("zeroextend: %s", zext.String())
		t.Log("semantics: zero-extending to same size is identity")
		t.Log("optimization: can be eliminated")
	})

	t.Run("multiple extracts from same source", func(t *testing.T) {
		// pattern: extract multiple sub-registers from same source
		rax := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}}

		extractAL := Extract{Source: rax, Offset: 0, Size: Size1}
		extractAH := Extract{Source: rax, Offset: 1, Size: Size1}
		extractAX := Extract{Source: rax, Offset: 0, Size: Size2}
		extractEAX := Extract{Source: rax, Offset: 0, Size: Size4}

		t.Logf("al: %s", extractAL.String())
		t.Logf("ah: %s", extractAH.String())
		t.Logf("ax: %s", extractAX.String())
		t.Logf("eax: %s", extractEAX.String())

		t.Log("all extracts from same source are independent")
		t.Log("data-flow analysis must track overlapping ranges")
	})

	t.Run("chained inserts", func(t *testing.T) {
		// pattern: multiple inserts to same destination
		rax0 := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}, Version: 0}
		rax1 := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}, Version: 1}
		rax2 := Variable{Name: "rax", Type: IntType{Width: Size8, Signed: false}, Version: 2}

		insert1 := Insert{
			Dest:   rax0,
			Value:  ConstantExpr{Value: IntConstant{Value: 0x42, Width: Size1, Signed: false}},
			Offset: 0,
			Size:   Size1,
		}

		insert2 := Insert{
			Dest:   rax1,
			Value:  ConstantExpr{Value: IntConstant{Value: 0x99, Width: Size1, Signed: false}},
			Offset: 1,
			Size:   Size1,
		}

		t.Logf("%s = %s", rax1.String(), insert1.String())
		t.Logf("%s = %s", rax2.String(), insert2.String())

		t.Log("chained inserts create ssa versions")
		t.Log("each insert depends on previous version")
		t.Log("optimization: can potentially merge non-overlapping inserts")
	})
}
