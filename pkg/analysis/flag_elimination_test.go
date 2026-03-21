package analysis

import (
	"fmt"
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// helpers for building test IR functions with flag-producing instructions
// ============================================================================

// flagProducer creates an Assign instruction whose source location indicates
// a flag-producing mnemonic (e.g., "add rax, rbx").
// the Loc field is set via the promoted exported field from the embedded baseInstruction.
func flagProducer(dest ir.Variable, mnemonic string) *ir.Assign {
	left := &ir.VariableExpr{Var: ir.Variable{Name: "a", Type: ir.IntType{Width: ir.Size8, Signed: false}}}
	right := &ir.VariableExpr{Var: ir.Variable{Name: "b", Type: ir.IntType{Width: ir.Size8, Signed: false}}}
	instr := &ir.Assign{
		Dest:   dest,
		Source: &ir.BinaryOp{Op: ir.BinOpAdd, Left: left, Right: right},
	}
	instr.Loc = ir.SourceLocation{Instruction: mnemonic + " rax, rbx"}
	return instr
}

// flagConsumer creates a Branch instruction whose source location indicates
// a flag-consuming mnemonic (e.g., "je target").
func flagConsumer(mnemonic string, trueTarget, falseTarget ir.BlockID) *ir.Branch {
	cond := &ir.ConstantExpr{Value: ir.BoolConstant{Value: true}}
	instr := &ir.Branch{Condition: cond, TrueTarget: trueTarget, FalseTarget: falseTarget}
	instr.Loc = ir.SourceLocation{Instruction: mnemonic + " target"}
	return instr
}

// pushfConsumer creates a Return instruction whose source location indicates pushf.
// used to test that pushf consumes all flags.
func pushfConsumer() *ir.Return {
	instr := &ir.Return{}
	instr.Loc = ir.SourceLocation{Instruction: "pushf"}
	return instr
}

// jumpInstr creates an unconditional jump instruction.
func jumpInstr(target ir.BlockID) ir.IRInstruction {
	return &ir.Jump{Target: target}
}

// retInstr creates a return instruction.
func retInstr() ir.IRInstruction {
	return &ir.Return{}
}

// buildFlagTestFunction builds a single-block function with the given instructions.
func buildFlagTestFunction(instrs []ir.IRInstruction) *ir.Function {
	return &ir.Function{
		Name: "test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID:           0,
				Instructions: instrs,
				Predecessors: nil,
				Successors:   nil,
			},
		},
		EntryBlock: 0,
	}
}

// ============================================================================
// TestFlagEliminator_NilFunction
// ============================================================================

func TestFlagEliminator_NilFunction(t *testing.T) {
	result, err := EliminateFlags(nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil function")
	}
	if result != nil {
		t.Fatal("expected nil result for nil function")
	}
}

// ============================================================================
// TestFlagEliminator_EmptyFunction
// ============================================================================

func TestFlagEliminator_EmptyFunction(t *testing.T) {
	fn := &ir.Function{
		Name:       "empty",
		Blocks:     map[ir.BlockID]*ir.BasicBlock{},
		EntryBlock: 0,
	}
	result, err := EliminateFlags(fn, nil, nil)
	if err == nil {
		t.Fatal("expected error for empty function")
	}
	if result != nil {
		t.Fatal("expected nil result for empty function")
	}
}

// ============================================================================
// TestFlagEliminator_NoFlagProducers
// ============================================================================

func TestFlagEliminator_NoFlagProducers(t *testing.T) {
	// function with only a return — no flag producers
	fn := buildFlagTestFunction([]ir.IRInstruction{retInstr()})

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalFlags != 0 {
		t.Errorf("expected 0 total flags, got %d", result.TotalFlags)
	}
	if result.EliminationRate != 1.0 {
		t.Errorf("expected 1.0 elimination rate for no producers, got %f", result.EliminationRate)
	}
}

// ============================================================================
// TestFlagEliminator_SingleProducerNoConsumer
// ============================================================================

func TestFlagEliminator_SingleProducerNoConsumer(t *testing.T) {
	// add rax, rbx  (flags produced but never consumed)
	// ret
	dest := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}
	fn := buildFlagTestFunction([]ir.IRInstruction{
		flagProducer(dest, "add"),
		retInstr(),
	})

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalFlags != 1 {
		t.Errorf("expected 1 total flag producer, got %d", result.TotalFlags)
	}
	if result.EliminatedFlags != 1 {
		t.Errorf("expected 1 eliminated flag producer, got %d", result.EliminatedFlags)
	}
	if result.EliminationRate != 1.0 {
		t.Errorf("expected 1.0 elimination rate, got %f", result.EliminationRate)
	}
}

// ============================================================================
// TestFlagEliminator_ProducerFollowedByConsumer
// ============================================================================

func TestFlagEliminator_ProducerFollowedByConsumer(t *testing.T) {
	// add rax, rbx  (produces ZF, SF, CF, OF, PF, AF)
	// je target     (consumes ZF only)
	dest := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}
	fn := &ir.Function{
		Name: "test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					flagProducer(dest, "add"),
					flagConsumer("je", 1, 2),
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID:           1,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalFlags != 1 {
		t.Errorf("expected 1 total flag producer, got %d", result.TotalFlags)
	}
	// producer is live because je consumes ZF
	if result.EliminatedFlags != 0 {
		t.Errorf("expected 0 eliminated (producer is live), got %d", result.EliminatedFlags)
	}
	if result.EliminationRate != 0.0 {
		t.Errorf("expected 0.0 elimination rate, got %f", result.EliminationRate)
	}

	// verify that only ZF is needed (je only needs ZF)
	producerPoint := ProgramPoint{BlockID: 0, InstrIdx: 0}
	needed := result.GetNeededCPUFlags(producerPoint)
	if len(needed) != 1 || needed[0] != ir.FlagZF {
		t.Errorf("expected only ZF needed for je, got %v", needed)
	}
}

// ============================================================================
// TestFlagEliminator_TwoProducersOneConsumer_FirstEliminated
// ============================================================================

func TestFlagEliminator_TwoProducersOneConsumer_FirstEliminated(t *testing.T) {
	// add rax, rbx  (flags produced — overwritten before any consumer)
	// add rcx, rdx  (flags produced — consumed by je)
	// je target     (consumes ZF)
	dest1 := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}
	dest2 := ir.Variable{Name: "rcx", Type: ir.IntType{Width: ir.Size8, Signed: false}}

	fn := &ir.Function{
		Name: "test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					flagProducer(dest1, "add"), // idx 0 — dead, overwritten by idx 1
					flagProducer(dest2, "add"), // idx 1 — live, consumed by je at idx 2
					flagConsumer("je", 1, 2),   // idx 2
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID:           1,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalFlags != 2 {
		t.Errorf("expected 2 total flag producers, got %d", result.TotalFlags)
	}
	// first add is dead (overwritten by second add before je)
	if result.EliminatedFlags != 1 {
		t.Errorf("expected 1 eliminated flag producer, got %d", result.EliminatedFlags)
	}
	// 1/2 = 50% elimination
	if result.EliminationRate < 0.49 || result.EliminationRate > 0.51 {
		t.Errorf("expected ~0.5 elimination rate, got %f", result.EliminationRate)
	}

	// first producer should be eliminated
	firstPoint := ProgramPoint{BlockID: 0, InstrIdx: 0}
	if !result.IsProducerEliminated(firstPoint) {
		t.Error("expected first add to be eliminated")
	}

	// second producer should be live
	secondPoint := ProgramPoint{BlockID: 0, InstrIdx: 1}
	if result.IsProducerEliminated(secondPoint) {
		t.Error("expected second add to be live")
	}
}

// ============================================================================
// TestFlagEliminator_HighEliminationRate_ArithmeticHeavy
// ============================================================================

// TestFlagEliminator_HighEliminationRate_ArithmeticHeavy verifies that a
// function with many arithmetic operations and a single conditional branch
// achieves >= 95% flag elimination rate.
func TestFlagEliminator_HighEliminationRate_ArithmeticHeavy(t *testing.T) {
	const numOps = 20 // 20 arithmetic ops, only last one's flags consumed

	instrs := make([]ir.IRInstruction, 0, numOps+1)
	for i := 0; i < numOps; i++ {
		dest := ir.Variable{
			Name: fmt.Sprintf("r%d", i),
			Type: ir.IntType{Width: ir.Size8, Signed: false},
		}
		instrs = append(instrs, flagProducer(dest, "add"))
	}
	// je consumes flags from the last add only
	instrs = append(instrs, flagConsumer("je", 1, 2))

	fn := &ir.Function{
		Name: "heavy",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID:           0,
				Instructions: instrs,
				Successors:   []ir.BlockID{1, 2},
			},
			1: {
				ID:           1,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalFlags != numOps {
		t.Errorf("expected %d total flag producers, got %d", numOps, result.TotalFlags)
	}
	// all but the last add should be eliminated (19/20 = 95%)
	if result.EliminatedFlags != numOps-1 {
		t.Errorf("expected %d eliminated, got %d", numOps-1, result.EliminatedFlags)
	}
	if result.EliminationRate < 0.95 {
		t.Errorf("expected >= 95%% elimination rate, got %.2f%%", result.EliminationRate*100)
	}
}

// ============================================================================
// TestFlagEliminator_FlagsAcrossBasicBlocks
// ============================================================================

func TestFlagEliminator_FlagsAcrossBasicBlocks(t *testing.T) {
	// bb0: add rax, rbx  (producer)
	//      jump bb1
	// bb1: je target     (consumer — ZF from bb0 is live across block boundary)
	dest := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}

	fn := &ir.Function{
		Name: "cross_block",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					flagProducer(dest, "add"),
					jumpInstr(1),
				},
				Successors: []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					flagConsumer("je", 2, 3),
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{2, 3},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{1},
			},
			3: {
				ID:           3,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{1},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalFlags != 1 {
		t.Errorf("expected 1 total flag producer, got %d", result.TotalFlags)
	}
	// producer in bb0 is live because je in bb1 consumes ZF
	if result.EliminatedFlags != 0 {
		t.Errorf("expected 0 eliminated (cross-block liveness), got %d", result.EliminatedFlags)
	}

	// verify ZF is needed at the producer
	producerPoint := ProgramPoint{BlockID: 0, InstrIdx: 0}
	needed := result.GetNeededCPUFlags(producerPoint)
	if len(needed) == 0 {
		t.Error("expected ZF to be needed at producer across block boundary")
	}
}

// ============================================================================
// TestFlagEliminator_FlagsInLoop
// ============================================================================

func TestFlagEliminator_FlagsInLoop(t *testing.T) {
	// bb0: jump bb1 (entry)
	// bb1: add rax, rbx  (producer — flags consumed by je in same block)
	//      je bb1, bb2   (consumer — back edge creates loop)
	// bb2: ret
	dest := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}

	fn := &ir.Function{
		Name: "loop",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID:           0,
				Instructions: []ir.IRInstruction{jumpInstr(1)},
				Successors:   []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					flagProducer(dest, "add"),
					flagConsumer("je", 1, 2), // back edge to bb1
				},
				Predecessors: []ir.BlockID{0, 1},
				Successors:   []ir.BlockID{1, 2},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{1},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalFlags != 1 {
		t.Errorf("expected 1 total flag producer, got %d", result.TotalFlags)
	}
	// producer is live because je in same block consumes ZF
	if result.EliminatedFlags != 0 {
		t.Errorf("expected 0 eliminated in loop, got %d", result.EliminatedFlags)
	}
}

// ============================================================================
// TestFlagEliminator_SelectiveMaterialization_JL
// ============================================================================

func TestFlagEliminator_SelectiveMaterialization_JL(t *testing.T) {
	// sub rax, rbx  (producer)
	// jl target     (consumes SF, OF only)
	dest := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}

	fn := &ir.Function{
		Name: "jl_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					flagProducer(dest, "sub"),
					flagConsumer("jl", 1, 2),
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID:           1,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	producerPoint := ProgramPoint{BlockID: 0, InstrIdx: 0}
	needed := result.GetNeededCPUFlags(producerPoint)

	// jl needs SF and OF only
	hasSF, hasOF := false, false
	for _, f := range needed {
		switch f {
		case ir.FlagSF:
			hasSF = true
		case ir.FlagOF:
			hasOF = true
		case ir.FlagZF, ir.FlagCF, ir.FlagPF, ir.FlagAF:
			t.Errorf("unexpected flag %v needed for jl", f)
		}
	}
	if !hasSF {
		t.Error("expected SF to be needed for jl")
	}
	if !hasOF {
		t.Error("expected OF to be needed for jl")
	}
}

// ============================================================================
// TestFlagEliminator_MultipleConsumers
// ============================================================================

func TestFlagEliminator_MultipleConsumers(t *testing.T) {
	// bb0: sub rax, rbx  (producer)
	//      jump bb1
	// bb1: je bb3, bb2   (consumes ZF)
	// bb2: jl bb3, bb4   (consumes SF, OF)
	// bb3: ret
	// bb4: ret
	dest := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}

	fn := &ir.Function{
		Name: "multi_consumer",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					flagProducer(dest, "sub"),
					jumpInstr(1),
				},
				Successors: []ir.BlockID{1},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					flagConsumer("je", 3, 2),
				},
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{3, 2},
			},
			2: {
				ID: 2,
				Instructions: []ir.IRInstruction{
					flagConsumer("jl", 3, 4),
				},
				Predecessors: []ir.BlockID{1},
				Successors:   []ir.BlockID{3, 4},
			},
			3: {
				ID:           3,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{1, 2},
			},
			4: {
				ID:           4,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{2},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// producer must be live (both je and jl consume its flags)
	if result.EliminatedFlags != 0 {
		t.Errorf("expected 0 eliminated, got %d", result.EliminatedFlags)
	}

	// needed flags should include ZF (from je) and SF, OF (from jl)
	producerPoint := ProgramPoint{BlockID: 0, InstrIdx: 0}
	needed := result.GetNeededCPUFlags(producerPoint)

	flagMap := make(map[ir.CPUFlag]bool)
	for _, f := range needed {
		flagMap[f] = true
	}
	if !flagMap[ir.FlagZF] {
		t.Error("expected ZF in needed flags (from je)")
	}
	if !flagMap[ir.FlagSF] {
		t.Error("expected SF in needed flags (from jl)")
	}
	if !flagMap[ir.FlagOF] {
		t.Error("expected OF in needed flags (from jl)")
	}
}

// ============================================================================
// TestFlagEliminator_ExtractMnemonic
// ============================================================================

func TestFlagEliminator_ExtractMnemonic(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"add rax, rbx", "add"},
		{"je target", "je"},
		{"ret", "ret"},
		{"", ""},
		{"  sub rax, 1", "sub"},
		{"cmp rax, rbx", "cmp"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractMnemonic(tt.input)
			if got != tt.expected {
				t.Errorf("extractMnemonic(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ============================================================================
// TestFlagEliminator_FlagsProducedByMnemonic
// ============================================================================

func TestFlagEliminator_FlagsProducedByMnemonic(t *testing.T) {
	tests := []struct {
		mnemonic    string
		wantNonZero bool
	}{
		{"add", true},
		{"sub", true},
		{"cmp", true},
		{"test", true},
		{"and", true},
		{"or", true},
		{"xor", true},
		{"shl", true},
		{"shr", true},
		{"mul", true},
		{"imul", true},
		{"mov", false},
		{"lea", false},
		{"push", false},
		{"pop", false},
		{"ret", false},
		{"jmp", false},
		{"je", false},
	}

	for _, tt := range tests {
		t.Run(tt.mnemonic, func(t *testing.T) {
			got := flagsProducedByMnemonic(tt.mnemonic)
			if tt.wantNonZero && got == 0 {
				t.Errorf("expected non-zero flags for %q, got 0", tt.mnemonic)
			}
			if !tt.wantNonZero && got != 0 {
				t.Errorf("expected zero flags for %q, got %d", tt.mnemonic, got)
			}
		})
	}
}

// ============================================================================
// TestFlagEliminator_FlagsConsumedByMnemonic
// ============================================================================

func TestFlagEliminator_FlagsConsumedByMnemonic(t *testing.T) {
	tests := []struct {
		mnemonic  string
		wantFlags flagSet
	}{
		{"je", flagBitZF},
		{"jne", flagBitZF},
		{"jz", flagBitZF},
		{"jl", flagBitSF | flagBitOF},
		{"jge", flagBitSF | flagBitOF},
		{"jle", flagBitZF | flagBitSF | flagBitOF},
		{"jg", flagBitZF | flagBitSF | flagBitOF},
		{"jb", flagBitCF},
		{"jae", flagBitCF},
		{"jbe", flagBitCF | flagBitZF},
		{"ja", flagBitCF | flagBitZF},
		{"js", flagBitSF},
		{"jns", flagBitSF},
		{"jo", flagBitOF},
		{"jno", flagBitOF},
		{"jp", flagBitPF},
		{"jnp", flagBitPF},
		{"lahf", flagBitZF | flagBitSF | flagBitAF | flagBitPF | flagBitCF},
		{"pushf", flagBitAll},
		{"pushfq", flagBitAll},
		{"add", 0},
		{"mov", 0},
		{"ret", 0},
	}

	for _, tt := range tests {
		t.Run(tt.mnemonic, func(t *testing.T) {
			got := flagsConsumedByMnemonic(tt.mnemonic)
			if got != tt.wantFlags {
				t.Errorf("flagsConsumedByMnemonic(%q) = %08b, want %08b", tt.mnemonic, got, tt.wantFlags)
			}
		})
	}
}

// ============================================================================
// TestFlagEliminator_EliminationRate_95Percent
// ============================================================================

// TestFlagEliminator_EliminationRate_95Percent verifies the 95%+ elimination
// target on a realistic arithmetic-heavy IR pattern.
// pattern: 100 arithmetic ops, only the last one's flags consumed by je.
// expected: 99/100 = 99% elimination rate.
func TestFlagEliminator_EliminationRate_95Percent(t *testing.T) {
	const numOps = 100

	instrs := make([]ir.IRInstruction, 0, numOps+1)
	for i := 0; i < numOps; i++ {
		dest := ir.Variable{
			Name: fmt.Sprintf("r%d", i),
			Type: ir.IntType{Width: ir.Size8, Signed: false},
		}
		instrs = append(instrs, flagProducer(dest, "add"))
	}
	instrs = append(instrs, flagConsumer("je", 1, 2))

	fn := &ir.Function{
		Name: "rate_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID:           0,
				Instructions: instrs,
				Successors:   []ir.BlockID{1, 2},
			},
			1: {
				ID:           1,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalFlags != numOps {
		t.Errorf("expected %d total flag producers, got %d", numOps, result.TotalFlags)
	}
	if result.EliminatedFlags != numOps-1 {
		t.Errorf("expected %d eliminated, got %d", numOps-1, result.EliminatedFlags)
	}
	if result.EliminationRate < 0.95 {
		t.Errorf("elimination rate %.2f%% is below 95%% target", result.EliminationRate*100)
	}
	t.Logf("flag elimination rate: %.2f%% (%d/%d eliminated)",
		result.EliminationRate*100, result.EliminatedFlags, result.TotalFlags)
}

// ============================================================================
// TestFlagEliminator_SemanticPreservation
// ============================================================================

// TestFlagEliminator_SemanticPreservation verifies that flags which ARE used
// are never eliminated — semantic correctness is preserved.
func TestFlagEliminator_SemanticPreservation(t *testing.T) {
	// every arithmetic op is immediately followed by a conditional branch
	// none should be eliminated
	const numOps = 10

	blocks := make(map[ir.BlockID]*ir.BasicBlock)

	// build a chain: bb0 -> bb1 -> ... -> bb(N-1) -> bbN (ret)
	// each block: add + je (consuming flags)
	exitBlock := ir.BlockID(numOps + 1)
	for i := 0; i < numOps; i++ {
		dest := ir.Variable{
			Name: fmt.Sprintf("r%d", i),
			Type: ir.IntType{Width: ir.Size8, Signed: false},
		}
		blockID := ir.BlockID(i)
		nextBlock := ir.BlockID(i + 1)

		var preds []ir.BlockID
		if i > 0 {
			preds = []ir.BlockID{ir.BlockID(i - 1)}
		}

		blocks[blockID] = &ir.BasicBlock{
			ID: blockID,
			Instructions: []ir.IRInstruction{
				flagProducer(dest, "add"),
				flagConsumer("je", nextBlock, exitBlock),
			},
			Predecessors: preds,
			Successors:   []ir.BlockID{nextBlock, exitBlock},
		}
	}
	// terminal blocks
	blocks[ir.BlockID(numOps)] = &ir.BasicBlock{
		ID:           ir.BlockID(numOps),
		Instructions: []ir.IRInstruction{retInstr()},
		Predecessors: []ir.BlockID{ir.BlockID(numOps - 1)},
	}
	blocks[exitBlock] = &ir.BasicBlock{
		ID:           exitBlock,
		Instructions: []ir.IRInstruction{retInstr()},
	}

	fn := &ir.Function{
		Name:       "semantic_preservation",
		Blocks:     blocks,
		EntryBlock: 0,
	}

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalFlags != numOps {
		t.Errorf("expected %d total flag producers, got %d", numOps, result.TotalFlags)
	}
	// all producers are immediately consumed — none should be eliminated
	if result.EliminatedFlags != 0 {
		t.Errorf("expected 0 eliminated (all flags consumed), got %d", result.EliminatedFlags)
	}
}

// ============================================================================
// TestFlagEliminator_GetNeededCPUFlags_AllFlags
// ============================================================================

func TestFlagEliminator_GetNeededCPUFlags_AllFlags(t *testing.T) {
	// pushf consumes all flags — verify all 6 are returned
	dest := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}

	fn := &ir.Function{
		Name: "pushf_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					flagProducer(dest, "add"),
					pushfConsumer(),
				},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	producerPoint := ProgramPoint{BlockID: 0, InstrIdx: 0}
	needed := result.GetNeededCPUFlags(producerPoint)

	if len(needed) != 6 {
		t.Errorf("expected 6 flags needed for pushf consumer, got %d: %v", len(needed), needed)
	}
}

// ============================================================================
// TestFlagEliminator_IsProducerEliminated
// ============================================================================

func TestFlagEliminator_IsProducerEliminated(t *testing.T) {
	dest := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}
	fn := buildFlagTestFunction([]ir.IRInstruction{
		flagProducer(dest, "add"),
		retInstr(),
	})

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	point := ProgramPoint{BlockID: 0, InstrIdx: 0}
	if !result.IsProducerEliminated(point) {
		t.Error("expected producer to be eliminated")
	}

	// non-existent point should not be eliminated
	nonExistent := ProgramPoint{BlockID: 99, InstrIdx: 0}
	if result.IsProducerEliminated(nonExistent) {
		t.Error("non-existent point should not be eliminated")
	}
}

// ============================================================================
// additional flag elimination tests (task 7.9)
// ============================================================================

// TestFlagEliminator_95PercentRate_MultiBlock verifies the 95%+ elimination
// target on a multi-block CFG where arithmetic operations span multiple blocks
// but only the last block's flags are consumed.
//
// structure: bb0 (10 adds) -> bb1 (10 adds) -> bb2 (je) -> bb3/bb4
// only the last add in bb1 has its flags consumed by je.
// expected: 19/20 = 95% elimination rate.
func TestFlagEliminator_95PercentRate_MultiBlock(t *testing.T) {
	const addsPerBlock = 10

	// build bb0: 10 adds + jump to bb1
	bb0Instrs := make([]ir.IRInstruction, 0, addsPerBlock+1)
	for i := 0; i < addsPerBlock; i++ {
		dest := ir.Variable{
			Name: fmt.Sprintf("r0_%d", i),
			Type: ir.IntType{Width: ir.Size8, Signed: false},
		}
		bb0Instrs = append(bb0Instrs, flagProducer(dest, "add"))
	}
	bb0Instrs = append(bb0Instrs, jumpInstr(1))

	// build bb1: 10 adds + je (only last add's flags consumed)
	bb1Instrs := make([]ir.IRInstruction, 0, addsPerBlock+1)
	for i := 0; i < addsPerBlock; i++ {
		dest := ir.Variable{
			Name: fmt.Sprintf("r1_%d", i),
			Type: ir.IntType{Width: ir.Size8, Signed: false},
		}
		bb1Instrs = append(bb1Instrs, flagProducer(dest, "add"))
	}
	bb1Instrs = append(bb1Instrs, flagConsumer("je", 2, 3))

	fn := &ir.Function{
		Name: "multiblock_rate",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID:           0,
				Instructions: bb0Instrs,
				Successors:   []ir.BlockID{1},
			},
			1: {
				ID:           1,
				Instructions: bb1Instrs,
				Predecessors: []ir.BlockID{0},
				Successors:   []ir.BlockID{2, 3},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{1},
			},
			3: {
				ID:           3,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{1},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	totalExpected := addsPerBlock * 2 // 20 total producers
	if result.TotalFlags != totalExpected {
		t.Errorf("expected %d total flag producers, got %d", totalExpected, result.TotalFlags)
	}

	// all bb0 adds (10) + first 9 adds in bb1 = 19 eliminated
	eliminatedExpected := totalExpected - 1
	if result.EliminatedFlags != eliminatedExpected {
		t.Errorf("expected %d eliminated, got %d", eliminatedExpected, result.EliminatedFlags)
	}

	if result.EliminationRate < 0.95 {
		t.Errorf("elimination rate %.2f%% is below 95%% target", result.EliminationRate*100)
	}
	t.Logf("multi-block flag elimination rate: %.2f%% (%d/%d)",
		result.EliminationRate*100, result.EliminatedFlags, result.TotalFlags)
}

// TestFlagEliminator_CmpInstruction verifies that cmp instructions are treated
// as flag producers (cmp sets all flags but does not write a register).
// cmp rax, rbx  (producer)
// je target     (consumer — ZF from cmp)
func TestFlagEliminator_CmpInstruction(t *testing.T) {
	dest := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}

	fn := &ir.Function{
		Name: "cmp_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					flagProducer(dest, "cmp"),
					flagConsumer("je", 1, 2),
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID:           1,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// cmp is a flag producer
	if result.TotalFlags != 1 {
		t.Errorf("expected 1 total flag producer (cmp), got %d", result.TotalFlags)
	}

	// cmp is live because je consumes ZF
	if result.EliminatedFlags != 0 {
		t.Errorf("expected 0 eliminated (cmp is live for je), got %d", result.EliminatedFlags)
	}

	// verify ZF is needed
	producerPoint := ProgramPoint{BlockID: 0, InstrIdx: 0}
	needed := result.GetNeededCPUFlags(producerPoint)
	hasZF := false
	for _, f := range needed {
		if f == ir.FlagZF {
			hasZF = true
		}
	}
	if !hasZF {
		t.Error("expected ZF to be needed at cmp producer for je consumer")
	}
}

// TestFlagEliminator_TestInstruction verifies that test instructions are treated
// as flag producers. test rax, rax sets ZF, SF, PF; clears CF, OF.
// test rax, rax  (producer)
// jz target      (consumer — ZF from test)
func TestFlagEliminator_TestInstruction(t *testing.T) {
	dest := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}

	fn := &ir.Function{
		Name: "test_instr",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					flagProducer(dest, "test"),
					flagConsumer("jz", 1, 2),
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID:           1,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalFlags != 1 {
		t.Errorf("expected 1 total flag producer (test), got %d", result.TotalFlags)
	}

	// test is live because jz consumes ZF
	if result.EliminatedFlags != 0 {
		t.Errorf("expected 0 eliminated (test is live for jz), got %d", result.EliminatedFlags)
	}
}

// TestFlagEliminator_OverwrittenBeforeUse_MultipleFlags verifies that when
// a producer's flags are overwritten by a subsequent producer before any
// consumer, the first producer is eliminated even if a consumer exists later.
// add r0  (producer 0 — all flags)
// sub r1  (producer 1 — all flags, overwrites producer 0)
// je      (consumer — ZF from producer 1 only)
// expected: producer 0 eliminated, producer 1 live
func TestFlagEliminator_OverwrittenBeforeUse_MultipleFlags(t *testing.T) {
	dest0 := ir.Variable{Name: "r0", Type: ir.IntType{Width: ir.Size8, Signed: false}}
	dest1 := ir.Variable{Name: "r1", Type: ir.IntType{Width: ir.Size8, Signed: false}}

	fn := &ir.Function{
		Name: "overwritten_flags",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					flagProducer(dest0, "add"), // idx 0 — dead
					flagProducer(dest1, "sub"), // idx 1 — live
					flagConsumer("je", 1, 2),   // idx 2
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID:           1,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalFlags != 2 {
		t.Errorf("expected 2 total flag producers, got %d", result.TotalFlags)
	}

	// producer 0 (add) is overwritten by producer 1 (sub) before je — eliminated
	if result.EliminatedFlags != 1 {
		t.Errorf("expected 1 eliminated (first add overwritten), got %d", result.EliminatedFlags)
	}

	p0 := ProgramPoint{BlockID: 0, InstrIdx: 0}
	p1 := ProgramPoint{BlockID: 0, InstrIdx: 1}

	if !result.IsProducerEliminated(p0) {
		t.Error("expected first add (idx 0) to be eliminated")
	}
	if result.IsProducerEliminated(p1) {
		t.Error("expected second sub (idx 1) to be live")
	}
}

// TestFlagEliminator_NoConsumers_AllEliminated verifies that when there are
// no flag consumers at all, all producers are eliminated (100% rate).
func TestFlagEliminator_NoConsumers_AllEliminated(t *testing.T) {
	const numOps = 15

	instrs := make([]ir.IRInstruction, 0, numOps+1)
	for i := 0; i < numOps; i++ {
		dest := ir.Variable{
			Name: fmt.Sprintf("r%d", i),
			Type: ir.IntType{Width: ir.Size8, Signed: false},
		}
		instrs = append(instrs, flagProducer(dest, "add"))
	}
	instrs = append(instrs, retInstr())

	fn := buildFlagTestFunction(instrs)

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalFlags != numOps {
		t.Errorf("expected %d total flag producers, got %d", numOps, result.TotalFlags)
	}
	if result.EliminatedFlags != numOps {
		t.Errorf("expected all %d producers eliminated, got %d", numOps, result.EliminatedFlags)
	}
	if result.EliminationRate != 1.0 {
		t.Errorf("expected 100%% elimination rate, got %.2f%%", result.EliminationRate*100)
	}
}

func TestFlagEliminator_GetNeededFlagsAt(t *testing.T) {
	dest := ir.Variable{Name: "rax", Type: ir.IntType{Width: ir.Size8, Signed: false}}
	fn := &ir.Function{
		Name: "needed_flags_at",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					flagProducer(dest, "add"),
					flagConsumer("je", 1, 2),
				},
				Successors: []ir.BlockID{1, 2},
			},
			1: {
				ID:           1,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
			2: {
				ID:           2,
				Instructions: []ir.IRInstruction{retInstr()},
				Predecessors: []ir.BlockID{0},
			},
		},
		EntryBlock: 0,
	}

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	producerPoint := ProgramPoint{BlockID: 0, InstrIdx: 0}
	bits := result.GetNeededFlagsAt(producerPoint)
	if bits == 0 {
		t.Error("expected non-zero needed flags bitmask for live producer")
	}
	if bits&uint8(flagBitZF) == 0 {
		t.Error("expected ZF bit set in needed flags for je consumer")
	}

	deadPoint := ProgramPoint{BlockID: 99, InstrIdx: 0}
	if result.GetNeededFlagsAt(deadPoint) != 0 {
		t.Error("expected 0 for non-existent point")
	}
}

func TestFlagEliminator_FlagsProducedByMnemonic_Extended(t *testing.T) {
	tests := []struct {
		mnemonic    string
		wantNonZero bool
	}{
		{"adc", true},
		{"sbb", true},
		{"neg", true},
		{"inc", true},
		{"dec", true},
		{"sal", true},
		{"sar", true},
		{"rol", true},
		{"ror", true},
		{"div", true},
		{"idiv", true},
		{"sahf", true},
		{"popf", true},
		{"popfq", true},
		{"clc", true},
		{"stc", true},
		{"cmc", true},
		{"nop", false},
		{"call", false},
	}

	for _, tt := range tests {
		t.Run(tt.mnemonic, func(t *testing.T) {
			got := flagsProducedByMnemonic(tt.mnemonic)
			if tt.wantNonZero && got == 0 {
				t.Errorf("expected non-zero flags for %q, got 0", tt.mnemonic)
			}
			if !tt.wantNonZero && got != 0 {
				t.Errorf("expected zero flags for %q, got %d", tt.mnemonic, got)
			}
		})
	}
}

func TestFlagEliminator_FlagsConsumedByMnemonic_CmovAndSet(t *testing.T) {
	tests := []struct {
		mnemonic  string
		wantFlags flagSet
	}{
		{"cmove", flagBitZF},
		{"cmovne", flagBitZF},
		{"cmovl", flagBitSF | flagBitOF},
		{"cmovge", flagBitSF | flagBitOF},
		{"cmovb", flagBitCF},
		{"cmovae", flagBitCF},
		{"sete", flagBitZF},
		{"setne", flagBitZF},
		{"setl", flagBitSF | flagBitOF},
		{"setge", flagBitSF | flagBitOF},
		{"setb", flagBitCF},
		{"setae", flagBitCF},
	}

	for _, tt := range tests {
		t.Run(tt.mnemonic, func(t *testing.T) {
			got := flagsConsumedByMnemonic(tt.mnemonic)
			if got != tt.wantFlags {
				t.Errorf("flagsConsumedByMnemonic(%q) = %08b, want %08b", tt.mnemonic, got, tt.wantFlags)
			}
		})
	}
}

func TestFlagEliminator_CpuFlagToBit_DefaultCase(t *testing.T) {
	got := cpuFlagToBit(ir.CPUFlag(99))
	if got != 0 {
		t.Errorf("expected 0 for unknown CPUFlag, got %d", got)
	}
}
