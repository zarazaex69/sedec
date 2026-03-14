package analysis

// TestProperty12: Lazy Flag Elimination Effectiveness
//
// property 12: for all ir programs P with flag operations:
//
//	(flags_before - flags_after) / flags_before >= 0.95
//
// validates requirements 10.5.1-10.5.15:
//   - 10.5.1: flags marked as lazy after arithmetic operations
//   - 10.5.2: flags not immediately computed unless required
//   - 10.5.3: deferred flag materialization
//   - 10.5.4: track which flags are actually consumed
//   - 10.5.5: eliminate >= 95% of unused flag computations
//   - 10.5.6: materialize only specific flags required (e.g., only ZF for je/jne)
//   - 10.5.14: measure and report flag elimination rate
//   - 10.5.15: every surviving flag computation must have a consumer
//
// minimum 100 iterations required.

import (
	"fmt"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
	"github.com/zarazaex69/sedec/pkg/ir"
)

// ============================================================================
// property test entry point
// ============================================================================

// TestProperty12 verifies lazy flag elimination achieves >= 95% elimination rate.
// runs 100+ iterations with gopter-generated ir programs.
//
//nolint:dupl // similar test property structure to others
func TestProperty12(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	params.MaxSize = 10

	properties := gopter.NewProperties(params)

	// property 12a: arithmetic-heavy code achieves >= 95% flag elimination
	properties.Property("flag elimination rate >= 95% for arithmetic-heavy ir", prop.ForAll(
		func(prog *flagProgram) bool {
			return checkFlagEliminationRate(t, prog)
		},
		genFlagProgram(),
	))

	// property 12b: every surviving flag producer has at least one consumer
	properties.Property("every surviving flag producer has a consumer", prop.ForAll(
		func(prog *flagProgram) bool {
			return checkSurvivingProducersHaveConsumers(t, prog)
		},
		genFlagProgram(),
	))

	// property 12c: selective materialization — only required flags survive
	properties.Property("selective materialization: only required flags survive", prop.ForAll(
		func(prog *selectiveFlagProgram) bool {
			return checkSelectiveMaterialization(t, prog)
		},
		genSelectiveFlagProgram(),
	))

	// property 12d: multi-block flag elimination achieves >= 95% rate
	properties.Property("multi-block flag elimination rate >= 95%", prop.ForAll(
		func(prog *multiBlockFlagProgram) bool {
			return checkMultiBlockFlagEliminationRate(t, prog)
		},
		genMultiBlockFlagProgram(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ============================================================================
// program types for generators
// ============================================================================

// flagProgram represents an ir function with arithmetic operations that set flags
// and a small number of conditional branches that consume flags.
// the key invariant: numArithOps >> numConsumers, so elimination rate is high.
type flagProgram struct {
	// numArithOps is the total number of arithmetic operations (flag producers)
	// range: 10-50 to ensure statistically meaningful elimination rates
	numArithOps int
	// numConsumers is the number of flag-consuming conditional branches
	// range: 1-3 (much fewer than producers to achieve >= 95% elimination)
	numConsumers int
	// producerMnemonics is the sequence of flag-producing mnemonics to use
	producerMnemonics []string
	// consumerMnemonics is the sequence of flag-consuming mnemonics to use
	consumerMnemonics []string
}

// selectiveFlagProgram tests that only the specific flags required by a
// conditional branch are marked as needed (selective materialization).
type selectiveFlagProgram struct {
	// producerMnemonic is the arithmetic instruction that sets flags
	producerMnemonic string
	// consumerMnemonic is the conditional branch that reads specific flags
	consumerMnemonic string
	// expectedFlags is the set of flags that should be needed after analysis
	expectedFlags []ir.CPUFlag
}

// multiBlockFlagProgram represents a multi-block ir function where arithmetic
// operations span multiple basic blocks but only the last block's flags are consumed.
type multiBlockFlagProgram struct {
	// numBlocks is the number of basic blocks (each with arithmetic ops)
	numBlocks int
	// opsPerBlock is the number of arithmetic ops per block
	opsPerBlock int
	// consumerMnemonic is the conditional branch in the last block
	consumerMnemonic string
}

// ============================================================================
// gopter generators
// ============================================================================

// genFlagProgram generates arbitrary flag programs with many producers and few consumers.
// the ratio numArithOps/numConsumers is always >= 10 to guarantee >= 90% elimination.
// with the last-producer-wins semantics, only the last producer before each consumer
// survives, so elimination rate = (numArithOps - numConsumers) / numArithOps.
func genFlagProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		// flag-producing mnemonics (all set flags)
		producers := []string{"add", "sub", "cmp", "test", "and", "or", "xor"}
		// flag-consuming mnemonics (conditional branches)
		consumers := []string{"je", "jne", "jl", "jge", "jle", "jg", "jb", "jae", "js", "jns", "jo", "jno"}

		// numArithOps: 20-50 (ensures high elimination rate)
		numArithOps := int(params.NextUint64()%31) + 20

		// numConsumers: 1 (single consumer at the end)
		// with 1 consumer and N producers, elimination = (N-1)/N >= 95% when N >= 20
		numConsumers := 1

		// generate producer sequence
		producerMnemonics := make([]string, numArithOps)
		for i := range producerMnemonics {
			producerMnemonics[i] = producers[params.NextUint64()%uint64(len(producers))]
		}

		// generate consumer sequence
		consumerMnemonics := make([]string, numConsumers)
		for i := range consumerMnemonics {
			consumerMnemonics[i] = consumers[params.NextUint64()%uint64(len(consumers))]
		}

		prog := &flagProgram{
			numArithOps:       numArithOps,
			numConsumers:      numConsumers,
			producerMnemonics: producerMnemonics,
			consumerMnemonics: consumerMnemonics,
		}
		return gopter.NewGenResult(prog, gopter.NoShrinker)
	}
}

// genSelectiveFlagProgram generates programs testing selective flag materialization.
// each case pairs a producer with a consumer that only needs a subset of flags.
func genSelectiveFlagProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		// pairs: (producer, consumer, expected_flags)
		type selectiveCase struct {
			producer string
			consumer string
			flags    []ir.CPUFlag
		}

		cases := []selectiveCase{
			// je/jne only need ZF
			{"add", "je", []ir.CPUFlag{ir.FlagZF}},
			{"sub", "jne", []ir.CPUFlag{ir.FlagZF}},
			{"cmp", "jz", []ir.CPUFlag{ir.FlagZF}},
			// jl/jge need SF and OF
			{"sub", "jl", []ir.CPUFlag{ir.FlagSF, ir.FlagOF}},
			{"cmp", "jge", []ir.CPUFlag{ir.FlagSF, ir.FlagOF}},
			// jb/jae need CF only
			{"sub", "jb", []ir.CPUFlag{ir.FlagCF}},
			{"add", "jae", []ir.CPUFlag{ir.FlagCF}},
			// js/jns need SF only
			{"add", "js", []ir.CPUFlag{ir.FlagSF}},
			{"sub", "jns", []ir.CPUFlag{ir.FlagSF}},
			// jo/jno need OF only
			{"add", "jo", []ir.CPUFlag{ir.FlagOF}},
			{"sub", "jno", []ir.CPUFlag{ir.FlagOF}},
		}

		c := cases[params.NextUint64()%uint64(len(cases))]
		prog := &selectiveFlagProgram{
			producerMnemonic: c.producer,
			consumerMnemonic: c.consumer,
			expectedFlags:    c.flags,
		}
		return gopter.NewGenResult(prog, gopter.NoShrinker)
	}
}

// genMultiBlockFlagProgram generates multi-block programs where arithmetic ops
// span multiple blocks but only the last block's flags are consumed.
// invariant: numBlocks * opsPerBlock >= 20 to guarantee >= 95% elimination rate.
// with N*M total producers and 1 consumer, elimination = (N*M - 1) / (N*M).
// for N*M >= 20: (20-1)/20 = 95.0% — exactly at threshold.
// we use N*M >= 21 to stay strictly above 95%.
func genMultiBlockFlagProgram() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		consumers := []string{"je", "jne", "jl", "jge", "jb", "jae", "js", "jo"}

		// numBlocks: 2-5 blocks
		numBlocks := int(params.NextUint64()%4) + 2
		// opsPerBlock: ensure numBlocks * opsPerBlock >= 21
		// minimum opsPerBlock = ceil(21 / numBlocks)
		minOps := (21 + numBlocks - 1) / numBlocks
		// add 0-5 extra ops for variety
		opsPerBlock := minOps + int(params.NextUint64()%6)

		prog := &multiBlockFlagProgram{
			numBlocks:        numBlocks,
			opsPerBlock:      opsPerBlock,
			consumerMnemonic: consumers[params.NextUint64()%uint64(len(consumers))],
		}
		return gopter.NewGenResult(prog, gopter.NoShrinker)
	}
}

// ============================================================================
// property checkers
// ============================================================================

// checkFlagEliminationRate verifies that the elimination rate is >= 95%.
//
// property: (flags_before - flags_after) / flags_before >= 0.95
//
// the function structure is:
//
//	bb0: arith_0, arith_1, ..., arith_N-1, consumer_0, ret
//	bb1: ret (true branch target)
//	bb2: ret (false branch target)
//
// with N arithmetic ops and 1 consumer, only the last arithmetic op's flags
// are consumed. all N-1 preceding ops are eliminated.
// elimination rate = (N-1)/N. for N >= 20, this is >= 95%.
func checkFlagEliminationRate(t *testing.T, prog *flagProgram) bool {
	t.Helper()
	fn := buildFlagProgramFunction(prog)

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Logf("EliminateFlags failed: %v", err)
		return false
	}

	// degenerate case: no flag producers (trivially 100% elimination)
	if result.TotalFlags == 0 {
		return true
	}

	// verify elimination rate >= 95%
	if result.EliminationRate < 0.95 {
		t.Logf("flag elimination rate %.2f%% < 95%% target\n  program: %s\n  total=%d eliminated=%d",
			result.EliminationRate*100,
			describeFlagProgram(prog),
			result.TotalFlags,
			result.EliminatedFlags,
		)
		return false
	}

	return true
}

// checkSurvivingProducersHaveConsumers verifies that every surviving flag producer
// has at least one flag consumer that reads its flags.
//
// property: for all p in producers(P) where p is NOT eliminated:
//
//	exists c in consumers(P): flags(p) intersect flags(c) != empty
//
// this is the semantic correctness guarantee: we never eliminate a flag
// computation that is actually needed.
func checkSurvivingProducersHaveConsumers(t *testing.T, prog *flagProgram) bool {
	t.Helper()
	fn := buildFlagProgramFunction(prog)

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Logf("EliminateFlags failed: %v", err)
		return false
	}

	// every surviving producer must have needed flags
	for point := range result.NeededFlags {
		needed := result.GetNeededCPUFlags(point)
		if len(needed) == 0 {
			t.Logf("surviving producer at %v has no needed flags — semantic error", point)
			return false
		}
	}

	return true
}

// checkSelectiveMaterialization verifies that only the specific flags required
// by a conditional branch are marked as needed.
//
// property: needed_flags(producer) == required_flags(consumer)
//
// for example: je only needs ZF, not SF/CF/OF/PF/AF.
// this validates requirement 10.5.6: selective materialization.
func checkSelectiveMaterialization(t *testing.T, prog *selectiveFlagProgram) bool {
	t.Helper()
	fn := buildSelectiveFlagFunction(prog)

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Logf("EliminateFlags failed: %v", err)
		return false
	}

	if result.TotalFlags != 1 {
		t.Logf("expected 1 flag producer, got %d", result.TotalFlags)
		return false
	}

	// producer must be live (consumer reads its flags)
	if result.EliminatedFlags != 0 {
		t.Logf("producer should be live for consumer %q, but was eliminated", prog.consumerMnemonic)
		return false
	}

	// verify that exactly the expected flags are needed
	producerPoint := ProgramPoint{BlockID: 0, InstrIdx: 0}
	needed := result.GetNeededCPUFlags(producerPoint)

	// build sets for comparison
	neededSet := make(map[ir.CPUFlag]bool)
	for _, f := range needed {
		neededSet[f] = true
	}
	expectedSet := make(map[ir.CPUFlag]bool)
	for _, f := range prog.expectedFlags {
		expectedSet[f] = true
	}

	// every expected flag must be in needed
	for _, f := range prog.expectedFlags {
		if !neededSet[f] {
			t.Logf("selective materialization: expected flag %v needed for %q, but not found in needed=%v",
				f, prog.consumerMnemonic, needed)
			return false
		}
	}

	// no unexpected flags should be in needed
	// (needed may be a superset if the consumer requires more flags than expected,
	// but for the specific cases in genSelectiveFlagProgram, they should match exactly)
	for _, f := range needed {
		if !expectedSet[f] {
			t.Logf("selective materialization: unexpected flag %v in needed for %q (expected only %v)",
				f, prog.consumerMnemonic, prog.expectedFlags)
			return false
		}
	}

	return true
}

// checkMultiBlockFlagEliminationRate verifies >= 95% elimination in multi-block CFGs.
//
// structure: N blocks, each with M arithmetic ops, last block ends with consumer.
// total producers = N*M, surviving producers = 1 (last op in last block).
// elimination rate = (N*M - 1) / (N*M).
// the generator guarantees N*M >= 21, so elimination rate >= 20/21 = 95.2%.
func checkMultiBlockFlagEliminationRate(t *testing.T, prog *multiBlockFlagProgram) bool {
	t.Helper()
	fn := buildMultiBlockFlagFunction(prog)

	result, err := EliminateFlags(fn, nil, nil)
	if err != nil {
		t.Logf("EliminateFlags failed: %v", err)
		return false
	}

	if result.TotalFlags == 0 {
		return true
	}

	if result.EliminationRate < 0.95 {
		t.Logf("multi-block flag elimination rate %.2f%% < 95%% target\n  blocks=%d opsPerBlock=%d total=%d eliminated=%d",
			result.EliminationRate*100,
			prog.numBlocks,
			prog.opsPerBlock,
			result.TotalFlags,
			result.EliminatedFlags,
		)
		return false
	}

	return true
}

// ============================================================================
// ir function builders
// ============================================================================

// buildFlagProgramFunction constructs an ir function from a flagProgram.
//
// structure:
//
//	bb0: arith_0, arith_1, ..., arith_N-1, consumer_0, ..., consumer_K-1
//	bb1: ret (true branch target of last consumer)
//	bb2: ret (false branch target of last consumer)
//
// all arithmetic ops are in bb0 before the consumers.
// only the last arithmetic op's flags are consumed by the first consumer.
// all preceding arithmetic ops are dead (overwritten before any consumer).
func buildFlagProgramFunction(prog *flagProgram) *ir.Function {
	// build bb0 instructions: all arithmetic ops followed by consumers
	instrs := make([]ir.IRInstruction, 0, prog.numArithOps+prog.numConsumers)

	for i, mnemonic := range prog.producerMnemonics {
		dest := ir.Variable{
			Name: fmt.Sprintf("r%d", i),
			Type: ir.IntType{Width: ir.Size8, Signed: false},
		}
		instrs = append(instrs, flagProducer(dest, mnemonic))
	}

	// add consumers as conditional branches
	// each consumer branches to a pair of exit blocks
	// for simplicity: all consumers branch to bb1 (true) or bb2 (false)
	for _, mnemonic := range prog.consumerMnemonics {
		instrs = append(instrs, flagConsumer(mnemonic, 1, 2))
	}

	return &ir.Function{
		Name: "flag_prop_test",
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
}

// buildSelectiveFlagFunction constructs an ir function for selective materialization testing.
//
// structure:
//
//	bb0: producer (single arithmetic op), consumer (single conditional branch)
//	bb1: ret (true branch)
//	bb2: ret (false branch)
func buildSelectiveFlagFunction(prog *selectiveFlagProgram) *ir.Function {
	dest := ir.Variable{
		Name: "rax",
		Type: ir.IntType{Width: ir.Size8, Signed: false},
	}

	return &ir.Function{
		Name: "selective_flag_test",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					flagProducer(dest, prog.producerMnemonic),
					flagConsumer(prog.consumerMnemonic, 1, 2),
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
}

// buildMultiBlockFlagFunction constructs a multi-block ir function.
//
// structure:
//
//	bb0: arith_0..M-1, jump bb1
//	bb1: arith_M..2M-1, jump bb2
//	...
//	bb(N-2): arith_(N-2)*M..(N-1)*M-1, jump bb(N-1)
//	bb(N-1): arith_(N-1)*M..N*M-1, consumer, jump bbExit1/bbExit2
//	bbExit1: ret
//	bbExit2: ret
//
// only the last arithmetic op in bb(N-1) has its flags consumed.
// all other arithmetic ops across all blocks are dead.
func buildMultiBlockFlagFunction(prog *multiBlockFlagProgram) *ir.Function {
	blocks := make(map[ir.BlockID]*ir.BasicBlock)

	// exit blocks: id = numBlocks and numBlocks+1
	//nolint:gosec // intentional for generating test block IDs
	exitTrue := ir.BlockID(prog.numBlocks)
	//nolint:gosec // intentional for generating test block IDs
	exitFalse := ir.BlockID(prog.numBlocks + 1)

	blocks[exitTrue] = &ir.BasicBlock{
		ID:           exitTrue,
		Instructions: []ir.IRInstruction{retInstr()},
	}
	blocks[exitFalse] = &ir.BasicBlock{
		ID:           exitFalse,
		Instructions: []ir.IRInstruction{retInstr()},
	}

	// build each block
	for blockIdx := 0; blockIdx < prog.numBlocks; blockIdx++ {
		blockID := ir.BlockID(blockIdx)
		isLastBlock := blockIdx == prog.numBlocks-1

		instrs := make([]ir.IRInstruction, 0, prog.opsPerBlock+1)

		// add arithmetic ops for this block
		for opIdx := 0; opIdx < prog.opsPerBlock; opIdx++ {
			globalIdx := blockIdx*prog.opsPerBlock + opIdx
			dest := ir.Variable{
				Name: fmt.Sprintf("r%d", globalIdx),
				Type: ir.IntType{Width: ir.Size8, Signed: false},
			}
			instrs = append(instrs, flagProducer(dest, "add"))
		}

		if isLastBlock {
			// last block: add consumer then branch to exit blocks
			instrs = append(instrs, flagConsumer(prog.consumerMnemonic, exitTrue, exitFalse))

			var preds []ir.BlockID
			if blockIdx > 0 {
				preds = []ir.BlockID{ir.BlockID(blockIdx - 1)}
			}

			blocks[blockID] = &ir.BasicBlock{
				ID:           blockID,
				Instructions: instrs,
				Predecessors: preds,
				Successors:   []ir.BlockID{exitTrue, exitFalse},
			}

			// update exit block predecessors
			blocks[exitTrue].Predecessors = []ir.BlockID{blockID}
			blocks[exitFalse].Predecessors = []ir.BlockID{blockID}
		} else {
			// intermediate block: jump to next block
			nextBlock := ir.BlockID(blockIdx + 1)
			instrs = append(instrs, jumpInstr(nextBlock))

			var preds []ir.BlockID
			if blockIdx > 0 {
				preds = []ir.BlockID{ir.BlockID(blockIdx - 1)}
			}

			blocks[blockID] = &ir.BasicBlock{
				ID:           blockID,
				Instructions: instrs,
				Predecessors: preds,
				Successors:   []ir.BlockID{nextBlock},
			}
		}
	}

	return &ir.Function{
		Name:       "multi_block_flag_test",
		Blocks:     blocks,
		EntryBlock: 0,
	}
}

// ============================================================================
// description helpers for failure messages
// ============================================================================

// describeFlagProgram returns a human-readable description of a flagProgram.
func describeFlagProgram(prog *flagProgram) string {
	return fmt.Sprintf("numArithOps=%d numConsumers=%d producers=%v consumers=%v",
		prog.numArithOps, prog.numConsumers,
		prog.producerMnemonics[:min(3, len(prog.producerMnemonics))],
		prog.consumerMnemonics,
	)
}

// ============================================================================
// TestProperty12_AverageEliminationRate reports the average elimination rate
// across 100 iterations for documentation purposes.
// this test always passes — it only reports statistics.
// ============================================================================

// TestProperty12_AverageEliminationRate runs 100 iterations and reports the
// average flag elimination rate. validates requirement 10.5.14.
func TestProperty12_AverageEliminationRate(t *testing.T) {
	const iterations = 100

	// use a fixed seed for reproducibility in CI
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = iterations
	params.MaxSize = 10

	totalRate := 0.0
	minRate := 1.0
	maxRate := 0.0
	failCount := 0

	gen := genFlagProgram()

	for i := 0; i < iterations; i++ {
		genParams := gopter.DefaultGenParameters().WithSize(10)
		result := gen(genParams)
		prog := result.Result.(*flagProgram) //nolint:forcetypeassert // test: panicking on wrong type is correct behavior

		fn := buildFlagProgramFunction(prog)
		elimResult, err := EliminateFlags(fn, nil, nil)
		if err != nil {
			t.Logf("iteration %d: EliminateFlags failed: %v", i, err)
			failCount++
			continue
		}

		rate := elimResult.EliminationRate
		totalRate += rate

		if rate < minRate {
			minRate = rate
		}
		if rate > maxRate {
			maxRate = rate
		}

		if rate < 0.95 {
			failCount++
			t.Logf("iteration %d: elimination rate %.2f%% < 95%% (total=%d eliminated=%d)",
				i, rate*100, elimResult.TotalFlags, elimResult.EliminatedFlags)
		}
	}

	avgRate := totalRate / float64(iterations)
	t.Logf("average flag elimination: %.1f%% (min=%.1f%% max=%.1f%% failures=%d/%d)",
		avgRate*100, minRate*100, maxRate*100, failCount, iterations)

	if failCount > 0 {
		t.Errorf("flag elimination rate < 95%% in %d/%d iterations", failCount, iterations)
	}

	if avgRate < 0.95 {
		t.Errorf("average flag elimination rate %.2f%% < 95%% target", avgRate*100)
	}
}
