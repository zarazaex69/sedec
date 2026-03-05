// Package cfg implements Control Flow Graph (CFG) construction and analysis for sedec decompiler.
//
// # Overview
//
// This package provides comprehensive CFG construction with support for:
//   - Basic block identification and boundary detection
//   - Control flow edge creation (conditional, unconditional, fallthrough, indirect)
//   - Indirect jump tracking and resolution
//   - Incremental CFG updates for cyclic feedback with type inference
//   - Edge provenance tracking for debugging and analysis
//
// # Architecture
//
// The CFG builder follows a multi-phase construction process:
//
//  1. Block Leader Identification: Determines basic block boundaries at branch targets
//     and after control flow instructions
//  2. Basic Block Creation: Groups instructions into basic blocks with single entry/exit
//  3. Edge Construction: Creates directed edges representing control flow between blocks
//  4. Entry/Exit Identification: Marks function entry point and return blocks
//
// # Indirect Jump Handling
//
// Indirect jumps (jmp rax, jmp [rax+8]) cannot be resolved statically and require
// runtime analysis. The package provides:
//
//   - UnresolvedIndirectJump: Tracks indirect jumps awaiting resolution
//   - IndirectJumpKind: Classifies jump types (vtable, handler table, interface table)
//   - AddIndirectTarget: Resolves jump targets discovered by type inference
//   - EdgeProvenance: Records which analysis pass discovered each edge
//
// # Incremental Updates
//
// The CFG supports incremental updates for cyclic feedback with type inference:
//
//   - UpdateTypeResolveIndirect: Add resolved targets to indirect jumps
//   - UpdateTypeSplitBlock: Split blocks when new branch targets discovered
//   - UpdateTypeAddEdge: Add edges between existing blocks
//   - BatchApplyUpdates: Efficiently apply multiple updates
//
// # Example Usage
//
//	// construct initial cfg
//	builder := cfg.NewCFGBuilder()
//	cfg, err := builder.Build(instructions)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// check for unresolved indirect jumps
//	for _, jump := range cfg.UnresolvedIndirectJumps {
//	    fmt.Printf("Indirect jump at 0x%x (kind: %s)\n",
//	        jump.JumpSite, jump.JumpKind)
//	}
//
//	// resolve indirect jump via type inference
//	provenance := &cfg.EdgeProvenance{
//	    AnalysisPass: "type_inference",
//	    Confidence:   0.9,
//	}
//	err = builder.AddIndirectTargetWithProvenance(0x1000, 0x2000, provenance)
//
//	// apply batch updates
//	updates := []*cfg.IncrementalUpdate{
//	    {
//	        UpdateType: cfg.UpdateTypeResolveIndirect,
//	        JumpSite:   0x3000,
//	        Targets:    []disasm.Address{0x4000, 0x5000},
//	        Provenance: provenance,
//	    },
//	}
//	err = builder.BatchApplyUpdates(updates)
//
//	// get statistics
//	stats := builder.GetIncrementalUpdateStats()
//	fmt.Printf("Resolution rate: %.2f%%\n", stats.ResolutionRate()*100)
//
// # Cyclic Feedback Loop
//
// The CFG builder integrates with Type_Inferencer for iterative refinement:
//
//  1. Initial CFG construction marks indirect jumps as unresolved
//  2. Type inference discovers function pointer arrays (vtables, handler tables)
//  3. Discovered targets are fed back to CFG builder via AddIndirectTarget
//  4. CFG is incrementally updated with new edges
//  5. Process repeats until convergence or iteration limit
//
// This cyclic refinement is critical for accurate decompilation of C++, Go,
// and heavily obfuscated code where indirect control flow is prevalent.
//
// # Performance
//
// Target performance metrics:
//   - Functions < 500 basic blocks: CFG construction in < 200ms
//   - Dominator tree computation: O(n log n) complexity via Lengauer-Tarjan
//   - Incremental updates: O(1) for adding edges, O(n) for splitting blocks
//
// # Thread Safety
//
// The CFG builder is NOT thread-safe. Each function should be analyzed by
// a separate builder instance. For parallel analysis, use goroutine worker
// pools with one builder per worker.
package cfg
