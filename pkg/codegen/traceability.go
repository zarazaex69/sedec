// package codegen - bidirectional traceability between ast, ir, and assembly.
// implements requirement 50: ast-to-ir-to-asm traceability with 1-to-1 mapping.
package codegen

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zarazaex69/sedec/pkg/ir"
	"github.com/zarazaex69/sedec/pkg/structuring"
)

// TraceabilityInfo maintains bidirectional mapping between ast nodes,
// ir instructions, and original assembly addresses.
// this satisfies requirements 50.1, 50.2, 50.3, 50.4, 50.5.
type TraceabilityInfo struct {
	// irToAsm maps ir instruction index (within function) to assembly address range.
	// key: ir instruction string identity (addr:mnemonic), value: source location
	irToAsm map[string]ir.SourceLocation

	// asmToIR maps assembly address to the set of ir instruction identities
	// that were produced from that assembly instruction.
	asmToIR map[ir.Address][]string

	// astNodeToAddrs maps an ast node identity string to the set of assembly
	// addresses that contributed to it. key: node identity, value: sorted addresses.
	astNodeToAddrs map[string][]ir.Address

	// addrToASTNodes maps an assembly address to the set of ast node identities
	// that were generated from it. supports requirement 50.5 (reverse query).
	addrToASTNodes map[ir.Address][]string

	// lineComments maps a generated c source line (trimmed) to the assembly
	// address annotation comment that should be appended to it.
	lineComments map[string]string
}

// NewTraceabilityInfo creates an empty TraceabilityInfo.
func NewTraceabilityInfo() *TraceabilityInfo {
	return &TraceabilityInfo{
		irToAsm:        make(map[string]ir.SourceLocation),
		asmToIR:        make(map[ir.Address][]string),
		astNodeToAddrs: make(map[string][]ir.Address),
		addrToASTNodes: make(map[ir.Address][]string),
		lineComments:   make(map[string]string),
	}
}

// RecordIRInstruction registers the mapping from an ir instruction to its
// originating assembly source location. called by the ir lifter or during
// code generation when iterating over ir basic blocks.
func (t *TraceabilityInfo) RecordIRInstruction(instr ir.IRInstruction) {
	loc := instr.Location()
	if loc.Address == 0 && loc.Instruction == "" {
		return
	}

	key := irInstrKey(instr)
	t.irToAsm[key] = loc

	// record reverse mapping: asm address → ir instruction keys
	existing := t.asmToIR[loc.Address]
	for _, k := range existing {
		if k == key {
			return // already recorded
		}
	}
	t.asmToIR[loc.Address] = append(existing, key)
}

// RecordASTNode registers the mapping from an ast node (identified by its
// string representation) to the set of assembly addresses that produced it.
// this is called during code generation when emitting statements.
func (t *TraceabilityInfo) RecordASTNode(nodeID string, addrs []ir.Address) {
	if nodeID == "" || len(addrs) == 0 {
		return
	}

	// merge with existing addresses for this node
	existing := t.astNodeToAddrs[nodeID]
	merged := mergeAddresses(existing, addrs)
	t.astNodeToAddrs[nodeID] = merged

	// record reverse mapping: asm address → ast node ids
	for _, addr := range addrs {
		nodes := t.addrToASTNodes[addr]
		found := false
		for _, n := range nodes {
			if n == nodeID {
				found = true
				break
			}
		}
		if !found {
			t.addrToASTNodes[addr] = append(nodes, nodeID)
		}
	}
}

// AddressesForASTNode returns all assembly addresses that contributed to the
// given ast node. satisfies requirement 50.4 (query: which asm produced this c var).
func (t *TraceabilityInfo) AddressesForASTNode(nodeID string) []ir.Address {
	addrs := t.astNodeToAddrs[nodeID]
	result := make([]ir.Address, len(addrs))
	copy(result, addrs)
	return result
}

// ASTNodesForAddress returns all ast node identities that were generated from
// the given assembly address. satisfies requirement 50.5 (query: which c code
// corresponds to this asm address).
func (t *TraceabilityInfo) ASTNodesForAddress(addr ir.Address) []string {
	nodes := t.addrToASTNodes[addr]
	result := make([]string, len(nodes))
	copy(result, nodes)
	return result
}

// SourceLocationForIR returns the assembly source location for an ir instruction.
func (t *TraceabilityInfo) SourceLocationForIR(instr ir.IRInstruction) (ir.SourceLocation, bool) {
	loc, ok := t.irToAsm[irInstrKey(instr)]
	return loc, ok
}

// AddressRangeForASTNode returns the contiguous address range [min, max] for
// all assembly addresses that contributed to the given ast node.
// satisfies requirement 50.11 (complete address ranges for multi-asm statements).
func (t *TraceabilityInfo) AddressRangeForASTNode(nodeID string) (min, max ir.Address, ok bool) {
	addrs := t.astNodeToAddrs[nodeID]
	if len(addrs) == 0 {
		return 0, 0, false
	}
	min = addrs[0]
	max = addrs[0]
	for _, a := range addrs[1:] {
		if a < min {
			min = a
		}
		if a > max {
			max = a
		}
	}
	return min, max, true
}

// AnnotateWithComments rewrites a generated c function body string by appending
// assembly address comments to lines that have traceability information.
// satisfies requirement 50.3 (embed assembly address annotations in comments).
//
// example output:
//
//	v0 = 42; /* 0x401000: mov eax, 0x2a */
func (t *TraceabilityInfo) AnnotateWithComments(body string) string {
	if len(t.lineComments) == 0 {
		return body
	}

	lines := strings.Split(body, "\n")
	result := make([]string, 0, len(lines))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if comment, ok := t.lineComments[trimmed]; ok && trimmed != "" {
			line = line + " " + comment
		}
		result = append(result, line)
	}

	return strings.Join(result, "\n")
}

// RegisterLineComment associates a generated c source line with an assembly
// address annotation comment. the line is stored trimmed for lookup.
func (t *TraceabilityInfo) RegisterLineComment(cLine string, addr ir.Address, asmText string) {
	trimmed := strings.TrimSpace(cLine)
	if trimmed == "" {
		return
	}
	t.lineComments[trimmed] = fmt.Sprintf("/* 0x%x: %s */", addr, asmText)
}

// ============================================================================
// TraceableGenerator wraps Generator with traceability tracking.
// it satisfies requirements 50.1, 50.2, 50.3, 50.6, 50.7, 50.8.
// ============================================================================

// TraceableGenerator extends Generator with full traceability support.
type TraceableGenerator struct {
	*Generator
}

// NewTraceableGenerator creates a generator that records traceability metadata.
func NewTraceableGenerator() *TraceableGenerator {
	return &TraceableGenerator{Generator: New()}
}

// GenerateWithTraceability produces a FunctionDecl and a populated TraceabilityInfo
// by walking the ir function and structured ast simultaneously.
// all ir instructions are registered in the traceability map, and each generated
// c line is annotated with the originating assembly address.
func (tg *TraceableGenerator) GenerateWithTraceability(
	fn *ir.Function,
	ast *structuring.StructuredAST,
) (FunctionDecl, *TraceabilityInfo) {
	trace := NewTraceabilityInfo()

	// phase 1: walk all ir instructions and record ir → asm mappings
	for _, block := range fn.Blocks {
		for _, instr := range block.Instructions {
			trace.RecordIRInstruction(instr)
		}
	}

	// phase 2: generate code with scope minimization
	decl := tg.GenerateFunctionWithScopeMinimization(fn, ast)

	// phase 3: walk the ast and collect address annotations per statement
	state := newGeneratorState(fn, ast)
	collectASTTraceability(ast.Body, state, trace)

	// phase 4: annotate generated body lines with assembly comments
	decl.Body = trace.AnnotateWithComments(decl.Body)

	return decl, trace
}

// collectASTTraceability walks the structured ast and registers ast node → asm
// address mappings by inspecting the source locations of ir instructions within
// each IRBlock node.
func collectASTTraceability(
	stmt structuring.Statement,
	state *generatorState,
	trace *TraceabilityInfo,
) {
	if stmt == nil {
		return
	}

	switch n := stmt.(type) {
	case structuring.IRBlock:
		// collect all addresses from instructions in this block
		addrs := make([]ir.Address, 0, len(n.Instructions))
		for _, instr := range n.Instructions {
			loc := instr.Location()
			if loc.Address != 0 || loc.Instruction != "" {
				addrs = append(addrs, loc.Address)
			}
		}

		if len(addrs) > 0 {
			nodeID := fmt.Sprintf("bb%d", n.BlockID)
			trace.RecordASTNode(nodeID, addrs)

			// register per-instruction line comments
			for _, instr := range n.Instructions {
				loc := instr.Location()
				if loc.Address == 0 && loc.Instruction == "" {
					continue
				}
				cLine := state.genIRInstruction(instr)
				if cLine != "" {
					trace.RegisterLineComment(cLine, loc.Address, loc.Instruction)
				}
			}
		}

	case structuring.Block:
		for _, s := range n.Stmts {
			collectASTTraceability(s, state, trace)
		}

	case structuring.IfStatement:
		collectASTTraceability(n.Then, state, trace)
		if n.Else != nil {
			collectASTTraceability(n.Else, state, trace)
		}

	case structuring.WhileStatement:
		collectASTTraceability(n.Body, state, trace)

	case structuring.DoWhileStatement:
		collectASTTraceability(n.Body, state, trace)

	case structuring.ForStatement:
		if n.Init != nil {
			collectASTTraceability(n.Init, state, trace)
		}
		collectASTTraceability(n.Body, state, trace)
		if n.Post != nil {
			collectASTTraceability(n.Post, state, trace)
		}
	}
}

// ============================================================================
// helpers
// ============================================================================

// irInstrKey returns a stable string key for an ir instruction based on its
// source location and string representation. used as map key in traceability maps.
func irInstrKey(instr ir.IRInstruction) string {
	loc := instr.Location()
	return fmt.Sprintf("0x%x|%s", loc.Address, instr.String())
}

// mergeAddresses merges two address slices, deduplicating and sorting the result.
func mergeAddresses(existing, newAddrs []ir.Address) []ir.Address {
	seen := make(map[ir.Address]struct{}, len(existing)+len(newAddrs))
	for _, a := range existing {
		seen[a] = struct{}{}
	}
	for _, a := range newAddrs {
		seen[a] = struct{}{}
	}

	result := make([]ir.Address, 0, len(seen))
	for a := range seen {
		result = append(result, a)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i] < result[j]
	})

	return result
}
