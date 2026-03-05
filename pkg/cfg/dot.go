package cfg

import (
	"fmt"
	"io"
	"strings"

	"github.com/zarazaex69/sedec/pkg/disasm"
)

// DotExportOptions configures the dot export behavior
type DotExportOptions struct {
	IncludeInstructions bool // include full instruction listing in nodes
	IncludeAddresses    bool // include virtual addresses in labels
	IncludeMetadata     bool // include block metadata (instruction count, etc.)
	ShowEdgeLabels      bool // show edge type labels
	ShowProvenance      bool // show edge provenance information
	MaxInstructionsShow int  // maximum instructions to show per block (0 = all)
}

// DefaultDotExportOptions returns sensible defaults for dot export
func DefaultDotExportOptions() *DotExportOptions {
	return &DotExportOptions{
		IncludeInstructions: true,
		IncludeAddresses:    true,
		IncludeMetadata:     true,
		ShowEdgeLabels:      true,
		ShowProvenance:      false,
		MaxInstructionsShow: 10,
	}
}

// ExportToDOT writes the cfg in graphviz dot format to the provided writer
func (cfg *CFG) ExportToDOT(w io.Writer, opts *DotExportOptions) error {
	if opts == nil {
		opts = DefaultDotExportOptions()
	}

	// write dot header
	if _, err := fmt.Fprintf(w, "digraph CFG {\n"); err != nil {
		return fmt.Errorf("failed to write dot header: %w", err)
	}

	// graph attributes for better visualization
	if _, err := fmt.Fprintf(w, "  // graph attributes\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  rankdir=TB;\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  node [shape=box, style=filled, fillcolor=lightblue];\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  edge [fontsize=10];\n\n"); err != nil {
		return err
	}

	// write nodes (basic blocks)
	if _, err := fmt.Fprintf(w, "  // basic blocks\n"); err != nil {
		return err
	}

	for _, block := range cfg.Blocks {
		if err := cfg.exportBlockToDOT(w, block, opts); err != nil {
			return fmt.Errorf("failed to export block %d: %w", block.ID, err)
		}
	}

	// write edges
	if _, err := fmt.Fprintf(w, "\n  // control flow edges\n"); err != nil {
		return err
	}

	for _, edge := range cfg.Edges {
		if err := cfg.exportEdgeToDOT(w, edge, opts); err != nil {
			return fmt.Errorf("failed to export edge %d->%d: %w", edge.From, edge.To, err)
		}
	}

	// write unresolved indirect jumps as special nodes
	if len(cfg.UnresolvedIndirectJumps) > 0 {
		if _, err := fmt.Fprintf(w, "\n  // unresolved indirect jumps\n"); err != nil {
			return err
		}

		for i, jump := range cfg.UnresolvedIndirectJumps {
			unresolvedID := fmt.Sprintf("unresolved_%d", i)
			label := fmt.Sprintf("Unresolved\\n%s\\n@0x%x",
				jump.JumpKind.String(),
				jump.JumpSite)

			if _, err := fmt.Fprintf(w, "  %s [label=%q, shape=diamond, fillcolor=orange];\n",
				unresolvedID, label); err != nil {
				return err
			}

			// connect from source block
			if _, err := fmt.Fprintf(w, "  block_%d -> %s [style=dashed, color=orange];\n",
				jump.BlockID, unresolvedID); err != nil {
				return err
			}

			// show possible targets if known
			for _, target := range jump.PossibleTargets {
				// find target block
				for _, block := range cfg.Blocks {
					if block.StartAddress == target {
						if _, err := fmt.Fprintf(w, "  %s -> block_%d [style=dotted, color=gray];\n",
							unresolvedID, block.ID); err != nil {
							return err
						}
						break
					}
				}
			}
		}
	}

	// write dot footer
	if _, err := fmt.Fprintf(w, "}\n"); err != nil {
		return fmt.Errorf("failed to write dot footer: %w", err)
	}

	return nil
}

// exportBlockToDOT writes a single basic block node in dot format
func (cfg *CFG) exportBlockToDOT(w io.Writer, block *BasicBlock, opts *DotExportOptions) error {
	label := cfg.buildBlockLabel(block, opts)
	fillColor := cfg.getBlockColor(block)

	// write node definition
	if _, err := fmt.Fprintf(w, "  block_%d [label=%q, fillcolor=%s];\n",
		block.ID, label, fillColor); err != nil {
		return err
	}

	return nil
}

// buildBlockLabel constructs the label string for a basic block
func (cfg *CFG) buildBlockLabel(block *BasicBlock, opts *DotExportOptions) string {
	var label strings.Builder

	// block header with id
	fmt.Fprintf(&label, "Block %d", block.ID)

	// add address range if requested
	if opts.IncludeAddresses {
		fmt.Fprintf(&label, "\\n[0x%x - 0x%x]", block.StartAddress, block.EndAddress)
	}

	// add metadata if requested
	if opts.IncludeMetadata {
		cfg.addBlockMetadata(&label, block)
	}

	// add instructions if requested
	if opts.IncludeInstructions && len(block.Instructions) > 0 {
		cfg.addBlockInstructions(&label, block, opts)
	}

	return label.String()
}

// addBlockMetadata adds metadata information to block label
func (cfg *CFG) addBlockMetadata(label *strings.Builder, block *BasicBlock) {
	instrCount := len(block.Instructions)
	fmt.Fprintf(label, "\\n%d instructions", instrCount)

	// mark entry block
	if block.ID == cfg.Entry {
		label.WriteString("\\n(ENTRY)")
	}

	// mark exit blocks
	for _, exitID := range cfg.Exits {
		if exitID == block.ID {
			label.WriteString("\\n(EXIT)")
			break
		}
	}
}

// addBlockInstructions adds instruction listing to block label
func (cfg *CFG) addBlockInstructions(label *strings.Builder, block *BasicBlock, opts *DotExportOptions) {
	label.WriteString("\\n---\\n")

	maxShow := opts.MaxInstructionsShow
	if maxShow == 0 || maxShow > len(block.Instructions) {
		maxShow = len(block.Instructions)
	}

	for i := 0; i < maxShow; i++ {
		instr := block.Instructions[i]
		instrStr := cfg.formatInstructionForDOT(instr, opts.IncludeAddresses)
		label.WriteString(instrStr)
		label.WriteString("\\l") // left-aligned line break in dot
	}

	// indicate truncation
	if maxShow < len(block.Instructions) {
		fmt.Fprintf(label, "... (%d more)\\l", len(block.Instructions)-maxShow)
	}
}

// getBlockColor determines node color based on block type
func (cfg *CFG) getBlockColor(block *BasicBlock) string {
	if block.ID == cfg.Entry {
		return "lightgreen"
	}

	for _, exitID := range cfg.Exits {
		if exitID == block.ID {
			return "lightcoral"
		}
	}

	return "lightblue"
}

// exportEdgeToDOT writes a single control flow edge in dot format
func (cfg *CFG) exportEdgeToDOT(w io.Writer, edge *Edge, opts *DotExportOptions) error {
	// base edge definition
	edgeStr := fmt.Sprintf("  block_%d -> block_%d", edge.From, edge.To)

	// build edge attributes
	var attrs []string

	// edge label showing type
	if opts.ShowEdgeLabels {
		attrs = append(attrs, fmt.Sprintf("label=%q", edge.Type.String()))
	}

	// edge styling based on type
	switch edge.Type {
	case EdgeTypeFallthrough:
		attrs = append(attrs, "style=solid", "color=black")
	case EdgeTypeUnconditional:
		attrs = append(attrs, "style=bold", "color=blue")
	case EdgeTypeConditional:
		attrs = append(attrs, "style=solid", "color=green")
	case EdgeTypeCall:
		attrs = append(attrs, "style=dashed", "color=purple")
	case EdgeTypeReturn:
		attrs = append(attrs, "style=dashed", "color=red")
	case EdgeTypeIndirect:
		attrs = append(attrs, "style=dotted", "color=orange")
	default:
		attrs = append(attrs, "style=solid", "color=gray")
	}

	// add provenance information if requested and available
	if opts.ShowProvenance && edge.Provenance != nil {
		provenanceLabel := fmt.Sprintf("%s (%.2f)", edge.Provenance.AnalysisPass, edge.Provenance.Confidence)
		attrs = append(attrs, fmt.Sprintf("xlabel=%q", provenanceLabel))
	}

	// write edge with attributes
	if len(attrs) > 0 {
		edgeStr += fmt.Sprintf(" [%s]", strings.Join(attrs, ", "))
	}
	edgeStr += ";\n"

	if _, err := fmt.Fprintf(w, "%s", edgeStr); err != nil {
		return err
	}

	return nil
}

// formatInstructionForDOT formats a single instruction for dot label
func (cfg *CFG) formatInstructionForDOT(instr *disasm.Instruction, includeAddress bool) string {
	var sb strings.Builder

	if includeAddress {
		sb.WriteString(fmt.Sprintf("0x%x: ", instr.Address))
	}

	// escape special characters for dot format
	mnemonic := escapeForDOT(instr.Mnemonic)
	sb.WriteString(mnemonic)

	if len(instr.Operands) > 0 {
		sb.WriteString(" ")
		operandStrs := make([]string, len(instr.Operands))
		for i, op := range instr.Operands {
			operandStrs[i] = escapeForDOT(op.String())
		}
		sb.WriteString(strings.Join(operandStrs, ", "))
	}

	return sb.String()
}

// escapeForDOT escapes special characters for dot label format
func escapeForDOT(s string) string {
	// escape backslashes first to avoid double-escaping
	s = strings.ReplaceAll(s, "\\", "\\\\")
	// escape quotes
	s = strings.ReplaceAll(s, "\"", "\\\"")
	// escape newlines (though we use \l and \n explicitly)
	s = strings.ReplaceAll(s, "\n", "\\n")
	// escape angle brackets (can interfere with html-like labels)
	s = strings.ReplaceAll(s, "<", "\\<")
	s = strings.ReplaceAll(s, ">", "\\>")
	return s
}
