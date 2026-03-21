package analysis

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

func rbpPlusOffset(offset int64) ir.Expression {
	return ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  ir.VariableExpr{Var: ir.Variable{Name: "rbp", Type: ir.IntType{Width: ir.Size8}}},
		Right: ir.ConstantExpr{Value: ir.IntConstant{Value: offset, Width: ir.Size8}},
	}
}

func TestRecoverStackVariables_BasicRewrite(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size4}}

	fn := &ir.Function{
		Name: "basic_stack",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Store{
						Address: rbpPlusOffset(-8),
						Value:   ir.ConstantExpr{Value: ir.IntConstant{Value: 42}},
						Size:    ir.Size4,
					},
					&ir.Load{
						Dest:    x,
						Address: rbpPlusOffset(-8),
						Size:    ir.Size4,
					},
				},
			},
		},
		EntryBlock: 0,
	}

	RecoverStackVariables(fn)

	for _, instr := range fn.Blocks[0].Instructions {
		if _, ok := instr.(*ir.Load); ok {
			t.Error("Load should have been rewritten to Assign")
		}
		if _, ok := instr.(*ir.Store); ok {
			t.Error("Store should have been rewritten to Assign")
		}
	}
}

func TestRecoverStackVariables_PositiveOffsetIgnored(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size4}}

	fn := &ir.Function{
		Name: "positive_offset",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Load{
						Dest:    x,
						Address: rbpPlusOffset(16),
						Size:    ir.Size4,
					},
				},
			},
		},
		EntryBlock: 0,
	}

	RecoverStackVariables(fn)

	if _, ok := fn.Blocks[0].Instructions[0].(*ir.Load); !ok {
		t.Error("positive offset Load should NOT be rewritten")
	}
}

func TestRecoverStackVariables_EmptyFunction(t *testing.T) {
	fn := &ir.Function{
		Name:       "empty",
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: {ID: 0}},
		EntryBlock: 0,
	}
	RecoverStackVariables(fn)
}

func TestRecoverStackVariables_NoFrameAccesses(t *testing.T) {
	fn := &ir.Function{
		Name: "no_frame",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{
						Dest:   ir.Variable{Name: "x"},
						Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 1}},
					},
				},
			},
		},
		EntryBlock: 0,
	}
	RecoverStackVariables(fn)
}

func TestRecoverStackVariables_FrameArtifactSkipped(t *testing.T) {
	load := &ir.Load{
		Dest:    ir.Variable{Name: "x"},
		Address: rbpPlusOffset(-4),
		Size:    ir.Size4,
	}
	load.Loc.IsFrameArtifact = true

	fn := &ir.Function{
		Name: "artifact",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID:           0,
				Instructions: []ir.IRInstruction{load},
			},
		},
		EntryBlock: 0,
	}

	RecoverStackVariables(fn)
}

func TestRecoverStackVariables_EbpAlias(t *testing.T) {
	addr := ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  ir.VariableExpr{Var: ir.Variable{Name: "EBP", Type: ir.IntType{Width: ir.Size4}}},
		Right: ir.ConstantExpr{Value: ir.IntConstant{Value: -4, Width: ir.Size4}},
	}

	fn := &ir.Function{
		Name: "ebp_alias",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Store{
						Address: addr,
						Value:   ir.ConstantExpr{Value: ir.IntConstant{Value: 1}},
						Size:    ir.Size4,
					},
				},
			},
		},
		EntryBlock: 0,
	}

	RecoverStackVariables(fn)

	if _, ok := fn.Blocks[0].Instructions[0].(*ir.Assign); !ok {
		t.Error("EBP-relative store should be rewritten to Assign")
	}
}

func TestExtractFrameOffset(t *testing.T) {
	tests := []struct {
		name   string
		expr   ir.Expression
		offset int64
		ok     bool
	}{
		{
			"rbp_minus_8",
			rbpPlusOffset(-8),
			-8,
			true,
		},
		{
			"not_add",
			ir.BinaryOp{Op: ir.BinOpSub, Left: ir.VariableExpr{Var: ir.Variable{Name: "rbp"}}, Right: ir.ConstantExpr{Value: ir.IntConstant{Value: 8}}},
			0,
			false,
		},
		{
			"not_frame_pointer",
			ir.BinaryOp{Op: ir.BinOpAdd, Left: ir.VariableExpr{Var: ir.Variable{Name: "rsp"}}, Right: ir.ConstantExpr{Value: ir.IntConstant{Value: -8}}},
			0,
			false,
		},
		{
			"not_constant_right",
			ir.BinaryOp{Op: ir.BinOpAdd, Left: ir.VariableExpr{Var: ir.Variable{Name: "rbp"}}, Right: ir.VariableExpr{Var: ir.Variable{Name: "x"}}},
			0,
			false,
		},
		{
			"not_variable_left",
			ir.BinaryOp{Op: ir.BinOpAdd, Left: ir.ConstantExpr{Value: ir.IntConstant{Value: 100}}, Right: ir.ConstantExpr{Value: ir.IntConstant{Value: -8}}},
			0,
			false,
		},
		{
			"not_binary_op",
			ir.VariableExpr{Var: ir.Variable{Name: "rbp"}},
			0,
			false,
		},
		{
			"float_constant_right",
			ir.BinaryOp{Op: ir.BinOpAdd, Left: ir.VariableExpr{Var: ir.Variable{Name: "rbp"}}, Right: ir.ConstantExpr{Value: ir.FloatConstant{Value: 1.0}}},
			0,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offset, ok := extractFrameOffset(tt.expr)
			if ok != tt.ok {
				t.Errorf("ok=%v, want %v", ok, tt.ok)
			}
			if ok && offset != tt.offset {
				t.Errorf("offset=%d, want %d", offset, tt.offset)
			}
		})
	}
}

func TestIsFramePointerVar(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"rbp", true},
		{"RBP", true},
		{"ebp", true},
		{"EBP", true},
		{"rsp", false},
		{"rax", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isFramePointerVar(tt.name); got != tt.want {
				t.Errorf("isFramePointerVar(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestAssignSlotNames_CollisionHandling(t *testing.T) {
	slots := map[int64]*frameSlot{
		-4: {offset: -4, size: ir.Size4, varType: ir.IntType{Width: ir.Size4}},
	}

	fn := &ir.Function{
		Name: "collision",
		Variables: []ir.Variable{
			{Name: "local_4"},
		},
	}

	assignSlotNames(slots, fn)

	if slots[-4].name != "local_4_" {
		t.Errorf("expected 'local_4_' (collision avoidance), got '%s'", slots[-4].name)
	}
}

func TestRecordSlot_DefaultSize(t *testing.T) {
	slots := make(map[int64]*frameSlot)
	recordSlot(slots, -8, 0)

	if slots[-8].size != ir.Size4 {
		t.Errorf("expected default size Size4, got %v", slots[-8].size)
	}
}

func TestRecordSlot_NoDuplicate(t *testing.T) {
	slots := make(map[int64]*frameSlot)
	recordSlot(slots, -8, ir.Size4)
	recordSlot(slots, -8, ir.Size8)

	if slots[-8].size != ir.Size4 {
		t.Errorf("expected first recorded size Size4, got %v", slots[-8].size)
	}
}

func TestRecoverStackVariables_ValueTypeLoadStore(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size4}}

	fn := &ir.Function{
		Name: "value_type",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					ir.Store{
						Address: rbpPlusOffset(-4),
						Value:   ir.ConstantExpr{Value: ir.IntConstant{Value: 10}},
						Size:    ir.Size4,
					},
					ir.Load{
						Dest:    x,
						Address: rbpPlusOffset(-4),
						Size:    ir.Size4,
					},
				},
			},
		},
		EntryBlock: 0,
	}

	RecoverStackVariables(fn)

	for _, instr := range fn.Blocks[0].Instructions {
		switch instr.(type) {
		case *ir.Load, ir.Load:
			t.Error("Load should have been rewritten")
		case *ir.Store, ir.Store:
			t.Error("Store should have been rewritten")
		}
	}
}
