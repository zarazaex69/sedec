package analysis

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/ir"
)

func TestPropagateReturnValues_SimpleChain(t *testing.T) {
	result := ir.Variable{Name: "result", Version: 1, Type: ir.IntType{Width: ir.Size8}}
	rax := ir.Variable{Name: "rax", Version: 1, Type: ir.IntType{Width: ir.Size8}}

	fn := &ir.Function{
		Name: "simple_chain",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: rax, Source: ir.VariableExpr{Var: result}},
					&ir.Return{Value: &rax},
				},
			},
		},
		EntryBlock: 0,
	}

	PropagateReturnValues(fn)

	ret, ok := ir.AsReturn(fn.Blocks[0].Instructions[1])
	if !ok {
		t.Fatal("expected Return instruction")
	}
	if ret.Value == nil {
		t.Fatal("expected non-nil return value")
	}
	if ret.Value.Name != "result" {
		t.Errorf("expected return value 'result', got '%s'", ret.Value.Name)
	}
}

func TestPropagateReturnValues_EaxAlias(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size4}}
	eax := ir.Variable{Name: "eax", Version: 1, Type: ir.IntType{Width: ir.Size4}}

	fn := &ir.Function{
		Name: "eax_alias",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: eax, Source: ir.VariableExpr{Var: x}},
					&ir.Return{Value: &eax},
				},
			},
		},
		EntryBlock: 0,
	}

	PropagateReturnValues(fn)

	ret, ok := ir.AsReturn(fn.Blocks[0].Instructions[1])
	if !ok {
		t.Fatal("expected Return instruction")
	}
	if ret.Value.Name != "x" {
		t.Errorf("expected return value 'x', got '%s'", ret.Value.Name)
	}
}

func TestPropagateReturnValues_NoReturn(t *testing.T) {
	fn := &ir.Function{
		Name: "no_return",
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

	PropagateReturnValues(fn)
}

func TestPropagateReturnValues_VoidReturn(t *testing.T) {
	fn := &ir.Function{
		Name: "void_return",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Return{Value: nil},
				},
			},
		},
		EntryBlock: 0,
	}

	PropagateReturnValues(fn)
}

func TestPropagateReturnValues_ConstantSourceNotPatched(t *testing.T) {
	rax := ir.Variable{Name: "rax", Version: 1, Type: ir.IntType{Width: ir.Size8}}

	fn := &ir.Function{
		Name: "const_source",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: rax, Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 42}}},
					&ir.Return{Value: &rax},
				},
			},
		},
		EntryBlock: 0,
	}

	PropagateReturnValues(fn)

	ret, ok := ir.AsReturn(fn.Blocks[0].Instructions[1])
	if !ok {
		t.Fatal("expected Return instruction")
	}
	if ret.Value.Name != "rax" {
		t.Errorf("expected 'rax' (constant source not patched), got '%s'", ret.Value.Name)
	}
}

func TestPropagateReturnValues_LoadBeforeReturn(t *testing.T) {
	rax := ir.Variable{Name: "rax", Version: 1, Type: ir.IntType{Width: ir.Size8}}

	fn := &ir.Function{
		Name: "load_return",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Load{
						Dest:    rax,
						Address: ir.ConstantExpr{Value: ir.IntConstant{Value: 0x1000}},
						Size:    ir.Size8,
					},
					&ir.Return{Value: &rax},
				},
			},
		},
		EntryBlock: 0,
	}

	PropagateReturnValues(fn)

	ret, ok := ir.AsReturn(fn.Blocks[0].Instructions[1])
	if !ok {
		t.Fatal("expected Return instruction")
	}
	if ret.Value.Name != "rax" {
		t.Errorf("expected 'rax' (Load resolves to VariableExpr of dest), got '%s'", ret.Value.Name)
	}
}

func TestPropagateReturnValues_MultipleBlocks(t *testing.T) {
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size8}}
	rax := ir.Variable{Name: "rax", Version: 1, Type: ir.IntType{Width: ir.Size8}}
	y := ir.Variable{Name: "y", Version: 1, Type: ir.IntType{Width: ir.Size8}}
	rax2 := ir.Variable{Name: "rax", Version: 2, Type: ir.IntType{Width: ir.Size8}}

	fn := &ir.Function{
		Name: "multi_block",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: rax, Source: ir.VariableExpr{Var: x}},
					&ir.Return{Value: &rax},
				},
			},
			1: {
				ID: 1,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: rax2, Source: ir.VariableExpr{Var: y}},
					&ir.Return{Value: &rax2},
				},
			},
		},
		EntryBlock: 0,
	}

	PropagateReturnValues(fn)

	ret0, _ := ir.AsReturn(fn.Blocks[0].Instructions[1])
	if ret0.Value.Name != "x" {
		t.Errorf("block 0: expected 'x', got '%s'", ret0.Value.Name)
	}

	ret1, _ := ir.AsReturn(fn.Blocks[1].Instructions[1])
	if ret1.Value.Name != "y" {
		t.Errorf("block 1: expected 'y', got '%s'", ret1.Value.Name)
	}
}

func TestCanonicalReturnReg(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"rax", "rax"},
		{"eax", "rax"},
		{"ax", "rax"},
		{"al", "rax"},
		{"ah", "rax"},
		{"rdx", "rdx"},
		{"edx", "rdx"},
		{"dx", "rdx"},
		{"dl", "rdx"},
		{"dh", "rdx"},
		{"xmm0", "xmm0"},
		{"xmm1", "xmm1"},
		{"rbx", "rbx"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := canonicalReturnReg(tt.input)
			if got != tt.want {
				t.Errorf("canonicalReturnReg(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestPropagateReturnValues_FrameArtifactSkipped(t *testing.T) {
	rax := ir.Variable{Name: "rax", Version: 1, Type: ir.IntType{Width: ir.Size8}}
	x := ir.Variable{Name: "x", Version: 1, Type: ir.IntType{Width: ir.Size8}}

	artifactAssign := &ir.Assign{Dest: rax, Source: ir.ConstantExpr{Value: ir.IntConstant{Value: 999}}}
	artifactAssign.Loc.IsFrameArtifact = true

	fn := &ir.Function{
		Name: "frame_artifact",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: rax, Source: ir.VariableExpr{Var: x}},
					artifactAssign,
					&ir.Return{Value: &rax},
				},
			},
		},
		EntryBlock: 0,
	}

	PropagateReturnValues(fn)

	ret, _ := ir.AsReturn(fn.Blocks[0].Instructions[2])
	if ret.Value.Name != "x" {
		t.Errorf("expected 'x' (skipping frame artifact), got '%s'", ret.Value.Name)
	}
}

func TestPropagateReturnValues_DeepChain(t *testing.T) {
	a := ir.Variable{Name: "a", Version: 1, Type: ir.IntType{Width: ir.Size8}}
	b := ir.Variable{Name: "b", Version: 1, Type: ir.IntType{Width: ir.Size8}}
	rax := ir.Variable{Name: "rax", Version: 1, Type: ir.IntType{Width: ir.Size8}}

	fn := &ir.Function{
		Name: "deep_chain",
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			0: {
				ID: 0,
				Instructions: []ir.IRInstruction{
					&ir.Assign{Dest: b, Source: ir.VariableExpr{Var: a}},
					&ir.Assign{Dest: rax, Source: ir.VariableExpr{Var: b}},
					&ir.Return{Value: &rax},
				},
			},
		},
		EntryBlock: 0,
	}

	PropagateReturnValues(fn)

	ret, _ := ir.AsReturn(fn.Blocks[0].Instructions[2])
	if ret.Value.Name != "a" {
		t.Errorf("expected 'a' (deep chain resolution), got '%s'", ret.Value.Name)
	}
}
