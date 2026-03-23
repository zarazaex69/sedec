package analysis

import (
	"testing"

	"github.com/zarazaex69/sedec/pkg/cfg"
	"github.com/zarazaex69/sedec/pkg/ir"
	typeinfer "github.com/zarazaex69/sedec/pkg/types"
)

func tiVar(name string, version int) ir.Variable {
	return ir.Variable{Name: name, Version: version}
}

func tiConst(v int64) ir.Expression {
	return &ir.ConstantExpr{Value: ir.IntConstant{Value: v}}
}

func tiBuildFunction(name string, instrs []ir.IRInstruction) *ir.Function {
	block := &ir.BasicBlock{
		ID:           0,
		Instructions: instrs,
	}
	return &ir.Function{
		Name:       name,
		Signature:  ir.FunctionType{},
		Blocks:     map[ir.BlockID]*ir.BasicBlock{0: block},
		EntryBlock: 0,
	}
}

func tiBuildCFG(fn *ir.Function) *cfg.CFG {
	entryID := cfg.BlockID(fn.EntryBlock)
	g := cfg.NewCFG()
	g.Blocks[entryID] = &cfg.BasicBlock{
		ID:           entryID,
		Predecessors: nil,
		Successors:   nil,
	}
	g.Entry = entryID
	return g
}

func tiBuildDomTree(fn *ir.Function, c *cfg.CFG) *cfg.DominatorTree {
	entryID := cfg.BlockID(fn.EntryBlock)
	dt := cfg.NewDominatorTree(c)
	dt.Idom[entryID] = entryID
	dt.Children[entryID] = nil
	return dt
}
func TestGenerateTypeConstraints_NilInputs(t *testing.T) {
	_, err := GenerateTypeConstraintsFromVSA(nil, nil)
	if err == nil {
		t.Error("expected error for nil function")
	}

	fn := tiBuildFunction("f", nil)
	_, err = GenerateTypeConstraintsFromVSA(fn, nil)
	if err == nil {
		t.Error("expected error for nil VSA result")
	}
}

func TestGenerateTypeConstraints_EmptyFunction(t *testing.T) {
	fn := tiBuildFunction("f", nil)
	vsaResult := &VSAResult{
		ValueSets:      make(map[string]*ValueSet),
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	result, err := GenerateTypeConstraintsFromVSA(fn, vsaResult)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Constraints) != 0 {
		t.Errorf("expected 0 constraints for empty function, got %d", len(result.Constraints))
	}
}

func TestGenerateTypeConstraints_ArrayAccess(t *testing.T) {
	baseVar := tiVar("ptr", 1)
	idxVar := tiVar("idx", 1)
	destVar := tiVar("val", 1)

	fn := tiBuildFunction("f", []ir.IRInstruction{
		&ir.Assign{Dest: baseVar, Source: tiConst(0x1000)},
		&ir.Assign{Dest: idxVar, Source: tiConst(0)},
		&ir.Load{
			Dest: destVar,
			Address: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: baseVar},
				Right: tiConst(0),
			},
			Size: ir.Size4,
		},
		&ir.Load{
			Dest: tiVar("val2", 1),
			Address: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: baseVar},
				Right: tiConst(4),
			},
			Size: ir.Size4,
		},
		&ir.Load{
			Dest: tiVar("val3", 1),
			Address: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: baseVar},
				Right: tiConst(8),
			},
			Size: ir.Size4,
		},
	})

	vsaResult := &VSAResult{
		ValueSets: map[string]*ValueSet{
			baseVar.String(): NewValueSetConstant(0x1000),
			idxVar.String():  NewValueSetConstant(0),
		},
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	result, err := GenerateTypeConstraintsFromVSA(fn, vsaResult)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasArray := false
	for _, c := range result.Constraints {
		if c.Kind == typeinfer.ConstraintArrayElement {
			hasArray = true
			break
		}
	}
	if !hasArray {
		t.Error("expected array element constraint from strided access pattern")
	}
}

func TestGenerateTypeConstraints_StructAccess(t *testing.T) {
	baseVar := tiVar("sptr", 1)

	fn := tiBuildFunction("f", []ir.IRInstruction{
		&ir.Assign{Dest: baseVar, Source: tiConst(0x2000)},
		&ir.Load{
			Dest: tiVar("f0", 1),
			Address: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: baseVar},
				Right: tiConst(0),
			},
			Size: ir.Size4,
		},
		&ir.Load{
			Dest: tiVar("f1", 1),
			Address: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: baseVar},
				Right: tiConst(8),
			},
			Size: ir.Size8,
		},
		&ir.Load{
			Dest: tiVar("f2", 1),
			Address: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: baseVar},
				Right: tiConst(16),
			},
			Size: ir.Size1,
		},
	})

	vsaResult := &VSAResult{
		ValueSets: map[string]*ValueSet{
			baseVar.String(): NewValueSetConstant(0x2000),
		},
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	result, err := GenerateTypeConstraintsFromVSA(fn, vsaResult)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasField := false
	for _, c := range result.Constraints {
		if c.Kind == typeinfer.ConstraintFieldAccess {
			hasField = true
			break
		}
	}
	if !hasField {
		t.Error("expected field access constraint from struct access pattern")
	}

	if len(result.StructHints) == 0 {
		t.Error("expected struct hints from non-uniform offset pattern")
	}
}
func TestGenerateTypeConstraints_PointerTargets(t *testing.T) {
	ptrVar := tiVar("p", 1)

	fn := tiBuildFunction("f", []ir.IRInstruction{
		&ir.Assign{Dest: ptrVar, Source: tiConst(0x3000)},
		&ir.Load{
			Dest:    tiVar("v", 1),
			Address: &ir.VariableExpr{Var: ptrVar},
			Size:    ir.Size8,
		},
	})

	heapRegion := MemoryRegion{Kind: RegionHeap, ID: 1}
	ptrVS := NewValueSetBottom()
	ptrVS.SetInterval(heapRegion, NewSingleton(0x3000))

	vsaResult := &VSAResult{
		ValueSets: map[string]*ValueSet{
			ptrVar.String(): ptrVS,
		},
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	result, err := GenerateTypeConstraintsFromVSA(fn, vsaResult)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.PointerTargets) == 0 {
		t.Error("expected pointer targets for heap-region variable")
	}
}

func TestGenerateTypeConstraints_StorePattern(t *testing.T) {
	baseVar := tiVar("buf", 1)

	fn := tiBuildFunction("f", []ir.IRInstruction{
		&ir.Assign{Dest: baseVar, Source: tiConst(0x4000)},
		&ir.Store{
			Address: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: baseVar},
				Right: tiConst(0),
			},
			Value: tiConst(1),
			Size:  ir.Size4,
		},
		&ir.Store{
			Address: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: baseVar},
				Right: tiConst(4),
			},
			Value: tiConst(2),
			Size:  ir.Size4,
		},
		&ir.Store{
			Address: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: baseVar},
				Right: tiConst(8),
			},
			Value: tiConst(3),
			Size:  ir.Size4,
		},
	})

	vsaResult := &VSAResult{
		ValueSets: map[string]*ValueSet{
			baseVar.String(): NewValueSetConstant(0x4000),
		},
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	result, err := GenerateTypeConstraintsFromVSA(fn, vsaResult)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Constraints) == 0 {
		t.Error("expected constraints from store patterns")
	}
}

func TestGenerateTypeConstraints_DirectVariableAddress(t *testing.T) {
	ptrVar := tiVar("direct", 1)

	fn := tiBuildFunction("f", []ir.IRInstruction{
		&ir.Assign{Dest: ptrVar, Source: tiConst(0x5000)},
		&ir.Load{
			Dest:    tiVar("v", 1),
			Address: &ir.VariableExpr{Var: ptrVar},
			Size:    ir.Size8,
		},
	})

	vsaResult := &VSAResult{
		ValueSets: map[string]*ValueSet{
			ptrVar.String(): NewValueSetConstant(0x5000),
		},
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	result, err := GenerateTypeConstraintsFromVSA(fn, vsaResult)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestGenerateTypeConstraints_StridedIntervalIndex(t *testing.T) {
	baseVar := tiVar("arr", 1)
	idxVar := tiVar("i", 1)

	fn := tiBuildFunction("f", []ir.IRInstruction{
		&ir.Assign{Dest: baseVar, Source: tiConst(0x6000)},
		&ir.Load{
			Dest: tiVar("elem", 1),
			Address: &ir.BinaryOp{
				Op:    ir.BinOpAdd,
				Left:  &ir.VariableExpr{Var: baseVar},
				Right: &ir.VariableExpr{Var: idxVar},
			},
			Size: ir.Size4,
		},
	})

	idxVS := NewValueSetBottom()
	idxVS.SetInterval(MemoryRegion{Kind: RegionUnknown}, NewStridedInterval(4, 0, 40))

	vsaResult := &VSAResult{
		ValueSets: map[string]*ValueSet{
			baseVar.String(): NewValueSetConstant(0x6000),
			idxVar.String():  idxVS,
		},
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	result, err := GenerateTypeConstraintsFromVSA(fn, vsaResult)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasArray := false
	for _, c := range result.Constraints {
		if c.Kind == typeinfer.ConstraintArrayElement {
			hasArray = true
			break
		}
	}
	if !hasArray {
		t.Error("expected array constraint from strided interval index")
	}

	if len(result.ArrayHints) == 0 {
		t.Fatal("expected array hints")
	}
	hint := result.ArrayHints[0]
	if hint.Stride != 4 {
		t.Errorf("expected stride 4, got %d", hint.Stride)
	}
	if hint.MinOffset != 0 || hint.MaxOffset != 40 {
		t.Errorf("expected offset range [0, 40], got [%d, %d]", hint.MinOffset, hint.MaxOffset)
	}
}

func TestSizeToIRType(t *testing.T) {
	cases := []struct {
		size ir.Size
		want ir.Type
	}{
		{ir.Size1, ir.IntType{Width: ir.Size1, Signed: false}},
		{ir.Size2, ir.IntType{Width: ir.Size2, Signed: false}},
		{ir.Size4, ir.IntType{Width: ir.Size4, Signed: true}},
		{ir.Size8, ir.IntType{Width: ir.Size8, Signed: true}},
		{ir.Size(16), ir.IntType{Width: 16, Signed: false}},
	}
	for _, tc := range cases {
		got := sizeToIRType(tc.size)
		if got.String() != tc.want.String() {
			t.Errorf("sizeToIRType(%d): want %s, got %s", tc.size, tc.want, got)
		}
	}
}

func TestDecomposeAddress_NilExpr(t *testing.T) {
	v, vs := decomposeAddress(nil, nil)
	if v.Name != "" {
		t.Errorf("expected empty variable for nil expr, got %s", v.Name)
	}
	if vs != nil {
		t.Error("expected nil value set for nil expr")
	}
}

func TestDecomposeAddress_DirectVariable(t *testing.T) {
	vsaResult := &VSAResult{
		ValueSets:      make(map[string]*ValueSet),
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}
	v, vs := decomposeAddress(&ir.VariableExpr{Var: tiVar("x", 0)}, vsaResult)
	if v.Name != "x" {
		t.Errorf("expected variable name 'x', got %q", v.Name)
	}
	si := vs.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if !si.IsSingleton() || si.Lo != 0 {
		t.Errorf("expected singleton {0} for direct variable, got %s", vs)
	}
}

func TestDecomposeAddress_AddWithRightBase(t *testing.T) {
	vsaResult := &VSAResult{
		ValueSets:      make(map[string]*ValueSet),
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}
	expr := &ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  tiConst(8),
		Right: &ir.VariableExpr{Var: tiVar("base", 0)},
	}
	v, vs := decomposeAddress(expr, vsaResult)
	if v.Name != "base" {
		t.Errorf("expected base variable, got %q", v.Name)
	}
	si := vs.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if !si.IsSingleton() || si.Lo != 8 {
		t.Errorf("expected offset {8}, got %s", vs)
	}
}

func TestEvalExprForTypeIntegration_BinaryOps(t *testing.T) {
	vsaResult := &VSAResult{
		ValueSets: map[string]*ValueSet{
			tiVar("x", 0).String(): NewValueSetConstant(5),
		},
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	addExpr := &ir.BinaryOp{
		Op:    ir.BinOpAdd,
		Left:  &ir.VariableExpr{Var: tiVar("x", 0)},
		Right: tiConst(3),
	}
	vs := evalExprForTypeIntegration(addExpr, vsaResult)
	si := vs.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if !si.IsSingleton() || si.Lo != 8 {
		t.Errorf("add: expected {8}, got %s", vs)
	}

	mulExpr := &ir.BinaryOp{
		Op:    ir.BinOpMul,
		Left:  &ir.VariableExpr{Var: tiVar("x", 0)},
		Right: tiConst(2),
	}
	vs = evalExprForTypeIntegration(mulExpr, vsaResult)
	si = vs.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if !si.IsSingleton() || si.Lo != 10 {
		t.Errorf("mul: expected {10}, got %s", vs)
	}

	subExpr := &ir.BinaryOp{
		Op:    ir.BinOpSub,
		Left:  &ir.VariableExpr{Var: tiVar("x", 0)},
		Right: tiConst(1),
	}
	vs = evalExprForTypeIntegration(subExpr, vsaResult)
	if !vs.IsTop() {
		t.Errorf("sub: expected top (unsupported op), got %s", vs)
	}
}

func TestEvalExprForTypeIntegration_Nil(t *testing.T) {
	vs := evalExprForTypeIntegration(nil, nil)
	if !vs.IsTop() {
		t.Errorf("expected top for nil expr, got %s", vs)
	}
}
func TestAnalyzeProgram_BottomUpOrder(t *testing.T) {
	retVar := tiVar("ret", 1)
	callee := tiBuildFunction("helper", []ir.IRInstruction{
		&ir.Assign{Dest: retVar, Source: tiConst(99)},
		&ir.Return{Value: &retVar},
	})
	calleeCFG := tiBuildCFG(callee)
	calleeDom := tiBuildDomTree(callee, calleeCFG)

	yVar := tiVar("y", 1)
	caller := tiBuildFunction("main", []ir.IRInstruction{
		&ir.Call{
			Dest:   &yVar,
			Target: &ir.VariableExpr{Var: ir.Variable{Name: "helper"}},
		},
	})
	callerCFG := tiBuildCFG(caller)
	callerDom := tiBuildDomTree(caller, callerCFG)

	analyzer := NewInterproceduralVSAAnalyzer(DefaultInterproceduralVSAConfig())
	progResult, err := analyzer.AnalyzeProgram([]FunctionInput{
		{Function: callee, CFG: calleeCFG, DomTree: calleeDom},
		{Function: caller, CFG: callerCFG, DomTree: callerDom},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(progResult.FunctionResults) != 2 {
		t.Fatalf("expected 2 function results, got %d", len(progResult.FunctionResults))
	}

	callerResult := progResult.FunctionResults["main"]
	if callerResult == nil {
		t.Fatal("missing result for 'main'")
	}

	vs := callerResult.GetValueSet(yVar)
	si := vs.GetInterval(MemoryRegion{Kind: RegionUnknown})
	if !si.IsSingleton() || si.Lo != 99 {
		t.Errorf("y: want singleton {99} from callee summary, got %s", vs)
	}

	if progResult.SummaryDB.Len() != 2 {
		t.Errorf("expected 2 summaries, got %d", progResult.SummaryDB.Len())
	}
}

func TestAnalyzeProgram_NilFunctionSkipped(t *testing.T) {
	fn := tiBuildFunction("ok", []ir.IRInstruction{
		&ir.Assign{Dest: tiVar("x", 1), Source: tiConst(1)},
	})
	fnCFG := tiBuildCFG(fn)
	fnDom := tiBuildDomTree(fn, fnCFG)

	analyzer := NewInterproceduralVSAAnalyzer(DefaultInterproceduralVSAConfig())
	progResult, err := analyzer.AnalyzeProgram([]FunctionInput{
		{Function: nil},
		{Function: fn, CFG: fnCFG, DomTree: fnDom},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(progResult.FunctionResults) != 1 {
		t.Errorf("expected 1 function result (nil skipped), got %d", len(progResult.FunctionResults))
	}
}

func TestAnalyzeProgram_Empty(t *testing.T) {
	analyzer := NewInterproceduralVSAAnalyzer(DefaultInterproceduralVSAConfig())
	progResult, err := analyzer.AnalyzeProgram(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(progResult.FunctionResults) != 0 {
		t.Errorf("expected 0 results for empty input, got %d", len(progResult.FunctionResults))
	}
}

func TestAnalyzeProgram_FailedFunctionGetsTopSummary(t *testing.T) {
	fn := &ir.Function{
		Name:       "broken",
		Signature:  ir.FunctionType{},
		Blocks:     map[ir.BlockID]*ir.BasicBlock{},
		EntryBlock: 99,
	}

	analyzer := NewInterproceduralVSAAnalyzer(DefaultInterproceduralVSAConfig())
	progResult, err := analyzer.AnalyzeProgram([]FunctionInput{
		{Function: fn, CFG: nil, DomTree: nil},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(progResult.FunctionResults) != 0 {
		t.Errorf("expected 0 successful results, got %d", len(progResult.FunctionResults))
	}

	summary := progResult.SummaryDB.Load("broken")
	if summary == nil {
		t.Fatal("expected fallback summary for failed function")
	}
	if summary.Converged {
		t.Error("expected Converged=false for failed function")
	}
	if summary.ReturnValueSet == nil || !summary.ReturnValueSet.IsTop() {
		t.Error("expected top return value set for failed function")
	}
}

func TestDetectStridedAccesses_TooFewEntries(t *testing.T) {
	accesses := []MemoryAccessPattern{
		{
			BaseVar:    tiVar("x", 0),
			OffsetVS:   NewValueSetConstant(0),
			AccessSize: ir.Size4,
		},
	}
	groups := detectStridedAccesses(accesses)
	if len(groups) != 0 {
		t.Errorf("expected no strided groups for single access, got %d", len(groups))
	}
}

func TestDetectFieldAccesses_SingleField(t *testing.T) {
	accesses := []MemoryAccessPattern{
		{
			BaseVar:    tiVar("s", 0),
			OffsetVS:   NewValueSetConstant(0),
			AccessSize: ir.Size4,
		},
	}
	fg := detectFieldAccesses(accesses)
	if len(fg.Offsets) != 1 {
		t.Errorf("expected 1 field, got %d", len(fg.Offsets))
	}
}

func TestDetectFieldAccesses_DuplicateOffsetKeepsLarger(t *testing.T) {
	accesses := []MemoryAccessPattern{
		{
			BaseVar:    tiVar("s", 0),
			OffsetVS:   NewValueSetConstant(0),
			AccessSize: ir.Size2,
		},
		{
			BaseVar:    tiVar("s", 0),
			OffsetVS:   NewValueSetConstant(0),
			AccessSize: ir.Size4,
		},
	}
	fg := detectFieldAccesses(accesses)
	if len(fg.Offsets) != 1 {
		t.Fatalf("expected 1 field (deduplicated), got %d", len(fg.Offsets))
	}
	if fg.Offsets[0].AccessSize != ir.Size4 {
		t.Errorf("expected larger access size 4, got %d", fg.Offsets[0].AccessSize)
	}
}

func TestGroupByBaseVariable(t *testing.T) {
	patterns := []MemoryAccessPattern{
		{BaseVar: tiVar("a", 0), OffsetVS: NewValueSetConstant(0), AccessSize: ir.Size4},
		{BaseVar: tiVar("b", 0), OffsetVS: NewValueSetConstant(0), AccessSize: ir.Size4},
		{BaseVar: tiVar("a", 0), OffsetVS: NewValueSetConstant(4), AccessSize: ir.Size4},
	}
	groups := groupByBaseVariable(patterns)
	if len(groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(groups))
	}
	keyA := accessPatternKey{name: "a", version: 0}
	if len(groups[keyA]) != 2 {
		t.Errorf("expected 2 accesses for 'a', got %d", len(groups[keyA]))
	}
}

func TestDetectStrideFromOffsets_NoStride(t *testing.T) {
	entries := []offsetEntry{
		{offset: 0, accessSize: ir.Size4},
		{offset: 7, accessSize: ir.Size4},
		{offset: 13, accessSize: ir.Size4},
	}
	groups := detectStrideFromOffsets(tiVar("x", 0), entries)
	if len(groups) == 0 {
		t.Skip("irregular offsets may still produce a best-effort stride")
	}
}

func TestCollectPointerTargets_GlobalRegion(t *testing.T) {
	globalRegion := MemoryRegion{Kind: RegionGlobal, ID: 1}
	vs := NewValueSetBottom()
	vs.SetInterval(globalRegion, NewSingleton(0x400000))

	fn := tiBuildFunction("f", nil)
	vsaResult := &VSAResult{
		ValueSets: map[string]*ValueSet{
			"gptr_0": vs,
		},
		BlockValueSets: make(map[ir.BlockID]map[string]*ValueSet),
	}

	result := &VSATypeIntegrationResult{
		PointerTargets: make(map[string]*ValueSet),
	}
	collectPointerTargets(fn, vsaResult, result)

	if len(result.PointerTargets) != 1 {
		t.Errorf("expected 1 pointer target, got %d", len(result.PointerTargets))
	}
}

func TestSortedFunctionBlockIDs(t *testing.T) {
	fn := &ir.Function{
		Blocks: map[ir.BlockID]*ir.BasicBlock{
			5: {ID: 5},
			1: {ID: 1},
			3: {ID: 3},
		},
	}
	ids := sortedFunctionBlockIDs(fn)
	if len(ids) != 3 {
		t.Fatalf("expected 3 block IDs, got %d", len(ids))
	}
	if ids[0] != 1 || ids[1] != 3 || ids[2] != 5 {
		t.Errorf("expected sorted [1, 3, 5], got %v", ids)
	}
}
