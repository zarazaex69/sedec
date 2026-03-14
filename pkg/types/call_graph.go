package typeinfer

import (
	"fmt"

	"github.com/zarazaex69/sedec/pkg/ir"
)

// FunctionID is the canonical identifier for a function in the call graph.
// it corresponds to the function name in the IR.
type FunctionID string

// CallingConvention identifies the ABI used by a function.
type CallingConvention int

// callingConventionUnknownStr is the string representation of an unknown calling convention.
const callingConventionUnknownStr = "unknown"

const (
	// CallingConventionUnknown means the ABI has not been determined.
	CallingConventionUnknown CallingConvention = iota

	// CallingConventionSystemVAMD64 is the Linux/macOS x86-64 ABI.
	// integer/pointer params: RDI, RSI, RDX, RCX, R8, R9
	// float params: XMM0-XMM7
	// return: RAX (integer), XMM0 (float)
	CallingConventionSystemVAMD64

	// CallingConventionMicrosoftX64 is the Windows x86-64 ABI.
	// integer/pointer params: RCX, RDX, R8, R9
	// float params: XMM0-XMM3
	// return: RAX (integer), XMM0 (float)
	CallingConventionMicrosoftX64
)

// String returns a human-readable name for the calling convention.
func (c CallingConvention) String() string {
	switch c {
	case CallingConventionUnknown:
		return callingConventionUnknownStr
	case CallingConventionSystemVAMD64:
		return "sysv_amd64"
	case CallingConventionMicrosoftX64:
		return "ms_x64"
	default:
		return callingConventionUnknownStr
	}
}

// CallSite represents a single call instruction within a caller function.
type CallSite struct {
	// Address is the virtual address of the call instruction.
	Address ir.Address

	// ArgExprs holds the argument expressions passed at this call site.
	// index i corresponds to parameter i of the callee.
	ArgExprs []ir.Expression

	// ReturnVar is the variable that receives the return value, or nil for void calls.
	ReturnVar *ir.Variable
}

// CallGraphNode represents a single function vertex in the call graph.
type CallGraphNode struct {
	// ID is the canonical function identifier.
	ID FunctionID

	// Params holds the inferred or declared parameter types.
	// nil entries mean the type is not yet known.
	Params []ir.Type

	// ReturnType is the inferred or declared return type.
	// nil means not yet known.
	ReturnType ir.Type

	// Convention is the calling convention used by this function.
	Convention CallingConvention
}

// CallGraphEdge represents a directed call edge from caller to callee.
type CallGraphEdge struct {
	// CallerID is the function that contains the call instruction.
	CallerID FunctionID

	// CalleeID is the function being called.
	CalleeID FunctionID

	// Site holds the call-site details (address, arguments, return variable).
	Site CallSite
}

// CallGraph is a directed graph of functions connected by call edges.
// it supports both forward (callees) and reverse (callers) traversal.
type CallGraph struct {
	// nodes maps FunctionID to its node descriptor.
	nodes map[FunctionID]*CallGraphNode

	// outEdges maps caller → list of outgoing call edges.
	outEdges map[FunctionID][]*CallGraphEdge

	// inEdges maps callee → list of incoming call edges.
	inEdges map[FunctionID][]*CallGraphEdge
}

// NewCallGraph allocates an empty call graph.
func NewCallGraph() *CallGraph {
	return &CallGraph{
		nodes:    make(map[FunctionID]*CallGraphNode),
		outEdges: make(map[FunctionID][]*CallGraphEdge),
		inEdges:  make(map[FunctionID][]*CallGraphEdge),
	}
}

// AddFunction registers a function node in the call graph.
// if the function already exists, its metadata is updated in place.
func (g *CallGraph) AddFunction(id FunctionID, params []ir.Type, ret ir.Type, conv CallingConvention) *CallGraphNode {
	if node, ok := g.nodes[id]; ok {
		// update existing node
		node.Params = params
		node.ReturnType = ret
		node.Convention = conv
		return node
	}
	node := &CallGraphNode{
		ID:         id,
		Params:     params,
		ReturnType: ret,
		Convention: conv,
	}
	g.nodes[id] = node
	return node
}

// AddCallEdge inserts a directed call edge from caller to callee.
// both functions must have been registered via AddFunction first.
// returns ErrUnknownFunction if either endpoint is missing.
func (g *CallGraph) AddCallEdge(caller, callee FunctionID, site CallSite) error {
	if _, ok := g.nodes[caller]; !ok {
		return &UnknownFunctionError{ID: caller}
	}
	if _, ok := g.nodes[callee]; !ok {
		return &UnknownFunctionError{ID: callee}
	}
	edge := &CallGraphEdge{
		CallerID: caller,
		CalleeID: callee,
		Site:     site,
	}
	g.outEdges[caller] = append(g.outEdges[caller], edge)
	g.inEdges[callee] = append(g.inEdges[callee], edge)
	return nil
}

// Callees returns all outgoing call edges from the given function.
func (g *CallGraph) Callees(id FunctionID) []*CallGraphEdge {
	return g.outEdges[id]
}

// Callers returns all incoming call edges to the given function.
func (g *CallGraph) Callers(id FunctionID) []*CallGraphEdge {
	return g.inEdges[id]
}

// Node returns the node descriptor for the given function, or nil if not found.
func (g *CallGraph) Node(id FunctionID) *CallGraphNode {
	return g.nodes[id]
}

// Functions returns all registered function IDs in an unspecified order.
func (g *CallGraph) Functions() []FunctionID {
	ids := make([]FunctionID, 0, len(g.nodes))
	for id := range g.nodes {
		ids = append(ids, id)
	}
	return ids
}

// TopologicalOrder returns the function IDs in a topological order suitable
// for bottom-up interprocedural propagation (leaves first, callers last).
//
// the algorithm is Kahn's BFS-based topological sort over the call graph.
// if the graph contains cycles (recursive calls), the cyclic nodes are
// appended after the acyclic prefix in an unspecified order.
// callers should use SCCs() to handle recursive groups explicitly.
//
// returns ErrCyclicCallGraph if the graph is not a DAG (cycles detected).
// in that case the partial order is still returned for diagnostic purposes.
func (g *CallGraph) TopologicalOrder() ([]FunctionID, error) {
	// compute in-degree for each node (number of distinct callers)
	inDegree := make(map[FunctionID]int, len(g.nodes))
	for id := range g.nodes {
		inDegree[id] = 0
	}
	for id := range g.nodes {
		for _, edge := range g.outEdges[id] {
			inDegree[edge.CalleeID]++
		}
	}

	// seed queue with nodes that have no callers (leaves / entry points)
	queue := make([]FunctionID, 0, len(g.nodes))
	for id, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, id)
		}
	}
	sortFunctionIDs(queue)

	result := make([]FunctionID, 0, len(g.nodes))
	for len(queue) > 0 {
		// pop front
		cur := queue[0]
		queue = queue[1:]
		result = append(result, cur)

		// reduce in-degree of all callees
		callees := make([]FunctionID, 0, len(g.outEdges[cur]))
		for _, edge := range g.outEdges[cur] {
			callees = append(callees, edge.CalleeID)
		}
		sortFunctionIDs(callees)
		for _, callee := range callees {
			inDegree[callee]--
			if inDegree[callee] == 0 {
				queue = append(queue, callee)
			}
		}
	}

	if len(result) != len(g.nodes) {
		// cycle detected: append remaining nodes
		remaining := make([]FunctionID, 0)
		for id := range g.nodes {
			if inDegree[id] > 0 {
				remaining = append(remaining, id)
			}
		}
		sortFunctionIDs(remaining)
		// reverse the acyclic prefix for bottom-up order, then append cyclic nodes
		reverseIDs(result)
		result = append(result, remaining...)
		return result, &CyclicCallGraphError{CycleSize: len(remaining)}
	}

	// reverse for bottom-up order: leaves (callees) first, callers last
	reverseIDs(result)
	return result, nil
}

// SCCs returns the strongly connected components of the call graph using
// Tarjan's algorithm. each SCC is returned as a slice of FunctionIDs.
// SCCs are returned in reverse topological order (a callee's SCC appears
// before its caller's SCC), which is the natural bottom-up order.
//
// single-node SCCs without self-edges represent non-recursive functions.
// SCCs with more than one node (or a self-edge) represent recursive groups.
func (g *CallGraph) SCCs() [][]FunctionID {
	// tarjan's SCC state
	index := 0
	stack := make([]FunctionID, 0, len(g.nodes))
	onStack := make(map[FunctionID]bool, len(g.nodes))
	indices := make(map[FunctionID]int, len(g.nodes))
	lowlinks := make(map[FunctionID]int, len(g.nodes))
	visited := make(map[FunctionID]bool, len(g.nodes))
	result := make([][]FunctionID, 0)

	// iterative tarjan using explicit call stack to avoid goroutine stack overflow
	// on deep call graphs
	var strongconnect func(v FunctionID)
	strongconnect = func(v FunctionID) {
		indices[v] = index
		lowlinks[v] = index
		index++
		stack = append(stack, v)
		onStack[v] = true
		visited[v] = true

		// visit all callees
		callees := make([]FunctionID, 0, len(g.outEdges[v]))
		for _, edge := range g.outEdges[v] {
			callees = append(callees, edge.CalleeID)
		}
		sortFunctionIDs(callees)

		for _, w := range callees {
			if !visited[w] {
				strongconnect(w)
				if lowlinks[w] < lowlinks[v] {
					lowlinks[v] = lowlinks[w]
				}
			} else if onStack[w] {
				if indices[w] < lowlinks[v] {
					lowlinks[v] = indices[w]
				}
			}
		}

		// if v is a root node, pop the SCC
		if lowlinks[v] == indices[v] {
			scc := make([]FunctionID, 0)
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				scc = append(scc, w)
				if w == v {
					break
				}
			}
			result = append(result, scc)
		}
	}

	// visit all nodes in deterministic order
	allIDs := make([]FunctionID, 0, len(g.nodes))
	for id := range g.nodes {
		allIDs = append(allIDs, id)
	}
	sortFunctionIDs(allIDs)

	for _, id := range allIDs {
		if !visited[id] {
			strongconnect(id)
		}
	}

	return result
}

// ============================================================================
// error types
// ============================================================================

// UnknownFunctionError is returned when a call edge references an unregistered function.
type UnknownFunctionError struct {
	ID FunctionID
}

func (e *UnknownFunctionError) Error() string {
	return fmt.Sprintf("call graph: unknown function %q", e.ID)
}

// CyclicCallGraphError is returned by TopologicalOrder when cycles are detected.
type CyclicCallGraphError struct {
	CycleSize int
}

func (e *CyclicCallGraphError) Error() string {
	return fmt.Sprintf("call graph: cycle detected (%d nodes in cycles)", e.CycleSize)
}

// ============================================================================
// utility
// ============================================================================

// reverseIDs reverses a slice of FunctionIDs in place.
func reverseIDs(ids []FunctionID) {
	for i, j := 0, len(ids)-1; i < j; i, j = i+1, j-1 {
		ids[i], ids[j] = ids[j], ids[i]
	}
}

// sortFunctionIDs sorts a slice of FunctionIDs in ascending lexicographic order
// for deterministic traversal across all graph algorithms.
func sortFunctionIDs(ids []FunctionID) {
	// insertion sort: call graphs are typically small (< 10k functions)
	for i := 1; i < len(ids); i++ {
		key := ids[i]
		j := i - 1
		for j >= 0 && ids[j] > key {
			ids[j+1] = ids[j]
			j--
		}
		ids[j+1] = key
	}
}
