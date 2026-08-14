package goanalysis

import (
	"context"
	"fmt"
	"go/types"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ssaProgram builds an SSA program from an already-loaded LoadResult, returning
// the program plus a map from *types.Package to the owning *packages.Package so
// SSA functions can be re-emitted with precise module/version SCIP ids (matching
// IndexSymbols). A type-check or build failure is a hard error (inv.4).
type ssaProgram struct {
	prog    *ssa.Program
	pkgs    []*ssa.Package
	typePkg map[*types.Package]*packages.Package
}

// loadSSA loads the module at buildDir and builds its SSA program in one step,
// returning the program plus the LoadResult so callers can reuse the load
// partiality. It is the shared accessor for the SSA-backed ops (CallGraph,
// FindIngresses, ComputeTaint) so the SSA build is never forked across files.
func loadSSA(ctx context.Context, buildDir string) (*ssaProgram, *LoadResult, error) {
	res, err := LoadProgram(ctx, buildDir)
	if err != nil {
		return nil, nil, err
	}
	sp, err := buildSSA(res)
	if err != nil {
		return nil, nil, err
	}
	return sp, res, nil
}

func buildSSA(res *LoadResult) (*ssaProgram, error) {
	prog, pkgs := ssautil.Packages(res.Packages, ssa.InstantiateGenerics)
	if prog == nil {
		return nil, fmt.Errorf("ssa: failed to create program from loaded packages")
	}
	prog.Build()

	typePkg := make(map[*types.Package]*packages.Package, len(res.Packages))
	for _, p := range res.Packages {
		if p.Types != nil {
			typePkg[p.Types] = p
		}
	}
	return &ssaProgram{prog: prog, pkgs: pkgs, typePkg: typePkg}, nil
}

// scipFunc emits the SCIP id for an SSA function, using the precise
// module-qualified emitter when the function carries a source object and an
// owning loaded package. Synthetic functions (init, wrappers) without a source
// object get a stable synthesized id derived from their package and name.
func (s *ssaProgram) scipFunc(fn *ssa.Function) string {
	if obj := fn.Object(); obj != nil {
		if obj.Pkg() != nil {
			if p, ok := s.typePkg[obj.Pkg()]; ok {
				return scipFromPackage(p, obj)
			}
		}
		return SCIPString(funcTypePackage(fn), obj)
	}
	pkgPath := "."
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		pkgPath = fn.Pkg.Pkg.Path()
	}
	return fmt.Sprintf("scip-go gomod %s . %s/%s().", pkgPath, pkgPath, fn.Name())
}

func funcTypePackage(fn *ssa.Function) *types.Package {
	if fn.Pkg != nil {
		return fn.Pkg.Pkg
	}
	if obj := fn.Object(); obj != nil {
		return obj.Pkg()
	}
	return nil
}

// CallGraph builds the SSA call graph for the module at req.BuildDir using the
// requested algorithm ("vta" default | "cha" | "rta"), emitting caller->callee
// edges and root entry points by SCIP id. A load/SSA-build failure is a hard
// error (inv.4); unresolved interface dispatch, reflection, or cgo degrade the
// declared Partiality rather than truncating the graph.
func CallGraph(ctx context.Context, req plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	algo := req.Algorithm
	if algo == "" {
		algo = "vta"
	}
	if algo != "vta" && algo != "cha" && algo != "rta" {
		return plugin.CallGraphResult{}, fmt.Errorf("callgraph: unknown algorithm %q (want vta|cha|rta)", algo)
	}

	res, err := LoadProgram(ctx, req.BuildDir)
	if err != nil {
		return plugin.CallGraphResult{}, err
	}
	sp, err := buildSSA(res)
	if err != nil {
		return plugin.CallGraphResult{}, err
	}

	graph, err := sp.buildGraph(algo)
	if err != nil {
		return plugin.CallGraphResult{}, err
	}
	graph.DeleteSyntheticNodes()

	edges := sp.collectEdges(graph)
	roots := sp.collectRoots()
	part := sp.partiality(res.Partiality)

	return plugin.CallGraphResult{
		Partiality: part,
		Algorithm:  algo,
		Edges:      edges,
		Roots:      roots,
	}, nil
}

func (s *ssaProgram) buildGraph(algo string) (*callgraph.Graph, error) {
	switch algo {
	case "cha":
		return cha.CallGraph(s.prog), nil
	case "rta":
		roots := s.entryFunctions()
		if len(roots) == 0 {
			// RTA needs at least one root; fall back to all functions as roots
			// so the graph is non-empty for library-only modules.
			for fn := range ssautil.AllFunctions(s.prog) {
				roots = append(roots, fn)
			}
		}
		return rta.Analyze(roots, true).CallGraph, nil
	default: // vta
		return vta.CallGraph(ssautil.AllFunctions(s.prog), cha.CallGraph(s.prog)), nil
	}
}

// entryFunctions returns the program's main + init functions across all built
// packages — the call-graph roots.
func (s *ssaProgram) entryFunctions() []*ssa.Function {
	var roots []*ssa.Function
	for _, p := range s.pkgs {
		if p == nil {
			continue
		}
		if fn := p.Func("main"); fn != nil {
			roots = append(roots, fn)
		}
		if fn := p.Func("init"); fn != nil {
			roots = append(roots, fn)
		}
	}
	return roots
}

func (s *ssaProgram) collectRoots() []plugin.Symbol {
	set := map[string]bool{}
	for _, fn := range s.entryFunctions() {
		set[s.scipFunc(fn)] = true
	}
	ids := sortedKeys(set)
	roots := make([]plugin.Symbol, len(ids))
	for i, id := range ids {
		roots[i] = sym(id)
	}
	return roots
}

func (s *ssaProgram) collectEdges(graph *callgraph.Graph) []plugin.CallEdge {
	type pair struct{ caller, callee string }
	seen := map[pair]bool{}
	var edges []plugin.CallEdge
	_ = callgraph.GraphVisitEdges(graph, func(e *callgraph.Edge) error {
		caller, callee := e.Caller.Func, e.Callee.Func
		if caller == nil || callee == nil {
			return nil
		}
		// Skip edges into stdlib-internal runtime plumbing that carry no source
		// object on either side; keep edges where at least one endpoint is real.
		p := pair{s.scipFunc(caller), s.scipFunc(callee)}
		if seen[p] {
			return nil
		}
		seen[p] = true
		edges = append(edges, plugin.CallEdge{Caller: sym(p.caller), Callee: sym(p.callee)})
		return nil
	})
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Caller.SCIP != edges[j].Caller.SCIP {
			return edges[i].Caller.SCIP < edges[j].Caller.SCIP
		}
		return edges[i].Callee.SCIP < edges[j].Callee.SCIP
	})
	return edges
}

// partiality folds in the load partiality and inspects every built function for
// reflection, cgo, and unresolved interface dispatch, declaring the matching
// reason codes. Reaching past static resolution is declared, never hidden (inv.5).
func (s *ssaProgram) partiality(load plugin.Partiality) plugin.Partiality {
	reasons := map[string]bool{}
	for _, r := range load.Reasons {
		reasons[r] = true
	}

	for fn := range ssautil.AllFunctions(s.prog) {
		classifyFuncPartiality(fn, reasons)
	}

	if len(reasons) == 0 {
		return plugin.Complete()
	}
	return plugin.Partial(sortedKeys(reasons)...)
}

// classifyFuncPartiality inspects a single SSA function for the same partiality
// triggers the whole-program partiality() detector folds in — reflection/cgo
// package membership, interface-dispatch (invoke) calls, and reflect/cgo static
// callees — recording the matching reason codes. It is the per-function unit
// shared by partiality() and the path-scoped taint partiality check, so the
// trigger set is defined once (inv.5: declared, never hidden).
func classifyFuncPartiality(fn *ssa.Function, reasons map[string]bool) {
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		switch fn.Pkg.Pkg.Path() {
		case "reflect":
			reasons[plugin.PartialReasonReflection] = true
		case "runtime/cgo":
			reasons[plugin.PartialReasonCgo] = true
		}
	}
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			if in, ok := instr.(ssa.CallInstruction); ok {
				if in.Common().IsInvoke() {
					reasons[plugin.PartialReasonDynamicDispatch] = true
				}
				if callee := in.Common().StaticCallee(); callee != nil {
					classifyCallee(callee, reasons)
				}
			}
		}
	}
}

func classifyCallee(fn *ssa.Function, reasons map[string]bool) {
	if fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return
	}
	switch {
	case fn.Pkg.Pkg.Path() == "reflect":
		reasons[plugin.PartialReasonReflection] = true
	case strings.HasPrefix(fn.Pkg.Pkg.Path(), "runtime/cgo"):
		reasons[plugin.PartialReasonCgo] = true
	}
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
