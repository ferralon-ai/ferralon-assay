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
	"golang.org/x/tools/go/types/typeutil"

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
	return callGraphOf(res, algo)
}

// callGraphOf builds the call graph of an already-loaded program; algo is "vta", "cha" or "rta".
func callGraphOf(res *LoadResult, algo string) (plugin.CallGraphResult, error) {
	sp, err := buildSSA(res)
	if err != nil {
		return plugin.CallGraphResult{}, err
	}

	graph, err := sp.buildGraph(algo)
	if err != nil {
		return plugin.CallGraphResult{}, err
	}
	// Callees outside the loaded syntax (export-data functions such as plugin.Open) are
	// deleted with the synthetic nodes, so the run-time calls are found first.
	runTime := sp.runTimeCalls(graph)
	graph.DeleteSyntheticNodes()

	edges := sp.collectEdges(graph)
	roots := sp.collectRoots()
	part := sp.partiality(res)
	for _, r := range runTime {
		part = withReason(part, r)
	}

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
// A cgo boundary the load could bound (cgoLimits) is declared as its scoped limits
// instead of a run-wide reason.
func (s *ssaProgram) partiality(load *LoadResult) plugin.Partiality {
	reasons := map[string]bool{}
	for _, r := range load.Partiality.Reasons {
		reasons[r] = true
	}

	for fn := range ssautil.AllFunctions(s.prog) {
		classifyFuncPartiality(fn, reasons)
	}

	scoped := slices.Clone(load.Partiality.Scoped)
	if reasons[plugin.PartialReasonCgo] && load.cgo != nil {
		delete(reasons, plugin.PartialReasonCgo)
		for _, r := range load.cgo {
			if !slices.ContainsFunc(scoped, func(s plugin.ScopedReason) bool {
				return s.Reason == r.Reason && s.Package == r.Package && s.Path == r.Path
			}) {
				scoped = append(scoped, r)
			}
		}
	}
	if len(reasons) == 0 && len(scoped) == 0 {
		return plugin.Complete()
	}
	part := plugin.Partial(sortedKeys(reasons)...)
	part.Scoped = scoped
	return part
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

// runTimeCallees maps each function that calls code chosen at run time to the reason it declares.
// reflect.Value's Call, CallSlice, Method and MethodByName call a function or method picked by a
// value or a name, and a template's Execute calls the methods and functions its text names; the
// call graph follows none of those calls. plugin.Open loads Go code the build never compiled.
var runTimeCallees = map[string]string{
	"(reflect.Value).Call":                      plugin.PartialReasonReflectiveCall,
	"(reflect.Value).CallSlice":                 plugin.PartialReasonReflectiveCall,
	"(reflect.Value).Method":                    plugin.PartialReasonReflectiveCall,
	"(reflect.Value).MethodByName":              plugin.PartialReasonReflectiveCall,
	"(*text/template.Template).Execute":         plugin.PartialReasonReflectiveCall,
	"(*text/template.Template).ExecuteTemplate": plugin.PartialReasonReflectiveCall,
	"(*html/template.Template).Execute":         plugin.PartialReasonReflectiveCall,
	"(*html/template.Template).ExecuteTemplate": plugin.PartialReasonReflectiveCall,
	"plugin.Open":                               plugin.PartialReasonPluginLoad,
}

// runTimeCalls returns the reasons runTimeCallees declares for the callees the program reaches
// from govulncheck's entry points.
func (s *ssaProgram) runTimeCalls(graph *callgraph.Graph) []string {
	var queue []*callgraph.Node
	for _, fn := range s.govulncheckEntries() {
		if n := graph.Nodes[fn]; n != nil {
			queue = append(queue, n)
		}
	}
	seen := map[*callgraph.Node]bool{}
	reasons := map[string]bool{}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if seen[n] {
			continue
		}
		seen[n] = true
		if fn, ok := n.Func.Object().(*types.Func); ok && n.Func.Object() != nil {
			if r, ok := runTimeCallees[fn.FullName()]; ok {
				reasons[r] = true
			}
		}
		for _, e := range n.Out {
			queue = append(queue, e.Callee)
		}
	}
	return sortedKeys(reasons)
}

// govulncheckEntries returns the functions govulncheck (v1.3.0, internal/vulncheck entryPoints)
// searches from: main and init of a main package, and every exported function or method, plus
// the package initializer, of any other loaded package. A run-time call only hides a call from
// its search when one of these reaches it.
func (s *ssaProgram) govulncheckEntries() []*ssa.Function {
	var entries []*ssa.Function
	for _, p := range s.pkgs {
		if p == nil {
			continue
		}
		if p.Pkg.Name() == "main" {
			for name, m := range p.Members {
				if name == "main" || name == "init" || strings.HasPrefix(name, "init#") {
					entries = append(entries, s.memberFuncs(m)...)
				}
			}
			continue
		}
		for _, m := range p.Members {
			for _, fn := range s.memberFuncs(m) {
				if (fn.Name() == "init" && fn.Synthetic == "package initializer") ||
					(fn.Synthetic == "" && fn.Object() != nil && fn.Object().Exported()) {
					entries = append(entries, fn)
				}
			}
		}
	}
	return entries
}

// memberFuncs returns a package member's function, or a named type's methods on T and *T.
func (s *ssaProgram) memberFuncs(m ssa.Member) []*ssa.Function {
	switch m := m.(type) {
	case *ssa.Function:
		return []*ssa.Function{m}
	case *ssa.Type:
		var fns []*ssa.Function
		for _, sel := range typeutil.IntuitiveMethodSet(m.Type(), &s.prog.MethodSets) {
			if fn := s.prog.MethodValue(sel); fn != nil {
				fns = append(fns, fn)
			}
		}
		return fns
	}
	return nil
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
