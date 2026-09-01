package kotlinanalysis

import (
	"context"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// mainDescriptors are the JVM descriptors a Kotlin/JVM program entry point (`main`) can
// carry: the classic `String[]` entry and Kotlin's parameterless `fun main()`.
var mainDescriptors = map[string]bool{
	"([Ljava/lang/String;)V": true,
	"()V":                    true,
}

// CallGraph builds the first-party call graph over the compiled build output. Each parsed
// method's bytecode Code edges (already extracted by the shared classfile parser) become
// CallEdges between canonical symbols. invokedynamic edges — the coroutine-builder /
// inline-lambda / SAM-conversion frontier — carry no static callee, so they are NOT
// emitted as edges; their presence instead raises a declared dynamic_dispatch partiality
// (fail-open: an opaque edge is evidence the graph is incomplete, never "no call here").
//
// Roots are the discoverable program entry points (`main`). Framework ingress (Spring) is
// GRANITE's lane — see FindIngresses.
func CallGraph(_ context.Context, req plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.CallGraphResult{}, err
	}

	var edges []plugin.CallEdge
	for _, c := range prog.classes {
		for _, m := range c.Methods {
			caller := SymbolFromMethodRef(m.Ref)
			for _, e := range m.Edges {
				if e.Kind == classfile.EdgeDynamic || e.To.Owner == "" {
					prog.reasons[plugin.PartialReasonDynamicDispatch] = true
					continue
				}
				edges = append(edges, plugin.CallEdge{
					Caller: caller,
					Callee: SymbolFromMethodRef(e.To),
				})
			}
		}
	}

	// Overlay #K: fold the Spring DI bean model's resolved interface→impl edges into the
	// graph (beanwire.go). Purely additive — with no beans this is a no-op and the graph is
	// byte-identical. Ambiguous injection declares bean_ambiguous; it never fabricates an edge.
	beanEdges, beanReasons := wireBeanEdges(prog.classes)
	edges = append(edges, beanEdges...)
	for _, r := range beanReasons {
		prog.reasons[r] = true
	}

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Caller.SCIP != edges[j].Caller.SCIP {
			return edges[i].Caller.SCIP < edges[j].Caller.SCIP
		}
		return edges[i].Callee.SCIP < edges[j].Callee.SCIP
	})

	roots := entryRoots(prog.classes)
	return plugin.CallGraphResult{
		Partiality: prog.partiality(),
		Algorithm:  "cha",
		Edges:      edges,
		Roots:      roots,
	}, nil
}

// entryRoots returns the canonical symbols of every discoverable program entry point
// (`main`), sorted by SCIP for determinism.
func entryRoots(classes []classfile.Class) []plugin.Symbol {
	var roots []plugin.Symbol
	for _, ref := range mainMethodRefs(classes) {
		roots = append(roots, SymbolFromMethodRef(ref))
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].SCIP < roots[j].SCIP })
	return roots
}

// mainMethodRefs returns the MethodRefs of every `main` entry point across the loaded
// classes, sorted for determinism. Kotlin lowers a top-level `fun main` onto the file's
// `<File>Kt` facade class, so this catches both facade and member entry points.
func mainMethodRefs(classes []classfile.Class) []classfile.MethodRef {
	var refs []classfile.MethodRef
	for _, c := range classes {
		for _, m := range c.Methods {
			if m.Ref.Name == "main" && mainDescriptors[m.Ref.Descriptor] {
				refs = append(refs, m.Ref)
			}
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].String() < refs[j].String() })
	return refs
}
