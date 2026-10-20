package javaanalysis

import (
	"fmt"
	"path/filepath"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/depreach"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// depgraph.go — composes steps (a)+(b)+(c) of dependency reachability: take every JAR the
// build graph resolved, parse its bytecode, and build the CHA engine that answers the
// two-trace PoNE. This is the dependency-level graph the reachability verdict rests on.
//
// Completeness is tracked honestly (inv.5): no graph, or a JAR that could not be read or fully
// parsed, is a Gap — a place the vulnerable sink could hide. A caller must not read "sink not
// found in the opened graph" as not_exploitable while Gaps is non-empty.

// dependencyGraph is the parsed dependency closure plus its completeness account.
type dependencyGraph struct {
	Engine   *depreach.Engine
	Complete bool              // every JAR the build graph names was read and fully parsed
	Gaps     []string          // one line per dependency the analysis could not fully open
	Classes  []classfile.Class // every class the analysis opened, retained for the call-edge projection
}

// depEdgeSymbol projects a dependency-bytecode method reference into a call-graph
// symbol id. The scheme is DELIBERATELY distinct from the source-lexical SCIP the
// first-party analyzer mints (scip-java maven …): a dependency method is identified
// by its owning class + full JVM descriptor, which cannot be reconciled with an
// arity-erased source id by string equality (that reconciliation is PLAN-242). The
// distinct prefix is what keeps a dependency edge from silently merging with a
// first-party one — the source→dependency crossing stays an explicit hazard until
// normalisation lands, never a fabricated identity.
func depEdgeSymbol(ref classfile.MethodRef) string {
	return "jvmref " + ref.Owner + "#" + ref.Name + ref.Descriptor
}

// callEdges projects the opened dependency classes into directed call-graph edges,
// one per resolvable invoke site. Dynamic (invokedynamic) edges carry no static
// callee (Owner == "") and are omitted here — they are completeness hazards the
// depreach engine already accounts for, not concrete edges. These edges make the
// persisted call graph dependency-inclusive: their presence is the evidence that the
// dependency closure was actually opened and searched, so a sink with no reaching
// path over a COMPLETE closure reads as a searched-negative (not_exploitable) rather
// than as an empty graph the refutation never ran on (undetermined).
func (dg *dependencyGraph) callEdges() []plugin.CallEdge {
	var edges []plugin.CallEdge
	for _, c := range dg.Classes {
		for _, m := range c.Methods {
			for _, e := range m.Edges {
				if e.To.Owner == "" { // invokedynamic: no static target
					continue
				}
				edges = append(edges, plugin.CallEdge{
					Caller: sym(depEdgeSymbol(m.Ref)),
					Callee: sym(depEdgeSymbol(e.To)),
				})
			}
		}
	}
	return edges
}

// buildDependencyGraph assembles a CHA engine over every dependency JAR the build graph names,
// in any scope, each read only when it still has its recorded digest. No graph, a JAR that
// cannot be read, and a JAR partially parsed are recorded as Gaps; the engine still contains
// whatever WAS opened, so a reachable path through an opened dependency is found even when
// another dependency is a gap.
func buildDependencyGraph(buildDir string, opts ...Option) (*dependencyGraph, error) {
	dg := &dependencyGraph{Complete: true}
	var cp depreach.Classpath
	g := BuildGraph(opts...)
	if g == nil {
		dg.Complete = false
		cp.Unlisted = true
		dg.Gaps = append(dg.Gaps, "dependency resolution partial: "+PartialReasonBuildGraphAbsent)
		dg.Engine = depreach.NewEngineOn(nil, cp)
		return dg, nil
	}

	var classes []classfile.Class
	for _, d := range graphJars(g) {
		jar, found := readJar(d)
		if found != jarFound {
			dg.Complete = false
			cp.Unlisted = true
			dg.Gaps = append(dg.Gaps, fmt.Sprintf("%s: %s unreadable or changed since the build resolved it", d.GAV(), filepath.Base(d.Path)))
			continue
		}
		pkgs, listed, closed := classfile.JarBytesPackages(jar.data)
		cp.Add(pkgs, listed && closed)
		if !listed {
			dg.Complete = false
			dg.Gaps = append(dg.Gaps, fmt.Sprintf("%s: JAR cannot be listed", d.GAV()))
			continue
		}
		jr, err := classfile.LoadJarBytes(jar.data)
		if err != nil {
			dg.Complete = false
			dg.Gaps = append(dg.Gaps, fmt.Sprintf("%s: %v", d.GAV(), err))
			continue
		}
		if len(jr.Failed) > 0 {
			dg.Complete = false
			for _, f := range jr.Failed {
				dg.Gaps = append(dg.Gaps, fmt.Sprintf("%s: %s", d.GAV(), f))
			}
		}
		classes = append(classes, jr.Classes...)
	}

	dg.Classes = classes
	dg.Engine = depreach.NewEngineOn(classes, cp)
	return dg, nil
}
