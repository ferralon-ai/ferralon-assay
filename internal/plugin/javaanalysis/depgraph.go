package javaanalysis

import (
	"context"
	"fmt"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/depreach"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// depgraph.go — composes steps (a)+(b)+(c) of dependency reachability: resolve the
// build's declared dependencies, locate each JAR in the local cache, parse its
// bytecode, and build the CHA engine that answers the two-trace PoNE. This is the
// dependency-level graph the reachability verdict rests on.
//
// Completeness is tracked honestly (inv.5): every declared dependency that could
// not be resolved to a version, located in the cache, or fully parsed is a Gap — a
// place the vulnerable sink could hide. A caller must not read "sink not found in
// the opened graph" as not_exploitable while Gaps is non-empty; the sink could live
// in a dependency we never opened. Transitive dependencies absent from the declared
// manifest are themselves a gap-source until PLAN-100/PLAN-140 supply the effective
// resolved graph — recorded, never silently assumed complete.

// dependencyGraph is the parsed dependency closure plus its completeness account.
type dependencyGraph struct {
	Engine   *depreach.Engine
	Complete bool              // every declared, resolved dependency JAR was located and fully parsed
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

// buildDependencyGraph resolves the build's declared dependencies and assembles a
// CHA engine over every dependency JAR it can open from the local cache. A missing
// manifest or unparseable build file (from ResolveDependencyVersions) and any
// unresolved / uncached / partially-parsed dependency are recorded as Gaps; the
// engine still contains whatever WAS opened, so a reachable path through an opened
// dependency is found even when another dependency is a gap.
func buildDependencyGraph(ctx context.Context, buildDir string) (*dependencyGraph, error) {
	res, err := ResolveDependencyVersions(ctx, plugin.ResolveVersionsRequest{BuildDir: buildDir})
	if err != nil {
		return nil, err
	}

	dg := &dependencyGraph{Complete: true}
	// A partial dependency-resolution result (no manifest, unparseable build file)
	// means the declared set itself is untrustworthy — the whole closure is a gap.
	if !res.Partiality.Complete {
		dg.Complete = false
		for _, r := range res.Partiality.Reasons {
			dg.Gaps = append(dg.Gaps, "dependency resolution partial: "+r)
		}
	}

	roots := mavenRepoRoots(buildDir)
	var classes []classfile.Class
	for _, d := range res.All {
		if !d.Resolved {
			dg.Complete = false
			dg.Gaps = append(dg.Gaps, fmt.Sprintf("%s: version unresolved", d.Coordinate))
			continue
		}
		jarPath, ok := LocateDependencyJar(roots, d.Coordinate, d.Version)
		if !ok {
			dg.Complete = false
			dg.Gaps = append(dg.Gaps, fmt.Sprintf("%s:%s: JAR not in local cache", d.Coordinate, d.Version))
			continue
		}
		jr, err := classfile.LoadJar(jarPath)
		if err != nil {
			dg.Complete = false
			dg.Gaps = append(dg.Gaps, fmt.Sprintf("%s:%s: %v", d.Coordinate, d.Version, err))
			continue
		}
		if len(jr.Failed) > 0 {
			dg.Complete = false
			for _, f := range jr.Failed {
				dg.Gaps = append(dg.Gaps, fmt.Sprintf("%s:%s: %s", d.Coordinate, d.Version, f))
			}
		}
		classes = append(classes, jr.Classes...)
	}

	dg.Classes = classes
	dg.Engine = depreach.NewEngine(classes)
	return dg, nil
}
