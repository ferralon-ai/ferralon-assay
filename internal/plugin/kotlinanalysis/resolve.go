package kotlinanalysis

import (
	"context"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// resolve.go — ResolveDependencySymbols (P2, §8 row 4): map the advisory's GIVEN vulnerable
// symbol(s) onto concrete symbols in the DEPENDENCY artifact the advisory names. Unlike the
// Java/.NET lanes (which resolve advisory symbols against FIRST-PARTY build output), the
// Kotlin lane resolves them against the dependency JAR itself: the JAR the build graph names for
// it (javaanalysis.CoordinateJars, digest-checked on read), indexed through the shared classfile
// reader, and matches the advisory symbol to a bytecode-canonical
// plugin.Symbol. This is the sound reuse of the JVM substrate row 4 asks for.
//
// Honest-absent on every gap (inv.5), never a fabricated match:
//   - no build graph → build_graph_absent, empty resolution.
//   - coordinate underivable, or the graph names no JAR for it → declared tool-unavailable
//     partiality (no_dependency_artifact), empty resolution.
//   - the JAR present but unreadable/partly unparseable → tool_failure partiality (a class
//     the analyzer could not read is a place a symbol could hide).
//   - the JAR fully read but no advisory symbol found in it → declared
//     advisory_symbol_unresolved partiality, empty resolution. Absence NEVER refutes: the
//     result stays non-Complete so no consumer reads the empty set as "not affected".

// partialReasonNoDependencyArtifact localizes the shared tool_failure base for the
// dependency-artifact-unavailable frontier: the build graph names no JAR for the advisory's
// coordinate, or the coordinate is underivable. Operational (artifact availability), not a
// language capability boundary.
const partialReasonNoDependencyArtifact = plugin.PartialReasonToolFailure + ":no_dependency_artifact"

// partialReasonAdvisorySymbolUnresolved localizes the honest-incomplete frontier where the
// dependency JAR was located and fully read, but none of the advisory's named symbols
// resolved to a concrete symbol in it. Operational (request/artifact content), not a
// desugaring boundary — kept non-Complete so absence never refutes.
const partialReasonAdvisorySymbolUnresolved = "advisory_symbol_unresolved"

// ResolveDependencySymbols resolves the advisory's vulnerable symbol(s) to concrete symbols
// in the named dependency's JAR. The advisory identifiers (PURL + symbols) are GIVEN
// (inv.7); this only resolves them, never originates them. Every resolved symbol was read
// from the dependency JAR, so each carries an Origin: the dependency's PURL without version.
// Matched maps each advisory symbol, verbatim as the request carried it, to the SCIPs it
// resolved to; an advisory symbol that resolved to nothing is absent from it.
func ResolveDependencySymbols(_ context.Context, req plugin.ResolveSymbolsRequest, opts ...javaanalysis.Option) (plugin.SymbolResolutionResult, error) {
	seen := map[string]bool{}
	wanted := make([]string, 0, len(req.AdvisorySymbols))
	for _, s := range req.AdvisorySymbols {
		if strings.TrimSpace(s) != "" && !seen[s] {
			seen[s] = true
			wanted = append(wanted, s)
		}
	}
	// No symbols named: nothing to resolve. A sound complete no-op, not a failure.
	if len(wanted) == 0 {
		return plugin.SymbolResolutionResult{Partiality: plugin.Complete()}, nil
	}

	g := javaanalysis.BuildGraph(opts...)
	if g == nil {
		return plugin.SymbolResolutionResult{Partiality: plugin.Partial(javaanalysis.PartialReasonBuildGraphAbsent)}, nil
	}
	jars, reasons, ok := dependencyJars(g, req.PURL)
	if !ok {
		return plugin.SymbolResolutionResult{Partiality: plugin.Partial(partialReasonNoDependencyArtifact)}, nil
	}
	var classes []classfile.Class
	for _, j := range jars {
		data, ok := javaanalysis.ReadRuntimeJar(j)
		if !ok {
			return plugin.SymbolResolutionResult{Partiality: plugin.Partial(plugin.PartialReasonToolFailure)}, nil
		}
		jr, err := classfile.LoadJarBytes(data)
		if err != nil {
			// A located-but-unreadable artifact is a declared tool_failure partiality (V2's
			// "artifact unreadable" mode), NOT a hard error — a corrupt cached JAR must not
			// crash the scan.
			return plugin.SymbolResolutionResult{Partiality: plugin.Partial(plugin.PartialReasonToolFailure)}, nil
		}
		if len(jr.Failed) > 0 {
			reasons[plugin.PartialReasonToolFailure] = true
		}
		classes = append(classes, jr.Classes...)
	}

	resolved, matched := matchAdvisorySymbols(classes, wanted)
	if len(matched) < len(wanted) {
		reasons[partialReasonAdvisorySymbolUnresolved] = true
	}
	coordinate, _, _ := parseMavenPURL(req.PURL)

	var origins map[string]string
	if len(resolved) > 0 {
		origin := "pkg:maven/" + strings.Replace(coordinate, ":", "/", 1)
		origins = make(map[string]string, len(resolved))
		for _, sym := range resolved {
			origins[sym.SCIP] = origin
		}
	}

	part := plugin.Complete()
	if len(reasons) > 0 {
		part = plugin.Partial(sortedKeys(reasons)...)
	}
	return plugin.SymbolResolutionResult{Partiality: part, Resolved: resolved, Origins: origins, Matched: matched}, nil
}

// dependencyJars returns the JARs the build graph resolved for the advisory's package, at the
// version the PURL pins when the build resolved that one. A pinned version the build did not
// resolve is declared, and every version the build did resolve is searched instead: those are
// the bytes that run. ok is false when the PURL is not a Maven package or the graph names no JAR
// for it.
func dependencyJars(g *buildgraph.Graph, purl string) (jars []javaanalysis.RuntimeJar, reasons map[string]bool, ok bool) {
	reasons = map[string]bool{}
	coordinate, pinned, ok := parseMavenPURL(purl)
	if !ok {
		return nil, nil, false
	}
	all := javaanalysis.CoordinateJars(g, coordinate, "")
	for _, j := range all {
		if j.Version == pinned {
			jars = append(jars, j)
		}
	}
	if len(jars) == 0 {
		if pinned != "" && len(all) > 0 {
			reasons[partialReasonNoDependencyArtifact] = true
		}
		jars = all
	}
	return jars, reasons, len(jars) > 0
}

// parseMavenPURL parses "pkg:maven/<group>/<artifact>[@version][?qualifiers]" into a
// "group:artifact" coordinate and (optional) version. ok is false for any non-Maven or
// malformed PURL (A2: Kotlin dependency artifacts are Maven-ecosystem-keyed).
func parseMavenPURL(purl string) (coordinate, version string, ok bool) {
	const prefix = "pkg:maven/"
	if !strings.HasPrefix(purl, prefix) {
		return "", "", false
	}
	rest := purl[len(prefix):]
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		version = strings.TrimSpace(rest[i+1:])
		rest = rest[:i]
	}
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return "", "", false
	}
	group := strings.TrimSpace(rest[:slash])
	artifact := strings.TrimSpace(rest[slash+1:])
	if group == "" || artifact == "" || strings.Contains(artifact, "/") {
		return "", "", false
	}
	return group + ":" + artifact, version, true
}

// matchAdvisorySymbols indexes the dependency classes into canonical plugin.Symbols and
// returns those matching any wanted advisory identifier, sorted by SCIP for determinism, plus
// the map from each wanted identifier (verbatim) to the sorted SCIPs it matched. Symbols are
// derived from the SAME bytecode a Java caller observes, so a match is a bytecode-canonical
// identity, not a heuristic.
func matchAdvisorySymbols(classes []classfile.Class, wanted []string) ([]plugin.Symbol, map[string][]string) {
	var resolved []plugin.Symbol
	matched := map[string][]string{}
	seen := map[string]bool{}
	consider := func(sym plugin.Symbol) {
		if seen[sym.SCIP] {
			return
		}
		seen[sym.SCIP] = true
		hit := false
		for _, w := range wanted {
			if advisorySymbolMatches(sym, strings.TrimSpace(w)) {
				matched[w] = append(matched[w], sym.SCIP)
				hit = true
			}
		}
		if hit {
			resolved = append(resolved, sym)
		}
	}
	for _, c := range classes {
		consider(SymbolFromClass(c))
		for _, m := range c.Methods {
			if m.Ref.Name == "<clinit>" {
				continue
			}
			consider(SymbolFromMethodRef(m.Ref))
		}
	}
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].SCIP < resolved[j].SCIP })
	for w := range matched {
		sort.Strings(matched[w])
	}
	return resolved, matched
}

// advisorySymbolMatches reports whether sym corresponds to the wanted advisory identifier.
// A JVM advisory names the sink by its package-qualified dotted form
// ("com.example.net.UrlFetcher.fetch"), tolerant of a trailing JVM descriptor/arity marker.
// Only the full package-qualified form matches: a type-qualified ("UrlFetcher.fetch") or bare
// ("fetch") name could be satisfied by a lookalike class elsewhere in the JAR while the real
// sink goes unchecked, so such a name stays unresolved.
func advisorySymbolMatches(sym plugin.Symbol, wanted string) bool {
	return eqIgnoringDescriptor(wanted, qualifiedSymbolName(sym))
}

// qualifiedSymbolName is the package-qualified dotted form of sym
// ("com.example.net.UrlFetcher.fetch(...)V"); a class in the unnamed package has no prefix.
func qualifiedSymbolName(sym plugin.Symbol) string {
	if sym.Package == "" {
		return sym.DisplayName
	}
	return sym.Package + "." + sym.DisplayName
}

// eqIgnoringDescriptor compares two symbol identifiers, ignoring a trailing "(...)"
// descriptor/arity marker on either operand so an advisory may name the symbol with or
// without a signature hint. The JVM DisplayName carries its descriptor beginning at the
// first '(' (e.g. "fetch(Ljava/lang/String;)V"), which this strips to the bare qualified
// name.
func eqIgnoringDescriptor(a, b string) bool {
	return a == b || stripDescriptor(a) == stripDescriptor(b)
}

// stripDescriptor removes a trailing "(...)" descriptor/arity marker from an identifier:
// "UrlFetcher.fetch(Ljava/lang/String;)V" → "UrlFetcher.fetch". A name with no paren is
// returned unchanged.
func stripDescriptor(s string) string {
	if i := strings.IndexByte(s, '('); i >= 0 {
		return s[:i]
	}
	return s
}
