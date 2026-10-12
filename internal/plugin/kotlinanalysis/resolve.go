package kotlinanalysis

import (
	"context"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// resolve.go — ResolveDependencySymbols (P2, §8 row 4): map the advisory's GIVEN vulnerable
// symbol(s) onto concrete symbols in the DEPENDENCY artifact the advisory names. Unlike the
// Java/.NET lanes (which resolve advisory symbols against FIRST-PARTY build output), the
// Kotlin lane resolves them against the dependency JAR itself: it locates the artifact in the
// build's local caches (LocateDependencyJar — zero-egress, never fetches), indexes it through
// the shared classfile reader, and matches the advisory symbol to a bytecode-canonical
// plugin.Symbol. This is the sound reuse of the JVM substrate row 4 asks for.
//
// Honest-absent on every gap (inv.5), never a fabricated match:
//   - coordinate/version underivable, or the JAR absent from every local cache → declared
//     tool-unavailable partiality (no_dependency_artifact), empty resolution.
//   - the JAR present but unreadable/partly unparseable → tool_failure partiality (a class
//     the analyzer could not read is a place a symbol could hide).
//   - the JAR fully read but no advisory symbol found in it → declared
//     advisory_symbol_unresolved partiality, empty resolution. Absence NEVER refutes: the
//     result stays non-Complete so no consumer reads the empty set as "not affected".

// partialReasonNoDependencyArtifact localizes the shared tool_failure base for the
// dependency-artifact-unavailable frontier: the advisory's dependency JAR could not be
// located in (or read from) the build's local caches — its version was UNRESOLVED, its
// coordinate underivable, or no cache held it. Operational (artifact availability), not a
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
func ResolveDependencySymbols(ctx context.Context, req plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
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

	jarPaths, reasons, ok := dependencyJars(ctx, req)
	if !ok {
		return plugin.SymbolResolutionResult{Partiality: plugin.Partial(partialReasonNoDependencyArtifact)}, nil
	}
	var classes []classfile.Class
	for _, jarPath := range jarPaths {
		jr, err := classfile.LoadJar(jarPath)
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
		group, artifact, _ := splitCoordinate(coordinate)
		origin := "pkg:maven/" + group + "/" + artifact
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

// dependencyJars returns the JAR(s) holding the bytes the build runs for the advisory's
// package. When the build's start scripts name the coordinate on a runtime classpath, those
// JARs are it (Gradle conflict resolution may have picked a version other than the declared
// one); a version the PURL pins that differs from them is declared. Otherwise the version
// comes from the PURL or the build files and the JAR from the local caches. ok is false when
// no JAR can be located.
func dependencyJars(ctx context.Context, req plugin.ResolveSymbolsRequest) (paths []string, reasons map[string]bool, ok bool) {
	reasons = map[string]bool{}
	coordinate, pinned, ok := parseMavenPURL(req.PURL)
	if !ok {
		return nil, nil, false
	}
	if jars := runtimeClasspathJars(req.BuildDir, coordinate); len(jars) > 0 {
		for _, j := range jars {
			paths = append(paths, j.path)
			if pinned != "" && j.version != pinned {
				reasons[partialReasonNoDependencyArtifact] = true
			}
		}
		return paths, reasons, true
	}
	coordinate, version, ok := coordinateAndVersion(ctx, req)
	if !ok {
		return nil, nil, false
	}
	jarPath, ok := LocateDependencyJar(req.BuildDir, coordinate, version)
	if !ok {
		return nil, nil, false
	}
	return []string{jarPath}, reasons, true
}

// runtimeClasspathJars returns the distinct JARs for coordinate ("group:artifact") on the
// build's start-script classpath.
func runtimeClasspathJars(buildDir, coordinate string) []classpathJar {
	rc, ok := findRuntimeClasspath(buildDir)
	if !ok {
		return nil
	}
	index := gradleCacheIndex(buildDir)
	seen := map[string]bool{}
	var out []classpathJar
	for _, name := range rc.entries {
		j, ok := locateClasspathJar(buildDir, rc, index, name)
		if ok && j.group+":"+j.artifact == coordinate && !seen[j.path] {
			seen[j.path] = true
			out = append(out, j)
		}
	}
	return out
}

// coordinateAndVersion derives the dependency coordinate ("group:artifact") and a concrete
// version from the request. The coordinate comes from the advisory PURL; the version comes
// from the PURL when it pins one (`@version`), otherwise from the build files via
// ResolveDependencyVersions (P1). ok is false when the coordinate cannot be parsed from a
// Maven PURL or no concrete version can be determined — either way the JAR cannot be located
// and the caller declares a tool-unavailable partiality.
func coordinateAndVersion(ctx context.Context, req plugin.ResolveSymbolsRequest) (coordinate, version string, ok bool) {
	coordinate, version, ok = parseMavenPURL(req.PURL)
	if !ok {
		return "", "", false
	}
	if version != "" {
		return coordinate, version, true
	}
	vres, err := ResolveDependencyVersions(ctx, plugin.ResolveVersionsRequest{
		BuildDir:   req.BuildDir,
		Coordinate: coordinate,
	})
	if err != nil || !vres.Found || !vres.Match.Resolved || vres.Match.Version == "" {
		return "", "", false
	}
	return coordinate, vres.Match.Version, true
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
