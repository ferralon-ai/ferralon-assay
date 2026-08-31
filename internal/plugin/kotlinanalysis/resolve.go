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
// (inv.7); this only resolves them, never originates them.
func ResolveDependencySymbols(ctx context.Context, req plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	wanted := make([]string, 0, len(req.AdvisorySymbols))
	for _, s := range req.AdvisorySymbols {
		if t := strings.TrimSpace(s); t != "" {
			wanted = append(wanted, t)
		}
	}
	// No symbols named: nothing to resolve. A sound complete no-op, not a failure.
	if len(wanted) == 0 {
		return plugin.SymbolResolutionResult{Partiality: plugin.Complete()}, nil
	}

	coordinate, version, ok := coordinateAndVersion(ctx, req)
	if !ok {
		return plugin.SymbolResolutionResult{Partiality: plugin.Partial(partialReasonNoDependencyArtifact)}, nil
	}
	jarPath, ok := LocateDependencyJar(req.BuildDir, coordinate, version)
	if !ok {
		return plugin.SymbolResolutionResult{Partiality: plugin.Partial(partialReasonNoDependencyArtifact)}, nil
	}

	res, err := classfile.LoadJar(jarPath)
	if err != nil {
		// A located-but-unreadable artifact is a declared tool_failure partiality (V2's
		// "artifact unreadable" mode), NOT a hard error — a corrupt cached JAR must not
		// crash the scan.
		return plugin.SymbolResolutionResult{Partiality: plugin.Partial(plugin.PartialReasonToolFailure)}, nil
	}

	reasons := map[string]bool{}
	if len(res.Failed) > 0 {
		reasons[plugin.PartialReasonToolFailure] = true
	}

	resolved := matchAdvisorySymbols(res.Classes, wanted)
	if len(resolved) == 0 {
		reasons[partialReasonAdvisorySymbolUnresolved] = true
	}

	part := plugin.Complete()
	if len(reasons) > 0 {
		part = plugin.Partial(sortedKeys(reasons)...)
	}
	return plugin.SymbolResolutionResult{Partiality: part, Resolved: resolved}, nil
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
// returns those matching any wanted advisory identifier, sorted by SCIP for determinism (no
// map is an iteration source on this path). Symbols are derived from the SAME bytecode a Java
// caller observes, so a match is a bytecode-canonical identity, not a heuristic.
func matchAdvisorySymbols(classes []classfile.Class, wanted []string) []plugin.Symbol {
	var resolved []plugin.Symbol
	for _, c := range classes {
		if sym := SymbolFromClass(c); advisorySymbolMatches(sym, wanted) {
			resolved = append(resolved, sym)
		}
		for _, m := range c.Methods {
			if m.Ref.Name == "<clinit>" {
				continue
			}
			if sym := SymbolFromMethodRef(m.Ref); advisorySymbolMatches(sym, wanted) {
				resolved = append(resolved, sym)
			}
		}
	}
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].SCIP < resolved[j].SCIP })
	return resolved
}

// advisorySymbolMatches reports whether sym corresponds to any wanted advisory identifier.
// A JVM advisory names the sink by a package-qualified dotted form
// ("com.example.net.UrlFetcher.fetch"), a type-qualified method ("UrlFetcher.fetch"), or a
// bare leaf ("fetch"); each is matched against the symbol's display forms, tolerant of a
// trailing JVM descriptor/arity marker.
func advisorySymbolMatches(sym plugin.Symbol, wanted []string) bool {
	forms := advisorySymbolForms(sym)
	for _, w := range wanted {
		for _, cand := range forms {
			if eqIgnoringDescriptor(w, cand) {
				return true
			}
		}
	}
	return false
}

// advisorySymbolForms returns the dotted variants an advisory might name a symbol by: the
// bare display name ("UrlFetcher.fetch(...)V"), the package-qualified form
// ("com.example.net.UrlFetcher.fetch(...)V"), and the last-dot leaf of the class-qualified
// display ("fetch(...)V").
func advisorySymbolForms(sym plugin.Symbol) []string {
	disp := sym.DisplayName
	forms := []string{disp}
	if sym.Package != "" {
		forms = append(forms, sym.Package+"."+disp)
	}
	if i := strings.LastIndexByte(disp, '.'); i >= 0 {
		forms = append(forms, disp[i+1:])
	}
	return forms
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
