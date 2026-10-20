package javaanalysis

import (
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// depsymbols.go — resolve a dependency advisory's symbols inside the dependency's own JAR.
// The advisory's PURL names a Maven coordinate; the JAR for every version of it the build
// resolved is the file the build graph names (never fetched), read through the shared classfile
// reader, and the advisory symbols are matched by full binary name against the classes it
// holds. Only that JAR is searched, so a first-party method that happens to share a name can
// never stand in for the vulnerable dependency method.
//
// Each resolved method carries the same id the dependency call graph uses
// ("jvmref Owner#NameDesc"), Symbol.Package is the Maven coordinate, and Origins maps it to
// the coordinate's versionless PURL. Every gap is scoped to the coordinate, bounded by what
// the JAR's code could call, callbacks into first-party code included (depclosure.go):
//   - the graph resolved no version of it, or no JAR for a version → tool_failure:no_dependency_artifact;
//   - a JAR is unreadable, no longer has the digest the graph recorded, or some classes in it
//     fail to parse → tool_failure.
// Each scoped reason is also listed run-wide in Reasons. An advisory symbol that matches
// nothing in a fully read JAR is advisory_symbol_unresolved.

const (
	reasonNoDependencyArtifact     = plugin.PartialReasonToolFailure + ":no_dependency_artifact"
	reasonAdvisorySymbolUnresolved = "advisory_symbol_unresolved"
)

// depSymbolResolution is the dependency-JAR resolution before it is shaped into the plugin
// result. matched maps each advisory symbol (verbatim) to the SCIPs it resolved to.
type depSymbolResolution struct {
	resolved []plugin.Symbol
	origins  map[string]string
	matched  map[string][]string
	part     plugin.Partiality
}

// isRootCoordinate reports whether coordinate names one of the build's own modules: an
// advisory against the project itself, whose code is first-party source. Without a graph no
// coordinate is known to be one.
func isRootCoordinate(g *buildgraph.Graph, coordinate string) bool {
	return g != nil && moduleCoordinates(g)[coordinate]
}

// resolveDependencyJarSymbols resolves wanted inside the JAR(s) the build graph resolved for
// coordinate. purlVersion, when the request PURL pins one the build resolved, is the only
// version searched; otherwise every one is. Without a graph nothing is known about the
// coordinate's code, and the result says so run-wide.
func resolveDependencyJarSymbols(g *buildgraph.Graph, coordinate, purlVersion string, wanted []string) depSymbolResolution {
	out := depSymbolResolution{origins: map[string]string{}, matched: map[string][]string{}, part: plugin.Complete()}
	if len(wanted) == 0 {
		return out
	}
	if g == nil {
		out.part = plugin.Partial(PartialReasonBuildGraphAbsent)
		return out
	}

	purl := mavenPURLNoVersion(coordinate)
	targets := BlindSpotTargets(g, coordinate)
	scoped := func(reason, path string) plugin.ScopedReason {
		return plugin.ScopedReason{Reason: reason, Package: purl, Path: path, Targets: targets}
	}

	// Only the versions the build resolved are searched: another version that happens to sit
	// in a cache is not the code the build runs. A version the request PURL pins narrows the
	// search when the build resolved it, and is ignored when it did not.
	versions := graphVersionsOf(g, coordinate)
	if purlVersion != "" && slices.Contains(versions, purlVersion) {
		versions = []string{purlVersion}
	}

	var scopedReasons []plugin.ScopedReason
	if len(versions) == 0 {
		scopedReasons = append(scopedReasons, scoped(reasonNoDependencyArtifact, coordinate))
	}
	bySCIP := map[string]plugin.Symbol{}
	matchedSet := map[string]map[string]bool{}
	read := false
	for _, v := range versions {
		jars := CoordinateJars(g, coordinate, v)
		if len(jars) == 0 {
			scopedReasons = append(scopedReasons, scoped(reasonNoDependencyArtifact, coordinate+":"+v))
			continue
		}
		for _, j := range jars {
			jar, found := readJar(j)
			if found != jarFound {
				scopedReasons = append(scopedReasons, scoped(plugin.PartialReasonToolFailure, j.GAV()+": "+filepath.Base(j.Path)+" unreadable or changed since the build resolved it"))
				continue
			}
			jr, err := classfile.LoadJarBytes(jar.data)
			if err != nil {
				scopedReasons = append(scopedReasons, scoped(plugin.PartialReasonToolFailure, filepath.Base(jar.path)))
				continue
			}
			if len(jr.Failed) > 0 {
				scopedReasons = append(scopedReasons, scoped(plugin.PartialReasonToolFailure, filepath.Base(jar.path)+"!"+strings.SplitN(jr.Failed[0], ": ", 2)[0]))
			}
			read = true
			for w, syms := range matchJarSymbols(jr.Classes, coordinate, wanted) {
				if matchedSet[w] == nil {
					matchedSet[w] = map[string]bool{}
				}
				for _, s := range syms {
					bySCIP[s.SCIP] = s
					matchedSet[w][s.SCIP] = true
				}
			}
		}
	}

	for scip, s := range bySCIP {
		out.resolved = append(out.resolved, s)
		out.origins[scip] = purl
	}
	sort.Slice(out.resolved, func(i, j int) bool { return out.resolved[i].SCIP < out.resolved[j].SCIP })
	for w, set := range matchedSet {
		scips := make([]string, 0, len(set))
		for s := range set {
			scips = append(scips, s)
		}
		sort.Strings(scips)
		out.matched[w] = scips
	}

	var reasons []string
	if read && len(out.matched) < len(wanted) {
		reasons = append(reasons, reasonAdvisorySymbolUnresolved)
	}
	// Every scoped reason is also carried run-wide until the gate reads Scoped.
	for _, r := range scopedReasons {
		if !slices.Contains(reasons, r.Reason) {
			reasons = append(reasons, r.Reason)
		}
	}
	if len(reasons) > 0 || len(scopedReasons) > 0 {
		out.part = plugin.Partiality{Complete: false, Reasons: reasons, Scoped: scopedReasons}
	}
	return out
}

// matchJarSymbols returns, per advisory symbol, the JAR methods it names. An advisory symbol
// must name a method or class by its full binary name: package, class chain and, for a method,
// its name ("com.fasterxml.jackson.databind.ObjectMapper.readValue"; '$' and '#' are read as
// '.'; a trailing "(...)" descriptor or arity marker is ignored). A shorter form
// ("ObjectMapper.readValue", "readValue") matches nothing: a lookalike class elsewhere in the
// JAR could satisfy it while the vulnerable method goes unchecked, so it stays unresolved.
// A symbol that names a class stands for every method the class declares, constructors and
// the static initializer included: entering the class's code means running one of them, and
// touching a static field runs <clinit> without calling anything else the class declares.
func matchJarSymbols(classes []classfile.Class, coordinate string, wanted []string) map[string][]plugin.Symbol {
	out := map[string][]plugin.Symbol{}
	for _, w := range wanted {
		want := normalizeAdvisorySymbol(w)
		if want == "" {
			continue
		}
		for _, c := range classes {
			fqcn := strings.ReplaceAll(strings.ReplaceAll(c.Name, "/", "."), "$", ".")
			classHit := fqcn == want
			if !classHit && !strings.HasPrefix(want, fqcn+".") {
				continue
			}
			for _, m := range c.Methods {
				if classHit || fqcn+"."+m.Ref.Name == want {
					out[w] = append(out[w], dependencyMethodSymbol(m.Ref, coordinate))
				}
			}
		}
	}
	return out
}

// normalizeAdvisorySymbol reduces an advisory symbol to the dotted binary-name form
// matchJarSymbols compares against.
func normalizeAdvisorySymbol(w string) string {
	w = strings.TrimSpace(stripArity(w))
	return strings.NewReplacer("$", ".", "#", ".").Replace(w)
}

// dependencyMethodSymbol builds the symbol for a method read from a dependency JAR. Package
// is the Maven coordinate the JAR belongs to, so the Java package moves into Enclosing with
// the class chain; the SCIP is the dependency call graph's node id for the method.
func dependencyMethodSymbol(ref classfile.MethodRef, coordinate string) plugin.Symbol {
	fqcn := strings.ReplaceAll(strings.ReplaceAll(ref.Owner, "/", "."), "$", ".")
	kind := plugin.SymbolKindMethod
	if ref.Name == "<init>" {
		kind = plugin.SymbolKindConstructor
	}
	return plugin.Symbol{
		Kind:        kind,
		Package:     coordinate,
		Enclosing:   fqcn,
		Name:        ref.Name,
		Descriptor:  ref.Descriptor,
		Generated:   strings.HasPrefix(ref.Name, "access$") || strings.HasPrefix(ref.Name, "lambda$"),
		DisplayName: fqcn + "." + ref.Name + ref.Descriptor,
		SCIP:        depEdgeSymbol(ref),
	}
}
