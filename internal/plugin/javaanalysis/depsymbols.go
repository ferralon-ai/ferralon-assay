package javaanalysis

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// depsymbols.go — resolve a dependency advisory's symbols inside the dependency's own JAR.
// The advisory's PURL names a Maven coordinate; the JAR for every version of it the build
// resolved is located in the local caches (never fetched), read through the shared classfile
// reader, and the advisory symbols are matched against the classes it holds. Only that JAR
// is searched, so a first-party method that happens to share a leaf name can never stand in
// for the vulnerable dependency method.
//
// Each resolved method carries the same id the dependency call graph uses
// ("jvmref Owner#NameDesc"), Symbol.Package is the Maven coordinate, and Origins maps it to
// the coordinate's versionless PURL. Every gap is scoped to the coordinate, bounded by what
// the JAR's code could call (depclosure.go):
//   - no version resolved, or no cache holds the JAR → tool_failure:no_dependency_artifact;
//   - the JAR is unreadable, or some classes in it fail to parse → tool_failure.
// An advisory symbol that matches nothing in a fully read JAR is advisory_symbol_unresolved.

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

// isRootCoordinate reports whether coordinate names one of the build's own reactor modules:
// an advisory against the project itself, whose code is first-party source.
func isRootCoordinate(buildDir, coordinate string) bool {
	for _, p := range findPOMs(buildDir) {
		pom, ok := parseMavenPOM(p)
		if !ok || pom.ArtifactID == "" {
			continue
		}
		if pom.GroupID+":"+pom.ArtifactID == coordinate {
			return true
		}
	}
	return false
}

// resolveDependencyJarSymbols resolves wanted inside the JAR(s) of coordinate. purlVersion,
// when the request PURL pins one, is the only version searched; otherwise every version the
// inventory resolved for the coordinate is.
func resolveDependencyJarSymbols(ctx context.Context, buildDir, coordinate, purlVersion string, wanted []string) (depSymbolResolution, error) {
	out := depSymbolResolution{origins: map[string]string{}, matched: map[string][]string{}, part: plugin.Complete()}
	if len(wanted) == 0 {
		return out, nil
	}

	inv, err := ResolveInventory(ctx, plugin.ResolveInventoryRequest{BuildDir: buildDir})
	if err != nil {
		return out, err
	}
	ix := indexInventory(inv)
	purl := mavenPURLNoVersion(coordinate)
	targets := dependencyTargets(ix, newMavenCache(buildDir), coordinate)
	scoped := func(reason, path string) plugin.ScopedReason {
		return plugin.ScopedReason{Reason: reason, Package: purl, Path: path, Targets: targets}
	}

	versions := ix.versionsOf(coordinate)
	if purlVersion != "" {
		versions = []string{purlVersion}
	}
	if len(versions) == 0 {
		if v, ok := declaredVersion(ctx, buildDir, coordinate); ok {
			versions = []string{v}
		}
	}

	var scopedReasons []plugin.ScopedReason
	if len(versions) == 0 {
		scopedReasons = append(scopedReasons, scoped(reasonNoDependencyArtifact, coordinate))
	}
	bySCIP := map[string]plugin.Symbol{}
	matchedSet := map[string]map[string]bool{}
	read := false
	for _, v := range versions {
		jarPath, ok := locateArtifactJar(buildDir, coordinate, v)
		if !ok {
			scopedReasons = append(scopedReasons, scoped(reasonNoDependencyArtifact, coordinate+":"+v))
			continue
		}
		jr, err := classfile.LoadJar(jarPath)
		if err != nil {
			scopedReasons = append(scopedReasons, scoped(plugin.PartialReasonToolFailure, filepath.Base(jarPath)))
			continue
		}
		if len(jr.Failed) > 0 {
			scopedReasons = append(scopedReasons, scoped(plugin.PartialReasonToolFailure, filepath.Base(jarPath)+"!"+strings.SplitN(jr.Failed[0], ": ", 2)[0]))
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
	if len(reasons) > 0 || len(scopedReasons) > 0 {
		out.part = plugin.Partiality{Complete: false, Reasons: reasons, Scoped: scopedReasons}
	}
	return out, nil
}

// declaredVersion falls back to the build files' literal declaration of coordinate when the
// inventory resolved no version for it.
func declaredVersion(ctx context.Context, buildDir, coordinate string) (string, bool) {
	res, err := ResolveDependencyVersions(ctx, plugin.ResolveVersionsRequest{BuildDir: buildDir, Coordinate: coordinate})
	if err != nil || !res.Found || !res.Match.Resolved || res.Match.Version == "" {
		return "", false
	}
	return res.Match.Version, true
}

// matchJarSymbols returns, per advisory symbol, the JAR methods it names. An advisory names
// a method by its package-qualified form ("com.fasterxml.jackson.databind.ObjectMapper.readValue"),
// a class-qualified form ("ObjectMapper.readValue") or a bare name ("readValue"); a trailing
// "(...)" descriptor or arity marker is ignored. An advisory that names a class
// ("org.apache.logging.log4j.core.lookup.JndiLookup") stands for every method the class
// declares, constructors included: entering the class's code means calling one of them.
// Static initializers are left out; they run on class load, not on a call.
func matchJarSymbols(classes []classfile.Class, coordinate string, wanted []string) map[string][]plugin.Symbol {
	out := map[string][]plugin.Symbol{}
	for _, w := range wanted {
		want := stripArity(w)
		for _, c := range classes {
			fqcn := strings.ReplaceAll(strings.ReplaceAll(c.Name, "/", "."), "$", ".")
			classHit := dottedSuffixMatch(fqcn, want)
			for _, m := range c.Methods {
				if m.Ref.Name == "<clinit>" {
					continue
				}
				if classHit || dottedSuffixMatch(fqcn+"."+m.Ref.Name, want) {
					out[w] = append(out[w], dependencyMethodSymbol(m.Ref, coordinate))
				}
			}
		}
	}
	return out
}

// dottedSuffixMatch reports whether want equals full or a suffix of full that starts at a
// '.' boundary: "ObjectMapper.readValue" and "readValue" match
// "com.fasterxml.jackson.databind.ObjectMapper.readValue"; "Mapper.readValue" does not.
func dottedSuffixMatch(full, want string) bool {
	if want == "" {
		return false
	}
	if full == want {
		return true
	}
	return strings.HasSuffix(full, "."+want)
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
