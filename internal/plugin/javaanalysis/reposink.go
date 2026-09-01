package javaanalysis

import (
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// This file is the #3 repo-sink overlay (edge-seam.md §4). It classifies a sink whose
// enclosing type is a Spring Data repository (an interface transitively extending a
// *Repository base — the type set foundation exposes as prog.repositoryTypes, unioned
// over the source lane and beangraph.RepositoryTypesFromClasses over the dependency/
// Kotlin classfiles) and raises plugin.PartialReasonRepositorySynthesized on it.
//
// Why this is partiality, not an edge: a repository method's implementation bytecode is
// runtime-synthesized by Spring Data — a derived-query finder (findBy*/deleteBy*/countBy*)
// or an @Query-annotated method whose body never exists in source or in the analyzed
// classfiles. The method is therefore a BODY-ABSENT DB sink: the edge INTO it already
// forms (abstract/`;`-terminated methods are indexed as declared methods, so a caller's
// `userRepo.findByName(x)` resolves and reachability to the sink works today), so this
// overlay adds NO edges. It adds only the honest partiality that no consumer may claim
// value-flow THROUGH the (absent) impl (inv.5: partiality-only, never fabricate/flip).
//
// Disjoint from #4: a repo @Query method may carry BOTH repository_synthesized_sink (this
// file) and spel_present (SpEL inside @Query, #4's spel.go) — the two reasons are distinct
// and additive; this overlay models only the synthesized-sink signal, never query
// semantics or SQLi taint.
func init() {
	registerSinkClassifier(newRepositorySinkClassifier)
}

// newRepositorySinkClassifier is the H3 factory. It precomputes, once per analysis, the
// SCIP id prefix of every FIRST-PARTY repository type (a source class whose simple name is
// in prog.repositoryTypes) so the returned per-sink classifier is a prefix membership test
// with no per-sink allocation. Determinism: prefixes are built in prog.sourceClasses order
// (a slice); prog.repositoryTypes is consulted only for membership, never iterated for
// output.
func newRepositorySinkClassifier(prog *program) func(symbolID string) []string {
	if prog == nil || len(prog.repositoryTypes) == 0 {
		return func(string) []string { return nil }
	}
	// typePrefixes are the id prefixes of repository types: scipSymbol with an empty
	// descriptor yields exactly "<package><enclosing chain each + '#'>", the portion of a
	// method sink id that precedes its method descriptor. A sink is a repo method IFF some
	// prefix is a prefix of the id AND the remaining descriptor is a method declared
	// DIRECTLY on that type (see repositorySinkMatches).
	var typePrefixes []string
	seen := map[string]bool{}
	for _, sc := range prog.sourceClasses {
		if len(sc.enclosing) == 0 || !prog.repositoryTypes[sc.name] {
			continue
		}
		prefix := scipSymbol(sc.pkg, sc.enclosing, "")
		if seen[prefix] {
			continue
		}
		seen[prefix] = true
		typePrefixes = append(typePrefixes, prefix)
	}
	if len(typePrefixes) == 0 {
		return func(string) []string { return nil }
	}
	return func(symbolID string) []string {
		for _, prefix := range typePrefixes {
			if repositorySinkMatches(symbolID, prefix) {
				return []string{plugin.PartialReasonRepositorySynthesized}
			}
		}
		return nil
	}
}

// repositorySinkMatches reports whether symbolID is a method declared directly on the
// repository type whose id prefix is typePrefix. It requires (1) the id to start with the
// type prefix, (2) the remaining descriptor to be a method descriptor — ends with ")."
// (methodDescriptor's shape; a field descriptor ends "name." with no paren), and (3) the
// remainder to contain no further '#', so a method on a type NESTED inside the repository
// (id "...Repo#Nested#m().") is excluded — only the repo type's own methods are synthesized
// sinks.
func repositorySinkMatches(symbolID, typePrefix string) bool {
	if !strings.HasPrefix(symbolID, typePrefix) {
		return false
	}
	descriptor := symbolID[len(typePrefix):]
	if strings.Contains(descriptor, "#") {
		return false
	}
	return strings.HasSuffix(descriptor, ").")
}
