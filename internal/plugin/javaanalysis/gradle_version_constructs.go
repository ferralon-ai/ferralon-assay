package javaanalysis

import (
	"sort"
	"strings"
)

// gradleVersionConstructNames are the Gradle constructs that can move a resolved version off
// what a lock and the literal declarations say, or that version a dependency through text the
// declaration reader does not see:
//
//   - resolution rules: resolutionStrategy (force, eachDependency, dependencySubstitution and
//     the rest), eachDependency/useVersion, dependencySubstitution;
//   - rich versions: strictly, require, prefer;
//   - force, in Groovy and as the Kotlin isForce property;
//   - enforcedPlatform, whose versions override the graph's;
//   - version catalogs: a libs. accessor, a versionCatalogs block, or a .toml reference.
var gradleVersionConstructNames = []string{
	"resolutionStrategy", "dependencySubstitution", "eachDependency", "useVersion",
	"strictly", "require", "prefer", "force", "isForce", "enforcedPlatform",
	"libs.", "versionCatalogs", ".toml",
}

// gradleVersionConstructs returns the names in gradleVersionConstructNames that occur in the
// given Gradle build or settings script sources, sorted. Comments are stripped first; a name
// counts as a whole word (a ".toml" reference only needs to end one), anywhere else, quoted
// strings included, since an interpolation can carry a catalog accessor. A hit says only that
// the script can version a dependency in a way a lock does not show; which dependency, if any,
// is not known.
func gradleVersionConstructs(sources ...string) []string {
	seen := map[string]bool{}
	for _, raw := range sources {
		src := stripGradleComments(raw)
		for _, name := range gradleVersionConstructNames {
			if !seen[name] && containsGradleWord(src, name) {
				seen[name] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// containsGradleWord reports whether name occurs in src with no identifier character before it
// (unless it starts with '.') and none after it (unless it ends with '.').
func containsGradleWord(src, name string) bool {
	for from := 0; ; {
		i := strings.Index(src[from:], name)
		if i < 0 {
			return false
		}
		i += from
		end := i + len(name)
		before := name[0] == '.' || i == 0 || !isGradleWordByte(src[i-1])
		after := name[len(name)-1] == '.' || end == len(src) || !isGradleWordByte(src[end])
		if before && after {
			return true
		}
		from = i + 1
	}
}

// isGradleWordByte leaves out '$', so a Groovy "$libs.x" interpolation still names libs.
func isGradleWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
