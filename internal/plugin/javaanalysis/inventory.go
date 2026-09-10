package javaanalysis

// inventory.go — the JVM whole-graph dependency resolver (§4.1 / PLAN-140 + PLAN-142). It
// reads what the build ALREADY resolved on disk — reactor POMs plus the warm ~/.m2 POM cache
// (Maven), or the lockfile plus the ~/.gradle modules-2 cache (Gradle) — and emits a
// plugin.DependencyInventory: one DependencyNode per resolved package instance, with parent
// edges, membership, integrity digest, and provenance.
//
// Zero-egress / §3.3 by construction: it NEVER invokes mvn/mvnw/gradle/gradlew/java/javac or
// docker, and NEVER touches the network. Every populated field traces to a concrete parse of a
// concrete on-disk file; everything it cannot read is a NAMED plugin.Partiality — never an
// inferred version, never a Complete() over a truncated graph (the §3.6 "build has no deps"
// failure). resolved / present-but-unresolved / absent are three distinct states.
//
// Kotlin rides this via kotlinanalysis.ResolveInventory delegating here (C6): build-file /
// resolved-state reading is JVM-generic, not Java-source-specific.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Honest-absent reason codes, localized onto the shared onyx-q6 vocabulary (plugin.go:120-128).
// Each names a SPECIFIC frontier the resolver could not soundly close; none is ever a guess.
const (
	// Maven residue.
	reasonParentUncached       = plugin.PartialReasonSourceUnpinned + ":parent_uncached"                 // a <parent> POM is absent from the cache; that inheritance level is unresolved
	reasonPropertyUnresolved   = plugin.PartialReasonSourceUnpinned + ":property_unresolved"             // a ${...} in a version resolves to env.*/settings.*/an unknown property
	reasonBOMUncached          = plugin.PartialReasonSourceUnpinned + ":bom_uncached"                    // an imported <scope>import</scope> BOM POM is absent from the cache
	reasonProfileActivation    = plugin.PartialReasonEnvConditionUnresolved + ":profile_activation"      // profile activation needs live JDK/OS/file/exec state; profile NOT assumed active
	reasonMavenUncachedSubtree = plugin.PartialReasonRelationshipUnexpressed + ":maven_uncached_subtree" // a transitive child POM is absent from the cache; its subtree is undetermined

	// Gradle residue.
	reasonGradleTransitive   = plugin.PartialReasonRelationshipUnexpressed + ":gradle_transitive"   // no lockfile for a project: declared-direct only, transitive edges undetermined (irreducible Gradle boundary)
	reasonGradleUncached     = plugin.PartialReasonRelationshipUnexpressed + ":gradle_uncached"     // a locked coordinate's cached POM is absent; its out-edges undetermined
	reasonGradleSubstitution = plugin.PartialReasonRelationshipUnexpressed + ":gradle_substitution" // a dependencySubstitution swapped identity; cached-POM edges may not match the locked entry
	reasonGradleVariant      = plugin.PartialReasonSourceUnpinned + ":gradle_variant"               // Gradle Module Metadata (.module) variant selection not recoverable from the POM alone
)

// ResolveInventory resolves the whole dependency graph for the module rooted at req.BuildDir.
// A missing/unreadable build dir is a hard error (inv.4); every other shortfall is declared
// partiality on the returned inventory. It selects the Maven engine when a reactor pom.xml is
// present, else the Gradle join, else an honest-absent floor (zero nodes, never Complete()).
func ResolveInventory(_ context.Context, req plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.DependencyInventory{}, fmt.Errorf("javaanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.DependencyInventory{}, fmt.Errorf("javaanalysis: build dir %q is not a directory", req.BuildDir)
	}
	return resolveInventory(req.BuildDir, newMavenCache(req.BuildDir), newGradleCache(""), req.TargetEnv), nil
}

// resolveInventory is the fixture-independent core: the cache readers are injected so a test
// (and S4's benchmark differential) can point them at a fixture m2/ or modules-2/ tree instead
// of the ambient ~/.m2 and ~/.gradle. It never reads os.UserHomeDir itself.
func resolveInventory(buildDir string, m2 *mavenCache, gradle *gradleCache, targetEnv map[string]string) plugin.DependencyInventory {
	poms := findPOMs(buildDir)
	if len(poms) > 0 {
		return resolveMaven(buildDir, poms, m2, targetEnv)
	}
	if hasGradleBuild(buildDir) {
		return resolveGradle(buildDir, gradle)
	}
	// Neither build system present: honest-absent floor. NEVER an empty Complete().
	return assembleInventory(nil, nil, plugin.Partial(plugin.PartialReasonNoManifest))
}

// findPOMs returns every pom.xml under root (the Maven reactor closure), lexicographically
// sorted for determinism. Standard build-output/VCS dirs are skipped.
func findPOMs(root string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree yields no POMs; keep walking.
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "pom.xml" {
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// hasGradleBuild reports whether a Gradle build root lives under root (any build/settings
// script, Groovy or Kotlin DSL).
func hasGradleBuild(root string) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		switch d.Name() {
		case "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts":
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// --- shared PURL + assembly --------------------------------------------------

// mavenPURL renders the normalized Package URL for a Maven-coordinate artifact. The group is
// the purl namespace with dots preserved (purl-spec maven type), e.g.
// ("org.apache.commons","commons-lang3","3.12.0") -> "pkg:maven/org.apache.commons/commons-lang3@3.12.0".
func mavenPURL(group, artifact, version string) string {
	return "pkg:maven/" + group + "/" + artifact + "@" + version
}

// mergeReasons appends add to base, de-duplicating while preserving first-seen order (dotnet
// discipline: partiality is cumulative + monotonically non-decreasing).
func mergeReasons(base []string, add ...string) []string {
	seen := make(map[string]bool, len(base)+len(add))
	out := make([]string, 0, len(base)+len(add))
	for _, r := range append(append([]string{}, base...), add...) {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// assembleInventory sorts nodes by ID and edges by (Parent, Child) — the frozen deterministic
// encoding order (§7) — de-duplicates edges, and attaches the graph-level partiality. No map is
// an iteration source on this output path.
func assembleInventory(nodes []plugin.DependencyNode, edges []plugin.DependencyEdge, part plugin.Partiality) plugin.DependencyInventory {
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	seen := make(map[string]bool, len(edges))
	uniq := make([]plugin.DependencyEdge, 0, len(edges))
	for _, e := range edges {
		k := e.Parent + "\x00" + e.Child
		if seen[k] {
			continue
		}
		seen[k] = true
		uniq = append(uniq, e)
	}
	sort.Slice(uniq, func(i, j int) bool {
		if uniq[i].Parent != uniq[j].Parent {
			return uniq[i].Parent < uniq[j].Parent
		}
		return uniq[i].Child < uniq[j].Child
	})

	return plugin.DependencyInventory{Partiality: part, Nodes: nodes, Edges: uniq}
}

// graphPartiality is Complete() iff the resolver hit no residue, else Partial over the sorted
// reason set. A zero-node graph is NEVER Complete() — the caller must have folded in at least
// one reason (the C3 floor); this asserts that with no_manifest as a backstop.
func graphPartiality(reasons []string, nodeCount int) plugin.Partiality {
	if len(reasons) == 0 {
		if nodeCount == 0 {
			return plugin.Partial(plugin.PartialReasonNoManifest)
		}
		return plugin.Complete()
	}
	sorted := append([]string{}, reasons...)
	sort.Strings(sorted)
	return plugin.Partial(sorted...)
}
