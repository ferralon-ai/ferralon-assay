package javaanalysis

// inventory_maven_graph.go — Maven passes 5-8: transitive graph build (BFS over cached POMs),
// nearest-wins mediation (declaration-order tiebreak), scope/optional/exclusions, and the
// deterministic emit. resolveMaven is the reactor-level entry the dispatcher calls.

import (
	"path/filepath"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// resolveMaven resolves every reactor module under buildDir and merges their graphs. Each module
// contributes nodes keyed by its own relative path (Membership.Project), so the same PURL in two
// modules gets distinct IDs (per-instance keying).
func resolveMaven(buildDir string, pomPaths []string, cache *mavenCache, targetEnv map[string]string) plugin.DependencyInventory {
	var reactorList []*mvnPOM
	reactor := map[string]*mvnPOM{}
	for _, p := range pomPaths {
		pom, ok := parseMavenPOM(p)
		if !ok {
			continue // unparseable reactor POM — recorded as tool_failure below.
		}
		reactorList = append(reactorList, pom)
		if ga := pom.GroupID + ":" + pom.ArtifactID; pom.ArtifactID != "" {
			if _, seen := reactor[ga]; !seen {
				reactor[ga] = pom
			}
		}
	}
	if len(reactorList) == 0 {
		return assembleInventory(nil, nil, plugin.Partial(plugin.PartialReasonToolFailure, plugin.PartialReasonNoManifest))
	}

	var nodes []plugin.DependencyNode
	var edges []plugin.DependencyEdge
	var reasons []string
	if len(reactorList) != len(pomPaths) {
		reasons = mergeReasons(reasons, plugin.PartialReasonToolFailure)
	}

	for _, pom := range reactorList {
		moduleRel := moduleRelPath(buildDir, pom.path)
		mn, me, mr := resolveModule(pom, moduleRel, reactor, cache, targetEnv)
		nodes = append(nodes, mn...)
		edges = append(edges, me...)
		reasons = mergeReasons(reasons, mr...)
	}

	return assembleInventory(nodes, edges, graphPartiality(reasons, len(nodes)))
}

func moduleRelPath(buildDir, pomPath string) string {
	rel, err := filepath.Rel(buildDir, filepath.Dir(pomPath))
	if err != nil || rel == "." {
		return ""
	}
	return filepath.ToSlash(rel)
}

// bfsItem is one queued dependency edge awaiting resolution.
type bfsItem struct {
	parentID   string          // node ID of the depending instance ("" for a module-direct dep)
	dep        mvnDep          // the dependency declaration (version already effective for direct deps)
	depth      int             // 0 = direct
	scope      string          // effective (narrowed) scope of THIS dep
	exclusions map[string]bool // "g:a" excluded along the path to here
}

// resolveModule runs passes 5-8 for a single reactor module: BFS candidate graph, nearest-wins
// mediation, scope/optional/exclusion pruning, and node emit. One node per GA (mediation is total
// over the candidate set); losers still receive an edge to the winner.
func resolveModule(pom *mvnPOM, moduleRel string, reactor map[string]*mvnPOM, cache *mavenCache, targetEnv map[string]string) ([]plugin.DependencyNode, []plugin.DependencyEdge, []string) {
	em := buildEffectiveModel(pom, reactor, cache, targetEnv, 0)
	reasons := append([]string{}, em.residue...)

	selected := map[string]string{} // "g:a" -> winning node ID
	var nodes []plugin.DependencyNode
	var edges []plugin.DependencyEdge

	// Seed the queue with the module's direct dependencies, in declaration order.
	var queue []bfsItem
	for _, d := range em.deps {
		queue = append(queue, bfsItem{dep: d, depth: 0, scope: defaultScope(d.Scope), exclusions: map[string]bool{}})
	}

	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		ga := it.dep.ga()

		if it.exclusions[ga] {
			continue // pruned by an <exclusions> up the path.
		}
		// Nearest-wins: a GA already selected at an equal/shallower depth wins; record the edge
		// to the incumbent and stop (never re-expand, never fabricate a second instance).
		if winID, ok := selected[ga]; ok {
			if it.parentID != "" {
				edges = append(edges, plugin.DependencyEdge{Parent: it.parentID, Child: winID})
			}
			continue
		}

		version := strings.TrimSpace(it.dep.Version)
		purl := mavenPURL(it.dep.GroupID, it.dep.ArtifactID, version)
		nodeID := moduleRel + "|" + it.scope + "|" + purl
		selected[ga] = nodeID

		var nodeReasons []string
		if version == "" || !isLiteralVersion(version) {
			// Present-but-unresolved: emitted with a declared reason, NEVER dropped, NEVER guessed.
			version = ""
			nodeReasons = append(nodeReasons, reasonPropertyUnresolved)
			reasons = mergeReasons(reasons, reasonPropertyUnresolved)
		}

		node := plugin.DependencyNode{
			ID:      nodeID,
			PURL:    purl,
			Version: version,
			Direct:  it.depth == 0,
			Membership: plugin.DependencyMembership{
				Project: moduleRel,
				Target:  it.scope,
			},
			Artifact: plugin.DependencyArtifact{
				Identity: it.dep.ArtifactID,
				Digest:   cache.digestFor(it.dep.GroupID, it.dep.ArtifactID, version),
			},
			Provenance: plugin.DependencyProvenance{
				Manifest: moduleRel,
				Resolver: "maven-effective",
			},
		}
		if it.parentID != "" {
			edges = append(edges, plugin.DependencyEdge{Parent: it.parentID, Child: nodeID})
		}

		// Pass 5 expansion: compile/runtime scopes propagate transitively as themselves; a direct
		// test/provided dep's own subtree is also on the module's (test/provided) classpath and is
		// expanded, its transitives narrowed to test/provided (Maven scope table). An unresolved
		// version can't be fetched → subtree undetermined.
		if version != "" && scopePropagates(it.scope) {
			child, ok := cache.get(it.dep.GroupID, it.dep.ArtifactID, version)
			if !ok {
				nodeReasons = append(nodeReasons, reasonMavenUncachedSubtree)
				reasons = mergeReasons(reasons, reasonMavenUncachedSubtree)
			} else {
				childEM := buildEffectiveModel(child, reactor, cache, targetEnv, 1)
				reasons = mergeReasons(reasons, childEM.residue...)
				childExcl := unionExclusions(it.exclusions, it.dep.Exclusions)
				for _, cd := range childEM.deps {
					if strings.EqualFold(cd.Optional, "true") {
						continue // optional transitives are NOT propagated.
					}
					ns, ok := narrowScope(it.scope, defaultScope(cd.Scope))
					if !ok {
						continue // scope not propagated (test/provided).
					}
					queue = append(queue, bfsItem{parentID: nodeID, dep: cd, depth: it.depth + 1, scope: ns, exclusions: childExcl})
				}
			}
		}
		// A direct test/provided dep is on the module's own path but its transitives are NOT
		// expanded (non-propagating scopes) — sound, no residue.

		node.Partiality = nodePartiality(nodeReasons)
		nodes = append(nodes, node)
	}

	return nodes, edges, reasons
}

func unionExclusions(base map[string]bool, add []mvnGA) map[string]bool {
	out := make(map[string]bool, len(base)+len(add))
	for k := range base {
		out[k] = true
	}
	for _, e := range add {
		out[e.GroupID+":"+e.ArtifactID] = true
	}
	return out
}

func defaultScope(s string) string {
	if s == "" {
		return "compile"
	}
	return strings.ToLower(s)
}

// scopePropagates reports whether a node in the given (already-narrowed) scope has its own
// transitive subtree expanded. compile/runtime propagate as the Maven main classpath; a direct
// test/provided dependency's transitives are on the module's test/provided classpath and are
// likewise expanded (narrowed to test/provided by narrowScope) — they are real, resolvable
// dependencies of the build, not honest-absent residue.
func scopePropagates(scope string) bool {
	switch scope {
	case "compile", "runtime", "test", "provided":
		return true
	default:
		return false
	}
}

// narrowScope applies the Maven transitive-scope table. ok is false when the child scope does not
// propagate through the parent at all (system/import, or a test/provided CHILD — those are never
// inherited transitively). A compile/runtime child inherits the parent's classpath: under a
// test/provided parent it narrows to test/provided (the parent dep's own subtree stays on that
// classpath), matching `dependency:tree`.
func narrowScope(parent, child string) (string, bool) {
	switch child {
	case "test", "provided", "system", "import":
		return "", false
	}
	switch parent {
	case "compile":
		return child, true // compile→compile, runtime→runtime
	case "runtime":
		return "runtime", true // compile and runtime both become runtime
	case "test":
		return "test", true // a test dep's compile/runtime transitives are test-scoped
	case "provided":
		return "provided", true // a provided dep's compile/runtime transitives are provided-scoped
	default:
		return "", false
	}
}

// nodePartiality is Complete() for a fully-pinned node (literal version, cached subtree), else
// Partial over its declared reasons (the three-state resolved/present-but-unresolved distinction).
func nodePartiality(reasons []string) plugin.Partiality {
	if len(reasons) == 0 {
		return plugin.Complete()
	}
	return plugin.Partial(mergeReasons(nil, reasons...)...)
}
