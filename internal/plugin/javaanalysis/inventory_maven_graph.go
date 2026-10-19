package javaanalysis

// inventory_maven_graph.go — Maven passes 5-8: transitive graph build (BFS over cached POMs),
// nearest-wins mediation (declaration-order tiebreak), scope/optional/exclusions, and the
// deterministic emit. resolveMaven is the reactor-level entry the dispatcher calls.

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// resolveMaven resolves every reactor module under buildDir and merges their graphs. Each module
// contributes nodes keyed by its own relative path (Membership.Project), so the same PURL in two
// modules gets distinct IDs (per-instance keying).
func resolveMaven(buildDir string, pomPaths []string, cache *mavenCache, targetEnv map[string]string) plugin.DependencyInventory {
	targetEnv = withMavenConfig(targetEnv, buildDir, pomPaths)
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
	var scoped []plugin.ScopedReason
	if len(reactorList) != len(pomPaths) {
		reasons = mergeReasons(reasons, plugin.PartialReasonToolFailure)
	}

	for _, pom := range reactorList {
		moduleRel := moduleRelPath(buildDir, pom.path)
		mn, me, mr, ms := resolveModule(pom, moduleRel, reactor, cache, targetEnv)
		nodes = append(nodes, mn...)
		edges = append(edges, me...)
		reasons = mergeReasons(reasons, mr...)
		scoped = append(scoped, ms...)
	}

	part := graphPartiality(reasons, len(nodes))
	part.Scoped = dedupScoped(scoped)
	return assembleInventory(nodes, edges, part)
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
// over the candidate set); losers still receive an edge to the winner. Undecided profiles come
// back as scoped reasons, each also in the run-wide reasons.
func resolveModule(pom *mvnPOM, moduleRel string, reactor map[string]*mvnPOM, cache *mavenCache, targetEnv map[string]string) ([]plugin.DependencyNode, []plugin.DependencyEdge, []string, []plugin.ScopedReason) {
	em := buildEffectiveModel(pom, reactor, cache, targetEnv, 0)
	// A transitive dependency an undecided profile of the module could manage or declare at
	// another version resolves to that version whenever the profile is on.
	alt := reversions(em)
	// What an undecided profile adds, re-declares, manages or excludes, here or in any POM the
	// graph reads, moves Maven's nearest-wins mediation everywhere below the module's direct
	// dependencies: a nearer declaration can win, or an excluded one can hand the GA to another
	// path. So no transitive version stands, and a graph that meets such a profile only after
	// emitting nodes is built again with every transitive withheld.
	alt.anyVersion = alt.anyVersion || mediationShifts(em)
	nodes, edges, reasons, scoped, shifted := resolveModuleGraph(pom, em, alt, moduleRel, reactor, cache, targetEnv)
	if shifted && !alt.anyVersion {
		alt.anyVersion = true
		nodes, edges, reasons, scoped, _ = resolveModuleGraph(pom, em, alt, moduleRel, reactor, cache, targetEnv)
	}
	return nodes, edges, reasons, withFirstPartyBound(scoped, em, reactor, cache, targetEnv)
}

// mediationShifts reports whether some undecided profile of em touches the dependency graph:
// it declares, re-declares or manages a dependency (touched), or what it changes is unknown.
func mediationShifts(em effectiveModel) bool {
	for _, u := range em.undecided {
		if u.anyVersion || len(u.touched) > 0 {
			return true
		}
	}
	return false
}

// resolveModuleGraph is one BFS over a module's graph under alt. shifted is true when a cached
// POM it reads has an undecided profile that touches the graph (mediationShifts).
func resolveModuleGraph(pom *mvnPOM, em effectiveModel, alt profileVersions, moduleRel string, reactor map[string]*mvnPOM, cache *mavenCache, targetEnv map[string]string) (nodes []plugin.DependencyNode, edges []plugin.DependencyEdge, reasons []string, scoped []plugin.ScopedReason, shifted bool) {
	reasons = append([]string{}, em.residue...)
	scoped = profileScoped(em, "", em.managed, reactor, cache, targetEnv)

	selected := map[string]string{} // "g:a" -> winning node ID
	nodeAt := map[string]int{}      // node ID -> index in nodes
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
			// A losing declaration that names another file of the same GA (a classifier or
			// non-jar type) may still put that file on the classpath, so the winner can no
			// longer say which bytes the build uses.
			if i, ok := nodeAt[winID]; ok && it.dep.variant() && !slices.Contains(nodes[i].Partiality.Reasons, reasonMavenArtifactVariant) {
				nodes[i].Partiality = nodePartiality(append(append([]string{}, nodes[i].Partiality.Reasons...), reasonMavenArtifactVariant))
			}
			continue
		}

		version := javaTrim(it.dep.Version)
		if mv, ok := em.managed[ga]; ok && it.depth > 0 {
			// The module's dependencyManagement (imported BOMs included) overrides the version a
			// transitive POM declares; only a direct declaration's own version beats it.
			version = javaTrim(mv)
		}
		if it.depth > 0 && it.dep.unresolvedBy == "" && (alt.anyVersion || alt.reversioned(ga, version)) {
			it.dep.unresolvedBy = reasonProfileActivation
		}
		if it.dep.unresolvedBy != "" {
			version = ""
		}
		purl := mavenPURL(it.dep.GroupID, it.dep.ArtifactID, version)
		nodeID := moduleRel + "|" + it.scope + "|" + purl
		selected[ga] = nodeID

		var nodeReasons []string
		if version == "" || !isLiteralVersion(version) {
			// Present-but-unresolved: emitted with a declared reason, NEVER dropped, NEVER guessed.
			version = ""
			why := reasonPropertyUnresolved
			if it.dep.unresolvedBy != "" {
				why = it.dep.unresolvedBy
			}
			nodeReasons = append(nodeReasons, why)
			reasons = mergeReasons(reasons, why)
		}
		// Node-level only: the package is still in the inventory, so this is not a graph limit
		// (which would block every not_exploitable of the ecosystem); it tells whatever binds
		// the node to bytes that the main JAR may not be the file the build uses.
		if it.dep.variant() {
			nodeReasons = append(nodeReasons, reasonMavenArtifactVariant)
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
		if version != "" && !scopePropagates(it.scope) && it.scope != "system" && it.scope != "import" {
			nodeReasons = append(nodeReasons, reasonMavenUnmodelledScope)
			reasons = mergeReasons(reasons, reasonMavenUnmodelledScope)
		}
		if version != "" && scopePropagates(it.scope) {
			child, ok := cache.get(it.dep.GroupID, it.dep.ArtifactID, version)
			if !ok {
				nodeReasons = append(nodeReasons, reasonMavenUncachedSubtree)
				reasons = mergeReasons(reasons, reasonMavenUncachedSubtree)
			} else {
				childEM := buildEffectiveModel(child, reactor, cache, targetEnv, 1)
				shifted = shifted || mediationShifts(childEM)
				reasons = mergeReasons(reasons, childEM.residue...)
				scoped = append(scoped, profileScoped(childEM, mavenPackage(it.dep.GroupID, it.dep.ArtifactID), em.managed, reactor, cache, targetEnv)...)
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
		nodeAt[nodeID] = len(nodes)
		nodes = append(nodes, node)
	}

	return nodes, edges, reasons, scoped, shifted
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

// defaultScope keeps the declared spelling: Maven compares scope names exactly, so "Test" is not
// "test" and stays an unmodelled scope.
func defaultScope(s string) string {
	if s == "" {
		return "compile"
	}
	return s
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
