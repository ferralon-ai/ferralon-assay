package jsanalysis

// inventory_npm.go — the npm inventory adapter (graph-representation.md §3a). It reads
// package-lock.json / npm-shrinkwrap.json (lockfileVersion 1/2/3). v2/v3 carry the resolved
// tree under `packages` keyed by install path; edges are resolved by the nearest-node_modules
// hoisting walk. v1 carries a nested `dependencies` tree; edges are the literal JSON nesting.
// No package manager is executed — every fact is read from the committed lockfile + manifest.
//
// Instance identity: npm mints a resolution-scope suffix ONLY for a same-(name,version) nested
// duplicate whose resolved child closure genuinely DIFFERS from a sibling instance (npm
// peer-conflict nesting) — such instances are semantically distinct and must not collapse, so
// each gets an install-path resolution-scope suffix per instance-key-contract.md §2 (npm row).
// The common cases keep ID == PURL: identical-closure duplicates at different paths collapse to
// one node via dedupByID while their distinct parent edges are preserved (invariant (ii)), and
// different versions are already distinct PURLs (invariant (i)). Detecting distinct closures is a
// structural compare of the two entries' resolved dependency sets — no package manager is run.

import (
	"encoding/json"
	"os"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

type npmAdapter struct{}

type npmLock struct {
	LockfileVersion int                   `json:"lockfileVersion"`
	Packages        map[string]npmLockPkg `json:"packages"`
	Dependencies    map[string]npmLockDep `json:"dependencies"`
}

type npmLockPkg struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OS                   []string          `json:"os"`
	CPU                  []string          `json:"cpu"`
}

type npmLockDep struct {
	Version      string                `json:"version"`
	Resolved     string                `json:"resolved"`
	Integrity    string                `json:"integrity"`
	Dependencies map[string]npmLockDep `json:"dependencies"`
}

func (npmAdapter) Parse(sel selectedLock, manifests []manifestFile) ([]plugin.DependencyNode, []plugin.DependencyEdge, plugin.Partiality) {
	data, err := os.ReadFile(sel.path)
	if err != nil {
		return nil, nil, plugin.Partial(plugin.PartialReasonToolFailure)
	}
	var lock npmLock
	if json.Unmarshal(data, &lock) != nil {
		return nil, nil, plugin.Partial(plugin.PartialReasonToolFailure)
	}

	// Root manifest for the membership/direct join and the minted project node.
	var rootMan invManifest
	var rootManPath string
	for _, m := range manifests {
		if m.dir == sel.root {
			rootMan = m.pkg
			rootManPath = m.path
			break
		}
	}

	if len(lock.Packages) == 0 {
		return npmParseV1(sel, lock, rootMan, rootManPath)
	}
	return npmParseV2V3(sel, lock, rootMan, rootManPath)
}

func npmParseV2V3(sel selectedLock, lock npmLock, rootMan invManifest, rootManPath string) ([]plugin.DependencyNode, []plugin.DependencyEdge, plugin.Partiality) {
	part := plugin.Complete()
	nodesByID := make(map[string]*plugin.DependencyNode)
	var order []string
	addNode := func(n plugin.DependencyNode) *plugin.DependencyNode {
		if existing, ok := nodesByID[n.ID]; ok {
			mergeNode(existing, n)
			return existing
		}
		cp := n
		nodesByID[n.ID] = &cp
		order = append(order, n.ID)
		return &cp
	}
	var edges []plugin.DependencyEdge

	// direct-dep install-dir names → membership target, from the root "" entry (authoritative)
	// falling back to the root package.json when the "" entry omits the maps.
	directTargets := npmDirectTargets(lock.Packages[""], rootMan)

	// pathToID maps a packages install path to the node ID installed there (for edge resolution).
	pathToID := make(map[string]string)

	// Distinct-closure detection (instance-key-contract.md §2, npm row): a same-(name,version)
	// nested duplicate whose RESOLVED child closure differs from a sibling is a semantically
	// distinct instance and must not collapse to one node — it gets an install-path scope suffix.
	// Identical-closure duplicates keep the bare PURL and collapse via dedupByID (invariant (ii)).
	needSuffix := npmDistinctClosureSuffixes(lock.Packages)

	for path, pkg := range lock.Packages {
		if path == "" {
			continue // the root project itself, not a dependency node
		}
		if !strings.HasPrefix(path, "node_modules/") {
			// A local/linked package (file:/link:) lives at a non-node_modules install path
			// (e.g. a file: workspace member at packages/*). Record its install path so its
			// declared deps resolve to member→dep edges in the edge pass below.
			local := npmEmitLocal(path, pkg, sel, addNode)
			pathToID[path] = local.ID
			continue
		}
		if pkg.Link {
			continue // symlink shim to a local package; the local entry above is the node
		}
		name := npmName(path, pkg.Name)
		if name == "" || pkg.Version == "" {
			part = mergePartiality(part, plugin.Partial(plugin.PartialReasonToolFailure))
			continue
		}
		purl := makePURL(name, pkg.Version)
		id := purl // npm suffix empty in the common case → ID == PURL
		if needSuffix[path] {
			id = makeID(purl, path) // distinct-closure instance → install-path scope suffix
		}
		node := plugin.DependencyNode{
			ID:         id,
			PURL:       purl,
			Version:    pkg.Version,
			Provenance: plugin.DependencyProvenance{Manifest: rootManPath, Lockfile: sel.path, Resolver: "npm"},
			Partiality: plugin.Complete(),
		}
		npmArtifact(&node, pkg)
		if len(pkg.OS) > 0 || len(pkg.CPU) > 0 {
			node.Partiality = mergePartiality(node.Partiality, plugin.Partial(plugin.PartialReasonPlatformCondition))
		}
		if seg, top := npmTopSegment(path); top {
			if target, ok := directTargets[seg]; ok {
				node.Direct = true
				node.Membership.Project = rootMan.Name
				node.Membership.Target = target
			}
		}
		addNode(node)
		pathToID[path] = id
	}

	// Edges: each dependency entry's declared deps, resolved by the hoisting walk. This covers
	// both hoisted node_modules packages and file: workspace members (packages/*): a member's
	// declared deps are recorded inline in its lockfile entry, and the hoisting walk from the
	// member's own path resolves each to its installed instance (its private node_modules first,
	// then ascending to the root), yielding the member→dep edges npm ls shows.
	for path, pkg := range lock.Packages {
		if path == "" || pkg.Link {
			continue
		}
		parentID, ok := pathToID[path]
		if !ok {
			continue
		}
		for _, depName := range npmChildNames(pkg) {
			if childPath, found := nearestNodeModules(lock.Packages, path, depName); found {
				if childID, ok := pathToID[childPath]; ok {
					edges = append(edges, plugin.DependencyEdge{Parent: parentID, Child: childID})
				}
			}
		}
	}

	// Minted root project node + direct edges from it.
	rootID := ""
	if rootMan.Name != "" && rootMan.Version != "" {
		rootID = makePURL(rootMan.Name, rootMan.Version)
		addNode(plugin.DependencyNode{
			ID:         rootID,
			PURL:       rootID,
			Version:    rootMan.Version,
			Membership: plugin.DependencyMembership{Project: rootMan.Name},
			Provenance: plugin.DependencyProvenance{Manifest: rootManPath, Lockfile: sel.path, Resolver: "npm", Runtime: runtimeSpec(rootMan)},
			Partiality: plugin.Complete(),
		})
	}
	if rootID != "" {
		for _, id := range order {
			if n := nodesByID[id]; n.Direct {
				edges = append(edges, plugin.DependencyEdge{Parent: rootID, Child: n.ID})
			}
		}
	}

	// npm: aliases whose target is absent from the lockfile (declared but not installed).
	part = mergePartiality(part, npmAliasesAbsent(lock, rootMan, sel, rootManPath, addNode, &edges, rootID))

	out := make([]plugin.DependencyNode, 0, len(order))
	for _, id := range order {
		out = append(out, *nodesByID[id])
	}
	return out, edges, part
}

// npmDistinctClosureSuffixes returns the set of v2/v3 install paths that must carry an
// install-path resolution-scope suffix: those in a same-(name,version) group where at least two
// entries have DIFFERENT resolved child closures (npm peer-conflict nesting). Identical-closure
// duplicates are left un-suffixed so they collapse to one node (invariant (ii)). Structural
// compare only — no package manager executed (§3.3).
func npmDistinctClosureSuffixes(pkgs map[string]npmLockPkg) map[string]bool {
	type nv struct{ name, version string }
	sigs := make(map[nv]map[string]struct{})
	paths := make(map[nv][]string)
	for path, pkg := range pkgs {
		if path == "" || pkg.Link || !strings.HasPrefix(path, "node_modules/") {
			continue
		}
		name := npmName(path, pkg.Name)
		if name == "" || pkg.Version == "" {
			continue
		}
		key := nv{name, pkg.Version}
		if sigs[key] == nil {
			sigs[key] = make(map[string]struct{})
		}
		sigs[key][npmClosureSignature(pkgs, path, pkg)] = struct{}{}
		paths[key] = append(paths[key], path)
	}
	need := make(map[string]bool)
	for key, s := range sigs {
		if len(s) > 1 { // distinct closures at the same (name,version) → distinct instances
			for _, p := range paths[key] {
				need[p] = true
			}
		}
	}
	return need
}

// npmClosureSignature is a deterministic signature of a package entry's RESOLVED child set (each
// child's base PURL, hoisting-walk resolved), used to tell two same-(name,version) installs apart
// by their closures. Unresolved children are omitted — they do not distinguish a closure.
func npmClosureSignature(pkgs map[string]npmLockPkg, fromPath string, pkg npmLockPkg) string {
	var children []string
	for _, depName := range npmChildNames(pkg) {
		if childPath, found := nearestNodeModules(pkgs, fromPath, depName); found {
			child := pkgs[childPath]
			children = append(children, makePURL(npmName(childPath, child.Name), child.Version))
		}
	}
	sort.Strings(children)
	return strings.Join(children, "\n")
}

// npmParseV1 is the lockfileVersion-1 fallback: nodes + edges from the nested `dependencies`
// tree. v1 cannot represent workspaces, so a workspaces root declares partiality.
func npmParseV1(sel selectedLock, lock npmLock, rootMan invManifest, rootManPath string) ([]plugin.DependencyNode, []plugin.DependencyEdge, plugin.Partiality) {
	part := plugin.Complete()
	if len(rootMan.Workspaces) > 0 {
		part = plugin.Partial(plugin.PartialReasonWorkspaceAttrib)
	}
	nodesByID := make(map[string]*plugin.DependencyNode)
	var order []string
	addNode := func(n plugin.DependencyNode) {
		if existing, ok := nodesByID[n.ID]; ok {
			mergeNode(existing, n)
			return
		}
		cp := n
		nodesByID[n.ID] = &cp
		order = append(order, n.ID)
	}
	var edges []plugin.DependencyEdge

	var walk func(name string, dep npmLockDep) string
	walk = func(name string, dep npmLockDep) string {
		if name == "" || dep.Version == "" {
			return ""
		}
		purl := makePURL(name, dep.Version)
		node := plugin.DependencyNode{
			ID:         purl,
			PURL:       purl,
			Version:    dep.Version,
			Provenance: plugin.DependencyProvenance{Manifest: rootManPath, Lockfile: sel.path, Resolver: "npm"},
			Partiality: plugin.Complete(),
		}
		node.Artifact = plugin.DependencyArtifact{Identity: artifactIdentity(dep.Resolved, name, dep.Version), Digest: mapIntegrity(dep.Integrity)}
		addNode(node)
		for childName, child := range dep.Dependencies {
			if childID := walk(childName, child); childID != "" {
				edges = append(edges, plugin.DependencyEdge{Parent: purl, Child: childID})
			}
		}
		return purl
	}
	for name, dep := range lock.Dependencies {
		id := walk(name, dep)
		if _, direct := directNameSet(rootMan)[name]; direct && id != "" {
			nodesByID[id].Direct = true
			nodesByID[id].Membership.Project = rootMan.Name
		}
	}

	out := make([]plugin.DependencyNode, 0, len(order))
	for _, id := range order {
		out = append(out, *nodesByID[id])
	}
	return out, edges, part
}

// npmEmitLocal emits a local/linked (file:/link:) dependency node: path identity, no registry
// version/integrity guarantee, declared partial (§5, cell 8).
func npmEmitLocal(path string, pkg npmLockPkg, sel selectedLock, addNode func(plugin.DependencyNode) *plugin.DependencyNode) *plugin.DependencyNode {
	name := pkg.Name
	if name == "" {
		name = strings.TrimPrefix(path, "./")
	}
	version := pkg.Version
	if version == "" {
		version = "0.0.0-local"
	}
	purl := makePURL(name, version)
	return addNode(plugin.DependencyNode{
		ID:         purl,
		PURL:       purl,
		Version:    pkg.Version, // may be empty: a local path carries no registry pin
		Provenance: plugin.DependencyProvenance{Lockfile: sel.path, Resolver: "npm"},
		Partiality: plugin.Partial(plugin.PartialReasonLocalPathDep),
	})
}

// npmArtifact fills a node's Artifact from the lockfile, honoring git provenance: a git dep
// carries no integrity, and a git dep with no pinned commit sha is declared git_ref_unpinned.
func npmArtifact(node *plugin.DependencyNode, pkg npmLockPkg) {
	if isGitResolved(pkg.Resolved) {
		node.Artifact = plugin.DependencyArtifact{} // git deps record no integrity
		if !gitPinned(pkg.Resolved) {
			node.Partiality = mergePartiality(node.Partiality, plugin.Partial(plugin.PartialReasonGitRefUnpinned))
		}
		return
	}
	node.Artifact = plugin.DependencyArtifact{
		Identity: artifactIdentity(pkg.Resolved, npmNameOrEmpty(node), node.Version),
		Digest:   mapIntegrity(pkg.Integrity),
	}
}

// npmNameOrEmpty recovers a node's package name from its PURL for artifact-filename derivation.
func npmNameOrEmpty(node *plugin.DependencyNode) string {
	p := strings.TrimPrefix(node.PURL, "pkg:npm/")
	if at := strings.LastIndexByte(p, '@'); at > 0 {
		p = p[:at]
	}
	return strings.ReplaceAll(p, "%40", "@")
}

// npmAliasesAbsent declares alias_target_absent for each root `npm:` alias whose install path
// is absent from the lockfile — the alias was declared but its target was never resolved.
func npmAliasesAbsent(lock npmLock, rootMan invManifest, sel selectedLock, rootManPath string, addNode func(plugin.DependencyNode) *plugin.DependencyNode, edges *[]plugin.DependencyEdge, rootID string) plugin.Partiality {
	part := plugin.Complete()
	for _, dm := range depMapsFor(rootMan) {
		for seg, rng := range dm.deps {
			if !strings.HasPrefix(rng, "npm:") {
				continue
			}
			if _, present := lock.Packages["node_modules/"+seg]; present {
				continue // resolved normally, handled by the main loop
			}
			name, version := parseNpmAlias(rng)
			if name == "" || version == "" {
				continue
			}
			purl := makePURL(name, version)
			n := addNode(plugin.DependencyNode{
				ID:         purl,
				PURL:       purl,
				Version:    version,
				Direct:     true,
				Membership: plugin.DependencyMembership{Project: rootMan.Name, Target: dm.target},
				Provenance: plugin.DependencyProvenance{Manifest: rootManPath, Lockfile: sel.path, Resolver: "npm"},
				Partiality: plugin.Partial(plugin.PartialReasonAliasTargetAbsent),
			})
			if rootID != "" {
				*edges = append(*edges, plugin.DependencyEdge{Parent: rootID, Child: n.ID})
			}
			part = mergePartiality(part, plugin.Partial(plugin.PartialReasonAliasTargetAbsent))
		}
	}
	return part
}

// parseNpmAlias parses "npm:target@1.2.3" (and scoped "npm:@scope/target@1.2.3") into name+version.
func parseNpmAlias(rng string) (name, version string) {
	body := strings.TrimPrefix(rng, "npm:")
	at := strings.LastIndexByte(body, '@')
	if at <= 0 {
		return body, ""
	}
	return body[:at], body[at+1:]
}

// npmDirectTargets returns the install-dir name → membership-target map for the root's direct
// deps, preferring the lockfile "" entry's maps and falling back to the root package.json.
func npmDirectTargets(root npmLockPkg, rootMan invManifest) map[string]string {
	out := make(map[string]string)
	put := func(target string, deps map[string]string) {
		for name := range deps {
			if _, exists := out[name]; !exists {
				out[name] = target
			}
		}
	}
	put("runtime", root.Dependencies)
	put("dev", root.DevDependencies)
	put("optional", root.OptionalDependencies)
	put("peer", root.PeerDependencies)
	put("runtime", rootMan.Dependencies)
	put("dev", rootMan.DevDependencies)
	put("optional", rootMan.OptionalDependencies)
	put("peer", rootMan.PeerDependencies)
	return out
}

// directNameSet is the set of direct dependency names declared in a manifest (all scopes).
func directNameSet(m invManifest) map[string]struct{} {
	out := make(map[string]struct{})
	for _, dm := range depMapsFor(m) {
		for name := range dm.deps {
			out[name] = struct{}{}
		}
	}
	return out
}

// npmChildNames returns the declared dependency install-dir names of a package entry whose
// edges the walk resolves (runtime + optional; peers are classified elsewhere, not edges).
func npmChildNames(pkg npmLockPkg) []string {
	var names []string
	seen := make(map[string]struct{})
	add := func(deps map[string]string) {
		for n := range deps {
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			names = append(names, n)
		}
	}
	add(pkg.Dependencies)
	add(pkg.OptionalDependencies)
	return names
}

// npmName derives a dependency's npm name from a v2/v3 install-path key (last node_modules
// segment), unless an explicit "name" (an alias target) overrides.
func npmName(installPath, explicit string) string {
	if explicit != "" {
		return explicit
	}
	const marker = "node_modules/"
	idx := strings.LastIndex(installPath, marker)
	if idx < 0 {
		return ""
	}
	return installPath[idx+len(marker):]
}

// npmTopSegment returns the install-dir name of a TOP-LEVEL package (directly under the root
// node_modules, scoped names included) and whether the path is top-level.
func npmTopSegment(path string) (string, bool) {
	const marker = "node_modules/"
	if !strings.HasPrefix(path, marker) {
		return "", false
	}
	rest := path[len(marker):]
	if strings.Contains(rest, "/node_modules/") {
		return "", false
	}
	return rest, true
}

// nearestNodeModules resolves a dependency reference to its installed path via npm's hoisting
// walk: probe fromPath/node_modules/<dep>, then ascend each parent node_modules directory to
// the root, returning the first install path present in the packages map.
func nearestNodeModules(pkgs map[string]npmLockPkg, fromPath, depName string) (string, bool) {
	prefix := fromPath
	for {
		cand := joinNodeModules(prefix, depName)
		if _, ok := pkgs[cand]; ok {
			return cand, true
		}
		if prefix == "" {
			return "", false
		}
		if idx := strings.LastIndex(prefix, "/node_modules/"); idx >= 0 {
			prefix = prefix[:idx]
		} else {
			prefix = "" // ascend to the root node_modules for a final probe
		}
	}
}

func joinNodeModules(prefix, dep string) string {
	if prefix == "" {
		return "node_modules/" + dep
	}
	return prefix + "/node_modules/" + dep
}

// isGitResolved reports whether a `resolved` URL is a git source.
func isGitResolved(resolved string) bool {
	return strings.HasPrefix(resolved, "git+") || strings.HasPrefix(resolved, "git://") ||
		strings.HasPrefix(resolved, "git@") || strings.Contains(resolved, ".git#") ||
		strings.HasSuffix(resolved, ".git")
}

// gitPinned reports whether a git `resolved` URL pins an exact 40-hex commit sha in its
// fragment. A moving ref (branch/tag) or no fragment is UNPINNED.
func gitPinned(resolved string) bool {
	h := strings.LastIndexByte(resolved, '#')
	if h < 0 {
		return false
	}
	frag := resolved[h+1:]
	// npm sometimes records "commit=<sha>" in the fragment.
	if eq := strings.LastIndexByte(frag, '='); eq >= 0 {
		frag = frag[eq+1:]
	}
	if len(frag) != 40 {
		return false
	}
	for i := 0; i < len(frag); i++ {
		c := frag[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
