package jsanalysis

// inventory.go is the whole-graph dependency resolver (§4.1, PLAN-160) — the NEW
// inventory path. It is deliberately separate from the flat ResolveDependencyVersions
// path (versions.go:44), whose callers are unaffected and whose code stays untouched.
//
// Design (graph-representation.md, D1): one node/edge type, three thin adapters (npm,
// yarn(Classic|Berry), pnpm), one shared assembly stage, no cross-dialect reconciliation.
// Because DependencyNode.ID already encodes package-instance identity per the frozen
// instance-key-contract.md, assembly is a pure set-union keyed by ID: dedupByID unions
// membership, dedupEdges preserves distinct (Parent,Child) rows. Output is deterministically
// sorted (nodes by ID, edges by (Parent,Child)); no map is an iteration source on the
// encoding path (C6).
//
// HARD CONSTRAINTS honored here: no package manager is ever executed (§3.3/§10.1) — every
// fact is read from committed lockfile/manifest metadata. Evidence only, no verdict logic
// (§3.8). A condition that cannot be resolved from metadata is DECLARED partial (§3.1),
// never guessed.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// recognizedLockNames is the fixed, deterministic order in which a root's lockfiles are
// probed. Order matters for the single-dialect npm case (package-lock.json wins over
// npm-shrinkwrap.json when both exist) and for stable selection.
var recognizedLockNames = []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}

// selectedLock is the ONE authoritative lockfile chosen for a project/workspace root
// (D3 SELECTION, not concatenation).
type selectedLock struct {
	dialect string // "npm" | "yarn" | "pnpm"
	path    string // absolute path to the selected lockfile
	root    string // the project/workspace root directory that owns it
}

// invManifest is the subset of a package.json the inventory path reads for the
// membership/direct join and runtime provenance. Distinct from manifest.go's packageJSON
// so neither parse constrains the other.
type invManifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Engines              map[string]string `json:"engines"`
	Workspaces           json.RawMessage   `json:"workspaces"`
	PackageManager       string            `json:"packageManager"`
}

// manifestFile is one parsed package.json plus its location, handed to an adapter for the
// membership/direct join.
type manifestFile struct {
	path string // path to the package.json
	dir  string // directory containing it
	pkg  invManifest
}

// inventoryAdapter is the common interface each dialect implements (graph-representation.md
// §2). Parse reads ONE selected authoritative lockfile plus the manifests at the roots it
// governs, and emits nodes + edges ALREADY in the frozen ID spelling. It resolves every edge
// child to a node ID internally; the assembly stage never re-resolves. Declared partiality is
// returned, never inferred safety.
type inventoryAdapter interface {
	Parse(sel selectedLock, manifests []manifestFile) ([]plugin.DependencyNode, []plugin.DependencyEdge, plugin.Partiality)
}

// ResolveInventory resolves the whole selected dependency graph for the buildable module
// (§4.1). It is the NEW inventory path; the flat ResolveDependencyVersions path is untouched.
func ResolveInventory(_ context.Context, req plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.DependencyInventory{}, fmt.Errorf("jsanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.DependencyInventory{}, fmt.Errorf("jsanalysis: build dir %q is not a directory", req.BuildDir)
	}

	roots := discoverProjectRoots(req.BuildDir)
	if len(roots) == 0 {
		// No lockfile and no package.json anywhere: honest absence, never an
		// empty-but-Complete inventory that would read downstream as "no dependencies".
		return plugin.DependencyInventory{Partiality: plugin.Partial(plugin.PartialReasonNoManifest)}, nil
	}

	var (
		allNodes  []plugin.DependencyNode
		allEdges  []plugin.DependencyEdge
		graphPart = plugin.Complete()
	)
	for _, root := range roots {
		sel, selPart := selectLockfile(root)
		if !selPart.Complete {
			// No authoritative lock (no_manifest) or two dialects with no signal
			// (lockfile_ambiguous): emit NO nodes for this root, declare the gap. Picking
			// the wrong PM produces a confidently-wrong graph, which §3.1 forbids.
			graphPart = mergePartiality(graphPart, selPart)
			continue
		}
		ad := adapterFor(sel.dialect)
		if ad == nil {
			graphPart = mergePartiality(graphPart, plugin.Partial(plugin.PartialReasonToolFailure))
			continue
		}
		n, e, p := ad.Parse(sel, manifestsUnder(root))
		allNodes = append(allNodes, n...)
		allEdges = append(allEdges, e...)
		graphPart = mergePartiality(graphPart, p)
	}

	nodes := dedupByID(allNodes)
	edges := dedupEdges(allEdges)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Parent != edges[j].Parent {
			return edges[i].Parent < edges[j].Parent
		}
		return edges[i].Child < edges[j].Child
	})
	return plugin.DependencyInventory{Partiality: graphPart, Nodes: nodes, Edges: edges}, nil
}

// discoverProjectRoots returns every directory that directly contains a recognized lockfile
// — the authoritative install roots. Vendored/build/VCS trees are skipped so a nested
// install never shadows the project's own lockfiles. When no lockfile exists anywhere but the
// build dir is itself a package (has a package.json), the build dir is returned so
// selectLockfile can declare no_manifest rather than silently emitting an empty graph.
func discoverProjectRoots(buildDir string) []string {
	seen := make(map[string]struct{})
	var roots []string
	_ = filepath.WalkDir(buildDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree yields no roots; keep walking.
		}
		if d.IsDir() {
			if path != buildDir && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		switch d.Name() {
		case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml":
			dir := filepath.Dir(path)
			if _, dup := seen[dir]; !dup {
				seen[dir] = struct{}{}
				roots = append(roots, dir)
			}
		}
		return nil
	})
	if len(roots) == 0 {
		if fi, err := os.Stat(filepath.Join(buildDir, "package.json")); err == nil && !fi.IsDir() {
			roots = append(roots, buildDir)
		}
	}
	sort.Strings(roots)
	return roots
}

// selectLockfile selects the ONE authoritative lockfile for a root (D3). corepack's
// packageManager field, when present, is an authoritative (metadata-only) tie-breaker; it is
// absent in every corpus fixture, so it is an optional strengthening signal, never a
// requirement. Two dialects with no signal is declared lockfile_ambiguous — never merged.
func selectLockfile(root string) (selectedLock, plugin.Partiality) {
	type lockCand struct{ path, dialect string }
	var locks []lockCand
	for _, name := range recognizedLockNames {
		p := filepath.Join(root, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			locks = append(locks, lockCand{path: p, dialect: dialectForLock(name)})
		}
	}
	if len(locks) == 0 {
		return selectedLock{}, plugin.Partial(plugin.PartialReasonNoManifest)
	}

	if pm := packageManagerDialect(root); pm != "" {
		for _, l := range locks {
			if l.dialect == pm {
				return selectedLock{dialect: pm, path: l.path, root: root}, plugin.Complete()
			}
		}
		// corepack declares a PM whose lock is absent: ambiguous, do not fall back.
		return selectedLock{}, plugin.Partial(plugin.PartialReasonLockfileAmbiguous)
	}

	distinct := make(map[string]struct{})
	for _, l := range locks {
		distinct[l.dialect] = struct{}{}
	}
	if len(distinct) == 1 {
		// locks is in recognizedLockNames order, so the first is the deterministic pick.
		return selectedLock{dialect: locks[0].dialect, path: locks[0].path, root: root}, plugin.Complete()
	}
	return selectedLock{}, plugin.Partial(plugin.PartialReasonLockfileAmbiguous)
}

// dialectForLock maps a lockfile filename to its package-manager dialect.
func dialectForLock(name string) string {
	switch name {
	case "package-lock.json", "npm-shrinkwrap.json":
		return "npm"
	case "yarn.lock":
		return "yarn"
	case "pnpm-lock.yaml":
		return "pnpm"
	}
	return ""
}

// packageManagerDialect reads the corepack "packageManager" field (e.g. "pnpm@9.0.0") from
// the root package.json and returns the dialect, or "" when absent/unreadable. Metadata read
// only — corepack is never invoked.
func packageManagerDialect(root string) string {
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return ""
	}
	var m struct {
		PackageManager string `json:"packageManager"`
	}
	if json.Unmarshal(data, &m) != nil || m.PackageManager == "" {
		return ""
	}
	pm := m.PackageManager
	if i := strings.IndexByte(pm, '@'); i >= 0 {
		pm = pm[:i]
	}
	switch pm {
	case "npm", "yarn", "pnpm":
		return pm
	}
	return ""
}

// adapterFor returns the adapter for a dialect. The yarn adapter carries both Classic and
// Berry edge-resolution modes and selects between them at parse time.
func adapterFor(dialect string) inventoryAdapter {
	switch dialect {
	case "npm":
		return npmAdapter{}
	case "yarn":
		return yarnAdapter{}
	case "pnpm":
		return pnpmAdapter{}
	}
	return nil
}

// manifestsUnder reads every package.json under root (same skip rules as the walkers), parsed
// into the invManifest subset for the membership/direct join.
func manifestsUnder(root string) []manifestFile {
	var out []manifestFile
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree contributes no manifests.
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "package.json" {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		var pkg invManifest
		if json.Unmarshal(data, &pkg) != nil {
			return nil
		}
		out = append(out, manifestFile{path: path, dir: filepath.Dir(path), pkg: pkg})
		return nil
	})
	return out
}

// --- shared assembly: dedup + sort ------------------------------------------

// dedupByID collapses nodes sharing an ID into one, unioning membership/direct/partiality
// (invariant (ii): a physically-duplicated identical instance is ONE node). Distinct IDs —
// including same-(name,version) instances that differ only by resolution-scope suffix
// (invariant (iii)) — are kept apart.
func dedupByID(nodes []plugin.DependencyNode) []plugin.DependencyNode {
	byID := make(map[string]*plugin.DependencyNode, len(nodes))
	var order []string
	for i := range nodes {
		n := nodes[i]
		if existing, ok := byID[n.ID]; ok {
			mergeNode(existing, n)
			continue
		}
		cp := n
		byID[n.ID] = &cp
		order = append(order, n.ID)
	}
	out := make([]plugin.DependencyNode, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out
}

// mergeNode unions the membership/direct/partiality facts of two nodes that share an ID.
// Direct is monotonic (true wins); membership scalars fill when empty; partiality reasons
// union and Complete degrades to partial if either is partial.
func mergeNode(dst *plugin.DependencyNode, src plugin.DependencyNode) {
	if src.Direct {
		dst.Direct = true
	}
	if dst.Membership.Project == "" {
		dst.Membership.Project = src.Membership.Project
	}
	if dst.Membership.Workspace == "" {
		dst.Membership.Workspace = src.Membership.Workspace
	}
	if dst.Membership.Target == "" {
		dst.Membership.Target = src.Membership.Target
	}
	if dst.Artifact.Identity == "" {
		dst.Artifact.Identity = src.Artifact.Identity
	}
	if dst.Artifact.Digest == "" {
		dst.Artifact.Digest = src.Artifact.Digest
	}
	if dst.Provenance.Manifest == "" {
		dst.Provenance.Manifest = src.Provenance.Manifest
	}
	if dst.Provenance.Runtime == "" {
		dst.Provenance.Runtime = src.Provenance.Runtime
	}
	dst.Partiality = mergePartiality(dst.Partiality, src.Partiality)
}

// dedupEdges removes identical (Parent,Child) rows while preserving distinct paths (two
// different parents pointing at one child stay two rows — invariant (ii)).
func dedupEdges(edges []plugin.DependencyEdge) []plugin.DependencyEdge {
	seen := make(map[plugin.DependencyEdge]struct{}, len(edges))
	out := make([]plugin.DependencyEdge, 0, len(edges))
	for _, e := range edges {
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	return out
}

// mergePartiality combines two partiality declarations: Complete only when both are, with a
// de-duplicated union of reason codes (stable in first-seen order).
func mergePartiality(a, b plugin.Partiality) plugin.Partiality {
	if a.Complete && b.Complete {
		return plugin.Complete()
	}
	seen := make(map[string]struct{})
	var reasons []string
	for _, r := range append(append([]string{}, a.Reasons...), b.Reasons...) {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		reasons = append(reasons, r)
	}
	return plugin.Partiality{Complete: false, Reasons: reasons}
}

// --- PURL / ID helpers (instance-key-contract.md §1/§2) ---------------------

// makePURL builds the normalized npm PURL: "pkg:npm/" [namespace "/"] name "@" version.
// Scoped packages (@scope/name) put "@scope" in the namespace (the '@' percent-encodes to
// %40). Names are lowercased defensively; the version is NEVER lowercased or range-collapsed.
func makePURL(name, version string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(name, "@") {
		if slash := strings.IndexByte(name, '/'); slash > 0 {
			scope := name[:slash] // "@scope"
			pkg := name[slash+1:] // "name"
			return "pkg:npm/" + pctEscape(scope) + "/" + pctEscape(pkg) + "@" + version
		}
	}
	return "pkg:npm/" + pctEscape(name) + "@" + version
}

// makeID appends the resolution-scope suffix to a PURL when a peer/virtual instance was
// minted; otherwise the ID is byte-identical to the PURL (the overwhelming common case,
// which makes ID==PURL trivially verifiable). The token is percent-encoded so '(', ')',
// '@', '#', ':' survive round-trip.
func makeID(purl, scopeToken string) string {
	if scopeToken == "" {
		return purl
	}
	return purl + "?resolution_scope=" + pctEscape(scopeToken)
}

// pctEscape percent-encodes every byte outside the RFC 3986 unreserved set (A-Za-z0-9-._~).
// It is used for both PURL name segments and resolution-scope tokens, so "@scope" → "%40scope"
// and "(supports-color@8.1.1)" → "%28supports-color%408.1.1%29" and "virtual:a1b2" →
// "virtual%3Aa1b2" all round-trip.
func pctEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		const hex = "0123456789ABCDEF"
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}

// mapIntegrity maps an SRI integrity string ("sha512-<b64>") to the algorithm-prefixed form
// ("sha512:<b64>"): the separator '-' becomes ':', the base64 payload is untouched (not
// decoded). An empty or malformed value yields "".
func mapIntegrity(sri string) string {
	sri = strings.TrimSpace(sri)
	if sri == "" {
		return ""
	}
	// A resolution may carry multiple space-separated hashes; take the first.
	if sp := strings.IndexByte(sri, ' '); sp >= 0 {
		sri = sri[:sp]
	}
	i := strings.IndexByte(sri, '-')
	if i <= 0 || i == len(sri)-1 {
		return ""
	}
	return sri[:i] + ":" + sri[i+1:]
}

// artifactIdentity returns the selected artifact's filename. When the lockfile records a
// tarball URL, its filename tail (minus any '#sha1' fragment) is used; otherwise the
// canonical registry filename "<bare-name>-<version>.tgz" is derived from the coordinate as a
// pure string. No tarball is fetched or opened.
func artifactIdentity(resolvedURL, name, version string) string {
	if resolvedURL != "" {
		u := resolvedURL
		if h := strings.IndexByte(u, '#'); h >= 0 {
			u = u[:h]
		}
		if strings.Contains(u, ".tgz") {
			if s := strings.LastIndexByte(u, '/'); s >= 0 {
				return u[s+1:]
			}
			return u
		}
	}
	if version == "" {
		return ""
	}
	bare := name
	if strings.HasPrefix(bare, "@") {
		if s := strings.IndexByte(bare, '/'); s >= 0 {
			bare = bare[s+1:]
		}
	}
	return bare + "-" + version + ".tgz"
}

// depMapsFor returns the four dependency maps of a manifest keyed by the membership target
// they imply ("runtime", "dev", "optional", "peer"). Order is deterministic.
func depMapsFor(m invManifest) []struct {
	target string
	deps   map[string]string
} {
	return []struct {
		target string
		deps   map[string]string
	}{
		{"runtime", m.Dependencies},
		{"dev", m.DevDependencies},
		{"optional", m.OptionalDependencies},
		{"peer", m.PeerDependencies},
	}
}
