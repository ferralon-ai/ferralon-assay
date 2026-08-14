package jsanalysis

// inventory_c2_test.go — the C2 differential (02-convergence.md): the resolver's whole-graph
// output is compared against the package manager's OWN resolved tree, captured once offline by a
// human with --ignore-scripts (§3.3/§10.1) and committed under testdata/inventory/capture as cold
// fixtures. No package manager is executed here — every native tree is parsed statically as bytes,
// per its dialect's shape, and diffed against ResolveInventory over the same lockfile on two
// invariants: the (name,version) instance multiset and the parent→child edge set.
//
// The comparison key is the node PURL (pkg:npm/<name>@<version>) on both sides, minted by the
// same makePURL so scoping/encoding normalize identically. Native tools flatten the pnpm/Berry
// peer-resolution suffix, so C2 is a (name,version)-granularity check by construction; the suffix
// itself is validated separately against the lockfile (TestInventory_YarnBerry_F1,
// TestInventory_PnpmPeer_ScopeSuffix). Captured roots carry no package.json, so ResolveInventory
// mints no project node — matching the native tools' root-excluded closures; the root object is
// excluded on the native side too.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const captureDir = invDir + "/capture"

func captureFile(t *testing.T, fixture, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(captureDir, fixture, name))
	if err != nil {
		t.Fatalf("read capture %s/%s: %v", fixture, name, err)
	}
	return data
}

// purlOfID strips the ?resolution_scope= qualifier from a node ID, recovering the (name,version)
// PURL. It works even when the suffixed ID has no matching node (the pnpm-v9 peer-suffix gap),
// which is exactly why edge endpoints are mapped by string-strip, not by node lookup.
func purlOfID(id string) string {
	if i := strings.Index(id, "?resolution_scope="); i >= 0 {
		return id[:i]
	}
	return id
}

func edgeKey(parentPURL, childPURL string) string { return parentPURL + " -> " + childPURL }

// riSets projects a ResolveInventory result to its (node-PURL set, edge-PURL-pair set).
func riSets(inv plugin.DependencyInventory) (nodes map[string]bool, edges map[string]bool) {
	nodes = make(map[string]bool)
	for _, n := range inv.Nodes {
		nodes[n.PURL] = true
	}
	edges = make(map[string]bool)
	for _, e := range inv.Edges {
		edges[edgeKey(purlOfID(e.Parent), purlOfID(e.Child))] = true
	}
	return nodes, edges
}

// diff reports the symmetric difference between a native (oracle) set and the RI set.
func diff(native, ri map[string]bool) (onlyNative, onlyRI []string) {
	for k := range native {
		if !ri[k] {
			onlyNative = append(onlyNative, k)
		}
	}
	for k := range ri {
		if !native[k] {
			onlyRI = append(onlyRI, k)
		}
	}
	sort.Strings(onlyNative)
	sort.Strings(onlyRI)
	return
}

// assertEqualSets asserts native == RI exactly (both directions).
func assertEqualSets(t *testing.T, what string, native, ri map[string]bool) {
	t.Helper()
	onlyNative, onlyRI := diff(native, ri)
	if len(onlyNative) > 0 {
		t.Errorf("%s: %d present in native tree but MISSING from inventory:\n  %s", what, len(onlyNative), strings.Join(onlyNative, "\n  "))
	}
	if len(onlyRI) > 0 {
		t.Errorf("%s: %d present in inventory but ABSENT from native tree:\n  %s", what, len(onlyRI), strings.Join(onlyRI, "\n  "))
	}
}

// assertNativeSubset asserts native ⊆ RI: every instance/edge the native oracle asserts is
// present in the inventory. Used when the capture is a partial enumeration (Berry `yarn info`).
func assertNativeSubset(t *testing.T, what string, native, ri map[string]bool) {
	t.Helper()
	onlyNative, _ := diff(native, ri)
	if len(onlyNative) > 0 {
		t.Errorf("%s: %d asserted by native tree but MISSING from inventory:\n  %s", what, len(onlyNative), strings.Join(onlyNative, "\n  "))
	}
}

// ---- native dialect parsers (static; no package manager) --------------------

// npm `npm ls --all --json`: a recursive nested object {name,version,dependencies:{<pkg>:{version,
// dependencies:{…}}}}. Child names are object keys; edges are the nesting. The top object is the
// root project (excluded) and its direct children are root→dep edges (excluded).
type npmLsNode struct {
	Version      string                `json:"version"`
	Dependencies map[string]*npmLsNode `json:"dependencies"`
}

func parseNpmLs(t *testing.T, data []byte) (nodes, edges map[string]bool) {
	t.Helper()
	var root struct {
		Version      string                `json:"version"`
		Dependencies map[string]*npmLsNode `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("parse npm ls native: %v", err)
	}
	nodes, edges = map[string]bool{}, map[string]bool{}
	var walk func(parentPURL string, deps map[string]*npmLsNode, isRoot bool)
	walk = func(parentPURL string, deps map[string]*npmLsNode, isRoot bool) {
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			child := deps[name]
			if child == nil || child.Version == "" {
				continue
			}
			cp := makePURL(name, child.Version)
			nodes[cp] = true
			if !isRoot {
				edges[edgeKey(parentPURL, cp)] = true
			}
			walk(cp, child.Dependencies, false)
		}
	}
	walk("", root.Dependencies, true)
	return nodes, edges
}

// pnpm `pnpm list --depth Infinity --json`: an array of importers, each a nested tree of
// {version,dependencies|devDependencies|optionalDependencies:{<pkg>:{version,…,deduped}}}. A
// deduped node is a back-reference (its subtree lives elsewhere) but still a real edge endpoint.
type pnpmListNode struct {
	Version              string                   `json:"version"`
	Dependencies         map[string]*pnpmListNode `json:"dependencies"`
	DevDependencies      map[string]*pnpmListNode `json:"devDependencies"`
	OptionalDependencies map[string]*pnpmListNode `json:"optionalDependencies"`
}

func (n *pnpmListNode) children() map[string]*pnpmListNode {
	out := map[string]*pnpmListNode{}
	for _, m := range []map[string]*pnpmListNode{n.Dependencies, n.DevDependencies, n.OptionalDependencies} {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func parsePnpmList(t *testing.T, data []byte) (nodes, edges map[string]bool) {
	t.Helper()
	var importers []*pnpmListNode
	if err := json.Unmarshal(data, &importers); err != nil {
		t.Fatalf("parse pnpm list native: %v", err)
	}
	nodes, edges = map[string]bool{}, map[string]bool{}
	seen := map[string]bool{}
	var walk func(parentPURL string, node *pnpmListNode, isRoot bool)
	walk = func(parentPURL string, node *pnpmListNode, isRoot bool) {
		kids := node.children()
		names := make([]string, 0, len(kids))
		for n := range kids {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			child := kids[name]
			if child == nil || child.Version == "" {
				continue
			}
			cp := makePURL(name, child.Version)
			nodes[cp] = true
			if !isRoot {
				edges[edgeKey(parentPURL, cp)] = true
			}
			// A package's children are identical wherever it recurs (one flattened instance),
			// so expanding it once suffices for a set comparison and is cycle-safe.
			if !seen[cp] {
				seen[cp] = true
				walk(cp, child, false)
			}
		}
	}
	for _, imp := range importers {
		walk("", imp, true) // each importer is a root; its direct deps are root edges (excluded)
	}
	return nodes, edges
}

// yarn classic `yarn list --json`: {type:"tree",data:{type:"list",trees:[{name:"pkg@version",
// children:[{name:"pkg@RANGE",shadow:true},…]}]}}. Top-level tree names carry RESOLVED versions
// (the node set); children carry descriptor RANGES (dedup back-references), resolved to versions
// via the committed yarn.lock descriptor table (the same table the adapter uses).
type yarnListNative struct {
	Data struct {
		Trees []yarnListTree `json:"trees"`
	} `json:"data"`
}

type yarnListTree struct {
	Name     string         `json:"name"`
	Children []yarnListTree `json:"children"`
	Shadow   bool           `json:"shadow"`
}

// splitYarnListName splits "pkg@version" / "@scope/pkg@version" (and range forms) into the name
// and the trailing version-or-range, using yarnDescriptorName for the scoped-name handling.
func splitYarnListName(s string) (name, tail string) {
	name = yarnDescriptorName(s)
	if len(s) > len(name)+1 {
		return name, s[len(name)+1:]
	}
	return name, ""
}

func parseYarnList(t *testing.T, native, lock []byte) (nodes, edges map[string]bool) {
	t.Helper()
	var doc yarnListNative
	if err := json.Unmarshal(native, &doc); err != nil {
		t.Fatalf("parse yarn list native: %v", err)
	}
	// descriptor "name@range" → resolved version, from the committed yarn.lock.
	table := map[string]string{}
	for _, b := range parseYarnClassic(lock) {
		for _, d := range b.descriptors {
			table[d] = b.version
		}
	}
	nodes, edges = map[string]bool{}, map[string]bool{}
	var unresolved []string
	for _, tree := range doc.Data.Trees {
		name, ver := splitYarnListName(tree.Name)
		if name == "" || ver == "" {
			continue
		}
		parentPURL := makePURL(name, ver)
		nodes[parentPURL] = true
		for _, ch := range tree.Children {
			cn, crange := splitYarnListName(ch.Name)
			if cn == "" {
				continue
			}
			cv, ok := table[cn+"@"+crange]
			if !ok {
				unresolved = append(unresolved, cn+"@"+crange)
				continue
			}
			edges[edgeKey(parentPURL, makePURL(cn, cv))] = true
		}
	}
	if len(unresolved) > 0 {
		sort.Strings(unresolved)
		t.Fatalf("yarn-classic: %d child ranges did not resolve against yarn.lock (HAZARD — range/lockfile ambiguity):\n  %s",
			len(unresolved), strings.Join(unresolved, "\n  "))
	}
	return nodes, edges
}

// yarn berry `yarn info --all --json`: NDJSON, one object per line, locators resolved. This
// capture is a PARTIAL enumeration (the workspace root + its direct deps), so Berry C2 is a
// containment check. Each object's `value` is a locator; its Dependencies list resolved locators.
type berryInfoLine struct {
	Value    string `json:"value"`
	Children struct {
		Version      string `json:"Version"`
		Dependencies []struct {
			Descriptor string `json:"descriptor"`
			Locator    string `json:"locator"`
		} `json:"Dependencies"`
	} `json:"children"`
}

// berryLocatorVersion extracts the resolved version from a Berry locator: "…#npm:<ver>" (virtual)
// or "name@npm:<ver>" (plain).
func berryLocatorVersion(loc string) string {
	if i := strings.Index(loc, "#npm:"); i >= 0 {
		return loc[i+len("#npm:"):]
	}
	if i := strings.Index(loc, "@npm:"); i >= 0 {
		return loc[i+len("@npm:"):]
	}
	return ""
}

func parseBerryInfo(t *testing.T, data []byte) (nodes, edges map[string]bool) {
	t.Helper()
	nodes, edges = map[string]bool{}, map[string]bool{}
	for _, raw := range strings.Split(string(data), "\n") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var line berryInfoLine
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("parse berry info line: %v\n  line=%s", err, raw)
		}
		isRoot := strings.Contains(line.Value, "@workspace:")
		parentName := berryDescriptorName(line.Value)
		parentPURL := makePURL(parentName, line.Children.Version)
		if !isRoot {
			nodes[parentPURL] = true
		}
		for _, dep := range line.Children.Dependencies {
			cn := berryDescriptorName(dep.Locator)
			cv := berryLocatorVersion(dep.Locator)
			if cn == "" || cv == "" {
				continue
			}
			cp := makePURL(cn, cv)
			nodes[cp] = true
			if !isRoot {
				edges[edgeKey(parentPURL, cp)] = true
			}
		}
	}
	return nodes, edges
}

// ---- C2: per-dialect differential ------------------------------------------

func TestInventory_C2_NpmExpress(t *testing.T) {
	inv := resolveDir(t, filepath.Join(captureDir, "npm-express"))
	nNodes, nEdges := parseNpmLs(t, captureFile(t, "npm-express", "native.json"))
	rNodes, rEdges := riSets(inv)
	assertEqualSets(t, "npm-express nodes", nNodes, rNodes)
	assertEqualSets(t, "npm-express edges", nEdges, rEdges)
}

// npm-workspace: the members @cap/a, @cap/b are file:-linked workspace packages installed at
// packages/* paths. ResolveInventory's npm adapter emits every member and every hoisted transitive
// as nodes, plus every edge — both the transitive edges among hoisted node_modules packages AND
// the member→direct-dep edges. A member's declared deps are recorded inline in its lockfile entry
// and resolved by the hoisting walk from the member's own install path, so the full edge set now
// matches native exactly (the four member-origin edges are no longer silently omitted).
func TestInventory_C2_NpmWorkspace(t *testing.T) {
	inv := resolveDir(t, filepath.Join(captureDir, "npm-workspace"))
	nNodes, nEdges := parseNpmLs(t, captureFile(t, "npm-workspace", "native.json"))
	rNodes, rEdges := riSets(inv)

	assertEqualSets(t, "npm-workspace nodes", nNodes, rNodes)
	assertEqualSets(t, "npm-workspace edges", nEdges, rEdges)

	// The four member→dep edges must be present (the gap this fix closed).
	members := map[string]bool{
		makePURL("@cap/a", "1.0.0"): true,
		makePURL("@cap/b", "1.0.0"): true,
	}
	memberEdges := 0
	for e := range rEdges {
		if members[strings.SplitN(e, " -> ", 2)[0]] {
			memberEdges++
		}
	}
	if memberEdges != 4 {
		t.Errorf("npm-workspace: expected 4 member→dep edges, got %d: %v", memberEdges, keys(rEdges))
	}
}

func TestInventory_C2_PnpmExpress(t *testing.T) {
	inv := resolveDir(t, filepath.Join(captureDir, "pnpm-express"))
	nNodes, nEdges := parsePnpmList(t, captureFile(t, "pnpm-express", "native.json"))
	rNodes, rEdges := riSets(inv)
	assertEqualSets(t, "pnpm-express nodes", nNodes, rNodes)
	assertEqualSets(t, "pnpm-express edges", nEdges, rEdges)
}

// pnpm-peer: the (name,version) multiset and edges match native at PURL granularity (the peer
// suffix is flattened by `pnpm list` and stripped from RI edge endpoints by purlOfID). The suffix
// itself is validated in TestInventory_PnpmPeer_ScopeSuffix.
func TestInventory_C2_PnpmPeer(t *testing.T) {
	inv := resolveDir(t, filepath.Join(captureDir, "pnpm-peer"))
	nNodes, nEdges := parsePnpmList(t, captureFile(t, "pnpm-peer", "native.json"))
	rNodes, rEdges := riSets(inv)
	assertEqualSets(t, "pnpm-peer nodes", nNodes, rNodes)
	assertEqualSets(t, "pnpm-peer edges", nEdges, rEdges)
}

func TestInventory_C2_YarnClassic(t *testing.T) {
	inv := resolveDir(t, filepath.Join(captureDir, "yarn-classic"))
	nNodes, nEdges := parseYarnList(t, captureFile(t, "yarn-classic", "native.json"), captureFile(t, "yarn-classic", "yarn.lock"))
	rNodes, rEdges := riSets(inv)
	assertEqualSets(t, "yarn-classic nodes", nNodes, rNodes)
	assertEqualSets(t, "yarn-classic edges", nEdges, rEdges)
}

// yarn-berry: `yarn info --all --json` here enumerates only the workspace root + its direct deps
// (not a recursive tree), so C2 is a containment check — every instance and edge the native oracle
// asserts must be present in the (full-closure) inventory.
func TestInventory_C2_YarnBerry(t *testing.T) {
	inv := resolveDir(t, filepath.Join(captureDir, "yarn-berry-virtual"))
	nNodes, nEdges := parseBerryInfo(t, captureFile(t, "yarn-berry-virtual", "native.json"))
	rNodes, rEdges := riSets(inv)
	assertNativeSubset(t, "yarn-berry nodes", nNodes, rNodes)
	assertNativeSubset(t, "yarn-berry edges", nEdges, rEdges)
}

// ---- Deliverable 1: verified Yarn Berry adapter (lifts F1) -------------------

// TestInventory_YarnBerry_F1 verifies the Berry adapter against the F1 specimen (Yarn 4.18.0,
// nodeLinker: node-modules). It confirms: (a) react-dom resolves to 18.2.0; (b) it carries a
// peer-differentiated resolution_scope suffix derived from the resolved peer set (react@18.2.0),
// lockfile-derivable and identical to the pnpm grammar; (c) the node and its outgoing edges share
// that suffixed ID (internally consistent — no dangling endpoint); and (d) berryVirtualToken
// extracts the exact virtual-locator token that actually appears in the native `yarn info` output
// (128 hex chars — SHA-512 — not the 64 the provisional contract note assumed).
func TestInventory_YarnBerry_F1(t *testing.T) {
	inv := resolveDir(t, filepath.Join(captureDir, "yarn-berry-virtual"))

	const wantID = "pkg:npm/react-dom@18.2.0?resolution_scope=%28react%4018.2.0%29"
	node, ok := findNode(inv, wantID)
	if !ok {
		t.Fatalf("F1: expected peer-scoped react-dom node %q; got %v", wantID, nodeIDs(inv))
	}
	if node.PURL != "pkg:npm/react-dom@18.2.0" || node.Version != "18.2.0" {
		t.Errorf("F1: react-dom PURL/version = %q / %q, want pkg:npm/react-dom@18.2.0 / 18.2.0", node.PURL, node.Version)
	}
	// The peer instance must be internally consistent: its edges use the suffixed ID, and both
	// endpoints resolve to real nodes (the pnpm-v9 failure mode this adapter avoids).
	if countEdges(inv, "pkg:npm/loose-envify@1.4.0") == 0 || !hasDepEdge(inv, wantID, "pkg:npm/loose-envify@1.4.0") {
		t.Errorf("F1: expected edge react-dom(scoped) -> loose-envify@1.4.0; edges=%v", inv.Edges)
	}
	ids := map[string]bool{}
	for _, n := range inv.Nodes {
		ids[n.ID] = true
	}
	for _, e := range inv.Edges {
		if !ids[e.Parent] || !ids[e.Child] {
			t.Errorf("F1: dangling edge endpoint %s -> %s (peer instance must be a node)", e.Parent, e.Child)
		}
	}

	// Confirm the virtual-locator token spelling against the real native capture. The virtual
	// locator lives ONLY in `yarn info` output (not the node-modules yarn.lock), so it is read
	// from native.json and passed through berryVirtualToken.
	loc := reactDomVirtualLocator(t, captureFile(t, "yarn-berry-virtual", "native.json"))
	token := berryVirtualToken(loc)
	if !strings.HasPrefix(token, "virtual:") {
		t.Fatalf("F1: berryVirtualToken(%q) = %q, want a virtual: token", loc, token)
	}
	hash := strings.TrimPrefix(token, "virtual:")
	if len(hash) != 128 || !isHex(hash) {
		t.Errorf("F1: virtual hash = %q (len %d); want 128 hex chars (SHA-512)", hash, len(hash))
	}
	if got := berryLocatorVersion(loc); got != "18.2.0" {
		t.Errorf("F1: locator version = %q, want 18.2.0 (the #npm: suffix)", got)
	}
}

// reactDomVirtualLocator pulls react-dom's virtual locator string out of the native `yarn info`
// NDJSON so the token-spelling assertion runs against the real specimen, not a hand-typed literal.
func reactDomVirtualLocator(t *testing.T, native []byte) string {
	t.Helper()
	for _, raw := range strings.Split(string(native), "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var line berryInfoLine
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			continue
		}
		for _, dep := range line.Children.Dependencies {
			if strings.HasPrefix(dep.Locator, "react-dom@virtual:") {
				return dep.Locator
			}
		}
	}
	t.Fatal("F1: react-dom virtual locator not found in native capture")
	return ""
}

// ---- Deliverable 3: pnpm-peer resolution_scope suffix -----------------------

// TestInventory_PnpmPeer_ScopeSuffix validates the peer-differentiated resolution_scope suffix for
// react-dom against the real pnpm v9 capture, replacing the hand-authored F6 fixture's role. The
// token is the parenthesized peer set of the lockfile snapshots: key react-dom@18.2.0(react@18.2.0)
// → ?resolution_scope=%28react%4018.2.0%29. Under pnpm lockfileVersion 9.0 the peer suffix lives in
// the `snapshots:` key while `packages:` keys are suffix-stripped; the adapter emits one node per
// `snapshots:` key (joining `packages:` for metadata), so this suffixed identity is a real node —
// the node-vs-edge reconciliation is asserted in TestInventory_PnpmV9PeerNode.
func TestInventory_PnpmPeer_ScopeSuffix(t *testing.T) {
	inv := resolveDir(t, filepath.Join(captureDir, "pnpm-peer"))
	const scopedID = "pkg:npm/react-dom@18.2.0?resolution_scope=%28react%4018.2.0%29"

	// The lockfile snapshots: key is the authoritative source of the token.
	lock := string(captureFile(t, "pnpm-peer", "pnpm-lock.yaml"))
	if !strings.Contains(lock, "react-dom@18.2.0(react@18.2.0):") {
		t.Fatal("pnpm-peer: expected snapshots key react-dom@18.2.0(react@18.2.0) in the lockfile")
	}

	present := false
	for _, e := range inv.Edges {
		if e.Parent == scopedID {
			present = true
			break
		}
	}
	if !present {
		t.Errorf("pnpm-peer: peer-differentiated id %q absent from inventory; edges=%v", scopedID, inv.Edges)
	}
	// The base package is one instance in this fixture (one react → one peer set).
	if got := countByPURL(inv, "pkg:npm/react-dom@18.2.0"); got != 1 {
		t.Errorf("pnpm-peer: expected one react-dom@18.2.0 instance, got %d", got)
	}
}

// TestInventory_PnpmV9PeerNode verifies the pnpm lockfileVersion 9.0 peer-instance fix: the
// adapter emits one node per `snapshots:` key (the authoritative per-resolved-instance block),
// joining `packages:` for metadata, so the peer-scoped react-dom instance is a real node — not a
// dangling edge endpoint. Under v9 the peer suffix lives in the `snapshots:` key while `packages:`
// keys are suffix-stripped; before the fix nodes were keyed off `packages:` (bare) and edges off
// `snapshots:` (suffixed), leaving the suffixed identity on edge endpoints with no matching node.
func TestInventory_PnpmV9PeerNode(t *testing.T) {
	inv := resolveDir(t, filepath.Join(captureDir, "pnpm-peer"))
	const scopedID = "pkg:npm/react-dom@18.2.0?resolution_scope=%28react%4018.2.0%29"

	node, ok := findNode(inv, scopedID)
	if !ok {
		t.Fatalf("pnpm-v9: expected peer-scoped react-dom node %q; got %v", scopedID, nodeIDs(inv))
	}
	if node.PURL != "pkg:npm/react-dom@18.2.0" || node.Version != "18.2.0" {
		t.Errorf("pnpm-v9: react-dom PURL/version = %q / %q, want pkg:npm/react-dom@18.2.0 / 18.2.0", node.PURL, node.Version)
	}

	// Every edge endpoint must correspond to an emitted node — zero dangling endpoints.
	ids := map[string]bool{}
	for _, n := range inv.Nodes {
		ids[n.ID] = true
	}
	for _, e := range inv.Edges {
		if !ids[e.Parent] || !ids[e.Child] {
			t.Errorf("pnpm-v9: dangling edge endpoint %s -> %s (peer instance must be a node)", e.Parent, e.Child)
		}
	}
}

// ---- small helpers ----------------------------------------------------------

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
