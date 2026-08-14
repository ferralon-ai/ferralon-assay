package jsanalysis

// inventory_test.go grades the whole-graph resolver against the PLAN-160 convergence criteria
// (02-convergence.md C1/C3/C4/C5/C6). C2 (differential-vs-native) and the verified Yarn Berry
// adapter now run against the committed native package-manager captures — see
// inventory_c2_test.go (TestInventory_C2_* and TestInventory_YarnBerry_F1).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const (
	// corpus fixtures reused (relative to this package dir → repo root/corpus).
	expressPnpmDir = "../../../corpus/testdata/repros/CVE-2024-29041-installed-unreachable"
	yarnJsdomDir   = "../../../corpus/testdata/repros/CVE-2023-26136-reachable-transitive"

	invDir = "testdata/inventory"
)

// --- helpers ----------------------------------------------------------------

func resolveDir(t *testing.T, dir string) plugin.DependencyInventory {
	t.Helper()
	inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("ResolveInventory(%s): %v", dir, err)
	}
	return inv
}

func findNode(inv plugin.DependencyInventory, id string) (plugin.DependencyNode, bool) {
	for _, n := range inv.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return plugin.DependencyNode{}, false
}

func hasNode(inv plugin.DependencyInventory, id string) bool {
	_, ok := findNode(inv, id)
	return ok
}

func hasDepEdge(inv plugin.DependencyInventory, parent, child string) bool {
	for _, e := range inv.Edges {
		if e.Parent == parent && e.Child == child {
			return true
		}
	}
	return false
}

func countEdges(inv plugin.DependencyInventory, child string) int {
	n := 0
	for _, e := range inv.Edges {
		if e.Child == child {
			n++
		}
	}
	return n
}

func countByPURL(inv plugin.DependencyInventory, purl string) int {
	n := 0
	for _, node := range inv.Nodes {
		if node.PURL == purl {
			n++
		}
	}
	return n
}

// allReasons collects every declared partiality reason across the graph and all nodes.
func allReasons(inv plugin.DependencyInventory) map[string]bool {
	out := make(map[string]bool)
	for _, r := range inv.Partiality.Reasons {
		out[r] = true
	}
	for _, n := range inv.Nodes {
		for _, r := range n.Partiality.Reasons {
			out[r] = true
		}
	}
	return out
}

func nodeHasReason(n plugin.DependencyNode, reason string) bool {
	for _, r := range n.Partiality.Reasons {
		if r == reason {
			return true
		}
	}
	return false
}

// --- C1: every §4.1 field is populated (non-vacuous) -------------------------

// TestInventory_C1_FieldsPopulated asserts that every §4.1 field the contract can populate
// from metadata is non-zero on at least one node, aggregated across the fixtures named in
// execution/c1-field-map.md. This is NOT the vacuous "the field exists on the type" check that
// PLAN-000 already established — it runs the real resolver and requires real values.
func TestInventory_C1_FieldsPopulated(t *testing.T) {
	express := resolveDir(t, expressPnpmDir)
	ws := resolveDir(t, filepath.Join(invDir, "pnpm-workspaces"))
	platform := resolveDir(t, filepath.Join(invDir, "npm-platform"))
	npm := resolveDir(t, filepath.Join(invDir, "npm-transitive"))

	all := append(append(append([]plugin.DependencyNode{}, express.Nodes...), ws.Nodes...), platform.Nodes...)
	all = append(all, npm.Nodes...)

	checks := map[string]func(plugin.DependencyNode) bool{
		"ID":                        func(n plugin.DependencyNode) bool { return n.ID != "" },
		"PURL":                      func(n plugin.DependencyNode) bool { return n.PURL != "" },
		"Version":                   func(n plugin.DependencyNode) bool { return n.Version != "" },
		"Direct(true)":              func(n plugin.DependencyNode) bool { return n.Direct },
		"Membership.Project":        func(n plugin.DependencyNode) bool { return n.Membership.Project != "" },
		"Membership.Workspace":      func(n plugin.DependencyNode) bool { return n.Membership.Workspace != "" },
		"Membership.Target":         func(n plugin.DependencyNode) bool { return n.Membership.Target != "" },
		"Artifact.Identity":         func(n plugin.DependencyNode) bool { return n.Artifact.Identity != "" },
		"Artifact.Digest":           func(n plugin.DependencyNode) bool { return n.Artifact.Digest != "" },
		"Provenance.Manifest":       func(n plugin.DependencyNode) bool { return n.Provenance.Manifest != "" },
		"Provenance.Lockfile":       func(n plugin.DependencyNode) bool { return n.Provenance.Lockfile != "" },
		"Provenance.Resolver":       func(n plugin.DependencyNode) bool { return n.Provenance.Resolver != "" },
		"Provenance.Runtime":        func(n plugin.DependencyNode) bool { return n.Provenance.Runtime != "" },
		"Node.Partiality(declared)": func(n plugin.DependencyNode) bool { return !n.Partiality.Complete },
	}
	for field, ok := range checks {
		found := false
		for _, n := range all {
			if ok(n) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("C1: no node populates %s across the fixture set (vacuity guard)", field)
		}
	}

	// The parent-edge reference (§4.1) must be present and reference real node IDs.
	if len(express.Edges) == 0 {
		t.Error("C1: express inventory has no parent edges")
	}
	for _, e := range express.Edges {
		if !hasNode(express, e.Parent) || !hasNode(express, e.Child) {
			t.Errorf("C1: edge %v references a missing node endpoint", e)
		}
	}

	// Digest must be algorithm-prefixed (sha512:…), not raw SRI (sha512-…).
	dn, _ := findNode(express, "pkg:npm/ms@2.0.0")
	if !strings.HasPrefix(dn.Artifact.Digest, "sha512:") {
		t.Errorf("C1: ms@2.0.0 digest = %q, want sha512: prefix", dn.Artifact.Digest)
	}
}

// --- C3: instance-key distinctness ------------------------------------------

// TestInventory_C3i_TwoVersionsDistinct_pnpm covers C3(i) via the reused express fixture: two
// versions of ms are two distinct nodes reached by distinct parents.
func TestInventory_C3i_TwoVersionsDistinct_pnpm(t *testing.T) {
	inv := resolveDir(t, expressPnpmDir)
	if !hasNode(inv, "pkg:npm/ms@2.0.0") || !hasNode(inv, "pkg:npm/ms@2.1.3") {
		t.Fatalf("C3(i): expected both ms@2.0.0 and ms@2.1.3 nodes")
	}
	if !hasDepEdge(inv, "pkg:npm/debug@2.6.9", "pkg:npm/ms@2.0.0") {
		t.Error("C3(i): missing edge debug@2.6.9 -> ms@2.0.0")
	}
	if !hasDepEdge(inv, "pkg:npm/send@0.18.0", "pkg:npm/ms@2.1.3") {
		t.Error("C3(i): missing edge send@0.18.0 -> ms@2.1.3")
	}
}

// TestInventory_C3i_TwoVersionsDistinct_npm covers C3(i) via the npm diamond fixture (F3).
func TestInventory_C3i_TwoVersionsDistinct_npm(t *testing.T) {
	inv := resolveDir(t, filepath.Join(invDir, "npm-diamond"))
	if !hasNode(inv, "pkg:npm/ms@2.0.0") || !hasNode(inv, "pkg:npm/ms@2.1.3") {
		t.Fatalf("C3(i) npm: expected both ms@2.0.0 and ms@2.1.3 nodes; got %v", nodeIDs(inv))
	}
	if !hasDepEdge(inv, "pkg:npm/debug@2.6.9", "pkg:npm/ms@2.0.0") {
		t.Error("C3(i) npm: missing edge debug@2.6.9 -> ms@2.0.0")
	}
	if !hasDepEdge(inv, "pkg:npm/send@0.18.0", "pkg:npm/ms@2.1.3") {
		t.Error("C3(i) npm: missing edge send@0.18.0 -> ms@2.1.3")
	}
}

// TestInventory_C3ii_SharedNode covers C3(ii): the negative control. One hoisted version reached
// by two paths is ONE node with TWO distinct parent edges.
func TestInventory_C3ii_SharedNode(t *testing.T) {
	inv := resolveDir(t, filepath.Join(invDir, "npm-shared"))
	const shared = "pkg:npm/shared-lib@2.0.0"
	if got := countByPURL(inv, shared); got != 1 {
		t.Fatalf("C3(ii): shared-lib@2.0.0 must be exactly ONE node; got %d", got)
	}
	if !hasDepEdge(inv, "pkg:npm/pkg-a@1.0.0", shared) || !hasDepEdge(inv, "pkg:npm/pkg-b@1.0.0", shared) {
		t.Errorf("C3(ii): expected two distinct parent edges into shared-lib; edges=%v", inv.Edges)
	}
	if got := countEdges(inv, shared); got != 2 {
		t.Errorf("C3(ii): expected 2 edges into shared-lib, got %d", got)
	}
}

// TestInventory_C3iii_PeerScopeDistinct_and_Mutation covers C3(iii) AND the mutation control:
// two same-(name,version) instances with distinct peer scope are TWO nodes whose IDs differ
// only by ?resolution_scope=. Collapsing the ID to (name,version) — i.e. to the PURL — merges
// them, which is exactly what the mutation destroys. The assertion goes red if the suffix is
// dropped (the two IDs would coincide).
func TestInventory_C3iii_PeerScopeDistinct_and_Mutation(t *testing.T) {
	inv := resolveDir(t, filepath.Join(invDir, "pnpm-peerscope"))
	id8 := "pkg:npm/debug@4.3.4?resolution_scope=%28supports-color%408.1.1%29"
	id9 := "pkg:npm/debug@4.3.4?resolution_scope=%28supports-color%409.0.0%29"
	if !hasNode(inv, id8) || !hasNode(inv, id9) {
		t.Fatalf("C3(iii): expected two peer-scoped debug@4.3.4 nodes\n  want %s\n  want %s\n  got %v", id8, id9, nodeIDs(inv))
	}
	if id8 == id9 {
		t.Fatal("C3(iii): the two IDs must be distinct")
	}
	// Mutation control: collapse to (name,version) == collapse to the PURL. Both instances
	// share ONE PURL, so the (name,version) key would merge 2 nodes into 1 — the property the
	// resolution-scope suffix exists to preserve (PLAN-165/260 inherit it).
	if got := countByPURL(inv, "pkg:npm/debug@4.3.4"); got != 2 {
		t.Fatalf("C3(iii) mutation control: two distinct IDs must share one PURL (collapse merges 2->1); countByPURL=%d", got)
	}
	// The distinct peer edges must survive too.
	if !hasDepEdge(inv, "pkg:npm/consumer-a@1.0.0", id8) || !hasDepEdge(inv, "pkg:npm/consumer-b@1.0.0", id9) {
		t.Errorf("C3(iii): expected distinct consumer->debug edges; edges=%v", inv.Edges)
	}
}

// TestInventory_NpmDistinctClosure_MintsSuffixedIDs is the A3 #3 fix: two same-(name,version) npm
// installs nested under distinct parents with DISTINCT resolved closures (debug->ms vs
// debug->supports-color, the npm peer-conflict-nesting shape) are semantically distinct instances
// and must NOT collapse to one node. Before the fix the npm adapter emitted a bare PURL for both,
// dedupByID merged them into one node with unioned edges and no partiality — a §3 preserve-Partiality
// violation. Now each distinct-closure instance carries an install-path resolution-scope suffix, so
// the instances stay distinct while sharing one PURL (the identity PLAN-165/260 inherit).
func TestInventory_NpmDistinctClosure_MintsSuffixedIDs(t *testing.T) {
	inv := resolveDir(t, filepath.Join(invDir, "npm-distinct-closure"))
	const debug = "pkg:npm/debug@4.3.4"

	// Two distinct instances, not a silent merge.
	if got := countByPURL(inv, debug); got != 2 {
		t.Fatalf("#3: distinct-closure debug@4.3.4 must be TWO nodes (was silently merged to 1 pre-fix); got %d", got)
	}
	// Each instance carries a resolution-scope suffix (no bare PURL), and the two differ — so the
	// mutation "collapse the ID to its PURL" merges 2->1, exactly the property PLAN-165/260 inherit.
	var ids []string
	for _, n := range inv.Nodes {
		if n.PURL == debug {
			ids = append(ids, n.ID)
			if n.ID == debug {
				t.Errorf("#3: a distinct-closure instance must carry a scope suffix, got bare PURL %q", n.ID)
			}
		}
	}
	if len(ids) == 2 && ids[0] == ids[1] {
		t.Fatalf("#3: the two distinct-closure instances must have DISTINCT ids; both = %q", ids[0])
	}
	// Both distinct closures are represented — each debug instance edges to its own child.
	if countEdges(inv, "pkg:npm/ms@2.1.3") < 1 || countEdges(inv, "pkg:npm/supports-color@9.0.0") < 1 {
		t.Errorf("#3: expected both closures (ms + supports-color) represented as edges; edges=%v", inv.Edges)
	}
}

// --- C4: workspaces resolve to per-member subgraphs, decline path gone -------

func TestInventory_C4_WorkspacesPerMember(t *testing.T) {
	inv := resolveDir(t, filepath.Join(invDir, "pnpm-workspaces"))

	// One project record per workspace member.
	app := "pkg:npm/app@1.0.0"
	lib := "pkg:npm/lib@1.0.0"
	if !hasNode(inv, app) || !hasNode(inv, lib) {
		t.Fatalf("C4: expected member nodes app and lib; got %v", nodeIDs(inv))
	}

	// Per-member direct dependencies (edges from each member to its own declared deps).
	leftPad := "pkg:npm/left-pad@1.3.0"
	if !hasDepEdge(inv, app, leftPad) || !hasDepEdge(inv, app, "pkg:npm/is-odd@3.0.1") || !hasDepEdge(inv, app, "pkg:npm/rimraf@5.0.0") {
		t.Errorf("C4: app member is missing a direct-dep edge; edges=%v", inv.Edges)
	}
	if !hasDepEdge(inv, lib, leftPad) {
		t.Errorf("C4: lib member is missing its left-pad direct-dep edge")
	}

	// Hoisted-dep attribution: left-pad is ONE node, attributed to BOTH declaring members
	// (two edges), NOT to the root alone.
	if got := countByPURL(inv, leftPad); got != 1 {
		t.Errorf("C4: left-pad must be one node, got %d", got)
	}
	if !hasDepEdge(inv, app, leftPad) || !hasDepEdge(inv, lib, leftPad) {
		t.Error("C4: hoisted left-pad must be attributed to the members that declare it")
	}
	if hasDepEdge(inv, "pkg:npm/ws-root@1.0.0", leftPad) {
		t.Error("C4: root must NOT be credited with a dep only the members declare")
	}

	// Transitive edge within a member subgraph.
	if !hasDepEdge(inv, "pkg:npm/is-odd@3.0.1", "pkg:npm/is-number@6.0.0") {
		t.Error("C4: missing transitive edge is-odd -> is-number")
	}

	// devDependency scope + workspace membership populated on a member node.
	rimraf, _ := findNode(inv, "pkg:npm/rimraf@5.0.0")
	if rimraf.Membership.Target != "dev" {
		t.Errorf("C4: rimraf Membership.Target = %q, want dev", rimraf.Membership.Target)
	}
	if rimraf.Membership.Workspace != "ws-root" {
		t.Errorf("C4: rimraf Membership.Workspace = %q, want ws-root", rimraf.Membership.Workspace)
	}
}

// TestInventory_C4_DeclinePathGone greps manifest.go to confirm the hasWorkspaces early-return
// no longer fires (a lingering decline path would make two code paths disagree about the same
// tree). Complements the behavioural assertion in manifest_test.go.
func TestInventory_C4_DeclinePathGone(t *testing.T) {
	data, err := os.ReadFile("manifest.go")
	if err != nil {
		t.Fatalf("read manifest.go: %v", err)
	}
	src := string(data)
	if strings.Contains(src, "hasWorkspaces(") {
		t.Error("C4: manifest.go still calls hasWorkspaces — the workspaces decline path must be gone")
	}
	if strings.Contains(src, "complicated") {
		t.Error("C4: manifest.go still has the `complicated` decline branch")
	}
}

// --- C5: every unresolvable condition is declared partial, never dropped -----

func TestInventory_C5_GitRefUnpinned(t *testing.T) {
	dir := filepath.Join(invDir, "npm-git")
	inv := resolveDir(t, dir)

	pinned, ok := findNode(inv, "pkg:npm/widget@1.0.0")
	if !ok {
		t.Fatal("C5 git: pinned widget node missing")
	}
	if nodeHasReason(pinned, plugin.PartialReasonGitRefUnpinned) {
		t.Error("C5 git: pinned git dep must NOT be flagged git_ref_unpinned")
	}
	unpinned, ok := findNode(inv, "pkg:npm/gadget@2.0.0")
	if !ok {
		t.Fatal("C5 git: unpinned gadget node missing")
	}
	if !nodeHasReason(unpinned, plugin.PartialReasonGitRefUnpinned) {
		t.Error("C5 git: unpinned git dep must be flagged git_ref_unpinned")
	}
	if pinned.Artifact.Digest != "" {
		t.Error("C5 git: a git dep carries no integrity digest")
	}

	// node-count-changes-when-removed control.
	base := len(inv.Nodes)
	mut := resolveDir(t, mutateNpmDrop(t, dir, "gadget"))
	if len(mut.Nodes) != base-1 {
		t.Errorf("C5 git: removing the unpinned dep must drop one node (%d -> %d)", base, len(mut.Nodes))
	}
	if allReasons(mut)[plugin.PartialReasonGitRefUnpinned] {
		t.Error("C5 git: git_ref_unpinned must disappear once the unpinned dep is removed")
	}
}

func TestInventory_C5_LocalPathDep(t *testing.T) {
	dir := filepath.Join(invDir, "npm-file")
	inv := resolveDir(t, dir)
	if !allReasons(inv)[plugin.PartialReasonLocalPathDep] {
		t.Fatalf("C5 file: expected local_path_dep; reasons=%v", allReasons(inv))
	}
	local, ok := findNode(inv, "pkg:npm/locallib@1.0.0")
	if !ok || !nodeHasReason(local, plugin.PartialReasonLocalPathDep) {
		t.Error("C5 file: locallib node must carry local_path_dep")
	}

	base := len(inv.Nodes)
	mut := resolveDir(t, mutateNpmDrop(t, dir, "locallib"))
	if len(mut.Nodes) != base-1 {
		t.Errorf("C5 file: removing the local dep must drop one node (%d -> %d)", base, len(mut.Nodes))
	}
	if allReasons(mut)[plugin.PartialReasonLocalPathDep] {
		t.Error("C5 file: local_path_dep must disappear once the local dep is removed")
	}
}

func TestInventory_C5_PlatformCondition(t *testing.T) {
	dir := filepath.Join(invDir, "npm-platform")
	inv := resolveDir(t, dir)

	fse, ok := findNode(inv, "pkg:npm/fsevents@2.3.3")
	if !ok || !nodeHasReason(fse, plugin.PartialReasonPlatformCondition) {
		t.Fatal("C5 platform: fsevents must carry platform_condition_unevaluable")
	}
	if fse.Provenance.Target != "" {
		t.Errorf("C5 platform: gated node Target must stay empty (never guessed), got %q", fse.Provenance.Target)
	}
	// Negative control: an un-gated dep does NOT carry the reason.
	lp, _ := findNode(inv, "pkg:npm/left-pad@1.3.0")
	if nodeHasReason(lp, plugin.PartialReasonPlatformCondition) {
		t.Error("C5 platform: un-gated left-pad must NOT carry platform_condition_unevaluable")
	}

	base := len(inv.Nodes)
	mut := resolveDir(t, mutateNpmDrop(t, dir, "fsevents"))
	if len(mut.Nodes) != base-1 {
		t.Errorf("C5 platform: removing the gated dep must drop one node (%d -> %d)", base, len(mut.Nodes))
	}
	if allReasons(mut)[plugin.PartialReasonPlatformCondition] {
		t.Error("C5 platform: platform_condition_unevaluable must disappear once the gated dep is removed")
	}
}

func TestInventory_C5_AliasTargetAbsent(t *testing.T) {
	dir := filepath.Join(invDir, "npm-alias")
	inv := resolveDir(t, dir)

	if !allReasons(inv)[plugin.PartialReasonAliasTargetAbsent] {
		t.Fatalf("C5 alias: expected alias_target_absent; reasons=%v", allReasons(inv))
	}
	// The present alias resolves to its real target with no partiality.
	if !hasNode(inv, "pkg:npm/ms@2.0.0") {
		t.Error("C5 alias: good-alias should resolve to ms@2.0.0")
	}
	// The absent alias yields a declared node carrying the reason.
	ghost, ok := findNode(inv, "pkg:npm/absent-pkg@9.9.9")
	if !ok || !nodeHasReason(ghost, plugin.PartialReasonAliasTargetAbsent) {
		t.Error("C5 alias: absent alias target must yield a node flagged alias_target_absent")
	}

	base := len(inv.Nodes)
	mut := resolveDir(t, mutateNpmDrop(t, dir, "ghost-alias"))
	if len(mut.Nodes) != base-1 {
		t.Errorf("C5 alias: removing the absent alias must drop one node (%d -> %d)", base, len(mut.Nodes))
	}
	if allReasons(mut)[plugin.PartialReasonAliasTargetAbsent] {
		t.Error("C5 alias: alias_target_absent must disappear once the alias is removed")
	}
}

func TestInventory_C5_LockfileAmbiguous(t *testing.T) {
	dir := filepath.Join(invDir, "ambiguous-lock")
	inv := resolveDir(t, dir)
	if !allReasons(inv)[plugin.PartialReasonLockfileAmbiguous] {
		t.Fatalf("C5 ambiguous: expected lockfile_ambiguous; partiality=%v", inv.Partiality)
	}
	if len(inv.Nodes) != 0 {
		t.Errorf("C5 ambiguous: a root with two dialects and no signal emits NO nodes, got %d", len(inv.Nodes))
	}

	// Removing one lockfile makes the root resolvable (single dialect) → nodes appear.
	mut := resolveDir(t, copyNpmOnly(t, dir))
	if allReasons(mut)[plugin.PartialReasonLockfileAmbiguous] {
		t.Error("C5 ambiguous: reason must clear once only one dialect remains")
	}
	if !hasNode(mut, "pkg:npm/ms@2.0.0") {
		t.Error("C5 ambiguous: with only package-lock.json, ms@2.0.0 must resolve")
	}
}

// TestInventory_PeerMetadataAbsent exercises the peer_metadata_absent path (Yarn Classic omits
// peer relationships): the declared peer carries the reason, an ordinary dependency does not.
func TestInventory_PeerMetadataAbsent(t *testing.T) {
	inv := resolveDir(t, filepath.Join(invDir, "yarn-peer"))
	host, ok := findNode(inv, "pkg:npm/host-lib@1.0.0")
	if !ok || !nodeHasReason(host, plugin.PartialReasonPeerMetadataAbsent) {
		t.Errorf("peer: host-lib must carry peer_metadata_absent; node=%+v", host)
	}
	widget, _ := findNode(inv, "pkg:npm/widget@1.0.0")
	if nodeHasReason(widget, plugin.PartialReasonPeerMetadataAbsent) {
		t.Error("peer: ordinary dependency widget must NOT carry peer_metadata_absent")
	}
}

// TestInventory_YarnClassicReuse resolves the reused Yarn Classic corpus fixture (jsdom), a
// real deep tree with resolutions, confirming the descriptor-table edge resolution on a real
// lockfile.
func TestInventory_YarnClassicReuse(t *testing.T) {
	inv := resolveDir(t, yarnJsdomDir)
	if len(inv.Nodes) == 0 || len(inv.Edges) == 0 {
		t.Fatalf("yarn classic: expected a populated graph; nodes=%d edges=%d", len(inv.Nodes), len(inv.Edges))
	}
	// jsdom is the root's direct dependency; agent-base -> debug@4 is a real descriptor edge.
	if !hasNode(inv, "pkg:npm/jsdom@22.1.0") {
		t.Errorf("yarn classic: expected jsdom@22.1.0 node")
	}
	for _, n := range inv.Nodes {
		if n.Provenance.Resolver != "" && n.Provenance.Resolver != "yarn" {
			t.Errorf("yarn classic: node %s resolver = %q, want yarn", n.ID, n.Provenance.Resolver)
		}
	}
}

// --- C6: determinism (repeat-run sha256, not a golden) ----------------------

// TestInventory_C6_Deterministic runs the resolver repeatedly and diffs a sha256 of the encoded
// inventory. Go randomizes each `range` over a map independently within a single process, so
// two in-process runs already exercise the map-iteration nondeterminism a cross-process diff
// targets: if any map leaked onto the encoding path, the hashes would diverge. Not a checked-in
// golden (which would only pin one process's output).
func TestInventory_C6_Deterministic(t *testing.T) {
	for _, dir := range []string{
		expressPnpmDir,
		filepath.Join(invDir, "npm-diamond"),
		filepath.Join(invDir, "pnpm-workspaces"),
		filepath.Join(invDir, "pnpm-peerscope"),
	} {
		var first string
		for i := 0; i < 8; i++ {
			inv := resolveDir(t, dir)
			b, err := json.Marshal(inv)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			sum := sha256.Sum256(b)
			h := hex.EncodeToString(sum[:])
			if i == 0 {
				first = h
				continue
			}
			if h != first {
				t.Fatalf("C6: non-deterministic encoding for %s (run %d hash %s != %s)", dir, i, h, first)
			}
		}
	}
}

// TestInventory_C6_SortedOutput asserts the explicit sort order (nodes by ID, edges by
// (Parent,Child)) that underpins determinism.
func TestInventory_C6_SortedOutput(t *testing.T) {
	inv := resolveDir(t, expressPnpmDir)
	for i := 1; i < len(inv.Nodes); i++ {
		if inv.Nodes[i-1].ID > inv.Nodes[i].ID {
			t.Errorf("C6: nodes not sorted by ID at %d: %q > %q", i, inv.Nodes[i-1].ID, inv.Nodes[i].ID)
		}
	}
	for i := 1; i < len(inv.Edges); i++ {
		a, b := inv.Edges[i-1], inv.Edges[i]
		if a.Parent > b.Parent || (a.Parent == b.Parent && a.Child > b.Child) {
			t.Errorf("C6: edges not sorted by (Parent,Child) at %d: %v > %v", i, a, b)
		}
	}
}

// --- mutation / control helpers ---------------------------------------------

func nodeIDs(inv plugin.DependencyInventory) []string {
	out := make([]string, 0, len(inv.Nodes))
	for _, n := range inv.Nodes {
		out = append(out, n.ID)
	}
	return out
}

// mutateNpmDrop copies an npm fixture (package.json + package-lock.json) into a temp dir with
// one dependency removed from every dependency map and from the packages tree — the "condition
// removed" control C5 requires.
func mutateNpmDrop(t *testing.T, srcDir, drop string) string {
	t.Helper()
	dst := t.TempDir()

	var pj map[string]any
	readJSON(t, filepath.Join(srcDir, "package.json"), &pj)
	dropFromDepMaps(pj, drop)
	writeJSON(t, filepath.Join(dst, "package.json"), pj)

	var pl map[string]any
	readJSON(t, filepath.Join(srcDir, "package-lock.json"), &pl)
	if pkgs, ok := pl["packages"].(map[string]any); ok {
		for key := range pkgs {
			if key == "node_modules/"+drop || key == drop || strings.HasPrefix(key, "node_modules/"+drop+"/") {
				delete(pkgs, key)
			}
		}
		if root, ok := pkgs[""].(map[string]any); ok {
			dropFromDepMaps(root, drop)
		}
	}
	writeJSON(t, filepath.Join(dst, "package-lock.json"), pl)
	return dst
}

// copyNpmOnly copies just package.json + package-lock.json (dropping any sibling yarn.lock) so
// an ambiguous root becomes single-dialect.
func copyNpmOnly(t *testing.T, srcDir string) string {
	t.Helper()
	dst := t.TempDir()
	for _, name := range []string{"package.json", "package-lock.json"} {
		data, err := os.ReadFile(filepath.Join(srcDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dst, name), data, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dst
}

func dropFromDepMaps(m map[string]any, drop string) {
	for _, k := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		if dm, ok := m[k].(map[string]any); ok {
			delete(dm, drop)
		}
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
