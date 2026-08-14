package goanalysis

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveInventory resolves the whole SELECTED dependency graph of the Go module
// rooted at req.BuildDir (§4.1), the first real implementation of the operation
// PLAN-000 declared. It is emphatically NOT a scan of go.mod's `require` block:
// the require list is not the build list (minimal version selection can raise a
// version above every stated require, `replace`/`exclude` redirect selections, and
// module-graph pruning omits transitive requirements from the main module's block).
//
// Authoritative source (PLAN-102 A5): the native module requirement graph from
// `go mod graph`, reconciled with go.mod parsed via modfile. That pairing is the
// only one that (a) survives vendoring — `go list -m all` cannot compute `all`
// under -mod=vendor, and half the Go repro corpus is vendored — and (b) carries
// parent edges, which §8 checkbox 2 makes mandatory. `go/packages` is deliberately
// not used: it is import-reachability-shaped and omits a module the build selects
// but no loaded package imports.
//
// What the toolchain is run for matters for §3.3/§10.1 (C4): `go mod graph` RESOLVES
// and reads metadata — it type-checks and runs no target code (no `go run`, `go
// generate`, `go test`, or build-for-execution). It is the only subprocess this
// resolver adds.
//
// Honest absence (§3.1/§3.6, C3): "go.mod absent or unparseable, so nothing was
// established" and "go.mod read cleanly and requires nothing" are DIFFERENT
// outcomes — the former declares graph-level partiality, the latter is a Complete()
// zero-node inventory. Collapsing them would make a whole-graph resolver less honest
// than the single-coordinate moduleVersionFromGoMod it augments, and would make a
// later CVE-watch read "we could not resolve this" as "this dependency is absent".
func ResolveInventory(ctx context.Context, req plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	if fi, err := os.Stat(req.BuildDir); err != nil || !fi.IsDir() {
		// No buildable directory: a hard error (inv.4), never a silent empty graph.
		if err == nil {
			err = &os.PathError{Op: "stat", Path: req.BuildDir, Err: os.ErrInvalid}
		}
		return plugin.DependencyInventory{}, err
	}

	// --- read + parse the manifest (C3 case (i) vs (ii) turns on this) ---
	modPath := filepath.Join(req.BuildDir, "go.mod")
	data, err := os.ReadFile(modPath)
	if err != nil {
		// go.mod absent (or unreadable): nothing was established. Declare it — this
		// is NOT a Complete() zero-node graph, which would claim "no dependencies".
		return plugin.DependencyInventory{Partiality: plugin.Partial(plugin.PartialReasonNoManifest)}, nil
	}
	mf, err := modfile.Parse(modPath, data, nil)
	if err != nil {
		// Unparseable go.mod: a real, distinct honest-absence reading from the clean
		// "requires nothing" case — carries a partiality reason where (ii) does not.
		return plugin.DependencyInventory{Partiality: plugin.Partial(plugin.PartialReasonToolFailure)}, nil
	}

	mainPath := ""
	if mf.Module != nil {
		mainPath = mf.Module.Mod.Path
	}
	goVersion := ""
	if mf.Go != nil {
		goVersion = mf.Go.Version
	}

	var graphReasons []string

	// A go.work root is a multi-module workspace. The plugin entry forces GOWORK=off
	// (correct for the analyzer's own hygiene), so only this single root is resolved;
	// declare the rest rather than silently omit it. PLAN-004's WorkspacePlan closes
	// this in a follow-on (A4).
	if fi, statErr := os.Stat(filepath.Join(req.BuildDir, "go.work")); statErr == nil && !fi.IsDir() {
		graphReasons = append(graphReasons, plugin.PartialReasonUnsupported)
	}

	// --- native module graph: the selected build list + parent edges ---
	edges, err := runModGraph(ctx, req.BuildDir)
	if err != nil {
		// Graph resolution failed (e.g. an unavailable transitive go.mod on a cold
		// cache with the proxy off): surface it, do not fabricate an empty graph.
		graphReasons = append(graphReasons, plugin.PartialReasonToolFailure)
		return plugin.DependencyInventory{Partiality: partiality(graphReasons)}, nil
	}

	// direct set: modfile require markers ARE the native Indirect oracle, offline.
	direct := make(map[string]bool, len(mf.Require))
	for _, r := range mf.Require {
		if !r.Indirect {
			direct[r.Mod.Path] = true
		}
	}

	// replace map: modfile carries what `go mod graph` hides (the redirect target).
	// Keyed by old path; a versioned old-key ("path v1.2.3") wins over a wildcard.
	type replaceTarget struct {
		newPath, newVersion string
		filesystem          bool
	}
	replaces := map[string]replaceTarget{}
	for _, rep := range mf.Replace {
		t := replaceTarget{newPath: rep.New.Path, newVersion: rep.New.Version}
		// A New with no version whose path is a filesystem path (./ ../ or absolute)
		// is a local replace: the selection is not pinned to a verifiable version.
		if rep.New.Version == "" && (strings.HasPrefix(rep.New.Path, ".") || strings.HasPrefix(rep.New.Path, "/") || filepath.IsAbs(rep.New.Path)) {
			t.filesystem = true
		}
		if rep.Old.Version != "" {
			replaces[rep.Old.Path+" "+rep.Old.Version] = t
		} else {
			replaces[rep.Old.Path] = t
		}
	}

	// go.sum supplies the artifact integrity digest without acquisition (C2 bullet 4).
	sums := readGoSum(filepath.Join(req.BuildDir, "go.sum"))
	haveLockfile := len(sums) > 0
	lockfile := ""
	if haveLockfile {
		lockfile = "go.sum"
	}

	// --- collect the selected version of every dependency module ---
	// Minimal version selection: the selected version is the max over every version
	// at which the module appears in the requirement graph. In a pruned graph each
	// module appears once at its selected version; the max is a safety net for the
	// unpruned (pre-1.17) case.
	selected := map[string]string{} // path -> selected version (original graph label)
	consider := func(tok graphNode) {
		if tok.version == "" || isToolchainPseudo(tok.path) || tok.path == mainPath {
			return
		}
		if cur, ok := selected[tok.path]; !ok || semver.Compare(tok.version, cur) > 0 {
			selected[tok.path] = tok.version
		}
	}
	for _, e := range edges {
		consider(e.from)
		consider(e.to)
	}

	// --- build one node per selected dependency module ---
	// pathID maps a module PATH to its single selected Node.ID. Edge endpoints map by
	// path, not path@version: minimal version selection collapses every version of a
	// module in the graph to the one selected version, so an edge stated at a
	// superseded version (low→common@v1.1.0) resolves to the selected node
	// (common@v1.2.0). A replace rewriting the version does not disturb this.
	pathID := make(map[string]string, len(selected))
	nodes := make([]plugin.DependencyNode, 0, len(selected))
	for path, ver := range selected {
		n := plugin.DependencyNode{
			Version:    ver,
			Direct:     direct[path],
			Membership: plugin.DependencyMembership{Project: mainPath},
			Provenance: plugin.DependencyProvenance{
				Manifest: "go.mod",
				Lockfile: lockfile,
				Resolver: "go mod",
				Runtime:  runtimeLabel(goVersion),
			},
		}

		var nodeReasons []string

		// Apply a replace (versioned key first, then wildcard) — the redirect the
		// graph does not show. A filesystem replace has no verifiable version.
		if rep, ok := replaces[path+" "+ver]; ok {
			applyReplace(&n, rep.newPath, rep.newVersion, rep.filesystem, &nodeReasons)
		} else if rep, ok := replaces[path]; ok {
			applyReplace(&n, rep.newPath, rep.newVersion, rep.filesystem, &nodeReasons)
		}

		n.PURL = goPURL(path, n.Version)
		n.ID = n.PURL

		// Artifact identity + digest from go.sum (no acquisition). Absent digest is
		// declared partial (source_unpinned) at the artifact bullet, never blank-posing.
		if dig, ok := sums[path+" "+n.Version]; ok && n.Version != "" {
			n.Artifact = plugin.DependencyArtifact{Identity: path + "@" + n.Version, Digest: dig}
		} else if !contains(nodeReasons, plugin.PartialReasonSourceUnpinned) {
			nodeReasons = append(nodeReasons, plugin.PartialReasonSourceUnpinned)
		}

		n.Partiality = partiality(nodeReasons)
		nodes = append(nodes, n)
		pathID[path] = n.ID
	}

	// --- edges between two dependency nodes (main-incident + pseudo edges dropped) ---
	edgeSet := map[plugin.DependencyEdge]struct{}{}
	for _, e := range edges {
		pid, pok := pathID[e.from.path]
		cid, cok := pathID[e.to.path]
		if !pok || !cok || pid == cid {
			continue
		}
		edgeSet[plugin.DependencyEdge{Parent: pid, Child: cid}] = struct{}{}
	}
	depEdges := make([]plugin.DependencyEdge, 0, len(edgeSet))
	for e := range edgeSet {
		depEdges = append(depEdges, e)
	}

	// --- deterministic ordering (C6): no map is an iteration source on the output ---
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	sort.Slice(depEdges, func(i, j int) bool {
		if depEdges[i].Parent != depEdges[j].Parent {
			return depEdges[i].Parent < depEdges[j].Parent
		}
		return depEdges[i].Child < depEdges[j].Child
	})

	inv := plugin.DependencyInventory{
		Partiality: partiality(graphReasons),
		Nodes:      nodes,
		Edges:      depEdges,
	}
	return inv, nil
}

// applyReplace rewrites a node to its replace target — the redirect `go mod graph`
// does not surface. A versioned replace (`=> other v1.2.3`) yields a resolved
// version; a filesystem replace (`=> ../dir`) is not pinned to a verifiable version,
// so declare it (source_unpinned) rather than present a fabricated or blank version
// as resolved. The module PATH remains the requiring coordinate (the require still
// names it); only the resolved version and its pinnedness change.
func applyReplace(n *plugin.DependencyNode, newPath, newVersion string, filesystem bool, reasons *[]string) {
	if filesystem {
		n.Version = ""
		*reasons = append(*reasons, plugin.PartialReasonSourceUnpinned)
		return
	}
	if newVersion != "" {
		n.Version = newVersion
	}
	_ = newPath // a module→module replace keeps the requiring path as identity
}

// graphNode is one "path@version" (or bare main-module "path") token of a
// `go mod graph` edge.
type graphNode struct {
	path    string
	version string
}

type graphEdge struct {
	from graphNode
	to   graphNode
}

// runModGraph invokes `go mod graph` in buildDir and parses its edge list. GOWORK
// is forced off so the target module is resolved standalone, never against an
// ambient workspace the analyzer process happens to run inside. This RESOLVES the
// module graph (§3.3 permits it) and executes no target code (C4).
func runModGraph(ctx context.Context, buildDir string) ([]graphEdge, error) {
	cmd := exec.CommandContext(ctx, "go", "mod", "graph")
	cmd.Dir = buildDir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	var edges []graphEdge
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		edges = append(edges, graphEdge{from: parseGraphNode(fields[0]), to: parseGraphNode(fields[1])})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return edges, nil
}

// parseGraphNode splits "path@version" into its parts; a bare token (the main
// module) yields an empty version.
func parseGraphNode(tok string) graphNode {
	if at := strings.LastIndexByte(tok, '@'); at >= 0 {
		return graphNode{path: tok[:at], version: tok[at+1:]}
	}
	return graphNode{path: tok}
}

// isToolchainPseudo reports whether a graph node is one of the synthetic go1.21+
// "go" / "toolchain" pseudo-modules, which are not dependencies.
func isToolchainPseudo(path string) bool { return path == "go" || path == "toolchain" }

// goPURL renders a normalized Go package URL. A version-less module (a filesystem
// replace) yields the bareword form; report.Package.Key() falls back to
// ecosystem:name for it.
func goPURL(path, version string) string {
	if version == "" {
		return "pkg:golang/" + path
	}
	return "pkg:golang/" + path + "@" + version
}

// runtimeLabel renders the resolution's runtime target from the go directive.
func runtimeLabel(goVersion string) string {
	if goVersion == "" {
		return "go"
	}
	return "go" + goVersion
}

// readGoSum parses go.sum into a "path version" -> "h1:hash" map, keeping only the
// module-zip hash (dropping the "/go.mod" lines). A missing or unreadable go.sum
// yields an empty map — the digest is then declared partial per node, never faked.
func readGoSum(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	sums := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 3 {
			continue
		}
		mod, ver, hash := fields[0], fields[1], fields[2]
		if strings.HasSuffix(ver, "/go.mod") {
			continue // the go.mod hash, not the artifact hash
		}
		sums[mod+" "+ver] = hash
	}
	return sums
}

// partiality builds a Partiality from accumulated reasons: Complete when none,
// Partial(reasons) otherwise. Reasons are de-duplicated and order-stable.
func partiality(reasons []string) plugin.Partiality {
	if len(reasons) == 0 {
		return plugin.Complete()
	}
	seen := map[string]bool{}
	var uniq []string
	for _, r := range reasons {
		if !seen[r] {
			seen[r] = true
			uniq = append(uniq, r)
		}
	}
	return plugin.Partial(uniq...)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
