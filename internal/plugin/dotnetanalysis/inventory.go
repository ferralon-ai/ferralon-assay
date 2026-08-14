package dotnetanalysis

// ResolveInventory is the .NET whole-graph dependency resolver (§4.1 / PLAN-150 Build 3a). It
// walks a single project's checkout files LEXICALLY and emits a plugin.DependencyInventory: one
// DependencyNode per resolved package instance, keyed per (project, TFM[, RID], PURL@version),
// with parent edges, membership, integrity digest, and provenance.
//
// It NEVER executes dotnet/MSBuild/NuGet/restore (C5): every populated field traces to a
// concrete parse of a concrete checkout file, and everything it cannot read is a NAMED
// plugin.Partiality — never an inferred version, never an empty Complete() that reads downstream
// as "this build has no dependencies" (§3.6).
//
// Precedence chain (A3), one single-source parser per tier, partiality cumulative and
// monotonically non-decreasing DOWN the chain (C3):
//
//	1. obj/project.assets.json  → full per-TFM/RID graph: versions, edges, direct/transitive,
//	                              sha512 digest, artifact identity            → Complete()
//	2. packages.lock.json       → graph + versions + edges + contentHash, no restore asset/RID
//	                              selection                       → Partial(no_resolver_output)
//	3. declared PackageReference/packages.config text (+ CPM merge) → direct pins only; ranges
//	   and unresolved CPM versions stay UNRESOLVED, conditions named
//	                              → Partial(no_resolver_output, no_lockfile, …)
//	4. nothing parseable        → ZERO nodes, Partial(no_resolver_output, no_lockfile,
//	                              no_manifest) — never an empty Complete()
//
// Scope: single-project, multi-TFM (Build 3a). The multi-PROJECT .sln/ProjectReference walk is
// Build 3b (deferred); a single .csproj/BuildDir is the input surface here.

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveInventory resolves the whole dependency graph for the module rooted at req.BuildDir.
// A missing/unreadable build dir is a hard error (inv.4); every other shortfall is declared
// partiality on the returned inventory.
func ResolveInventory(_ context.Context, req plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.DependencyInventory{}, fmt.Errorf("dotnetanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.DependencyInventory{}, fmt.Errorf("dotnetanalysis: build dir %q is not a directory", req.BuildDir)
	}

	// Build 3b: a .sln (or ≥2 project files) makes this a multi-PROJECT workspace — delegate to the
	// tree-walker, which runs THIS per-project resolver for each member and merges (inventory_multiproject.go).
	// A single project with no .sln falls through to the 3a single-project path unchanged.
	if sln, projects, ok := discoverWorkspace(req.BuildDir); ok {
		return resolveWorkspace(req.BuildDir, sln, projects), nil
	}

	projPath, hasProject := findProjectFile(req.BuildDir)
	projRel := "" // owning project path, relative to the build dir (Membership.Project)
	projDir := req.BuildDir
	if hasProject {
		projDir = filepath.Dir(projPath)
		if rel, rerr := filepath.Rel(req.BuildDir, projPath); rerr == nil {
			projRel = filepath.ToSlash(rel)
		}
	}

	// Tier 1: project.assets.json (restore output). Searched WITHOUT skipping obj/, since that
	// is exactly where restore writes it.
	if assetsPath, ok := findFile(req.BuildDir, "project.assets.json", true); ok {
		if data, rerr := os.ReadFile(assetsPath); rerr == nil {
			if nodes, edges, pok := parseAssets(data, projRel); pok {
				return assemble(nodes, edges, plugin.Complete()), nil
			}
			// Malformed restore output: surface tool_failure, fall to a lower tier.
			return tierFallback(req.BuildDir, projDir, projRel, req.BuildDir, []string{plugin.PartialReasonToolFailure}), nil
		}
	}

	return tierFallback(req.BuildDir, projDir, projRel, req.BuildDir, nil), nil
}

// tierFallback runs the lock → declared-text → nothing tiers, carrying any reasons already
// accumulated at a higher tier (e.g. a malformed assets file's tool_failure). buildDir scopes the
// lock/manifest file search; cpmRoot is the upper bound of the Directory.Packages.props (CPM)
// upward walk — the two DIFFER in the multi-project layer, where the search stays inside each
// project's own tree while CPM discovery must reach the shared solution root (inventory_multiproject.go).
func tierFallback(buildDir, projDir, projRel, cpmRoot string, carried []string) plugin.DependencyInventory {
	// Tier 2: packages.lock.json.
	if lockPath, ok := findFile(buildDir, "packages.lock.json", false); ok {
		if data, rerr := os.ReadFile(lockPath); rerr == nil {
			lockRel := relTo(buildDir, lockPath)
			if nodes, edges, pok := parseLockGraph(data, projRel, lockRel); pok {
				reasons := mergeReasons(carried, reasonNoResolverOutput)
				return assemble(nodes, edges, plugin.Partial(reasons...))
			}
			carried = mergeReasons(carried, plugin.PartialReasonToolFailure)
		}
	}

	// Tier 3: declared PackageReference / packages.config text (+ CPM).
	nodes, extraReasons, hasDeclared, declOK := parseDeclared(buildDir, projDir, projRel, cpmRoot)
	if hasDeclared {
		if !declOK {
			// A declared manifest existed but was structurally unparseable.
			reasons := mergeReasons(carried, reasonNoResolverOutput, reasonNoLockfile, plugin.PartialReasonToolFailure)
			return assemble(nil, nil, plugin.Partial(reasons...))
		}
		reasons := mergeReasons(carried, reasonNoResolverOutput, reasonNoLockfile)
		reasons = mergeReasons(reasons, extraReasons...)
		return assemble(nodes, nil, plugin.Partial(reasons...))
	}

	// Tier 4: nothing parseable. Zero nodes, cumulative reasons + no_manifest — NEVER an empty
	// Complete() (the §3.6 "build has no deps" failure).
	reasons := mergeReasons(carried, reasonNoResolverOutput, reasonNoLockfile, plugin.PartialReasonNoManifest)
	return assemble(nil, nil, plugin.Partial(reasons...))
}

// --- tier 1: project.assets.json ---------------------------------------------

type assetsFile struct {
	Targets                     map[string]map[string]assetsTarget `json:"targets"`
	Libraries                   map[string]assetsLibrary           `json:"libraries"`
	ProjectFileDependencyGroups map[string][]string                `json:"projectFileDependencyGroups"`
}

type assetsTarget struct {
	Type         string            `json:"type"`
	Dependencies map[string]string `json:"dependencies"`
}

type assetsLibrary struct {
	Type   string `json:"type"`
	Path   string `json:"path"`
	Sha512 string `json:"sha512"`
}

// parseAssets builds the per-TFM/RID node+edge graph from a restore's project.assets.json.
// A distinct-scope instance of one package (same PURL under a different TFM or RID) gets a
// distinct Node.ID, so a package present only under net472 can never appear reachable under
// net8.0 (C4 anti-flattening).
func parseAssets(data []byte, projRel string) ([]plugin.DependencyNode, []plugin.DependencyEdge, bool) {
	var af assetsFile
	if err := json.Unmarshal(data, &af); err != nil {
		return nil, nil, false
	}
	var nodes []plugin.DependencyNode
	var edges []plugin.DependencyEdge

	for targetKey, target := range af.Targets {
		tfm, rid := splitTargetKey(targetKey)
		direct := directSet(af.ProjectFileDependencyGroups[tfm])

		// id (lower-cased) → "<id>/<version>" key within THIS target, for edge resolution.
		idIndex := make(map[string]string, len(target))
		for pkgKey, tgt := range target {
			if !strings.EqualFold(tgt.Type, "package") {
				continue // "project" == a ProjectReference (multi-project, Build 3b) — skip.
			}
			id, _ := splitPkgKey(pkgKey)
			if id != "" {
				idIndex[strings.ToLower(id)] = pkgKey
			}
		}

		for pkgKey, tgt := range target {
			if !strings.EqualFold(tgt.Type, "package") {
				continue
			}
			id, ver := splitPkgKey(pkgKey)
			if id == "" || ver == "" {
				continue
			}
			purl := nugetPURL(id, ver)
			nodeID := makeNodeID(projRel, tfm, rid, purl)
			lib := af.Libraries[pkgKey]
			nodes = append(nodes, plugin.DependencyNode{
				ID:      nodeID,
				PURL:    purl,
				Version: ver,
				Direct:  direct[strings.ToLower(id)],
				Membership: plugin.DependencyMembership{
					Project: projRel,
					Target:  tfm,
				},
				Artifact: plugin.DependencyArtifact{
					Identity: lib.Path,
					Digest:   sha512Digest(lib.Sha512),
				},
				Provenance: plugin.DependencyProvenance{
					Manifest: projRel,
					Resolver: "nuget/restore(assets)",
					Runtime:  tfm,
					Target:   rid,
				},
				Partiality: ridPartiality(rid),
			})
			for child := range tgt.Dependencies {
				childKey, ok := idIndex[strings.ToLower(child)]
				if !ok {
					continue // child not present in this target's set — skip (never fabricate).
				}
				cid, cver := splitPkgKey(childKey)
				childID := makeNodeID(projRel, tfm, rid, nugetPURL(cid, cver))
				edges = append(edges, plugin.DependencyEdge{Parent: nodeID, Child: childID})
			}
		}
	}
	return nodes, edges, true
}

// --- tier 2: packages.lock.json ----------------------------------------------

type lockGraph struct {
	Dependencies map[string]map[string]lockGraphEntry `json:"dependencies"`
}

type lockGraphEntry struct {
	Type         string            `json:"type"`
	Resolved     string            `json:"resolved"`
	ContentHash  string            `json:"contentHash"`
	Dependencies map[string]string `json:"dependencies"`
}

// parseLockGraph builds the per-TFM node+edge graph from packages.lock.json: exact resolved
// versions and contentHash digests for both direct and transitive packages, but NO restore
// asset/RID selection (the graph-level no_resolver_output step-down the caller records).
func parseLockGraph(data []byte, projRel, lockRel string) ([]plugin.DependencyNode, []plugin.DependencyEdge, bool) {
	var lg lockGraph
	if err := json.Unmarshal(data, &lg); err != nil {
		return nil, nil, false
	}
	var nodes []plugin.DependencyNode
	var edges []plugin.DependencyEdge

	for tfm, pkgs := range lg.Dependencies {
		index := make(map[string]string, len(pkgs)) // lower(id) → resolved version
		for name, e := range pkgs {
			if strings.EqualFold(e.Type, "Project") {
				continue
			}
			index[strings.ToLower(name)] = e.Resolved
		}
		for name, e := range pkgs {
			if strings.EqualFold(e.Type, "Project") {
				continue // a sibling project reference, not a NuGet package.
			}
			ver := strings.TrimSpace(e.Resolved)
			purl := nugetPURL(name, ver)
			nodeID := makeNodeID(projRel, tfm, "", purl)
			var reasons []string
			if ver == "" {
				reasons = append(reasons, reasonUnresolvedVersionRange)
			}
			reasons = append(reasons, reasonNoRuntimeTarget) // lockfiles carry no RID selection.
			nodes = append(nodes, plugin.DependencyNode{
				ID:      nodeID,
				PURL:    purl,
				Version: ver,
				Direct:  strings.EqualFold(e.Type, "Direct"),
				Membership: plugin.DependencyMembership{
					Project: projRel,
					Target:  tfm,
				},
				Artifact: plugin.DependencyArtifact{
					Digest: sha512Digest(e.ContentHash),
				},
				Provenance: plugin.DependencyProvenance{
					Manifest: projRel,
					Lockfile: lockRel,
					Resolver: "nuget(packages.lock.json)",
					Runtime:  tfm,
				},
				Partiality: plugin.Partial(reasons...),
			})
			for child := range e.Dependencies {
				cver, ok := index[strings.ToLower(child)]
				if !ok {
					continue
				}
				childID := makeNodeID(projRel, tfm, "", nugetPURL(child, cver))
				edges = append(edges, plugin.DependencyEdge{Parent: nodeID, Child: childID})
			}
		}
	}
	return nodes, edges, true
}

// --- tier 3: declared PackageReference / packages.config text (+ CPM) --------

type projectXML struct {
	PropertyGroups []struct {
		TargetFramework    string `xml:"TargetFramework"`
		TargetFrameworks   string `xml:"TargetFrameworks"`
		RuntimeIdentifier  string `xml:"RuntimeIdentifier"`
		RuntimeIdentifiers string `xml:"RuntimeIdentifiers"`
	} `xml:"PropertyGroup"`
	ItemGroups []struct {
		Condition   string `xml:"Condition,attr"`
		PackageRefs []struct {
			Include     string `xml:"Include,attr"`
			VersionAttr string `xml:"Version,attr"`
			VersionElem string `xml:"Version"`
			Condition   string `xml:"Condition,attr"`
		} `xml:"PackageReference"`
	} `xml:"ItemGroup"`
}

type packageVersionsXML struct {
	ItemGroups []struct {
		PackageVersions []struct {
			Include     string `xml:"Include,attr"`
			VersionAttr string `xml:"Version,attr"`
			VersionElem string `xml:"Version"`
		} `xml:"PackageVersion"`
	} `xml:"ItemGroup"`
}

type declaredRef struct {
	id             string
	version        string // exact pin; empty when unresolved
	resolved       bool
	condition      string
	groupCondition string
}

// parseDeclared resolves the directly-declared dependency set lexically: PackageReference pins
// (with Central Package Management merge from Directory.Packages.props) and legacy
// packages.config. It emits one node per (TFM, package); transitives and edges are unknown
// without a lockfile (the caller's no_lockfile). Ranges/floats and unresolved CPM versions stay
// UNRESOLVED (version empty, node-level unresolved_version_range) — never guessed. Unevaluable
// conditions are marked unevaluated_condition, never silently applied.
//
// Returns (nodes, extra graph-level reasons, a declared manifest existed, it parsed cleanly).
// cpmRoot bounds the Directory.Packages.props upward walk (buildDir in the single-project path;
// the solution root in the multi-project path, so a root-level CPM props file is discovered).
func parseDeclared(buildDir, projDir, projRel, cpmRoot string) ([]plugin.DependencyNode, []string, bool, bool) {
	projPath, hasProject := findProjectFile(buildDir)
	configPath, hasConfig := findFile(buildDir, "packages.config", false)
	if !hasProject && !hasConfig {
		return nil, nil, false, false
	}

	cpm := loadCPM(cpmRoot, projDir)

	var nodes []plugin.DependencyNode
	extra := map[string]bool{}

	if hasProject {
		data, err := os.ReadFile(projPath)
		if err != nil {
			return nil, nil, true, false
		}
		var px projectXML
		if err := xml.Unmarshal(data, &px); err != nil {
			return nil, nil, true, false
		}
		tfms := projectTFMs(px)
		if len(tfms) == 0 {
			tfms = []string{""}
		}
		refs := projectRefs(px, cpm)
		for _, tfm := range tfms {
			for _, r := range refs {
				matches, evaluable := evalTFMConditionBoth(r.groupCondition, r.condition, tfm)
				if evaluable && !matches {
					continue // the condition provably excludes this ref for this TFM.
				}
				var reasons []string
				purl := ""
				if r.resolved {
					purl = nugetPURL(r.id, r.version)
				} else {
					purl = "pkg:nuget/" + strings.ToLower(r.id)
					reasons = append(reasons, reasonUnresolvedVersionRange)
					extra[reasonUnresolvedVersionRange] = true
				}
				if !evaluable {
					reasons = append(reasons, reasonUnevaluatedCondition)
					extra[reasonUnevaluatedCondition] = true
				}
				reasons = append(reasons, reasonNoRuntimeTarget)
				nodes = append(nodes, declaredNode(projRel, tfm, purl, r, reasons))
			}
		}
	}

	if hasConfig {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, nil, true, false
		}
		cfgRefs, ok := parseConfigRefs(data)
		if !ok {
			return nil, nil, true, false
		}
		for _, r := range cfgRefs {
			var reasons []string
			purl := ""
			if r.resolved {
				purl = nugetPURL(r.id, r.version)
			} else {
				purl = "pkg:nuget/" + strings.ToLower(r.id)
				reasons = append(reasons, reasonUnresolvedVersionRange)
				extra[reasonUnresolvedVersionRange] = true
			}
			reasons = append(reasons, reasonNoRuntimeTarget)
			nodes = append(nodes, declaredNode(projRel, r.groupCondition, purl, r, reasons))
		}
	}

	// Deterministic extra-reason order.
	var extraReasons []string
	for _, r := range []string{reasonUnresolvedVersionRange, reasonUnevaluatedCondition} {
		if extra[r] {
			extraReasons = append(extraReasons, r)
		}
	}
	return nodes, extraReasons, true, true
}

func declaredNode(projRel, tfm, purl string, r declaredRef, reasons []string) plugin.DependencyNode {
	return plugin.DependencyNode{
		ID:      makeNodeID(projRel, tfm, "", purl),
		PURL:    purl,
		Version: r.version,
		Direct:  true, // every declared dependency is direct; transitives need a lockfile.
		Membership: plugin.DependencyMembership{
			Project: projRel,
			Target:  tfm,
		},
		Provenance: plugin.DependencyProvenance{
			Manifest: projRel,
			Resolver: "msbuild-lexical(declared)",
			Runtime:  tfm,
		},
		Partiality: plugin.Partial(reasons...),
	}
}

func projectTFMs(px projectXML) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, pg := range px.PropertyGroups {
		add(pg.TargetFramework)
		for _, t := range strings.Split(pg.TargetFrameworks, ";") {
			add(t)
		}
	}
	sort.Strings(out)
	return out
}

func projectRefs(px projectXML, cpm map[string]cpmVersion) []declaredRef {
	var out []declaredRef
	for _, ig := range px.ItemGroups {
		for _, pr := range ig.PackageRefs {
			id := strings.TrimSpace(pr.Include)
			if id == "" {
				continue
			}
			raw := strings.TrimSpace(pr.VersionAttr)
			if raw == "" {
				raw = strings.TrimSpace(pr.VersionElem)
			}
			r := declaredRef{id: id, condition: pr.Condition, groupCondition: ig.Condition}
			if raw != "" {
				r.version, r.resolved = exactNuGetPin(raw)
			} else if cv, ok := cpm[strings.ToLower(id)]; ok {
				// Central Package Management: the version lives in Directory.Packages.props.
				r.version, r.resolved = cv.version, cv.resolved
			}
			out = append(out, r)
		}
	}
	return out
}

// --- CPM (Directory.Packages.props) ------------------------------------------

type cpmVersion struct {
	version  string
	resolved bool
}

// loadCPM collects the nearest-wins Directory.Packages.props PackageVersion pins by walking UP
// from the project dir to `root` INCLUSIVE (MSBuild import order is nearest-wins; replicated
// lexically, no import execution). `root` is the hermetic upper bound: the walk never escapes it
// (single-project → the BuildDir; multi-project → the solution root, so a root-level CPM props file
// shared by subdir projects is found — the standard CPM layout). An exact PackageVersion resolves a
// version-less PackageReference; a range/float there stays UNRESOLVED.
func loadCPM(root, projDir string) map[string]cpmVersion {
	out := map[string]cpmVersion{}
	dir := projDir
	for {
		p := filepath.Join(dir, "Directory.Packages.props")
		if data, err := os.ReadFile(p); err == nil {
			var pv packageVersionsXML
			if xml.Unmarshal(data, &pv) == nil {
				for _, ig := range pv.ItemGroups {
					for _, e := range ig.PackageVersions {
						id := strings.ToLower(strings.TrimSpace(e.Include))
						if id == "" {
							continue
						}
						if _, seen := out[id]; seen {
							continue // nearer (already-collected) props wins.
						}
						raw := strings.TrimSpace(e.VersionAttr)
						if raw == "" {
							raw = strings.TrimSpace(e.VersionElem)
						}
						ver, resolved := exactNuGetPin(raw)
						out[id] = cpmVersion{version: ver, resolved: resolved}
					}
				}
			}
		}
		if dir == root || !strings.HasPrefix(dir, root) {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return out
}

// parseConfigRefs reads legacy packages.config (always exact versions). The bool is false on an
// unparseable file (the caller degrades to tool_failure). groupCondition carries the entry's
// targetFramework so packages.config nodes are TFM-scoped like the rest.
func parseConfigRefs(data []byte) ([]declaredRef, bool) {
	var doc struct {
		Packages []struct {
			ID              string `xml:"id,attr"`
			Version         string `xml:"version,attr"`
			TargetFramework string `xml:"targetFramework,attr"`
		} `xml:"package"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, false
	}
	var out []declaredRef
	for _, p := range doc.Packages {
		id := strings.TrimSpace(p.ID)
		if id == "" {
			continue
		}
		ver, resolved := exactNuGetPin(strings.TrimSpace(p.Version))
		out = append(out, declaredRef{
			id:             id,
			version:        ver,
			resolved:       resolved,
			groupCondition: strings.TrimSpace(p.TargetFramework),
		})
	}
	return out, true
}

// --- shared helpers ----------------------------------------------------------

// makeNodeID builds the stable per-instance key "<project>|<TFM>[/<RID>]|<PURL>" so distinct
// resolution scopes of one PURL get distinct IDs and DependencyEdge endpoints stay unambiguous.
func makeNodeID(project, tfm, rid, purl string) string {
	scope := tfm
	if rid != "" {
		scope = tfm + "/" + rid
	}
	return project + "|" + scope + "|" + purl
}

// nugetPURL renders the normalized Package URL for a NuGet package (ids are case-insensitive →
// lower-cased; dots preserved).
func nugetPURL(id, version string) string {
	return "pkg:nuget/" + strings.ToLower(strings.TrimSpace(id)) + "@" + strings.TrimSpace(version)
}

func sha512Digest(b64 string) string {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return ""
	}
	return "sha512:" + b64
}

// ridPartiality names a portable (RID-agnostic) resolution per node; a RID-specific selection
// is Complete().
func ridPartiality(rid string) plugin.Partiality {
	if rid == "" {
		return plugin.Partial(reasonNoRuntimeTarget)
	}
	return plugin.Complete()
}

// splitTargetKey splits an assets `targets` key into (TFM, RID): "net8.0" → ("net8.0",""),
// "net8.0/linux-x64" → ("net8.0","linux-x64").
func splitTargetKey(key string) (tfm, rid string) {
	if i := strings.IndexByte(key, '/'); i >= 0 {
		return key[:i], key[i+1:]
	}
	return key, ""
}

// splitPkgKey splits an assets/library key "<id>/<version>" (NuGet ids never contain '/').
func splitPkgKey(key string) (id, version string) {
	if i := strings.LastIndexByte(key, '/'); i >= 0 {
		return key[:i], key[i+1:]
	}
	return key, ""
}

// directSet builds the lower-cased id set from a projectFileDependencyGroups entry (each line is
// "<id>[ >= <version>]").
func directSet(group []string) map[string]bool {
	out := make(map[string]bool, len(group))
	for _, line := range group {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			out[strings.ToLower(fields[0])] = true
		}
	}
	return out
}

// evalTFMConditionBoth evaluates a PackageReference's own condition AND its enclosing
// ItemGroup's condition against a TFM. It is evaluable only when BOTH are (an unevaluable one
// makes the whole verdict unevaluable). Matches means the ref applies to this TFM.
func evalTFMConditionBoth(groupCond, refCond, tfm string) (matches, evaluable bool) {
	gm, ge := evalTFMCondition(groupCond, tfm)
	rm, re := evalTFMCondition(refCond, tfm)
	if !ge || !re {
		return gm && rm, false
	}
	return gm && rm, true
}

// evalTFMCondition evaluates the reachable-without-MSBuild subset of an MSBuild Condition: an
// empty condition always applies; "'$(TargetFramework)'=='netX'" / "!=" is evaluated against
// the TFM. Any other form is unevaluable (matches defaults true so the declaration is emitted,
// but the caller marks it unevaluated_condition).
func evalTFMCondition(cond, tfm string) (matches, evaluable bool) {
	c := strings.TrimSpace(cond)
	if c == "" {
		return true, true
	}
	norm := strings.ReplaceAll(c, " ", "")
	for _, op := range []string{"==", "!="} {
		prefix := "'$(TargetFramework)'" + op
		if strings.HasPrefix(norm, prefix) {
			want := strings.Trim(strings.TrimPrefix(norm, prefix), "'")
			eq := strings.EqualFold(want, tfm)
			if op == "==" {
				return eq, true
			}
			return !eq, true
		}
	}
	return true, false
}

// --- file discovery ----------------------------------------------------------

// findProjectFile returns the single project file under buildDir (Build 3a is single-project;
// the multi-project .sln walk is Build 3b). Deterministic: the lexicographically-first match.
func findProjectFile(buildDir string) (string, bool) {
	var found []string
	_ = filepath.WalkDir(buildDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree yields no project; keep walking.
		}
		if d.IsDir() {
			if path != buildDir && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(d.Name())) {
		case ".csproj", ".fsproj", ".vbproj":
			found = append(found, path)
		}
		return nil
	})
	if len(found) == 0 {
		return "", false
	}
	sort.Strings(found)
	return found[0], true
}

// findFile returns the lexicographically-first file named `name` under buildDir. When
// includeObj is true the obj/ tree is walked (restore output lives in obj/); otherwise the
// standard build-output/VCS dirs are skipped.
func findFile(buildDir, name string, includeObj bool) (string, bool) {
	var found []string
	_ = filepath.WalkDir(buildDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr
		}
		if d.IsDir() {
			if path == buildDir {
				return nil
			}
			if includeObj && d.Name() == "obj" {
				return nil
			}
			if skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == name {
			found = append(found, path)
		}
		return nil
	})
	if len(found) == 0 {
		return "", false
	}
	sort.Strings(found)
	return found[0], true
}

func relTo(base, path string) string {
	if rel, err := filepath.Rel(base, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return path
}

// --- assembly ----------------------------------------------------------------

// mergeReasons appends add to base, de-duplicating while preserving first-seen order.
func mergeReasons(base []string, add ...string) []string {
	seen := make(map[string]bool, len(base)+len(add))
	out := make([]string, 0, len(base)+len(add))
	for _, r := range base {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	for _, r := range add {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// assemble sorts nodes by ID and edges by (Parent, Child) — the frozen deterministic encoding
// order (§7) — and de-duplicates edges.
func assemble(nodes []plugin.DependencyNode, edges []plugin.DependencyEdge, part plugin.Partiality) plugin.DependencyInventory {
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	seen := make(map[string]bool, len(edges))
	uniq := edges[:0]
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
