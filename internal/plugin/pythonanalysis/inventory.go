package pythonanalysis

// Whole-graph dependency inventory assembly (PLAN-170 E5, §4.1).
//
// ResolveInventory projects the lane-local selected-set records (pyReq, produced by the
// E1-E4 parsers) onto the shared plugin.DependencyInventory the whole scanner speaks. It is
// the environment-AWARE counterpart to ResolveDependencyVersions: the advisory path
// (retained, unchanged) answers "does coordinate X appear anywhere" with a sound
// over-approximation; this path answers "what is the SELECTED/installed graph for the
// declared target environment", evaluating markers (C1), resolving extras against the
// request's Selection (C2), and carrying parent edges + direct/transitive classification
// where the format expresses them (C4).
//
// No process execution (C5): every input is a manifest/lockfile a human or CI already wrote;
// the resolver is never launched. The target environment is DECLARED on the request
// (req.TargetEnv), never probed by starting an interpreter (§3.3).
//
// Determinism (C7): Nodes are emitted sorted by ID and Edges by (Parent, Child); the only
// maps consumed on the output path are read by explicit key (targetDescriptor) or already
// sorted into slices upstream (pyReq.Parents via sortedParents). No map is an iteration
// source on the encoding path.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveInventory resolves the whole selected dependency graph for the checked-out module at
// req.BuildDir, evaluating environment markers against req.TargetEnv and extras against
// req.Selection. A missing/unreadable build dir is a hard error (inv.4); a build dir with no
// recognized manifest, or one whose manifest cannot be parsed, degrades the graph-level
// Partiality (no_manifest / tool_failure) rather than fabricating an empty-but-complete graph
// (which reads downstream as "this build has no dependencies", §3.1).
func ResolveInventory(_ context.Context, req plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.DependencyInventory{}, fmt.Errorf("pythonanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.DependencyInventory{}, fmt.Errorf("pythonanalysis: build dir %q is not a directory", req.BuildDir)
	}

	manifests := manifestFiles(req.BuildDir)

	var (
		nodes       []plugin.DependencyNode
		edges       []plugin.DependencyEdge
		parseFailed bool
	)
	for _, m := range manifests {
		reqs, ok := manifestToPyReqs(m, req.TargetEnv, req.Selection)
		if !ok {
			parseFailed = true
			continue
		}
		// The node ID is scoped to the declaring file's path within the build dir, so a
		// package that appears in two manifests (or two requirements*.txt) yields two distinct
		// package-instance keys (§4.1 "distinct instances of the same PURL in different
		// resolution scopes get distinct IDs") rather than colliding. Edge endpoints, which the
		// parsers carry as bare package names within one lockfile, are resolved against the
		// SAME scope so a lock's edges stay internally consistent.
		scope := m
		if rel, err := filepath.Rel(req.BuildDir, m); err == nil {
			scope = rel
		}
		idFor := func(name string) string { return scope + "#" + name }

		for _, r := range reqs {
			if !r.Selected && !r.Unresolved {
				// A marker that evaluated FALSE excludes the requirement from the SELECTED set
				// (C1). The exclusion is evaluated, not a silent drop — the pyReq layer recorded
				// it; the installed-graph inventory simply does not carry it. An UNRESOLVED node
				// (marker referencing an unbound variable) is NOT excluded: its presence is
				// undetermined, so it stays in the inventory as a partial node (§3.1 — never
				// infer a dependency's absence from an unresolvable condition).
				continue
			}
			nodes = append(nodes, buildNode(idFor(r.Name), r, req))
			for _, parent := range r.Parents {
				edges = append(edges, plugin.DependencyEdge{Parent: idFor(parent), Child: idFor(r.Name)})
			}
		}
	}

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Parent != edges[j].Parent {
			return edges[i].Parent < edges[j].Parent
		}
		return edges[i].Child < edges[j].Child
	})

	part := plugin.Complete()
	switch {
	case len(manifests) == 0:
		part = plugin.Partial(plugin.PartialReasonNoManifest)
	case parseFailed:
		part = plugin.Partial(plugin.PartialReasonToolFailure)
	}
	return plugin.DependencyInventory{Partiality: part, Nodes: nodes, Edges: edges}, nil
}

// manifestToPyReqs parses one recognized manifest into selected-set pyReq records for the
// declared environment. The three edge-bearing / marker-aware formats route through their
// selected-set parsers (requirements*.txt -> resolveRequirements, pdm.lock -> parsePDMLock,
// uv.lock -> parseUVLock, all E1-E4). The three formats whose inventory-level edge extraction
// is deferred (poetry.lock, Pipfile.lock, pyproject.toml — see e5-notes) are lifted from their
// existing advisory resolution so their packages are still inventoried (never silently
// dropped), conservatively classified relUnexpressed so no edge is inferred that was not read.
func manifestToPyReqs(path string, env map[string]string, selection []string) ([]pyReq, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	switch filepath.Base(path) {
	case "pdm.lock":
		reqs, err := parsePDMLock(data, env, selection)
		if err != nil {
			return nil, false
		}
		return reqs, true
	case "uv.lock":
		reqs, err := parseUVLock(data, env, selection)
		if err != nil {
			return nil, false
		}
		return reqs, true
	case "poetry.lock":
		deps, ok := parsePoetryLock(data)
		return liftAdvisory(deps, "poetry.lock"), ok
	case "Pipfile.lock":
		deps, ok := parsePipfileLock(data)
		return liftAdvisory(deps, "Pipfile.lock"), ok
	case "pyproject.toml":
		deps, ok := parsePyproject(data)
		return liftAdvisory(deps, "pyproject.toml"), ok
	default: // requirements*.txt
		return resolveRequirements(data, env, selection), true
	}
}

// liftAdvisory projects an advisory-path []plugin.ResolvedDependency onto selected-set pyReq
// records for a format whose inventory-level edge/marker reading is deferred this cycle. Each
// package is Selected (it is in the declared set) and relUnexpressed (this cycle derives no
// edges for it, so it is neither claimed direct nor given an inferred parent — C4 safe). An
// unresolved (range / unlocked) coordinate carries source_unpinned; the exact installed
// identity is undetermined without a fetch, never guessed.
func liftAdvisory(deps []plugin.ResolvedDependency, source string) []pyReq {
	out := make([]pyReq, 0, len(deps))
	for _, d := range deps {
		r := pyReq{
			Name:         normalizePyCoordinate(d.Coordinate),
			Version:      strings.TrimSpace(d.Version),
			Resolved:     d.Resolved,
			Source:       source,
			Kind:         reqNormal,
			Selected:     true,
			Relationship: relUnexpressed,
		}
		if !d.Resolved {
			r.Partial = append(r.Partial, plugin.PartialReasonSourceUnpinned)
		}
		out = append(out, r)
	}
	return out
}

// buildNode projects one selected pyReq onto a plugin.DependencyNode. Version is the exact
// resolved pin or "" (fail-open survives — an unresolved range never fabricates a version);
// Direct is true only on positive relDirect evidence (relTransitive and relUnexpressed both
// yield false, so a format with no edge data is never defaulted to "direct" — C4).
func buildNode(id string, r pyReq, req plugin.ResolveInventoryRequest) plugin.DependencyNode {
	runtime, target := targetDescriptor(req.TargetEnv)
	return plugin.DependencyNode{
		ID:      id,
		PURL:    pyPURL(r.Name, r.Version, r.Resolved),
		Version: strings.TrimSpace(r.Version),
		Direct:  r.Relationship == relDirect,
		Membership: plugin.DependencyMembership{
			Project: req.BuildDir,
			// Extras/group scope that produced this node's inclusion (C2 provenance): the subset
			// of the request's Selection that selected it, in declared order. Empty for a node
			// present unconditionally.
			Target: strings.Join(r.SelectedExtras, ","),
		},
		Artifact: plugin.DependencyArtifact{
			Identity: artifactIdentity(r),
			// The DECLARED lockfile integrity digest E4 retained — NOT verified against a fetched
			// artifact (that is PLAN-200/270). The first declared hash, deterministically, since
			// the field is singular and no target-platform wheel is selected this cycle.
			Digest: firstHash(r.Hashes),
		},
		Provenance: nodeProvenance(r, runtime, target),
		Partiality: nodePartiality(r),
	}
}

// pyPURL builds the normalized Package URL. The name is already PEP 503-normalized by the
// upstream parsers (normalizePyCoordinate); the version rides only when an exact pin resolved.
func pyPURL(name, version string, resolved bool) string {
	if name == "" {
		return ""
	}
	purl := "pkg:pypi/" + name
	if resolved && strings.TrimSpace(version) != "" {
		purl += "@" + strings.TrimSpace(version)
	}
	return purl
}

// artifactIdentity is the selected artifact's identity. pyReq does not retain the per-wheel
// filename (E4 kept the hashes, not the filenames), so a registry package is identified by its
// exact coordinate; a VCS/URL/editable/include source is identified by its raw spec text.
func artifactIdentity(r pyReq) string {
	switch r.Kind {
	case reqVCS, reqURL, reqEditable, reqInclude:
		if r.Raw != "" {
			return r.Raw
		}
	}
	if r.Resolved && strings.TrimSpace(r.Version) != "" {
		return r.Name + "@" + strings.TrimSpace(r.Version)
	}
	return r.Name
}

// firstHash returns the first declared integrity digest (algorithm-prefixed, e.g.
// "sha256:...") or "" when the format declared none.
func firstHash(hashes []string) string {
	if len(hashes) == 0 {
		return ""
	}
	return hashes[0]
}

// nodeProvenance records how the node was resolved: the manifest/lockfile that declared it,
// the resolver tool, and the declared runtime/target the resolution targeted (§6 Phase 1
// bullet 3, resolver half). The build-context half of runtime/target is PLAN-173.
func nodeProvenance(r pyReq, runtime, target string) plugin.DependencyProvenance {
	p := plugin.DependencyProvenance{Runtime: runtime, Target: target}
	switch r.Source {
	case "pdm.lock":
		p.Lockfile, p.Resolver = "pdm.lock", "pdm"
	case "uv.lock":
		p.Lockfile, p.Resolver = "uv.lock", "uv"
	case "poetry.lock":
		p.Lockfile, p.Resolver = "poetry.lock", "poetry"
	case "Pipfile.lock":
		p.Lockfile, p.Resolver = "Pipfile.lock", "pipenv"
	case "pyproject.toml":
		p.Manifest, p.Resolver = "pyproject.toml", "pip"
	default: // requirements.txt
		p.Manifest, p.Resolver = "requirements.txt", "pip"
	}
	return p
}

// targetDescriptor projects the declared target-environment descriptor onto the
// (runtime, target) provenance strings. It reads specific well-known PEP 508 keys by name —
// never iterating the map — so the output is deterministic (C7) regardless of map order.
func targetDescriptor(env map[string]string) (runtime, target string) {
	if env == nil {
		return "", ""
	}
	if v := strings.TrimSpace(env["python_full_version"]); v != "" {
		runtime = "python" + v
	} else if v := strings.TrimSpace(env["python_version"]); v != "" {
		runtime = "python" + v
	}
	plat := strings.TrimSpace(env["sys_platform"])
	mach := strings.TrimSpace(env["platform_machine"])
	switch {
	case plat != "" && mach != "":
		target = plat + "/" + mach
	case plat != "":
		target = plat
	case mach != "":
		target = mach
	}
	return runtime, target
}

// nodePartiality folds the node's declared partiality: the source/marker reasons the E1-E3
// parsers attached (source_unpinned, env_condition_unresolved:<var>) plus the relationship
// reason derived from its classification (relationship_unexpressed for an unclassified node).
// The reasons are already the canonical shared plugin codes; their order is deterministic
// (parser source order, then the relationship reason).
func nodePartiality(r pyReq) plugin.Partiality {
	reasons := append([]string(nil), r.Partial...)
	if rr := r.relationshipReason(); rr != "" {
		reasons = append(reasons, rr)
	}
	if len(reasons) == 0 {
		return plugin.Complete()
	}
	return plugin.Partial(reasons...)
}
