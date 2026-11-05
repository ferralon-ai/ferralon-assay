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

	"github.com/BurntSushi/toml"

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

	manifests, read := manifestFiles(req.BuildDir)
	uninstalled := inventoryUninstalled(req.BuildDir)

	var (
		nodes       []plugin.DependencyNode
		edges       []plugin.DependencyEdge
		parseFailed bool
		// unpinned is set when a requirements line installs something no node names: an
		// unnamed archive or URL, a local directory whose own manifest is not inventoried, or
		// a "-r" include that cannot be read.
		unpinned    bool
		includes    []reqLink
		constraints []reqLink
		locals      []reqLink
	)
	walked := make(map[string]bool, len(manifests))
	for _, m := range manifests {
		walked[filepath.Clean(m)] = true
	}
	projectDirs := map[string]bool{}            // project directory -> its build definitions are all read in full
	declared := map[string][]string{}           // project directory -> the [tool.poetry] runtime dependencies it declares
	inventoried := map[string]map[string]bool{} // project directory -> the packages its manifests put in the inventory
	emit := func(path string, rf reqFile) {
		// The node ID is scoped to the declaring file's path within the build dir, so a
		// package that appears in two manifests (or two requirements*.txt) yields two distinct
		// package-instance keys (§4.1 "distinct instances of the same PURL in different
		// resolution scopes get distinct IDs") rather than colliding. Edge endpoints, which the
		// parsers carry as bare package names within one lockfile, are resolved against the
		// SAME scope so a lock's edges stay internally consistent.
		scope := path
		if rel, err := filepath.Rel(req.BuildDir, path); err == nil {
			scope = rel
		}
		idFor := func(name string) string { return scope + "#" + name }
		left := uninstalled(path)

		for _, r := range rf.reqs {
			if !r.Selected && !r.Unresolved {
				// A marker that evaluated FALSE excludes the requirement from the SELECTED set
				// (C1). The exclusion is evaluated, not a silent drop — the pyReq layer recorded
				// it; the installed-graph inventory simply does not carry it. An UNRESOLVED node
				// (marker referencing an unbound variable) is NOT excluded: its presence is
				// undetermined, so it stays in the inventory as a partial node (§3.1 — never
				// infer a dependency's absence from an unresolvable condition).
				continue
			}
			n := buildNode(idFor(r.Name), r, req)
			n.NotInstalled = left[r.Name]
			nodes = append(nodes, n)
			for _, parent := range r.Parents {
				edges = append(edges, plugin.DependencyEdge{Parent: idFor(parent), Child: idFor(r.Name)})
			}
		}
		if rf.unnamed || rf.skipped {
			unpinned = true
		}
		for _, t := range rf.includes {
			includes = append(includes, reqLink{from: path, target: t})
		}
		for _, t := range rf.constraints {
			constraints = append(constraints, reqLink{from: path, target: t})
		}
		for _, t := range rf.locals {
			locals = append(locals, reqLink{from: path, target: t})
		}
	}
	for _, m := range manifests {
		rf, ok := manifestToPyReqs(m, req.TargetEnv, req.Selection)
		if !ok {
			parseFailed = true
			continue
		}
		dir := filepath.Dir(filepath.Clean(m))
		switch filepath.Base(m) {
		case "pyproject.toml", "setup.py", "setup.cfg", "hatch_build.py":
			// A project directory is inventoried only when every build definition in it
			// declares its dependencies as literals. The advisory reader is the strict one: a
			// computed setup.py install_requires reads as no dependencies here, but fails there.
			_, _, complete := parseManifest(m)
			if prev, seen := projectDirs[dir]; !seen || prev {
				projectDirs[dir] = complete
			}
			if filepath.Base(m) == "pyproject.toml" {
				declared[dir] = append(declared[dir], poetryRuntimeDeps(m)...)
			}
		}
		if !strings.HasSuffix(m, ".txt") {
			if inventoried[dir] == nil {
				inventoried[dir] = map[string]bool{}
			}
			for _, r := range rf.reqs {
				inventoried[dir][normalizePyCoordinate(r.Name)] = true
			}
		}
		emit(m, rf)
	}

	// A project directory also counts as read in full only when the inventory carries every
	// runtime dependency it declares under [tool.poetry]: the strict reader accepts that
	// table, but with no lock beside it nothing here puts it in the inventory.
	for dir, names := range declared {
		for _, n := range names {
			if !inventoried[dir][n] {
				projectDirs[dir] = false
				break
			}
		}
	}

	// A "-r" include that the walk did not already inventory is read in place, as pip would
	// read it. A "-c" constraint file is read too: its pins install nothing, but pip installs
	// the "-r" includes it names. Either one that cannot be read (a URL, a file generated later)
	// leaves the graph incomplete.
	buildReal, err := filepath.EvalSymlinks(req.BuildDir)
	if err != nil {
		buildReal = req.BuildDir
	}
	walkedReal := make(map[string]bool, len(walked))
	for m := range walked {
		if r, err := filepath.EvalSymlinks(m); err == nil {
			walkedReal[r] = true
		}
	}
	followed := map[string]bool{}
	constrained := map[string]bool{}
	for len(includes) > 0 || len(constraints) > 0 {
		constraint := len(includes) == 0
		var inc reqLink
		if constraint {
			inc, constraints = constraints[0], constraints[1:]
		} else {
			inc, includes = includes[0], includes[1:]
		}
		path, key, read := includePath(buildReal, inc, walkedReal, followed)
		if path == "" {
			if !read {
				unpinned = true
			}
			continue
		}
		if constraint {
			if constrained[key] {
				continue
			}
			constrained[key] = true
		} else {
			followed[key] = true
		}
		data, err := readRegular(path)
		if err != nil {
			unpinned = true
			continue
		}
		rf := parseRequirementsFile(data, req.TargetEnv, req.Selection)
		if constraint {
			rf = reqFile{includes: rf.includes, constraints: rf.constraints, skipped: rf.skipped}
		} else {
			applyViaEdges(rf.reqs, pipCompileVia(data))
		}
		emit(path, rf)
	}

	for _, l := range locals {
		if !localInventoried(req.BuildDir, l, projectDirs) {
			unpinned = true
		}
	}

	have := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		have[n.ID] = true
	}
	nodes = append(nodes, scriptInventory(req, have)...)

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Parent != edges[j].Parent {
			return edges[i].Parent < edges[j].Parent
		}
		return edges[i].Child < edges[j].Child
	})

	// A directory the walk could not read may hold a manifest the inventory is missing.
	if !read {
		parseFailed = true
	}
	var reasons []string
	if len(manifests) == 0 {
		reasons = append(reasons, plugin.PartialReasonNoManifest)
	}
	if parseFailed {
		reasons = append(reasons, plugin.PartialReasonToolFailure)
	}
	if unpinned {
		reasons = append(reasons, plugin.PartialReasonSourceUnpinned)
	}
	part := plugin.Complete()
	if len(reasons) > 0 {
		part = plugin.Partial(reasons...)
	}
	return plugin.DependencyInventory{Partiality: part, Nodes: nodes, Edges: edges}, nil
}

// inventoryUninstalled returns, for a manifest path, the packages by normalized name that every
// install the build is known to run leaves out of the environment, shared with version
// resolution's scoping (poetryInstalls). A script surface that may install a package no
// manifest names (scriptWithheld), an allowed pip install -r of a file the inventory need not
// read, or an unrecognised install surface may each put such a package in place, so any of
// them leaves every package installed. What tooling names, the distributions an interpreter
// seeds and those an allowed pip self-upgrade or ensurepip installs, is never left out, nor is
// what a seeded distribution requires (seededRequirements).
func inventoryUninstalled(buildDir string) func(path string) map[string]bool {
	_, _, scriptWithheld, installs, poetry, tooling, unrecognised, _, _ := versionSurfaces(buildDir)
	if scriptWithheld || unrecognised != "" || len(installs) > 0 {
		return func(string) map[string]bool { return nil }
	}
	return func(path string) map[string]bool {
		out := poetry.uninstalled(path)
		for n := range tooling {
			delete(out, n)
		}
		for _, n := range seededRequirements {
			delete(out, n)
		}
		return out
	}
}

// manifestToPyReqs parses one recognized manifest into selected-set pyReq records for the
// declared environment. The edge-bearing / marker-aware formats route through their
// selected-set parsers (requirements*.txt -> resolveRequirements, with pip-compile "# via"
// edges; pdm.lock -> parsePDMLock; uv.lock -> parseUVLock; poetry.lock ->
// parsePoetryLockSelected). Formats that carry no edges (Pipfile.lock) or only declare
// specifiers (pyproject.toml, setup.cfg, setup.py, hatch_build.py) are lifted from their
// advisory resolution so their packages are still inventoried (never silently dropped),
// classified relUnexpressed so no edge is inferred that was not read.
func manifestToPyReqs(path string, env map[string]string, selection []string) (reqFile, bool) {
	data, err := readRegular(path)
	if err != nil {
		return reqFile{}, false
	}
	var reqs []pyReq
	switch filepath.Base(path) {
	case "pdm.lock":
		reqs, err = parsePDMLock(data, env, selection)
	case "uv.lock":
		reqs, err = parseUVLock(data, env, selection)
	case "poetry.lock":
		reqs, err = parsePoetryLockSelected(data, env, selection)
	case "Pipfile.lock":
		return liftManifest(parsePipfileLock(data))("Pipfile.lock")
	case "pyproject.toml":
		return liftManifest(parsePyproject(path, data))("pyproject.toml")
	case "setup.cfg":
		return liftManifest(parseSetupCfg(path, data))("setup.cfg")
	case "setup.py":
		return liftManifest(parseSetupPy(data))("setup.py")
	case "hatch_build.py":
		return liftManifest(parseHatchBuild(data))("hatch_build.py")
	case "hatch.toml":
		// Its environments are development installs, which pyproject.toml's [tool.hatch] does
		// not inventory either.
		var h hatchConfig
		return reqFile{}, toml.Unmarshal(data, &h) == nil
	default: // requirements*.txt
		rf := parseRequirementsFile(data, env, selection)
		applyViaEdges(rf.reqs, pipCompileVia(data))
		return rf, true
	}
	if err != nil {
		return reqFile{}, false
	}
	return reqFile{reqs: reqs}, true
}

// poetryRuntimeDeps names the dependencies a pyproject declares only under
// [tool.poetry.dependencies], which the poetry backend installs when [project].dependencies
// is absent. "python" is the interpreter constraint, not a package.
func poetryRuntimeDeps(path string) []string {
	data, err := readRegular(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Project struct {
			Dependencies []string `toml:"dependencies"`
		} `toml:"project"`
		Tool struct {
			Poetry struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if toml.Unmarshal(data, &doc) != nil || len(doc.Project.Dependencies) > 0 {
		return nil
	}
	var names []string
	for n := range doc.Tool.Poetry.Dependencies {
		if n = normalizePyCoordinate(n); n != "python" {
			names = append(names, n)
		}
	}
	return names
}

// liftManifest adapts an advisory-path parser's result for manifestToPyReqs.
func liftManifest(deps []plugin.ResolvedDependency, ok bool) func(source string) (reqFile, bool) {
	return func(source string) (reqFile, bool) { return reqFile{reqs: liftAdvisory(deps, source)}, ok }
}

// reqLink is a "-r" include or local directory install, with the requirements file that
// declared it.
type reqLink struct{ from, target string }

// includePath resolves a "-r" include the way pip does: relative to the including file. It is
// already read when it is a manifest the walk inventoried or an include already followed, both
// keyed by real path (walkedReal, followed), so a symlinked directory cannot re-include a file
// it reaches. It returns the path still to read and its real-path key, or "" with read
// reporting whether the include is covered. A URL, a missing target, or one outside the build
// dir is not read.
func includePath(buildReal string, inc reqLink, walkedReal, followed map[string]bool) (path, key string, read bool) {
	t := inc.target
	if strings.Contains(t, "://") {
		return "", "", false
	}
	// Cleaned as text before any symlink is followed, as pip's os.path.abspath does.
	path = filepath.Clean(t)
	if !filepath.IsAbs(t) {
		path = filepath.Join(filepath.Dir(inc.from), t)
	}
	key, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", "", false
	}
	if walkedReal[key] || followed[key] {
		return "", "", true
	}
	if !within(buildReal, key) {
		return "", "", false
	}
	return path, key, false
}

// localInventoried reports whether a local directory install (".", "-e ./pkg") is a project
// whose own build definitions the inventory read in full (projectDirs maps a directory to
// that), so the line adds nothing unnamed. pip
// resolves the path against its working directory, which the file does not state: the build
// root and the requirements file's directory are both taken, and neither may be a project the
// inventory did not read. One of them must be an inventoried project.
func localInventoried(buildDir string, l reqLink, projectDirs map[string]bool) bool {
	t := strings.TrimPrefix(l.target, "file:")
	if strings.Contains(t, "://") {
		return false
	}
	candidates := []string{filepath.Clean(t)}
	if !filepath.IsAbs(t) {
		candidates = []string{filepath.Join(buildDir, t), filepath.Join(filepath.Dir(l.from), t)}
	}
	found := false
	for _, c := range candidates {
		complete, seen := projectDirs[c]
		switch {
		case seen && complete:
			found = true
		case seen || isPyProjectDir(c):
			return false
		}
	}
	return found
}

// isPyProjectDir reports whether dir holds a file that makes it an installable project.
func isPyProjectDir(dir string) bool {
	for _, f := range []string{"pyproject.toml", "setup.py", "setup.cfg"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}

// within reports whether path lies inside dir.
func within(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// liftAdvisory projects an advisory-path []plugin.ResolvedDependency onto selected-set pyReq
// records for a format that expresses no edges. Each package is Selected (it is in the declared
// set) and relUnexpressed (no edge was read for it, so it is neither claimed direct nor given an
// inferred parent — C4 safe). An unresolved (range / unlocked) coordinate carries
// source_unpinned; the exact installed
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

// pyPURL builds the Package URL. The purl pypi type names a project by its PEP 503
// normalized name, so "types-PyYAML" and "types_pyyaml" are one package; the version rides
// only when an exact pin resolved.
func pyPURL(name, version string, resolved bool) string {
	name = normalizePyCoordinate(name)
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
	case "pyproject.toml", "setup.cfg", "setup.py", "hatch_build.py":
		p.Manifest, p.Resolver = r.Source, "pip"
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
