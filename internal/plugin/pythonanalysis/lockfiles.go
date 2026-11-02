package pythonanalysis

// pdm.lock, uv.lock and poetry.lock resolver parsers (PLAN-170 E4, C3 formats + C4 parent
// edges).
//
// Both formats are TOML built around a "[[package]]" array-of-tables carrying a package's
// name, exact pinned version, dependency edges, and artifact hashes. E4 must read the dependency
// edges and hashes, which live in multi-line arrays and inline tables (array-of-strings for
// pdm, array-of-inline-tables for uv). A partial hand-rolled TOML reader for those is exactly
// the fragile reimplementation OQ2 ruled against, so parsing goes through the L0-approved
// pure-Go github.com/BurntSushi/toml (MIT, no shell-out — C5-clean; named + licensed in the
// lane PR as a PLAN-270/PLAN-402 toolchain input).
//
// The two formats express parent edges differently:
//   - pdm.lock: dependencies = [ "MarkupSafe>=2.0", ... ] — PEP 508 requirement STRINGS. The
//     child name (and any guarding marker/extras) is extracted by REUSING the E1/E2
//     parseRequirementSpec + evaluateMarker path; this reuse is why E1/E2 precede E4.
//   - uv.lock: dependencies = [ { name = "markupsafe", marker = "..." }, ... ] — inline
//     tables naming the child directly, read natively.
//
// Classification (C4): a node is transitive when a parent edge names it as another package's
// dependency. A pdm.lock graph root (zero in-degree) is a declared direct dependency — the
// lockfile contains only the project's dependency closure, so a root is direct on evidence,
// not by default. A uv.lock direct dependency is one named by the project's own root package
// (source = { editable | virtual }); that root node is not itself emitted as a dependency. A
// node the format leaves unclassifiable falls to relUnexpressed, never relDirect (C4).
//
// No process execution (C5): the resolver is never invoked; these read the lockfile a human or
// CI already produced.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// --- pdm.lock ----------------------------------------------------------------

type pdmLock struct {
	Package []pdmPackage `toml:"package"`
}

type pdmPackage struct {
	Name         string    `toml:"name"`
	Version      string    `toml:"version"`
	Marker       string    `toml:"marker"` // optional package-level environment marker
	Dependencies []string  `toml:"dependencies"`
	Files        []pdmFile `toml:"files"`
	// A package installed from a VCS checkout, a URL or a local path carries its VCS kind
	// (git, hg, svn, bzr), url or path (editable = true marks a path installed in place) instead
	// of index files.
	Git      string `toml:"git"`
	Hg       string `toml:"hg"`
	Svn      string `toml:"svn"`
	Bzr      string `toml:"bzr"`
	URL      string `toml:"url"`
	Path     string `toml:"path"`
	Editable bool   `toml:"editable"`
}

// redirected reports whether the package installs from a VCS checkout, a URL or a local path
// rather than an index, so its locked version is not the index release an advisory describes.
func (p pdmPackage) redirected() bool {
	return p.Git != "" || p.Hg != "" || p.Svn != "" || p.Bzr != "" || p.URL != "" || p.Path != "" || p.Editable
}

type pdmFile struct {
	File string `toml:"file"`
	Hash string `toml:"hash"`
}

// parsePDMLock parses a pdm.lock into the selected set for the declared environment. Each
// [[package]] becomes a pyReq with its exact pinned version, sorted parent edges, and retained
// file hashes. env/selection resolve the markers guarding pdm's PEP 508 dependency strings
// (reused E1/E2 evaluator); pass nil for both when no environment is declared. An unreadable /
// structurally invalid file is an error the caller degrades partiality on.
func parsePDMLock(data []byte, env map[string]string, selection []string) ([]pyReq, error) {
	var lock pdmLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("pythonanalysis: parse pdm.lock: %w", err)
	}

	// Parent map: child (normalized) → set of parent names. Built first so classification can
	// read in-degree.
	parents := map[string]map[string]bool{}
	for _, p := range lock.Package {
		parent := normalizePyCoordinate(p.Name)
		if parent == "" {
			continue
		}
		for _, dep := range p.Dependencies {
			child, active := pdmEdgeChild(dep, env, selection)
			if child == "" || !active {
				continue // marker evaluated false → edge inactive under this environment
			}
			if parents[child] == nil {
				parents[child] = map[string]bool{}
			}
			parents[child][parent] = true
		}
	}

	out := make([]pyReq, 0, len(lock.Package))
	for _, p := range lock.Package {
		name := normalizePyCoordinate(p.Name)
		if name == "" {
			continue
		}
		r := pyReq{
			Name:         name,
			Version:      strings.TrimSpace(p.Version),
			Resolved:     strings.TrimSpace(p.Version) != "",
			Source:       "pdm.lock",
			Kind:         reqNormal,
			Marker:       strings.TrimSpace(p.Marker),
			Parents:      sortedParents(parents[name]),
			Hashes:       pdmHashes(p.Files),
			Selected:     true, // a locked package is in the installed set (target-env re-selection is E5)
			Relationship: classifyPDM(parents[name]),
			Redirected:   p.redirected(),
		}
		out = append(out, r)
	}
	return out, nil
}

// pdmEdgeChild extracts the child package name from a pdm.lock PEP 508 dependency string,
// REUSING the E1/E2 evaluator: parseRequirementSpec for the name (+extras) and evaluateMarker
// for any guarding marker. A marker that evaluates false makes the edge inactive; an unbound
// (unresolved) marker keeps it active — never infer a dependency's absence from an unresolvable
// condition (§3.1).
func pdmEdgeChild(dep string, env map[string]string, selection []string) (child string, active bool) {
	spec := dep
	marker := ""
	if i := strings.IndexByte(dep, ';'); i >= 0 {
		marker = strings.TrimSpace(dep[i+1:])
		spec = strings.TrimSpace(dep[:i])
	}
	name, _, _, _ := parseRequirementSpec(spec)
	child = normalizePyCoordinate(name)
	if child == "" {
		return "", false
	}
	if marker != "" {
		mr := evaluateMarker(marker, env, selection)
		if !mr.unresolved && !mr.selected {
			return child, false // marker evaluated false → edge inactive
		}
	}
	return child, true
}

// classifyPDM classifies a pdm.lock node: transitive when it has any parent edge, otherwise a
// direct dependency (a graph root of the project's locked closure — evidence, not a default).
func classifyPDM(parents map[string]bool) relKind {
	if len(parents) > 0 {
		return relTransitive
	}
	return relDirect
}

// pdmHashes returns the file hashes for a pdm package in declared order (C3 integrity).
func pdmHashes(files []pdmFile) []string {
	var out []string
	for _, f := range files {
		if h := strings.TrimSpace(f.Hash); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// --- uv.lock -----------------------------------------------------------------

type uvLock struct {
	Package []uvPackage `toml:"package"`
}

type uvPackage struct {
	Name         string       `toml:"name"`
	Version      string       `toml:"version"`
	Source       uvSource     `toml:"source"`
	Dependencies []uvDep      `toml:"dependencies"`
	Sdist        uvArtifact   `toml:"sdist"`
	Wheels       []uvArtifact `toml:"wheels"`
}

// uvSource is uv's inline-table package source. A root project carries editable or virtual
// (its path); a resolved dependency carries registry (the index URL), or git, url, path or
// directory when a [tool.uv.sources] entry redirects it.
type uvSource struct {
	Registry  string `toml:"registry"`
	Editable  string `toml:"editable"`
	Virtual   string `toml:"virtual"`
	Git       string `toml:"git"`
	URL       string `toml:"url"`
	Path      string `toml:"path"`
	Directory string `toml:"directory"`
}

// redirected reports whether the package installs from a git checkout, a URL or a local path
// rather than an index. Its locked version is whatever that source's metadata says, which does
// not make it the index release of that version an advisory describes.
func (s uvSource) redirected() bool {
	return s.Git != "" || s.URL != "" || s.Path != "" || s.Directory != ""
}

type uvDep struct {
	Name   string `toml:"name"`
	Marker string `toml:"marker"`
}

type uvArtifact struct {
	URL  string `toml:"url"`
	Hash string `toml:"hash"`
}

// isRoot reports whether a uv package is the project/workspace itself (an editable or virtual
// source) rather than a resolved dependency. Its dependencies define the direct set; it is not
// emitted as a dependency node.
func (p uvPackage) isRoot() bool {
	return strings.TrimSpace(p.Source.Editable) != "" || strings.TrimSpace(p.Source.Virtual) != ""
}

// parseUVLock parses a uv.lock into the selected set for the declared environment. The project
// root package (source = editable | virtual) is not emitted; its active dependencies seed the
// direct set. Every other [[package]] becomes a pyReq with its exact version, sorted parent
// edges (from non-root packages), and hashes. env/selection resolve any edge markers.
func parseUVLock(data []byte, env map[string]string, selection []string) ([]pyReq, error) {
	var lock uvLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("pythonanalysis: parse uv.lock: %w", err)
	}

	direct := map[string]bool{}             // names the root project declares directly
	parents := map[string]map[string]bool{} // child → parent set (non-root edges only)
	for _, p := range lock.Package {
		owner := normalizePyCoordinate(p.Name)
		for _, d := range p.Dependencies {
			child, active := uvEdgeChild(d, env, selection)
			if child == "" || !active {
				continue
			}
			if p.isRoot() {
				direct[child] = true // an edge from the project itself → a direct dependency
				continue
			}
			if parents[child] == nil {
				parents[child] = map[string]bool{}
			}
			parents[child][owner] = true
		}
	}

	out := make([]pyReq, 0, len(lock.Package))
	for _, p := range lock.Package {
		if p.isRoot() {
			continue // the project itself is not a dependency node
		}
		name := normalizePyCoordinate(p.Name)
		if name == "" {
			continue
		}
		r := pyReq{
			Name:         name,
			Version:      strings.TrimSpace(p.Version),
			Resolved:     strings.TrimSpace(p.Version) != "",
			Source:       "uv.lock",
			Kind:         reqNormal,
			Parents:      sortedParents(parents[name]),
			Hashes:       uvHashes(p),
			Selected:     true,
			Relationship: classifyUV(name, direct, parents[name]),
			Redirected:   p.Source.redirected(),
		}
		out = append(out, r)
	}
	return out, nil
}

// uvEdgeChild reads a uv.lock inline-table dependency, returning the child name and whether the
// edge is active under env (a false marker deactivates it; an unbound marker keeps it active,
// §3.1).
func uvEdgeChild(d uvDep, env map[string]string, selection []string) (child string, active bool) {
	child = normalizePyCoordinate(d.Name)
	if child == "" {
		return "", false
	}
	if m := strings.TrimSpace(d.Marker); m != "" {
		mr := evaluateMarker(m, env, selection)
		if !mr.unresolved && !mr.selected {
			return child, false
		}
	}
	return child, true
}

// classifyUV classifies a uv.lock node: direct when the project root declares it; else
// transitive when a non-root package names it as a dependency; else unexpressed (never
// defaulted to direct, C4).
func classifyUV(name string, direct map[string]bool, parents map[string]bool) relKind {
	switch {
	case direct[name]:
		return relDirect
	case len(parents) > 0:
		return relTransitive
	default:
		return relUnexpressed
	}
}

// uvHashes returns a uv package's artifact hashes in a documented, deterministic order: each
// wheel hash in declared order, then the sdist hash (C3 integrity, C7 determinism).
func uvHashes(p uvPackage) []string {
	var out []string
	for _, w := range p.Wheels {
		if h := strings.TrimSpace(w.Hash); h != "" {
			out = append(out, h)
		}
	}
	if h := strings.TrimSpace(p.Sdist.Hash); h != "" {
		out = append(out, h)
	}
	return out
}

// --- poetry.lock -------------------------------------------------------------

type poetryLock struct {
	Package []poetryPackage `toml:"package"`
}

// poetryPackage is one locked package. Dependencies maps a child name to its constraint, which
// poetry writes as a version string, an inline table (version / markers / optional / extras /
// python), or an array of such tables (one per environment-specific constraint).
type poetryPackage struct {
	Name         string                 `toml:"name"`
	Version      string                 `toml:"version"`
	Dependencies map[string]interface{} `toml:"dependencies"`
	Files        []pdmFile              `toml:"files"`
	Source       poetrySource           `toml:"source"`
}

// poetrySource is a package's [package.source]. It is absent for PyPI and typed legacy for
// another index; git, url, file and directory install whatever that ref, archive or tree holds.
type poetrySource struct {
	Type string `toml:"type"`
	URL  string `toml:"url"`
}

// redirected reports whether the package installs from somewhere other than an index. An
// unrecognized type counts, and so does a url with no type, since this reader cannot tell what
// either serves.
func (s poetrySource) redirected() bool {
	t := strings.TrimSpace(s.Type)
	if t == "" {
		return s.URL != ""
	}
	return t != "legacy"
}

// parsePoetryLockSelected parses a poetry.lock into the selected set for the declared environment,
// reading parent edges from each package's [package.dependencies]. A dependency's markers gate
// its edge exactly as on pdm/uv (false → inactive, unbound → active). An optional dependency
// (optional = true, enabled through the parent's [package.extras]) is kept as an edge when the
// child is locked: poetry records which extras of the parent are requested only in the
// requesting package's constraint and in pyproject, so the edge is an over-approximation rather
// than an omission. An edge to a child absent from the lock produces nothing (only locked
// packages become nodes). Classification follows pdm.lock: poetry.lock does not record the
// project root, so a package no locked package depends on is a direct dependency of the
// project's locked closure.
func parsePoetryLockSelected(data []byte, env map[string]string, selection []string) ([]pyReq, error) {
	var lock poetryLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("pythonanalysis: parse poetry.lock: %w", err)
	}

	parents := map[string]map[string]bool{}
	for _, p := range lock.Package {
		parent := normalizePyCoordinate(p.Name)
		if parent == "" {
			continue
		}
		for dep, constraint := range p.Dependencies {
			child := normalizePyCoordinate(dep)
			if child == "" || !poetryEdgeActive(constraint, env, selection) {
				continue
			}
			if parents[child] == nil {
				parents[child] = map[string]bool{}
			}
			parents[child][parent] = true
		}
	}

	out := make([]pyReq, 0, len(lock.Package))
	for _, p := range lock.Package {
		name := normalizePyCoordinate(p.Name)
		if name == "" {
			continue
		}
		ver := strings.TrimSpace(p.Version)
		out = append(out, pyReq{
			Name:         name,
			Version:      ver,
			Resolved:     ver != "",
			Source:       "poetry.lock",
			Kind:         reqNormal,
			Parents:      sortedParents(parents[name]),
			Hashes:       pdmHashes(p.Files),
			Selected:     true,
			Relationship: classifyPDM(parents[name]),
			Redirected:   p.Source.redirected(),
		})
	}
	return out, nil
}

// poetryEdgeActive reports whether a poetry dependency constraint yields an active edge under
// env. A plain version string is unconditional. A table is active unless its markers evaluate
// false. An array of tables is active when any element is.
func poetryEdgeActive(constraint interface{}, env map[string]string, selection []string) bool {
	switch c := constraint.(type) {
	case map[string]interface{}:
		m, _ := c["markers"].(string)
		if m = strings.TrimSpace(m); m == "" {
			return true
		}
		mr := evaluateMarker(m, env, selection)
		return mr.unresolved || mr.selected
	case []interface{}:
		for _, e := range c {
			if poetryEdgeActive(e, env, selection) {
				return true
			}
		}
		return false
	case []map[string]interface{}:
		for _, e := range c {
			if poetryEdgeActive(e, env, selection) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

// --- shared ------------------------------------------------------------------

// sortedParents returns the parent set as a sorted slice, so a node's Parents field — the one
// place a map feeds the output — is emitted deterministically (C7).
func sortedParents(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// --- advisory-path adapters --------------------------------------------------

// parsePDMLockAdvisory / parseUVLockAdvisory adapt the E4 parsers to the environment-blind
// advisory path (ResolveDependencyVersions), which wants {coordinate, version} pins and ignores
// edges/markers. isManifest now recognizes pdm.lock/uv.lock, so parseManifest must route them
// here rather than letting parseRequirementLines mis-read TOML.
func parsePDMLockAdvisory(data []byte) ([]plugin.ResolvedDependency, bool) {
	reqs, err := parsePDMLock(data, nil, nil)
	if err != nil {
		return nil, false
	}
	return pyReqsToResolved(reqs), true
}

func parseUVLockAdvisory(data []byte) ([]plugin.ResolvedDependency, bool) {
	reqs, err := parseUVLock(data, nil, nil)
	if err != nil {
		return nil, false
	}
	return pyReqsToResolved(reqs), true
}

// pyReqsToResolved projects the selected-set pyReq records onto the advisory path's
// ResolvedDependency, preserving each package's exact pin (or UNRESOLVED when unpinned or
// redirected off its index).
func pyReqsToResolved(reqs []pyReq) []plugin.ResolvedDependency {
	out := make([]plugin.ResolvedDependency, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, pyResolved(r.Name, r.Version, r.Resolved && !r.Redirected, r.Source))
	}
	return out
}
