package pythonanalysis

// pdm.lock and uv.lock resolver parsers (PLAN-170 E4, C3 formats + C4 parent edges).
//
// Both formats are TOML built around a "[[package]]" array-of-tables carrying a package's
// name, exact pinned version, dependency edges, and artifact hashes. Unlike poetry.lock —
// which the lexical tomlString path reads only for flat scalars — E4 must read the dependency
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
// (its path); a resolved dependency carries registry (the index URL).
type uvSource struct {
	Registry string `toml:"registry"`
	Editable string `toml:"editable"`
	Virtual  string `toml:"virtual"`
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
// here rather than letting parseRequirementsTxt mis-read TOML.
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
// ResolvedDependency, preserving each package's exact pin (or UNRESOLVED when unpinned).
func pyReqsToResolved(reqs []pyReq) []plugin.ResolvedDependency {
	out := make([]plugin.ResolvedDependency, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, pyResolved(r.Name, r.Version, r.Resolved, r.Source))
	}
	return out
}
