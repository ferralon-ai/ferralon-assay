package pythonanalysis

// Exhaustiveness of the advisory-path dependency set (plugin.DependencyVersionResult.Exhaustive).
//
// Exhaustive is the claim that a PyPI project absent from All is provably not installed by this
// build, which lets the pipeline's intake guard disqualify an advisory for a package the
// codebase does not have. It is claimed only when all of these hold, and fails open otherwise:
//
//   - every manifest the resolver discovers parses, and at least one is a complete,
//     edge-bearing lockfile (uv.lock, pdm.lock, poetry.lock), each of which records the full
//     resolved closure; a poetry.lock's lexical advisory read and TOML decode agree on its
//     package set;
//   - the coordinate is not a first-party project (a uv workspace root or member, a pyproject
//     [project] or [tool.poetry] name, a setup.cfg [metadata] name, a setup.py literal name),
//     and every setup.py names its project literally: lockfiles omit the project itself, so its
//     absence from them proves nothing;
//   - every other discovered manifest is governed by the complete lockfiles in the nearest
//     directory at or above it that has any, and each of those lockfiles covers it on its own,
//     never through a union with another lock (pyLock.covers): every name it declares for
//     installation is locked at a version its range admits (every locked version, for a
//     declaration without an environment marker), each extra it asks for is recorded with all
//     the packages it pulls in, and a project definition outside the lock's directory is one
//     the lock resolves (a workspace member or path source);
//   - every file under the build dir that names or holds a Python install surface is one the
//     resolver reads fully (ManifestCandidates): an install format it never parses (Pipfile,
//     pylock.toml, rye's requirements.lock, pixi.toml, a pyproject configuring pixi, conda
//     environment files, *.in, tox deps, nox installs, a requirement file under any name), a
//     manifest outside the directories it discovers, a requirements file with an editable,
//     VCS or URL line or an include it does not read, a computed setup.py, any hatch_build.py,
//     a dynamic [project] field with no source it reads, a symlink or symlinked directory, or
//     an unreadable entry each fail open. The walk skips only node_modules and site-packages
//     (buildtree.Skipped);
//   - no installed copy of the coordinate is present: a *.dist-info or *.egg-info anywhere
//     (directly inside a site-packages, or anywhere the walk reaches, a build backend's
//     vendored copy included), an .egg-link or .egg, or a wheel or sdist archive named for it.
//
// Lockfile group/category/dev membership is never consulted: every locked package counts as
// present whatever group it belongs to.
//
// Build-time requirements ([build-system].requires, setup_requires) are declarations, found on
// the advisory path like any other, but not part of coverage: build-isolation environments are
// not runtime installs, and no lockfile records them. A package the build backend's own
// dependency closure brings into that environment, an interpreter-seeded pip, and a
// Dockerfile RUN pip install are outside what Exhaustive covers.

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// exhaustiveManifestSet reports whether the parsed manifests (found under root) enumerate every
// installable package. perFile maps each manifest path to what parseManifest returned for it.
// The cheap manifest checks run before the walks of the build dir.
func exhaustiveManifestSet(root, coordinate string, manifests []string, perFile map[string][]plugin.ResolvedDependency, parseFailed bool) bool {
	if parseFailed || len(manifests) == 0 {
		return false
	}
	coord := normalizePyCoordinate(coordinate)
	if names, ok := firstPartyNames(manifests); !ok || names[coord] {
		return false
	}
	locks := map[string][]*pyLock{} // directory → its complete lockfiles
	for _, m := range manifests {
		if !completeLockfiles[filepath.Base(m)] {
			continue
		}
		if filepath.Base(m) == "poetry.lock" && !poetryLockConsistent(m, perFile[m]) {
			return false
		}
		l, ok := readPyLock(m)
		if !ok {
			return false
		}
		locks[l.dir] = append(locks[l.dir], l)
	}
	if len(locks) == 0 {
		return false
	}
	for _, m := range manifests {
		if completeLockfiles[filepath.Base(m)] {
			continue
		}
		governing := governingLocks(filepath.Dir(m), root, locks)
		if len(governing) == 0 {
			return false
		}
		decls, ok := manifestDecls(m)
		if !ok {
			return false
		}
		for _, l := range governing {
			if !l.covers(m, decls) {
				return false
			}
		}
	}
	if !buildtree.AllFullyRead(newPySurface(root).candidates()) {
		return false
	}
	return !installedCopyPresent(root, coord)
}

// governingLocks returns the complete lockfiles in the nearest directory at or above dir (and
// not above root) that has any.
func governingLocks(dir, root string, locks map[string][]*pyLock) []*pyLock {
	root = filepath.Clean(root)
	for d := filepath.Clean(dir); ; {
		if ls := locks[d]; len(ls) > 0 {
			return ls
		}
		if d == root {
			return nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return nil
		}
		d = parent
	}
}

// installedCopyPresent walks root and reports whether an installed copy of coord may be in it:
// installed metadata (*.dist-info, *.egg-info, .egg-link, .egg) or a distribution archive named
// for it. A site-packages directory is not entered, so its entries are checked one level deep.
// An entry the walk cannot read counts as present.
func installedCopyPresent(root, coord string) bool {
	found := false
	hit := func() error {
		found = true
		return filepath.SkipAll
	}
	_ = buildtree.Walk(root, func(e buildtree.Entry, err error) error {
		if err != nil {
			return hit()
		}
		if e.Symlink {
			return nil // a candidate that is never fully read; ManifestCandidates fails open on it
		}
		name := e.D.Name()
		if e.Skipped {
			if name != "site-packages" {
				return nil
			}
			entries, err := os.ReadDir(e.Path)
			if err != nil {
				return hit()
			}
			for _, x := range entries {
				if n, ok := installedDistName(x.Name()); ok && n == coord {
					return hit()
				}
			}
			return nil
		}
		if n, ok := installedDistName(name); ok && n == coord {
			return hit()
		}
		if !e.D.IsDir() && archiveNames(name, coord) {
			return hit()
		}
		return nil
	})
	return found
}

// completeLockfiles are the formats whose [[package]] set is the full resolved closure.
var completeLockfiles = map[string]bool{"uv.lock": true, "pdm.lock": true, "poetry.lock": true}

// poetryLockConsistent reports whether poetry.lock decodes as TOML and the lexical advisory
// read (lexical) found exactly the package names the decode does. The advisory path's Found is
// computed from the lexical read, so a package it missed would otherwise read as absent.
func poetryLockConsistent(path string, lexical []plugin.ResolvedDependency) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	reqs, err := parsePoetryLockSelected(data, nil, nil)
	if err != nil {
		return false
	}
	want := map[string]bool{}
	for _, r := range reqs {
		want[normalizePyCoordinate(r.Name)] = true
	}
	got := map[string]bool{}
	for _, d := range lexical {
		got[normalizePyCoordinate(d.Coordinate)] = true
	}
	if len(got) != len(want) {
		return false
	}
	for n := range want {
		if !got[n] {
			return false
		}
	}
	return true
}

// firstPartyNames collects the normalized names of the projects the manifests define. ok is
// false when a project's name cannot be read without executing it (a setup.py with no literal
// name="..." argument), so the caller cannot rule out that the coordinate is first-party.
func firstPartyNames(manifests []string) (names map[string]bool, ok bool) {
	names = map[string]bool{}
	for _, m := range manifests {
		switch filepath.Base(m) {
		case "uv.lock":
			for _, n := range uvRootNames(m) {
				names[n] = true
			}
		case "pyproject.toml":
			data, err := os.ReadFile(m)
			if err != nil {
				return nil, false
			}
			var pp struct {
				Project struct {
					Name string `toml:"name"`
				} `toml:"project"`
				Tool struct {
					Poetry struct {
						Name string `toml:"name"`
					} `toml:"poetry"`
				} `toml:"tool"`
			}
			if toml.Unmarshal(data, &pp) != nil {
				return nil, false
			}
			for _, n := range []string{pp.Project.Name, pp.Tool.Poetry.Name} {
				if n != "" {
					names[normalizePyCoordinate(n)] = true
				}
			}
		case "setup.cfg":
			data, err := os.ReadFile(m)
			if err != nil {
				return nil, false
			}
			if n := setupCfgName(string(data)); n != "" {
				names[normalizePyCoordinate(n)] = true
			}
		case "setup.py":
			data, err := os.ReadFile(m)
			if err != nil {
				return nil, false
			}
			lits, litOK := setupPyLiteralNames(string(data))
			if !litOK && !setupCfgNamed(manifests, m) {
				return nil, false
			}
			for _, n := range lits {
				names[normalizePyCoordinate(n)] = true
			}
		}
	}
	return names, true
}

// setupCfgName returns the [metadata] name of a setup.cfg, or "".
func setupCfgName(src string) string {
	section := ""
	for _, raw := range strings.Split(src, "\n") {
		t := strings.TrimSpace(raw)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.ToLower(strings.TrimSpace(t[1 : len(t)-1]))
			continue
		}
		if section != "metadata" {
			continue
		}
		if k := strings.IndexAny(t, "=:"); k > 0 && strings.EqualFold(strings.TrimSpace(t[:k]), "name") {
			return strings.TrimSpace(t[k+1:])
		}
	}
	return ""
}

// setupCfgNamed reports whether a setup.cfg beside setupPy declares a [metadata] name (the
// common "setup.py is a shim, metadata lives in setup.cfg" layout).
func setupCfgNamed(manifests []string, setupPy string) bool {
	cfg := filepath.Join(filepath.Dir(setupPy), "setup.cfg")
	for _, m := range manifests {
		if m == cfg {
			data, err := os.ReadFile(m)
			return err == nil && setupCfgName(string(data)) != ""
		}
	}
	return false
}

// setupPyLiteralNames returns every string literal passed as a name= keyword in setup.py (an
// over-inclusive set is safe here). ok is false when there is none, or when any name= value is
// not a plain literal (setup(name=NAME)), since the project name then cannot be read.
func setupPyLiteralNames(src string) (names []string, ok bool) {
	for i := 0; ; {
		k := strings.Index(src[i:], "name")
		if k < 0 {
			return names, len(names) > 0
		}
		start := i + k
		i = start + len("name")
		if start > 0 && isIdentChar(src[start-1]) || i < len(src) && isIdentChar(src[i]) {
			continue
		}
		j := skipPySpace(src, i)
		if j >= len(src) || src[j] != '=' || j+1 < len(src) && src[j+1] == '=' {
			continue
		}
		j = skipPySpace(src, j+1)
		v, _, isF, lit := readPyString(src, j)
		if !lit || isF {
			return nil, false
		}
		names = append(names, v)
	}
}

// uvRootNames returns the normalized names of a uv.lock's project/workspace-member packages.
func uvRootNames(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lock uvLock
	if toml.Unmarshal(data, &lock) != nil {
		return nil
	}
	var out []string
	for _, p := range lock.Package {
		if p.isRoot() {
			out = append(out, normalizePyCoordinate(p.Name))
		}
	}
	return out
}

// installedDistName returns the normalized distribution name of an installed-metadata entry
// (Name-1.0.dist-info, Name.egg-info, Name-1.0-py3.11.egg-info, Name.egg-link, Name-1.0.egg).
// Installers escape '-' in the name to '_', so the name ends at the first '-'.
func installedDistName(entry string) (string, bool) {
	for _, suffix := range []string{".dist-info", ".egg-info", ".egg-link", ".egg"} {
		if base, ok := strings.CutSuffix(entry, suffix); ok && base != "" {
			if i := strings.IndexByte(base, '-'); i > 0 {
				base = base[:i]
			}
			return normalizePyCoordinate(base), true
		}
	}
	return "", false
}

// archiveNames reports whether file is a distribution archive (wheel or sdist) that could be
// coord's: its normalized name starts with coord followed by a version separator.
func archiveNames(file, coord string) bool {
	lower := strings.ToLower(file)
	for _, ext := range []string{".whl", ".tar.gz", ".tgz", ".tar.bz2", ".zip"} {
		if base, ok := strings.CutSuffix(lower, ext); ok {
			return strings.HasPrefix(normalizePyCoordinate(base), coord+"-")
		}
	}
	return false
}

// includeTarget returns the file an include line names, in any of pip's spellings
// (-r f, -rf, -r=f, --requirement f, --requirement=f, and the -c/--constraint equivalents).
func includeTarget(line string) (string, bool) {
	for _, flag := range []string{"--requirement", "--constraint", "-r", "-c"} {
		rest, ok := strings.CutPrefix(line, flag)
		if !ok {
			continue
		}
		if strings.HasPrefix(flag, "--") && rest != "" && rest[0] != '=' && rest[0] != ' ' && rest[0] != '\t' {
			continue // a longer option sharing the prefix
		}
		return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), "=")), true
	}
	return "", false
}

// pyprojectDynamicCovered reports whether a pyproject.toml that lists dependencies or
// optional-dependencies in [project].dynamic names a source for them that the resolver reads:
// a [tool.setuptools.dynamic] or hatch-requirements-txt file list (parsePyproject reads those
// files), [tool.poetry] dependencies (manifestDecls reads them for coverage), or,
// under the setuptools backend (named or defaulted), a setup.py / setup.cfg beside it (each a
// parsed manifest; setup.py must also be complete).
// Any other backend computes the field from something never read (a hatch_build.py metadata
// hook, a plugin), so the declared set is unknown.
func pyprojectDynamicCovered(path string, manifests []string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var pp pyprojectDeps
	var extra struct {
		BuildSystem struct {
			Backend string `toml:"build-backend"`
		} `toml:"build-system"`
		Tool struct {
			Poetry struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if toml.Unmarshal(data, &pp) != nil || toml.Unmarshal(data, &extra) != nil {
		return false
	}
	dir := filepath.Dir(path)
	setuptools := extra.BuildSystem.Backend == "" || strings.HasPrefix(extra.BuildSystem.Backend, "setuptools")
	for _, m := range manifests {
		if setuptools && filepath.Dir(m) == dir && (filepath.Base(m) == "setup.py" || filepath.Base(m) == "setup.cfg") {
			return true
		}
	}
	hook, _ := pp.Tool.Hatch.Metadata.Hooks["requirements_txt"].(map[string]any)
	for _, field := range pp.Project.Dynamic {
		var covered bool
		switch field {
		case "dependencies":
			_, setuptools := pp.Tool.Setuptools.Dynamic["dependencies"]
			_, hatch := hook["files"]
			covered = setuptools || hatch || len(extra.Tool.Poetry.Dependencies) > 0
		case "optional-dependencies":
			_, setuptools := pp.Tool.Setuptools.Dynamic["optional-dependencies"]
			_, hatch := hook["optional-dependencies"]
			covered = setuptools || hatch
		default:
			continue
		}
		if !covered {
			return false
		}
	}
	return true
}
