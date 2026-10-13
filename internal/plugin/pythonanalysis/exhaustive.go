package pythonanalysis

// Exhaustiveness of the advisory-path dependency set (plugin.DependencyVersionResult.Exhaustive).
//
// Exhaustive is the claim that a PyPI project absent from All is provably not installed by this
// build, which lets the pipeline's intake guard disqualify an advisory for a package the
// codebase does not have. It is claimed only against a complete, edge-bearing lockfile: uv.lock,
// pdm.lock, or poetry.lock, each of which records the full resolved closure. Anything weaker
// fails open (Exhaustive=false):
//
//   - no such lockfile (requirements files, declared-only manifests, Pipfile.lock alone);
//   - any manifest that failed to parse;
//   - any manifest outside the directory subtree a lockfile governs (a sibling project the lock
//     does not cover);
//   - any name a non-lock manifest declares that no lockfile contains, or an exact pin that
//     disagrees with every locked version of that name (a stale or partial lock);
//   - any editable, VCS, or URL requirement in a requirements file (its dependencies are not
//     enumerated anywhere we read);
//   - the coordinate names a first-party project (a uv workspace root/member, a pyproject
//     [project] or [tool.poetry] name, a setup.cfg [metadata] name, a setup.py literal name), or
//     a setup.py whose name is not a literal: lockfiles omit the project itself, so its absence
//     from them proves nothing (Go's oracle counts the root module as present for the same
//     reason);
//   - a poetry.lock whose lexical advisory read and TOML decode disagree on the package set;
//   - a pyproject.toml declaring, outside [project], a name no lockfile contains: PEP 735
//     [dependency-groups], [tool.uv] dev-dependencies, [tool.poetry] dependencies,
//     dev-dependencies and groups, [tool.pdm] dev-dependencies, [tool.hatch] environment
//     dependencies (a non-frozen sync re-locks and installs it);
//   - a requirements file whose -r/-c include is not itself a parsed manifest;
//   - anything the walk of the whole build dir (everything but .git; no skip list) finds that
//     installs packages the parsed manifests do not account for: a manifest the resolver did not
//     read (one under build/, env/, a dot-dir, ...), an install manifest it never parses
//     (requirements-style *.txt it does not recognize or any under a requirements*/ directory,
//     *.in, Pipfile, environment.yml, tox.ini deps, noxfile.py installs), a symlinked
//     directory, or an installed copy of the coordinate (a site-packages/dist-packages
//     *.dist-info or *.egg-info, a stray *.dist-info/*.egg-info, a wheel, egg, sdist archive or
//     .egg-link named for it).
//
// Lockfile group/category/dev membership is never consulted: every locked package counts as
// present whatever group it belongs to.

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// completeLockfiles are the formats whose [[package]] set is the full resolved closure.
var completeLockfiles = map[string]bool{"uv.lock": true, "pdm.lock": true, "poetry.lock": true}

// exhaustiveManifestSet reports whether the parsed manifests (found under root) enumerate every
// installable package. perFile maps each manifest path to what parseManifest returned for it.
func exhaustiveManifestSet(root, coordinate string, manifests []string, perFile map[string][]plugin.ResolvedDependency, parseFailed bool) bool {
	if parseFailed || len(manifests) == 0 {
		return false
	}
	coord := normalizePyCoordinate(coordinate)
	if names, ok := firstPartyNames(manifests); !ok || names[coord] {
		return false
	}
	parsed := make(map[string]bool, len(manifests))
	for _, m := range manifests {
		parsed[filepath.Clean(m)] = true
	}
	if !installSurfaceCovered(root, coord, parsed) {
		return false
	}
	var lockDirs []string
	locked := map[string]map[string]bool{} // normalized name → locked versions
	for _, m := range manifests {
		if !completeLockfiles[filepath.Base(m)] {
			continue
		}
		if filepath.Base(m) == "poetry.lock" && !poetryLockConsistent(m, perFile[m]) {
			return false
		}
		lockDirs = append(lockDirs, filepath.Dir(m))
		if filepath.Base(m) == "uv.lock" {
			// Workspace members are locked as editable/virtual roots, which the advisory path does
			// not emit as dependencies; a pyproject naming a sibling member is still covered.
			for _, n := range uvRootNames(m) {
				if locked[n] == nil {
					locked[n] = map[string]bool{}
				}
			}
		}
		for _, d := range perFile[m] {
			n := normalizePyCoordinate(d.Coordinate)
			if locked[n] == nil {
				locked[n] = map[string]bool{}
			}
			if d.Resolved {
				locked[n][d.Version] = true
			}
		}
	}
	if len(lockDirs) == 0 {
		return false
	}
	for _, m := range manifests {
		if !underAny(filepath.Dir(m), lockDirs) {
			return false
		}
		if completeLockfiles[filepath.Base(m)] {
			continue
		}
		if isRequirementsFile(filepath.Base(m)) && (requirementsHasUnenumeratedSource(m) || !includesParsed(m, parsed)) {
			return false
		}
		if filepath.Base(m) == "pyproject.toml" {
			names, ok := pyprojectGroupNames(m)
			if !ok {
				return false
			}
			for _, n := range names {
				if _, isLocked := locked[n]; !isLocked {
					return false
				}
			}
		}
		for _, d := range perFile[m] {
			versions, ok := locked[normalizePyCoordinate(d.Coordinate)]
			if !ok {
				return false
			}
			if d.Resolved && !versions[d.Version] {
				return false
			}
		}
	}
	return true
}

func isRequirementsFile(base string) bool {
	return strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")
}

// underAny reports whether dir is one of roots or nested beneath one.
func underAny(dir string, roots []string) bool {
	for _, r := range roots {
		rel, err := filepath.Rel(r, dir)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// requirementsHasUnenumeratedSource reports whether a requirements file declares an editable,
// VCS, or direct-URL requirement, whose own dependencies no lockfile we read enumerates.
func requirementsHasUnenumeratedSource(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	for _, raw := range joinContinuations(string(data)) {
		line := strings.TrimSpace(stripReqCommentSafe(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "-") {
			if kind, ok := optionKind(line); ok && kind == reqEditable {
				return true
			}
			continue
		}
		if _, ok := urlKind(line); ok {
			return true
		}
		if r, ok := parsePEP508(line); ok && r.URL != "" {
			return true
		}
	}
	return false
}

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

// installSurfaceCovered walks root (everything but .git) and reports whether every install
// surface in it is a manifest the resolver parsed (parsed holds their cleaned paths), and no
// installed copy of coord is present.
func installSurfaceCovered(root, coord string, parsed map[string]bool) bool {
	covered := true
	fail := func() error {
		covered = false
		return filepath.SkipAll
	}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return fail()
		}
		name := d.Name()
		if d.Type()&fs.ModeSymlink != 0 {
			info, err := os.Stat(path)
			if err != nil || info.IsDir() {
				return fail() // WalkDir does not follow it, so what it holds goes unread
			}
		}
		if d.IsDir() {
			switch {
			case name == ".git" && path != root:
				return filepath.SkipDir
			case name == "site-packages" || name == "dist-packages":
				entries, err := os.ReadDir(path)
				if err != nil {
					return fail()
				}
				for _, e := range entries {
					if n, ok := installedDistName(e.Name()); ok && n == coord {
						return fail()
					}
				}
				return filepath.SkipDir
			}
			if n, ok := installedDistName(name); ok {
				if n == coord {
					return fail()
				}
				return filepath.SkipDir
			}
			return nil
		}
		if isManifest(name) {
			if !parsed[filepath.Clean(path)] {
				return fail()
			}
			return nil
		}
		if n, ok := installedDistName(name); ok && n == coord {
			return fail()
		}
		if archiveNames(name, coord) || unparsedInstallManifest(path, name) {
			return fail()
		}
		return nil
	})
	return covered
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

// unparsedInstallManifest reports whether path is an install manifest the resolver never parses.
// The recognized requirements*.txt family is a manifest (isManifest) and is handled by the caller.
func unparsedInstallManifest(path, name string) bool {
	lower := strings.ToLower(name)
	ext := filepath.Ext(lower)
	switch {
	case name == "Pipfile":
		return true
	case (ext == ".yml" || ext == ".yaml") && (strings.HasPrefix(lower, "environment") || strings.HasPrefix(lower, "conda")):
		return true
	case ext == ".in":
		return name != "MANIFEST.in"
	case ext == ".txt":
		return strings.Contains(lower, "requirements") || strings.Contains(lower, "constraints") ||
			strings.HasPrefix(strings.ToLower(filepath.Base(filepath.Dir(path))), "requirements")
	case name == "tox.ini":
		data, err := os.ReadFile(path)
		if err != nil {
			return true
		}
		for _, line := range strings.Split(string(data), "\n") {
			if k, _, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "deps" {
				return true
			}
		}
	case name == "noxfile.py":
		data, err := os.ReadFile(path)
		return err != nil || strings.Contains(string(data), ".install(")
	}
	return false
}

// includesParsed reports whether every -r/--requirement and -c/--constraint include in the
// requirements file at path names a manifest the resolver parsed.
func includesParsed(path string, parsed map[string]bool) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, raw := range joinContinuations(string(data)) {
		line := strings.TrimSpace(stripReqCommentSafe(raw))
		target, isInclude := includeTarget(line)
		if !isInclude {
			continue
		}
		if target == "" || strings.Contains(target, "://") {
			return false
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		if !parsed[filepath.Clean(target)] {
			return false
		}
	}
	return true
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

// pyprojectGroupNames returns the normalized names a pyproject.toml declares outside [project]
// for a sync or environment to install. ok is false when the file does not decode into the
// expected shapes or an entry is not a readable requirement.
func pyprojectGroupNames(path string) (names []string, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	type poetryDeps map[string]any
	var pp struct {
		DependencyGroups map[string][]any `toml:"dependency-groups"`
		Tool             struct {
			UV struct {
				DevDependencies []string `toml:"dev-dependencies"`
			} `toml:"uv"`
			Poetry struct {
				Dependencies    poetryDeps `toml:"dependencies"`
				DevDependencies poetryDeps `toml:"dev-dependencies"`
				Group           map[string]struct {
					Dependencies poetryDeps `toml:"dependencies"`
				} `toml:"group"`
			} `toml:"poetry"`
			PDM struct {
				DevDependencies map[string][]string `toml:"dev-dependencies"`
			} `toml:"pdm"`
			Hatch struct {
				Envs map[string]struct {
					Dependencies      []string `toml:"dependencies"`
					ExtraDependencies []string `toml:"extra-dependencies"`
				} `toml:"envs"`
			} `toml:"hatch"`
		} `toml:"tool"`
	}
	if toml.Unmarshal(data, &pp) != nil {
		return nil, false
	}
	var reqs []string
	for _, group := range pp.DependencyGroups {
		for _, e := range group {
			switch v := e.(type) {
			case string:
				reqs = append(reqs, v)
			case map[string]any:
				if _, inc := v["include-group"]; !inc || len(v) != 1 {
					return nil, false
				}
			default:
				return nil, false
			}
		}
	}
	reqs = append(reqs, pp.Tool.UV.DevDependencies...)
	for _, group := range pp.Tool.PDM.DevDependencies {
		reqs = append(reqs, group...)
	}
	for _, env := range pp.Tool.Hatch.Envs {
		reqs = append(reqs, env.Dependencies...)
		reqs = append(reqs, env.ExtraDependencies...)
	}
	for _, r := range reqs {
		req, ok := parsePEP508(r)
		if !ok {
			return nil, false
		}
		names = append(names, normalizePyCoordinate(req.Name))
	}
	poetry := []poetryDeps{pp.Tool.Poetry.Dependencies, pp.Tool.Poetry.DevDependencies}
	for _, g := range pp.Tool.Poetry.Group {
		poetry = append(poetry, g.Dependencies)
	}
	for _, deps := range poetry {
		for n := range deps {
			if n != "python" {
				names = append(names, normalizePyCoordinate(n))
			}
		}
	}
	return names, true
}
