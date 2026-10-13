package pythonanalysis

// The Python install-surface classifier: which files under a build dir name or hold something
// a Python installer could read, and whether the resolver reads each of them fully.

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
)

// ManifestCandidates returns every Python install surface under root, sorted by path: each file
// whose name or content looks like a Python manifest, lockfile or requirement file
// (pyCandidate), plus every symlink that leaves root, symlinked directory the walk does not
// read through its target, and unreadable entry (buildtree.Candidates). FullyRead is true only for a regular file the resolver discovers
// (manifestFiles) or reads through a discovered manifest's file directive, that parses, and
// whose parse captures everything it can cause to be installed (pySurface.fullyRead).
func ManifestCandidates(root string) []buildtree.Candidate {
	return newPySurface(root).candidates()
}

// pySurface is one build dir's resolver view, shared by ManifestCandidates and the
// Exhaustive check so both judge a file the same way.
type pySurface struct {
	root       string
	manifests  []string        // manifestFiles(root), cleaned
	discovered map[string]bool // the same set, by cleaned path
	readVia    map[string]bool // files read in full through a fully read manifest's file directive
	memo       map[string]bool // fullyRead results
	visiting   map[string]bool // fullyRead cycle guard
}

func newPySurface(root string) *pySurface {
	s := &pySurface{
		root:       root,
		discovered: map[string]bool{},
		readVia:    map[string]bool{},
		memo:       map[string]bool{},
		visiting:   map[string]bool{},
	}
	for _, m := range manifestFiles(root) {
		m = filepath.Clean(m)
		s.manifests = append(s.manifests, m)
		s.discovered[m] = true
	}
	for _, m := range s.manifests {
		if base := filepath.Base(m); base != "pyproject.toml" && base != "setup.cfg" {
			continue
		}
		if decls, ok := manifestDecls(m); ok && s.fullyRead(m) {
			for _, f := range decls.files {
				s.readVia[f] = true
			}
		}
	}
	return s
}

func (s *pySurface) candidates() []buildtree.Candidate {
	cs := buildtree.Candidates(s.root, pyCandidate, func(path string) bool {
		p := filepath.Clean(path)
		return s.readVia[p] || s.fullyRead(p)
	})
	slices.SortFunc(cs, func(a, b buildtree.Candidate) int { return strings.Compare(a.Path, b.Path) })
	return cs
}

// fullyRead reports whether the discovered manifest at path is a regular file that parses and
// whose every installable declaration the coverage check reads (manifestDecls), with every
// requirement-file include it names itself fully read. hatch_build.py never is: a build hook
// can add dependencies the source does not spell out.
func (s *pySurface) fullyRead(path string) bool {
	if done, ok := s.memo[path]; ok {
		return done
	}
	if s.visiting[path] {
		return true // an include cycle adds nothing beyond the files already on it
	}
	s.visiting[path] = true
	got := s.fullyReadUncached(path)
	delete(s.visiting, path)
	s.memo[path] = got
	return got
}

func (s *pySurface) fullyReadUncached(path string) bool {
	if !s.discovered[path] {
		return false
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return false
	}
	if _, ok := parseManifest(path); !ok {
		return false
	}
	switch base := filepath.Base(path); {
	case base == "hatch_build.py":
		return false
	case base == "poetry.lock":
		deps, _ := parseManifest(path)
		return poetryLockConsistent(path, deps)
	case completeLockfiles[base] || base == "Pipfile.lock":
		return true
	case base == "pyproject.toml":
		if !pyprojectDynamicCovered(path, s.manifests) {
			return false
		}
	}
	decls, ok := manifestDecls(path)
	if !ok {
		return false
	}
	for _, inc := range decls.includes {
		if !s.readVia[inc] && !s.fullyRead(inc) {
			return false
		}
	}
	return true
}

// foreignLocks are *.lock files other ecosystems own; every other *.lock is a Python candidate.
var foreignLocks = map[string]bool{
	"Cargo.lock": true, "Gemfile.lock": true, "composer.lock": true, "yarn.lock": true,
	"bun.lock": true, "bun.lockb": true, "deno.lock": true, "flake.lock": true, "Podfile.lock": true,
	"mix.lock": true, "pubspec.lock": true, "conan.lock": true, "paket.lock": true,
	"packages.lock": true, "Package.resolved": true, "gradle.lockfile": true, "go.sum": true,
	"Cartfile.resolved": true, "shard.lock": true, "renv.lock": true, "Manifest.toml": true,
	"cabal.project.freeze": true, "stack.yaml.lock": true, "elm.lock": true, "esy.lock": true,
	"pnpm-lock.yaml": true, "package-lock.json": true, "npm-shrinkwrap.json": true,
}

// docExts are formats no Python installer reads its configuration from, so a TOML or YAML
// snippet quoted in one is documentation, not a manifest. A requirement file can have any
// name, so the requirement-line rule still applies to them.
var docExts = map[string]bool{
	".md": true, ".markdown": true, ".rst": true, ".adoc": true, ".html": true, ".htm": true,
	".ipynb": true, ".py": true, ".pyi": true,
}

// pyCandidate is the Python classifier: it reports whether the file at path, with up to
// buildtree.HeadSize bytes of content head (nil when binary or empty), names or holds a Python
// install surface, and the rule that matched.
func pyCandidate(path string, head []byte) (string, bool) {
	if why, ok := pyCandidateName(path); ok {
		return why, true
	}
	return pyCandidateContent(path, head)
}

func pyCandidateName(path string) (string, bool) {
	if inner, ok := buildtree.TemplateInner(path); ok {
		if why, ok := pyCandidateName(inner); ok {
			return "templated " + why, true
		}
	}
	name := filepath.Base(path)
	lower := strings.ToLower(name)
	ext := filepath.Ext(lower)
	dir := strings.ToLower(filepath.Base(filepath.Dir(path)))
	switch {
	case isManifest(name):
		return "manifest name", true
	case name == "Pipfile", name == "pixi.toml", name == "pixi.lock", name == "pylock.toml",
		strings.HasPrefix(lower, "pylock.") && ext == ".toml",
		strings.HasPrefix(lower, "conda-lock") && (ext == ".yml" || ext == ".yaml"):
		return "install manifest name", true
	case (ext == ".yml" || ext == ".yaml") && (strings.HasPrefix(lower, "environment") || strings.HasPrefix(lower, "conda")):
		return "conda environment name", true
	case ext == ".in" && name != "MANIFEST.in":
		return "requirements input name", true
	case (ext == ".txt" || ext == ".lock" || ext == ".pip") &&
		(strings.Contains(lower, "requirement") || strings.Contains(lower, "constraint") || strings.HasPrefix(dir, "requirements")):
		return "requirements file name", true
	case (ext == ".lock" || ext == ".lockb") && !foreignLocks[name]:
		return "lockfile name", true
	case name == "tox.ini":
		if data, err := readRegular(path); err != nil || toxHasDeps(string(data)) {
			return "tox deps", true
		}
	case name == "noxfile.py":
		if data, err := readRegular(path); err != nil || strings.Contains(string(data), ".install(") {
			return "nox install", true
		}
	}
	return "", false
}

func toxHasDeps(src string) bool {
	for _, line := range strings.Split(src, "\n") {
		if k, _, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "deps" {
			return true
		}
	}
	return false
}

// pyTOMLHeaders are tables only a Python project or environment definition declares.
var pyTOMLHeaders = []string{
	"[project]", "[build-system]", "[dependency-groups]", "[pypi-dependencies]",
	"[tool.poetry", "[tool.pdm", "[tool.uv", "[tool.hatch", "[tool.setuptools", "[tool.pixi",
}

// pyLockMarkers are strings a Python lockfile's [[package]] entries carry.
var pyLockMarkers = []string{"requires-python", "requires_python", "python-versions", "pythonhosted.org", "pypi.org"}

func pyCandidateContent(path string, head []byte) (string, bool) {
	if head == nil {
		return "", false
	}
	src := string(head)
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".py" {
		if strings.Contains(src, "setup(") || strings.Contains(src, "setuptools") {
			for _, k := range []string{"install_requires", "setup_requires", "extras_require", "tests_require"} {
				if strings.Contains(src, k) {
					return "setup() call content", true
				}
			}
		}
		return "", false
	}
	if requirementLines(src) {
		return "requirement lines", true
	}
	if docExts[ext] {
		return "", false
	}
	lines := strings.Split(src, "\n")
	hasLine := func(pred func(string) bool) bool {
		for _, l := range lines {
			if pred(strings.TrimRight(l, "\r")) {
				return true
			}
		}
		return false
	}
	if hasLine(func(l string) bool {
		t := strings.TrimSpace(l)
		for _, h := range pyTOMLHeaders {
			if t == h || strings.HasPrefix(h, "[tool.") && strings.HasPrefix(t, h) && (t[len(h)] == ']' || t[len(h)] == '.') {
				return true
			}
		}
		return false
	}) {
		return "Python TOML table", true
	}
	if hasLine(func(l string) bool { return strings.TrimSpace(l) == "[[package]]" }) &&
		!strings.Contains(src, "crates.io-index") && !strings.Contains(src, "@generated by Cargo") {
		for _, m := range pyLockMarkers {
			if strings.Contains(src, m) {
				return "Python lock content", true
			}
		}
	}
	if hasLine(func(l string) bool { return strings.HasPrefix(l, "dependencies:") }) &&
		hasLine(func(l string) bool {
			t := strings.TrimSpace(l)
			return t == "- pip:" || strings.HasPrefix(l, "channels:")
		}) {
		return "conda environment content", true
	}
	return "", false
}

// requirementLines reports whether src reads as a pip requirements file: every non-comment
// logical line is a well-formed PEP 508 requirement or a pip option, and at least one line
// carries a version operator, a direct reference or an option, so a list of bare words (a
// word list, a VERSION file) is not taken for one.
func requirementLines(src string) bool {
	strong := false
	for _, raw := range joinContinuations(src) {
		line := strings.TrimSpace(stripReqCommentSafe(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "-") {
			if len(line) < 2 || !(line[1] == '-' || line[1] >= 'a' && line[1] <= 'z' || line[1] >= 'A' && line[1] <= 'Z') {
				return false
			}
			strong = true
			continue
		}
		if i := strings.Index(line, " --"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		r, ok := parsePEP508(line)
		if !ok {
			return false
		}
		if r.Specifier != "" || r.URL != "" {
			strong = true
		}
	}
	return strong
}
