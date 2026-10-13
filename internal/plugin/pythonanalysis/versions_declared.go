package pythonanalysis

import (
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/ferralon-ai/ferralon-assay/internal/pep440"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// --- surfaces read only to see that they declare nothing ------------------------
//
// See declaresNothing (versions_surfaces.go). A surface that does declare dependencies takes
// the parse-failure path: the result is declared-partial and every Found match is
// UNRESOLVED, even when that surface's own lock sits beside it, since an installer
// re-resolves a stale lock.

// pipfileNonPackageTables are the Pipfile tables that are not package categories. Every
// other table ([packages], [dev-packages], and any custom pipenv category) declares
// packages.
var pipfileNonPackageTables = map[string]bool{"source": true, "requires": true, "pipenv": true, "scripts": true}

// pipfileDeclares reports whether a Pipfile has a non-empty package category.
func pipfileDeclares(data []byte) bool {
	var doc map[string]any
	if err := toml.Unmarshal(data, &doc); err != nil {
		return true
	}
	for table, v := range doc {
		if pkgs, isTable := v.(map[string]any); isTable && !pipfileNonPackageTables[table] && len(pkgs) > 0 {
			return true
		}
	}
	return false
}

// condaDeclares reports whether a conda environment file installs anything besides the
// interpreter and pip: a conda package, whose name and version scheme need not match
// PyPI's, or a pip: section.
func condaDeclares(data []byte) bool {
	var doc struct {
		Dependencies []any `yaml:"dependencies"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return true
	}
	for _, e := range doc.Dependencies {
		s, isSpec := e.(string)
		if !isSpec || !isCondaToolPackage(s) {
			return true
		}
	}
	return false
}

// isCondaToolPackage reports whether a conda spec names the interpreter or pip itself.
func isCondaToolPackage(spec string) bool {
	s := strings.TrimSpace(spec)
	if i := strings.LastIndex(s, "::"); i >= 0 {
		s = s[i+2:]
	}
	if i := strings.IndexAny(s, "=<>!~ "); i >= 0 {
		s = s[:i]
	}
	return s == "python" || s == "pip"
}

// --- pyproject.toml ----------------------------------------------------------------

// pyprojectDoc is the subset of pyproject.toml version resolution reads ([project]
// dependencies and [build-system] requires) plus the tables it recognizes as unread install
// surfaces.
type pyprojectDoc struct {
	BuildSystem struct {
		Requires []string `toml:"requires"`
	} `toml:"build-system"`
	Project struct {
		Dependencies         []string       `toml:"dependencies"`
		OptionalDependencies map[string]any `toml:"optional-dependencies"`
		Dynamic              []string       `toml:"dynamic"`
	} `toml:"project"`
	DependencyGroups map[string]any `toml:"dependency-groups"`
	Tool             struct {
		Poetry struct {
			Dependencies    map[string]any `toml:"dependencies"`
			DevDependencies map[string]any `toml:"dev-dependencies"`
			Group           map[string]struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`
		UV struct {
			DevDependencies []any `toml:"dev-dependencies"`
		} `toml:"uv"`
		PDM struct {
			DevDependencies map[string]any `toml:"dev-dependencies"`
		} `toml:"pdm"`
	} `toml:"tool"`
}

// parsePyprojectVersions reads pyproject.toml's [project].dependencies, each entry with the
// specifier a same-directory lock's pin must satisfy to cover it, and [build-system].requires,
// which no lock covers. The bool is false when the file does not decode, when an entry
// installs a local path other than the project itself, or when the file declares
// dependencies anywhere version resolution does not read: [project] optional-dependencies or
// dynamic dependencies, [dependency-groups], [tool.poetry] dependencies, dev-dependencies or
// groups, [tool.uv] dev-dependencies, or [tool.pdm] dev-dependencies.
func parsePyprojectVersions(data []byte, dir string) ([]plugin.ResolvedDependency, []manifestOrigin, bool) {
	var doc pyprojectDoc
	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, nil, false
	}
	var (
		deps     []plugin.ResolvedDependency
		origins  []manifestOrigin
		readable = !pyprojectHasUnreadTables(doc)
	)
	for _, spec := range doc.Project.Dependencies {
		d, o, keep, ok := pep508Entry(spec, dir)
		readable = readable && ok
		if keep {
			deps = append(deps, d)
			origins = append(origins, o)
		}
	}
	for _, spec := range doc.BuildSystem.Requires {
		d, o, keep, ok := pep508Entry(spec, dir)
		readable = readable && ok
		if keep {
			o.lockedBy = nil // a build frontend resolves build requirements on its own, not from the project's lock
			deps = append(deps, d)
			origins = append(origins, o)
		}
	}
	return deps, origins, readable
}

func pyprojectHasUnreadTables(doc pyprojectDoc) bool {
	for _, f := range doc.Project.Dynamic {
		if f == "dependencies" || f == "optional-dependencies" {
			return true
		}
	}
	p := doc.Tool.Poetry
	for name := range p.Dependencies {
		if !strings.EqualFold(name, "python") { // the interpreter constraint, not a package
			return true
		}
	}
	for _, g := range p.Group {
		if len(g.Dependencies) > 0 {
			return true
		}
	}
	return len(doc.Project.OptionalDependencies) > 0 || len(doc.DependencyGroups) > 0 ||
		len(p.DevDependencies) > 0 || len(doc.Tool.UV.DevDependencies) > 0 || len(doc.Tool.PDM.DevDependencies) > 0
}

// pep508Entry turns one [project].dependencies string into an entry and its origin. Only an
// exact "==" pin resolves. A "name @ url" direct reference is UNRESOLVED and no lock covers
// it. A file: URL other than the project's own directory makes ok false; the project's own
// directory is dropped (keep false).
func pep508Entry(spec, dir string) (d plugin.ResolvedDependency, o manifestOrigin, keep, ok bool) {
	s := strings.TrimSpace(spec)
	o = manifestOrigin{dir: dir, lockedBy: projectLocks}
	if loc, isFile := fileURLPath(s); isFile {
		return d, o, false, isProjectDir(loc, dir)
	}
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if name := directReferenceName(s); name != "" && strings.Contains(s, "@") {
		o.directRef = true
		return pyResolved(name, "", false, "pyproject.toml"), o, true, true
	}
	name, version, resolved, _ := parseRequirementSpec(s)
	if name == "" {
		return d, o, false, true
	}
	rest := strings.TrimSpace(s[len(name):])
	if strings.HasPrefix(rest, "[") {
		if j := strings.IndexByte(rest, ']'); j >= 0 {
			rest = strings.TrimSpace(rest[j+1:])
		}
	}
	o.spec = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(rest, "("), ")"))
	return pyResolved(name, version, resolved, "pyproject.toml"), o, true, true
}

// isSelfPath reports whether a local install path names the project's own directory.
func isSelfPath(p string) bool {
	p = strings.TrimSpace(p)
	if i := strings.IndexByte(p, '['); i >= 0 { // ".[dev]" installs the project with extras
		p = p[:i]
	}
	p = strings.TrimRight(p, "/")
	return p == "."
}

// --- lock pin against a declared specifier ---------------------------------------

// lockPinSatisfies reports whether a lock's pinned version satisfies the declaration's PEP
// 440 specifier, so the lock is the declaration's resolution rather than a stale one. A
// direct reference is never covered. Anything this cannot evaluate (an unparseable version
// or clause) reports false, so the declaration keeps its veto.
func lockPinSatisfies(o manifestOrigin, version string) bool {
	if o.directRef {
		return false
	}
	v, ok := pep440.Parse(version)
	if !ok {
		return false
	}
	spec := strings.TrimSpace(o.spec)
	if spec == "" {
		return true
	}
	for _, c := range strings.Split(spec, ",") {
		if sat, cok := pep440.Satisfies(v, version, strings.TrimSpace(c)); !cok || !sat {
			return false
		}
	}
	return true
}
