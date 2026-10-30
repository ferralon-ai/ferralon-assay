package pythonanalysis

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
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

// pyprojectDoc is the subset of pyproject.toml version resolution reads: [project]
// dependencies, [build-system] requires, PEP 735 [dependency-groups], the [tool.poetry]
// dependency tables, the uv and pdm dev-dependencies, and the names [tool.uv.sources] redirects.
type pyprojectDoc struct {
	BuildSystem struct {
		Requires []string `toml:"requires"`
	} `toml:"build-system"`
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
		Dynamic              []string            `toml:"dynamic"`
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
			Sources         any   `toml:"sources"`
		} `toml:"uv"`
		PDM struct {
			DevDependencies map[string]any `toml:"dev-dependencies"`
		} `toml:"pdm"`
	} `toml:"tool"`
}

// parsePyprojectVersions reads pyproject.toml's [project] dependencies and
// optional-dependencies, each entry with the specifier a same-directory lock's pin must
// satisfy to cover it, dynamic dependencies from the requirement files a dynamic-metadata
// table names, and [build-system].requires, which no lock covers. The bool is false when the
// file does not decode, when an entry installs a local path other than the project itself or
// ends in a backslash (setuptoolsJoins),
// when dynamic dependencies name no file this reader can read, when a dependency group or
// tool dependency table holds an entry it cannot read (pyprojectToolDeps), or when
// [tool.uv.sources] is not a table. An entry [tool.uv.sources] names is a direct reference.
func parsePyprojectVersions(path string, data []byte, dir string) ([]plugin.ResolvedDependency, []manifestOrigin, bool) {
	var doc pyprojectDoc
	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, nil, false
	}
	var (
		deps     []plugin.ResolvedDependency
		origins  []manifestOrigin
		readable = true
	)
	addSpec := func(spec string) {
		d, o, keep, ok := pep508Entry(spec, dir)
		readable = readable && ok && !setuptoolsJoins(spec)
		if keep {
			deps = append(deps, d)
			origins = append(origins, o)
		}
	}
	for _, spec := range doc.Project.Dependencies {
		addSpec(spec)
	}
	for _, g := range slices.Sorted(maps.Keys(doc.Project.OptionalDependencies)) {
		for _, spec := range doc.Project.OptionalDependencies[g] {
			addSpec(spec)
		}
	}
	tdeps, torigins, tok := pyprojectToolDeps(doc, dir)
	deps, origins, readable = append(deps, tdeps...), append(origins, torigins...), readable && tok
	if pyprojectDynamicDeps(doc) {
		// Dynamic dependencies are read only from the requirement files a dynamic-metadata
		// table names; with none named, nothing here can say what the build backend will
		// declare.
		var pp pyprojectDeps
		if err := toml.Unmarshal(data, &pp); err != nil {
			return deps, origins, false
		}
		files, ok := pyprojectDynamicFiles(pp)
		if !ok || len(files) == 0 {
			return deps, origins, false
		}
		for _, f := range files {
			fdeps, fileOK := readRequirementFiles(filepath.Dir(path), f, "pyproject.toml")
			deps = append(deps, fdeps...)
			origins = append(origins, originsFor(fdeps, manifestOrigin{dir: dir})...)
			readable = readable && fileOK
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
	redirected, sourcesOK := uvSourceNames(doc.Tool.UV.Sources)
	readable = readable && sourcesOK
	for i, d := range deps {
		if redirected[normalizePyCoordinate(d.Coordinate)] {
			deps[i] = pyResolved(d.Coordinate, "", false, d.Source)
			origins[i].directRef = true
		}
	}
	return deps, origins, readable
}

// uvSourceNames returns the normalized names a [tool.uv.sources] table redirects. uv installs
// each from its source (a git ref, a URL, a local path, a workspace member or a named index)
// whatever the declaration's specifier says, so its entries read as direct references: never
// resolved here, and never covered by a lock. ok is false when the table is not a table.
func uvSourceNames(sources any) (map[string]bool, bool) {
	if sources == nil {
		return nil, true
	}
	t, isMap := sources.(map[string]any)
	if !isMap {
		return nil, false
	}
	names := make(map[string]bool, len(t))
	for name := range t {
		names[normalizePyCoordinate(name)] = true
	}
	return names, true
}

// uvSourced reports whether any pyproject.toml among manifests names want in [tool.uv.sources].
// A workspace root's sources apply to every member, and a lock written before the source was
// added still pins an index release, so a source anywhere leaves the coordinate unresolved and
// its lock entries incomplete. A pyproject that does not decode is already read as a failure.
func uvSourced(manifests []string, want string) bool {
	for _, m := range manifests {
		if filepath.Base(m) != "pyproject.toml" {
			continue
		}
		data, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		var doc pyprojectDoc
		if toml.Unmarshal(data, &doc) != nil {
			continue
		}
		if names, _ := uvSourceNames(doc.Tool.UV.Sources); names[want] {
			return true
		}
	}
	return false
}

// pyprojectDynamicDeps reports whether [project].dynamic lists dependencies or
// optional-dependencies.
func pyprojectDynamicDeps(doc pyprojectDoc) bool {
	for _, f := range doc.Project.Dynamic {
		if f == "dependencies" || f == "optional-dependencies" {
			return true
		}
	}
	return false
}

// pyprojectToolDeps reads the pyproject tables that declare installs outside [project]: PEP 735
// [dependency-groups], [tool.uv] dev-dependencies and [tool.pdm] dev-dependencies as PEP 508
// strings, and the [tool.poetry] dependencies, dev-dependencies and group tables as poetry
// constraints. Each declaration is covered only by its own tool's lock in the same directory
// (PEP 735 groups by groupLocks). ok is false when an entry is not a well-formed
// requirement, a group is malformed (dependencyGroupSpecs), a poetry constraint does not
// translate, or a poetry entry installs a local path or file.
func pyprojectToolDeps(doc pyprojectDoc, dir string) ([]plugin.ResolvedDependency, []manifestOrigin, bool) {
	var (
		deps    []plugin.ResolvedDependency
		origins []manifestOrigin
		ok      = true
	)
	addPEP508 := func(spec string, lockedBy []string) {
		d, o, keep, entryOK := pep508Entry(spec, dir)
		ok = ok && entryOK
		if keep {
			o.lockedBy = lockedBy
			deps = append(deps, d)
			origins = append(origins, o)
		}
	}
	addAny := func(v any, lockedBy []string) {
		entries, isList := v.([]any)
		if v != nil && !isList {
			ok = false
			return
		}
		for _, e := range entries {
			s, isStr := e.(string)
			if !isStr {
				ok = false
				return
			}
			addPEP508(s, lockedBy)
		}
	}

	groupSpecs, groupsOK := dependencyGroupSpecs(doc.DependencyGroups)
	ok = ok && groupsOK
	for _, s := range groupSpecs {
		addPEP508(s, groupLocks)
	}
	addAny(doc.Tool.UV.DevDependencies, []string{"uv.lock"})
	for _, g := range slices.Sorted(maps.Keys(doc.Tool.PDM.DevDependencies)) {
		addAny(doc.Tool.PDM.DevDependencies[g], []string{"pdm.lock"})
	}

	p := doc.Tool.Poetry
	tables := []map[string]any{p.Dependencies, p.DevDependencies}
	for _, g := range slices.Sorted(maps.Keys(p.Group)) {
		tables = append(tables, p.Group[g].Dependencies)
	}
	for _, t := range tables {
		for _, name := range slices.Sorted(maps.Keys(t)) {
			if strings.EqualFold(name, "python") { // the interpreter constraint, not a package
				continue
			}
			if poetryInstallsLocal(t[name]) {
				ok = false
				continue
			}
			decls, declOK := poetryDecls(name, t[name])
			if !declOK {
				ok = false
				continue
			}
			for _, d := range decls {
				if d.Direct {
					deps = append(deps, pyResolved(name, "", false, "pyproject.toml"))
					origins = append(origins, manifestOrigin{dir: dir, directRef: true})
					continue
				}
				addPEP508(name+d.Specifier, []string{"poetry.lock"})
			}
		}
	}
	return deps, origins, ok
}

// poetryInstallsLocal reports whether a [tool.poetry] dependency value, or any element of an
// array of them, installs from a local path or file, whose version nothing here reads.
func poetryInstallsLocal(v any) bool {
	entries, isList := v.([]any)
	if !isList {
		entries = []any{v}
	}
	for _, e := range entries {
		if m, isMap := e.(map[string]any); isMap {
			if _, has := m["path"]; has {
				return true
			}
			if _, has := m["file"]; has {
				return true
			}
		}
	}
	return false
}

// dependencyGroupSpecs returns every requirement string a PEP 735 [dependency-groups] table
// declares, group by group in sorted order. An {include-group = "..."} entry adds nothing,
// since every group is read; it is only checked. ok is false, and the table must be treated as
// unread, when two group names normalize alike, a group is not an array, an entry is neither a
// string nor a table whose only key is include-group with a string value, an include names no
// group, or includes form a cycle: an installer rejects each of these, so nothing here can say
// what it installs. The strings themselves are not validated.
func dependencyGroupSpecs(groups map[string]any) ([]string, bool) {
	entries := make(map[string][]any, len(groups))
	for name, v := range groups {
		n := normalizePyCoordinate(name)
		list, isList := v.([]any)
		if _, dup := entries[n]; dup || !isList {
			return nil, false
		}
		entries[n] = list
	}
	includes := make(map[string][]string, len(entries))
	var specs []string
	for _, g := range slices.Sorted(maps.Keys(entries)) {
		for _, e := range entries[g] {
			switch v := e.(type) {
			case string:
				specs = append(specs, v)
			case map[string]any:
				target, isStr := v["include-group"].(string)
				if !isStr || len(v) != 1 {
					return nil, false
				}
				t := normalizePyCoordinate(target)
				if _, known := entries[t]; !known {
					return nil, false
				}
				includes[g] = append(includes[g], t)
			default:
				return nil, false
			}
		}
	}
	const (
		visiting = 1
		done     = 2
	)
	state := make(map[string]int, len(entries))
	var acyclic func(string) bool
	acyclic = func(g string) bool {
		switch state[g] {
		case visiting:
			return false
		case done:
			return true
		}
		state[g] = visiting
		for _, t := range includes[g] {
			if !acyclic(t) {
				return false
			}
		}
		state[g] = done
		return true
	}
	for _, g := range slices.Sorted(maps.Keys(entries)) {
		if !acyclic(g) {
			return nil, false
		}
	}
	return specs, true
}

// pep508Entry turns one [project].dependencies string into an entry and its origin. Only an
// exact "==" pin resolves. A "name @ url" direct reference is UNRESOLVED and no lock covers
// it. A file: URL other than the project's own directory makes ok false; the project's own
// directory is dropped (keep false). Name and specifier come from parsePEP508, and a string
// it rejects makes ok false.
func pep508Entry(spec, dir string) (d plugin.ResolvedDependency, o manifestOrigin, keep, ok bool) {
	s := strings.TrimSpace(spec)
	o = manifestOrigin{dir: dir, lockedBy: projectLocks}
	if loc, isFile := fileURLPath(s); isFile {
		return d, o, false, isProjectDir(loc, dir)
	}
	r, valid := parsePEP508(s)
	if !valid {
		return d, o, false, false
	}
	if r.URL != "" {
		o.directRef = true
		return pyResolved(r.Name, "", false, "pyproject.toml"), o, true, true
	}
	o.spec = r.Specifier
	version, resolved := specifierPin(r.Specifier)
	d = pyResolved(r.Name, version, resolved, "pyproject.toml")
	if !d.Resolved {
		d.Constraint = r.Specifier
	}
	return d, o, true, true
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
