package pythonanalysis

import (
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/ferralon-ai/ferralon-assay/internal/pep440"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/scriptsurface"
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
// dependency tables, the uv and pdm dev-dependencies, and the hatch environments'
// dependencies.
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
		} `toml:"uv"`
		PDM struct {
			DevDependencies map[string]any `toml:"dev-dependencies"`
		} `toml:"pdm"`
		Hatch hatchConfig `toml:"hatch"`
	} `toml:"tool"`
}

// hatchConfig is pyproject.toml's [tool.hatch], as version resolution and the coverage
// check both read it.
type hatchConfig struct {
	Sources any `toml:"sources"`
	Env     struct {
		Collectors map[string]any `toml:"collectors"`
	} `toml:"env"`
	Envs map[string]struct {
		Type              any `toml:"type"`
		Dependencies      any `toml:"dependencies"`
		ExtraDependencies any `toml:"extra-dependencies"`
		PreInstall        any `toml:"pre-install-commands"`
		PostInstall       any `toml:"post-install-commands"`
		Scripts           any `toml:"scripts"`
		ExtraScripts      any `toml:"extra-scripts"`
		EnvVars           any `toml:"env-vars"`
		Sources           any `toml:"sources"`
		Workspace         any `toml:"workspace"`
		Overrides         any `toml:"overrides"`
	} `toml:"envs"`
}

// installsPast reports whether hatch can install what its environments' dependency lists do
// not say. Sources and workspace members redirect a declared dependency to a local path, a
// git ref or a URL at install time; a collector other than the built-in default is a plugin
// that can rewrite any environment; and an environment can install past its lists itself
// (hatchEnvInstalls).
func (h hatchConfig) installsPast() bool {
	if h.Sources != nil {
		return true
	}
	for c := range h.Env.Collectors {
		if c != "default" {
			return true
		}
	}
	for _, env := range h.Envs {
		if env.Sources != nil || env.Workspace != nil ||
			hatchEnvInstalls(env.Type, env.Overrides, env.EnvVars, env.PreInstall, env.PostInstall, env.Scripts, env.ExtraScripts) {
			return true
		}
	}
	return false
}

// parsePyprojectVersions reads pyproject.toml's [project] dependencies and
// optional-dependencies, each entry with the specifier a same-directory lock's pin must
// satisfy to cover it, dynamic dependencies from the requirement files a dynamic-metadata
// table names, and [build-system].requires, which no lock covers. The bool is false when the
// file does not decode, when an entry installs a local path other than the project itself or
// ends in a backslash (setuptoolsJoins),
// when dynamic dependencies name no file this reader can read, or when a dependency group or
// tool dependency table holds an entry it cannot read (pyprojectToolDeps).
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
	return deps, origins, readable
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
// [dependency-groups], [tool.uv] dev-dependencies, [tool.pdm] dev-dependencies and each
// [tool.hatch.envs] environment's dependencies and extra-dependencies as PEP 508 strings, and
// the [tool.poetry] dependencies, dev-dependencies and group tables as poetry constraints. Each
// declaration is covered only by its own tool's lock in the same directory (PEP 735 groups by
// groupLocks); hatch has no lock, so nothing covers its environments. ok is false when an
// entry is not a well-formed requirement, a group is malformed (dependencyGroupSpecs), a
// poetry constraint does not translate, a poetry entry installs a local path or file, or a
// hatch environment can install past its dependency lists (hatchEnvInstalls).
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
	ok = ok && !doc.Tool.Hatch.installsPast()
	for _, e := range slices.Sorted(maps.Keys(doc.Tool.Hatch.Envs)) {
		env := doc.Tool.Hatch.Envs[e]
		addAny(env.Dependencies, nil)
		addAny(env.ExtraDependencies, nil)
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

// hatchEnvInstalls reports whether a hatch environment can install what its dependency lists
// do not say: its type is not the built-in "virtual" (a plugin installs by its own keys), its
// overrides are not a table or set dependencies, extra-dependencies, commands, scripts or
// env-vars that do (matrix and other overrides add values this reader does not evaluate), a
// pre- or post-install command or a script names an installer (hatchCommandsInstall), or an
// env-var sets a PIP_* or UV_* variable, which every pip or uv the environment runs reads.
func hatchEnvInstalls(typ, overrides, envVars any, commands ...any) bool {
	if t, isStr := typ.(string); typ != nil && (!isStr || t != "virtual") {
		return true
	}
	if _, isMap := overrides.(map[string]any); overrides != nil && !isMap {
		return true
	}
	return hatchOverridesInstall(overrides) || hatchEnvVarsInstall(envVars) ||
		slices.ContainsFunc(commands, hatchCommandsInstall)
}

// hatchOverridesInstall reports whether an overrides value sets dependencies,
// extra-dependencies, sources, workspace or type anywhere in it, or sets commands, scripts or
// env-vars that install. A set- prefix overwrites the option rather than appending to it, and
// counts the same.
func hatchOverridesInstall(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, sub := range t {
			switch strings.TrimPrefix(k, "set-") {
			case "dependencies", "extra-dependencies", "sources", "workspace", "type":
				return true
			case "pre-install-commands", "post-install-commands", "scripts", "extra-scripts":
				if hatchCommandsInstall(sub) {
					return true
				}
			case "env-vars":
				if hatchEnvVarsInstall(sub) {
					return true
				}
			}
			if hatchOverridesInstall(sub) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(t, hatchOverridesInstall)
	case []map[string]any:
		return slices.ContainsFunc(t, func(m map[string]any) bool { return hatchOverridesInstall(m) })
	}
	return false
}

// hatchCommandsInstall reports whether any string in v, at any depth, has a word laneToken
// names, split the way the build-script veto splits a command (scriptsurface.NamesToken), so
// a quoted, chained, path-qualified or {env:...}-defaulted installer counts.
func hatchCommandsInstall(v any) bool {
	switch t := v.(type) {
	case string:
		return scriptsurface.NamesToken(t, laneToken, nil)
	case []any:
		return slices.ContainsFunc(t, hatchCommandsInstall)
	case map[string]any:
		return slices.ContainsFunc(slices.Collect(maps.Values(t)), hatchCommandsInstall)
	case []map[string]any:
		return slices.ContainsFunc(t, func(m map[string]any) bool { return hatchCommandsInstall(m) })
	}
	return false
}

// hatchEnvVarsInstall reports whether any key or string in v, at any depth, sets a PIP_* or
// UV_* variable (laneEnvRE), or names an installer a command can reach through $VAR or
// {env:VAR} (hatchCommandsInstall): the env-vars table, or an override's KEY=VALUE strings
// and key fields.
func hatchEnvVarsInstall(v any) bool {
	switch t := v.(type) {
	case string:
		return laneEnvRE.MatchString(t) || hatchCommandsInstall(t)
	case []any:
		return slices.ContainsFunc(t, hatchEnvVarsInstall)
	case map[string]any:
		for k, sub := range t {
			if laneEnvRE.MatchString(k) || hatchEnvVarsInstall(sub) {
				return true
			}
		}
	case []map[string]any:
		return slices.ContainsFunc(t, func(m map[string]any) bool { return hatchEnvVarsInstall(m) })
	}
	return false
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
