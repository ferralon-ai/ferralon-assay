package pythonanalysis

// Per-lock coverage: what each non-lock manifest declares for installation (manifestDecls), what
// each complete lockfile records (readPyLock), and whether one lock, on its own, holds every
// declaration of one manifest at a version its range admits and with the extras it asks for.

import (
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/ferralon-ai/ferralon-assay/internal/pep440"
)

// pyDecl is one requirement a manifest declares for installation.
type pyDecl struct {
	Name      string   // normalized project name
	Specifier string   // comma-separated PEP 440 clauses; "" admits any version
	Extras    []string // normalized extra names
	Marked    bool     // carries an environment marker (applies to some environments only)
	Direct    bool     // a direct reference (path, VCS, URL) the lock resolves under its name
}

// pyDecls is what manifestDecls read from one manifest.
type pyDecls struct {
	reqs     []pyDecl
	files    []string // requirement files read in full through a file directive (cleaned)
	includes []string // requirement files a -r/-c line names (cleaned), each checked on its own
	nested   []string // the -r includes among them: pip installs what they list with the file
	hashed   bool     // a requirement line carries --hash, or an option line is --require-hashes
}

// manifestDecls returns every requirement the non-lock manifest at path declares in a role that
// installs it at runtime or into a development environment: requirements lines, PEP 621
// dependencies and optional-dependencies (with the files a dynamic-metadata table names), PEP
// 735 groups, uv/pdm dev-dependencies, hatch environments, poetry dependency tables, setup.cfg
// and setup.py install_requires and extras_require, and Pipfile.lock pins. Build-time
// requirements ([build-system].requires, setup_requires) are not among them: they install into
// an isolated build environment, not the runtime one, and no lockfile records them. ok is
// false when anything the file declares cannot be read as a requirement: an editable, VCS or
// URL requirements line, an unreadable entry, a pyproject that does not decode or configures
// pixi, a computed setup.py, any hatch_build.py.
func manifestDecls(path string) (pyDecls, bool) {
	data, err := readRegular(path)
	if err != nil {
		return pyDecls{}, false
	}
	var out pyDecls
	add := func(spec string, direct bool) bool {
		r, ok := parsePEP508(spec)
		if !ok || r.URL != "" && !direct {
			return false
		}
		out.reqs = append(out.reqs, pyDecl{
			Name:      normalizePyCoordinate(r.Name),
			Specifier: r.Specifier,
			Extras:    r.Extras,
			Marked:    r.Marker != "",
			Direct:    r.URL != "",
		})
		return true
	}
	addAll := func(specs []string, direct bool) bool {
		for _, s := range specs {
			if !add(s, direct) {
				return false
			}
		}
		return true
	}
	switch base := filepath.Base(path); {
	case base == "hatch_build.py":
		return out, false
	case base == "setup.py":
		specs, complete := scanSetupPy(string(data))
		return out, complete && addAll(specs, true)
	case base == "setup.cfg":
		scan := scanSetupCfg(path, data)
		out.files = scan.files
		return out, scan.ok && addAll(scan.specs, true)
	case base == "pyproject.toml":
		return pyprojectDecls(path, data, out)
	case base == "Pipfile.lock":
		deps, ok := parsePipfileLock(data)
		for _, d := range deps {
			spec := ""
			if d.Resolved {
				spec = "==" + d.Version
			}
			out.reqs = append(out.reqs, pyDecl{Name: normalizePyCoordinate(d.Coordinate), Specifier: spec})
		}
		return out, ok
	case isManifest(base): // requirements*.txt
		return requirementsDecls(path, data, out)
	}
	return out, false
}

// requirementsDecls reads a pip requirements file. Each -r/-c include is recorded for the caller
// to check on its own; other option lines (--index-url, --hash, ...) declare nothing. An
// editable, VCS, URL or local-path line, or any line that is not a requirement, is not read.
func requirementsDecls(path string, data []byte, out pyDecls) (pyDecls, bool) {
	for _, raw := range joinContinuations(string(data)) {
		line := strings.TrimSpace(stripReqCommentSafe(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "-") {
			if target, isInclude := includeTarget(line); isInclude {
				if target == "" || strings.Contains(target, "://") {
					return out, false
				}
				if !filepath.IsAbs(target) {
					target = filepath.Join(filepath.Dir(path), target)
				}
				out.includes = append(out.includes, filepath.Clean(target))
				if !strings.HasPrefix(line, "-c") && !strings.HasPrefix(line, "--constraint") {
					out.nested = append(out.nested, filepath.Clean(target))
				}
				continue
			}
			if kind, ok := optionKind(line); ok && kind == reqEditable {
				return out, false
			}
			if f := strings.Fields(line); f[0] == "--require-hashes" {
				out.hashed = true
			}
			continue
		}
		if _, isURL := urlKind(line); isURL {
			return out, false
		}
		if i := strings.Index(line, " --"); i >= 0 {
			for _, f := range strings.Fields(line[i:]) {
				out.hashed = out.hashed || f == "--hash" || strings.HasPrefix(f, "--hash=")
			}
			line = strings.TrimSpace(line[:i])
		}
		r, ok := parsePEP508(line)
		if !ok || r.URL != "" {
			return out, false
		}
		out.reqs = append(out.reqs, pyDecl{
			Name:      normalizePyCoordinate(r.Name),
			Specifier: r.Specifier,
			Extras:    r.Extras,
			Marked:    r.Marker != "",
		})
	}
	return out, true
}

// pyprojectAll is every pyproject.toml table that declares something to install.
type pyprojectAll struct {
	DependencyGroups map[string][]any `toml:"dependency-groups"`
	Tool             struct {
		UV struct {
			DevDependencies []string `toml:"dev-dependencies"`
		} `toml:"uv"`
		Poetry struct {
			Dependencies    map[string]any `toml:"dependencies"`
			DevDependencies map[string]any `toml:"dev-dependencies"`
			Group           map[string]struct {
				Dependencies map[string]any `toml:"dependencies"`
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
		Pixi map[string]any `toml:"pixi"`
	} `toml:"tool"`
}

func pyprojectDecls(path string, data []byte, out pyDecls) (pyDecls, bool) {
	var pp pyprojectDeps
	var all pyprojectAll
	if toml.Unmarshal(data, &pp) != nil || toml.Unmarshal(data, &all) != nil || all.Tool.Pixi != nil {
		return out, false
	}
	add := func(specs []string) bool {
		for _, s := range specs {
			r, ok := parsePEP508(s)
			if !ok {
				return false
			}
			out.reqs = append(out.reqs, pyDecl{
				Name:      normalizePyCoordinate(r.Name),
				Specifier: r.Specifier,
				Extras:    r.Extras,
				Marked:    r.Marker != "",
				Direct:    r.URL != "",
			})
		}
		return true
	}
	addProject := func(specs []string) bool {
		return !slices.ContainsFunc(specs, setuptoolsJoins) && add(specs)
	}
	if !addProject(pp.Project.Dependencies) {
		return out, false
	}
	for _, g := range slices.Sorted(maps.Keys(pp.Project.OptionalDependencies)) {
		if !addProject(pp.Project.OptionalDependencies[g]) {
			return out, false
		}
	}
	files, ok := pyprojectDynamicFiles(pp)
	if !ok {
		return out, false
	}
	for _, f := range files {
		specs, read, ok := readRequirementSpecs(filepath.Dir(path), f)
		out.files = append(out.files, read...)
		if !ok || !add(specs) {
			return out, false
		}
	}
	for _, g := range slices.Sorted(maps.Keys(all.DependencyGroups)) {
		for _, e := range all.DependencyGroups[g] {
			switch v := e.(type) {
			case string:
				if !add([]string{v}) {
					return out, false
				}
			case map[string]any:
				if _, inc := v["include-group"]; !inc || len(v) != 1 {
					return out, false
				}
			default:
				return out, false
			}
		}
	}
	if !add(all.Tool.UV.DevDependencies) {
		return out, false
	}
	for _, g := range slices.Sorted(maps.Keys(all.Tool.PDM.DevDependencies)) {
		if !add(all.Tool.PDM.DevDependencies[g]) {
			return out, false
		}
	}
	for _, e := range slices.Sorted(maps.Keys(all.Tool.Hatch.Envs)) {
		env := all.Tool.Hatch.Envs[e]
		if !add(env.Dependencies) || !add(env.ExtraDependencies) {
			return out, false
		}
	}
	poetry := []map[string]any{all.Tool.Poetry.Dependencies, all.Tool.Poetry.DevDependencies}
	for _, g := range slices.Sorted(maps.Keys(all.Tool.Poetry.Group)) {
		poetry = append(poetry, all.Tool.Poetry.Group[g].Dependencies)
	}
	for _, deps := range poetry {
		for _, n := range slices.Sorted(maps.Keys(deps)) {
			if n == "python" {
				continue
			}
			ds, ok := poetryDecls(n, deps[n])
			if !ok {
				return out, false
			}
			out.reqs = append(out.reqs, ds...)
		}
	}
	return out, true
}

// poetryDecls reads one [tool.poetry] dependency: a constraint string, an inline table (version,
// extras, markers, python, optional, or a git/path/url/file source), or an array of such tables.
func poetryDecls(name string, v any) ([]pyDecl, bool) {
	if !validProjectName(name) {
		return nil, false
	}
	n := normalizePyCoordinate(name)
	switch t := v.(type) {
	case string:
		spec, ok := poetrySpecifier(t)
		return []pyDecl{{Name: n, Specifier: spec}}, ok
	case map[string]any:
		d := pyDecl{Name: n}
		for _, k := range []string{"git", "path", "url", "file"} {
			if _, has := t[k]; has {
				d.Direct = true
			}
		}
		if ver, has := t["version"]; has {
			s, isStr := ver.(string)
			if !isStr {
				return nil, false
			}
			spec, ok := poetrySpecifier(s)
			if !ok {
				return nil, false
			}
			d.Specifier = spec
		}
		if xs, has := t["extras"]; has {
			list, isList := stringList(xs)
			if !isList {
				return nil, false
			}
			for _, x := range list {
				d.Extras = append(d.Extras, normalizePyCoordinate(x))
			}
		}
		_, markers := t["markers"]
		_, python := t["python"]
		_, platform := t["platform"]
		d.Marked = markers || python || platform
		return []pyDecl{d}, true
	case []any:
		var out []pyDecl
		for _, e := range t {
			m, isMap := e.(map[string]any)
			if !isMap {
				return nil, false
			}
			ds, ok := poetryDecls(name, m)
			if !ok {
				return nil, false
			}
			for i := range ds {
				ds[i].Marked = true // one of several environment-specific constraints
			}
			out = append(out, ds...)
		}
		return out, true
	}
	return nil, false
}

// poetrySpecifier translates a poetry constraint ("^1.2", "~1.2.3", "1.2.*", ">=1,<2", "1.2.3",
// "*") into comma-separated PEP 440 clauses. ok is false for an alternation ("||") or any clause
// it cannot translate.
func poetrySpecifier(c string) (string, bool) {
	c = strings.TrimSpace(c)
	if c == "" || c == "*" {
		return "", true
	}
	if strings.Contains(c, "||") || strings.Contains(c, "|") {
		return "", false
	}
	var clauses []string
	for _, part := range strings.FieldsFunc(c, func(r rune) bool { return r == ',' }) {
		for _, tok := range joinPoetryOps(strings.Fields(part)) {
			cl, ok := poetryClause(tok)
			if !ok {
				return "", false
			}
			clauses = append(clauses, cl...)
		}
	}
	return strings.Join(clauses, ","), true
}

// joinPoetryOps rejoins an operator written apart from its version (">= 1.2") into one token.
func joinPoetryOps(fields []string) []string {
	var out []string
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if strings.Trim(f, "<>=!~^") == "" && i+1 < len(fields) {
			f += fields[i+1]
			i++
		}
		out = append(out, f)
	}
	return out
}

func poetryClause(tok string) ([]string, bool) {
	switch {
	case tok == "*":
		return nil, true
	case strings.HasPrefix(tok, "^"):
		return caretRange(tok[1:])
	case strings.HasPrefix(tok, "~") && !strings.HasPrefix(tok, "~="):
		return tildeRange(tok[1:])
	case strings.HasPrefix(tok, "==="), strings.HasPrefix(tok, "=="), strings.HasPrefix(tok, "!="),
		strings.HasPrefix(tok, ">="), strings.HasPrefix(tok, "<="), strings.HasPrefix(tok, "~="),
		strings.HasPrefix(tok, ">"), strings.HasPrefix(tok, "<"):
		return []string{tok}, true
	case strings.HasPrefix(tok, "="):
		return []string{"=" + tok}, true
	}
	if _, ok := pep440.Parse(strings.TrimSuffix(tok, ".*")); ok {
		return []string{"==" + tok}, true
	}
	return nil, false
}

// releaseParts splits a plain release ("1.2.3") into its numbers.
func releaseParts(v string) ([]int, bool) {
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, len(out) > 0
}

func joinRelease(parts []int) string {
	s := make([]string, len(parts))
	for i, p := range parts {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ".")
}

// caretRange: ^1.2.3 is >=1.2.3,<2.0.0; ^0.2.3 is >=0.2.3,<0.3.0; ^0.0.3 is >=0.0.3,<0.0.4; ^0 is
// >=0,<1.
func caretRange(v string) ([]string, bool) {
	parts, ok := releaseParts(v)
	if !ok {
		return nil, false
	}
	upper := make([]int, len(parts))
	i := 0
	for i < len(parts)-1 && parts[i] == 0 {
		i++
	}
	copy(upper, parts[:i])
	upper[i] = parts[i] + 1
	return []string{">=" + v, "<" + joinRelease(upper[:i+1])}, true
}

// tildeRange: ~1.2.3 is >=1.2.3,<1.3.0; ~1.2 is >=1.2,<1.3; ~1 is >=1,<2.
func tildeRange(v string) ([]string, bool) {
	parts, ok := releaseParts(v)
	if !ok {
		return nil, false
	}
	k := 1
	if len(parts) == 1 {
		k = 0
	}
	upper := append([]int(nil), parts[:k+1]...)
	upper[k]++
	return []string{">=" + v, "<" + joinRelease(upper)}, true
}

// pyLock is what one complete lockfile records, for coverage.
type pyLock struct {
	path     string
	dir      string
	versions map[string][]string            // normalized name → every locked version ("" when none)
	extras   map[string]map[string][]string // name → extra → normalized names it pulls in
	members  map[string]bool                // local projects the lock resolves, by slash path relative to dir
}

// readPyLock decodes a uv.lock, poetry.lock or pdm.lock. ok is false when it does not decode.
func readPyLock(path string) (*pyLock, bool) {
	data, err := readRegular(path)
	if err != nil {
		return nil, false
	}
	l := &pyLock{
		path:     path,
		dir:      filepath.Dir(path),
		versions: map[string][]string{},
		extras:   map[string]map[string][]string{},
		members:  map[string]bool{},
	}
	addExtra := func(name, extra string, deps []string) {
		if l.extras[name] == nil {
			l.extras[name] = map[string][]string{}
		}
		l.extras[name][normalizePyCoordinate(extra)] = append(l.extras[name][normalizePyCoordinate(extra)], deps...)
	}
	member := func(p string) {
		if p = strings.TrimSpace(p); p != "" && !strings.Contains(p, "://") && !filepath.IsAbs(p) {
			l.members[filepath.ToSlash(filepath.Clean(p))] = true
		}
	}
	switch filepath.Base(path) {
	case "uv.lock":
		var lock struct {
			Package []struct {
				Name    string `toml:"name"`
				Version string `toml:"version"`
				Source  struct {
					Editable  string `toml:"editable"`
					Virtual   string `toml:"virtual"`
					Directory string `toml:"directory"`
				} `toml:"source"`
				OptionalDependencies map[string][]struct {
					Name string `toml:"name"`
				} `toml:"optional-dependencies"`
			} `toml:"package"`
		}
		if toml.Unmarshal(data, &lock) != nil {
			return nil, false
		}
		for _, p := range lock.Package {
			n := normalizePyCoordinate(p.Name)
			l.versions[n] = append(l.versions[n], p.Version)
			for x, deps := range p.OptionalDependencies {
				var names []string
				for _, d := range deps {
					names = append(names, normalizePyCoordinate(d.Name))
				}
				addExtra(n, x, names)
			}
			member(p.Source.Editable)
			member(p.Source.Virtual)
			member(p.Source.Directory)
		}
	case "poetry.lock":
		var lock struct {
			Package []struct {
				Name    string              `toml:"name"`
				Version string              `toml:"version"`
				Extras  map[string][]string `toml:"extras"`
				Source  struct {
					Type string `toml:"type"`
					URL  string `toml:"url"`
				} `toml:"source"`
			} `toml:"package"`
		}
		if toml.Unmarshal(data, &lock) != nil {
			return nil, false
		}
		for _, p := range lock.Package {
			n := normalizePyCoordinate(p.Name)
			l.versions[n] = append(l.versions[n], p.Version)
			for x, deps := range p.Extras {
				var names []string
				for _, d := range deps {
					names = append(names, leadingProjectName(d))
				}
				addExtra(n, x, names)
			}
			if p.Source.Type == "directory" {
				member(p.Source.URL)
			}
		}
	case "pdm.lock":
		var lock struct {
			Package []struct {
				Name         string   `toml:"name"`
				Version      string   `toml:"version"`
				Extras       []string `toml:"extras"`
				Dependencies []string `toml:"dependencies"`
			} `toml:"package"`
		}
		if toml.Unmarshal(data, &lock) != nil {
			return nil, false
		}
		for _, p := range lock.Package {
			n := normalizePyCoordinate(p.Name)
			l.versions[n] = append(l.versions[n], p.Version)
			if len(p.Extras) == 0 {
				continue
			}
			var names []string
			for _, d := range p.Dependencies {
				names = append(names, leadingProjectName(d))
			}
			for _, x := range p.Extras {
				addExtra(n, x, names)
			}
		}
	default:
		return nil, false
	}
	return l, true
}

// leadingProjectName returns the normalized project name a requirement string starts with
// ("PySocks (>=1.5.6,!=1.5.7)", "pysocks>=1.5.6").
func leadingProjectName(req string) string {
	req = strings.TrimSpace(req)
	i := 0
	for i < len(req) && isNameChar(req[i]) {
		i++
	}
	return normalizePyCoordinate(req[:i])
}

// coversDecl reports whether the lock, on its own, holds d: its name is locked; unless it is a
// direct reference, some locked version satisfies its specifier, and every locked version does
// when the declaration applies to every environment (no marker); and each extra it asks for is
// one the lock records for that name, with every package the extra pulls in locked too.
func (l *pyLock) coversDecl(d pyDecl) bool {
	versions, ok := l.versions[d.Name]
	if !ok {
		return false
	}
	if !d.Direct && d.Specifier != "" {
		some, every := false, true
		for _, v := range versions {
			if satisfiesAll(v, d.Specifier) {
				some = true
			} else {
				every = false
			}
		}
		if !some || !d.Marked && !every {
			return false
		}
	}
	for _, x := range d.Extras {
		deps, recorded := l.extras[d.Name][x]
		if !recorded {
			return false
		}
		for _, n := range deps {
			if _, locked := l.versions[n]; !locked {
				return false
			}
		}
	}
	return true
}

// satisfiesAll reports whether version v satisfies every comma-separated PEP 440 clause of spec.
// An unparseable version or clause does not satisfy.
func satisfiesAll(v, spec string) bool {
	pv, ok := pep440.Parse(v)
	if !ok {
		return false
	}
	for _, clause := range strings.Split(spec, ",") {
		sat, ok := pep440.Satisfies(pv, v, strings.TrimSpace(clause))
		if !ok || !sat {
			return false
		}
	}
	return true
}

// covers reports whether the lock, on its own, covers the manifest at path: every declaration
// it holds (coversDecl), and, for a project definition in a directory other than the lock's
// that declares anything, the lock records that directory as a project it resolves (a uv
// workspace member or path source, a poetry directory source). A requirements file or
// Pipfile.lock is not a project and needs no such record.
func (l *pyLock) covers(path string, decls pyDecls) bool {
	if len(decls.reqs) == 0 {
		return true
	}
	switch filepath.Base(path) {
	case "pyproject.toml", "setup.py", "setup.cfg":
		if dir := filepath.Dir(path); dir != l.dir {
			rel, err := filepath.Rel(l.dir, dir)
			if err != nil || !l.members[filepath.ToSlash(rel)] {
				return false
			}
		}
	}
	for _, d := range decls.reqs {
		if !l.coversDecl(d) {
			return false
		}
	}
	return true
}

// --- requirements files pip may resolve past -----------------------------------------
//
// pip resolves a requirements file's dependencies itself, from the index: a lock holding every
// name the file lists says nothing about a newer release's new dependency. A requirements file
// therefore covers only with proof that pip refuses any distribution the files do not list.

// reqInstalls decides, for the requirements files a build's manifests reach, whether pip may
// install a package they do not list.
type reqInstalls struct {
	installs pipInstalls         // every allowed pip install -r the script surfaces run
	decls    map[string]*pyDecls // requirements file → what it reads as; nil when it does not
	includer map[string][]string // requirements file → the requirements files that -r it
	directed map[string]bool     // files a pyproject.toml or setup.cfg names in a file directive
	memo     map[string]bool
	visiting map[string]bool
}

// newReqInstalls reads every requirements file among manifests and every file they -r, and
// the file directives of every other manifest.
func newReqInstalls(manifests []string, installs pipInstalls) *reqInstalls {
	r := &reqInstalls{installs: installs, decls: map[string]*pyDecls{}, includer: map[string][]string{},
		directed: map[string]bool{}, memo: map[string]bool{}, visiting: map[string]bool{}}
	var queue []string
	for _, m := range manifests {
		switch base := filepath.Base(m); {
		case isRequirementsName(base):
			queue = append(queue, filepath.Clean(m))
		case base == "pyproject.toml" || base == "setup.cfg":
			if d, ok := manifestDecls(m); ok {
				for _, f := range d.files {
					r.directed[filepath.Clean(f)] = true
				}
			}
		}
	}
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		if _, seen := r.decls[f]; seen {
			continue
		}
		r.decls[f] = nil
		data, err := readRegular(f)
		if err != nil {
			continue
		}
		d, ok := requirementsDecls(f, data, pyDecls{})
		if !ok {
			continue
		}
		r.decls[f] = &d
		for _, inc := range d.nested {
			r.includer[inc] = append(r.includer[inc], f)
			queue = append(queue, inc)
		}
	}
	return r
}

// hashMode reports whether pip installs the file in hash-checking mode however it is run:
// a requirement in it or in a file it -r's, at any depth, carries --hash, or one of them sets
// --require-hashes. pip then requires a hash for every requirement and every dependency, and
// fails the install on any it lacks (pip's RequirementCommand.get_requirements turns
// require_hashes on when any requirement has hash options). A -c constraint file's hashes are
// not counted.
func (r *reqInstalls) hashMode(f string) bool {
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(f string) bool {
		if seen[f] {
			return false
		}
		seen[f] = true
		d := r.decls[f]
		if d == nil {
			return false
		}
		if d.hashed {
			return true
		}
		for _, inc := range d.nested {
			if walk(inc) {
				return true
			}
		}
		return false
	}
	return walk(filepath.Clean(f))
}

// refused reports whether pip refuses, wherever the build installs the requirements file f,
// any distribution the files it installs with do not list: f is in hash-checking mode; or f
// is installed at least once, and every install of it (by a script surface, or through a
// requirements file that -r's it) passes --no-deps or --require-hashes, or is through a file
// pip refuses for. A file named requirements.txt, which Python buildpacks install on their own
// whenever it is there, or named in a file directive, which installs it with the project and
// its dependencies, is installed some way this does not see.
func (r *reqInstalls) refused(f string) bool {
	f = filepath.Clean(f)
	if v, ok := r.memo[f]; ok {
		return v
	}
	if r.visiting[f] {
		return false
	}
	r.visiting[f] = true
	defer delete(r.visiting, f)
	v := r.hashMode(f) || r.narrowed(f)
	r.memo[f] = v
	return v
}

func (r *reqInstalls) narrowed(f string) bool {
	if filepath.Base(f) == "requirements.txt" || r.directed[f] || r.decls[f] == nil {
		return false
	}
	paths := 0
	for _, in := range r.installs[f] {
		if !in.noDeps && !in.requireHashes {
			return false
		}
		paths++
	}
	for _, x := range r.includer[f] {
		if !r.refused(x) {
			return false
		}
		paths++
	}
	return paths > 0
}
