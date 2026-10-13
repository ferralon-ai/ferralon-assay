package pythonanalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveDependencyVersions reads the Python codebase's INSTALLED (pinned) dependency
// versions from its manifests — requirements.txt (pip freeze / hashed pins), poetry.lock,
// pdm.lock, uv.lock, Pipfile.lock, and the declared-specifier build definitions (PEP 621
// pyproject.toml, setup.cfg, setup.py, hatch_build.py) — and returns the resolved version for the
// advisory's requested coordinate (the PyPI project name). It is the cheap Assess-tier
// input to the disqualification predicate, the Python mirror of jsanalysis /
// javaanalysis ResolveDependencyVersions.
//
// SOUNDNESS (inv.5): this NEVER guesses a version. Python's packaging zoo often carries a
// RANGE ("flask>=2.0") rather than a pinned install, or several inconsistent manifests, or
// none. Only an EXACT pin (poetry.lock/Pipfile.lock version, a requirements.txt "=="
// pin, or a PEP 621 "==" pin) yields Resolved=true; a range, a prefix ("==1.4.*"), or an
// unreadable entry is an UNRESOLVED marker (Resolved=false) the predicate fails OPEN on,
// never fabricating a not-affected. A declared range is carried as Constraint (evidence only).
//
// Exhaustive is set only when a complete lockfile covers every manifest found (exhaustive.go),
// so a coordinate absent from All is provably not installed; otherwise absence proves nothing.
//
// Hard error vs. partiality (inv.4 / inv.5):
//   - A missing/unreadable build dir is a hard error.
//   - A build dir with NO recognized manifest degrades Partiality to declared-partial
//     (no_manifest) rather than hard-failing the run: a repo that declares no Python
//     dependencies anywhere is a normal shape, not a tool failure. The recognized set
//     already includes the DECLARED manifests (pyproject.toml, requirements*.txt), so unlike
//     JS there is nothing left to seed — All is legitimately empty. Soundness rests entirely
//     on the declared partiality: the result is Complete=false, so a consumer must not read
//     the empty All as proof the dependency is absent and fabricate a not-affected.
//   - An unparseable manifest degrades Partiality to declared-partial (tool_failure); the
//     coordinate it would have carried becomes UNRESOLVED, not absent.
//
// "plugin resolves, pipeline ranges" symmetry: this op resolves only the concrete installed
// literal version. Advisory RANGE matching (PEP 440 specifiers, ordering) is applied by the
// pipeline disqualification predicate (pipeline/pypi_version.go), never here.
func ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.DependencyVersionResult{}, fmt.Errorf("pythonanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.DependencyVersionResult{}, fmt.Errorf("pythonanalysis: build dir %q is not a directory", req.BuildDir)
	}

	manifests := manifestFiles(req.BuildDir)

	var (
		all         []plugin.ResolvedDependency
		parseFailed bool
		perFile     = make(map[string][]plugin.ResolvedDependency, len(manifests))
	)
	for _, m := range manifests {
		deps, ok := parseManifest(m)
		if !ok {
			parseFailed = true
		}
		perFile[m] = deps
		all = append(all, deps...)
	}

	part := plugin.Complete()
	switch {
	case len(manifests) == 0:
		part = plugin.Partial(plugin.PartialReasonNoManifest)
	case parseFailed:
		part = plugin.Partial(plugin.PartialReasonToolFailure)
	}

	res := plugin.DependencyVersionResult{
		Partiality: part,
		All:        all,
		Exhaustive: exhaustiveManifestSet(req.BuildDir, req.Coordinate, manifests, perFile, parseFailed),
	}
	want := normalizePyCoordinate(req.Coordinate)
	if want != "" {
		for _, d := range all {
			if normalizePyCoordinate(d.Coordinate) == want {
				res.Found = true
				res.Match = d
				// A resolved match wins over an UNRESOLVED one for the same coordinate.
				if d.Resolved {
					break
				}
			}
		}
	}
	return res, nil
}

// manifestFiles returns every recognized Python manifest under root, skipping
// build-output / virtualenv / VCS trees so a vendored install does not shadow the
// project's own top-level manifest.
func manifestFiles(root string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree yields no manifests; keep walking.
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if isManifest(d.Name()) {
			out = append(out, path)
		}
		return nil
	})
	return out
}

// isManifest reports whether name is a recognized Python dependency manifest: the lockfiles,
// the declared-specifier build definitions (pyproject.toml, setup.cfg, setup.py,
// hatch_build.py), and the requirements*.txt family (requirements.txt, requirements-dev.txt,
// ...), so split requirement files still resolve.
func isManifest(name string) bool {
	switch name {
	case "poetry.lock", "Pipfile.lock", "pyproject.toml", "pdm.lock", "uv.lock",
		"setup.cfg", "setup.py", "hatch_build.py":
		return true
	}
	return strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt")
}

// parseManifest dispatches on the manifest's name to the format-specific parser. The
// bool is false when the file cannot be read or is structurally unparseable (the caller
// degrades partiality).
func parseManifest(path string) ([]plugin.ResolvedDependency, bool) {
	data, err := readRegular(path)
	if err != nil {
		return nil, false
	}
	return parseManifestData(path, data)
}

// parseManifestData is parseManifest over contents already read from path.
func parseManifestData(path string, data []byte) ([]plugin.ResolvedDependency, bool) {
	base := filepath.Base(path)
	switch {
	case base == "poetry.lock":
		return parsePoetryLock(data)
	case base == "Pipfile.lock":
		return parsePipfileLock(data)
	case base == "pdm.lock":
		return parsePDMLockAdvisory(data)
	case base == "uv.lock":
		return parseUVLockAdvisory(data)
	case base == "pyproject.toml":
		deps, ok := parsePyproject(path, data)
		return append(deps, buildRequires(path, data)...), ok
	case base == "setup.cfg":
		deps, ok := parseSetupCfg(path, data)
		return append(deps, buildRequires(path, data)...), ok
	case base == "setup.py":
		deps, ok := parseSetupPy(data)
		return append(deps, buildRequires(path, data)...), ok
	case base == "hatch_build.py":
		return parseHatchBuild(data)
	default: // requirements*.txt
		return parseRequirementsTxt(data)
	}
}

// buildRequires returns the build-time requirements a build definition declares
// ([build-system].requires in pyproject.toml, setup_requires in setup.cfg and setup.py) as
// declared dependencies of the advisory path, so a coordinate a build installs is found rather
// than read as absent. They are not runtime installs: the inventory does not carry them and no
// lockfile is expected to cover them (exhaustive.go). Entries that are not well-formed PEP 508
// requirements, and a setup_requires value that is not literal, are skipped.
func buildRequires(path string, data []byte) []plugin.ResolvedDependency {
	var specs []string
	source := filepath.Base(path)
	switch source {
	case "pyproject.toml":
		var pp struct {
			BuildSystem struct {
				Requires []string `toml:"requires"`
			} `toml:"build-system"`
		}
		if toml.Unmarshal(data, &pp) == nil {
			specs = pp.BuildSystem.Requires
		}
	case "setup.cfg":
		specs = scanSetupCfg(path, data).buildSpecs
	case "setup.py":
		specs, _ = scanSetupPyKeys(string(data), setupPyBuildKeys)
	}
	var out []plugin.ResolvedDependency
	for _, spec := range specs {
		if d, ok := declaredDependency(spec, source); ok {
			out = append(out, d)
		}
	}
	return out
}

// --- requirements.txt --------------------------------------------------------

// parseRequirementsTxt parses a pip requirements file. Only an EXACT "==" pin yields a
// resolved version; a range/compatible/prefix spec, an editable/URL/-r include, or an
// option line is UNRESOLVED (or skipped). Continuation lines ("\") and hashed pins
// ("pkg==1.2.3 --hash=sha256:...") are handled; environment markers (";...") and inline
// comments ("#...") are stripped.
func parseRequirementsTxt(data []byte) ([]plugin.ResolvedDependency, bool) {
	var out []plugin.ResolvedDependency
	for _, req := range joinContinuations(string(data)) {
		line := stripReqComment(req)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "-") { // -r include, -e editable, --option
			continue
		}
		if strings.Contains(line, "://") || strings.HasPrefix(line, "git+") {
			continue // URL / VCS requirement — no PyPI-pinned version
		}
		// Drop an environment marker ("; python_version < '3.8'") and any --hash tokens.
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		if i := strings.Index(line, "--hash"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		name, version, resolved, _ := parseRequirementSpec(line) // advisory path ignores extras
		if name == "" {
			continue
		}
		d := pyResolved(name, version, resolved, "requirements.txt")
		if !d.Resolved {
			d.Constraint = requirementConstraint(line)
		}
		out = append(out, d)
	}
	return out, true
}

// parseRequirementSpec extracts (name, version, resolved, extras) from a single requirement
// spec. It resolves ONLY an exact "==X.Y.Z" pin (not a "==1.4.*" prefix); anything else
// (range, compatible, bare name) is UNRESOLVED. The extras group "[a,b]" is CAPTURED (PLAN-170
// E2, replacing the old unconditional skip) and returned normalized; the advisory path
// (parseRequirementsTxt, parsePyproject) ignores it, while the selected-set path resolves it
// against the declared extras selection.
func parseRequirementSpec(spec string) (name, version string, resolved bool, extras []string) {
	// Name runs up to the first operator/extras/space.
	end := len(spec)
	for i, c := range spec {
		if c == '=' || c == '<' || c == '>' || c == '!' || c == '~' || c == '[' || c == ' ' || c == '\t' {
			end = i
			break
		}
	}
	name = strings.TrimSpace(spec[:end])
	// A Jinja2-templated line is not a requirement (finding F9). airflow (and
	// others) ship requirements files rendered through Jinja at build time; read
	// literally, a "{% if … %}" control statement tokenizes to a package named
	// "{%" and a "pkg=={{ ver }}" line to a version of "{{" — junk nodes that
	// pollute the SBOM. A templated NAME carries no recoverable identity, so the
	// line is dropped (empty name → caller skips); a templated VERSION is handled
	// below, leaving the real name pinned to an UNRESOLVED version rather than a
	// garbage literal. A pinned requirement that merely SITS inside a template
	// block (e.g. "funcsigs==1.0.2" between "{% if %}"/"{% endif %}") carries no
	// delimiters of its own and still parses normally.
	if name == "" || containsJinja(name) {
		return "", "", false, nil
	}
	rest := strings.TrimSpace(spec[end:])
	// Capture an extras group "[a,b]" (E2) instead of discarding it.
	if strings.HasPrefix(rest, "[") {
		if j := strings.IndexByte(rest, ']'); j >= 0 {
			extras = parseExtrasGroup(rest[1:j])
			rest = strings.TrimSpace(rest[j+1:])
		}
	}
	if !strings.HasPrefix(rest, "==") {
		return name, "", false, extras // not an exact pin → UNRESOLVED
	}
	ver := strings.TrimSpace(rest[2:])
	// A version with a further comma-clause or a "*" prefix is not a single exact pin.
	if i := strings.IndexAny(ver, ", \t"); i >= 0 {
		ver = ver[:i]
	}
	if ver == "" || strings.Contains(ver, "*") || containsJinja(ver) {
		return name, "", false, extras // "*" prefix or a Jinja-templated version → UNRESOLVED
	}
	return name, ver, true, extras
}

// containsJinja reports whether s carries a Jinja2 template delimiter, including a
// bare "{", "}", or "%" left after tokenizing a "{% … %}" / "{{ … }}" construct.
// PyPI project names and PEP 440 versions never contain these characters, so their
// presence marks a token as template syntax rather than a real coordinate.
func containsJinja(s string) bool {
	return strings.ContainsAny(s, "{}%")
}

// parseExtrasGroup splits the body of an extras group "a, b" into normalized extra names in
// declared order (PEP 503-style normalization, so the group matches a declared selection the
// same way regardless of case or separator). Empty entries are dropped.
func parseExtrasGroup(body string) []string {
	var out []string
	for _, e := range strings.Split(body, ",") {
		if n := normalizePyCoordinate(e); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// joinContinuations splits a requirements file into logical lines the way pip's requirement
// file reader does before it strips comments (req_file.join_lines over str.splitlines). Lines
// break where Python's str.splitlines breaks them. A line ending in a backslash is joined to the
// next, with every backslash at either end of it removed and nothing put in their place. The
// exception is a comment line (first non-blank character '#'), which never continues and gets
// one leading space. A backslash followed by trailing blanks does not continue a line.
func joinContinuations(data string) []string {
	var out []string
	var cur strings.Builder
	pending := false
	for _, line := range pySplitLines(data) {
		comment := strings.HasPrefix(strings.TrimLeftFunc(line, pyIsSpace), "#")
		if !strings.HasSuffix(line, "\\") || comment {
			if comment {
				line = " " + line
			}
			if pending {
				cur.WriteString(line)
				out = append(out, cur.String())
				cur.Reset()
				pending = false
			} else {
				out = append(out, line)
			}
			continue
		}
		pending = true
		cur.WriteString(strings.Trim(line, "\\"))
	}
	if pending {
		out = append(out, cur.String())
	}
	return out
}

// pySplitLines splits s at every line boundary Python's str.splitlines recognises, dropping the
// boundaries. A trailing boundary yields no empty last line.
func pySplitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch r {
		case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
		case '\r':
			if strings.HasPrefix(s[i+1:], "\n") {
				n = 2
			}
		default:
			i += n
			continue
		}
		out = append(out, s[start:i])
		i += n
		start = i
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// pyIsSpace reports whether r is whitespace to Python's str.isspace, which a regular expression's
// \s matches.
func pyIsSpace(r rune) bool {
	return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f
}

// stripReqComment removes a "# ..." inline comment (a '#' that starts a token).
func stripReqComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

// --- poetry.lock (TOML) ------------------------------------------------------

// parsePoetryLock parses poetry.lock lexically (no TOML library — pure-Go,
// dependency-free, matching the scanner ethos). Each resolved package is a
// "[[package]]" block carrying `name = "x"` and `version = "1.2.3"`. A block missing a
// version is UNRESOLVED.
func parsePoetryLock(data []byte) ([]plugin.ResolvedDependency, bool) {
	var out []plugin.ResolvedDependency
	var name, version string
	inPackage := false

	flush := func() {
		if inPackage && name != "" {
			out = append(out, pyResolved(name, version, version != "", "poetry.lock"))
		}
		name, version = "", ""
	}

	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "[[package]]" {
			flush()
			inPackage = true
			continue
		}
		if strings.HasPrefix(line, "[") { // any other table closes the package block
			flush()
			inPackage = false
			continue
		}
		if !inPackage {
			continue
		}
		if v, ok := tomlString(line, "name"); ok {
			name = v
		}
		if v, ok := tomlString(line, "version"); ok {
			version = v
		}
	}
	flush()
	return out, true
}

// tomlString matches a `key = "value"` line for the given key and returns the unquoted
// value. It is deliberately minimal (the only shape poetry.lock/pyproject use for these
// scalar fields).
func tomlString(line, key string) (string, bool) {
	prefix := key + " ="
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	rest := strings.TrimSpace(line[len(prefix):])
	rest = strings.Trim(rest, `"'`)
	return rest, rest != ""
}

// --- Pipfile.lock (JSON) -----------------------------------------------------

// pipfileLock is the subset of Pipfile.lock we read: the "default" and "develop"
// dependency maps, each package → {"version": "==1.2.3", ...}.
type pipfileLock struct {
	Default map[string]pipfileEntry `json:"default"`
	Develop map[string]pipfileEntry `json:"develop"`
}

type pipfileEntry struct {
	Version string `json:"version"`
}

// parsePipfileLock parses Pipfile.lock. Pipenv pins every dependency with an exact
// "==X.Y.Z" version, so a present version field resolves; a missing one is UNRESOLVED.
// Each section is walked in sorted key order so All is identical across runs.
func parsePipfileLock(data []byte) ([]plugin.ResolvedDependency, bool) {
	var pl pipfileLock
	if err := json.Unmarshal(data, &pl); err != nil {
		return nil, false
	}
	var out []plugin.ResolvedDependency
	collect := func(m map[string]pipfileEntry) {
		for _, name := range slices.Sorted(maps.Keys(m)) {
			e := m[name]
			ver := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(e.Version), "=="))
			out = append(out, pyResolved(name, ver, ver != "" && !strings.Contains(ver, "*"), "Pipfile.lock"))
		}
	}
	collect(pl.Default)
	collect(pl.Develop)
	return out, true
}

// --- pyproject.toml (PEP 621) ------------------------------------------------

// pyprojectDeps is the subset read here: [project].dependencies and
// [project].optional-dependencies, and the requirement files that supply them when they are
// dynamic ([tool.setuptools.dynamic], or hatch-requirements-txt's
// [tool.hatch.metadata.hooks.requirements_txt]).
type pyprojectDeps struct {
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
		Dynamic              []string            `toml:"dynamic"`
	} `toml:"project"`
	Tool struct {
		Setuptools struct {
			Dynamic map[string]any `toml:"dynamic"`
		} `toml:"setuptools"`
		Hatch struct {
			Metadata struct {
				Hooks map[string]any `toml:"hooks"`
			} `toml:"metadata"`
		} `toml:"hatch"`
	} `toml:"tool"`
}

// parsePyproject reads a PEP 621 pyproject.toml's [project].dependencies and every
// [project].optional-dependencies group, plus every requirement file a dynamic-metadata table
// names for them (pyprojectDynamicFiles), read relative to the pyproject. Each entry is a
// declared PEP 508 requirement: an exact "==" pin resolves, a range rides in Constraint with
// Resolved=false (the authoritative pins live in a lockfile). ok is false when a dynamic table
// has a shape not read here or a file it names fails readRequirementFiles. A file the TOML
// decoder rejects (a templated pyproject, say) falls back to the lexical [project] dependencies
// reader, so such a file still contributes the names it visibly declares.
func parsePyproject(path string, data []byte) ([]plugin.ResolvedDependency, bool) {
	var pp pyprojectDeps
	if err := toml.Unmarshal(data, &pp); err != nil {
		return parsePyprojectLexical(data)
	}
	var out []plugin.ResolvedDependency
	add := func(spec string) {
		if d, ok := declaredDependency(spec, "pyproject.toml"); ok {
			out = append(out, d)
		}
	}
	for _, spec := range pp.Project.Dependencies {
		add(spec)
	}
	for _, g := range slices.Sorted(maps.Keys(pp.Project.OptionalDependencies)) {
		for _, spec := range pp.Project.OptionalDependencies[g] {
			add(spec)
		}
	}
	files, ok := pyprojectDynamicFiles(pp)
	if !ok {
		return out, false
	}
	for _, f := range files {
		deps, fileOK := readRequirementFiles(filepath.Dir(path), f, "pyproject.toml")
		out = append(out, deps...)
		if !fileOK {
			return out, false
		}
	}
	return out, true
}

// pyprojectDynamicFiles returns, in a stable order, every requirement file named for
// dependencies or optional-dependencies by [tool.setuptools.dynamic] ({file = "a.txt"} or
// {file = ["a.txt", ...]}, per field and per optional group) and by
// [tool.hatch.metadata.hooks.requirements_txt] (files = [...] and an optional-dependencies
// table of file lists). ok is false for any other shape of those entries.
func pyprojectDynamicFiles(pp pyprojectDeps) (files []string, ok bool) {
	fileKey := func(v any) bool {
		m, isMap := v.(map[string]any)
		if !isMap || len(m) != 1 {
			return false
		}
		names, isList := stringList(m["file"])
		files = append(files, names...)
		return isList
	}
	dyn := pp.Tool.Setuptools.Dynamic
	if v, present := dyn["dependencies"]; present && !fileKey(v) {
		return nil, false
	}
	if v, present := dyn["optional-dependencies"]; present {
		groups, isMap := v.(map[string]any)
		if !isMap {
			return nil, false
		}
		for _, g := range slices.Sorted(maps.Keys(groups)) {
			if !fileKey(groups[g]) {
				return nil, false
			}
		}
	}
	if v, present := pp.Tool.Hatch.Metadata.Hooks["requirements_txt"]; present {
		hook, isMap := v.(map[string]any)
		if !isMap {
			return nil, false
		}
		if fv, has := hook["files"]; has {
			names, isList := stringList(fv)
			if !isList {
				return nil, false
			}
			files = append(files, names...)
		}
		if ov, has := hook["optional-dependencies"]; has {
			groups, isMap := ov.(map[string]any)
			if !isMap {
				return nil, false
			}
			for _, g := range slices.Sorted(maps.Keys(groups)) {
				names, isList := stringList(groups[g])
				if !isList {
					return nil, false
				}
				files = append(files, names...)
			}
		}
	}
	return files, true
}

// stringList accepts a TOML string or array of strings.
func stringList(v any) ([]string, bool) {
	switch t := v.(type) {
	case string:
		return []string{t}, true
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, isStr := e.(string)
			if !isStr {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

// parsePyprojectLexical reads the "dependencies = [ ... ]" array under a "[project]" table
// line by line, resolving only exact "==" pins. It is the fallback for a file the TOML decoder
// rejects.
func parsePyprojectLexical(data []byte) ([]plugin.ResolvedDependency, bool) {
	var out []plugin.ResolvedDependency
	inProject := false
	inDeps := false

	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if strings.HasPrefix(line, "[") {
			inProject = line == "[project]"
			inDeps = false
			continue
		}
		if !inProject {
			continue
		}
		if strings.HasPrefix(line, "dependencies") && strings.Contains(line, "[") {
			inDeps = true
			line = line[strings.IndexByte(line, '[')+1:]
		}
		if !inDeps {
			continue
		}
		for _, entry := range strings.Split(line, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "]" || entry == "" {
				continue
			}
			closed := strings.Contains(entry, "]")
			entry = strings.Trim(entry, "[]")
			entry = strings.TrimSpace(strings.Trim(strings.TrimSpace(entry), `"'`))
			if entry != "" {
				name, version, resolved, _ := parseRequirementSpec(entry) // advisory path ignores extras
				if name != "" {
					out = append(out, pyResolved(name, version, resolved, "pyproject.toml"))
				}
			}
			if closed {
				inDeps = false
			}
		}
	}
	return out, true
}

// --- shared helpers ----------------------------------------------------------

// pyResolved builds a ResolvedDependency for a PyPI package. An empty/unresolved version
// is UNRESOLVED (Resolved=false), never guessed.
func pyResolved(name, version string, resolved bool, source string) plugin.ResolvedDependency {
	version = strings.TrimSpace(version)
	if name == "" || version == "" || !resolved {
		return plugin.ResolvedDependency{Coordinate: name, Resolved: false, Source: source}
	}
	return plugin.ResolvedDependency{Coordinate: name, Version: version, Resolved: true, Source: source}
}

// normalizePyCoordinate applies PEP 503 name normalization: lowercase, and collapse runs
// of '-', '_', '.' to a single '-'. So "Flask", "flask", and "deep_diff"/"deep-diff"
// match the way PyPI treats them.
func normalizePyCoordinate(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	var b strings.Builder
	prevDash := false
	for _, r := range c {
		if r == '-' || r == '_' || r == '.' {
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
			continue
		}
		b.WriteRune(r)
		prevDash = false
	}
	return strings.Trim(b.String(), "-")
}
