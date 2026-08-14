package pythonanalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveDependencyVersions reads the Python codebase's INSTALLED (pinned) dependency
// versions from its manifests — requirements.txt (pip freeze / hashed pins), poetry.lock,
// Pipfile.lock, and PEP 621 pyproject.toml — and returns the resolved version for the
// advisory's requested coordinate (the PyPI project name). It is the cheap Assess-tier
// input to the disqualification predicate, the Python mirror of jsanalysis /
// javaanalysis ResolveDependencyVersions.
//
// SOUNDNESS (inv.5): this NEVER guesses a version. Python's packaging zoo often carries a
// RANGE ("flask>=2.0") rather than a pinned install, or several inconsistent manifests, or
// none. Only an EXACT pin (poetry.lock/Pipfile.lock version, a requirements.txt "=="
// pin, or a PEP 621 "==" pin) yields Resolved=true; a range, a prefix ("==1.4.*"), or an
// unreadable entry is an UNRESOLVED marker (Resolved=false) the predicate fails OPEN on,
// never fabricating a not-affected.
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
	)
	for _, m := range manifests {
		deps, ok := parseManifest(m)
		if !ok {
			parseFailed = true
		}
		all = append(all, deps...)
	}

	part := plugin.Complete()
	switch {
	case len(manifests) == 0:
		part = plugin.Partial(plugin.PartialReasonNoManifest)
	case parseFailed:
		part = plugin.Partial(plugin.PartialReasonToolFailure)
	}

	res := plugin.DependencyVersionResult{Partiality: part, All: all}
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

// isManifest reports whether name is a recognized Python dependency manifest. A
// requirements*.txt family (requirements.txt, requirements-dev.txt, ...) is accepted so
// split requirement files still resolve.
func isManifest(name string) bool {
	switch name {
	case "poetry.lock", "Pipfile.lock", "pyproject.toml", "pdm.lock", "uv.lock":
		return true
	}
	return strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt")
}

// parseManifest dispatches on the manifest's name to the format-specific parser. The
// bool is false when the file cannot be read or is structurally unparseable (the caller
// degrades partiality).
func parseManifest(path string) ([]plugin.ResolvedDependency, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
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
		return parsePyproject(data)
	default: // requirements*.txt
		return parseRequirementsTxt(data)
	}
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
		out = append(out, pyResolved(name, version, resolved, "requirements.txt"))
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
	if name == "" {
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
	if ver == "" || strings.Contains(ver, "*") {
		return name, "", false, extras
	}
	return name, ver, true, extras
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

// joinContinuations splits a requirements file into logical requirement strings, joining
// backslash-continued physical lines.
func joinContinuations(data string) []string {
	var out []string
	var cur strings.Builder
	for _, raw := range strings.Split(data, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.HasSuffix(strings.TrimRight(line, " \t"), "\\") {
			cur.WriteString(strings.TrimSuffix(strings.TrimRight(line, " \t"), "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(line)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
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
func parsePipfileLock(data []byte) ([]plugin.ResolvedDependency, bool) {
	var pl pipfileLock
	if err := json.Unmarshal(data, &pl); err != nil {
		return nil, false
	}
	var out []plugin.ResolvedDependency
	collect := func(m map[string]pipfileEntry) {
		for name, e := range m {
			ver := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(e.Version), "=="))
			out = append(out, pyResolved(name, ver, ver != "" && !strings.Contains(ver, "*"), "Pipfile.lock"))
		}
	}
	collect(pl.Default)
	collect(pl.Develop)
	return out, true
}

// --- pyproject.toml (PEP 621) ------------------------------------------------

// parsePyproject parses a PEP 621 pyproject.toml's "[project] dependencies" array
// lexically, resolving only exact "==" pins (pyproject usually carries ranges, so most
// entries are UNRESOLVED — the authoritative pins live in poetry.lock/Pipfile.lock). It
// reads the "dependencies = [ ... ]" array under a "[project]" table.
func parsePyproject(data []byte) ([]plugin.ResolvedDependency, bool) {
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
