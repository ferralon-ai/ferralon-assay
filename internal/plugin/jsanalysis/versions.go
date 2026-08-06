package jsanalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveDependencyVersions reads the JS/TS codebase's INSTALLED (resolved) dependency
// versions from its lockfiles — package-lock.json (npm, lockfileVersion 1/2/3),
// yarn.lock (classic v1 and berry v2+), and pnpm-lock.yaml — and returns the resolved
// version for the advisory's requested coordinate (the npm package name). It is the
// cheap Assess-tier input to the disqualification predicate, the JS mirror of
// javaanalysis.ResolveDependencyVersions.
//
// SOUNDNESS (inv.5): this NEVER guesses a version. A lockfile entry whose version cannot
// be read confidently — a package key with no resolvable version, an unparseable entry —
// is returned with Resolved=false (an UNRESOLVED marker). The pipeline fails OPEN on
// UNRESOLVED, never fabricating a not-affected.
//
// Hard error vs. partiality (inv.4 / inv.5):
//   - A missing/unreadable build dir is a hard error.
//   - A build dir with NO lockfile degrades Partiality to declared-partial (no_manifest)
//     rather than hard-failing the run: shipping no committed lockfile is a normal shape for
//     a real JS library (express@4.x), not a tool failure. It stays SOUND because the
//     degraded result is never a silent empty success: every dependency package.json
//     DECLARES is seeded as an UNRESOLVED coordinate (Resolved=false), so the predicate sees
//     "present, version unknown" and fails OPEN — it can never read the degrade as "package
//     not present" and fabricate a not-affected. When there is no package.json either, All
//     is empty but Partiality is declared-partial, which is what distinguishes it from a
//     clean scan.
//   - An unparseable lockfile degrades Partiality to declared-partial (tool_failure); the
//     coordinate it would have carried becomes UNRESOLVED, not absent.
//
// "plugin resolves, pipeline ranges" symmetry (matching Java): this op resolves only the
// concrete installed literal version. Advisory RANGE matching (^ ~ || x-ranges, npm
// ordering) is applied by the pipeline disqualification predicate (pipeline/npm_version.go),
// never here.
func ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.DependencyVersionResult{}, fmt.Errorf("jsanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.DependencyVersionResult{}, fmt.Errorf("jsanalysis: build dir %q is not a directory", req.BuildDir)
	}

	locks := lockFiles(req.BuildDir)

	var (
		all         []plugin.ResolvedDependency
		parseFailed bool
	)
	for _, l := range locks {
		deps, ok := parseLockfile(l)
		if !ok {
			parseFailed = true
		}
		all = append(all, deps...)
	}

	part := plugin.Complete()
	switch {
	case len(locks) == 0:
		// No installed-version source. Seed every DECLARED dependency as UNRESOLVED so the
		// predicate still evaluates it (fail-open) instead of reading its absence from All
		// as "not a dependency".
		all = declaredDependencies(req.BuildDir)
		part = plugin.Partial(plugin.PartialReasonNoManifest)
	case parseFailed:
		part = plugin.Partial(plugin.PartialReasonToolFailure)
	}

	res := plugin.DependencyVersionResult{Partiality: part, All: all}
	want := normalizeNPMCoordinate(req.Coordinate)
	if want != "" {
		for _, d := range all {
			if normalizeNPMCoordinate(d.Coordinate) == want {
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

// lockFiles returns every recognized lockfile under root (npm/yarn/pnpm), skipping
// build-output/VCS/node_modules trees so a nested install does not shadow the project's
// own top-level lockfile with transitive duplicates.
func lockFiles(root string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree yields no lockfiles; keep walking.
		}
		if d.IsDir() {
			// skipDir already excludes node_modules/dist/build/VCS, so a nested install's
			// transitive lockfiles never shadow the project's own top-level lockfile.
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		switch d.Name() {
		case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml":
			out = append(out, path)
		}
		return nil
	})
	return out
}

// declaredDependencyFields are the package.json dependency maps seeded when no lockfile
// exists. ALL FOUR are read on purpose: seeding is a fail-OPEN measure, so over-inclusion
// only costs an extra UNRESOLVED coordinate the predicate declines to disqualify, while
// under-inclusion drops a dependency the predicate would then read as absent — the exact
// fabricated-not-affected hazard the degrade exists to prevent. devDependencies are present
// in a checked-out tree; peerDependencies are expected present at runtime.
var declaredDependencyFields = []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}

// declaredDependencies reads every package.json under root (same skip rules as lockFiles,
// so node_modules never contributes) and returns each declared dependency name as an
// UNRESOLVED coordinate. Declared RANGES are deliberately discarded: this op resolves only
// installed literals (inv.5 — it never guesses a version), and range matching belongs to the
// pipeline predicate. An unreadable or unparseable package.json contributes nothing; the
// caller has already declared the result partial.
func declaredDependencies(root string) []plugin.ResolvedDependency {
	seen := make(map[string]struct{})
	var out []plugin.ResolvedDependency
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree declares no dependencies; keep walking.
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "package.json" {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		var manifest map[string]json.RawMessage
		if json.Unmarshal(data, &manifest) != nil {
			return nil
		}
		for _, field := range declaredDependencyFields {
			raw, ok := manifest[field]
			if !ok {
				continue
			}
			var deps map[string]string
			if json.Unmarshal(raw, &deps) != nil {
				continue
			}
			for name := range deps {
				key := normalizeNPMCoordinate(name)
				if key == "" {
					continue
				}
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, npmResolved(name, ""))
			}
		}
		return nil
	})
	return out
}

// parseLockfile dispatches on the lockfile's name to the format-specific parser. The
// bool is false when the file cannot be read or is structurally unparseable (the caller
// degrades partiality).
func parseLockfile(path string) ([]plugin.ResolvedDependency, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	switch filepath.Base(path) {
	case "package-lock.json", "npm-shrinkwrap.json":
		return parsePackageLock(data)
	case "yarn.lock":
		return parseYarnLock(data)
	case "pnpm-lock.yaml":
		return parsePnpmLock(data)
	}
	return nil, false
}

// --- package-lock.json (npm) -------------------------------------------------

// packageLock is the subset of npm's package-lock.json we read. lockfileVersion 2 and 3
// carry the resolved tree under "packages" (keyed by install path, "" for the root and
// "node_modules/<name>" for deps); v1 carries it under "dependencies" (keyed by name,
// possibly nested). We read both so all three lockfile versions resolve.
type packageLock struct {
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]packageLockPkg `json:"packages"`
	Dependencies    map[string]packageLockDep `json:"dependencies"`
}

type packageLockPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type packageLockDep struct {
	Version      string                    `json:"version"`
	Dependencies map[string]packageLockDep `json:"dependencies"`
}

// parsePackageLock parses package-lock.json (v1/v2/v3). v2/v3's "packages" map is
// preferred when present (it is the authoritative resolved tree); v1's "dependencies"
// map is the fallback. A package whose version is empty is UNRESOLVED, never guessed.
func parsePackageLock(data []byte) ([]plugin.ResolvedDependency, bool) {
	var pl packageLock
	if err := json.Unmarshal(data, &pl); err != nil {
		return nil, false
	}

	var out []plugin.ResolvedDependency
	if len(pl.Packages) > 0 {
		for installPath, pkg := range pl.Packages {
			if installPath == "" {
				// The "" install path is the root project itself, not a dependency — skip
				// it even when it carries a "name" field.
				continue
			}
			name := packageLockName(installPath, pkg.Name)
			if name == "" {
				continue
			}
			out = append(out, npmResolved(name, pkg.Version))
		}
		return out, true
	}

	for name, dep := range pl.Dependencies {
		collectV1(name, dep, &out)
	}
	return out, true
}

// packageLockName derives the dependency's npm name from a v2/v3 "packages" key. The key
// is the install path: "" for the root, "node_modules/<name>" or
// "node_modules/<a>/node_modules/<scope>/<name>" for nested installs. The LAST
// node_modules segment is the resolved package name; an explicit "name" field overrides.
func packageLockName(installPath, explicit string) string {
	if explicit != "" {
		return explicit
	}
	const marker = "node_modules/"
	idx := strings.LastIndex(installPath, marker)
	if idx < 0 {
		return ""
	}
	return installPath[idx+len(marker):]
}

// collectV1 walks the v1 "dependencies" tree, emitting one ResolvedDependency per node
// (nested transitive deps included).
func collectV1(name string, dep packageLockDep, out *[]plugin.ResolvedDependency) {
	*out = append(*out, npmResolved(name, dep.Version))
	for child, c := range dep.Dependencies {
		collectV1(child, c, out)
	}
}

// --- yarn.lock (classic v1 + berry v2+) --------------------------------------

// parseYarnLock parses both yarn.lock dialects. Classic v1 is a custom format
// (unquoted "name@range:" headers, two-space-indented "version \"x\"" fields); berry
// v2+ is YAML-ish (quoted "\"name@npm:range\":" headers, "version: x" fields). The
// parser handles BOTH lexically: it recognizes a header line (column-0, ends with ':',
// not a YAML metadata key) and the following indented "version" field, deriving the
// package name from the header's first descriptor. An entry with no version line is
// UNRESOLVED. The version-field syntax difference (quoted string vs bare) is normalized.
func parseYarnLock(data []byte) ([]plugin.ResolvedDependency, bool) {
	lines := strings.Split(string(data), "\n")
	var out []plugin.ResolvedDependency

	var curName string
	haveEntry := false
	flush := func(version string) {
		if !haveEntry {
			return
		}
		out = append(out, npmResolved(curName, version))
	}

	pendingVersion := ""
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// A header line starts at column 0 (no leading whitespace) and ends with ':'.
		if !startsWithSpace(line) && strings.HasSuffix(trimmed, ":") {
			// Close the previous entry before opening a new one.
			flush(pendingVersion)
			curName = yarnHeaderName(strings.TrimSuffix(trimmed, ":"))
			pendingVersion = ""
			// __metadata and other yarn metadata blocks (leading "__") are not packages.
			haveEntry = curName != "" && !strings.HasPrefix(curName, "__")
			continue
		}
		// Indented field line: look for the version field of the current entry.
		if v, ok := yarnVersionField(trimmed); ok {
			pendingVersion = v
		}
	}
	flush(pendingVersion)
	return out, true
}

// yarnHeaderName extracts the package name from a yarn.lock entry header. The header is
// a comma-separated list of descriptors, each "name@range" (classic) or
// "name@npm:range" / "\"name@npm:range\"" (berry). We take the first descriptor and
// strip the trailing "@range". A scoped name ("@scope/pkg@range") keeps its leading '@'.
func yarnHeaderName(header string) string {
	first := header
	if i := strings.IndexByte(header, ','); i >= 0 {
		first = header[:i]
	}
	first = strings.TrimSpace(first)
	first = strings.Trim(first, "\"'")
	// Strip a leading '@' scope marker before locating the descriptor's '@range' split.
	scoped := strings.HasPrefix(first, "@")
	body := first
	if scoped {
		body = first[1:]
	}
	at := strings.IndexByte(body, '@')
	if at < 0 {
		if scoped {
			return "@" + body
		}
		return body
	}
	name := body[:at]
	if scoped {
		return "@" + name
	}
	return name
}

// yarnVersionField recognizes both yarn dialects' version field: classic
// `version "1.2.3"` and berry `version: 1.2.3` (value optionally quoted). It returns the
// bare version string.
func yarnVersionField(trimmed string) (string, bool) {
	var rest string
	switch {
	case strings.HasPrefix(trimmed, "version:"):
		rest = strings.TrimSpace(trimmed[len("version:"):])
	case strings.HasPrefix(trimmed, "version "):
		rest = strings.TrimSpace(trimmed[len("version "):])
	default:
		return "", false
	}
	rest = strings.Trim(rest, "\"'")
	if rest == "" {
		return "", false
	}
	return rest, true
}

// --- pnpm-lock.yaml ----------------------------------------------------------

// parsePnpmLock parses pnpm-lock.yaml lexically (no YAML library: pure-Go,
// dependency-free, matching the scanner ethos). pnpm records resolved packages under a
// top-level "packages:" block; each key is a package descriptor, either
//
//	/name@version:                (lockfileVersion 6+/9)
//	/name/version:                (lockfileVersion 5)
//	'/@scope/name@version':       (scoped, quoted)
//
// The version is the trailing segment of the descriptor key; an indented "version:"
// field, when present, overrides. A descriptor we cannot split into name+version is
// UNRESOLVED.
func parsePnpmLock(data []byte) ([]plugin.ResolvedDependency, bool) {
	lines := strings.Split(string(data), "\n")
	var out []plugin.ResolvedDependency

	inPackages := false
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Top-level "packages:" opens the resolved-package block; any other column-0 key
		// (settings:, dependencies:, lockfileVersion:) closes it.
		if !startsWithSpace(line) {
			inPackages = strings.HasPrefix(trimmed, "packages:")
			continue
		}
		if !inPackages {
			continue
		}
		// A package entry key is indented two spaces and ends with ':'; deeper-indented
		// lines are that entry's fields (resolution:, engines:, ...), which we skip.
		if indentWidth(line) != 2 || !strings.HasSuffix(trimmed, ":") {
			continue
		}
		key := strings.TrimSuffix(trimmed, ":")
		key = strings.Trim(key, "\"'")
		if name, ver, ok := pnpmDescriptor(key); ok {
			out = append(out, npmResolved(name, ver))
		} else if name != "" {
			out = append(out, npmResolved(name, "")) // descriptor named a package but no parseable version → UNRESOLVED
		}
	}
	return out, true
}

// pnpmDescriptor splits a pnpm package descriptor key into (name, version). It accepts
// the leading '/', the '@'-separated form (/name@1.2.3, /@scope/name@1.2.3) and the
// '/'-separated v5 form (/name/1.2.3, /@scope/name/1.2.3). A trailing "(peer)" build id
// ("@1.2.3(react@18.0.0)") is trimmed off the version. ok is false when no version
// segment can be isolated; name may still be non-empty for the UNRESOLVED fallback.
func pnpmDescriptor(key string) (name, version string, ok bool) {
	body := strings.TrimPrefix(key, "/")
	// A trailing peer-deps suffix "(react@18.0.0)" can contain '@' — strip it up front so
	// it never confuses the version '@' search.
	body = trimPnpmPeer(body)
	// v6+/v9: "name@version" or "@scope/name@version". The version '@' is the LAST '@'
	// whose left side still contains a name.
	if i := lastVersionAt(body); i >= 0 {
		name = body[:i]
		version = body[i+1:]
		if name != "" && version != "" {
			return name, version, true
		}
		return name, "", false
	}
	// v5: "name/version" or "@scope/name/version" — version is the trailing path segment.
	if j := strings.LastIndexByte(body, '/'); j >= 0 {
		cand := trimPnpmPeer(body[j+1:])
		if looksLikeVersion(cand) {
			return body[:j], cand, true
		}
	}
	return body, "", false
}

// lastVersionAt returns the index of the '@' that introduces the version in a pnpm
// "name@version" descriptor, or -1. A scoped name's leading '@' (index 0) is never the
// version separator. The version '@' is the last '@' followed by a version-looking
// segment.
func lastVersionAt(body string) int {
	for i := len(body) - 1; i > 0; i-- {
		if body[i] == '@' && looksLikeVersion(trimPnpmPeer(body[i+1:])) {
			return i
		}
	}
	return -1
}

// trimPnpmPeer strips a trailing pnpm peer-suffix "(...)" from a version segment.
func trimPnpmPeer(v string) string {
	if i := strings.IndexByte(v, '('); i >= 0 {
		return v[:i]
	}
	return v
}

// looksLikeVersion reports whether s begins with a digit — the cheap discriminator
// between a version segment and a package-name segment in a pnpm descriptor.
func looksLikeVersion(s string) bool {
	return s != "" && s[0] >= '0' && s[0] <= '9'
}

// --- shared helpers ----------------------------------------------------------

// npmResolved builds a ResolvedDependency for an npm package. An empty version is
// UNRESOLVED (Resolved=false), never guessed.
func npmResolved(name, version string) plugin.ResolvedDependency {
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return plugin.ResolvedDependency{Coordinate: name, Resolved: false, Source: "npm"}
	}
	return plugin.ResolvedDependency{Coordinate: name, Version: version, Resolved: true, Source: "npm"}
}

// normalizeNPMCoordinate trims and lowercases an npm package name for matching the
// request coordinate against parsed lockfile entries. npm names are already lowercase by
// registry rule; lowercasing is defensive.
func normalizeNPMCoordinate(c string) string {
	return strings.ToLower(strings.TrimSpace(c))
}

// startsWithSpace reports whether a line begins with a space or tab (i.e. is indented).
func startsWithSpace(line string) bool {
	return line != "" && (line[0] == ' ' || line[0] == '\t')
}

// indentWidth counts the leading space characters of a line (tabs counted as one each).
func indentWidth(line string) int {
	w := 0
	for w < len(line) && (line[w] == ' ' || line[w] == '\t') {
		w++
	}
	return w
}
