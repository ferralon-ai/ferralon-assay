package jsanalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
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
//   - An unparseable lockfile degrades Partiality to declared-partial (tool_failure), and
//     every Found Match is UNRESOLVED: the broken file may hold another copy of any
//     coordinate, so the readable lockfiles cannot decide its version. A coordinate no
//     readable lockfile holds stays not found. A v1 package-lock or yarn.lock that holds an
//     npm alias entry takes the same path: the entry is keyed by the alias, so the real
//     package's copy is filed under no name this resolver reads.
//   - Any other install surface under the build dir, matched by name or content anywhere the
//     shared walk reaches (everything but node_modules and site-packages), takes the same
//     path: a bun or deno lock, a pnpmfile, a lockfile in a directory lockFiles skips, a
//     package copy under .yarn or .pnpm-store. See versions_surfaces.go.
//   - A package installed in a node_modules directory under the build dir is another copy of
//     it: it takes part in Match like a lockfile entry, without joining All.
//
// Multiple installed copies: Match is chosen by matchCoordinate, which never picks one copy
// out of several distinct versions. See its doc comment for the rule.
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
	copies, copiesRead := installedCopies(req.BuildDir)

	var all []plugin.ResolvedDependency
	parseFailed := unreadSurfaces(req.BuildDir, locks) || !copiesRead
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
	res.Match, res.Found = matchCoordinate(append(all[:len(all):len(all)], copies...), normalizeNPMCoordinate(req.Coordinate))
	if parseFailed && res.Found {
		res.Match.Version = ""
		res.Match.Resolved = false
	}
	return res, nil
}

// matchCoordinate selects the Match for the normalized coordinate want across every entry in
// all — every lockfile, nested copies included. A JS tree routinely installs several copies
// of one package (node_modules/qs next to node_modules/x/node_modules/qs), and the predicate
// reads a single Match, so the rule is:
//
//   - every matching copy resolved to the SAME version (N copies of one version count as one):
//     Match is that version, Resolved=true;
//   - two or more distinct resolved versions, or any matching copy whose version is unknown:
//     Match is UNRESOLVED (Resolved=false, Version empty).
//
// Picking one copy would let a range that straddles the installed set rule the advisory
// not-affected on the copy that happens to sit outside it while a vulnerable copy is still
// installed. UNRESOLVED makes the predicate fail OPEN instead. Versions compare as exact
// strings: two spellings of one version read as distinct, which can only fail open.
func matchCoordinate(all []plugin.ResolvedDependency, want string) (plugin.ResolvedDependency, bool) {
	if want == "" {
		return plugin.ResolvedDependency{}, false
	}
	var (
		match    plugin.ResolvedDependency
		found    bool
		unknown  bool
		versions = make(map[string]struct{})
	)
	for _, d := range all {
		if normalizeNPMCoordinate(d.Coordinate) != want {
			continue
		}
		if !found {
			match, found = d, true
		}
		if !d.Resolved {
			unknown = true
			continue
		}
		if len(versions) == 0 {
			match = d
		}
		versions[d.Version] = struct{}{}
	}
	if found && (unknown || len(versions) != 1) {
		match.Version = ""
		match.Resolved = false
	}
	return match, found
}

// lockFiles returns every recognized lockfile under root (npm/yarn/pnpm), skipping
// build-output/VCS/node_modules trees so a nested install does not shadow the project's
// own top-level lockfile with transitive duplicates. A lockfile in a skipped tree other than
// node_modules is an install surface this does not read, so it vetoes (unreadSurfaces).
func lockFiles(root string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree yields no lockfiles; keep walking.
		}
		if d.IsDir() {
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
	for _, path := range packageManifests(root) {
		manifest, ok := readManifest(path)
		if !ok {
			continue
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
			for _, name := range slices.Sorted(maps.Keys(deps)) {
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
	}
	return out
}

// packageManifests returns every package.json under root, with the same skip rules as
// lockFiles.
func packageManifests(root string) []string {
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
		if d.Name() == "package.json" {
			out = append(out, path)
		}
		return nil
	})
	return out
}

// readManifest decodes the package.json at path as a JSON object. ok is false when it
// cannot be read or is not one.
func readManifest(path string) (map[string]json.RawMessage, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var manifest map[string]json.RawMessage
	if json.Unmarshal(data, &manifest) != nil || manifest == nil {
		return nil, false
	}
	return manifest, true
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
// Every map is walked in sorted key order so All is identical across runs.
func parsePackageLock(data []byte) ([]plugin.ResolvedDependency, bool) {
	var pl packageLock
	if err := json.Unmarshal(data, &pl); err != nil {
		return nil, false
	}

	var out []plugin.ResolvedDependency
	if len(pl.Packages) > 0 {
		for _, installPath := range slices.Sorted(maps.Keys(pl.Packages)) {
			pkg := pl.Packages[installPath]
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

	readable := true
	for _, name := range slices.Sorted(maps.Keys(pl.Dependencies)) {
		if collectV1(name, pl.Dependencies[name], &out) {
			readable = false
		}
	}
	return out, readable
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
// (nested transitive deps included). It reports whether the tree holds an npm alias
// ("version": "npm:real@1.2.3"): v1 keys the entry by the alias, so the real package's copy
// is filed under no name this parser reads. The alias entry is UNRESOLVED and the caller
// treats the lockfile as unparseable.
func collectV1(name string, dep packageLockDep, out *[]plugin.ResolvedDependency) bool {
	aliased := strings.HasPrefix(strings.TrimSpace(dep.Version), "npm:")
	if aliased {
		*out = append(*out, npmResolved(name, ""))
	} else {
		*out = append(*out, npmResolved(name, dep.Version))
	}
	for _, child := range slices.Sorted(maps.Keys(dep.Dependencies)) {
		if collectV1(child, dep.Dependencies[child], out) {
			aliased = true
		}
	}
	return aliased
}

// --- yarn.lock (classic v1 + berry v2+) --------------------------------------

// parseYarnLock parses both yarn.lock dialects. Classic v1 is a custom format
// (unquoted "name@range:" headers, two-space-indented "version \"x\"" fields); berry
// v2+ is YAML-ish (quoted "\"name@npm:range\":" headers, "version: x" fields). The
// parser handles BOTH lexically: it recognizes a header line (column-0, ends with ':',
// not a YAML metadata key) and the following indented "version" field, deriving the
// package name from the header's first descriptor. An entry with no version line is
// UNRESOLVED. The version-field syntax difference (quoted string vs bare) is normalized.
//
// An npm alias entry (yarnHeaderHasAlias) is keyed by the alias, so the real package's copy
// is filed under no name this parser reads: the entry is UNRESOLVED and the bool is false.
func parseYarnLock(data []byte) ([]plugin.ResolvedDependency, bool) {
	lines := strings.Split(string(data), "\n")
	var out []plugin.ResolvedDependency

	var curName string
	haveEntry, curAlias, readable := false, false, true
	flush := func(version string) {
		if !haveEntry {
			return
		}
		if curAlias {
			version = ""
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
			header := strings.TrimSuffix(trimmed, ":")
			curName = yarnHeaderName(header)
			pendingVersion = ""
			// __metadata and other yarn metadata blocks (leading "__") are not packages.
			haveEntry = curName != "" && !strings.HasPrefix(curName, "__")
			curAlias = haveEntry && yarnHeaderHasAlias(header)
			if curAlias {
				readable = false
			}
			continue
		}
		// Indented field line: look for the version field of the current entry.
		if v, ok := yarnVersionField(trimmed); ok {
			pendingVersion = v
		}
	}
	flush(pendingVersion)
	return out, readable
}

// yarnHeaderHasAlias reports whether any descriptor in a yarn.lock header is an npm alias:
// classic "alias@npm:real@^1.0.0", berry "alias@npm:real@npm:^1.0.0", or a bare
// "alias@npm:real" that names a package rather than a range. Berry's ordinary
// "name@npm:^1.2.0" range is not an alias; a range that starts with a letter ("npm:latest")
// cannot be told apart from a bare alias and counts as one.
func yarnHeaderHasAlias(header string) bool {
	for _, d := range strings.Split(header, ",") {
		body := strings.TrimPrefix(strings.Trim(strings.TrimSpace(d), "\"'"), "@")
		at := strings.IndexByte(body, '@')
		if at < 0 {
			continue
		}
		r, isNPM := strings.CutPrefix(body[at+1:], "npm:")
		if !isNPM || r == "" {
			continue
		}
		if strings.IndexByte(r, '@') > 0 || r[0] == '@' || (r[0] >= 'a' && r[0] <= 'z') || (r[0] >= 'A' && r[0] <= 'Z') {
			return true
		}
	}
	return false
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
