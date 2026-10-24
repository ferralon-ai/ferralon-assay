package jsanalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
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
//     readable lockfile holds stays not found. A lockfile with an opaque entry (lockInfo.opaque:
//     a git, tarball or path entry, or bundled packages, whose real package the lock does not
//     name) takes the same path: that copy is filed under no name this resolver reads.
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
// Matches lists every lockfile entry and installed copy of the coordinate. MatchesComplete is set
// only when the lockfiles cover every package.json under the build dir and every surface and
// installed copy was read (lockSetCovers), and no yarn cache archive could hold another copy.
//
// Exhaustive is set only when the lockfiles cover every package.json under the build dir
// (exhaustive.go) and no script surface may install a package outside them (unreadSurfaces),
// so a coordinate absent from All is provably not installed; with no lockfile
// (the declared-seed path) or any doubt it stays false and absence proves nothing.
//
// "plugin resolves, pipeline ranges" symmetry (matching Java): this op resolves only the
// concrete installed literal version. Advisory RANGE matching (^ ~ || x-ranges, npm
// ordering) is applied by the pipeline disqualification predicate (pipeline/npm_version.go),
// never here.
func ResolveDependencyVersions(ctx context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.DependencyVersionResult{}, fmt.Errorf("jsanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.DependencyVersionResult{}, fmt.Errorf("jsanalysis: build dir %q is not a directory", req.BuildDir)
	}

	locks := lockFiles(req.BuildDir)
	copies, copiesRead := installedCopies(req.BuildDir)

	var (
		all    []plugin.ResolvedDependency
		parsed = make(map[string]lockInfo, len(locks))
	)
	parseFailed := !copiesRead
	lockFailed := false // a lock that does not parse; exhaustiveLockSet judges every other surface itself
	for _, l := range locks {
		info, ok := parseLockfile(l)
		if !ok {
			lockFailed = true
		}
		if !ok || info.opaque {
			parseFailed = true
		}
		parsed[l] = info
		all = append(all, info.deps...)
	}
	unread, scriptWithheld := installSurfaces(ctx, req.BuildDir, func() map[string]lockInfo { return parsed })
	parseFailed = parseFailed || unread

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

	res := plugin.DependencyVersionResult{
		Partiality: part,
		All:        all,
		Exhaustive: exhaustiveLockSet(req.BuildDir, req.Coordinate, parsed, lockFailed) && !scriptWithheld,
	}
	want := normalizeNPMCoordinate(req.Coordinate)
	installs := append(all[:len(all):len(all)], copies...)
	res.Match, res.Found = matchCoordinate(installs, want)
	if parseFailed && res.Found {
		res.Match.Version = ""
		res.Match.Resolved = false
	}
	for _, d := range installs {
		if want != "" && normalizeNPMCoordinate(d.Coordinate) == want {
			res.Matches = append(res.Matches, d)
		}
	}
	res.MatchesComplete = len(res.Matches) > 0 && lockSetCovers(req.BuildDir, req.Coordinate, parsed, parseFailed) &&
		!installedCopyPresent(req.BuildDir, want, false)
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
	data, err := readRegular(path)
	if err != nil {
		return nil, false
	}
	var manifest map[string]json.RawMessage
	if json.Unmarshal(data, &manifest) != nil || manifest == nil {
		return nil, false
	}
	return manifest, true
}

// lockInfo is what one lockfile records: the installed packages under their real names, and the
// facts the exhaustiveness check (exhaustive.go) needs before it can trust the lock.
type lockInfo struct {
	// kind is lockNPM (package-lock v2/v3), lockNPMv1, lockYarn or lockPnpm.
	kind string
	// deps are the installed packages, each under its real package name.
	deps []plugin.ResolvedDependency
	// names is every name the lock keys a package by, normalized: real names and alias keys
	// alike, so a package.json's declared keys can be checked against it.
	names map[string]bool
	// opaque is set when some entry's installed package cannot be identified from the lock: a git,
	// tarball or path dependency recorded only under the key it was declared as, or (pnpm) a
	// package that ships bundled packages the lock names only in its bundledDependencies list.
	opaque bool
	// importers maps each project the lock records, by directory relative to the lock ("." for
	// its own), to the specs it recorded: dependency field → declared name → spec. Field "" holds
	// specs a format records without their field (pnpm v5 specifiers). A yarn.lock records berry
	// workspaces here with no specs.
	importers map[string]map[string]map[string]string
	// peers maps each npm v2/v3 project, keyed like importers, to the peerDependencies specs it
	// recorded. It is kept apart from importers so a peer alone never makes a project recorded.
	peers map[string]map[string]string
	// installed maps each npm v2/v3 install path ("node_modules/<name>", nested or under a
	// workspace folder) to the version installed there: a link's target's version, and "" when
	// the entry installs a package other than its folder name (an alias) or records none.
	installed map[string]string
	// descriptors is every "name@range" a yarn.lock entry header lists.
	descriptors map[string]bool
	// rootVersions maps each key of a v1 package-lock's top-level "dependencies" (the packages
	// installed at the root's node_modules, every direct dependency among them) to the version
	// string it records.
	rootVersions map[string]string
}

const (
	lockNPM   = "npm"
	lockNPMv1 = "npm-v1"
	lockYarn  = "yarn"
	lockPnpm  = "pnpm"
)

func newLockInfo(kind string) lockInfo {
	return lockInfo{
		kind:         kind,
		names:        map[string]bool{},
		importers:    map[string]map[string]map[string]string{},
		peers:        map[string]map[string]string{},
		installed:    map[string]string{},
		descriptors:  map[string]bool{},
		rootVersions: map[string]string{},
	}
}

// add records an installed package under its real name.
func (l *lockInfo) add(name, version string) {
	l.deps = append(l.deps, npmResolved(name, version))
	l.names[normalizeNPMCoordinate(name)] = true
}

// record notes that project declared name with spec in field.
func (l *lockInfo) record(project, field, name, spec string) {
	byField := l.importers[project]
	if byField == nil {
		byField = map[string]map[string]string{}
		l.importers[project] = byField
	}
	if byField[field] == nil {
		byField[field] = map[string]string{}
	}
	byField[field][name] = spec
}

// parseLockfile dispatches on the lockfile's name to the format-specific parser. The
// bool is false when the file cannot be read or is structurally unparseable (the caller
// degrades partiality).
func parseLockfile(path string) (lockInfo, bool) {
	data, err := readRegular(path)
	if err != nil {
		return lockInfo{}, false
	}
	switch filepath.Base(path) {
	case "package-lock.json", "npm-shrinkwrap.json":
		return parsePackageLock(data)
	case "yarn.lock":
		return parseYarnLock(data)
	case "pnpm-lock.yaml":
		return parsePnpmLock(data)
	}
	return lockInfo{}, false
}

// npmIdentity returns the real package an entry keyed key with spec installs, for the spec forms
// a lockfile records: a registry version or range (the package is key), or an "npm:<name>@<ver>"
// alias (the package is name). ok is false for anything else (git, tarball, path), whose package
// name the lock does not state.
func npmIdentity(key, spec string) (name, version string, ok bool) {
	if rest, alias := strings.CutPrefix(spec, "npm:"); alias {
		if i := strings.LastIndexByte(rest, '@'); i > 0 {
			return rest[:i], rest[i+1:], true
		}
		if bareAliasTarget(rest) {
			return key, "", false
		}
		return key, rest, true
	}
	if strings.ContainsAny(spec, ":/") {
		return key, "", false
	}
	return key, spec, true
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
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Link                 bool              `json:"link"`
	Resolved             string            `json:"resolved"`
}

type packageLockDep struct {
	Version      string                    `json:"version"`
	Dependencies map[string]packageLockDep `json:"dependencies"`
}

// parsePackageLock parses package-lock.json (v1/v2/v3). v2/v3's "packages" map is
// preferred when present (it is the authoritative resolved tree); v1's "dependencies"
// map is the fallback. A package whose version is empty is UNRESOLVED, never guessed.
// Every map is walked in sorted key order so All is identical across runs.
func parsePackageLock(data []byte) (lockInfo, bool) {
	var pl packageLock
	if err := json.Unmarshal(data, &pl); err != nil {
		return lockInfo{}, false
	}

	if len(pl.Packages) > 0 {
		info := newLockInfo(lockNPM)
		for _, installPath := range slices.Sorted(maps.Keys(pl.Packages)) {
			pkg := pl.Packages[installPath]
			if !strings.Contains(installPath, "node_modules/") {
				// The root ("") and each workspace folder are projects: record the specs npm
				// locked them against.
				project := installPath
				if project == "" {
					project = "."
				}
				for field, deps := range map[string]map[string]string{
					"dependencies": pkg.Dependencies, "devDependencies": pkg.DevDependencies, "optionalDependencies": pkg.OptionalDependencies,
				} {
					for n, spec := range deps {
						info.record(project, field, n, spec)
					}
				}
				if len(pkg.PeerDependencies) > 0 {
					info.peers[project] = pkg.PeerDependencies
				}
				if installPath == "" {
					// The "" install path is the root project itself, not a dependency — skip
					// it even when it carries a "name" field.
					continue
				}
			}
			if key := packageLockName(installPath, ""); key != "" {
				info.names[normalizeNPMCoordinate(key)] = true // the folder name: an alias key when "name" differs
				info.installed[installPath] = installedVersion(pl.Packages, key, pkg)
			}
			name := packageLockName(installPath, pkg.Name)
			if name == "" {
				continue
			}
			info.add(name, pkg.Version)
		}
		return info, true
	}

	info := newLockInfo(lockNPMv1)
	for _, name := range slices.Sorted(maps.Keys(pl.Dependencies)) {
		info.rootVersions[name] = pl.Dependencies[name].Version
		collectV1(name, pl.Dependencies[name], &info)
	}
	return info, true
}

// installedVersion returns the version of the package named key that a v2/v3 entry installs: a
// link's target's own version, and "" for an entry installing another package (an alias).
func installedVersion(packages map[string]packageLockPkg, key string, pkg packageLockPkg) string {
	if pkg.Link {
		pkg = packages[pkg.Resolved]
	}
	if pkg.Name != "" && pkg.Name != key {
		return ""
	}
	return pkg.Version
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
// (nested transitive deps included). v1 keys an aliased package by its alias and records
// "npm:<name>@<version>" as the version, so the entry is emitted under the real name. An entry
// whose version is not a registry version names no package and marks the lock opaque.
func collectV1(key string, dep packageLockDep, info *lockInfo) {
	info.names[normalizeNPMCoordinate(key)] = true
	name, version, ok := npmIdentity(key, dep.Version)
	if !ok {
		info.opaque = true
	}
	info.add(name, version)
	for _, child := range slices.Sorted(maps.Keys(dep.Dependencies)) {
		collectV1(child, dep.Dependencies[child], info)
	}
}

// --- yarn.lock (classic v1 + berry v2+) --------------------------------------

// parseYarnLock parses both yarn.lock dialects. Classic v1 is a custom format
// (unquoted "name@range:" headers, two-space-indented "version \"x\"" fields); berry
// v2+ is YAML-ish (quoted "\"name@npm:range\":" headers, "version: x" fields). The
// parser handles BOTH lexically: it recognizes a header line (column-0, ends with ':',
// not a YAML metadata key) and the following indented "version" field. Every descriptor
// in the header is read: its name is a key the lock covers, and its range names the real
// package (yarnIdentity), so an alias "foo@npm:json5@^2" installs json5. An entry with no
// version line is UNRESOLVED. The version-field syntax difference (quoted string vs bare)
// is normalized.
func parseYarnLock(data []byte) (lockInfo, bool) {
	info := newLockInfo(lockYarn)
	var g quoteGuard
	var (
		real      []string
		haveEntry bool
		version   string
	)
	flush := func() {
		if !haveEntry {
			return
		}
		for _, n := range real {
			info.add(n, version)
		}
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if startsWithSpace(line) {
			g.line(trimmed)
		} else {
			g.yarnTop(trimmed)
		}
		// A header line starts at column 0 (no leading whitespace) and ends with ':'.
		if !startsWithSpace(line) && strings.HasSuffix(trimmed, ":") {
			flush()
			real, version, haveEntry = nil, "", false
			seen := map[string]bool{}
			for _, d := range g.descriptors(strings.TrimSuffix(trimmed, ":")) {
				name, rng := splitDescriptor(d)
				// __metadata and other yarn metadata blocks (leading "__") are not packages.
				if name == "" || strings.HasPrefix(name, "__") {
					continue
				}
				haveEntry = true
				info.descriptors[d] = true
				info.names[normalizeNPMCoordinate(name)] = true
				if ws, ok := strings.CutPrefix(rng, "workspace:"); ok && info.importers[ws] == nil {
					info.importers[ws] = map[string]map[string]string{}
				}
				target, ok := yarnIdentity(name, rng)
				if !ok {
					info.opaque = true
					target = name
				}
				if key := normalizeNPMCoordinate(target); !seen[key] {
					seen[key] = true
					real = append(real, target)
				}
			}
			continue
		}
		// Indented field line: look for the version field of the current entry.
		if v, ok := yarnVersionField(trimmed, &g); ok {
			version = v
		}
	}
	flush()
	return info, !g.raw
}

// splitDescriptor splits a yarn descriptor "name@range" at the '@' that ends the name; a scoped
// name ("@scope/pkg@range") keeps its leading '@'.
func splitDescriptor(d string) (name, rng string) {
	start := 0
	if strings.HasPrefix(d, "@") {
		start = 1
	}
	at := strings.IndexByte(d[start:], '@')
	if at < 0 {
		return d, ""
	}
	return d[:start+at], d[start+at+1:]
}

// bareAliasTarget reports whether the part of an "npm:" spec after the prefix, holding no
// "@version", may name a package ("npm:real", "npm:@scope/real") rather than a range. A dist-tag
// ("npm:latest") cannot be told apart from a package name and counts as one.
func bareAliasTarget(rest string) bool {
	if rest == "" {
		return false
	}
	c := rest[0]
	return c == '@' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// yarnIdentity returns the real package a yarn descriptor's range installs: the descriptor's
// own name for a registry range (classic "^2.2.1", berry "npm:^2.2.1"), a workspace, or a patch
// of the same package; the target for an "npm:<name>@<range>" alias. ok is false for any other
// protocol (git, tarball, file, link, portal, a patch of a different package), whose package
// name the lock does not state.
func yarnIdentity(name, rng string) (string, bool) {
	switch {
	case strings.HasPrefix(rng, "npm:"):
		rest := rng[len("npm:"):]
		if i := strings.LastIndexByte(rest, '@'); i > 0 {
			return rest[:i], true
		}
		return name, !bareAliasTarget(rest)
	case strings.HasPrefix(rng, "workspace:"):
		return name, true
	case strings.HasPrefix(rng, "patch:"):
		inner, _ := splitDescriptor(rng[len("patch:"):])
		return name, normalizeNPMCoordinate(inner) == normalizeNPMCoordinate(name)
	case !strings.ContainsAny(rng, ":/"):
		return name, true
	}
	return name, false
}

// yarnVersionField recognizes both yarn dialects' version field: classic
// `version "1.2.3"` and berry `version: 1.2.3` (value optionally quoted). It returns the
// bare version string.
func yarnVersionField(trimmed string, g *quoteGuard) (string, bool) {
	var rest string
	switch {
	case strings.HasPrefix(trimmed, "version:"):
		rest = strings.TrimSpace(trimmed[len("version:"):])
	case strings.HasPrefix(trimmed, "version "):
		rest = strings.TrimSpace(trimmed[len("version "):])
	default:
		return "", false
	}
	rest = g.scalar(rest)
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
//	/name@version:                (lockfileVersion 6)
//	name@version:                 (lockfileVersion 9)
//	/name/version:                (lockfileVersion 5)
//	'/@scope/name@version':       (scoped, quoted)
//
// The name and version come from the descriptor key; an entry's indented "name:" and "version:"
// fields, when present, override (pnpm writes them for git, tarball and custom-registry entries,
// whose key is not a registry descriptor). A non-registry key with no "name:" field names no
// package and marks the lock opaque. A registry descriptor we cannot split into name+version is
// UNRESOLVED. An entry with a "bundledDependencies:" field also marks the lock opaque: pnpm
// installs those packages from inside the entry's tarball and gives them no entry of their own.
//
// The specs each project was locked against are read from "importers:" (or, for a single-project
// lock, the top-level specifiers/dependency blocks): v5 "specifiers:" maps and v6+ per-dependency
// "specifier:" fields.
func parsePnpmLock(data []byte) (lockInfo, bool) {
	info := newLockInfo(lockPnpm)
	var g quoteGuard

	var (
		block                    string // current column-0 key
		entryKey, entryName, ver string // current packages: entry
		haveEntry                bool
		project, section, dep    string // current importer, dependency block, dependency
		sectionIndent            int
	)
	flush := func() {
		if !haveEntry {
			return
		}
		haveEntry = false
		name, keyVer, ok := pnpmDescriptor(entryKey)
		plain := ok && (strings.HasPrefix(entryKey, "/") || lastVersionAt(trimPnpmPeer(entryKey)) >= 0)
		switch {
		case entryName != "":
			name = entryName
			if ver == "" && plain {
				ver = keyVer
			}
		case plain:
			if ver == "" {
				ver = keyVer
			}
		default:
			info.opaque = true
			if name == "" {
				return
			}
			ver = "" // descriptor named a package but no parseable version → UNRESOLVED
		}
		info.add(name, ver)
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		ind := indentWidth(line)
		if ind == 0 {
			g.pnpmTop(trimmed)
		} else {
			g.line(trimmed)
		}
		if ind == 0 {
			flush()
			block, _ = yamlField(trimmed, &g)
			project, section, dep = "", "", ""
			switch block {
			case "specifiers", "dependencies", "devDependencies", "optionalDependencies":
				project, section, sectionIndent = ".", block, 0
			}
			continue
		}
		switch block {
		case "packages":
			// A package entry key is indented two spaces and ends with ':'; its fields sit
			// deeper (resolution:, engines:, name:, version:, ...).
			if ind == 2 && !strings.HasSuffix(trimmed, ":") && !strings.HasSuffix(trimmed, ": {}") {
				g.raw = true
			}
			if ind == 2 && strings.HasSuffix(trimmed, ":") {
				flush()
				entryKey = g.scalar(strings.TrimSuffix(trimmed, ":"))
				entryName, ver, haveEntry = "", "", true
				continue
			}
			if haveEntry && ind == 4 {
				switch k, v := yamlField(trimmed, &g); k {
				case "name":
					entryName = g.scalar(v)
				case "version":
					ver = g.scalar(v)
				case "bundledDependencies", "bundleDependencies":
					info.opaque = true
				}
			}
			continue
		case "importers":
			if ind == 2 {
				project, _ = yamlField(trimmed, &g)
				section, dep = "", ""
				continue
			}
			if ind == 4 {
				section, _ = yamlField(trimmed, &g)
				sectionIndent, dep = 4, ""
				continue
			}
		}
		if project == "" || section == "" {
			continue
		}
		k, v := yamlField(trimmed, &g)
		switch {
		case ind == sectionIndent+2 && section == "specifiers":
			info.record(project, "", k, g.scalar(v))
		case ind == sectionIndent+2:
			dep = k
			info.names[normalizeNPMCoordinate(k)] = true
		case ind == sectionIndent+4 && dep != "" && k == "specifier":
			info.record(project, section, dep, g.scalar(v))
		}
	}
	flush()
	return info, !g.raw
}

// yamlField splits a lexical YAML mapping line "key: value" (or "key:") into its unquoted key
// and its value as written, which a reader that uses it unquotes through g.
func yamlField(trimmed string, g *quoteGuard) (key, value string) {
	if strings.HasSuffix(trimmed, ":") {
		return g.scalar(strings.TrimSuffix(trimmed, ":")), ""
	}
	i := strings.Index(trimmed, ": ")
	if i < 0 {
		return g.scalar(trimmed), ""
	}
	return g.scalar(trimmed[:i]), strings.TrimSpace(trimmed[i+2:])
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
// registry rule; lowercasing is defensive. A PURL-encoded scope ("%40scope/name") is decoded,
// so it matches the lockfile's "@scope/name".
func normalizeNPMCoordinate(c string) string {
	if dec, err := url.PathUnescape(c); err == nil {
		c = dec
	}
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
