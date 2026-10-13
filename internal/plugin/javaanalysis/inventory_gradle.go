package javaanalysis

// inventory_gradle.go — Part B: the Gradle selected-graph reader. NOT a resolver — a JOIN. The
// lockfile supplies WHICH versions won (the node set); the ~/.gradle modules-2 cached POMs supply
// WHO depends on whom (the edges); intersecting drops any POM edge whose target is not in the
// locked set (drift Q5). No Gradle execution, no network. Precedence for a node's version source,
// high→low: lockfile > libs.versions.toml catalog > constraints{}/platform(...) > build-script
// text — each node records which source won. A no-lockfile project is declared-direct only, its
// transitive set the irreducible honest-absent residue.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// --- cached-POM reader (test-overridable) ------------------------------------

// gradleCache resolves a locked coordinate to its cached POM under
// modules-2/files-2.1/<g>/<a>/<v>/<hash>/<a>-<v>.pom. The <hash> dir is content-addressed, so the
// reader globs it. Injected so a test can point `root` at a fixture modules-2 tree.
type gradleCache struct{ root string }

func newGradleCache(root string) *gradleCache {
	if root == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			root = filepath.Join(home, ".gradle", "caches", "modules-2", "files-2.1")
		}
	}
	return &gradleCache{root: root}
}

// pom returns the cached POM for a locked coordinate, or (nil,false) on a cache-miss. The first
// hash dir (lexicographically) that holds the POM wins — deterministic. A coordinate that cannot
// name a cache path, or a POM that resolves outside the cache, is a miss.
func (c *gradleCache) pom(g, a, v string) (*mvnPOM, bool) {
	if c.root == "" || !validGAV(g, a, v) {
		return nil, false
	}
	base := filepath.Join(c.root, g, a, v)
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil, false
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, h := range names {
		path, st := inCache(c.root, filepath.Join(g, a, v, h, a+"-"+v+".pom"))
		if st == cacheEscape {
			return nil, false
		}
		if st != cacheHit {
			continue
		}
		if p, ok := parseMavenPOM(path); ok {
			return p, true
		}
	}
	return nil, false
}

// digest reads the on-disk .sha1 sidecar for a locked coordinate (jar preferred), "" when absent.
func (c *gradleCache) digest(g, a, v string) string {
	if c.root == "" || !validGAV(g, a, v) {
		return ""
	}
	base := filepath.Join(c.root, g, a, v)
	entries, err := os.ReadDir(base)
	if err != nil {
		return ""
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, ext := range []string{".jar.sha1", ".pom.sha1"} {
		for _, h := range names {
			path, st := inCache(c.root, filepath.Join(g, a, v, h, a+"-"+v+ext))
			if st == cacheEscape {
				return ""
			}
			if st != cacheHit {
				continue
			}
			if data, err := os.ReadFile(path); err == nil {
				if s := strings.TrimSpace(string(data)); s != "" {
					return "sha1:" + strings.Fields(s)[0]
				}
			}
		}
	}
	return ""
}

// --- readers -----------------------------------------------------------------

type lockedEntry struct {
	group, artifact, version string
	configs                  []string
	projects                 []string // the project dirs whose lock holds it
}

func (e lockedEntry) ga() string { return e.group + ":" + e.artifact }

// readLockfiles parses every lock state Gradle itself reads under root (see gradleLockProject).
// Lines are "g:a:v=conf1,conf2"; "empty=..." and comments are ignored. Returns the merged
// map "g:a:v" -> entry (configs accumulated), the set of lockfile rel paths, whether any lockfile
// existed at all, and every line that is neither of those nor a coordinate ("file:line").
// A group:artifact locked at two versions (compileClasspath at one, runtimeClasspath at another,
// or different lockfiles) keeps both: either can be the code that runs.
func readLockfiles(root string) (map[string]*lockedEntry, []string, bool, []string) {
	out := map[string]*lockedEntry{}
	var files, unparsed []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		project, ok := gradleLockProject(root, path)
		if !ok {
			return nil
		}
		rel := relToBase(root, path)
		files = append(files, rel)
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			unparsed = append(unparsed, rel)
			return nil
		}
		for n, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty=") {
				continue
			}
			coord, configs, ok := splitLockLine(line)
			if !ok {
				unparsed = append(unparsed, rel+":"+strconv.Itoa(n+1))
				continue
			}
			g, a, v, ok := splitGAV(coord)
			if !ok {
				unparsed = append(unparsed, rel+":"+strconv.Itoa(n+1))
				continue
			}
			key := g + ":" + a + ":" + v
			if e, seen := out[key]; seen {
				e.configs = mergeReasons(e.configs, configs...)
				e.projects = mergeReasons(e.projects, project)
				continue
			}
			out[key] = &lockedEntry{group: g, artifact: a, version: v, configs: configs, projects: []string{project}}
		}
		return nil
	})
	sort.Strings(files)
	sort.Strings(unparsed)
	return out, files, len(files) > 0, unparsed
}

// gradleLockProject reports whether path is where Gradle keeps a project's lock state, and
// returns that project's directory: gradle.lockfile in the project directory, or
// <configuration>.lockfile in its gradle/dependency-locks. A project directory is root or one
// holding a build script. A *.lockfile anywhere else (a test resource, a fixture, the
// buildscript or settings lock) is nothing Gradle resolves the build's dependencies from.
func gradleLockProject(root, path string) (string, bool) {
	dir, name := filepath.Dir(path), filepath.Base(path)
	switch {
	case name == "gradle.lockfile":
	case strings.HasSuffix(name, ".lockfile") && filepath.Base(dir) == "dependency-locks" && filepath.Base(filepath.Dir(dir)) == "gradle":
		dir = filepath.Dir(filepath.Dir(dir))
	default:
		return "", false
	}
	if dir == filepath.Clean(root) || len(gradleScriptsIn(dir)) > 0 {
		return dir, true
	}
	return "", false
}

func splitLockLine(line string) (coord string, configs []string, ok bool) {
	i := strings.IndexByte(line, '=')
	if i < 0 {
		return "", nil, false
	}
	coord = strings.TrimSpace(line[:i])
	for _, c := range strings.Split(line[i+1:], ",") {
		if c = strings.TrimSpace(c); c != "" {
			configs = append(configs, c)
		}
	}
	sort.Strings(configs)
	return coord, configs, coord != ""
}

func splitGAV(coord string) (g, a, v string, ok bool) {
	parts := strings.Split(coord, ":")
	if len(parts) < 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], parts[0] != "" && parts[1] != "" && parts[2] != ""
}

func relToBase(base, path string) string {
	if rel, err := filepath.Rel(base, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return path
}

// catalogEntry is one resolved libs.versions.toml [libraries] alias.
type catalogEntry struct{ group, artifact, version string }

// readCatalog parses gradle/libs.versions.toml: the [versions] table and the [libraries] aliases
// (module/group+name, literal version or version.ref). Only literal or ref-resolved versions are
// kept; anything else is left unresolved (never guessed). Returns coord "g:a" -> entry.
func readCatalog(root string) map[string]catalogEntry {
	data, err := os.ReadFile(filepath.Join(root, "gradle", "libs.versions.toml"))
	if err != nil {
		return nil
	}
	versions := map[string]string{}
	libs := map[string]catalogEntry{}
	section := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(stripTOMLComment(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		key, val, ok := splitTOMLKV(line)
		if !ok {
			continue
		}
		switch section {
		case "versions":
			versions[key] = strings.Trim(val, `"`)
		case "libraries":
			if e, ok := parseCatalogLib(val, versions); ok {
				libs[e.group+":"+e.artifact] = e
			}
		}
	}
	return libs
}

func parseCatalogLib(val string, versions map[string]string) (catalogEntry, bool) {
	val = strings.TrimSpace(val)
	// Shorthand: "g:a:v".
	if strings.HasPrefix(val, `"`) {
		if g, a, v, ok := splitGAV(strings.Trim(val, `"`)); ok {
			return catalogEntry{g, a, v}, true
		}
		return catalogEntry{}, false
	}
	// Inline table: { module = "g:a", version.ref = "x" } or group/name/version.
	var e catalogEntry
	if m := tomlField(val, "module"); m != "" {
		if i := strings.IndexByte(m, ':'); i > 0 {
			e.group, e.artifact = m[:i], m[i+1:]
		}
	}
	if g := tomlField(val, "group"); g != "" {
		e.group = g
	}
	if n := tomlField(val, "name"); n != "" {
		e.artifact = n
	}
	if v := tomlField(val, "version"); v != "" {
		e.version = v
	} else if ref := tomlField(val, "version.ref"); ref != "" {
		e.version = versions[ref]
	}
	return e, e.group != "" && e.artifact != ""
}

// tomlField extracts a quoted `key = "value"` from an inline-table body.
func tomlField(s, key string) string {
	i := strings.Index(s, key)
	if i < 0 {
		return ""
	}
	rest := s[i+len(key):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	rest = rest[j+1:]
	k := strings.IndexByte(rest, '"')
	if k < 0 {
		return ""
	}
	// Guard against version.ref matching version.
	if key == "version" && strings.HasPrefix(strings.TrimSpace(s[i+len("version"):]), ".ref") {
		return ""
	}
	return rest[:k]
}

func splitTOMLKV(line string) (key, val string, ok bool) {
	i := strings.IndexByte(line, '=')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

func stripTOMLComment(line string) string {
	inStr := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inStr = !inStr
		case '#':
			if !inStr {
				return line[:i]
			}
		}
	}
	return line
}

// --- join --------------------------------------------------------------------

// resolveGradle builds the selected graph by joining locked versions (nodes) with cached-POM
// edges. No lockfile ⇒ declared-direct only with the gradle_transitive residue.
func resolveGradle(buildDir string, cache *gradleCache) plugin.DependencyInventory {
	locked, lockFiles, haveLock, unparsed := readLockfiles(buildDir)
	catalog := readCatalog(buildDir)
	declared := gradleDeclaredDirect(buildDir) // "g:a" -> declared (script/catalog) direct set

	if !haveLock {
		return gradleNoLockfile(declared, catalog)
	}

	lockRel := ""
	if len(lockFiles) > 0 {
		lockRel = lockFiles[0]
	}

	// Node set from the lockfile (the authoritative selected versions). A group:artifact locked at
	// several versions gets a node per version.
	nodeIDs := map[string][]string{} // "g:a" -> node IDs, one per locked version
	keys := make([]string, 0, len(locked))
	for k := range locked {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var nodes []plugin.DependencyNode
	var reasons []string
	if len(unparsed) > 0 {
		// A line that is not a coordinate may lock one: the node set is not known in full.
		reasons = mergeReasons(reasons, reasonGradleLockUnparsed)
	}
	unconfirmed := unconfirmedLocks(buildDir, lockFiles, locked, catalog)
	nodeAt := map[string]int{} // locked key -> index of its node
	for _, k := range keys {
		e := locked[k]
		ga := e.ga()
		if unconfirmed[ga] {
			if len(nodeIDs[ga]) == 0 {
				purl := mavenPURL(e.group, e.artifact, "")
				nodeIDs[ga] = []string{"||" + purl}
				_, direct := declared[ga]
				nodes = append(nodes, plugin.DependencyNode{
					ID:         "||" + purl,
					PURL:       purl,
					Direct:     direct,
					Artifact:   plugin.DependencyArtifact{Identity: e.artifact},
					Provenance: plugin.DependencyProvenance{Lockfile: lockRel, Resolver: "gradle-lockfile"},
					Partiality: plugin.Partial(reasonGradleLockUnconfirmed),
				})
				reasons = mergeReasons(reasons, reasonGradleLockUnconfirmed)
			}
			continue
		}
		nodeAt[k] = len(nodes)
		cfg := ""
		if len(e.configs) > 0 {
			cfg = e.configs[0]
		}
		purl := mavenPURL(e.group, e.artifact, e.version)
		id := "|" + cfg + "|" + purl
		nodeIDs[ga] = append(nodeIDs[ga], id)
		nodes = append(nodes, plugin.DependencyNode{
			ID:      id,
			PURL:    purl,
			Version: e.version,
			Direct:  func() bool { _, ok := declared[ga]; return ok }(),
			Membership: plugin.DependencyMembership{
				Target: cfg,
			},
			Artifact: plugin.DependencyArtifact{
				Identity: e.artifact,
				Digest:   cache.digest(e.group, e.artifact, e.version),
			},
			Provenance: plugin.DependencyProvenance{
				Lockfile: lockRel,
				Resolver: "gradle-lockfile",
			},
			Partiality: plugin.Complete(),
		})
	}

	// Edges from cached POMs, filtered to the locked set (drift Q5). A child locked at several
	// versions gets an edge to each: the lockfile does not say which one this parent's
	// configuration selected.
	var edges []plugin.DependencyEdge
	for _, k := range keys {
		i, ok := nodeAt[k]
		if !ok {
			continue // unconfirmed: no version, so no POM to read edges from
		}
		e := locked[k]
		parentID := nodes[i].ID
		pom, ok := cache.pom(e.group, e.artifact, e.version)
		if !ok {
			// Cached POM absent → this node's out-edges undetermined (per-node, never edgeless).
			reasons = mergeReasons(reasons, reasonGradleUncached)
			nodes[i].Partiality = plugin.Partial(reasonGradleUncached)
			continue
		}
		for _, d := range pom.Deps {
			if strings.EqualFold(d.Scope, "test") || strings.EqualFold(d.Scope, "provided") || strings.EqualFold(d.Optional, "true") {
				continue
			}
			for _, cid := range nodeIDs[d.GroupID+":"+d.ArtifactID] {
				edges = append(edges, plugin.DependencyEdge{Parent: parentID, Child: cid})
			}
		}
	}

	// Declared-direct coordinates absent from EVERY lockfile belong to an unlocked subproject of a
	// mixed multiproject (one subproject locks, another does not). They are NOT part of the locked
	// selection, so their transitive edges are unexpressed — the irreducible gradle_transitive
	// residue. Emitting them (never dropping them) also forbids a falsely-Complete graph over the
	// truncated subproject: without this, a single subproject's lockfile would make the whole build
	// report Complete while silently omitting the unlocked subproject's dependencies.
	var declaredKeys []string
	for k := range declared {
		if _, locked := nodeIDs[k]; !locked {
			declaredKeys = append(declaredKeys, k)
		}
	}
	sort.Strings(declaredKeys)
	// Nor is the version the script states for it the one that ran: a lock that lacks a declared
	// coordinate is one the build did not write, so it vouches for no version.
	for _, k := range declaredKeys {
		g, a := splitGA(k)
		purl := mavenPURL(g, a, "")
		nodes = append(nodes, plugin.DependencyNode{
			ID:         "||" + purl,
			PURL:       purl,
			Direct:     true,
			Artifact:   plugin.DependencyArtifact{Identity: a},
			Provenance: plugin.DependencyProvenance{Resolver: "gradle-script"},
			Partiality: plugin.Partial(reasonGradleTransitive, reasonGradleLockUnconfirmed),
		})
		reasons = mergeReasons(reasons, reasonGradleTransitive, reasonGradleLockUnconfirmed)
	}

	return assembleInventory(nodes, edges, graphPartiality(reasons, len(nodes)))
}

// gradleNoLockfile emits the declared-direct nodes only, each flagged with the irreducible
// gradle_transitive residue (no selected-version source, no on-disk graph). The catalog resolves a
// declared alias's version where present; otherwise the node is present-but-unresolved.
func gradleNoLockfile(declared map[string]plugin.ResolvedDependency, catalog map[string]catalogEntry) plugin.DependencyInventory {
	keys := make([]string, 0, len(declared))
	for k := range declared {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var nodes []plugin.DependencyNode
	for _, k := range keys {
		g, a := splitGA(k)
		version := ""
		resolver := "gradle-script"
		// Precedence: catalog (alias) > script-literal version. Neither → UNRESOLVED, never guessed.
		if ce, ok := catalog[k]; ok && ce.version != "" {
			version = ce.version
			resolver = "gradle-catalog"
		} else if rd := declared[k]; rd.Resolved && rd.Version != "" {
			version = rd.Version
		}
		nodeReasons := []string{reasonGradleTransitive}
		if version == "" {
			nodeReasons = append(nodeReasons, plugin.PartialReasonSourceUnpinned)
		}
		purl := mavenPURL(g, a, version)
		nodes = append(nodes, plugin.DependencyNode{
			ID:         "||" + purl,
			PURL:       purl,
			Version:    version,
			Direct:     true,
			Artifact:   plugin.DependencyArtifact{Identity: a},
			Provenance: plugin.DependencyProvenance{Resolver: resolver},
			Partiality: plugin.Partial(nodeReasons...),
		})
	}
	reasons := []string{reasonGradleTransitive}
	return assembleInventory(nodes, nil, graphPartiality(reasons, len(nodes)))
}

func splitGA(k string) (g, a string) {
	if i := strings.IndexByte(k, ':'); i >= 0 {
		return k[:i], k[i+1:]
	}
	return k, ""
}

// unconfirmedLocks returns the group:artifacts whose locked versions the build scripts do not
// confirm. A lock outlives the script edit that stales it, and Gradle reads it only for the
// configurations locking covers. Each project's lock is checked against the scripts that
// declare for that project: its own build script and, for a subproject, the root's (whose
// allprojects/subprojects blocks reach it). A GA's locked versions stand only when every such
// declaration is consistent with that project's lock: a literal version must be one it holds,
// and a dynamic, interpolated or absent one (a platform or constraint supplies it) is
// consistent only when locking is enforced for the project, since then Gradle fails any
// resolution that departs from the lock. A declaration the project's lock lacks, while some
// other lock holds the GA, leaves it unconfirmed too, and a script that cannot be read
// confirms nothing in its project's lock. A catalog alias's version stands in for a
// declaration that has none.
func unconfirmedLocks(root string, lockFiles []string, locked map[string]*lockedEntry, catalog map[string]catalogEntry) map[string]bool {
	byProject := map[string]map[string]map[string]bool{} // project dir -> "g:a" -> versions
	for _, rel := range lockFiles {
		if dir, ok := gradleLockProject(root, filepath.Join(root, filepath.FromSlash(rel))); ok {
			byProject[dir] = map[string]map[string]bool{} // a lock that holds nothing still answers for its project
		}
	}
	anyLock := map[string]bool{}
	for _, e := range locked {
		anyLock[e.ga()] = true
		for _, dir := range e.projects {
			if byProject[dir] == nil {
				byProject[dir] = map[string]map[string]bool{}
			}
			if byProject[dir][e.ga()] == nil {
				byProject[dir][e.ga()] = map[string]bool{}
			}
			byProject[dir][e.ga()][e.version] = true
		}
	}
	out := map[string]bool{}
	for dir, versions := range byProject {
		scripts := gradleScriptsIn(dir)
		if filepath.Clean(dir) != filepath.Clean(root) {
			scripts = append(scripts, gradleScriptsIn(root)...)
		}
		declarations, readAll := gradleDeclarations(scripts)
		if !readAll {
			for ga := range versions {
				out[ga] = true
			}
			continue
		}
		enforced := gradleLockingEnforced(scripts)
		for ga, decls := range declarations {
			if !anyLock[ga] {
				continue // absent from every lock: the caller reports it unresolved
			}
			if versions[ga] == nil {
				out[ga] = true
				continue
			}
			for _, d := range decls {
				v := d.Version
				if !d.Resolved {
					v = catalog[ga].version
				}
				if !exactGradleVersion(v) {
					v = "" // a range, dynamic selector or interpolation names no one version
				}
				if v == "" && enforced {
					continue
				}
				if !versions[ga][v] {
					out[ga] = true
				}
			}
		}
	}
	return out
}

// gradleScriptsIn returns the build scripts directly in dir that are regular files.
func gradleScriptsIn(dir string) []string {
	var out []string
	for _, name := range []string{"build.gradle", "build.gradle.kts"} {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			out = append(out, path)
		}
	}
	return out
}

// gradleLockingEnforced reports whether scripts lock every configuration in Gradle's default,
// strict mode (dependencyLocking { lockAllConfigurations() } with no LENIENT in any of them).
// Locking set up any other way (per configuration, in a plugin or an init script) is not
// recognized, and a declaration only the lock can version then stays unconfirmed.
func gradleLockingEnforced(scripts []string) bool {
	all := false
	for _, gp := range scripts {
		data, err := os.ReadFile(gp)
		if err != nil {
			return false
		}
		src := stripGradleComments(string(data))
		if strings.Contains(src, "LENIENT") {
			return false
		}
		all = all || strings.Contains(src, "lockAllConfigurations()")
	}
	return all
}

// exactGradleVersion reports whether v names exactly one version: not empty, not interpolated,
// and not a dynamic selector (1.+, latest.release, a [1.0,2.0) range). A strict pin (1.0!!) is
// not interpreted and counts as dynamic.
func exactGradleVersion(v string) bool {
	return isLiteralGradleVersion(v) && !strings.ContainsAny(v, "+[](),!") && !strings.HasPrefix(v, "latest.")
}

// gradleCoordinateString matches a quoted string in g:a[:v[:classifier]][@ext] notation.
var gradleCoordinateString = regexp.MustCompile(`^([\w.\-]+):([\w.\-]+)(?::([^:@\s]*))?(?::[^:@\s]*)?(?:@\w+)?$`)

// gradleDeclarations returns every declaration scripts make, keyed "g:a". Besides the
// configuration-line scan, it reads every quoted coordinate string and every map-notation line
// anywhere in the comment-stripped scripts, so a declaration on one line with its block
// (dependencies { implementation 'g:a:v' }) or in a constraints block still counts. A string
// that only looks like a coordinate costs nothing unless a lock holds its GA. readAll is false
// when a script cannot be read.
func gradleDeclarations(scripts []string) (map[string][]plugin.ResolvedDependency, bool) {
	out := map[string][]plugin.ResolvedDependency{}
	add := func(rd plugin.ResolvedDependency) {
		if c := strings.TrimSpace(rd.Coordinate); c != "" {
			out[c] = append(out[c], rd)
		}
	}
	for _, gp := range scripts {
		data, err := os.ReadFile(gp)
		if err != nil {
			return nil, false
		}
		deps, _ := parseGradle(gp)
		for _, rd := range deps {
			add(rd)
		}
		src := stripGradleComments(string(data))
		for _, s := range quotedStrings(src) {
			m := gradleCoordinateString.FindStringSubmatch(s)
			if m == nil {
				continue
			}
			rd := plugin.ResolvedDependency{Coordinate: m[1] + ":" + m[2], Source: "gradle"}
			if isLiteralGradleVersion(m[3]) {
				rd.Version, rd.Resolved = m[3], true
			}
			add(rd)
		}
		for _, line := range strings.Split(src, "\n") {
			if rd, ok := gradleMapNotation(line); ok {
				add(rd)
			}
		}
	}
	return out, true
}

// quotedStrings returns the contents of every single- or double-quoted string in src that
// closes on its own line.
func quotedStrings(src string) []string {
	var out []string
	for i := 0; i < len(src); i++ {
		q := src[i]
		if q != '"' && q != '\'' {
			continue
		}
		j := i + 1
		for j < len(src) && src[j] != q && src[j] != '\n' {
			if src[j] == '\\' {
				j++
			}
			j++
		}
		if j < len(src) && src[j] == q {
			out = append(out, src[i+1:j])
		}
		i = j
	}
	return out
}

// gradleDeclaredDirect returns the directly-declared coordinates from the build scripts (the
// existing lexical scan, demoted to lowest fidelity), keyed "g:a" → the resolved declaration. It
// carries the script-literal version (when present) so a no-lockfile project can still pin a
// declared dep; a non-literal / version-less declaration stays UNRESOLVED (never guessed).
func gradleDeclaredDirect(root string) map[string]plugin.ResolvedDependency {
	out := map[string]plugin.ResolvedDependency{}
	_, gradles := buildFiles(root)
	for _, gp := range gradles {
		deps, _ := parseGradle(gp)
		for _, rd := range deps {
			c := strings.TrimSpace(rd.Coordinate)
			if c == "" {
				continue
			}
			if prev, ok := out[c]; ok && prev.Resolved {
				continue // keep the first resolved declaration.
			}
			out[c] = rd
		}
	}
	return out
}
