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
			if data, err := readRegular(path); err == nil {
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

// gradleProjectLock is one project's lock state per configuration: the configurations its lock
// holds an entry for, and those an "empty=" line names.
type gradleProjectLock struct {
	entries, empty map[string]bool
}

// gradleConfigPinned reports whether Gradle resolves a project's configuration only to versions
// its lock state holds. A project whose legacy lock directory could hold lock state
// (gradleLegacyLocks) is never pinned, whatever gradle.lockfile says: which of the two Gradle
// binds isn't decided here, and the legacy lines aren't read as versions. Otherwise, in the
// default lock mode a configuration with no lock state, or with empty lock state, is not
// constrained at all, so it is pinned only when the lock holds an entry for it. STRICT mode fails
// the build for a configuration with no lock state, so there it is pinned unless an "empty=" line
// names it.
func gradleConfigPinned(dir string, lock *gradleProjectLock, strict bool, conf string) bool {
	if gradleLegacyLocks(dir) {
		return false
	}
	if lock != nil && lock.entries[conf] {
		return true
	}
	return strict && (lock == nil || !lock.empty[conf])
}

// gradleLegacyLocks reports whether project dir's gradle/dependency-locks could hold lock state.
// Gradle reads gradle/dependency-locks/<configuration>.lockfile as a configuration's lock state,
// and this reader does not take those lines as versions, so a configuration may be pinned to
// versions not read here. The directory present, or not ruled absent (an error other than
// not-exist), counts.
func gradleLegacyLocks(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, "gradle", "dependency-locks"))
	return err == nil || !missing(err)
}

// readLockfiles parses every lock state Gradle itself reads under root (see gradleLockProject).
// Lines are "g:a:v=conf1,conf2" or "empty=conf1,conf2"; comments are ignored. Returns the merged
// map "g:a:v" -> entry (configs accumulated), the set of lockfile rel paths, whether any lockfile
// existed at all, every line that is neither of those nor a coordinate ("file:line"), and each
// project's lock state per configuration (project dir -> state).
// A group:artifact locked at two versions (compileClasspath at one, runtimeClasspath at another,
// or different lockfiles) keeps both: either can be the code that runs.
func readLockfiles(root string) (map[string]*lockedEntry, []string, bool, []string, map[string]*gradleProjectLock) {
	out := map[string]*lockedEntry{}
	state := map[string]*gradleProjectLock{}
	var files, unparsed []string
	projects, _ := gradleProjects(root)
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
		project, ok := gradleLockProject(root, path, projects)
		if !ok {
			return nil
		}
		rel := relToBase(root, path)
		files = append(files, rel)
		data, rerr := readRegular(path)
		if rerr != nil {
			unparsed = append(unparsed, rel)
			return nil
		}
		if state[project] == nil {
			state[project] = &gradleProjectLock{entries: map[string]bool{}, empty: map[string]bool{}}
		}
		for n, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			coord, configs, ok := splitLockLine(line)
			if coord == "empty" {
				for _, c := range configs {
					state[project].empty[c] = true
				}
				continue
			}
			if !ok {
				unparsed = append(unparsed, rel+":"+strconv.Itoa(n+1))
				continue
			}
			g, a, v, ok := splitGAV(coord)
			if !ok {
				unparsed = append(unparsed, rel+":"+strconv.Itoa(n+1))
				continue
			}
			for _, c := range configs {
				state[project].entries[c] = true
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
	return out, files, len(files) > 0, unparsed, state
}

// gradleLockProject reports whether path is where Gradle keeps a project's lock state, and
// returns that project's directory: gradle.lockfile in the project directory, or
// <configuration>.lockfile in its gradle/dependency-locks. A project directory is one in
// projects (see gradleProjects); when the settings script cannot be read in full (projects is
// nil), it is root or one holding a build script, and unconfirmedLocks confirms none of them. A
// *.lockfile anywhere else (a test resource, a fixture, a directory the settings script does not
// include, the buildscript or settings lock) is nothing Gradle resolves the build's dependencies
// from.
func gradleLockProject(root, path string, projects map[string]bool) (string, bool) {
	dir, name := filepath.Dir(path), filepath.Base(path)
	switch {
	case name == "gradle.lockfile":
	case strings.HasSuffix(name, ".lockfile") && filepath.Base(dir) == "dependency-locks" && filepath.Base(filepath.Dir(dir)) == "gradle":
		dir = filepath.Dir(filepath.Dir(dir))
	default:
		return "", false
	}
	if projects != nil {
		return dir, projects[dir]
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
	data, err := readRegular(filepath.Join(root, "gradle", "libs.versions.toml"))
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
	locked, lockFiles, haveLock, unparsed, lockState := readLockfiles(buildDir)
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
	unconfirmed := unconfirmedLocks(buildDir, locked, lockState)
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

// unconfirmedLocks returns the group:artifacts whose locked versions the build does not
// confirm. A lock outlives the script edit that stales it, and Gradle reads it only for the
// configurations locking covers. Nothing is confirmed unless every script Gradle would evaluate
// is made of SAFE statements (gradleBuildSafe): any other statement, unread script, buildSrc,
// init script or settings construct can move a version, so every locked GA is unconfirmed. The
// projects are root and those the root settings script includes (see gradleProjects); each,
// with or without a lock, is checked against the scripts that declare for it: its own build
// script and, for a subproject, the root's, whose allprojects/subprojects blocks reach it. A
// project's locked GAs stand only when the project locks every configuration
// (gradleLockingEnforced); a project with no locking statement leaves its lock unread by Gradle.
// Locking constrains only a configuration with lock state, so the project's runtimeClasspath
// must also be pinned (gradleConfigPinned): an entry for it in the lock, or STRICT mode with no
// "empty=" line naming it. A project whose runtimeClasspath is not pinned, or whose lock holds
// nothing (or that has none), but whose scripts declare anything may resolve any GA, transitively
// too, so it confirms no lock. Otherwise every declaration must be consistent with that project's
// lock: a literal version must be one it holds, a dynamic one passes (Gradle fails a pinned
// configuration's resolution that the lock state does not hold), and a declaration with no
// version, or one the project's lock lacks, leaves the GA unconfirmed.
func unconfirmedLocks(root string, locked map[string]*lockedEntry, state map[string]*gradleProjectLock) map[string]bool {
	out, unknown := gradleLockConfirmation(root, locked, state)
	if unknown != "" {
		for _, e := range locked {
			out[e.ga()] = true
		}
	}
	return out
}

// gradleLockConfirmation is unconfirmedLocks' predicate. unknown is empty, or names the first
// reason no locked GA can be confirmed: then what any project resolves is unknown, and every
// lock is unconfirmed. Otherwise out holds the GAs it leaves unconfirmed one by one.
func gradleLockConfirmation(root string, locked map[string]*lockedEntry, state map[string]*gradleProjectLock) (out map[string]bool, unknown string) {
	out = map[string]bool{}
	if why, ok := gradleBuildSafe(root); !ok {
		return out, why
	}
	projects, ok := gradleProjects(root)
	if !ok {
		return out, "the settings script can't be read in full"
	}
	rootSrcs, ok := readGradleSources(gradleScriptsIn(root))
	if !ok {
		return out, "the root build script can't be read"
	}
	byProject := map[string]map[string]map[string]bool{} // project dir -> "g:a" -> versions
	for dir := range projects {
		byProject[dir] = map[string]map[string]bool{}
	}
	anyLock := map[string]bool{}
	for _, e := range locked {
		anyLock[e.ga()] = true
		for _, dir := range e.projects {
			if byProject[dir] == nil {
				return out, relToBase(root, dir) + " holds a lock outside the project set" // readLockfiles and the set disagree
			}
			if byProject[dir][e.ga()] == nil {
				byProject[dir][e.ga()] = map[string]bool{}
			}
			byProject[dir][e.ga()][e.version] = true
		}
	}
	for dir, versions := range byProject {
		own, inherited := rootSrcs, []string(nil)
		if dir != filepath.Clean(root) {
			if own, ok = readGradleSources(gradleScriptsIn(dir)); !ok {
				return out, relToBase(root, dir) + "'s build script can't be read"
			}
			inherited = rootSrcs
		}
		declarations := gradleDeclarations(append(append([]string{}, own...), inherited...))
		if len(versions) == 0 {
			if len(declarations) > 0 {
				return out, relToBase(root, dir) + " declares dependencies, but no lock read for it holds any" // what a project that locks nothing resolves, transitively too, is unknown
			}
			continue
		}
		enforced, strict := gradleLockingEnforced(own, inherited)
		if !enforced {
			for ga := range versions {
				out[ga] = true
			}
			continue
		}
		if !gradleConfigPinned(dir, state[dir], strict, "runtimeClasspath") {
			if len(declarations) > 0 {
				return out, relToBase(root, dir) + "'s runtimeClasspath is not pinned by its lock" // an unpinned runtimeClasspath resolves whatever it is asked for
			}
			for ga := range versions {
				out[ga] = true
			}
			continue
		}
		for ga, declared := range declarations {
			if !anyLock[ga] {
				continue // absent from every lock: the caller reports it unresolved
			}
			if versions[ga] == nil {
				out[ga] = true
				continue
			}
			for _, v := range declared {
				if v == "" || exactGradleVersion(v) && !versions[ga][v] {
					out[ga] = true
				}
			}
		}
	}
	return out, ""
}

// gradleProjects returns the directories of root and of every project the root settings script
// creates. An include creates the project it names and each project on its path: "a:b" creates
// :a at a and :a:b at a/b. ok is false when a settings script exists but cannot be read in full
// (gradleSettingsProjects), or a path has an empty segment, since then any directory could be a
// project.
func gradleProjects(root string) (map[string]bool, bool) {
	projects := map[string]bool{filepath.Clean(root): true}
	for _, path := range gradleSettingsIn(root) {
		names, ok := gradleSettingsProjects(path)
		if !ok {
			return nil, false
		}
		for _, n := range names {
			dir := filepath.Clean(root)
			for _, seg := range strings.Split(strings.TrimPrefix(n, ":"), ":") {
				if seg == "" {
					return nil, false
				}
				dir = filepath.Join(dir, seg)
				projects[dir] = true
			}
		}
	}
	return projects, true
}

// gradleSettingsIn returns the settings scripts at root: every name present, readable or not.
func gradleSettingsIn(root string) []string {
	return gradleFilesIn(root, "settings.gradle", "settings.gradle.kts")
}

// gradleScriptsIn returns the build scripts directly in dir: every name present, readable or
// not, so one that is not a regular file is read, and fails, rather than skipped.
func gradleScriptsIn(dir string) []string {
	return gradleFilesIn(dir, "build.gradle", "build.gradle.kts")
}

func gradleFilesIn(dir string, names ...string) []string {
	var out []string
	for _, name := range names {
		path := filepath.Join(dir, name)
		if _, err := os.Lstat(path); err == nil || !missing(err) {
			out = append(out, path)
		}
	}
	return out
}

// readGradleSources reads each script with readRegular and strips its comments. ok is false
// when one cannot be read or its comments cannot be stripped reliably.
func readGradleSources(paths []string) ([]string, bool) {
	var out []string
	for _, p := range paths {
		data, err := readRegular(p)
		if err != nil {
			return nil, false
		}
		src, ok := stripGradleCommentsChecked(string(data))
		if !ok {
			return nil, false
		}
		out = append(out, src)
	}
	return out, true
}

// gradleLockingEnforced reports whether a project locks every configuration, and whether in
// STRICT mode, from its own build script sources (comment-stripped) and, for a subproject, the
// root's. Gradle's default lock mode is not STRICT: it constrains only the configurations that
// have lock state (gradleConfigPinned). The recognizer is an allow-list: the project's own script
// must hold dependencyLocking { lockAllConfigurations() } as a top-level statement, that call
// alone in the block or with a STRICT lock mode (gradleLockingBody), and nothing else in its
// script or the root's may touch locking (another dependencyLocking, a lock mode, LENIENT,
// lockAllConfigurations anywhere else). Only the root's own top-level statement of that shape is
// allowed there, since it locks the root project alone. A statement inside buildscript {}, under
// a condition or in a closure is not top level. A triple-quoted string, or braces or parentheses
// that don't balance, mean not enforced.
func gradleLockingEnforced(own, root []string) (enforced, strict bool) {
	found, strictN := 0, 0
	for _, src := range own {
		rest, n, s, ok := gradleLockAllStatements(src)
		if !ok || touchesLocking(rest) {
			return false, false
		}
		found, strictN = found+n, strictN+s
	}
	for _, src := range root {
		rest, _, _, ok := gradleLockAllStatements(src)
		if !ok || touchesLocking(rest) {
			return false, false
		}
	}
	return found > 0, found > 0 && strictN == found
}

// gradleLockingBody reports whether a dependencyLocking block's body (comment-stripped) is one
// this reader admits: lockAllConfigurations() alone, or with a STRICT lock mode set as
// lockMode = LockMode.STRICT or lockMode.set(LockMode.STRICT), in either order, separated by a
// newline or ';'. Spaces and tabs inside a statement are ignored.
func gradleLockingBody(body string) (ok, strict bool) {
	var stmts []string
	for _, st := range strings.FieldsFunc(body, func(r rune) bool { return r == '\n' || r == '\r' || r == ';' }) {
		if st = strings.NewReplacer(" ", "", "\t", "").Replace(st); st != "" {
			stmts = append(stmts, st)
		}
	}
	lockAll, strictN := 0, 0
	for _, st := range stmts {
		switch st {
		case "lockAllConfigurations()":
			lockAll++
		case "lockMode=LockMode.STRICT", "lockMode.set(LockMode.STRICT)":
			strictN++
		default:
			return false, false
		}
	}
	if lockAll != 1 {
		return false, false
	}
	return true, strictN > 0
}

func touchesLocking(src string) bool {
	l := strings.ToLower(src)
	for _, w := range []string{"dependencylocking", "lockmode", "lenient", "lockallconfigurations"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

// gradleLockAllStatements finds every top-level dependencyLocking { lockAllConfigurations() }
// statement in comment-stripped src, with or without a STRICT lock mode in the block
// (gradleLockingBody), and returns src without them, how many there were, and how many set
// STRICT.
// Top level means outside every brace and parenthesis, and the statement must start one: what
// precedes it is the start of the script, a ';', a '}', the end of a string or of a word other
// than else or do, or a call's closing parenthesis (not an if, while, for or when condition).
// ok is false for a triple-quoted string or unbalanced braces or parentheses.
func gradleLockAllStatements(src string) (rest string, n, strict int, ok bool) {
	if strings.Contains(src, `"""`) || strings.Contains(src, `'''`) {
		return "", 0, 0, false
	}
	const kw = "dependencyLocking"
	var b strings.Builder
	braces, parens := 0, 0
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '"' || c == '\'':
			j := skipQuoted(src, i)
			b.WriteString(src[i:j])
			i = j - 1
			continue
		case braces == 0 && parens == 0 && strings.HasPrefix(src[i:], kw) &&
			(i == 0 || !isGradleIdentByte(src[i-1])) && statementStart(src[:i]):
			k := i + len(kw)
			for k < len(src) && (src[k] == ' ' || src[k] == '\t' || src[k] == '\n' || src[k] == '\r') {
				k++
			}
			if k < len(src) && src[k] == '{' {
				end, balanced := matchBrace(src, k)
				if !balanced {
					return "", 0, 0, false
				}
				if _, endsHere := statementEnd(src[end+1:]); endsHere {
					if body, isStrict := gradleLockingBody(src[k+1 : end]); body {
						n++
						if isStrict {
							strict++
						}
						i = end
						continue
					}
				}
			}
		case c == '{':
			braces++
		case c == '}':
			if braces--; braces < 0 {
				return "", 0, 0, false
			}
		case c == '(':
			parens++
		case c == ')':
			if parens--; parens < 0 {
				return "", 0, 0, false
			}
		}
		b.WriteByte(c)
	}
	if braces != 0 || parens != 0 {
		return "", 0, 0, false
	}
	return b.String(), n, strict, true
}

// statementStart reports whether a statement can start right after before (see
// gradleLockAllStatements).
func statementStart(before string) bool {
	t := strings.TrimRight(before, " \t\r\n")
	if t == "" {
		return true
	}
	switch c := t[len(t)-1]; {
	case c == ';' || c == '}' || c == '"' || c == '\'':
		return true
	case c == ')':
		open := matchParenBack(t)
		if open < 0 {
			return false
		}
		w := lastWord(strings.TrimRight(t[:open], " \t"))
		return w != "" && w != "if" && w != "while" && w != "for" && w != "when" && w != "catch"
	case isGradleIdentByte(c) && c != '.':
		w := lastWord(t)
		return w != "else" && w != "do"
	}
	return false
}

// matchParenBack returns the index of the '(' matching the ')' that ends s, or -1.
func matchParenBack(s string) int {
	depth := 0
	for i := len(s) - 1; i >= 0; i-- {
		switch s[i] {
		case ')':
			depth++
		case '(':
			if depth--; depth == 0 {
				return i
			}
		}
	}
	return -1
}

// lastWord returns the identifier that ends s, or "".
func lastWord(s string) string {
	i := len(s)
	for i > 0 && isGradleIdentByte(s[i-1]) && s[i-1] != '.' {
		i--
	}
	return s[i:]
}

// matchBrace returns the index of the brace closing the one at open, skipping quoted strings.
func matchBrace(src string, open int) (int, bool) {
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '"', '\'':
			i = skipQuoted(src, i) - 1
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// skipQuoted returns the index just past the quoted string starting at src[i], or the end of
// the line when it doesn't close there.
func skipQuoted(src string, i int) int {
	q := src[i]
	j := i + 1
	for j < len(src) && src[j] != q && src[j] != '\n' {
		if src[j] == '\\' {
			j++
		}
		j++
	}
	if j < len(src) && src[j] == q {
		j++
	}
	if j > len(src) {
		j = len(src)
	}
	return j
}

func isGradleIdentByte(c byte) bool {
	return c == '_' || c == '.' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// exactGradleVersion reports whether v names exactly one version: not empty, not interpolated,
// and not a dynamic selector (1.+, latest.release, a [1.0,2.0) range). A strict pin (1.0!!) is
// not interpreted and counts as dynamic.
func exactGradleVersion(v string) bool {
	return isLiteralGradleVersion(v) && !strings.ContainsAny(v, "+[](),!") && !strings.HasPrefix(v, "latest.")
}

// gradleCoordinateString matches a quoted string in g:a[:v[:classifier]][@ext] notation.
var gradleCoordinateString = regexp.MustCompile(`^([\w.\-]+):([\w.\-]+)(?::([^:@\s]*))?(?::[^:@\s]*)?(?:@\w+)?$`)

// gradleDeclarations returns the version every declaration in the comment-stripped sources
// gives, keyed "g:a": the raw version text, "" for none. It reads every quoted coordinate string
// and every map-notation line anywhere in the sources, so a declaration on one line with its
// block (dependencies { implementation 'g:a:v' }) or in a constraints block still counts. A
// string that only looks like a coordinate costs nothing unless a lock holds its GA.
func gradleDeclarations(srcs []string) map[string][]string {
	out := map[string][]string{}
	for _, src := range srcs {
		for _, s := range quotedStrings(src) {
			if m := gradleCoordinateString.FindStringSubmatch(s); m != nil {
				ga := m[1] + ":" + m[2]
				out[ga] = append(out[ga], m[3])
			}
		}
		for _, line := range strings.Split(src, "\n") {
			if rd, ok := gradleMapNotation(line); ok {
				v, _ := gradleMapValue(line, "version")
				out[rd.Coordinate] = append(out[rd.Coordinate], v)
			}
		}
	}
	return out
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
