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
	"sort"
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
// hash dir (lexicographically) that holds the POM wins — deterministic.
func (c *gradleCache) pom(g, a, v string) (*mvnPOM, bool) {
	if c.root == "" || g == "" || a == "" || v == "" {
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
		if p, ok := parseMavenPOM(filepath.Join(base, h, a+"-"+v+".pom")); ok {
			return p, true
		}
	}
	return nil, false
}

// digest reads the on-disk .sha1 sidecar for a locked coordinate (jar preferred), "" when absent.
func (c *gradleCache) digest(g, a, v string) string {
	if c.root == "" {
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
			if data, err := os.ReadFile(filepath.Join(base, h, a+"-"+v+ext)); err == nil {
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
}

func (e lockedEntry) ga() string { return e.group + ":" + e.artifact }

// readLockfiles parses every gradle.lockfile and gradle/dependency-locks/<config>.lockfile under
// root. Lines are "g:a:v=conf1,conf2"; "empty=..." and comments are ignored. Returns the merged
// map "g:a" -> entry (first-seen version wins; configs accumulated) and the set of lockfile rel
// paths, plus whether any lockfile existed at all.
func readLockfiles(root string) (map[string]*lockedEntry, []string, bool) {
	out := map[string]*lockedEntry{}
	var files []string
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
		name := d.Name()
		if name != "gradle.lockfile" && !strings.HasSuffix(name, ".lockfile") {
			return nil
		}
		files = append(files, relToBase(root, path))
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty=") {
				continue
			}
			coord, configs, ok := splitLockLine(line)
			if !ok {
				continue
			}
			g, a, v, ok := splitGAV(coord)
			if !ok {
				continue
			}
			key := g + ":" + a
			if e, seen := out[key]; seen {
				e.configs = mergeReasons(e.configs, configs...)
				continue
			}
			out[key] = &lockedEntry{group: g, artifact: a, version: v, configs: configs}
		}
		return nil
	})
	sort.Strings(files)
	return out, files, len(files) > 0
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
	locked, lockFiles, haveLock := readLockfiles(buildDir)
	catalog := readCatalog(buildDir)
	declared := gradleDeclaredDirect(buildDir) // "g:a" -> declared (script/catalog) direct set

	if !haveLock {
		return gradleNoLockfile(declared, catalog)
	}

	lockRel := ""
	if len(lockFiles) > 0 {
		lockRel = lockFiles[0]
	}

	// Node set from the lockfile (the authoritative selected versions).
	nodeID := map[string]string{} // "g:a" -> node ID
	keys := make([]string, 0, len(locked))
	for k := range locked {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var nodes []plugin.DependencyNode
	var reasons []string
	for _, k := range keys {
		e := locked[k]
		cfg := ""
		if len(e.configs) > 0 {
			cfg = e.configs[0]
		}
		purl := mavenPURL(e.group, e.artifact, e.version)
		id := "|" + cfg + "|" + purl
		nodeID[k] = id
		nodes = append(nodes, plugin.DependencyNode{
			ID:      id,
			PURL:    purl,
			Version: e.version,
			Direct:  func() bool { _, ok := declared[k]; return ok }(),
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

	// Edges from cached POMs, filtered to the locked set (drift Q5).
	var edges []plugin.DependencyEdge
	for i, k := range keys {
		e := locked[k]
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
			childKey := d.GroupID + ":" + d.ArtifactID
			if cid, present := nodeID[childKey]; present {
				edges = append(edges, plugin.DependencyEdge{Parent: nodeID[k], Child: cid})
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
		if _, locked := nodeID[k]; !locked {
			declaredKeys = append(declaredKeys, k)
		}
	}
	sort.Strings(declaredKeys)
	for _, k := range declaredKeys {
		g, a := splitGA(k)
		version := ""
		resolver := "gradle-script"
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
		reasons = mergeReasons(reasons, reasonGradleTransitive)
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
