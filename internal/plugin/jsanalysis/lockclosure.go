package jsanalysis

import (
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// lockClosures answers "which packages can code loaded from package P reach?" from the
// npm v2/v3 lockfile that governs the importing file: it finds the installed instance of P
// the Node resolver would pick from that file's directory, then follows everything that
// instance's require() can resolve, transitively. Node resolves a bare specifier through
// every node_modules directory on the requiring package's path, whatever the package
// declares, so the reach of an instance is its runtime, optional, and peer dependencies
// plus every package installed in a node_modules directory on its install path, which
// always includes the hoisted top level. Any answer it cannot give exactly (no lockfile, a
// v1/yarn/pnpm lock, a package the lock does not list, a required dependency the lock does
// not install, a node_modules on disk holding a package the lock does not list, NODE_PATH
// set on a surface that may launch the production process) is nil, which a ScopedReason
// reads as unbounded.
//
// The JS package-load refutation builds a fuller install model (disk, yarn, and pnpm
// engines); when it lands, closureOf should delegate to that model's resolve and closure.
type lockClosures struct {
	root   string                // absolute build dir
	graphs map[string]*lockGraph // lockfile dir (build-relative, "" = root) -> parsed lock; nil = unusable
	govern map[string]string     // build-relative dir -> governing lockfile dir; "\x00" = none
	memo   map[string][]string   // lockDir + "\x00" + install path -> closure names
	// nodePath is 0 until the build tree is scanned, then 1 when no candidate production
	// surface sets NODE_PATH and 2 when one does.
	nodePath int
}

// lockGraph is one npm v2/v3 lockfile's `packages` map, keyed by install path relative to
// the lockfile's directory ("node_modules/a", "node_modules/a/node_modules/b", "packages/x").
type lockGraph struct {
	pkgs map[string]lockEntry
	// installedIn maps a directory (relative to the lockfile) to the keys of the packages
	// installed directly in its node_modules; built on first use.
	installedIn map[string][]string
}

type lockEntry struct {
	Name                 string                     `json:"name"`
	Link                 bool                       `json:"link"`
	Resolved             string                     `json:"resolved"`
	Dependencies         map[string]string          `json:"dependencies"`
	OptionalDependencies map[string]string          `json:"optionalDependencies"`
	PeerDependencies     map[string]string          `json:"peerDependencies"`
	PeerDependenciesMeta map[string]lockPeerMetaRaw `json:"peerDependenciesMeta"`
}

type lockPeerMetaRaw struct {
	Optional bool `json:"optional"`
}

const lockNoGovern = "\x00"

func newLockClosures(root string) *lockClosures {
	return &lockClosures{root: root, graphs: map[string]*lockGraph{}, govern: map[string]string{}, memo: map[string][]string{}}
}

// closureOf returns the package names (P first, then the rest of its resolution reach,
// sorted) that code loaded as pkg from fromDir can reach, or nil when the lock cannot bound it. "" in the
// closure stands for first-party code reached through a workspace link.
func (lc *lockClosures) closureOf(fromDir, pkg string) []string {
	if lc.nodePathSet() {
		return nil
	}
	lockDir := lc.governingLock(fromDir)
	if lockDir == lockNoGovern {
		return nil
	}
	g := lc.graph(lockDir)
	if g == nil {
		return nil
	}
	key, ok := g.resolve(lockRel(lockDir, fromDir), pkg)
	if !ok {
		return nil
	}
	names, ok := lc.closure(lockDir, g, key)
	if !ok {
		return nil
	}
	out := []string{pkg}
	for _, n := range names {
		if n != pkg {
			out = append(out, n)
		}
	}
	return out
}

// closure walks the instance at key and everything it can load: declared dependencies
// resolved from the dependent's install path, and every package installed in a
// node_modules directory on that path, which an undeclared (phantom) require() reaches. It
// reports false when a required dependency has no installed instance, since that
// dependency's code is unknown.
func (lc *lockClosures) closure(lockDir string, g *lockGraph, key string) ([]string, bool) {
	memoKey := lockDir + "\x00" + key
	if names, ok := lc.memo[memoKey]; ok {
		return names, names != nil
	}
	names := map[string]bool{}
	seen := map[string]bool{key: true}
	queue := []string{key}
	complete := true
	for len(queue) > 0 && complete {
		cur := queue[0]
		queue = queue[1:]
		e, from := g.entry(cur)
		if g.pkgs[cur].Link {
			// A workspace link is first-party code.
			names[""] = true
		}
		names[lockEntryName(cur, e)] = true
		if alias := lockKeyName(cur); alias != "" {
			names[alias] = true
		}
		visit := func(dep string, required bool) {
			k, ok := g.resolve(from, dep)
			if !ok {
				if required {
					complete = false
				}
				return
			}
			if !seen[k] {
				seen[k] = true
				queue = append(queue, k)
			}
		}
		for _, d := range sortedKeysLock(e.Dependencies) {
			visit(d, true)
		}
		for _, d := range sortedKeysLock(e.OptionalDependencies) {
			visit(d, false)
		}
		for _, d := range sortedKeysLock(e.PeerDependencies) {
			visit(d, !e.PeerDependenciesMeta[d].Optional)
		}
		for _, k := range g.reachable(from) {
			if !seen[k] {
				seen[k] = true
				queue = append(queue, k)
			}
		}
	}
	if !complete {
		lc.memo[memoKey] = nil
		return nil, false
	}
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	lc.memo[memoKey] = out
	return out, true
}

// entry returns the lock entry at key and the directory its dependencies resolve from. A
// workspace link resolves through to the linked directory's entry.
func (g *lockGraph) entry(key string) (lockEntry, string) {
	e := g.pkgs[key]
	if e.Link && e.Resolved != "" {
		target := path.Clean(e.Resolved)
		return g.pkgs[target], target
	}
	return e, key
}

// reachable returns every installed package a require() from dir can resolve by name: the
// packages in dir/node_modules and in each ancestor's, skipping directories that are
// themselves node_modules, as resolve does.
func (g *lockGraph) reachable(dir string) []string {
	if g.installedIn == nil {
		g.installedIn = map[string][]string{}
		keys := make([]string, 0, len(g.pkgs))
		for k := range g.pkgs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			i := strings.LastIndex(k, "node_modules/")
			if i < 0 {
				continue
			}
			parent := strings.TrimSuffix(k[:i], "/")
			g.installedIn[parent] = append(g.installedIn[parent], k)
		}
	}
	var out []string
	for d := dir; ; d = lockParent(d) {
		if path.Base(d) != "node_modules" {
			out = append(out, g.installedIn[d]...)
		}
		if d == "" {
			return out
		}
	}
}

// resolve applies the Node node_modules lookup for pkg from dir (relative to the lockfile):
// dir/node_modules/pkg, then each ancestor's, skipping directories that are themselves
// node_modules.
func (g *lockGraph) resolve(dir, pkg string) (string, bool) {
	for d := dir; ; d = lockParent(d) {
		if path.Base(d) != "node_modules" {
			k := path.Join(d, "node_modules", pkg)
			if d == "" {
				k = "node_modules/" + pkg
			}
			if _, ok := g.pkgs[k]; ok {
				return k, true
			}
		}
		if d == "" {
			return "", false
		}
	}
}

// governingLock finds the nearest directory at or above dir holding package-lock.json or
// npm-shrinkwrap.json.
func (lc *lockClosures) governingLock(dir string) string {
	if v, ok := lc.govern[dir]; ok {
		return v
	}
	var found string
	switch {
	case lc.hasLock(dir):
		found = dir
	case dir == "":
		found = lockNoGovern
	default:
		found = lc.governingLock(lockParent(dir))
	}
	lc.govern[dir] = found
	return found
}

func (lc *lockClosures) hasLock(dir string) bool {
	for _, name := range []string{"npm-shrinkwrap.json", "package-lock.json"} {
		if _, err := os.Stat(filepath.Join(lc.root, filepath.FromSlash(dir), name)); err == nil {
			return true
		}
	}
	return false
}

// graph parses the lockfile in lockDir once. npm-shrinkwrap.json wins over
// package-lock.json, as in npm. Only lockfileVersion 2 and 3 carry the `packages` map.
func (lc *lockClosures) graph(lockDir string) *lockGraph {
	if g, ok := lc.graphs[lockDir]; ok {
		return g
	}
	var g *lockGraph
	for _, name := range []string{"npm-shrinkwrap.json", "package-lock.json"} {
		data, err := os.ReadFile(filepath.Join(lc.root, filepath.FromSlash(lockDir), name))
		if err != nil {
			continue
		}
		var raw struct {
			LockfileVersion int                  `json:"lockfileVersion"`
			Packages        map[string]lockEntry `json:"packages"`
		}
		if json.Unmarshal(data, &raw) == nil && raw.LockfileVersion >= 2 && raw.Packages != nil {
			g = &lockGraph{pkgs: raw.Packages}
		}
		break
	}
	if g != nil && !lc.diskMatchesLock(lockDir, g) {
		g = nil
	}
	lc.graphs[lockDir] = g
	return g
}

// diskMatchesLock reports whether every package installed on disk under lockDir is listed
// in the lock. When one is not (a stale lock, a hand install), Node resolves through a
// layout the lock does not describe, so no reach read from the lock bounds what loads. An
// absent node_modules is the layout an install from the lock produces. Dot entries (.bin,
// .package-lock.json) are npm's own, and a workspace link's own node_modules is checked at
// the linked directory's key.
func (lc *lockClosures) diskMatchesLock(lockDir string, g *lockGraph) bool {
	base := filepath.Join(lc.root, filepath.FromSlash(lockDir))
	dirs := []string{""}
	for k := range g.pkgs {
		if k != "" && !strings.Contains(k, "node_modules/") {
			dirs = append(dirs, k)
		}
	}
	for len(dirs) > 0 {
		d := dirs[len(dirs)-1]
		dirs = dirs[:len(dirs)-1]
		nm := path.Join(d, "node_modules")
		entries, err := os.ReadDir(filepath.Join(base, filepath.FromSlash(nm)))
		if err != nil {
			continue
		}
		for _, e := range entries {
			names := []string{e.Name()}
			if strings.HasPrefix(e.Name(), ".") {
				continue
			}
			if strings.HasPrefix(e.Name(), "@") {
				scoped, err := os.ReadDir(filepath.Join(base, filepath.FromSlash(nm), e.Name()))
				if err != nil {
					return false
				}
				names = names[:0]
				for _, se := range scoped {
					if !strings.HasPrefix(se.Name(), ".") {
						names = append(names, e.Name()+"/"+se.Name())
					}
				}
			}
			for _, n := range names {
				k := nm + "/" + n
				entry, ok := g.pkgs[k]
				if !ok {
					return false
				}
				if !entry.Link {
					dirs = append(dirs, k)
				}
			}
		}
	}
	return true
}

// nodePathAssign matches NODE_PATH being given a value: `NODE_PATH=x` (shell, .env,
// Procfile, package.json scripts), `NODE_PATH: x` and `"NODE_PATH": "x"` (YAML, JSON
// manifests), `ENV NODE_PATH x` (Dockerfile), and `name: NODE_PATH` (Kubernetes env lists).
var nodePathAssign = regexp.MustCompile(`\bNODE_PATH\b["']?\s*[=:]|\bENV\s+NODE_PATH\s|\bname:\s*["']?NODE_PATH\b`)

// nodePathSet reports whether any file that may launch or configure the production
// process sets NODE_PATH. Node resolves a bare specifier through every NODE_PATH directory
// after the node_modules walk, so a package's code can then reach packages no lockfile
// lists. Candidates are container files, Procfiles, env files, shell scripts, and every
// JSON, YAML, or TOML file (package.json scripts, CI workflows, compose and deploy
// manifests), outside directories the lane does not index other than .github.
func (lc *lockClosures) nodePathSet() bool {
	if lc.nodePath == 0 {
		lc.nodePath = 1
		_ = filepath.WalkDir(lc.root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			name := d.Name()
			if d.IsDir() {
				if p != lc.root && skipDir(name) && name != ".github" {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || !nodePathCandidate(name) {
				return nil
			}
			if b, err := os.ReadFile(p); err == nil && nodePathAssign.Match(b) {
				lc.nodePath = 2
				return filepath.SkipAll
			}
			return nil
		})
	}
	return lc.nodePath == 2
}

// nodePathCandidate reports whether a file of this name can set the production process's
// environment.
func nodePathCandidate(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "package-lock.json", "npm-shrinkwrap.json":
		return false
	}
	for _, prefix := range []string{"dockerfile", "containerfile", "procfile", ".env"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	switch path.Ext(lower) {
	case ".dockerfile", ".json", ".yml", ".yaml", ".toml", ".sh", ".env":
		return true
	}
	return false
}

// lockEntryName is the package's real name: the entry's `name` (set for aliases and
// links), else the last node_modules segment of its install path.
func lockEntryName(key string, e lockEntry) string {
	if e.Name != "" {
		return e.Name
	}
	return lockKeyName(key)
}

// lockKeyName is the name a package is installed under: the path after the last
// node_modules/ segment ("@scope/name" or "name"); "" for a non-node_modules path.
func lockKeyName(key string) string {
	i := strings.LastIndex(key, "node_modules/")
	if i < 0 {
		return ""
	}
	return key[i+len("node_modules/"):]
}

// lockRel expresses a build-relative dir relative to the lockfile's dir.
func lockRel(lockDir, dir string) string {
	if lockDir == "" {
		return dir
	}
	if dir == lockDir {
		return ""
	}
	return strings.TrimPrefix(dir, lockDir+"/")
}

func lockParent(d string) string {
	p := path.Dir(d)
	if p == "." || p == "/" {
		return ""
	}
	return p
}

func sortedKeysLock(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
