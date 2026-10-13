package jsanalysis

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// lockClosures answers "which packages can code loaded from package P reach?" from the
// npm lockfile (v1, v2 or v3) that governs the importing file: it finds the installed instance of P
// the Node resolver would pick from that file's directory, then follows everything that
// instance's require() can resolve, transitively. Node resolves a bare specifier through
// every node_modules directory on the requiring package's path, whatever the package
// declares, so the reach of an instance is its runtime, optional, and peer dependencies
// plus every package installed in a node_modules directory on its install path, which
// always includes the hoisted top level. Any answer it cannot give exactly is nil, which a
// ScopedReason reads as unbounded: no lockfile or one it cannot read; a package the lock does not
// list; a required dependency the lock does not install; a link to a directory above the
// lockfile's; a node_modules on disk, anywhere under the lockfile's directory, holding a
// package the lock does not list at that position; a node_modules in a directory above the
// lockfile's; and anything resolutionOverridden reports.
//
// The JS package-load refutation builds a fuller install model (disk, yarn, and pnpm
// engines); when it lands, closureOf should delegate to that model's resolve and closure.
type lockClosures struct {
	root   string                // absolute build dir
	graphs map[string]*lockGraph // lockfile dir (build-relative, "" = root) -> parsed lock; nil = unusable
	govern map[string]string     // build-relative dir -> governing lockfile dir; "\x00" = none
	memo   map[string][]string   // lockDir + "\x00" + install path -> closure names
	// scanned is set once the build tree has been walked; overridden and nodeModules hold
	// what the walk found (see resolutionOverridden).
	scanned    bool
	overridden bool
	// tsPaths and tsRunner record a tsconfig paths setting and a TypeScript runner seen
	// anywhere in the tree; together they override resolution.
	tsPaths, tsRunner bool
	// nodeModules lists the build-relative directory holding each node_modules the walk saw
	// ("" = the build root), in walk order.
	nodeModules []string
}

// lockGraph is one npm lockfile's install tree, keyed by install path relative to the
// lockfile's directory ("node_modules/a", "node_modules/a/node_modules/b", "packages/x"): a
// v2/v3 lock's `packages` map as written, or a v1 lock's nested `dependencies` converted to it.
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
	if lc.resolutionOverridden() {
		return nil
	}
	lockDir := lc.governingLock(fromDir)
	if lockDir == lockNoGovern {
		return nil
	}
	// A lockfile, a workspaces root or a package.json declaring dependencies above the
	// governing lock means an install there puts a node_modules on every resolution path from
	// it, whether or not one is on disk now, and npm installs a workspace member from the
	// root's lock, not its own.
	for d := lockDir; d != ""; {
		d = lockParent(d)
		if lc.hasLock(d) || lc.declaresInstall(d) {
			return nil
		}
	}
	// Node walks every ancestor node_modules, so one above the lockfile's directory is on
	// every installed package's resolution path, and the lock does not describe it.
	for _, d := range lc.nodeModules {
		if d != lockDir && (d == "" || strings.HasPrefix(lockDir, d+"/")) {
			return nil
		}
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

// declaresInstall reports whether dir's package.json declares workspaces or a non-empty
// dependency field of any kind: an install there needs no lockfile. One that is not a regular
// file or cannot be read or decoded counts, since npm would not install from it as this lane
// reads it.
func (lc *lockClosures) declaresInstall(dir string) bool {
	data, err := readRegularFile(filepath.Join(lc.root, filepath.FromSlash(dir), "package.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	var m map[string]json.RawMessage
	if err != nil || json.Unmarshal(data, &m) != nil {
		return true
	}
	for _, field := range []string{"workspaces", "dependencies", "devDependencies", "optionalDependencies",
		"peerDependencies", "bundleDependencies", "bundledDependencies"} {
		switch strings.TrimSpace(string(m[field])) {
		case "", "null", "[]", "{}", "false":
		default:
			return true
		}
	}
	return false
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
// package-lock.json, as in npm. A v2/v3 lock is read from its `packages` map, a v1 lock from
// its nested `dependencies` tree (v1Packages). A lock that is present but not a regular file,
// or cannot be read, leaves the graph unread.
func (lc *lockClosures) graph(lockDir string) *lockGraph {
	if g, ok := lc.graphs[lockDir]; ok {
		return g
	}
	var g *lockGraph
	for _, name := range []string{"npm-shrinkwrap.json", "package-lock.json"} {
		data, err := readRegularFile(filepath.Join(lc.root, filepath.FromSlash(lockDir), name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			break
		}
		var raw struct {
			LockfileVersion int                  `json:"lockfileVersion"`
			Name            string               `json:"name"`
			Packages        map[string]lockEntry `json:"packages"`
			Dependencies    map[string]v1Dep     `json:"dependencies"`
		}
		if json.Unmarshal(data, &raw) != nil {
			break
		}
		switch {
		case raw.LockfileVersion >= 2 && raw.Packages != nil:
			g = &lockGraph{pkgs: raw.Packages}
		case raw.LockfileVersion == 1:
			if pkgs, ok := v1Packages(raw.Name, raw.Dependencies); ok {
				g = &lockGraph{pkgs: pkgs}
			}
		}
		break
	}
	if g != nil {
		// A `file:` link to a directory above the lockfile's has a key above it ("../x"), and
		// that directory's dependencies resolve through node_modules the lock does not describe.
		for k := range g.pkgs {
			if k == ".." || strings.HasPrefix(k, "../") {
				g = nil
				break
			}
		}
	}
	if g != nil && !lc.diskMatchesLock(lockDir, g) {
		g = nil
	}
	lc.graphs[lockDir] = g
	return g
}

// v1Dep is one entry of a lockfileVersion 1 `dependencies` tree. Its position in the tree is
// its install position: a top-level entry is installed in node_modules, and an entry under
// another's `dependencies` in that package's node_modules. `requires` names what the
// package's code requires, resolved by the Node walk from its position like any require.
// dev, optional, peer and bundled flags are not read: a flagged entry is still installed
// where the tree puts it, so it stays in the reach.
type v1Dep struct {
	Version      string            `json:"version"`
	Requires     map[string]string `json:"requires"`
	Dependencies map[string]v1Dep  `json:"dependencies"`
}

// v1Packages converts a v1 `dependencies` tree to the v2 `packages` shape closure reads. Every
// name in `requires` counts as required, since v1 does not mark which are optional. It reports
// false for anything it cannot place: a name that is not a package name, or a `file:`
// directory dependency, which npm links and whose own dependencies the lock does not list.
func v1Packages(rootName string, deps map[string]v1Dep) (map[string]lockEntry, bool) {
	pkgs := map[string]lockEntry{"": {Name: rootName}}
	var add func(parent string, deps map[string]v1Dep) bool
	add = func(parent string, deps map[string]v1Dep) bool {
		for name, d := range deps {
			if !npmPackageName(name) || v1DirectoryLink(d.Version) {
				return false
			}
			key := "node_modules/" + name
			if parent != "" {
				key = parent + "/" + key
			}
			e := lockEntry{Dependencies: d.Requires}
			if real, ok := strings.CutPrefix(d.Version, "npm:"); ok {
				// An alias records the real package as npm:<name>@<version>.
				if i := strings.LastIndex(real, "@"); i > 0 {
					real = real[:i]
				}
				if !npmPackageName(real) {
					return false
				}
				e.Name = real
			}
			pkgs[key] = e
			if !add(key, d.Dependencies) {
				return false
			}
		}
		return true
	}
	if !add("", deps) {
		return nil, false
	}
	return pkgs, true
}

// npmPackageName reports whether name is a plain or scoped npm package name, so it can sit in
// an install path.
func npmPackageName(name string) bool {
	parts := strings.Split(name, "/")
	switch {
	case len(parts) == 2 && (!strings.HasPrefix(parts[0], "@") || parts[0] == "@"):
		return false
	case len(parts) > 2, len(parts) == 1 && strings.HasPrefix(name, "@"):
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\\\x00") {
			return false
		}
	}
	return true
}

// v1DirectoryLink reports whether a v1 version is a `file:` dependency on a directory rather
// than a tarball.
func v1DirectoryLink(version string) bool {
	target, ok := strings.CutPrefix(version, "file:")
	if !ok {
		return false
	}
	lower := strings.ToLower(target)
	return !strings.HasSuffix(lower, ".tgz") && !strings.HasSuffix(lower, ".tar.gz") && !strings.HasSuffix(lower, ".tar")
}

// diskMatchesLock reports whether every package installed on disk under lockDir is listed
// in the lock at the position it is installed. When one is not (a stale lock, a hand
// install, a committed src/node_modules), Node resolves through a layout the lock does not
// describe, so no reach read from the lock bounds what loads. Every node_modules the build
// walk saw under the lockfile's governance is checked, plus each one nested in an installed
// package. An absent node_modules is the layout an install from the lock produces. Dot
// entries (.bin, .package-lock.json) are npm's own (resolutionOverridden vetoes pnpm's and
// yarn's), and a workspace link's own node_modules is checked at the linked directory's key.
func (lc *lockClosures) diskMatchesLock(lockDir string, g *lockGraph) bool {
	base := filepath.Join(lc.root, filepath.FromSlash(lockDir))
	dirs := []string{""}
	for k := range g.pkgs {
		if k != "" && !strings.Contains(k, "node_modules/") {
			dirs = append(dirs, k)
		}
	}
	for _, d := range lc.nodeModules {
		if lc.governingLock(d) == lockDir {
			dirs = append(dirs, lockRel(lockDir, d))
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

// launchToken matches, anywhere in a file, a launch setting or resolver hook under which Node
// resolves or loads packages the lock does not describe: NODE_PATH (extra resolution directories),
// NODE_OPTIONS (which can carry any flag below), NODE_PRESERVE_SYMLINKS, npm's node-options
// (exported as NODE_OPTIONS to the scripts npm runs), and the node flags that preload a
// module or a loader, keep symlinked paths, or add export conditions: --require, --import,
// --loader, --experimental-loader, --preserve-symlinks (and -main), --conditions, and
// --experimental-policy, whose manifest can redirect a dependency.
//
// It also matches the resolver hooks first-party code or config can install: module-alias
// (and its package.json _moduleDirectories and _moduleAliases), app-module-path,
// tsconfig-paths, babel-plugin-module-resolver, a bundler's resolve.alias or resolve.modules,
// patches of Module._resolveFilename, _nodeModulePaths, _findPath or _initPaths, Node's
// registerHooks and getBuiltinModule('module'), and the Module internals reached without
// importing node:module: Module._load, Module._extensions, Module.prototype.require,
// require.extensions, module.constructor's _load, _extensions and prototype.require,
// module.register, and reassigning require or module.require.
var launchToken = regexp.MustCompile(
	`\bNODE_PATH\b|\bNODE_OPTIONS\b|\bNODE_PRESERVE_SYMLINKS\b|\bnode-options\b` +
		`|\b(?:_moduleDirectories|_moduleAliases|module-alias|app-module-path|tsconfig-paths|module-resolver|_resolveFilename|_nodeModulePaths|_findPath|_initPaths|registerHooks)\b` +
		`|\bgetBuiltinModule\s*\(\s*['"\x60](?:node:)?module['"\x60]|\bresolve\.(?:alias|modules)\b` +
		`|\b(?:Module|constructor)\.(?:_load|_extensions|prototype\.require)\b|\brequire\.extensions\b|\bmodule\.register\b` +
		`|\b(?:module|global|globalThis)\.require\s*=[^=]|(?m:(?:^|[;{}(,])[ \t]*require[ \t]*=[^=])` +
		`|--(?:require|import|loader|experimental-loader|experimental-policy|preserve-symlinks|conditions)\b`)

// launchNeedles prefilter launchToken: a window holding none of them cannot match.
var launchNeedles = [][]byte{
	[]byte("NODE_PATH"), []byte("NODE_OPTIONS"), []byte("NODE_PRESERVE_SYMLINKS"),
	[]byte("node-options"), []byte("--require"), []byte("--import"), []byte("--loader"),
	[]byte("--experimental-loader"), []byte("--experimental-policy"), []byte("--preserve-symlinks"), []byte("--conditions"),
	[]byte("_moduleDirectories"), []byte("_moduleAliases"), []byte("module-alias"),
	[]byte("app-module-path"), []byte("tsconfig-paths"), []byte("module-resolver"),
	[]byte("_resolveFilename"), []byte("_nodeModulePaths"), []byte("_findPath"), []byte("_initPaths"),
	[]byte("registerHooks"), []byte("getBuiltinModule"), []byte("resolve."),
	[]byte("_load"), []byte("_extensions"), []byte("prototype.require"), []byte("require.extensions"),
	[]byte("module.register"), []byte("require"),
}

// nodeCommand and shortFlag together leave every closure unbounded: a file that names node,
// nodejs, nodemon or npx as a word and holds -r (preload a module) or -C (add an export
// condition) as a whole token anywhere, = form included. Command lines are not parsed, so a
// flag on a continuation line, in a separate args list or in an argv array counts, and so
// does a -r that belongs to another command in the same file.
var (
	nodeCommand = regexp.MustCompile(`\b(?:node|nodejs|nodemon|npx)(?:\.exe)?\b`)
	shortFlag   = regexp.MustCompile(`(?:^|[\s"'\[,])-[rC](?:$|[\s"'\],=])`)
)

// moduleImport matches a load of node:module, and moduleInternal a use, under whatever name
// the file binds it to, of what that module offers to change how Node loads code: the
// Module._load, _extensions and prototype.require internals, globalPaths, and a bare call
// of the ESM register hook. A file holding both leaves every closure unbounded.
var (
	moduleImport   = regexp.MustCompile(`(?:\bfrom|\brequire\(|\bimport\()\s*['"\x60](?:node:)?module['"\x60]`)
	moduleInternal = regexp.MustCompile(`\.(?:_load|_extensions|globalPaths)\b|\.prototype\.require\b|(?:^|[^.\w$])register\s*\(`)
)

// bundlerName and bundlerResolve together leave every closure unbounded: a file that names a
// bundler, in its name or its text, and mentions an alias or sets a modules key, which
// redirects what the bundle, the code that runs, loads in place of the specifier Node would
// resolve. A package name that only contains one of the words (postcss-modules, alias-hq) is
// not a mention.
var (
	bundlerName    = regexp.MustCompile(`\b(?:webpack|vite|rollup|rolldown|esbuild|rspack)\b`)
	bundlerResolve = regexp.MustCompile(`(?:^|[^\w-])(?:alias(?:$|[^\w-])|["']?modules["']?\s*:)`)
)

// tsPathsSetting matches, in a tsconfig or jsconfig file, compilerOptions that make specifiers
// resolve outside Node's own resolution (paths, baseUrl) or a base config from a package the
// walk does not read, which may set them. tsRunner matches a TypeScript runner or runtime that
// applies those settings when the program runs: ts-node (with a paths plugin), tsx,
// @swc-node/register, esbuild-register, @esbuild-kit, bun. Either alone leaves resolution to
// Node; a tree holding both leaves every closure unbounded.
var (
	tsPathsSetting = regexp.MustCompile(`"(?:paths|baseUrl)"\s*:|"extends"\s*:\s*(?:\[|"[^."])`)
	tsRunner       = regexp.MustCompile(`\b(?:ts-node|swc-node|esbuild-register|esbuild-kit)\b|(?:^|[\s"'\[,=/])(?:tsx|bun)(?:$|[\s"',\]/])`)
)

// tsConfigName matches the file names TypeScript and editors read compilerOptions from.
var tsConfigName = regexp.MustCompile(`^(?:tsconfig|jsconfig)(?:\.[^/]*)?\.json$`)

// installerMarkers name files that mean something other than npm installs (or installed)
// packages here: a yarn, pnpm or bun lockfile, a pnpm workspace root, or a Yarn Plug'n'Play
// runtime. Their layout (yarn and bun hoisting, pnpm's .pnpm store and hidden hoist, PnP's own
// resolution map) differs from the npm lock's positions.
var installerMarkers = map[string]bool{
	"yarn.lock": true, "pnpm-lock.yaml": true, "pnpm-workspace.yaml": true, "bun.lock": true, "bun.lockb": true,
	".pnp.cjs": true, ".pnp.js": true, ".pnp.loader.mjs": true,
}

// npmLockNames are the lockfiles resolutionOverridden parses rather than scans. yarn.lock and
// pnpm-lock.yaml are installerMarkers, which veto before any scan.
var npmLockNames = map[string]bool{"package-lock.json": true, "npm-shrinkwrap.json": true}

// npmLockParses reports whether the file at p decodes as an npm lockfile: a lockfileVersion
// and a packages or dependencies map of entries.
func npmLockParses(p string) bool {
	data, err := readRegularFile(p)
	if err != nil {
		return false
	}
	var raw struct {
		LockfileVersion int                 `json:"lockfileVersion"`
		Packages        map[string]struct{} `json:"packages"`
		Dependencies    map[string]struct{} `json:"dependencies"`
	}
	return json.Unmarshal(data, &raw) == nil && raw.LockfileVersion >= 1 && (raw.Packages != nil || raw.Dependencies != nil)
}

// errNotRegularFile is readRegularFile's error for a path that is not a regular file.
var errNotRegularFile = errors.New("not a regular file")

// readRegularFile reads the file at p only when it resolves, through any symlink, to a regular
// file. It stats before it opens and never opens a pipe, socket or device, since opening a pipe
// with no writer blocks. It follows a symlink to a regular file wherever it points: one that
// leaves the build tree is vetoed by resolutionOverridden's walk, not here.
func readRegularFile(p string) ([]byte, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, &fs.PathError{Op: "read", Path: p, Err: errNotRegularFile}
	}
	return os.ReadFile(p)
}

// installedByOther name entries a node_modules holds when pnpm or yarn installed it.
var installedByOther = []string{".pnpm", ".modules.yaml", ".yarn-state.yml"}

// nodeModulesLinker matches a .yarnrc.yml that selects the node_modules linker. Yarn 2+
// defaults to Plug'n'Play, so a .yarnrc.yml without it is a PnP install.
var nodeModulesLinker = regexp.MustCompile(`(?m)^\s*nodeLinker:\s*["']?node-modules["']?\s*(?:#.*)?$`)

// resolutionOverridden walks the build tree once, by the shared walker rule (every directory
// except node_modules and site-packages is entered; node_modules is visited, not entered; no
// symlink is followed), recording every node_modules it sees. It reports true, leaving every
// closure unbounded, when the walk finds:
//   - a file anywhere containing a launchToken, or both halves of a nodeCommand/shortFlag,
//     moduleImport/moduleInternal or bundlerName/bundlerResolve pair.
//     Over-firing on a mention is the price of not enumerating launch surfaces. The one file
//     not scanned is an npm lockfile that parses as one: it lists what npm installs, not how
//     Node launches or resolves, and a direct dependency or devDependency on a hook package is
//     declared in a package.json, which is scanned;
//   - an npm lockfile that does not parse as one;
//   - a tsconfig or jsconfig paths setting and a TypeScript runner, anywhere in the tree;
//   - an installerMarker, a .yarnrc.yml that does not select the node_modules linker, or a
//     node_modules holding pnpm's or yarn's state;
//   - a symlink that leaves the build tree or does not resolve, a symlink inside the tree to
//     something that is neither a regular file nor a directory (opening a pipe would block the
//     walk), a symlinked node_modules, or anything it cannot read;
//   - a symlinked directory whose target the walk does not itself read. One inside the tree is
//     read in full only when its target resolves inside the tree's real path to a directory the
//     walk enters at that real path: not node_modules, site-packages or anything under one. The
//     walk never follows the link, so a link cycle cannot make it loop.
func (lc *lockClosures) resolutionOverridden() bool {
	if lc.scanned {
		return lc.overridden
	}
	lc.scanned = true
	veto := func() error {
		lc.overridden = true
		return filepath.SkipAll
	}
	realRoot, rootErr := filepath.EvalSymlinks(lc.root)
	// walked holds the real path of every directory the walk entered and listed. The walk never
	// follows a symlink, so a walked path is root's real path joined with its path under root.
	walked := map[string]bool{}
	realOf := func(path string) string {
		rel, err := filepath.Rel(lc.root, path)
		if err != nil {
			return ""
		}
		return filepath.Join(realRoot, rel)
	}
	var linkedDirs []string
	_ = walkBuildTree(lc.root, func(e buildTreeEntry, err error) error {
		if err != nil || e.Escapes {
			return veto()
		}
		name := e.D.Name()
		if e.Skipped {
			if name != "node_modules" {
				return nil
			}
			if e.Symlink {
				return veto()
			}
			for _, m := range installedByOther {
				if _, err := os.Lstat(filepath.Join(e.Path, m)); err == nil {
					return veto()
				}
			}
			rel, _ := filepath.Rel(lc.root, filepath.Dir(e.Path))
			if rel = filepath.ToSlash(rel); rel == "." {
				rel = ""
			}
			lc.nodeModules = append(lc.nodeModules, rel)
			return nil
		}
		if installerMarkers[name] {
			return veto()
		}
		if e.Symlink && buildTreeIsDir(e.Path) {
			linkedDirs = append(linkedDirs, e.Path)
			return nil
		}
		if e.D.IsDir() {
			walked[realOf(e.Path)] = true
			return nil
		}
		if !e.Symlink && !e.D.Type().IsRegular() {
			return nil
		}
		if e.Symlink {
			fi, err := os.Stat(e.Path)
			if err != nil {
				return veto()
			}
			if !fi.Mode().IsRegular() {
				return veto() // opening a pipe would block
			}
		}
		if npmLockNames[name] {
			if npmLockParses(e.Path) {
				return nil
			}
			return veto()
		}
		// A symlinked file inside the tree is read through the link, since its target may sit
		// in a directory the walk does not enter.
		sc, err := scanLaunchFile(e.Path, name == ".yarnrc.yml", tsConfigName.MatchString(name), bundlerName.MatchString(name))
		if err != nil || sc.overrides() {
			return veto()
		}
		lc.tsPaths = lc.tsPaths || sc.tsPaths
		lc.tsRunner = lc.tsRunner || sc.tsRunner
		return nil
	})
	if lc.tsPaths && lc.tsRunner {
		lc.overridden = true
	}
	for _, link := range linkedDirs {
		if lc.overridden {
			break
		}
		target, err := filepath.EvalSymlinks(link)
		if rootErr != nil || err != nil || !walked[target] {
			lc.overridden = true
		}
	}
	return lc.overridden
}

// launchScan is what scanLaunchFile found in one file.
type launchScan struct {
	// token is a launchToken, or a .yarnrc.yml that does not select the node_modules linker.
	token                        bool
	nodeCommand, shortFlag       bool
	moduleImport, moduleInternal bool
	bundlerName, bundlerResolve  bool
	// tsPaths is set only for a tsconfig or jsconfig file.
	tsPaths, tsRunner bool
}

// overrides reports whether the file alone leaves every closure unbounded.
func (sc launchScan) overrides() bool {
	return sc.token || sc.nodeCommand && sc.shortFlag || sc.moduleImport && sc.moduleInternal ||
		sc.bundlerName && sc.bundlerResolve
}

// scanLaunchFile scans the file at p in overlapping windows, so a file of any size is read in
// bounded memory. yarnrc marks a .yarnrc.yml, tsconfig a tsconfig or jsconfig file, and
// bundler a file whose name names a bundler.
func scanLaunchFile(p string, yarnrc, tsconfig, bundler bool) (launchScan, error) {
	sc := launchScan{bundlerName: bundler}
	f, err := os.Open(p)
	if err != nil {
		return sc, err
	}
	defer f.Close()
	const window, overlap = 1 << 20, 512
	buf := make([]byte, 0, window+overlap)
	linker := false
	for {
		n, err := io.ReadFull(f, buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if hasNeedle(buf) && launchToken.Match(buf) {
			sc.token = true
			return sc, nil
		}
		if yarnrc && nodeModulesLinker.Match(buf) {
			linker = true
		}
		sc.nodeCommand = sc.nodeCommand || nodeCommand.Match(buf)
		sc.shortFlag = sc.shortFlag || shortFlag.Match(buf)
		sc.moduleImport = sc.moduleImport || moduleImport.Match(buf)
		sc.bundlerName = sc.bundlerName || bundlerName.Match(buf)
		sc.bundlerResolve = sc.bundlerResolve || bundlerResolve.Match(buf)
		sc.moduleInternal = sc.moduleInternal || moduleInternal.Match(buf)
		sc.tsPaths = sc.tsPaths || tsconfig && tsPathsSetting.Match(buf)
		sc.tsRunner = sc.tsRunner || tsRunner.Match(buf)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			sc.token = yarnrc && !linker
			return sc, nil
		}
		if err != nil {
			return sc, err
		}
		if len(buf) > overlap {
			buf = append(buf[:0], buf[len(buf)-overlap:]...)
		}
	}
}

func hasNeedle(b []byte) bool {
	for _, n := range launchNeedles {
		if bytes.Contains(b, n) {
			return true
		}
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
