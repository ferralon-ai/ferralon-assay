package jsanalysis

// Exhaustiveness of the advisory-path dependency set (plugin.DependencyVersionResult.Exhaustive).
//
// Exhaustive claims that an npm package absent from All is provably not installed by this
// build, which lets the pipeline's intake guard disqualify an advisory for a package the
// codebase does not have. package-lock.json / npm-shrinkwrap.json, yarn.lock and pnpm-lock.yaml
// each record the full resolved tree, so the claim is made against them, and only when:
//
//   - at least one lockfile exists, every lockfile parsed, and every entry in each names the
//     package it installs (an alias resolves to its target; a git, tarball or path entry the lock
//     records only under its declared key does not);
//   - the walk of the whole build dir (everything but .git; no skip list) finds no lockfile the
//     resolver did not read, no symlinked directory, and no installed copy of the coordinate in a
//     node_modules tree or a yarn cache;
//   - every package.json that declares a dependency is a project its governing lockfiles (those
//     in the nearest directory at or above it holding any) record: the lock's own root, or a
//     workspace the lock (or, for classic yarn, the root package.json's "workspaces") names;
//   - each governing lockfile, on its own, keys every name the package.json declares in
//     dependencies, devDependencies, optionalDependencies or peerDependencies, and recorded the
//     same spec for each non-peer one (npm v2/v3 project entries, yarn header descriptors, pnpm
//     importer specifiers), so a non-frozen install would not re-resolve it. A v1 package-lock
//     records no specs, so it never covers a package.json that declares one. Peers are checked by
//     name: a peer the lock does not install is still expected present at runtime (the host
//     provides it), so its absence here proves nothing;
//   - the coordinate is not the name of any package.json under the build dir: a lockfile does
//     not list the project (or a workspace package) as its own dependency, so its absence from
//     the lock proves nothing about a first-party advisory.
//
// The lockfile "dev"/"optional" flags are never consulted: every locked package counts as
// present whatever its flags say.
//
// The per-name cross-check also bounds the lexical yarn/pnpm readers: a dialect they misread
// drops declared names or specs and so fails open. Anything else fails open.

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var lockedDependencyFields = []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}

// rangedDependencyFields are the fields a lockfile installs from and records the spec of.
var rangedDependencyFields = []string{"dependencies", "devDependencies", "optionalDependencies"}

var lockfileNames = map[string]bool{"package-lock.json": true, "npm-shrinkwrap.json": true, "yarn.lock": true, "pnpm-lock.yaml": true}

// exhaustiveLockSet reports whether the parsed lockfiles (path → what parseLockfile read)
// enumerate every installable package for every package.json under root.
func exhaustiveLockSet(root, coordinate string, locks map[string]lockInfo, parseFailed bool) bool {
	if parseFailed || len(locks) == 0 {
		return false
	}
	byDir := map[string][]lockInfo{}
	for path, l := range locks {
		if l.opaque {
			return false
		}
		byDir[filepath.Dir(path)] = append(byDir[filepath.Dir(path)], l)
	}
	coord := normalizeNPMCoordinate(coordinate)
	exhaustive := true
	fail := func() error {
		exhaustive = false
		return filepath.SkipAll
	}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return fail()
		}
		name := d.Name()
		if d.Type()&fs.ModeSymlink != 0 {
			info, err := os.Stat(path)
			if err != nil {
				return fail()
			}
			if !info.IsDir() {
				return nil
			}
			if name != "node_modules" {
				return fail() // WalkDir does not follow it, so what it holds goes unread
			}
		} else if !d.IsDir() {
			switch {
			case lockfileNames[name]:
				if _, read := locks[path]; !read {
					return fail()
				}
			case name == "package.json":
				if !projectCovered(path, coord, byDir) {
					return fail()
				}
			case yarnCacheHolds(path, coord):
				return fail()
			}
			return nil
		}
		switch {
		case name == ".git" && path != root:
			return filepath.SkipDir
		case name == "node_modules":
			installed := map[string]bool{}
			if !installedPackages(path, installed, map[string]bool{}) || installed[coord] {
				return fail()
			}
			return filepath.SkipDir
		}
		return nil
	})
	return exhaustive
}

// projectCovered reports whether the package.json at path is covered by its governing lockfiles
// and does not itself define the coordinate. An unreadable or malformed package.json is not
// covered; one that declares no dependency installs nothing and is.
func projectCovered(path, coord string, byDir map[string][]lockInfo) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var manifest map[string]json.RawMessage
	if json.Unmarshal(data, &manifest) != nil {
		return false
	}
	if raw, ok := manifest["name"]; ok {
		var name string
		if json.Unmarshal(raw, &name) != nil || normalizeNPMCoordinate(name) == coord {
			return false
		}
	}
	declared := map[string]map[string]string{}
	declares := false
	for _, field := range lockedDependencyFields {
		raw, ok := manifest[field]
		if !ok {
			continue
		}
		var deps map[string]string
		if json.Unmarshal(raw, &deps) != nil {
			return false
		}
		declared[field] = deps
		declares = declares || len(deps) > 0
	}
	if !declares {
		return true
	}
	dir := filepath.Dir(path)
	lockDir, governing := governingLocks(dir, byDir)
	if len(governing) == 0 {
		return false
	}
	rel, err := filepath.Rel(lockDir, dir)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	for _, l := range governing {
		if !lockCovers(l, lockDir, rel, declared) {
			return false
		}
	}
	return true
}

// governingLocks returns the nearest directory at or above dir that holds a lockfile, and its
// lockfiles.
func governingLocks(dir string, byDir map[string][]lockInfo) (string, []lockInfo) {
	for {
		if l, ok := byDir[dir]; ok {
			return dir, l
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil
		}
		dir = parent
	}
}

// lockCovers reports whether one lockfile records the project at rel (relative to the lock's
// directory) with every declared name, and the same spec for each name it installs from.
func lockCovers(l lockInfo, lockDir, rel string, declared map[string]map[string]string) bool {
	for _, deps := range declared {
		for n := range deps {
			if !l.names[normalizeNPMCoordinate(n)] {
				return false
			}
		}
	}
	switch l.kind {
	case lockNPM, lockPnpm:
		recorded, ok := l.importers[rel]
		if !ok {
			return false
		}
		for _, f := range rangedDependencyFields {
			for n, spec := range declared[f] {
				if !specRecorded(recorded, f, n, spec) {
					return false
				}
			}
		}
		return true
	case lockYarn:
		if rel != "." && l.importers[rel] == nil && !yarnWorkspace(lockDir, rel) {
			return false
		}
		for _, f := range rangedDependencyFields {
			for n, spec := range declared[f] {
				if !l.descriptors[n+"@"+spec] && !l.descriptors[n+"@npm:"+spec] {
					return false
				}
			}
		}
		return true
	default: // lockNPMv1 records no specs
		for _, f := range rangedDependencyFields {
			if len(declared[f]) > 0 {
				return false
			}
		}
		return true
	}
}

func specRecorded(recorded map[string]map[string]string, field, name, spec string) bool {
	for _, f := range []string{field, ""} {
		if got, ok := recorded[f][name]; ok && got == spec {
			return true
		}
	}
	return false
}

// yarnWorkspace reports whether the package.json in lockDir names rel as a workspace (classic
// yarn.lock does not record workspaces itself). A pattern filepath.Match cannot evaluate ("**")
// matches nothing.
func yarnWorkspace(lockDir, rel string) bool {
	data, err := os.ReadFile(filepath.Join(lockDir, "package.json"))
	if err != nil {
		return false
	}
	var root struct {
		Workspaces json.RawMessage `json:"workspaces"`
	}
	if json.Unmarshal(data, &root) != nil || len(root.Workspaces) == 0 {
		return false
	}
	var patterns []string
	if json.Unmarshal(root.Workspaces, &patterns) != nil {
		var obj struct {
			Packages []string `json:"packages"`
		}
		if json.Unmarshal(root.Workspaces, &obj) != nil {
			return false
		}
		patterns = obj.Packages
	}
	for _, p := range patterns {
		p = strings.TrimSuffix(strings.TrimPrefix(filepath.ToSlash(p), "./"), "/")
		if ok, err := filepath.Match(p, rel); err == nil && ok {
			return true
		}
	}
	return false
}

// installedPackages adds to into every package installed in the node_modules tree nm, by its
// install name and its package.json name, descending into nested node_modules and pnpm's .pnpm
// store. It reports false when a directory in the tree cannot be read.
func installedPackages(nm string, into, visited map[string]bool) bool {
	real, err := filepath.EvalSymlinks(nm)
	if err != nil {
		return false
	}
	if visited[real] {
		return true
	}
	visited[real] = true
	entries, err := os.ReadDir(nm)
	if err != nil {
		return false
	}
	for _, e := range entries {
		n := e.Name()
		dir := filepath.Join(nm, n)
		switch {
		case n == ".pnpm":
			store, err := os.ReadDir(dir)
			if err != nil {
				return false
			}
			for _, s := range store {
				inner := filepath.Join(dir, s.Name())
				if s.Name() != "node_modules" {
					inner = filepath.Join(inner, "node_modules")
				}
				if isDir(inner) && !installedPackages(inner, into, visited) {
					return false
				}
			}
		case strings.HasPrefix(n, "."):
			// .bin, .cache, .package-lock.json, .modules.yaml: not packages.
		case strings.HasPrefix(n, "@"):
			scope, err := os.ReadDir(dir)
			if err != nil {
				return false
			}
			for _, s := range scope {
				if !installedPackage(filepath.Join(dir, s.Name()), n+"/"+s.Name(), into, visited) {
					return false
				}
			}
		default:
			if !installedPackage(dir, n, into, visited) {
				return false
			}
		}
	}
	return true
}

func installedPackage(dir, installName string, into, visited map[string]bool) bool {
	if !isDir(dir) {
		return true
	}
	into[normalizeNPMCoordinate(installName)] = true
	if data, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil {
		var m struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(data, &m) == nil && m.Name != "" {
			into[normalizeNPMCoordinate(m.Name)] = true
		}
	}
	if nested := filepath.Join(dir, "node_modules"); isDir(nested) {
		return installedPackages(nested, into, visited)
	}
	return true
}

// yarnCacheHolds reports whether path is a yarn berry cache archive (.yarn/cache/<name>-<...>.zip,
// a scope's '/' flattened to '-') whose name could be the coordinate's.
func yarnCacheHolds(path, coord string) bool {
	dir := filepath.Dir(path)
	if filepath.Ext(path) != ".zip" || filepath.Base(dir) != "cache" || filepath.Base(filepath.Dir(dir)) != ".yarn" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(filepath.Base(path)), strings.ReplaceAll(coord, "/", "-")+"-")
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
