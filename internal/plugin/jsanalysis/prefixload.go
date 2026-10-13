package jsanalysis

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// prefixLoadKind is how a static-prefix load (`require('./plugins/' + n)`) is accounted for.
type prefixLoadKind int

const (
	// prefixUnbounded: the load can reach code this lane cannot enumerate; it stays a
	// run-wide limit.
	prefixUnbounded prefixLoadKind = iota
	// prefixFirstParty: every file the prefix names is an in-tree module, and the call
	// graph gets a real edge to each one's top-level frame (see prefixSuffixMayTraverse).
	prefixFirstParty
	// prefixPackage: the load reaches into one npm package (`require('pkg/' + n)`); it is a
	// limit attributed to that package (see prefixSuffixMayTraverse).
	prefixPackage
)

// prefixSuffixMayTraverse records that the runtime part of a static-prefix specifier is
// unconstrained, so the prefix bounds where the load can land only up to path traversal.
// Node normalizes `..` segments in a specifier before resolving it: './plugins/' + n with
// n = '../node_modules/json5' loads json5, and 'lodash/' + '../json5' does the same from
// inside the lodash prefix. When the suffix comes from input, that is a path-traversal
// load, exactly where a refutation must not stand. So while this holds, a first-party
// prefix still gets real edges to the modules it names, but also keeps its run-wide
// computed limit, and a package prefix's limit is attributed to the package with
// unbounded Targets rather than its resolution reach. Narrowing it needs proof that a
// suffix cannot carry a '..' segment, which a lexical scan cannot give today.
const prefixSuffixMayTraverse = true

// maxPrefixWalk bounds the directory walk behind one first-party prefix load; a larger
// subtree is not enumerated.
const maxPrefixWalk = 20000

// prefixCodeExtensions are the file extensions a runtime require/import can load as code.
// A file with one of them under the prefix must be an in-tree module for the load to be
// enumerated; JSON and other data files run no code.
var prefixCodeExtensions = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true, ".tsx": true,
	".mts": true, ".cts": true, ".vue": true, ".node": true, ".wasm": true,
}

// classifyPrefixLoad decides how a static-prefix load in fromModule is accounted for. For
// prefixFirstParty it returns the in-tree modules the load can reach; for prefixPackage, the
// npm package it reaches into.
func (rs *resolver) classifyPrefixLoad(fromModule string, pl prefixLoad) (prefixLoadKind, []string, string) {
	switch {
	case isRelativeSpecifier(pl.prefix):
		if mods, ok := rs.enumeratePrefix(fromModule, pl.prefix); ok {
			return prefixFirstParty, mods, ""
		}
		return prefixUnbounded, nil, ""
	case strings.HasPrefix(pl.prefix, "/"), strings.HasPrefix(pl.prefix, "#"), strings.HasPrefix(pl.prefix, "node:"):
		return prefixUnbounded, nil, ""
	}
	pkg, ok := prefixPackageName(pl.prefix)
	if !ok {
		return prefixUnbounded, nil, ""
	}
	if builtin, _ := nodeBuiltin(pkg); builtin {
		return prefixUnbounded, nil, ""
	}
	// A prefix some first-party mapping claims (a tsconfig paths alias, a workspace member,
	// the package's own name) can land in first-party code; leave it unbounded.
	if _, _, ok := rs.resolveTsPaths(fromModule, pl.prefix+"x"); ok {
		return prefixUnbounded, nil, ""
	}
	if self, _ := rs.governingPackageJSON(fromModule); self != nil && self.name == pkg {
		return prefixUnbounded, nil, ""
	}
	if rs.isWorkspaceMemberName(pkg) {
		return prefixUnbounded, nil, ""
	}
	return prefixPackage, nil, pkg
}

// prefixPackageName returns the package a bare prefix reaches into when the prefix spells
// out a complete package name followed by '/': "pkg/..." or "@scope/pkg/...".
func prefixPackageName(prefix string) (string, bool) {
	parts := strings.SplitN(prefix, "/", 3)
	var name string
	switch {
	case strings.HasPrefix(prefix, "@"):
		if len(parts) < 3 {
			return "", false
		}
		name = parts[0] + "/" + parts[1]
	default:
		if len(parts) < 2 {
			return "", false
		}
		name = parts[0]
	}
	return name, validNPMName(name)
}

// isWorkspaceMemberName reports whether name is a workspace member's package name.
func (rs *resolver) isWorkspaceMemberName(name string) bool {
	root, ok := rs.rootManifest()
	if !ok || len(root.workspaces) == 0 {
		return false
	}
	for _, member := range rs.workspaceMemberDirs(root.workspaces) {
		if mm := rs.memberManifest(member); mm != nil && mm.name == name {
			return true
		}
	}
	return false
}

// errPrefixUnbounded stops a prefix walk that met something it cannot enumerate.
var errPrefixUnbounded = errors.New("prefix load not enumerable")

// enumeratePrefix lists the in-tree modules a relative static-prefix load can reach: every
// code file whose path, relative to the prefix's directory, starts with the prefix's last
// segment. It reports false when the set is not knowable: the directory is missing or
// outside the build, the walk is too large, or a match is a symlink, a node_modules
// directory, or a code file the parse did not include (a skipped build directory, an
// unsupported extension, a native addon).
func (rs *resolver) enumeratePrefix(fromModule, prefix string) ([]string, bool) {
	slash := strings.LastIndexByte(prefix, '/')
	dir := path.Join(moduleDir(fromModule), prefix[:slash])
	if dir == "." {
		dir = ""
	}
	if dir == ".." || strings.HasPrefix(dir, "../") {
		return nil, false
	}
	stem := prefix[slash+1:]
	absDir := filepath.Join(rs.prog.root, filepath.FromSlash(dir))
	if info, err := os.Stat(absDir); err != nil || !info.IsDir() {
		return nil, false
	}
	var mods []string
	seen := map[string]bool{}
	visited := 0
	err := filepath.WalkDir(absDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return errPrefixUnbounded
		}
		if p == absDir {
			return nil
		}
		visited++
		if visited > maxPrefixWalk {
			return errPrefixUnbounded
		}
		rel, rerr := filepath.Rel(absDir, p)
		if rerr != nil {
			return errPrefixUnbounded
		}
		rel = filepath.ToSlash(rel)
		if !strings.HasPrefix(rel, stem) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			return errPrefixUnbounded
		case d.IsDir():
			if d.Name() == "node_modules" {
				return errPrefixUnbounded
			}
			return nil
		case !d.Type().IsRegular():
			return errPrefixUnbounded
		}
		name := d.Name()
		if strings.HasSuffix(name, ".d.ts") || !prefixCodeExtensions[filepath.Ext(name)] {
			return nil
		}
		mod := moduleOf(rs.prog.root, p)
		if !rs.prog.moduleSet[mod] {
			return errPrefixUnbounded
		}
		if !seen[mod] {
			seen[mod] = true
			mods = append(mods, mod)
		}
		return nil
	})
	if err != nil || len(mods) == 0 {
		return nil, false
	}
	sort.Strings(mods)
	return mods, true
}

// moduleDir is the build-relative directory of a module id ("" for the build root).
func moduleDir(module string) string {
	d := path.Dir(module)
	if d == "." {
		return ""
	}
	return d
}
