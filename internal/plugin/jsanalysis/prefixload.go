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
)

// prefixSuffixMayTraverse records that the runtime part of a static-prefix specifier is
// unconstrained, so the prefix bounds where the load can land only up to path traversal.
// Node normalizes `..` segments in a specifier before resolving it: './plugins/' + n with
// n = '../node_modules/json5' loads json5. When the suffix comes from input, that is a
// path-traversal load, exactly where a refutation must not stand. So while this holds, a
// first-party prefix still gets real edges to the modules it names, but also keeps its
// run-wide computed limit. Narrowing it needs proof that a suffix cannot carry a '..'
// segment, which a lexical scan cannot give today.
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
// prefixFirstParty it returns the in-tree modules the load can reach. Any prefix that is
// not relative (a package, a builtin, an alias, an absolute path) is prefixUnbounded.
func (rs *resolver) classifyPrefixLoad(fromModule string, pl prefixLoad) (prefixLoadKind, []string) {
	if !isRelativeSpecifier(pl.prefix) {
		return prefixUnbounded, nil
	}
	if mods, ok := rs.enumeratePrefix(fromModule, pl.prefix); ok {
		return prefixFirstParty, mods
	}
	return prefixUnbounded, nil
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
