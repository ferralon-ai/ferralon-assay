package jsanalysis

import (
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// A semantic region is the tree under a pnpm or yarn classic lock root. Neither lock records a
// physical install layout the lane can trust: yarn classic hoists at install time, and pnpm's
// hoist and linker settings decide what its symlinked store exposes. Inside such a region
// lookup does not walk paths. It answers from the lock's edges:
//
//  1. a declared load (the requirer's own lock edge) resolves to that edge's target, which every
//     linker guarantees;
//  2. a load of a name the requirer's tarball bundles (node_modules/<name>/ inside it) resolves to
//     nothing: the bundled copy is unread;
//  3. a package loading its own name resolves to itself;
//  4. any other (phantom) load resolves to the one copy the region pins, or, with several, to
//     none of them: the load site's limit, bounded by the name, covers whichever copy runs.
//
// The phantom rule over-approximates every hoist setting: a load that pnpm or yarn did not in
// fact make loadable gains an edge it would not have at run time, and never loses one.
//
// Placed entries carry synthetic install paths (<root>/node_modules/.pnpm/<key>/node_modules/
// <name>, <root>/node_modules/.yarn-classic/<name>@<version>/node_modules/<name>). They are
// module ids only: tarballs come from the store, and nothing stats, reads or walks a synthetic
// path, so a directory of the same name an earlier install left on disk is never consulted.
type depRegion struct {
	// prefix is the build-relative lock root ("" for the build root).
	prefix string
	// semantic marks a pnpm or yarn classic region; an npm region keeps the physical walk.
	semantic bool
	// importers are the first-party projects the lock installs for, longest directory first.
	importers []*depImporter
	// copies lists every placed entry by each name it can be loaded under.
	copies map[string][]*depEntry
	// byPath holds the region's placed entries by synthetic install path.
	byPath map[string]*depEntry
}

// depImporter is one first-party project of a semantic region: its build-relative directory and
// the entries its manifest's declared dependencies resolve to.
type depImporter struct {
	dir  string
	deps map[string]*depEntry
}

func newDepRegion(prefix string) *depRegion {
	return &depRegion{prefix: prefix, semantic: true, copies: map[string][]*depEntry{}, byPath: map[string]*depEntry{}}
}

// place records e at its synthetic install path, loadable under its own name.
func (r *depRegion) place(e *depEntry) {
	r.byPath[e.path] = e
	r.addCopy(e.name, e)
}

// addCopy records that e can be loaded under name.
func (r *depRegion) addCopy(name string, e *depEntry) {
	if !slices.Contains(r.copies[name], e) {
		r.copies[name] = append(r.copies[name], e)
	}
}

// addImporter records a first-party project at the build-relative directory dir.
func (r *depRegion) addImporter(dir string, deps map[string]*depEntry) {
	r.importers = append(r.importers, &depImporter{dir: dir, deps: deps})
	slices.SortStableFunc(r.importers, func(a, b *depImporter) int { return len(b.dir) - len(a.dir) })
}

// syntheticPath returns a unique install path for an entry placed under store ("pnpm" or
// "yarn-classic") with directory key key, or "" when key or name cannot form one; the caller then
// keys it by index.
func (r *depRegion) syntheticPath(store, key, name string) string {
	key = strings.ReplaceAll(key, "/", "+")
	if !safeSegment(key) || !safeLoadName(name) {
		return ""
	}
	return path.Join(r.prefix, "node_modules", "."+store, key, "node_modules", name)
}

// uniquePath returns syntheticPath, or an index-keyed path when that is unusable or taken.
func (r *depRegion) uniquePath(store, key, name string) string {
	if p := r.syntheticPath(store, key, name); p != "" && r.byPath[p] == nil {
		return p
	}
	for i := len(r.byPath); ; i++ {
		if p := r.syntheticPath(store, "~"+strconv.Itoa(i), name); r.byPath[p] == nil {
			return p
		}
	}
}

// safeSegment reports whether s is one path segment the walk and installPathOf cannot misread.
func safeSegment(s string) bool {
	return s != "" && !strings.HasPrefix(s, ".") && s != "node_modules" &&
		!strings.ContainsAny(s, `/\:`) && !strings.Contains(s, "..")
}

// safeLoadName reports whether name is an npm package name a synthetic path can end in, so that
// installPathOf and installedName read it back unchanged.
func safeLoadName(name string) bool {
	if name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, `\:`) || strings.HasPrefix(name, ".") {
		return false
	}
	scope, rest, scoped := strings.Cut(name, "/")
	if !scoped {
		return name != "node_modules"
	}
	return strings.HasPrefix(scope, "@") && len(scope) > 1 && safeSegment(rest) && !strings.Contains(rest, "/")
}

// within reports whether the build-relative dir is prefix or lies under it.
func within(dir, prefix string) bool {
	return prefix == "" || dir == prefix || strings.HasPrefix(dir, prefix+"/")
}

// regionAt returns the region whose root is the longest prefix of dir, or nil.
func (l *depLayout) regionAt(dir string) *depRegion {
	var best *depRegion
	for _, r := range l.regions {
		if within(dir, r.prefix) && (best == nil || len(r.prefix) > len(best.prefix)) {
			best = r
		}
	}
	return best
}

// resolve answers a load of name from the build-relative directory dir inside r. found is false
// only for a phantom load of a name r pins no copy of: Node's walk then continues above r.
func (r *depRegion) resolve(dir, name string) (e *depEntry, found bool) {
	if ip := installPathOf(dir + "/_"); ip != "" {
		req := r.byPath[ip]
		if req == nil {
			return nil, true
		}
		if t, ok := req.deps[name]; ok {
			return t, true
		}
		if req.bundles[name] {
			return nil, true
		}
		if installedName(req.path) == name {
			return req, true
		}
	} else if imp := r.importerAt(dir); imp != nil {
		if t, ok := imp.deps[name]; ok {
			return t, true
		}
	}
	switch c := r.copies[name]; len(c) {
	case 0:
		return nil, false
	case 1:
		return c[0], true
	default:
		return nil, true
	}
}

// importerAt returns the importer whose directory is the longest prefix of dir.
func (r *depRegion) importerAt(dir string) *depImporter {
	for _, imp := range r.importers {
		if within(dir, imp.dir) {
			return imp
		}
	}
	return nil
}

// workspaceMembers returns the root-relative directories under root holding a package.json that
// patterns select (root itself excluded). A pattern may use "**" for any number of segments and a
// leading "!" to exclude. ok is false when a directory cannot be read or a directory symlink is
// met: the member it links may be selected, and its manifest is not walked.
func workspaceMembers(root string, patterns []string) (members []string, ok bool) {
	if len(patterns) == 0 {
		return nil, true
	}
	ok = true
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			ok = false
			return filepath.SkipAll
		}
		if d.IsDir() {
			if p != root && (d.Name() == "node_modules" || d.Name() == ".git") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			if fi, err := os.Stat(p); err != nil || fi.IsDir() {
				ok = false
				return filepath.SkipAll
			}
		}
		if d.Name() != "package.json" {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(p))
		if err != nil {
			ok = false
			return filepath.SkipAll
		}
		rel = filepath.ToSlash(rel)
		if rel != "." && workspaceSelects(patterns, rel) {
			members = append(members, rel)
		}
		return nil
	})
	slices.Sort(members)
	return members, ok
}

// workspaceSelects reports whether the workspace globs select the root-relative directory rel.
func workspaceSelects(patterns []string, rel string) bool {
	in := false
	for _, p := range patterns {
		neg := strings.HasPrefix(p, "!")
		p = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(p, "!"), "./"), "/")
		if globMatch(strings.Split(p, "/"), strings.Split(rel, "/")) {
			in = !neg
		}
	}
	return in
}

// globMatch matches path segments against pattern segments; "**" matches any number of them.
func globMatch(pat, segs []string) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(segs); i++ {
			if globMatch(pat[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	if len(segs) == 0 {
		return false
	}
	ok, err := path.Match(pat[0], segs[0])
	return err == nil && ok && globMatch(pat[1:], segs[1:])
}

// readOptional reads the regular file at p. A file that is not there is (nil, true); one there
// that cannot be read is (nil, false).
func readOptional(p string) ([]byte, bool) {
	data, err := readRegular(p)
	switch {
	case err == nil:
		return data, true
	case absent(err):
		if _, lerr := os.Lstat(p); lerr == nil {
			return nil, false // a dangling symlink names a file the lane cannot see
		}
		return nil, true
	}
	return nil, false
}

// joinRel joins a build-relative prefix and a root-relative directory, keeping the build root
// as "".
func joinRel(prefix, dir string) string {
	if p := path.Join(prefix, dir); p != "." {
		return p
	}
	return ""
}
