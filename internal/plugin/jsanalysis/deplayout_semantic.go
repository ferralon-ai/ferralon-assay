package jsanalysis

import (
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
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
//  4. any other (phantom) load may find any copy the region pins (one pnpm or yarn hoisted) or,
//     when none is hoisted where the requirer's walk passes, whatever Node's walk finds above the
//     region's root. Its candidates are the union of both: one candidate resolves to it, several
//     resolve to none, and the load site's limit targets every candidate. The walk above is
//     closed-world only over directories it has positive grounds for: a lock installs for them,
//     or nothing there can install into their node_modules. Any other directory on it, up to the
//     build root, leaves the layout incomplete (outerUnaccounted).
//
// The phantom rule over-approximates every hoist and linker setting: whatever copy the load runs
// is a candidate, so a load either gains an edge or is bounded by a limit, and is never silently
// resolved to the wrong copy. This rests on every directory the walk passes inside the region
// holding only copies the lock pins, so a virtual store or modules directory outside the region's
// node_modules leaves the layout incomplete.
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
	// workspaces are an npm region's workspace directories (build-relative): the lock installs
	// their manifests' dependencies.
	workspaces map[string]bool
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

// resolve answers a load of name from the build-relative directory dir inside r. decided is true
// when the lock fixes the answer: a declared edge, a name the requirer bundles (nil: the bundled
// copy is unread) or the requirer's own name. Otherwise the load is a phantom and copies lists
// every copy r pins of name. Whichever one pnpm or yarn made loadable, if any, is among them, but
// with none hoisted Node's walk climbs out of r, so the caller adds what the walk finds above it.
func (r *depRegion) resolve(dir, name string) (e *depEntry, copies []*depEntry, decided bool) {
	if ip := installPathOf(dir + "/_"); ip != "" {
		req := r.byPath[ip]
		if req == nil {
			return nil, nil, true
		}
		if t, ok := req.deps[name]; ok {
			return t, nil, true
		}
		if req.bundles[name] {
			return nil, nil, true
		}
		if installedName(req.path) == name {
			return req, nil, true
		}
	} else if imp := r.importerAt(dir); imp != nil {
		if t, ok := imp.deps[name]; ok {
			return t, nil, true
		}
	}
	return nil, r.copies[name], false
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

// workspaceSegment is a workspace pattern segment pnpm and yarn classic both read as itself:
// no glob syntax, and no leading "." (so neither "." nor "..").
var workspaceSegment = regexp.MustCompile(`^[A-Za-z0-9_@-][A-Za-z0-9._@-]*$`)

// workspacePatternShape splits a workspace pattern of a shape the lane reads exactly as pnpm and
// yarn classic do: a literal relative path ("packages/a"), or a literal prefix with one trailing
// "/*" ("packages/*"). ok is false for every other pattern: a "!" (yarn ignores it, pnpm
// excludes with it), "**", a "*" anywhere else, any other glob syntax, a leading "/" or "./",
// a "." or empty segment, or a node_modules or bower_components segment (yarn selects members
// there, pnpm skips them).
func workspacePatternShape(p string) (prefix string, star, ok bool) {
	prefix, star = strings.CutSuffix(p, "/*")
	for _, s := range strings.Split(prefix, "/") {
		if !workspaceSegment.MatchString(s) || strings.EqualFold(s, "node_modules") ||
			strings.EqualFold(s, "bower_components") {
			return "", false, false
		}
	}
	return prefix, star, true
}

// workspaceMembers returns the root-relative directories under root that the workspace patterns
// select (root excluded), with ok false unless that set is the one pnpm and yarn classic
// select. A selected directory is a member through a regular file named exactly package.json.
// ok is false for a pattern outside workspacePatternShape; a pattern path met in another case,
// through a symlink, or unreadable; and, among the directories a pattern may select, a symlink,
// a node_modules or bower_components entry, a dot-named directory holding a manifest (neither
// tool's "*" matches it, and the lane does not model that), or a manifest the lane does not
// read as the tool does (memberManifest).
func workspaceMembers(root string, patterns []string) (members []string, ok bool) {
	seen := map[string]bool{}
	for _, p := range patterns {
		prefix, star, ok := workspacePatternShape(p)
		if !ok {
			return nil, false
		}
		present, ok := exactPath(root, prefix)
		if !ok {
			return nil, false
		}
		if !present {
			continue
		}
		dirs := []string{prefix}
		if star {
			entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(prefix)))
			if err != nil {
				return nil, false
			}
			dirs = dirs[:0]
			for _, e := range entries {
				switch {
				case e.Type()&os.ModeSymlink != 0, strings.EqualFold(e.Name(), "node_modules"),
					strings.EqualFold(e.Name(), "bower_components"):
					return nil, false
				case !e.IsDir():
				case strings.HasPrefix(e.Name(), "."):
					if has, ok := memberManifest(filepath.Join(root, filepath.FromSlash(prefix), e.Name())); has || !ok {
						return nil, false
					}
				default:
					dirs = append(dirs, prefix+"/"+e.Name())
				}
			}
		}
		for _, d := range dirs {
			has, ok := memberManifest(filepath.Join(root, filepath.FromSlash(d)))
			if !ok {
				return nil, false
			}
			if has {
				seen[d] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(seen)), true
}

// exactPath reports whether the root-relative directory rel exists, with ok false when one of
// its segments exists only under another case (the tools match it on a case-insensitive
// filesystem), is a symlink, or cannot be read.
func exactPath(root, rel string) (present, ok bool) {
	dir := root
	for _, seg := range strings.Split(rel, "/") {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return false, false
		}
		i := slices.IndexFunc(entries, func(e os.DirEntry) bool { return strings.EqualFold(e.Name(), seg) })
		switch {
		case i < 0:
			return false, true
		case entries[i].Name() != seg || entries[i].Type()&os.ModeSymlink != 0:
			return false, false
		case !entries[i].IsDir():
			return false, true
		}
		dir = filepath.Join(dir, seg)
	}
	return true, true
}

// memberManifest reports whether dir holds a regular file named exactly package.json. ok is
// false when dir cannot be read, or holds a package.json that is not a regular file, a name
// differing from package.json only in case, or a pnpmAltManifests file in any case.
func memberManifest(dir string) (has, ok bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, false
	}
	for _, e := range entries {
		switch n := e.Name(); {
		case n == "package.json":
			if !e.Type().IsRegular() {
				return false, false
			}
			has = true
		case strings.EqualFold(n, "package.json"),
			slices.ContainsFunc(pnpmAltManifests, func(f string) bool { return strings.EqualFold(f, n) }):
			return false, false
		}
	}
	return has, true
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
