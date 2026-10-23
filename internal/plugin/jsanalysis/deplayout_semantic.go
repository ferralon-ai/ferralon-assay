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

// workspaceMembers returns the root-relative directories under root holding a package.json that
// patterns select (root itself excluded). A pattern may use "**" for any number of segments and a
// leading "!" to exclude. ok is false when a directory cannot be read, a directory symlink is
// met (the member it links may be selected, and its manifest is not walked), a manifest's name
// differs from package.json only in case, or a pattern or match is one the lane can't read as
// pnpm and yarn classic do (workspaceGlobReadable, workspaceSelects).
func workspaceMembers(root string, patterns []string) (members []string, ok bool) {
	if len(patterns) == 0 {
		return nil, true
	}
	if slices.ContainsFunc(patterns, func(p string) bool { return !workspaceGlobReadable(p) }) {
		return nil, false
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
		if !strings.EqualFold(d.Name(), "package.json") {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(p))
		if err != nil {
			ok = false
			return filepath.SkipAll
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		in, decided := workspaceSelects(patterns, rel)
		if !decided || in && d.Name() != "package.json" {
			ok = false
			return filepath.SkipAll
		}
		if in {
			members = append(members, rel)
		}
		return nil
	})
	slices.Sort(members)
	return members, ok
}

// workspaceGlobReadable reports whether the lane reads the workspace pattern p as pnpm
// (picomatch) and yarn classic (node-glob) do. Both expand braces and extglobs, read "[!a]" as a
// negated class and POSIX classes inside brackets, and accept members outside the root ("../x"),
// none of which globMatch models, so a pattern using any of them is refused rather than read
// narrower.
func workspaceGlobReadable(p string) bool {
	p = strings.TrimPrefix(p, "!")
	if p == "" || strings.ContainsAny(p, "{}()|\\[]") || strings.HasPrefix(p, "/") {
		return false
	}
	return !slices.Contains(strings.Split(p, "/"), "..")
}

// workspaceSelects reports whether the workspace globs select the root-relative directory rel,
// and whether that answer holds for pnpm and yarn classic on any filesystem. It does not hold
// when matching rel ignoring case gives another answer (both tools match case-insensitively on
// a case-insensitive filesystem), or when a wildcard matched a dot-named segment (neither
// tool's wildcards match one).
func workspaceSelects(patterns []string, rel string) (in, decided bool) {
	segs := strings.Split(rel, "/")
	folded := strings.Split(strings.ToLower(rel), "/")
	for _, p := range patterns {
		neg := strings.HasPrefix(p, "!")
		p = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(p, "!"), "./"), "/")
		pat := strings.Split(p, "/")
		exact := globMatch(pat, segs, false)
		if exact != globMatch(strings.Split(strings.ToLower(p), "/"), folded, false) ||
			exact != globMatch(pat, segs, true) {
			return false, false
		}
		if exact {
			in = !neg
		}
	}
	return in, true
}

// globMatch matches path segments against pattern segments; "**" matches any number of them.
// With noDot, a wildcard does not match a segment that starts with ".".
func globMatch(pat, segs []string, noDot bool) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(segs); i++ {
			if noDot && i > 0 && strings.HasPrefix(segs[i-1], ".") {
				return false
			}
			if globMatch(pat[1:], segs[i:], noDot) {
				return true
			}
		}
		return false
	}
	if len(segs) == 0 {
		return false
	}
	if noDot && strings.HasPrefix(segs[0], ".") && !strings.HasPrefix(pat[0], ".") {
		return false
	}
	ok, err := path.Match(pat[0], segs[0])
	return err == nil && ok && globMatch(pat[1:], segs[1:], noDot)
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
