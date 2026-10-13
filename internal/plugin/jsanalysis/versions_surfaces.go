package jsanalysis

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// --- install surfaces ------------------------------------------------------------
//
// Version resolution reads the lockfiles lockFiles discovers, and the package.json files
// packageManifests discovers. Every other file under the build dir that names or holds a
// JavaScript install surface, found by the shared walk (buildtree.Candidates, which enters
// everything but node_modules and site-packages, .git included), vetoes the pin. A
// package.json the walker discovers but that does not decode vetoes too. Classification is by
// name, case-insensitively, or by content, so a surface this lane has no reader for (bun,
// deno, a pnpmfile, a copy under .yarn or .pnpm-store, a lock in a directory lockFiles skips)
// vetoes by default instead of being listed one name at a time.

// unreadSurfaces reports whether any install surface under root goes unread; locks is what
// lockFiles(root) returned.
func unreadSurfaces(root string, locks []string) bool {
	read := make(map[string]bool, len(locks))
	for _, l := range locks {
		read[l] = true
	}
	for _, m := range packageManifests(root) {
		if _, ok := readManifest(m); ok {
			read[m] = true
		}
	}
	for _, c := range buildtree.Candidates(root, npmInstallSurface, func(path string) bool { return read[path] }) {
		if !c.FullyRead {
			return true
		}
	}
	return false
}

// npmSurfaceNames are the lowercased manifests and lockfiles npm, yarn, pnpm, bun, deno and
// bower read, other than the *.lock and *.lockb names npmSurfaceName matches as a class (yarn,
// bun, deno).
var npmSurfaceNames = map[string]bool{
	"package.json": true, "package-lock.json": true, "npm-shrinkwrap.json": true,
	"pnpm-lock.yaml": true, "pnpm-lock.yml": true, "deno.json": true, "deno.jsonc": true,
	"bower.json": true, "import_map.json": true,
}

// npmForeignLocks are lowercased *.lock and *.lockb names other ecosystems own; every other
// one is a JavaScript install surface. Python's rye writes requirements*.lock, matched apart.
var npmForeignLocks = map[string]bool{
	"uv.lock": true, "poetry.lock": true, "pdm.lock": true, "pipfile.lock": true, "pixi.lock": true,
	"cargo.lock": true, "gemfile.lock": true, "composer.lock": true, "flake.lock": true,
	"podfile.lock": true, "mix.lock": true, "pubspec.lock": true, "conan.lock": true,
	"paket.lock": true, "packages.lock": true, "shard.lock": true, "renv.lock": true,
	"elm.lock": true, "esy.lock": true,
}

// npmDocExts are formats no JavaScript installer reads its configuration from.
var npmDocExts = map[string]bool{
	".md": true, ".markdown": true, ".rst": true, ".adoc": true, ".html": true, ".htm": true,
	".txt": true, ".ipynb": true,
}

// npmRewriteWords are the settings through which .npmrc, .yarnrc* and pnpm-workspace.yaml add
// or swap packages at install time.
var npmRewriteWords = []string{"packageExtensions", "overrides", "resolutions", "pnpmfile"}

// npmInstallSurface reports whether the file at path, with its buildtree.Head (nil when binary,
// empty or not a regular file, and then judged through buildtree.NULHeadMatch), names or holds
// a JavaScript install surface, and the rule that matched. Every file ManifestCandidates
// classifies (jsCandidate) is one too.
func npmInstallSurface(path string, head []byte) (string, bool) {
	if why, ok := npmSurface(path, head); ok {
		return why, true
	}
	return jsCandidate(path, head)
}

func npmSurface(path string, head []byte) (string, bool) {
	if why, ok := npmSurfaceName(path); ok {
		return why, true
	}
	lower := strings.ToLower(filepath.Base(path))
	if strings.HasPrefix(lower, ".yarnrc") || strings.HasPrefix(lower, ".npmrc") || strings.HasPrefix(lower, "pnpm-workspace.") {
		for _, w := range npmRewriteWords {
			if bytes.Contains(head, []byte(w)) {
				return "install rewrite config", true
			}
		}
		return "", false
	}
	return npmSurfaceContent(path, head)
}

func npmSurfaceName(path string) (string, bool) {
	if inner, ok := buildtree.TemplateInner(path); ok {
		if why, ok := npmSurfaceName(inner); ok {
			return "templated " + why, true
		}
	}
	lower := strings.ToLower(filepath.Base(path))
	ext := filepath.Ext(lower)
	switch {
	case npmSurfaceNames[lower]:
		return "manifest name", true
	case strings.Contains(lower, "pnpmfile") && !npmDocExts[ext]:
		return "pnpm install hook", true
	case (ext == ".lock" || ext == ".lockb") && !npmForeignLocks[lower] &&
		!strings.Contains(lower, "requirement") && !strings.Contains(lower, "constraint"):
		return "lockfile name", true
	}
	return "", false
}

var (
	npmJSONDepsRE = regexp.MustCompile(`"(dependencies|devDependencies|peerDependencies|optionalDependencies)"\s*:\s*\{\s*("[^"]*"\s*:\s*"|\})`)
	npmJSONLockRE = regexp.MustCompile(`"lockfileVersion"\s*:`)
)

// npmSurfaceContent matches a JSON head with a dependency map of string specs or a
// lockfileVersion key, a yarn lockfile, and a pnpm lockfile, whatever the file is called. A
// JSON head with a string name and version under .yarn or .pnpm-store is a cached package
// copy.
func npmSurfaceContent(path string, head []byte) (string, bool) {
	if npmDocExts[strings.ToLower(filepath.Ext(path))] {
		return "", false
	}
	if head == nil {
		return buildtree.NULHeadMatch(path, npmSurfaceContent)
	}
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(head, []byte("\xef\xbb\xbf")), " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '{' {
		switch {
		case npmJSONLockRE.Match(trimmed):
			return "lockfile content", true
		case npmJSONDepsRE.Match(trimmed):
			return "package manifest content", true
		case underPackageCache(path) && namesPackage(trimmed):
			return "cached package copy", true
		}
		return "", false
	}
	src := string(head)
	if strings.Contains(src, "# yarn lockfile v1") {
		return "yarn lock content", true
	}
	top := map[string]bool{}
	for _, l := range strings.Split(src, "\n") {
		if k, _, ok := strings.Cut(strings.TrimRight(l, "\r"), ":"); ok && k != "" && k == strings.TrimSpace(k) {
			top[k] = true
		}
	}
	switch {
	case top["__metadata"]:
		return "yarn lock content", true
	case top["lockfileVersion"] && (top["importers"] || top["packages"] || top["specifiers"] || top["dependencies"]):
		return "pnpm lock content", true
	}
	return "", false
}

// underPackageCache reports whether path lies under a .yarn or .pnpm-store directory, where
// yarn and pnpm keep package copies.
func underPackageCache(path string) bool {
	for _, seg := range strings.Split(filepath.ToSlash(path), "/") {
		if s := strings.ToLower(seg); s == ".yarn" || s == ".pnpm-store" {
			return true
		}
	}
	return false
}

// namesPackage reports whether a JSON head carries a string "name" and "version".
func namesPackage(head []byte) bool {
	var p struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	return json.Unmarshal(head, &p) == nil && p.Name != "" && p.Version != ""
}

// --- installed copies -------------------------------------------------------------

// installedCopies reads every package installed in a node_modules directory under root, which
// the shared walk does not enter, laid out the way npm, yarn and pnpm install: each package
// directory (scoped ones under their @scope), its own nested node_modules, and pnpm's
// .pnpm/<id>/node_modules. Each copy is its package.json name at its version, or UNRESOLVED
// when it names no version. A directory or package.json that is there but cannot be read
// makes ok false. A symlink wherever this reads one (a node_modules, a package or @scope entry,
// a .pnpm/<id>) is followed when it resolves inside root, whatever its target is named, and
// makes ok false when it leaves root or does not resolve (an npm link). Each directory is read
// once as a package and once as a node_modules, at its real path: a link can make one directory
// both, and each role reads different copies from it.
func installedCopies(root string) (copies []plugin.ResolvedDependency, ok bool) {
	ok = true
	realRoot, rootErr := filepath.EvalSymlinks(root)
	escapes := func(path string) bool { return rootErr != nil || !buildtree.Inside(realRoot, path) }
	// realDir reports whether path is a directory, following a symlink that resolves inside
	// root. read is false when the path is there but cannot be read, or is a symlink that
	// escapes or does not resolve.
	realDir := func(path string) (dir, read bool) {
		info, err := os.Lstat(path)
		switch {
		case err != nil:
			return false, absent(err)
		case info.Mode()&fs.ModeSymlink != 0:
			if escapes(path) {
				return false, false
			}
			if info, err = os.Stat(path); err != nil {
				return false, absent(err)
			}
		}
		return info.IsDir(), true
	}
	// once reports whether path's real path is seen for the first time in the role whose set
	// is seen. A path that does not resolve makes ok false.
	pkgSeen, nmSeen := map[string]bool{}, map[string]bool{}
	once := func(seen map[string]bool, path string) bool {
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			ok = false
			return false
		}
		if seen[real] {
			return false
		}
		seen[real] = true
		return true
	}
	// entryDir reports whether the directory entry e of dir is a directory to read, following
	// a symlink as realDir does and making ok false where realDir cannot read it.
	entryDir := func(dir string, e fs.DirEntry) bool {
		if e.Type()&fs.ModeSymlink == 0 {
			return e.IsDir()
		}
		d, read := realDir(filepath.Join(dir, e.Name()))
		if !read {
			ok = false
		}
		return d
	}
	var readDir func(dir string)
	readNodeModules := func(nm string) {
		switch d, read := realDir(nm); {
		case !read:
			ok = false
		case d:
			readDir(nm)
		}
	}
	readPkg := func(dir string) {
		if !once(pkgSeen, dir) {
			return
		}
		data, err := readRegular(filepath.Join(dir, "package.json"))
		switch {
		case err == nil:
			var p struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}
			if json.Unmarshal(data, &p) != nil {
				ok = false
				return
			}
			name := p.Name
			if name == "" {
				name = filepath.Base(dir)
				if scope := filepath.Base(filepath.Dir(dir)); strings.HasPrefix(scope, "@") {
					name = scope + "/" + name
				}
			}
			copies = append(copies, npmResolved(name, p.Version))
		case !absent(err):
			ok = false
			return
		}
		readNodeModules(filepath.Join(dir, "node_modules"))
	}
	readDir = func(dir string) {
		if !once(nmSeen, dir) {
			return
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			ok = false
			return
		}
		for _, e := range ents {
			p := filepath.Join(dir, e.Name())
			if e.Name() == ".bin" || !entryDir(dir, e) {
				continue
			}
			switch {
			case e.Name() == ".pnpm":
				ids, err := os.ReadDir(p)
				if err != nil {
					ok = false
					continue
				}
				for _, id := range ids {
					if entryDir(p, id) {
						readNodeModules(filepath.Join(p, id.Name(), "node_modules"))
					}
				}
			case strings.HasPrefix(e.Name(), "@"):
				pkgs, err := os.ReadDir(p)
				if err != nil {
					ok = false
					continue
				}
				for _, s := range pkgs {
					if entryDir(p, s) {
						readPkg(filepath.Join(p, s.Name()))
					}
				}
			case strings.HasPrefix(e.Name(), "."): // .cache and installer state hold no packages
			default:
				readPkg(p)
			}
		}
	}
	_ = buildtree.Walk(root, func(e buildtree.Entry, err error) error {
		switch {
		case err != nil:
			if !absent(err) {
				ok = false
			}
		case e.D.Name() == "node_modules" && (e.Skipped || e.Symlink):
			readNodeModules(e.Path)
		}
		return nil
	})
	return copies, ok
}
