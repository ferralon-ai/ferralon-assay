package jsanalysis

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// depEntry is one package the lock installs, at its build-relative install directory
// ("node_modules/a/node_modules/b", or "web/node_modules/b" under a nested root).
type depEntry struct {
	path    string
	name    string
	version string
	purl    string
	digest  string
	// unreadable marks an entry whose code is never read: a link, git, file: or alias
	// install, or one the lock pins with no integrity.
	unreadable bool
	// lockInstallScript is the lock's own hasInstallScript flag (npm v2/v3), which keeps an
	// install script visible when the tarball is not read.
	lockInstallScript bool
	// scriptsUnknown marks an entry from a lock that does not record install scripts (npm v1,
	// pnpm, yarn classic): unread, it may run one.
	scriptsUnknown bool
	// deps are the entry's own lock edges by load name (pnpm and yarn classic only).
	deps map[string]*depEntry
	// bundles are the names the read tarball ships under its own node_modules.
	bundles map[string]bool
	// patched marks a pnpm entry the install patches: its tarball is verified for its manifest
	// facts, and its code, which is not what runs, is never read.
	patched bool
}

// depLayout is the install tree the selected lockfiles describe, keyed by install path. Node's
// resolution walk runs over it instead of over the disk.
type depLayout struct {
	// byPath holds the npm entries; each semantic region holds its own.
	byPath map[string]*depEntry
	// regions are the lock roots, npm (walked by path) and semantic (pnpm, yarn classic).
	regions []*depRegion
	// berry marks a yarn berry lock anywhere in the build: its install layout is not modeled.
	berry bool
	// incomplete marks a lockfile that could not be read or selected, or an install surface the
	// lane does not read (installSurfaces): the build may install a copy no lock read here places.
	incomplete bool
	// unplaced are the packages of a pnpm or yarn classic lock the lane could not place: never
	// read, and never found by lookup.
	unplaced []*depEntry
}

// entries returns every placed entry, npm and semantic, in install-path order.
func (l *depLayout) entries() []*depEntry {
	all := maps.Clone(l.byPath)
	for _, r := range l.regions {
		if r.semantic {
			maps.Copy(all, r.byPath)
		}
	}
	out := make([]*depEntry, 0, len(all))
	for _, p := range slices.Sorted(maps.Keys(all)) {
		out = append(out, all[p])
	}
	return out
}

// buildDepLayout reads every selected lockfile under buildDir into one layout: npm locks by
// install path, pnpm and yarn classic locks as semantic regions; yarn berry marks the layout. An
// install surface the versions op would not read, or a script that may install a package outside
// the locks read here, leaves the whole layout incomplete: neither names the packages it changes.
func buildDepLayout(ctx context.Context, buildDir string) *depLayout {
	l := &depLayout{byPath: map[string]*depEntry{}}
	if unread, _ := installSurfaces(ctx, buildDir, func() map[string]lockInfo { return parsedLocks(buildDir) }); unread {
		l.incomplete = true
	}
	roots, read := discoverProjectRoots(buildDir)
	if !read {
		l.incomplete = true
	}
	for _, root := range roots {
		sel, part := selectLockfile(root)
		if !part.Complete {
			if !hasOnlyReason(part.Reasons, plugin.PartialReasonNoManifest) {
				l.incomplete = true
			}
			continue
		}
		rel, err := filepath.Rel(buildDir, sel.root)
		if err != nil {
			l.incomplete = true
			continue
		}
		prefix := filepath.ToSlash(rel)
		if prefix == "." {
			prefix = ""
		}
		data, err := readRegular(sel.path)
		if err != nil {
			l.incomplete = true
			continue
		}
		switch sel.dialect {
		case "yarn":
			// Not isYarnBerry: yarn classic writes an npm: alias as "<alias>@npm:<name>@<range>", so only
			// the berry metadata block decides. A lock with neither it nor the v1 header is incomplete.
			if strings.Contains(string(data), "__metadata:") {
				l.berry = true
				continue
			}
			l.addYarnClassic(prefix, sel.root, sel.path, data)
		case "pnpm":
			l.addPnpm(prefix, sel.root, sel.path, data)
		case "npm":
			var lock npmLock
			if json.Unmarshal(data, &lock) != nil {
				l.incomplete = true
				continue
			}
			r := &depRegion{prefix: prefix, workspaces: map[string]bool{}}
			if len(lock.Packages) > 0 {
				l.addNpmV2(prefix, lock.Packages)
				for key := range lock.Packages {
					if key != "" && installedName(key) == "" {
						r.workspaces[path.Join(prefix, key)] = true
					}
				}
			} else {
				l.addNpmV1(prefix, "", lock.Dependencies)
			}
			l.regions = append(l.regions, r)
		}
	}
	if l.doubleClaimed() || l.outerUnaccounted(buildDir) {
		l.incomplete = true
	}
	return l
}

// outerUnaccounted reports a directory above a nested semantic region, up to the build root,
// that the walk out of the region cannot treat as empty. That walk takes a directory with no
// placed entry to hold no install, which holds only on positive grounds: a lock installs for the
// directory (installsFor), or nothing there can make a package manager install into its
// node_modules (inertDir). Discovery makes a root only where it finds a lock, so a lock-less
// manifest with dependencies or workspaces, or a workspace or package-manager config, may be
// installed with copies the lane never sees. The scan stops at the build root, where Node's walk
// does not: sound when the build directory is the checkout root.
func (l *depLayout) outerUnaccounted(buildDir string) bool {
	checked := map[string]bool{}
	for _, r := range l.regions {
		if !r.semantic || r.prefix == "" {
			continue
		}
		for a := relParent(r.prefix); ; a = relParent(a) {
			if !checked[a] {
				checked[a] = true
				if !l.installsFor(a) && !inertDir(buildDir, filepath.Join(buildDir, filepath.FromSlash(a))) {
					return true
				}
			}
			if a == "" {
				break
			}
		}
	}
	return false
}

// installConfigFiles are the files whose presence lets a package manager install into, or
// configure an install of, their directory without its package.json declaring anything: a
// workspace root, a lock, an rc file, a pnpmfile hook, a manifest pnpm reads in place of
// package.json (pnpmAltManifests), a binding.gyp (npm, pnpm and yarn run `node-gyp rebuild` for
// it at install when no install or preinstall script is set), or an install already on disk. A
// .npmrc is judged by its keys instead (outerNpmrcKeys). The install veto flags a pnpmfile on its
// own; it stays here so this judgment does not rest on the veto's name matching.
var installConfigFiles = append([]string{
	"pnpm-workspace.yaml", ".yarnrc", ".yarnrc.yml", ".pnpmfile.cjs", ".pnpmfile.mjs",
	"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "node_modules",
	"binding.gyp",
}, pnpmAltManifests...)

// pnpmAltManifests are the manifests pnpm installs from when a directory has no package.json.
// The lane reads neither, so a directory holding one is never judged by its package.json alone.
var pnpmAltManifests = []string{"package.yaml", "package.json5"}

// outerNpmrcKeys are the .npmrc settings an inert directory may set. Each chooses where packages
// are fetched from and how (registry, TLS, proxy, retries) or what an install prints, audits or
// saves; none adds a package, moves one between node_modules directories or loads code. A scoped
// registry (@scope:registry) and a key scoped to one registry's credentials (//host/:_authToken)
// pass too (npmrcSetsOnly). Hoist and linker settings, pnpmfile and global-pnpmfile, and any
// unknown key withhold, as does a file npmrcSetsOnly cannot read or parse.
var outerNpmrcKeys = map[string]bool{
	"registry": true, "always-auth": true, "strict-ssl": true, "ca": true, "cafile": true,
	"proxy": true, "https-proxy": true, "noproxy": true, "fetch-retries": true,
	"fetch-timeout": true, "fund": true, "audit": true, "loglevel": true, "progress": true,
	"update-notifier": true, "save-exact": true, "save-prefix": true,
}

// inertManifestKeys are the package.json keys that cannot make npm, yarn or pnpm install anything
// into the manifest's directory. Any other key, including workspaces and every dependency map
// (even an empty one, which is simpler than proving it empty), leaves the directory unaccounted.
var inertManifestKeys = map[string]bool{
	// Describe or publish the package.
	"name": true, "version": true, "private": true, "description": true, "license": true,
	"author": true, "contributors": true, "repository": true, "homepage": true, "bugs": true,
	"keywords": true, "files": true, "funding": true, "publishConfig": true,
	// Steer how the package itself loads, never what node_modules holds.
	"type": true, "main": true, "module": true, "types": true, "typings": true, "sideEffects": true,
	// Pick the tool or fail an install on a mismatch, never change the tree.
	"engines": true, "packageManager": true,
	// Admitted without an install hook (inertScripts).
	"scripts": true,
	// Exposed to scripts as npm_package_config_* environment, never read by an installer.
	"config": true,
	// Tool configuration read only by the named tool when it runs, never by a package manager.
	"prettier": true, "browserslist": true, "eslintConfig": true, "eslintIgnore": true,
	"stylelint": true, "jest": true, "babel": true, "lint-staged": true, "husky": true,
	"commitlint": true, "nyc": true, "c8": true, "ava": true, "mocha": true, "xo": true,
	"postcss": true, "remarkConfig": true, "size-limit": true, "release": true, "renovate": true,
}

// installHookScripts are the install hooks outside installHook's pre and post classes. prepare,
// prepublish, prepublishOnly and prepack fall in the pre class.
var installHookScripts = map[string]bool{"install": true, "dependencies": true}

// installHook reports whether a script name may run on an install. Rather than list each
// manager's hooks, any pre or post script, any manager-namespaced script (pnpm:devPreinstall) and
// the named install hooks count; prebuild and postbuild are lost to precision.
func installHook(name string) bool {
	return strings.HasPrefix(name, "pre") || strings.HasPrefix(name, "post") ||
		strings.Contains(name, ":") || installHookScripts[name]
}

// inertDir reports whether dir, a directory inside the build root buildDir, holds nothing that
// installs into its node_modules: no installConfigFiles entry in any case, a .npmrc that is
// absent or sets only outerNpmrcKeys, and a package.json that is absent or readable, parseable
// and made only of inertManifestKeys. A .npmrc or package.json named in another case is not
// judged; it withholds.
func inertDir(buildDir, dir string) bool {
	if found, err := entryFold(dir, installConfigFiles...); found || err != nil || !exactCase(dir, ".npmrc", "package.json") {
		return false
	}
	rc := filepath.Join(dir, ".npmrc")
	if _, err := os.Lstat(rc); !absent(err) && (err != nil || !npmrcSetsOnly(buildDir, rc, outerNpmrcKeys)) {
		return false
	}
	p := filepath.Join(dir, "package.json")
	if _, err := os.Lstat(p); absent(err) {
		return true
	}
	data, err := readRegular(p)
	if err != nil {
		return false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(data, &m) != nil || m == nil {
		return false
	}
	for k, v := range m {
		if !inertManifestKeys[k] || k == "scripts" && !inertScripts(v) {
			return false
		}
	}
	return true
}

// entryFold reports whether dir holds an entry named one of names, ignoring case. A build may
// run on a case-insensitive filesystem, where a package manager opening binding.gyp finds a
// Binding.gyp.
func entryFold(dir string, names ...string) (bool, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, e := range ents {
		if slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, e.Name()) }) {
			return true, nil
		}
	}
	return false, nil
}

// exactCase reports whether dir can be listed and holds no entry whose name differs from one of
// names only in case: a file the package manager reads on a case-insensitive filesystem that
// the lane, reading by exact name, might not judge the same way.
func exactCase(dir string, names ...string) bool {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if slices.ContainsFunc(names, func(n string) bool { return n != e.Name() && strings.EqualFold(n, e.Name()) }) {
			return false
		}
	}
	return true
}

// inertScripts reports whether a scripts value is an object with no install hook.
func inertScripts(v json.RawMessage) bool {
	var scripts map[string]json.RawMessage
	if json.Unmarshal(v, &scripts) != nil {
		return false
	}
	for k := range scripts {
		if installHook(k) {
			return false
		}
	}
	return true
}

// installsFor reports whether some lock installs the dependencies of the manifest in the
// build-relative directory dir: dir is a lock root, a semantic importer or an npm workspace.
func (l *depLayout) installsFor(dir string) bool {
	for _, r := range l.regions {
		if r.prefix == dir || r.workspaces[dir] {
			return true
		}
		for _, imp := range r.importers {
			if imp.dir == dir {
				return true
			}
		}
	}
	return false
}

// manifestDeclaresDeps reports whether the package.json at p declares any dependency, or exists
// and cannot be read or parsed.
func manifestDeclaresDeps(p string) bool {
	if _, err := os.Lstat(p); absent(err) {
		return false
	}
	var m invManifest
	data, err := readRegular(p)
	return err != nil || json.Unmarshal(data, &m) != nil ||
		len(m.Dependencies)+len(m.DevDependencies)+len(m.OptionalDependencies)+len(m.PeerDependencies) > 0
}

// relParent returns the build-relative parent of dir ("" for the build root).
func relParent(dir string) string {
	if dir = path.Dir(dir); dir == "." {
		return ""
	}
	return dir
}

// doubleClaimed reports a directory two locks both install for: an npm install path inside a
// semantic region, a semantic importer inside a deeper lock root, or a synthetic path an npm
// lock also names. Longest-prefix choice would silently drop one lock's account of it.
func (l *depLayout) doubleClaimed() bool {
	for p := range l.byPath {
		if r := l.regionAt(path.Dir(p)); r != nil && r.semantic {
			return true
		}
	}
	for _, r := range l.regions {
		if !r.semantic {
			continue
		}
		for _, imp := range r.importers {
			if l.regionAt(imp.dir) != r {
				return true
			}
		}
		for p := range r.byPath {
			if l.byPath[p] != nil {
				return true
			}
		}
	}
	return false
}

// addUnplaced records every package the pnpm or yarn classic lock at lockPath pins. The
// line-based readers decode an unrecognised file as zero entries, so a lock that pins nothing
// while a manifest it governs declares a dependency is not read.
func (l *depLayout) addUnplaced(lockPath, root string) {
	info, ok := parseLockfile(lockPath)
	if !ok || info.opaque || len(info.deps) == 0 && manifestsDeclareDeps(root) {
		l.incomplete = true
	}
	l.addUnplacedDeps(info.deps)
}

// addUnplacedDeps records each pinned dependency as an unread entry; one the lock does not
// identify by name and version leaves the layout incomplete.
func (l *depLayout) addUnplacedDeps(deps []plugin.ResolvedDependency) {
	for _, d := range deps {
		if d.Coordinate == "" || d.Version == "" {
			l.incomplete = true
			continue
		}
		l.unplaced = append(l.unplaced, &depEntry{
			name: d.Coordinate, version: d.Version, purl: makePURL(d.Coordinate, d.Version),
			unreadable: true, scriptsUnknown: true,
		})
	}
}

// manifestsDeclareDeps reports whether any package.json at or under root, outside node_modules
// and .git, declares a dependency. A workspace member may sit under any directory name (build/,
// vendor/), so nothing else is pruned. A directory symlink is not followed and counts as
// declaring: the member it links may declare dependencies the walk cannot see. A manifest that
// cannot be read or decoded counts as declaring.
func manifestsDeclareDeps(root string) bool {
	declares := false
	walkErr := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			declares = true
			return filepath.SkipAll
		}
		if d.IsDir() {
			if p != root && (d.Name() == "node_modules" || d.Name() == ".git") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			if fi, err := os.Stat(p); err == nil && fi.IsDir() {
				declares = true
				return filepath.SkipAll
			}
		}
		if d.Name() != "package.json" {
			return nil
		}
		if manifestDeclaresDeps(p) {
			declares = true
			return filepath.SkipAll
		}
		return nil
	})
	return declares || walkErr != nil
}

func hasOnlyReason(reasons []string, r string) bool {
	return len(reasons) == 1 && reasons[0] == r
}

func (l *depLayout) add(e *depEntry) {
	if _, dup := l.byPath[e.path]; !dup {
		l.byPath[e.path] = e
	}
}

// addNpmV2 adds the install paths of an npm v2/v3 packages map.
func (l *depLayout) addNpmV2(prefix string, pkgs map[string]npmLockPkg) {
	for key, pkg := range pkgs {
		name := installedName(key)
		if name == "" {
			continue
		}
		version := pkg.Version
		if pkg.Link {
			if target, ok := pkgs[pkg.Resolved]; ok && target.Version != "" {
				version = target.Version
			}
		}
		if version == "" {
			version = "0.0.0-local"
		}
		e := &depEntry{
			path:              path.Join(prefix, key),
			name:              name,
			version:           version,
			purl:              makePURL(name, version),
			digest:            mapIntegrity(pkg.Integrity),
			lockInstallScript: pkg.HasInstallScript,
		}
		e.unreadable = pkg.Link || e.digest == "" || isGitResolved(pkg.Resolved) ||
			strings.HasPrefix(pkg.Resolved, "file:") || strings.HasPrefix(pkg.Version, "file:") ||
			(pkg.Name != "" && pkg.Name != name)
		l.add(e)
	}
}

// addNpmV1 adds an npm v1 dependencies tree, nesting each level under its parent's
// node_modules.
func (l *depLayout) addNpmV1(prefix, parent string, deps map[string]npmLockDep) {
	for name, dep := range deps {
		if name == "" || dep.Version == "" {
			continue
		}
		key := "node_modules/" + name
		if parent != "" {
			key = parent + "/" + key
		}
		e := &depEntry{
			path:    path.Join(prefix, key),
			name:    name,
			version: dep.Version,
			purl:    makePURL(name, dep.Version),
			digest:  mapIntegrity(dep.Integrity),
			// A v1 lock does not record hasInstallScript.
			scriptsUnknown: true,
		}
		e.unreadable = e.digest == "" || isGitResolved(dep.Resolved) ||
			isGitResolved(dep.Version) ||
			strings.HasPrefix(dep.Version, "npm:") || strings.HasPrefix(dep.Version, "file:") ||
			strings.HasPrefix(dep.Version, "link:") || strings.HasPrefix(dep.Resolved, "file:")
		l.add(e)
		l.addNpmV1(prefix, key, dep.Dependencies)
	}
}

// installedName returns the package name an install path names: the segment(s) after its last
// node_modules/, or "" when the path is not under a node_modules directory.
func installedName(installPath string) string {
	const marker = "node_modules/"
	i := strings.LastIndex(installPath, marker)
	if i < 0 || (i > 0 && installPath[i-1] != '/') {
		return ""
	}
	name := installPath[i+len(marker):]
	if name == "" || strings.HasPrefix(name, ".") {
		return ""
	}
	return name
}

// lookup resolves package name loaded from the build-relative directory fromDir: the one copy
// Node's walk can find, or nil when it finds none or the layout leaves several candidates.
func (l *depLayout) lookup(fromDir, name string) *depEntry {
	e, _ := l.walk(fromDir, name)
	return e
}

// lookupCandidates returns the copies a load lookup leaves unresolved could run: empty when the
// walk finds no copy at all.
func (l *depLayout) lookupCandidates(fromDir, name string) []*depEntry {
	_, c := l.walk(fromDir, name)
	return c
}

// walk runs Node's node_modules walk for name from fromDir. Outside a semantic region each
// ancestor not itself named node_modules is probed for node_modules/<name>, up to the build root.
// Inside one the region answers a declared load from the lock's edges; a phantom's candidates are
// the region's copies of name plus whatever the walk finds above the region's root. It returns the
// single entry found, else nil and every candidate (none: no copy on the walk's path).
func (l *depLayout) walk(fromDir, name string) (*depEntry, []*depEntry) {
	if name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, `\:`) {
		return nil, nil
	}
	dir := fromDir
	if dir == "." {
		dir = ""
	}
	for {
		if r := l.regionAt(dir); r != nil && r.semantic {
			e, copies, decided := r.resolve(dir, name)
			if decided {
				return e, nil
			}
			cands := slices.Clone(copies)
			if r.prefix != "" {
				oe, outer := l.walk(relParent(r.prefix), name)
				if oe != nil {
					outer = []*depEntry{oe}
				}
				for _, c := range outer {
					if !slices.Contains(cands, c) {
						cands = append(cands, c)
					}
				}
			}
			if len(cands) == 1 {
				return cands[0], nil
			}
			return nil, cands
		}
		if path.Base(dir) != "node_modules" {
			if e := l.byPath[path.Join(dir, "node_modules", name)]; e != nil {
				return e, nil
			}
		}
		if dir == "" {
			return nil, nil
		}
		dir = relParent(dir)
	}
}

// Read caps for one package. A package over any of them stays unread.
const (
	maxTarballBytes  = 64 << 20
	maxUnpackedBytes = 256 << 20
	maxPackageFiles  = 20000
	maxSourceBytes   = 4 << 20
)

// errPackageUnread marks a tarball whose contents the lane will not use.
var errPackageUnread = errors.New("jsanalysis: dependency package unread")

// depPackage is one read package: its manifest, its source files and the facts its tarball
// carries.
type depPackage struct {
	entry    *depEntry
	manifest *pkgManifest
	sources  []depFile
	// files is every regular file in the package, package-relative.
	files         map[string]bool
	installScript bool
	native        bool
}

type depFile struct {
	rel string
	// module is the file's module id inside its package: the extension-stripped path for the
	// file a stem resolves to, the full path for a sibling Node can also load (a dual
	// package's .mjs beside its .js).
	module string
	data   []byte
}

// bytesHandle is an in-memory artifactcache.Handle: the bytes verified are the bytes parsed.
type bytesHandle struct{ *bytes.Reader }

func (bytesHandle) Path() string { return "" }
func (bytesHandle) Close() error { return nil }

// readDepPackage reads e's tarball from store into memory, verifies it against the lock's
// integrity and unpacks it from those same bytes.
func readDepPackage(
	ctx context.Context, store artifactcache.Store, e *depEntry,
) (*depPackage, error) {
	ref := artifactcache.Ref{PURL: e.purl, Digest: e.digest}
	h, err := store.Lookup(ctx, ref)
	if err != nil {
		return nil, err
	}
	data, err := readCapped(h, maxTarballBytes)
	_ = h.Close()
	if err != nil {
		return nil, err
	}
	if err := artifactcache.Verify(bytesHandle{bytes.NewReader(data)}, ref); err != nil {
		return nil, err
	}
	return unpackDepPackage(ctx, e, data)
}

func readCapped(h artifactcache.Handle, limit int64) ([]byte, error) {
	if h.Size() > limit {
		return nil, errPackageUnread
	}
	return io.ReadAll(io.NewSectionReader(h, 0, h.Size()))
}

// tarSlack is the tar framing (headers, padding, end blocks) admitted on top of
// maxUnpackedBytes when the decompressed stream is counted.
const tarSlack = (maxPackageFiles + 2) * 1024

// unpackDepPackage lists the tarball's regular files, keeping source text, and reads the
// manifest facts. Any entry path that could escape the package, or that the tarball holds twice
// (also as two names differing only in case, one file on a case-insensitive filesystem), fails
// the whole package: extraction keeps the last copy of a duplicate, and which copy the lane read
// would be a guess.
func unpackDepPackage(ctx context.Context, e *depEntry, tgz []byte) (*depPackage, error) {
	zr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return nil, errPackageUnread
	}
	tr := tar.NewReader(&cappedReader{ctx: ctx, r: zr, left: maxUnpackedBytes + tarSlack})
	pkg := &depPackage{entry: e, files: map[string]bool{}}
	folded := map[string]bool{}
	byStem := map[string][]depFile{}
	var manifest []byte
	var unpacked int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			return nil, errPackageUnread
		}
		rel, ok := packageRelative(hdr.Name)
		if !ok {
			return nil, errPackageUnread
		}
		if !hdr.FileInfo().Mode().IsRegular() || rel == "" {
			continue
		}
		if pkg.files[rel] || folded[strings.ToLower(rel)] || len(pkg.files) >= maxPackageFiles {
			return nil, errPackageUnread
		}
		pkg.files[rel] = true
		folded[strings.ToLower(rel)] = true
		unpacked += hdr.Size
		if unpacked > maxUnpackedBytes {
			return nil, errPackageUnread
		}
		if strings.HasPrefix(rel, "node_modules/") || strings.Contains(rel, "/node_modules/") {
			continue
		}
		keep := rel == "package.json" || depSourceFile(rel)
		if !keep {
			continue
		}
		if hdr.Size > maxSourceBytes {
			return nil, errPackageUnread
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxSourceBytes+1))
		if err != nil || int64(len(body)) > maxSourceBytes {
			return nil, errPackageUnread
		}
		if rel == "package.json" {
			manifest = body
			continue
		}
		stem := stripJSExt(rel)
		byStem[stem] = append(byStem[stem], depFile{rel: rel, data: body})
	}
	if manifest == nil {
		return nil, errPackageUnread
	}
	pkg.manifest = parsePkgManifest(manifest)
	if pkg.manifest == nil {
		return nil, errPackageUnread
	}
	pkg.installScript, pkg.native = manifestFacts(manifest, pkg.files)
	for _, stem := range slices.Sorted(maps.Keys(byStem)) {
		pkg.sources = append(pkg.sources, stemSources(stem, byStem[stem])...)
	}
	return pkg, nil
}

// stemSources orders the files sharing one extension-stripped id by sourceRank. The first is
// the module the stem resolves to; every other file Node itself can load (.js, .cjs, .mjs) is
// kept as its own module under its full path, so a dual package's other half is parsed too.
func stemSources(stem string, files []depFile) []depFile {
	slices.SortFunc(files, func(a, b depFile) int {
		return sourceRank(path.Ext(a.rel)) - sourceRank(path.Ext(b.rel))
	})
	out := []depFile{{rel: files[0].rel, module: stem, data: files[0].data}}
	for _, f := range files[1:] {
		switch path.Ext(f.rel) {
		case ".js", ".cjs", ".mjs":
			f.module = f.rel
			out = append(out, f)
		}
	}
	return out
}

// cappedReader reads r until left bytes are spent, then fails; it checks ctx before each read.
type cappedReader struct {
	ctx  context.Context
	r    io.Reader
	left int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	if c.left <= 0 {
		return 0, errPackageUnread
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// packageRelative strips a tarball entry's top directory ("package/" in an npm tarball) and
// reports false for a name that is absolute, uses backslashes or climbs out of the package.
func packageRelative(name string) (string, bool) {
	if strings.HasPrefix(name, "/") || strings.Contains(name, `\`) {
		return "", false
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return "", false
		}
	}
	name = strings.TrimPrefix(name, "./")
	_, rel, _ := strings.Cut(name, "/")
	return path.Clean("/" + rel)[1:], true
}

// depSourceFile reports whether rel is JS/TS source the lane parses; declaration files carry no
// code.
func depSourceFile(rel string) bool {
	for _, d := range []string{".d.ts", ".d.mts", ".d.cts"} {
		if strings.HasSuffix(rel, d) {
			return false
		}
	}
	return isSourceExt(path.Ext(rel))
}

// sourceRank orders the files sharing one extension-stripped module id: the first is parsed, so
// a package's emitted JS wins over the TypeScript it shipped beside it.
func sourceRank(ext string) int {
	switch ext {
	case ".js":
		return 0
	case ".cjs":
		return 1
	case ".mjs":
		return 2
	case ".jsx":
		return 3
	case ".ts":
		return 4
	case ".tsx":
		return 5
	}
	return 6
}

// nativeLoaders are the packages that locate and load a compiled addon.
var nativeLoaders = map[string]bool{
	"bindings": true, "node-gyp-build": true, "node-pre-gyp": true,
	"@mapbox/node-pre-gyp": true, "prebuild-install": true,
}

// manifestFacts reads the install-script and native-addon facts from a tarball manifest. npm
// runs `node-gyp rebuild` for a package with a binding.gyp and no install or preinstall script;
// the name is matched in any case, since the install may extract onto a case-insensitive
// filesystem.
func manifestFacts(manifest []byte, files map[string]bool) (installScript, native bool) {
	var m struct {
		Scripts      map[string]string `json:"scripts"`
		Dependencies map[string]string `json:"dependencies"`
	}
	_ = json.Unmarshal(manifest, &m)
	gyp := false
	for f := range files {
		gyp = gyp || strings.EqualFold(f, "binding.gyp")
	}
	for _, s := range []string{"preinstall", "install", "postinstall"} {
		if strings.TrimSpace(m.Scripts[s]) != "" {
			installScript = true
		}
	}
	if gyp && strings.TrimSpace(m.Scripts["install"]) == "" &&
		strings.TrimSpace(m.Scripts["preinstall"]) == "" {
		installScript = true
	}
	native = gyp
	for f := range files {
		if strings.HasSuffix(f, ".node") {
			native = true
		}
	}
	for d := range m.Dependencies {
		if nativeLoaders[d] {
			native = true
		}
	}
	return installScript, native
}
