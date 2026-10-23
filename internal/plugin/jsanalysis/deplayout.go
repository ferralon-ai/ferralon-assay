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
}

// depLayout is the install tree the selected lockfiles describe, keyed by install path. Node's
// resolution walk runs over it instead of over the disk.
type depLayout struct {
	byPath map[string]*depEntry
	// berry marks a yarn berry lock anywhere in the build: its install layout is not modeled.
	berry bool
	// incomplete marks a lockfile that could not be read or selected.
	incomplete bool
}

// entries returns the layout's entries in install-path order.
func (l *depLayout) entries() []*depEntry {
	out := make([]*depEntry, 0, len(l.byPath))
	for _, p := range slices.Sorted(maps.Keys(l.byPath)) {
		out = append(out, l.byPath[p])
	}
	return out
}

// buildDepLayout reads every selected npm lockfile under buildDir into one layout. yarn classic
// and pnpm locks contribute no entries; yarn berry marks the layout.
func buildDepLayout(buildDir string) *depLayout {
	l := &depLayout{byPath: map[string]*depEntry{}}
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
			if isYarnBerry(data) {
				l.berry = true
			}
		case "npm":
			var lock npmLock
			if json.Unmarshal(data, &lock) != nil {
				l.incomplete = true
				continue
			}
			if len(lock.Packages) > 0 {
				l.addNpmV2(prefix, lock.Packages)
			} else {
				l.addNpmV1(prefix, "", lock.Dependencies)
			}
		}
	}
	return l
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
		}
		e.unreadable = e.digest == "" || isGitResolved(dep.Resolved) || isGitResolved(dep.Version) ||
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

// lookup runs Node's node_modules walk for package name from the build-relative directory
// fromDir: each ancestor not itself named node_modules is probed for node_modules/<name>, up to
// the build root.
func (l *depLayout) lookup(fromDir, name string) *depEntry {
	if name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, `\:`) {
		return nil
	}
	dir := fromDir
	if dir == "." {
		dir = ""
	}
	for {
		if path.Base(dir) != "node_modules" {
			if e := l.byPath[path.Join(dir, "node_modules", name)]; e != nil {
				return e
			}
		}
		if dir == "" {
			return nil
		}
		dir = path.Dir(dir)
		if dir == "." {
			dir = ""
		}
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
	rel  string
	data []byte
}

// bytesHandle is an in-memory artifactcache.Handle: the bytes verified are the bytes parsed.
type bytesHandle struct{ *bytes.Reader }

func (bytesHandle) Path() string { return "" }
func (bytesHandle) Close() error { return nil }

// readDepPackage reads e's tarball from store into memory, verifies it against the lock's
// integrity and unpacks it from those same bytes.
func readDepPackage(ctx context.Context, store artifactcache.Store, e *depEntry) (*depPackage, error) {
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

// unpackDepPackage lists the tarball's regular files, keeping source text, and reads the
// manifest facts. Any entry path that could escape the package fails the whole package.
func unpackDepPackage(ctx context.Context, e *depEntry, tgz []byte) (*depPackage, error) {
	zr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return nil, errPackageUnread
	}
	tr := tar.NewReader(zr)
	pkg := &depPackage{entry: e, files: map[string]bool{}}
	byStem := map[string]depFile{}
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
			return nil, errPackageUnread
		}
		rel, ok := packageRelative(hdr.Name)
		if !ok {
			return nil, errPackageUnread
		}
		if !hdr.FileInfo().Mode().IsRegular() || rel == "" {
			continue
		}
		if len(pkg.files) >= maxPackageFiles {
			return nil, errPackageUnread
		}
		pkg.files[rel] = true
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
		if prev, ok := byStem[stem]; ok && sourceRank(path.Ext(prev.rel)) <= sourceRank(path.Ext(rel)) {
			continue
		}
		byStem[stem] = depFile{rel: rel, data: body}
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
		pkg.sources = append(pkg.sources, byStem[stem])
	}
	return pkg, nil
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
// runs `node-gyp rebuild` for a package with a binding.gyp and no install or preinstall script.
func manifestFacts(manifest []byte, files map[string]bool) (installScript, native bool) {
	var m struct {
		Scripts      map[string]string `json:"scripts"`
		Dependencies map[string]string `json:"dependencies"`
	}
	_ = json.Unmarshal(manifest, &m)
	gyp := files["binding.gyp"]
	for _, s := range []string{"preinstall", "install", "postinstall"} {
		if strings.TrimSpace(m.Scripts[s]) != "" {
			installScript = true
		}
	}
	if gyp && strings.TrimSpace(m.Scripts["install"]) == "" && strings.TrimSpace(m.Scripts["preinstall"]) == "" {
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
