package assembly

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// resolve.go — the dependency artifact-LOCATE + READ front (PLAN-350 barrier-3a).
// The whole-program graph needs a dependency's compiled .dll BYTES on disk so
// Read can parse its IL/metadata. This file's sole job is to LOCATE that file in
// the build's already-populated caches/output and READ its bytes. It NEVER
// restores, fetches, executes, or loads a system assembly: a dll not already
// present is a declared miss (ok=false) the CALLER (barrier-3b) turns into a
// completeness hazard — never a silent "this dependency has no code", never a
// fabricated empty assembly. This mirrors the contract of cobalt's Java depcache.
//
// project.assets.json is the AUTHORITATIVE locator (restore records exactly where
// each package landed via packageFolders + the per-target compile keys), so it is
// preferred over path convention. Two path-convention fallbacks follow, each a
// declared miss when absent, never a fetch: the NuGet global cache and the
// project's own build output.
//
// This is additive to the landed PLAN-150 resolver: it reads project.assets.json
// through its OWN minimal locator view (AssetsLocator), leaving inventory.go's
// assetsFile type untouched.

// AssetsLocator is resolve.go's local, additive view of project.assets.json —
// only the fields needed to LOCATE a dependency dll:
//   - packageFolders: the ordered NuGet cache roots the restore actually used
//     (zero-egress-aware: a per-build/CI cache relocates the global folder and
//     this records where it truly landed). Searched first, in order.
//   - libraries[<id>/<ver>].path: the "<id-lowercased>/<version>" folder relative
//     to a packageFolder.
//   - targets[<target>][<id>/<ver>].compile: keys are the package-folder-relative
//     .dll paths (e.g. "lib/net8.0/Foo.dll", "ref/net8.0/Foo.dll"). The "_._"
//     placeholder key means "no assembly" — treated as no locatable dll (a miss),
//     never an error. compile is the reference surface CHA reads.
//
// The authoritative resolved path is: packageFolder / library.path / <compile-key>.
type AssetsLocator struct {
	packageFolders []string                     // ordered restore cache roots
	libPath        map[string]string            // "<id>/<ver>" -> "<id-lower>/<ver>"
	compile        map[string]map[string]string // target -> "<id>/<ver>" -> chosen compile rel dll ("" => only _._/none)
}

// assetsLocatorFile is the minimal unmarshal target. compile stays RawMessage so
// its keys can be read in their original JSON order (Go maps do not preserve it,
// and packageFolder/compile priority is order-sensitive).
type assetsLocatorFile struct {
	PackageFolders json.RawMessage `json:"packageFolders"`
	Libraries      map[string]struct {
		Path string `json:"path"`
	} `json:"libraries"`
	Targets map[string]map[string]struct {
		Compile json.RawMessage `json:"compile"`
	} `json:"targets"`
}

// ParseAssetsLocator parses a project.assets.json into the locator view. ok is
// false only when the bytes are not valid JSON of the expected shape; an assets
// file that simply lacks packageFolders/compile parses fine (the locator then
// resolves nothing from it and the caller falls through to the path-convention
// fallbacks).
func ParseAssetsLocator(data []byte) (*AssetsLocator, bool) {
	var af assetsLocatorFile
	if err := json.Unmarshal(data, &af); err != nil {
		return nil, false
	}
	a := &AssetsLocator{
		packageFolders: orderedObjectKeys(af.PackageFolders),
		libPath:        make(map[string]string, len(af.Libraries)),
		compile:        make(map[string]map[string]string, len(af.Targets)),
	}
	for key, lib := range af.Libraries {
		if p := strings.TrimSpace(lib.Path); p != "" {
			a.libPath[key] = p
		}
	}
	for target, pkgs := range af.Targets {
		m := make(map[string]string, len(pkgs))
		for pkgKey, tl := range pkgs {
			m[pkgKey] = firstCompileDll(tl.Compile)
		}
		a.compile[target] = m
	}
	return a, true
}

// firstCompileDll returns the first non-"_._" compile key in JSON order, or "" when
// the compile block is absent, empty, or holds only the "_._" placeholder (meaning
// no locatable assembly for this library in this target).
func firstCompileDll(raw json.RawMessage) string {
	for _, k := range orderedObjectKeys(raw) {
		if k == "_._" {
			continue
		}
		return k
	}
	return ""
}

// NugetPackageRoots returns the package-cache roots to search, in priority order:
// the assets packageFolders first (the restore-recorded truth), then the single
// global cache — NUGET_PACKAGES when set, else ~/.nuget/packages. Non-existent
// roots are harmless (the locators simply find nothing in them). It never fetches.
func NugetPackageRoots(buildDir string, a *AssetsLocator) []string {
	var roots []string
	if a != nil {
		roots = append(roots, a.packageFolders...)
	}
	if env := strings.TrimSpace(os.Getenv("NUGET_PACKAGES")); env != "" {
		roots = append(roots, env)
	} else if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, ".nuget", "packages"))
	}
	return roots
}

// LocateDll resolves a dependency's dll via the AUTHORITATIVE assets path:
// packageFolder / library.path / <compile-key>, statting each root in order and
// returning the first existing file. ok is false when the library has no path, its
// compile is absent or only "_._", or the composed file exists under no root — a
// declared miss, never a fetch and never a path that escapes a root.
//
// target is the assets targets key ("net8.0" or "net8.0/linux-x64"); pkgKey is
// "<id>/<version>".
func (a *AssetsLocator) LocateDll(roots []string, target, pkgKey string) (string, bool) {
	if a == nil {
		return "", false
	}
	libRel, ok := a.libPath[pkgKey]
	if !ok || libRel == "" {
		return "", false
	}
	tgt, ok := a.compile[target]
	if !ok {
		return "", false
	}
	compileRel := tgt[pkgKey]
	if compileRel == "" { // absent or "_._": no locatable dll for this library.
		return "", false
	}
	for _, root := range roots {
		if root == "" {
			continue
		}
		// libRel and compileRel come from the (restore-written) assets file; still
		// guard traversal so a crafted relpath can never resolve outside the root.
		candidate, ok := containedPath(root, libRel, compileRel)
		if !ok {
			continue
		}
		if isFile(candidate) {
			return candidate, true
		}
	}
	return "", false
}

// LocateNugetCacheDll is the path-convention fallback for the NuGet global cache:
// <root>/<id-lowercased>/<version>/lib/<tfmHint>/<id>.dll, first existing hit wins.
// It never walks the cache guessing: without a tfmHint it cannot form the path and
// returns a miss. Malformed id/version (empty, or containing a path separator or
// "..") is rejected so a crafted id can never resolve outside a root.
func LocateNugetCacheDll(roots []string, id, version, tfmHint string) (string, bool) {
	if !validPathComponent(id) || !validPathComponent(version) || !validPathComponent(tfmHint) {
		return "", false
	}
	idLower := strings.ToLower(id)
	dll := id + ".dll"
	for _, root := range roots {
		if root == "" {
			continue
		}
		candidate, ok := containedPath(root, idLower, version, "lib", tfmHint, dll)
		if !ok {
			continue
		}
		if isFile(candidate) {
			return candidate, true
		}
	}
	return "", false
}

// LocateBuildOutput is the path-convention fallback for the project's own build
// output: a flat filename match for "<name>.dll" under <buildDir>/bin then
// <buildDir>/publish (bin's config/tfm nesting is walked; publish is flat).
// First lexical hit wins. name must be a plain component (no separators/"..").
func LocateBuildOutput(buildDir, name string) (string, bool) {
	if !validPathComponent(name) {
		return "", false
	}
	target := name + ".dll"
	for _, sub := range []string{"bin", "publish"} {
		root := filepath.Join(buildDir, sub)
		var found string
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil //nolint:nilerr // an unreadable subtree yields no match; keep walking.
			}
			if d.IsDir() {
				return nil
			}
			if d.Name() == target {
				found = path
				return filepath.SkipAll
			}
			return nil
		})
		if found != "" {
			return found, true
		}
	}
	return "", false
}

// ResolveDependencyDll locates one dependency's dll, preferring the authoritative
// assets path, then the NuGet global cache, then the project build output — each a
// declared miss when absent, never a fetch. target is the assets targets key (also
// used as the cache tfm hint); pkgKey is "<id>/<version>". ok is false when no
// locator finds the file.
func ResolveDependencyDll(buildDir, target, pkgKey string, a *AssetsLocator) (string, bool) {
	roots := NugetPackageRoots(buildDir, a)
	if path, ok := a.LocateDll(roots, target, pkgKey); ok {
		return path, true
	}
	id, version := splitAssetsKey(pkgKey)
	tfmHint, _ := splitTarget(target)
	if path, ok := LocateNugetCacheDll(roots, id, version, tfmHint); ok {
		return path, true
	}
	if id != "" {
		if path, ok := LocateBuildOutput(buildDir, id); ok {
			return path, true
		}
	}
	return "", false
}

// ReadAssembly reads a located dll's bytes and parses them into the typed model.
// It LOADS NOTHING into any runtime — Read parses bytes only. ok is false (never a
// panic) on a read error or a malformed PE/metadata; the caller records a
// completeness hazard. Use ReadResult directly for the degrade-not-fail batch path.
func ReadAssembly(path string) (*Assembly, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	a, err := Read(data)
	if err != nil {
		return nil, false
	}
	return a, true
}

// --- helpers -----------------------------------------------------------------

// containedPath joins parts under root and confirms the cleaned result stays within
// root, so a ".." component can never resolve to a sibling or ancestor. ok is false
// when the join escapes root.
func containedPath(root string, parts ...string) (string, bool) {
	cleanRoot := filepath.Clean(root)
	joined := filepath.Join(append([]string{cleanRoot}, parts...)...)
	if joined == cleanRoot {
		return joined, true
	}
	if strings.HasPrefix(joined, cleanRoot+string(filepath.Separator)) {
		return joined, true
	}
	return "", false
}

// validPathComponent reports whether s is safe to use as a single path segment:
// non-empty, no path separators, and no ".." — a defense-in-depth guard on inputs
// (dependency ids/versions) that feed convention-based path construction.
func validPathComponent(s string) bool {
	if s == "" {
		return false
	}
	if strings.ContainsRune(s, '/') || strings.ContainsRune(s, filepath.Separator) {
		return false
	}
	if s == "." || s == ".." || strings.Contains(s, "..") {
		return false
	}
	return true
}

// isFile reports whether path exists and is a regular file (not a directory).
func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// splitAssetsKey splits an assets "<id>/<version>" key (NuGet ids never contain
// '/'). A key without a '/' yields ("", "").
func splitAssetsKey(key string) (id, version string) {
	if i := strings.LastIndexByte(key, '/'); i >= 0 {
		return key[:i], key[i+1:]
	}
	return "", ""
}

// splitTarget splits an assets targets key into (tfm, rid): "net8.0" ->
// ("net8.0",""), "net8.0/linux-x64" -> ("net8.0","linux-x64").
func splitTarget(key string) (tfm, rid string) {
	if i := strings.IndexByte(key, '/'); i >= 0 {
		return key[:i], key[i+1:]
	}
	return key, ""
}

// orderedObjectKeys returns the keys of a JSON object in their original textual
// order (Go maps lose it, and packageFolder/compile priority is order-sensitive).
// A nil/absent, non-object, or malformed value yields no keys.
func orderedObjectKeys(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	tok, err := dec.Token()
	if err != nil {
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil
	}
	var keys []string
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil
		}
		key, ok := kt.(string)
		if !ok {
			return nil
		}
		keys = append(keys, key)
		if err := skipJSONValue(dec); err != nil {
			return nil
		}
	}
	return keys
}

// skipJSONValue consumes exactly one JSON value from dec (scalar or a balanced
// object/array), leaving the decoder positioned after it.
func skipJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok || (d != '{' && d != '[') {
		return nil // a scalar value is a single token.
	}
	depth := 1
	for depth > 0 {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if dd, ok := t.(json.Delim); ok {
			switch dd {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}
