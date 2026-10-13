package assembly

import (
	"encoding/json"
	"os"
	"path"
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
// only the fields needed to LOCATE a dependency's dlls:
//   - packageFolders: the ordered NuGet cache roots the restore actually used
//     (zero-egress-aware: a per-build/CI cache relocates the global folder and
//     this records where it truly landed). Searched first, in order.
//   - libraries[<id>/<ver>].path: the "<id-lowercased>/<version>" folder relative
//     to a packageFolder.
//   - targets[<target>][<id>/<ver>].runtime / .compile: keys are the
//     package-folder-relative .dll paths (e.g. "lib/net8.0/Foo.dll",
//     "ref/net8.0/Foo.dll"). runtime is preferred: it names the implementation
//     the app runs, while compile may name a reference assembly whose bodies are
//     stubs. compile is the fallback only when a package declares no runtime block.
//     The "_._" placeholder key means "no assembly here": a runtime block holding
//     only "_._" over a compile dll says the framework supplies the implementation,
//     so the package's lib bytes are not what runs (FrameworkSupplied).
//   - targets[<target>][<id>/<ver>].runtimeTargets: implementations under
//     runtimes/<rid>/lib/... that replace the runtime block on a matching runtime.
//     In a portable target (no RID in the key) their presence means the bytes that run
//     depend on the machine (RIDSpecific); a "<tfm>/<rid>" target records the asset
//     restore resolved for that runtime in its runtime block.
//
// The authoritative resolved path is: packageFolder / library.path / <dll-key>.
type AssetsLocator struct {
	packageFolders []string                       // ordered restore cache roots
	libPath        map[string]string              // "<id>/<ver>" -> "<id-lower>/<ver>"
	dlls           map[string]map[string][]string // target -> "<id>/<ver>" -> rel dlls (runtime, else compile); nil => only _._/none
	framework      map[string]map[string][]string // target -> "<id>/<ver>" whose runtime is "_._" over compile dlls -> those compile dlls
	ridSpecific    map[string]map[string]bool     // target -> "<id>/<ver>" with a runtimeTargets runtime asset
}

// assetsLocatorFile is the minimal unmarshal target. runtime/compile stay
// RawMessage so their keys can be read in their original JSON order (Go maps do
// not preserve it, and packageFolder/dll priority is order-sensitive).
type assetsLocatorFile struct {
	PackageFolders json.RawMessage `json:"packageFolders"`
	Libraries      map[string]struct {
		Path string `json:"path"`
	} `json:"libraries"`
	Targets map[string]map[string]struct {
		Runtime        json.RawMessage `json:"runtime"`
		Compile        json.RawMessage `json:"compile"`
		RuntimeTargets map[string]struct {
			AssetType string `json:"assetType"`
		} `json:"runtimeTargets"`
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
		dlls:           make(map[string]map[string][]string, len(af.Targets)),
		framework:      make(map[string]map[string][]string),
		ridSpecific:    make(map[string]map[string]bool),
	}
	for key, lib := range af.Libraries {
		if p := strings.TrimSpace(lib.Path); p != "" {
			a.libPath[key] = p
		}
	}
	for target, pkgs := range af.Targets {
		m := make(map[string][]string, len(pkgs))
		for pkgKey, tl := range pkgs {
			dlls := dllKeys(tl.Runtime)
			if len(dlls) == 0 {
				compile := dllKeys(tl.Compile)
				if len(orderedObjectKeys(tl.Runtime)) == 0 {
					dlls = compile
				} else if len(compile) > 0 {
					if a.framework[target] == nil {
						a.framework[target] = map[string][]string{}
					}
					a.framework[target][pkgKey] = compile
				}
			}
			m[pkgKey] = dlls
			for _, rt := range tl.RuntimeTargets {
				if strings.EqualFold(rt.AssetType, "runtime") {
					if a.ridSpecific[target] == nil {
						a.ridSpecific[target] = map[string]bool{}
					}
					a.ridSpecific[target][pkgKey] = true
					break
				}
			}
		}
		a.dlls[target] = m
	}
	return a, true
}

// dllKeys returns the .dll keys of a runtime/compile block in JSON order, skipping
// the "_._" placeholder and non-assembly assets (.xml docs, .pdb, native files).
func dllKeys(raw json.RawMessage) []string {
	var out []string
	for _, k := range orderedObjectKeys(raw) {
		if k == "_._" || !strings.EqualFold(filepath.Ext(k), ".dll") {
			continue
		}
		out = append(out, k)
	}
	return out
}

// FrameworkSupplied reports whether restore recorded this package in target with a
// runtime block of only "_._" over a compile dll: the shared framework supplies the
// implementation at run time, so neither the package's ref nor lib bytes are the code
// that runs.
func (a *AssetsLocator) FrameworkSupplied(target, pkgKey string) bool {
	return a != nil && len(a.framework[target][pkgKey]) > 0
}

// FrameworkCompileNames returns the assembly names (file names without ".dll") of the
// compile dlls a framework-supplied package declares in target: the assemblies the
// first-party build compiled against and the shared framework supplies at run time. nil
// when the package is not framework-supplied there.
func (a *AssetsLocator) FrameworkCompileNames(target, pkgKey string) []string {
	if a == nil {
		return nil
	}
	return assemblyNames(a.framework[target][pkgKey])
}

// PackageAssemblyNames returns the assembly names of every dll a package in target
// supplies itself (its runtime dlls, else its compile dlls). A framework-supplied
// package's names are not included: the framework, not the package, supplies those.
func (a *AssetsLocator) PackageAssemblyNames(target string) []string {
	if a == nil {
		return nil
	}
	var out []string
	for _, dlls := range a.dlls[target] {
		out = append(out, assemblyNames(dlls)...)
	}
	return out
}

func assemblyNames(dlls []string) []string {
	var out []string
	for _, d := range dlls {
		base := path.Base(d)
		out = append(out, base[:len(base)-len(path.Ext(base))])
	}
	return out
}

// RIDSpecific reports whether restore recorded, for this package in target, an
// implementation under runtimes/<rid>/ that replaces its runtime block on a matching
// runtime: which bytes run depends on the runtime the build was produced for.
func (a *AssetsLocator) RIDSpecific(target, pkgKey string) bool {
	return a != nil && a.ridSpecific[target][pkgKey]
}

// HasPackage reports whether restore recorded pkgKey in target.
func (a *AssetsLocator) HasPackage(target, pkgKey string) bool {
	if a == nil {
		return false
	}
	_, ok := a.dlls[target][pkgKey]
	return ok
}

// HasNoAssemblies reports whether restore recorded this package in target as
// carrying no assembly at all (no runtime or compile dll, only "_._" or nothing): a
// metapackage or a content/analyzer/build-only package. When no locator finds a dll
// for such a package either, it holds no code a call could land in, so the miss is
// not one. false when the target or package is not recorded (then nothing is known).
func (a *AssetsLocator) HasNoAssemblies(target, pkgKey string) bool {
	if a == nil {
		return false
	}
	tgt, ok := a.dlls[target]
	if !ok {
		return false
	}
	dlls, ok := tgt[pkgKey]
	return ok && len(dlls) == 0 && len(a.framework[target][pkgKey]) == 0
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

// LocateDlls resolves every dll a dependency contributes to target via the
// AUTHORITATIVE assets path: packageFolder / library.path / <dll-key>, statting
// each root in order. ok is true only when every recorded dll exists under some
// root; a package with a dll that cannot be found is a declared miss as a whole
// (a partially loaded package would make its missing half read as absent code).
// ok is also false when the library has no path or records no dll — never a fetch
// and never a path that escapes a root.
//
// target is the assets targets key ("net8.0" or "net8.0/linux-x64"); pkgKey is
// "<id>/<version>".
func (a *AssetsLocator) LocateDlls(roots []string, target, pkgKey string) ([]string, bool) {
	if a == nil {
		return nil, false
	}
	libRel, ok := a.libPath[pkgKey]
	if !ok || libRel == "" {
		return nil, false
	}
	rels := a.dlls[target][pkgKey]
	if len(rels) == 0 {
		return nil, false
	}
	out := make([]string, 0, len(rels))
	for _, rel := range rels {
		path, found := locateUnderRoots(roots, libRel, rel)
		if !found {
			return nil, false
		}
		out = append(out, path)
	}
	return out, true
}

// locateUnderRoots returns the first root under which libRel/rel is a regular file.
// libRel and rel come from the (restore-written) assets file; traversal is still
// guarded so a crafted relpath can never resolve outside a root.
func locateUnderRoots(roots []string, libRel, rel string) (string, bool) {
	for _, root := range roots {
		if root == "" {
			continue
		}
		candidate, ok := containedPath(root, libRel, rel)
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

// ResolveDependencyDlls locates a dependency's dlls, preferring the authoritative
// assets path, then the NuGet global cache, then the project build output — each a
// declared miss when absent, never a fetch. The two path-convention fallbacks can
// only name the package's eponymous dll. target is the assets targets key (also
// used as the cache tfm hint); pkgKey is "<id>/<version>". ok is false when no
// locator finds the files.
func ResolveDependencyDlls(buildDir, target, pkgKey string, a *AssetsLocator) ([]string, bool) {
	if a.FrameworkSupplied(target, pkgKey) {
		return nil, false
	}
	roots := NugetPackageRoots(buildDir, a)
	if paths, ok := a.LocateDlls(roots, target, pkgKey); ok {
		return paths, true
	}
	id, version := splitAssetsKey(pkgKey)
	tfmHint, _ := splitTarget(target)
	if path, ok := LocateNugetCacheDll(roots, id, version, tfmHint); ok {
		return []string{path}, true
	}
	if id != "" {
		if path, ok := LocateBuildOutput(buildDir, id); ok {
			return []string{path}, true
		}
	}
	return nil, false
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
