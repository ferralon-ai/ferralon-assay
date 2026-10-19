package assembly

import (
	"os"
	"path/filepath"
	"testing"
)

// resolve_test.go — the LOCATE + READ contract. Fixtures are a HAND-LAID fake
// on-disk cache layout in t.TempDir(); nothing here restores, fetches, execs, or
// loads a system assembly. The dll bytes need not be a valid PE for the locator
// tests (the locator returns a path and reads bytes; parsing is Read's concern,
// exercised separately in the ReadAssembly test over the real synthesized PE).

// writeDll writes a few placeholder bytes at <root>/<parts...>, creating parents.
func writeDll(t *testing.T, root string, parts ...string) string {
	t.Helper()
	p := filepath.Join(append([]string{root}, parts...)...)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte("MZ\x00\x00not-a-real-pe"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

// assetsJSON renders a minimal project.assets.json with one packageFolders block,
// one library path, and one target compile map.
func assetsJSON(folders []string, libKey, libPath, target, compileDll string) []byte {
	pf := ""
	for i, f := range folders {
		if i > 0 {
			pf += ",\n"
		}
		pf += `    ` + jsonStr(f) + `: {}`
	}
	compile := `{` + jsonStr(compileDll) + `: {}}`
	if compileDll == "_._" {
		compile = `{"_._": {}}`
	}
	return []byte(`{
  "version": 3,
  "targets": {
    ` + jsonStr(target) + `: {
      ` + jsonStr(libKey) + `: { "type": "package", "compile": ` + compile + ` }
    }
  },
  "libraries": {
    ` + jsonStr(libKey) + `: { "type": "package", "path": ` + jsonStr(libPath) + ` }
  },
  "packageFolders": {
` + pf + `
  }
}`)
}

// jsonStr is a tiny JSON string quoter for fixture assembly (paths here contain no
// characters needing escape beyond the quotes).
func jsonStr(s string) string { return `"` + s + `"` }

func TestLocateDlls_AssetsHappyPath(t *testing.T) {
	cache := t.TempDir()
	// The authoritative compose is packageFolder / library.path / compile-key.
	// A wrong compose — dropping the packageFolder root, or joining the compile key
	// without library.path — would miss this file and (correctly) return ok=false;
	// the happy path proves the EXACT join is what resolves.
	want := writeDll(t, cache, "microsoft.extensions.primitives", "8.0.0", "lib", "net8.0", "Microsoft.Extensions.Primitives.dll")

	data := assetsJSON(
		[]string{cache},
		"Microsoft.Extensions.Primitives/8.0.0",
		"microsoft.extensions.primitives/8.0.0",
		"net8.0",
		"lib/net8.0/Microsoft.Extensions.Primitives.dll",
	)
	a, ok := ParseAssetsLocator(data)
	if !ok {
		t.Fatal("ParseAssetsLocator: ok=false on valid assets")
	}
	roots := NugetPackageRoots(t.TempDir(), a)
	got, ok := a.LocateDlls(roots, "net8.0", "Microsoft.Extensions.Primitives/8.0.0")
	if !ok {
		t.Fatalf("LocateDlls: ok=false, want the composed path %q", want)
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("LocateDlls composed %q, want [%q]", got, want)
	}
}

func TestLocateDlls_MutationControls(t *testing.T) {
	cache := t.TempDir()
	writeDll(t, cache, "foo", "1.0.0", "lib", "net8.0", "Foo.dll")

	tests := []struct {
		name       string
		compileDll string // what the assets compile key points at
		wantOK     bool
	}{
		// Mutation control: compile points at a dll that is NOT on disk -> declared
		// miss (ok=false), not a panic and not a wrong path.
		{"compile-points-at-absent-dll", "lib/net8.0/Nope.dll", false},
		// _._ placeholder: no locatable dll for this library in this target ->
		// ok=false, DISTINCT in intent from "file absent" (both are misses).
		{"underscore-placeholder", "_._", false},
		{"real-dll-on-disk", "lib/net8.0/Foo.dll", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := assetsJSON([]string{cache}, "Foo/1.0.0", "foo/1.0.0", "net8.0", tt.compileDll)
			a, ok := ParseAssetsLocator(data)
			if !ok {
				t.Fatal("ParseAssetsLocator ok=false")
			}
			_, ok = a.LocateDlls(NugetPackageRoots(t.TempDir(), a), "net8.0", "Foo/1.0.0")
			if ok != tt.wantOK {
				t.Fatalf("LocateDlls ok=%v, want %v", ok, tt.wantOK)
			}
		})
	}
}

func TestLocateDlls_PackageFolderPriority(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	// Present only in the SECOND packageFolder.
	want := writeDll(t, second, "bar", "2.0.0", "lib", "net8.0", "Bar.dll")

	data := assetsJSON(
		[]string{first, second},
		"Bar/2.0.0", "bar/2.0.0", "net8.0", "lib/net8.0/Bar.dll",
	)
	a, ok := ParseAssetsLocator(data)
	if !ok {
		t.Fatal("ParseAssetsLocator ok=false")
	}
	// packageFolders order must be preserved (Go maps do not): first-then-second.
	if len(a.packageFolders) != 2 || a.packageFolders[0] != first || a.packageFolders[1] != second {
		t.Fatalf("packageFolders order = %v, want [%q %q]", a.packageFolders, first, second)
	}
	roots := NugetPackageRoots(t.TempDir(), a)
	got, ok := a.LocateDlls(roots, "net8.0", "Bar/2.0.0")
	if !ok || len(got) != 1 || got[0] != want {
		t.Fatalf("LocateDlls = %q,%v; want [%q],true", got, ok, want)
	}

	// Present in NEITHER -> declared miss.
	dataMiss := assetsJSON([]string{first, second}, "Baz/3.0.0", "baz/3.0.0", "net8.0", "lib/net8.0/Baz.dll")
	am, _ := ParseAssetsLocator(dataMiss)
	if _, ok := am.LocateDlls(NugetPackageRoots(t.TempDir(), am), "net8.0", "Baz/3.0.0"); ok {
		t.Fatal("LocateDlls ok=true for a dll absent from every packageFolder")
	}
}

func TestLocateNugetCacheDll_EnvHonoredOverHome(t *testing.T) {
	envCache := t.TempDir()
	want := writeDll(t, envCache, "newtonsoft.json", "13.0.3", "lib", "net8.0", "Newtonsoft.Json.dll")

	// Point NUGET_PACKAGES at the temp cache; the global-cache fallback must honor
	// it OVER ~/.nuget/packages (which we never touch — hermetic).
	t.Setenv("NUGET_PACKAGES", envCache)
	roots := NugetPackageRoots(t.TempDir(), nil)
	if len(roots) != 1 || roots[0] != envCache {
		t.Fatalf("NugetPackageRoots with NUGET_PACKAGES set = %v, want [%q]", roots, envCache)
	}
	got, ok := LocateNugetCacheDll(roots, "Newtonsoft.Json", "13.0.3", "net8.0")
	if !ok || got != want {
		t.Fatalf("LocateNugetCacheDll = %q,%v; want %q,true", got, ok, want)
	}

	// Missing tfm hint -> cannot form the path, never walks guessing -> ok=false.
	if _, ok := LocateNugetCacheDll(roots, "Newtonsoft.Json", "13.0.3", ""); ok {
		t.Fatal("LocateNugetCacheDll resolved with empty tfmHint")
	}
}

func TestLocateNugetCacheDll_MalformedAndTraversal(t *testing.T) {
	cache := t.TempDir()
	// A file that a naive join of a "../"-laden id could try to escape toward.
	outside := filepath.Join(filepath.Dir(cache), "escape.dll")
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	roots := []string{cache}

	tests := []struct {
		name, id, version, tfm string
	}{
		{"empty-id", "", "1.0.0", "net8.0"},
		{"empty-version", "Foo", "", "net8.0"},
		{"slash-in-id", "Foo/Bar", "1.0.0", "net8.0"},
		{"dotdot-id", "..", "1.0.0", "net8.0"},
		{"traversal-id", "../../etc", "1.0.0", "net8.0"},
		{"traversal-version", "Foo", "../..", "net8.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := LocateNugetCacheDll(roots, tt.id, tt.version, tt.tfm)
			if ok {
				t.Fatalf("malformed input resolved to %q (must never escape the root)", got)
			}
		})
	}

	// Defense in depth: even if the guard let a crafted relpath through, the
	// containment check keeps the join inside the root.
	if p, ok := containedPath(cache, "..", "escape.dll"); ok {
		t.Fatalf("containedPath escaped root: %q", p)
	}
}

func TestLocateBuildOutput_BinAndPublish(t *testing.T) {
	build := t.TempDir()
	// bin/<config>/<tfm>/<name>.dll — nested, walked.
	wantBin := writeDll(t, build, "bin", "Release", "net8.0", "App.dll")
	if got, ok := LocateBuildOutput(build, "App"); !ok || got != wantBin {
		t.Fatalf("LocateBuildOutput(bin) = %q,%v; want %q,true", got, ok, wantBin)
	}

	// publish/<name>.dll — flat.
	build2 := t.TempDir()
	wantPub := writeDll(t, build2, "publish", "Lib.dll")
	if got, ok := LocateBuildOutput(build2, "Lib"); !ok || got != wantPub {
		t.Fatalf("LocateBuildOutput(publish) = %q,%v; want %q,true", got, ok, wantPub)
	}

	// Absent -> declared miss; malformed name -> ok=false.
	if _, ok := LocateBuildOutput(build, "Nope"); ok {
		t.Fatal("LocateBuildOutput resolved an absent dll")
	}
	if _, ok := LocateBuildOutput(build, "../etc/passwd"); ok {
		t.Fatal("LocateBuildOutput accepted a traversal name")
	}
}

func TestReadAssembly(t *testing.T) {
	dir := t.TempDir()

	// A real (synthesized) minimal PE — reuse the assembly package's standard
	// fixture; do NOT hand-fabricate PE bytes.
	realPE := filepath.Join(dir, "real.dll")
	if err := os.WriteFile(realPE, standardFixture(0x00).data, 0o644); err != nil {
		t.Fatalf("write real PE: %v", err)
	}
	a, ok := ReadAssembly(realPE)
	if !ok || a == nil {
		t.Fatalf("ReadAssembly over a real PE = %v,%v; want non-nil,true", a, ok)
	}

	// Non-existent path -> ok=false, no panic.
	if got, ok := ReadAssembly(filepath.Join(dir, "does-not-exist.dll")); ok || got != nil {
		t.Fatalf("ReadAssembly over missing path = %v,%v; want nil,false", got, ok)
	}

	// Truncated / garbage bytes -> ok=false, no panic.
	garbage := filepath.Join(dir, "garbage.dll")
	if err := os.WriteFile(garbage, []byte("MZ this is not a PE at all"), 0o644); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	if got, ok := ReadAssembly(garbage); ok || got != nil {
		t.Fatalf("ReadAssembly over garbage = %v,%v; want nil,false", got, ok)
	}

	// A truncated prefix of the real PE -> ok=false, no panic (Read is prefix-safe).
	trunc := filepath.Join(dir, "trunc.dll")
	full := standardFixture(0x00).data
	if err := os.WriteFile(trunc, full[:len(full)/2], 0o644); err != nil {
		t.Fatalf("write trunc: %v", err)
	}
	if _, ok := ReadAssembly(trunc); ok {
		t.Fatal("ReadAssembly over a truncated PE returned ok=true")
	}
}

// TestFrameworkSupplied: a runtime block of only "_._" over a compile dll is the framework
// supplying the package at run time: no dll resolves (not the compile asset, not the cache
// convention path), and the package is not codeless either.
func TestFrameworkSupplied(t *testing.T) {
	cache := t.TempDir()
	writeDll(t, cache, "system.buffers", "4.5.1", "ref", "net8.0", "System.Buffers.dll")
	writeDll(t, cache, "system.buffers", "4.5.1", "lib", "net8.0", "System.Buffers.dll")
	data := []byte(`{"version":3,"targets":{"net8.0":{` +
		`"System.Buffers/4.5.1":{"type":"package","compile":{"ref/net8.0/System.Buffers.dll":{}},"runtime":{"lib/net8.0/_._":{}}},` +
		`"Meta/1.0.0":{"type":"package","compile":{"lib/net8.0/_._":{}},"runtime":{"lib/net8.0/_._":{}}},` +
		`"RefOnly/1.0.0":{"type":"package","compile":{"ref/net8.0/RefOnly.dll":{}}}}},` +
		`"libraries":{"System.Buffers/4.5.1":{"type":"package","path":"system.buffers/4.5.1"},` +
		`"Meta/1.0.0":{"type":"package","path":"meta/1.0.0"},"RefOnly/1.0.0":{"type":"package","path":"refonly/1.0.0"}},` +
		`"packageFolders":{` + jsonStr(cache) + `:{}}}`)
	a, ok := ParseAssetsLocator(data)
	if !ok {
		t.Fatal("ParseAssetsLocator ok=false")
	}
	t.Setenv("NUGET_PACKAGES", cache)
	cases := []struct {
		pkg                     string
		framework, noAssemblies bool
		compileDlls             int
	}{
		{"System.Buffers/4.5.1", true, false, 0},
		{"Meta/1.0.0", false, true, 0},
		{"RefOnly/1.0.0", false, false, 1}, // no runtime block: compile is the implementation
	}
	for _, c := range cases {
		if got := a.FrameworkSupplied("net8.0", c.pkg); got != c.framework {
			t.Errorf("%s: FrameworkSupplied = %v, want %v", c.pkg, got, c.framework)
		}
		if got := a.HasNoAssemblies("net8.0", c.pkg); got != c.noAssemblies {
			t.Errorf("%s: HasNoAssemblies = %v, want %v", c.pkg, got, c.noAssemblies)
		}
		if got := len(a.dlls["net8.0"][c.pkg]); got != c.compileDlls {
			t.Errorf("%s: %d dlls recorded, want %d", c.pkg, got, c.compileDlls)
		}
	}
	if paths, ok := ResolveDependencyDlls(t.TempDir(), "net8.0", "System.Buffers/4.5.1", a); ok {
		t.Fatalf("ResolveDependencyDlls = %v for a framework-supplied package, want a miss", paths)
	}
	if _, why := ReadDependency(t.TempDir(), DepRef{Target: "net8.0", PkgKey: "System.Buffers/4.5.1"}, a); why != MissFrameworkSupplied {
		t.Fatalf("ReadDependency miss = %q, want %q", why, MissFrameworkSupplied)
	}
}

// TestDependencyDlls_RuntimeSpecificAssets: a package that ships its implementation under
// runtimes/<rid>/lib/ beside a lib/ dll (often a PlatformNotSupported stub) is read from the
// target restore resolved for the build's runtime, and only from there. With the runtime
// unknown, ambiguous, or not restored, the package is a named miss; the lib/ dll, which both
// the assets runtime block and the cache convention path name, is never read in its place.
func TestDependencyDlls_RuntimeSpecificAssets(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("NUGET_PACKAGES", cache)
	stub := writeDll(t, cache, "rid", "1.0.0", "lib", "net8.0", "Rid.dll")
	win := writeDll(t, cache, "rid", "1.0.0", "runtimes", "win", "lib", "net8.0", "Rid.dll")
	plain := writeDll(t, cache, "plain", "1.0.0", "lib", "net8.0", "Plain.dll")
	writeDll(t, cache, "gone", "1.0.0", "lib", "net8.0", "Gone.dll")
	ridRow := func(runtimeDll string) string {
		return `"Rid/1.0.0":{"type":"package","compile":{"lib/net8.0/Rid.dll":{}},"runtime":{"` + runtimeDll + `":{}},` +
			`"runtimeTargets":{"runtimes/win/lib/net8.0/Rid.dll":{"assetType":"runtime","rid":"win"}}}`
	}
	data := []byte(`{"version":3,"targets":{` +
		`"net8.0":{` + ridRow("lib/net8.0/Rid.dll") + `,` +
		`"Plain/1.0.0":{"type":"package","runtime":{"lib/net8.0/Plain.dll":{}},` +
		`"runtimeTargets":{"runtimes/linux-x64/native/libplain.so":{"assetType":"native","rid":"linux-x64"}}},` +
		`"Gone/1.0.0":{"type":"package","runtime":{"lib/net8.0/Gone.dll":{}},` +
		`"runtimeTargets":{"runtimes/win/lib/net8.0/Gone.dll":{"assetType":"runtime","rid":"win"}}}},` +
		`"net8.0/win-x64":{"Rid/1.0.0":{"type":"package","runtime":{"runtimes/win/lib/net8.0/Rid.dll":{}}},` +
		`"Gone/1.0.0":{"type":"package","runtime":{"runtimes/win/lib/net8.0/Gone.dll":{}}}},` +
		`"net8.0/linux-x64":{"Rid/1.0.0":{"type":"package","runtime":{"lib/net8.0/Rid.dll":{}}}}},` +
		`"libraries":{"Rid/1.0.0":{"type":"package","path":"rid/1.0.0"},"Plain/1.0.0":{"type":"package","path":"plain/1.0.0"},` +
		`"Gone/1.0.0":{"type":"package","path":"gone/1.0.0"}},` +
		`"packageFolders":{` + jsonStr(cache) + `:{}}}`)
	a, ok := ParseAssetsLocator(data)
	if !ok {
		t.Fatal("ParseAssetsLocator ok=false")
	}
	cases := []struct {
		name     string
		pkg      string
		runtime  Runtime
		want     string // located path; "" when a miss
		wantMiss string
	}{
		{"RID resolved: the runtime's implementation", "Rid/1.0.0", Runtime{RID: "win-x64"}, win, ""},
		{"RID resolved to lib/ by restore", "Rid/1.0.0", Runtime{RID: "linux-x64"}, stub, ""},
		{"RID unknown (portable build)", "Rid/1.0.0", Runtime{}, "", MissRIDUnknown},
		{"RID ambiguous", "Rid/1.0.0", Runtime{Ambiguous: true}, "", MissRIDAmbiguous},
		{"RID the restore did not resolve", "Rid/1.0.0", Runtime{RID: "osx-arm64"}, "", MissRIDUnknown},
		{"RID resolved, its asset missing: no fallback to lib/", "Gone/1.0.0", Runtime{RID: "win-x64"}, "", MissNotLocated},
		{"native-only runtimeTargets do not make a package runtime-specific", "Plain/1.0.0", Runtime{}, plain, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			paths, miss := dependencyDlls(t.TempDir(), DepRef{Target: "net8.0", PkgKey: c.pkg, Runtime: c.runtime}, a)
			if miss != c.wantMiss {
				t.Fatalf("miss = %q, want %q (paths %v)", miss, c.wantMiss, paths)
			}
			if c.want == "" {
				if len(paths) != 0 {
					t.Fatalf("paths = %v, want none", paths)
				}
				return
			}
			if len(paths) != 1 || paths[0] != c.want {
				t.Fatalf("paths = %v, want [%s]", paths, c.want)
			}
		})
	}
}
