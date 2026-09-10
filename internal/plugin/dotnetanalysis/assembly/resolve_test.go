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

func TestLocateDll_AssetsHappyPath(t *testing.T) {
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
	got, ok := a.LocateDll(roots, "net8.0", "Microsoft.Extensions.Primitives/8.0.0")
	if !ok {
		t.Fatalf("LocateDll: ok=false, want the composed path %q", want)
	}
	if got != want {
		t.Fatalf("LocateDll composed %q, want %q", got, want)
	}
}

func TestLocateDll_MutationControls(t *testing.T) {
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
			_, ok = a.LocateDll(NugetPackageRoots(t.TempDir(), a), "net8.0", "Foo/1.0.0")
			if ok != tt.wantOK {
				t.Fatalf("LocateDll ok=%v, want %v", ok, tt.wantOK)
			}
		})
	}
}

func TestLocateDll_PackageFolderPriority(t *testing.T) {
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
	got, ok := a.LocateDll(roots, "net8.0", "Bar/2.0.0")
	if !ok || got != want {
		t.Fatalf("LocateDll = %q,%v; want %q,true", got, ok, want)
	}

	// Present in NEITHER -> declared miss.
	dataMiss := assetsJSON([]string{first, second}, "Baz/3.0.0", "baz/3.0.0", "net8.0", "lib/net8.0/Baz.dll")
	am, _ := ParseAssetsLocator(dataMiss)
	if _, ok := am.LocateDll(NugetPackageRoots(t.TempDir(), am), "net8.0", "Baz/3.0.0"); ok {
		t.Fatal("LocateDll ok=true for a dll absent from every packageFolder")
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
