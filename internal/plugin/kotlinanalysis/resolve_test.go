package kotlinanalysis

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// resolve_test.go — P1 (ResolveDependencyVersions delegation, §8 rows 1/9) and P2
// (ResolveDependencySymbols against the dependency JAR, §8 row 4). Both drive REAL build-file
// parsing and REAL classfile.LoadJar over hermetically emitted artifacts (no kotlinc/JVM
// toolchain exists in this environment), so the coverage runs through the production parsers,
// not hand-built structs.

// --- P1: ResolveDependencyVersions -------------------------------------------

func writeBuildFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// TestResolveDependencyVersions_KotlinDSLLiterals proves the delegated shared parser
// resolves the Kotlin-DSL parenthesized, double-quoted configuration forms to concrete
// versions (row 1: declared versions match the native resolver's for the literal case).
func TestResolveDependencyVersions_KotlinDSLLiterals(t *testing.T) {
	dir := t.TempDir()
	writeBuildFile(t, dir, "build.gradle.kts", `
dependencies {
    implementation("com.example:widget:1.2.3")
    api("com.example:api-lib:4.5.6")
    testImplementation("org.jetbrains:annotations:24.0.0")
}
`)

	cases := []struct {
		coordinate string
		version    string
	}{
		{"com.example:widget", "1.2.3"},
		{"com.example:api-lib", "4.5.6"},
		{"org.jetbrains:annotations", "24.0.0"},
	}
	for _, tc := range cases {
		res, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{
			BuildDir: dir, Coordinate: tc.coordinate,
		})
		if err != nil {
			t.Fatalf("ResolveDependencyVersions(%q): %v", tc.coordinate, err)
		}
		if !res.Partiality.Complete {
			t.Errorf("%q: partiality not Complete: %+v", tc.coordinate, res.Partiality)
		}
		if !res.Found || !res.Match.Resolved {
			t.Fatalf("%q: Found=%v Resolved=%v, want both true", tc.coordinate, res.Found, res.Match.Resolved)
		}
		if res.Match.Version != tc.version {
			t.Errorf("%q: version = %q, want %q", tc.coordinate, res.Match.Version, tc.version)
		}
	}
}

// TestResolveDependencyVersions_HonestIncompleteForms proves the declared Kotlin-DSL
// boundary (row 1/9 fail-open): version-catalog references, the kotlin() helper, and
// interpolated versions MUST NOT resolve to a fabricated version. A coordinate the parser
// cannot pin is either absent (Found=false) or UNRESOLVED (Resolved=false) — never a wrong
// version the disqualification predicate could act on.
func TestResolveDependencyVersions_HonestIncompleteForms(t *testing.T) {
	dir := t.TempDir()
	writeBuildFile(t, dir, "build.gradle.kts", `
val jacksonVersion = "2.15.0"
dependencies {
    implementation(libs.retrofit)
    implementation(kotlin("stdlib"))
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
}
`)

	// Interpolated version: the coordinate is parsed but its version is UNRESOLVED, not guessed.
	res, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{
		BuildDir: dir, Coordinate: "com.fasterxml.jackson.core:jackson-databind",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Found && res.Match.Resolved {
		t.Errorf("interpolated version was fabricated as resolved: %+v", res.Match)
	}

	// Version-catalog reference: no literal coordinate at all, so it is simply absent.
	for _, coord := range []string{"libs:retrofit", "org.jetbrains.kotlin:kotlin-stdlib"} {
		res, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{
			BuildDir: dir, Coordinate: coord,
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.Found && res.Match.Resolved {
			t.Errorf("%q: non-literal DSL form fabricated a resolved version: %+v", coord, res.Match)
		}
	}
}

// TestResolveDependencyVersions_NoBuildFile proves no_manifest partiality (fail open) when
// the checkout carries no build file at all — never a confident empty that reads as absence.
func TestResolveDependencyVersions_NoBuildFile(t *testing.T) {
	dir := t.TempDir()
	res, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{
		BuildDir: dir, Coordinate: "com.example:widget",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Partiality.Complete {
		t.Fatal("no-build-file case rendered Complete: honest-absent violated")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonNoManifest) {
		t.Errorf("partiality %v missing no_manifest", res.Partiality.Reasons)
	}
}

// --- P2: ResolveDependencySymbols --------------------------------------------

// writeJarFixture emits a JAR of the given internalName->classBytes entries into the Gradle
// module cache layout LocateDependencyJar globs, and returns the build dir it lives under.
func writeGradleJarFixture(t *testing.T, group, artifact, version string, classes map[string][]byte) string {
	t.Helper()
	build := t.TempDir()
	hashDir := filepath.Join(build, ".gradle", "caches", "modules-2", "files-2.1",
		group, artifact, version, "deadbeef")
	if err := os.MkdirAll(hashDir, 0o755); err != nil {
		t.Fatal(err)
	}
	jarPath := filepath.Join(hashDir, artifact+"-"+version+".jar")
	f, err := os.Create(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for internalName, data := range classes {
		w, err := zw.Create(internalName + ".class")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return build
}

// vulnClass emits a dependency class com/example/net/UrlFetcher with a single method
// fetch(Ljava/lang/String;)V — the "vulnerable symbol" an advisory names.
func vulnClass() []byte {
	b := newKClassBuilder()
	b.addMethod("fetch", "(Ljava/lang/String;)V", []byte{opReturn})
	return b.build("com/example/net/UrlFetcher", "java/lang/Object")
}

// TestResolveDependencySymbols_ResolvesAgainstDependencyJar is the row-4 happy path: the
// build declares the vulnerable dependency's version, its JAR sits in the local Gradle
// cache, and the advisory names the sink by its package-qualified form. The op locates the
// JAR, indexes it through the real parser, and resolves the advisory symbol to a concrete
// bytecode-canonical plugin.Symbol — Complete, no partiality.
func TestResolveDependencySymbols_ResolvesAgainstDependencyJar(t *testing.T) {
	build := writeGradleJarFixture(t, "com.example", "vuln", "1.2.3", map[string][]byte{
		"com/example/net/UrlFetcher": vulnClass(),
	})
	writeBuildFile(t, build, "build.gradle.kts", `
dependencies {
    implementation("com.example:vuln:1.2.3")
}
`)

	for _, advisory := range []string{
		"com.example.net.UrlFetcher.fetch",
		"UrlFetcher.fetch",
		"fetch",
	} {
		res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
			BuildDir:        build,
			PURL:            "pkg:maven/com.example/vuln",
			AdvisorySymbols: []string{advisory},
		})
		if err != nil {
			t.Fatalf("advisory %q: %v", advisory, err)
		}
		if !res.Partiality.Complete {
			t.Errorf("advisory %q: partiality not Complete: %+v", advisory, res.Partiality)
		}
		if len(res.Resolved) != 1 {
			t.Fatalf("advisory %q: got %d resolved, want 1: %+v", advisory, len(res.Resolved), res.Resolved)
		}
		got := res.Resolved[0]
		if got.Name != "fetch" || got.Enclosing != "UrlFetcher" || got.Package != "com.example.net" {
			t.Errorf("advisory %q: resolved symbol = %+v, want fetch on com.example.net.UrlFetcher", advisory, got)
		}
	}
}

// TestResolveDependencySymbols_PURLPinnedVersion proves the version may come straight from
// the PURL (`@version`), with no build file consulted at all.
func TestResolveDependencySymbols_PURLPinnedVersion(t *testing.T) {
	build := writeGradleJarFixture(t, "com.example", "vuln", "9.9.9", map[string][]byte{
		"com/example/net/UrlFetcher": vulnClass(),
	})
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir:        build,
		PURL:            "pkg:maven/com.example/vuln@9.9.9",
		AdvisorySymbols: []string{"com.example.net.UrlFetcher.fetch"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Partiality.Complete || len(res.Resolved) != 1 {
		t.Fatalf("PURL-pinned resolution failed: complete=%v resolved=%+v", res.Partiality.Complete, res.Resolved)
	}
}

// TestResolveDependencySymbols_JarAbsentIsHonestPartiality proves that when the dependency
// artifact is not in any local cache, the op declares no_dependency_artifact partiality with
// an empty resolution — never a fabricated match, never a clean empty.
func TestResolveDependencySymbols_JarAbsentIsHonestPartiality(t *testing.T) {
	build := t.TempDir()
	writeBuildFile(t, build, "build.gradle.kts", `
dependencies {
    implementation("com.example:vuln:1.2.3")
}
`)
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir:        build,
		PURL:            "pkg:maven/com.example/vuln",
		AdvisorySymbols: []string{"com.example.net.UrlFetcher.fetch"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Partiality.Complete {
		t.Fatal("absent-JAR case rendered Complete: honest-absent violated")
	}
	if !hasReason(res.Partiality, partialReasonNoDependencyArtifact) {
		t.Errorf("partiality %v missing %q", res.Partiality.Reasons, partialReasonNoDependencyArtifact)
	}
	if len(res.Resolved) != 0 {
		t.Errorf("absent-JAR case carried resolved symbols: %+v", res.Resolved)
	}
}

// TestResolveDependencySymbols_VersionUnresolvedIsHonestPartiality proves that a
// non-literal version form (which P1 leaves UNRESOLVED) blocks JAR location and yields
// no_dependency_artifact — the version boundary and the symbol op compose fail-open.
func TestResolveDependencySymbols_VersionUnresolvedIsHonestPartiality(t *testing.T) {
	build := writeGradleJarFixture(t, "com.example", "vuln", "1.2.3", map[string][]byte{
		"com/example/net/UrlFetcher": vulnClass(),
	})
	// Version catalog form: coordinate never resolves to a literal version, so the JAR
	// (which does exist in cache) cannot be located by coordinate+version.
	writeBuildFile(t, build, "build.gradle.kts", `
dependencies {
    implementation(libs.vuln)
}
`)
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir:        build,
		PURL:            "pkg:maven/com.example/vuln",
		AdvisorySymbols: []string{"com.example.net.UrlFetcher.fetch"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Partiality.Complete {
		t.Fatal("unresolved-version case rendered Complete: honest-absent violated")
	}
	if !hasReason(res.Partiality, partialReasonNoDependencyArtifact) {
		t.Errorf("partiality %v missing %q", res.Partiality.Reasons, partialReasonNoDependencyArtifact)
	}
}

// TestResolveDependencySymbols_SymbolAbsentIsHonestPartiality proves the negative frontier:
// the JAR is located and fully read, but the advisory names a symbol not present in it. The
// op declares advisory_symbol_unresolved (non-Complete) with an empty resolution — absence
// never refutes, never a fabricated match.
func TestResolveDependencySymbols_SymbolAbsentIsHonestPartiality(t *testing.T) {
	build := writeGradleJarFixture(t, "com.example", "vuln", "1.2.3", map[string][]byte{
		"com/example/net/UrlFetcher": vulnClass(),
	})
	writeBuildFile(t, build, "build.gradle.kts", `
dependencies {
    implementation("com.example:vuln:1.2.3")
}
`)
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir:        build,
		PURL:            "pkg:maven/com.example/vuln",
		AdvisorySymbols: []string{"com.example.net.UrlFetcher.doesNotExist"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Partiality.Complete {
		t.Fatal("symbol-absent case rendered Complete: absence must not refute")
	}
	if !hasReason(res.Partiality, partialReasonAdvisorySymbolUnresolved) {
		t.Errorf("partiality %v missing %q", res.Partiality.Reasons, partialReasonAdvisorySymbolUnresolved)
	}
	if len(res.Resolved) != 0 {
		t.Errorf("symbol-absent case carried resolved symbols: %+v", res.Resolved)
	}
}

// TestResolveDependencySymbols_Deterministic guards the determinism invariant: the resolved
// slice is SCIP-sorted, so repeated resolutions of the same inputs are byte-equivalent (no
// map is an iteration source on the encoding path).
func TestResolveDependencySymbols_Deterministic(t *testing.T) {
	build := writeGradleJarFixture(t, "com.example", "vuln", "1.2.3", map[string][]byte{
		"com/example/net/UrlFetcher": func() []byte {
			b := newKClassBuilder()
			b.addMethod("fetch", "(Ljava/lang/String;)V", []byte{opReturn})
			b.addMethod("open", "()V", []byte{opReturn})
			b.addMethod("read", "()V", []byte{opReturn})
			return b.build("com/example/net/UrlFetcher", "java/lang/Object")
		}(),
	})
	req := plugin.ResolveSymbolsRequest{
		BuildDir:        build,
		PURL:            "pkg:maven/com.example/vuln@1.2.3",
		AdvisorySymbols: []string{"UrlFetcher.fetch", "UrlFetcher.open", "UrlFetcher.read"},
	}
	first, err := ResolveDependencySymbols(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		next, err := ResolveDependencySymbols(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first.Resolved, next.Resolved) {
			t.Fatalf("non-deterministic resolution:\n first=%+v\n next =%+v", first.Resolved, next.Resolved)
		}
	}
}
