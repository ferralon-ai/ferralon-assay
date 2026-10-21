package kotlinanalysis

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// resolve_test.go — P1 (ResolveDependencyVersions delegation, §8 rows 1/9) and P2
// (ResolveDependencySymbols against the dependency JAR, §8 row 4). Versions come from the build
// tool's resolved graph; symbols run through REAL classfile.LoadJar over hermetically emitted
// JARs the graph names (no kotlinc/JVM toolchain exists in this environment), so the coverage
// runs through the production readers, not hand-built structs.

// --- P1: ResolveDependencyVersions -------------------------------------------

func writeBuildFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// TestResolveDependencyVersions_GraphVersions proves the delegated resolver answers with the
// version the build tool resolved, whatever the scope (row 1).
func TestResolveDependencyVersions_GraphVersions(t *testing.T) {
	graph := graphOption(t, graphModule(".", "app",
		graphDep{group: "com.example", artifact: "widget", version: "1.2.3"},
		graphDep{group: "com.example", artifact: "api-lib", version: "4.5.6"},
		graphDep{group: "org.jetbrains", artifact: "annotations", version: "24.0.0", scope: "test"}))
	for _, tc := range []struct{ coordinate, version string }{
		{"com.example:widget", "1.2.3"},
		{"com.example:api-lib", "4.5.6"},
		{"org.jetbrains:annotations", "24.0.0"},
	} {
		res, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{
			BuildDir: t.TempDir(), Coordinate: tc.coordinate,
		}, graph)
		if err != nil {
			t.Fatalf("ResolveDependencyVersions(%q): %v", tc.coordinate, err)
		}
		if !res.Partiality.Complete {
			t.Errorf("%q: partiality not Complete: %+v", tc.coordinate, res.Partiality)
		}
		if !res.Found || !res.Match.Resolved || res.Match.Version != tc.version {
			t.Errorf("%q: match = %+v (found %v), want resolved %s", tc.coordinate, res.Match, res.Found, tc.version)
		}
	}
}

// TestResolveDependencyVersions_ModulesDisagree proves the delegated resolver's agreement rule
// reaches Kotlin builds: two modules resolving different versions of a coordinate leave the
// Match unresolved, so neither copy alone decides the verdict.
func TestResolveDependencyVersions_ModulesDisagree(t *testing.T) {
	graph := graphOption(t,
		graphModule("a", "a", graphDep{group: "com.example", artifact: "widget", version: "1.2.3"}),
		graphModule("b", "b", graphDep{group: "com.example", artifact: "widget", version: "1.2.2"}))
	res, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: t.TempDir(), Coordinate: "com.example:widget"}, graph)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Found || res.Match.Resolved || res.Match.Version != "" {
		t.Fatalf("match = %+v, want found and unresolved", res.Match)
	}
}

// TestResolveDependencyVersions_NoGraph proves build_graph_absent partiality (fail open) when
// no graph was handed in — never a confident empty that reads as absence.
func TestResolveDependencyVersions_NoGraph(t *testing.T) {
	res, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{
		BuildDir: t.TempDir(), Coordinate: "com.example:widget",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Partiality.Complete || !hasReason(res.Partiality, javaanalysis.PartialReasonBuildGraphAbsent) {
		t.Fatalf("partiality %+v, want %s", res.Partiality, javaanalysis.PartialReasonBuildGraphAbsent)
	}
	if !res.Found || res.Match.Resolved {
		t.Errorf("match = %+v (found %v), want found and unresolved", res.Match, res.Found)
	}
}

// --- P2: ResolveDependencySymbols --------------------------------------------

// writeGradleJarFixture emits a JAR of the given internalName->classBytes entries into a Gradle
// module cache under a fresh build dir, and returns the dir; cacheGraph names the JAR.
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
// graph resolves the vulnerable dependency to a JAR, and the advisory names the sink by its
// package-qualified form. The op indexes the JAR through the real parser and resolves the
// advisory symbol to a concrete bytecode-canonical plugin.Symbol — Complete, no partiality. A
// name without its full package stays unresolved: a lookalike class elsewhere in the JAR could
// satisfy it while the real sink goes unchecked.
func TestResolveDependencySymbols_ResolvesAgainstDependencyJar(t *testing.T) {
	build := writeGradleJarFixture(t, "com.example", "vuln", "1.2.3", map[string][]byte{
		"com/example/net/UrlFetcher": vulnClass(),
	})

	tests := []struct {
		advisory string
		resolved bool
	}{
		{"com.example.net.UrlFetcher.fetch", true},
		{"com.example.net.UrlFetcher.fetch(Ljava/lang/String;)V", true},
		{"UrlFetcher.fetch", false},
		{"fetch", false},
		{"net.UrlFetcher.fetch", false},
	}
	for _, tc := range tests {
		t.Run(tc.advisory, func(t *testing.T) {
			res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
				BuildDir:        build,
				PURL:            "pkg:maven/com.example/vuln",
				AdvisorySymbols: []string{tc.advisory},
			}, cacheGraph(t, build))
			if err != nil {
				t.Fatal(err)
			}
			if !tc.resolved {
				if len(res.Resolved) != 0 || len(res.Matched) != 0 || !hasReason(res.Partiality, partialReasonAdvisorySymbolUnresolved) {
					t.Fatalf("want unresolved, got resolved=%+v matched=%v partiality=%+v", res.Resolved, res.Matched, res.Partiality)
				}
				return
			}
			if !res.Partiality.Complete {
				t.Errorf("partiality not Complete: %+v", res.Partiality)
			}
			if len(res.Resolved) != 1 {
				t.Fatalf("got %d resolved, want 1: %+v", len(res.Resolved), res.Resolved)
			}
			got := res.Resolved[0]
			if got.Name != "fetch" || got.Enclosing != "UrlFetcher" || got.Package != "com.example.net" {
				t.Errorf("resolved symbol = %+v, want fetch on com.example.net.UrlFetcher", got)
			}
		})
	}
}

// TestResolveDependencySymbols_LookalikeClassIsNotTheSink: the JAR holds the real sink and a
// same-named class in another package. Only the advisory's full package selects; the lookalike
// never satisfies it, and a lookalike alone leaves the symbol unresolved.
func TestResolveDependencySymbols_LookalikeClassIsNotTheSink(t *testing.T) {
	lookalike := func() []byte {
		b := newKClassBuilder()
		b.addMethod("fetch", "(Ljava/lang/String;)V", []byte{opReturn})
		return b.build("com/example/shaded/UrlFetcher", "java/lang/Object")
	}
	tests := []struct {
		name        string
		classes     map[string][]byte
		wantMatched map[string][]string
	}{
		{
			name: "real sink and lookalike: only the real sink",
			classes: map[string][]byte{
				"com/example/net/UrlFetcher":    vulnClass(),
				"com/example/shaded/UrlFetcher": lookalike(),
			},
			wantMatched: map[string][]string{
				"com.example.net.UrlFetcher.fetch": {"com/example/net/UrlFetcher.fetch(Ljava/lang/String;)V"},
			},
		},
		{
			name:        "lookalike only: unresolved",
			classes:     map[string][]byte{"com/example/shaded/UrlFetcher": lookalike()},
			wantMatched: map[string][]string{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			build := writeGradleJarFixture(t, "com.example", "vuln", "1.2.3", tc.classes)
			res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
				BuildDir:        build,
				PURL:            "pkg:maven/com.example/vuln@1.2.3",
				AdvisorySymbols: []string{"com.example.net.UrlFetcher.fetch"},
			}, cacheGraph(t, build))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(res.Matched, tc.wantMatched) {
				t.Errorf("Matched = %v, want %v", res.Matched, tc.wantMatched)
			}
			if wantUnresolved := len(tc.wantMatched) == 0; hasReason(res.Partiality, partialReasonAdvisorySymbolUnresolved) != wantUnresolved {
				t.Errorf("advisory_symbol_unresolved = %v, want %v (%+v)", !wantUnresolved, wantUnresolved, res.Partiality)
			}
		})
	}
}

// TestResolveDependencySymbols_PURLPinnedVersion proves the version may come straight from
// the PURL (`@version`).
func TestResolveDependencySymbols_PURLPinnedVersion(t *testing.T) {
	build := writeGradleJarFixture(t, "com.example", "vuln", "9.9.9", map[string][]byte{
		"com/example/net/UrlFetcher": vulnClass(),
	})
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir:        build,
		PURL:            "pkg:maven/com.example/vuln@9.9.9",
		AdvisorySymbols: []string{"com.example.net.UrlFetcher.fetch"},
	}, cacheGraph(t, build))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Partiality.Complete || len(res.Resolved) != 1 {
		t.Fatalf("PURL-pinned resolution failed: complete=%v resolved=%+v", res.Partiality.Complete, res.Resolved)
	}
}

// TestResolveDependencySymbols_JarAbsentIsHonestPartiality proves that when the graph names no
// JAR for the dependency the op never renders a clean empty or a fabricated match. A coordinate a
// complete graph lacks is dependency_not_in_build, bounded to that package alone; beside a build
// of the other tool, or named by the graph without a JAR, it stays a run-wide
// no_dependency_artifact.
func TestResolveDependencySymbols_JarAbsentIsHonestPartiality(t *testing.T) {
	const purl = "pkg:maven/com.example/vuln"
	for _, tc := range []struct {
		name        string
		otherTool   bool
		inGraph     bool
		wantRunWide []string
		wantScoped  []plugin.ScopedReason
	}{
		{name: "absent from a complete graph",
			wantScoped: []plugin.ScopedReason{{Reason: javaanalysis.PartialReasonDependencyNotInBuild, Package: purl, Path: "com.example:vuln", Targets: []string{purl}}}},
		{name: "absent beside a build of the other tool", otherTool: true, wantRunWide: []string{partialReasonNoDependencyArtifact}},
		{name: "in the graph without a JAR", inGraph: true, wantRunWide: []string{partialReasonNoDependencyArtifact}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := t.TempDir()
			if tc.otherTool {
				if err := os.WriteFile(filepath.Join(build, "pom.xml"), []byte("<project/>"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var extra []graphDep
			if tc.inGraph {
				extra = append(extra, graphDep{group: "com.example", artifact: "vuln", version: "1.0.0", jar: filepath.Join(build, "vuln-1.0.0.pom")})
			}
			res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
				BuildDir:        build,
				PURL:            purl,
				AdvisorySymbols: []string{"com.example.net.UrlFetcher.fetch"},
			}, cacheGraph(t, build, extra...))
			if err != nil {
				t.Fatal(err)
			}
			if res.Partiality.Complete || len(res.Resolved) != 0 {
				t.Fatalf("absent-JAR case rendered complete or resolved: %+v", res)
			}
			if !reflect.DeepEqual(res.Partiality.Reasons, tc.wantRunWide) || !reflect.DeepEqual(res.Partiality.Scoped, tc.wantScoped) {
				t.Errorf("partiality %+v, want run-wide %v scoped %+v", res.Partiality, tc.wantRunWide, tc.wantScoped)
			}
		})
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
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir:        build,
		PURL:            "pkg:maven/com.example/vuln",
		AdvisorySymbols: []string{"com.example.net.UrlFetcher.doesNotExist"},
	}, cacheGraph(t, build))
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
		AdvisorySymbols: []string{"com.example.net.UrlFetcher.fetch", "com.example.net.UrlFetcher.open", "com.example.net.UrlFetcher.read"},
	}
	graph := cacheGraph(t, build)
	first, err := ResolveDependencySymbols(context.Background(), req, graph)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		next, err := ResolveDependencySymbols(context.Background(), req, graph)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first.Resolved, next.Resolved) {
			t.Fatalf("non-deterministic resolution:\n first=%+v\n next =%+v", first.Resolved, next.Resolved)
		}
	}
}
