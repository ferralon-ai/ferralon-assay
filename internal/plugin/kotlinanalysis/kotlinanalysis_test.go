package kotlinanalysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestIndexSymbols_AbsentBuildOutputIsHonestPartiality is the honest-absent invariant
// (inv.5 / §3.6): a checked-out tree with NO compiled build output must yield a DECLARED
// tool-unavailable partiality carrying an empty symbol set — never a confident-empty
// Complete() result, and never a hard error (the dir exists and is readable).
func TestIndexSymbols_AbsentBuildOutputIsHonestPartiality(t *testing.T) {
	dir := t.TempDir()
	// A Kotlin source file with no compiled output is exactly the tool-unavailable case.
	if err := os.WriteFile(filepath.Join(dir, "Main.kt"), []byte("fun main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("IndexSymbols returned a hard error for a present-but-uncompiled tree: %v", err)
	}
	if res.Partiality.Complete {
		t.Fatal("absent build output rendered as Complete: honest-absent violated")
	}
	if !hasReason(res.Partiality, partialReasonNoBuildOutput) {
		t.Fatalf("partiality reasons %v missing %q", res.Partiality.Reasons, partialReasonNoBuildOutput)
	}
	if len(res.Symbols) != 0 {
		t.Fatalf("expected empty symbol set for absent build output, got %d", len(res.Symbols))
	}
}

// TestReachability_AbsentBuildOutputFailsOpen confirms reachability over a tree with no
// build output never refutes: absence of evidence is declared partiality, never a clean
// empty (no-path-found) result the caller could read as "not reachable".
func TestReachability_AbsentBuildOutputFailsOpen(t *testing.T) {
	dir := t.TempDir()
	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{
		BuildDir: dir,
		Symbols:  []string{"com/example/Vuln.sink(Ljava/lang/String;)V"},
	})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if res.Partiality.Complete {
		t.Fatal("absent build output produced a Complete reachability result: fail-open violated")
	}
}

// TestLoadProgram_MissingDirIsHardError distinguishes a malformed request (dir does not
// exist) — a hard error (inv.4) — from a present-but-uncompiled tree (declared partiality).
func TestLoadProgram_MissingDirIsHardError(t *testing.T) {
	if _, err := loadProgram(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("expected a hard error for a nonexistent build dir")
	}
}

// TestSymbolFromMethodRef_Canonicalization pins the R3 ABI normalization rules that carry
// interop identity: constructor kind, companion declaring class ($-preserved), verbatim
// descriptor, and Generated markers for the facade / $default synthetics.
func TestSymbolFromMethodRef_Canonicalization(t *testing.T) {
	tests := []struct {
		name string
		ref  classfile.MethodRef
		want plugin.Symbol
	}{
		{
			name: "constructor",
			ref:  classfile.MethodRef{Owner: "com/example/UrlService", Name: "<init>", Descriptor: "(Ljava/lang/String;)V"},
			want: plugin.Symbol{Kind: plugin.SymbolKindConstructor, Package: "com.example", Enclosing: "UrlService", Name: "<init>", Descriptor: "(Ljava/lang/String;)V"},
		},
		{
			name: "companion declaring class preserves $",
			ref:  classfile.MethodRef{Owner: "com/example/UrlService$Companion", Name: "create", Descriptor: "()Lcom/example/UrlService;"},
			want: plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: "com.example", Enclosing: "UrlService$Companion", Name: "create", Descriptor: "()Lcom/example/UrlService;", Generated: true},
		},
		{
			name: "default-args bridge is generated",
			ref:  classfile.MethodRef{Owner: "com/example/DemoKt", Name: "greet$default", Descriptor: "(Ljava/lang/String;ILjava/lang/Object;)V"},
			want: plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: "com.example", Enclosing: "DemoKt", Name: "greet$default", Descriptor: "(Ljava/lang/String;ILjava/lang/Object;)V", Generated: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SymbolFromMethodRef(tt.ref)
			got.SCIP, got.DisplayName = "", "" // identity fields only
			if got != tt.want {
				t.Errorf("SymbolFromMethodRef(%v):\n got  %+v\n want %+v", tt.ref, got, tt.want)
			}
		})
	}
}

// TestParseMethodRef round-trips a MethodRef through String() and back — the sink-string
// contract Reachability parses.
func TestParseMethodRef(t *testing.T) {
	orig := classfile.MethodRef{Owner: "com/example/UrlKt", Name: "fetch", Descriptor: "(Ljava/lang/String;)V"}
	got, ok := parseMethodRef(orig.String())
	if !ok || got != orig {
		t.Fatalf("parseMethodRef(%q) = %v, %v; want %v", orig.String(), got, ok, orig)
	}
	if _, ok := parseMethodRef("not a method ref"); ok {
		t.Fatal("parseMethodRef accepted a malformed string")
	}
}

// TestLocateDependencyJar_Gradle verifies the Gradle module-cache locator globs the
// content-hash subdirectory Gradle interposes and finds the JAR by coordinate+version.
func TestLocateDependencyJar_Gradle(t *testing.T) {
	build := t.TempDir()
	hashDir := filepath.Join(build, ".gradle", "caches", "modules-2", "files-2.1",
		"com.google.code.gson", "gson", "2.10.1", "abc123def")
	if err := os.MkdirAll(hashDir, 0o755); err != nil {
		t.Fatal(err)
	}
	jar := filepath.Join(hashDir, "gson-2.10.1.jar")
	if err := os.WriteFile(jar, []byte("PK"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := LocateDependencyJar(build, "com.google.code.gson:gson", "2.10.1")
	if !ok || got != jar {
		t.Fatalf("LocateDependencyJar Gradle = %q, %v; want %q", got, ok, jar)
	}
}

// TestCapabilityManifest_Honest asserts the manifest is honest (K5): Supported with a jvm
// runtime and CHA semantics, no framework axis claimed (not implemented), the build-file
// Resolvers axis declared (P1: version resolution went live), and the desugaring boundaries
// declared. A future axis addition updates this test in step.
func TestCapabilityManifest_Honest(t *testing.T) {
	m := CapabilityManifest()
	if !m.Supported || m.Language != "kotlin" {
		t.Fatalf("manifest not an honest supported kotlin manifest: %+v", m)
	}
	if len(m.Frameworks) != 0 {
		t.Errorf("manifest claims frameworks it does not detect: %v", m.Frameworks)
	}
	// Resolvers ARE now claimed (build-file version resolution is live) and must name the
	// build-file formats the shared parser actually reads.
	for _, want := range []string{"build.gradle.kts", "pom.xml"} {
		if !contains(m.Resolvers, want) {
			t.Errorf("manifest omits resolver %q it now reads: %v", want, m.Resolvers)
		}
	}
	for _, want := range []string{"invokedynamic", "coroutine_dispatch", "inline_function", "reflection"} {
		if !contains(m.DynamicBoundaries, want) {
			t.Errorf("manifest omits desugaring boundary %q: %v", want, m.DynamicBoundaries)
		}
	}
}

func hasReason(p plugin.Partiality, reason string) bool { return contains(p.Reasons, reason) }

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
