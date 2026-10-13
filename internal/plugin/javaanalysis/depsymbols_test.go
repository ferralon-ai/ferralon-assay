package javaanalysis

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const netkitPURL = "pkg:maven/com.evil/netkit"

var netkitFetch = classfile.MethodRef{Owner: "com/evil/netkit/UrlFetcher", Name: "fetch", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;"}

// netkitOwnPom is netkit's own POM in the local cache: what its code was compiled against.
// Only the optional, provided and profile dependencies widen the closure past what the
// inventory's edges show; the test-scoped one never reaches netkit's runtime classpath.
const netkitOwnPom = `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.evil</groupId><artifactId>netkit</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency><groupId>com.dep</groupId><artifactId>optdep</artifactId><version>1</version><optional>true</optional></dependency>
    <dependency><groupId>com.dep</groupId><artifactId>provdep</artifactId><version>1</version><scope>provided</scope></dependency>
    <dependency><groupId>com.dep</groupId><artifactId>testdep</artifactId><version>1</version><scope>test</scope></dependency>
  </dependencies>
  <profiles>
    <profile><id>extra</id>
      <dependencies><dependency><groupId>com.dep</groupId><artifactId>profdep</artifactId><version>1</version><optional>true</optional></dependency></dependencies>
    </profile>
  </profiles>
</project>`

func writeNetkitOwnPom(t *testing.T, build string) {
	t.Helper()
	dir := filepath.Join(build, ".m2", "repository", "com", "evil", "netkit", "1.0.0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "netkit-1.0.0.pom"), []byte(netkitOwnPom), 0o644); err != nil {
		t.Fatal(err)
	}
}

func resolveNetkit(t *testing.T, build string, symbols ...string) plugin.SymbolResolutionResult {
	t.Helper()
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir: build, PURL: netkitPURL, AdvisorySymbols: symbols,
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	return res
}

func scips(syms []plugin.Symbol) []string {
	out := make([]string, 0, len(syms))
	for _, s := range syms {
		out = append(out, s.SCIP)
	}
	sort.Strings(out)
	return out
}

// A dependency advisory resolves to the method read from the dependency's JAR, under the
// id the dependency call graph uses, with the Maven coordinate as its package and origin.
func TestResolveDependencySymbols_ResolvesInsideDependencyJar(t *testing.T) {
	build := buildNetkitFixture(t, false)
	writeNetkitOwnPom(t, build)

	for _, advisory := range []string{"com.evil.netkit.UrlFetcher.fetch", "com.evil.netkit.UrlFetcher#fetch", "com.evil.netkit.UrlFetcher.fetch(1)"} {
		t.Run(advisory, func(t *testing.T) {
			res := resolveNetkit(t, build, advisory)
			if !res.Partiality.Complete {
				t.Fatalf("want complete, got %+v", res.Partiality)
			}
			want := depEdgeSymbol(netkitFetch)
			if got := scips(res.Resolved); !reflect.DeepEqual(got, []string{want}) {
				t.Fatalf("resolved %v, want [%s]", got, want)
			}
			s := res.Resolved[0]
			if s.Package != "com.evil:netkit" || s.Enclosing != "com.evil.netkit.UrlFetcher" || s.Name != "fetch" || s.Kind != plugin.SymbolKindMethod {
				t.Errorf("symbol fields: %+v", s)
			}
			if res.Origins[want] != netkitPURL {
				t.Errorf("origin of %s = %q, want %q", want, res.Origins[want], netkitPURL)
			}
			if got := res.Matched[advisory]; !reflect.DeepEqual(got, []string{want}) {
				t.Errorf("matched[%q] = %v, want [%s]", advisory, got, want)
			}
		})
	}
}

// A first-party method sharing the advisory's leaf name never stands in for the dependency
// method: only the dependency's JAR is searched.
func TestResolveDependencySymbols_FirstPartyLeafNeverResolvesDependencyAdvisory(t *testing.T) {
	build := buildNetkitFixture(t, false)
	writeNetkitOwnPom(t, build)
	withFirstPartySource(t, build, "src/main/java/com/acme/Client.java", `package com.acme;
public class Client {
  public String fetch(String u) { return u; }
  public Object readValue(String s) { return s; }
}
`)

	res := resolveNetkit(t, build, "com.evil.netkit.UrlFetcher.fetch")
	for _, s := range res.Resolved {
		if s.Package != "com.evil:netkit" {
			t.Errorf("first-party symbol resolved for a dependency advisory: %+v", s)
		}
	}
	if len(res.Resolved) != 1 {
		t.Errorf("want only netkit's fetch, got %v", scips(res.Resolved))
	}

	res = resolveNetkit(t, build, "com.fasterxml.jackson.databind.ObjectMapper.readValue")
	if len(res.Resolved) != 0 {
		t.Errorf("advisory absent from the JAR resolved to %v", scips(res.Resolved))
	}
	if res.Partiality.Complete || !reflect.DeepEqual(res.Partiality.Reasons, []string{reasonAdvisorySymbolUnresolved}) {
		t.Errorf("want %s, got %+v", reasonAdvisorySymbolUnresolved, res.Partiality)
	}
}

// An advisory that names a class stands for every method the class declares, its static
// initializer included: touching a static field of the class runs <clinit>, and the reach
// engine follows that, so leaving it out would narrow the sink set.
func TestResolveDependencySymbols_ClassAdvisoryExpandsToMethods(t *testing.T) {
	build := t.TempDir()
	if err := os.WriteFile(filepath.Join(build, "pom.xml"), []byte(netkitPom), 0o644); err != nil {
		t.Fatal(err)
	}
	writeNetkitOwnPom(t, build)
	b := &cpb{}
	classBytes := emitClass(b, "com/evil/netkit/UrlFetcher", []mspec{
		{"<init>", "()V", []byte{0xB1}},
		{"<clinit>", "()V", []byte{0xB1}},
		{"fetch", "(Ljava/lang/String;)Ljava/lang/String;", []byte{0xB1}},
	})
	writeJar(t, filepath.Join(build, ".m2", "repository", "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.jar"), "com/evil/netkit/UrlFetcher.class", classBytes)

	res := resolveNetkit(t, build, "com.evil.netkit.UrlFetcher")
	want := []string{
		depEdgeSymbol(classfile.MethodRef{Owner: "com/evil/netkit/UrlFetcher", Name: "<init>", Descriptor: "()V"}),
		depEdgeSymbol(classfile.MethodRef{Owner: "com/evil/netkit/UrlFetcher", Name: "<clinit>", Descriptor: "()V"}),
		depEdgeSymbol(netkitFetch),
	}
	sort.Strings(want)
	if got := scips(res.Resolved); !reflect.DeepEqual(got, want) {
		t.Fatalf("resolved %v, want %v", got, want)
	}
	for _, s := range res.Resolved {
		if s.Name == "<init>" && s.Kind != plugin.SymbolKindConstructor {
			t.Errorf("<init> kind = %s, want constructor", s.Kind)
		}
	}
}

// netkit's JAR is the advisory package's code. Present, it is read and costs nothing. Missing,
// it is scoped to netkit and bounded by netkit, everything netkit's code can call (including
// the optional, provided and profile dependencies Maven leaves out of the transitive graph),
// and first-party code, which netkit can call back into. Without netkit's POM that closure is
// unknown, so Targets is nil, never a closure guessed from the edges. Until the gate reads
// Scoped, every scoped reason is carried run-wide too, or the gate never sees it.
func TestResolveDependencySymbols_ScopedNoDependencyArtifact(t *testing.T) {
	for _, tc := range []struct {
		name        string
		jar, ownPom bool
		wantScoped  bool
		wantTargets []string
	}{
		{name: "jar present", jar: true, ownPom: true},
		{name: "jar missing, closure known", ownPom: true, wantScoped: true,
			wantTargets: []string{"", "pkg:maven/com.dep/optdep", "pkg:maven/com.dep/profdep", "pkg:maven/com.dep/provdep", netkitPURL}},
		{name: "jar missing, metadata missing", wantScoped: true, wantTargets: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := buildNetkitFixture(t, !tc.jar)
			if tc.ownPom {
				writeNetkitOwnPom(t, build)
			}
			res := resolveNetkit(t, build, "com.evil.netkit.UrlFetcher.fetch")
			if !tc.wantScoped {
				if !res.Partiality.Complete || len(res.Partiality.Scoped) != 0 || len(res.Resolved) != 1 {
					t.Fatalf("want one resolved symbol and complete partiality, got %+v", res)
				}
				return
			}
			if len(res.Resolved) != 0 || res.Partiality.Complete {
				t.Fatalf("want unresolved and partial, got %+v", res)
			}
			if !reflect.DeepEqual(res.Partiality.Reasons, []string{reasonNoDependencyArtifact}) {
				t.Errorf("run-wide mirror = %v, want [%s]", res.Partiality.Reasons, reasonNoDependencyArtifact)
			}
			if len(res.Partiality.Scoped) != 1 {
				t.Fatalf("want one scoped reason, got %+v", res.Partiality.Scoped)
			}
			sr := res.Partiality.Scoped[0]
			if sr.Reason != reasonNoDependencyArtifact || sr.Package != netkitPURL || sr.Path != "com.evil:netkit:1.0.0" {
				t.Errorf("scoped reason = %+v", sr)
			}
			if !reflect.DeepEqual(sr.Targets, tc.wantTargets) {
				t.Errorf("targets = %q, want %q", sr.Targets, tc.wantTargets)
			}
		})
	}
}

// A coordinate the build never resolved has no JAR to read: scoped, unbounded.
func TestResolveDependencySymbols_UnknownCoordinate(t *testing.T) {
	build := buildNetkitFixture(t, false)
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir: build, PURL: "pkg:maven/org.yaml/snakeyaml", AdvisorySymbols: []string{"org.yaml.snakeyaml.Yaml.load"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Resolved) != 0 || len(res.Partiality.Scoped) != 1 || res.Partiality.Scoped[0].Package != "pkg:maven/org.yaml/snakeyaml" || res.Partiality.Scoped[0].Targets != nil {
		t.Errorf("got %+v", res)
	}
}

// An advisory against the project's own module keeps matching first-party source.
func TestResolveDependencySymbols_RootPackageMatchesFirstParty(t *testing.T) {
	build := buildNetkitFixture(t, false)
	withFirstPartySource(t, build, "src/main/java/com/acme/Client.java", `package com.acme;
public class Client {
  public String fetch(String u) { return u; }
}
`)
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir: build, PURL: "pkg:maven/com.acme/app@1.0.0", AdvisorySymbols: []string{"com.acme.Client.fetch"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Resolved) != 1 || res.Resolved[0].Package == "com.evil:netkit" || len(res.Origins) != 0 {
		t.Errorf("want the first-party Client.fetch with no origin, got %+v", res)
	}
}

// realPath is path with every symlink resolved: what locateArtifactJar returns.
func realPath(t *testing.T, path string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A JAR found only in the Gradle module cache resolves the same way.
func TestLocateArtifactJar_GradleCache(t *testing.T) {
	build := t.TempDir()
	jar := filepath.Join(build, ".gradle", "caches", "modules-2", "files-2.1", "com.evil", "netkit", "1.0.0", "0a1b2c", "netkit-1.0.0.jar")
	writeJar(t, jar, "com/evil/netkit/UrlFetcher.class", emitClass(&cpb{}, "com/evil/netkit/UrlFetcher", nil))
	got, found := locateArtifactJar(build, "com.evil:netkit", "1.0.0")
	if found != jarFound || got != realPath(t, jar) {
		t.Errorf("locateArtifactJar = %q, %v; want %q", got, found, jar)
	}
	if _, found := locateArtifactJar(build, "com.evil:netkit", "2.0.0"); found != jarMissing {
		t.Errorf("a version that is not cached: %v, want missing", found)
	}
}

// Copies in the Maven repository and the Gradle cache are compared whichever cache comes
// first: the same bytes resolve, different bytes resolve neither, and a copy that cannot be
// read, first or later, resolves neither and says so.
func TestLocateArtifactJar_ComparesEveryCache(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("file modes do not stop root reading a copy")
	}
	class := func(owner string) []byte { return emitClass(&cpb{}, owner, nil) }
	for _, tc := range []struct {
		name        string
		gradleOwner string
		unreadable  string // "m2" or "gradle"
		want        jarLookup
	}{
		{name: "same bytes", gradleOwner: "com/evil/netkit/UrlFetcher", want: jarFound},
		{name: "different bytes", gradleOwner: "com/evil/netkit/Other", want: jarCopiesDiffer},
		{name: "first copy unreadable", gradleOwner: "com/evil/netkit/UrlFetcher", unreadable: "m2", want: jarUnreadable},
		{name: "later copy unreadable", gradleOwner: "com/evil/netkit/UrlFetcher", unreadable: "gradle", want: jarUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := t.TempDir()
			copies := map[string]string{
				"m2":     filepath.Join(build, ".m2", "repository", "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.jar"),
				"gradle": filepath.Join(build, ".gradle", "caches", "modules-2", "files-2.1", "com.evil", "netkit", "1.0.0", "0a1b2c", "netkit-1.0.0.jar"),
			}
			writeJar(t, copies["m2"], "com/evil/netkit/UrlFetcher.class", class("com/evil/netkit/UrlFetcher"))
			writeJar(t, copies["gradle"], "com/evil/netkit/UrlFetcher.class", class(tc.gradleOwner))
			if tc.unreadable != "" {
				if err := os.Chmod(copies[tc.unreadable], 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(copies[tc.unreadable], 0o644) })
			}
			got, found := locateArtifactJar(build, "com.evil:netkit", "1.0.0")
			if found != tc.want || (found == jarFound) != (got != "") || (found == jarFound && got != realPath(t, copies["m2"])) {
				t.Fatalf("locateArtifactJar = %q, %v; want %v", got, found, tc.want)
			}
		})
	}
}

// A cached JAR is read only from inside the cache. A version or coordinate that walks out of
// it, or a cached copy that is a symlink out of it, is reported as a tool failure scoped to the
// package, never bound and reported complete. Links that stay inside the cache, and a cache root
// that is itself a symlink, are fine.
func TestLocateArtifactJar_StaysInsideTheCache(t *testing.T) {
	fetchJar := func(t *testing.T, path string) {
		t.Helper()
		b := &cpb{}
		writeJar(t, path, "com/evil/netkit/UrlFetcher.class", emitClass(b, "com/evil/netkit/UrlFetcher", []mspec{{"fetch", "(Ljava/lang/String;)Ljava/lang/String;", []byte{0xB1}}}))
	}
	m2Jar := func(build, version string) string {
		return filepath.Join(build, ".m2", "repository", "com", "evil", "netkit", version, "netkit-"+version+".jar")
	}
	symlink := func(t *testing.T, target, link string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	const traversal = "../../../../../planted/fake"
	for _, tc := range []struct {
		name    string
		version string
		setup   func(t *testing.T, build string)
		want    jarLookup
	}{
		{name: "version walks out of the cache", version: traversal, setup: func(t *testing.T, build string) {
			// Where a lexical join of the version lands: inside the build, outside the cache.
			fetchJar(t, filepath.Join(build, ".m2", "repository", "com", "evil", "netkit", traversal, "netkit-"+traversal+".jar"))
		}, want: jarUnreadable},
		{name: "cached jar links out of the cache", version: "1.0.0", setup: func(t *testing.T, build string) {
			outside := filepath.Join(t.TempDir(), "elsewhere.jar")
			fetchJar(t, outside)
			symlink(t, outside, m2Jar(build, "1.0.0"))
		}, want: jarUnreadable},
		{name: "gradle copy links out of the cache", version: "1.0.0", setup: func(t *testing.T, build string) {
			outside := filepath.Join(t.TempDir(), "elsewhere.jar")
			fetchJar(t, outside)
			symlink(t, outside, filepath.Join(build, ".gradle", "caches", "modules-2", "files-2.1", "com.evil", "netkit", "1.0.0", "0a1b2c", "netkit-1.0.0.jar"))
		}, want: jarUnreadable},
		{name: "version directory links out of the cache", version: "1.0.0", setup: func(t *testing.T, build string) {
			outside := t.TempDir()
			fetchJar(t, filepath.Join(outside, "netkit-1.0.0.jar"))
			symlink(t, outside, filepath.Dir(m2Jar(build, "1.0.0")))
		}, want: jarUnreadable},
		{name: "link inside the cache", version: "1.0.0", setup: func(t *testing.T, build string) {
			real := filepath.Join(build, ".m2", "repository", "blobs", "netkit.jar")
			fetchJar(t, real)
			symlink(t, real, m2Jar(build, "1.0.0"))
		}, want: jarFound},
		{name: "cache root is a symlink", version: "1.0.0", setup: func(t *testing.T, build string) {
			repo := t.TempDir()
			fetchJar(t, filepath.Join(repo, "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.jar"))
			symlink(t, repo, filepath.Join(build, ".m2", "repository"))
		}, want: jarFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := filepath.Join(t.TempDir(), "a", "b", "c", "d", "proj")
			if err := os.MkdirAll(build, 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(build, "pom.xml"), strings.Replace(netkitPom, "<artifactId>netkit</artifactId><version>1.0.0</version>",
				"<artifactId>netkit</artifactId><version>"+tc.version+"</version>", 1))
			tc.setup(t, build)
			writeNetkitOwnPom(t, build)

			if _, found := locateArtifactJar(build, "com.evil:netkit", tc.version); found != tc.want {
				t.Fatalf("locateArtifactJar = %v, want %v", found, tc.want)
			}
			res := resolveNetkit(t, build, "com.evil.netkit.UrlFetcher.fetch")
			if tc.want == jarFound {
				if !res.Partiality.Complete || len(res.Resolved) != 1 {
					t.Fatalf("want fetch resolved and complete, got %+v", res)
				}
				return
			}
			if len(res.Resolved) != 0 || res.Partiality.Complete {
				t.Fatalf("bound a JAR from outside the cache: %+v", res)
			}
			if len(res.Partiality.Scoped) != 1 || res.Partiality.Scoped[0].Reason != plugin.PartialReasonToolFailure || res.Partiality.Scoped[0].Package != netkitPURL {
				t.Errorf("want one scoped %s on %s, got %+v", plugin.PartialReasonToolFailure, netkitPURL, res.Partiality.Scoped)
			}
		})
	}
}

// A JAR that is there but cannot be read as a JAR, or holds a class that fails to parse, is a
// tool failure scoped to the package. Symbols from the classes that did parse still resolve.
func TestResolveDependencySymbols_UnreadableJarIsScopedToolFailure(t *testing.T) {
	jarPath := func(build string) string {
		return filepath.Join(build, ".m2", "repository", "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.jar")
	}
	for _, tc := range []struct {
		name         string
		write        func(t *testing.T, path string)
		wantResolved int
		wantPath     string
	}{
		{name: "not a zip", write: func(t *testing.T, path string) {
			writeFile(t, path, "not a jar")
		}, wantPath: "netkit-1.0.0.jar"},
		{name: "a class fails to parse", write: func(t *testing.T, path string) {
			b := &cpb{}
			writeJarEntries(t, path, map[string][]byte{
				"com/evil/netkit/UrlFetcher.class": emitClass(b, "com/evil/netkit/UrlFetcher", []mspec{{"fetch", "(Ljava/lang/String;)Ljava/lang/String;", []byte{0xB1}}}),
				"com/evil/netkit/Broken.class":     {0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00},
			})
		}, wantResolved: 1, wantPath: "netkit-1.0.0.jar!com/evil/netkit/Broken.class"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := buildNetkitFixture(t, true)
			writeNetkitOwnPom(t, build)
			tc.write(t, jarPath(build))
			res := resolveNetkit(t, build, "com.evil.netkit.UrlFetcher.fetch")
			if len(res.Resolved) != tc.wantResolved || res.Partiality.Complete {
				t.Fatalf("want %d resolved and partial, got %+v", tc.wantResolved, res)
			}
			if len(res.Partiality.Scoped) != 1 {
				t.Fatalf("want one scoped reason, got %+v", res.Partiality.Scoped)
			}
			sr := res.Partiality.Scoped[0]
			if sr.Reason != plugin.PartialReasonToolFailure || sr.Package != netkitPURL || sr.Path != tc.wantPath {
				t.Errorf("scoped reason = %+v, want %s on %s at %q", sr, plugin.PartialReasonToolFailure, netkitPURL, tc.wantPath)
			}
			if !slices.Contains(res.Partiality.Reasons, plugin.PartialReasonToolFailure) {
				t.Errorf("run-wide mirror missing: %v", res.Partiality.Reasons)
			}
		})
	}
}

// A symbol short of the full binary name resolves nothing, even when the JAR holds exactly
// one method it could mean: the JAR can also hold a lookalike, and a partial form cannot tell
// the two apart. The miss is reported, so the advisory is never cleared on it.
func TestResolveDependencySymbols_PartialNameStaysUnresolved(t *testing.T) {
	build := t.TempDir()
	if err := os.WriteFile(filepath.Join(build, "pom.xml"), []byte(netkitPom), 0o644); err != nil {
		t.Fatal(err)
	}
	writeNetkitOwnPom(t, build)
	b := &cpb{}
	real := emitClass(b, "com/evil/netkit/UrlFetcher", []mspec{{"fetch", "(Ljava/lang/String;)Ljava/lang/String;", []byte{0xB1}}})
	b2 := &cpb{}
	lookalike := emitClass(b2, "com/evil/netkit/shaded/UrlFetcher", []mspec{{"fetch", "(Ljava/lang/String;)Ljava/lang/String;", []byte{0xB1}}})
	writeJarEntries(t, filepath.Join(build, ".m2", "repository", "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.jar"), map[string][]byte{
		"com/evil/netkit/UrlFetcher.class":        real,
		"com/evil/netkit/shaded/UrlFetcher.class": lookalike,
	})

	for _, advisory := range []string{"UrlFetcher.fetch", "fetch", "netkit.UrlFetcher.fetch", "UrlFetcher"} {
		t.Run(advisory, func(t *testing.T) {
			res := resolveNetkit(t, build, advisory)
			if len(res.Resolved) != 0 || len(res.Matched) != 0 {
				t.Errorf("partial form resolved: %v", scips(res.Resolved))
			}
			if !reflect.DeepEqual(res.Partiality.Reasons, []string{reasonAdvisorySymbolUnresolved}) {
				t.Errorf("want %s, got %+v", reasonAdvisorySymbolUnresolved, res.Partiality)
			}
		})
	}

	res := resolveNetkit(t, build, "com.evil.netkit.UrlFetcher.fetch")
	if got := scips(res.Resolved); !reflect.DeepEqual(got, []string{depEdgeSymbol(netkitFetch)}) {
		t.Errorf("full name resolved %v, want only the unshaded fetch", got)
	}
}

// Only the version the build resolved is read. A different version in the cache is not the
// code the build runs: it neither resolves the advisory nor stands in for the missing JAR,
// even when the advisory PURL names that version.
func TestResolveDependencySymbols_ReadsOnlyTheResolvedVersion(t *testing.T) {
	build := buildNetkitFixture(t, true) // the pom resolves netkit 1.0.0, whose JAR is absent
	writeNetkitOwnPom(t, build)
	b := &cpb{}
	other := emitClass(b, "com/evil/netkit/UrlFetcher", []mspec{{"fetch", "(Ljava/lang/String;)Ljava/lang/String;", []byte{0xB1}}})
	writeJar(t, filepath.Join(build, ".m2", "repository", "com", "evil", "netkit", "2.0.0", "netkit-2.0.0.jar"), "com/evil/netkit/UrlFetcher.class", other)

	for _, purl := range []string{netkitPURL, netkitPURL + "@2.0.0"} {
		t.Run(purl, func(t *testing.T) {
			res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
				BuildDir: build, PURL: purl, AdvisorySymbols: []string{"com.evil.netkit.UrlFetcher.fetch"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Resolved) != 0 {
				t.Errorf("resolved from a version the build does not use: %v", scips(res.Resolved))
			}
			if len(res.Partiality.Scoped) != 1 || res.Partiality.Scoped[0].Reason != reasonNoDependencyArtifact || res.Partiality.Scoped[0].Path != "com.evil:netkit:1.0.0" {
				t.Errorf("want the resolved version's JAR reported missing, got %+v", res.Partiality)
			}
		})
	}
}

// A dependency declared with a classifier (or a non-jar type) uses a different file than the
// main JAR, so the main JAR is not read in its place: the advisory stays unresolved, scoped.
func TestResolveDependencySymbols_ClassifierVariantIsNotBound(t *testing.T) {
	build := buildNetkitFixture(t, false)
	writeNetkitOwnPom(t, build)
	pom := strings.Replace(netkitPom, "<version>1.0.0</version>\n    </dependency>", "<version>1.0.0</version><classifier>jdk8</classifier>\n    </dependency>", 1)
	if pom == netkitPom {
		t.Fatal("fixture: classifier not inserted")
	}
	if err := os.WriteFile(filepath.Join(build, "pom.xml"), []byte(pom), 0o644); err != nil {
		t.Fatal(err)
	}

	res := resolveNetkit(t, build, "com.evil.netkit.UrlFetcher.fetch")
	if len(res.Resolved) != 0 {
		t.Errorf("main JAR read for a classifier dependency: %v", scips(res.Resolved))
	}
	if len(res.Partiality.Scoped) != 1 || res.Partiality.Scoped[0].Reason != reasonNoDependencyArtifact || res.Partiality.Scoped[0].Package != netkitPURL {
		t.Errorf("want scoped no_dependency_artifact for netkit, got %+v", res.Partiality)
	}
	if !slices.Contains(res.Partiality.Reasons, reasonNoDependencyArtifact) {
		t.Errorf("run-wide reasons miss the variant: %v", res.Partiality.Reasons)
	}
}

func TestNormalizeAdvisorySymbol(t *testing.T) {
	for in, want := range map[string]string{
		"com.fasterxml.jackson.databind.ObjectMapper.readValue":      "com.fasterxml.jackson.databind.ObjectMapper.readValue",
		"com.fasterxml.jackson.databind.ObjectMapper#readValue":      "com.fasterxml.jackson.databind.ObjectMapper.readValue",
		"org.apache.logging.log4j.core.lookup.JndiLookup$Inner.m(2)": "org.apache.logging.log4j.core.lookup.JndiLookup.Inner.m",
		" com.a.B.c ": "com.a.B.c",
		"":            "",
	} {
		if got := normalizeAdvisorySymbol(in); got != want {
			t.Errorf("normalizeAdvisorySymbol(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCoordinateOfPURL(t *testing.T) {
	for _, tc := range []struct {
		purl, coord, version string
		ok                   bool
	}{
		{"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10", "com.fasterxml.jackson.core:jackson-databind", "2.9.10", true},
		{"pkg:maven/org.yaml/snakeyaml", "org.yaml:snakeyaml", "", true},
		{"pkg:maven/org.yaml/snakeyaml@1.33?type=jar", "org.yaml:snakeyaml", "1.33", true},
		{"pkg:npm/lodash@4.17.0", "", "", false},
		{"pkg:maven/snakeyaml", "", "", false},
		{"", "", "", false},
	} {
		c, v, ok := coordinateOfPURL(tc.purl)
		if c != tc.coord || v != tc.version || ok != tc.ok {
			t.Errorf("coordinateOfPURL(%q) = %q, %q, %v", tc.purl, c, v, ok)
		}
	}
}

// writeJarEntries writes a JAR holding each named entry, in name order.
func writeJarEntries(t *testing.T, path string, entries map[string][]byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entries[n]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
