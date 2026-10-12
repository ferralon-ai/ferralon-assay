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

// An advisory that names a class stands for every method the class declares; its static
// initializer runs on class load and is not a call target.
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

// A cached POM but no JAR: the gap is scoped to netkit and bounded by everything netkit's
// code can call, including the optional, provided and profile dependencies Maven leaves
// out of the transitive graph.
func TestResolveDependencySymbols_MissingJarIsScopedToItsClosure(t *testing.T) {
	build := buildNetkitFixture(t, true)
	writeNetkitOwnPom(t, build)

	res := resolveNetkit(t, build, "com.evil.netkit.UrlFetcher.fetch")
	if len(res.Resolved) != 0 || res.Partiality.Complete {
		t.Fatalf("want unresolved and partial, got %+v", res)
	}
	// Until the gate reads Scoped, the miss is carried run-wide too, or the gate never sees it.
	if !reflect.DeepEqual(res.Partiality.Reasons, []string{reasonNoDependencyArtifact}) {
		t.Errorf("run-wide reasons = %v, want [%s]", res.Partiality.Reasons, reasonNoDependencyArtifact)
	}
	if len(res.Partiality.Scoped) != 1 {
		t.Fatalf("want one scoped reason, got %+v", res.Partiality.Scoped)
	}
	sr := res.Partiality.Scoped[0]
	if sr.Reason != reasonNoDependencyArtifact || sr.Package != netkitPURL {
		t.Errorf("scoped reason = %+v", sr)
	}
	wantTargets := []string{"pkg:maven/com.dep/optdep", "pkg:maven/com.dep/profdep", "pkg:maven/com.dep/provdep", netkitPURL}
	if !reflect.DeepEqual(sr.Targets, wantTargets) {
		t.Errorf("targets = %v, want %v", sr.Targets, wantTargets)
	}
}

// Without netkit's POM its declared dependencies are unknown, so nothing bounds what its
// code can call: Targets is nil (unbounded), never a closure guessed from the edges.
func TestResolveDependencySymbols_UnreadableClosureIsUnbounded(t *testing.T) {
	build := buildNetkitFixture(t, true)

	res := resolveNetkit(t, build, "com.evil.netkit.UrlFetcher.fetch")
	if len(res.Partiality.Scoped) != 1 {
		t.Fatalf("want one scoped reason, got %+v", res.Partiality)
	}
	if sr := res.Partiality.Scoped[0]; sr.Targets != nil || sr.Package != netkitPURL || sr.Reason != reasonNoDependencyArtifact {
		t.Errorf("want unbounded no_dependency_artifact for netkit, got %+v", sr)
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

// A JAR found only in the Gradle module cache resolves the same way.
func TestLocateArtifactJar_GradleCache(t *testing.T) {
	build := t.TempDir()
	jar := filepath.Join(build, ".gradle", "caches", "modules-2", "files-2.1", "com.evil", "netkit", "1.0.0", "0a1b2c", "netkit-1.0.0.jar")
	writeJar(t, jar, "com/evil/netkit/UrlFetcher.class", emitClass(&cpb{}, "com/evil/netkit/UrlFetcher", nil))
	got, ok := locateArtifactJar(build, "com.evil:netkit", "1.0.0")
	if !ok || got != jar {
		t.Errorf("locateArtifactJar = %q, %v; want %q", got, ok, jar)
	}
	if _, ok := locateArtifactJar(build, "com.evil:netkit", "2.0.0"); ok {
		t.Error("located a version that is not cached")
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
