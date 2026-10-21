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
	"testing"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const netkitPURL = "pkg:maven/com.evil/netkit"

var netkitFetch = classfile.MethodRef{Owner: "com/evil/netkit/UrlFetcher", Name: "fetch", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;"}

// resolveNetkit resolves symbols against netkit under the graph naming netkit's JAR.
func resolveNetkit(t *testing.T, build string, symbols ...string) plugin.SymbolResolutionResult {
	t.Helper()
	return resolveUnder(t, build, netkitPURL, netkitGraph(t, build), symbols...)
}

func resolveUnder(t *testing.T, build, purl string, graph Option, symbols ...string) plugin.SymbolResolutionResult {
	t.Helper()
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir: build, PURL: purl, AdvisorySymbols: symbols,
	}, graph)
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

// netkit's JAR is the advisory package's code. Present, it is read and costs nothing. Named by
// the graph but gone, it is a tool_failure scoped to netkit and bounded by everything the build
// resolved beside it and first-party code, which netkit can call back into. A coordinate a
// complete graph lacks is not a dependency: dependency_not_in_build, bounded to netkit alone and
// never run-wide, so it holds no other advisory. Beside a build of the other tool the graph is not
// complete, and the coordinate stays an unbounded no_dependency_artifact. Until the gate reads
// Scoped, every other scoped reason is carried run-wide too, or the gate never sees it.
func TestResolveDependencySymbols_ScopedMisses(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		purl                    string // "" ⇒ netkit's
		jar, inGraph, otherTool bool
		unlisted                bool // the graph's module installs something it does not list
		multi                   bool // the graph holds a second module with sources
		wantReason              string
		wantRunWide             []string
		wantPath                string
		wantTargets             []string
	}{
		{name: "jar present", jar: true, inGraph: true},
		{name: "jar gone", inGraph: true, wantReason: plugin.PartialReasonToolFailure, wantRunWide: []string{plugin.PartialReasonToolFailure},
			wantPath: "com.evil:netkit:1.0.0: netkit-1.0.0.jar unreadable or changed since the build resolved it", wantTargets: []string{"", netkitPURL}},
		{name: "not resolved by the build", jar: true, wantReason: PartialReasonDependencyNotInBuild,
			wantPath: "com.evil:netkit", wantTargets: []string{netkitPURL}},
		{name: "not resolved by a multi-module build", jar: true, multi: true, wantReason: PartialReasonDependencyNotInBuild,
			wantPath: "com.evil:netkit", wantTargets: []string{netkitPURL}},
		{name: "not resolved beside a build of the other tool", jar: true, otherTool: true, wantReason: reasonNoDependencyArtifact,
			wantRunWide: []string{reasonNoDependencyArtifact}, wantPath: "com.evil:netkit"},
		{name: "not resolved by a build installing what its graph does not list", jar: true, unlisted: true, wantReason: reasonNoDependencyArtifact,
			wantRunWide: []string{reasonNoDependencyArtifact}, wantPath: "com.evil:netkit"},
		// The version lane matches either way, so the symbol lane must too.
		{name: "another case", purl: "pkg:maven/com.Evil/NetKit@1.0.0", jar: true, inGraph: true},
		{name: "a subpath", purl: "pkg:maven/com.evil/netkit@1.0.0#sub", jar: true, inGraph: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := buildNetkitFixture(t, !tc.jar)
			graph := netkitGraph(t, build)
			if !tc.inGraph {
				m := testModule(t, ".", "app")
				if tc.unlisted {
					m.Unlisted = []string{"maven-dependency-plugin execution copy-agent"}
				}
				mods := []buildgraph.Module{m}
				if tc.multi {
					for _, d := range []string{"src", filepath.Join("lib", "src")} {
						if err := os.MkdirAll(filepath.Join(build, d), 0o755); err != nil {
							t.Fatal(err)
						}
					}
					mods = append(mods, testModule(t, "lib", "lib"))
				}
				graph = graphOption(t, "maven", mods...)
			}
			if tc.otherTool {
				if err := os.WriteFile(filepath.Join(build, "build.gradle"), []byte("plugins { id 'java' }\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			purl := tc.purl
			if purl == "" {
				purl = netkitPURL
			}
			res := resolveUnder(t, build, purl, graph, "com.evil.netkit.UrlFetcher.fetch")
			if tc.wantReason == "" {
				if !res.Partiality.Complete || len(res.Partiality.Scoped) != 0 || len(res.Resolved) != 1 {
					t.Fatalf("want one resolved symbol and complete partiality, got %+v", res)
				}
				return
			}
			if len(res.Resolved) != 0 || res.Partiality.Complete {
				t.Fatalf("want unresolved and partial, got %+v", res)
			}
			if !reflect.DeepEqual(res.Partiality.Reasons, tc.wantRunWide) {
				t.Errorf("run-wide mirror = %v, want %v", res.Partiality.Reasons, tc.wantRunWide)
			}
			if len(res.Partiality.Scoped) != 1 {
				t.Fatalf("want one scoped reason, got %+v", res.Partiality.Scoped)
			}
			sr := res.Partiality.Scoped[0]
			if sr.Reason != tc.wantReason || sr.Package != netkitPURL || sr.Path != tc.wantPath {
				t.Errorf("scoped reason = %+v", sr)
			}
			if !reflect.DeepEqual(sr.Targets, tc.wantTargets) {
				t.Errorf("targets = %q, want %q", sr.Targets, tc.wantTargets)
			}
		})
	}
}

// Without a build graph nothing is known about a dependency's code.
func TestResolveDependencySymbols_NoGraph(t *testing.T) {
	build := buildNetkitFixture(t, false)
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir: build, PURL: netkitPURL, AdvisorySymbols: []string{"com.evil.netkit.UrlFetcher.fetch"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Resolved) != 0 || !reflect.DeepEqual(res.Partiality.Reasons, []string{PartialReasonBuildGraphAbsent}) {
		t.Errorf("want unresolved with %s, got %+v", PartialReasonBuildGraphAbsent, res)
	}
}

// A coordinate a complete graph lacks is a known absence of that package alone, never a tool
// failure.
func TestResolveDependencySymbols_UnknownCoordinate(t *testing.T) {
	build := buildNetkitFixture(t, false)
	res := resolveUnder(t, build, "pkg:maven/org.yaml/snakeyaml", netkitGraph(t, build), "org.yaml.snakeyaml.Yaml.load")
	want := []plugin.ScopedReason{{Reason: PartialReasonDependencyNotInBuild, Package: "pkg:maven/org.yaml/snakeyaml", Path: "org.yaml:snakeyaml", Targets: []string{"pkg:maven/org.yaml/snakeyaml"}}}
	if len(res.Resolved) != 0 || res.Partiality.Complete || len(res.Partiality.Reasons) != 0 || !reflect.DeepEqual(res.Partiality.Scoped, want) {
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
	res := resolveUnder(t, build, "pkg:maven/com.example/app@1", netkitGraph(t, build), "com.acme.Client.fetch")
	if len(res.Resolved) != 1 || res.Resolved[0].Package == "com.evil:netkit" || len(res.Origins) != 0 {
		t.Errorf("want the first-party Client.fetch with no origin, got %+v", res)
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

// Every version of the coordinate the build resolved is read, one per module here, and a gone
// JAR for either is reported.
func TestResolveDependencySymbols_EveryResolvedVersionIsRead(t *testing.T) {
	build := buildNetkitFixture(t, false)
	gone := filepath.Join(build, ".m2", "repository", "com", "evil", "netkit", "2.0.0", "netkit-2.0.0.jar")
	graph := graphOption(t, "gradle",
		testModule(t, "a", "a", graphDep{group: "com.evil", artifact: "netkit", version: "1.0.0", jar: netkitJarPath(build)}),
		testModule(t, "b", "b", graphDep{group: "com.evil", artifact: "netkit", version: "2.0.0", jar: gone}))

	res := resolveUnder(t, build, netkitPURL, graph, "com.evil.netkit.UrlFetcher.fetch")
	if len(res.Resolved) != 1 || res.Partiality.Complete {
		t.Fatalf("want 1.0.0's fetch resolved and 2.0.0's gone JAR reported, got %+v", res)
	}
	var paths []string
	for _, sr := range res.Partiality.Scoped {
		if sr.Reason == plugin.PartialReasonToolFailure && sr.Package == netkitPURL {
			paths = append(paths, sr.Path)
		}
	}
	if want := []string{"com.evil:netkit:2.0.0: netkit-2.0.0.jar unreadable or changed since the build resolved it"}; !reflect.DeepEqual(paths, want) {
		t.Errorf("scoped tool_failure paths = %v, want %v", paths, want)
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
	build := buildNetkitFixture(t, true) // the graph resolves netkit 1.0.0, whose JAR is absent
	b := &cpb{}
	other := emitClass(b, "com/evil/netkit/UrlFetcher", []mspec{{"fetch", "(Ljava/lang/String;)Ljava/lang/String;", []byte{0xB1}}})
	writeJar(t, filepath.Join(build, ".m2", "repository", "com", "evil", "netkit", "2.0.0", "netkit-2.0.0.jar"), "com/evil/netkit/UrlFetcher.class", other)

	for _, purl := range []string{netkitPURL, netkitPURL + "@2.0.0"} {
		t.Run(purl, func(t *testing.T) {
			res := resolveUnder(t, build, purl, netkitGraph(t, build), "com.evil.netkit.UrlFetcher.fetch")
			if len(res.Resolved) != 0 {
				t.Errorf("resolved from a version the build does not use: %v", scips(res.Resolved))
			}
			if len(res.Partiality.Scoped) != 1 || res.Partiality.Scoped[0].Reason != plugin.PartialReasonToolFailure ||
				res.Partiality.Scoped[0].Path != "com.evil:netkit:1.0.0: netkit-1.0.0.jar unreadable or changed since the build resolved it" {
				t.Errorf("want the resolved version's JAR reported missing, got %+v", res.Partiality)
			}
		})
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
		c, v, ok := CoordinateOfPURL(tc.purl)
		if c != tc.coord || v != tc.version || ok != tc.ok {
			t.Errorf("CoordinateOfPURL(%q) = %q, %q, %v", tc.purl, c, v, ok)
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

// A reactor sibling is a module the build is, so the symbol lane never calls it absent.
func TestResolveDependencySymbols_ReactorCoordinate(t *testing.T) {
	build := buildNetkitFixture(t, false)
	src := filepath.Join(build, "src", "main", "java", "com", "example", "core")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "Core.java"), []byte("package com.example.core;\n\npublic class Core {\n    public void run() {}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := testModule(t, ".", "app")
	core := testModule(t, ".", "core")
	app.Nodes = append(app.Nodes, buildgraph.Node{ID: core.Root, Group: "com.example", Artifact: "core", Version: "1", Type: "jar", Scope: "compile"})
	app.Edges = append(app.Edges, buildgraph.Edge{From: app.Root, To: core.Root})
	res := resolveUnder(t, build, "pkg:maven/com.example/core", graphOption(t, "maven", app, core), "com.example.core.Core.run")
	for _, sr := range res.Partiality.Scoped {
		if sr.Reason == PartialReasonDependencyNotInBuild {
			t.Fatalf("reactor sibling declared not in the build: %+v", res.Partiality)
		}
	}
}
