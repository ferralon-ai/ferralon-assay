package dotnetanalysis

// depsymbols_test.go — resolving a NuGet advisory's symbols inside the package's restored
// assemblies. Every dll is a synthesized PE (the peb builder); the package folder is a temp
// dir named by project.assets.json's packageFolders, so nothing reads a real NuGet cache.

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const (
	xCustomAttribute = 0x0C
	xNestedClass     = 0x29
)

var (
	sigStaticStringToObject = []byte{0x00, 0x01, 0x1C, 0x0E} // static object M(string)
	sigStaticIntVoid        = []byte{0x00, 0x01, 0x01, 0x08} // static void M(int)
	sigStaticStringVoid     = []byte{0x00, 0x01, 0x01, 0x0E} // static void M(string)
	sigInstGetObject        = []byte{0x20, 0x00, 0x1C}       // instance object get_X()
)

// markReferenceAssembly adds [assembly: ReferenceAssembly] — the attribute the SDK stamps on
// ref/ compile assets, whose method bodies are stubs.
func (b *peb) markReferenceAssembly() {
	attr := b.extTypeRef("System.Runtime.CompilerServices", "ReferenceAssemblyAttribute")
	ctor := b.memberRef(attr, ".ctor", sigInstVoid)
	const hasCustomAttributeAssembly = 14
	b.row(xCustomAttribute, 1<<5|hasCustomAttributeAssembly, (ctor&0xFFFFFF)<<3|3, b.blob([]byte{0x01, 0x00, 0x00, 0x00}))
}

// newtonsoftLike builds an assembly "Newtonsoft.Json" with the shapes an advisory names:
// a static method, a constructor, a property accessor, a nested type's method and a generic
// type's method. Bodies are empty.
func newtonsoftLike(refAsm bool) []byte {
	b := scaffold()
	obj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	b.addType(0, "<Module>", "", 0, nil)
	b.addType(0x1, "JsonConvert", "Newtonsoft.Json", obj, []mspec{
		{name: "DeserializeObject", flags: 0x16, sig: sigStaticStringToObject, il: body()},
		{name: "SerializeObject", flags: 0x16, sig: sigStaticStringToObject, il: body()},
	})
	if !refAsm {
		// A reference assembly declares the API surface too, so only the real one carries
		// these; the stub reading as code would be the false negative this guards.
		b.addType(0x1, "JObject", "Newtonsoft.Json.Linq", obj, []mspec{
			{name: ".ctor", flags: 0x1806, sig: sigInstVoid, il: body()},
			{name: "Parse", flags: 0x16, sig: sigStaticStringToObject, il: body()},
			{name: "get_Root", flags: 0x0806, sig: sigInstGetObject, il: body()},
		})
		outer, _ := b.addType(0x1, "Outer", "Newtonsoft.Json", obj, nil)
		inner, _ := b.addType(0x2, "Inner", "", obj, []mspec{{name: "Run", flags: 0x16, sig: sigStaticVoid, il: body()}})
		b.row(xNestedClass, inner, outer)
		b.addType(0x1, "Box`1", "Newtonsoft.Json", obj, []mspec{{name: "Get", flags: 0x16, sig: sigStaticVoid, il: body()}})
	}
	if refAsm {
		b.markReferenceAssembly()
	}
	return b.bytesNamed("Newtonsoft.Json")
}

// depFixture is a build dir plus an out-of-tree NuGet package folder.
type depFixture struct {
	buildDir string
	pkgRoot  string
}

// writePkgFile places a file under the package folder (relative to the package root).
func (f depFixture) writePkgFile(t *testing.T, rel string, data []byte) {
	t.Helper()
	p := filepath.Join(f.pkgRoot, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// newDepFixture writes a first-party project whose source declares its own
// Newtonsoft.Json.JsonConvert.DeserializeObject (the leaf-name decoy) and an assets file
// built from targetsJSON/librariesJSON with the package folder as its only root.
func newDepFixture(t *testing.T, targetsJSON, librariesJSON string) depFixture {
	t.Helper()
	t.Setenv("NUGET_PACKAGES", t.TempDir())
	pkgRoot := t.TempDir()
	assets := `{"version":3,"targets":{"net8.0":{` + targetsJSON + `}},"libraries":{` + librariesJSON + `},` +
		`"packageFolders":{"` + filepath.ToSlash(pkgRoot) + `/":{}}}`
	dir := composeILBuildDir(t, map[string][]byte{
		"App.csproj": restoredProject,
		"Decoy.cs": []byte(`namespace Newtonsoft.Json { public static class JsonConvert {
	public static object DeserializeObject(string s) { return null; } } }
namespace App { public static class Json { public static object DeserializeObject(string s) { return null; } } }
`),
		"obj/project.assets.json": []byte(assets),
	})
	return depFixture{buildDir: dir, pkgRoot: pkgRoot}
}

const newtonsoftLib = `"Newtonsoft.Json/12.0.3":{"type":"package","path":"newtonsoft.json/12.0.3"}`

func resolveNewtonsoft(t *testing.T, f depFixture, symbols ...string) plugin.SymbolResolutionResult {
	t.Helper()
	res, err := ResolveDependencySymbols(t.Context(), plugin.ResolveSymbolsRequest{
		BuildDir: f.buildDir, PURL: "pkg:nuget/Newtonsoft.Json@12.0.3", AdvisorySymbols: symbols,
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	return res
}

var (
	scipDeserialize = funcSCIP("Newtonsoft.Json", []string{"JsonConvert"}, "DeserializeObject", 1)
	scipJObjectCtor = funcSCIP("Newtonsoft.Json.Linq", []string{"JObject"}, ".ctor", 0)
	scipJObjectRoot = funcSCIP("Newtonsoft.Json.Linq", []string{"JObject"}, "get_Root", 0)
	scipParse       = funcSCIP("Newtonsoft.Json.Linq", []string{"JObject"}, "Parse", 1)
	scipInnerRun    = funcSCIP("Newtonsoft.Json", []string{"Outer", "Inner"}, "Run", 0)
	scipBoxGet      = funcSCIP("Newtonsoft.Json", []string{"Box"}, "Get", 0)
)

// TestResolveDependencySymbols_MatchesPackageCode: each advisory symbol resolves to the
// package's own method, keyed verbatim in Matched, with Origins naming the package and
// Symbol.Package the NuGet id. The first-party decoy with the same qualified name is never
// read, and a bare member name matches nothing.
func TestResolveDependencySymbols_MatchesPackageCode(t *testing.T) {
	f := newDepFixture(t,
		`"Newtonsoft.Json/12.0.3":{"type":"package","runtime":{"lib/net8.0/Newtonsoft.Json.dll":{}}}`,
		newtonsoftLib)
	f.writePkgFile(t, "newtonsoft.json/12.0.3/lib/net8.0/Newtonsoft.Json.dll", newtonsoftLike(false))

	cases := []struct {
		symbol string
		want   []string // nil = must be absent from Matched
	}{
		{"Newtonsoft.Json.JsonConvert.DeserializeObject", []string{scipDeserialize}},
		{"JsonConvert.DeserializeObject(String)", []string{scipDeserialize}},
		{"Json.JsonConvert.DeserializeObject", []string{scipDeserialize}},
		{"Newtonsoft.Json.Linq.JObject::Parse", []string{scipParse}},
		{"Newtonsoft.Json.Linq.JObject.JObject", []string{scipJObjectCtor}},
		{"JObject.Root", []string{scipJObjectRoot}},
		{"Newtonsoft.Json.Outer.Inner.Run", []string{scipInnerRun}},
		{"Outer+Inner.Run", nil}, // metadata '+' spelling is not a C# source name
		{"Newtonsoft.Json.Box<T>.Get", []string{scipBoxGet}},
		{"Newtonsoft.Json.Box`1.Get", []string{scipBoxGet}},
		{"DeserializeObject", nil},
		{"Newtonsoft.Json.JsonConvert.PopulateObject", nil},
	}
	var symbols []string
	for _, c := range cases {
		symbols = append(symbols, c.symbol)
	}
	res := resolveNewtonsoft(t, f, symbols...)

	for _, c := range cases {
		got, ok := res.Matched[c.symbol]
		if c.want == nil {
			if ok {
				t.Errorf("Matched[%q] = %v, want absent", c.symbol, got)
			}
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Matched[%q] = %v, want %v", c.symbol, got, c.want)
		}
	}
	for _, s := range res.Resolved {
		if s.Package != "Newtonsoft.Json" {
			t.Errorf("Resolved %s: Package = %q, want the NuGet id", s.SCIP, s.Package)
		}
		if res.Origins[s.SCIP] != "pkg:nuget/newtonsoft.json" {
			t.Errorf("Origins[%s] = %q, want pkg:nuget/newtonsoft.json", s.SCIP, res.Origins[s.SCIP])
		}
		if strings.Contains(s.SCIP, "App") {
			t.Errorf("first-party decoy resolved: %s", s.SCIP)
		}
	}
	if len(res.Origins) != len(res.Resolved) {
		t.Errorf("Origins has %d entries for %d resolved symbols", len(res.Origins), len(res.Resolved))
	}
	// Some advisory symbols named nothing in code that was read: disclosed, never a refutation.
	if !hasILReason(res.Partiality, partialReasonAdvisorySymbolUnresolved) || res.Partiality.Complete {
		t.Errorf("partiality = %+v, want %s", res.Partiality, partialReasonAdvisorySymbolUnresolved)
	}
}

// TestResolveDependencySymbols_FullyMatchedIsComplete: every advisory symbol resolved and
// every occurrence read → Complete.
func TestResolveDependencySymbols_FullyMatchedIsComplete(t *testing.T) {
	f := newDepFixture(t,
		`"Newtonsoft.Json/12.0.3":{"type":"package","runtime":{"lib/net8.0/Newtonsoft.Json.dll":{}}}`,
		newtonsoftLib)
	f.writePkgFile(t, "newtonsoft.json/12.0.3/lib/net8.0/Newtonsoft.Json.dll", newtonsoftLike(false))
	res := resolveNewtonsoft(t, f, "Newtonsoft.Json.JsonConvert.DeserializeObject", "JObject.Parse")
	if !res.Partiality.Complete {
		t.Fatalf("partiality = %+v, want Complete", res.Partiality)
	}
	if len(res.Matched) != 2 {
		t.Fatalf("Matched = %v, want both symbols", res.Matched)
	}
}

// TestResolveDependencySymbols_PrefersRuntimeOverRefAssembly: restore records both a ref/
// compile asset (a stub reference assembly) and the lib/ runtime asset; resolution reads
// the runtime one.
func TestResolveDependencySymbols_PrefersRuntimeOverRefAssembly(t *testing.T) {
	f := newDepFixture(t,
		`"Newtonsoft.Json/12.0.3":{"type":"package","compile":{"ref/net8.0/Newtonsoft.Json.dll":{}},`+
			`"runtime":{"lib/net8.0/Newtonsoft.Json.dll":{}}}`,
		newtonsoftLib)
	f.writePkgFile(t, "newtonsoft.json/12.0.3/ref/net8.0/Newtonsoft.Json.dll", newtonsoftLike(true))
	f.writePkgFile(t, "newtonsoft.json/12.0.3/lib/net8.0/Newtonsoft.Json.dll", newtonsoftLike(false))
	res := resolveNewtonsoft(t, f, "JObject.Parse")
	if !reflect.DeepEqual(res.Matched["JObject.Parse"], []string{scipParse}) || !res.Partiality.Complete {
		t.Fatalf("Matched = %v, partiality = %+v; want the runtime assembly read", res.Matched, res.Partiality)
	}
}

// TestResolveDependencySymbols_MissingArtifactIsScoped: the package's code is not readable
// → a scoped no_dependency_artifact (or tool_failure for an unparsable dll) bounded by the
// package and its restore closure, and nothing resolved.
func TestResolveDependencySymbols_MissingArtifactIsScoped(t *testing.T) {
	targets := `"Newtonsoft.Json/12.0.3":{"type":"package","dependencies":{"System.Buffers":"4.5.0"},` +
		`"compile":{"ref/net8.0/Newtonsoft.Json.dll":{}}},` +
		`"System.Buffers/4.5.0":{"type":"package","dependencies":{"System.Memory":"4.5.0"}},` +
		`"System.Memory/4.5.0":{"type":"package"},` +
		`"Unrelated/1.0.0":{"type":"package"}`
	wantTargets := []string{"pkg:nuget/newtonsoft.json", "pkg:nuget/system.buffers", "pkg:nuget/system.memory"}
	cases := []struct {
		name       string
		dll        []byte // nil = not on disk
		wantReason string
	}{
		{"not on disk", nil, partialReasonNoDependencyArtifact},
		{"reference assembly only", newtonsoftLike(true), partialReasonNoDependencyArtifact},
		{"unparsable", []byte("MZ not a PE"), plugin.PartialReasonToolFailure},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newDepFixture(t, targets, newtonsoftLib)
			if c.dll != nil {
				f.writePkgFile(t, "newtonsoft.json/12.0.3/ref/net8.0/Newtonsoft.Json.dll", c.dll)
			}
			res := resolveNewtonsoft(t, f, "Newtonsoft.Json.JsonConvert.DeserializeObject")
			if len(res.Resolved) != 0 || len(res.Matched) != 0 || len(res.Origins) != 0 {
				t.Fatalf("resolved from unread code: %+v", res)
			}
			if res.Partiality.Complete || len(res.Partiality.Scoped) != 1 {
				t.Fatalf("partiality = %+v, want one scoped limit", res.Partiality)
			}
			if !hasILReason(res.Partiality, c.wantReason) {
				t.Errorf("Reasons = %v, want %s run-wide too", res.Partiality.Reasons, c.wantReason)
			}
			got := res.Partiality.Scoped[0]
			if got.Reason != c.wantReason || got.Package != "pkg:nuget/newtonsoft.json" {
				t.Errorf("scoped = %+v, want reason %s on pkg:nuget/newtonsoft.json", got, c.wantReason)
			}
			if !reflect.DeepEqual(got.Targets, wantTargets) {
				t.Errorf("Targets = %v, want the package plus its restore closure %v", got.Targets, wantTargets)
			}
		})
	}
}

// TestAssetsGraphClosure_UnresolvedDependencyIsUnbounded: a dependency restore did not
// resolve in the target leaves the hidden code's reach unknown → nil Targets.
func TestAssetsGraphClosure_UnresolvedDependencyIsUnbounded(t *testing.T) {
	g := parseAssetsGraph([]byte(`{"targets":{"net8.0":{"A/1.0.0":{"type":"package","dependencies":{"Gone":"1.0.0"}}}}}`))
	if got := g.closure("net8.0", "A/1.0.0"); got != nil {
		t.Fatalf("closure = %v, want nil (unbounded)", got)
	}
	if got := g.closure("net8.0", "Absent/1.0.0"); got != nil {
		t.Fatalf("closure of an unrecorded key = %v, want nil", got)
	}
}

// TestResolveDependencySymbols_NoAssetsOrNotRestored: without restore output the package's
// code is unknown → scoped, nothing resolved; the first-party decoy is still never matched.
// A package restore didn't record is unknown too while the build isn't closed (here, a
// vendored assembly); absent_test.go covers the closed build.
func TestResolveDependencySymbols_NoAssetsOrNotRestored(t *testing.T) {
	t.Setenv("NUGET_PACKAGES", t.TempDir())
	noAssets := composeILBuildDir(t, map[string][]byte{
		"App.csproj": []byte("<Project></Project>"),
		"Decoy.cs":   []byte(`namespace Newtonsoft.Json { public static class JsonConvert { public static object DeserializeObject(string s) { return null; } } }`),
	})
	other := newDepFixture(t, `"Other/1.0.0":{"type":"package"}`, `"Other/1.0.0":{"type":"package","path":"other/1.0.0"}`)
	writeFixtureFile(t, other.buildDir, "lib/Vendor.dll", "MZ")
	for name, dir := range map[string]string{"no assets": noAssets, "package not restored": other.buildDir} {
		t.Run(name, func(t *testing.T) {
			res := resolveNewtonsoft(t, depFixture{buildDir: dir}, "Newtonsoft.Json.JsonConvert.DeserializeObject")
			if len(res.Resolved) != 0 || len(res.Matched) != 0 {
				t.Fatalf("resolved without the package's code: %+v", res)
			}
			if res.Partiality.Complete || len(res.Partiality.Scoped) != 1 ||
				res.Partiality.Scoped[0].Reason != partialReasonNoDependencyArtifact ||
				!hasILReason(res.Partiality, partialReasonNoDependencyArtifact) {
				t.Fatalf("partiality = %+v, want no_dependency_artifact scoped and run-wide", res.Partiality)
			}
		})
	}
}

// TestResolveDependencySymbols_CodelessPackageIsNotAMiss: a metapackage restore records with
// no assemblies has no code to read; it is neither a miss nor a match.
func TestResolveDependencySymbols_CodelessPackageIsNotAMiss(t *testing.T) {
	f := newDepFixture(t,
		`"Newtonsoft.Json/12.0.3":{"type":"package","compile":{"lib/netstandard1.0/_._":{}}}`,
		newtonsoftLib)
	res := resolveNewtonsoft(t, f, "Newtonsoft.Json.JsonConvert.DeserializeObject")
	if len(res.Partiality.Scoped) != 0 {
		t.Fatalf("scoped = %+v, want none for a package with no assemblies", res.Partiality.Scoped)
	}
	if !hasILReason(res.Partiality, partialReasonAdvisorySymbolUnresolved) {
		t.Fatalf("partiality = %+v, want %s", res.Partiality, partialReasonAdvisorySymbolUnresolved)
	}
}

// TestResolveDependencySymbols_FirstPartyProjectUsesSource: an advisory against a package
// the repo itself builds resolves against its source, without Origins.
func TestResolveDependencySymbols_FirstPartyProjectUsesSource(t *testing.T) {
	dir := composeILBuildDir(t, map[string][]byte{
		"MyLib/MyLib.csproj": []byte("<Project></Project>"),
		"MyLib/Api.cs":       []byte(`namespace MyLib { public static class Api { public static void Run(int x) { } } }`),
	})
	res, err := ResolveDependencySymbols(t.Context(), plugin.ResolveSymbolsRequest{
		BuildDir: dir, PURL: "pkg:nuget/MyLib@1.0.0", AdvisorySymbols: []string{"MyLib.Api.Run"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Resolved) != 1 || len(res.Origins) != 0 {
		t.Fatalf("Resolved = %+v, Origins = %v; want one first-party symbol with no origin", res.Resolved, res.Origins)
	}
}

func TestNormalizeAdvisorySymbol(t *testing.T) {
	cases := map[string]string{
		"Newtonsoft.Json.JsonConvert.DeserializeObject":      "newtonsoft.json.jsonconvert.deserializeobject",
		" JsonConvert.DeserializeObject(String, Type) ":      "jsonconvert.deserializeobject",
		"System.Collections.Generic.List<T>.Sort":            "system.collections.generic.list.sort",
		"Dictionary<string, List<int>>.Add":                  "dictionary.add",
		"Newtonsoft.Json.Linq.JToken::Parse":                 "newtonsoft.json.linq.jtoken.parse",
		"Newtonsoft.Json.Serialization.JsonContract`1.Build": "newtonsoft.json.serialization.jsoncontract.build",
	}
	for in, want := range cases {
		if got := normalizeAdvisorySymbol(in); got != want {
			t.Errorf("normalizeAdvisorySymbol(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNugetCoordinate(t *testing.T) {
	cases := []struct {
		purl, id, version string
		ok                bool
	}{
		{"pkg:nuget/Newtonsoft.Json@12.0.3", "Newtonsoft.Json", "12.0.3", true},
		{"pkg:nuget/Scriban@6.2.1?repository_url=x#sub", "Scriban", "6.2.1", true},
		{"pkg:NuGet/Foo", "Foo", "", true},
		{"pkg:npm/lodash@4.17.21", "", "", false},
		{"pkg:nuget/a/b@1", "", "", false},
		{"nuget/Foo@1", "", "", false},
	}
	for _, c := range cases {
		id, version, ok := nugetCoordinate(c.purl)
		if id != c.id || version != c.version || ok != c.ok {
			t.Errorf("nugetCoordinate(%q) = %q, %q, %v; want %q, %q, %v", c.purl, id, version, ok, c.id, c.version, c.ok)
		}
	}
}

// TestLoadSpanningSet_RefAssemblyIsAMiss: the IL tier reading a stub reference assembly
// would see empty bodies (leaves) and could clear a sink behind them; it is a declared miss.
func TestLoadSpanningSet_RefAssemblyIsAMiss(t *testing.T) {
	f := newDepFixture(t,
		`"Newtonsoft.Json/12.0.3":{"type":"package","compile":{"ref/net8.0/Newtonsoft.Json.dll":{}}}`,
		newtonsoftLib)
	f.writePkgFile(t, "newtonsoft.json/12.0.3/ref/net8.0/Newtonsoft.Json.dll", newtonsoftLike(true))
	_, data, ok := readAssetsFile(f.buildDir)
	if !ok {
		t.Fatal("no assets file")
	}
	locator, _ := assembly.ParseAssetsLocator(data)
	set := assembly.LoadSpanningSet(f.buildDir, nil, locator, []assembly.DepRef{{Target: "net8.0", PkgKey: "Newtonsoft.Json/12.0.3"}})
	if len(set.Misses) != 1 || set.Misses[0].Reason != assembly.MissReferenceAssembly {
		t.Fatalf("misses = %+v, want one reference-assembly miss", set.Misses)
	}
	if slices.ContainsFunc(set.Assemblies, func(a *assembly.Assembly) bool { return a != nil && a.Name == "Newtonsoft.Json" }) {
		t.Fatal("reference assembly loaded into the spanning set")
	}
}

// TestDependencySymbols_ReconcileInReachability: the SCIPs resolution hands out are the keys
// the IL tier reconciles, so a resolved dependency symbol is searched (or reached) by
// Reachability over the same restore.
func TestDependencySymbols_ReconcileInReachability(t *testing.T) {
	symbols := []string{"JsonConvert.DeserializeObject", "Newtonsoft.Json.Outer.Inner.Run", "JObject.Parse"}
	for _, callParse := range []bool{false, true} {
		ab := scaffold()
		aObj := cTypeDefOrRef(xTypeRef, ab.extTypeRef("System", "Object"))
		var calls [][]byte
		if callParse {
			jobject := ab.extTypeRefScoped(ab.asmRef("Newtonsoft.Json"), "Newtonsoft.Json.Linq", "JObject")
			calls = append(calls, ilCall(ab.memberRef(jobject, "Parse", sigStaticStringToObject)))
		}
		ab.addType(0, "<Module>", "", 0, nil)
		_, inM := ab.addType(0, "Program", "App", aObj, []mspec{{name: "Main", flags: 0x16, sig: sigStaticVoid, il: body(calls...)}})
		ab.entry = mtok(xMethodDef, inM[0])

		f := newDepFixture(t,
			`"Newtonsoft.Json/12.0.3":{"type":"package","runtime":{"lib/net8.0/Newtonsoft.Json.dll":{}}}`,
			newtonsoftLib)
		f.writePkgFile(t, "newtonsoft.json/12.0.3/lib/net8.0/Newtonsoft.Json.dll", newtonsoftLike(false))
		if err := os.MkdirAll(filepath.Join(f.buildDir, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.buildDir, "bin", "App.dll"), ab.bytesNamed("App"), 0o644); err != nil {
			t.Fatal(err)
		}

		res := resolveNewtonsoft(t, f, symbols...)
		var sinks []string
		for _, w := range symbols {
			sinks = append(sinks, res.Matched[w]...)
		}
		if len(sinks) != 3 {
			t.Fatalf("Matched = %v, want one SCIP per symbol", res.Matched)
		}
		reach, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: f.buildDir, Symbols: sinks})
		if err != nil {
			t.Fatal(err)
		}
		if !callParse {
			if !reflect.DeepEqual(reach.Searched, sinks) || len(reach.Paths) != 0 {
				t.Errorf("empty Main: Searched = %v, paths = %d; want all of %v searched", reach.Searched, len(reach.Paths), sinks)
			}
			continue
		}
		if len(reach.Paths) != 1 || reach.Paths[0].Sink.SCIP != scipParse || slices.Contains(reach.Searched, scipParse) {
			t.Errorf("Main calls Parse: paths = %+v, Searched = %v; want one path to %s, not searched", reach.Paths, reach.Searched, scipParse)
		}
	}
}

// writeAppBuild places a first-party App.dll built for tfm under bin/Release/<tfm>/.
func writeAppBuild(t *testing.T, buildDir, tfm string) {
	t.Helper()
	p := filepath.Join(buildDir, "bin", "Release", tfm, "App.dll")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, appMain(""), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestResolveDependencySymbols_VersionOfTheBuiltTarget: restore resolved Newtonsoft.Json
// 13.0.1 for net8.0 and 12.0.3 for netstandard2.0. An advisory against 12.0.3 resolves only
// when the first-party build is the netstandard2.0 one; the net8.0 build runs 13.0.1, so the
// requested version's code is not what it runs.
func TestResolveDependencySymbols_VersionOfTheBuiltTarget(t *testing.T) {
	for _, tfm := range []string{"net8.0", "netstandard2.0"} {
		t.Run(tfm, func(t *testing.T) {
			t.Setenv("NUGET_PACKAGES", t.TempDir())
			pkgRoot := t.TempDir()
			assets := `{"version":3,"targets":{` +
				`"net8.0":{"Newtonsoft.Json/13.0.1":{"type":"package","runtime":{"lib/net8.0/Newtonsoft.Json.dll":{}}}},` +
				`"netstandard2.0":{"Newtonsoft.Json/12.0.3":{"type":"package","runtime":{"lib/netstandard2.0/Newtonsoft.Json.dll":{}}}}},` +
				`"libraries":{` + newtonsoftLib + `,"Newtonsoft.Json/13.0.1":{"type":"package","path":"newtonsoft.json/13.0.1"}},` +
				`"packageFolders":{"` + filepath.ToSlash(pkgRoot) + `/":{}}}`
			f := depFixture{buildDir: composeILBuildDir(t, map[string][]byte{
				"App.csproj":              restoredProject,
				"obj/project.assets.json": []byte(assets),
			}), pkgRoot: pkgRoot}
			f.writePkgFile(t, "newtonsoft.json/13.0.1/lib/net8.0/Newtonsoft.Json.dll", newtonsoftLike(false))
			f.writePkgFile(t, "newtonsoft.json/12.0.3/lib/netstandard2.0/Newtonsoft.Json.dll", newtonsoftLike(false))
			writeAppBuild(t, f.buildDir, tfm)

			res := resolveNewtonsoft(t, f, "Newtonsoft.Json.JsonConvert.DeserializeObject")
			if tfm == "netstandard2.0" {
				if len(res.Matched) != 1 || !res.Partiality.Complete {
					t.Fatalf("Matched = %v, partiality = %+v; want the 12.0.3 code matched", res.Matched, res.Partiality)
				}
				return
			}
			if len(res.Matched) != 0 || len(res.Resolved) != 0 {
				t.Fatalf("resolved 12.0.3 for a build that runs 13.0.1: %+v", res)
			}
			if !hasILReason(res.Partiality, partialReasonNoDependencyArtifact) || len(res.Partiality.Scoped) != 1 {
				t.Fatalf("partiality = %+v, want no_dependency_artifact scoped and run-wide", res.Partiality)
			}
		})
	}
}

// jsonConvertOnly is a Newtonsoft.Json build that has JsonConvert.DeserializeObject but no
// JObject.Parse, so which version's bytes were read shows in what matched.
func jsonConvertOnly() []byte {
	b := scaffold()
	obj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	b.addType(0, "<Module>", "", 0, nil)
	b.addType(0x1, "JsonConvert", "Newtonsoft.Json", obj, []mspec{
		{name: "DeserializeObject", flags: 0x16, sig: sigStaticStringToObject, il: body()},
	})
	return b.bytesNamed("Newtonsoft.Json")
}

// TestResolveDependencySymbols_TwoVersionRestoreGraph: restore resolved Newtonsoft.Json
// 13.0.1 for net8.0 and 12.0.3 for netstandard2.0. The advisory PURL's version, when it has
// one, filters occurrences to that exact version; without one, every occurrence in the
// bound target is read. With no built program to bind a target, every target's copy is
// read and the run carries restore_target_unbound, so a straddling graph never narrows to
// one version's bytes silently.
func TestResolveDependencySymbols_TwoVersionRestoreGraph(t *testing.T) {
	const (
		deserialize = "Newtonsoft.Json.JsonConvert.DeserializeObject"
		parse       = "Newtonsoft.Json.Linq.JObject.Parse"
	)
	tests := []struct {
		name        string
		purlVersion string
		builtTFM    string // "" = no built program
		wantMatched []string
		wantReasons []string
	}{
		{"unversioned/net8.0 reads 13.0.1 only", "", "net8.0", []string{deserialize}, []string{partialReasonAdvisorySymbolUnresolved}},
		{"unversioned/netstandard2.0 reads 12.0.3 only", "", "netstandard2.0", []string{deserialize, parse}, nil},
		{"unversioned/unbound reads both", "", "", []string{deserialize, parse}, []string{partialReasonTargetUnbound}},
		{"12.0.3/unbound reads 12.0.3 only", "12.0.3", "", []string{deserialize, parse}, []string{partialReasonTargetUnbound}},
		{"13.0.1/unbound reads 13.0.1 only", "13.0.1", "", []string{deserialize}, []string{partialReasonAdvisorySymbolUnresolved, partialReasonTargetUnbound}},
		{"13.0.1/netstandard2.0 is not restored there", "13.0.1", "netstandard2.0", nil, []string{partialReasonNoDependencyArtifact}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("NUGET_PACKAGES", t.TempDir())
			pkgRoot := t.TempDir()
			assets := `{"version":3,"targets":{` +
				`"net8.0":{"Newtonsoft.Json/13.0.1":{"type":"package","runtime":{"lib/net8.0/Newtonsoft.Json.dll":{}}}},` +
				`"netstandard2.0":{"Newtonsoft.Json/12.0.3":{"type":"package","runtime":{"lib/netstandard2.0/Newtonsoft.Json.dll":{}}}}},` +
				`"libraries":{` + newtonsoftLib + `,"Newtonsoft.Json/13.0.1":{"type":"package","path":"newtonsoft.json/13.0.1"}},` +
				`"packageFolders":{"` + filepath.ToSlash(pkgRoot) + `/":{}}}`
			f := depFixture{buildDir: composeILBuildDir(t, map[string][]byte{
				"App.csproj":              restoredProject,
				"obj/project.assets.json": []byte(assets),
			}), pkgRoot: pkgRoot}
			f.writePkgFile(t, "newtonsoft.json/13.0.1/lib/net8.0/Newtonsoft.Json.dll", jsonConvertOnly())
			f.writePkgFile(t, "newtonsoft.json/12.0.3/lib/netstandard2.0/Newtonsoft.Json.dll", newtonsoftLike(false))
			if tt.builtTFM != "" {
				writeAppBuild(t, f.buildDir, tt.builtTFM)
			}
			purl := "pkg:nuget/Newtonsoft.Json"
			if tt.purlVersion != "" {
				purl += "@" + tt.purlVersion
			}
			res, err := ResolveDependencySymbols(t.Context(), plugin.ResolveSymbolsRequest{
				BuildDir: f.buildDir, PURL: purl, AdvisorySymbols: []string{deserialize, parse},
			})
			if err != nil {
				t.Fatalf("ResolveDependencySymbols: %v", err)
			}
			var matched []string
			for s := range res.Matched {
				matched = append(matched, s)
			}
			slices.Sort(matched)
			want := slices.Clone(tt.wantMatched)
			slices.Sort(want)
			if !slices.Equal(matched, want) {
				t.Errorf("Matched = %v, want %v", matched, want)
			}
			got := slices.Clone(res.Partiality.Reasons)
			slices.Sort(got)
			wantReasons := slices.Clone(tt.wantReasons)
			slices.Sort(wantReasons)
			if !slices.Equal(got, wantReasons) {
				t.Errorf("Reasons = %v, want %v", got, wantReasons)
			}
			if res.Partiality.Complete != (len(tt.wantReasons) == 0) {
				t.Errorf("Complete = %v with reasons %v", res.Partiality.Complete, got)
			}
		})
	}
}

// lookalikeAssembly is a second assembly of the package declaring types whose short names
// shadow the real API: Evil.Linq.JObject.Parse and Shadow.Newtonsoft.Json.Linq.JObject.Parse.
func lookalikeAssembly() []byte {
	b := scaffold()
	obj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	b.addType(0, "<Module>", "", 0, nil)
	b.addType(0x1, "JObject", "Evil.Linq", obj, []mspec{{name: "Parse", flags: 0x16, sig: sigStaticStringToObject, il: body()}})
	b.addType(0x1, "JObject", "Shadow.Newtonsoft.Json.Linq", obj, []mspec{{name: "Parse", flags: 0x16, sig: sigStaticStringToObject, il: body()}})
	return b.bytesNamed("Newtonsoft.Json.Lookalike")
}

// TestResolveDependencySymbols_LookalikeAcrossAssemblies: a shortened advisory symbol that
// names methods of more than one qualified type is ambiguous and stays out of Matched; a
// fully qualified one names its own type only, even when a deeper namespace ends the same.
func TestResolveDependencySymbols_LookalikeAcrossAssemblies(t *testing.T) {
	f := newDepFixture(t,
		`"Newtonsoft.Json/12.0.3":{"type":"package","runtime":{"lib/net8.0/Newtonsoft.Json.dll":{},"lib/net8.0/Newtonsoft.Json.Lookalike.dll":{}}}`,
		newtonsoftLib)
	f.writePkgFile(t, "newtonsoft.json/12.0.3/lib/net8.0/Newtonsoft.Json.dll", newtonsoftLike(false))
	f.writePkgFile(t, "newtonsoft.json/12.0.3/lib/net8.0/Newtonsoft.Json.Lookalike.dll", lookalikeAssembly())
	scipEvil := funcSCIP("Evil.Linq", []string{"JObject"}, "Parse", 1)
	scipShadow := funcSCIP("Shadow.Newtonsoft.Json.Linq", []string{"JObject"}, "Parse", 1)

	cases := []struct {
		symbol string
		want   []string // nil = ambiguous, absent from Matched
	}{
		{"JObject.Parse", nil},
		{"Linq.JObject.Parse", nil},
		{"Newtonsoft.Json.Linq.JObject.Parse", []string{scipParse}},
		{"Evil.Linq.JObject.Parse", []string{scipEvil}},
		{"JsonConvert.DeserializeObject", []string{scipDeserialize}},
	}
	for _, c := range cases {
		t.Run(c.symbol, func(t *testing.T) {
			res := resolveNewtonsoft(t, f, c.symbol)
			got, ok := res.Matched[c.symbol]
			if c.want == nil {
				if ok {
					t.Fatalf("Matched[%q] = %v, want absent (ambiguous)", c.symbol, got)
				}
				if !hasILReason(res.Partiality, partialReasonAdvisorySymbolAmbiguous) ||
					!hasILReason(res.Partiality, partialReasonAdvisorySymbolUnresolved) {
					t.Fatalf("Reasons = %v, want ambiguous and unresolved", res.Partiality.Reasons)
				}
				// The candidates stay resolved so a path to any of them is still reported.
				var scips []string
				for _, s := range res.Resolved {
					scips = append(scips, s.SCIP)
				}
				if !slices.Contains(scips, scipParse) || !slices.Contains(scips, scipEvil) || !slices.Contains(scips, scipShadow) {
					t.Fatalf("Resolved = %v, want every candidate", scips)
				}
				return
			}
			if !reflect.DeepEqual(got, c.want) || !res.Partiality.Complete {
				t.Fatalf("Matched[%q] = %v (partiality %+v), want %v", c.symbol, got, res.Partiality, c.want)
			}
			if len(res.Resolved) != len(c.want) {
				t.Fatalf("Resolved = %+v, want only the matched method", res.Resolved)
			}
		})
	}
}

// TestResolveDependencySymbols_RuntimePlaceholderIsFrameworkSupplied: restore records the
// package's runtime asset as "_._" over a compile dll — the shared framework supplies the
// implementation — so neither the compile dll nor the lib dll on disk is the code that runs.
func TestResolveDependencySymbols_RuntimePlaceholderIsFrameworkSupplied(t *testing.T) {
	f := newDepFixture(t,
		`"Newtonsoft.Json/12.0.3":{"type":"package","compile":{"ref/net8.0/Newtonsoft.Json.dll":{}},"runtime":{"lib/net8.0/_._":{}}}`,
		newtonsoftLib)
	f.writePkgFile(t, "newtonsoft.json/12.0.3/ref/net8.0/Newtonsoft.Json.dll", newtonsoftLike(false))
	f.writePkgFile(t, "newtonsoft.json/12.0.3/lib/net8.0/Newtonsoft.Json.dll", newtonsoftLike(false))
	res := resolveNewtonsoft(t, f, "Newtonsoft.Json.JsonConvert.DeserializeObject")
	if len(res.Resolved) != 0 || len(res.Matched) != 0 {
		t.Fatalf("resolved from bytes the framework replaces: %+v", res)
	}
	if len(res.Partiality.Scoped) != 1 || !strings.Contains(res.Partiality.Scoped[0].Path, assembly.MissFrameworkSupplied) ||
		!hasILReason(res.Partiality, partialReasonNoDependencyArtifact) {
		t.Fatalf("partiality = %+v, want a framework-supplied miss, scoped and run-wide", res.Partiality)
	}
}
