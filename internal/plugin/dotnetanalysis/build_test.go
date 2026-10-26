package dotnetanalysis

// build_test.go — which first-party build a run analyzes and which restore target its
// dependencies are read from. A run supports one project and one entry assembly; the
// dependency bytes must be the restore target's the build was compiled for.

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// markTargetFramework adds [assembly: TargetFramework(name)], as the SDK stamps every build.
func (b *peb) markTargetFramework(name string) {
	attr := b.extTypeRef("System.Runtime.Versioning", "TargetFrameworkAttribute")
	ctor := b.memberRef(attr, ".ctor", []byte{0x20, 0x01, 0x01, 0x0E})
	const hasCustomAttributeAssembly = 14
	val := append([]byte{0x01, 0x00, byte(len(name))}, name...)
	val = append(val, 0x00, 0x00)
	b.row(xCustomAttribute, 1<<5|hasCustomAttributeAssembly, (ctor&0xFFFFFF)<<3|3, b.blob(val))
}

// appMain builds App.dll whose Main calls nothing; tfm, when set, is stamped as its
// TargetFramework attribute.
func appMain(tfm string) []byte {
	ab := scaffold()
	aObj := cTypeDefOrRef(xTypeRef, ab.extTypeRef("System", "Object"))
	ab.addType(0, "<Module>", "", 0, nil)
	_, inM := ab.addType(0, "Program", "App", aObj, []mspec{{name: "Main", flags: 0x16, sig: sigStaticVoid, il: body()}})
	ab.entry = mtok(xMethodDef, inM[0])
	if tfm != "" {
		ab.markTargetFramework(tfm)
	}
	return ab.bytesNamed("App")
}

// refAppMain is the reference-assembly copy of App.dll the SDK writes under ref/.
func refAppMain() []byte {
	ab := scaffold()
	aObj := cTypeDefOrRef(xTypeRef, ab.extTypeRef("System", "Object"))
	ab.addType(0, "<Module>", "", 0, nil)
	ab.addType(0, "Program", "App", aObj, []mspec{{name: "Main", flags: 0x16, sig: sigStaticVoid, il: body()}})
	ab.markReferenceAssembly()
	return ab.bytesNamed("App")
}

// twoTargetAssets restores Newtonsoft.Json 12.0.3 for net8.0 (its lib dll is in the package
// folder) and for netstandard2.0 (whose lib dll is not).
func twoTargetAssets(pkgRoot string) []byte {
	row := func(tfm string) string {
		return `"Newtonsoft.Json/12.0.3":{"type":"package","runtime":{"lib/` + tfm + `/Newtonsoft.Json.dll":{}}}`
	}
	return []byte(`{"version":3,"targets":{"net8.0":{` + row("net8.0") + `},"netstandard2.0":{` + row("netstandard2.0") + `}},` +
		`"libraries":{` + newtonsoftLib + `},"packageFolders":{"` + filepath.ToSlash(pkgRoot) + `/":{}}}`)
}

func TestReachability_BindsToTheBuiltTargetFramework(t *testing.T) {
	cases := []struct {
		name       string
		dlls       map[string][]byte
		wantSearch bool
		wantReason string // "" = no layout or miss reason expected
	}{
		{"net8.0 build reads the net8.0 restore", map[string][]byte{"bin/Release/net8.0/App.dll": appMain("")}, true, ""},
		{"netstandard2.0 build reads the netstandard2.0 restore, whose dll is missing",
			map[string][]byte{"bin/Release/netstandard2.0/App.dll": appMain("")}, false, partialReasonNoDependencyArtifact},
		{"TargetFramework attribute binds outside a framework-named directory",
			map[string][]byte{"bin/App.dll": appMain(".NETStandard,Version=v2.0")}, false, partialReasonNoDependencyArtifact},
		{"attribute binds net8.0", map[string][]byte{"bin/App.dll": appMain(".NETCoreApp,Version=v8.0")}, true, ""},
		{"no framework named and two restore targets", map[string][]byte{"bin/App.dll": appMain("")}, false, partialReasonTargetUnbound},
		{"stale build for a framework the restore lacks", map[string][]byte{"bin/Release/net6.0/App.dll": appMain("")}, false, partialReasonTargetUnbound},
		{"a build per framework is two entry assemblies", map[string][]byte{
			"bin/Release/net8.0/App.dll":         appMain(""),
			"bin/Release/netstandard2.0/App.dll": appMain(""),
		}, false, partialReasonMultipleProjects},
		{"Debug and Release of one framework are one entry assembly", map[string][]byte{
			"bin/Debug/net8.0/App.dll":   appMain(""),
			"bin/Release/net8.0/App.dll": appMain(""),
		}, true, ""},
		{"a reference-assembly copy is not an entry assembly", map[string][]byte{
			"bin/Release/net8.0/App.dll":     appMain(""),
			"bin/Release/net8.0/ref/App.dll": refAppMain(),
		}, true, ""},
		{"an unreadable copy may be another build", map[string][]byte{
			"bin/Release/net8.0/App.dll": appMain(""),
			"bin/Release/net7.0/App.dll": []byte("MZ\x00\x00not-a-real-pe"),
		}, false, partialReasonMultipleProjects},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("NUGET_PACKAGES", t.TempDir())
			pkgRoot := t.TempDir()
			files := map[string][]byte{
				"App.csproj":              restoredProject,
				"obj/project.assets.json": twoTargetAssets(pkgRoot),
			}
			for k, v := range c.dlls {
				files[k] = v
			}
			dir := composeILBuildDir(t, files)
			f := depFixture{buildDir: dir, pkgRoot: pkgRoot}
			f.writePkgFile(t, "newtonsoft.json/12.0.3/lib/net8.0/Newtonsoft.Json.dll", newtonsoftLike(false))

			res, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{scipDeserialize}})
			if err != nil {
				t.Fatal(err)
			}
			if got := slices.Contains(res.Searched, scipDeserialize); got != c.wantSearch {
				t.Fatalf("searched = %v, want %v (partiality %+v)", got, c.wantSearch, res.Partiality)
			}
			if c.wantReason == "" {
				if !res.Partiality.Complete {
					t.Fatalf("partiality = %+v, want Complete", res.Partiality)
				}
				return
			}
			if !hasILReason(res.Partiality, c.wantReason) {
				t.Fatalf("Reasons = %v, want %s", res.Partiality.Reasons, c.wantReason)
			}
		})
	}
}

// TestReachability_MultipleProjectsUnsupported: a second project is never traced, so the run
// says so in Reasons, under a code the gate reads as did-not-run, and searches nothing.
func TestReachability_MultipleProjectsUnsupported(t *testing.T) {
	for _, extra := range []string{"", "Web/Web.csproj"} {
		files := map[string][]byte{
			"App.csproj":              restoredProject,
			"bin/App.dll":             appCalling(nil, false, true),
			"bin/Dep.dll":             depWithBoomOverloads(false),
			"obj/project.assets.json": depAssetsJSON("Dep/1.0.0"),
		}
		if extra != "" {
			files[extra] = []byte("<Project></Project>")
		}
		res, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: composeILBuildDir(t, files), Symbols: []string{boomSCIP}})
		if err != nil {
			t.Fatal(err)
		}
		multi := extra != ""
		if got := hasILReason(res.Partiality, partialReasonMultipleProjects); got != multi {
			t.Fatalf("extra project %q: %s present = %v, want %v", extra, partialReasonMultipleProjects, got, multi)
		}
		if got := len(res.Searched) > 0; got == multi {
			t.Fatalf("extra project %q: Searched = %v", extra, res.Searched)
		}
	}
	if got := report.ClassifyPartialityReason(partialReasonMultipleProjects); got != report.PartialityDidNotRun {
		t.Fatalf("%s classifies as %v, want did-not-run", partialReasonMultipleProjects, got)
	}
}

func TestCanonicalTFM(t *testing.T) {
	cases := map[string]string{
		".NETCoreApp,Version=v8.0":  "netcoreapp|8.0",
		"net8.0":                    "netcoreapp|8.0",
		"net5.0":                    "netcoreapp|5.0",
		"netcoreapp3.1":             "netcoreapp|3.1",
		".NETStandard,Version=v2.0": "netstandard|2.0",
		"netstandard2.0":            "netstandard|2.0",
		"net472":                    "netframework|4.7.2",
		".NETFramework,Version=v4.7.2,Profile=Client": "netframework|4.7.2",
		"net8.0-windows": "netcoreapp|8.0#windows",
		"Release":        "",
		"net4.8":         "",
	}
	for in, want := range cases {
		got, ok := canonicalTFM(in)
		if want == "" {
			if ok {
				t.Errorf("canonicalTFM(%q) = %q, want no framework", in, got)
			}
			continue
		}
		if got != want {
			t.Errorf("canonicalTFM(%q) = %q, want %q", in, got, want)
		}
	}
	// The attribute does not carry the platform, so net8.0 and net8.0-windows both match it.
	if _, ok := bindTarget([]string{"net8.0", "net8.0-windows"}, "netcoreapp|8.0"); ok {
		t.Error("bound an attribute-only framework to one of two platform targets")
	}
	if got, ok := bindTarget([]string{"net8.0", "net8.0/linux-x64"}, "netcoreapp|8.0"); !ok || got != "net8.0" {
		t.Errorf("bindTarget = %q, %v; want the runtime-independent net8.0", got, ok)
	}
	if got, ok := bindTarget([]string{"net8.0", "net8.0/linux-x64"}, ""); !ok || got != "net8.0" {
		t.Errorf("bindTarget = %q, %v; a runtime-specific key is not a second target", got, ok)
	}
}

// newtonsoftStub is a lib/ dll a runtime-specific package ships beside its real
// implementation: the same assembly name, without the JObject API.
func newtonsoftStub() []byte {
	b := scaffold()
	obj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	b.addType(0, "<Module>", "", 0, nil)
	b.addType(0x1, "JsonConvert", "Newtonsoft.Json", obj, []mspec{
		{name: "DeserializeObject", flags: 0x16, sig: sigStaticStringToObject, il: body()},
	})
	return b.bytesNamed("Newtonsoft.Json")
}

// depsJSON is the <name>.deps.json the SDK writes beside a build; rid "" is a portable build.
func depsJSON(rid string) []byte {
	name := ".NETCoreApp,Version=v8.0"
	if rid != "" {
		name += "/" + rid
	}
	return []byte(`{"runtimeTarget":{"name":"` + name + `","signature":""},"targets":{}}`)
}

// TestReachability_RuntimeSpecificAssets: Newtonsoft.Json is restored with a lib/ stub and a
// runtimes/win/ implementation. The build's deps.json names the runtime it was built for; the
// dependency is read from that runtime's restore target, or is a named miss when the runtime is
// unknown or ambiguous. The stub is never read: it lacks JObject.Parse, so reading it would
// leave the sink out of the loaded set rather than named.
func TestReachability_RuntimeSpecificAssets(t *testing.T) {
	cases := []struct {
		name       string
		files      map[string][]byte
		wantSearch bool
		wantReason string // "" = Complete
	}{
		{"RID resolved", map[string][]byte{
			"bin/Release/net8.0/win-x64/App.dll":       appMain(".NETCoreApp,Version=v8.0"),
			"bin/Release/net8.0/win-x64/App.deps.json": depsJSON("win-x64"),
			"publish/App.dll":                          appMain(".NETCoreApp,Version=v8.0"),
			"publish/App.deps.json":                    depsJSON("win-x64"),
		}, true, ""},
		{"RID unknown: portable build", map[string][]byte{
			"bin/Release/net8.0/App.dll":       appMain(".NETCoreApp,Version=v8.0"),
			"bin/Release/net8.0/App.deps.json": depsJSON(""),
		}, false, partialReasonRIDUnknown},
		{"RID unknown: no deps.json", map[string][]byte{
			"bin/Release/net8.0/win-x64/App.dll": appMain(".NETCoreApp,Version=v8.0"),
		}, false, partialReasonRIDUnknown},
		{"RID unknown: restore did not resolve the build's runtime", map[string][]byte{
			"bin/Release/net8.0/osx-arm64/App.dll":       appMain(".NETCoreApp,Version=v8.0"),
			"bin/Release/net8.0/osx-arm64/App.deps.json": depsJSON("osx-arm64"),
		}, false, partialReasonRIDUnknown},
		{"RID ambiguous: two runtime builds", map[string][]byte{
			"bin/Release/net8.0/win-x64/App.dll":         appMain(".NETCoreApp,Version=v8.0"),
			"bin/Release/net8.0/win-x64/App.deps.json":   depsJSON("win-x64"),
			"bin/Release/net8.0/linux-x64/App.dll":       appMain(".NETCoreApp,Version=v8.0"),
			"bin/Release/net8.0/linux-x64/App.deps.json": depsJSON("linux-x64"),
		}, false, partialReasonRIDAmbiguous},
		{"RID ambiguous: a portable and a runtime build", map[string][]byte{
			"bin/Debug/net8.0/App.dll":                 appMain(".NETCoreApp,Version=v8.0"),
			"bin/Debug/net8.0/App.deps.json":           depsJSON(""),
			"bin/Release/net8.0/win-x64/App.dll":       appMain(".NETCoreApp,Version=v8.0"),
			"bin/Release/net8.0/win-x64/App.deps.json": depsJSON("win-x64"),
		}, false, partialReasonRIDAmbiguous},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("NUGET_PACKAGES", t.TempDir())
			pkgRoot := t.TempDir()
			assets := `{"version":3,"targets":{` +
				`"net8.0":{"Newtonsoft.Json/12.0.3":{"type":"package","compile":{"lib/net8.0/Newtonsoft.Json.dll":{}},` +
				`"runtime":{"lib/net8.0/Newtonsoft.Json.dll":{}},` +
				`"runtimeTargets":{"runtimes/win/lib/net8.0/Newtonsoft.Json.dll":{"assetType":"runtime","rid":"win"}}}},` +
				`"net8.0/win-x64":{"Newtonsoft.Json/12.0.3":{"type":"package","compile":{"lib/net8.0/Newtonsoft.Json.dll":{}},` +
				`"runtime":{"runtimes/win/lib/net8.0/Newtonsoft.Json.dll":{}}}},` +
				`"net8.0/linux-x64":{"Newtonsoft.Json/12.0.3":{"type":"package","compile":{"lib/net8.0/Newtonsoft.Json.dll":{}},` +
				`"runtime":{"lib/net8.0/Newtonsoft.Json.dll":{}}}}},` +
				`"libraries":{` + newtonsoftLib + `},"packageFolders":{"` + filepath.ToSlash(pkgRoot) + `/":{}}}`
			files := map[string][]byte{
				"App.csproj":              restoredProject,
				"obj/project.assets.json": []byte(assets),
			}
			for k, v := range c.files {
				files[k] = v
			}
			dir := composeILBuildDir(t, files)
			f := depFixture{buildDir: dir, pkgRoot: pkgRoot}
			f.writePkgFile(t, "newtonsoft.json/12.0.3/lib/net8.0/Newtonsoft.Json.dll", newtonsoftStub())
			f.writePkgFile(t, "newtonsoft.json/12.0.3/runtimes/win/lib/net8.0/Newtonsoft.Json.dll", newtonsoftLike(false))

			res, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{scipParse}})
			if err != nil {
				t.Fatal(err)
			}
			if got := slices.Contains(res.Searched, scipParse); got != c.wantSearch {
				t.Fatalf("searched = %v, want %v (partiality %+v)", got, c.wantSearch, res.Partiality)
			}
			sym := resolveNewtonsoft(t, f, "Newtonsoft.Json.Linq.JObject.Parse")
			if c.wantReason == "" {
				if !res.Partiality.Complete {
					t.Fatalf("partiality = %+v, want Complete", res.Partiality)
				}
				if len(sym.Matched) != 1 || !sym.Partiality.Complete {
					t.Fatalf("symbol resolution = %+v, want JObject.Parse matched from the runtime's implementation", sym)
				}
				return
			}
			if !hasILReason(res.Partiality, c.wantReason) || len(res.Partiality.Scoped) != 1 ||
				res.Partiality.Scoped[0].Reason != c.wantReason {
				t.Fatalf("partiality = %+v, want %s scoped and run-wide", res.Partiality, c.wantReason)
			}
			if report.ClassifyPartialityReason(c.wantReason) != report.PartialityDidNotRun {
				t.Fatalf("%s must classify did_not_run", c.wantReason)
			}
			if len(sym.Matched) != 0 || !hasILReason(sym.Partiality, c.wantReason) {
				t.Fatalf("symbol resolution = %+v, want no match and %s", sym, c.wantReason)
			}
		})
	}
}
