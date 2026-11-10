package dotnetanalysis

// build_test.go — which first-party build a run analyzes and which restore target its
// dependencies are read from. A run supports one project and one entry assembly; the
// dependency bytes must be the restore target's the build was compiled for.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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

// An unreadable build directory beside a readable copy may hold another build, as an unreadable
// copy may: the run surfaces it rather than tracing the readable copy as the only one.
func TestReachability_UnreadableBuildDirBesideACopy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	t.Setenv("NUGET_PACKAGES", t.TempDir())
	pkgRoot := t.TempDir()
	dir := composeILBuildDir(t, map[string][]byte{
		"App.csproj":                 restoredProject,
		"obj/project.assets.json":    twoTargetAssets(pkgRoot),
		"bin/Release/net8.0/App.dll": appMain(""),
		"bin/Release/net7.0/App.xml": []byte("<doc/>"),
	})
	f := depFixture{buildDir: dir, pkgRoot: pkgRoot}
	f.writePkgFile(t, "newtonsoft.json/12.0.3/lib/net8.0/Newtonsoft.Json.dll", newtonsoftLike(false))
	locked := filepath.Join(dir, "bin", "Release", "net7.0")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	res, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{scipDeserialize}})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(res.Searched, scipDeserialize) || !hasILReason(res.Partiality, partialReasonMultipleProjects) {
		t.Fatalf("searched = %v, partiality = %+v, want unsearched with %s", res.Searched, res.Partiality, partialReasonMultipleProjects)
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

// TestCompiledProjects: a project this build never compiled is not a second program, but the
// drop holds only while the SDK's obj/ convention is the evidence for it.
func TestCompiledProjects(t *testing.T) {
	const (
		app       = "App.csproj"
		installer = "Installer/Installer.csproj"
		appObj    = "obj/Release/net8.0/App.dll"
		empty     = "<Project></Project>"
	)
	refTo := func(include string) string {
		return `<Project><ItemGroup><ProjectReference Include="` + include + `" /></ItemGroup></Project>`
	}
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"one project is kept", map[string]string{app: empty}, []string{app}},
		{"an installer the build never compiled is dropped", map[string]string{
			app: empty, appObj: "", installer: empty, "Installer/obj/project.assets.json": "{}",
		}, []string{app}},
		{"a runtime-specific intermediate path is the convention", map[string]string{
			app: empty, "obj/Release/net8.0/linux-x64/App.dll": "", installer: empty,
		}, []string{app}},
		{"a reference to an unrelated project keeps the drop", map[string]string{
			app: refTo(`..\Lib\Lib.csproj`), appObj: "", installer: empty,
		}, []string{app}},
		{"both compiled", map[string]string{
			app: empty, appObj: "", installer: empty, "Installer/obj/Debug/net8.0/Installer.dll": "",
		}, []string{app, installer}},
		{"nothing compiled", map[string]string{app: empty, installer: empty}, []string{app, installer}},
		{"a compiled project with no intermediate assembly", map[string]string{
			app: empty, "bin/Release/net8.0/App.dll": "", installer: empty,
		}, []string{app, installer}},
		{"an assembly outside the conventional obj path", map[string]string{
			app: empty, "obj/App.dll": "", installer: empty,
		}, []string{app, installer}},
		{"the other project built only to bin", map[string]string{
			app: empty, appObj: "", installer: empty, "Installer/bin/Installer.dll": "",
		}, []string{app, installer}},
		{"Directory.Build.props moves obj", map[string]string{
			app: empty, appObj: "", installer: empty,
			"Directory.Build.props": "<Project><PropertyGroup><BaseIntermediateOutputPath>../build/</BaseIntermediateOutputPath></PropertyGroup></Project>",
		}, []string{app, installer}},
		{"a nested Directory.Build.targets opts into artifacts output", map[string]string{
			app: empty, appObj: "", installer: empty,
			"Installer/Directory.Build.targets": "<Project><PropertyGroup><UseArtifactsOutput>true</UseArtifactsOutput></PropertyGroup></Project>",
		}, []string{app, installer}},
		{"the dropped project sets its own intermediate path", map[string]string{
			app: empty, appObj: "",
			installer: "<Project><PropertyGroup><IntermediateOutputPath>/tmp/i/</IntermediateOutputPath></PropertyGroup></Project>",
		}, []string{app, installer}},
		{"an artifacts directory at the root", map[string]string{
			app: empty, appObj: "", installer: empty, "artifacts/README": "",
		}, []string{app, installer}},
		{"a compiled project references the uncompiled one", map[string]string{
			app: refTo(`Installer\Installer.csproj`), appObj: "", installer: empty,
		}, []string{app, installer}},
		{"a reference differing only in case", map[string]string{
			app: refTo(`installer/INSTALLER.csproj`), appObj: "", installer: empty,
		}, []string{app, installer}},
		{"a compiled project whose AssemblyName differs from its file", map[string]string{
			app: empty, appObj: "",
			"Worker/Worker.csproj":                      "<Project><PropertyGroup><AssemblyName>Corp.Worker</AssemblyName></PropertyGroup></Project>",
			"Worker/obj/Release/net8.0/Corp.Worker.dll": "",
		}, []string{app, "Worker/Worker.csproj"}},
		{"an intermediate assembly older than the restore", map[string]string{
			app: empty, appObj: "", "obj/project.assets.json": "{}", installer: empty,
		}, []string{app, installer}},
		{"an intermediate assembly newer than the restore", map[string]string{
			app: empty, appObj: "", "obj/project.assets.json": "{}", installer: empty,
		}, []string{app}},
		{"an imported props file moves obj", map[string]string{
			app: empty, appObj: "", installer: empty,
			"build/common.props": "<Project><PropertyGroup><IntermediateOutputPath>out/</IntermediateOutputPath></PropertyGroup></Project>",
		}, []string{app, installer}},
		{"Directory.Build.rsp sets an artifacts path", map[string]string{
			app: empty, appObj: "", installer: empty, "Directory.Build.rsp": "--artifacts-path out",
		}, []string{app, installer}},
		{"Directory.Build.rsp sets an intermediate path", map[string]string{
			app: empty, appObj: "", installer: empty, "Directory.Build.rsp": "-p:Configuration=Release;BaseIntermediateOutputPath=o/",
		}, []string{app, installer}},
		{"a project imports a props file from a dot-directory", map[string]string{
			app: empty, appObj: "",
			installer:          `<Project><Import Project="..\.build\out.props" /></Project>`,
			".build/out.props": "<Project><PropertyGroup><BaseIntermediateOutputPath>out/</BaseIntermediateOutputPath></PropertyGroup></Project>",
		}, []string{app, installer}},
		{"a project imports a .proj file that moves obj", map[string]string{
			app: empty, appObj: "",
			installer:           `<Project><Import Project="$(MSBuildThisFileDirectory)../build/Output.proj" /></Project>`,
			"build/Output.proj": "<Project><PropertyGroup><IntermediateOutputPath>out/</IntermediateOutputPath></PropertyGroup></Project>",
		}, []string{app, installer}},
		{"a project's .user file moves obj", map[string]string{
			app: empty, appObj: "", installer: empty,
			installer + ".user": "<Project><PropertyGroup><BaseIntermediateOutputPath>out/</BaseIntermediateOutputPath></PropertyGroup></Project>",
		}, []string{app, installer}},
		{"an import through an unknown property", map[string]string{
			app: empty, appObj: "", installer: `<Project><Import Project="$(RepoRoot)/eng/out.props" /></Project>`,
		}, []string{app, installer}},
		{"a response file with a comma-separated property list", map[string]string{
			app: empty, appObj: "", installer: empty, "Directory.Build.rsp": "-p:Configuration=Release,BaseIntermediateOutputPath=o/",
		}, []string{app, installer}},
		{"toolchain, Sdk and missing optional imports keep the drop", map[string]string{
			app: empty, appObj: "",
			installer: `<Project><Import Project="$(MSBuildToolsPath)\Microsoft.CSharp.targets" /><Import Project="Sdk.props" Sdk="Microsoft.NET.Sdk" />` +
				`<Import Project="..\packages\Tool.1.0\build\Tool.targets" Condition="Exists('..\packages\Tool.1.0\build\Tool.targets')" /></Project>`,
		}, []string{app}},
		{"a props file reading an unrelated property keeps the drop", map[string]string{
			app: empty, appObj: "", installer: empty,
			"Directory.Build.props": "<Project><PropertyGroup><OutputPath>out/</OutputPath></PropertyGroup></Project>",
		}, []string{app}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string][]byte{}
			for k, v := range c.files {
				files[k] = []byte(v)
			}
			dir := composeILBuildDir(t, files)
			shift := time.Minute
			if c.name == "an intermediate assembly older than the restore" {
				shift = -time.Minute
			}
			shiftObjAssemblies(t, dir, shift)
			got := compiledProjects(dir, findProjectFiles(dir))
			var rel []string
			for _, p := range got {
				rel = append(rel, relSlash(dir, p))
			}
			if !slices.Equal(rel, c.want) {
				t.Fatalf("kept %v, want %v", rel, c.want)
			}
		})
	}
}

// An unreadable obj/ may hold the build, so its project counts as compiled.
func TestCompiledProjects_UnreadableObj(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	dir := composeILBuildDir(t, map[string][]byte{
		"App.csproj":                       []byte("<Project></Project>"),
		"obj/Release/net8.0/App.dll":       nil,
		"Installer/Installer.csproj":       []byte("<Project></Project>"),
		"Installer/obj/project.nuget.json": nil,
	})
	locked := filepath.Join(dir, "Installer", "obj")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if got := compiledProjects(dir, findProjectFiles(dir)); len(got) != 2 {
		t.Fatalf("kept %v, want both", got)
	}
}

// TestReachability_UncompiledProjectBesideTheBuild: GoNorth's shape. The installer project the
// build never compiled no longer withholds the run, and the dependencies come from the traced
// project's own restore, not the installer's, which sorts first.
func TestReachability_UncompiledProjectBesideTheBuild(t *testing.T) {
	for _, installerCompiled := range []bool{false, true} {
		files := map[string][]byte{
			"App.csproj":                        restoredProject,
			"bin/App.dll":                       appCalling(nil, false, true),
			"bin/Dep.dll":                       depWithBoomOverloads(false),
			"obj/project.assets.json":           depAssetsJSON("Dep/1.0.0"),
			"obj/Release/net8.0/App.dll":        appCalling(nil, false, true),
			"Installer/Installer.csproj":        []byte("<Project></Project>"),
			"Installer/obj/project.assets.json": depAssetsJSON("Other/1.0.0"),
		}
		if installerCompiled {
			files["Installer/obj/Release/net8.0/Installer.dll"] = nil
		}
		dir := composeILBuildDir(t, files)
		shiftObjAssemblies(t, dir, time.Minute)
		res, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{boomSCIP}})
		if err != nil {
			t.Fatal(err)
		}
		if got := hasILReason(res.Partiality, partialReasonMultipleProjects); got != installerCompiled {
			t.Fatalf("installer compiled %v: %s present = %v (partiality %+v)", installerCompiled, partialReasonMultipleProjects, got, res.Partiality)
		}
		if got := slices.Contains(res.Searched, boomSCIP); got == installerCompiled {
			t.Fatalf("installer compiled %v: Searched = %v (partiality %+v)", installerCompiled, res.Searched, res.Partiality)
		}
	}
}

// shiftObjAssemblies sets the modification time of every .dll under an obj/ directory in dir to
// now plus d, ordering it against the restore output written beside it.
func shiftObjAssemblies(t *testing.T, dir string, d time.Duration) {
	t.Helper()
	when := time.Now().Add(d)
	_ = filepath.WalkDir(dir, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() || filepath.Ext(path) != ".dll" {
			return nil //nolint:nilerr // fixture walk
		}
		if strings.Contains(filepath.ToSlash(path), "/obj/") {
			if err := os.Chtimes(path, when, when); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	})
}

// TestResolveInventory_RootProjectReadsItsOwnRestore: a root project's inventory comes from its
// own obj/project.assets.json, not a nested project's, which sorts first.
func TestResolveInventory_RootProjectReadsItsOwnRestore(t *testing.T) {
	dir := composeILBuildDir(t, map[string][]byte{
		"App.csproj":                        []byte("<Project></Project>"),
		"obj/project.assets.json":           depAssetsJSON("Dep/1.0.0"),
		"Installer/Installer.csproj":        []byte("<Project></Project>"),
		"Installer/obj/project.assets.json": depAssetsJSON("Other/1.0.0"),
	})
	inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	var app []string
	for _, n := range inv.Nodes {
		if strings.HasPrefix(n.ID, "App.csproj|") {
			app = append(app, n.ID)
		}
	}
	if len(app) == 0 || slices.ContainsFunc(app, func(id string) bool { return strings.Contains(strings.ToLower(id), "other") }) ||
		!slices.ContainsFunc(app, func(id string) bool { return strings.Contains(strings.ToLower(id), "/dep@") }) {
		t.Fatalf("App.csproj nodes = %v, want Dep only (all %v)", app, inv.Nodes)
	}
}

// A lockfile or packages.config inside a nested project's directory is that project's.
func TestFindOwnFile_SkipsNestedProjects(t *testing.T) {
	dir := composeILBuildDir(t, map[string][]byte{
		"App.csproj":                        nil,
		"Installer/Installer.csproj":        nil,
		"Installer/packages.lock.json":      nil,
		"Installer/obj/project.assets.json": nil,
		"src/packages.lock.json":            nil,
	})
	if got, ok := findOwnFile(dir, dir, "packages.lock.json", false); !ok || relSlash(dir, got) != "src/packages.lock.json" {
		t.Fatalf("lock = %q, %v; want src/packages.lock.json", got, ok)
	}
	if got, ok := findOwnFile(dir, dir, "project.assets.json", true); ok {
		t.Fatalf("assets = %q, want none outside the nested project", got)
	}
}

// An import above the build root that moves one project's obj keeps every project.
func TestCompiledProjects_ImportAboveBuildDir(t *testing.T) {
	root := composeILBuildDir(t, map[string][]byte{
		"eng/out.props":                    []byte("<Project><PropertyGroup><BaseIntermediateOutputPath>out/</BaseIntermediateOutputPath></PropertyGroup></Project>"),
		"src/App/App.csproj":               []byte("<Project></Project>"),
		"src/App/obj/Release/net8.0/A.dll": nil,
		"src/Worker/Worker.csproj":         []byte(`<Project><Import Project="..\..\eng\out.props" /></Project>`),
	})
	dir := filepath.Join(root, "src")
	shiftObjAssemblies(t, dir, time.Minute)
	if got := compiledProjects(dir, findProjectFiles(dir)); len(got) != 2 {
		t.Fatalf("kept %v, want both projects", got)
	}
}

// A Directory.Build.props above the build root that moves one project's obj keeps every project.
func TestCompiledProjects_DirectoryBuildPropsAboveBuildDir(t *testing.T) {
	root := composeILBuildDir(t, map[string][]byte{
		"Directory.Build.props":            []byte(`<Project><PropertyGroup><BaseIntermediateOutputPath Condition="'$(MSBuildProjectName)' == 'Worker'">out/</BaseIntermediateOutputPath></PropertyGroup></Project>`),
		"src/App/App.csproj":               []byte("<Project></Project>"),
		"src/App/obj/Release/net8.0/A.dll": nil,
		"src/Worker/Worker.csproj":         []byte("<Project></Project>"),
	})
	dir := filepath.Join(root, "src")
	shiftObjAssemblies(t, dir, time.Minute)
	if got := compiledProjects(dir, findProjectFiles(dir)); len(got) != 2 {
		t.Fatalf("kept %v, want both projects", got)
	}
}

// Imports resolved through MSBuild escapes, property functions and per-project properties; each
// case's build root is sub under the composed tree.
func TestCompiledProjects_ImportResolution(t *testing.T) {
	const moves = "<Project><PropertyGroup><BaseIntermediateOutputPath>out/</BaseIntermediateOutputPath></PropertyGroup></Project>"
	cases := []struct {
		name  string
		sub   string
		files map[string]string
		want  int
	}{
		{"GetPathOfFileAbove reaches a props file above the build root", "src", map[string]string{
			"Common.props": moves, "src/App/App.csproj": "<Project></Project>", "src/App/obj/Release/net8.0/A.dll": "",
			"src/Worker/Worker.csproj": `<Project><Import Project="$([MSBuild]::GetPathOfFileAbove('Common.props', '$(MSBuildThisFileDirectory)../'))" /></Project>`,
		}, 2},
		{"GetDirectoryNameOfFileAbove reaches a props file above the build root", "src", map[string]string{
			"Common.props": moves, "src/App/App.csproj": "<Project></Project>", "src/App/obj/Release/net8.0/A.dll": "",
			"src/Worker/Worker.csproj": `<Project><Import Project="$([MSBuild]::GetDirectoryNameOfFileAbove($(MSBuildThisFileDirectory), Common.props))\Common.props" /></Project>`,
		}, 2},
		{"a shared props file imports a per-project file", "", map[string]string{
			"App/App.csproj": "<Project></Project>", "App/obj/Release/net8.0/A.dll": "",
			"Worker/Worker.csproj":  "<Project></Project>",
			"Worker/local.settings": moves,
			"Directory.Build.props": `<Project><Import Project="$(MSBuildProjectDirectory)\local.settings" Condition="Exists('$(MSBuildProjectDirectory)\local.settings')" /></Project>`,
		}, 2},
		{"an escaped import path", "", map[string]string{
			"App/App.csproj": "<Project></Project>", "App/obj/Release/net8.0/A.dll": "",
			"Worker/Worker.csproj": `<Project><Import Project="..\build%5Cout.settings" /></Project>`, "build/out.settings": moves,
		}, 2},
		{"a property function the expander does not model", "", map[string]string{
			"App/App.csproj": "<Project></Project>", "App/obj/Release/net8.0/A.dll": "",
			"Worker/Worker.csproj": `<Project><Import Project="$([System.IO.Path]::Combine('..', 'out.settings'))" /></Project>`,
		}, 2},
		{"a build root whose path holds glob metacharacters", "repo[1]", map[string]string{
			"repo[1]/App/App.csproj": "<Project></Project>", "repo[1]/App/obj/Release/net8.0/A.dll": "",
			"repo[1]/Worker/Worker.csproj": `<Project><Import Project="..\build\out.settings" /></Project>`, "repo[1]/build/out.settings": moves,
		}, 2},
		{"the chained Directory.Build.props idiom keeps the drop", "", map[string]string{
			"App/App.csproj": "<Project></Project>", "App/obj/Release/net8.0/A.dll": "", "Worker/Worker.csproj": "<Project></Project>",
			"Directory.Build.props":        "<Project><PropertyGroup><LangVersion>latest</LangVersion></PropertyGroup></Project>",
			"Worker/Directory.Build.props": `<Project><Import Project="$([MSBuild]::GetPathOfFileAbove('Directory.Build.props', '$(MSBuildThisFileDirectory)../'))" /></Project>`,
		}, 1},
		{"a commented-out import keeps the drop", "", map[string]string{
			"App/App.csproj": "<Project></Project>", "App/obj/Release/net8.0/A.dll": "",
			"Worker/Worker.csproj": `<Project><!-- <Import Project="$(Foo)\x.props" /> --></Project>`,
		}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string][]byte{}
			for k, v := range c.files {
				files[k] = []byte(v)
			}
			dir := filepath.Join(composeILBuildDir(t, files), c.sub)
			shiftObjAssemblies(t, dir, time.Minute)
			if got := compiledProjects(dir, findProjectFiles(dir)); len(got) != c.want {
				t.Fatalf("kept %v, want %d", got, c.want)
			}
		})
	}
}

// The single-project inventory reads its own project's lockfile and packages.config, even when
// the project sits in a subdirectory of the build root.
func TestResolveInventory_SingleNestedProjectReadsItsOwnFiles(t *testing.T) {
	cases := []struct {
		name  string
		files map[string][]byte
		want  []string
	}{
		{"lockfile beside the project", map[string][]byte{
			"src/App/App.csproj": []byte(`<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>`),
			"src/App/packages.lock.json": []byte(`{"version":1,"dependencies":{"net8.0":{` +
				`"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.1, )","resolved":"13.0.1"},` +
				`"Transitive.Pkg":{"type":"Transitive","resolved":"2.0.0"}}}}`),
		}, []string{"newtonsoft.json@13.0.1", "transitive.pkg@2.0.0"}},
		{"packages.config beside a legacy project", map[string][]byte{
			"src/Legacy/Legacy.csproj":   []byte(`<Project ToolsVersion="15.0"></Project>`),
			"src/Legacy/packages.config": []byte(`<packages><package id="Newtonsoft.Json" version="9.0.1" /></packages>`),
		}, []string{"newtonsoft.json@9.0.1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: composeILBuildDir(t, c.files)})
			if err != nil {
				t.Fatal(err)
			}
			ids := strings.ToLower(fmt.Sprint(inv.Nodes))
			for _, w := range c.want {
				if !strings.Contains(ids, w) {
					t.Errorf("missing %s in %v", w, inv.Nodes)
				}
			}
		})
	}
}

// Declared-manifest parsing reads the project being resolved, not a nested one that sorts first.
func TestResolveInventory_DeclaredManifestIsTheResolvedProjects(t *testing.T) {
	ref := func(id string) []byte {
		return []byte(`<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="` + id + `" Version="1.0.0" /></ItemGroup></Project>`)
	}
	inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: composeILBuildDir(t, map[string][]byte{
		"Zeta.csproj":                ref("Dep"),
		"Installer/Installer.csproj": ref("Other"),
	})})
	if err != nil {
		t.Fatal(err)
	}
	var zeta []string
	for _, n := range inv.Nodes {
		if strings.HasPrefix(n.ID, "Zeta.csproj|") {
			zeta = append(zeta, strings.ToLower(n.ID))
		}
	}
	if j := strings.Join(zeta, " "); !strings.Contains(j, "/dep@") || strings.Contains(j, "other") {
		t.Fatalf("Zeta.csproj nodes = %v, want Dep only (all %v)", zeta, inv.Nodes)
	}
}
