package dotnetanalysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

func writeFixtureFile(t *testing.T, dir, rel, data string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

// closedBuild is a build restore settles on a trusted assets file that records only Other,
// with nothing else in the tree that could bring a package in. edit, when set, changes it.
func closedBuild(t *testing.T, edit func(t *testing.T, dir string)) string {
	t.Helper()
	f := newDepFixture(t, `"Other/1.0.0":{"type":"package"}`, `"Other/1.0.0":{"type":"package","path":"other/1.0.0"}`)
	if edit != nil {
		edit(t, f.buildDir)
	}
	return f.buildDir
}

// withFile adds one file to the build.
func withFile(rel, data string) func(*testing.T, string) {
	return func(t *testing.T, dir string) { writeFixtureFile(t, dir, rel, data) }
}

// withItems rewrites App.csproj to hold items beside what its restore was made from.
func withItems(items string) func(*testing.T, string) {
	return withFile("App.csproj", projectDeclaring([]string{"net8.0"}, nil, items))
}

func exhaustiveFor(t *testing.T, dir, coordinate string) plugin.DependencyVersionResult {
	t.Helper()
	res, err := ResolveDependencyVersions(t.Context(), plugin.ResolveVersionsRequest{BuildDir: dir, Coordinate: coordinate})
	if err != nil {
		t.Fatalf("ResolveDependencyVersions: %v", err)
	}
	return res
}

// TestNotInBuild_ClosedBuild: in a closed build a package restore didn't record is not present
// in the build. The symbol lookup says so for that package alone, with no run-wide reason, and
// the version read vouches for the absence. A package restore did record is present.
func TestNotInBuild_ClosedBuild(t *testing.T) {
	dir := closedBuild(t, nil)
	res := resolveNewtonsoft(t, depFixture{buildDir: dir}, "Newtonsoft.Json.JsonConvert.DeserializeObject")
	want := plugin.Partiality{Scoped: []plugin.ScopedReason{{
		Reason:  partialReasonDependencyNotInBuild,
		Package: "pkg:nuget/newtonsoft.json",
		Path:    "Newtonsoft.Json is not present in the build",
		Targets: []string{"pkg:nuget/newtonsoft.json"},
	}}}
	if len(res.Resolved) != 0 || len(res.Matched) != 0 || res.Partiality.Complete ||
		len(res.Partiality.Reasons) != 0 || !slices.EqualFunc(res.Partiality.Scoped, want.Scoped, scopedEqual) {
		t.Fatalf("result = %+v, want only %+v", res, want)
	}
	if v := exhaustiveFor(t, dir, "Newtonsoft.Json"); !v.Exhaustive || v.Found {
		t.Fatalf("absent package: Exhaustive=%v Found=%v, want true/false", v.Exhaustive, v.Found)
	}
	if v := exhaustiveFor(t, dir, "Other"); !v.Found {
		t.Fatalf("recorded package: Found=false, want true")
	}
	if got := report.ClassifyPartialityReason(partialReasonDependencyNotInBuild); got != report.PartialityDidNotRun {
		t.Fatalf("ClassifyPartialityReason = %q, want did-not-run: intake, not the lane's word, settles the advisory", got)
	}
}

func scopedEqual(a, b plugin.ScopedReason) bool {
	return a.Reason == b.Reason && a.Package == b.Package && a.Path == b.Path && slices.Equal(a.Targets, b.Targets)
}

// TestNotInBuild_OpenBuildKeepsMainsAnswer: anything this lane does not positively close leaves
// the answer as it was: no_dependency_artifact, unbounded, scoped and run-wide, and no
// Exhaustive.
func TestNotInBuild_OpenBuildKeepsMainsAnswer(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*testing.T, string)
	}{
		{"vendored assembly", withFile("lib/Newtonsoft.Json.dll", "MZ")},
		{"vendored executable", withFile("tools/run.exe", "MZ")},
		{"windows metadata", withFile("lib/Api.winmd", "MZ")},
		{"package file in the tree", withFile("feed/newtonsoft.json.13.0.1.nupkg", "PK")},
		{"paket dependencies", withFile("paket.dependencies", "nuget Newtonsoft.Json\n")},
		{"paket lock", withFile("paket.lock", "NUGET\n")},
		{"paket references", withFile("src/paket.references", "Newtonsoft.Json\n")},
		{"F# script", withFile("build.fsx", "#r \"nuget: Newtonsoft.Json\"\n")},
		{"C# script", withFile("tool.csx", "#r \"nuget: Newtonsoft.Json, 13.0.1\"\n")},
		{"cake script", withFile("build.cake", "#addin nuget:?package=Newtonsoft.Json\n")},
		{"shared project", withFile("Shared/Shared.shproj", "<Project/>")},
		{"shared project items", withFile("Shared/Shared.projitems", "<Project/>")},
		{"another project kind", withFile("Db/Db.sqlproj", "<Project/>")},
		{"traversal project", withFile("build.proj", "<Project/>")},
		{"solution naming a project outside the tree", withFile("App.sln", "Project(\"{FAE04EC0}\") = \"Lib\", \"..\\Lib\\Lib.csproj\", \"{1}\"\nEndProject\n")},
		{"solution naming a project in a skipped directory", func(t *testing.T, dir string) {
			writeFixtureFile(t, dir, ".tools/Tool.csproj", projectDeclaring([]string{"net8.0"}, nil, ""))
			writeFixtureFile(t, dir, "App.slnx", `<Solution><Project Path=".tools/Tool.csproj" /></Solution>`)
		}},
		{"symlink", func(t *testing.T, dir string) {
			if err := os.Symlink("Decoy.cs", filepath.Join(dir, "Link.cs")); err != nil {
				t.Fatal(err)
			}
		}},
		{"assembly in a dot directory", withFile(".vendor/Newtonsoft.Json.dll", "MZ")},
		{"assembly under packages", withFile("packages/Newtonsoft.Json.13.0.1/lib/netstandard2.0/Newtonsoft.Json.dll", "MZ")},
		{"assembly under node_modules", withFile("node_modules/x/x.dll", "MZ")},
		{"assembly in a nested bin directory", withFile("tools/bin/Vendor.dll", "MZ")},
		{"item reaching into build output", withItems(`<ItemGroup><None Include="bin/vendor/payload.bin" CopyToOutputDirectory="PreserveNewest" /></ItemGroup>`)},
		{"item reaching into restore output", withItems(`<ItemGroup><Content Include="obj\vendor\payload.bin" /></ItemGroup>`)},
		{"reference to an assembly a package ships under another name", withItems(`<ItemGroup><Reference Include="ICSharpCode.SharpZipLib" /></ItemGroup>`)},
		{"assembly search paths", withItems(`<PropertyGroup><AssemblySearchPaths>{CandidateAssemblyFiles};vendor</AssemblySearchPaths></PropertyGroup>`)},
		{"an assembly search path toggle", withItems(`<PropertyGroup><AssemblySearchPath_UseGAC>true</AssemblySearchPath_UseGAC></PropertyGroup>`)},
		{"reference path", withItems(`<PropertyGroup><ReferencePath>vendor</ReferencePath></PropertyGroup>`)},
		{"references added by property", withItems(`<PropertyGroup><AdditionalExplicitAssemblyReferences>Vendor</AdditionalExplicitAssemblyReferences></PropertyGroup>`)},
		{"lockfile without a project", withFile("orphan/packages.lock.json", `{"version":1,"dependencies":{}}`)},
		{"a project with no restore record", withFile("Lib/Lib.csproj", projectDeclaring([]string{"net8.0"}, nil, ""))},
		{"stale restore record", withItems(`<ItemGroup><PackageReference Include="Serilog" Version="3.0.0" /></ItemGroup>`)},
		{"reference with a hint path", withItems(`<ItemGroup><Reference Include="Vendor"><HintPath>vendor/Vendor.dll</HintPath></Reference></ItemGroup>`)},
		{"reference to an assembly file", withItems(`<ItemGroup><Reference Include="vendor\Vendor.dll" /></ItemGroup>`)},
		{"reference to an assembly file by name", withItems(`<ItemGroup><Reference Include="Vendor.dll" /></ItemGroup>`)},
		{"reference to an assembly by path", withItems(`<ItemGroup><Reference Include="lib/Vendor" /></ItemGroup>`)},
		{"framework-named reference to an assembly file", withItems(`<ItemGroup><Reference Include="System.Vendor.dll" /></ItemGroup>`)},
		{"framework-named reference by path", withItems(`<ItemGroup><Reference Include="System.Vendor/Lib" /></ItemGroup>`)},
		{"framework reference with a hint path", withItems(`<ItemGroup><Reference Include="System.Xml"><HintPath>vendor\System.Xml</HintPath></Reference></ItemGroup>`)},
		{"two projects in one directory", withFile("Lib.csproj", projectDeclaring([]string{"net8.0"}, nil, ""))},
		{"download dependencies restore wrote in another shape", withDownloadValue("net8.0", "pending")},
		{"reference with unknown metadata", withItems(`<ItemGroup><Reference Include="Vendor"><Foo>x</Foo></Reference></ItemGroup>`)},
		{"package download", withItems(`<ItemGroup><PackageDownload Include="Newtonsoft.Json" Version="[13.0.1]" /></ItemGroup>`)},
		{"analyzer item", withItems(`<ItemGroup><Analyzer Include="tools/Gen.dll" /></ItemGroup>`)},
		{"target", withItems(`<Target Name="Fetch" BeforeTargets="Build"><Exec Command="curl -o x https://example.invalid/x" /></Target>`)},
		{"using task", withItems(`<UsingTask TaskName="Fetch" AssemblyFile="tasks.dll" />`)},
		{"item definition group", withItems(`<ItemDefinitionGroup><Reference><Private>true</Private></Reference></ItemDefinitionGroup>`)},
		{"content copied from outside the tree", withItems(`<ItemGroup><Content Include="..\vendor\**" CopyToOutputDirectory="Always" /></ItemGroup>`)},
		{"content from a property", withItems(`<ItemGroup><None Include="$(VendorDir)/x" /></ItemGroup>`)},
		{"none naming an assembly", withItems(`<ItemGroup><None Include="Newtonsoft.Json.dll" CopyToOutputDirectory="Always" /></ItemGroup>`)},
		{"embedded resource from a rooted path", withItems(`<ItemGroup><EmbeddedResource Include="/opt/vendor/x.bin" /></ItemGroup>`)},
		{"link metadata outside the tree", withItems(`<ItemGroup><None Include="x.txt"><Link>..\x.txt</Link></None></ItemGroup>`)},
		{"escaped parent path", withItems(`<ItemGroup><None Include="%2E%2E/vendor/payload.bin" CopyToOutputDirectory="PreserveNewest" /></ItemGroup>`)},
		{"escaped rooted path", withItems(`<ItemGroup><None Include="%2Fopt/vendor/payload.bin" CopyToOutputDirectory="PreserveNewest" /></ItemGroup>`)},
		{"escaped import", withItems(`<Import Project="%2E%2E/outside.props" Condition="Exists('%2E%2E/outside.props')" />`)},
		{"item reaching into git metadata", withItems(`<ItemGroup><None Include=".git/vendor/payload.bin" CopyToOutputDirectory="PreserveNewest" /></ItemGroup>`)},
		{"vendored shared library", withFile("native/libSkiaSharp.so", "\x7fELF")},
		{"vendored versioned shared library", withFile("native/libSkiaSharp.so.1", "\x7fELF")},
		{"vendored dynamic library", withFile("native/libSkiaSharp.dylib", "\xcf\xfa")},
		{"vendored static library", withFile("native/libSkiaSharp.a", "!<arch>")},
		{"file named as a framework reference", func(t *testing.T, dir string) {
			withItems(`<ItemGroup><Reference Include="System.Net.Http.Formatting" /></ItemGroup>`)(t, dir)
			writeFixtureFile(t, dir, "System.Net.Http.Formatting", "MZ")
		}},
		{"an explicit target platform", withItems(`<PropertyGroup><TargetPlatformIdentifier>Windows</TargetPlatformIdentifier></PropertyGroup>`)},
		{"an explicit target platform version", withItems(`<PropertyGroup><TargetPlatformVersion>10.0.19041.0</TargetPlatformVersion></PropertyGroup>`)},
		{"wildcard content", withItems(`<ItemGroup><Content Include="wwwroot\**" /></ItemGroup>`)},
		{"wildcard reaching skipped directories", withItems(`<ItemGroup><None Include="**/*.so" CopyToOutputDirectory="PreserveNewest" /></ItemGroup>`)},
		{"single-character wildcard", withItems(`<ItemGroup><None Include="b?n/x.txt" /></ItemGroup>`)},
		{"item naming a shared library", withItems(`<ItemGroup><None Include="native/libSkiaSharp.so" CopyToOutputDirectory="PreserveNewest" /></ItemGroup>`)},
		{"item naming a versioned shared library", withItems(`<ItemGroup><None Include="native/libSkiaSharp.so.1" CopyToOutputDirectory="PreserveNewest" /></ItemGroup>`)},
		{"item naming a dynamic library", withItems(`<ItemGroup><None Include="native/libSkiaSharp.dylib" CopyToOutputDirectory="PreserveNewest" /></ItemGroup>`)},
		{"item naming a static library", withItems(`<ItemGroup><None Include="native/libSkiaSharp.a" /></ItemGroup>`)},
		{"assembly in a nested git directory", withFile("vendor/.git/Newtonsoft.Json.dll", "MZ")},
		{"an SDK hook property", withItems(`<PropertyGroup><CodeAnalysisTargets>hooks/ca.targets</CodeAnalysisTargets></PropertyGroup>`)},
		{"a framework search-path property", withItems(`<PropertyGroup><WinFXAssemblyDirectory>vendor</WinFXAssemblyDirectory></PropertyGroup>`)},
		{"an unknown property", withItems(`<PropertyGroup><NewtonsoftVersion>13.0.1</NewtonsoftVersion></PropertyGroup>`)},
		{"a response file beside the project", withFile("MSBuild.rsp", "-p:CodeAnalysisTargets=hooks/ca.targets\n")},
		{"a toolset import climbing out", withItems(`<Import Project="$(MSBuildToolsPath)/../../../../hooks/h.targets" />`)},
		{"a toolset import expanding a property", withItems(`<Import Project="$(MSBuildBinPath)/$(Hook)" />`)},
		{"a toolset import listing a second file", withItems(`<Import Project="$(MSBuildToolsPath)/Microsoft.Common.Test.targets;hooks/h.targets" />`)},
		{"an import listing two files", withItems(`<Import Project="build/a.targets;build/hook.targets" Condition="Exists('build/a.targets;build/hook.targets')" />`)},
		{"a vendored script", withFile("wwwroot/lib/moment/moment.min.js", "")},
		{"a vendored stylesheet source", withFile("wwwroot/lib/bs/less/variables.less", "")},
		{"a vendored script committed gzip-compressed only", withFile("wwwroot/lib/moment/moment.min.js.gz", "")},
		{"a vendored script committed brotli-compressed only", withFile("wwwroot/lib/moment/moment.min.js.br", "")},
		{"a toolset import with a wildcard", withItems(`<Import Project="$(MSBuildBinPath)/hooks/*.targets" />`)},
		{"a project's PackageId", withItems(`<PropertyGroup><PackageId>Newtonsoft.Json</PackageId></PropertyGroup>`)},
		{"a project's AssemblyName", withItems(`<PropertyGroup><AssemblyName>App.Web</AssemblyName></PropertyGroup>`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := closedBuild(t, tc.edit)
			res := resolveNewtonsoft(t, depFixture{buildDir: dir}, "Newtonsoft.Json.JsonConvert.DeserializeObject")
			if res.Partiality.Complete || len(res.Partiality.Scoped) != 1 ||
				res.Partiality.Scoped[0].Reason != partialReasonNoDependencyArtifact ||
				res.Partiality.Scoped[0].Targets != nil ||
				!hasILReason(res.Partiality, partialReasonNoDependencyArtifact) {
				t.Fatalf("partiality = %+v, want no_dependency_artifact unbounded, scoped and run-wide", res.Partiality)
			}
			if v := exhaustiveFor(t, dir, "Newtonsoft.Json"); v.Exhaustive {
				t.Fatalf("Exhaustive = true for a build that is not closed")
			}
		})
	}
}

// TestNotInBuild_WantSpecific: a package the build could hold other than through restore's
// record is never proven absent, though the build is closed for every other package.
func TestNotInBuild_WantSpecific(t *testing.T) {
	for _, tc := range []struct {
		name, coordinate string
		edit             func(*testing.T, string)
	}{
		{"the build's own project", "App", nil},
		{"a framework reference by name", "System.Text.Json", withItems(`<ItemGroup><Reference Include="System.Text.Json" /></ItemGroup>`)},
		{"a strong-named framework reference", "System.Net.Http", withItems(`<ItemGroup><Reference Include="System.Net.Http, Version=4.0.0.0, Culture=neutral" /></ItemGroup>`)},
		{"a shared framework", "Microsoft.AspNetCore.App", withItems(`<ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" /></ItemGroup>`)},
		{"a runtime pack", "Microsoft.NETCore.App.Runtime.linux-x64", nil},
		{"an ASP.NET Core runtime pack", "Microsoft.AspNetCore.App.Runtime.win-x64", nil},
		{"a desktop runtime pack", "Microsoft.WindowsDesktop.App.Runtime.win-x64", nil},
		{"an AOT compiler pack", "Microsoft.DotNet.ILCompiler", nil},
		{"a runtime-specific package", "runtime.linux-x64.Microsoft.DotNet.ILCompiler", nil},
		{"a targeting pack", "Microsoft.Windows.SDK.NET.Ref", nil},
		{"the .NET Standard targeting pack", "NETStandard.Library.Ref", nil},
		{"a workload runtime pack", "Microsoft.NET.Runtime.WebAssembly.Sdk", nil},
		{"a workload manifest", "Microsoft.NET.Workload.Mono.ToolChain.Current.Manifest-8.0.100", nil},
		{"an SDK pack", "Microsoft.NET.Sdk.Android.Manifest-8.0.100", nil},
		{"framework reference assemblies", "Microsoft.NETFramework.ReferenceAssemblies.net48", nil},
		{"a download restore records", "Contoso.Pack", withDownload("net8.0", "Contoso.Pack")},
		{"a vendored library", "jQuery", withFile("wwwroot/lib/jquery/LICENSE.txt", "")},
		{"a vendored library named with a dash", "jQuery.Validation", withFile("wwwroot/lib/jquery-validation/LICENSE.md", "")},
		{"a vendored library named with an underscore", "Bootstrap.Sass", withFile("vendor/bootstrap_sass/README", "")},
		{"a dashed id vendored with a dash", "bootstrap-select", withFile("wwwroot/lib/bootstrap-select/LICENSE", "")},
		{"a dashed id vendored with a dot", "bootstrap-select", withFile("vendor/bootstrap.select/LICENSE", "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := closedBuild(t, tc.edit)
			if v := exhaustiveFor(t, dir, tc.coordinate); v.Exhaustive {
				t.Fatalf("Exhaustive = true for %s", tc.coordinate)
			}
			if v := exhaustiveFor(t, dir, "Serilog"); !v.Exhaustive || v.Found {
				t.Fatalf("an unrelated package: Exhaustive=%v Found=%v, want true/false", v.Exhaustive, v.Found)
			}
		})
	}
}

// TestNotInBuild_ClosedControls: what brings no package in leaves the build closed.
func TestNotInBuild_ClosedControls(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*testing.T, string)
	}{
		{"linked source from outside the project", withItems(`<ItemGroup><Compile Include="..\Shared\Util.cs" /></ItemGroup>`)},
		{"framework reference", withItems(`<ItemGroup><Reference Include="System.Xml" /></ItemGroup>`)},
		{"framework reference with metadata", withItems(`<ItemGroup><Reference Include="System.Data, Version=4.0.0.0"><Private>False</Private><RequiredTargetFramework>3.5</RequiredTargetFramework></Reference></ItemGroup>`)},
		{"shared framework", withItems(`<ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" /></ItemGroup>`)},
		{"content copied to output", withItems(`<ItemGroup><None Include="appsettings.json" CopyToOutputDirectory="PreserveNewest" /></ItemGroup>`)},
		{"conditioned content", withItems(`<ItemGroup><Content Include="wwwroot\site.css" Condition="'$(Configuration)' == 'Debug'" /></ItemGroup>`)},
		{"inert properties", withItems(`<PropertyGroup><OutputType>Exe</OutputType><Nullable>enable</Nullable><ImplicitUsings>enable</ImplicitUsings><LangVersion>latest</LangVersion><TreatWarningsAsErrors>true</TreatWarningsAsErrors></PropertyGroup>`)},
		{"restore toggles", withItems(`<PropertyGroup><RestoreLockedMode>false</RestoreLockedMode><CentralPackageTransitivePinningEnabled>false</CentralPackageTransitivePinningEnabled></PropertyGroup>`)},
		{"project extensions", withItems(`<ProjectExtensions><VisualStudio><Ref Path="..\x.dll" /></VisualStudio></ProjectExtensions>`)},
		{"solution naming the project", withFile("App.sln", "Project(\"{FAE04EC0}\") = \"App\", \"App.csproj\", \"{1}\"\nEndProject\n")},
		{"build output assembly", withFile("bin/Debug/net8.0/App.dll", "MZ")},
		{"restore output", withFile("obj/Debug/net8.0/App.dll", "MZ")},
		{"git metadata", withFile(".git/objects/x.dll", "MZ")},
		{"content under a folder named like output", withItems(`<ItemGroup><Content Include="wwwroot\binary.js" /></ItemGroup>`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := closedBuild(t, tc.edit)
			if v := exhaustiveFor(t, dir, "Newtonsoft.Json"); !v.Exhaustive || v.Found {
				t.Fatalf("Exhaustive=%v Found=%v, want true/false", v.Exhaustive, v.Found)
			}
		})
	}
}

// TestNotInBuild_CurrentLockfileAloneOpen: a current packages.lock.json settles what restore
// installs but not the packs the SDK downloads beside it, so it alone never proves absence.
// A package it lists, transitive included, is still found.
func TestNotInBuild_CurrentLockfileAloneOpen(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"App.csproj": `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup><PackageReference Include="DotNetZip" Version="[1.0,2.0)" /></ItemGroup>
</Project>`,
		"packages.lock.json": `{"version": 1, "dependencies": {"net8.0": {
  "DotNetZip": {"type": "Direct", "requested": "[1.0,2.0)", "resolved": "1.16.0"},
  "System.Text.Json": {"type": "Transitive", "resolved": "8.0.4"}}}}`,
	})
	if v := exhaustiveFor(t, dir, "Newtonsoft.Json"); v.Exhaustive {
		t.Fatalf("absent: Exhaustive = true on a lockfile alone")
	}
	if v := exhaustiveFor(t, dir, "System.Text.Json"); !v.Found {
		t.Fatalf("transitive: Found=false, want true")
	}
}

// TestNotInBuild_NoProjectOpen: a tree with no project settles nothing, so it proves no
// package absent, however closed the rest of it is.
func TestNotInBuild_NoProjectOpen(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"empty":       {},
		"source only": {"C.cs": "class C {}\n"},
	} {
		t.Run(name, func(t *testing.T) {
			if v := exhaustiveFor(t, writeTree(t, files), "Newtonsoft.Json"); v.Exhaustive {
				t.Fatalf("Exhaustive = true with no project")
			}
		})
	}
}

// TestNotInBuild_PlatformTargetOpen: a target framework that names a platform pulls in
// workload packs restore never records, so the build is open for every package.
func TestNotInBuild_PlatformTargetOpen(t *testing.T) {
	for _, tfm := range []string{"net8.0-android", "net10.0-windows10.0.19041.0"} {
		t.Run(tfm, func(t *testing.T) {
			dir := composeILBuildDir(t, map[string][]byte{
				"App.csproj":              restoredProject,
				"obj/project.assets.json": []byte(`{"version":3,"targets":{"` + tfm + `":{"Other/1.0.0":{"type":"package"}}},"libraries":{"Other/1.0.0":{"type":"package","path":"other/1.0.0"}}}`),
			})
			if v := exhaustiveFor(t, dir, "Other"); !v.Found || !v.Partiality.Complete {
				t.Fatalf("restore output not trusted for %s: %+v", tfm, v)
			}
			if v := exhaustiveFor(t, dir, "Serilog"); v.Exhaustive {
				t.Fatalf("Exhaustive = true for a %s build", tfm)
			}
		})
	}
}

// withDownloadValue sets alias's downloadDependencies in the build's trusted assets file to v.
func withDownloadValue(alias string, v any) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		editAssetsFramework(t, dir, alias, func(fw map[string]any) { fw["downloadDependencies"] = v })
	}
}

// withDownload records a download dependency for alias in the build's trusted assets file, as
// restore does for a pack the SDK downloads.
func withDownload(alias, id string) func(*testing.T, string) {
	return withDownloadValue(alias, []any{map[string]any{"name": id, "version": "[1.0.0, 1.0.0]"}})
}

// editAssetsFramework applies edit to alias's entry under project.frameworks in the build's
// assets file.
func editAssetsFramework(t *testing.T, dir, alias string, edit func(map[string]any)) {
	t.Helper()
	path := filepath.Join(dir, "obj", "project.assets.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var assets map[string]any
	if err := json.Unmarshal(data, &assets); err != nil {
		t.Fatal(err)
	}
	edit(assets["project"].(map[string]any)["frameworks"].(map[string]any)[alias].(map[string]any))
	out, err := json.Marshal(assets)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}
