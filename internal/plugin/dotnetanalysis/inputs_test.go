package dotnetanalysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// rangeA is a project whose Newtonsoft.Json version only its restore output or lockfile can
// determine.
var rangeA = csproj("Newtonsoft.Json", "[13.0,14.0)")

// rangeLock is a current lock for rangeA.
var rangeLock = lockEntries("Direct", "[13.0.0, 14.0.0)", map[string]string{"net8.0": "13.0.3"})

// rangeAssets is a current restore output for rangeA.
func rangeAssets() map[string]any {
	return assetsDoc("A/A.csproj", "net8.0", map[string]string{"Newtonsoft.Json": "[13.0.0, 14.0.0)"},
		map[string]string{"Newtonsoft.Json/13.0.3": "package"})
}

// TestVersions_InputSet: a project's version resolves only when every input MSBuild or NuGet
// consults for it is read and agrees. Each buildInputs entry has a row where it is present and
// not modeled (the project withholds) and, where it is modeled, a row where it is read and
// agrees (the project resolves). Every row starts from A, whose own declaration resolves.
func TestVersions_InputSet(t *testing.T) {
	cpmOn := `<PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>`
	dgspec := func(spec map[string]any) string {
		return jsonOf(map[string]any{"format": 1, "restore": map[string]any{"{{ROOT}}/A/A.csproj": map[string]any{}},
			"projects": map[string]any{"{{ROOT}}/A/A.csproj": spec}})
	}
	cache := func(success bool) string {
		return jsonOf(map[string]any{"version": 2, "dgSpecHash": "x", "success": success,
			"projectFilePath": "{{ROOT}}/A/A.csproj", "expectedPackageFiles": []string{}, "logs": []any{}})
	}
	withKey := func(doc map[string]any, where, key string) map[string]any {
		obj := doc["project"].(map[string]any)
		if where == "restore" {
			obj = obj["restore"].(map[string]any)
		}
		obj[key] = true
		return doc
	}
	foreignAssets := func() map[string]any {
		doc := rangeAssets()
		doc["project"] = projectSpec("{{ROOT}}/B", "B", []string{"net8.0"}, nil, map[string]string{"Newtonsoft.Json": "[13.0.0, 14.0.0)"})
		return doc
	}
	lockNet8 := lockEntries("Direct", "[13.0.0, 14.0.0)", map[string]string{"net8.0": "13.0.3"})
	lockBoth := lockEntries("Direct", "[13.0.0, 14.0.0)", map[string]string{"net6.0": "13.0.3", "net8.0": "13.0.3"})
	twoTFMs := func(tfms ...string) string {
		return projectDeclaring(tfms, nil, `<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0,14.0)" /></ItemGroup>`)
	}
	closureLock := func(otherRange string) string {
		return `{"version": 1, "dependencies": {"net8.0": {
  "Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.0, 14.0.0)", "resolved": "13.0.3"},
  "Other": {"type": "Transitive", "resolved": "1.0.0"},
  "b": {"type": "Project", "dependencies": {"Other": "` + otherRange + `"}}}}}`
	}
	refB := projectDeclaring([]string{"net8.0"}, nil,
		`<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0,14.0)" /><ProjectReference Include="../B/B.csproj" /></ItemGroup>`)
	bLock := `{"version": 1, "dependencies": {"net8.0": {"Other": {"type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0"}}}}`

	cases := []struct {
		name    string
		files   map[string]string
		root    string // the build dir under the tree, when not its root
		version string // "" wants an unknown copy
		reason  string
	}{
		{name: "control: A's own pin", files: map[string]string{}, version: "13.0.3"},
		{name: "control: a byte-order mark", files: map[string]string{"A/A.csproj": "\xef\xbb\xbf" + csproj("Newtonsoft.Json", "[13.0.3]")}, version: "13.0.3"},

		// B1: an Import path is followed only when it resolves to a file this lane reads.
		{name: "B1: an import through a property set in a file", files: map[string]string{
			"A/Directory.Build.props": msbuild(`<PropertyGroup><VSToolsPath>$(MSBuildThisFileDirectory)tools</VSToolsPath></PropertyGroup><Import Project="$(VSToolsPath)/x.targets" />`),
			"A/tools/x.targets":       msbuild(`<ItemGroup><PackageReference Update="Newtonsoft.Json" Version="12.0.1" /></ItemGroup>`),
		}, reason: reasonBuildInputUnmodeled},
		{name: "B1 control: the same import by a computed path is read", files: map[string]string{
			"A/Directory.Build.props": msbuild(`<Import Project="$(MSBuildThisFileDirectory)tools/x.targets" />`),
			"A/tools/x.targets":       msbuild(`<ItemGroup><PackageReference Update="Newtonsoft.Json" Version="12.0.1" /></ItemGroup>`),
		}, reason: reasonPackageReferenceUnmodeled},
		{name: "an import through an environment variable", files: map[string]string{
			"A/Directory.Build.props": msbuild(`<Import Project="$(SomeEnvVar)/x.targets" />`),
		}, reason: reasonBuildInputUnmodeled},
		{name: "an import through an environment variable, beside the file its empty expansion names", files: map[string]string{
			"A/Directory.Build.props": msbuild(`<Import Project="$(SomeEnvVar)x.targets" />`),
			"A/x.targets":             msbuild(""),
		}, reason: reasonBuildInputUnmodeled},
		{name: "a toolset import is the installation's", files: map[string]string{
			"A/Directory.Build.props": msbuild(`<Import Project="$(MSBuildToolsPath)/Microsoft.Common.targets" />`),
		}, version: "13.0.3"},
		{name: "a Directory.Packages.props import by a computed path is read", files: map[string]string{
			"Directory.Packages.props": `<Project>` + cpmOn + `<Import Project="$(MSBuildThisFileDirectory)eng/Versions.props" /></Project>`,
			"eng/Versions.props":       `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
			"A/A.csproj":               csproj("Newtonsoft.Json", ""),
			"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
		}, version: "13.0.3"},
		{name: "a Directory.Packages.props import with another version makes the lock stale", files: map[string]string{
			"Directory.Packages.props": `<Project>` + cpmOn + `<Import Project="$(MSBuildThisFileDirectory)eng/Versions.props" /></Project>`,
			"eng/Versions.props":       `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>`,
			"A/A.csproj":               csproj("Newtonsoft.Json", ""),
			"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
		}},

		// B2: a project's .user file is imported after it.
		{name: "B2: a .csproj.user", files: map[string]string{"A/A.csproj.user": msbuild("")}, reason: reasonBuildInputUnmodeled},
		{name: "B2: a .vbproj.user", files: map[string]string{
			"V/V.vbproj": csproj("Newtonsoft.Json", "[13.0.3]"), "V/V.vbproj.user": msbuild(""),
		}, reason: reasonBuildInputUnmodeled},
		{name: "B2: a .fsproj.user", files: map[string]string{
			"F/F.fsproj": csproj("Newtonsoft.Json", "[13.0.3]"), "F/F.fsproj.user": msbuild(""),
		}, reason: reasonBuildInputUnmodeled},
		{name: "B2 control: another project's .user is not imported", files: map[string]string{"A/Other.csproj.user": msbuild("")}, version: "13.0.3"},

		// B3: a response file can set any property.
		{name: "B3: Directory.Build.rsp beside the project", files: map[string]string{
			"A/Directory.Build.rsp": "-p:ManagePackageVersionsCentrally=false\n",
		}, reason: reasonBuildInputUnmodeled},
		{name: "B3: Directory.Build.rsp above the project", files: map[string]string{
			"Directory.Build.rsp": "-p:NuGetLockFilePath=other.lock.json\n",
		}, reason: reasonBuildInputUnmodeled},
		{name: "B3: Directory.Build.rsp elsewhere in the tree", files: map[string]string{
			"tools/Directory.Build.rsp": "-p:NuGetLockFilePath=other.lock.json\n",
		}, reason: reasonBuildInputUnmodeled},

		// B4: GetPathOfFileAbove only from the importing file's parent. The root file is what
		// the canonical form would find, so reading it in place of S's would resolve.
		{name: "B4: GetPathOfFileAbove from another directory", files: map[string]string{
			"Directory.Build.props":   msbuild(""),
			"S/Directory.Build.props": msbuild(newtonsoftRef12),
			"A/Directory.Build.props": msbuild(`<Import Project="$([MSBuild]::GetPathOfFileAbove('Directory.Build.props', '$(MSBuildThisFileDirectory)../S/'))" />`),
		}, reason: reasonBuildInputUnmodeled},

		// B5: a ProjectReference must stay in the tree.
		{name: "B5: a ProjectReference outside the build tree", root: "repo", files: map[string]string{
			"repo/A/A.csproj":    projectDeclaring([]string{"net8.0"}, nil, `<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.3]" /><ProjectReference Include="../../outside/O/O.csproj" /></ItemGroup>`),
			"outside/O/O.csproj": csproj("Newtonsoft.Json", "[12.0.1]"),
		}, reason: reasonBuildInputUnmodeled},
		{name: "B5 control: a ProjectReference inside the tree", files: map[string]string{
			"A/A.csproj": projectDeclaring([]string{"net8.0"}, nil, `<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.3]" /><ProjectReference Include="../B/B.csproj" /></ItemGroup>`),
			"B/B.csproj": sdkProject(""),
		}, version: "13.0.3"},

		{name: "a walk-up input above the build tree", root: "repo", files: map[string]string{
			"Directory.Build.props": msbuild(newtonsoftRef12),
			"repo/A/A.csproj":       csproj("Newtonsoft.Json", "[13.0.3]"),
		}, reason: reasonBuildInputUnmodeled},
		{name: "a walk-up input above the build tree, behind a nearer one", root: "repo", files: map[string]string{
			"Directory.Build.props":        msbuild(newtonsoftRef12),
			"repo/A/Directory.Build.props": msbuild(""),
			"repo/A/A.csproj":              csproj("Newtonsoft.Json", "[13.0.3]"),
		}, reason: reasonBuildInputUnmodeled},

		// N5: SDKs only from the bundled set, unversioned.
		{name: "control: a bundled SDK", files: map[string]string{
			"A/A.csproj": strings.Replace(csproj("Newtonsoft.Json", "[13.0.3]"), `Sdk="Microsoft.NET.Sdk"`, `Sdk="Microsoft.NET.Sdk.Web"`, 1),
		}, version: "13.0.3"},
		{name: "an SDK outside the bundled set", files: map[string]string{
			"A/A.csproj": strings.Replace(csproj("Newtonsoft.Json", "[13.0.3]"), `Sdk="Microsoft.NET.Sdk"`, `Sdk="Microsoft.NET.Sdk.Custom"`, 1),
		}, reason: reasonPackageReferenceUnmodeled},
		{name: "a versioned SDK", files: map[string]string{
			"A/A.csproj": strings.Replace(csproj("Newtonsoft.Json", "[13.0.3]"), `Sdk="Microsoft.NET.Sdk"`, `Sdk="Microsoft.NET.Sdk/8.0.100"`, 1),
		}, reason: reasonPackageReferenceUnmodeled},

		// B6: restore output is trusted only when it records this project as it stands.
		{name: "B6 control: current restore output", files: map[string]string{
			"A/A.csproj": rangeA, "A/obj/project.assets.json": jsonOf(rangeAssets()),
		}, version: "13.0.3"},
		{name: "B6: restore output of another project", files: map[string]string{
			"A/A.csproj": rangeA, "A/obj/project.assets.json": jsonOf(foreignAssets()),
		}, reason: reasonRestoreOutputStale},
		{name: "B6: restore output for another framework", files: map[string]string{
			"A/A.csproj": rangeA,
			"A/obj/project.assets.json": jsonOf(assetsDoc("A/A.csproj", "net6.0", map[string]string{"Newtonsoft.Json": "[13.0.0, 14.0.0)"},
				map[string]string{"Newtonsoft.Json/13.0.3": "package"})),
		}, reason: reasonRestoreOutputStale},
		{name: "B6: restore output recording another range", files: map[string]string{
			"A/A.csproj": rangeA,
			"A/obj/project.assets.json": jsonOf(assetsDoc("A/A.csproj", "net8.0", map[string]string{"Newtonsoft.Json": "[12.0.0, 14.0.0)"},
				map[string]string{"Newtonsoft.Json/13.0.3": "package"})),
		}, reason: reasonRestoreOutputStale},
		{name: "B6: restore output with a project field the lane can't compare", files: map[string]string{
			"A/A.csproj": rangeA, "A/obj/project.assets.json": jsonOf(withKey(rangeAssets(), "project", "futureField")),
		}, reason: reasonRestoreOutputStale},
		{name: "B6: restore output with a restore field the lane can't compare", files: map[string]string{
			"A/A.csproj": rangeA, "A/obj/project.assets.json": jsonOf(withKey(rangeAssets(), "restore", "futureField")),
		}, reason: reasonRestoreOutputStale},
		{name: "B6: an exact pin beside untrusted restore output", files: map[string]string{
			"A/obj/project.assets.json": jsonOf(foreignAssets()),
		}, reason: reasonRestoreOutputStale},
		{name: "B6 control: a dgspec that matches", files: map[string]string{
			"A/A.csproj": rangeA, "A/obj/project.assets.json": jsonOf(rangeAssets()),
			"A/obj/A.csproj.nuget.dgspec.json": dgspec(rangeAssets()["project"].(map[string]any)),
		}, version: "13.0.3"},
		{name: "B6: a dgspec of another restore", files: map[string]string{
			"A/A.csproj": rangeA, "A/obj/project.assets.json": jsonOf(rangeAssets()),
			"A/obj/A.csproj.nuget.dgspec.json": dgspec(projectSpec("{{ROOT}}/A", "A", []string{"net8.0"}, nil, map[string]string{"Newtonsoft.Json": "[12.0.0, 14.0.0)"})),
		}, reason: reasonRestoreOutputStale},
		{name: "B6 control: a successful restore cache", files: map[string]string{
			"A/A.csproj": rangeA, "A/obj/project.assets.json": jsonOf(rangeAssets()), "A/obj/project.nuget.cache": cache(true),
		}, version: "13.0.3"},
		{name: "B6: a failed restore cache", files: map[string]string{
			"A/A.csproj": rangeA, "A/obj/project.assets.json": jsonOf(rangeAssets()), "A/obj/project.nuget.cache": cache(false),
		}, reason: reasonRestoreOutputStale},
		{name: "restore-generated imports without restore output", files: map[string]string{
			"A/A.csproj": rangeA, "A/packages.lock.json": rangeLock, "A/obj/A.csproj.nuget.g.props": msbuild(""),
		}, reason: reasonRestoreOutputStale},

		// B7: a lock is current only with a section per framework.
		{name: "B7: a lock for one of two frameworks", files: map[string]string{
			"A/A.csproj": twoTFMs("net8.0", "netstandard2.0"), "A/packages.lock.json": lockNet8,
		}},
		{name: "B7 control: a lock for both frameworks", files: map[string]string{
			"A/A.csproj": twoTFMs("net6.0", "net8.0"), "A/packages.lock.json": lockBoth,
		}, version: "13.0.3"},
		{name: "B7: a lock for a framework the project lacks", files: map[string]string{
			"A/A.csproj": rangeA, "A/packages.lock.json": lockBoth,
		}},
		{name: "control: a current lock", files: map[string]string{"A/A.csproj": rangeA, "A/packages.lock.json": rangeLock}, version: "13.0.3"},
		{name: "a lock with a field the lane can't compare", files: map[string]string{
			"A/A.csproj":           rangeA,
			"A/packages.lock.json": `{"version": 1, "futureField": true, "dependencies": {"net8.0": {"Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.0, 14.0.0)", "resolved": "13.0.3"}}}}`,
		}},

		// A lock records each project of the reference closure with what it declares.
		{name: "lock closure control: the referenced project as it stands", files: map[string]string{
			"A/A.csproj": refB, "A/packages.lock.json": closureLock("[1.0.0, )"),
			"B/B.csproj": csproj("Other", "1.0.0"), "B/packages.lock.json": bLock,
		}, version: "13.0.3"},
		{name: "lock closure: the referenced project at another range", files: map[string]string{
			"A/A.csproj": refB, "A/packages.lock.json": closureLock("[0.9.0, )"),
			"B/B.csproj": csproj("Other", "1.0.0"), "B/packages.lock.json": bLock,
		}},
		{name: "lock closure: a project entry the project no longer references", files: map[string]string{
			"A/A.csproj": rangeA, "A/packages.lock.json": closureLock("[1.0.0, )"),
			"B/B.csproj": csproj("Other", "1.0.0"), "B/packages.lock.json": bLock,
		}},
		{name: "lock closure: the referenced project missing", files: map[string]string{
			"A/A.csproj": refB, "A/packages.lock.json": rangeLock,
			"B/B.csproj": csproj("Other", "1.0.0"), "B/packages.lock.json": bLock,
		}},

		// Every other buildInputs entry, present and not modeled.
		{name: "Directory.Build.props with an unknown PackageReference attribute", files: map[string]string{
			"A/Directory.Build.props": msbuild(`<ItemGroup><PackageReference Include="Other" Version="1.0.0" Future="x" /></ItemGroup>`),
		}, reason: reasonPackageReferenceUnmodeled},
		{name: "a project file with an unknown PackageReference attribute", files: map[string]string{
			"A/A.csproj": sdkProject(`<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.3]" Future="x" /></ItemGroup>`),
		}, reason: reasonPackageReferenceUnmodeled},
		{name: "Directory.Packages.props with an unknown PackageVersion attribute", files: map[string]string{
			"Directory.Packages.props": `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" Future="x" /></ItemGroup></Project>`,
		}, reason: reasonPackageReferenceUnmodeled},
		{name: "global.json naming MSBuild SDKs", files: map[string]string{
			"global.json": `{"sdk": {"version": "8.0.100"}, "msbuild-sdks": {"My.Sdk": "1.0.0"}}`,
		}, reason: reasonBuildInputUnmodeled},
		{name: "control: global.json picking the SDK", files: map[string]string{"global.json": `{"sdk": {"version": "8.0.100", "rollForward": "latestFeature"}}`}, version: "13.0.3"},
		{name: "nuget.config with an unknown section", files: map[string]string{
			"nuget.config": `<configuration><futureSection /></configuration>`,
		}, reason: reasonBuildInputUnmodeled},
		{name: "control: nuget.config choosing sources", files: map[string]string{
			"nuget.config": `<configuration><packageSources><clear /><add key="nuget" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>`,
		}, version: "13.0.3"},
		{name: "a per-project lockfile name", files: map[string]string{"A/packages.A.lock.json": rangeLock}, reason: reasonBuildInputUnmodeled},
		{name: "project.json", files: map[string]string{"A/project.json": `{}`}, reason: reasonBuildInputUnmodeled},
		{name: "a project extension import", files: map[string]string{"A/obj/A.csproj.custom.props": msbuild("")}, reason: reasonBuildInputUnmodeled},
		{name: "a solution hook", files: map[string]string{"Directory.Solution.props": msbuild("")}, reason: reasonBuildInputUnmodeled},
		{name: "a project-directory input named with other case", files: map[string]string{"A/Packages.Lock.json": rangeLock}, reason: reasonBuildInputUnmodeled},
		{name: "a walk-up input named with other case", files: map[string]string{"A/directory.build.props": msbuild(newtonsoftRef12)}, reason: reasonBuildInputUnmodeled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"A/A.csproj": csproj("Newtonsoft.Json", "[13.0.3]")}
			if tc.root != "" {
				files = map[string]string{}
			}
			for k, v := range tc.files {
				files[k] = v
			}
			dir := writeTree(t, files)
			if tc.root != "" {
				dir = filepath.Join(dir, tc.root)
			}
			r, kept := installedOf(t, dir, "Newtonsoft.Json")
			checkKept(t, kept, tc.version)
			if tc.reason != "" && !slices.Contains(r.Partiality.Reasons, tc.reason) {
				t.Errorf("want reason %q; got %v", tc.reason, r.Partiality.Reasons)
			}
		})
	}
}

// TestVersions_FIFOInputWithholds: an input that is not a regular file is never opened, so a
// FIFO named like one withholds instead of blocking the read.
func TestVersions_FIFOInputWithholds(t *testing.T) {
	dir := writeTree(t, map[string]string{"A/A.csproj": csproj("Newtonsoft.Json", "[13.0.3]")})
	if err := syscall.Mkfifo(filepath.Join(dir, "A", "Directory.Build.props"), 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan []plugin.ResolvedDependency, 1)
	go func() {
		_, kept := installedOf(t, dir, "Newtonsoft.Json")
		done <- kept
	}()
	select {
	case kept := <-done:
		checkKept(t, kept, "")
	case <-time.After(20 * time.Second):
		t.Fatal("reading the build inputs blocked on a FIFO")
	}
}

// TestReadInput_OnlyRegularFilesInTheTree pins readInput's admission rules directly.
func TestReadInput_OnlyRegularFilesInTheTree(t *testing.T) {
	dir := writeTree(t, map[string]string{"in/a.props": "\xef\xbb\xbf<Project />", "out/b.props": "<Project />"})
	root := filepath.Join(dir, "in")
	if err := os.Symlink(filepath.Join(dir, "out", "b.props"), filepath.Join(root, "link.props")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "fifo.props"), 0o644); err != nil {
		t.Fatal(err)
	}
	rootReal := realRoot(root)
	cases := []struct {
		name string
		want inputStatus
		data string
	}{
		{"a.props", inputRead, "<Project />"},
		{"missing.props", inputAbsent, ""},
		{"link.props", inputUnmodeled, ""},
		{"fifo.props", inputUnmodeled, ""},
		{"A.props", inputUnmodeled, ""},
	}
	for _, c := range cases {
		data, _, st := readInput(rootReal, filepath.Join(root, c.name))
		if c.name == "A.props" && st == inputAbsent {
			continue // a case-sensitive filesystem has no such file
		}
		if st != c.want || string(data) != c.data {
			t.Errorf("%s: status %v data %q, want %v %q", c.name, st, data, c.want, c.data)
		}
	}
}

// TestReachability_RestoreTrust: the IL tier loads dependency bytes through the same restore
// output the version resolver reads, so it searches only when AssetsTrusted holds for it.
func TestReachability_RestoreTrust(t *testing.T) {
	cases := []struct {
		name     string
		edit     func(t *testing.T, dir string)
		searched bool
	}{
		{name: "control: current restore output", edit: func(*testing.T, string) {}, searched: true},
		{name: "a dgspec of the project as it stands", edit: func(t *testing.T, dir string) {
			writeDGSpec(t, dir, assetsProject(t, dir))
		}, searched: true},
		{name: "a dgspec of another restore", edit: func(t *testing.T, dir string) {
			spec := assetsProject(t, dir)
			spec["restore"].(map[string]any)["originalTargetFrameworks"] = []string{"net6.0"}
			writeDGSpec(t, dir, spec)
		}},
		{name: "a project now on another framework", edit: func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "App.csproj"), projectDeclaring([]string{"net6.0"}, nil, ""))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := composeILBuildDir(t, map[string][]byte{
				"App.csproj":              restoredProject,
				"bin/App.dll":             appCalling(nil, false, true),
				"bin/Dep.dll":             depWithBoomOverloads(false),
				"obj/project.assets.json": depAssetsJSON("Dep/1.0.0"),
			})
			tc.edit(t, dir)
			res, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{boomSCIP}})
			if err != nil {
				t.Fatal(err)
			}
			if got := slices.Contains(res.Searched, boomSCIP); got != tc.searched {
				t.Fatalf("Searched = %v, want searched %v", res.Searched, tc.searched)
			}
			if got := hasILReason(res.Partiality, partialReasonRestoreUntrusted); got == tc.searched {
				t.Fatalf("Reasons = %v, want %s present %v", res.Partiality.Reasons, partialReasonRestoreUntrusted, !tc.searched)
			}
		})
	}
}

// assetsProject returns the project spec recorded in dir's obj/project.assets.json.
func assetsProject(t *testing.T, dir string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "obj", "project.assets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var assets map[string]any
	if err := json.Unmarshal(data, &assets); err != nil {
		t.Fatal(err)
	}
	return assets["project"].(map[string]any)
}

// writeDGSpec writes dir's obj/App.csproj.nuget.dgspec.json holding spec for App.csproj.
func writeDGSpec(t *testing.T, dir string, spec map[string]any) {
	t.Helper()
	path := spec["restore"].(map[string]any)["projectPath"].(string)
	writeFile(t, filepath.Join(dir, "obj", "App.csproj.nuget.dgspec.json"), jsonOf(map[string]any{
		"format": 1, "restore": map[string]any{path: map[string]any{}}, "projects": map[string]any{path: spec},
	}))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
