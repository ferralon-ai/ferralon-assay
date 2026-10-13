package dotnetanalysis

import (
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// assetsJSON renders an obj/project.assets.json with one target holding the given
// "id/version" library keys and their types.
func assetsJSON(libs map[string]string) string {
	var parts []string
	for _, key := range slices.Sorted(maps.Keys(libs)) {
		parts = append(parts, `"`+key+`": {"type": "`+libs[key]+`"}`)
	}
	return `{"version": 3, "targets": {"net8.0": {` + strings.Join(parts, ", ") + `}}}`
}

// centralTransitiveLock renders a packages.lock.json with Other as a version-less Direct
// reference and Newtonsoft.Json as a CentralTransitive entry.
func centralTransitiveLock(requested, resolved string) string {
	return `{"version": 1, "dependencies": {"net8.0": {` +
		`"Other": {"type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0"}, ` +
		`"Newtonsoft.Json": {"type": "CentralTransitive", "requested": "` + requested + `", "resolved": "` + resolved + `"}}}}`
}

func msbuild(items string) string {
	return `<Project>` + items + `</Project>`
}

const (
	newtonsoftRef12 = `<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[12.0.1]" /></ItemGroup>`
	otherRef        = `<ItemGroup><PackageReference Include="Other" Version="1.0.0" /></ItemGroup>`
)

// Every surface that can change which copy of a package a project installs is read, or the
// project's copy is unknown. Each row fails if its surface is ignored.
func TestVersions_UnreadSurfaces(t *testing.T) {
	pinA := csproj("Newtonsoft.Json", "[13.0.3]")
	cases := []struct {
		name    string
		files   map[string]string
		version string // "" means Found but UNRESOLVED
		reason  string // a partiality reason the result must carry
	}{
		{
			name: "restore output is the installed set",
			files: map[string]string{
				"A/A.csproj":                csproj("Newtonsoft.Json", "[13.0,14.0)"),
				"A/obj/project.assets.json": assetsJSON(map[string]string{"Newtonsoft.Json/13.0.3": "package"}),
			},
			version: "13.0.3",
		},
		{
			name: "a plain Version is a minimum when no lock covers it",
			files: map[string]string{
				"A/A.csproj": csproj("Newtonsoft.Json", "13.0.3"),
			},
		},
		{
			name: "a plain GlobalPackageReference Version is a minimum when no lock covers it",
			files: map[string]string{
				"Directory.Packages.props": msbuild(`<ItemGroup><GlobalPackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup>`),
				"A/A.csproj":               csproj("Other", "[1.0.0]"),
			},
		},
		{
			name: "a plain Version a current lock covers",
			files: map[string]string{
				"A/A.csproj":           csproj("Newtonsoft.Json", "13.0.3"),
				"A/packages.lock.json": lockEntries("Direct", "[13.0.3, )", map[string]string{"net8.0": "13.0.4"}),
			},
			version: "13.0.4",
		},
		{
			name: "restore output overrides a stale lockfile",
			files: map[string]string{
				"A/A.csproj":                pinA,
				"A/packages.lock.json":      lockEntries("Direct", "[12.0.1, )", map[string]string{"net8.0": "12.0.1"}),
				"A/obj/project.assets.json": assetsJSON(map[string]string{"Newtonsoft.Json/13.0.3": "package"}),
			},
			version: "13.0.3",
		},
		{
			name: "a transitive copy in another project's restore output",
			files: map[string]string{
				"A/A.csproj":                pinA,
				"B/B.csproj":                csproj("Other", "1.0.0"),
				"B/obj/project.assets.json": assetsJSON(map[string]string{"Other/1.0.0": "package", "Newtonsoft.Json/12.0.1": "package"}),
			},
		},
		{
			name: "restore output that lists only a project reference of that name",
			files: map[string]string{
				"A/A.csproj":                pinA,
				"B/B.csproj":                csproj("Other", "1.0.0"),
				"B/obj/project.assets.json": assetsJSON(map[string]string{"Other/1.0.0": "package", "Newtonsoft.Json/1.0.0": "project"}),
			},
			version: "13.0.3",
		},
		{
			name: "another project with packages and no lockfile",
			files: map[string]string{
				"A/A.csproj": pinA,
				"B/B.csproj": csproj("Other", "1.0.0"),
			},
			reason: reasonNoLockfile,
		},
		{
			name: "another project with a current lockfile that doesn't list it",
			files: map[string]string{
				"A/A.csproj":           pinA,
				"B/B.csproj":           csproj("Other", "1.0.0"),
				"B/packages.lock.json": `{"version": 1, "dependencies": {"net8.0": {"Other": {"type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0"}}}}`,
			},
			version: "13.0.3",
		},
		{
			name: "another project's lockfile missing one of its declared packages",
			files: map[string]string{
				"A/A.csproj":           pinA,
				"B/B.csproj":           msbuild(otherRef + `<ItemGroup><PackageReference Include="Extra" Version="2.0.0" /></ItemGroup>`),
				"B/packages.lock.json": `{"version": 1, "dependencies": {"net8.0": {"Other": {"type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0"}}}}`,
			},
			reason: reasonLockfileStale,
		},
		{
			name: "another project's lockfile still listing a package it no longer declares",
			files: map[string]string{
				"A/A.csproj": pinA,
				"B/B.csproj": csproj("Other", "1.0.0"),
				"B/packages.lock.json": `{"version": 1, "dependencies": {"net8.0": {
  "Other": {"type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0"},
  "Removed": {"type": "Direct", "requested": "[2.0.0, )", "resolved": "2.0.0"}}}}`,
			},
			reason: reasonLockfileStale,
		},
		{
			name: "a stale lockfile does not decide against a direct pin",
			files: map[string]string{
				"A/A.csproj":           pinA,
				"A/packages.lock.json": lockEntries("Direct", "[12.0.1, )", map[string]string{"net8.0": "12.0.1"}),
			},
			version: "13.0.3",
		},
		{
			name: "a lock listing another package in place of the declared one covers nothing",
			files: map[string]string{
				"A/A.csproj": msbuild(otherRef + `<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0,14.0)" /></ItemGroup>`),
				"A/packages.lock.json": `{"version": 1, "dependencies": {"net8.0": {
  "Other": {"type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0"},
  "Serilog": {"type": "Direct", "requested": "[3.0.0, )", "resolved": "3.0.0"}}}}`,
			},
		},
		{
			name: "Directory.Build.props injects a PackageReference",
			files: map[string]string{
				"A/A.csproj":              pinA,
				"B/B.csproj":              csproj("Other", "1.0.0"),
				"B/Directory.Build.props": msbuild(newtonsoftRef12),
			},
		},
		{
			name: "an injected pin is the project's declaration",
			files: map[string]string{
				"B/B.csproj":              csproj("Other", "1.0.0"),
				"B/Directory.Build.props": msbuild(newtonsoftRef12),
			},
			version: "12.0.1",
		},
		{
			name: "an injected reference makes the lockfile's Direct set current",
			files: map[string]string{
				"B/B.csproj":              csproj("Other", "1.0.0"),
				"B/Directory.Build.props": msbuild(`<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[12.0,13.0)" /></ItemGroup>`),
				"B/packages.lock.json": `{"version": 1, "dependencies": {"net8.0": {
  "Other": {"type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0"},
  "Newtonsoft.Json": {"type": "Direct", "requested": "[12.0.0, 13.0.0)", "resolved": "12.0.3"}}}}`,
			},
			version: "12.0.3",
		},
		{
			name: "Directory.Build.targets updates a PackageReference",
			files: map[string]string{
				"A/A.csproj":                pinA,
				"A/Directory.Build.targets": msbuild(`<ItemGroup><PackageReference Update="Newtonsoft.Json" Version="12.0.1" /></ItemGroup>`),
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "only the nearest Directory.Build.props is imported",
			files: map[string]string{
				"Directory.Build.props":   msbuild(newtonsoftRef12),
				"A/Directory.Build.props": msbuild(""),
				"A/A.csproj":              pinA,
			},
			version: "13.0.3",
		},
		{
			name: "a Directory.Build.props that chains to its parent",
			files: map[string]string{
				"Directory.Build.props":   msbuild(newtonsoftRef12),
				"A/Directory.Build.props": msbuild(`<Import Project="$([MSBuild]::GetPathOfFileAbove('Directory.Build.props', '$(MSBuildThisFileDirectory)../'))" />`),
				"A/A.csproj":              pinA,
			},
		},
		{
			name: "a Directory.Build.props with an import it can't follow",
			files: map[string]string{
				"A/Directory.Build.props": msbuild(`<Import Project="$(RepoRoot)/eng/Versions.props" />`),
				"A/A.csproj":              pinA,
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "a GlobalPackageReference",
			files: map[string]string{
				"Directory.Packages.props": msbuild(`<ItemGroup><GlobalPackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup>`),
				"A/A.csproj":               pinA,
			},
		},
		{
			name: "a project file imports a file declaring the package",
			files: map[string]string{
				"common.props": msbuild(newtonsoftRef12),
				"A/A.csproj":   `<Project Sdk="Microsoft.NET.Sdk"><Import Project="..\common.props" /><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
			},
		},
		{
			name: "a project file imports a file it can't locate",
			files: map[string]string{
				"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><Import Project="$(SolutionDir)common.props" /><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "a project file's toolset import declares nothing",
			files: map[string]string{
				"A/A.csproj": `<Project><Import Project="$(MSBuildToolsPath)\Microsoft.CSharp.targets" /><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.3]" /></ItemGroup></Project>`,
			},
			version: "13.0.3",
		},
		{
			name: "an imported file that imports further",
			files: map[string]string{
				"common.props": msbuild(`<Import Project="$(RepoRoot)/eng/Versions.props" />`),
				"A/A.csproj":   `<Project Sdk="Microsoft.NET.Sdk"><Import Project="../common.props" /><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "a Directory.Packages.props with an import",
			files: map[string]string{
				"Directory.Packages.props": msbuild(`<Import Project="eng/Global.props" />`),
				"A/A.csproj":               pinA,
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "two projects sharing a directory share its lockfile",
			files: map[string]string{
				"A/A1.csproj": csproj("Newtonsoft.Json", "[13.0,14.0)"),
				"A/A2.csproj": csproj("Other", "1.0.0"),
				"A/packages.lock.json": `{"version": 1, "dependencies": {"net8.0": {
  "Other": {"type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0"},
  "Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.0, 14.0.0)", "resolved": "13.0.3"}}}}`,
			},
		},
		{
			name: "a PackageReference inside a Choose",
			files: map[string]string{
				"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup>
<Choose><When Condition="'$(Legacy)' == 'true'"><ItemGroup><PackageReference Update="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></When></Choose></Project>`,
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "a project that turns off the Directory.Build.props import",
			files: map[string]string{
				"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><ImportDirectoryBuildProps>false</ImportDirectoryBuildProps></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "a commented-out PackageReference is not a declaration",
			files: map[string]string{
				"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><!-- <PackageReference Include="Newtonsoft.Json" Version="12.0.1" /> --><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.3]" /></ItemGroup></Project>`,
			},
			version: "13.0.3",
		},
		{
			name: "a GlobalPackageReference in Directory.Build.targets is declared",
			files: map[string]string{
				"Directory.Build.targets": msbuild(`<ItemGroup><GlobalPackageReference Include="Newtonsoft.Json" Version="[13.0.3]" /></ItemGroup>`),
				"A/A.csproj":              msbuild(otherRef),
			},
			version: "13.0.3",
		},
		{
			name: "a GlobalPackageReference makes a lock that lacks it stale",
			files: map[string]string{
				"Directory.Packages.props": msbuild(`<ItemGroup><GlobalPackageReference Include="Newtonsoft.Json" Version="[13.0.3]" /></ItemGroup>`),
				"A/A.csproj":               msbuild(otherRef),
				"A/packages.lock.json":     lockEntries("Direct", "[12.0.1, )", map[string]string{"net8.0": "12.0.1"}),
			},
			version: "13.0.3",
		},
		{
			name: "a PackageReference in Directory.Packages.props is declared",
			files: map[string]string{
				"Directory.Packages.props": msbuild(newtonsoftRef12),
				"A/A.csproj":               msbuild(otherRef),
			},
			version: "12.0.1",
		},
		{
			name: "a VersionOverride update in Directory.Build.targets",
			files: map[string]string{
				"Directory.Packages.props": cpmProps("13.0.3"),
				"Directory.Build.targets":  msbuild(`<ItemGroup><PackageReference Update="Newtonsoft.Json" VersionOverride="12.0.1" /></ItemGroup>`),
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "a PackageVersion in Directory.Build.targets",
			files: map[string]string{
				"Directory.Packages.props": cpmProps("13.0.3"),
				"Directory.Build.targets":  msbuild(`<ItemGroup><PackageVersion Update="Newtonsoft.Json" Version="12.0.1" /></ItemGroup>`),
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "a PackageVersion in the project file",
			files: map[string]string{
				"Directory.Packages.props": cpmProps("13.0.3"),
				"A/A.csproj":               `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageVersion Update="Newtonsoft.Json" Version="12.0.1" /><PackageReference Include="Newtonsoft.Json" /></ItemGroup></Project>`,
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "a PackageVersion in an imported file",
			files: map[string]string{
				"Directory.Packages.props": cpmProps("13.0.3"),
				"versions.props":           msbuild(`<ItemGroup><PackageVersion Update="Newtonsoft.Json" Version="12.0.1" /></ItemGroup>`),
				"A/A.csproj":               `<Project Sdk="Microsoft.NET.Sdk"><Import Project="..\versions.props" /><ItemGroup><PackageReference Include="Newtonsoft.Json" /></ItemGroup></Project>`,
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "ManagePackageVersionsCentrally in Directory.Build.props is not a version",
			files: map[string]string{
				"Directory.Build.props":    msbuild(`<PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>`),
				"Directory.Packages.props": cpmProps("13.0.3"),
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
			version: "13.0.3",
		},
		{
			name: "a conditioned injected reference leaves the transitive copy open",
			files: map[string]string{
				"Directory.Build.props": msbuild(`<ItemGroup Condition="'$(TargetFramework)' == 'net8.0'"><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup>`),
				"A/A.csproj":            msbuild(otherRef),
			},
			reason: reasonNoLockfile,
		},
		{
			name: "a conditioned project reference leaves the transitive copy open",
			files: map[string]string{
				"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Other" Version="1.0.0" /><PackageReference Include="Newtonsoft.Json" Version="13.0.3" Condition="'$(TargetFramework)' == 'net48'" /></ItemGroup></Project>`,
			},
			reason: reasonNoLockfile,
		},
		{
			name: "a conditioned Version element leaves the transitive copy open",
			files: map[string]string{
				"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Other" Version="1.0.0" /><PackageReference Include="Newtonsoft.Json"><Version Condition="'$(TargetFramework)' == 'net48'">13.0.3</Version></PackageReference></ItemGroup></Project>`,
			},
			reason: reasonNoLockfile,
		},
		{
			name: "a conditioned import leaves the transitive copy open",
			files: map[string]string{
				"common.props": msbuild(newtonsoftRef12),
				"A/A.csproj":   `<Project Sdk="Microsoft.NET.Sdk"><ImportGroup Condition="'$(Legacy)' == 'true'"><Import Project="..\common.props" /></ImportGroup><ItemGroup><PackageReference Include="Other" Version="1.0.0" /></ItemGroup></Project>`,
			},
			reason: reasonNoLockfile,
		},
		{
			name: "a conditioned chain to the parent Directory.Build.props",
			files: map[string]string{
				"Directory.Build.props":   msbuild(newtonsoftRef12),
				"A/Directory.Build.props": msbuild(`<Import Project="$([MSBuild]::GetPathOfFileAbove('Directory.Build.props', '$(MSBuildThisFileDirectory)../'))" Condition="'$(Legacy)' == 'true'" />`),
				"A/A.csproj":              msbuild(otherRef),
			},
			reason: reasonNoLockfile,
		},
		{
			name: "R1: the last of two Version elements is the one MSBuild keeps",
			files: map[string]string{
				"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json"><Version>12.0.1</Version><Version>13.0.3</Version></PackageReference></ItemGroup></Project>`,
			},
		},
		{
			name: "R1: a Version attribute and a Version element",
			files: map[string]string{
				"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1"><Version>13.0.3</Version></PackageReference></ItemGroup></Project>`,
			},
		},
		{
			name: "R1: two VersionOverride elements",
			files: map[string]string{
				"Directory.Packages.props": cpmProps("13.0.3"),
				"A/A.csproj":               `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json"><VersionOverride>13.0.3</VersionOverride><VersionOverride>12.0.1</VersionOverride></PackageReference></ItemGroup></Project>`,
				"A/packages.lock.json":     lockEntries("Direct", "[12.0.1, )", map[string]string{"net8.0": "12.0.1"}),
			},
		},
		{
			name: "R2: an Update under Choose",
			files: map[string]string{
				"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup><Choose><When Condition="'$(TargetFramework)' == 'net48'"><ItemGroup><PackageReference Update="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></When></Choose></Project>`,
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "R2: an Include only under Choose in another project",
			files: map[string]string{
				"A/A.csproj": pinA,
				"B/B.csproj": `<Project Sdk="Microsoft.NET.Sdk"><Choose><When Condition="'$(TargetFramework)' == 'net48'"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></When></Choose></Project>`,
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "R2: an Include listing several packages",
			files: map[string]string{
				"A/A.csproj": pinA,
				"B/B.csproj": csproj("Serilog;Newtonsoft.Json", "12.0.1"),
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "R2: a property-valued Include",
			files: map[string]string{
				"A/A.csproj": pinA,
				"B/B.csproj": csproj("$(JsonPackage)", "12.0.1"),
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "R2: item types match without case",
			files: map[string]string{
				"A/A.csproj": pinA,
				"B/B.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><packagereference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>`,
			},
		},
		{
			name: "R2: an imported file updates the reference",
			files: map[string]string{
				"deps.props": msbuild(`<ItemGroup><PackageReference Update="Newtonsoft.Json" Version="12.0.1" /></ItemGroup>`),
				"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><Import Project="..\deps.props" /><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "R2: an SDK that brings its own references",
			files: map[string]string{
				"A/A.csproj": `<Project Sdk="MSTest.Sdk/3.6.0"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "R2: a target that adds a reference",
			files: map[string]string{
				"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup><Target Name="Pin" BeforeTargets="CollectPackageReferences"><ItemGroup><PackageReference Update="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Target></Project>`,
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "R2: a task that adds a reference",
			files: map[string]string{
				"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup><Target Name="Pin" BeforeTargets="Restore"><CreateItem Include="Newtonsoft.Json" AdditionalMetadata="Version=12.0.1"><Output TaskParameter="Include" ItemName="PackageReference" /></CreateItem></Target></Project>`,
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "R2: an SDK import that brings its own references",
			files: map[string]string{
				"A/A.csproj": `<Project><Import Project="Sdk.props" Sdk="MSTest.Sdk" /><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "R2: an Sdk element that brings its own references",
			files: map[string]string{
				"A/A.csproj": `<Project><Sdk Name="MSTest.Sdk" /><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "R2: an item definition that sets a default version",
			files: map[string]string{
				"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemDefinitionGroup><PackageReference><Version>12.0.1</Version></PackageReference></ItemDefinitionGroup><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "R2: an ordinary project file with a project reference is read",
			files: map[string]string{
				"A/A.csproj": `<?xml version="1.0" encoding="utf-8"?>
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)' == 'Debug|AnyCPU'"><DebugType>full</DebugType></PropertyGroup>
  <ItemGroup><Compile Remove="wwwroot\**" /><None Update="appsettings.json"><CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory></None></ItemGroup>
  <ItemGroup Condition="'$(TargetFramework)' == 'net8.0'"><ProjectReference Include="..\Lib\Lib.csproj" /></ItemGroup>
  <ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.3]" PrivateAssets="all" /></ItemGroup>
  <Target Name="Stamp" AfterTargets="Build"><Exec Command="echo built" /></Target>
</Project>`,
			},
			version: "13.0.3",
		},
		{
			name: "R2: an ordinary project file with central management is read",
			files: map[string]string{
				"A/A.csproj": `<?xml version="1.0" encoding="utf-8"?>
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile></PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)' == 'Debug|AnyCPU'"><DebugType>full</DebugType></PropertyGroup>
  <ItemGroup><Compile Remove="wwwroot\**" /><None Update="appsettings.json"><CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory></None></ItemGroup>
  <ItemGroup Condition="'$(TargetFramework)' == 'net8.0'"><Content Include="data\*.json" /></ItemGroup>
  <ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.3]" PrivateAssets="all" /></ItemGroup>
  <Target Name="Stamp" AfterTargets="Build"><Exec Command="echo built" /></Target>
</Project>`,
			},
			version: "13.0.3",
		},
		{
			name: "R3: ManagePackageVersionsCentrally false in the project file",
			files: map[string]string{
				"Directory.Packages.props": cpmProps("13.0.3"),
				"A/A.csproj":               `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json" /></ItemGroup></Project>`,
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "R3: a conditioned central-management property",
			files: map[string]string{
				"Directory.Packages.props": cpmProps("13.0.3"),
				"A/A.csproj":               `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup Condition="'$(Legacy)' == 'true'"><CentralPackageVersionOverrideEnabled>true</CentralPackageVersionOverrideEnabled></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json" /></ItemGroup></Project>`,
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "R3: a stale CentralTransitive lock entry",
			files: map[string]string{
				"Directory.Packages.props": `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /><PackageVersion Include="Other" Version="1.0.0" /></ItemGroup></Project>`,
				"A/A.csproj":               csproj("Other", ""),
				"A/packages.lock.json":     centralTransitiveLock("[12.0.1, )", "12.0.1"),
			},
			reason: reasonLockfileStale,
		},
		{
			name: "R3: a current CentralTransitive lock entry",
			files: map[string]string{
				"Directory.Packages.props": `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /><PackageVersion Include="Other" Version="1.0.0" /></ItemGroup></Project>`,
				"A/A.csproj":               csproj("Other", ""),
				"A/packages.lock.json":     centralTransitiveLock("[13.0.3, )", "13.0.3"),
			},
			version: "13.0.3",
		},
		{
			name: "R4: Directory.Build.targets updates the version",
			files: map[string]string{
				"Directory.Build.targets": msbuild(`<ItemGroup><PackageReference Update="Newtonsoft.Json" Version="12.0.1" /></ItemGroup>`),
				"A/A.csproj":              pinA,
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "R4: a nested Directory.Build.props injects into an empty project",
			files: map[string]string{
				"A/A.csproj":              pinA,
				"B/Directory.Build.props": msbuild(newtonsoftRef12),
				"B/B.csproj":              `<Project Sdk="Microsoft.NET.Sdk" />`,
			},
		},
		{
			name: "R4: a Choose in Directory.Build.props",
			files: map[string]string{
				"Directory.Build.props": msbuild(`<Choose><When Condition="true"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></When></Choose>`),
				"A/A.csproj":            pinA,
			},
			reason: reasonPackageReferenceUnmodeled,
		},
		{
			name: "a packages.config project keeps its packages.config",
			files: map[string]string{
				"Legacy/Legacy.csproj":   `<Project ToolsVersion="15.0"><Import Project="$(VSToolsPath)\WebApplications\Microsoft.WebApplication.targets" /><Import Project="..\packages\Foo.1.0\build\Foo.targets" Condition="Exists('..\packages\Foo.1.0\build\Foo.targets')" /></Project>`,
				"Legacy/packages.config": `<packages><package id="Newtonsoft.Json" version="12.0.3" /></packages>`,
			},
			version: "12.0.3",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := versionsOf(t, writeTree(t, tc.files), "Newtonsoft.Json")
			if !r.Found {
				t.Fatalf("Newtonsoft.Json not found; got %+v", r)
			}
			if tc.version == "" {
				if r.Match.Resolved || r.Match.Version != "" {
					t.Fatalf("want UNRESOLVED; got %+v", r.Match)
				}
			} else if !r.Match.Resolved || r.Match.Version != tc.version {
				t.Fatalf("want resolved %s; got %+v", tc.version, r.Match)
			}
			if tc.reason != "" && !slices.Contains(r.Partiality.Reasons, tc.reason) {
				t.Errorf("want reason %q; got %v", tc.reason, r.Partiality.Reasons)
			}
		})
	}
}

// Restore output that exists but can't be read vetoes, like any other unreadable manifest.
func TestVersions_UnreadableAssetsVetoes(t *testing.T) {
	for _, body := range []string{`{"targets": `, `{"version": 3}`} {
		r := versionsOf(t, writeTree(t, map[string]string{
			"A/A.csproj":                csproj("Other", "1.0.0"),
			"A/obj/project.assets.json": body,
		}), "Newtonsoft.Json")
		if !r.Found || r.Match.Resolved || !slices.Contains(r.Partiality.Reasons, plugin.PartialReasonToolFailure) {
			t.Errorf("assets %q: want Found, UNRESOLVED, tool_failure; got %+v", body, r)
		}
	}
}

// An import that leaves the scanned tree can't be read as part of the build, so the project's
// declared set is unknown even when the file happens to exist.
func TestVersions_ImportOutsideTree(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"outside.props":   msbuild(""),
		"repo/A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><Import Project="../../outside.props" /><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
	})
	r := versionsOf(t, filepath.Join(dir, "repo"), "Newtonsoft.Json")
	if !r.Found || r.Match.Resolved || !slices.Contains(r.Partiality.Reasons, reasonPackageReferenceUnmodeled) {
		t.Fatalf("want Found, UNRESOLVED, %s; got %+v", reasonPackageReferenceUnmodeled, r)
	}
}

// parseMSBuild models only what it knows; each row is one shape it must reject or accept.
func TestParseMSBuild(t *testing.T) {
	ref := `<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup>`
	cases := []struct {
		name string
		xml  string
		role msbuildRole
		ok   bool
	}{
		{name: "plain", xml: msbuild(ref), ok: true},
		{name: "stray text", xml: `<Project>13.0.3` + ref + `</Project>`},
		{name: "document type declaration", xml: `<!DOCTYPE Project>` + msbuild(ref)},
		{name: "prefixed attribute", xml: `<Project xmlns:x="urn:x"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" x:Condition="false" /></ItemGroup></Project>`},
		{name: "element under metadata", xml: msbuild(`<ItemGroup><PackageReference Include="Newtonsoft.Json"><Version><When>12.0.1</When></Version></PackageReference></ItemGroup>`)},
		{name: "restore toggle set from a property", xml: msbuild(`<PropertyGroup><RestoreLockedMode>$(CI)</RestoreLockedMode></PropertyGroup>` + ref)},
		{name: "restore toggle set to a literal", xml: msbuild(`<PropertyGroup><RestoreLockedMode>true</RestoreLockedMode></PropertyGroup>` + ref), ok: true},
		{name: "Exclude on a package item", xml: msbuild(`<ItemGroup><PackageReference Include="Newtonsoft.Json" Exclude="Newtonsoft.Json" Version="13.0.3" /></ItemGroup>`)},
		{name: "task output into PackageVersion", xml: msbuild(`<Target Name="Pin"><CreateItem Include="Newtonsoft.Json"><Output TaskParameter="Include" ItemName="PackageVersion" /></CreateItem></Target>` + ref)},
		{name: "lowercase package item in a target", xml: msbuild(`<Target Name="Add"><ItemGroup><packagereference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Target>` + ref)},
		{name: "PackageVersion in a project file", xml: msbuild(`<ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup>` + ref)},
		{name: "PackageVersion in Directory.Packages.props", xml: msbuild(`<ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup>` + ref), role: roleCentral, ok: true},
		{name: "Microsoft.NET.Sdk import", xml: `<Project><Import Project="Sdk.props" Sdk="Microsoft.NET.Sdk" />` + ref + `</Project>`, ok: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := parseMSBuild([]byte(tc.xml), tc.role, "msbuild"); ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
		})
	}
}

// A project file parseMSBuild can't model still lists its references, unresolved, so the
// dependency set (All) keeps them.
func TestParseProjectFile_UnmodeledKeepsReferences(t *testing.T) {
	entries, ok := parseProjectFile([]byte(`<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup><Choose><When Condition="true"><ItemGroup><PackageReference Update="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></When></Choose></Project>`))
	if !ok || len(entries) != 1 || entries[0].dep.Coordinate != "Newtonsoft.Json" || entries[0].dep.Resolved || entries[0].dep.Version != "" || entries[0].spec != specUnread {
		t.Fatalf("got %+v, %v; want one unresolved Newtonsoft.Json", entries, ok)
	}
}
