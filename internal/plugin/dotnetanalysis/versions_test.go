package dotnetanalysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// legacyProject is a non-SDK project as Visual Studio's classic template writes it: it imports
// only files MSBuild ships.
const legacyProject = `<Project ToolsVersion="15.0"><Import Project="$(MSBuildExtensionsPath)\$(MSBuildToolsVersion)\Microsoft.Common.props" />` +
	`<PropertyGroup><OutputType>Library</OutputType></PropertyGroup><Import Project="$(MSBuildToolsPath)\Microsoft.CSharp.targets" /></Project>`

func versionsOf(t *testing.T, dir, coordinate string) plugin.DependencyVersionResult {
	t.Helper()
	res, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{
		BuildDir:   dir,
		Coordinate: coordinate,
	})
	if err != nil {
		t.Fatalf("ResolveDependencyVersions: %v", err)
	}
	return res
}

// A .csproj exact-bracket PackageReference pin resolves; a plain minimum, a range and a floating
// version stay UNRESOLVED (the predicate fails open on them, never a false not-affected).
func TestVersions_CsprojPinsAndRanges(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"App.csproj": `
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="DotNetZip" Version="1.16.0" />
    <PackageReference Include="Newtonsoft.Json" Version="[13.0.1]" />
    <PackageReference Include="RangePkg" Version="[1.0,2.0)" />
    <PackageReference Include="FloatPkg" Version="1.2.*" />
    <PackageReference Include="ElemVer"><Version>[4.5.6]</Version></PackageReference>
    <PackageReference Include="ElemMin"><Version>4.5.6</Version></PackageReference>
    <PackageReference Include="NoVersionPkg" />
  </ItemGroup>
</Project>
`,
	})

	// A plain Version is a minimum: restore takes the lowest available version at or above it,
	// which need not be 1.16.0 (NU1603). FOUND but UNRESOLVED.
	if r := versionsOf(t, dir, "DotNetZip"); !r.Found || r.Match.Resolved {
		t.Errorf("DotNetZip plain 1.16.0 must be Found+UNRESOLVED; got %+v", r)
	}
	if r := versionsOf(t, dir, "ElemMin"); !r.Found || r.Match.Resolved {
		t.Errorf("ElemMin plain child <Version> must be Found+UNRESOLVED; got %+v", r)
	}
	// Exact-bracket "[13.0.1]" unwraps to an exact pin.
	if r := versionsOf(t, dir, "Newtonsoft.Json"); !r.Found || !r.Match.Resolved || r.Match.Version != "13.0.1" {
		t.Errorf("Newtonsoft.Json [13.0.1] must resolve to 13.0.1; got %+v", r)
	}
	// Child-element exact-bracket version.
	if r := versionsOf(t, dir, "ElemVer"); !r.Found || !r.Match.Resolved || r.Match.Version != "4.5.6" {
		t.Errorf("ElemVer child <Version>[4.5.6]</Version> must resolve to 4.5.6; got %+v", r)
	}
	// A range is FOUND but UNRESOLVED (fail open).
	if r := versionsOf(t, dir, "RangePkg"); !r.Found || r.Match.Resolved {
		t.Errorf("RangePkg range must be Found+UNRESOLVED; got %+v", r)
	}
	// A floating version is FOUND but UNRESOLVED.
	if r := versionsOf(t, dir, "FloatPkg"); !r.Found || r.Match.Resolved {
		t.Errorf("FloatPkg float must be Found+UNRESOLVED; got %+v", r)
	}
	// Central-Package-Management (no Version) is FOUND but UNRESOLVED (version lives in
	// Directory.Packages.props, out of MVP).
	if r := versionsOf(t, dir, "NoVersionPkg"); !r.Found || r.Match.Resolved {
		t.Errorf("version-less PackageReference must be Found+UNRESOLVED; got %+v", r)
	}
	// Coordinate matching is case-insensitive.
	if r := versionsOf(t, dir, "newtonsoft.json"); !r.Found || r.Match.Version != "13.0.1" {
		t.Errorf("coordinate match must be case-insensitive; got %+v", r)
	}
}

// packages.lock.json carries exact resolved versions for Direct AND Transitive packages and
// is preferred over a .csproj range for the same coordinate.
func TestVersions_LockPreferredOverCsprojRange(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"App.csproj": `
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="DotNetZip" Version="[1.0,2.0)" />
  </ItemGroup>
</Project>
`,
		"packages.lock.json": `
{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "DotNetZip": { "type": "Direct", "requested": "[1.0,2.0)", "resolved": "1.16.0" },
      "System.Text.Json": { "type": "Transitive", "resolved": "8.0.4" }
    }
  }
}
`,
	})

	// The lockfile's exact resolved pin wins over the .csproj range.
	if r := versionsOf(t, dir, "DotNetZip"); !r.Found || !r.Match.Resolved || r.Match.Version != "1.16.0" {
		t.Errorf("lockfile exact pin must win over csproj range; got %+v", r)
	}
	if m := versionsOf(t, dir, "DotNetZip").Match; m.Source != "packages.lock.json" {
		t.Errorf("resolved match should come from the lockfile; got source %q", m.Source)
	}
	// A transitive dependency (never named in the csproj) resolves from the lockfile.
	if r := versionsOf(t, dir, "System.Text.Json"); !r.Found || !r.Match.Resolved || r.Match.Version != "8.0.4" {
		t.Errorf("transitive System.Text.Json must resolve from the lockfile; got %+v", r)
	}
}

// packages.config (legacy) carries exact versions.
func TestVersions_PackagesConfig(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"packages.config": `
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="starkbank-ecdsa" version="1.3.3" targetFramework="net472" />
  <package id="DotNetZip" version="1.9.1.8" targetFramework="net472" />
</packages>
`,
	})
	if r := versionsOf(t, dir, "starkbank-ecdsa"); !r.Found || !r.Match.Resolved || r.Match.Version != "1.3.3" {
		t.Errorf("starkbank-ecdsa must resolve to 1.3.3; got %+v", r)
	}
	// A 4-segment version resolves as-is (the pipeline comparator handles ordering).
	if r := versionsOf(t, dir, "DotNetZip"); !r.Found || r.Match.Version != "1.9.1.8" {
		t.Errorf("DotNetZip 4-segment version must resolve; got %+v", r)
	}
}

// A build dir with no recognized manifest degrades to declared-partial (no_manifest) — a
// normal repo shape must not turn the run red. The recognized set already covers the DECLARED
// manifests (.csproj, packages.config), so there is nothing to seed; the partiality is the
// entire soundness guarantee against a consumer misreading the empty result as "no dependency".
func TestVersions_NoManifest_DegradesToPartial(t *testing.T) {
	dir := writeTree(t, map[string]string{"Program.cs": "class P {}\n"})
	res := versionsOf(t, dir, "x") // versionsOf t.Fatals on a hard error

	if res.Partiality.Complete {
		t.Fatal("no manifest must never report Complete — it must be distinguishable from a clean scan")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonNoManifest) {
		t.Fatalf("Reasons = %v, want %q", res.Partiality.Reasons, plugin.PartialReasonNoManifest)
	}
	if len(res.All) != 0 {
		t.Fatalf("nothing is declared, so nothing may be reported; All=%+v", res.All)
	}
	if res.Found {
		t.Fatalf("no manifest cannot make a coordinate Found; got %+v", res.Match)
	}
}

// A missing build dir stays a hard error (inv.4) — only the no-manifest branch degrades.
func TestVersions_MissingBuildDirIsHardError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nope")
	if _, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: dir, Coordinate: "x"}); err == nil {
		t.Fatal("a missing build dir must be a hard error")
	}
}

// An unparseable manifest degrades Partiality to declared-partial (tool_failure), never a
// confident Complete, and leaves every coordinate Found but unresolved: the manifest could
// declare it at any version.
func TestVersions_UnparseableManifest_Partial(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"packages.lock.json": "{ this is not valid json",
	})
	res := versionsOf(t, dir, "anything")
	if res.Partiality.Complete {
		t.Errorf("an unparseable manifest must NOT be Complete; got %+v", res.Partiality)
	}
	if !res.Found || res.Match.Resolved || res.Match.Coordinate != "anything" {
		t.Errorf("an unparseable manifest must leave the coordinate Found and unresolved; got %+v", res)
	}
}

// A coordinate not declared anywhere is not Found (the pipeline fails open on a
// missing/unresolved match — never a fabricated not-affected).
func TestVersions_UnknownCoordinate_NotFound(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"App.csproj": "<Project><ItemGroup><PackageReference Include=\"A\" Version=\"1.0.0\" /></ItemGroup></Project>\n",
	})
	if r := versionsOf(t, dir, "NotDeclared"); r.Found {
		t.Errorf("an undeclared coordinate must not be Found; got %+v", r)
	}
}

// newtonsoftProject is an SDK project referencing Newtonsoft.Json at version, with extra spliced in
// at the top level.
func newtonsoftProject(version, extra string) string {
	return `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>` + extra +
		`<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="` + version + `" /></ItemGroup></Project>`
}

const newtonsoftLock = `{"version": 1, "dependencies": {"net8.0": {"Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.1]", "resolved": "13.0.1"}}}}`

// lockFile builds a packages.lock.json from lockSection values.
func lockFile(sections ...string) string {
	return `{"version": 1, "dependencies": {` + strings.Join(sections, ",") + `}}`
}

// lockSection is one target framework's section of a lockFile, holding lockEntry values.
func lockSection(tfm string, entries ...string) string {
	return fmt.Sprintf(`%q: {%s}`, tfm, strings.Join(entries, ","))
}

func lockEntry(name, kind, requested, resolved string) string {
	return fmt.Sprintf(`%q: {"type": %q, "requested": %q, "resolved": %q}`, name, kind, requested, resolved)
}

// TestVersions_AllowList pins which .NET builds the Match resolves in. Every copy of the package
// must be a pin from a source this reader models whole, and all copies must agree. The
// multi-project, Directory.Build.targets and packages.config rows are builds where one copy alone
// would put the version outside the range while another copy sits inside it.
func TestVersions_AllowList(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		wantVer string
	}{
		{"projects agree", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""), "B/B.csproj": newtonsoftProject("[13.0.1]", "")}, "13.0.1"},
		{"patched project first", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""), "B/B.csproj": newtonsoftProject("[12.0.3]", "")}, ""},
		{"affected project first", map[string]string{"A/A.csproj": newtonsoftProject("[12.0.3]", ""), "B/B.csproj": newtonsoftProject("[13.0.1]", "")}, ""},
		{"Directory.Build.targets update", map[string]string{"App.csproj": newtonsoftProject("[13.0.1]", ""),
			"Directory.Build.targets": `<Project><ItemGroup><PackageReference Update="Newtonsoft.Json" Version="[12.0.3]" /></ItemGroup></Project>`}, ""},
		{"Directory.Build.props above the project", map[string]string{"src/App/App.csproj": newtonsoftProject("[13.0.1]", ""), "Directory.Build.props": "<Project/>"}, ""},
		{"Directory.Packages.props", map[string]string{"App.csproj": newtonsoftProject("[13.0.1]", ""), "directory.packages.props": "<Project/>"}, ""},
		{"Directory.Build.rsp", map[string]string{"App.csproj": newtonsoftProject("[13.0.1]", ""), "Directory.Build.rsp": "-p:X=1"}, ""},
		{"user file", map[string]string{"App.csproj": newtonsoftProject("[13.0.1]", ""), "App.csproj.user": "<Project/>"}, ""},
		{"obj import", map[string]string{"App.csproj": newtonsoftProject("[13.0.1]", ""), "obj/App.csproj.custom.targets": "<Project/>"}, ""},
		{"packages.config and project disagree", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`, "A/A.csproj": legacyProject,
			"B/B.csproj": newtonsoftProject("[12.0.3]", "")}, ""},
		{"packages.config covers its legacy project", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`, "A/A.csproj": legacyProject}, "13.0.1"},
		{"legacy project imports a stock file in another spelling", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`,
			"A/A.csproj": `<Project><Import Project=" $(MSBuildBinPath)/microsoft.csharp.TARGETS" /></Project>`}, "13.0.1"},
		{"legacy project imports a .targets that adds a PackageReference", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`,
			"A/A.csproj":  `<Project><Import Project="$(MSBuildToolsPath)\Microsoft.CSharp.targets" /><Import Project="x.targets" /></Project>`,
			"A/x.targets": `<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[12.0.3]" /></ItemGroup></Project>`}, ""},
		{"legacy template's configuration property groups", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`,
			"A/A.csproj": strings.Replace(legacyProject, "</Project>", `<PropertyGroup Condition=" '$(Configuration)|$(Platform)' == 'Debug|AnyCPU' "><DebugSymbols>true</DebugSymbols><OutputPath>bin\Debug\</OutputPath><DefineConstants>DEBUG;TRACE</DefineConstants></PropertyGroup></Project>`, 1)}, "13.0.1"},
		{"legacy project names a file for the stock imports to import", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`,
			"A/A.csproj":  strings.Replace(legacyProject, "<OutputType>", `<CustomAfterMicrosoftCommonTargets>$(MSBuildProjectDirectory)\x.targets</CustomAfterMicrosoftCommonTargets><OutputType>`, 1),
			"A/x.targets": `<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[12.0.3]" /></ItemGroup></Project>`}, ""},
		{"legacy project names a file for the C# targets to import", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`,
			"A/A.csproj":  strings.Replace(legacyProject, "<OutputType>", `<CustomBeforeMicrosoftCSharpTargets>$(MSBuildProjectDirectory)\x.targets</CustomBeforeMicrosoftCSharpTargets><OutputType>`, 1),
			"A/x.targets": `<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[12.0.3]" /></ItemGroup></Project>`}, ""},
		{"legacy project redefines MSBuildExtensionsPath", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`,
			"A/A.csproj":                        `<Project><PropertyGroup><MSBuildExtensionsPath>$(MSBuildProjectDirectory)\ext</MSBuildExtensionsPath></PropertyGroup>` + strings.TrimPrefix(legacyProject, `<Project ToolsVersion="15.0">`),
			"A/ext/15.0/Microsoft.Common.props": `<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[12.0.3]" /></ItemGroup></Project>`}, ""},
		{"legacy project with a target", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`,
			"A/A.csproj": strings.Replace(legacyProject, "</Project>", `<Target Name="AfterBuild" /></Project>`, 1)}, ""},
		{"legacy project with an ImportGroup", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`,
			"A/A.csproj": `<Project><ImportGroup><Import Project="x.targets" /></ImportGroup></Project>`}, ""},
		{"SDK project beside packages.config", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`, "A/A.csproj": newtonsoftProject("[12.0.3]", "")}, "12.0.3"},
		{"PackageReference project beside packages.config", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`,
			"A/A.csproj": strings.Replace(legacyProject, "</Project>", `<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[12.0.3]" /></ItemGroup></Project>`, 1)}, ""},
		{"packages.config under a Directory file", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`, "A/A.csproj": "<Project/>", "Directory.Build.props": "<Project/>"}, ""},
		{"unmodeled project without the reference", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""), "B/B.csproj": `<Project Sdk="Microsoft.NET.Sdk"><Import Project="x.targets" /></Project>`}, ""},
		{"item name in another case", map[string]string{"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><packageReference Include="Newtonsoft.Json" Version="[13.0.1]" /></ItemGroup></Project>`}, "13.0.1"},
		{"item name in another case disagrees", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""),
			"B/B.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><packagereference Include="Newtonsoft.Json" Version="[12.0.3]" /></ItemGroup></Project>`}, ""},
		{"project reference in another case", map[string]string{"App.csproj": newtonsoftProject("13.0.1", `<ItemGroup><projectreference Include="Lib/Lib.csproj" /></ItemGroup>`),
			"packages.lock.json": lockFile(lockSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")))}, ""},
		{"lock covers its project", map[string]string{"App.csproj": newtonsoftProject("13.0.1", ""),
			"packages.lock.json": lockFile(lockSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")))}, "13.0.1"},
		{"lock covers each framework", map[string]string{"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFrameworks>net6.0;net8.0</TargetFrameworks></PropertyGroup>` +
			`<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>`,
			"packages.lock.json": lockFile(lockSection("net6.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")),
				lockSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")),
				lockSection("net8.0/win-x64"))}, "13.0.1"},
		{"lock beside an unmodeled project", map[string]string{"App.csproj": newtonsoftProject("13.0.1", "<Import Project=\"x.targets\" />"),
			"packages.lock.json": lockFile(lockSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")))}, ""},
		{"stale lock", map[string]string{"App.csproj": newtonsoftProject("13.0.3", ""),
			"packages.lock.json": lockFile(lockSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[12.0.1, )", "12.0.1")))}, ""},
		{"lock missing a framework", map[string]string{"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFrameworks>net6.0;net8.0</TargetFrameworks></PropertyGroup>` +
			`<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>`,
			"packages.lock.json": lockFile(lockSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[12.0.1, )", "13.0.1")))}, ""},
		{"lock frameworks disagree", map[string]string{"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFrameworks>net6.0;net8.0</TargetFrameworks></PropertyGroup>` +
			`<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>`,
			"packages.lock.json": lockFile(lockSection("net6.0", lockEntry("Newtonsoft.Json", "Direct", "[12.0.1, )", "12.0.1")),
				lockSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[12.0.1, )", "13.0.1")))}, ""},
		{"lock with a direct id the project lacks", map[string]string{"App.csproj": newtonsoftProject("13.0.1", ""),
			"packages.lock.json": lockFile(lockSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1"), lockEntry("Other", "Direct", "[1.0.0, )", "1.0.0")))}, ""},
		{"lock beside a project reference", map[string]string{"App.csproj": newtonsoftProject("13.0.1", `<ItemGroup><ProjectReference Include="../Lib/Lib.csproj" /></ItemGroup>`),
			"packages.lock.json": lockFile(lockSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")))}, ""},
		{"lock with a central transitive entry", map[string]string{"App.csproj": newtonsoftProject("13.0.1", ""),
			"packages.lock.json": lockFile(lockSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1"), lockEntry("Other", "CentralTransitive", "[1.0.0, )", "1.0.0")))}, ""},
		{"lock for another framework", map[string]string{"App.csproj": newtonsoftProject("13.0.1", ""),
			"packages.lock.json": lockFile(lockSection("net6.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")))}, ""},
		{"lock missing a direct id", map[string]string{"App.csproj": newtonsoftProject("13.0.1", `<ItemGroup><PackageReference Include="Other" Version="1.0.0" /></ItemGroup>`),
			"packages.lock.json": lockFile(lockSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")))}, ""},
		{"lock beside a conditional reference", map[string]string{"App.csproj": newtonsoftProject("13.0.1", `<ItemGroup><PackageReference Include="Other" Version="1.0.0" Condition="'$(X)' == 'y'" /></ItemGroup>`),
			"packages.lock.json": lockFile(lockSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1"), lockEntry("Other", "Direct", "[1.0.0, )", "1.0.0")))}, ""},
		{"lock shared by two projects", map[string]string{"App.csproj": newtonsoftProject("13.0.1", ""), "Tool.csproj": newtonsoftProject("13.0.1", ""),
			"packages.lock.json": lockFile(lockSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")))}, ""},
		{"project could restore it transitively", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""),
			"B/B.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Other" Version="[1.0.0]" /></ItemGroup></Project>`}, ""},
		{"lock records the transitive copy", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""),
			"B/B.csproj":           `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Other" Version="[1.0.0]" /></ItemGroup></Project>`,
			"B/packages.lock.json": lockFile(lockSection("net8.0", lockEntry("Other", "Direct", "[1.0.0]", "1.0.0"), lockEntry("Newtonsoft.Json", "Transitive", "", "12.0.1")))}, ""},
		{"lock records an agreeing transitive copy", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""),
			"B/B.csproj":           `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Other" Version="[1.0.0]" /></ItemGroup></Project>`,
			"B/packages.lock.json": lockFile(lockSection("net8.0", lockEntry("Other", "Direct", "[1.0.0]", "1.0.0"), lockEntry("Newtonsoft.Json", "Transitive", "", "13.0.1")))}, "13.0.1"},
		{"project with only a project reference", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""),
			"B/B.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="../A/A.csproj" /></ItemGroup></Project>`}, "13.0.1"},
		{"update of another package", map[string]string{"App.csproj": newtonsoftProject("[13.0.1]", `<ItemGroup><PackageReference Update="Other" Version="[1.0.0]" /></ItemGroup>`)}, ""},
		{"unparseable project beside a pin", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""), "B/B.csproj": "<Project"}, ""},
		{"lock beside a disagreeing project", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""), "A/packages.lock.json": newtonsoftLock, "B/B.csproj": newtonsoftProject("[12.0.3]", "")}, ""},
		{"conditional item group", map[string]string{"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup Condition="'$(X)' == ''"><PackageReference Include="Newtonsoft.Json" Version="[13.0.1]" /></ItemGroup></Project>`}, ""},
		{"conditional reference", map[string]string{"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.1]" Condition="true" /></ItemGroup></Project>`}, ""},
		{"update in the project", map[string]string{"App.csproj": newtonsoftProject("[13.0.1]", `<ItemGroup><PackageReference Update="Newtonsoft.Json" Version="[12.0.3]" /></ItemGroup>`)}, ""},
		{"pinned project beside a property version", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""),
			"B/B.csproj": newtonsoftProject("$(NewtonsoftVersion)", "<PropertyGroup><NewtonsoftVersion>[12.0.3]</NewtonsoftVersion></PropertyGroup>")}, ""},
		{"property-named reference", map[string]string{"App.csproj": newtonsoftProject("[13.0.1]", `<ItemGroup><PackageReference Include="$(Pkg)" Version="[12.0.3]" /></ItemGroup>`)}, ""},
		{"import-steering property", map[string]string{"App.csproj": newtonsoftProject("[13.0.1]", `<PropertyGroup><CustomAfterMicrosoftCommonTargets>x.targets</CustomAfterMicrosoftCommonTargets></PropertyGroup>`)}, ""},
		{"import", map[string]string{"App.csproj": newtonsoftProject("[13.0.1]", `<Import Project="x.targets" />`)}, ""},
		{"target", map[string]string{"App.csproj": newtonsoftProject("[13.0.1]", `<Target Name="T" />`)}, ""},
		{"custom SDK", map[string]string{"App.csproj": `<Project Sdk="Custom.Sdk/1.0"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.1]" /></ItemGroup></Project>`}, ""},
		{"web SDK", map[string]string{"App.csproj": `<Project Sdk="Microsoft.NET.Sdk.Web"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.1]" /></ItemGroup></Project>`}, "13.0.1"},
		{"version override", map[string]string{"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.1]" VersionOverride="12.0.3" /></ItemGroup></Project>`}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := versionsOf(t, writeTree(t, tc.files), "Newtonsoft.Json")
			if !res.Found {
				t.Fatalf("Newtonsoft.Json must be Found; got %+v", res)
			}
			if res.Match.Resolved != (tc.wantVer != "") || res.Match.Version != tc.wantVer {
				t.Fatalf("match = %+v, want version %q resolved %v", res.Match, tc.wantVer, tc.wantVer != "")
			}
		})
	}
}

// NuGet ignores packages.config for a project that is SDK-style or uses PackageReference, so its
// copy is no copy at all: a project like that which doesn't reference the package doesn't carry it.
func TestVersions_UngovernedPackagesConfig(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
	}{
		{"SDK project without the package beside packages.config", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`,
			"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>`}},
		{"Sdk element beside packages.config", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`, "A/A.csproj": `<Project><Sdk Name="Microsoft.NET.Sdk" /></Project>`}},
		{"Sdk import beside packages.config", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`, "A/A.csproj": `<Project><Import Project="Sdk.props" Sdk="Microsoft.NET.Sdk" /></Project>`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if res := versionsOf(t, writeTree(t, tc.files), "Newtonsoft.Json"); res.Found {
				t.Fatalf("Newtonsoft.Json must not be Found; got %+v", res)
			}
		})
	}
}

// A subtree the walk can't list could hold a copy at any version: the run is partial and the
// Match unresolved, not complete on the copies the walk did reach.
func TestVersions_UnlistableSubtree_Partial(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists any directory")
	}
	dir := writeTree(t, map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""), "B/B.csproj": newtonsoftProject("[13.0.1]", "")})
	if res := versionsOf(t, dir, "Newtonsoft.Json"); !res.Match.Resolved || res.Match.Version != "13.0.1" {
		t.Fatalf("control: match = %+v, want 13.0.1", res.Match)
	}
	locked := filepath.Join(dir, "B")
	if _, err := os.Stat(filepath.Join(dir, "b")); err == nil {
		locked = filepath.Join(dir, "b")
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	res := versionsOf(t, dir, "Newtonsoft.Json")
	if res.Partiality.Complete {
		t.Errorf("partiality = %+v, want partial", res.Partiality)
	}
	if !res.Found || res.Match.Resolved || res.Match.Version != "" {
		t.Fatalf("match = %+v, want found and unresolved", res.Match)
	}
}

// NuGet restores an item whatever the case of its name, so a malicious-package match must see it.
func TestVersions_ItemNameInAnotherCase_Presence(t *testing.T) {
	dir := writeTree(t, map[string]string{"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><packagereference Include="Newtonsoft.Json" Version="[13.0.1]" /></ItemGroup></Project>`})
	if res := versionsOf(t, dir, "Newtonsoft.Json"); res.Presence == nil || res.Presence.Version != "13.0.1" {
		t.Fatalf("presence = %+v, want 13.0.1", res.Presence)
	}
}

// Matches lists every project's reference, so a project pinned at another version is visible. A
// project file beside packages.lock.json is superseded by the lock, and each target framework the
// lock restores at its own version is listed.
func TestVersions_MatchesEveryProject(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"Api/Api.csproj":       `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.1]" /></ItemGroup></Project>`,
		"Worker/Worker.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0,14.0)" /></ItemGroup></Project>`,
		"Worker/packages.lock.json": `{"version": 1, "dependencies": {
  "net6.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.0"}},
  "net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"}}
}}`,
	})
	r := versionsOf(t, dir, "newtonsoft.json")
	got := map[string]bool{}
	for _, m := range r.Matches {
		if !m.Resolved {
			t.Fatalf("an unresolved match survived: %+v", m)
		}
		got[m.Version] = true
	}
	if len(r.Matches) != 3 || !got["13.0.0"] || !got["13.0.1"] || !got["13.0.3"] {
		t.Fatalf("Matches = %+v, want Newtonsoft.Json 13.0.0, 13.0.1 and 13.0.3", r.Matches)
	}
}

// The .NET lane never vouches for its Matches, even where every declaration it reads is an exact
// pin: a Choose block or a custom SDK can add a version it does not read. Matches still lists the
// pins as evidence.
func TestVersions_NeverMatchesComplete(t *testing.T) {
	const pin = `<PackageReference Include="Newtonsoft.Json" Version="[13.0.1]" />`
	tests := []struct {
		name  string
		files map[string]string
	}{
		{"exact-bracket direct pin", map[string]string{
			"Api/Api.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>` + pin + `</ItemGroup></Project>`,
		}},
		{"lock beside the project", map[string]string{
			"Api/Api.csproj":         `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>` + pin + `</ItemGroup></Project>`,
			"Api/packages.lock.json": `{"version": 1, "dependencies": {"net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"}}}}`,
		}},
		{"packages.config", map[string]string{
			"Legacy/Legacy.csproj":   `<Project ToolsVersion="15.0"></Project>`,
			"Legacy/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`,
		}},
		{"a Choose block re-versions the pin", map[string]string{
			"Api/Api.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>` + pin + `</ItemGroup><Choose><When Condition="'$(TargetFramework)' == 'net48'"><ItemGroup><PackageReference Update="Newtonsoft.Json" Version="[12.0.1]" /></ItemGroup></When></Choose></Project>`,
		}},
		{"a custom SDK", map[string]string{
			"Api/Api.csproj": `<Project Sdk="Acme.Build.Sdk/1.0.0"><ItemGroup>` + pin + `</ItemGroup></Project>`,
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := versionsOf(t, writeTree(t, tc.files), "Newtonsoft.Json")
			if r.MatchesComplete {
				t.Fatalf("MatchesComplete = true, want false (Matches %+v)", r.Matches)
			}
			if len(r.Matches) != 1 || r.Matches[0].Version != "13.0.1" || !r.Matches[0].Resolved {
				t.Fatalf("Matches = %+v, want Newtonsoft.Json 13.0.1 as evidence", r.Matches)
			}
		})
	}
}
