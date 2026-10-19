package dotnetanalysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
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
// confident Complete, and vetoes every coordinate: it could declare any version of anything.
func TestVersions_UnparseableManifest_Vetoes(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
	}{
		{
			name: "a truncated project file beside a pin",
			files: map[string]string{
				"A/A.csproj": csproj("Newtonsoft.Json", "13.0.3"),
				"B/B.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1"`,
			},
		},
		{
			name: "a malformed lockfile beside a pin",
			files: map[string]string{
				"A/A.csproj":           csproj("Newtonsoft.Json", "13.0.3"),
				"B/packages.lock.json": "{ this is not valid json",
			},
		},
		{
			name:  "a malformed lockfile alone",
			files: map[string]string{"packages.lock.json": "{ this is not valid json"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := versionsOf(t, writeTree(t, tc.files), "Newtonsoft.Json")
			if res.Partiality.Complete {
				t.Errorf("an unparseable manifest must NOT be Complete; got %+v", res.Partiality)
			}
			if !res.Found || res.Match.Resolved || res.Match.Version != "" {
				t.Errorf("want Found and UNRESOLVED; got found=%v %+v", res.Found, res.Match)
			}
		})
	}
	if res := versionsOf(t, writeTree(t, map[string]string{"packages.lock.json": "{"}), ""); res.Found {
		t.Errorf("an empty coordinate must not be Found; got %+v", res.Match)
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

// A coordinate the tree shows is not installed is not Found. One a project could pull in
// transitively, with nothing recording what restore installed, is Found and UNRESOLVED (the
// pipeline fails open either way, never a fabricated not-affected).
func TestVersions_UndeclaredCoordinate(t *testing.T) {
	app := csproj("A", "1.0.0")
	cases := []struct {
		name   string
		files  map[string]string
		found  bool
		reason string
	}{
		{
			name:   "a project with other packages and no lockfile",
			files:  map[string]string{"App.csproj": app},
			found:  true,
			reason: reasonNoLockfile,
		},
		{
			name: "a project with a current lockfile that doesn't list it",
			files: map[string]string{
				"App.csproj":         app,
				"packages.lock.json": `{"version": 1, "dependencies": {"net8.0": {"A": {"type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0"}}}}`,
			},
		},
		{
			name: "a project with a stale lockfile",
			files: map[string]string{
				"App.csproj":         app,
				"packages.lock.json": `{"version": 1, "dependencies": {"net8.0": {"A": {"type": "Direct", "requested": "[0.9.0, )", "resolved": "0.9.0"}}}}`,
			},
			found:  true,
			reason: reasonLockfileStale,
		},
		{
			name: "a project whose restore output doesn't list it",
			files: map[string]string{
				"App.csproj":              app,
				"obj/project.assets.json": assetsJSON("App.csproj", map[string]string{"A": "[1.0.0, )"}, map[string]string{"A/1.0.0": "package"}),
			},
		},
		{
			name:  "a project with no package references",
			files: map[string]string{"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"></Project>`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := versionsOf(t, writeTree(t, tc.files), "NotDeclared")
			if r.Found != tc.found || r.Match.Resolved {
				t.Fatalf("want Found=%v and unresolved; got %+v", tc.found, r)
			}
			if tc.reason != "" && !slices.Contains(r.Partiality.Reasons, tc.reason) {
				t.Errorf("want reason %q; got %v", tc.reason, r.Partiality.Reasons)
			}
		})
	}
}

func cpmProps(version string) string {
	return `<Project><PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>` +
		`<ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="` + version + `" /></ItemGroup></Project>`
}

func csproj(pkg, version string) string {
	attr := ""
	if version != "" {
		attr = ` Version="` + version + `"`
	}
	return sdkProject(`<ItemGroup><PackageReference Include="` + pkg + `"` + attr + ` /></ItemGroup>`)
}

// sdkProject renders an SDK project file targeting net8.0 that holds items.
func sdkProject(items string) string {
	return projectDeclaring([]string{"net8.0"}, nil, items)
}

// lockJSON renders a packages.lock.json with one Direct Newtonsoft.Json entry per framework,
// requesting the range restore records for a bare "13.0.3" declaration. An empty version
// omits "resolved".
func lockJSON(byTFM map[string]string) string {
	return lockEntries("Direct", "[13.0.3, )", byTFM)
}

// lockEntries is lockJSON with the entry type and "requested" chosen; an empty requested
// omits it.
func lockEntries(typ, requested string, byTFM map[string]string) string {
	s := `{"version": 1, "dependencies": {`
	first := true
	for tfm, v := range byTFM {
		if !first {
			s += ","
		}
		first = false
		resolved := ""
		if v != "" {
			resolved = `, "resolved": "` + v + `"`
		}
		if requested != "" {
			resolved = `, "requested": "` + requested + `"` + resolved
		}
		s += `"` + tfm + `": {"Newtonsoft.Json": {"type": "` + typ + `"` + resolved + `}}`
	}
	return s + "}}"
}

// Every copy the tree installs is handed on: each project's own installed set and every
// target framework of a lockfile, so copies that straddle versions all reach the agreement
// rule. A copy whose version the inputs don't determine is handed on as unknown, and a
// lockfile covers only the project beside it, while current.
func TestVersions_InstalledCopies(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		version string   // "" wants an unknown copy
		kept    []string // when set, the distinct resolved versions kept, and no unknown copy
	}{
		{
			name:  "lockfile target frameworks disagree",
			files: map[string]string{"App/packages.lock.json": lockJSON(map[string]string{"net6.0": "13.0.1", "net8.0": "13.0.3"})},
			kept:  []string{"13.0.1", "13.0.3"},
		},
		{
			name: "two projects pin different versions",
			files: map[string]string{
				"A/A.csproj": csproj("Newtonsoft.Json", "13.0.1"),
				"B/B.csproj": csproj("Newtonsoft.Json", "13.0.3"),
			},
		},
		{
			name: "two projects' lockfiles disagree",
			files: map[string]string{
				"A/packages.lock.json": lockJSON(map[string]string{"net8.0": "13.0.1"}),
				"B/packages.lock.json": lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
			kept: []string{"13.0.1", "13.0.3"},
		},
		{
			name: "packages.config and a project pin disagree",
			files: map[string]string{
				"Legacy/packages.config": `<packages><package id="Newtonsoft.Json" version="12.0.3" /></packages>`,
				"Web/Web.csproj":         csproj("Newtonsoft.Json", "13.0.3"),
			},
		},
		{
			name: "a lockfile entry without a resolved version beside a pin",
			files: map[string]string{
				"A/packages.lock.json": lockJSON(map[string]string{"net8.0": ""}),
				"B/B.csproj":           csproj("Newtonsoft.Json", "13.0.3"),
			},
		},
		{
			name: "a range is not covered by another project's lockfile",
			files: map[string]string{
				"A/A.csproj":           csproj("Newtonsoft.Json", "[13.0,14.0)"),
				"B/packages.lock.json": lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a range is covered by its own project's lockfile",
			files: map[string]string{
				"A/A.csproj":           csproj("Newtonsoft.Json", "[13.0,14.0)"),
				"A/packages.lock.json": lockEntries("Direct", "[13.0.0, 14.0.0)", map[string]string{"net8.0": "13.0.3"}),
			},
			version: "13.0.3",
		},
		{
			name: "a float is covered by its own project's lockfile",
			files: map[string]string{
				"A/A.csproj":           csproj("Newtonsoft.Json", "13.*"),
				"A/packages.lock.json": lockEntries("Direct", "[13.*, )", map[string]string{"net8.0": "13.0.3"}),
			},
			version: "13.0.3",
		},
		{
			name: "a stale lockfile does not cover its project's range",
			files: map[string]string{
				"A/A.csproj":           csproj("Newtonsoft.Json", "[13.0.3,)"),
				"A/packages.lock.json": lockEntries("Direct", "[12.0.1, )", map[string]string{"net8.0": "12.0.1"}),
			},
		},
		{
			name: "a lockfile stale for one target framework does not cover",
			files: map[string]string{
				"A/A.csproj": csproj("Newtonsoft.Json", "[13.0,14.0)"),
				"A/packages.lock.json": `{"version": 1, "dependencies": {
  "net6.0": {"Newtonsoft.Json": {"type": "Direct", "requested": "[12.0.1, )", "resolved": "13.0.3"}},
  "net8.0": {"Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.0, 14.0.0)", "resolved": "13.0.3"}}
}}`,
			},
		},
		{
			name: "a lockfile requesting other bounds does not cover",
			files: map[string]string{
				"A/A.csproj":           csproj("Newtonsoft.Json", "(13.0,14.0]"),
				"A/packages.lock.json": lockEntries("Direct", "[13.0.0, 14.0.0)", map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a lockfile entry without requested does not cover",
			files: map[string]string{
				"A/A.csproj":           csproj("Newtonsoft.Json", "[13.0,14.0)"),
				"A/packages.lock.json": lockEntries("Direct", "", map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a transitive-only lockfile entry does not cover a declared range",
			files: map[string]string{
				"A/A.csproj":           csproj("Newtonsoft.Json", "[13.0,14.0)"),
				"A/packages.lock.json": lockEntries("Transitive", "[13.0.0, 14.0.0)", map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a property-valued version is not covered",
			files: map[string]string{
				"A/A.csproj":           csproj("Newtonsoft.Json", "$(NewtonsoftVersion)"),
				"A/packages.lock.json": lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a central-package-management reference is covered by its own lockfile",
			files: map[string]string{
				"Directory.Packages.props": cpmProps("13.0.3"),
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
			version: "13.0.3",
		},
		{
			name: "a central-package-management reference with a stale lockfile",
			files: map[string]string{
				"Directory.Packages.props": cpmProps("13.0.3"),
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockEntries("Direct", "[12.0.1, )", map[string]string{"net8.0": "12.0.1"}),
			},
		},
		{
			name: "the nearest Directory.Packages.props decides",
			files: map[string]string{
				"Directory.Packages.props":   cpmProps("13.0.3"),
				"A/Directory.Packages.props": cpmProps("12.0.1"),
				"A/A.csproj":                 csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":       lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a central-package-management reference with no PackageVersion",
			files: map[string]string{
				"Directory.Packages.props": `<Project><ItemGroup><PackageVersion Include="Other" Version="1.0.0" /></ItemGroup></Project>`,
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a central-package-management reference with no props file",
			files: map[string]string{
				"A/A.csproj":           csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json": lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a central-package-management reference with an unreadable props file",
			files: map[string]string{
				"Directory.Packages.props": `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3"`,
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a PackageVersion Update in the props file covers nothing",
			files: map[string]string{
				"Directory.Packages.props": `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /><PackageVersion Update="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>`,
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a PackageVersion Remove in the props file covers nothing",
			files: map[string]string{
				"Directory.Packages.props": `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /><PackageVersion Remove="Other" /></ItemGroup></Project>`,
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "an Import in the props file covers nothing",
			files: map[string]string{
				"Directory.Packages.props": `<Project><Import Project="versions.props" /><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a conditioned PackageVersion covers nothing",
			files: map[string]string{
				"Directory.Packages.props": `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" Condition="'$(TargetFramework)' == 'net8.0'" /></ItemGroup></Project>`,
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a conditioned ItemGroup in the props file covers nothing",
			files: map[string]string{
				"Directory.Packages.props": `<Project><ItemGroup Condition="'$(TargetFramework)' == 'net8.0'"><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a conditioned property in the props file covers nothing",
			files: map[string]string{
				"Directory.Packages.props": `<Project><PropertyGroup><ManagePackageVersionsCentrally Condition="'$(Legacy)' != 'true'">true</ManagePackageVersionsCentrally></PropertyGroup><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "an unmodeled item in the props file covers nothing",
			files: map[string]string{
				"Directory.Packages.props": `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>`,
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "an unmodeled element in the props file covers nothing",
			files: map[string]string{
				"Directory.Packages.props": `<Project><Choose><When Condition="true"><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></When></Choose><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "an unmodeled attribute in the props file covers nothing",
			files: map[string]string{
				"Directory.Packages.props": `<Project Sdk="Microsoft.Build.NoTargets"><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a property-valued PackageVersion covers nothing",
			files: map[string]string{
				"Directory.Packages.props": `<Project><PropertyGroup><NewtonsoftVersion>13.0.3</NewtonsoftVersion></PropertyGroup><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="$(NewtonsoftVersion)" /></ItemGroup></Project>`,
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "central package management turned off covers nothing",
			files: map[string]string{
				"Directory.Packages.props": `<Project><PropertyGroup><ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally></PropertyGroup><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "an Include listing several packages covers nothing",
			files: map[string]string{
				"Directory.Packages.props": `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json;Other" Version="12.0.1" /><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "conflicting PackageVersion entries cover nothing",
			files: map[string]string{
				"Directory.Packages.props": `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="12.0.1" /><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
				"A/A.csproj":               csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a props file with literal properties and a Version element is covered",
			files: map[string]string{
				"Directory.Packages.props": `<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <!-- pinned for CVE review -->
  <PropertyGroup Label="cpm">
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json"><Version>13.0.3</Version></PackageVersion>
  </ItemGroup>
</Project>`,
				"A/A.csproj":           csproj("Newtonsoft.Json", ""),
				"A/packages.lock.json": lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
			version: "13.0.3",
		},
		{
			name: "a lockfile including a lower bound the project excludes does not cover",
			files: map[string]string{
				"A/A.csproj":           csproj("Newtonsoft.Json", "(13.0,14.0)"),
				"A/packages.lock.json": lockEntries("Direct", "[13.0.0, 14.0.0)", map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a lockfile excluding an upper bound the project includes does not cover",
			files: map[string]string{
				"A/A.csproj":           csproj("Newtonsoft.Json", "[13.0,14.0]"),
				"A/packages.lock.json": lockEntries("Direct", "[13.0.0, 14.0.0)", map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a VersionOverride is the declared version",
			files: map[string]string{
				"Directory.Packages.props": cpmProps("12.0.1"),
				"A/A.csproj":               `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json" VersionOverride="13.0.3" /></ItemGroup></Project>`,
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
			version: "13.0.3",
		},
		{
			name: "a VersionOverride with a stale lockfile",
			files: map[string]string{
				"Directory.Packages.props": cpmProps("13.0.3"),
				"A/A.csproj":               `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json" VersionOverride="12.0.1" /></ItemGroup></Project>`,
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a project file Update moves its own pin",
			files: map[string]string{
				"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /><PackageReference Update="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>`,
			},
		},
		{
			name: "a project file Remove edits its references",
			files: map[string]string{
				"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /><PackageReference Remove="Newtonsoft.Json" /></ItemGroup></Project>`,
			},
		},
		{
			name: "a project file Update with a VersionOverride makes the lockfile stale",
			files: map[string]string{
				"Directory.Packages.props": cpmProps("13.0.3"),
				"A/A.csproj":               `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json" /><PackageReference Update="Newtonsoft.Json" VersionOverride="12.0.1" /></ItemGroup></Project>`,
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a VersionOverride element is the declared version",
			files: map[string]string{
				"Directory.Packages.props": cpmProps("13.0.3"),
				"A/A.csproj":               `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json"><VersionOverride>12.0.1</VersionOverride></PackageReference></ItemGroup></Project>`,
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "a VersionOverride element matching the lockfile is covered",
			files: map[string]string{
				"Directory.Packages.props": cpmProps("12.0.1"),
				"A/A.csproj":               `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json"><VersionOverride>13.0.3</VersionOverride></PackageReference></ItemGroup></Project>`,
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
			version: "13.0.3",
		},
		{
			name: "a Version element is the project's pin",
			files: map[string]string{
				"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json"><Version>[13.0.3]</Version></PackageReference></ItemGroup></Project>`,
			},
			version: "13.0.3",
		},
		{
			name: "a conditioned Version element is not a pin",
			files: map[string]string{
				"A/A.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json"><Version Condition="'$(TargetFramework)' == 'net8.0'">13.0.3</Version></PackageReference></ItemGroup></Project>`,
			},
		},
		{
			name: "a conditioned VersionOverride element is not covered",
			files: map[string]string{
				"Directory.Packages.props": cpmProps("12.0.1"),
				"A/A.csproj":               `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json"><VersionOverride Condition="'$(TargetFramework)' == 'net8.0'">13.0.3</VersionOverride></PackageReference></ItemGroup></Project>`,
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "every copy agrees",
			files: map[string]string{
				"A/A.csproj":             projectDeclaring([]string{"net6.0", "net8.0"}, nil, `<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup>`),
				"A/packages.lock.json":   lockJSON(map[string]string{"net6.0": "13.0.3", "net8.0": "13.0.3"}),
				"B/B.csproj":             csproj("newtonsoft.json", "[13.0.3]"),
				"Legacy/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.3" /></packages>`,
			},
			version: "13.0.3",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, kept := installedOf(t, writeTree(t, tc.files), "Newtonsoft.Json")
			if tc.kept != nil {
				checkKeptSet(t, kept, tc.kept)
				return
			}
			checkKept(t, kept, tc.version)
		})
	}
}

// parseMSBuild reads a Directory.Packages.props's PackageVersion items only from a plain file;
// anything it doesn't model makes the file unreadable rather than silently skipped.
func TestParseMSBuild_CentralVersions(t *testing.T) {
	cases := []struct {
		name  string
		props string
		want  string // Newtonsoft.Json's PackageVersion when readable
		ok    bool
	}{
		{name: "plain file", props: cpmProps("13.0.3"), want: "13.0.3", ok: true},
		{name: "Version element", props: `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json"><Version>13.0.3</Version></PackageVersion></ItemGroup></Project>`, want: "13.0.3", ok: true},
		{name: "byte-order mark", props: "\ufeff" + cpmProps("13.0.3"), want: "13.0.3", ok: true},
		{name: "conflicting duplicates read as unknown", props: `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /><PackageVersion Include="newtonsoft.json" Version="12.0.1" /></ItemGroup></Project>`, want: "", ok: true},
		{name: "inert subtree", props: `<Project><ItemDefinitionGroup /><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`, want: "13.0.3", ok: true},
		{name: "condition on the Version element", props: `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json"><Version Condition="true">13.0.3</Version></PackageVersion></ItemGroup></Project>`},
		{name: "condition on the item group", props: `<Project><ItemGroup Condition="true"><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`},
		{name: "Update", props: `<Project><ItemGroup><PackageVersion Update="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`},
		{name: "unknown metadata", props: `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" Foo="x" /></ItemGroup></Project>`},
		{name: "document type declaration", props: `<!DOCTYPE Project><Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`},
		{name: "Sdk on the project", props: `<Project Sdk="Microsoft.Build.CentralPackageVersions/2.1.3"><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`},
		{name: "conditioned property", props: `<Project><PropertyGroup><CentralPackageTransitivePinningEnabled Condition="'$(CI)' == 'true'">true</CentralPackageTransitivePinningEnabled></PropertyGroup><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`},
		{name: "central management turned off", props: `<Project><PropertyGroup><ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally></PropertyGroup><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`},
		{name: "stray text", props: `<Project>13.0.3<ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`},
		{name: "truncated", props: `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />`},
		{name: "GlobalPackageReference beside it", props: `<Project><ItemGroup><GlobalPackageReference Include="Newtonsoft.Json" Version="12.0.1" /><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`, want: "13.0.3", ok: true},
		{name: "GlobalPackageReference unknown metadata", props: `<Project><ItemGroup><GlobalPackageReference Include="StyleCop.Analyzers" Version="1.1.118" Foo="x" /><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mf, ok := parseMSBuild([]byte(tc.props), roleCentral, "msbuild")
			if ok != tc.ok || mf.versions["newtonsoft.json"] != tc.want {
				t.Fatalf("got %v, %v; want %q, %v", mf.versions, ok, tc.want, tc.ok)
			}
		})
	}
	if _, ok := parseMSBuild([]byte(cpmProps("13.0.3")), roleProject, "msbuild"); ok {
		t.Fatal("a PackageVersion outside Directory.Packages.props parsed")
	}
}

// All lists every distinct (id, version) of a lockfile in sorted framework-then-id order, so
// it is the same on every run.
func TestVersions_LockAllDeterministic(t *testing.T) {
	dir := writeTree(t, map[string]string{"packages.lock.json": `{"version": 1, "dependencies": {
  "net8.0": {"Zeta": {"type": "Direct", "resolved": "2.0.0"}, "Alpha": {"type": "Transitive", "resolved": "1.0.0"}},
  "net6.0": {"Zeta": {"type": "Direct", "resolved": "1.5.0"}, "Alpha": {"type": "Transitive", "resolved": "1.0.0"}}
}}`})
	want := []string{"Alpha@1.0.0", "Zeta@1.5.0", "Zeta@2.0.0"}
	for run := range 50 {
		var got []string
		for _, d := range versionsOf(t, dir, "Zeta").All {
			got = append(got, d.Coordinate+"@"+d.Version)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("run %d: All = %v, want %v", run, got, want)
		}
	}
}

// newtonsoftProject is an SDK project referencing Newtonsoft.Json at version, with extra spliced in
// at the top level.
func newtonsoftProject(version, extra string) string {
	return `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>` + extra +
		`<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="` + version + `" /></ItemGroup></Project>`
}

const newtonsoftLock = `{"version": 1, "dependencies": {"net8.0": {"Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.1]", "resolved": "13.0.1"}}}}`

// lockDoc builds a packages.lock.json from lockSection values.
func lockDoc(sections ...string) string {
	return `{"version": 1, "dependencies": {` + strings.Join(sections, ",") + `}}`
}

// lockDocSection is one target framework's section of a lockDoc, holding lockEntry values.
func lockDocSection(tfm string, entries ...string) string {
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
		// An empty Directory file is read and adds nothing; one that adds a reference disagrees.
		{"Directory.Build.props above the project", map[string]string{"src/App/App.csproj": newtonsoftProject("[13.0.1]", ""), "Directory.Build.props": "<Project/>"}, "13.0.1"},
		{"Directory.Build.props adds a reference", map[string]string{"src/App/App.csproj": newtonsoftProject("[13.0.1]", ""),
			"Directory.Build.props": `<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[12.0.3]" /></ItemGroup></Project>`}, ""},
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
		{"packages.config under a Directory file", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`, "A/A.csproj": "<Project/>", "Directory.Build.props": "<Project/>"}, "13.0.1"},
		{"packages.config under a Directory file that adds a reference", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`, "A/A.csproj": "<Project/>",
			"Directory.Build.props": `<Project><ItemGroup><PackageReference Include="Other" Version="[1.0.0]" /></ItemGroup></Project>`}, ""},
		{"packages.config under a legacy template and a Directory file", map[string]string{"A/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.1" /></packages>`, "A/A.csproj": legacyProject, "Directory.Build.props": "<Project/>"}, ""},
		{"unmodeled project without the reference", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""), "B/B.csproj": `<Project Sdk="Microsoft.NET.Sdk"><Import Project="x.targets" /></Project>`}, ""},
		{"item name in another case", map[string]string{"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><packageReference Include="Newtonsoft.Json" Version="[13.0.1]" /></ItemGroup></Project>`}, "13.0.1"},
		{"item name in another case disagrees", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""),
			"B/B.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><packagereference Include="Newtonsoft.Json" Version="[12.0.3]" /></ItemGroup></Project>`}, ""},
		{"project reference in another case", map[string]string{"App.csproj": newtonsoftProject("13.0.1", `<ItemGroup><projectreference Include="Lib/Lib.csproj" /></ItemGroup>`),
			"packages.lock.json": lockDoc(lockDocSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")))}, ""},
		{"lock covers its project", map[string]string{"App.csproj": newtonsoftProject("13.0.1", ""),
			"packages.lock.json": lockDoc(lockDocSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")))}, "13.0.1"},
		{"lock covers each framework", map[string]string{"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFrameworks>net6.0;net8.0</TargetFrameworks><RuntimeIdentifiers>win-x64</RuntimeIdentifiers></PropertyGroup>` +
			`<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>`,
			"packages.lock.json": lockDoc(lockDocSection("net6.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")),
				lockDocSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")),
				lockDocSection("net6.0/win-x64"), lockDocSection("net8.0/win-x64"))}, "13.0.1"},
		{"lock with a runtime section the project doesn't declare", map[string]string{"App.csproj": newtonsoftProject("13.0.1", ""),
			"packages.lock.json": lockDoc(lockDocSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")), lockDocSection("net8.0/win-x64"))}, ""},
		{"lock beside an unmodeled project", map[string]string{"App.csproj": newtonsoftProject("13.0.1", "<Import Project=\"x.targets\" />"),
			"packages.lock.json": lockDoc(lockDocSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")))}, ""},
		{"stale lock", map[string]string{"App.csproj": newtonsoftProject("13.0.3", ""),
			"packages.lock.json": lockDoc(lockDocSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[12.0.1, )", "12.0.1")))}, ""},
		{"lock missing a framework", map[string]string{"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFrameworks>net6.0;net8.0</TargetFrameworks></PropertyGroup>` +
			`<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>`,
			"packages.lock.json": lockDoc(lockDocSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[12.0.1, )", "13.0.1")))}, ""},
		{"lock frameworks disagree", map[string]string{"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFrameworks>net6.0;net8.0</TargetFrameworks></PropertyGroup>` +
			`<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>`,
			"packages.lock.json": lockDoc(lockDocSection("net6.0", lockEntry("Newtonsoft.Json", "Direct", "[12.0.1, )", "12.0.1")),
				lockDocSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[12.0.1, )", "13.0.1")))}, ""},
		{"lock with a direct id the project lacks", map[string]string{"App.csproj": newtonsoftProject("13.0.1", ""),
			"packages.lock.json": lockDoc(lockDocSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1"), lockEntry("Other", "Direct", "[1.0.0, )", "1.0.0")))}, ""},
		{"lock beside a project reference", map[string]string{"App.csproj": newtonsoftProject("13.0.1", `<ItemGroup><ProjectReference Include="../Lib/Lib.csproj" /></ItemGroup>`),
			"packages.lock.json": lockDoc(lockDocSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")))}, ""},
		{"lock with a central transitive entry", map[string]string{"App.csproj": newtonsoftProject("13.0.1", ""),
			"packages.lock.json": lockDoc(lockDocSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1"), lockEntry("Other", "CentralTransitive", "[1.0.0, )", "1.0.0")))}, ""},
		{"lock for another framework", map[string]string{"App.csproj": newtonsoftProject("13.0.1", ""),
			"packages.lock.json": lockDoc(lockDocSection("net6.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")))}, ""},
		{"lock missing a direct id", map[string]string{"App.csproj": newtonsoftProject("13.0.1", `<ItemGroup><PackageReference Include="Other" Version="1.0.0" /></ItemGroup>`),
			"packages.lock.json": lockDoc(lockDocSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")))}, ""},
		{"lock beside a conditional reference", map[string]string{"App.csproj": newtonsoftProject("13.0.1", `<ItemGroup><PackageReference Include="Other" Version="1.0.0" Condition="'$(X)' == 'y'" /></ItemGroup>`),
			"packages.lock.json": lockDoc(lockDocSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1"), lockEntry("Other", "Direct", "[1.0.0, )", "1.0.0")))}, ""},
		{"lock shared by two projects", map[string]string{"App.csproj": newtonsoftProject("13.0.1", ""), "Tool.csproj": newtonsoftProject("13.0.1", ""),
			"packages.lock.json": lockDoc(lockDocSection("net8.0", lockEntry("Newtonsoft.Json", "Direct", "[13.0.1, )", "13.0.1")))}, ""},
		{"project could restore it transitively", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""),
			"B/B.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Other" Version="[1.0.0]" /></ItemGroup></Project>`}, ""},
		{"lock records the transitive copy", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""),
			"B/B.csproj":           `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Other" Version="[1.0.0]" /></ItemGroup></Project>`,
			"B/packages.lock.json": lockDoc(lockDocSection("net8.0", lockEntry("Other", "Direct", "[1.0.0]", "1.0.0"), lockEntry("Newtonsoft.Json", "Transitive", "", "12.0.1")))}, ""},
		{"lock records an agreeing transitive copy", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""),
			"B/B.csproj":           `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Other" Version="[1.0.0]" /></ItemGroup></Project>`,
			"B/packages.lock.json": lockDoc(lockDocSection("net8.0", lockEntry("Other", "Direct", "[1.0.0]", "1.0.0"), lockEntry("Newtonsoft.Json", "Transitive", "", "13.0.1")))}, "13.0.1"},
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
		// A target is skipped unless it names a restore item, in an element or an attribute.
		{"target", map[string]string{"App.csproj": newtonsoftProject("[13.0.1]", `<Target Name="T" />`)}, "13.0.1"},
		{"target that adds a reference", map[string]string{"App.csproj": newtonsoftProject("[13.0.1]",
			`<Target Name="T" BeforeTargets="Restore"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[12.0.3]" /></ItemGroup></Target>`)}, ""},
		{"target hooked to the reference collection", map[string]string{"App.csproj": newtonsoftProject("[13.0.1]", `<Target Name="T" BeforeTargets="CollectPackageReferences" />`)}, ""},
		{"custom SDK", map[string]string{"App.csproj": `<Project Sdk="Custom.Sdk/1.0"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.1]" /></ItemGroup></Project>`}, ""},
		{"web SDK", map[string]string{"App.csproj": `<Project Sdk="Microsoft.NET.Sdk.Web"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.1]" /></ItemGroup></Project>`}, "13.0.1"},
		{"version override", map[string]string{"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.1]" VersionOverride="12.0.3" /></ItemGroup></Project>`}, ""},
		{"version override element", map[string]string{"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.1]"><VersionOverride>[12.0.3]</VersionOverride></PackageReference></ItemGroup></Project>`}, ""},
		{"project referencing a project without the package", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""),
			"B/B.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="../C/C.csproj" /></ItemGroup></Project>`,
			"C/C.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Other" Version="[1.0.0]" /></ItemGroup></Project>`}, ""},
		{"project referencing a project with a minimum", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""),
			"B/B.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="../C/C.csproj" /></ItemGroup></Project>`,
			"C/C.csproj": newtonsoftProject("13.0.1", "")}, ""},
		{"project referencing through an empty project", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""),
			"B/B.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="../C/C.csproj" /></ItemGroup></Project>`,
			"C/C.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="../A/A.csproj" /></ItemGroup></Project>`}, "13.0.1"},
		{"conditioned project reference", map[string]string{"A/A.csproj": newtonsoftProject("[13.0.1]", ""),
			"B/B.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><ProjectReference Include="../A/A.csproj" Condition="'$(X)' == ''" /></ItemGroup></Project>`}, ""},
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
