package dotnetanalysis

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

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
// confident Complete.
func TestVersions_UnparseableManifest_Partial(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"packages.lock.json": "{ this is not valid json",
	})
	res := versionsOf(t, dir, "anything")
	if res.Partiality.Complete {
		t.Errorf("an unparseable manifest must NOT be Complete; got %+v", res.Partiality)
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

// MatchesComplete holds only when every project's version of the coordinate is one NuGet
// restores as written: a lock beside the project, an exact-bracket direct pin, or no references
// at all. Anything that can bring in another version leaves it false.
func TestVersions_MatchesComplete(t *testing.T) {
	const (
		lock = `{"version": 1, "dependencies": {"net8.0": {
  "Newtonsoft.Json": {"type": "Transitive", "resolved": "13.0.3"},
  "Serilog": {"type": "Direct", "resolved": "3.1.1"}}}}`
		lockWithout = `{"version": 1, "dependencies": {"net8.0": {"Serilog": {"type": "Direct", "resolved": "3.1.1"}}}}`
		bare        = `<Project Sdk="Microsoft.NET.Sdk"></Project>`
	)
	proj := func(items string) string {
		return `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>` + items + `</ItemGroup></Project>`
	}
	pin := func(v string) string { return `<PackageReference Include="Newtonsoft.Json" Version="` + v + `" />` }
	tests := []struct {
		name     string
		files    map[string]string
		want     bool
		versions []string
	}{
		{"exact-bracket direct pin", map[string]string{"Api/Api.csproj": proj(pin("[13.0.1]"))}, true, []string{"13.0.1"}},
		{"plain version is a minimum", map[string]string{"Api/Api.csproj": proj(pin("13.0.1"))}, false, nil},
		{"lock beside the project", map[string]string{
			"Api/Api.csproj": proj(`<PackageReference Include="Serilog" Version="3.1.1" />`), "Api/packages.lock.json": lock,
		}, true, []string{"13.0.3"}},
		{"lock and an exact pin in another project", map[string]string{
			"Api/Api.csproj": proj(`<PackageReference Include="Serilog" Version="3.1.1" />`), "Api/packages.lock.json": lock,
			"Worker/Worker.csproj": proj(pin("[12.0.3]")), "Docs/Docs.csproj": bare,
		}, true, []string{"13.0.3", "12.0.3"}},
		{"stale lock omits a declared coordinate", map[string]string{
			"Api/Api.csproj": proj(pin("[13.0.1]")), "Api/packages.lock.json": lockWithout,
			"Worker/Worker.csproj": proj(pin("[12.0.3]")),
		}, false, nil},
		{"unlocked project with other packages", map[string]string{
			"Api/Api.csproj": proj(pin("[13.0.1]")), "Worker/Worker.csproj": proj(`<PackageReference Include="Serilog" Version="[3.1.1]" />`),
		}, false, nil},
		{"unlocked project referencing a project", map[string]string{
			"Api/Api.csproj": proj(pin("[13.0.1]")), "Worker/Worker.csproj": proj(`<ProjectReference Include="../Lib/Lib.csproj" />`),
		}, false, nil},
		{"conditional pin", map[string]string{
			"Api/Api.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup Condition="'$(TargetFramework)' == 'net6.0'">` + pin("[13.0.1]") + `</ItemGroup></Project>`,
		}, false, nil},
		{"pin updated elsewhere", map[string]string{
			"Api/Api.csproj": proj(pin("[13.0.1]") + `<PackageReference Update="Newtonsoft.Json" Version="[13.0.3]" />`),
		}, false, nil},
		{"explicit import", map[string]string{
			"Api/Api.csproj": `<Project Sdk="Microsoft.NET.Sdk"><Import Project="../shared.props" /><ItemGroup>` + pin("[13.0.1]") + `</ItemGroup></Project>`,
		}, false, nil},
		{"Directory.Packages.props", map[string]string{"Api/Api.csproj": proj(pin("[13.0.1]")), "Directory.Packages.props": `<Project />`}, false, nil},
		{"Directory.Build.props", map[string]string{"Api/Api.csproj": proj(pin("[13.0.1]")), "Api/Directory.Build.props": `<Project />`}, false, nil},
		{"packages.config beside a classic project", map[string]string{
			"Legacy/Legacy.csproj":   `<Project ToolsVersion="15.0"><Import Project="$(MSBuildToolsPath)\Microsoft.CSharp.targets" /></Project>`,
			"Legacy/packages.config": `<packages><package id="Newtonsoft.Json" version="12.0.3" /></packages>`,
		}, true, []string{"12.0.3"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := versionsOf(t, writeTree(t, tc.files), "Newtonsoft.Json")
			if r.MatchesComplete != tc.want {
				t.Fatalf("MatchesComplete = %v, want %v (Matches %+v)", r.MatchesComplete, tc.want, r.Matches)
			}
			var got []string
			for _, m := range r.Matches {
				got = append(got, m.Version)
			}
			if tc.versions != nil && !slices.Equal(got, tc.versions) {
				t.Fatalf("Matches = %v, want %v", got, tc.versions)
			}
		})
	}
}

// An MSBuild-wide file applies from any directory above a project, the build directory's own
// ancestors included, so one above the build directory leaves MatchesComplete false.
func TestVersions_MatchesCompleteAncestorProps(t *testing.T) {
	const api = `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.1]" /></ItemGroup></Project>`
	for _, tc := range []struct {
		above string
		want  bool
	}{
		{"", true},
		{"Directory.Build.props", false},
		{"Directory.Build.targets", false},
		{"Directory.Packages.props", false},
	} {
		t.Run("above: "+tc.above, func(t *testing.T) {
			files := map[string]string{"repo/Api/Api.csproj": api}
			if tc.above != "" {
				files[tc.above] = `<Project />`
			}
			r := versionsOf(t, filepath.Join(writeTree(t, files), "repo"), "Newtonsoft.Json")
			if r.MatchesComplete != tc.want {
				t.Fatalf("MatchesComplete = %v, want %v (Matches %+v)", r.MatchesComplete, tc.want, r.Matches)
			}
		})
	}
}

// A subtree the walk cannot read may hold another project, so Matches cannot be complete.
func TestVersions_MatchesCompleteUnreadableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-0 directory")
	}
	dir := writeTree(t, map[string]string{
		"Api/Api.csproj":       `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.1]" /></ItemGroup></Project>`,
		"Hidden/Hidden.csproj": `<Project Sdk="Microsoft.NET.Sdk"></Project>`,
	})
	hidden := filepath.Join(dir, "Hidden")
	if err := os.Chmod(hidden, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(hidden, 0o755) })
	if r := versionsOf(t, dir, "Newtonsoft.Json"); r.MatchesComplete {
		t.Fatalf("an unreadable subtree must leave MatchesComplete false; got %+v", r.Matches)
	}
}
