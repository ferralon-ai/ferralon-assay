package dotnetanalysis

import (
	"context"
	"path/filepath"
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

// A .csproj exact PackageReference pin resolves; a range and a floating version stay
// UNRESOLVED (the predicate fails open on them, never a false not-affected).
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
    <PackageReference Include="ElemVer"><Version>4.5.6</Version></PackageReference>
    <PackageReference Include="NoVersionPkg" />
  </ItemGroup>
</Project>
`,
	})

	// Exact attr pin.
	if r := versionsOf(t, dir, "DotNetZip"); !r.Found || !r.Match.Resolved || r.Match.Version != "1.16.0" {
		t.Errorf("DotNetZip must resolve to 1.16.0; got %+v", r)
	}
	// Exact-bracket "[13.0.1]" unwraps to an exact pin.
	if r := versionsOf(t, dir, "Newtonsoft.Json"); !r.Found || !r.Match.Resolved || r.Match.Version != "13.0.1" {
		t.Errorf("Newtonsoft.Json [13.0.1] must resolve to 13.0.1; got %+v", r)
	}
	// Child-element version.
	if r := versionsOf(t, dir, "ElemVer"); !r.Found || !r.Match.Resolved || r.Match.Version != "4.5.6" {
		t.Errorf("ElemVer child <Version> must resolve to 4.5.6; got %+v", r)
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
	if r := versionsOf(t, dir, "dotnetzip"); !r.Found || r.Match.Version != "1.16.0" {
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
