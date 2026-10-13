package dotnetanalysis

import (
	"context"
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
				"B/B.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1"`,
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

func cpmProps(version string) string {
	return `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="` + version + `" /></ItemGroup></Project>`
}

func csproj(pkg, version string) string {
	attr := ""
	if version != "" {
		attr = ` Version="` + version + `"`
	}
	return `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="` + pkg + `"` + attr + ` /></ItemGroup></Project>`
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

// When the copies of a package straddle versions, no single copy decides: Match is
// UNRESOLVED so the predicate fails open. Each row runs 50 times so a map-order draw
// can't pass on a lucky run.
func TestVersions_MultipleCopies(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		version string // "" means Found but UNRESOLVED
	}{
		{
			name:  "lockfile target frameworks disagree",
			files: map[string]string{"App/packages.lock.json": lockJSON(map[string]string{"net6.0": "13.0.1", "net8.0": "13.0.3"})},
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
				"A/packages.lock.json":     lockJSON(map[string]string{"net6.0": "13.0.3", "net8.0": "13.0.3"}),
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
			name: "a VersionOverride is the declared version",
			files: map[string]string{
				"Directory.Packages.props": cpmProps("12.0.1"),
				"A/A.csproj":               `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" VersionOverride="13.0.3" /></ItemGroup></Project>`,
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
			version: "13.0.3",
		},
		{
			name: "a VersionOverride with a stale lockfile",
			files: map[string]string{
				"Directory.Packages.props": cpmProps("13.0.3"),
				"A/A.csproj":               `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" VersionOverride="12.0.1" /></ItemGroup></Project>`,
				"A/packages.lock.json":     lockJSON(map[string]string{"net8.0": "13.0.3"}),
			},
		},
		{
			name: "every copy agrees",
			files: map[string]string{
				"A/A.csproj":             csproj("Newtonsoft.Json", "13.0.3"),
				"A/packages.lock.json":   lockJSON(map[string]string{"net6.0": "13.0.3", "net8.0": "13.0.3"}),
				"B/B.csproj":             csproj("newtonsoft.json", "13.0.3"),
				"Legacy/packages.config": `<packages><package id="Newtonsoft.Json" version="13.0.3" /></packages>`,
			},
			version: "13.0.3",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, tc.files)
			for run := range 50 {
				r := versionsOf(t, dir, "Newtonsoft.Json")
				if !r.Found {
					t.Fatalf("run %d: Newtonsoft.Json not found", run)
				}
				if tc.version == "" {
					if r.Match.Resolved || r.Match.Version != "" {
						t.Fatalf("run %d: copies straddle, want UNRESOLVED; got %+v", run, r.Match)
					}
					continue
				}
				if !r.Match.Resolved || r.Match.Version != tc.version {
					t.Fatalf("run %d: want resolved %s; got %+v", run, tc.version, r.Match)
				}
			}
		})
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
