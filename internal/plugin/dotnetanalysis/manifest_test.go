package dotnetanalysis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// buildManifestFor runs BuildManifest over a hand-authored fixture tree (fixtures written to
// t.TempDir() via the package writeTree idiom). It NEVER shells out to dotnet/MSBuild/NuGet — the
// .csproj/global.json/restore-artifact bytes are read lexically.
func buildManifestFor(t *testing.T, dir string) plugin.BuildManifestResult {
	t.Helper()
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	return res
}

// singleTFMCsproj is the minimal single-language .NET project carrying exactly one TargetFramework.
func singleTFMCsproj(tfm string) string {
	return `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>` + tfm +
		`</TargetFramework></PropertyGroup></Project>`
}

// slnTwoProjects is a lexically-parsed .sln naming two member projects (multi-project workspace).
const slnTwoProjects = `Microsoft Visual Studio Solution File, Format Version 12.00
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "ProjA", "ProjA\ProjA.csproj", "{11111111-1111-1111-1111-111111111111}"
EndProject
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "ProjB", "ProjB\ProjB.csproj", "{22222222-2222-2222-2222-222222222222}"
EndProject
`

// --- C1: every deliverable-7 item lands as a field OR a naming reason ---------

// TestManifest_C1_DeliverableSevenCoverage is one table over the 7 deliverable items. For each, a
// fixture where the item is present and an assertion of the EXACT frozen field value OR the EXACT
// partiality reason string that homes it.
func TestManifest_C1_DeliverableSevenCoverage(t *testing.T) {
	cases := []struct {
		name  string
		tree  map[string]string
		check func(t *testing.T, res plugin.BuildManifestResult)
	}{
		{
			name: "item1_sdk_toolchain_global_json",
			tree: map[string]string{
				"App.csproj":  singleTFMCsproj("net8.0"),
				"global.json": `{"sdk":{"version":"8.0.100"}}`,
			},
			check: func(t *testing.T, res plugin.BuildManifestResult) {
				if res.Runtime.Toolchain != "8.0.100" {
					t.Errorf("SDK item: want Runtime.Toolchain=8.0.100; got %q", res.Runtime.Toolchain)
				}
			},
		},
		{
			name: "item2_multi_project_solution",
			tree: map[string]string{
				"App.sln":            slnTwoProjects,
				"ProjA/ProjA.csproj": singleTFMCsproj("net8.0"),
				"ProjB/ProjB.csproj": singleTFMCsproj("net8.0"),
			},
			check: func(t *testing.T, res plugin.BuildManifestResult) {
				if !hasReason(res.Partiality, reasonMultiProjectSolution) {
					t.Errorf("solution/projects item: want reason %q; got %v", reasonMultiProjectSolution, res.Partiality.Reasons)
				}
			},
		},
		{
			name: "item3_configuration",
			tree: map[string]string{
				"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework><Configuration>Release</Configuration></PropertyGroup></Project>`,
			},
			check: func(t *testing.T, res plugin.BuildManifestResult) {
				if res.Configuration != "Release" {
					t.Errorf("configuration item: want Configuration=Release; got %q", res.Configuration)
				}
			},
		},
		{
			name: "item4_target_framework",
			tree: map[string]string{"App.csproj": singleTFMCsproj("net8.0")},
			check: func(t *testing.T, res plugin.BuildManifestResult) {
				if res.Runtime.Version != "net8.0" {
					t.Errorf("TFM item: want Runtime.Version=net8.0; got %q", res.Runtime.Version)
				}
			},
		},
		{
			name: "item5_runtime_identifier",
			tree: map[string]string{
				"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework><RuntimeIdentifier>linux-x64</RuntimeIdentifier></PropertyGroup></Project>`,
			},
			check: func(t *testing.T, res plugin.BuildManifestResult) {
				if res.Target != "linux-x64" {
					t.Errorf("RID item: want Target=linux-x64; got %q", res.Target)
				}
			},
		},
		{
			name: "item6_restore_provenance_present",
			tree: map[string]string{
				"App.csproj":              singleTFMCsproj("net8.0"),
				"obj/project.assets.json": `{"version":3,"targets":{"net8.0":{}},"libraries":{}}`,
			},
			check: func(t *testing.T, res plugin.BuildManifestResult) {
				// Restore artifact present ⇒ the provenance is homed: NOT no_lockfile, and the
				// Resolver identity is recorded.
				if hasReason(res.Partiality, reasonNoLockfile) {
					t.Errorf("restore-provenance item: present assets must not carry %q; got %v", reasonNoLockfile, res.Partiality.Reasons)
				}
				if res.Resolver.Name != "dotnet" {
					t.Errorf("restore-provenance item: want Resolver.Name=dotnet; got %q", res.Resolver.Name)
				}
			},
		},
		{
			name: "item7_property_set_unhomed",
			tree: map[string]string{
				"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework><OutputType>Exe</OutputType></PropertyGroup></Project>`,
			},
			check: func(t *testing.T, res plugin.BuildManifestResult) {
				// OutputType has no frozen home ⇒ it lands as a naming reason.
				if !hasReason(res.Partiality, reasonPropertySetUnhomed) {
					t.Errorf("property-set item: want reason %q; got %v", reasonPropertySetUnhomed, res.Partiality.Reasons)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.check(t, buildManifestFor(t, writeTree(t, c.tree)))
		})
	}
}

// TestManifest_C1_NegativeControl_NoProjectVsMalformed is the REQUIRED negative control. A dir with
// NO project file and a dir with a present-but-MALFORMED .csproj must be DISTINGUISHABLE (different
// partiality/reasons); a control that accepts both measures nothing. The measurable distinction:
// no-project names no_manifest (there is genuinely nothing to read); a present-but-unparseable
// project does NOT — a file exists, it simply carries no derivable facts. Neither may be Complete().
func TestManifest_C1_NegativeControl_NoProjectVsMalformed(t *testing.T) {
	noProject := buildManifestFor(t, writeTree(t, map[string]string{
		"README.md": "no project file here\n",
	}))
	malformed := buildManifestFor(t, writeTree(t, map[string]string{
		"App.csproj": `garbage-not-valid-xml <<<<`, // present .csproj, unparseable content
	}))

	if noProject.Partiality.Complete {
		t.Errorf("no-project dir must not be Complete(); got %+v", noProject.Partiality)
	}
	if malformed.Partiality.Complete {
		t.Errorf("malformed-project dir must not be Complete(); got %+v", malformed.Partiality)
	}
	if !hasReason(noProject.Partiality, plugin.PartialReasonNoManifest) {
		t.Errorf("no-project dir must carry %q; got %v", plugin.PartialReasonNoManifest, noProject.Partiality.Reasons)
	}
	if hasReason(malformed.Partiality, plugin.PartialReasonNoManifest) {
		t.Errorf("a present (malformed) .csproj is not no_manifest — the two must stay distinct; got %v", malformed.Partiality.Reasons)
	}
	// The load-bearing distinction the negative control exists to enforce.
	if reflect.DeepEqual(reasonSet(noProject.Partiality), reasonSet(malformed.Partiality)) {
		t.Fatalf("no-project and malformed-project are not distinguishable; both reasons = %v", noProject.Partiality.Reasons)
	}
}

// --- C2: property set grep-aligned (programmatic, not by eye) ------------------

// TestManifest_C2_PropertySetAligned asserts the code parser matches the ratified 6-included /
// 3-excluded property set. The CODE side is read programmatically from the package source: struct
// field identifiers are collected via go/ast (comment-immune — manifest.go's prose deliberately
// NAMES the excluded properties, so a raw text grep would false-positive; the AST sees only fields).
//
// DEVIATION (flagged for nickel): the DOC side — execution/property-set.md — lives in the
// team-brain cycle folder OUTSIDE the repo. A checked-in, hermetic Go test must not read
// ~/.team-brain (it would break CI/portability), so the doc's verdict is transcribed here as the
// literal included/excluded lists and the code is checked against it. Drift in the code turns this
// red; a future doc edit is mirrored by editing these literals.
func TestManifest_C2_PropertySetAligned(t *testing.T) {
	included := []string{"TargetFramework", "RuntimeIdentifier", "Configuration", "DefineConstants", "LangVersion", "OutputType"}
	excluded := []string{"Nullable", "AssemblyName", "RootNamespace"}

	fields := parserFieldNames(t)

	for _, name := range included {
		if !fields[name] {
			t.Errorf("included property %q must appear as a parser field; not found in package source", name)
		}
	}
	for _, name := range excluded {
		if fields[name] {
			t.Errorf("excluded property %q must NOT appear in the parser; found as a field", name)
		}
	}
}

// parserFieldNames collects every struct field identifier across the package's non-test .go source
// via go/ast. Reading struct fields (not raw text) makes the check immune to the excluded property
// names that appear in manifest.go's explanatory comments.
func parserFieldNames(t *testing.T) map[string]bool {
	t.Helper()
	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package source: %v", err)
	}
	out := map[string]bool{}
	fset := token.NewFileSet()
	for _, f := range goFiles {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok {
				return true
			}
			for _, field := range st.Fields.List {
				for _, id := range field.Names {
					out[id.Name] = true
				}
			}
			return true
		})
	}
	if len(out) == 0 {
		t.Fatal("collected zero struct fields — the AST walk found no package source")
	}
	return out
}

// --- C3: determinism, no golden -----------------------------------------------

// TestManifest_C3_DeterministicNoGolden computes the manifest for one representative fixture 64
// times in-process and asserts every canonical (json.Marshal) encoding is byte-identical. It logs
// the sha256 of that encoding so nickel can run the binary twice, in separate processes, and diff
// the digests. NO golden manifest file is checked in — the fixture's ProjectRoot is relative ("."),
// so the encoding carries no absolute temp path and the digest is stable ACROSS processes.
func TestManifest_C3_DeterministicNoGolden(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"App.csproj":  `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework><RuntimeIdentifier>linux-x64</RuntimeIdentifier><OutputType>Exe</OutputType></PropertyGroup></Project>`,
		"global.json": `{"sdk":{"version":"8.0.100"}}`,
	})

	first, err := json.Marshal(buildManifestFor(t, dir))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const iterations = 64
	for i := 0; i < iterations; i++ {
		cur, err := json.Marshal(buildManifestFor(t, dir))
		if err != nil {
			t.Fatalf("marshal iter %d: %v", i, err)
		}
		if !bytes.Equal(first, cur) {
			t.Fatalf("non-deterministic manifest at iter %d:\n first=%s\n cur  =%s", i, first, cur)
		}
	}
	sum := sha256.Sum256(first)
	t.Logf("C3-sha256: %s", hex.EncodeToString(sum[:]))
}

// --- C4: condition-gated TFM --------------------------------------------------

// TestManifest_C4_ConditionGatedTFM presents a .csproj that sets TargetFramework twice under
// mutually exclusive Conditions. This pass cannot evaluate which wins, so the manifest must DECLARE
// the ambiguity (multi_target_framework surfacing both candidates, or unevaluated_condition) and
// must NOT collapse to exactly one TFM while claiming Complete().
//
// MUTATION CONTROL: if manifest.go were changed to take the FIRST conditioned TargetFramework match
// and mark Complete() — i.e. Runtime.Version set to a single TFM with Partiality.Complete==true —
// BOTH assertions below go red (no ambiguity reason, and single-TFM+Complete). The impl cannot be
// mutated from this test; 02a's code must satisfy this. If it does not, that is an impl gap to route
// back to 02a, never a reason to soften this test.
func TestManifest_C4_ConditionGatedTFM(t *testing.T) {
	res := buildManifestFor(t, writeTree(t, map[string]string{
		"App.csproj": `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup Condition="'$(Configuration)'=='Debug'"><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)'=='Release'"><TargetFramework>net9.0</TargetFramework></PropertyGroup>
</Project>`,
	}))

	declaresAmbiguity := hasReason(res.Partiality, reasonMultiTargetFramework) || hasReason(res.Partiality, reasonUnevaluatedCondition)
	if !declaresAmbiguity {
		t.Errorf("condition-gated dual TFM must carry %q or %q; got %v",
			reasonMultiTargetFramework, reasonUnevaluatedCondition, res.Partiality.Reasons)
	}
	if res.Runtime.Version != "" && res.Partiality.Complete {
		t.Errorf("must not collapse to a single TFM (%q) with Complete() partiality", res.Runtime.Version)
	}
}
