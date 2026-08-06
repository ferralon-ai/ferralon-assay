// toolchain_inventory_test.go
//
// The provenance-honest half of the toolchain-fact regression: the fact must be PRODUCED by the real
// codebase_inventory stage from a real go.mod on disk, never hand-seeded into the inventory artifact.
//
// This is the exact discipline whose absence let the U7 go-toolchain comparator merge with no input.
// disqual_gotoolchain_u7_test.go declares an "intake → inventory → version axis" span but hand-writes
// the inventory artifact at the middle seam (disqual_versionscheme_u5_test.go:87), which is the one
// place the defect lived — an integration test whose single faked seam is the broken one. So every
// case below runs the REAL stage and reads back the REAL artifact, and the only stub in the path is
// the plugin's non-manifest ops.
package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/goanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// goManifestPlugin is a Go plugin whose BuildManifest is the REAL goanalysis.BuildManifest — a
// genuine modfile parse of the go.mod on disk. Every other op stays stubbed: the subject of these
// tests is where the directive values come from, not analysis.
type goManifestPlugin struct{ plugin.StubPlugin }

// toolchainFactEqual compares two facts by VALUE, dereferencing Contradiction. A bare `!=` on
// ToolchainFact compares the Contradiction POINTER, so two facts describing the same refuted claim
// would read as different and every contradiction assertion would fail for the wrong reason.
func toolchainFactEqual(a, b ToolchainFact) bool {
	if a.Version != b.Version || a.Bound != b.Bound || a.Source != b.Source {
		return false
	}
	switch {
	case a.Contradiction == nil && b.Contradiction == nil:
		return true
	case a.Contradiction == nil || b.Contradiction == nil:
		return false
	default:
		return *a.Contradiction == *b.Contradiction
	}
}

func (goManifestPlugin) Language() string { return "go" }

func (goManifestPlugin) BuildManifest(ctx context.Context, req plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	return goanalysis.BuildManifest(ctx, req)
}

// writeGoModFixture materializes a real single-module tree whose go.mod is exactly goMod.
func writeGoModFixture(t *testing.T, goMod string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	return dir
}

// toolchainInventoryFields reads back only what these tests assert on: the produced fact plus the
// raw go_version it must be derived beside rather than instead of.
type toolchainInventoryFields struct {
	Language  string        `json:"language"`
	GoVersion string        `json:"go_version"`
	Toolchain ToolchainFact `json:"toolchain"`
}

// runRealInventory runs the REAL codebase_inventory stage over the on-disk tree and returns what it
// actually wrote. Nothing is seeded into the inventory artifact; the advisory id is deliberately
// unknown to the default source, so facts are zero and no dependency resolution runs.
func runRealInventory(t *testing.T, stage codebaseInventory) toolchainInventoryFields {
	t.Helper()
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-toolchain-fact", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-TEST-NO-SUCH-ADVISORY", Source: "corpus"},
		Codebase: assessment.CodebaseRef{
			Repo:        "example.com/target",
			Revision:    "v1",
			Acquisition: assessment.Acquisition{Mode: "git"},
		},
	}}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("codebase_inventory.Run: %v", err)
	}
	arts, err := store.Query(c.ID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		t.Fatalf("no inventory artifact: %v", err)
	}
	var inv toolchainInventoryFields
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	return inv
}

// TestCodebaseInventory_ToolchainFactFromRealGoMod is the test whose absence let the version axis
// stay dark: a real Go module on disk, the real stage, and the fact read back off the artifact it
// actually produced.
func TestCodebaseInventory_ToolchainFactFromRealGoMod(t *testing.T) {
	tests := []struct {
		name          string
		goMod         string
		declared      string // tier 1, as the Action's subject-go-version would supply it
		observed      string // tier 2, as the pre-setup-go runner sample would supply it
		trust         bool   // the Action's trust-observed-go: whether tier 2 describes the subject
		wantGoVersion string // the raw `go` directive: recorded verbatim, unchanged by this work
		want          ToolchainFact
	}{
		{
			name:          "go directive alone is a floor",
			goMod:         "module example.com/target\n\ngo 1.20\n",
			wantGoVersion: "1.20",
			want:          ToolchainFact{Version: "go1.20.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
		},
		{
			name:          "toolchain directive outranks the go directive it sits above",
			goMod:         "module example.com/target\n\ngo 1.20\n\ntoolchain go1.20.14\n",
			wantGoVersion: "1.20",
			want:          ToolchainFact{Version: "go1.20.14", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective},
		},
		{
			name:          "the higher floor wins even when it is the go directive",
			goMod:         "module example.com/target\n\ngo 1.22\n\ntoolchain go1.20.14\n",
			wantGoVersion: "1.22",
			want:          ToolchainFact{Version: "go1.22.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
		},
		{
			// The observation must be AT OR ABOVE the floor to outrank it. Below it, the repo's own
			// directive refutes the claim and the contradiction guard takes over — covered by
			// TestResolveToolchainFact's contradiction cases and by the case below.
			name:          "a TRUSTED observed runner toolchain is exact and outranks both floors",
			goMod:         "module example.com/target\n\ngo 1.20\n\ntoolchain go1.20.14\n",
			observed:      "go1.21.0",
			trust:         true,
			wantGoVersion: "1.20",
			want:          ToolchainFact{Version: "go1.21.0", Bound: ToolchainBoundExact, Source: ToolchainSourceCIObserved},
		},
		{
			// THE SHIPPED NO-CONFIG DEFAULT, produced by the real stage off a real go.mod: an
			// observation is present (the Action always samples it) and trust-observed-go is unset, so
			// resolution ignores it and lands on the tighter go.mod floor. This is what a customer who
			// merges the scaffolded workflow and configures nothing gets — floors only, so M3
			// disqualifies solely when a floor is past the fix and M4 will not refute from absence.
			name:          "the no-config default ignores the observation and resolves the floor",
			goMod:         "module example.com/target\n\ngo 1.20\n\ntoolchain go1.20.14\n",
			observed:      "go1.26.4",
			wantGoVersion: "1.20",
			want:          ToolchainFact{Version: "go1.20.14", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective},
		},
		{
			// Same input, no floors at all: the fact is UNRESOLVED rather than silently adopting the
			// runner's Go. The version axis then fails open (inv.5) instead of deriving a not-affected
			// from a version that describes the scanner's environment.
			name:          "the no-config default with no directives resolves NOTHING, not the runner's Go",
			goMod:         "module example.com/target\n",
			observed:      "go1.26.4",
			wantGoVersion: "",
			want:          ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
		{
			name:          "a subject declaration outranks everything",
			goMod:         "module example.com/target\n\ngo 1.20\n\ntoolchain go1.20.14\n",
			declared:      "go1.24.1",
			observed:      "go1.26.3",
			trust:         true,
			wantGoVersion: "1.20",
			want:          ToolchainFact{Version: "go1.24.1", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
		},
		{
			// The contradiction guard through the REAL stage over a REAL go.mod: a declaration below
			// the manifest's own toolchain directive is refuted by the repo, so the exact claim is
			// discarded for the floor and the discarded input is recorded. M3 still disqualifies off
			// the floor; M4's gate is denied because the bound is no longer exact.
			name:          "a declaration BELOW the manifest floor is refuted and demoted to the floor",
			goMod:         "module example.com/target\n\ngo 1.20\n\ntoolchain go1.24.0\n",
			declared:      "go1.19.13",
			wantGoVersion: "1.20",
			want: ToolchainFact{
				Version: "go1.24.0",
				Bound:   ToolchainBoundMinimum,
				Source:  ToolchainSourceToolchainDirective,
				Contradiction: &ToolchainContradiction{
					ClaimedVersion: "go1.19.13", ClaimedSource: ToolchainSourceSubjectDeclared,
					FloorVersion: "go1.24.0", FloorSource: ToolchainSourceToolchainDirective,
				},
			},
		},
		{
			name:          "a go.mod with no version directive at all resolves nothing",
			goMod:         "module example.com/target\n",
			wantGoVersion: "",
			want:          ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buildDir := writeGoModFixture(t, tc.goMod)
			inv := runRealInventory(t, codebaseInventory{
				checkout:         dirCheckout{dir: buildDir, lang: "go"},
				plugin:           goManifestPlugin{},
				subjectGoVersion: tc.declared,
				ciGoVersion:      tc.observed,
				trustCIGoVersion: tc.trust,
			})
			if !toolchainFactEqual(inv.Toolchain, tc.want) {
				t.Errorf("toolchain = %+v, want %+v", inv.Toolchain, tc.want)
			}
			if inv.GoVersion != tc.wantGoVersion {
				t.Errorf("go_version = %q, want %q — the raw directive must stay verbatim beside the fact", inv.GoVersion, tc.wantGoVersion)
			}
		})
	}
}

// TestCodebaseInventory_ToolchainFactIsAlwaysRecorded pins the disclosure: every inventory artifact
// carries the field, and an unresolved fact says so explicitly rather than going missing. A silently
// absent field is how the version axis stayed dark for three weeks.
func TestCodebaseInventory_ToolchainFactIsAlwaysRecorded(t *testing.T) {
	buildDir := writeGoModFixture(t, "module example.com/target\n\ngo 1.20\n")
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-toolchain-present", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-TEST-NO-SUCH-ADVISORY", Source: "corpus"},
		Codebase:      assessment.CodebaseRef{Repo: "example.com/target", Revision: "v1"},
	}}
	stage := codebaseInventory{checkout: dirCheckout{dir: buildDir, lang: "go"}} // plugin == nil
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("codebase_inventory.Run: %v", err)
	}
	arts, _ := store.Query(c.ID, artifact.TypeInventory)
	if len(arts) == 0 {
		t.Fatal("no inventory artifact")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(arts[0].Payload, &raw); err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	if _, ok := raw["toolchain"]; !ok {
		t.Fatalf("inventory payload must always carry \"toolchain\"; got keys %v", keysOf(raw))
	}
	var fact ToolchainFact
	if err := json.Unmarshal(raw["toolchain"], &fact); err != nil {
		t.Fatalf("decode toolchain: %v", err)
	}
	// No plugin ⇒ no manifest read ⇒ no directives, even though the go.mod on disk declares one.
	want := ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved}
	if fact != want {
		t.Errorf("toolchain = %+v, want %+v", fact, want)
	}
}

// TestCodebaseInventory_NonGoSubjectResolvesNoToolchain guards the category error the fact exists to
// close. A JS subject's BuildManifestResult.GoVersion carries a node engine range (jsanalysis reuses
// the field), and the two exact tiers describe a Go build environment. Resolving any of them for a
// non-Go subject would label something that is not the subject's Go toolchain as exactly that —
// including the SCANNER's own Go, arriving via the observed tier on every Action run.
func TestCodebaseInventory_NonGoSubjectResolvesNoToolchain(t *testing.T) {
	buildDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(buildDir, "package.json"), []byte(`{"engines":{"node":">=18"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	inv := runRealInventory(t, codebaseInventory{
		checkout: dirCheckout{dir: buildDir, lang: "js"},
		// The runner sample is present and exact, exactly as it is on a real Action run scanning a
		// JS repo — and it is still not a fact about this subject.
		//
		// Trust is asserted deliberately: with it withheld, the observation would be discarded by the
		// ruling-7 gate and this test would pass without ever exercising the LANGUAGE gate it exists
		// to guard. Both gates must independently refuse.
		ciGoVersion:      "go1.26.3",
		trustCIGoVersion: true,
		subjectGoVersion: "go1.21.3",
	})
	if inv.Language != "js" {
		t.Fatalf("language = %q, want js", inv.Language)
	}
	want := ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved}
	if inv.Toolchain != want {
		t.Errorf("toolchain = %+v, want %+v — a non-Go subject has no Go toolchain fact", inv.Toolchain, want)
	}
}

// TestSubjectToolchainReachesTheStageThroughAssembly walks the LAST link of the chain: the option a
// caller passes must survive stage assembly and arrive at codebase_inventory. Both assemblers are
// covered because both wire the config into the stage independently, so a mistake in one would not
// show up in the other — and the SBOM slice is what the pr-inherit head resolver runs.
func TestSubjectToolchainReachesTheStageThroughAssembly(t *testing.T) {
	buildDir := writeGoModFixture(t, "module example.com/target\n\ngo 1.20\n")

	// The trust flag is asserted alongside the versions because it is a THIRD field threaded through
	// two independent assemblers, and a flag dropped in one of them would silently restore the
	// premise ruling 7 removed — the stage would resolve exact from an observation nobody vouched for.
	for _, tc := range []struct {
		name     string
		declared string
		observed string
		trust    bool
		want     ToolchainFact
	}{
		{
			name:     "a declaration outranks everything and survives assembly",
			declared: "go1.24.1",
			observed: "go1.26.3",
			want:     ToolchainFact{Version: "go1.24.1", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
		},
		{
			name:     "trust survives assembly: the observation becomes the exact fact",
			observed: "go1.26.3",
			trust:    true,
			want:     ToolchainFact{Version: "go1.26.3", Bound: ToolchainBoundExact, Source: ToolchainSourceCIObserved},
		},
		{
			name:     "WITHHELD trust survives assembly: the observation is discarded for the floor",
			observed: "go1.26.3",
			want:     ToolchainFact{Version: "go1.20.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := []AssessOption{
				WithCheckout(dirCheckout{dir: buildDir, lang: "go"}),
				WithPlugin(goManifestPlugin{}),
				WithSubjectToolchain(tc.declared, tc.observed, tc.trust),
			}
			for _, asm := range []struct {
				name   string
				stages []Stage
			}{
				{"AssessStages", AssessStages(opts...)},
				{"SBOMStages", SBOMStages(opts...)},
			} {
				t.Run(asm.name, func(t *testing.T) {
					var stage Stage
					for _, s := range asm.stages {
						if s.Name() == "codebase_inventory" {
							stage = s
						}
					}
					if stage == nil {
						t.Fatal("no codebase_inventory stage in the assembled set")
					}
					inv, ok := stage.(codebaseInventory)
					if !ok {
						t.Fatalf("codebase_inventory is %T, want codebaseInventory", stage)
					}
					got := runRealInventory(t, inv)
					if !toolchainFactEqual(got.Toolchain, tc.want) {
						t.Errorf("toolchain = %+v, want %+v — the injected fact must survive assembly intact", got.Toolchain, tc.want)
					}
				})
			}
		})
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
