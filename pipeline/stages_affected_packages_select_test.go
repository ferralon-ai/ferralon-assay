// stages_affected_packages_select_test.go
//
// Select-by-target hermetic proof for the v3 affected_packages[] multi-package block (cycle
// 2026-07-23-affected-block-multipkg). A SYNTHETIC two-gomod-module advisory (example.com/a primary
// + example.com/b secondary) drives moduleVersionFromGoMod directly — no plugin/toolchain — against
// a target whose go.mod requires ONLY the SECONDARY package. The proof:
//
//   - WITHOUT the array, the scalar primary (example.com/a) is unmatched → resolved_version "" →
//     the version axis has nothing to reason over → OPEN. The secondary is invisible.
//   - WITH the array, codebase_inventory selects example.com/b (the package the target actually
//     depends on) → resolved_version is the go.mod-declared version → the version axis engages over
//     the SELECTED package's ranges: a vulnerable version PROCEEDS, a patched version DISQUALIFIES
//     (version_not_in_affected_range) — proving the selection reached the downstream extractors.
//
// This is the "a secondary-package target resolves instead of falling OPEN" assertion the marquee
// CVE-2023-39325 fixture cannot exercise cleanly (its two packages use two different resolution
// primitives — go.mod vs toolchain — contract §5).
package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// multipkgSelectSource returns a fixed synthetic multi-package advisory. When withArray is false the
// affected_packages[] block is omitted (a v2/single-package advisory), so only the scalar primary
// (example.com/a) is available to the resolver — the pre-v3 behavior.
type multipkgSelectSource struct{ withArray bool }

func (s multipkgSelectSource) Lookup(string) (AdvisoryFacts, bool) {
	facts := AdvisoryFacts{
		// Scalar primary (v2 back-compat) = example.com/a. Its range is never consulted here because
		// the target does not depend on it; it exists to prove the primary is UNMATCHED without the array.
		Module:         "example.com/a",
		VersionScheme:  "gomod",
		PURL:           "pkg:golang/example.com/a",
		AffectedRanges: []Range{{Fixed: "v9.9.9", FixedVersion: "v9.9.9"}},
		Symbols:        []string{"example.com/a.Sink"},
		// first_party trust is required for the version axis to be allowed to disqualify (inv.5
		// refute-gate); without it disqualify() always fails open and the patched-secondary case
		// could not demonstrate the axis engaging.
		Provenance: Provenance{Source: "synthetic", TrustTier: TrustFirstParty},
	}
	if s.withArray {
		facts.AffectedPackages = []AffectedPackage{
			{
				Module:         "example.com/a",
				VersionScheme:  "gomod",
				PURL:           "pkg:golang/example.com/a",
				AffectedRanges: []Range{{Fixed: "v9.9.9", FixedVersion: "v9.9.9"}},
				Symbols:        []string{"example.com/a.Sink"},
			},
			{
				Module:        "example.com/b",
				VersionScheme: "gomod",
				PURL:          "pkg:golang/example.com/b",
				// Fixed at v1.5.0 — kept on the v1 major so the synthetic go.mod require stays a valid
				// module path (Go semantic-import-versioning would demand a /v2 path suffix for v2+).
				AffectedRanges: []Range{{Fixed: "v1.5.0", FixedVersion: "v1.5.0"}},
				Symbols:        []string{"example.com/b.Reset"},
			},
		}
	}
	return facts, true
}

// dirCheckout is a hermetic checkout returning a fixed build dir + language (no git, no network).
type dirCheckout struct{ dir, lang string }

func (d dirCheckout) Fetch(context.Context, string, string) (string, string, error) {
	return d.dir, d.lang, nil
}

// writeGoModRequiringB creates a Go module tree whose go.mod requires ONLY example.com/b (the
// secondary package) at bVersion — the primary example.com/a is deliberately absent.
func writeGoModRequiringB(t *testing.T, bVersion string) string {
	t.Helper()
	dir := t.TempDir()
	goMod := "module example.com/target\n\ngo 1.21\n\nrequire example.com/b " + bVersion + "\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	return dir
}

type selectInventoryFields struct {
	ResolvedVersion    string `json:"resolved_version"`
	SelectedModule     string `json:"selected_module"`
	SelectedCoordinate string `json:"selected_coordinate"`
}

// runMultipkgSelect drives advisory_intake + codebase_inventory (and, when asked, stage-3
// disqualification) over the synthetic advisory against a go.mod requiring example.com/b@bVersion.
func runMultipkgSelect(t *testing.T, withArray bool, bVersion string) (selectInventoryFields, DisqualResult) {
	t.Helper()
	buildDir := writeGoModRequiringB(t, bVersion)
	store := artifact.NewMemStore()
	src := multipkgSelectSource{withArray: withArray}
	c := &assessment.Assessment{ID: "case-multipkg-select", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-TEST-MULTIPKG", Source: "corpus"},
		Codebase: assessment.CodebaseRef{
			Repo:        "example.com/target",
			Revision:    "v1",
			Acquisition: assessment.Acquisition{Mode: "git"},
		},
	}}
	if err := (advisoryIntake{src: src}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}
	if err := (codebaseInventory{checkout: dirCheckout{dir: buildDir, lang: "go"}, src: src}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("codebase_inventory: %v", err)
	}
	arts, err := store.Query(c.ID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		t.Fatalf("no inventory artifact: %v", err)
	}
	var inv selectInventoryFields
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	return inv, runDisqual(t, store, c.ID)
}

// WITHOUT the array: the scalar primary (example.com/a) is unmatched (the target requires
// example.com/b, not a), so nothing resolves — resolved_version "" and no selection. The secondary
// is invisible to the pre-v3 path.
func TestMultipkgSelect_WithoutArray_SecondaryUnresolved(t *testing.T) {
	inv, _ := runMultipkgSelect(t, false, "v1.0.0")
	if inv.ResolvedVersion != "" {
		t.Errorf("resolved_version = %q, want empty (scalar primary example.com/a is unmatched)", inv.ResolvedVersion)
	}
	if inv.SelectedModule != "" || inv.SelectedCoordinate != "" {
		t.Errorf("selection = (%q,%q), want none (no array to select from)", inv.SelectedModule, inv.SelectedCoordinate)
	}
}

// WITH the array: select-by-target picks example.com/b (the package the target actually depends on),
// so resolved_version is the go.mod-declared version. A VULNERABLE version (v1.0.0 < fixed v1.5.0)
// engages the version axis and PROCEEDS (still affected) — the exact flip from OPEN to real analysis.
func TestMultipkgSelect_WithArray_SecondaryResolves(t *testing.T) {
	inv, res := runMultipkgSelect(t, true, "v1.0.0")
	if inv.ResolvedVersion != "v1.0.0" {
		t.Fatalf("resolved_version = %q, want v1.0.0 (example.com/b selected)", inv.ResolvedVersion)
	}
	if inv.SelectedModule != "example.com/b" {
		t.Errorf("selected_module = %q, want example.com/b", inv.SelectedModule)
	}
	if res.Disqualified {
		t.Errorf("vulnerable secondary (v1.0.0 < fixed v1.5.0) must PROCEED, got disqualified: %+v", res)
	}
}

// WITH the array + a PATCHED secondary (v1.5.0 >= fixed v1.5.0): the version axis, now reasoning over
// the SELECTED package's ranges (not the primary's), proves not-affected — disqualified with
// version_not_in_affected_range. This proves the selection reached the downstream version extractor.
func TestMultipkgSelect_WithArray_PatchedSecondaryDisqualifies(t *testing.T) {
	inv, res := runMultipkgSelect(t, true, "v1.5.0")
	if inv.ResolvedVersion != "v1.5.0" {
		t.Fatalf("resolved_version = %q, want v1.5.0", inv.ResolvedVersion)
	}
	if !res.Disqualified || res.Reason != ReasonVersionNotInRange {
		t.Fatalf("patched secondary (v2.0.0) must disqualify version_not_in_affected_range, got %+v", res)
	}
}
