package jsanalysis

// inventory_sbom_test.go — C1/C2 SBOM-instance observations (PLAN-165). These tests observe
// PLAN-100's inventory→report.SBOM projection for the npm ecosystem end-to-end: they drive the REAL
// exported resolver trigger.ResolveSBOM over hand-authored lockfile fixtures (C1) and the reused
// CVE-2023-26136 yarn repro (C2), and assert on the projected report.SBOM.
//
// Harness (C6-clean, subprocess-free): jsInventoryAdapter is an in-test plugin.LanguagePlugin whose
// Language() is "js" and whose ResolveInventory delegates to this package's in-process
// ResolveInventory over the fixture lockfile dir (no package manager, no bundler, no target code is
// ever executed — every fact is read statically from committed lockfiles). Every other plugin
// operation keeps plugin.StubPlugin's behavior; the ResolveSBOM path never calls the symbol/ingress
// ops, so the stubbed methods are inert. ResolveSBOM acquires the fixture as a vendored_repro
// CodebaseRef (checkout.ResolveVendored classifies the tree as "js" from its .js source, matching the
// adapter's Language()), resolves the inventory once, and projects it — the same projection the
// baseline producer shares.
//
// Acyclic: package trigger does not import jsanalysis, so this test-only reverse edge (jsanalysis
// test → trigger) introduces no import cycle.

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// jsInventoryAdapter is the in-test LanguagePlugin that routes the JS lane's real inventory resolver
// into the pipeline. It embeds StubPlugin (inert symbol/ingress/etc. ops) and overrides exactly two
// axes: Language() -> "js" (so the vendored_repro's detected language matches and the pipeline routes
// here) and ResolveInventory (delegating to jsanalysis.ResolveInventory over the checked-out dir).
type jsInventoryAdapter struct {
	plugin.StubPlugin
}

func (jsInventoryAdapter) Language() string { return "js" }

func (jsInventoryAdapter) ResolveInventory(ctx context.Context, req plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	return ResolveInventory(ctx, req)
}

// resolveSBOMForDir drives the REAL trigger.ResolveSBOM projection over a vendored_repro fixture dir,
// with the JS inventory adapter injected. The returned report.SBOM is exactly what a PR-head SBOM
// resolution would diff against the baseline.
func resolveSBOMForDir(t *testing.T, dir string) report.SBOM {
	t.Helper()
	sbom, notes, err := trigger.ResolveSBOM(context.Background(), trigger.ResolveSBOMRequest{
		Codebase: assessment.CodebaseRef{
			Repo:        "example.com/js-fixture",
			Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: dir},
		},
		AssessOptions: []pipeline.AssessOption{pipeline.WithPlugin(jsInventoryAdapter{})},
	})
	if err != nil {
		t.Fatalf("ResolveSBOM(%s): %v", dir, err)
	}
	// These fixtures are fully-resolved synthetic lockfiles: the inventory resolves cleanly, so the
	// scan-level partiality channel (PLAN-104) must be empty. Asserting it guards the version-survival
	// claims below — a partial resolution that silently dropped an instance would otherwise be able to
	// masquerade as a clean single-entry result.
	if len(notes) != 0 {
		t.Fatalf("ResolveSBOM(%s): expected clean resolution, got partiality notes %+v", dir, notes)
	}
	return sbom
}

func countPackagesByPURL(sbom report.SBOM, purl string) int {
	n := 0
	for _, p := range sbom.Packages {
		if p.PURL == purl {
			n++
		}
	}
	return n
}

func countPackagesByName(sbom report.SBOM, name string) int {
	n := 0
	for _, p := range sbom.Packages {
		if p.Name == name {
			n++
		}
	}
	return n
}

func sbomHasPackage(sbom report.SBOM, want report.Package) bool {
	for _, p := range sbom.Packages {
		if p == want { // report.Package is all-scalar and comparable
			return true
		}
	}
	return false
}

func sbomHasRelationship(sbom report.SBOM, parent, child string) bool {
	for _, r := range sbom.Relationships {
		if r.Parent == parent && r.Child == child {
			return true
		}
	}
	return false
}

func countRelationshipsToChild(sbom report.SBOM, child string) int {
	n := 0
	for _, r := range sbom.Relationships {
		if r.Child == child {
			n++
		}
	}
	return n
}

const sbomFixtureDir = invDir + "/sbom"

// TestSBOM_JS_DiamondTwoVersions is C1's load-bearing case: two parents pull the SAME package name at
// DIFFERENT versions (pkg-a→shared@1.0.0, pkg-b→shared@2.0.0). Distinct versions are distinct PURLs
// (invariant (i)), so the projection MUST carry TWO distinct `shared` packages, each with its own
// parent edge — a version-collapsing producer would drop one instance and its edge.
func TestSBOM_JS_DiamondTwoVersions(t *testing.T) {
	sbom := resolveSBOMForDir(t, filepath.Join(sbomFixtureDir, "diamond-two-versions"))

	if got := countPackagesByName(sbom, "shared"); got != 2 {
		t.Fatalf("diamond: want 2 distinct `shared` packages, got %d: %+v", got, sbom.Packages)
	}
	if got := countPackagesByPURL(sbom, "pkg:npm/shared@1.0.0"); got != 1 {
		t.Errorf("diamond: want exactly 1 shared@1.0.0 entry, got %d: %+v", got, sbom.Packages)
	}
	if got := countPackagesByPURL(sbom, "pkg:npm/shared@2.0.0"); got != 1 {
		t.Errorf("diamond: want exactly 1 shared@2.0.0 entry, got %d: %+v", got, sbom.Packages)
	}
	if !sbomHasRelationship(sbom, "pkg:npm/pkg-a@1.0.0", "pkg:npm/shared@1.0.0") {
		t.Errorf("diamond: missing edge pkg-a@1.0.0 -> shared@1.0.0; rels=%+v", sbom.Relationships)
	}
	if !sbomHasRelationship(sbom, "pkg:npm/pkg-b@1.0.0", "pkg:npm/shared@2.0.0") {
		t.Errorf("diamond: missing edge pkg-b@1.0.0 -> shared@2.0.0; rels=%+v", sbom.Relationships)
	}
}

// TestSBOM_JS_SingleVersionControl is the C1 negative control: a single hoisted shared@1.0.0 pulled
// through one parent yields exactly ONE `shared` package. It proves the diamond's two entries are the
// two versions, not a projection that double-counts every transitive.
func TestSBOM_JS_SingleVersionControl(t *testing.T) {
	sbom := resolveSBOMForDir(t, filepath.Join(sbomFixtureDir, "single-version"))

	if got := countPackagesByName(sbom, "shared"); got != 1 {
		t.Fatalf("single-version: want 1 `shared` package, got %d: %+v", got, sbom.Packages)
	}
	if got := countPackagesByPURL(sbom, "pkg:npm/shared@1.0.0"); got != 1 {
		t.Errorf("single-version: want exactly 1 shared@1.0.0 entry, got %d: %+v", got, sbom.Packages)
	}
	if got := countPackagesByPURL(sbom, "pkg:npm/shared@2.0.0"); got != 0 {
		t.Errorf("single-version: no shared@2.0.0 should exist, got %d: %+v", got, sbom.Packages)
	}
}

// TestSBOM_JS_SameVersionTwoParents is the second C1 control: two parents pull the SAME (name,version)
// shared@1.0.0. Same version is one PURL → exactly ONE `shared` package (instances collapse to one
// package-granularity node), but the TWO distinct parent edges (pkg-a→shared, pkg-b→shared) both
// survive — the parent chains stay recoverable even where the instance collapses.
func TestSBOM_JS_SameVersionTwoParents(t *testing.T) {
	sbom := resolveSBOMForDir(t, filepath.Join(sbomFixtureDir, "same-version-two-parents"))

	if got := countPackagesByName(sbom, "shared"); got != 1 {
		t.Fatalf("same-version: want 1 `shared` package, got %d: %+v", got, sbom.Packages)
	}
	if got := countPackagesByPURL(sbom, "pkg:npm/shared@1.0.0"); got != 1 {
		t.Errorf("same-version: want exactly 1 shared@1.0.0 entry, got %d: %+v", got, sbom.Packages)
	}
	if !sbomHasRelationship(sbom, "pkg:npm/pkg-a@1.0.0", "pkg:npm/shared@1.0.0") {
		t.Errorf("same-version: missing edge pkg-a@1.0.0 -> shared@1.0.0; rels=%+v", sbom.Relationships)
	}
	if !sbomHasRelationship(sbom, "pkg:npm/pkg-b@1.0.0", "pkg:npm/shared@1.0.0") {
		t.Errorf("same-version: missing edge pkg-b@1.0.0 -> shared@1.0.0; rels=%+v", sbom.Relationships)
	}
	if got := countRelationshipsToChild(sbom, "pkg:npm/shared@1.0.0"); got != 2 {
		t.Errorf("same-version: want 2 distinct parent edges into shared@1.0.0, got %d: %+v", got, sbom.Relationships)
	}
}

// TestSBOM_JS_VulnerableTransitivePresent is C2's first leg: the advisory-named transitive dependency
// (tough-cookie@4.1.2, CVE-2023-26136), pulled in by jsdom@22.1.0, reaches the projected SBOM as a
// transitive package with its exact resolved PURL — the identity a CVE-watch query keys on.
func TestSBOM_JS_VulnerableTransitivePresent(t *testing.T) {
	sbom := resolveSBOMForDir(t, yarnJsdomDir)

	want := report.Package{
		Ecosystem: "npm",
		Name:      "tough-cookie",
		Version:   "4.1.2",
		PURL:      "pkg:npm/tough-cookie@4.1.2",
		Direct:    false,
	}
	if !sbomHasPackage(sbom, want) {
		t.Fatalf("C2: advisory-named transitive %+v absent from SBOM: %+v", want, sbom.Packages)
	}
}

// TestSBOM_JS_NoAdvisoryPackagePresent is C2's second leg and the inventory-keyed proof: a co-present
// transitive that NO advisory in these tests names (asynckit@0.4.0) is ALSO in the SBOM. On an
// advisory-keyed producer it could never appear; its presence proves the SBOM is keyed on the
// resolved inventory, not the advisory work set.
func TestSBOM_JS_NoAdvisoryPackagePresent(t *testing.T) {
	sbom := resolveSBOMForDir(t, yarnJsdomDir)

	want := report.Package{
		Ecosystem: "npm",
		Name:      "asynckit",
		Version:   "0.4.0",
		PURL:      "pkg:npm/asynckit@0.4.0",
		Direct:    false,
	}
	if !sbomHasPackage(sbom, want) {
		t.Fatalf("C2: no-advisory transitive %+v absent from SBOM (SBOM is advisory-keyed, not inventory-keyed): %+v", want, sbom.Packages)
	}
}
