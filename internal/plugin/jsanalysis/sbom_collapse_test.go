package jsanalysis

// sbom_collapse_test.go — q16 CHARACTERIZATION (PLAN-165, L0 RULED). The peer/Berry collapse of
// two same-name@version package instances into ONE report.Package is BY DESIGN, not a defect: the
// report.SBOM is coordinate-presence (package-granular), while the per-resolution-scope instance
// closure lives in the instance-granular plugin.DependencyInventory (the substrate Phase-2/3
// reachability keys on). This test documents that layering; it is NOT a gap report.
//
// Capture note (verified this cycle): the existing peer/Berry captures
// (testdata/inventory/capture/pnpm-peer and .../yarn-berry-virtual) each resolve to a SINGLE
// peer-scoped instance of react-dom@18.2.0 — countByPURL == 1 — so neither actually contains the
// same-name@version PAIR this characterization needs. Rather than fabricate a pair in a capture that
// has none, the pair is realized honestly in the pnpm-peer-collapse fixture: one shared@1.0.0 that
// pnpm v9 peer-resolves TWO ways (pkg-a supplies peer@1.0.0, pkg-b supplies peer@2.0.0), yielding two
// `snapshots:` instances with identical bare PURL and distinct ?resolution_scope= IDs.

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestSBOM_JS_PeerInstancesCollapseToOnePackage is the q16 characterization. It observes, over ONE
// fixture, both granularities at once:
//
//   - INVENTORY (instance-granular): two distinct DependencyNode instances of shared@1.0.0, with the
//     SAME bare PURL and IDs that differ ONLY in the ?resolution_scope= suffix.
//   - report.SBOM (package-granular): those two instances collapse to EXACTLY ONE report.Package
//     (one shared@1.0.0 coordinate), AND the two distinct parent edges (pkg-a→shared, pkg-b→shared)
//     BOTH survive onto the collapsed key.
//
// Non-vacuity: a producer that keyed the SBOM on the inventory node ID (not Package.Key()) would
// emit TWO shared@1.0.0 packages and fail the count-1 assertion; a producer that collapsed instances
// but did NOT re-express edges over the collapsed keys (dropping or merging a parent) would fail the
// two-surviving-parent-edges assertion.
func TestSBOM_JS_PeerInstancesCollapseToOnePackage(t *testing.T) {
	dir := filepath.Join(sbomFixtureDir, "pnpm-peer-collapse")

	// --- instance-granular precondition: two shared@1.0.0 instances, scope-distinguished only ---
	inv := resolveDir(t, dir)
	const sharedPURL = "pkg:npm/shared@1.0.0"
	if got := countByPURL(inv, sharedPURL); got != 2 {
		t.Fatalf("precondition: expected exactly 2 peer-scoped shared@1.0.0 instances in the inventory, got %d; ids=%v", got, nodeIDs(inv))
	}
	var scopedIDs []string
	for _, n := range inv.Nodes {
		if n.PURL == sharedPURL {
			scopedIDs = append(scopedIDs, n.ID)
			// The instance's bare PURL is identical; the ONLY discriminator is the resolution scope.
			if !strings.HasPrefix(n.ID, sharedPURL+"?resolution_scope=") {
				t.Errorf("shared instance ID %q is not a %s scope-suffixed id", n.ID, sharedPURL)
			}
		}
	}
	if len(scopedIDs) == 2 && scopedIDs[0] == scopedIDs[1] {
		t.Fatalf("the two shared instances must have DISTINCT scope ids, both were %q", scopedIDs[0])
	}

	// --- package-granular projection: the two instances collapse to exactly one package ---
	sbom := resolveSBOMForDir(t, dir)
	if got := countPackagesByPURL(sbom, sharedPURL); got != 1 {
		t.Fatalf("collapse: SBOM must carry EXACTLY ONE %s package (package-granular), got %d: %+v", sharedPURL, got, sbom.Packages)
	}
	if got := countPackagesByName(sbom, "shared"); got != 1 {
		t.Fatalf("collapse: SBOM must carry exactly one `shared` package, got %d: %+v", got, sbom.Packages)
	}

	// --- both distinct parent edges survive onto the collapsed key ---
	// Relationship endpoints are Package.Key() (== PURL here), not the per-instance node IDs.
	if !sbomHasRelationship(sbom, "pkg:npm/pkg-a@1.0.0", sharedPURL) {
		t.Errorf("collapse: parent edge pkg-a@1.0.0 -> %s did not survive the collapse; rels=%+v", sharedPURL, sbom.Relationships)
	}
	if !sbomHasRelationship(sbom, "pkg:npm/pkg-b@1.0.0", sharedPURL) {
		t.Errorf("collapse: parent edge pkg-b@1.0.0 -> %s did not survive the collapse; rels=%+v", sharedPURL, sbom.Relationships)
	}
	if got := countRelationshipsToChild(sbom, sharedPURL); got != 2 {
		t.Errorf("collapse: want 2 distinct parent edges into the collapsed %s, got %d: %+v", sharedPURL, got, sbom.Relationships)
	}
}
