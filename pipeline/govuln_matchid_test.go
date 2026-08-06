package pipeline

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

// TestGovulnMatchID_GONativePassesThrough is the no-regression case: an advisory whose
// PRIMARY id is already a GO-YYYY-NNNN id (the nucleon / x/text GO-2021-0113 shape that
// govulncheck emits verbatim) is returned unchanged, without ever consulting the store.
func TestGovulnMatchID_GONativePassesThrough(t *testing.T) {
	store := artifact.NewMemStore()
	// Deliberately no normalized-advisory artifact in the store: a GO- primary must resolve
	// without one (the fast path), proving it never depends on aliases.
	if got := govulnMatchID(store, "case-1", "GO-2021-0113"); got != "GO-2021-0113" {
		t.Errorf("GO-native primary: got %q, want %q", got, "GO-2021-0113")
	}
}

// TestGovulnMatchID_CVEResolvesToGOAlias is the regression proof: a CVE/GHSA-keyed advisory
// (CVE-2024-45337, the x/crypto demo hero) resolves to the first GO- entry in the
// normalized-advisory artifact's aliases (GO-2024-3321) — the id govulncheck actually keys
// its findings by. Before this resolver the call site passed the raw CVE id straight into
// parseFindings' `f.OSV == vulnID` filter, dropping every finding.
func TestGovulnMatchID_CVEResolvesToGOAlias(t *testing.T) {
	store := artifact.NewMemStore()
	putJSON(t, store, "case-2", artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id": "CVE-2024-45337",
		// aliases ordered GHSA-first, exactly as AdvisoryTable records CVE-2024-45337, to prove
		// the resolver skips the non-GO alias and picks the GO- one.
		"aliases": []string{"GHSA-v778-237x-gjrc", "GO-2024-3321"},
	})
	if got := govulnMatchID(store, "case-2", "CVE-2024-45337"); got != "GO-2024-3321" {
		t.Errorf("CVE primary with GO- alias: got %q, want %q", got, "GO-2024-3321")
	}
}

// TestGovulnMatchID_NoGOAliasFallsBackToPrimary is the fail-safe / corpus-gap path: a
// CVE-keyed advisory whose aliases carry NO GO- id falls back to the primary id. This is the
// path that keeps inv.5's fail-open honest — the resolver never fabricates a GO- id, so a
// govulncheck miss under the (unmatchable) primary id still yields the UNKNOWN/partial the
// advisory is owed rather than a false clean. It also marks a real corpus gap: an advisory with
// no GO- alias can never be matched against a govulncheck stream.
func TestGovulnMatchID_NoGOAliasFallsBackToPrimary(t *testing.T) {
	store := artifact.NewMemStore()
	putJSON(t, store, "case-3", artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id": "CVE-2099-0001",
		"aliases": []string{"GHSA-xxxx-yyyy-zzzz"}, // no GO- alias
	})
	if got := govulnMatchID(store, "case-3", "CVE-2099-0001"); got != "CVE-2099-0001" {
		t.Errorf("CVE primary without GO- alias: got %q, want %q", got, "CVE-2099-0001")
	}
}

// TestGovulnMatchID_NoAdvisoryArtifactFallsBackToPrimary proves the store-miss fail-safe:
// with no normalized-advisory artifact at all (a store error or an empty query), the primary
// id is returned rather than an error or an empty id.
func TestGovulnMatchID_NoAdvisoryArtifactFallsBackToPrimary(t *testing.T) {
	store := artifact.NewMemStore()
	if got := govulnMatchID(store, "case-4", "CVE-2099-0002"); got != "CVE-2099-0002" {
		t.Errorf("CVE primary with no advisory artifact: got %q, want %q", got, "CVE-2099-0002")
	}
}
