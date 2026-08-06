package pipeline

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/intel"
)

// KEV/EPSS are CVE-keyed feeds, and trigger's priorityFor joins them on an advisory's ID
// PLUS its Aliases (a GO-/GHSA-keyed advisory has to match through its CVE alias). That join
// is only sound if an advisory's alias set names the SAME vulnerability its id does.
//
// It did not. AdvisoryTable merged both CVEs of the gogs incomplete-fix chain under
// CVE-2024-55947, carrying the successor CVE-2025-8110 in the predecessor's Aliases. kev.json
// lists only CVE-2025-8110, so the join reported KEVListed against CVE-2024-55947 — a CVE CISA
// does not list. That is customer-visible: report.json's kev_listed, the SARIF properties
// block, report.html, the Tier-1 PR-comment KEV column, and finding ranking (findingRank sorts
// KEV-listed higher) all read it, and report.Priority documents the field as meaning CISA
// records active exploitation of THAT CVE.
//
// These two tests guard the fix and the class of defect behind it.

// TestKEVAttributionFollowsListedCVE pins the join to the CVE that is actually in the feed.
// An entry keyed by a CVE must never take a KEV hit that belongs to a different CVE.
func TestKEVAttributionFollowsListedCVE(t *testing.T) {
	for id, facts := range AdvisoryTable {
		if !strings.HasPrefix(id, "CVE-") {
			continue // GO-/GHSA-/house-keyed entries legitimately match through a CVE alias
		}
		ids := append([]string{id}, facts.Aliases...)
		e, ok := intel.KEV(ids...)
		if !ok {
			continue
		}
		if e.CVEID != id {
			t.Errorf("advisory %s takes its KEV listing from %s: the entry claims a CVE it is not, "+
				"so kev_listed/kev_date_added are attributed to the wrong vulnerability (aliases=%v)",
				id, e.CVEID, facts.Aliases)
		}
	}

	// The concrete case, stated directly so a regression names itself: only the successor is
	// on KEV, and the predecessor must not inherit it.
	pred := AdvisoryTable["CVE-2024-55947"]
	if _, ok := intel.KEV(append([]string{"CVE-2024-55947"}, pred.Aliases...)...); ok {
		t.Error("CVE-2024-55947 (gogs predecessor) resolves a KEV listing; CISA lists only its successor CVE-2025-8110")
	}
	succ, ok := AdvisoryTable["CVE-2025-8110"]
	if !ok {
		t.Fatal("CVE-2025-8110 (gogs successor) missing from AdvisoryTable")
	}
	e, ok := intel.KEV(append([]string{"CVE-2025-8110"}, succ.Aliases...)...)
	if !ok {
		t.Fatal("CVE-2025-8110 (gogs successor) resolves no KEV listing; it is in kev.json")
	}
	if e.CVEID != "CVE-2025-8110" {
		t.Errorf("gogs successor KEV listing attributed to %s, want CVE-2025-8110", e.CVEID)
	}
}

// TestNoEntryAliasesAnotherEntrysPrimaryID guards the structural cause rather than the symptom.
// Two advisories are two vulnerabilities; if one lists the other's primary id as an alias, then
// every CVE-keyed join downstream (KEV, EPSS, govulnMatchID's first GO- alias, aliasIndex work-set
// resolution) has one slot for two answers and must get at least one of them wrong.
func TestNoEntryAliasesAnotherEntrysPrimaryID(t *testing.T) {
	for id, facts := range AdvisoryTable {
		for _, a := range facts.Aliases {
			if a == id {
				continue
			}
			if _, isPrimary := AdvisoryTable[a]; isPrimary {
				t.Errorf("advisory %s lists %s in its Aliases, but %s is its own AdvisoryTable entry: "+
					"two vulnerabilities merged under one id — split them and join with Lineage",
					id, a, a)
			}
		}
	}
}
