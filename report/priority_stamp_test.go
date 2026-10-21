package report

import (
	"encoding/json"
	"strings"
	"testing"
)

// epssPriority is a stamped EPSS-only Priority.
func epssPriority(score float64) *Priority {
	return &Priority{EPSSScore: score, EPSSAsOf: "2026-10-19"}
}

// TestPriorityWireCarriesEachValuesStamp: on the wire every value sits beside its own stamp, the
// report names the signals file once, and the old report-wide snapshot field is gone.
func TestPriorityWireCarriesEachValuesStamp(t *testing.T) {
	r := NewBuilder(Subject{Repo: "r", ResolvedCommit: "c"}).
		AddFinding(gradedCandidate("CVE-2025-8110", GradeControlFlowOnly, &Priority{
			EPSSScore: 0.91, EPSSPercentile: 0.99, EPSSAsOf: "2026-10-18",
			KEVListed: true, KEVDateAdded: "2025-07-28", KEVCatalogVersion: "2026.10.19", KEVDateReleased: "2026-10-19T18:00:00Z",
		})).
		AddFinding(gradedCandidate("CVE-2024-55947", GradeControlFlowOnly, &Priority{
			KEVCatalogVersion: "2026.10.19", KEVDateReleased: "2026-10-19T18:00:00Z",
		})).
		WithProvenance(Provenance{Intel: &IntelProvenance{SignalsDigest: "sha256:abc"}}).
		Build()
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Advisories []struct {
			Advisory struct{ ID string } `json:"advisory"`
			Priority map[string]any      `json:"priority"`
		} `json:"advisories"`
		Provenance struct {
			Intel map[string]any `json:"intel"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if got := doc.Provenance.Intel["signals_digest"]; got != "sha256:abc" {
		t.Errorf("provenance.intel.signals_digest = %v, want sha256:abc", got)
	}
	if strings.Contains(string(b), `"snapshot"`) {
		t.Errorf("the report-wide snapshot field must be gone:\n%s", b)
	}
	byID := map[string]map[string]any{}
	for _, a := range doc.Advisories {
		byID[a.Advisory.ID] = a.Priority
	}
	listed := byID["CVE-2025-8110"]
	for k, want := range map[string]any{
		"epss_score": 0.91, "epss_percentile": 0.99, "epss_as_of": "2026-10-18",
		"kev_listed": true, "kev_date_added": "2025-07-28",
		"kev_catalog_version": "2026.10.19", "kev_date_released": "2026-10-19T18:00:00Z",
	} {
		if listed[k] != want {
			t.Errorf("CVE-2025-8110 priority[%s] = %v, want %v", k, listed[k], want)
		}
	}
	// A stamped "not listed" carries its catalog stamp and no EPSS fields at all — an absent value
	// is absent, never a zero.
	notListed := byID["CVE-2024-55947"]
	if len(notListed) != 2 || notListed["kev_catalog_version"] != "2026.10.19" || notListed["kev_date_released"] == nil {
		t.Errorf("CVE-2024-55947 priority = %v, want only the KEV catalog stamp", notListed)
	}
}

// TestValidateRejectsUnstampedPriority: no priority value is ever set without its stamp.
func TestValidateRejectsUnstampedPriority(t *testing.T) {
	const cat, rel = "2026.10.19", "2026-10-19T18:00:00Z"
	for name, p := range map[string]*Priority{
		"epss score, no as_of":        {EPSSScore: 0.5},
		"epss percentile, no as_of":   {EPSSPercentile: 0.5, KEVCatalogVersion: cat, KEVDateReleased: rel},
		"kev listed, no stamp":        {KEVListed: true, EPSSAsOf: "2026-10-19", EPSSScore: 0.1},
		"kev date_added, no stamp":    {KEVDateAdded: "2025-01-01", EPSSAsOf: "2026-10-19", EPSSScore: 0.1},
		"half a catalog stamp":        {KEVListed: true, KEVCatalogVersion: cat},
		"other half":                  {KEVDateReleased: rel},
		"date_added while not listed": {KEVDateAdded: "2025-01-01", KEVCatalogVersion: cat, KEVDateReleased: rel},
		"empty block":                 {},
	} {
		r := NewBuilder(Subject{ResolvedCommit: "c"}).AddFinding(gradedCandidate("CVE-1", GradeControlFlowOnly, p)).Build()
		if err := r.Validate(); err == nil {
			t.Errorf("%s: Validate accepted %+v", name, *p)
		}
	}
}

// TestWithPriorityReplacesEveryRow: a run ranks every row by its own signals. A row added with a
// Priority from elsewhere (an inherited baseline row) is re-derived, and with no signals every row
// ends with none.
func TestWithPriorityReplacesEveryRow(t *testing.T) {
	stale := &Priority{EPSSScore: 0.99, EPSSAsOf: "2026-07-29"}
	build := func(fn func(Advisory) *Priority) []AdvisoryFinding {
		return NewBuilder(Subject{ResolvedCommit: "c"}).
			AddFinding(gradedCandidate("CVE-A", GradeControlFlowOnly, stale)).
			AddFinding(gradedCandidate("CVE-B", GradeControlFlowOnly, nil)).
			WithPriority(fn).
			Build().Advisories
	}
	for _, f := range build(func(Advisory) *Priority { return nil }) {
		if f.Priority != nil {
			t.Errorf("no signals: %s kept Priority %+v", f.Advisory.ID, *f.Priority)
		}
	}
	// CVE-B now outranks CVE-A: the order follows the re-derived values, not the added ones.
	got := build(func(a Advisory) *Priority {
		if a.ID == "CVE-B" {
			return epssPriority(0.5)
		}
		return epssPriority(0.1)
	})
	if got[0].Advisory.ID != "CVE-B" || got[0].Priority.EPSSScore != 0.5 || got[1].Priority.EPSSScore != 0.1 {
		t.Errorf("re-derived order/values = %s %+v, %s %+v", got[0].Advisory.ID, got[0].Priority, got[1].Advisory.ID, got[1].Priority)
	}
}

// TestUpgradeDropsUnstampedPriority: a stored v2 Report written before per-value stamps carries
// priority values dated only by the removed report-wide snapshot. Reading it drops those (so the
// stored state still validates) and keeps a stamped one.
func TestUpgradeDropsUnstampedPriority(t *testing.T) {
	stored := `{"schema_version": "` + SchemaVersion + `", "subject": {"repo": "r", "resolved_commit": "c"},
	  "sbom": {"packages": []},
	  "advisories": [
	    {"advisory": {"id": "CVE-OLD", "source": "osv"}, "verdict": "not_exploitable",
	     "priority": {"epss_score": 0.5, "epss_percentile": 0.9, "kev_listed": true, "snapshot": "2026-07-29"}},
	    {"advisory": {"id": "CVE-NEW", "source": "osv"}, "verdict": "not_exploitable",
	     "priority": {"epss_score": 0.2, "epss_as_of": "2026-10-19"}}],
	  "provenance": {"commit_sha": "c", "analyzer_version": "v", "advisory_cursor": "", "timestamp": "2026-10-20T00:00:00Z"}}`
	var r Report
	if err := json.Unmarshal([]byte(stored), &r); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err == nil {
		t.Fatal("the stored snapshot-era priority should not validate as-is")
	}
	up, err := Upgrade(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Validate(); err != nil {
		t.Fatalf("upgraded report does not validate: %v", err)
	}
	for _, f := range up.Advisories {
		switch f.Advisory.ID {
		case "CVE-OLD":
			if f.Priority != nil {
				t.Errorf("CVE-OLD kept its unstamped priority %+v", *f.Priority)
			}
		case "CVE-NEW":
			if f.Priority == nil || f.Priority.EPSSAsOf != "2026-10-19" {
				t.Errorf("CVE-NEW lost its stamped priority: %+v", f.Priority)
			}
		}
	}
	if r.Advisories[0].Priority == nil {
		t.Error("Upgrade mutated its input's findings")
	}
}
