package report

import (
	"encoding/json"
	"reflect"
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
		"zero percentile, no as_of":   {HasPercentile: true, KEVCatalogVersion: cat, KEVDateReleased: rel},
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

// storedPriorityReport is a stored Report at the given schema version whose two findings carry the
// given priority blocks (raw JSON), in the shape the producer of that version wrote.
func storedPriorityReport(t *testing.T, version, oldPriority, newPriority string) Report {
	t.Helper()
	stored := `{"schema_version": "` + version + `", "subject": {"repo": "r", "resolved_commit": "c"},
	  "sbom": {"packages": []},
	  "advisories": [
	    {"advisory": {"id": "CVE-OLD", "source": "osv"}, "verdict": "not_exploitable", "priority": ` + oldPriority + `},
	    {"advisory": {"id": "CVE-NEW", "source": "osv"}, "verdict": "not_exploitable", "priority": ` + newPriority + `}],
	  "provenance": {"commit_sha": "c", "analyzer_version": "v", "advisory_cursor": "", "timestamp": "2026-10-20T00:00:00Z"}}`
	var r Report
	if err := json.Unmarshal([]byte(stored), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

const (
	// snapshotEraPriority is a v2 priority block written before per-value stamps: dated only by the
	// report-wide snapshot field v3 removed.
	snapshotEraPriority = `{"epss_score": 0.5, "epss_percentile": 0.9, "kev_listed": true, "snapshot": "2026-07-29"}`
	// stampedPriority carries both its EPSS and its KEV stamps.
	stampedPriority = `{"epss_score": 0.2, "epss_as_of": "2026-10-19", "kev_catalog_version": "2026.10.19", "kev_date_released": "2026-10-19T18:00:00Z"}`
	// stampedNotListed is a stamped KEV "not listed" observation with no EPSS value.
	stampedNotListed = `{"kev_catalog_version": "2026.10.19", "kev_date_released": "2026-10-19T18:00:00Z"}`
)

// TestUpgradeV2DropsUnstampedPriority: a stored v2 Report written before per-value stamps carries
// priority values dated only by the removed report-wide snapshot. The v2 → v3 step drops those (so
// the stored state still validates) and keeps a stamped one.
func TestUpgradeV2DropsUnstampedPriority(t *testing.T) {
	r := storedPriorityReport(t, SchemaVersionV2, snapshotEraPriority, stampedPriority)
	if err := r.Validate(); err == nil {
		t.Fatal("the stored snapshot-era priority should not validate as-is")
	}
	up, err := Upgrade(r)
	if err != nil {
		t.Fatal(err)
	}
	if up.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %q, want %q", up.SchemaVersion, SchemaVersion)
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

// TestUpgradeV2KeepsStampedPriority: a v2 Report whose priority blocks already carry their stamps
// (written between #167 and the v3 bump) upgrades to v3 changed in nothing but its version.
func TestUpgradeV2KeepsStampedPriority(t *testing.T) {
	r := storedPriorityReport(t, SchemaVersionV2, stampedNotListed, stampedPriority)
	up, err := Upgrade(r)
	if err != nil {
		t.Fatal(err)
	}
	want := r
	want.SchemaVersion = SchemaVersion
	if !reflect.DeepEqual(up, want) {
		t.Errorf("Upgrade changed more than the version:\n got %+v\nwant %+v", up, want)
	}
	if err := up.Validate(); err != nil {
		t.Errorf("upgraded report does not validate: %v", err)
	}
}

// TestUpgradeV1ReachesV3: a v1 document runs every step — its withheld ids become rows (v1 → v2)
// and its snapshot-era priority is dropped (v2 → v3) — and lands on the current schema.
func TestUpgradeV1ReachesV3(t *testing.T) {
	r := storedPriorityReport(t, SchemaVersionV1, snapshotEraPriority, stampedPriority)
	r.Partiality = []PartialityNote{{Reason: ReasonGoToolchainNotScanned, Ecosystem: "Go", Advisories: []string{"GO-2021-0264"}}}
	up, err := Upgrade(r)
	if err != nil {
		t.Fatal(err)
	}
	if up.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %q, want %q", up.SchemaVersion, SchemaVersion)
	}
	if err := up.Validate(); err != nil {
		t.Fatalf("upgraded report does not validate: %v", err)
	}
	byID := map[string]AdvisoryFinding{}
	for _, f := range up.Advisories {
		byID[f.Advisory.ID] = f
	}
	if f, ok := byID["GO-2021-0264"]; !ok || f.Verdict != VerdictUndetermined {
		t.Errorf("the v1 withheld id did not become an undetermined row: %+v", up.Advisories)
	}
	if p := byID["CVE-OLD"].Priority; p != nil {
		t.Errorf("CVE-OLD kept its unstamped priority %+v", *p)
	}
	if p := byID["CVE-NEW"].Priority; p == nil || p.EPSSAsOf != "2026-10-19" {
		t.Errorf("CVE-NEW lost its stamped priority: %+v", p)
	}
}

// TestUpgradeV3IsANoOp: the unstamped-priority drop belongs to the v2 → v3 step alone. A v3 document
// passes through Upgrade untouched — even one carrying an unstamped priority, which no v3 producer
// writes and which Validate (not Upgrade) refuses.
func TestUpgradeV3IsANoOp(t *testing.T) {
	r := storedPriorityReport(t, SchemaVersion, snapshotEraPriority, stampedPriority)
	up, err := Upgrade(r)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(up, r) {
		t.Errorf("Upgrade changed a v3 document:\n got %+v\nwant %+v", up, r)
	}
	if err := up.Validate(); err == nil {
		t.Error("an unstamped priority in a v3 document validated")
	}
}

// TestV3ReportRoundTrips: a freshly built v3 Report survives encode → decode → Upgrade → encode
// byte-identically, so a stored v3 baseline re-reads as exactly what was written.
func TestV3ReportRoundTrips(t *testing.T) {
	r := NewBuilder(Subject{Repo: "r", ResolvedCommit: "c"}).
		AddFinding(gradedCandidate("CVE-ZERO", GradeControlFlowOnly, &Priority{EPSSAsOf: "2026-10-18"})).
		AddFinding(gradedCandidate("CVE-KEV", GradeControlFlowOnly, &Priority{
			EPSSScore: 0.91, EPSSPercentile: 0.99, EPSSAsOf: "2026-10-18",
			KEVListed: true, KEVDateAdded: "2025-07-28", KEVCatalogVersion: "2026.10.19", KEVDateReleased: "2026-10-19T18:00:00Z",
		})).
		AddFinding(gradedCandidate("CVE-NOTLISTED", GradeControlFlowOnly, &Priority{
			KEVCatalogVersion: "2026.10.19", KEVDateReleased: "2026-10-19T18:00:00Z",
		})).
		WithProvenance(Provenance{Intel: &IntelProvenance{SignalsDigest: "sha256:abc"}}).
		Build()
	if r.SchemaVersion != SchemaVersion || SchemaVersion != "tegron.report.v3" {
		t.Fatalf("Build stamped %q (SchemaVersion = %q), want tegron.report.v3", r.SchemaVersion, SchemaVersion)
	}
	first, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	up, err := Upgrade(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Validate(); err != nil {
		t.Fatalf("round-tripped report does not validate: %v", err)
	}
	second, err := json.Marshal(up)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Errorf("v3 round trip changed the document:\nfirst  %s\nsecond %s", first, second)
	}
}

// TestEPSSScoreZeroSerializes: a genuine EPSS score of 0 sits beside its epss_as_of on the wire (an
// as-of with no score would read as a missing value), while a priority block with no EPSS value — a
// KEV-only observation — carries no epss_score at all. A score with no stamp is written too, never
// hidden, and the decoded document fails Validate for it.
func TestEPSSScoreZeroSerializes(t *testing.T) {
	for name, tc := range map[string]struct {
		p                    Priority
		wantScore, unstamped bool
	}{
		"zero score with its as_of": {Priority{EPSSAsOf: "2026-10-18"}, true, false},
		"nonzero score":             {Priority{EPSSScore: 0.3, EPSSAsOf: "2026-10-18"}, true, false},
		"unstamped score":           {Priority{EPSSScore: 0.3}, true, true},
		"kev only, listed":          {Priority{KEVListed: true, KEVCatalogVersion: "2026.10.19", KEVDateReleased: "2026-10-19T18:00:00Z"}, false, false},
		"kev only, not listed":      {Priority{KEVCatalogVersion: "2026.10.19", KEVDateReleased: "2026-10-19T18:00:00Z"}, false, false},
	} {
		b, back := priorityRoundTrip(t, name, tc.p)
		score, ok := b["epss_score"]
		if ok != tc.wantScore {
			t.Errorf("%s: epss_score present = %v, want %v: %v", name, ok, tc.wantScore, b)
			continue
		}
		if ok && score != tc.p.EPSSScore {
			t.Errorf("%s: epss_score = %v, want %v", name, score, tc.p.EPSSScore)
		}
		if p := back.Advisories[0].Priority; p == nil || *p != tc.p {
			t.Errorf("%s: decoded %+v, want %+v", name, p, tc.p)
		}
		if err := back.Validate(); (err != nil) != tc.unstamped {
			t.Errorf("%s: Validate of the decoded document = %v, want an error %v", name, err, tc.unstamped)
		}
	}
}

// TestEPSSPercentileZeroSerializes: epss_percentile is on the wire whenever the signals file sourced
// one, zero included, and reads back as sourced; an unsourced percentile is omitted and reads back
// as unsourced. A nonzero percentile is never hidden, flagged or not.
func TestEPSSPercentileZeroSerializes(t *testing.T) {
	const asOf = "2026-08-02"
	for name, tc := range map[string]struct {
		p, back Priority
		wantPct bool
	}{
		// CVE-2026-50268's real signals record: {"score": 0.00047, "percentile": 0, "as_of": "2026-08-02"}.
		"sourced zero percentile": {
			p:       Priority{EPSSScore: 0.00047, HasPercentile: true, EPSSAsOf: asOf},
			back:    Priority{EPSSScore: 0.00047, HasPercentile: true, EPSSAsOf: asOf},
			wantPct: true,
		},
		"sourced nonzero percentile": {
			p:       Priority{EPSSScore: 0.2, EPSSPercentile: 0.5, HasPercentile: true, EPSSAsOf: asOf},
			back:    Priority{EPSSScore: 0.2, EPSSPercentile: 0.5, HasPercentile: true, EPSSAsOf: asOf},
			wantPct: true,
		},
		"nonzero percentile, flag unset": {
			p:       Priority{EPSSScore: 0.2, EPSSPercentile: 0.5, EPSSAsOf: asOf},
			back:    Priority{EPSSScore: 0.2, EPSSPercentile: 0.5, HasPercentile: true, EPSSAsOf: asOf},
			wantPct: true,
		},
		"unsourced percentile": {
			p:    Priority{EPSSScore: 0.2, EPSSAsOf: asOf},
			back: Priority{EPSSScore: 0.2, EPSSAsOf: asOf},
		},
		"kev only": {
			p:    Priority{KEVCatalogVersion: "2026.10.19", KEVDateReleased: "2026-10-19T18:00:00Z"},
			back: Priority{KEVCatalogVersion: "2026.10.19", KEVDateReleased: "2026-10-19T18:00:00Z"},
		},
	} {
		b, back := priorityRoundTrip(t, name, tc.p)
		pct, ok := b["epss_percentile"]
		if ok != tc.wantPct {
			t.Errorf("%s: epss_percentile present = %v, want %v: %v", name, ok, tc.wantPct, b)
			continue
		}
		if ok && pct != tc.p.EPSSPercentile {
			t.Errorf("%s: epss_percentile = %v, want %v", name, pct, tc.p.EPSSPercentile)
		}
		p := back.Advisories[0].Priority
		if p == nil || *p != tc.back {
			t.Errorf("%s: decoded %+v, want %+v", name, p, tc.back)
		}
		if p.HasEPSSPercentile() != tc.wantPct {
			t.Errorf("%s: decoded HasEPSSPercentile = %v, want %v", name, p.HasEPSSPercentile(), tc.wantPct)
		}
		if err := back.Validate(); err != nil {
			t.Errorf("%s: decoded document does not validate: %v", name, err)
		}
	}
}

// TestV3DecodesSourcedZeroPercentile: a stored v3 document whose priority carries
// "epss_percentile": 0 reads back, through Upgrade, as a sourced percentile of 0.
func TestV3DecodesSourcedZeroPercentile(t *testing.T) {
	r := storedPriorityReport(t, SchemaVersion,
		`{"epss_score": 0.00047, "epss_percentile": 0, "epss_as_of": "2026-08-02"}`,
		`{"epss_score": 0.2, "epss_as_of": "2026-10-19"}`)
	up, err := Upgrade(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, f := range up.Advisories {
		if want := f.Advisory.ID == "CVE-OLD"; f.Priority.HasPercentile != want || f.Priority.HasEPSSPercentile() != want {
			t.Errorf("%s: HasPercentile = %v, HasEPSSPercentile = %v, want %v", f.Advisory.ID, f.Priority.HasPercentile, f.Priority.HasEPSSPercentile(), want)
		}
	}
}

// priorityRoundTrip encodes a one-finding Report carrying p, and returns the encoded priority block
// and the document decoded back.
func priorityRoundTrip(t *testing.T, name string, p Priority) (map[string]any, Report) {
	t.Helper()
	b, err := json.Marshal(NewBuilder(Subject{ResolvedCommit: "c"}).AddFinding(gradedCandidate("CVE-1", GradeControlFlowOnly, &p)).Build())
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var doc struct {
		Advisories []struct {
			Priority map[string]any `json:"priority"`
		} `json:"advisories"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var back Report
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return doc.Advisories[0].Priority, back
}
