package projection_test

import (
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
)

func TestReportSARIF_ResultPerFinding(t *testing.T) {
	log, err := projection.ProjectReportSARIF(fixtureReport())
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs: got %d, want 1", len(log.Runs))
	}
	if got := log.Runs[0].Tool.Driver.Name; got != brand.Name {
		t.Fatalf("driver name: got %q, want %q", got, brand.Name)
	}
	if got, want := len(log.Runs[0].Results), 3; got != want {
		t.Fatalf("results: got %d, want %d", got, want)
	}
	if log.Version != projection.SARIFVersion {
		t.Fatalf("sarif version: got %q, want %q", log.Version, projection.SARIFVersion)
	}
}

// TestReportSARIF_Inv5_NoErrorLevel asserts the OSS Report never emits SARIF
// level "error" (which implies a proven finding). A reachable_candidate is "warning".
func TestReportSARIF_Inv5_NoErrorLevel(t *testing.T) {
	log, err := projection.ProjectReportSARIF(fixtureReport())
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	for _, r := range log.Runs[0].Results {
		if r.Level == "error" {
			t.Fatalf("inv.5 VIOLATION: %q got level=error — OSS Report may never be error", r.RuleID)
		}
	}
}

func TestReportSARIF_LevelMapping(t *testing.T) {
	log, err := projection.ProjectReportSARIF(fixtureReport())
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	level := map[string]string{}
	for _, r := range log.Runs[0].Results {
		level[r.RuleID] = r.Level
	}
	cases := map[string]string{
		"GO-2021-0001":   "none",    // disqualified
		"GO-2022-0002":   "note",    // not_exploitable
		"CVE-2023-39325": "warning", // reachable_candidate
	}
	for id, want := range cases {
		if level[id] != want {
			t.Fatalf("%s level: got %q, want %q", id, level[id], want)
		}
	}
}

func TestReportSARIF_CandidateCarriesPathProperty(t *testing.T) {
	log, err := projection.ProjectReportSARIF(fixtureReport())
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	for _, r := range log.Runs[0].Results {
		if r.RuleID == "CVE-2023-39325" {
			if r.Properties == nil || r.Properties.Tegron["reachable_path"] == nil {
				t.Fatalf("candidate result missing reachable_path property")
			}
			return
		}
	}
	t.Fatal("CVE-2023-39325 result not found")
}

// TestReportSARIF_EveryResultHasLocation is the regression guard for the live
// code-scanning rejection (run 27705632815: "expected at least one location"). Every
// result MUST carry >=1 location with a non-empty physicalLocation URI.
func TestReportSARIF_EveryResultHasLocation(t *testing.T) {
	log, err := projection.ProjectReportSARIF(fixtureReport())
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	for _, r := range log.Runs[0].Results {
		if len(r.Locations) < 1 {
			t.Fatalf("%s: got %d locations, want >=1", r.RuleID, len(r.Locations))
		}
		loc := r.Locations[0]
		if loc.PhysicalLocation == nil {
			t.Fatalf("%s: location has no physicalLocation", r.RuleID)
		}
		if loc.PhysicalLocation.ArtifactLocation.URI == "" {
			t.Fatalf("%s: physicalLocation URI is empty", r.RuleID)
		}
		// All fixture findings are Go-ecosystem → go.mod.
		if got := loc.PhysicalLocation.ArtifactLocation.URI; got != "go.mod" {
			t.Fatalf("%s: URI got %q, want go.mod", r.RuleID, got)
		}
		if loc.PhysicalLocation.Region == nil || loc.PhysicalLocation.Region.StartLine != 1 {
			t.Fatalf("%s: want region startLine 1, got %+v", r.RuleID, loc.PhysicalLocation.Region)
		}
	}
}

// TestReportSARIF_UnknownEcosystemFallbackLocation asserts a finding whose package is
// nil (or whose ecosystem maps to no manifest) still gets a non-empty fallback URI, so
// code-scanning ingestion can never break on a missing location.
func TestReportSARIF_UnknownEcosystemFallbackLocation(t *testing.T) {
	r := report.NewBuilder(report.Subject{Repo: "example/repo"}).
		ReachableCandidate(
			report.Advisory{ID: "CVE-9999-0001", Source: "osv"},
			nil, // no package → ecosystem unknown → fallback URI
			"some/path",
			"a reachable candidate with no resolved package",
		).
		WithProvenance(report.Provenance{AnalyzerVersion: "test"}).
		Build()

	log, err := projection.ProjectReportSARIF(r)
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	if len(log.Runs[0].Results) != 1 {
		t.Fatalf("results: got %d, want 1", len(log.Runs[0].Results))
	}
	loc := log.Runs[0].Results[0].Locations
	if len(loc) < 1 || loc[0].PhysicalLocation == nil {
		t.Fatalf("nil-package finding got no location")
	}
	if got := loc[0].PhysicalLocation.ArtifactLocation.URI; got != "." {
		t.Fatalf("fallback URI: got %q, want %q", got, ".")
	}
}

func TestMarshalReportSARIF_RoundTrips(t *testing.T) {
	b, err := projection.MarshalReportSARIF(fixtureReport())
	if err != nil {
		t.Fatalf("MarshalReportSARIF: %v", err)
	}
	var log projection.SARIFLog
	if err := json.Unmarshal(b, &log); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(log.Runs[0].Results) != 3 {
		t.Fatalf("round-trip results: got %d, want 3", len(log.Runs[0].Results))
	}
}

// TestReportSARIF_Priority_SetsRankAndProperties asserts that a finding with a
// Priority populates the SARIF rank field and intel properties.
func TestReportSARIF_Priority_SetsRankAndProperties(t *testing.T) {
	log, err := projection.ProjectReportSARIF(fixtureReportWithPriority())
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}

	var priorityResult *projection.SARIFResult
	for i := range log.Runs[0].Results {
		if log.Runs[0].Results[i].RuleID == "CVE-2024-0001" {
			r := log.Runs[0].Results[i]
			priorityResult = &r
			break
		}
	}
	if priorityResult == nil {
		t.Fatal("CVE-2024-0001 result not found")
	}

	// rank = EPSSPercentile * 100 = 0.98 * 100 = 98.0
	if priorityResult.Rank == nil {
		t.Fatalf("rank is nil; want 98.0")
	}
	if got := *priorityResult.Rank; got != 98.0 {
		t.Errorf("rank: got %v, want 98.0", got)
	}

	if priorityResult.Properties == nil {
		t.Fatal("properties is nil")
	}
	props := priorityResult.Properties.Tegron

	if v, ok := props["epss_score"]; !ok || v != 0.940 {
		t.Errorf("epss_score: got %v (ok=%v), want 0.940", v, ok)
	}
	if v, ok := props["epss_percentile"]; !ok || v != 0.98 {
		t.Errorf("epss_percentile: got %v (ok=%v), want 0.98", v, ok)
	}
	if v, ok := props["kev_listed"]; !ok || v != true {
		t.Errorf("kev_listed: got %v (ok=%v), want true", v, ok)
	}
	if v, ok := props["kev_date_added"]; !ok || v != "2024-01-15" {
		t.Errorf("kev_date_added: got %v (ok=%v), want 2024-01-15", v, ok)
	}
	if v, ok := props["intel_snapshot"]; !ok || v != "2026-06-15" {
		t.Errorf("intel_snapshot: got %v (ok=%v), want 2026-06-15", v, ok)
	}
	if v, ok := props["reachability_grade"]; !ok || v != "attacker_tainted" {
		t.Errorf("reachability_grade: got %v (ok=%v), want attacker_tainted", v, ok)
	}
	if v, ok := props["entry_point"]; !ok || v != "net/http.HandlerFunc" {
		t.Errorf("entry_point: got %v (ok=%v), want net/http.HandlerFunc", v, ok)
	}
	if v, ok := props["attacker_controllable"]; !ok || v != true {
		t.Errorf("attacker_controllable: got %v (ok=%v), want true", v, ok)
	}
	// KEV finding should be tagged CISA-KEV.
	tags, _ := props["tags"].([]string)
	found := false
	for _, tag := range tags {
		if tag == "CISA-KEV" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("CISA-KEV tag not in properties.tags: %v", tags)
	}
}

// TestReportSARIF_NilPriority_NoRankNoIntelProps asserts that a finding with nil
// Priority has no rank and no EPSS/KEV properties — no panic.
func TestReportSARIF_NilPriority_NoRankNoIntelProps(t *testing.T) {
	log, err := projection.ProjectReportSARIF(fixtureReportWithPriority())
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}

	var noPriResult *projection.SARIFResult
	for i := range log.Runs[0].Results {
		if log.Runs[0].Results[i].RuleID == "GO-2021-NOPRI" {
			r := log.Runs[0].Results[i]
			noPriResult = &r
			break
		}
	}
	if noPriResult == nil {
		t.Fatal("GO-2021-NOPRI result not found")
	}
	if noPriResult.Rank != nil {
		t.Errorf("nil-Priority finding has rank set; want nil, got %v", *noPriResult.Rank)
	}
	if noPriResult.Properties != nil {
		props := noPriResult.Properties.Tegron
		if _, ok := props["epss_score"]; ok {
			t.Error("nil-Priority finding unexpectedly has epss_score property")
		}
		if _, ok := props["kev_listed"]; ok {
			t.Error("nil-Priority finding unexpectedly has kev_listed property")
		}
	}
}
