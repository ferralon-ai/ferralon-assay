package report

import (
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/verdict"
)

func TestBuilderProducesValidDeterministicReport(t *testing.T) {
	pkgGo := Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7"}
	pkgMaven := Package{Ecosystem: "Maven", Name: "com.example:widget", Version: "1.2.3"}

	r, err := NewBuilder(Subject{Repo: "r", Revision: "main", ResolvedCommit: "abc"}).
		AddPackages(pkgMaven, pkgGo).
		Disqualified(Advisory{ID: "GO-2021-0001", Source: "osv"}, &pkgGo, verdict.BasisVersionNotAffected, "below first affected").
		NotExploitable(Advisory{ID: "GHSA-x", Source: "ghsa"}, &pkgMaven, verdict.BasisSymbolAbsent, "symbol absent").
		ReachableCandidate(Advisory{ID: "CVE-2024-1", Source: "nvd"}, nil, "h -> f", "").
		WithProvenance(Provenance{AnalyzerVersion: "v0.2.0", AdvisoryCursor: "osv@x"}).
		BuildValidated()
	if err != nil {
		t.Fatalf("BuildValidated: %v", err)
	}

	if r.SchemaVersion != SchemaVersion {
		t.Errorf("schema version: got %q want %q", r.SchemaVersion, SchemaVersion)
	}
	if r.Provenance.CommitSHA != "abc" {
		t.Errorf("CommitSHA should default from subject: got %q", r.Provenance.CommitSHA)
	}
	if r.Provenance.Timestamp.IsZero() {
		t.Error("Build should default Timestamp")
	}

	// SBOM sorted: Go before Maven.
	if len(r.SBOM.Packages) != 2 || r.SBOM.Packages[0].Ecosystem != "Go" {
		t.Errorf("SBOM not stably sorted: %+v", r.SBOM.Packages)
	}
	// Findings sorted by advisory ID: CVE- < GHSA- < GO-.
	wantIDs := []string{"CVE-2024-1", "GHSA-x", "GO-2021-0001"}
	for i, want := range wantIDs {
		if r.Advisories[i].Advisory.ID != want {
			t.Errorf("findings[%d]: got %q want %q", i, r.Advisories[i].Advisory.ID, want)
		}
	}
}

func TestBuilderTimestampPreserved(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := NewBuilder(Subject{ResolvedCommit: "c"}).
		WithProvenance(Provenance{Timestamp: ts}).
		Build()
	if !r.Provenance.Timestamp.Equal(ts) {
		t.Errorf("explicit timestamp overwritten: got %v want %v", r.Provenance.Timestamp, ts)
	}
}

func TestBuildValidatedRejectsBadFinding(t *testing.T) {
	_, err := NewBuilder(Subject{ResolvedCommit: "c"}).
		AddFinding(AdvisoryFinding{Advisory: Advisory{ID: "x"}, Verdict: Verdict("exploitable")}).
		BuildValidated()
	if err == nil {
		t.Fatal("expected BuildValidated to reject a non-deterministic verdict")
	}
}
