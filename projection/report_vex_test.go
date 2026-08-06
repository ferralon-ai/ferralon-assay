package projection_test

import (
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/projection"
)

func TestReportVEX_StatementPerFinding(t *testing.T) {
	doc, err := projection.ProjectReportVEX(fixtureReport())
	if err != nil {
		t.Fatalf("ProjectReportVEX: %v", err)
	}
	if got, want := len(doc.Statements), 3; got != want {
		t.Fatalf("statements: got %d, want %d", got, want)
	}
	if doc.Author != brand.Name {
		t.Fatalf("author: got %q, want %q", doc.Author, brand.Name)
	}
	if doc.Context != projection.OpenVEXSchemaVersion {
		t.Fatalf("context: got %q, want %q", doc.Context, projection.OpenVEXSchemaVersion)
	}
}

// TestReportVEX_Inv5_CandidateIsUnderInvestigation is the headline honesty guard:
// a reachable_candidate MUST map to under_investigation, NEVER affected.
func TestReportVEX_Inv5_CandidateIsUnderInvestigation(t *testing.T) {
	doc, err := projection.ProjectReportVEX(fixtureReport())
	if err != nil {
		t.Fatalf("ProjectReportVEX: %v", err)
	}
	for _, s := range doc.Statements {
		if s.Vulnerability.ID == "CVE-2023-39325" {
			if s.Status == projection.VEXStatusAffected {
				t.Fatalf("inv.5 VIOLATION: reachable_candidate projected as affected")
			}
			if s.Status != projection.VEXStatusUnderInvestigation {
				t.Fatalf("reachable_candidate: got status %q, want under_investigation", s.Status)
			}
			if s.ImpactStatement == "" {
				t.Fatalf("candidate should carry an impact statement")
			}
			return
		}
	}
	t.Fatal("candidate finding CVE-2023-39325 not found in VEX statements")
}

// TestReportVEX_NoAffectedEver asserts that across every deterministic verdict the
// OSS Report can carry, no statement is ever "affected" (the OSS tool cannot prove).
func TestReportVEX_NoAffectedEver(t *testing.T) {
	doc, err := projection.ProjectReportVEX(fixtureReport())
	if err != nil {
		t.Fatalf("ProjectReportVEX: %v", err)
	}
	for _, s := range doc.Statements {
		if s.Status == projection.VEXStatusAffected {
			t.Fatalf("inv.5 VIOLATION: %q projected as affected — OSS Report may never be affected", s.Vulnerability.ID)
		}
	}
}

func TestReportVEX_DisqualifiedAndNotExploitable_NotAffected(t *testing.T) {
	doc, err := projection.ProjectReportVEX(fixtureReport())
	if err != nil {
		t.Fatalf("ProjectReportVEX: %v", err)
	}
	byID := map[string]string{}
	for _, s := range doc.Statements {
		byID[s.Vulnerability.ID] = s.Status
	}
	if byID["GO-2021-0001"] != projection.VEXStatusNotAffected {
		t.Fatalf("disqualified: got %q, want not_affected", byID["GO-2021-0001"])
	}
	if byID["GO-2022-0002"] != projection.VEXStatusNotAffected {
		t.Fatalf("not_exploitable: got %q, want not_affected", byID["GO-2022-0002"])
	}
}

func TestReportVEX_ProductIDPrefersPURL(t *testing.T) {
	doc, err := projection.ProjectReportVEX(fixtureReport())
	if err != nil {
		t.Fatalf("ProjectReportVEX: %v", err)
	}
	for _, s := range doc.Statements {
		if s.Vulnerability.ID == "GO-2021-0001" {
			if got := s.Products[0].ID; got != "pkg:golang/golang.org/x/text@v0.3.7" {
				t.Fatalf("product id: got %q, want the package PURL", got)
			}
			return
		}
	}
	t.Fatal("GO-2021-0001 not found")
}

func TestReportVEX_DeterministicTimestamp(t *testing.T) {
	doc, err := projection.ProjectReportVEX(fixtureReport())
	if err != nil {
		t.Fatalf("ProjectReportVEX: %v", err)
	}
	if doc.Timestamp != "2026-06-15T12:30:00Z" {
		t.Fatalf("timestamp: got %q, want the report provenance timestamp (deterministic)", doc.Timestamp)
	}
}

func TestMarshalReportVEX_RoundTrips(t *testing.T) {
	b, err := projection.MarshalReportVEX(fixtureReport())
	if err != nil {
		t.Fatalf("MarshalReportVEX: %v", err)
	}
	var doc projection.VEXDocument
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Statements) != 3 {
		t.Fatalf("round-trip statements: got %d, want 3", len(doc.Statements))
	}
}
