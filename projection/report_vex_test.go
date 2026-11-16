package projection_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
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

func TestReportVEX_ProductIDOmitsUnresolvedPin(t *testing.T) {
	for _, tc := range []struct {
		name string
		pkg  report.Package
		want string
	}{
		{"resolved", report.Package{Ecosystem: "Go", Name: "gopkg.in/yaml.v2", Version: "v2.4.0"}, "gopkg.in/yaml.v2@v2.4.0"},
		{"observed, not resolved", report.Package{Ecosystem: "cfamily", Name: "zlib", Version: "1.2.11", PartialReason: plugin.PartialReasonSourceUnpinned + ":sole_source_unproven"}, "zlib"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkg := tc.pkg
			r := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "deadbeef"}).
				AddPackage(pkg).
				AddFinding(report.AdvisoryFinding{
					Advisory:           report.Advisory{ID: "CVE-2018-25032", Source: "corpus"},
					Package:            &pkg,
					Verdict:            report.VerdictUndetermined,
					UndeterminedReason: report.ReasonAnalysisDidNotRun,
				}).
				WithProvenance(report.Provenance{AnalyzerVersion: "ferralon-assay v0.2.0", Timestamp: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)}).
				Build()
			doc, err := projection.ProjectReportVEX(r)
			if err != nil {
				t.Fatalf("ProjectReportVEX: %v", err)
			}
			if got := doc.Statements[0].Products[0].ID; got != tc.want {
				t.Errorf("product id = %q, want %q", got, tc.want)
			}
		})
	}
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

// TestReportVEX_ScopedVerdictProducts: a scoped verdict's statement names one product per binary, the
// module's purl at the scanned commit with the binary's directory as a percent-encoded `binary`
// qualifier, a main at the module root included, and says "binaries" for more than one. A scope with
// no module has no product to name and is refused.
func TestReportVEX_ScopedVerdictProducts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		module  string
		commit  string
		targets []string
		want    []string // product ids; nil = refused
		impact  string
	}{
		{"one binary under cmd", "example.com/m", "abc123", []string{"cmd/tool"},
			[]string{"pkg:golang/example.com/m@abc123?binary=cmd%2Ftool"}, "the shipped binary `cmd/tool`;"},
		{"a main at the module root", "example.com/m", "abc123", []string{"."},
			[]string{"pkg:golang/example.com/m@abc123?binary=."}, "the shipped binary `.`;"},
		{"several binaries", "example.com/m", "abc123", []string{"cmd/a", "cmd/b"},
			[]string{"pkg:golang/example.com/m@abc123?binary=cmd%2Fa", "pkg:golang/example.com/m@abc123?binary=cmd%2Fb"}, "the shipped binaries `cmd/a`, `cmd/b`;"},
		{"no scanned commit", "example.com/m", "", []string{"cmd/tool"},
			[]string{"pkg:golang/example.com/m?binary=cmd%2Ftool"}, "`cmd/tool`"},
		{"a directory a qualifier may not hold bare", "example.com/m", "abc123", []string{"cmd/a&b c=d+e"},
			[]string{"pkg:golang/example.com/m@abc123?binary=cmd%2Fa%26b%20c%3Dd%2Be"}, "`cmd/a&b c=d+e`"},
		{"no module", "", "abc123", []string{"cmd/tool"}, nil, ""},
	} {
		r := report.Report{
			SchemaVersion: report.SchemaVersion,
			Subject:       report.Subject{Repo: "example.com/m", ResolvedCommit: tc.commit},
			Advisories: []report.AdvisoryFinding{{
				Advisory: report.Advisory{ID: "GO-1"},
				Package:  &report.Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.1.0", PURL: "pkg:golang/golang.org/x/net@v0.1.0"},
				Verdict:  report.VerdictUndetermined,
				ScopedVerdicts: []report.ScopedVerdict{{
					Verdict:  report.VerdictNotExploitable,
					Scope:    report.Scope{Kind: report.ScopeBinaries, Targets: tc.targets, Module: tc.module},
					Evidence: report.EvidenceSummary{Basis: verdict.BasisSymbolUnreachable, Detail: "started from the mains only"},
				}},
			}},
		}
		doc, err := projection.ProjectReportVEX(r)
		if tc.want == nil {
			if err == nil {
				t.Errorf("%s: projected %+v, want refused", tc.name, doc)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: ProjectReportVEX: %v", tc.name, err)
		}
		if len(doc.Statements) != 2 {
			t.Fatalf("%s: %d statements, want the finding's and the scoped one", tc.name, len(doc.Statements))
		}
		bin := doc.Statements[1]
		var got []string
		for _, p := range bin.Products {
			got = append(got, p.ID)
			if len(p.Subcomponents) != 1 || p.Subcomponents[0].ID != "pkg:golang/golang.org/x/net@v0.1.0" {
				t.Errorf("%s: product %s subcomponents = %+v, want the dependency", tc.name, p.ID, p.Subcomponents)
			}
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: products = %q, want %q", tc.name, got, tc.want)
		}
		if bin.Status != projection.VEXStatusNotAffected || !strings.Contains(bin.ImpactStatement, tc.impact) {
			t.Errorf("%s: statement = %s %q, want not_affected naming %q", tc.name, bin.Status, bin.ImpactStatement, tc.impact)
		}
	}
}
