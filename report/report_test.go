package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// fullReport returns a Report exercising every field, including the optional ones,
// so the round-trip test proves nothing is dropped.
func fullReport() Report {
	pkg := Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7", PURL: "pkg:golang/golang.org/x/text@v0.3.7"}
	return Report{
		SchemaVersion: SchemaVersion,
		Subject: Subject{
			Repo:           "https://github.com/acme/widget",
			Revision:       "main",
			ResolvedCommit: "abc123",
		},
		SBOM: SBOM{Packages: []Package{
			pkg,
			{Ecosystem: "Maven", Name: "com.example:widget", Version: "1.2.3"},
		}},
		Advisories: []AdvisoryFinding{
			{
				Advisory: Advisory{ID: "GO-2021-0001", Source: "osv", Aliases: []string{"CVE-2021-0001"}},
				Package:  &pkg,
				Verdict:  VerdictDisqualified,
				Evidence: EvidenceSummary{
					Basis:  verdict.BasisVersionNotAffected,
					Detail: "resolved v0.3.7 is below first affected v0.3.8",
				},
			},
			{
				Advisory: Advisory{ID: "GHSA-aaaa-bbbb-cccc", Source: "ghsa"},
				Verdict:  VerdictNotExploitable,
				Evidence: EvidenceSummary{
					Basis:  verdict.BasisSymbolAbsent,
					Detail: "vulnerable symbol absent from built artifact",
				},
			},
			{
				Advisory: Advisory{ID: "CVE-2024-9999", Source: "nvd"},
				Verdict:  VerdictReachableCandidate,
				Evidence: EvidenceSummary{
					ReachablePath: "net/http.Handler -> pkg.VulnFunc",
					Detail:        "an HTTP handler reaches the advisory symbol",
				},
			},
		},
		Provenance: Provenance{
			CommitSHA:       "abc123",
			AnalyzerVersion: "ferralon-assay/0.2.0",
			AdvisoryCursor:  "osv@2026-06-15T00:00:00Z",
			Timestamp:       time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
		},
		Baseline: &BaselineRef{
			CommitSHA: "def456",
			StateRef:  "refs/tegron/state",
			BlobSHA:   "deadbeef",
		},
	}
}

func TestReportJSONRoundTrip(t *testing.T) {
	orig := fullReport()

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got Report
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("round-trip mismatch:\n orig=%+v\n  got=%+v", orig, got)
	}

	// Re-marshal must be byte-identical: stable serialization is required for the
	// StateStore's content-addressed (changed-blob-only) writes.
	data2, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(data, data2) {
		t.Fatalf("re-marshal not byte-identical:\n first=%s\nsecond=%s", data, data2)
	}
}

func TestReportOmitsEmptyOptionalFields(t *testing.T) {
	r := Report{
		SchemaVersion: SchemaVersion,
		Subject:       Subject{Repo: "r", ResolvedCommit: "c"},
		Provenance:    Provenance{CommitSHA: "c", Timestamp: time.Unix(0, 0).UTC()},
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, absent := range []string{`"baseline"`, `"revision"`} {
		if bytes.Contains(data, []byte(absent)) {
			t.Errorf("expected %s to be omitted, got: %s", absent, data)
		}
	}
}

func TestVerdictValid(t *testing.T) {
	for _, v := range []Verdict{VerdictDisqualified, VerdictNotExploitable, VerdictReachableCandidate, VerdictUndetermined, VerdictMaliciousPresent} {
		if !v.Valid() {
			t.Errorf("%q should be valid", v)
		}
	}
	for _, v := range []Verdict{"exploitable", "reasoned_exploitable", "reasoned_not_exploitable", "", "bogus"} {
		if Verdict(v).Valid() {
			t.Errorf("%q must NOT be valid (inv. 5)", v)
		}
	}
}

func TestReportValidate(t *testing.T) {
	t.Run("full report is valid", func(t *testing.T) {
		if err := fullReport().Validate(); err != nil {
			t.Fatalf("expected valid, got %v", err)
		}
	})

	t.Run("missing schema version", func(t *testing.T) {
		r := fullReport()
		r.SchemaVersion = ""
		if err := r.Validate(); err == nil {
			t.Fatal("expected error for empty schema version")
		}
	})

	t.Run("non-deterministic verdict rejected (inv. 5)", func(t *testing.T) {
		r := fullReport()
		r.Advisories[0].Verdict = Verdict("exploitable")
		if err := r.Validate(); err == nil {
			t.Fatal("expected error for exploitable verdict")
		}
	})

	t.Run("reachable candidate with refutation basis rejected", func(t *testing.T) {
		r := fullReport()
		r.Advisories[2].Evidence.Basis = verdict.BasisSymbolAbsent
		if err := r.Validate(); err == nil {
			t.Fatal("expected error: a candidate cannot carry a not-exploitability basis")
		}
	})
}

// undeterminedReport is the minimal legal undetermined finding: a verdict, a reason, and nothing
// that would make it an assertion.
func undeterminedReport() Report {
	r := fullReport()
	r.Advisories = []AdvisoryFinding{{
		Advisory:           Advisory{ID: "GO-2021-0264", Source: "osv"},
		Verdict:            VerdictUndetermined,
		UndeterminedReason: ReasonGoToolchainNotScanned,
		Evidence:           EvidenceSummary{Detail: UndeterminedDetail(ReasonGoToolchainNotScanned)},
	}}
	return r
}

// TestReportValidate_Undetermined is the structural guard on the fourth verdict. Each rejection
// closes a way `undetermined` could decay back into the defect it was added to remove — a basis is what
// makes a refutation a claim, and an unexplained non-verdict is silent suppression wearing a label.
func TestReportValidate_Undetermined(t *testing.T) {
	t.Run("minimal undetermined finding is valid", func(t *testing.T) {
		if err := undeterminedReport().Validate(); err != nil {
			t.Fatalf("expected valid, got %v", err)
		}
	})

	t.Run("refutation basis rejected", func(t *testing.T) {
		r := undeterminedReport()
		r.Advisories[0].Evidence.Basis = verdict.BasisSymbolAbsent
		if err := r.Validate(); err == nil {
			t.Fatal("expected error: an undetermined finding established nothing, so it has no grounds")
		}
	})

	t.Run("missing reason rejected", func(t *testing.T) {
		r := undeterminedReport()
		r.Advisories[0].UndeterminedReason = ""
		if err := r.Validate(); err == nil {
			t.Fatal("expected error: an undetermined finding with no reason is an unexplained omission")
		}
	})

	t.Run("reason on a verdict that established something rejected", func(t *testing.T) {
		for _, v := range []Verdict{VerdictDisqualified, VerdictNotExploitable, VerdictReachableCandidate} {
			r := undeterminedReport()
			r.Advisories[0].Verdict = v
			r.Advisories[0].Evidence = EvidenceSummary{}
			if err := r.Validate(); err == nil {
				t.Errorf("%q carrying an undetermined_reason was accepted; a reason explains only an absent verdict", v)
			}
		}
	})

	t.Run("reachability grade rejected", func(t *testing.T) {
		r := undeterminedReport()
		r.Advisories[0].Evidence.Grade = GradeControlFlowOnly
		if err := r.Validate(); err == nil {
			t.Fatal("expected error: a grade refines only a reachable_candidate")
		}
	})
}
