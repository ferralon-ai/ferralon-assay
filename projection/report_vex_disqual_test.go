package projection_test

import (
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// disqualReport returns a one-finding Report whose single disqualification carries the given
// refutation basis. Findings are set directly rather than through report.Builder, which fills
// the version basis for every disqualification it records.
func disqualReport(t *testing.T, basis verdict.NonExploitableBasis, detail string) report.Report {
	t.Helper()
	r := fixtureReport()
	for i := range r.Advisories {
		if r.Advisories[i].Verdict != report.VerdictDisqualified {
			continue
		}
		f := r.Advisories[i]
		f.Evidence.Basis = basis
		f.Evidence.Detail = detail
		r.Advisories = []report.AdvisoryFinding{f}
		return r
	}
	t.Fatal("fixtureReport carries no disqualified finding")
	return r
}

func statementFor(t *testing.T, r report.Report) projection.VEXStatement {
	t.Helper()
	doc, err := projection.ProjectReportVEX(r)
	if err != nil {
		t.Fatalf("ProjectReportVEX: %v", err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("statements: got %d, want 1", len(doc.Statements))
	}
	return doc.Statements[0]
}

// The OpenVEX half of the disqualification-basis defect: the projector asserted
// vulnerable_code_not_present for every disqualification, taken from the verdict alone. A
// disqualification with no basis was never adjudicated on the version or symbol axis — the
// advisory belongs to another ecosystem, or its package is absent from the manifest — so
// "the vulnerable code is not present" is a claim nothing in the run supports.
//
// not_affected is still correct and stays (the status is verdict-driven, inv. 5). Only the
// justification is withheld, which OpenVEX §3.2 permits.
func TestReportVEX_UnadjudicatedDisqualificationHasNoJustification(t *testing.T) {
	s := statementFor(t, disqualReport(t, verdict.BasisNone,
		"the advisory's package is absent from this codebase's dependency manifest; no version or symbol comparison was performed"))

	if s.Status != projection.VEXStatusNotAffected {
		t.Errorf("status = %q, want not_affected (verdict-driven, inv. 5)", s.Status)
	}
	if s.Justification != "" {
		t.Errorf("justification = %q, want none: no axis adjudicated this advisory against the subject",
			s.Justification)
	}
}

// The justification must be absent from the wire, not merely empty: a consumer reads the
// document, not the struct.
func TestReportVEX_UnadjudicatedDisqualificationOmitsJustificationOnTheWire(t *testing.T) {
	b, err := projection.MarshalReportVEX(disqualReport(t, verdict.BasisNone, "no comparison was performed"))
	if err != nil {
		t.Fatalf("MarshalReportVEX: %v", err)
	}
	var doc struct {
		Statements []map[string]any `json:"statements"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("statements: got %d, want 1", len(doc.Statements))
	}
	if just, ok := doc.Statements[0]["justification"]; ok {
		t.Errorf("document carries justification %v; an unadjudicated disqualification has none to state", just)
	}
}

// The adjudicated axes keep their justification: this must not pass by dropping every one.
func TestReportVEX_AdjudicatedDisqualificationKeepsNotPresent(t *testing.T) {
	for _, basis := range []verdict.NonExploitableBasis{
		verdict.BasisVersionNotAffected,
		verdict.BasisSymbolAbsent,
	} {
		s := statementFor(t, disqualReport(t, basis, "adjudicated and cleared"))
		if s.Status != projection.VEXStatusNotAffected {
			t.Errorf("basis %q: status = %q, want not_affected", basis, s.Status)
		}
		if s.Justification != projection.VEXJustNotPresent {
			t.Errorf("basis %q: justification = %q, want %q", basis, s.Justification, projection.VEXJustNotPresent)
		}
	}
}
