// symbol_confidence_test.go
//
// B1 provenance-as-confidence (RFC §4.1): SymbolConfidence qualifies a reachable_candidate by how
// its vulnerable symbols were derived. These pin the STRUCTURAL honest-absent guarantee at the
// report boundary — the field is a permitted-value strength label AND it may appear on nothing but a
// reachable_candidate, so Validate() rejects it on any verdict that could rest on absence.
package report

import "testing"

func TestSymbolConfidence_Valid(t *testing.T) {
	cases := []struct {
		c    SymbolConfidence
		want bool
	}{
		{"", true}, // empty is valid: a candidate need not carry a derivation signal
		{SymbolConfidenceHigh, true},
		{SymbolConfidenceModerate, true},
		{"low", false},        // not a defined label
		{"diff-lexed", false}, // the raw provenance tag is NOT a confidence label
	}
	for _, tc := range cases {
		if got := tc.c.Valid(); got != tc.want {
			t.Errorf("SymbolConfidence(%q).Valid() = %v, want %v", tc.c, got, tc.want)
		}
	}
}

// TestValidateRejectsSymbolConfidenceOnNonCandidate is the structural inv.5 gate: a derivation-
// confidence signal on anything but a reachable_candidate is rejected, so provenance-as-confidence
// can never annotate — let alone drive — a disqualification, not_exploitable, or undetermined verdict.
func TestValidateRejectsSymbolConfidenceOnNonCandidate(t *testing.T) {
	for _, v := range []Verdict{VerdictNotExploitable, VerdictDisqualified} {
		r := NewBuilder(Subject{ResolvedCommit: "c"}).
			AddFinding(AdvisoryFinding{
				Advisory: Advisory{ID: "X", Source: "osv"},
				Verdict:  v,
				Evidence: EvidenceSummary{SymbolConfidence: SymbolConfidenceModerate},
			}).Build()
		if err := r.Validate(); err == nil {
			t.Errorf("verdict %q: expected Validate to reject a symbol confidence on a non-candidate verdict (inv.5, strength-not-admission)", v)
		}
	}
}

func TestValidateRejectsUnknownSymbolConfidence(t *testing.T) {
	r := NewBuilder(Subject{ResolvedCommit: "c"}).
		AddFinding(AdvisoryFinding{
			Advisory: Advisory{ID: "X", Source: "osv"},
			Verdict:  VerdictReachableCandidate,
			Evidence: EvidenceSummary{ReachablePath: "a → b", SymbolConfidence: SymbolConfidence("certain")},
		}).Build()
	if err := r.Validate(); err == nil {
		t.Fatal("expected Validate to reject an unknown symbol confidence label")
	}
}

func TestValidateAcceptsSymbolConfidenceOnCandidate(t *testing.T) {
	r := NewBuilder(Subject{ResolvedCommit: "c"}).
		AddFinding(AdvisoryFinding{
			Advisory: Advisory{ID: "X", Source: "osv"},
			Verdict:  VerdictReachableCandidate,
			Evidence: EvidenceSummary{ReachablePath: "main.handler → pkg.Vuln", SymbolConfidence: SymbolConfidenceModerate},
		}).Build()
	if err := r.Validate(); err != nil {
		t.Fatalf("a candidate carrying a valid symbol confidence should validate, got: %v", err)
	}
	if r.Advisories[0].Evidence.SymbolConfidence != SymbolConfidenceModerate {
		t.Fatalf("symbol confidence lost through Build: %+v", r.Advisories[0].Evidence)
	}
}
