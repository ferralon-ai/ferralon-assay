// symbol_confidence_test.go
//
// B1 provenance-as-confidence (RFC §4.1). Three levels of pin, cheapest first:
//   - symbolConfidenceFor: the total, fail-quiet tier→label mapping (absent/unrecognized ⇒ "").
//   - advisorySymbolProvenance: the S1 reader (absent/unreadable ⇒ "").
//   - finding(): the wiring — a reachable_candidate carries the confidence derived from the
//     advisory's provenance, an absent tag leaves it empty, and (the honest-absent heart of it)
//     provenance is read only inside the candidate arm, so a NON-candidate never carries a label.
package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/report"
)

func TestSymbolConfidenceFor(t *testing.T) {
	cases := []struct {
		provenance string
		want       report.SymbolConfidence
	}{
		{"", ""}, // absent ⇒ no signal (honest-absent, NOT low)
		{"osv-declared", report.SymbolConfidenceHigh},
		{"curated", report.SymbolConfidenceHigh},
		{"diff-lexed", report.SymbolConfidenceModerate}, // lower label, never a gate
		{"reasoning", ""},        // reserved-not-emitted tier ⇒ no signal yet
		{"some-future-tier", ""}, // open set: never invent a confidence we don't know
	}
	for _, tc := range cases {
		if got := symbolConfidenceFor(tc.provenance); got != tc.want {
			t.Errorf("symbolConfidenceFor(%q) = %q, want %q", tc.provenance, got, tc.want)
		}
	}
}

func TestAdvisorySymbolProvenance(t *testing.T) {
	cases := []struct {
		name    string
		advJSON string
		want    string
	}{
		{"present", `{"symbol_provenance":"diff-lexed"}`, "diff-lexed"},
		{"absent key", `{"vuln_id":"CVE-X"}`, ""},
		{"empty value", `{"symbol_provenance":""}`, ""},
		{"unreadable", `not json`, ""},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assessmentID := "01900000-0000-7000-8000-0000000000c" + string(rune('0'+i))
			store := artifact.NewMemStore()
			if _, err := store.Put(&artifact.Artifact{AssessmentID: assessmentID, Type: artifact.TypeNormalizedAdvisory, Payload: []byte(tc.advJSON)}); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if got := advisorySymbolProvenance(store, assessmentID); got != tc.want {
				t.Errorf("advisorySymbolProvenance = %q, want %q", got, tc.want)
			}
		})
	}
	// No artifact at all ⇒ "" (honest-absent, not an error).
	if got := advisorySymbolProvenance(artifact.NewMemStore(), "missing"); got != "" {
		t.Errorf("advisorySymbolProvenance(empty store) = %q, want \"\"", got)
	}
}

// TestFinding_CandidateArm_SetsSymbolConfidence drives the real finding() over a seeded store: a
// candidate pair is present (so finding() takes the reachable_candidate arm), and the normalized
// advisory carries a provenance tag. It asserts the finding is a candidate carrying the confidence
// the tag maps to — and that an absent tag leaves the label empty (the candidate is byte-identical
// to today on that axis).
func TestFinding_CandidateArm_SetsSymbolConfidence(t *testing.T) {
	cases := []struct {
		name    string
		advJSON string
		want    report.SymbolConfidence
	}{
		{"osv-declared ⇒ high", `{"symbol_provenance":"osv-declared"}`, report.SymbolConfidenceHigh},
		{"diff-lexed ⇒ moderate", `{"symbol_provenance":"diff-lexed"}`, report.SymbolConfidenceModerate},
		{"absent ⇒ no label", `{"vuln_id":"CVE-X"}`, ""},
		{"unrecognized ⇒ no label", `{"symbol_provenance":"mystery"}`, ""},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assessmentID := "01900000-0000-7000-8000-0000000000d" + string(rune('0'+i))
			store := artifact.NewMemStore()
			put := func(typ artifact.Type, payload string) {
				t.Helper()
				if _, err := store.Put(&artifact.Artifact{AssessmentID: assessmentID, Type: typ, Payload: []byte(payload)}); err != nil {
					t.Fatalf("Put %s: %v", typ, err)
				}
			}
			// A candidate pair makes finding() take the reachable_candidate arm; no disqualification
			// or malicious-presence artifact is present, so the earlier arms fall through.
			put(artifact.TypeCandidatePair, `{}`)
			put(artifact.TypeNormalizedAdvisory, tc.advJSON)

			f := finding(store, assessmentID, report.Advisory{ID: "CVE-X", Source: "osv"}, nil)
			if f.Verdict != report.VerdictReachableCandidate {
				t.Fatalf("verdict = %q, want reachable_candidate (fixture must produce a candidate)", f.Verdict)
			}
			if f.Evidence.SymbolConfidence != tc.want {
				t.Errorf("SymbolConfidence = %q, want %q", f.Evidence.SymbolConfidence, tc.want)
			}
		})
	}
}

// TestFinding_NonCandidate_NeverCarriesConfidence is the honest-absent heart: an advisory that
// carries provenance but resolves to a NON-candidate verdict must carry NO confidence label —
// proving provenance is read only inside the candidate arm and can never touch a refutation. Here
// no candidate pair is seeded, so finding() falls to its default (not_exploitable) arm.
func TestFinding_NonCandidate_NeverCarriesConfidence(t *testing.T) {
	const assessmentID = "01900000-0000-7000-8000-0000000000e0"
	store := artifact.NewMemStore()
	// Provenance is present and authoritative, but there is NO candidate pair, so the finding
	// resolves to a non-candidate verdict.
	if _, err := store.Put(&artifact.Artifact{AssessmentID: assessmentID, Type: artifact.TypeNormalizedAdvisory, Payload: []byte(`{"symbol_provenance":"osv-declared"}`)}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	f := finding(store, assessmentID, report.Advisory{ID: "CVE-X", Source: "osv"}, nil)
	if f.Verdict == report.VerdictReachableCandidate {
		t.Fatalf("fixture unexpectedly produced a candidate; want a non-candidate verdict, got %q", f.Verdict)
	}
	if f.Evidence.SymbolConfidence != "" {
		t.Errorf("non-candidate finding carries SymbolConfidence %q — provenance must never reach a non-candidate verdict (inv.5)", f.Evidence.SymbolConfidence)
	}
}
