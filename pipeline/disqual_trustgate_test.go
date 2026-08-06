// disqual_trustgate_test.go
//
// Slice U8c: the advisory TrustTier refute-gate (inv.5). A not-affected refute may be driven ONLY
// by a first-party fact. A fact that is provably out-of-range or symbol-absent but carries a
// low-trust provenance (byo / third_party / zero / unrecognized) MUST NOT refute — it falls open to
// insufficient_evidence. The gate can only ever REMOVE refutes; it never fabricates a not-affected
// and never enables a refute that first-party trust would not already have produced.
package pipeline

import (
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

// A provably out-of-range fact refutes under first-party trust but is SUPPRESSED under every other
// tier. The version axis is identical (v0.3.7 outside affects<v0.3.7); only trust differs.
func TestDisqualify_OutOfRange_RefuteGatedByTrust(t *testing.T) {
	cases := []struct {
		name        string
		trust       TrustTier
		wantDisq    bool
		wantReason  string
	}{
		{"first_party refutes", TrustFirstParty, true, ReasonVersionNotInRange},
		{"byo suppressed", TrustByO, false, ReasonInsufficient},
		{"third_party suppressed", TrustThirdParty, false, ReasonInsufficient},
		{"zero trust suppressed", "", false, ReasonInsufficient},
		{"unknown trust suppressed", TrustTier("vendor_hunch"), false, ReasonInsufficient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := disqualify(mkRange("v0.3.7"), true, "v0.3.7", true, "", false, tc.trust)
			if got != tc.wantDisq {
				t.Fatalf("disqualify = %v, want %v (trust %q)", got, tc.wantDisq, tc.trust)
			}
			if reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q (trust %q)", reason, tc.wantReason, tc.trust)
			}
		})
	}
}

// A provably-absent symbol refutes under first-party trust but is suppressed under low/zero trust.
func TestDisqualify_SymbolAbsent_RefuteGatedByTrust(t *testing.T) {
	cases := []struct {
		name       string
		trust      TrustTier
		wantDisq   bool
		wantReason string
	}{
		{"first_party refutes", TrustFirstParty, true, ReasonSymbolAbsent},
		{"byo suppressed", TrustByO, false, ReasonInsufficient},
		{"third_party suppressed", TrustThirdParty, false, ReasonInsufficient},
		{"zero trust suppressed", "", false, ReasonInsufficient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := disqualify(nil, false, "", false, "absent", true, tc.trust)
			if got != tc.wantDisq {
				t.Fatalf("disqualify = %v, want %v (trust %q)", got, tc.wantDisq, tc.trust)
			}
			if reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q (trust %q)", reason, tc.wantReason, tc.trust)
			}
		})
	}
}

// extractAdvisoryTrust maps only the three known enum strings to their tier; every miss, empty, or
// UNRECOGNIZED value fails OPEN (zero tier, ok=false) — never defaulting up to first_party.
func TestExtractAdvisoryTrust_Recognition(t *testing.T) {
	cases := []struct {
		name      string
		seed      any // nil ⇒ no advisory artifact at all
		wantTier  TrustTier
		wantOK    bool
	}{
		{"first_party", map[string]any{"trust_tier": "first_party"}, TrustFirstParty, true},
		{"byo", map[string]any{"trust_tier": "byo"}, TrustByO, true},
		{"third_party", map[string]any{"trust_tier": "third_party"}, TrustThirdParty, true},
		{"empty string", map[string]any{"trust_tier": ""}, "", false},
		{"missing field", map[string]any{"vuln_id": "X"}, "", false},
		{"unrecognized string", map[string]any{"trust_tier": "FIRST_PARTY"}, "", false},
		{"garbage string", map[string]any{"trust_tier": "trusted"}, "", false},
		{"no advisory artifact", nil, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			caseID := "case-trust"
			if tc.seed != nil {
				payload, err := json.Marshal(tc.seed)
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				if _, err := store.Put(&artifact.Artifact{AssessmentID: caseID, Type: artifact.TypeNormalizedAdvisory, ProducedBy: "test", Payload: payload}); err != nil {
					t.Fatalf("Put: %v", err)
				}
			}
			gotTier, gotOK := extractAdvisoryTrust(store, caseID)
			if gotTier != tc.wantTier || gotOK != tc.wantOK {
				t.Fatalf("extractAdvisoryTrust = %q,%v; want %q,%v", gotTier, gotOK, tc.wantTier, tc.wantOK)
			}
		})
	}
}

// tableSource stamps the curated table's first-party provenance (fill-only) so its facts remain
// refute-eligible, while preserving every other field. A miss stays (zero, false).
func TestTableSource_StampsFirstPartyTrust(t *testing.T) {
	facts, ok := tableSource{}.Lookup("GO-2021-0113")
	if !ok {
		t.Fatalf("Lookup(GO-2021-0113) = _,false; want a hit")
	}
	if facts.Provenance.TrustTier != TrustFirstParty {
		t.Fatalf("TrustTier = %q, want %q (curated table is first-party)", facts.Provenance.TrustTier, TrustFirstParty)
	}
	// U8a field parity: the stamp fills only the previously-zero tier, never touches other fields.
	want := AdvisoryTable["GO-2021-0113"]
	if facts.Module != want.Module || facts.UpperExclusive != want.UpperExclusive || facts.FixedVersion != want.FixedVersion {
		t.Fatalf("non-provenance fields drifted from AdvisoryTable: got %+v", facts)
	}
	if _, ok := (tableSource{}).Lookup("NO-SUCH-ID"); ok {
		t.Fatalf("Lookup(miss) = _,true; want false")
	}
}

// The full disqualification stage suppresses a would-be version refute when the serialized advisory
// carries a low-trust tier, and fires it when the tier is first_party — the end-to-end gate.
func TestRun_OutOfRange_TrustGatedAtStage(t *testing.T) {
	cases := []struct {
		name     string
		tier     string
		wantDisq bool
	}{
		{"first_party refutes", "first_party", true},
		{"byo suppressed", "byo", false},
		{"third_party suppressed", "third_party", false},
		{"absent tier suppressed", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			caseID := "case-stage-trust"
			adv := map[string]any{
				"vuln_id":         "GO-2021-0113",
				"affected_ranges": []map[string]string{{"upper_exclusive": "v0.3.7"}},
			}
			if tc.tier != "" {
				adv["trust_tier"] = tc.tier
			}
			putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, adv)
			putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{"resolved_version": "v0.3.7"})

			res := runDisqual(t, store, caseID)
			if res.Disqualified != tc.wantDisq {
				t.Fatalf("Disqualified = %v, want %v (tier %q)", res.Disqualified, tc.wantDisq, tc.tier)
			}
			if !tc.wantDisq && res.Reason != ReasonInsufficient {
				t.Fatalf("Reason = %q, want %q (suppressed refute must fail open)", res.Reason, ReasonInsufficient)
			}
		})
	}
}
