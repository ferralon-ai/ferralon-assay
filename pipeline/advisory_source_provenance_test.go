// advisory_source_provenance_test.go
//
// A2 (cycle 2026-08-24 corpus-scaffold): the corpus's record-scoped `symbol_provenance` derivation
// tag decodes onto AdvisoryFacts.SymbolProvenance STORE-ONLY. Two properties are pinned:
//
//  1. Decode is verbatim and open-set — the emitted vocabulary decodes, an UNRECOGNIZED tier passes
//     through untouched (never rejected, never coerced to zero), and an ABSENT tag decodes to "" —
//     "" is UNKNOWN derivation, not low-confidence and not untrusted (honest-absent, inv.5).
//  2. It is INERT: nothing projects it. The normalized_advisory artifact every downstream stage
//     reads carries no `symbol_provenance` key even when a source supplies one, so the tag cannot
//     enter any admission, reachability, or refute path this cycle. A future provenance-as-confidence
//     consumer is a separate (B) change; this test is the guard that keeps A2 store-only until then.
package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// TestToFacts_SymbolProvenance_Decodes covers verbatim, open-set decode of the record-scoped tag.
func TestToFacts_SymbolProvenance_Decodes(t *testing.T) {
	tests := []struct {
		name string
		wire string // symbol_provenance as it appears on the wire ("" ⇒ field omitted)
		want string
	}{
		{"absent", "", ""}, // honest-absent: no tag ⇒ "" ⇒ unknown derivation
		{"osv-declared", "osv-declared", "osv-declared"},
		{"curated", "curated", "curated"},
		{"diff-lexed", "diff-lexed", "diff-lexed"},                     // the growth frontier; still just a stored string
		{"reserved reasoning tier", "reasoning", "reasoning"},          // reserved-not-emitted; open set tolerates it
		{"unrecognized future tier", "some-new-tier", "some-new-tier"}, // OPEN SET: passes through untouched
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := advisoryDoc{
				SchemaVersion:    normalizedAdvisorySchemaVersionV3,
				VulnID:           "CVE-PROV",
				Symbols:          []string{"pkg.Vuln"},
				SymbolProvenance: tc.wire,
			}
			facts, ok := doc.toFacts("CVE-PROV")
			if !ok {
				t.Fatalf("toFacts ok=false, want true (an unrecognized provenance tier must NOT reject the document)")
			}
			if facts.SymbolProvenance != tc.want {
				t.Errorf("SymbolProvenance = %q, want %q", facts.SymbolProvenance, tc.want)
			}
			// The provenance tag never disturbs the symbols it annotates.
			if len(facts.Symbols) != 1 || facts.Symbols[0] != "pkg.Vuln" {
				t.Errorf("Symbols = %v, want [pkg.Vuln] (provenance decode must not touch the symbol set)", facts.Symbols)
			}
		})
	}
}

// TestSymbolProvenance_ProjectedForCandidateStrength records the store-only → consumed transition.
// A2 landed symbol_provenance store-only and a guard here asserted it did NOT reach the
// normalized_advisory artifact — deliberately failing the moment a change projected it, to force
// the transition to be an explicit, reviewed (B) step. That step is B1 (provenance-as-confidence),
// reviewed and approved: the S1 projection now CARRIES symbol_provenance so the candidate-scoped
// strength consumer (trigger.symbolConfidenceFor, read only after a candidate forms) can read it.
// The tag remains structurally walled off from admission/disqualify/refute — that invariant is
// enforced in the report and trigger packages, not here; this only pins that the projection exists.
func TestSymbolProvenance_ProjectedForCandidateStrength(t *testing.T) {
	src := selectionStubSource{facts: AdvisoryFacts{
		Module:           "example.com/x",
		VersionScheme:    "gomod",
		Symbols:          []string{"pkg.Vuln"},
		SymbolProvenance: "diff-lexed",
	}}

	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-prov", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-PROV", Source: "corpus"},
	}}
	stages := AssessStages(WithAdvisorySource(src))
	if err := stages[0].Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake run: %v", err)
	}
	arts, err := store.Query(c.ID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		t.Fatalf("no normalized_advisory artifact written (err=%v)", err)
	}

	var got struct {
		SymbolProvenance string   `json:"symbol_provenance"`
		AdvisorySymbols  []string `json:"advisory_symbols"`
	}
	if err := json.Unmarshal(arts[0].Payload, &got); err != nil {
		t.Fatalf("decode normalized_advisory: %v", err)
	}
	if got.SymbolProvenance != "diff-lexed" {
		t.Errorf("symbol_provenance = %q, want %q (B1 projects the tag for the candidate-strength consumer)", got.SymbolProvenance, "diff-lexed")
	}
	if len(got.AdvisorySymbols) != 1 || got.AdvisorySymbols[0] != "pkg.Vuln" {
		t.Errorf("advisory_symbols = %v, want [pkg.Vuln] (the symbol axis still projects alongside its tag)", got.AdvisorySymbols)
	}
}

// TestSymbolProvenance_AbsentOmittedFromProjection pins honest-absent at the projection: an advisory
// with no provenance tag emits NO symbol_provenance key (omitempty), so absence stays absence on the
// wire — never a serialized "" that a reader could mistake for a declared-empty derivation.
func TestSymbolProvenance_AbsentOmittedFromProjection(t *testing.T) {
	src := selectionStubSource{facts: AdvisoryFacts{
		Module:        "example.com/x",
		VersionScheme: "gomod",
		Symbols:       []string{"pkg.Vuln"},
		// SymbolProvenance intentionally unset.
	}}

	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-prov-absent", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-PROV", Source: "corpus"},
	}}
	stages := AssessStages(WithAdvisorySource(src))
	if err := stages[0].Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake run: %v", err)
	}
	arts, _ := store.Query(c.ID, artifact.TypeNormalizedAdvisory)
	if len(arts) == 0 {
		t.Fatal("no normalized_advisory artifact written")
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(arts[0].Payload, &keys); err != nil {
		t.Fatalf("decode normalized_advisory: %v", err)
	}
	if _, present := keys["symbol_provenance"]; present {
		t.Errorf("symbol_provenance projected for an advisory with no tag — absent must stay absent (honest-absent, inv.5), never a serialized empty")
	}
}
