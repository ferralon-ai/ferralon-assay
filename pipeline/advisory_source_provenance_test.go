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

// TestSymbolProvenance_StoreOnly_NotProjected is the inert guard: a source that supplies a provenance
// tag must NOT see it reach the normalized_advisory artifact downstream stages read. The symbols
// themselves still flow (advisory_symbols present); the derivation tag does not (no symbol_provenance
// key). If a future change wires provenance into the projection, this test fails — deliberately — so
// the store-only → consumed transition is an explicit, reviewed (B) step, never a silent leak.
func TestSymbolProvenance_StoreOnly_NotProjected(t *testing.T) {
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

	var keys map[string]json.RawMessage
	if err := json.Unmarshal(arts[0].Payload, &keys); err != nil {
		t.Fatalf("decode normalized_advisory: %v", err)
	}
	if _, leaked := keys["symbol_provenance"]; leaked {
		t.Errorf("normalized_advisory carries symbol_provenance — A2 must stay STORE-ONLY; nothing may project it until the (B) provenance-as-confidence change lands under review")
	}
	// Sanity: the symbols the tag annotates DO flow through, so the absence above is inertness of the
	// tag, not a dropped symbol axis.
	if _, ok := keys["advisory_symbols"]; !ok {
		t.Errorf("normalized_advisory missing advisory_symbols — the symbol axis should still project; check the fixture, not the provenance guard")
	}
}
