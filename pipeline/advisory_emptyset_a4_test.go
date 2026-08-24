// advisory_emptyset_a4_test.go
//
// A4 (cycle 2026-08-24 corpus-scaffold): guard_symbols[] is data-empty (1 record) and trigger is
// fully reserved (0 records) across the corpus today. These pins lock the honest-absent posture of
// their S1 projection so a FUTURE non-empty set is HANDLED, never assumed-absent-as-false:
//
//   - An EMPTY guard set / ZERO trigger projects NOTHING (omitted key) — absence asserts nothing, it
//     is not "no guard ⇒ nothing mitigates ⇒ affected" nor "no trigger ⇒ not exploitable". The
//     per-class constant framing is the unchanged fallback (inv.5).
//   - A NON-EMPTY guard set / POPULATED trigger DOES project, verbatim — proving the path is
//     data-driven, so when Gene populates these fields no consumer change is needed and no
//     assume-absent shortcut can regress into a false verdict.
//
// The projection is the single seam both fields cross (stages.go advisory_intake); pinning it here is
// where the empty-vs-populated contract is cheapest to enforce.
package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// normalizedAdvisoryKeys runs the injected-source advisory_intake stage for facts and returns the
// decoded key set of the emitted normalized_advisory artifact.
func normalizedAdvisoryKeys(t *testing.T, facts AdvisoryFacts) map[string]json.RawMessage {
	t.Helper()
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-a4", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-A4", Source: "corpus"},
	}}
	stages := AssessStages(WithAdvisorySource(selectionStubSource{facts: facts}))
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
	return keys
}

// TestGuardSymbolsProjection_EmptyVsPopulated pins the guard_symbols projection contract.
func TestGuardSymbolsProjection_EmptyVsPopulated(t *testing.T) {
	base := AdvisoryFacts{Module: "example.com/x", VersionScheme: "gomod"}

	t.Run("empty asserts nothing", func(t *testing.T) {
		keys := normalizedAdvisoryKeys(t, base) // GuardSymbols nil
		if _, present := keys["advisory_guards"]; present {
			t.Errorf("advisory_guards projected for an empty guard set — an empty set must assert nothing (honest-absent, inv.5)")
		}
	})

	t.Run("populated is handled", func(t *testing.T) {
		facts := base
		facts.GuardSymbols = []string{"isRepositoryGitPath"}
		keys := normalizedAdvisoryKeys(t, facts)
		raw, present := keys["advisory_guards"]
		if !present {
			t.Fatalf("advisory_guards NOT projected for a populated guard set — a future non-empty set must be handled, not dropped")
		}
		var got []string
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("decode advisory_guards: %v", err)
		}
		if len(got) != 1 || got[0] != "isRepositoryGitPath" {
			t.Errorf("advisory_guards = %v, want [isRepositoryGitPath] (projected verbatim)", got)
		}
	})
}

// TestTriggerProjection_ZeroVsPopulated pins the trigger projection contract.
func TestTriggerProjection_ZeroVsPopulated(t *testing.T) {
	base := AdvisoryFacts{Module: "example.com/x", VersionScheme: "gomod"}

	t.Run("zero asserts nothing", func(t *testing.T) {
		keys := normalizedAdvisoryKeys(t, base) // Trigger zero
		if _, present := keys["trigger"]; present {
			t.Errorf("trigger projected for a zero descriptor — a reserved/absent trigger must fall back to the per-class constant framing, asserting nothing (inv.5)")
		}
	})

	t.Run("populated is handled", func(t *testing.T) {
		facts := base
		facts.Trigger = TriggerRoute{IngressKind: "http", Route: "/fetch", Param: "url", MalformedToken: "internal-address"}
		keys := normalizedAdvisoryKeys(t, facts)
		raw, present := keys["trigger"]
		if !present {
			t.Fatalf("trigger NOT projected for a populated descriptor — a future non-empty trigger must be handled, not dropped")
		}
		var got struct {
			IngressKind    string `json:"ingress_kind"`
			Route          string `json:"route"`
			Param          string `json:"param"`
			MalformedToken string `json:"malformed_token"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("decode trigger: %v", err)
		}
		if got.IngressKind != "http" || got.Route != "/fetch" || got.Param != "url" || got.MalformedToken != "internal-address" {
			t.Errorf("trigger projected wrong: %+v", got)
		}
	})
}
