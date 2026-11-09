// stages_advisory_source_test.go
//
// The WithAdvisorySource option must flow through the AssessStages / SBOMStages assembly seam into
// the S1 advisory_intake stage, so a stage built with the option reads the INJECTED source rather
// than the process default. GO-2021-0113 is a fixture id (module golang.org/x/text); the injected
// source returns a distinct sentinel module, so the artifact's module tells us which source the stage
// actually read.
package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

const injectedSentinelModule = "example.com/injected/advisory-module"

// intakeModuleFromStages runs the advisory_intake stage (always index 0 of an AssessStages /
// SBOMStages slice) for vulnID and returns the module recorded on the normalized_advisory artifact.
func intakeModuleFromStages(t *testing.T, stages []Stage, vulnID string) string {
	t.Helper()
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-optflow", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: vulnID, Source: "corpus"},
	}}
	if err := stages[0].Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake run: %v", err)
	}
	arts, err := store.Query(c.ID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		t.Fatalf("no normalized_advisory artifact written (err=%v)", err)
	}
	var adv struct {
		Module string `json:"module"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		t.Fatalf("decode normalized_advisory: %v", err)
	}
	return adv.Module
}

// AssessStages(WithAdvisorySource(src)) threads the injected source into advisory_intake: a fixture
// id resolves through the injected source (sentinel module), not the default.
func TestAssessStages_WithAdvisorySource_ReadsInjected(t *testing.T) {
	src := selectionStubSource{facts: AdvisoryFacts{Module: injectedSentinelModule}}
	got := intakeModuleFromStages(t, AssessStages(WithAdvisorySource(src)), "GO-2021-0113")
	if got != injectedSentinelModule {
		t.Fatalf("module = %q, want the injected sentinel %q (option did not flow into S1)", got, injectedSentinelModule)
	}
}

// Without the option, advisory_intake reads the process default: with the fixtures installed the id
// resolves to their module, and with nothing installed it resolves nothing at all.
func TestAssessStages_NoOption_ReadsDefault(t *testing.T) {
	swapDefaultSource(t, fixtureSource())
	if got := intakeModuleFromStages(t, AssessStages(), "GO-2021-0113"); got != "golang.org/x/text" {
		t.Fatalf("module = %q, want golang.org/x/text (the installed default)", got)
	}

	defaultAdvisorySourceVar = nil
	if got := intakeModuleFromStages(t, AssessStages(), "GO-2021-0113"); got != "" {
		t.Fatalf("module = %q, want empty: an unset default carries no advisory facts", got)
	}
}

// SBOMStages mirrors AssessStages: the option flows into its S1 advisory_intake too.
func TestSBOMStages_WithAdvisorySource_ReadsInjected(t *testing.T) {
	src := selectionStubSource{facts: AdvisoryFacts{Module: injectedSentinelModule}}
	got := intakeModuleFromStages(t, SBOMStages(WithAdvisorySource(src)), "GO-2021-0113")
	if got != injectedSentinelModule {
		t.Fatalf("module = %q, want the injected sentinel %q (option did not flow into SBOMStages S1)", got, injectedSentinelModule)
	}
}
