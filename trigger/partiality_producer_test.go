package trigger

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

func seedFootprint(t *testing.T, store *artifact.MemStore, assessmentID string, flags []string) {
	t.Helper()
	payload, err := json.Marshal(artifact.ExposureFootprintPayload{
		SchemaVersion:   artifact.ExposureFootprintSchemaVersion,
		AssessmentID:    assessmentID,
		PartialityFlags: flags,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := store.Put(&artifact.Artifact{
		AssessmentID: assessmentID, Type: artifact.TypeExposureFootprint, ProducedBy: "test", Payload: payload,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

func seedDisqual(t *testing.T, store *artifact.MemStore, assessmentID string, disqualified bool) {
	t.Helper()
	reason := pipeline.ReasonInsufficient
	if disqualified {
		reason = pipeline.ReasonVersionNotInRange
	}
	payload, err := json.Marshal(pipeline.DisqualResult{Disqualified: disqualified, Reason: reason})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := store.Put(&artifact.Artifact{
		AssessmentID: assessmentID, Type: artifact.TypeDiscovery, ProducedBy: "test", Payload: payload,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

// The core producer defect: S4 ingress / S5 symbol / S6 reachability partiality is
// unioned into the exposure footprint, and reading only the inventory artifact dropped
// every axis but S2. A reachability pass that could not resolve an ingress must reach
// report.Partiality, or it renders as a clean not_exploitable.
func TestPartialityNotes_ReadsAllAxesFromFootprint(t *testing.T) {
	store := artifact.NewMemStore()
	seedInventory(t, store, "a1", map[string]any{
		"language":         "go",
		"partiality_flags": []string{plugin.PartialReasonNoManifest},
	})
	seedFootprint(t, store, "a1", []string{
		plugin.PartialReasonNoManifest,  // S2, also on the inventory
		plugin.PartialReasonNoIngress,   // S4 — dropped before this fix
		plugin.PartialReasonReflection,  // S6 — dropped before this fix
		plugin.PartialReasonUnsupported, // S5 — dropped before this fix
	})

	got := partialityNotes(store, "a1")
	if len(got) != 4 {
		t.Fatalf("partialityNotes = %+v, want all four axes", got)
	}
	for _, want := range []string{
		plugin.PartialReasonNoManifest,
		plugin.PartialReasonNoIngress,
		plugin.PartialReasonReflection,
		plugin.PartialReasonUnsupported,
	} {
		found := false
		for _, n := range got {
			if n.Reason == want {
				found = true
				if n.Ecosystem != "Go" {
					t.Errorf("note %q ecosystem = %q, want Go", want, n.Ecosystem)
				}
			}
		}
		if !found {
			t.Errorf("axis %q never reached report.Partiality", want)
		}
	}
}

// A run whose stage set produced no footprint (or that failed before S4) must still
// disclose the S2 axis rather than losing it to the new read path.
func TestPartialityNotes_FallsBackToInventoryWithoutFootprint(t *testing.T) {
	store := artifact.NewMemStore()
	seedInventory(t, store, "a1", map[string]any{
		"language":         "js",
		"partiality_flags": []string{plugin.PartialReasonNoManifest},
	})

	got := partialityNotes(store, "a1")
	want := report.PartialityNote{Reason: plugin.PartialReasonNoManifest, Ecosystem: "npm"}
	if len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Fatalf("partialityNotes = %+v, want %+v", got, want)
	}
}

// The regression gate: a fully-resolved assessment must disclose NOTHING. This is what
// keeps the fix from being a blunt instrument that marks every scan uncertain — silence
// is the clean-scan signal, and a disclosure on every run carries no signal at all.
func TestPartialityNotes_CleanFootprintDisclosesNothing(t *testing.T) {
	store := artifact.NewMemStore()
	seedInventory(t, store, "a1", map[string]any{"language": "go", "resolved_version": "v1.4.0"})
	seedFootprint(t, store, "a1", nil)

	if got := partialityNotes(store, "a1"); len(got) != 0 {
		t.Fatalf("a fully-resolved assessment must disclose nothing, got %+v", got)
	}
}

// A failed analysis step names the step and the advisory it was evaluating. Without the
// name the disclosure is unactionable, and without the note the advisory silently
// vanishes from the counts.
func TestAssessFailureNote_NamesStepAndAdvisory(t *testing.T) {
	err := &pipeline.StageError{Stage: "reachability_ingress", Err: errors.New("boom")}
	got := assessFailureNote(assessment.VulnRef{ID: "GO-2021-0113"}, err)

	if got.Reason != plugin.PartialReasonToolFailure {
		t.Errorf("Reason = %q, want %q", got.Reason, plugin.PartialReasonToolFailure)
	}
	if !strings.Contains(got.Detail, "reachability_ingress") {
		t.Errorf("Detail %q does not name the failed step", got.Detail)
	}
	if !strings.Contains(got.Detail, "GO-2021-0113") {
		t.Errorf("Detail %q does not name the advisory", got.Detail)
	}
}

// An error that is not a StageError still discloses, with a generic step name — an
// unnamed failure must never degrade to silence.
func TestAssessFailureNote_UnwrappedError(t *testing.T) {
	got := assessFailureNote(assessment.VulnRef{ID: "GHSA-xxxx"}, errors.New("plain"))
	if got.Reason != plugin.PartialReasonToolFailure {
		t.Fatalf("Reason = %q, want %q", got.Reason, plugin.PartialReasonToolFailure)
	}
	if !strings.Contains(got.Detail, "GHSA-xxxx") {
		t.Errorf("Detail %q does not name the advisory", got.Detail)
	}
}

// The orchestrator must name the stage that failed, so the trigger layer can disclose
// WHICH analysis step did not run, and must keep the cause unwrappable.
func TestStageError_NamesStageAndUnwraps(t *testing.T) {
	cause := errors.New("tool exited 2")
	err := error(&pipeline.StageError{Stage: "symbol_mapping", Err: cause})

	if !strings.Contains(err.Error(), "symbol_mapping") {
		t.Errorf("Error() = %q, does not name the stage", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Error("StageError does not unwrap to its cause")
	}
}

// errPlugin is a StubPlugin whose symbol resolution fails, standing in for any wrapped
// analyzer tool that breaks mid-run (the S4 symbol_mapping stage).
type errPlugin struct{ plugin.StubPlugin }

func (errPlugin) ResolveDependencySymbols(context.Context, plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	return plugin.SymbolResolutionResult{}, errors.New("analyzer subprocess failed")
}

// A failing advisory must not discard the whole scan. The advisories that resolved keep
// their verdicts and the failure is disclosed by name — "failed scan is not no results".
func TestBuildBaselineReport_FailedAdvisoryDisclosedNotFatal(t *testing.T) {
	rep, err := buildBaselineReport(context.Background(), BaselineRequest{
		Subject: Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"},
		Advisories: []assessment.VulnRef{
			{ID: "GO-2021-0113", Source: "osv"},
		},
		AssessOptions: []pipeline.AssessOption{pipeline.WithPlugin(errPlugin{})},
	})
	if err != nil {
		t.Fatalf("a failed advisory must not abort the report: %v", err)
	}
	if len(rep.Partiality) == 0 {
		t.Fatal("a failed advisory produced no disclosure")
	}
	var found bool
	for _, n := range rep.Partiality {
		if n.Reason == plugin.PartialReasonToolFailure && strings.Contains(n.Detail, "GO-2021-0113") {
			found = true
		}
	}
	if !found {
		t.Errorf("Partiality = %+v, want a tool_failure note naming GO-2021-0113", rep.Partiality)
	}
	for _, f := range rep.Advisories {
		if f.Advisory.ID == "GO-2021-0113" {
			t.Errorf("an advisory whose analysis failed must carry no verdict, got %q", f.Verdict)
		}
	}
}

// A disqualified advisory is settled on the version axis, which is conclusive. The
// analysis steps below it ran anyway, and their limits must not qualify a scan whose
// findings are all cleanly ruled out on version — that is the noise floor that would
// make the disclosure meaningless.
func TestPartialityNotes_DisqualifiedAssessmentDisclosesNothing(t *testing.T) {
	store := artifact.NewMemStore()
	seedInventory(t, store, "a1", map[string]any{"language": "go", "resolved_version": "v0.3.8"})
	seedFootprint(t, store, "a1", []string{plugin.PartialReasonReflection, plugin.PartialReasonDynamicDispatch})
	seedDisqual(t, store, "a1", true)

	if got := partialityNotes(store, "a1"); len(got) != 0 {
		t.Fatalf("a disqualified assessment must disclose nothing, got %+v", got)
	}
}

// The converse, and the heart of I-03: a NOT-disqualified assessment whose reachability
// pass could not see a path declares reflection/dynamic_dispatch. That is the analyzer
// saying "unknown", not "safe", and it must reach the Report — otherwise the finding
// renders as a clean not_exploitable.
func TestPartialityNotes_UndisqualifiedReachabilityMissDiscloses(t *testing.T) {
	store := artifact.NewMemStore()
	seedInventory(t, store, "a1", map[string]any{"language": "go", "resolved_version": "v0.3.6"})
	seedFootprint(t, store, "a1", []string{plugin.PartialReasonReflection})
	seedDisqual(t, store, "a1", false)

	got := partialityNotes(store, "a1")
	if len(got) != 1 || got[0].Reason != plugin.PartialReasonReflection {
		t.Fatalf("partialityNotes = %+v, want the reflection disclosure", got)
	}
}
