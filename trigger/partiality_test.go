package trigger

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

func seedInventory(t *testing.T, store *artifact.MemStore, assessmentID string, v any) {
	t.Helper()
	payload, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := store.Put(&artifact.Artifact{
		AssessmentID: assessmentID, Type: artifact.TypeInventory, ProducedBy: "test", Payload: payload,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

// The inventory's language tag is mapped onto the SBOM ecosystem vocabulary, so the
// disclosure names the ecosystem the customer recognizes ("npm", not "js").
func TestPartialityNotes_MapsLanguageToEcosystem(t *testing.T) {
	store := artifact.NewMemStore()
	seedInventory(t, store, "a1", map[string]any{
		"language":         "js",
		"partiality_flags": []string{plugin.PartialReasonNoManifest},
	})

	got := partialityNotes(store, "a1")
	want := []report.PartialityNote{{Reason: plugin.PartialReasonNoManifest, Ecosystem: "npm"}}
	if len(got) != 1 || !reflect.DeepEqual(got[0], want[0]) {
		t.Fatalf("partialityNotes = %+v, want %+v", got, want)
	}
}

// A fully-resolved assessment discloses nothing — the silence-when-clean guarantee at
// the mapping layer.
func TestPartialityNotes_SilentWhenComplete(t *testing.T) {
	store := artifact.NewMemStore()
	seedInventory(t, store, "a1", map[string]any{"language": "js", "resolved_version": "1.4.0"})

	if got := partialityNotes(store, "a1"); len(got) != 0 {
		t.Fatalf("a complete assessment must disclose nothing, got %+v", got)
	}
	if got := partialityNotes(store, "no-such-assessment"); len(got) != 0 {
		t.Fatalf("a missing inventory must disclose nothing, got %+v", got)
	}
}

// An inherited PR report re-emits the baseline's verdicts verbatim, so it must
// re-emit the baseline's coverage limits too — otherwise an inherited partial scan
// renders clean on the PR surface.
func TestInheritBaseline_CarriesPartiality(t *testing.T) {
	baseline := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "base"}).
		AddPartiality(report.PartialityNote{Reason: plugin.PartialReasonNoManifest, Ecosystem: "npm"}).
		Build()

	got := inheritBaseline(&baseline, PRInheritRequest{
		Subject: Subject{Repo: "github.com/example/widget", ResolvedCommit: "head"},
	}, &statestore.State{})

	if len(got.Partiality) != 1 || got.Partiality[0].Reason != plugin.PartialReasonNoManifest {
		t.Fatalf("inherited Report Partiality = %+v, want the baseline's no_manifest note", got.Partiality)
	}
}
