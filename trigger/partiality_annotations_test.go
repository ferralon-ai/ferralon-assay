package trigger

import (
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

var inactiveInstall = plugin.Annotation{
	Reason: plugin.AnnotationInstallSurfaceInactive,
	Path:   "ci/steps.yml:2",
	Detail: "install commands found at ci/steps.yml:2; this analysis assumes they are not active",
}

func annotatedInventory(t *testing.T, store *artifact.MemStore) {
	t.Helper()
	seedInventory(t, store, "a1", map[string]any{
		"language": "python", "resolved_version": "1.0.0",
		"annotations": []plugin.Annotation{inactiveInstall},
	})
}

// A disqualification rests on the version an assumption qualifies, so the assumption is
// disclosed on it while the analysis limits below it stay silent.
func TestPartialityNotes_DisqualifiedAssessmentDisclosesAssumption(t *testing.T) {
	store := artifact.NewMemStore()
	annotatedInventory(t, store)
	seedFootprint(t, store, "a1", []string{plugin.PartialReasonReflection})
	seedDisqual(t, store, "a1", true)

	want := []report.PartialityNote{{Reason: inactiveInstall.Reason, Ecosystem: "PyPI", Path: inactiveInstall.Path, Detail: inactiveInstall.Detail}}
	if got := partialityNotes(store, "a1"); !reflect.DeepEqual(got, want) {
		t.Fatalf("partialityNotes = %+v, want %+v", got, want)
	}
}

// On an undisqualified assessment the assumption joins the analysis limits, and is classed
// inherent: it never reads as a step that did not run.
func TestPartialityNotes_AssumptionJoinsLimits(t *testing.T) {
	store := artifact.NewMemStore()
	annotatedInventory(t, store)
	seedFootprint(t, store, "a1", []string{plugin.PartialReasonReflection})
	seedDisqual(t, store, "a1", false)

	got := partialityNotes(store, "a1")
	var reasons []string
	for _, n := range got {
		reasons = append(reasons, n.Reason)
		if n.Reason == inactiveInstall.Reason && report.ClassifyPartialityReason(n.Reason) != report.PartialityInherentLimit {
			t.Errorf("assumption classed %v, want inherent", report.ClassifyPartialityReason(n.Reason))
		}
	}
	if want := []string{inactiveInstall.Reason, plugin.PartialReasonReflection}; !reflect.DeepEqual(reasons, want) {
		t.Fatalf("reasons = %v, want %v", reasons, want)
	}
}

// The row carries the assessment's annotations whatever its verdict.
func TestAnnotations_ReadFromInventory(t *testing.T) {
	store := artifact.NewMemStore()
	annotatedInventory(t, store)
	if got := annotations(store, "a1"); !reflect.DeepEqual(got, []plugin.Annotation{inactiveInstall}) {
		t.Fatalf("annotations = %+v", got)
	}
	if got := annotations(store, "absent"); got != nil {
		t.Fatalf("annotations without an inventory = %+v, want none", got)
	}
}
