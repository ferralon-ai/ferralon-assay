package trigger

import (
	"reflect"
	"slices"
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

// The reachability result's Cause details its tool_failure note, once, and stays off a
// result whose Cause names an unsearched method.
func TestPartialityNotes_ReachabilityFailureCause(t *testing.T) {
	const cause = "the import of azure in pkg/views.py resolves to no distribution a manifest read here declares, and Dockerfile was not read in full"
	cases := []struct {
		name      string
		reasons   []string
		footprint []string
		want      string
	}{
		{"detailed", []string{plugin.PartialReasonToolFailure}, []string{plugin.PartialReasonReflection, plugin.PartialReasonToolFailure}, cause},
		{"no footprint tool_failure", []string{plugin.PartialReasonToolFailure}, []string{plugin.PartialReasonReflection}, cause},
		{"unsearched methods", []string{plugin.PartialReasonToolFailure, plugin.PartialReasonUnsearchedMethods}, []string{plugin.PartialReasonToolFailure}, ""},
		{"no tool_failure", []string{plugin.PartialReasonDynamicDispatch}, []string{plugin.PartialReasonToolFailure}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			annotatedInventory(t, store)
			p := plugin.Partial(c.reasons...)
			p.Cause = cause
			putJSON(t, store, "a1", artifact.TypeReachability, map[string]any{
				"reachability": plugin.ReachabilityResult{Partiality: p},
				"call_graph":   plugin.CallGraphResult{Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch)},
			})
			seedFootprint(t, store, "a1", c.footprint)
			seedDisqual(t, store, "a1", false)
			var details []string
			failures := 0
			for _, n := range partialityNotes(store, "a1") {
				if n.Reason == plugin.PartialReasonToolFailure {
					failures++
					details = append(details, n.Detail)
				}
			}
			wantFailures := 1
			if c.want == "" && !slices.Contains(c.footprint, plugin.PartialReasonToolFailure) {
				wantFailures = 0
			}
			if failures != wantFailures {
				t.Fatalf("tool_failure notes = %d (%q), want %d", failures, details, wantFailures)
			}
			if wantFailures == 1 && details[0] != c.want {
				t.Errorf("detail = %q, want %q", details[0], c.want)
			}
		})
	}
}

// An assumption the reachability analysis rests on (a lane's call graph) reaches the row and
// its partiality notes beside the inventory's, once each, and stays off a disqualified row,
// whose verdict that analysis did not reach.
func TestAnnotations_ReachabilityAssumption(t *testing.T) {
	py2 := plugin.Annotation{Reason: plugin.AnnotationAssumptionPrefix + "py2_implicit_relative_import", Path: "pkg/views.py", Detail: "the import of forms is read as a module of the importing file's own package"}
	for _, disqual := range []bool{false, true} {
		store := artifact.NewMemStore()
		annotatedInventory(t, store)
		putJSON(t, store, "a1", artifact.TypeReachability, map[string]any{
			"reachability": plugin.ReachabilityResult{Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch), Annotations: []plugin.Annotation{py2, inactiveInstall}},
			"call_graph":   plugin.CallGraphResult{Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch)},
		})
		seedDisqual(t, store, "a1", disqual)
		want := []plugin.Annotation{inactiveInstall, py2}
		if disqual {
			want = want[:1]
		}
		if got := annotations(store, "a1"); !reflect.DeepEqual(got, want) {
			t.Errorf("disqualified=%v: annotations = %+v, want %+v", disqual, got, want)
		}
		var notes []plugin.Annotation
		for _, n := range partialityNotes(store, "a1") {
			if n.Reason == py2.Reason || n.Reason == inactiveInstall.Reason {
				notes = append(notes, plugin.Annotation{Reason: n.Reason, Path: n.Path, Detail: n.Detail})
			}
		}
		if !reflect.DeepEqual(notes, want) {
			t.Errorf("disqualified=%v: partiality notes = %+v, want %+v", disqual, notes, want)
		}
	}
}
