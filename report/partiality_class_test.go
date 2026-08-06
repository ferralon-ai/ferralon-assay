package report_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// The classification table, pinned. Only limits of the METHOD are quiet; a limit that
// says a step of the analysis did not happen is loud, and so is everything unknown.
func TestClassifyPartialityReason(t *testing.T) {
	for reason, want := range map[string]report.PartialityClass{
		plugin.PartialReasonReflection:      report.PartialityInherentLimit,
		plugin.PartialReasonDynamicDispatch: report.PartialityInherentLimit,

		plugin.PartialReasonCgo:                      report.PartialityDidNotRun,
		plugin.PartialReasonUnsupported:              report.PartialityDidNotRun,
		plugin.PartialReasonToolFailure:              report.PartialityDidNotRun,
		plugin.PartialReasonNoIngress:                report.PartialityDidNotRun,
		plugin.PartialReasonNoManifest:               report.PartialityDidNotRun,
		plugin.PartialReasonNoPlugin:                 report.PartialityDidNotRun,
		plugin.PartialReasonReachabilityUndetermined: report.PartialityDidNotRun,
	} {
		if got := report.ClassifyPartialityReason(reason); got != want {
			t.Errorf("ClassifyPartialityReason(%q) = %q, want %q", reason, got, want)
		}
	}
}

// THE default. The reason vocabulary is open, so a build will meet codes it does not
// know; sending them to the quiet arm would let a genuine failure hide behind a
// taxonomy gap, which is the silent clean scan by another route.
func TestClassifyPartialityReason_UnknownIsLoud(t *testing.T) {
	for _, reason := range []string{"future_reason_code", "", "no_corpus", "REFLECTION"} {
		if got := report.ClassifyPartialityReason(reason); got != report.PartialityDidNotRun {
			t.Errorf("ClassifyPartialityReason(%q) = %q, want %q", reason, got, report.PartialityDidNotRun)
		}
	}
}

// EffectiveClass is where the default has to live: a note that never passed through
// the Builder — a Report from a writer predating the field, a hand-assembled one —
// must still resolve loud.
func TestEffectiveClass_DefaultsLoud(t *testing.T) {
	for _, n := range []report.PartialityNote{
		{Reason: "no_manifest"},
		{Reason: "reflection"},
		{Reason: "no_manifest", Class: "did_not_run"},
		{Reason: "reflection", Class: "some_future_arm"},
	} {
		if got := n.EffectiveClass(); got != report.PartialityDidNotRun {
			t.Errorf("%+v EffectiveClass = %q, want %q", n, got, report.PartialityDidNotRun)
		}
	}
	quiet := report.PartialityNote{Reason: "reflection", Class: report.PartialityInherentLimit}
	if got := quiet.EffectiveClass(); got != report.PartialityInherentLimit {
		t.Errorf("an explicitly-inherent note resolved to %q", got)
	}
}

// AddPartiality is the single stamping point, so two producers of the same reason
// cannot disagree and split one disclosure into two after de-duplication.
func TestAddPartiality_StampsClassFromReason(t *testing.T) {
	r := partialityBuilder().
		AddPartiality(report.PartialityNote{Reason: "reflection", Ecosystem: "Go"}).
		AddPartiality(report.PartialityNote{Reason: "no_manifest", Ecosystem: "Go"}).
		Build()

	want := map[string]report.PartialityClass{
		"reflection":  report.PartialityInherentLimit,
		"no_manifest": report.PartialityDidNotRun,
	}
	if len(r.Partiality) != len(want) {
		t.Fatalf("Partiality = %+v, want %d notes", r.Partiality, len(want))
	}
	for _, n := range r.Partiality {
		if n.Class != want[n.Reason] {
			t.Errorf("%q stamped %q, want %q", n.Reason, n.Class, want[n.Reason])
		}
	}
}

// An explicit Class survives the builder: a producer that knows its own limit is
// methodological may say so under a code the reader does not yet know.
func TestAddPartiality_KeepsExplicitClass(t *testing.T) {
	r := partialityBuilder().
		AddPartiality(report.PartialityNote{Reason: "future_limit_code", Class: report.PartialityInherentLimit}).
		Build()

	if len(r.Partiality) != 1 || r.Partiality[0].Class != report.PartialityInherentLimit {
		t.Fatalf("Partiality = %+v, want the explicit inherent class preserved", r.Partiality)
	}
}

// Additive per §11: the field is omitted when empty, so a reader predating it sees
// exactly the bytes it always saw, and the note still round-trips.
func TestPartialityClass_JSONAdditive(t *testing.T) {
	b, err := json.Marshal(report.PartialityNote{Reason: "no_manifest", Ecosystem: "npm"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(b), "class") {
		t.Errorf("an unclassified note serialized %s; the field must be omitempty", b)
	}

	stamped := report.PartialityNote{Reason: "reflection", Class: report.PartialityInherentLimit}
	b, err = json.Marshal(stamped)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(b), `"class":"inherent_limit"`) {
		t.Errorf("stamped note serialized %s, want a class field", b)
	}
	var back report.PartialityNote
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(back, stamped) {
		t.Errorf("round-trip = %+v, want %+v", back, stamped)
	}
}
