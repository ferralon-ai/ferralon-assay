// workset_partiality_reach_test.go
//
// F-5: the work-set widening and the partiality producer were built on two disjoint branches, so
// nothing could exercise the seam between them. This file is that exercise, and it is deliberately
// placed in package main because this is the ONLY package that can see both halves: the reason codes
// and unresolvedDetail are unexported here, and report/projection are the producer stack's.
//
// What it pins:
//
//   - Every reason code this command mints classifies into the LOUD arm. The taxonomy defaults that
//     way for unknown codes, so this is a regression test against someone later declaring one of
//     them inherent — which would file a work set the pass never covered under "this is how static
//     analysis works" and render it as a clean scan.
//   - The identities of the unassessed advisories travel resolveWorkSet → BaselineRequest.WorkSetLimits
//     → Report.Partiality → SARIF, on a pass with ZERO findings. Zero findings is the case the
//     disclosure exists for: it is the only thing separating "we found nothing" from "we did not look".
package main

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// TestWorkSetReasons_ClassifyLoud pins the arm every work-set reason code lands in.
//
// The inherent-limit rows are controls, not subjects: without them a test that only ever asserts
// "did_not_run" would pass just as well against a ClassifyPartialityReason that returned the loud arm
// unconditionally, and would therefore prove nothing about these three codes in particular.
func TestWorkSetReasons_ClassifyLoud(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		want   report.PartialityClass
	}{
		{"osv query failed", reasonWorkSetNotWidened, report.PartialityDidNotRun},
		{"no dependency inventory", reasonWorkSetNoInventory, report.PartialityDidNotRun},
		{"advisories with no facts", reasonAdvisoryFactsUnavailable, report.PartialityDidNotRun},
		{"no manifest (borrowed from plugin)", plugin.PartialReasonNoManifest, report.PartialityDidNotRun},
		{"control: reflection is methodology", plugin.PartialReasonReflection, report.PartialityInherentLimit},
		{"control: dynamic dispatch is methodology", plugin.PartialReasonDynamicDispatch, report.PartialityInherentLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := report.ClassifyPartialityReason(tt.reason); got != tt.want {
				t.Errorf("ClassifyPartialityReason(%q) = %q, want %q", tt.reason, got, tt.want)
			}
			// Through the Builder, which is where the class is actually stamped: a producer that
			// leaves Class unset must still come out of Build() in the right arm, and the arm a sink
			// renders is EffectiveClass, never the raw field.
			rep := report.NewBuilder(report.Subject{Repo: "example.com/fixture", ResolvedCommit: "sha"}).
				AddPartiality(report.PartialityNote{Reason: tt.reason}).
				Build()
			if len(rep.Partiality) != 1 {
				t.Fatalf("Partiality = %+v, want exactly the one note", rep.Partiality)
			}
			if got := rep.Partiality[0].Class; got != tt.want {
				t.Errorf("built note Class = %q, want %q", got, tt.want)
			}
			if got := rep.Partiality[0].EffectiveClass(); got != tt.want {
				t.Errorf("built note EffectiveClass() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestWorkSetPartiality_UnassessedIDsReachSARIF is the F-5 proof test: it runs the real widening,
// hands its limits to the real baseline path, and reads the real SARIF projection.
//
// Neither parent branch can compile it, let alone pass it. On teg-workset-widen alone,
// report.PartialityNote has no Detail field, report.PartialityClass and EffectiveClass do not exist,
// and ProjectReportSARIF emits no partiality results at all — a zero-finding Report projects to an
// empty result set, which is a clean scan. On teg-partiality-producer alone, resolveWorkSet,
// unresolvedDetail, the three reason codes and BaselineRequest.WorkSetLimits do not exist, so the
// widening's limits have no route into a Report in the first place.
func TestWorkSetPartiality_UnassessedIDsReachSARIF(t *testing.T) {
	unassessed := []string{"GHSA-zzzz-zzzz-zzzz", "GHSA-aaaa-aaaa-aaaa", "GHSA-mmmm-mmmm-mmmm"}
	acq := goFixture(t, fixtureGoMod)
	ws := resolveWorkSet(context.Background(), acq, &fakeOSV{ids: unassessed}, nil)

	store, _ := newStateStore(t)
	// Advisories is empty on purpose: this is a pass that established nothing and found nothing. If
	// the limit does not survive to SARIF here, the log is byte-indistinguishable from a clean scan.
	rep, err := trigger.RunBaseline(context.Background(), store, trigger.BaselineRequest{
		Subject:       trigger.Subject{Repo: "example.com/fixture", Revision: "main", ResolvedCommit: "sha"},
		Codebase:      assessment.CodebaseRef{Repo: "example.com/fixture", Revision: "main"},
		Advisories:    nil,
		WorkSetLimits: ws.partiality,
	})
	if err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
	if len(rep.Advisories) != 0 {
		t.Fatalf("fixture produced findings (%d); the zero-finding case is the one under test", len(rep.Advisories))
	}

	note := findNote(t, rep.Partiality, reasonAdvisoryFactsUnavailable)
	if note.Detail == "" {
		t.Fatal("the note reached the Report with an empty Detail — the identities died in resolveWorkSet (B-4)")
	}
	if note.EffectiveClass() != report.PartialityDidNotRun {
		t.Errorf("unassessed advisories landed in the %q arm, want the loud arm", note.EffectiveClass())
	}

	log, err := projection.ProjectReportSARIF(*rep)
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("Runs = %d, want 1", len(log.Runs))
	}

	res := findSARIFResult(t, log.Runs[0].Results, reasonAdvisoryFactsUnavailable)
	if res.RuleID != projection.PartialCoverageRuleID {
		t.Errorf("ruleId = %q, want %q (the analysis-limits rule is the quiet arm)", res.RuleID, projection.PartialCoverageRuleID)
	}
	if res.Level != "warning" {
		t.Errorf("level = %q, want %q", res.Level, "warning")
	}
	detail, _ := res.Properties.Tegron["detail"].(string)
	for _, id := range unassessed {
		if !strings.Contains(detail, id) {
			t.Errorf("SARIF detail property does not name %s:\n%s", id, detail)
		}
		if !strings.Contains(res.Message.Text, id) {
			t.Errorf("SARIF message does not name %s:\n%s", id, res.Message.Text)
		}
	}
	if !strings.Contains(detail, "3 advisory id(s)") {
		t.Errorf("SARIF detail property elided the exact count:\n%s", detail)
	}
}

// TestWorkSetPartiality_CleanRunEmitsNoLimit is the other half of the claim. A disclosure that fires
// on every run cannot distinguish anything, so a widening that resolved everything must project to a
// SARIF log with no partial-coverage result at all.
func TestWorkSetPartiality_CleanRunEmitsNoLimit(t *testing.T) {
	acq := goFixture(t, fixtureGoMod)
	ws := resolveWorkSet(context.Background(), acq, &fakeOSV{}, nil)

	store, _ := newStateStore(t)
	rep, err := trigger.RunBaseline(context.Background(), store, trigger.BaselineRequest{
		Subject:       trigger.Subject{Repo: "example.com/fixture", Revision: "main", ResolvedCommit: "sha"},
		Codebase:      assessment.CodebaseRef{Repo: "example.com/fixture", Revision: "main"},
		WorkSetLimits: ws.partiality,
	})
	if err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}

	log, err := projection.ProjectReportSARIF(*rep)
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	for _, r := range log.Runs[0].Results {
		if r.Properties == nil {
			continue
		}
		if reason, _ := r.Properties.Tegron["partiality_reason"].(string); reason == reasonAdvisoryFactsUnavailable {
			t.Errorf("a run with nothing unassessed still emitted %q:\n%s", reason, r.Message.Text)
		}
	}
}

func findNote(t *testing.T, notes []report.PartialityNote, reason string) report.PartialityNote {
	t.Helper()
	for _, n := range notes {
		if n.Reason == reason {
			return n
		}
	}
	t.Fatalf("no %q note on the Report; notes = %+v", reason, notes)
	return report.PartialityNote{}
}

func findSARIFResult(t *testing.T, results []projection.SARIFResult, reason string) projection.SARIFResult {
	t.Helper()
	for _, r := range results {
		if r.Properties == nil {
			continue
		}
		if got, _ := r.Properties.Tegron["partiality_reason"].(string); got == reason {
			return r
		}
	}
	t.Fatalf("no SARIF result carries partiality_reason %q; results = %+v", reason, results)
	return projection.SARIFResult{}
}
