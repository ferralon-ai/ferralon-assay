package report_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
)

func partialityBuilder() *report.Builder {
	return report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"})
}

// The load-bearing case: a scan with ZERO findings that could not resolve its
// dependencies must still be distinguishable from a genuinely clean one.
func TestPartiality_SurvivesAZeroFindingReport(t *testing.T) {
	r := partialityBuilder().
		AddPartiality(report.PartialityNote{Reason: "no_manifest", Ecosystem: "npm"}).
		Build()

	if len(r.Advisories) != 0 {
		t.Fatalf("fixture should have no findings, got %d", len(r.Advisories))
	}
	if len(r.Partiality) != 1 || r.Partiality[0].Reason != "no_manifest" {
		t.Fatalf("Partiality = %+v, want one no_manifest note", r.Partiality)
	}
}

// Callers add one note per assessment, so the same limit arrives once per advisory.
// The customer must read it once.
func TestPartiality_DeduplicatedAndStablySorted(t *testing.T) {
	r := partialityBuilder().
		AddPartiality(report.PartialityNote{Reason: "no_manifest", Ecosystem: "npm"}).
		AddPartiality(report.PartialityNote{Reason: "no_manifest", Ecosystem: "npm"}).
		AddPartiality(report.PartialityNote{Reason: "tool_failure", Ecosystem: "PyPI"}).
		AddPartiality(report.PartialityNote{Reason: "no_manifest", Ecosystem: "Maven"}).
		Build()

	// Class is stamped by AddPartiality, so it is part of the built note (and of the
	// de-duplication key): two producers of the same reason must classify it the same
	// way or the customer reads one limit twice.
	want := []report.PartialityNote{
		{Reason: "no_manifest", Ecosystem: "Maven", Class: report.PartialityDidNotRun},
		{Reason: "no_manifest", Ecosystem: "npm", Class: report.PartialityDidNotRun},
		{Reason: "tool_failure", Ecosystem: "PyPI", Class: report.PartialityDidNotRun},
	}
	if len(r.Partiality) != len(want) {
		t.Fatalf("Partiality = %+v, want %+v", r.Partiality, want)
	}
	for i := range want {
		if !reflect.DeepEqual(r.Partiality[i], want[i]) {
			t.Errorf("Partiality[%d] = %+v, want %+v", i, r.Partiality[i], want[i])
		}
	}
}

// assessFailureNote (trigger/assess.go) mints one tool_failure note per failed
// advisory, differing ONLY in Detail (the failed step + the advisory id). Before the dedup key
// widened from {Reason, Ecosystem} to {Reason, Ecosystem, Detail} (the narrower key main's
// gotoolchain work carried, keyed for unioning Advisories under a shared limit), N such
// disclosures silently collapsed to one, keeping only the first advisory's Detail — dropping
// exactly the per-advisory disclosure the wider key exists to preserve. Widening a dedup key can only add
// disclosures, never remove one, so this direction needed no design sign-off.
func TestPartiality_DistinctDetailStaysDistinctDisclosures(t *testing.T) {
	r := partialityBuilder().
		AddPartiality(report.PartialityNote{Reason: "tool_failure", Detail: "assess (GHSA-1111)"}).
		AddPartiality(report.PartialityNote{Reason: "tool_failure", Detail: "assess (GHSA-2222)"}).
		AddPartiality(report.PartialityNote{Reason: "tool_failure", Detail: "assess (GHSA-3333)"}).
		Build()

	if len(r.Partiality) != 3 {
		t.Fatalf("got %d tool_failure disclosures, want 3 (one per failed advisory): %+v", len(r.Partiality), r.Partiality)
	}
	seen := map[string]bool{}
	for _, n := range r.Partiality {
		if n.Reason != "tool_failure" {
			t.Errorf("unexpected reason %q in %+v", n.Reason, r.Partiality)
		}
		seen[n.Detail] = true
	}
	for _, want := range []string{"assess (GHSA-1111)", "assess (GHSA-2222)", "assess (GHSA-3333)"} {
		if !seen[want] {
			t.Errorf("missing disclosure for %q; Partiality = %+v", want, r.Partiality)
		}
	}
}

// An unnamed limit renders as nothing, which is worse than silence — drop it.
func TestPartiality_EmptyReasonDropped(t *testing.T) {
	r := partialityBuilder().AddPartiality(report.PartialityNote{Ecosystem: "npm"}).Build()
	if len(r.Partiality) != 0 {
		t.Fatalf("a note with no reason must be dropped, got %+v", r.Partiality)
	}
}

// Silence is the clean-scan signal: the field must be absent from the wire, so a
// reader (and the renderers) can treat presence as meaningful.
func TestPartiality_OmittedFromJSONWhenClean(t *testing.T) {
	b, err := json.Marshal(partialityBuilder().Build())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "partiality") {
		t.Errorf("a clean Report must omit the partiality field entirely:\n%s", b)
	}
}

// The Report round-trips losslessly; the additive field must not break that.
func TestPartiality_RoundTrips(t *testing.T) {
	orig := partialityBuilder().
		AddPartiality(report.PartialityNote{Reason: "no_manifest", Ecosystem: "npm"}).
		AddPartiality(report.PartialityNote{Reason: "unsupported_phase1"}).
		Build()

	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back report.Report
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.Partiality) != len(orig.Partiality) {
		t.Fatalf("round-trip Partiality = %+v, want %+v", back.Partiality, orig.Partiality)
	}
	for i := range orig.Partiality {
		if !reflect.DeepEqual(back.Partiality[i], orig.Partiality[i]) {
			t.Errorf("round-trip Partiality[%d] = %+v, want %+v", i, back.Partiality[i], orig.Partiality[i])
		}
	}
	if back.Partiality[1].Ecosystem != "" {
		t.Errorf("a scan-wide note must round-trip with an empty ecosystem, got %q", back.Partiality[1].Ecosystem)
	}
}

// Disclosure is not a verdict: a partial Report with valid findings still validates,
// and Validate has nothing to say about the notes.
func TestPartiality_DoesNotAffectValidation(t *testing.T) {
	pkg := report.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	r := partialityBuilder().
		ReachableCandidate(report.Advisory{ID: "CVE-2021-23337", Source: "nvd"}, &pkg, "app.handler → lodash.template", "candidate").
		AddPartiality(report.PartialityNote{Reason: "no_manifest", Ecosystem: "npm"}).
		Build()
	if err := r.Validate(); err != nil {
		t.Fatalf("a partial Report with valid findings must validate: %v", err)
	}
}
