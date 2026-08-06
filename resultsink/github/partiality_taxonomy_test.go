package github_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// ---------------------------------------------------------------------------
// The partiality taxonomy: inherent limits are disclosed QUIETLY, steps that did
// not run are disclosed LOUDLY.
//
// The case that motivated the split: goanalysis/reach.go declares reflection +
// dynamic_dispatch whenever govulncheck reports the vuln present but finds no
// reachable trace — which is the common not_exploitable path. Once those reasons
// reached the Report, every real Go scan started headlining "Partial coverage",
// and a qualifier that fires on every run can no longer mark the runs where the
// analyzer was missing or a tool failed.
// ---------------------------------------------------------------------------

// The footer label and one of its sentences: the quiet arm must be PRESENT and
// readable, never suppressed.
const (
	limitsFooterLabel = "Analysis limits"
	reflectionCopy    = "calls made through reflection are not visible to static analysis"
)

// goScanReport is a real Go scan's shape: one grounded-safe finding, and the
// reflection + dynamic_dispatch limits the reachability reconciler declares on
// exactly that path.
func goScanReport(extra ...report.PartialityNote) report.Report {
	pkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7"}
	return report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		NotExploitable(report.Advisory{ID: "GO-2021-0113", Source: "osv"}, &pkg, verdict.BasisSymbolAbsent, "no reachable path to the advisory symbol").
		AddPartiality(report.PartialityNote{Reason: "reflection", Ecosystem: "Go"}).
		AddPartiality(report.PartialityNote{Reason: "dynamic_dispatch", Ecosystem: "Go"}).
		AddPartiality(extra...).
		WithProvenance(report.Provenance{CommitSHA: "abc123", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).
		Build()
}

// The clean-scan headline for the one-finding Go fixture. A scan whose only limits
// are inherent must emit this VERBATIM.
const goCleanHeadline = "**No reachable candidates.** 1 advisory finding(s) are grounded-safe (1 not exploitable, 0 disqualified)."

// AC — THE motivating case. A Go scan whose only partiality is reflection and
// dynamic dispatch reads clean in the headline, and carries its limits in the footer.
func TestBothSurfaces_InherentLimitsOnly_HeadlineCleanFooterPresent(t *testing.T) {
	for name, s := range bothSurfaces(t, goScanReport()) {
		if !strings.Contains(s, goCleanHeadline) {
			t.Errorf("%s: an inherent-limits-only scan must keep the unqualified headline %q\n---\n%s", name, goCleanHeadline, s)
		}
		for _, unwanted := range []string{"Partial coverage", wantHeadlineTail} {
			if strings.Contains(s, unwanted) {
				t.Errorf("%s: methodology must not fire the loud qualifier, found %q\n---\n%s", name, unwanted, s)
			}
		}
		// Quiet, but never absent.
		for _, want := range []string{limitsFooterLabel, reflectionCopy, "dynamic dispatch could not be narrowed"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s: limits footer missing %q — quiet is not suppression\n---\n%s", name, want, s)
			}
		}
		// And it sits BELOW the results: it qualifies nothing above it.
		if i, j := strings.Index(s, limitsFooterLabel), strings.Index(s, "| Verdict | Count |"); i < 0 || j < 0 || i < j {
			t.Errorf("%s: the limits footer must follow the counts table (footer@%d, table@%d)\n---\n%s", name, i, j, s)
		}
	}
}

// AC — the loud arm is untouched. A missing analyzer, a failed tool and an
// unreadable manifest still qualify the headline exactly as task 02 made them.
// "reachability_undetermined" (B-1) belongs in this list, not the inherent-limit
// fixture above: an undetermined result is specific to THIS run, not the method.
func TestBothSurfaces_DidNotRunReasons_StillQualifyHeadline(t *testing.T) {
	for _, reason := range []string{"no_language_plugin", "tool_failure", "no_manifest", "unsupported_phase1", "no_known_ingress", "cgo", "reachability_undetermined"} {
		r := goScanReport(report.PartialityNote{Reason: reason, Ecosystem: "Go"})
		for name, s := range bothSurfaces(t, r) {
			if strings.Contains(s, goCleanHeadline) {
				t.Errorf("%s/%s: emitted the unqualified clean headline on a run that skipped a step\n---\n%s", name, reason, s)
			}
			for _, want := range []string{"**Partial coverage — no reachable candidates in what was assessed.**", wantHeadlineTail, disclosureHeading} {
				if !strings.Contains(s, want) {
					t.Errorf("%s/%s: missing %q\n---\n%s", name, reason, want, s)
				}
			}
		}
	}
}

// AC — an unrecognized reason code renders LOUD. Defaulting the unknown to the quiet
// arm would let a genuine failure hide behind a taxonomy gap, which is the same silent
// clean scan by another route.
func TestBothSurfaces_UnknownReasonCode_RendersLoud(t *testing.T) {
	r := goScanReport(report.PartialityNote{Reason: "future_reason_code", Ecosystem: "Go"})
	for name, s := range bothSurfaces(t, r) {
		for _, want := range []string{disclosureHeading, wantHeadlineTail, "`future_reason_code`"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s: an unrecognized reason must render loud; missing %q\n---\n%s", name, want, s)
			}
		}
		// And it must not have been filed under methodology instead.
		if i := strings.Index(s, limitsFooterLabel); i >= 0 && strings.Contains(s[i:], "future_reason_code") {
			t.Errorf("%s: an unrecognized reason was rendered as an inherent limit\n---\n%s", name, s)
		}
	}
}

// A note whose Class was never stamped — a Report from a writer that predates the
// field, or one assembled without the Builder — must still render loud. The default
// lives in EffectiveClass, not in the stamping, so it survives a bypassed builder.
func TestBothSurfaces_UnstampedNote_RendersLoud(t *testing.T) {
	r := goScanReport()
	r.Partiality = append(r.Partiality, report.PartialityNote{Reason: "no_manifest", Ecosystem: "Go"})

	for name, s := range bothSurfaces(t, r) {
		if !strings.Contains(s, disclosureHeading) || !strings.Contains(s, wantHeadlineTail) {
			t.Errorf("%s: a note with no Class must render loud\n---\n%s", name, s)
		}
	}
}

// A note a writer explicitly classified as inherent is honoured as inherent, even
// under a reason code this build does not know. Carrying the arm on the note is the
// point: a newer producer can classify its own limit without a reader release.
func TestBothSurfaces_ExplicitInherentClass_RendersQuiet(t *testing.T) {
	r := goScanReport(report.PartialityNote{Reason: "future_limit_code", Ecosystem: "Go", Class: report.PartialityInherentLimit})

	for name, s := range bothSurfaces(t, r) {
		if strings.Contains(s, disclosureHeading) || strings.Contains(s, wantHeadlineTail) {
			t.Errorf("%s: an explicitly-inherent note must not fire the qualifier\n---\n%s", name, s)
		}
		if !strings.Contains(s, "`future_limit_code`") {
			t.Errorf("%s: an unrecognized inherent limit must still be stated verbatim\n---\n%s", name, s)
		}
	}
}

// The two arms are independent: a scan carrying both discloses both, each in its own
// place, and the headline follows the loud one.
func TestBothSurfaces_MixedArms_LoudAboveQuietBelow(t *testing.T) {
	r := goScanReport(report.PartialityNote{Reason: "no_language_plugin", Ecosystem: "Go"})

	for name, s := range bothSurfaces(t, r) {
		loud, quiet := strings.Index(s, disclosureHeading), strings.Index(s, limitsFooterLabel)
		if loud < 0 {
			t.Errorf("%s: the did-not-run arm is missing\n---\n%s", name, s)
		}
		if quiet < 0 {
			t.Errorf("%s: the inherent arm is missing\n---\n%s", name, s)
		}
		if loud >= 0 && quiet >= 0 && loud > quiet {
			t.Errorf("%s: the did-not-run disclosure must precede the limits footer\n---\n%s", name, s)
		}
		if !strings.Contains(s, wantHeadlineTail) {
			t.Errorf("%s: a mixed scan's headline follows the loud arm\n---\n%s", name, s)
		}
	}
}

// UNIFORM. The same reason may not be loud on one surface and quiet on another —
// the Tier-0 panel and the Tier-1 body disclose the same arms, from the same helpers.
func TestBothSurfaces_ArmsAgree(t *testing.T) {
	for _, r := range []report.Report{
		goScanReport(),
		goScanReport(report.PartialityNote{Reason: "no_manifest", Ecosystem: "Go"}),
		goScanReport(report.PartialityNote{Reason: "future_reason_code"}),
	} {
		s := bothSurfaces(t, r)
		t0, t1 := s["Tier-0"], s["Tier-1"]
		for _, probe := range []string{disclosureHeading, limitsFooterLabel, wantHeadlineTail, reflectionCopy} {
			// Tier-1 quotes its loud block inside a [!NOTE] callout, so match on the
			// bare sentence, which both surfaces carry either way.
			if strings.Contains(t0, probe) != strings.Contains(t1, probe) {
				t.Errorf("surfaces disagree on %q: Tier-0=%v Tier-1=%v\n--- Tier-0 ---\n%s\n--- Tier-1 ---\n%s",
					probe, strings.Contains(t0, probe), strings.Contains(t1, probe), t0, t1)
			}
		}
	}
}

// A clean scan is still silent on both arms — the guarantee the whole disclosure
// rests on.
func TestBothSurfaces_CleanScan_NoLimitsFooter(t *testing.T) {
	for name, s := range bothSurfaces(t, cleanReport()) {
		if strings.Contains(s, limitsFooterLabel) {
			t.Errorf("%s: a scan with nothing to disclose must render no limits footer\n---\n%s", name, s)
		}
	}
}

// Annotations are out of scope for the taxonomy exactly as they are for the
// disclosure: they only MARK candidates, so silence there asserts nothing.
func TestTaxonomy_DoesNotChangeAnnotations(t *testing.T) {
	annotationsFor := func(r report.Report) string {
		var buf bytes.Buffer
		sink := &ghsink.Tier0Summary{Annotations: &buf}
		if err := sink.Publish(context.Background(), resultsink.Result{Report: r}); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		return buf.String()
	}
	base := annotationsFor(goScanReport())
	for _, r := range []report.Report{
		goScanReport(report.PartialityNote{Reason: "no_manifest", Ecosystem: "Go"}),
		goScanReport(report.PartialityNote{Reason: "future_reason_code"}),
	} {
		if got := annotationsFor(r); got != base {
			t.Errorf("annotations changed with the arm:\n--- with ---\n%s\n--- base ---\n%s", got, base)
		}
	}
}

// DISCLOSURE ONLY. Everything from the counts table to the end of the candidate rows
// is byte-identical with and without the inherent limits — the footer adds a section,
// it never moves a verdict or a count.
func TestInherentLimits_LeaveCountsAndVerdictsIdentical(t *testing.T) {
	pkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7"}
	clean := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		NotExploitable(report.Advisory{ID: "GO-2021-0113", Source: "osv"}, &pkg, verdict.BasisSymbolAbsent, "no reachable path to the advisory symbol").
		WithProvenance(report.Provenance{CommitSHA: "abc123", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).
		Build()

	countsThroughResults := func(s string) string {
		i := strings.Index(s, "| Verdict | Count |")
		if i < 0 {
			t.Fatalf("no counts table in:\n%s", s)
		}
		s = s[i:]
		if j := strings.Index(s, "<details>"); j >= 0 {
			s = s[:j]
		}
		return strings.TrimSpace(s)
	}

	c, p := bothSurfaces(t, clean), bothSurfaces(t, goScanReport())
	for surface := range c {
		if got, want := countsThroughResults(p[surface]), countsThroughResults(c[surface]); got != want {
			t.Errorf("%s: the limits footer moved a count or a verdict\n--- with ---\n%s\n--- without ---\n%s", surface, got, want)
		}
	}

	// And at the source: the notes changed nothing about the findings.
	withLimits := goScanReport()
	if len(clean.Advisories) != len(withLimits.Advisories) {
		t.Fatalf("finding count changed: %d vs %d", len(clean.Advisories), len(withLimits.Advisories))
	}
	for i := range clean.Advisories {
		if clean.Advisories[i].Verdict != withLimits.Advisories[i].Verdict {
			t.Errorf("advisory %d verdict changed: %q vs %q", i, clean.Advisories[i].Verdict, withLimits.Advisories[i].Verdict)
		}
	}
}
