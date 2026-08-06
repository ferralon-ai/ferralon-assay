// undetermined_disclosure_test.go
//
// The GitHub surfaces are where an `undetermined` row is most dangerous, because they do not list
// every finding — they render a HEADLINE and a counts table, and a skimming reader stops at the
// headline. Before this change `tally` recognized three verdicts, so a report whose every advisory
// was unassessed rendered as "**No advisory findings.**": the silent clean scan the whole cycle
// exists to remove, restated on the most-read line of the product.
//
// These tests pin that (a) an unassessed advisory is counted and named, (b) it never joins the
// grounded-safe count, and (c) a fully-resolved scan's panel is unchanged — a disclosure that
// appears on every run carries no signal.
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

// allUndeterminedReport is the disposition for a subject whose toolchain floor
// sits inside every affected range: four toolchain advisories, no verdict for any of them, one
// disclosed limit. Nothing was found and nothing was refuted.
func allUndeterminedReport() report.Report {
	b := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"})
	for _, id := range []string{"CVE-2023-39325", "CVE-2023-45283", "CVE-2024-24790", "GO-2021-0264"} {
		b.Undetermined(report.Advisory{ID: id, Source: "corpus"}, nil, report.ReasonGoToolchainNotScanned)
	}
	return b.AddPartiality(report.PartialityNote{Reason: report.ReasonGoToolchainNotScanned, Ecosystem: "Go"}).
		WithProvenance(report.Provenance{CommitSHA: "abc123", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).
		Build()
}

// mixedUndeterminedReport is the commoner shape: real verdicts alongside one unassessed advisory.
func mixedUndeterminedReport() report.Report {
	pkg := report.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	return report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		NotExploitable(report.Advisory{ID: "CVE-2021-23337", Source: "nvd"}, &pkg, verdict.BasisSymbolAbsent, "vulnerable symbol absent").
		Disqualified(report.Advisory{ID: "CVE-2020-0001", Source: "nvd"}, &pkg, verdict.BasisVersionNotAffected, "resolved version below first affected").
		Undetermined(report.Advisory{ID: "GO-2021-0264", Source: "corpus"}, nil, report.ReasonGoToolchainUnresolved).
		AddPartiality(report.PartialityNote{Reason: report.ReasonGoToolchainUnresolved, Ecosystem: "Go"}).
		WithProvenance(report.Provenance{CommitSHA: "abc123", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).
		Build()
}

// TestSinks_AllUndeterminedScanNeverReadsAsNoFindings is the regression this file exists for. It
// asserts the negative directly, because the failure mode is a string that looks entirely reasonable.
func TestSinks_AllUndeterminedScanNeverReadsAsNoFindings(t *testing.T) {
	r := allUndeterminedReport()
	for surface, body := range map[string]string{
		"Tier-0": renderedTier0Summary(t, r),
		"Tier-1": renderedTier1Body(t, resultsink.Result{Report: r}),
	} {
		if strings.Contains(body, "**No advisory findings.**") {
			t.Errorf("%s reads as a clean scan on a run that established nothing\n---\n%s", surface, body)
		}
		for _, want := range []string{
			"No verdict was established for any of the 4 advisories evaluated.",
			"This run is not a complete assessment of the codebase.",
			"| Not assessed (no verdict established) | 4 |",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s missing %q\n---\n%s", surface, want, body)
			}
		}
	}
}

// TestSinks_UndeterminedNeverJoinsTheGroundedSafeCount is the arithmetic half of the same honesty
// property: "N advisory finding(s) are grounded-safe" must count refutations only. Folding an
// unassessed advisory in there would be the original defect expressed as a number.
func TestSinks_UndeterminedNeverJoinsTheGroundedSafeCount(t *testing.T) {
	r := mixedUndeterminedReport()
	for surface, body := range map[string]string{
		"Tier-0": renderedTier0Summary(t, r),
		"Tier-1": renderedTier1Body(t, resultsink.Result{Report: r}),
	} {
		if !strings.Contains(body, "2 advisory finding(s) are grounded-safe (1 not exploitable, 1 disqualified, 1 not assessed)") {
			t.Errorf("%s does not count 2 grounded-safe and disclose 1 unassessed\n---\n%s", surface, body)
		}
		if strings.Contains(body, "3 advisory finding(s) are grounded-safe") {
			t.Errorf("%s folded the unassessed advisory into the grounded-safe count\n---\n%s", surface, body)
		}
		if !strings.Contains(body, "| Not assessed (no verdict established) | 1 |") {
			t.Errorf("%s counts table omits the unassessed row\n---\n%s", surface, body)
		}
	}
}

// TestSinks_CandidateHeadlineStillDisclosesUnassessed covers the arm a reader is most likely to act
// on: a candidate was found, and the parenthetical that follows must not imply the rest was cleared.
func TestSinks_CandidateHeadlineStillDisclosesUnassessed(t *testing.T) {
	pkg := report.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	r := report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		ReachableCandidate(report.Advisory{ID: "CVE-2021-23337", Source: "nvd"}, &pkg, "handler → sink", "").
		Undetermined(report.Advisory{ID: "GO-2021-0264", Source: "corpus"}, nil, report.ReasonGoToolchainNotScanned).
		AddPartiality(report.PartialityNote{Reason: report.ReasonGoToolchainNotScanned, Ecosystem: "Go"}).
		WithProvenance(report.Provenance{CommitSHA: "abc123", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).
		Build()

	body := renderedTier0Summary(t, r)
	if !strings.Contains(body, "(0 not exploitable, 0 disqualified, 1 not assessed.)") {
		t.Errorf("candidate headline does not disclose the unassessed advisory\n---\n%s", body)
	}
	if !strings.Contains(body, "This run is not a complete assessment of the codebase.") {
		t.Errorf("candidate headline is not qualified\n---\n%s", body)
	}
}

// TestSinks_FullyResolvedScanPanelIsUnchanged is the silence guarantee, and it is what makes the
// counts row load-bearing rather than decorative: it appears only when something was unassessed.
func TestSinks_FullyResolvedScanPanelIsUnchanged(t *testing.T) {
	for surface, body := range map[string]string{
		"Tier-0": renderedTier0Summary(t, cleanReport()),
		"Tier-1": renderedTier1Body(t, resultsink.Result{Report: cleanReport()}),
	} {
		if strings.Contains(body, "not assessed") {
			t.Errorf("%s mentions unassessed advisories on a fully-resolved scan\n---\n%s", surface, body)
		}
		if !strings.Contains(body, "**No reachable candidates.** 2 advisory finding(s) are grounded-safe (1 not exploitable, 1 disqualified).") {
			t.Errorf("%s headline changed on a scan with nothing to disclose\n---\n%s", surface, body)
		}
	}
}

// TestSinks_UndeterminedIsNotAnnotated keeps the ::warning:: channel meaning what it says. An
// annotation is an action item pinned to a line of code; an unassessed advisory has no line and no
// action beyond configuring the scan, and annotating it would train readers to ignore the channel.
func TestSinks_UndeterminedIsNotAnnotated(t *testing.T) {
	var annotations bytes.Buffer
	sink := &ghsink.Tier0Summary{Annotations: &annotations}
	if err := sink.Publish(context.Background(), resultsink.Result{Report: allUndeterminedReport()}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if annotations.Len() != 0 {
		t.Errorf("undetermined findings emitted annotations:\n%s", annotations.String())
	}
}
