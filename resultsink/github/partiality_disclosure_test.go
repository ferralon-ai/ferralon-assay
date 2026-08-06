package github_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// The sentence fragment both surfaces must carry for a no-lockfile scan. It is the
// whole point of the field: a customer reading a GREEN run must be able to tell that
// their npm dependencies were NOT pinned, and therefore not fully assessed.
const wantNoManifestCopy = "Installed npm dependency versions could not be pinned: no lockfile or pinned-version manifest was found."

// The line every disclosure is introduced by; its ABSENCE is the clean-scan signal.
const disclosureHeading = "**Partial coverage.**"

// noManifestReport is the shape the F8 degrade produces on a real repo that commits no
// lockfile: a GREEN scan whose findings are grounded-safe, and which would be
// byte-indistinguishable from a genuinely clean scan without the partiality note.
func noManifestReport() report.Report {
	return partialReport(report.PartialityNote{Reason: "no_manifest", Ecosystem: "npm"})
}

// cleanReport is the same scan with nothing to disclose — the control.
func cleanReport() report.Report { return partialReport() }

func partialReport(notes ...report.PartialityNote) report.Report {
	pkg := report.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	return report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		NotExploitable(report.Advisory{ID: "CVE-2021-23337", Source: "nvd"}, &pkg, verdict.BasisSymbolAbsent, "vulnerable symbol absent").
		Disqualified(report.Advisory{ID: "CVE-2020-0001", Source: "nvd"}, &pkg, verdict.BasisVersionNotAffected, "resolved version below first affected").
		AddPartiality(notes...).
		WithProvenance(report.Provenance{CommitSHA: "abc123", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).
		Build()
}

// renderedTier0Summary publishes r to a temp step-summary file and returns the GFM.
func renderedTier0Summary(t *testing.T, r report.Report) string {
	t.Helper()
	summaryPath := filepath.Join(t.TempDir(), "summary.md")
	sink := &ghsink.Tier0Summary{SummaryPath: summaryPath, Annotations: io.Discard}
	if err := sink.Publish(context.Background(), resultsink.Result{Report: r}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	b, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	return string(b)
}

// AC — a no-manifest scan is disclosed on the primary customer surface (the Actions
// job-summary panel).
func TestTier0_NoManifestScan_DisclosesPartialCoverage(t *testing.T) {
	s := renderedTier0Summary(t, noManifestReport())

	for _, want := range []string{disclosureHeading, wantNoManifestCopy, "not a complete dependency assessment"} {
		if !strings.Contains(s, want) {
			t.Errorf("Tier-0 summary missing %q\n---\n%s", want, s)
		}
	}
	// The disclosure qualifies the counts, so it must precede them.
	if i, j := strings.Index(s, disclosureHeading), strings.Index(s, "| Verdict | Count |"); i < 0 || j < 0 || i > j {
		t.Errorf("disclosure must precede the counts table (disclosure@%d, table@%d)\n---\n%s", i, j, s)
	}
}

// AC — and on the shared Tier-1 body, which feeds both the pinned Issue and the sticky
// PR comment.
func TestTier1_NoManifestScan_DisclosesPartialCoverage(t *testing.T) {
	body := renderedTier1Body(t, resultsink.Result{Report: noManifestReport()})

	for _, want := range []string{"> [!NOTE]", "> " + disclosureHeading, wantNoManifestCopy} {
		if !strings.Contains(body, want) {
			t.Errorf("Tier-1 body missing %q\n---\n%s", want, body)
		}
	}
}

// The silence-when-clean guarantee. A disclosure that renders on every run carries no
// signal, so a fully-resolved scan must show nothing at all on either surface.
func TestBothSurfaces_CleanScan_RenderNoDisclosure(t *testing.T) {
	surfaces := map[string]string{
		"Tier-0": renderedTier0Summary(t, cleanReport()),
		"Tier-1": renderedTier1Body(t, resultsink.Result{Report: cleanReport()}),
	}
	for name, s := range surfaces {
		for _, unwanted := range []string{disclosureHeading, "Partial coverage", "could not be pinned", "could not fully resolve"} {
			if strings.Contains(s, unwanted) {
				t.Errorf("%s: a clean scan must render no disclosure, found %q\n---\n%s", name, unwanted, s)
			}
		}
	}
}

// DISCLOSURE ONLY. Every verdict, count and candidate row must be byte-identical with
// and without the partiality note — if this test fails, the change stopped being a
// disclosure and started being a behaviour change.
func TestDisclosure_LeavesVerdictsAndCountsByteIdentical(t *testing.T) {
	stripDisclosure := func(s string) string {
		var kept []string
		for _, line := range strings.Split(s, "\n") {
			// The headline is disclosure-bearing too: with partiality present it names
			// the coverage limit rather than summarizing the run as clean. It is
			// stripped alongside the block for the same reason — it is the disclosure,
			// not the data. What it summarizes (the counts, the candidate rows, the
			// verdicts) is compared below and pinned byte-for-byte by
			// TestPartialityHeadline_LeavesCountsAndVerdictsIdentical.
			if isHeadlineLine(line) ||
				strings.HasPrefix(line, disclosureHeading) ||
				strings.HasPrefix(line, "- Installed") ||
				strings.HasPrefix(line, "> [!NOTE]") ||
				strings.HasPrefix(line, "> "+disclosureHeading) ||
				strings.HasPrefix(line, "> - Installed") ||
				line == ">" {
				continue
			}
			kept = append(kept, line)
		}
		return strings.Join(kept, "\n")
	}

	for name, pair := range map[string][2]string{
		"Tier-0": {renderedTier0Summary(t, cleanReport()), renderedTier0Summary(t, noManifestReport())},
		"Tier-1": {
			renderedTier1Body(t, resultsink.Result{Report: cleanReport()}),
			renderedTier1Body(t, resultsink.Result{Report: noManifestReport()}),
		},
	} {
		// Stripped on BOTH sides: the headline is one of the disclosure-bearing lines
		// now, so the clean render's own headline comes out too. What remains is
		// exactly the data — heading, provenance, counts, candidate rows.
		clean, partial := stripDisclosure(pair[0]), stripDisclosure(pair[1])
		// The disclosure block is followed by a blank separator line; normalize it away.
		if got, want := strings.TrimSpace(collapseBlankRuns(partial)), strings.TrimSpace(collapseBlankRuns(clean)); got != want {
			t.Errorf("%s: disclosure changed more than the disclosure\n--- with (stripped) ---\n%s\n--- without ---\n%s", name, got, want)
		}
	}

	// And the verdict data itself is untouched at the source.
	c, p := cleanReport(), noManifestReport()
	if len(c.Advisories) != len(p.Advisories) {
		t.Fatalf("finding count changed: %d vs %d", len(c.Advisories), len(p.Advisories))
	}
	for i := range c.Advisories {
		if c.Advisories[i].Verdict != p.Advisories[i].Verdict {
			t.Errorf("advisory %d verdict changed: %q vs %q", i, c.Advisories[i].Verdict, p.Advisories[i].Verdict)
		}
	}
}

// Tier-0 annotations are the fail/pass-adjacent surface; a disclosure must not add or
// remove a single one.
func TestDisclosure_DoesNotChangeAnnotations(t *testing.T) {
	annotationsFor := func(r report.Report) string {
		var buf bytes.Buffer
		sink := &ghsink.Tier0Summary{Annotations: &buf}
		if err := sink.Publish(context.Background(), resultsink.Result{Report: r}); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		return buf.String()
	}
	if got, want := annotationsFor(noManifestReport()), annotationsFor(cleanReport()); got != want {
		t.Errorf("annotations changed:\n--- with ---\n%s\n--- without ---\n%s", got, want)
	}
}

// The reason vocabulary is OPEN. An unrecognized code must be disclosed verbatim, not
// dropped — dropping it restores exactly the silent-clean-scan failure the field exists
// to prevent.
func TestDisclosure_UnknownReasonCode_StillDisclosed(t *testing.T) {
	r := partialReport(report.PartialityNote{Reason: "future_reason_code", Ecosystem: "PyPI"})

	for name, s := range map[string]string{
		"Tier-0": renderedTier0Summary(t, r),
		"Tier-1": renderedTier1Body(t, resultsink.Result{Report: r}),
	} {
		if !strings.Contains(s, "`future_reason_code`") {
			t.Errorf("%s must disclose an unrecognized reason code verbatim\n---\n%s", name, s)
		}
		if !strings.Contains(s, "PyPI dependency") {
			t.Errorf("%s must scope the disclosure to the ecosystem\n---\n%s", name, s)
		}
	}
}

// ---------------------------------------------------------------------------
// B1 — the headline may not summarize a partial run as clean or safe.
//
// The disclosure block is scan-level and sits below the headline; the safety claim a
// customer actually reads is the headline itself. A reader who stops at "**No
// reachable candidates.** … grounded-safe" has been told something stronger than a
// run that could not pin its dependency versions can support.
// ---------------------------------------------------------------------------

// The exact clean-scan headline for the two-finding fixture. Its ABSENCE is what B1
// buys on a partial scan; its byte-identical presence on a clean scan is the
// silent-when-clean guarantee.
const cleanGroundedSafeHeadline = "**No reachable candidates.** 2 advisory finding(s) are grounded-safe (1 not exploitable, 1 disqualified)."

// The qualifier a partiality-present headline carries on every branch.
const wantHeadlineTail = "This run is not a complete assessment of the codebase."

// emptyReport is the zero-finding scan — the case where a bare "**No advisory
// findings.**" reads most like a clean bill of health.
func emptyReport(notes ...report.PartialityNote) report.Report {
	return report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		AddPartiality(notes...).
		WithProvenance(report.Provenance{CommitSHA: "abc123", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).
		Build()
}

// candidateReport is the scan that already reads as "not clean" in the headline — the
// qualifier still belongs, because the counts it reports are a floor.
func candidateReport(notes ...report.PartialityNote) report.Report {
	pkg := report.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	return report.NewBuilder(report.Subject{Repo: "github.com/example/widget", ResolvedCommit: "abc123"}).
		ReachableCandidate(report.Advisory{ID: "CVE-2019-10744", Source: "nvd"}, &pkg, "handler → defaultsDeep", "reachable").
		NotExploitable(report.Advisory{ID: "CVE-2021-23337", Source: "nvd"}, &pkg, verdict.BasisSymbolAbsent, "vulnerable symbol absent").
		AddPartiality(notes...).
		WithProvenance(report.Provenance{CommitSHA: "abc123", AnalyzerVersion: "v0.2.0", Timestamp: time.Unix(0, 0).UTC()}).
		Build()
}

func bothSurfaces(t *testing.T, r report.Report) map[string]string {
	t.Helper()
	return map[string]string{
		"Tier-0": renderedTier0Summary(t, r),
		"Tier-1": renderedTier1Body(t, resultsink.Result{Report: r}),
	}
}

// AC — a partial scan with only grounded-safe findings must not headline as safe.
func TestBothSurfaces_PartialScan_HeadlineDoesNotClaimSafety(t *testing.T) {
	for name, s := range bothSurfaces(t, noManifestReport()) {
		if strings.Contains(s, cleanGroundedSafeHeadline) {
			t.Errorf("%s: partial scan emitted the unqualified clean headline %q\n---\n%s", name, cleanGroundedSafeHeadline, s)
		}
		for _, want := range []string{"**Partial coverage — no reachable candidates in what was assessed.**", wantHeadlineTail} {
			if !strings.Contains(s, want) {
				t.Errorf("%s: headline missing %q\n---\n%s", name, want, s)
			}
		}
		// The counts themselves are still reported, unchanged, in the headline.
		if !strings.Contains(s, "2 advisory finding(s) are grounded-safe (1 not exploitable, 1 disqualified)") {
			t.Errorf("%s: headline dropped its counts\n---\n%s", name, s)
		}
	}
}

// AC — and the zero-finding case, where "no findings" reads most like all-clear.
func TestBothSurfaces_PartialScan_ZeroFindings_HeadlineDoesNotClaimClean(t *testing.T) {
	partial := emptyReport(report.PartialityNote{Reason: "no_manifest", Ecosystem: "npm"})
	for name, s := range bothSurfaces(t, partial) {
		if strings.Contains(s, "**No advisory findings.**") {
			t.Errorf("%s: partial zero-finding scan emitted the unqualified clean headline\n---\n%s", name, s)
		}
		for _, want := range []string{"**Partial coverage — no advisory findings in what was assessed.**", wantHeadlineTail} {
			if !strings.Contains(s, want) {
				t.Errorf("%s: headline missing %q\n---\n%s", name, want, s)
			}
		}
	}
}

// AC — a candidate-bearing partial scan keeps its count verbatim and gains only the
// qualifier.
func TestBothSurfaces_PartialScan_WithCandidates_HeadlineKeepsCountsAndQualifies(t *testing.T) {
	partial := candidateReport(report.PartialityNote{Reason: "no_manifest", Ecosystem: "npm"})
	for name, s := range bothSurfaces(t, partial) {
		if !strings.Contains(s, "**1 reachable candidate(s)** found — review below. (1 not exploitable, 0 disqualified.) "+wantHeadlineTail) {
			t.Errorf("%s: candidate headline must keep its counts verbatim and append only the qualifier\n---\n%s", name, s)
		}
	}
}

// SILENT WHEN CLEAN. With nothing to disclose the headline must be byte-identical to
// what it has always been — on both the grounded-safe and the zero-finding branch.
func TestBothSurfaces_CleanScan_HeadlineByteIdentical(t *testing.T) {
	for name, s := range bothSurfaces(t, cleanReport()) {
		if !strings.Contains(s, cleanGroundedSafeHeadline) {
			t.Errorf("%s: clean headline changed; want %q\n---\n%s", name, cleanGroundedSafeHeadline, s)
		}
	}
	for name, s := range bothSurfaces(t, emptyReport()) {
		if !strings.Contains(s, "**No advisory findings.**") {
			t.Errorf("%s: clean zero-finding headline changed\n---\n%s", name, s)
		}
	}
	for name, s := range bothSurfaces(t, candidateReport()) {
		if !strings.Contains(s, "**1 reachable candidate(s)** found — review below. (1 not exploitable, 0 disqualified.)\n") {
			t.Errorf("%s: clean candidate headline changed\n---\n%s", name, s)
		}
	}
	for name, s := range bothSurfaces(t, cleanReport()) {
		if strings.Contains(s, "Partial coverage") || strings.Contains(s, wantHeadlineTail) {
			t.Errorf("%s: a clean scan's headline must carry no qualifier\n---\n%s", name, s)
		}
	}
}

// DISCLOSURE ONLY, at the headline. The qualified headline changes no verdict and no
// count: everything from the counts table down — the counts, the candidate rows, the
// verdict labels — is byte-identical with and without the partiality note.
func TestPartialityHeadline_LeavesCountsAndVerdictsIdentical(t *testing.T) {
	note := report.PartialityNote{Reason: "no_manifest", Ecosystem: "npm"}
	fromCounts := func(s string) string {
		i := strings.Index(s, "| Verdict | Count |")
		if i < 0 {
			t.Fatalf("no counts table in:\n%s", s)
		}
		return s[i:]
	}

	for _, tc := range []struct {
		name           string
		clean, partial report.Report
	}{
		{"grounded-safe", cleanReport(), noManifestReport()},
		{"zero findings", emptyReport(), emptyReport(note)},
		{"with candidates", candidateReport(), candidateReport(note)},
	} {
		clean, partial := bothSurfaces(t, tc.clean), bothSurfaces(t, tc.partial)
		for surface := range clean {
			if got, want := fromCounts(partial[surface]), fromCounts(clean[surface]); got != want {
				t.Errorf("%s/%s: the headline qualifier moved a count or a verdict\n--- partial ---\n%s\n--- clean ---\n%s", tc.name, surface, got, want)
			}
		}
		// And at the source: same findings, same verdicts, same order.
		if len(tc.clean.Advisories) != len(tc.partial.Advisories) {
			t.Fatalf("%s: finding count changed: %d vs %d", tc.name, len(tc.clean.Advisories), len(tc.partial.Advisories))
		}
		for i := range tc.clean.Advisories {
			if tc.clean.Advisories[i].Verdict != tc.partial.Advisories[i].Verdict {
				t.Errorf("%s: advisory %d verdict changed: %q vs %q", tc.name, i, tc.clean.Advisories[i].Verdict, tc.partial.Advisories[i].Verdict)
			}
		}
	}
}

// isHeadlineLine reports whether a rendered line is the one-line verdict headline, in
// either its plain or its partiality-qualified form.
func isHeadlineLine(line string) bool {
	return strings.HasPrefix(line, "**No reachable candidates.**") ||
		strings.HasPrefix(line, "**No advisory findings.**") ||
		strings.HasPrefix(line, "**Partial coverage — ") ||
		strings.Contains(line, "reachable candidate(s)** found")
}

// collapseBlankRuns squashes runs of blank lines so the comparison above is not
// defeated by the separator line the stripped disclosure block leaves behind.
func collapseBlankRuns(s string) string {
	var out []string
	prevBlank := false
	for _, line := range strings.Split(s, "\n") {
		blank := strings.TrimSpace(line) == ""
		if blank && prevBlank {
			continue
		}
		out = append(out, line)
		prevBlank = blank
	}
	return strings.Join(out, "\n")
}
