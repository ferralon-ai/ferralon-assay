package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// ShowcaseSummary is the showcase lane's part of the floor summary: what the lane pins and how the
// ledgers' comparator observations line up with what Assay is expected to emit.
type ShowcaseSummary struct {
	CorpusRelease string `json:"corpus_release"`
	GoVersion     string `json:"go_version"`
	// ObservedByEngine counts ledger rows by comparator_observed, then by engine_expected verdict.
	ObservedByEngine map[string]map[report.Verdict]int `json:"observed_by_engine"`
	// AdjudicatedByStatus counts ledger rows by adjudicated.status.
	AdjudicatedByStatus map[string]int `json:"adjudicated_by_status"`
}

// showcaseSummary tallies the ledgers' comparator observations against their engine_expected verdicts,
// and their adjudications.
func showcaseSummary(sc *Showcase, ledgers map[string]Ledger) *ShowcaseSummary {
	s := &ShowcaseSummary{CorpusRelease: sc.CorpusRelease, GoVersion: sc.GoVersion,
		ObservedByEngine: map[string]map[report.Verdict]int{}, AdjudicatedByStatus: map[string]int{}}
	for _, l := range ledgers {
		for _, r := range l.Rows {
			if s.ObservedByEngine[r.ComparatorObserved] == nil {
				s.ObservedByEngine[r.ComparatorObserved] = map[report.Verdict]int{}
			}
			s.ObservedByEngine[r.ComparatorObserved][r.EngineExpected.Verdict]++
			s.AdjudicatedByStatus[r.Adjudicated.Status]++
		}
	}
	return s
}

// reasonCounts counts findings by "verdict/reason".
func reasonCounts(fs []report.AdvisoryFinding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[engineOf(f).String()]++
	}
	return out
}

// checkHeader holds a ledger's build scope against the showcase pins: a ledger written for another
// commit, toolchain, corpus release or build does not describe this scan.
func checkHeader(sc *Showcase, t Target, h LedgerHeader) []string {
	var bad []string
	add := func(field, ledger, pinned string) {
		if ledger != pinned {
			bad = append(bad, fmt.Sprintf("header %s: ledger %q, targets file %q", field, ledger, pinned))
		}
	}
	add("repo", h.Repo, t.Repo)
	add("upstream_sha", h.UpstreamSHA, t.Ref)
	add("go_version", h.GoVersion, sc.GoVersion)
	add("corpus_release", h.CorpusRelease, sc.CorpusRelease)
	add("goos", h.GOOS, sc.GOOS)
	add("goarch", h.GOARCH, sc.GOARCH)
	add("cgo", fmt.Sprint(h.CGO), fmt.Sprint(sc.CGO))
	return bad
}

// evaluateShowcase judges one showcase scan: the floor's own checks, then the ledger. On the pinned
// scan a ledger difference fails the target, whether the engine regressed or improved (an improvement
// passes once the ledger is updated in the same change). On the floating scan every failure and every
// difference is reported and none fails: the floating corpus moves under the lane by design.
func evaluateShowcase(t Target, sc *Showcase, kind string, lg *Ledger, lgErr error, sr *scanResult) RepoResult {
	res := evaluate(t, sc.Policy, sr)
	res.Lane = kind
	var lines []string
	if sr != nil && sr.hasReport {
		if r, err := decodeReport(sr.report); err == nil {
			scanRows := engineRows(r.Advisories)
			res.Reasons = reasonCounts(r.Advisories)
			if lg != nil {
				d := compareLedger(*lg, scanRows)
				lines = append(d.Lines, boundDiffs(*lg, scanRows, scanInputsOf(sc, r, sr.meta))...)
				res.Failures = append(res.Failures, incompleteScan(r, *lg, d.Matched)...)
			}
		}
	}
	var fail *Failure
	switch {
	case lg == nil:
		fail = &Failure{Kind: KindLedger, Detail: fmt.Sprintf("no usable ledger for %s: %v", t.Name(), lgErr)}
	case kind == laneShowcase:
		if bad := checkHeader(sc, t, lg.Header); len(bad) > 0 {
			fail = &Failure{Kind: KindLedger, Detail: "the ledger's build scope is not the pinned one", Findings: bad}
		} else if len(lines) > 0 {
			fail = &Failure{Kind: KindLedger,
				Detail:   fmt.Sprintf("%d differences from floor/expect/%s.yaml (update the ledger in the same change: docs/floor.md)", len(lines), t.Name()),
				Findings: lines}
		}
	}
	if kind == laneShowcaseFloating {
		res.Drift = lines
		res.ReportOnly = res.Failures
		res.Failures = nil
		res.Pass = true
		return res
	}
	if fail != nil {
		res.Failures = append(res.Failures, *fail)
	}
	res.Pass = len(res.Failures) == 0
	return res
}

// showcaseMarkdown renders the showcase section of the job summary.
func (s Summary) showcaseMarkdown() string {
	if s.Showcase == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n### Showcase lane\n\nPinned corpus `%s`, Go `%s`. The pinned scan fails on any ledger difference; the floating scan is report-only.\n\n",
		s.Showcase.CorpusRelease, s.Showcase.GoVersion)
	b.WriteString("| Target | Scan | Corpus | Go | Duration | Peak memory | Ledger rows differing | Verdicts by reason |\n|---|---|---|---|---|---|---|---|\n")
	for _, r := range s.Repos {
		if r.Lane != laneShowcase && r.Lane != laneShowcaseFloating {
			continue
		}
		scan, diff := "pinned", len(r.failureFindings())
		if r.Lane == laneShowcaseFloating {
			scan, diff = "floating (report-only)", len(r.Drift)
		}
		mem := "—"
		if r.PeakRSSKB != nil {
			mem = fmt.Sprintf("%.1f GiB", float64(*r.PeakRSSKB)/(1<<20))
		}
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s | %s | %d | %s |\n", cell(repoName(r.Repo)), scan,
			cell(r.CorpusRelease), cell(r.GoVersion), formatDuration(r.DurationSeconds), mem, diff, cell(formatReasonMap(r.Reasons)))
	}
	b.WriteString("\n**comparator_observed × engine_expected** (ledger rows; the comparator is an observation, not ground truth):\n\n| comparator_observed |")
	columns := append(slices.Clone(verdictOrder), VerdictNotEmitted)
	for _, v := range columns {
		fmt.Fprintf(&b, " %s |", v)
	}
	b.WriteString("\n|---|" + strings.Repeat("---|", len(columns)) + "\n")
	for _, tr := range truths {
		row, ok := s.Showcase.ObservedByEngine[tr]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "| %s |", tr)
		for _, v := range columns {
			fmt.Fprintf(&b, " %d |", row[v])
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "\n**Adjudicated** (a reviewer's conclusions, apart from the comparator): %s\n", formatReasonMap(s.Showcase.AdjudicatedByStatus))
	for _, r := range s.Repos {
		if len(r.Drift) > 0 {
			fmt.Fprintf(&b, "\n**Floating drift, %s** (report-only, %d rows):\n\n", repoName(r.Repo), len(r.Drift))
			for i, d := range r.Drift {
				if i == driftLines {
					fmt.Fprintf(&b, "- … %d more\n", len(r.Drift)-i)
					break
				}
				fmt.Fprintf(&b, "- %s\n", cell(d))
			}
		}
		for _, f := range r.ReportOnly {
			fmt.Fprintf(&b, "\n- report-only, %s: `%s`: %s\n", repoName(r.Repo), f.Kind, cell(f.Detail))
		}
	}
	return b.String()
}

// driftLines is how many floating-drift rows the Markdown summary lists per target.
const driftLines = 40

// failureFindings is the ledger lines of a repository's ledger failure.
func (r RepoResult) failureFindings() []string {
	for _, f := range r.Failures {
		if f.Kind == KindLedger {
			return f.Findings
		}
	}
	return nil
}

func formatReasonMap(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("`%s` %d", k, m[k])
	}
	return strings.Join(parts, ", ")
}
