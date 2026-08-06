// tier0_summary.go — the Tier 0 GitHub ResultSink: a zero-permission surface that
// renders the deterministic scan headline into the GitHub Actions job summary and
// emits ::warning:: workflow-command annotations for reachable candidates.
//
// # Zero permission / forked-PR safety
//
// This sink makes NO GitHub API calls and requires NO token. It writes GFM to the
// file named by $GITHUB_STEP_SUMMARY and prints ::warning:: lines to a writer the
// Actions runner scrapes (stdout). Both work identically with an absent or
// read-only token, so a forked pull_request — whose GITHUB_TOKEN is read-only —
// gets the same headline and annotations as a trusted run. This is the universal
// surface that always survives.
//
// # Invariant 5 (deterministic verdicts only)
//
// The sink renders report.Verdict and nothing else. The Report can only carry
// disqualified / not_exploitable / reachable_candidate (report.Verdict.Valid), so
// no `affected` / `error` / Case / Assessment / living-verdict concept can appear —
// the boundary is structural, inherited from the Report it is handed.
package github

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
)

// Tier0Summary is a resultsink.ResultSink that publishes the scan headline to the
// GitHub Actions job summary and emits ::warning:: annotations for reachable
// candidates. It holds no token and performs no network I/O.
type Tier0Summary struct {
	// SummaryPath is the file the GFM headline is appended to. Empty means the
	// summary step is unavailable (e.g. not inside Actions) and the summary is
	// skipped; annotations still emit. Defaults from $GITHUB_STEP_SUMMARY via
	// NewTier0Summary.
	SummaryPath string
	// Annotations is where ::warning:: workflow commands are written. The Actions
	// runner scrapes the step's stdout, so this defaults to os.Stdout. Injectable
	// for tests.
	Annotations io.Writer
	// Workspace is the checkout root; annotation file paths are made relative to it
	// so the GitHub UI anchors them to the right file. Defaults from
	// $GITHUB_WORKSPACE.
	Workspace string
}

// Compile-time assurance that Tier0Summary implements the sink contract.
var _ resultsink.ResultSink = (*Tier0Summary)(nil)

// NewTier0Summary builds a Tier0Summary from a detected Env snapshot. It wires the
// summary path and workspace from the environment and sends annotations to stdout
// (where the Actions runner reads workflow commands). No token is consulted.
func NewTier0Summary(env Env) *Tier0Summary {
	return &Tier0Summary{
		SummaryPath: env.StepSummaryPath,
		Annotations: os.Stdout,
		Workspace:   env.Workspace,
	}
}

// Publish writes the GFM headline to the job summary (when a summary path is set)
// and emits a ::warning:: annotation for each reachable_candidate finding. It never
// calls the GitHub API and returns an error only on a local write failure.
func (s *Tier0Summary) Publish(_ context.Context, res Result) error {
	if s.SummaryPath != "" {
		if err := s.writeSummary(res.Report); err != nil {
			return err
		}
	}
	if s.Annotations != nil {
		if err := s.writeAnnotations(res.Report); err != nil {
			return err
		}
	}
	return nil
}

// Result is the payload type alias for resultsink.Result, re-exported so callers in
// this package read naturally without importing both names.
type Result = resultsink.Result

// writeSummary appends the rendered GFM headline to the step-summary file. GitHub
// appends successive step summaries, so the sink appends (does not truncate).
func (s *Tier0Summary) writeSummary(r report.Report) error {
	f, err := os.OpenFile(s.SummaryPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("resultsink/github: open step summary: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := io.WriteString(f, renderSummary(r)); err != nil {
		return fmt.Errorf("resultsink/github: write step summary: %w", err)
	}
	return nil
}

// writeAnnotations emits one ::warning:: workflow command per reachable_candidate.
// Only candidates are annotated: disqualified / not_exploitable are grounded-safe
// and would be annotation noise. inv. 5 keeps this to honest "candidate" framing —
// never "error", never "vulnerable".
func (s *Tier0Summary) writeAnnotations(r report.Report) error {
	for i := range r.Advisories {
		f := r.Advisories[i]
		if f.Verdict != report.VerdictReachableCandidate {
			continue
		}
		if _, err := io.WriteString(s.Annotations, s.annotationLine(f)+"\n"); err != nil {
			return fmt.Errorf("resultsink/github: write annotation: %w", err)
		}
	}
	return nil
}

// annotationLine builds a single ::warning file=...::message workflow command for a
// reachable candidate. The file points at the dependency manifest where the package
// is declared (inferred from the ecosystem) so the GitHub UI anchors the warning to
// a real file; the message carries honest candidate framing and the path.
func (s *Tier0Summary) annotationLine(f report.AdvisoryFinding) string {
	msg := candidateMessage(f)
	if file := s.manifestPath(f.Package); file != "" {
		return fmt.Sprintf("::warning file=%s::%s", escapeProp(file), escapeData(msg))
	}
	return fmt.Sprintf("::warning::%s", escapeData(msg))
}

// manifestPath returns the repo-relative manifest file where pkg is declared,
// inferred from the ecosystem (Go → go.mod, npm → package.json, Maven → pom.xml).
// The Report carries no source location for a dependency finding, so the manifest
// is the honest, deterministic file to anchor the annotation to. Returns "" when
// the package or ecosystem is unknown (the annotation then omits file=).
func (s *Tier0Summary) manifestPath(pkg *report.Package) string {
	if pkg == nil {
		return ""
	}
	return report.ManifestForEcosystem(pkg.Ecosystem)
}

// candidateMessage builds the honest one-line annotation message for a candidate.
func candidateMessage(f report.AdvisoryFinding) string {
	var b strings.Builder
	b.WriteString(f.Advisory.ID)
	if f.Package != nil {
		fmt.Fprintf(&b, " (%s@%s)", f.Package.Name, f.Package.Version)
	}
	b.WriteString(": reachable candidate path found")
	if f.Evidence.ReachablePath != "" {
		fmt.Fprintf(&b, " — %s", f.Evidence.ReachablePath)
	}
	b.WriteString(". A candidate for exploitability, not a proof.")
	return b.String()
}

// counts tallies findings by verdict for the summary headline.
type counts struct {
	candidate, notExploitable, disqualified, undetermined int
}

func tally(r report.Report) counts {
	var c counts
	for i := range r.Advisories {
		switch r.Advisories[i].Verdict {
		case report.VerdictReachableCandidate:
			c.candidate++
		case report.VerdictNotExploitable:
			c.notExploitable++
		case report.VerdictDisqualified:
			c.disqualified++
		case report.VerdictUndetermined:
			c.undetermined++
		}
	}
	return c
}

// groundedSafe is the count of findings that ARE a refutation. It deliberately excludes
// undetermined, which is the whole reason the headline has to consult the tally rather than
// subtract candidates from the total: a panel that folded unassessed advisories into
// "grounded-safe" would restate the defect in the one line a skimming reader is guaranteed to read.
func (c counts) groundedSafe() int { return c.notExploitable + c.disqualified }

// renderSummary builds the GFM job-summary headline: a one-line verdict statement, a
// counts table, and a per-candidate table when any candidate exists. It renders only
// the four deterministic verdicts (inv. 5).
func renderSummary(r report.Report) string {
	c := tally(r)
	var b strings.Builder

	b.WriteString("## " + brand.Tier0SummaryHeading + "\n\n")

	if r.Subject.Repo != "" {
		fmt.Fprintf(&b, "**Repository:** `%s`  \n", r.Subject.Repo)
	}
	if commit := r.Provenance.CommitSHA; commit != "" {
		fmt.Fprintf(&b, "**Commit:** `%s`  \n", commit)
	}
	// The analyzer line renders the report's recorded provenance verbatim.
	// brand.Tier0RenderAnalyzer is the downstream-fork override: a rebrand that does
	// not want to disclose its analyzer build sets it false, suppressing the line here
	// while the recorded analyzer_version is still persisted as-is for the
	// engine→backend contract. It is unconditionally true for this build (Eric ruled
	// 2026-08-03): the analyzer identity is public, and the line is the citation
	// anchor tying a rendered verdict back to the build that produced it.
	if v := r.Provenance.AnalyzerVersion; v != "" && brand.Tier0RenderAnalyzer {
		fmt.Fprintf(&b, "**Analyzer:** `%s`  \n", v)
	}
	b.WriteString("\n")

	b.WriteString(headline(c, hasCoverageGap(r)))
	b.WriteString("\n\n")

	// Disclosed BEFORE the counts, because it qualifies them: the counts of a scan
	// that could not resolve part of the codebase do not mean what the same counts
	// mean on a fully-resolved one. Renders nothing when there is nothing to disclose.
	// Only the did-not-run arm sits here; inherent limits go to the footer below.
	b.WriteString(partialityBlock(r))

	b.WriteString(countsTable(c))

	if c.candidate > 0 {
		b.WriteString("### Reachable candidates\n\n")
		b.WriteString("These advisories have a reachable code path. A candidate is **not** a proof of exploitability: proving it requires observing the path execute, which this scan does not do.\n\n")
		b.WriteString("| Advisory | Package | Candidate path |\n|---|---|---|\n")
		for _, f := range candidates(r) {
			pkg := "—"
			if f.Package != nil {
				pkg = fmt.Sprintf("`%s@%s`", f.Package.Name, f.Package.Version)
			}
			path := f.Evidence.ReachablePath
			if path == "" {
				path = "—"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", f.Advisory.ID, pkg, mdCell(path))
		}
		b.WriteString("\n")
	}

	// Methodology, last and collapsed: it qualifies nothing above it, so it must not sit
	// between the reader and the results.
	b.WriteString(limitsFooter(r))

	return b.String()
}

// partialHeadlineTail qualifies a headline whose counts a disclosed coverage limit
// made incomplete. Same voice as the disclosure it points at (partialityLine): a
// limit is a boundary on what was assessed, not a defect found.
const partialHeadlineTail = "This run is not a complete assessment of the codebase."

// headline is the one-line verdict statement at the top of the summary. It is the one
// line a skimming reader is guaranteed to read, so when the scan disclosed a coverage
// limit the headline says so itself: "no reachable candidates" / "no advisory
// findings" must never read as a whole-codebase safety claim on a run that could not
// resolve part of the codebase. The per-finding verdicts below can be grounded-safe
// while the run as a whole is not a complete assessment, and only the headline can
// carry that distinction to a reader who stops there.
//
// Disclosure only: the counts are rendered verbatim in both forms, no verdict is
// consulted or changed, and with nothing to disclose (partial == false) every string
// is byte-identical to what a scan with no partiality has always emitted.
//
// An `undetermined` count qualifies the headline on its own, without waiting for a
// partiality note: an unassessed advisory IS the incompleteness, and a run whose only
// non-refutation is a row rather than a note must not read as complete.
func headline(c counts, partial bool) string {
	partial = partial || c.undetermined > 0
	switch {
	case c.candidate > 0:
		h := fmt.Sprintf("**%d reachable candidate(s)** found — review below. (%d not exploitable, %d disqualified%s.)",
			c.candidate, c.notExploitable, c.disqualified, notAssessedTail(c))
		if partial {
			h += " " + partialHeadlineTail
		}
		return h
	case c.groundedSafe() > 0:
		if partial {
			return fmt.Sprintf("**Partial coverage — no reachable candidates in what was assessed.** %d advisory finding(s) are grounded-safe (%d not exploitable, %d disqualified%s). %s",
				c.groundedSafe(), c.notExploitable, c.disqualified, notAssessedTail(c), partialHeadlineTail)
		}
		return fmt.Sprintf("**No reachable candidates.** %d advisory finding(s) are grounded-safe (%d not exploitable, %d disqualified).",
			c.groundedSafe(), c.notExploitable, c.disqualified)
	case c.undetermined > 0:
		// Nothing was refuted and nothing was found: every advisory evaluated is unassessed.
		// This case exists so the line cannot fall through to "no advisory findings", which
		// would be the silent clean scan with extra steps.
		return fmt.Sprintf("**No verdict was established for any of the %d advisor%s evaluated.** %s",
			c.undetermined, plural(c.undetermined, "y", "ies"), partialHeadlineTail)
	default:
		if partial {
			return "**Partial coverage — no advisory findings in what was assessed.** " + partialHeadlineTail
		}
		return "**No advisory findings.**"
	}
}

// hasCoverageGap reports whether this report discloses a step of the analysis that did
// not run. It is the ONLY condition the headline qualifier fires on.
//
// An inherent limit of static analysis is deliberately excluded: it holds for
// essentially every scan, and a qualifier that fires on every scan can no longer
// distinguish the runs that actually lost coverage. Those limits are still disclosed,
// in the footer (limitsFooter) — quieter, never absent.
//
// The headline is qualified on exactly the condition the loud block renders on, so a
// qualified headline can never appear without the note that explains it (or the
// reverse).
func hasCoverageGap(r report.Report) bool { return len(didNotRunLines(r)) > 0 }

// notAssessedTail appends the unassessed count to a counts parenthetical, or "" when every
// advisory got a verdict. It is inside the same parenthetical as the refutation counts so a reader
// cannot take those counts for the whole evaluated set.
func notAssessedTail(c counts) string {
	if c.undetermined == 0 {
		return ""
	}
	return fmt.Sprintf(", %d not assessed", c.undetermined)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// didNotRunLines renders one honest sentence per step of the analysis that did not run,
// in the Report's stable order. It returns nil when nothing in this run failed to
// happen — a clean scan must render nothing at all, or a disclosure that appears on
// every run stops carrying any signal.
func didNotRunLines(r report.Report) []string {
	out := make([]string, 0, len(r.Partiality))
	for _, n := range r.Partiality {
		if n.EffectiveClass() != report.PartialityDidNotRun {
			continue
		}
		if line := partialityLine(n); line != "" {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// inherentLimitLines renders one sentence per inherent limit of the analysis method, in
// the Report's stable order. Returns nil when the scan declared none.
func inherentLimitLines(r report.Report) []string {
	out := make([]string, 0, len(r.Partiality))
	for _, n := range r.Partiality {
		if n.EffectiveClass() != report.PartialityInherentLimit {
			continue
		}
		if line := limitLine(n); line != "" {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// partialityLine phrases one DID-NOT-RUN limit for a customer: what could not be
// established, and what that means for the verdicts above. A limit is a disclosed
// boundary, not a failure, so the copy states the boundary plainly and never implies
// something is broken or unsafe. An unrecognized reason code is disclosed verbatim
// rather than dropped — silently omitting an unknown limit is exactly the
// clean-looking-but-unassessed scan the field exists to prevent.
func partialityLine(n report.PartialityNote) string {
	scope := "dependency"
	if n.Ecosystem != "" {
		scope = n.Ecosystem + " dependency"
	}
	switch n.Reason {
	case plugin.PartialReasonNoManifest:
		return fmt.Sprintf("Installed %s versions could not be pinned: no lockfile or pinned-version manifest was found. Advisories for those dependencies were kept in scope rather than ruled out on version, so this run is not a complete dependency assessment.", scope)
	case plugin.PartialReasonNoPlugin:
		return fmt.Sprintf("No analyzer is available for this codebase's language, so its %s set was not analyzed. The advisories below were not ruled out — they were not assessed.", scope)
	case plugin.PartialReasonToolFailure:
		// Names the step and the advisory: an advisory whose analysis failed carries no
		// verdict, so it is absent from the counts and only this line accounts for it.
		if n.Detail != "" {
			return fmt.Sprintf("An analysis step did not complete (`%s`). That advisory has no verdict and is **not** counted below.", mdCell(n.Detail))
		}
		return "An analysis step did not complete, so one or more advisories have no verdict and are **not** counted below."
	default:
		if n.Detail != "" {
			return fmt.Sprintf("Part of the %s analysis was incomplete (`%s`: `%s`), so this run covers less than the whole codebase.", scope, mdCell(n.Reason), mdCell(n.Detail))
		}
		return fmt.Sprintf("Part of the %s analysis was incomplete (`%s`), so this run covers less than the whole codebase.", scope, mdCell(n.Reason))
	}
}

// limitLine phrases one INHERENT limit of the analysis method for a customer. These
// are methodology, not incident: the copy says what static analysis cannot see and
// stops there. It deliberately borrows none of partialityLine's "could not be
// established" / "were not assessed" framing, because nothing about this run fell
// short — the same sentence would be just as true of a scan where everything worked.
func limitLine(n report.PartialityNote) string {
	var body string
	switch n.Reason {
	case plugin.PartialReasonReflection:
		body = "calls made through reflection are not visible to static analysis, so a path that reaches vulnerable code only by reflection is not represented above"
	case plugin.PartialReasonDynamicDispatch:
		body = "some dynamic dispatch could not be narrowed to a single implementation, so the call graph over those calls is approximate"
	default:
		// An inherent limit this build does not recognize: state the code verbatim rather
		// than drop it. Reaching here needs a writer that classified the note explicitly,
		// since ClassifyPartialityReason sends every unknown code to the loud arm.
		body = fmt.Sprintf("a known limit of the analysis method applies (`%s`)", mdCell(n.Reason))
		if n.Detail != "" {
			body = fmt.Sprintf("a known limit of the analysis method applies (`%s`: `%s`)", mdCell(n.Reason), mdCell(n.Detail))
		}
	}
	if n.Ecosystem != "" {
		return n.Ecosystem + " analysis: " + body + "."
	}
	return strings.ToUpper(body[:1]) + body[1:] + "."
}

// partialityBlock renders the did-not-run disclosure for the Tier-0 job-summary panel,
// or "" when every step of the analysis ran. Plain GFM, matching the surrounding panel
// (which uses no alert callouts).
func partialityBlock(r report.Report) string {
	lines := didNotRunLines(r)
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("**Partial coverage.** This scan could not fully resolve the codebase:\n\n")
	for _, l := range lines {
		fmt.Fprintf(&b, "- %s\n", l)
	}
	b.WriteString("\n")
	return b.String()
}

// limitsFooterSummary is the collapsed footer's visible label. It shares no wording
// with the partial-coverage disclosure above it, so a reader skimming for trouble can
// tell at a glance that this section is not trouble.
const limitsFooterSummary = "Analysis limits"

// limitsFooter renders the scan's inherent analysis limits as a collapsed footer at the
// bottom of the panel — present and readable, out of the reader's way. It is the quiet
// arm of the taxonomy, and it is shared verbatim by the Tier-0 panel and the Tier-1
// body so that no limit can be loud on one surface and quiet on another.
//
// Returns "" when the scan declared no inherent limit, keeping the silence-when-clean
// guarantee intact on both surfaces.
func limitsFooter(r report.Report) string {
	lines := inherentLimitLines(r)
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("<details>\n<summary>" + limitsFooterSummary + "</summary>\n\n")
	b.WriteString("These describe what static analysis cannot see. They hold for every scan of this kind and are listed for completeness — no step of this run was skipped or failed.\n\n")
	for _, l := range lines {
		fmt.Fprintf(&b, "- %s\n", l)
	}
	b.WriteString("\n</details>\n\n")
	return b.String()
}

// countsTable renders the per-verdict counts table shared by the Tier-0 job summary and the Tier-1
// comment/issue body. The "Not assessed" row appears only when something was unassessed, so a fully
// resolved scan's table is byte-identical to what it has always been — and an unassessed advisory
// is never folded into a neighbouring row to keep the shape constant.
func countsTable(c counts) string {
	var b strings.Builder
	b.WriteString("| Verdict | Count |\n|---|---:|\n")
	fmt.Fprintf(&b, "| Reachable candidate | %d |\n", c.candidate)
	fmt.Fprintf(&b, "| Not exploitable | %d |\n", c.notExploitable)
	fmt.Fprintf(&b, "| Disqualified | %d |\n", c.disqualified)
	if c.undetermined > 0 {
		fmt.Fprintf(&b, "| Not assessed (no verdict established) | %d |\n", c.undetermined)
	}
	b.WriteString("\n")
	return b.String()
}

// candidates returns the reachable_candidate findings in stable order.
func candidates(r report.Report) []report.AdvisoryFinding {
	out := make([]report.AdvisoryFinding, 0)
	for i := range r.Advisories {
		if r.Advisories[i].Verdict == report.VerdictReachableCandidate {
			out = append(out, r.Advisories[i])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Advisory.ID < out[j].Advisory.ID })
	return out
}

// mdCell escapes a value for use inside a GFM table cell (pipes break columns).
func mdCell(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

// escapeData escapes a string for the message portion of a workflow command.
// GitHub requires %, \r and \n to be percent-encoded in command data.
func escapeData(s string) string {
	r := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	return r.Replace(s)
}

// escapeProp escapes a string for a workflow-command property value (e.g. file=).
// In addition to data escaping, ',' and ':' must be encoded.
func escapeProp(s string) string {
	r := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C")
	return r.Replace(s)
}
