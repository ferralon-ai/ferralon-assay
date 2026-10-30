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
// disqualified / not_exploitable / reachable_candidate / undetermined /
// malicious_package_present (report.Verdict.Valid), so no Case / Assessment /
// living-verdict concept can appear — the boundary is structural, inherited from
// the Report it is handed. `::error::` is reserved for malicious_package_present.
package github

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
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
		if err := s.writeSummary(res); err != nil {
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
func (s *Tier0Summary) writeSummary(res Result) error {
	f, err := os.OpenFile(s.SummaryPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("resultsink/github: open step summary: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := io.WriteString(f, renderSummary(res.Report, res.DependencyFetch)); err != nil {
		return fmt.Errorf("resultsink/github: write step summary: %w", err)
	}
	return nil
}

// writeAnnotations emits one workflow command per decisive or candidate finding:
// ::error:: for a malicious_package_present (a decisive determination that a
// known-malicious package is installed) and ::warning:: for a reachable_candidate.
// disqualified / not_exploitable / undetermined are not annotated — grounded-safe or
// unassessed rows would be annotation noise. inv. 5 keeps "error" to the one decisive
// verdict; a candidate is never "error" and never "vulnerable".
func (s *Tier0Summary) writeAnnotations(r report.Report) error {
	for i := range r.Advisories {
		f := r.Advisories[i]
		switch f.Verdict {
		case report.VerdictMaliciousPresent:
			if _, err := io.WriteString(s.Annotations, s.maliciousAnnotationLine(f)+"\n"); err != nil {
				return fmt.Errorf("resultsink/github: write annotation: %w", err)
			}
		case report.VerdictReachableCandidate:
			if _, err := io.WriteString(s.Annotations, s.annotationLine(f)+"\n"); err != nil {
				return fmt.Errorf("resultsink/github: write annotation: %w", err)
			}
		}
	}
	return nil
}

// maliciousAnnotationLine builds a single ::error file=...::message workflow command
// for a malicious-present finding, anchored to the dependency manifest where the
// package is declared. The message is decisive (a known-malicious package is present)
// and clinical — remediation, not alarm.
func (s *Tier0Summary) maliciousAnnotationLine(f report.AdvisoryFinding) string {
	msg := maliciousMessage(f)
	if file := s.manifestPath(f.Package); file != "" {
		return fmt.Sprintf("::error file=%s::%s", escapeProp(file), escapeData(msg))
	}
	return fmt.Sprintf("::error::%s", escapeData(msg))
}

// maliciousMessage builds the honest one-line annotation message for a malicious-present finding.
func maliciousMessage(f report.AdvisoryFinding) string {
	var b strings.Builder
	b.WriteString(f.Advisory.ID)
	if f.Package != nil {
		fmt.Fprintf(&b, " (%s)", f.Package.Label())
	}
	b.WriteString(": known-malicious package present at a listed affected version. Remove or replace this dependency.")
	return b.String()
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
		fmt.Fprintf(&b, " (%s)", f.Package.Label())
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
	candidate, notExploitable, disqualified, undetermined, maliciousPresent int
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
		case report.VerdictMaliciousPresent:
			c.maliciousPresent++
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
// the five deterministic verdicts (inv. 5). fetch is the run's dependency fetch outcomes,
// which name registries: the job summary is the one surface that renders them.
func renderSummary(r report.Report, fetch []resultsink.DependencyFetchNote) string {
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

	b.WriteString(headline(c, headlineTail(r)))
	b.WriteString("\n\n")

	// Disclosed BEFORE the counts, because it qualifies them: the counts of a scan
	// that could not resolve part of the codebase do not mean what the same counts
	// mean on a fully-resolved one. Renders nothing when there is nothing to disclose.
	// Only the did-not-run arm sits here; inherent limits go to the footer below.
	b.WriteString(partialityBlock(r))
	b.WriteString(dependencyFetchBlock(fetch))

	b.WriteString(countsTable(c))

	if c.candidate > 0 {
		b.WriteString("### Reachable candidates\n\n")
		b.WriteString("These advisories have a reachable code path. A candidate is **not** a proof of exploitability: proving it requires observing the path execute, which this scan does not do.\n\n")
		b.WriteString("| Advisory | Package | Candidate path |\n|---|---|---|\n")
		for _, f := range candidates(r) {
			pkg := "—"
			if f.Package != nil {
				pkg = fmt.Sprintf("`%s`", f.Package.Label())
			}
			path := f.Evidence.ReachablePath
			if path == "" {
				path = "—"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", f.Advisory.ID, pkg, mdCell(path))
		}
		b.WriteString("\n")
	}

	if absent := rangeAbsent(r); len(absent) > 0 {
		b.WriteString("### Reachable, with no version range to check\n\n")
		for _, f := range absent {
			fmt.Fprintf(&b, "- %s\n", rangeAbsentLine(f))
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

// cutShortHeadlineTail replaces partialHeadlineTail when the scan stopped before it finished, so a
// reader who stops at the headline learns the cause and that the remedy is below.
const cutShortHeadlineTail = "The scan was cut short before every advisory was assessed; see below for how to give it more time."

// headlineTail is the qualifier the headline carries: none when the report discloses no step that
// did not run, the cut-short tail when the scan stopped early, and partialHeadlineTail otherwise.
func headlineTail(r report.Report) string {
	if !hasCoverageGap(r) {
		return ""
	}
	for _, n := range r.Partiality {
		if n.Reason == report.ReasonScanCutShort {
			return cutShortHeadlineTail
		}
	}
	return partialHeadlineTail
}

// headline is the one-line verdict statement at the top of the summary. It is the one
// line a skimming reader is guaranteed to read, so when the scan disclosed a coverage
// limit the headline says so itself: "no reachable candidates" / "no advisory
// findings" must never read as a whole-codebase safety claim on a run that could not
// resolve part of the codebase. The per-finding verdicts below can be grounded-safe
// while the run as a whole is not a complete assessment, and only the headline can
// carry that distinction to a reader who stops there.
//
// Disclosure only: the counts are rendered verbatim in both forms, no verdict is
// consulted or changed, and with nothing to disclose (tail == "") every string
// is byte-identical to what a scan with no partiality has always emitted.
//
// An `undetermined` count qualifies the headline on its own, without waiting for a
// partiality note: an unassessed advisory IS the incompleteness, and a run whose only
// non-refutation is a row rather than a note must not read as complete.
func headline(c counts, tail string) string {
	if tail == "" && c.undetermined > 0 {
		tail = partialHeadlineTail
	}
	partial := tail != ""
	switch {
	case c.maliciousPresent > 0:
		// The decisive OSS "affected" leads the headline: a known-malicious package is present.
		// This is not a candidate owing follow-up — it is a determined finding that owes
		// remediation, so it outranks every other line.
		h := fmt.Sprintf("**%d known-malicious package(s) present** — remove or replace. (%d reachable candidate(s), %d not exploitable, %d disqualified%s.)",
			c.maliciousPresent, c.candidate, c.notExploitable, c.disqualified, notAssessedTail(c))
		if partial {
			h += " " + tail
		}
		return h
	case c.candidate > 0:
		h := fmt.Sprintf("**%d reachable candidate(s)** found — review below. (%d not exploitable, %d disqualified%s.)",
			c.candidate, c.notExploitable, c.disqualified, notAssessedTail(c))
		if partial {
			h += " " + tail
		}
		return h
	case c.groundedSafe() > 0:
		if partial {
			return fmt.Sprintf("**Partial coverage — no reachable candidates in what was assessed.** %d advisory finding(s) are grounded-safe (%d not exploitable, %d disqualified%s). %s",
				c.groundedSafe(), c.notExploitable, c.disqualified, notAssessedTail(c), tail)
		}
		return fmt.Sprintf("**No reachable candidates.** %d advisory finding(s) are grounded-safe (%d not exploitable, %d disqualified).",
			c.groundedSafe(), c.notExploitable, c.disqualified)
	case c.undetermined > 0:
		// Nothing was refuted and nothing was found: every advisory evaluated is unassessed.
		// This case exists so the line cannot fall through to "no advisory findings", which
		// would be the silent clean scan with extra steps.
		return fmt.Sprintf("**No verdict was established for any of the %d advisor%s evaluated.** %s",
			c.undetermined, plural(c.undetermined, "y", "ies"), tail)
	default:
		if partial {
			return "**Partial coverage — no advisory findings in what was assessed.** " + tail
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
//
// Every dependency_code_unavailable note of one ecosystem renders as a single line where the
// first of them stands: a cve-watch run carries the notes of the earlier runs whose verdicts it
// keeps, so several can arrive with different causes, and the run itself may have read its code.
func didNotRunLines(r report.Report) []string {
	out := make([]string, 0, len(r.Partiality))
	depCode := map[string][]string{}
	for _, n := range r.Partiality {
		if n.EffectiveClass() == report.PartialityDidNotRun && n.Reason == report.PartialReasonDependencyCodeUnavailable {
			depCode[partialityScope(n)] = append(depCode[partialityScope(n)], n.Detail)
		}
	}
	var own string
	if r.DependencyCode != nil {
		own = r.DependencyCode.Cause.Describe()
	}
	for _, n := range r.Partiality {
		if n.EffectiveClass() != report.PartialityDidNotRun {
			continue
		}
		line := partialityLine(n)
		if n.Reason == report.PartialReasonDependencyCodeUnavailable {
			scope := partialityScope(n)
			details, first := depCode[scope]
			if !first {
				continue
			}
			delete(depCode, scope)
			line = dependencyCodeUnavailableLine(scope, details, own)
		}
		if line != "" {
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
	scope := partialityScope(n)
	switch n.Reason {
	case plugin.PartialReasonNoManifest:
		return fmt.Sprintf("Installed %s versions could not be pinned: no lockfile or pinned-version manifest was found. Advisories for those dependencies were kept in scope rather than ruled out on version, so this run is not a complete dependency assessment.", scope)
	case plugin.PartialReasonNoPlugin:
		return fmt.Sprintf("No analyzer is available for this codebase's language, so its %s set was not analyzed. The advisories below were not ruled out — they were not assessed.", scope)
	case report.ReasonScanCutShort:
		if n.Detail != "" {
			return fmt.Sprintf("The scan was cut short before it finished (`%s`). Every advisory it did not assess has no verdict and is counted as not assessed.", mdCell(n.Detail))
		}
		return "The scan was cut short before it finished, so one or more advisories have no verdict and are counted as not assessed."
	case report.PartialReasonDependencyCodeUnavailable:
		return dependencyCodeUnavailableLine(scope, []string{n.Detail}, n.Detail)
	case report.ReasonDependencyNotFetched:
		return fmt.Sprintf("Some advisories were last assessed on a run that did not read all the %s code the lockfile pins, so the verdicts that run reached are withheld and counted as not assessed. A later run that reads that code assesses them again.", scope)
	case plugin.PartialReasonToolFailure:
		// Names the step and the advisory. The advisory's row is undetermined, so it is
		// counted as not assessed.
		if n.Detail != "" {
			return fmt.Sprintf("An analysis step did not complete (`%s`). That advisory has no verdict and is counted as not assessed.", mdCell(n.Detail))
		}
		return "An analysis step did not complete, so one or more advisories have no verdict and are counted as not assessed."
	default:
		if n.Detail != "" {
			return fmt.Sprintf("Part of the %s analysis was incomplete (`%s`: `%s`), so this run covers less than the whole codebase.", scope, mdCell(n.Reason), mdCell(n.Detail))
		}
		return fmt.Sprintf("Part of the %s analysis was incomplete (`%s`), so this run covers less than the whole codebase.", scope, mdCell(n.Reason))
	}
}

// partialityScope names what a note's line is about: "dependency", or "<ecosystem> dependency".
func partialityScope(n report.PartialityNote) string {
	if n.Ecosystem != "" {
		return n.Ecosystem + " dependency"
	}
	return "dependency"
}

// dependencyCodeUnavailableLine phrases the tool_failure:dependency_code_unavailable notes of one
// scope as one line. details are the notes' Details, each "kind" or "kind: package..."; own is the
// cause of the run's own fall-back, or "" when it read its code. A note other than own was carried
// from an earlier run whose verdicts this run keeps, so the line says some verdicts were reached
// on an earlier run rather than that this scan read none. Each distinct kind adds its fix hint. The
// Report names no registry, so neither does this line: the job summary's dependency code block
// names it where the run has one to name.
func dependencyCodeUnavailableLine(scope string, details []string, own string) string {
	var carried []string
	ownSeen := false
	for _, d := range details {
		if own != "" && d == own {
			ownSeen = true
			continue
		}
		carried = append(carried, d)
	}
	var line string
	if ownSeen {
		line = fmt.Sprintf("The scan read none of its %s code (`%s`), as with dependency code off, so every verdict below was reached without looking inside dependencies.", scope, mdCell(own))
		if len(carried) > 0 {
			line += fmt.Sprintf(" Some were reached on an earlier run that did not read it either%s.", causeList(carried))
		}
	} else {
		line = fmt.Sprintf("Some verdicts below were reached on an earlier run that did not read its %s code%s, as with dependency code off, so they were reached without looking inside dependencies.", scope, causeList(carried))
	}
	var hints []string
	for _, d := range append([]string{own}, carried...) {
		if h := dependencyCodeHint(d); h != "" && !slices.Contains(hints, h) {
			hints = append(hints, h)
		}
	}
	return line + strings.Join(hints, "")
}

// causeList renders note Details as " (`a`; `b`)", skipping empty ones, or "" when none is left.
func causeList(details []string) string {
	var causes []string
	for _, d := range details {
		if d != "" && !slices.Contains(causes, "`"+mdCell(d)+"`") {
			causes = append(causes, "`"+mdCell(d)+"`")
		}
	}
	if len(causes) == 0 {
		return ""
	}
	return " (" + strings.Join(causes, "; ") + ")"
}

// dependencyCodeHint is the fix hint, with its leading space, for a dependency_code_unavailable
// Detail, or "" when its kind names no setting the operator could change.
func dependencyCodeHint(detail string) string {
	kind, _, _ := strings.Cut(detail, ":")
	switch kind {
	case "policy_refused":
		switch {
		case strings.HasSuffix(detail, artifactcache.PolicyMissingCredential):
			return " A registry asked for a token the run did not have: give the scan step the registry's token variable, or point the npm configuration at a registry it can read."
		case strings.HasSuffix(detail, artifactcache.PolicyCredentialRejected):
			return " A registry refused the token the run sent: renew the token or give it read access to the package, and if a curation proxy fronts the registry, check whether it blocks the package."
		}
		return " The fetch policy refused a package for the reason named: check the npm configuration's registry for that package."
	case "registry_unavailable", "registry_unreachable":
		return " A registry could not be reached or did not answer: check that it is up and reachable from the runner."
	case "not_served":
		return " A registry does not serve a package the lockfile pins: check the npm configuration names the registry that serves it."
	case "integrity_mismatch":
		return " A fetched package did not match the lockfile's integrity hash: check the lockfile against the registry it resolves from."
	case "npmrc_malformed":
		return " The npm configuration could not be read: fix the file and line it names."
	case "fetch_failed":
		return " A package fetch failed outside any registry answer, such as a dropped transfer or a cache that could not be written: check the runner's network and that the dependency cache directory is writable."
	case "cancelled":
		return dependencyTimeoutHint
	case "inventory_failed":
		if strings.HasSuffix(detail, "cancelled") {
			return dependencyTimeoutHint
		}
		// Otherwise the JS analyzer failed to list the locked packages, for a reason of its own
		// that names no setting the operator could change, so the line names the cause and stops.
	}
	return ""
}

// dependencyTimeoutHint is the fix for dependency fetching that ran out of time.
var dependencyTimeoutHint = " Dependency fetching ran out of time or the run was cancelled: set " + brand.EnvPrefix +
	"_DEPENDENCY_TIMEOUT for the scan step to allow it longer than the default 15 minutes, or give the job more time."

// dependencyFetchBlock renders the run's dependency fetch outcomes for the job summary, one line
// per registry with what to do about it, or "" when the fetch needs nothing from the operator. It
// names registries, which no other surface does.
func dependencyFetchBlock(fetch []resultsink.DependencyFetchNote) string {
	if len(fetch) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("**Dependency code.**\n\n")
	for _, n := range fetch {
		fmt.Fprintf(&b, "- %s\n", dependencyFetchLine(n))
	}
	b.WriteString("\n")
	return b.String()
}

// dependencyFetchLine phrases one registry's outcome. An outcome this build does not know is stated
// verbatim rather than dropped.
func dependencyFetchLine(n resultsink.DependencyFetchNote) string {
	reg := mdCode(n.Registry)
	var what string
	switch n.Outcome {
	case resultsink.DependencyFetchCredentialRejected:
		what = fmt.Sprintf("%s refused the token this run sent (HTTP 401 or 403) for %s, so the run fails.", reg, mdCode(n.Package))
	case resultsink.DependencyFetchStalled:
		what = fmt.Sprintf("%s has served nothing on %d cve-watch runs since %s, holding the advisory cursor, so the run fails.", reg, n.HeldRuns, n.Since.UTC().Format("2006-01-02 15:04 UTC"))
	case resultsink.DependencyFetchHeld:
		what = fmt.Sprintf("%s served nothing on this run, so the advisory cursor holds (%d %s since %s).", reg, n.HeldRuns, plural(n.HeldRuns, "held run", "held runs"), n.Since.UTC().Format("2006-01-02 15:04 UTC"))
	case resultsink.DependencyFetchMissingCredential:
		what = fmt.Sprintf("%s asked for a token this run did not have.", reg)
	default:
		what = fmt.Sprintf("%s: %s.", reg, mdCode(n.Outcome))
	}
	if n.Hint == "" {
		return what
	}
	return what + " " + strings.ToUpper(n.Hint[:1]) + n.Hint[1:]
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
	if c.maliciousPresent > 0 {
		fmt.Fprintf(&b, "| Malicious package present | %d |\n", c.maliciousPresent)
	}
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

// rangeAbsent returns the findings left undetermined because the advisory gives no version range
// Assay can check, in stable order. Each still carries the path that reached the advisory's code.
func rangeAbsent(r report.Report) []report.AdvisoryFinding {
	var out []report.AdvisoryFinding
	for i := range r.Advisories {
		f := r.Advisories[i]
		if f.Verdict == report.VerdictUndetermined && f.UndeterminedReason == report.ReasonAdvisoryRangeAbsent {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Advisory.ID < out[j].Advisory.ID })
	return out
}

// rangeAbsentLine renders one range-absent finding. It states only what the report holds: the
// installed version when one was resolved, the entry point or path, and whatever partial bounds the
// advisory records. Every value from the advisory or the codebase is a code span, so none of it can
// render as markup, a link, a mention or math.
func rangeAbsentLine(f report.AdvisoryFinding) string {
	version, subject := "version not determined", "the installed version"
	if f.Package != nil && f.Package.Version != "" && !f.Package.PinUnresolved() {
		version = mdCode(f.Package.Version)
		subject = version
	}
	var b strings.Builder
	if f.Package != nil {
		fmt.Fprintf(&b, "%s %s", mdCode(f.Package.Name), version)
		if f.Package.Ecosystem != "" {
			fmt.Fprintf(&b, " (%s)", mdCode(f.Package.Ecosystem))
		}
	} else {
		fmt.Fprintf(&b, "Code named in the advisory, %s,", version)
	}
	switch {
	case f.Evidence.EntryPoint != nil && f.Evidence.EntryPoint.Symbol != "":
		fmt.Fprintf(&b, " is reachable from %s", mdCode(f.Evidence.EntryPoint.Symbol))
	case f.Evidence.ReachablePath != "":
		fmt.Fprintf(&b, " is reachable along %s", mdCode(f.Evidence.ReachablePath))
	default:
		b.WriteString(" is reachable")
	}
	fmt.Fprintf(&b, " and is named in %s. The advisory does not give a version range Assay can check %s against", mdCode(f.Advisory.ID), subject)
	if bounds := boundsText(f.Evidence.AdvisoryBounds); bounds != "" {
		fmt.Fprintf(&b, "; it records: %s", bounds)
	}
	fmt.Fprintf(&b, ". Confirm with the advisory or the maintainer whether %s is affected.", subject)
	return b.String()
}

// boundsText describes the bounds of a range-absent advisory, one clause per range. A GIT range's
// bounds are commits and are named as such; "no fix" is said only of a range with no fixed or
// last_affected event.
func boundsText(bounds []report.AdvisoryBound) string {
	var parts []string
	for _, bd := range bounds {
		var p []string
		switch bd.Type {
		case "":
		case "GIT":
			p = append(p, "by commit")
		default:
			p = append(p, "by "+mdCode(bd.Type))
		}
		events := len(p)
		if bd.Introduced != "" {
			p = append(p, "introduced "+mdCode(bd.Introduced))
		}
		if bd.Fixed != "" {
			p = append(p, "fixed in "+mdCode(bd.Fixed))
		}
		if bd.LastAffected != "" {
			p = append(p, "last affected "+mdCode(bd.LastAffected))
		}
		if bd.Introduced != "" && bd.Fixed == "" && bd.LastAffected == "" {
			p = append(p, "no fix")
		}
		if len(p) > events {
			parts = append(parts, strings.Join(p, ", "))
		}
	}
	return strings.Join(parts, "; ")
}

// mdCode renders a value as a GFM code span. The fence is one backtick longer than the longest
// backtick run in the value, so the value cannot close it; HTML inside a code span is literal.
func mdCode(s string) string {
	s = foldLines(s)
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	return fence + s + fence
}

func foldLines(s string) string {
	return strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ").Replace(s)
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
