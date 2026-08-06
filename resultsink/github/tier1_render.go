// tier1_render.go — the shared deterministic Markdown body the Tier 1 write surfaces
// (sticky PR comment, pinned-Issue dashboard) render. Both surfaces wrap this body
// with an HTML-comment marker so they can find-or-update their single artifact on a
// re-run rather than spamming a new one per push.
//
// The body renders only the four deterministic verdicts (inv. 5) via the same
// tally/headline/candidates helpers Tier 0 uses; it can never surface
// affected/error/exploitable or any Case/Assessment/living-verdict concept.
package github

import (
	"fmt"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// renderTier1Body builds the Markdown body shared by the sticky comment and the
// pinned-issue dashboard: a headline, a per-verdict counts table, and a per-candidate
// table when any candidate exists. It is deterministic (no wall-clock, stable order).
func renderTier1Body(r report.Report) string {
	c := tally(r)
	var b strings.Builder

	b.WriteString("## " + brand.Tier1SummaryHeading + "\n\n")
	if r.Subject.Repo != "" {
		fmt.Fprintf(&b, "**Repository:** `%s`  \n", r.Subject.Repo)
	}
	if commit := r.Provenance.CommitSHA; commit != "" {
		fmt.Fprintf(&b, "**Commit:** `%s`  \n", commit)
	}
	// The analyzer line renders the report's recorded provenance verbatim.
	// brand.Tier1RenderAnalyzer is the downstream-fork override: a rebrand that does
	// not want to disclose its analyzer build sets it false, suppressing the line here
	// while the recorded analyzer_version is still persisted as-is for the
	// engine→backend contract. It is unconditionally true for this build (Eric ruled
	// 2026-08-03), same as tier0_summary.go's Tier0RenderAnalyzer gate.
	if v := r.Provenance.AnalyzerVersion; v != "" && brand.Tier1RenderAnalyzer {
		fmt.Fprintf(&b, "**Analyzer:** `%s`  \n", v)
	}
	b.WriteString("\n")

	b.WriteString(headline(c, hasCoverageGap(r)))
	b.WriteString("\n\n")

	// Same placement rationale as the Tier-0 panel: the disclosure qualifies the
	// counts, so it precedes them. Rendered as a [!NOTE] callout to match this
	// surface's existing tone; absent entirely when every step of the analysis ran.
	// Only the did-not-run arm; inherent limits go to the shared footer below.
	b.WriteString(partialityCallout(r))

	b.WriteString(countsTable(c))

	if c.candidate > 0 {
		cands := candidates(r)
		b.WriteString("### Reachable candidates\n\n")
		b.WriteString("These advisories have a reachable code path. A candidate is **not** a proof of exploitability: proving it requires observing the path execute, which this scan does not do.\n\n")
		b.WriteString("> [!NOTE]\n")
		b.WriteString("> **Reachability grade** is evidence strength, not a verdict — `attacker_tainted` ranks above `control_flow_only`, but neither grade proves this code can be exploited. **EPSS/KEV** describe how often the CVE is exploited *in the wild* across all software, not whether this codebase calls the vulnerable path.\n\n")
		b.WriteString("| Advisory | Package | Grade | Entry point | EPSS | KEV | Candidate path |\n|---|---|---|---|---|---|---|\n")
		for _, f := range cands {
			pkg := "—"
			if f.Package != nil {
				pkg = fmt.Sprintf("`%s@%s`", f.Package.Name, f.Package.Version)
			}
			path := f.Evidence.ReachablePath
			if path == "" {
				path = "—"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s | %s |\n",
				f.Advisory.ID,
				pkg,
				gradeCell(f.Evidence.Grade),
				entryPointCell(f.Evidence.EntryPoint),
				epssCell(f.Priority),
				kevCell(f.Priority),
				mdCell(path),
			)
		}
		b.WriteString("\n")
		if snap := intelSnapshot(cands); snap != "" {
			fmt.Fprintf(&b, "_EPSS/KEV intel snapshot: %s._\n\n", mdCell(snap))
		}
	}

	// The same collapsed footer the Tier-0 panel renders, from the same helper: an
	// inherent limit must read identically wherever a customer meets it.
	b.WriteString(limitsFooter(r))

	return b.String()
}

// partialityCallout renders the steps of the analysis that did not run as a GitHub
// [!NOTE] alert — informational, not a warning: a disclosed limit is a boundary on what
// was assessed, not a defect found. Returns "" when every step ran, so a run whose only
// limits are inherent (and a fully-resolved run) keeps a visually clean PR comment and
// pinned Issue — the silence-when-clean guarantee that makes the disclosure worth
// reading at all.
func partialityCallout(r report.Report) string {
	lines := didNotRunLines(r)
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("> [!NOTE]\n")
	b.WriteString("> **Partial coverage.** This scan could not fully resolve the codebase:\n")
	b.WriteString(">\n") // blank quoted line so the list below renders as a list, not a lazy continuation
	for _, l := range lines {
		fmt.Fprintf(&b, "> - %s\n", l)
	}
	b.WriteString("\n")
	return b.String()
}

// gradeCell renders the reachability grade as a labelled marker. The grade is
// evidence strength (inv. 5), never a verdict — the labels mirror the report
// constants so a reader can map them back to the schema. An ungraded candidate
// shows an em-dash.
func gradeCell(g report.ReachabilityGrade) string {
	switch g {
	case report.GradeAttackerTainted:
		return "`attacker_tainted`"
	case report.GradeControlFlowOnly:
		return "`control_flow_only`"
	default:
		return "—"
	}
}

// entryPointCell renders the candidate path's ingress and whether the
// deterministic ingress analysis classed it attacker-controllable. It is
// evidence about the path head, not a verdict (inv. 5). Nil entry → em-dash.
func entryPointCell(e *report.EntryPoint) string {
	if e == nil || e.Symbol == "" {
		return "—"
	}
	out := fmt.Sprintf("`%s`", e.Symbol)
	if e.Kind != "" {
		out += fmt.Sprintf(" (%s)", e.Kind)
	}
	if e.AttackerControllable {
		out += " — attacker-controllable"
	}
	return mdCell(out)
}

// epssCell renders the EPSS score and percentile as exploitation-likelihood
// context (inv. 5), never an exploitability claim. Nil Priority → em-dash.
func epssCell(p *report.Priority) string {
	if p == nil {
		return "—"
	}
	return fmt.Sprintf("%.3f (p%d)", p.EPSSScore, int(p.EPSSPercentile*100+0.5))
}

// kevCell renders a CISA KEV-listed marker (with date-added when present) when
// the CVE is in the catalog, and nothing otherwise — an unlisted CVE prints an
// em-dash rather than asserting "not KEV". KEV is in-the-wild context (inv. 5).
func kevCell(p *report.Priority) string {
	if p == nil || !p.KEVListed {
		return "—"
	}
	if p.KEVDateAdded != "" {
		return mdCell(fmt.Sprintf("KEV-listed (%s)", p.KEVDateAdded))
	}
	return "KEV-listed"
}

// intelSnapshot returns the pinned EPSS/KEV snapshot date shared by the
// candidates' Priority records (rendered once as a footer, not per finding). It
// returns the first non-empty Snapshot it finds; empty when no candidate carried
// matched intel.
func intelSnapshot(cands []report.AdvisoryFinding) string {
	for i := range cands {
		if cands[i].Priority != nil && cands[i].Priority.Snapshot != "" {
			return cands[i].Priority.Snapshot
		}
	}
	return ""
}

// withMarker wraps a rendered body with an HTML-comment marker line so a re-run can
// locate and overwrite the single artifact it owns. The marker is invisible in the
// rendered GitHub UI but matchable in the raw body.
func withMarker(marker, body string) string {
	return marker + "\n" + body
}

// hasMarker reports whether a raw comment/issue body carries the given marker.
func hasMarker(body, marker string) bool {
	return strings.Contains(body, marker)
}
