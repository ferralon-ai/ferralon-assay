package trigger

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// analysisOr is the context a run's analysis half runs under: the request's Analysis context, or
// ctx when the caller set none.
func analysisOr(analysis, ctx context.Context) context.Context {
	if analysis == nil {
		return ctx
	}
	return analysis
}

// assessWithin runs one advisory's assessment under analysis and reports stopped when the scan
// stopped before the assessment returned. A stopped assessment's result is discarded whether it
// succeeded or failed: a stage may swallow the cancellation and return a result built on work it
// never finished, and a refutation resting on that would be a false negative.
func assessWithin(analysis context.Context, areq assessment.Request, opts ...pipeline.AssessOption) (artifact.Store, string, bool, error) {
	if analysis.Err() != nil {
		return nil, "", true, nil
	}
	start := time.Now()
	st, assessmentID, err := assess(analysis, areq, opts...)
	if analysis.Err() != nil {
		return nil, "", true, nil
	}
	observePhase(analysis, "advisory", start)
	return st, assessmentID, false, err
}

// inventoryWithin resolves the codebase inventory under analysis. When the scan stopped before it
// returned, the inventory is declared unresolved instead, so the Report is still built and every
// advisory still gets its row.
func inventoryWithin(analysis context.Context, codebase assessment.CodebaseRef, opts ...pipeline.AssessOption) (plugin.DependencyInventory, string, error) {
	start := time.Now()
	inv, language, _, err := pipeline.ResolveCodebaseInventory(analysis, codebase, "", opts...)
	if analysis.Err() != nil {
		return plugin.DependencyInventory{Partiality: plugin.Partial(report.ReasonScanCutShort)}, language, nil
	}
	observePhase(analysis, "inventory", start)
	return inv, language, err
}

// cutShortFinding is the row for an advisory the scan stopped before assessing. Like
// assessFailureFinding it carries no Package and no Basis: nothing was resolved for it.
func cutShortFinding(adv assessment.VulnRef) report.AdvisoryFinding {
	return report.AdvisoryFinding{
		Advisory:           report.Advisory{ID: adv.ID, Source: adv.Source},
		Verdict:            report.VerdictUndetermined,
		UndeterminedReason: report.ReasonScanCutShort,
		Evidence:           report.EvidenceSummary{Detail: "the scan stopped before this advisory was assessed"},
	}
}

// cutShortCountSep separates a cut-short note's count from the stop's cause.
const cutShortCountSep = " advisories were not assessed: "

// cutShortNote is the one scan-level disclosure for a Report holding cut rows of its total
// unassessed. Its detail carries the stop's cause, which names how to give the scan more time.
func cutShortNote(cut, total int, cause string) report.PartialityNote {
	return report.PartialityNote{
		Reason: report.ReasonScanCutShort,
		Detail: fmt.Sprintf("%d of %d%s%s", cut, total, cutShortCountSep, cause),
	}
}

// stopCause is the cause of a stopped analysis, as a cut-short note states it.
func stopCause(analysis context.Context) string {
	return context.Cause(analysis).Error()
}

// isCutShortCount reports whether n is the scan-level count cutShortNote writes, as opposed to an
// inventory or work set the scan stopped before resolving.
func isCutShortCount(n report.PartialityNote) bool {
	return n.Reason == report.ReasonScanCutShort && strings.Contains(n.Detail, cutShortCountSep)
}

// withoutCutShortCount is notes less their cut-short count. A pass that carries rows forward drops
// it and states a count of its own (recountCutShort), since a carried row may have been replaced.
func withoutCutShortCount(notes []report.PartialityNote) []report.PartialityNote {
	var out []report.PartialityNote
	for _, n := range notes {
		if !isCutShortCount(n) {
			out = append(out, n)
		}
	}
	return out
}

// recountCutShort is the cut-short count for the rows a pass built, or false when none of them is
// a scan_cut_short row. cause is the pass's own stop when it cut rows itself, else "", and then the
// cause the carried notes stated stands.
func recountCutShort(rows []report.AdvisoryFinding, carried []report.PartialityNote, cause string) (report.PartialityNote, bool) {
	cut := 0
	for _, f := range rows {
		if f.UndeterminedReason == report.ReasonScanCutShort {
			cut++
		}
	}
	if cut == 0 {
		return report.PartialityNote{}, false
	}
	for _, n := range carried {
		if _, c, ok := strings.Cut(n.Detail, cutShortCountSep); cause == "" && ok && n.Reason == report.ReasonScanCutShort {
			cause = c
		}
	}
	if cause == "" {
		cause = "an earlier scan was cut short"
	}
	return cutShortNote(cut, len(rows), cause), true
}

// priorSBOMNote discloses a baseline Report whose SBOM is the one stored before it, because the
// scan stopped before this commit's dependency inventory resolved. A stored SBOM may itself have
// been carried, so the note names no commit.
var priorSBOMNote = report.PartialityNote{
	Reason: report.ReasonScanCutShort,
	Detail: "the scan stopped before the dependency inventory was resolved; the SBOM is from the last baseline that resolved it, kept so CVE-watch still queries it",
}

// hasCutShort reports whether notes disclose a scan cut short.
func hasCutShort(notes []report.PartialityNote) bool {
	return slices.ContainsFunc(notes, func(n report.PartialityNote) bool { return n.Reason == report.ReasonScanCutShort })
}

// inventoryCutShort reports whether notes declare an inventory the scan stopped before resolving.
func inventoryCutShort(notes []report.PartialityNote) bool {
	for _, n := range notes {
		if n.Reason == report.ReasonScanCutShort && n.Detail == inventoryLimitDetail {
			return true
		}
	}
	return false
}

// ownStop is the cause recountCutShort states for a pass that cut rows itself, "" for one that cut
// none.
func ownStop(analysis context.Context, cut int) string {
	if cut == 0 {
		return ""
	}
	return stopCause(analysis)
}
