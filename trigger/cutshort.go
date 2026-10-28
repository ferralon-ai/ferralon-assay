package trigger

import (
	"context"
	"fmt"
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
	observePhase(analysis, "advisory", start)
	if analysis.Err() != nil {
		return nil, "", true, nil
	}
	return st, assessmentID, false, err
}

// inventoryWithin resolves the codebase inventory under analysis. When the scan stopped before it
// returned, the inventory is declared unresolved instead, so the Report is still built and every
// advisory still gets its row.
func inventoryWithin(analysis context.Context, codebase assessment.CodebaseRef, opts ...pipeline.AssessOption) (plugin.DependencyInventory, string, error) {
	start := time.Now()
	inv, language, _, err := pipeline.ResolveCodebaseInventory(analysis, codebase, "", opts...)
	observePhase(analysis, "inventory", start)
	if analysis.Err() != nil {
		return plugin.DependencyInventory{Partiality: plugin.Partial(report.ReasonScanCutShort)}, language, nil
	}
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

// cutShortNote is the one scan-level disclosure for a pass that left cut of its total advisories
// unassessed. Its detail carries the stop's cause, which names how to give the scan more time.
func cutShortNote(analysis context.Context, cut, total int) report.PartialityNote {
	return report.PartialityNote{
		Reason: report.ReasonScanCutShort,
		Detail: fmt.Sprintf("%d of %d advisories were not assessed: %v", cut, total, context.Cause(analysis)),
	}
}

// priorSBOMNote discloses a baseline Report whose SBOM is the one stored before it, because the
// scan stopped before this commit's dependency inventory resolved.
var priorSBOMNote = report.PartialityNote{
	Reason: report.ReasonScanCutShort,
	Detail: "the scan stopped before the dependency inventory was resolved; the SBOM is the previous baseline's, kept so CVE-watch still queries it",
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
