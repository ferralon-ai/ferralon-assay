package trigger

import (
	"context"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// ResolveSBOMRequest configures a whole-graph PR-head SBOM resolution: resolve the codebase's whole
// dependency inventory once (pipeline.ResolveCodebaseInventory) and project it to a report.SBOM. It
// touches no StateStore — a PR run must never write the baseline.
type ResolveSBOMRequest struct {
	// Codebase tells the resolver how to acquire the codebase (clone / vendored repro). The CLI
	// passes a vendored_repro target already on disk.
	Codebase assessment.CodebaseRef
	// AssessOptions are the pipeline seams (WithPlugin / WithCheckout) the inventory resolution runs
	// with. Empty = the hermetic path (no language plugin), which yields a declared-partial empty
	// SBOM rather than a silently empty one.
	AssessOptions []pipeline.AssessOption
}

// ResolveSBOM resolves the codebase's whole-graph SBOM by resolving the dependency inventory once
// and projecting it (sbomFromInventory). Post-PLAN-100 the SBOM is INVENTORY-keyed, not
// advisory-keyed: a dependency reaches the SBOM whether or not any advisory names it — the property
// §4.1 requires so a later CVE-watch can discover advisories for packages absent from the current
// work set.
//
// It is the PR-inherit head-SBOM resolver: the result is diffed against the stored baseline SBOM to
// decide the inherit fast path vs. re-analysis. It builds no Report and touches no StateStore, so a
// PR run cannot mutate baseline state (Risk: a PR run must never write the baseline).
//
// It returns the inventory's scan-level partiality alongside the package set (PLAN-104, revising
// PLAN-100's choice to drop it here). The diff needs only the package set to decide inherit-vs-
// reanalyze, but an unresolved head inventory can make a changed dependency set look unchanged — so
// the caller forwards these notes as PRInheritRequest.DiffLimits, disclosed on the fast path (§4.1 /
// C3). Absent means the inventory resolved cleanly, exactly as it does for buildBaselineReport.
func ResolveSBOM(ctx context.Context, req ResolveSBOMRequest) (report.SBOM, []report.PartialityNote, error) {
	inv, language, _, err := pipeline.ResolveCodebaseInventory(ctx, req.Codebase, "", req.AssessOptions...)
	if err != nil {
		return report.SBOM{}, nil, err
	}
	sbom, notes := sbomFromInventory(inv, ecosystemFor(language))
	return sbom, notes, nil
}
