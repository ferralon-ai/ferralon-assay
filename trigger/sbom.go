package trigger

import (
	"context"
	"fmt"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// ResolveSBOMRequest configures a cheap PR-head SBOM resolution: run the S1+S2
// SBOM-producing slice for each advisory against one codebase and collect the
// resolved dependency packages. It touches no StateStore — a PR run must never
// write the baseline.
type ResolveSBOMRequest struct {
	// Codebase tells the SBOM slice how to acquire the codebase (clone / vendored
	// repro). The CLI passes a vendored_repro target already on disk.
	Codebase assessment.CodebaseRef
	// Advisories is the corpus whose modules define the resolved package set. The
	// SBOM is advisory-keyed: a module absent from this corpus contributes zero
	// packages (a dependency nobody has an advisory for is invisible to the diff).
	Advisories []assessment.VulnRef
	// AssessOptions are the pipeline seams (WithPlugin / WithCheckout) the SBOM
	// stages run with. Empty = the hermetic stub path.
	AssessOptions []pipeline.AssessOption
}

// ResolveSBOM resolves the codebase's advisory-keyed SBOM by running only the cheap
// S1+S2 SBOM slice (pipeline.SBOMStages) per advisory — no disqualification, symbol
// mapping, reachability, or verdict work. For each advisory it reads back the
// resolved package (advisoryFromArtifacts), unions distinct packages, and sorts by
// {Ecosystem, Name} for deterministic content addressing.
//
// It is the PR-inherit head-SBOM resolver: the result is diffed against the stored
// baseline SBOM to decide the inherit fast path vs. re-analysis. It mirrors the
// SBOM-building loop in buildBaselineReport but runs the two-stage slice instead of
// the full S1–S6 pipeline and never builds a Report or touches the StateStore, so a
// PR run cannot mutate baseline state (Risk: a PR run must never write the baseline).
func ResolveSBOM(ctx context.Context, req ResolveSBOMRequest) (report.SBOM, error) {
	seenPkg := make(map[report.Package]struct{})
	var pkgs []report.Package
	for _, adv := range req.Advisories {
		areq := assessment.Request{Vulnerability: adv, Codebase: req.Codebase}
		st, assessmentID, err := assessSBOM(ctx, areq, req.AssessOptions...)
		if err != nil {
			return report.SBOM{}, err
		}
		_, pkg := advisoryFromArtifacts(st, assessmentID, areq)
		if pkg == nil {
			continue
		}
		if _, ok := seenPkg[*pkg]; ok {
			continue
		}
		seenPkg[*pkg] = struct{}{}
		pkgs = append(pkgs, *pkg)
	}

	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Ecosystem != pkgs[j].Ecosystem {
			return pkgs[i].Ecosystem < pkgs[j].Ecosystem
		}
		return pkgs[i].Name < pkgs[j].Name
	})
	return report.SBOM{Packages: pkgs}, nil
}

// assessSBOM runs the cheap S1+S2 SBOM slice for one advisory against one codebase
// and returns the artifact store holding the run's output. It mirrors assess but
// composes pipeline.SBOMStages — the two stages that produce the SBOM facts — so the
// resolver never runs the analysis stages it does not need.
func assessSBOM(ctx context.Context, req assessment.Request, opts ...pipeline.AssessOption) (artifact.Store, string, error) {
	assessments := assessment.NewMemStore()
	store := artifact.NewMemStore()

	a, err := assessments.Create(req)
	if err != nil {
		return nil, "", fmt.Errorf("trigger: create assessment: %w", err)
	}

	orch := pipeline.NewOrchestrator(assessments, store, pipeline.SBOMStages(opts...))
	if err := orch.Run(ctx, a.ID); err != nil {
		return nil, "", fmt.Errorf("trigger: resolve sbom %s: %w", req.Vulnerability.ID, err)
	}
	return store, a.ID, nil
}
