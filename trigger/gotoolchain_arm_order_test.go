// gotoolchain_arm_order_test.go
//
// The regression gate for deviation 3: `undeterminedReason` is correct ONLY because it is called from
// `finding()`'s `default:` arm, with the disqualified and candidate checks as the two earlier `case`s.
// That placement replaced two clauses the predicate used to carry itself, so control flow — not a
// condition — is now what stops an established verdict from being restated as "we established
// nothing".
//
// The disqualified half of that was already gated (TestBaseline_DisqualifiedToolchainAdvisoryIsReported
// uses a subject that is also undetermined-eligible, so hoisting the undetermined check fails it). The
// candidate half was not: no test in this package asserted a candidate at all. A future edit that
// hoisted the check above the candidate arm would have SUPPRESSED A REAL POSITIVE FINDING on a
// toolchain advisory with the whole suite green — the failure the predicate's own comment calls "a far
// worse failure than the one this closes".
//
// It is not theoretical. Pre-opt-in (`go_toolchain_not_scanned`), govulncheck runs against the
// ANALYZER's Go and can find a path to a stdlib symbol; arm order is the only thing keeping that
// finding a candidate.
package trigger

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// toolchainCandidatePlugin is goManifestPlugin with the one difference that matters here: its
// reachability answer carries a resolved path, which is what makes the pipeline write a candidate
// pair. The ingress is attacker-controllable and ON the trace, so the finding grades as a real
// candidate rather than a bare one — the strongest thing arm order has to protect.
type toolchainCandidatePlugin struct{ goManifestPlugin }

const (
	toolchainCandidateIngress = "scip go stdlibapp . main/Handler()."
	toolchainCandidateSink    = "scip go stdlibapp . archive/zip/Reader#Open()."
)

func (toolchainCandidatePlugin) FindIngresses(context.Context, plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	return plugin.IngressResult{
		Partiality: plugin.Complete(),
		Ingresses: []plugin.Ingress{{
			Symbol:   toolchainCandidateIngress,
			Kind:     "http_route",
			Selector: "/upload",
		}},
	}, nil
}

func (toolchainCandidatePlugin) Reachability(context.Context, plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	return plugin.ReachabilityResult{
		Partiality: plugin.Complete(),
		Paths: []plugin.ReachPath{{
			Ingress: toolchainCandidateIngress,
			Trace:   []string{toolchainCandidateIngress, toolchainCandidateSink},
		}},
	}, nil
}

// TestGoToolchainArmOrder_CandidateOutranksUndetermined runs ONE undetermined-eligible subject two
// ways, differing only in whether the analysis found a path. Both arms are needed: the undetermined
// arm proves the fixture really is eligible (otherwise the candidate arm would pass for the wrong
// reason), and the candidate arm proves eligibility does not override a positive finding.
func TestGoToolchainArmOrder_CandidateOutranksUndetermined(t *testing.T) {
	// go 1.20 ⇒ floor go1.20.0, and GO-2021-0264 declares no affected range at all, so the version
	// axis can never disqualify it. Reachability alone decides the disposition.
	const goFloorMod = "module example.com/target\n\ngo 1.20\n"

	t.Run("no path found: undetermined", func(t *testing.T) {
		rep := runGoBaseline(t, goFloorMod, stdlibNoRangeAdvisory)
		assertUndetermined(t, rep, "GO-2021-0264", report.ReasonGoToolchainNotScanned)
	})

	t.Run("path found: reachable_candidate, never undetermined", func(t *testing.T) {
		rep := runGoBaseline(t, goFloorMod, stdlibNoRangeAdvisory,
			pipeline.WithPlugin(toolchainCandidatePlugin{}))

		if len(rep.Advisories) != 1 {
			t.Fatalf("advisories[] = %+v, want exactly the candidate finding", rep.Advisories)
		}
		f := rep.Advisories[0]
		if f.Verdict != report.VerdictReachableCandidate {
			t.Fatalf("GO-2021-0264 verdict = %q, want %q — a path WAS found, and the undetermined check must not reach an advisory the candidate arm already answered",
				f.Verdict, report.VerdictReachableCandidate)
		}
		if f.UndeterminedReason != "" {
			t.Errorf("candidate carries undetermined_reason %q", f.UndeterminedReason)
		}
		if f.Evidence.ReachablePath == "" {
			t.Error("candidate carries no reachable_path; the fixture did not actually produce a candidate pair, so this test would pass vacuously")
		}
		if f.Evidence.Grade != report.GradeAttackerTainted {
			t.Errorf("grade = %q, want %q — the attacker-controllable ingress is on the trace", f.Evidence.Grade, report.GradeAttackerTainted)
		}
		if err := rep.Validate(); err != nil {
			t.Errorf("report invalid: %v", err)
		}

		// A finding with an established verdict must not ALSO be disclosed as a coverage limit: the
		// limit and the undetermined row appear together or not at all.
		for _, n := range rep.Partiality {
			if n.Reason == report.ReasonGoToolchainNotScanned || n.Reason == report.ReasonGoToolchainUnresolved {
				t.Errorf("limit %q emitted alongside a reachable candidate", n.Reason)
			}
		}

		// At the wire, candidate and undetermined share the `under_investigation` status, so status
		// alone cannot tell them apart. The impact statement is the discriminator: a candidate
		// carries one, an undetermined finding must not (it has no finding to characterize).
		doc, err := projection.ProjectReportVEX(*rep)
		if err != nil {
			t.Fatalf("ProjectReportVEX: %v", err)
		}
		if len(doc.Statements) != 1 {
			t.Fatalf("OpenVEX statements = %d, want 1", len(doc.Statements))
		}
		if doc.Statements[0].Status != projection.VEXStatusUnderInvestigation {
			t.Errorf("status = %q, want %q", doc.Statements[0].Status, projection.VEXStatusUnderInvestigation)
		}
		if doc.Statements[0].ImpactStatement == "" {
			t.Error("candidate statement carries no impact statement — at the wire it is now indistinguishable from an undetermined row")
		}
	})
}
