// gotoolchain_repro_disclosure_test.go
//
// The hermetic half of the toolchain-disclosure regression. A live end-to-end test elsewhere
// carried a skip whose stated reason WAS the defect — "the host govulncheck toolchain is 1.26.3 so
// the vulnerable symbol is not flagged" — which made it the defect's own regression test, disabled.
// A skip cannot assert anything, so the assertion lives here, over the same fixture tree, in the
// suite that runs on every commit.
//
// What it pins is not "the fixture is now green". It pins that the outcome is an honest DISCLOSED
// PARTIAL rather than the false green: no not_exploitable row, no OpenVEX not_affected attestation, and
// the advisory named in a scan-level coverage limit. That is the assertion the skip should always have
// been, and it holds whether or not the subject-toolchain reachability flag is on.
//
// The fixture stays unscannable for a separate, measured reason that is asserted where it lives rather
// than claimed here: GO-2021-0264's affected range tops out at Go 1.17.2, and the analyzer's package
// loader cannot drive a go command older than 1.20 — goanalysis' loaderMinMinor, whose own table pins
// go1.17.1 as out of reach (TestGoRelease_Loadable). This file asserts the DISPOSITION; that file
// asserts the CAUSE.
package trigger

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/corpus"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// The corpus repro's own Dockerfile pins FROM golang:1.17.1 — a subject deliberately built inside
// GO-2021-0264's affected range (Go 1.16.0-1.16.9 / 1.17.0-1.17.2). Declaring it is what a customer
// with that build would do, and it is the strongest input the fact can take: exact.
const (
	reproFixtureRelPath = "testdata/repros/GO-2021-0264-reachable/"
	reproPinnedGo       = "go1.17.1"
)

// runGoBaselineIn is runGoBaseline against an EXISTING tree rather than a synthesized go.mod, so the
// fixture under assertion is the one the corpus ships and the one the live harness builds.
func runGoBaselineIn(t *testing.T, buildDir string, advisories []assessment.VulnRef, opts ...pipeline.AssessOption) *report.Report {
	t.Helper()
	opts = append([]pipeline.AssessOption{
		pipeline.WithCheckout(fixedCheckout{dir: buildDir, lang: "go"}),
		pipeline.WithPlugin(goManifestPlugin{}),
	}, opts...)
	rep, err := buildBaselineReport(context.Background(), BaselineRequest{
		Subject:       Subject{Repo: "github.com/ferralon-ai/tegron-corpus-repros", Revision: "main", ResolvedCommit: "deadbeef"},
		Codebase:      assessment.CodebaseRef{Repo: "github.com/ferralon-ai/tegron-corpus-repros", Revision: "main"},
		Advisories:    advisories,
		AssessOptions: opts,
	})
	if err != nil {
		t.Fatalf("buildBaselineReport: %v", err)
	}
	return rep
}

// assessRepro runs the S1–S6 assess pipeline once over the repro tree and returns its store, so the
// artifacts the report projection hides — the toolchain fact, the scan record — can be read directly.
func assessRepro(t *testing.T, buildDir string) (artifact.Store, string, error) {
	t.Helper()
	return assess(context.Background(), assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "GO-2021-0264", Source: "corpus"},
		Codebase:      assessment.CodebaseRef{Repo: "github.com/ferralon-ai/tegron-corpus-repros", Revision: "main"},
	},
		pipeline.WithCheckout(fixedCheckout{dir: buildDir, lang: "go"}),
		pipeline.WithPlugin(goManifestPlugin{}),
		pipeline.WithSubjectToolchain(reproPinnedGo, "", false),
		pipeline.WithSubjectToolchainReachability(true),
	)
}

// TestRepro_GO20210264_YieldsADisclosedPartialNotAFalseGreen runs the real baseline over the real
// corpus repro tree, with the fixture's own pinned toolchain declared, in both flag states. The
// disposition must be identical in both, because the flag alone establishes nothing: without a scan
// that actually ran under the subject's toolchain, an exact fact is still only a fact.
func TestRepro_GO20210264_YieldsADisclosedPartialNotAFalseGreen(t *testing.T) {
	reproDir := corpus.ReproPath(reproFixtureRelPath)

	for _, flagOn := range []bool{false, true} {
		name := "flag off"
		if flagOn {
			name = "flag on, no subject scan (the flag alone changes nothing)"
		}
		t.Run(name, func(t *testing.T) {
			rep := runGoBaselineIn(t, reproDir,
				[]assessment.VulnRef{{ID: "GO-2021-0264", Source: "corpus"}},
				pipeline.WithSubjectToolchain(reproPinnedGo, "", false),
				pipeline.WithSubjectToolchainReachability(flagOn),
			)

			for _, f := range rep.Advisories {
				if f.Verdict != report.VerdictUndetermined {
					t.Errorf("advisories[] carries %s with verdict %q basis %q — the vulnerable symbol's absence was established against the ANALYZER's toolchain, not the subject's go1.17.1, so no verdict may rest on it",
						f.Advisory.ID, f.Verdict, f.Evidence.Basis)
				}
			}

			ids := undeterminedByReason(rep)[report.ReasonGoToolchainNotScanned]
			if len(ids) != 1 || ids[0] != "GO-2021-0264" {
				t.Errorf("undetermined under %s = %v, want [GO-2021-0264]", report.ReasonGoToolchainNotScanned, ids)
			}

			// The consequence that mattered enough to open this cycle: the machine-readable
			// safety attestation is gone. It must fall out of the VERDICT, not out of projector
			// code — report_vex.go's default arm already routes an unknown verdict to
			// under_investigation, so no edit there was needed or made.
			assertNoNotAffected(t, rep, "GO-2021-0264")
		})
	}
}

// TestRepro_GO20210264_TheFactItselfIsExactAndHonest separates the two halves the ADR insists are
// different quantities. The subject fact resolves EXACT from the declaration — the strongest bound
// there is — and the advisory is still withheld. That is the asymmetry stated as a test: an exact bound
// licenses a refutation only together with a scan that actually used it.
func TestRepro_GO20210264_TheFactItselfIsExactAndHonest(t *testing.T) {
	reproDir := corpus.ReproPath(reproFixtureRelPath)
	store, id, err := assessRepro(t, reproDir)
	if err != nil {
		t.Fatalf("assess: %v", err)
	}

	fact, ok := pipeline.Toolchain(store, id)
	if !ok {
		t.Fatal("no inventory toolchain fact recorded")
	}
	want := pipeline.ToolchainFact{
		Version: reproPinnedGo,
		Bound:   pipeline.ToolchainBoundExact,
		Source:  pipeline.ToolchainSourceSubjectDeclared,
	}
	if fact != want {
		t.Errorf("toolchain fact = %+v, want %+v", fact, want)
	}
	if pipeline.SubjectToolchainScanned(store, id) {
		t.Error("SubjectToolchainScanned = true with no analysis under the subject's toolchain; nothing here is evidence about the subject")
	}
	if _, undetermined := undeterminedReason(store, id); !undetermined {
		t.Errorf("undeterminedReason reports an established verdict on an exact-but-unscanned toolchain; basis %q would be emitted unestablished", verdict.BasisSymbolAbsent)
	}
}
