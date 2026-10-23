package trigger

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// These tests pin the PR re-analysis fast path (an unchanged SBOM) to the invariant the slow path
// keeps: an advisory is never left without a row. The baseline holds a row for twoPackageAdvisory
// (A) only; wiringAdvisory (C) is new to the work set. tracker#357.

// countingCheckout is fixedCheckout counting its fetches, so a test can tell whether any
// assessment ran.
type countingCheckout struct {
	fixedCheckout
	fetches *int
}

func (c countingCheckout) Fetch(ctx context.Context, repo, revision string) (checkout.WorkspacePlan, error) {
	*c.fetches++
	return c.fixedCheckout.Fetch(ctx, repo, revision)
}

// fastPathRun runs PR re-analysis of workSet over a head identical to a baseline that holds
// wiringPkg and a row for twoPackageAdvisory. cursor is the run's advisory cursor. It returns the
// result and the number of checkouts the run fetched.
func fastPathRun(t *testing.T, workSet []assessment.VulnRef, p plugin.LanguagePlugin, cursor string) (*PRInheritResult, int) {
	t.Helper()
	pkg := wiringPkg
	baseline := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
		AddPackage(pkg).
		NotExploitable(report.Advisory{ID: twoPackageAdvisory.ID, Source: twoPackageAdvisory.Source}, &pkg, "vulnerable_symbol_absent", baselineDetail).
		WithProvenance(report.Provenance{CommitSHA: "base-sha", AdvisoryCursor: twoPackageAdvisory.ID}).
		Build()
	store := &memStore{state: &statestore.State{Report: &baseline, SBOM: baseline.SBOM, Cursor: twoPackageAdvisory.ID}}
	fetches := 0
	res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
		Subject:    Subject{Repo: "r", ResolvedCommit: "pr-sha"},
		Codebase:   assessment.CodebaseRef{Repo: "r", Revision: "main"},
		PRSBOM:     report.SBOM{Packages: []report.Package{wiringPkg}},
		Advisories: workSet,
		Cursor:     cursor,
		AssessOptions: []pipeline.AssessOption{
			pipeline.WithCheckout(countingCheckout{fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}, &fetches}),
			pipeline.WithPlugin(p),
		},
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	if !res.Inherited {
		t.Fatalf("took the slow path (changed = %q); every case here leaves the SBOM unchanged", res.ChangedPackages)
	}
	return res, fetches
}

// oneRow returns the report's only row for the advisory id, failing the test unless there is
// exactly one.
func oneRow(t *testing.T, rep *report.Report, id string) report.AdvisoryFinding {
	t.Helper()
	rows := rowsFor(rep, id)
	if len(rows) != 1 {
		t.Fatalf("%d rows for %s, want 1: %+v", len(rows), id, rows)
	}
	return rows[0]
}

// TestInheritFastPath_NewAdvisoryGetsFreshRow_Issue357: Eric's repro. A baseline holding A, a
// work set holding A and C, and an unchanged SBOM: A inherits its baseline row, and C, which has
// no row to inherit, is assessed and gets a fresh one.
func TestInheritFastPath_NewAdvisoryGetsFreshRow_Issue357(t *testing.T) {
	res, fetches := fastPathRun(t, []assessment.VulnRef{twoPackageAdvisory, wiringAdvisory},
		refutingGoPlugin{inventory: plugin.Complete()}, "")
	if a := oneRow(t, res.Report, twoPackageAdvisory.ID); a.Evidence.Detail != baselineDetail {
		t.Errorf("A's row is not the baseline's: %s, %q", a.Verdict, a.Evidence.Detail)
	}
	c := oneRow(t, res.Report, wiringAdvisory.ID)
	if c.Verdict != report.VerdictNotExploitable || c.Advisory.Source != wiringAdvisory.Source {
		t.Errorf("C's row = %s from %q, want the assessment's not_exploitable from %q", c.Verdict, c.Advisory.Source, wiringAdvisory.Source)
	}
	if fetches != 1 {
		t.Errorf("fetched %d checkouts, want 1: C alone is assessed", fetches)
	}
}

// TestInheritFastPath_EveryAdvisoryRowed_NoAssessment: the control. With a baseline row for every
// work-set advisory the fast path is a pure inherit: the row is the baseline's and no assessment
// runs, so no checkout is fetched.
func TestInheritFastPath_EveryAdvisoryRowed_NoAssessment(t *testing.T) {
	res, fetches := fastPathRun(t, []assessment.VulnRef{twoPackageAdvisory},
		refutingGoPlugin{inventory: plugin.Complete()}, "")
	if a := oneRow(t, res.Report, twoPackageAdvisory.ID); a.Evidence.Detail != baselineDetail {
		t.Errorf("A's row is not the baseline's: %s, %q", a.Verdict, a.Evidence.Detail)
	}
	if len(res.Report.Advisories) != 1 {
		t.Errorf("%d rows, want only A's: %+v", len(res.Report.Advisories), res.Report.Advisories)
	}
	if fetches != 0 {
		t.Errorf("fetched %d checkouts, want none: nothing needed assessing", fetches)
	}
	if len(res.AssessedAdvisories) != 0 {
		t.Errorf("AssessedAdvisories = %q, want none", res.AssessedAdvisories)
	}
}

// TestInheritFastPath_AssessedAdvisories: the result names the advisories the fast path assessed,
// each once, and a migrated v1 row (no source) counts as a row, as it does on the slow path.
func TestInheritFastPath_AssessedAdvisories(t *testing.T) {
	res, _ := fastPathRun(t, []assessment.VulnRef{twoPackageAdvisory, wiringAdvisory, wiringAdvisory},
		refutingGoPlugin{inventory: plugin.Complete()}, "")
	if want := []string{wiringAdvisory.ID}; !slices.Equal(res.AssessedAdvisories, want) {
		t.Errorf("AssessedAdvisories = %q, want %q", res.AssessedAdvisories, want)
	}
	oneRow(t, res.Report, wiringAdvisory.ID)

	migrated := &report.Report{Advisories: []report.AdvisoryFinding{{Advisory: report.Advisory{ID: wiringAdvisory.ID}}}}
	if got := unrowedAdvisories(migrated, []assessment.VulnRef{wiringAdvisory}); len(got) != 0 {
		t.Errorf("unrowed = %+v, want none: the migrated v1 row stands for it", got)
	}
}

// TestInheritFastPath_CursorClaimsOnlyRowedOrDisclosed: the Report's cursor names A and C; after
// the run every advisory it names has a row or a partiality note naming it, whether C's
// assessment succeeds or fails.
func TestInheritFastPath_CursorClaimsOnlyRowedOrDisclosed(t *testing.T) {
	cases := []struct {
		name     string
		p        plugin.LanguagePlugin
		wantNote bool // C's row is undetermined, and a note names C
	}{
		{"C assessed", refutingGoPlugin{inventory: plugin.Complete()}, false},
		{"C's assessment fails", failingReachabilityPlugin{refutingGoPlugin{inventory: plugin.Complete()}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cursor := twoPackageAdvisory.ID + "," + wiringAdvisory.ID
			res, _ := fastPathRun(t, []assessment.VulnRef{twoPackageAdvisory, wiringAdvisory}, tc.p, cursor)
			rep := res.Report
			if rep.Provenance.AdvisoryCursor != cursor {
				t.Fatalf("AdvisoryCursor = %q, want %q", rep.Provenance.AdvisoryCursor, cursor)
			}
			noted := func(id string) bool {
				return slices.ContainsFunc(rep.Partiality, func(n report.PartialityNote) bool {
					return strings.Contains(n.Detail, id)
				})
			}
			for id := range cursorSet(rep.Provenance.AdvisoryCursor) {
				if len(rowsFor(rep, id)) == 0 && !noted(id) {
					t.Errorf("the cursor claims %s, which has neither a row nor a partiality note", id)
				}
			}
			if tc.wantNote {
				if c := oneRow(t, rep, wiringAdvisory.ID); c.Verdict != report.VerdictUndetermined || !noted(wiringAdvisory.ID) {
					t.Errorf("C's row = %s, noted = %v; want undetermined and a note naming %s", c.Verdict, noted(wiringAdvisory.ID), wiringAdvisory.ID)
				}
			}
		})
	}
}
