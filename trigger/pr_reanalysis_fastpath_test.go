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

// fastPathEdit changes a fastPathRun's baseline and request before the run, leaving the head's
// packages as the baseline's so the run still takes the fast path.
type fastPathEdit func(baseline *report.Report, req *PRInheritRequest)

// fastPathRun runs PR re-analysis of workSet over a head identical to a baseline that holds
// wiringPkg and a row for twoPackageAdvisory. cursor is the run's advisory cursor; edits change
// the baseline and request first. It returns the result and the number of checkouts the run
// fetched.
func fastPathRun(t *testing.T, workSet []assessment.VulnRef, p plugin.LanguagePlugin, cursor string, edits ...fastPathEdit) (*PRInheritResult, int) {
	t.Helper()
	pkg := wiringPkg
	baseline := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
		AddPackage(pkg).
		NotExploitable(report.Advisory{ID: twoPackageAdvisory.ID, Source: twoPackageAdvisory.Source}, &pkg, "vulnerable_symbol_absent", baselineDetail).
		WithProvenance(report.Provenance{CommitSHA: "base-sha", AdvisoryCursor: twoPackageAdvisory.ID}).
		Build()
	fetches := 0
	req := PRInheritRequest{
		Subject:    Subject{Repo: "r", ResolvedCommit: "pr-sha"},
		Codebase:   assessment.CodebaseRef{Repo: "r", Revision: "main"},
		PRSBOM:     report.SBOM{Packages: []report.Package{wiringPkg}},
		Advisories: workSet,
		Cursor:     cursor,
		AssessOptions: []pipeline.AssessOption{
			pipeline.WithCheckout(countingCheckout{fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}, &fetches}),
			pipeline.WithPlugin(p),
		},
	}
	for _, edit := range edits {
		edit(&baseline, &req)
	}
	store := &memStore{state: &statestore.State{Report: &baseline, SBOM: baseline.SBOM, Cursor: twoPackageAdvisory.ID}}
	res, err := RunPRInherit(context.Background(), store, req)
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

	// Two sources sharing C's id are two rows, but one id to name.
	otherSource := assessment.VulnRef{ID: wiringAdvisory.ID, Source: "osv"}
	res, _ = fastPathRun(t, []assessment.VulnRef{twoPackageAdvisory, wiringAdvisory, otherSource},
		refutingGoPlugin{inventory: plugin.Complete()}, "")
	if want := []string{wiringAdvisory.ID}; !slices.Equal(res.AssessedAdvisories, want) {
		t.Errorf("two sources: AssessedAdvisories = %q, want %q", res.AssessedAdvisories, want)
	}

	migrated := &report.Report{Advisories: []report.AdvisoryFinding{{Advisory: report.Advisory{ID: wiringAdvisory.ID}}}}
	if got := unrowedAdvisories(migrated, []assessment.VulnRef{wiringAdvisory}); len(got) != 0 {
		t.Errorf("unrowed = %+v, want none: the migrated v1 row stands for it", got)
	}

	// A scan_cut_short row is no row: its advisory is assessed like one the baseline never held.
	cut := &report.Report{Advisories: []report.AdvisoryFinding{cutShortFinding(wiringAdvisory)}}
	if got := unrowedAdvisories(cut, []assessment.VulnRef{wiringAdvisory}); !slices.Equal(got, []assessment.VulnRef{wiringAdvisory}) {
		t.Errorf("unrowed = %+v, want %s: a cut row stands for nothing", got, wiringAdvisory.ID)
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

// forkNamingSource is the advisory table, with C also naming example.com/fork beside
// golang.org/x/text. The fork is in the build only where a replace directive brings it in.
type forkNamingSource struct{}

func (forkNamingSource) Lookup(id string) (pipeline.AdvisoryFacts, bool) {
	facts, ok := pipeline.NewTableSource().Lookup(id)
	if id != wiringAdvisory.ID {
		return facts, ok
	}
	affected := func(module string) pipeline.AffectedPackage {
		return pipeline.AffectedPackage{
			Module: module, PURL: "pkg:golang/" + module,
			UpperExclusive: facts.UpperExclusive, FixedVersion: facts.FixedVersion,
			Symbols: facts.Symbols,
		}
	}
	facts.AffectedPackages = []pipeline.AffectedPackage{affected("golang.org/x/text"), affected("example.com/fork")}
	return facts, ok
}

// TestInheritFastPath_FreshRowIsTheHeads: C's fresh row is the head's, held to the head's
// inventory limits and checked against the head's Go module list, and an undetermined one carries
// the notes that explain it. The last row is the control.
func TestInheritFastPath_FreshRowIsTheHeads(t *testing.T) {
	didNotRun := inventoryPartialityNotes(partialInv, "Go")
	// The baseline and head both carry a complete Go build list; the head replaces x/text with
	// example.com/fork, which changes the module list and nothing changedPackages compares.
	replaceOnly := func(baseline *report.Report, req *PRInheritRequest) {
		baseline.SBOM.GoBuildList, baseline.SBOM.GoMainModule = plugin.BuildListGoModGraph, "example.com/target"
		fork := wiringPkg
		fork.Replace = "example.com/fork"
		req.PRSBOM = report.SBOM{GoBuildList: plugin.BuildListGoModGraph, GoMainModule: "example.com/target", Packages: []report.Package{fork}}
		req.AssessOptions = append(req.AssessOptions, pipeline.WithAdvisorySource(forkNamingSource{}))
	}
	cases := []struct {
		name       string
		edit       fastPathEdit
		wantReason string                  // C's undetermined reason; "" wants the assessment's not_exploitable
		wantNotes  []report.PartialityNote // notes the Report must carry for C's undetermined row
	}{
		{"G0: the head's Go inventory did not run",
			func(_ *report.Report, req *PRInheritRequest) { req.DiffLimits = didNotRun },
			report.ReasonAnalysisDidNotRun, didNotRun},
		{"a replace-only head brings the fork C names into the build",
			replaceOnly,
			report.ReasonVulnerableSymbolUnresolved, []report.PartialityNote{{Reason: report.ReasonVulnerableSymbolUnresolved, Ecosystem: "Go"}}},
		{"control: a complete head with no replace",
			func(*report.Report, *PRInheritRequest) {},
			"", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := fastPathRun(t, []assessment.VulnRef{twoPackageAdvisory, wiringAdvisory},
				refutingGoPlugin{inventory: plugin.Complete()}, "", tc.edit)
			c := oneRow(t, res.Report, wiringAdvisory.ID)
			if tc.wantReason == "" {
				if c.Verdict != report.VerdictNotExploitable {
					t.Errorf("C's row = %s/%s, want not_exploitable", c.Verdict, c.UndeterminedReason)
				}
				return
			}
			if c.Verdict != report.VerdictUndetermined || c.UndeterminedReason != tc.wantReason {
				t.Errorf("C's row = %s/%s, want undetermined/%s", c.Verdict, c.UndeterminedReason, tc.wantReason)
			}
			for _, n := range tc.wantNotes {
				if !slices.ContainsFunc(res.Report.Partiality, func(got report.PartialityNote) bool {
					return got.Reason == n.Reason && got.Ecosystem == n.Ecosystem && got.Detail == n.Detail
				}) {
					t.Errorf("C's row is undetermined, but the Report carries no %+v: %+v", n, res.Report.Partiality)
				}
			}
		})
	}
}

// TestInheritBaseline_ValidatesFreshRows: the fresh rows are validated, as the slow path's are;
// the baseline's rows are re-emitted unvalidated, as they always have been, whether or not fresh
// rows sit beside them, so a stored row today's Validate rejects never fails the run.
func TestInheritBaseline_ValidatesFreshRows(t *testing.T) {
	valid := report.AdvisoryFinding{Advisory: report.Advisory{ID: "FERRALON-TEST-357", Source: "corpus"},
		Verdict: report.VerdictUndetermined, UndeterminedReason: report.ReasonAnalysisDidNotRun}
	invalid := valid
	invalid.UndeterminedReason = "" // an undetermined row must say why
	storedInvalid := invalid
	storedInvalid.Advisory.ID = "FERRALON-TEST-STORED"
	cases := []struct {
		name    string
		stored  []report.AdvisoryFinding
		fresh   []report.AdvisoryFinding
		wantErr bool
	}{
		{"an invalid fresh row", nil, []report.AdvisoryFinding{invalid}, true},
		{"a valid fresh row", nil, []report.AdvisoryFinding{valid}, false},
		{"pure inherit of an invalid stored row", []report.AdvisoryFinding{invalid}, nil, false},
		{"an invalid stored row beside a valid fresh row", []report.AdvisoryFinding{storedInvalid}, []report.AdvisoryFinding{valid}, false},
		{"an invalid fresh row beside an invalid stored row", []report.AdvisoryFinding{storedInvalid}, []report.AdvisoryFinding{invalid}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseline := report.Report{SchemaVersion: report.SchemaVersion, Advisories: tc.stored}
			_, err := inheritBaseline(&baseline, PRInheritRequest{Subject: Subject{Repo: "r", ResolvedCommit: "pr-sha"}},
				&statestore.State{}, tc.fresh, nil, "")
			if (err != nil) != tc.wantErr {
				t.Errorf("inheritBaseline err = %v, want error: %v", err, tc.wantErr)
			}
		})
	}
}
