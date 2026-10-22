package trigger

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// factSource is an AdvisorySource over a fixed set of records.
type factSource map[string]pipeline.AdvisoryFacts

func (s factSource) Lookup(id string) (pipeline.AdvisoryFacts, bool) {
	f, ok := s[id]
	return f, ok
}

// sharedAliasAdvisory names CVE-2021-38561, which GO-2021-0113 also aliases, and is in no
// AdvisoryTable entry: the fact source the run is given is the only place its aliases are read.
const sharedAliasAdvisory = "GHSA-2099-aaaa-0001"

// claimsScopeSource is the table, plus sharedAliasAdvisory.
func claimsScopeSource() pipeline.AdvisorySource {
	return pipeline.NewChainSource(factSource{sharedAliasAdvisory: {Aliases: []string{"CVE-2021-38561"}}}, pipeline.NewTableSource())
}

// TestRankWithClaimsTheWorkSet: a run's claims are its work set, not only its rows. A GO row aliasing
// CVE-2021-38561 takes that CVE's EPSS when nothing else in the run names it, and none when an
// advisory the run was asked about names it too, though that advisory has no row in the report.
func TestRankWithClaimsTheWorkSet(t *testing.T) {
	sig := prioritySignals(t)
	row := report.AdvisoryFinding{Advisory: report.Advisory{ID: "GO-2021-0113", Source: "osv", Aliases: []string{"CVE-2021-38561", "GHSA-ppp9-7jff-5vj2"}}, Verdict: report.VerdictDisqualified}
	rank := func(workSet ...string) *report.Priority {
		b := report.NewBuilder(report.Subject{Repo: "github.com/example/widget"}).AddFinding(row)
		var refs []assessment.VulnRef
		for _, id := range workSet {
			refs = append(refs, assessment.VulnRef{ID: id, Source: "osv"})
		}
		rankWith(b, sig, refs, claimsScopeSource())
		return b.Build().Advisories[0].Priority
	}
	if p := rank("GO-2021-0113"); p == nil || p.EPSSAsOf != "2026-10-18" {
		t.Errorf("work set of the row alone: priority = %+v, want CVE-2021-38561's EPSS through its alias", p)
	}
	if p := rank("GO-2021-0113", sharedAliasAdvisory); p != nil {
		t.Errorf("%s, in the work set with no row, also names CVE-2021-38561: priority = %+v, want none", sharedAliasAdvisory, *p)
	}
}

// TestRowRanksTheSameOnEveryPath: one work set, three reports — the baseline, where the
// shared-alias advisory is deferred and so has no row; the PR-inherit fast path; and the PR
// re-analysis, which assesses that advisory into a row of its own. GO-2021-0113's row ranks the same
// in all three, and, with the advisory naming its CVE in the work set, has no priority in any.
// Without it, the row takes the CVE's EPSS in all three, so the equality is not vacuous.
func TestRowRanksTheSameOnEveryPath(t *testing.T) {
	ctx := context.Background()
	sig := prioritySignals(t)
	codebase := goFixtureModule(t)
	opts := []pipeline.AssessOption{
		pipeline.WithPlugin(fakeInventoryPlugin{lang: "go", inv: twoPackageInventory()}),
		pipeline.WithAdvisorySource(claimsScopeSource()),
	}
	subject := Subject{Repo: "example.com/app", ResolvedCommit: "sha"}
	priorityOf := func(t *testing.T, rep *report.Report) *report.Priority {
		t.Helper()
		for _, f := range rep.Advisories {
			if f.Advisory.ID == "GO-2021-0113" {
				return f.Priority
			}
		}
		t.Fatalf("no GO-2021-0113 row in %+v", rep.Advisories)
		return nil
	}
	for _, c := range []struct {
		name    string
		workSet []assessment.VulnRef
		want    *report.Priority
	}{
		{"shared alias in the work set", []assessment.VulnRef{{ID: "GO-2021-0113", Source: "osv"}, {ID: sharedAliasAdvisory, Source: "ghsa"}}, nil},
		{"row alone", []assessment.VulnRef{{ID: "GO-2021-0113", Source: "osv"}}, &report.Priority{EPSSScore: 0.0123, EPSSPercentile: 0.456, HasPercentile: true, EPSSAsOf: "2026-10-18"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			baseline, err := buildBaselineReport(ctx, BaselineRequest{
				Subject: subject, Codebase: codebase, Advisories: c.workSet, AssessOptions: opts, Signals: sig,
				Bands: map[string]Band{sharedAliasAdvisory: BandDeferred},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range baseline.Advisories {
				if f.Advisory.ID == sharedAliasAdvisory {
					t.Fatalf("the baseline holds a row for deferred %s", sharedAliasAdvisory)
				}
			}
			store := &memStore{}
			if _, err := store.Write(ctx, &statestore.State{Report: baseline, SBOM: baseline.SBOM}); err != nil {
				t.Fatal(err)
			}
			pr := func(head report.SBOM) *report.Report {
				res, err := RunPRInherit(ctx, store, PRInheritRequest{
					Subject: subject, Codebase: codebase, PRSBOM: head, Advisories: c.workSet, AssessOptions: opts, Signals: sig,
				})
				if err != nil {
					t.Fatal(err)
				}
				return res.Report
			}
			changed := baseline.SBOM
			changed.Packages = append([]report.Package{{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.8"}}, changed.Packages...)
			reports := map[string]*report.Report{"baseline": baseline, "PR inherit": pr(baseline.SBOM), "PR re-analysis": pr(changed)}
			if len(c.workSet) > 1 {
				rows := false
				for _, f := range reports["PR re-analysis"].Advisories {
					rows = rows || f.Advisory.ID == sharedAliasAdvisory
				}
				if !rows {
					t.Fatalf("the PR re-analysis holds no row for %s; the case needs one", sharedAliasAdvisory)
				}
			}
			for path, rep := range reports {
				got := priorityOf(t, rep)
				if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
					t.Errorf("%s: GO-2021-0113 priority = %+v, want %+v", path, got, c.want)
				}
			}
		})
	}
}
