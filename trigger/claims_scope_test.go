package trigger

import (
	"context"
	"strings"
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

// TestRowRanksTheSameOnEveryPath: one work set, four reports — the baseline, where the
// shared-alias advisory is deferred and so has no row; the PR-inherit fast path; the PR re-analysis,
// which assesses that advisory into a row of its own; and a CVE-watch earnest run, which assesses
// only an advisory new to its cursor and inherits GO-2021-0113's row, so the shared-alias advisory
// holds no row there either. GO-2021-0113's row ranks the same in all four, and, with the advisory
// naming its CVE in the work set, has no priority in any. Without it, the row takes the CVE's EPSS in
// all four, so the equality is not vacuous.
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
			// The cursor holds the work set; OSV.dev now also reports an advisory new to it.
			var cursor []string
			for _, v := range c.workSet {
				cursor = append(cursor, v.ID)
			}
			watchStore := &memStore{state: &statestore.State{Report: baseline, SBOM: baseline.SBOM, Cursor: strings.Join(cursor, ",")}}
			watch, err := RunCVEWatch(ctx, watchStore, &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{
				{ID: "GO-2021-0113", Package: report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.6"}},
				{ID: "GO-2099-0002", Package: report.Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.17.0"}},
			}}}, CVEWatchRequest{Subject: subject, Codebase: codebase, Advisories: c.workSet, AssessOptions: opts, Signals: sig})
			if err != nil {
				t.Fatal(err)
			}
			if watch.Heartbeat || len(watch.NewAdvisories) != 1 {
				t.Fatalf("CVE watch: heartbeat %v, new %v; the case needs one earnest run over one new advisory", watch.Heartbeat, watch.NewAdvisories)
			}
			for _, f := range watch.Report.Advisories {
				if f.Advisory.ID == sharedAliasAdvisory {
					t.Fatalf("the CVE watch holds a row for %s; the case needs none", sharedAliasAdvisory)
				}
			}
			reports := map[string]*report.Report{"baseline": baseline, "PR inherit": pr(baseline.SBOM), "PR re-analysis": pr(changed), "CVE watch": watch.Report}
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

// TestReanalysisClaimsTheWorkSet: on a PR re-analysis the claim of an advisory whose package did not
// change comes from the work set, not from its row. The baseline was assessed when the shared-alias
// advisory's record named no alias, so the row the re-analysis inherits for it names none; its record
// now names CVE-2021-38561, so GO-2021-0113's row has no priority. With the advisory out of the work
// set, its inherited row claims nothing and the row takes the CVE's EPSS, so the claim is the work
// set's.
func TestReanalysisClaimsTheWorkSet(t *testing.T) {
	ctx := context.Background()
	sig := prioritySignals(t)
	codebase := goFixtureModule(t)
	opts := func(aliases ...string) []pipeline.AssessOption {
		return []pipeline.AssessOption{
			pipeline.WithPlugin(fakeInventoryPlugin{lang: "go", inv: twoPackageInventory()}),
			pipeline.WithAdvisorySource(pipeline.NewChainSource(factSource{sharedAliasAdvisory: {Module: "golang.org/x/net", Aliases: aliases}}, pipeline.NewTableSource())),
		}
	}
	subject := Subject{Repo: "example.com/app", ResolvedCommit: "sha"}
	both := []assessment.VulnRef{{ID: "GO-2021-0113", Source: "osv"}, {ID: sharedAliasAdvisory, Source: "ghsa"}}
	baseline, err := buildBaselineReport(ctx, BaselineRequest{Subject: subject, Codebase: codebase, Advisories: both, AssessOptions: opts(), Signals: sig})
	if err != nil {
		t.Fatal(err)
	}
	store := &memStore{}
	if _, err := store.Write(ctx, &statestore.State{Report: baseline, SBOM: baseline.SBOM}); err != nil {
		t.Fatal(err)
	}
	head := baseline.SBOM
	head.Packages = append([]report.Package{{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.8"}}, head.Packages...)
	for _, c := range []struct {
		name     string
		workSet  []assessment.VulnRef
		wantNone bool
	}{
		{"shared alias in the work set", both, true},
		{"shared alias out of the work set", both[:1], false},
	} {
		res, err := RunPRInherit(ctx, store, PRInheritRequest{
			Subject: subject, Codebase: codebase, PRSBOM: head, Advisories: c.workSet, AssessOptions: opts("CVE-2021-38561"), Signals: sig,
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.Inherited {
			t.Fatalf("%s: the PR took the fast path; the case needs a re-analysis", c.name)
		}
		var got *report.Priority
		for _, f := range res.Report.Advisories {
			switch f.Advisory.ID {
			case sharedAliasAdvisory:
				if len(f.Advisory.Aliases) != 0 {
					t.Fatalf("%s: %s's row names %v; the case needs the inherited row that names none", c.name, sharedAliasAdvisory, f.Advisory.Aliases)
				}
			case "GO-2021-0113":
				got = f.Priority
			}
		}
		if (got == nil) != c.wantNone {
			t.Errorf("%s: GO-2021-0113 priority = %+v, want none: %v", c.name, got, c.wantNone)
		}
	}
}

// TestClaimedAliasStillVotes is Eric's scenario end to end: GO-2099-0010 aliases CVE-2024-55947, a
// stamped "not listed" no other advisory names, and CVE-2025-8110, KEV-listed and an advisory of
// the work set in its own right, deferred so it has no row. A claimed alias is never the source, but
// it still takes part in the agreement check: the two records disagree, so the row has no priority
// rather than CVE-2024-55947's "not listed".
func TestClaimedAliasStillVotes(t *testing.T) {
	const goX, cveB = "GO-2099-0010", "CVE-2025-8110"
	src := pipeline.NewChainSource(factSource{
		goX:  {Module: "golang.org/x/text", Aliases: []string{"CVE-2024-55947", cveB}},
		cveB: {Module: "golang.org/x/text", Aliases: []string{goX}},
	}, pipeline.NewTableSource())
	rep, err := buildBaselineReport(context.Background(), BaselineRequest{
		Subject:    Subject{Repo: "example.com/app", ResolvedCommit: "sha"},
		Codebase:   goFixtureModule(t),
		Advisories: []assessment.VulnRef{{ID: goX, Source: "osv"}, {ID: cveB, Source: "osv"}},
		AssessOptions: []pipeline.AssessOption{
			pipeline.WithPlugin(fakeInventoryPlugin{lang: "go", inv: twoPackageInventory()}),
			pipeline.WithAdvisorySource(src),
		},
		Signals: prioritySignals(t),
		Bands:   map[string]Band{cveB: BandDeferred},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows := 0
	for _, f := range rep.Advisories {
		switch f.Advisory.ID {
		case cveB:
			t.Fatalf("the baseline holds a row for deferred %s", cveB)
		case goX:
			rows++
			if len(f.Advisory.Aliases) != 2 {
				t.Fatalf("%s's row names %v; the case needs both CVE aliases", goX, f.Advisory.Aliases)
			}
			if f.Priority != nil {
				t.Errorf("%s: priority = %+v, want none (its CVE aliases disagree, one of them claimed)", goX, *f.Priority)
			}
		}
	}
	if rows != 1 {
		t.Fatalf("%d %s rows, want 1", rows, goX)
	}
}
