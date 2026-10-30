package trigger

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// An assessment concerns the finding's package and every package the advisory record names; ""
// stands for each one the record or the finding cannot name, including the packages a record
// with no affected_packages[] set may affect beyond its primary.
func TestAssessedPackages(t *testing.T) {
	complete := map[string]any{
		"coordinate": "@corp/b", "purl": "pkg:npm/%40corp/b",
		"affected_packages": []map[string]any{
			{"coordinate": "@corp/b", "purl": "pkg:npm/%40corp/b"},
			{"coordinate": "b-legacy", "purl": "pkg:npm/b-legacy"},
		},
	}
	for _, tc := range []struct {
		name     string
		advisory map[string]any // nil: no normalized advisory on record
		pkg      *report.Package
		want     []string
	}{
		{
			name:     "a record listing every package, and the finding's package URL",
			advisory: complete,
			pkg:      &report.Package{Ecosystem: "npm", Name: "@corp/b", Version: "1.0.0", PURL: "pkg:npm/%40corp/b@1.0.0"},
			want:     []string{"pkg:npm/%40corp/b@1.0.0", "pkg:npm/%40corp/b", "pkg:npm/%40corp/b", "pkg:npm/b-legacy"},
		},
		{
			name:     "an npm finding package with no package URL is named from its name",
			advisory: complete,
			pkg:      &report.Package{Ecosystem: "npm", Name: "@corp/b", Version: "1.0.0"},
			want:     []string{"pkg:npm/@corp/b", "pkg:npm/%40corp/b", "pkg:npm/%40corp/b", "pkg:npm/b-legacy"},
		},
		{
			name:     "a finding package of another ecosystem with no package URL is unnamed",
			advisory: complete,
			pkg:      &report.Package{Ecosystem: "Go", Name: "golang.org/x/text"},
			want:     []string{"", "pkg:npm/%40corp/b", "pkg:npm/%40corp/b", "pkg:npm/b-legacy"},
		},
		{
			name: "an affected_packages element with no package URL is unnamed",
			advisory: map[string]any{
				"purl":              "pkg:npm/a",
				"affected_packages": []map[string]any{{"purl": "pkg:npm/a"}, {"coordinate": "b"}},
			},
			want: []string{"pkg:npm/a", "pkg:npm/a", ""},
		},
		{
			name:     "a record naming only its primary may affect a package it does not name",
			advisory: map[string]any{"coordinate": "a", "purl": "pkg:npm/a"},
			want:     []string{"pkg:npm/a", ""},
		},
		{
			name: "no record names nothing it can vouch for",
			pkg:  &report.Package{Ecosystem: "npm", Name: "a", PURL: "pkg:npm/a@1.0.0"},
			want: []string{"pkg:npm/a@1.0.0", ""},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			if tc.advisory != nil {
				putJSON(t, store, "a1", artifact.TypeNormalizedAdvisory, tc.advisory)
			}
			if got := assessedPackages(store, "a1", tc.pkg); !slices.Equal(got, tc.want) {
				t.Fatalf("assessedPackages = %q, want %q", got, tc.want)
			}
		})
	}
}

// The dependency-fetch hook of a cve-watch earnest run sees the packages each advisory it
// re-assessed concerns, from the run's own assessment.
func TestRunCVEWatch_HookSeesAssessedPackages(t *testing.T) {
	store, _ := groundedBaseline()
	store.state.DepFetch = &statestore.DepFetch{Reassess: []string{wiringAdvisory.ID}}
	osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: wiringAdvisory.ID, Package: wiringPkg}}}}
	var got *DependencyFetchRun
	req := CVEWatchRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "sha"},
		AssessOptions: wiringOptions(t, plugin.Complete()),
		DependencyFetch: func(prior *statestore.DepFetch, run DependencyFetchRun) *statestore.DepFetch {
			got = &run
			return prior
		},
	}
	if _, err := RunCVEWatch(context.Background(), store, osv, req); err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if got == nil {
		t.Fatal("the hook was not called")
	}
	// The wiring advisory is a built-in Go record naming only its primary, and the finding's Go
	// package carries no package URL: both leave a package unnamed.
	want := []string{"", "pkg:golang/golang.org/x/text", ""}
	if p := got.Packages[wiringAdvisory.ID]; !slices.Equal(p, want) || len(got.Packages) != 1 {
		t.Fatalf("Packages = %q, want only %s: %q", got.Packages, wiringAdvisory.ID, want)
	}
}

// withheldGoPlugin is refutingGoPlugin with its call graph's partiality set, so the JS lane's
// limit for an unread package, an unbounded uninspectable_package, can withhold its refutation.
type withheldGoPlugin struct {
	refutingGoPlugin
	callGraph plugin.Partiality
}

func (p withheldGoPlugin) CallGraph(context.Context, plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return plugin.CallGraphResult{Partiality: p.callGraph, Algorithm: "vta"}, nil
}

// A cve-watch run whose analysis withheld a refutation on a package it read names that advisory
// undetermined, so the record lists it; the next run, which reads every package, re-assesses the
// listed advisory although OSV reports nothing new, and reaches the not_exploitable again.
func TestRunCVEWatch_HookSeesWithheldVerdict(t *testing.T) {
	store, _ := groundedBaseline()
	store.state.Cursor = ""
	osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: wiringAdvisory.ID, Package: wiringPkg}}}}
	run := func(cg plugin.Partiality) (*CVEWatchResult, DependencyFetchRun) {
		t.Helper()
		var got *DependencyFetchRun
		res, err := RunCVEWatch(context.Background(), store, osv, CVEWatchRequest{
			Subject: Subject{Repo: "r", ResolvedCommit: "sha"},
			AssessOptions: []pipeline.AssessOption{
				pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}),
				pipeline.WithPlugin(withheldGoPlugin{refutingGoPlugin: refutingGoPlugin{inventory: plugin.Complete()}, callGraph: cg}),
			},
			DependencyFetch: func(prior *statestore.DepFetch, r DependencyFetchRun) *statestore.DepFetch {
				got = &r
				// The record a JS run that missed a package writes for an undetermined advisory.
				if r.Undetermined[wiringAdvisory.ID] {
					return &statestore.DepFetch{Reassess: []string{wiringAdvisory.ID}}
				}
				return &statestore.DepFetch{}
			},
		})
		if err != nil {
			t.Fatalf("RunCVEWatch: %v", err)
		}
		if got == nil || res.Report == nil {
			t.Fatal("the run was not earnest")
		}
		return res, *got
	}

	unread := plugin.Partiality{Scoped: []plugin.ScopedReason{{Reason: plugin.PartialReasonUninspectablePackage, Package: "pkg:npm/%40corp/b@1.0.0"}}}
	res, got := run(unread)
	if v := wiringVerdict(t, res.Report); v != report.VerdictUndetermined {
		t.Fatalf("with an unread package: verdict = %q, want undetermined", v)
	}
	if !got.Undetermined[wiringAdvisory.ID] || len(got.Undetermined) != 1 {
		t.Fatalf("Undetermined = %v, want only %s", got.Undetermined, wiringAdvisory.ID)
	}

	res, got = run(plugin.Complete())
	if !slices.Equal(res.Reassessed, []string{wiringAdvisory.ID}) {
		t.Fatalf("Reassessed = %q, want [%s]", res.Reassessed, wiringAdvisory.ID)
	}
	if v := wiringVerdict(t, res.Report); v != report.VerdictNotExploitable {
		t.Fatalf("after a full read: verdict = %q, want not_exploitable", v)
	}
	if len(got.Undetermined) != 0 {
		t.Fatalf("after a full read: Undetermined = %v, want none", got.Undetermined)
	}
}

// secondCallPlugin is refutingGoPlugin whose second reachability pass misbehaves: it fails when
// cancel is nil, and otherwise cancels the scan's analysis before it returns, cutting it short.
type secondCallPlugin struct {
	refutingGoPlugin
	calls  *atomic.Int32
	cancel context.CancelFunc
}

func (p secondCallPlugin) Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	if p.calls.Add(1) == 2 {
		if p.cancel == nil {
			return plugin.ReachabilityResult{}, errors.New("reachability failed")
		}
		p.cancel()
	}
	return p.refutingGoPlugin.Reachability(ctx, req)
}

// An advisory under two sources whose one assessment completes and whose other fails or is cut
// short is undetermined, so a partial read keeps it listed for the row the run did not reach.
func TestRunCVEWatch_HookSeesUnreachedSibling(t *testing.T) {
	for _, tc := range []struct {
		name string
		cut  bool
	}{{"failed", false}, {"cut short", true}} {
		t.Run(tc.name, func(t *testing.T) {
			pkg := wiringPkg
			stored := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
				AddPackage(pkg).
				NotExploitable(report.Advisory{ID: wiringAdvisory.ID, Source: "corpus"}, &pkg, "vulnerable_symbol_absent", "no path").
				NotExploitable(report.Advisory{ID: wiringAdvisory.ID, Source: "osv"}, &pkg, "vulnerable_symbol_absent", "no path").
				WithProvenance(report.Provenance{CommitSHA: "base-sha", AdvisoryCursor: wiringAdvisory.ID}).
				Build()
			store := &memStore{state: &statestore.State{Report: &stored, SBOM: stored.SBOM, Cursor: wiringAdvisory.ID,
				DepFetch: &statestore.DepFetch{Reassess: []string{wiringAdvisory.ID}}}}
			osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: wiringAdvisory.ID, Package: wiringPkg}}}}
			analysis, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := secondCallPlugin{refutingGoPlugin: refutingGoPlugin{inventory: plugin.Complete()}, calls: &atomic.Int32{}}
			if tc.cut {
				p.cancel = cancel
			}
			var got *DependencyFetchRun
			_, err := RunCVEWatch(context.Background(), store, osv, CVEWatchRequest{
				Subject:  Subject{Repo: "r", ResolvedCommit: "sha"},
				Analysis: analysis,
				AssessOptions: []pipeline.AssessOption{
					pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}),
					pipeline.WithPlugin(p),
				},
				DependencyFetch: func(prior *statestore.DepFetch, r DependencyFetchRun) *statestore.DepFetch {
					got = &r
					return prior
				},
			})
			if err != nil {
				t.Fatalf("RunCVEWatch: %v", err)
			}
			if got == nil {
				t.Fatal("the hook was not called")
			}
			if n := p.calls.Load(); n != 2 {
				t.Fatalf("reachability ran %d times, want 2", n)
			}
			if len(got.Assessed) != 1 || got.Assessed[0].ID != wiringAdvisory.ID {
				t.Fatalf("Assessed = %+v, want only the completed %s", got.Assessed, wiringAdvisory.ID)
			}
			if !got.Undetermined[wiringAdvisory.ID] {
				t.Fatalf("Undetermined = %v, want %s", got.Undetermined, wiringAdvisory.ID)
			}
		})
	}
}
