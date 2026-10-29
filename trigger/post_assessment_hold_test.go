package trigger

import (
	"context"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// holdFixture is a stored baseline whose cursor predates GO-2021-0113, and an OSV answer that
// makes GO-2021-0113 new, so a cve-watch run re-assesses it through the counting plugin.
func holdFixture(t *testing.T, calls *atomic.Int32) (*memStore, *fakeOSV, CVEWatchRequest) {
	t.Helper()
	pkg := wiringPkg
	baseline := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
		AddPackage(pkg).
		WithProvenance(report.Provenance{CommitSHA: "base-sha", AdvisoryCursor: "GO-2000-0001"}).
		Build()
	store := &memStore{state: &statestore.State{Report: &baseline, SBOM: baseline.SBOM, Cursor: "GO-2000-0001"}}
	osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: "GO-2021-0113", Package: pkg}}}}
	req := CVEWatchRequest{
		Subject:  Subject{Repo: "r", ResolvedCommit: "sha"},
		Codebase: assessment.CodebaseRef{Repo: "example.com/target", Revision: "main"},
		AssessOptions: []pipeline.AssessOption{
			pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}),
			pipeline.WithPlugin(analysisCountingPlugin{calls: calls}),
		},
	}
	return store, osv, req
}

// TestRunCVEWatch_HoldConsultedAfterAssessment pins when the hold is decided. The condition here
// only becomes true once the re-assessment has run, as a dependency fetch that fell back does:
// a value fixed before RunCVEWatch reads it false and advances the cursor, while Hold, consulted
// after the re-assessment, sees it and holds.
func TestRunCVEWatch_HoldConsultedAfterAssessment(t *testing.T) {
	for _, tc := range []struct {
		name       string
		set        func(req *CVEWatchRequest, calls *atomic.Int32)
		wantCursor string
	}{
		{
			name:       "HoldCursor fixed before the run cannot see it",
			set:        func(req *CVEWatchRequest, calls *atomic.Int32) { req.HoldCursor = calls.Load() > 0 },
			wantCursor: "GO-2021-0113",
		},
		{
			name: "Hold consulted after the re-assessment holds",
			set: func(req *CVEWatchRequest, calls *atomic.Int32) {
				req.Hold = func() bool { return calls.Load() > 0 }
			},
			wantCursor: "GO-2000-0001",
		},
		{
			name:       "Hold false advances",
			set:        func(req *CVEWatchRequest, _ *atomic.Int32) { req.Hold = func() bool { return false } },
			wantCursor: "GO-2021-0113",
		},
		{
			name:       "no hold advances",
			set:        func(*CVEWatchRequest, *atomic.Int32) {},
			wantCursor: "GO-2021-0113",
		},
		{
			name:       "HoldCursor still holds",
			set:        func(req *CVEWatchRequest, _ *atomic.Int32) { req.HoldCursor = true },
			wantCursor: "GO-2000-0001",
		},
		{
			name: "HoldCursor holds whatever Hold says",
			set: func(req *CVEWatchRequest, _ *atomic.Int32) {
				req.HoldCursor = true
				req.Hold = func() bool { return false }
			},
			wantCursor: "GO-2000-0001",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			store, osv, req := holdFixture(t, &calls)
			tc.set(&req, &calls)
			res, err := RunCVEWatch(context.Background(), store, osv, req)
			if err != nil {
				t.Fatalf("RunCVEWatch: %v", err)
			}
			if res.Heartbeat || calls.Load() == 0 {
				t.Fatalf("want an earnest run that re-assessed through the plugin (heartbeat %v, calls %d)", res.Heartbeat, calls.Load())
			}
			if store.writes != 1 {
				t.Fatalf("writes = %d, want the Report written once", store.writes)
			}
			if store.state.Cursor != tc.wantCursor {
				t.Fatalf("cursor = %q, want %q", store.state.Cursor, tc.wantCursor)
			}
			if got := statestore.Merge(&statestore.State{}, store.state).Cursor; got != tc.wantCursor {
				t.Fatalf("merged cursor = %q, want %q", got, tc.wantCursor)
			}
		})
	}
}

// TestRunCVEWatch_HoldNotConsultedOnHeartbeat: a heartbeat assesses nothing, so it has no
// re-assessment for Hold to judge and never calls it.
func TestRunCVEWatch_HoldNotConsultedOnHeartbeat(t *testing.T) {
	store, _ := seedBaseline(t)
	osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: "GO-2021-0113", Package: wiringPkg}}}}
	req := CVEWatchRequest{
		Hold: func() bool { t.Fatal("Hold consulted on a heartbeat"); return true },
		DependencyFetch: func(*statestore.DepFetch, DependencyFetchRun) *statestore.DepFetch {
			t.Fatal("DependencyFetch called on a heartbeat")
			return nil
		},
	}
	res, err := RunCVEWatch(context.Background(), store, osv, req)
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if !res.Heartbeat {
		t.Fatalf("want a heartbeat, got %+v", res)
	}
}

// TestRunCVEWatch_DependencyFetchSeesTheRun pins what the earnest run hands its dependency-fetch
// hook: the stored record, whether the cursor was held (by either hold), and the advisories it
// re-assessed. The hook's answer is what the run writes.
func TestRunCVEWatch_DependencyFetchSeesTheRun(t *testing.T) {
	stored := &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{"https://registry.npmjs.org/": {HasServed: true}}}
	for _, tc := range []struct {
		name     string
		set      func(req *CVEWatchRequest)
		wantHeld bool
	}{
		{"advanced", func(*CVEWatchRequest) {}, false},
		{"held by Hold", func(req *CVEWatchRequest) { req.Hold = func() bool { return true } }, true},
		{"held by HoldCursor", func(req *CVEWatchRequest) { req.HoldCursor = true }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			store, osv, req := holdFixture(t, &calls)
			store.state.DepFetch = stored
			tc.set(&req)
			want := &statestore.DepFetch{Reassess: []string{"GO-2021-0113"}}
			var got []DependencyFetchRun
			req.DependencyFetch = func(prior *statestore.DepFetch, run DependencyFetchRun) *statestore.DepFetch {
				if prior != stored {
					t.Errorf("hook got prior %+v, want the stored record", prior)
				}
				got = append(got, run)
				return want
			}
			if _, err := RunCVEWatch(context.Background(), store, osv, req); err != nil {
				t.Fatalf("RunCVEWatch: %v", err)
			}
			if len(got) != 1 || got[0].Baseline || got[0].Held != tc.wantHeld || !slices.Equal(assessedIDs(got[0]), []string{"GO-2021-0113"}) {
				t.Fatalf("hook runs = %+v, want one cve-watch run, held %v, assessing GO-2021-0113", got, tc.wantHeld)
			}
			if !slices.Contains(got[0].Assessed[0].Aliases, "GHSA-ppp9-7jff-5vj2") {
				t.Fatalf("assessed advisory %+v does not carry its advisory record's aliases", got[0].Assessed[0])
			}
			if store.lastSeen.DepFetch != want {
				t.Fatalf("written DepFetch = %+v, want the hook's answer", store.lastSeen.DepFetch)
			}
		})
	}
}

// TestRunCVEWatch_NoDependencyFetchCarriesStored: without a hook the earnest run writes the
// stored record unchanged.
func TestRunCVEWatch_NoDependencyFetchCarriesStored(t *testing.T) {
	var calls atomic.Int32
	store, osv, req := holdFixture(t, &calls)
	stored := &statestore.DepFetch{Reassess: []string{"GO-2000-0001"}}
	store.state.DepFetch = stored
	if _, err := RunCVEWatch(context.Background(), store, osv, req); err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if store.lastSeen.DepFetch != stored {
		t.Fatalf("written DepFetch = %+v, want the stored record carried", store.lastSeen.DepFetch)
	}
}

// TestRunBaseline_DependencyFetchSeesTheRun: a baseline hands its hook the stored record, marks the
// run a baseline, and lists the advisories it assessed; the hook's answer is what it writes.
func TestRunBaseline_DependencyFetchSeesTheRun(t *testing.T) {
	store, _ := groundedBaseline()
	stored := &statestore.DepFetch{Reassess: []string{wiringAdvisory.ID}}
	store.state.DepFetch = stored
	want := &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{"https://registry.npmjs.org/": {HasServed: true}}}
	var got []DependencyFetchRun
	_, err := RunBaseline(context.Background(), store, BaselineRequest{
		Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "example.com/target", Revision: "main"},
		Advisories:    []assessment.VulnRef{wiringAdvisory},
		AssessOptions: wiringOptions(t, plugin.Complete()),
		DependencyFetch: func(prior *statestore.DepFetch, run DependencyFetchRun) *statestore.DepFetch {
			if prior != stored {
				t.Errorf("hook got prior %+v, want the stored record", prior)
			}
			got = append(got, run)
			return want
		},
	})
	if err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
	if len(got) != 1 || !got[0].Baseline || got[0].Held || !slices.Equal(assessedIDs(got[0]), []string{wiringAdvisory.ID}) {
		t.Fatalf("hook runs = %+v, want one baseline run that assessed %s", got, wiringAdvisory.ID)
	}
	if !slices.Contains(got[0].Assessed[0].Aliases, "GHSA-ppp9-7jff-5vj2") {
		t.Fatalf("assessed advisory %+v does not carry its advisory record's aliases", got[0].Assessed[0])
	}
	if store.lastSeen.DepFetch != want {
		t.Fatalf("written DepFetch = %+v, want the hook's answer", store.lastSeen.DepFetch)
	}
}

// TestRunBaseline_CutAdvisoryNotAssessed: an advisory the baseline cut short is not in Assessed,
// so a hook cannot clear a re-assessment the run never made.
func TestRunBaseline_CutAdvisoryNotAssessed(t *testing.T) {
	opts, analysis := stoppingOptions(t, "inventory", stopAndWait)
	store, _ := groundedBaseline()
	var got []DependencyFetchRun
	if _, err := RunBaseline(context.Background(), store, BaselineRequest{
		Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		Advisories:    cutShortCorpus,
		AssessOptions: opts,
		Analysis:      analysis,
		DependencyFetch: func(prior *statestore.DepFetch, run DependencyFetchRun) *statestore.DepFetch {
			got = append(got, run)
			return prior
		},
	}); err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
	if len(got) != 1 || len(got[0].Assessed) != 0 {
		t.Fatalf("hook runs = %+v, want one with nothing assessed", got)
	}
}

// assessedIDs is the advisory IDs run.Assessed lists, in order.
func assessedIDs(run DependencyFetchRun) []string {
	var ids []string
	for _, a := range run.Assessed {
		ids = append(ids, a.ID)
	}
	return ids
}
