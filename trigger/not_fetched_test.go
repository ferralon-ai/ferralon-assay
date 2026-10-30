package trigger

import (
	"context"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/gittest"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

var leftPad = report.Package{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}

// notFetchedReport is a built Report holding one row of each verdict, plus a stale
// dependency_not_fetched note whose row is gone.
func notFetchedReport() report.Report {
	pkg := leftPad
	b := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "sha"}).
		AddPackage(pkg).
		Disqualified(report.Advisory{ID: "GHSA-disq", Source: "osv"}, &pkg, verdict.BasisVersionNotAffected, "outside the range").
		NotExploitable(report.Advisory{ID: "GHSA-refuted", Source: "osv", Aliases: []string{"CVE-2026-0001"}}, &pkg, verdict.BasisSymbolUnreachable, "no path").
		NotExploitable(report.Advisory{ID: "GHSA-unlisted", Source: "osv"}, &pkg, verdict.BasisSymbolUnreachable, "no path").
		ReachableCandidate(report.Advisory{ID: "GHSA-reach", Source: "osv"}, &pkg, "a → b", "").
		Undetermined(report.Advisory{ID: "GHSA-undet", Source: "osv"}, &pkg, report.ReasonAdvisorySymbolAbsent).
		AddFinding(report.AdvisoryFinding{
			Advisory: report.Advisory{ID: "MAL-0001", Source: "osv"}, Package: &pkg, Verdict: report.VerdictMaliciousPresent,
			Evidence: report.EvidenceSummary{Detail: "malicious package"},
		}).
		AddPartiality(report.PartialityNote{Reason: report.ReasonDependencyNotFetched, Ecosystem: "PyPI"}).
		WithProvenance(report.Provenance{CommitSHA: "sha", AdvisoryCursor: "c"})
	return b.Build()
}

func rowByID(rep *report.Report, id string) report.AdvisoryFinding {
	for _, f := range rep.Advisories {
		if f.Advisory.ID == id {
			return f
		}
	}
	return report.AdvisoryFinding{}
}

// TestWithNotFetched pins the projection: a listed advisory never keeps a refuting verdict, a row
// that claims nothing about the advisory not applying keeps what it has, an unlisted row is
// untouched (the list is not an inventory), and the dependency_not_fetched notes follow the rows.
func TestWithNotFetched(t *testing.T) {
	for _, tc := range []struct {
		name         string
		dep          *statestore.DepFetch
		wantWithheld []string
	}{
		{name: "no record withholds nothing", dep: nil},
		{name: "empty list withholds nothing", dep: &statestore.DepFetch{}},
		{
			name:         "listed refuting rows are withheld, by ID or alias",
			dep:          &statestore.DepFetch{Reassess: []string{"GHSA-disq", "CVE-2026-0001"}},
			wantWithheld: []string{"GHSA-disq", "GHSA-refuted"},
		},
		{
			name: "listed rows that refute nothing keep their verdict",
			dep:  &statestore.DepFetch{Reassess: []string{"GHSA-reach", "GHSA-undet", "MAL-0001"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := notFetchedReport()
			before := slices.Clone(in.Advisories)
			got, err := withNotFetched(&in, tc.dep)
			if err != nil {
				t.Fatalf("withNotFetched: %v", err)
			}
			if !slices.EqualFunc(in.Advisories, before, func(a, b report.AdvisoryFinding) bool {
				return a.Advisory.ID == b.Advisory.ID && a.Verdict == b.Verdict
			}) {
				t.Fatal("withNotFetched modified its input")
			}
			for _, f := range before {
				g := rowByID(got, f.Advisory.ID)
				if slices.Contains(tc.wantWithheld, f.Advisory.ID) {
					if g.Verdict != report.VerdictUndetermined || g.UndeterminedReason != report.ReasonDependencyNotFetched ||
						g.Evidence.Detail != report.UndeterminedDetail(report.ReasonDependencyNotFetched) || g.Package == nil {
						t.Errorf("%s: got %s/%q %+v, want undetermined dependency_not_fetched with its package", f.Advisory.ID, g.Verdict, g.UndeterminedReason, g.Evidence)
					}
					continue
				}
				if g.Verdict != f.Verdict || g.UndeterminedReason != f.UndeterminedReason {
					t.Errorf("%s: got %s/%q, want %s/%q unchanged", f.Advisory.ID, g.Verdict, g.UndeterminedReason, f.Verdict, f.UndeterminedReason)
				}
			}
			var notes []report.PartialityNote
			for _, n := range got.Partiality {
				if n.Reason == report.ReasonDependencyNotFetched {
					notes = append(notes, n)
				}
			}
			if len(tc.wantWithheld) == 0 {
				if len(notes) != 0 {
					t.Errorf("notes = %+v, want the stale note dropped with no row carrying the reason", notes)
				}
			} else if len(notes) != 1 || notes[0].Ecosystem != "npm" {
				t.Errorf("notes = %+v, want one dependency_not_fetched note scoped to npm", notes)
			}
			if err := got.Validate(); err != nil {
				t.Errorf("projected report invalid: %v", err)
			}
			if !slices.IsSortedFunc(got.Advisories, func(a, b report.AdvisoryFinding) int {
				return rank(b) - rank(a)
			}) {
				t.Errorf("rows not ordered as Build orders them: %v", verdictIDs(got))
			}
		})
	}
}

// rank orders reachable candidates first, then undetermined rows, then the rest.
func rank(f report.AdvisoryFinding) int {
	switch f.Verdict {
	case report.VerdictReachableCandidate:
		return 2
	case report.VerdictUndetermined:
		return 1
	}
	return 0
}

func verdictIDs(rep *report.Report) []string {
	var out []string
	for _, f := range rep.Advisories {
		out = append(out, f.Advisory.ID+"="+string(f.Verdict))
	}
	return out
}

// TestNotFetchedRetry: a cve-watch run assesses again every stored row the record lists or that is
// withheld for want of dependency code, by ID or alias and whatever source assessed it, each once as
// itself; a row OSV's new advisory replaces anyway is left to that assessment.
func TestNotFetchedRetry(t *testing.T) {
	pkg := leftPad
	stored := report.NewBuilder(report.Subject{Repo: "r"}).
		Undetermined(report.Advisory{ID: "GHSA-marked", Source: "osv", Aliases: []string{"CVE-2026-0002"}}, &pkg, report.ReasonDependencyNotFetched).
		Undetermined(report.Advisory{ID: "GHSA-other", Source: "osv"}, &pkg, report.ReasonAdvisorySymbolAbsent).
		NotExploitable(report.Advisory{ID: "GHSA-plain", Source: "osv"}, &pkg, verdict.BasisSymbolUnreachable, "no path").
		NotExploitable(report.Advisory{ID: "GHSA-plain", Source: "corpus"}, &pkg, verdict.BasisSymbolUnreachable, "no path").
		NotExploitable(report.Advisory{ID: "GHSA-aliased", Source: "corpus", Aliases: []string{"CVE-2026-0003"}}, &pkg, verdict.BasisSymbolUnreachable, "no path").
		Build()
	for _, tc := range []struct {
		name   string
		dep    *statestore.DepFetch
		newIDs []string
		want   []string
	}{
		{name: "only the marked row", want: []string{"GHSA-marked/osv"}},
		{name: "listed, every source", dep: &statestore.DepFetch{Reassess: []string{"GHSA-plain"}}, want: []string{"GHSA-marked/osv", "GHSA-plain/corpus", "GHSA-plain/osv"}},
		{name: "listed by alias", dep: &statestore.DepFetch{Reassess: []string{"CVE-2026-0003"}}, want: []string{"GHSA-aliased/corpus", "GHSA-marked/osv"}},
		{name: "new osv row left to its assessment", dep: &statestore.DepFetch{Reassess: []string{"GHSA-plain"}}, newIDs: []string{"GHSA-plain", "GHSA-marked"}, want: []string{"GHSA-plain/corpus"}},
		{name: "listed but not stored", dep: &statestore.DepFetch{Reassess: []string{"GHSA-gone"}}, want: []string{"GHSA-marked/osv"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, f := range notFetchedRetry(&stored, tc.dep, tc.newIDs) {
				got = append(got, f.Advisory.ID+"/"+f.Advisory.Source)
			}
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("retry = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRunCVEWatch_ReassessListed drives the stored record through cve-watch. The stored row is a
// grounded not_exploitable and OSV reports nothing new, so without the record the run is a
// heartbeat. A listed advisory sends the run back to assess it; when the run again reads less
// dependency code than the lock pins (the hook keeps it listed) the written row is withheld as
// dependency_not_fetched, and when it reads it all (the hook clears it) the refuting verdict the
// run reached stands.
func TestRunCVEWatch_ReassessListed(t *testing.T) {
	listed := &statestore.DepFetch{Reassess: []string{wiringAdvisory.ID}}
	for _, tc := range []struct {
		name   string
		stored *statestore.DepFetch
		// marked stores the row already withheld as dependency_not_fetched; fresh leaves the
		// advisory off the stored cursor, so OSV reports it as new.
		marked, fresh bool
		hook          func(prior *statestore.DepFetch) *statestore.DepFetch
		wantHeartbeat bool
		wantVerdict   report.Verdict
		wantReason    string
	}{
		{name: "nothing listed is a heartbeat", wantHeartbeat: true, wantVerdict: report.VerdictNotExploitable},
		{
			name: "listed, a heartbeat of a run that records no dependency acquisition leaves the stored row", stored: listed,
			wantHeartbeat: true, wantVerdict: report.VerdictNotExploitable,
		},
		{
			name: "listed and withheld, a run that records no dependency acquisition retries nothing", stored: listed, marked: true,
			wantHeartbeat: true, wantVerdict: report.VerdictUndetermined, wantReason: report.ReasonDependencyNotFetched,
		},
		{
			name: "withheld and the record lost, a run that records no dependency acquisition retries nothing", marked: true,
			wantHeartbeat: true, wantVerdict: report.VerdictUndetermined, wantReason: report.ReasonDependencyNotFetched,
		},
		{
			name: "listed and new to the cursor, a run that records no dependency acquisition withholds it", stored: listed, fresh: true,
			wantVerdict: report.VerdictUndetermined, wantReason: report.ReasonDependencyNotFetched,
		},
		{
			name: "listed, read again without dependency code",
			hook: func(prior *statestore.DepFetch) *statestore.DepFetch { return prior }, stored: listed,
			wantVerdict: report.VerdictUndetermined, wantReason: report.ReasonDependencyNotFetched,
		},
		{
			name: "listed, read with dependency code",
			hook: func(*statestore.DepFetch) *statestore.DepFetch { return nil }, stored: listed,
			wantVerdict: report.VerdictNotExploitable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := groundedBaseline()
			store.state.DepFetch = tc.stored
			if tc.marked {
				rep, err := withNotFetched(store.state.Report, listed)
				if err != nil {
					t.Fatal(err)
				}
				store.state.Report = rep
			}
			if tc.fresh {
				store.state.Cursor = ""
			}
			osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: wiringAdvisory.ID, Package: wiringPkg}}}}
			req := CVEWatchRequest{
				Subject:       Subject{Repo: "r", ResolvedCommit: "sha"},
				AssessOptions: wiringOptions(t, plugin.Complete()),
			}
			if tc.hook != nil {
				req.DependencyFetch = func(prior *statestore.DepFetch, _ DependencyFetchRun) *statestore.DepFetch { return tc.hook(prior) }
			}
			res, err := RunCVEWatch(context.Background(), store, osv, req)
			if err != nil {
				t.Fatalf("RunCVEWatch: %v", err)
			}
			if res.Heartbeat != tc.wantHeartbeat {
				t.Fatalf("heartbeat = %v, want %v", res.Heartbeat, tc.wantHeartbeat)
			}
			switch {
			case tc.wantHeartbeat:
			case tc.fresh:
				if len(res.Reassessed) != 0 || !slices.Equal(res.NewAdvisories, []string{wiringAdvisory.ID}) {
					t.Fatalf("reassessed %v new %v, want %s new and nothing reassessed", res.Reassessed, res.NewAdvisories, wiringAdvisory.ID)
				}
			default:
				if !slices.Equal(res.Reassessed, []string{wiringAdvisory.ID}) || len(res.NewAdvisories) != 0 {
					t.Fatalf("reassessed %v new %v, want %s reassessed and nothing new", res.Reassessed, res.NewAdvisories, wiringAdvisory.ID)
				}
			}
			if tc.hook == nil && !reflect.DeepEqual(store.state.DepFetch, tc.stored) {
				t.Fatalf("a run that records no dependency acquisition changed the record to %+v, want %+v", store.state.DepFetch, tc.stored)
			}
			f := rowByID(store.state.Report, wiringAdvisory.ID)
			if f.Verdict != tc.wantVerdict || f.UndeterminedReason != tc.wantReason {
				t.Fatalf("stored row %s/%q, want %s/%q", f.Verdict, f.UndeterminedReason, tc.wantVerdict, tc.wantReason)
			}
		})
	}
}

// TestRunCVEWatch_RetryOnlyRunReachesAnalysis: the run a listed advisory forces really assesses its
// stored row, rather than carrying it.
func TestRunCVEWatch_RetryOnlyRunReachesAnalysis(t *testing.T) {
	var calls atomic.Int32
	store, osv, req := holdFixture(t, &calls)
	pkg := wiringPkg
	stored := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
		AddPackage(pkg).
		NotExploitable(report.Advisory{ID: "GO-2021-0113", Source: "osv"}, &pkg, verdict.BasisSymbolUnreachable, "no path").
		WithProvenance(report.Provenance{CommitSHA: "base-sha", AdvisoryCursor: "GO-2021-0113"}).
		Build()
	store.state.Report = &stored
	store.state.Cursor = "GO-2021-0113"
	store.state.DepFetch = &statestore.DepFetch{Reassess: []string{"GO-2021-0113"}}
	req.DependencyFetch = func(prior *statestore.DepFetch, _ DependencyFetchRun) *statestore.DepFetch { return prior }
	res, err := RunCVEWatch(context.Background(), store, osv, req)
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if res.Heartbeat || calls.Load() == 0 {
		t.Fatalf("heartbeat %v, analysis calls %d; want an earnest run that assessed the listed advisory", res.Heartbeat, calls.Load())
	}
}

// TestRunBaseline_WithholdsWhatStaysListed: a baseline that did not clear a listed advisory (it
// read less dependency code than the lock pins) writes no refuting verdict for it; one that
// cleared it writes the verdict it reached.
func TestRunBaseline_WithholdsWhatStaysListed(t *testing.T) {
	for _, tc := range []struct {
		name        string
		hook        func(prior *statestore.DepFetch) *statestore.DepFetch
		wantVerdict report.Verdict
	}{
		{"still listed", func(prior *statestore.DepFetch) *statestore.DepFetch { return prior }, report.VerdictUndetermined},
		{"cleared", func(*statestore.DepFetch) *statestore.DepFetch { return nil }, report.VerdictNotExploitable},
		{"a run that records no dependency acquisition still withholds", nil, report.VerdictUndetermined},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := groundedBaseline()
			store.state.DepFetch = &statestore.DepFetch{Reassess: []string{wiringAdvisory.ID}}
			req := BaselineRequest{
				Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
				Advisories:    []assessment.VulnRef{wiringAdvisory},
				AssessOptions: wiringOptions(t, plugin.Complete()),
			}
			if tc.hook != nil {
				req.DependencyFetch = func(prior *statestore.DepFetch, _ DependencyFetchRun) *statestore.DepFetch { return tc.hook(prior) }
			}
			rep, err := RunBaseline(context.Background(), store, req)
			if err != nil {
				t.Fatalf("RunBaseline: %v", err)
			}
			if got := rowByID(rep, wiringAdvisory.ID).Verdict; got != tc.wantVerdict {
				t.Fatalf("verdict = %s, want %s", got, tc.wantVerdict)
			}
		})
	}
}

// TestRunCVEWatch_RecordBoundToAnotherReportIsIgnored: a reassess list bound to a report.json other
// than the stored one is dropped by the store, so it neither sends the advisory back to assessment
// nor withholds the stored row. The control writes the same list bound to the stored report.
func TestRunCVEWatch_RecordBoundToAnotherReportIsIgnored(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	for _, rebind := range []bool{false, true} {
		name := "bound"
		if rebind {
			name = "bound to another report"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			git := func(stdin string, args ...string) string {
				t.Helper()
				cmd := gittest.Command(append([]string{"-C", dir}, args...)...)
				cmd.Env = append(cmd.Env, "GIT_CONFIG_NOSYSTEM=1")
				if stdin != "" {
					cmd.Stdin = strings.NewReader(stdin)
				}
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, out)
				}
				return strings.TrimSpace(string(out))
			}
			git("", "init", "--bare", "-q")
			store := statestore.NewGitRefStore(statestore.Config{GitDir: dir})
			seed, _ := groundedBaseline()
			seed.state.DepFetch = &statestore.DepFetch{Reassess: []string{wiringAdvisory.ID}}
			if _, err := store.Write(context.Background(), seed.state); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if rebind {
				// A writer that does not model depfetch.json rewrites report.json and carries the
				// record: append a byte of whitespace, which leaves the report readable.
				ref := statestore.DefaultRef
				var entries []string
				for _, line := range strings.Split(git("", "ls-tree", ref), "\n") {
					meta, file, _ := strings.Cut(line, "\t")
					if file == "report.json" {
						body := git("", "cat-file", "blob", strings.Fields(meta)[2])
						blob := git(body+"\n\n", "hash-object", "-w", "--stdin")
						meta = strings.Join(append(strings.Fields(meta)[:2], blob), " ")
					}
					entries = append(entries, meta+"\t"+file)
				}
				tree := git(strings.Join(entries, "\n")+"\n", "mktree")
				commit := git("", "commit-tree", tree, "-p", ref, "-m", "carry")
				git("", "update-ref", ref, commit)
			}
			st, err := store.Read(context.Background())
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if (st.DepFetch == nil) != rebind {
				t.Fatalf("record read back %+v; the fixture did not set up the case", st.DepFetch)
			}
			osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: wiringAdvisory.ID, Package: wiringPkg}}}}
			res, err := RunCVEWatch(context.Background(), store, osv, CVEWatchRequest{
				Subject:       Subject{Repo: "r", ResolvedCommit: "sha"},
				AssessOptions: wiringOptions(t, plugin.Complete()),
				DependencyFetch: func(prior *statestore.DepFetch, _ DependencyFetchRun) *statestore.DepFetch {
					return prior
				},
			})
			if err != nil {
				t.Fatalf("RunCVEWatch: %v", err)
			}
			if res.Heartbeat != rebind {
				t.Fatalf("heartbeat = %v, want %v", res.Heartbeat, rebind)
			}
			after, err := store.Read(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			want := report.VerdictUndetermined
			if rebind {
				want = report.VerdictNotExploitable
			}
			if got := rowByID(after.Report, wiringAdvisory.ID).Verdict; got != want {
				t.Fatalf("stored verdict = %s, want %s", got, want)
			}
		})
	}
}

// racingStore is a statestore.MemStore where another writer commits winner just before the first
// Write lands, so that Write loses its CAS and the store merges it onto winner.
type racingStore struct {
	*statestore.MemStore
	winner func(cur *statestore.State) *statestore.State
	raced  bool
}

func (s *racingStore) Write(ctx context.Context, next *statestore.State) (*statestore.State, error) {
	if !s.raced {
		s.raced = true
		cur, err := s.MemStore.Read(ctx)
		if err != nil {
			return nil, err
		}
		if _, err := s.MemStore.Write(ctx, s.winner(cur)); err != nil {
			return nil, err
		}
	}
	return s.MemStore.Write(ctx, next)
}

// TestLostCASWithholdsWhatTheMergeLists: a run that leaves an advisory on the reassess list loses
// its CAS to a later fallback baseline that refuted the same advisory. The merge keeps the
// baseline's later not_exploitable and unions the run's list, which names the advisory; every kind
// of state write withholds the merged state again before it is written and published.
func TestLostCASWithholdsWhatTheMergeLists(t *testing.T) {
	listed := func(prior *statestore.DepFetch, _ DependencyFetchRun) *statestore.DepFetch { return prior }
	osv := func() *fakeOSV {
		return &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: wiringAdvisory.ID, Package: wiringPkg}}}}
	}
	cveWatch := func(t *testing.T, store statestore.StateStore) *report.Report {
		res, err := RunCVEWatch(context.Background(), store, osv(), CVEWatchRequest{
			Subject:         Subject{Repo: "r", ResolvedCommit: "sha"},
			AssessOptions:   wiringOptions(t, plugin.Complete()),
			DependencyFetch: listed,
		})
		if err != nil {
			t.Fatalf("RunCVEWatch: %v", err)
		}
		return res.Report
	}
	for _, tc := range []struct {
		name string
		// rowless seeds a report with no row for the advisory, so nothing is retried.
		rowless bool
		run     func(t *testing.T, store statestore.StateStore) *report.Report // the published report, nil for none
	}{
		{name: "cve-watch earnest", run: cveWatch},
		{name: "cve-watch heartbeat", rowless: true, run: func(t *testing.T, store statestore.StateStore) *report.Report {
			res, err := RunCVEWatch(context.Background(), store, osv(), CVEWatchRequest{
				Subject: Subject{Repo: "r", ResolvedCommit: "sha"}, AssessOptions: wiringOptions(t, plugin.Complete()), DependencyFetch: listed,
			})
			if err != nil {
				t.Fatalf("RunCVEWatch: %v", err)
			}
			if !res.Heartbeat {
				t.Fatal("not a heartbeat")
			}
			return nil
		}},
		{name: "baseline", run: func(t *testing.T, store statestore.StateStore) *report.Report {
			rep, err := RunBaseline(context.Background(), store, BaselineRequest{
				Subject:         Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
				Advisories:      []assessment.VulnRef{wiringAdvisory},
				AssessOptions:   wiringOptions(t, plugin.Complete()),
				DependencyFetch: listed,
			})
			if err != nil {
				t.Fatalf("RunBaseline: %v", err)
			}
			return rep
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seed, baseline := groundedBaseline()
			st := *seed.state
			if tc.rowless {
				empty := report.NewBuilder(baseline.Subject).AddPackages(baseline.SBOM.Packages...).WithProvenance(baseline.Provenance).Build()
				st.Report = &empty
			}
			st.DepFetch = &statestore.DepFetch{Reassess: []string{wiringAdvisory.ID}}
			inner := statestore.NewMemStore()
			if _, err := inner.Write(context.Background(), &st); err != nil {
				t.Fatalf("seed: %v", err)
			}
			store := &racingStore{MemStore: inner, winner: func(cur *statestore.State) *statestore.State {
				later := *baseline
				later.Provenance.Timestamp = time.Now().UTC().Add(time.Hour)
				w := *cur
				w.Report = &later
				w.DepFetch = nil
				return &w
			}}
			published := tc.run(t, store)
			stored, err := inner.Read(context.Background())
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if !store.raced {
				t.Fatal("the write did not race")
			}
			if stored.DepFetch == nil || !slices.Contains(stored.DepFetch.Reassess, wiringAdvisory.ID) {
				t.Fatalf("merged reassess list %+v, want it to name %s", stored.DepFetch, wiringAdvisory.ID)
			}
			reps := map[string]*report.Report{"stored": stored.Report}
			if published != nil {
				reps["published"] = published
			}
			for name, rep := range reps {
				f := rowByID(rep, wiringAdvisory.ID)
				if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != report.ReasonDependencyNotFetched {
					t.Fatalf("%s row %s/%q, want undetermined/%q", name, f.Verdict, f.UndeterminedReason, report.ReasonDependencyNotFetched)
				}
			}
			if stored.Remerge != nil {
				t.Fatal("the store kept the writer's Remerge hook")
			}
		})
	}
}
