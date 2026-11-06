package trigger

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/gittest"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

var depCodeNote = report.PartialityNote{Reason: report.PartialReasonDependencyCodeUnavailable, Ecosystem: "npm", Detail: "registry_unreachable"}

// fellBack is the disclosure of a run that read no dependency code, readAll that of one that read
// all of it.
func fellBack(rep *report.Report) {
	rep.AddPartiality(depCodeNote)
	rep.DependencyCode = &report.DependencyCode{Source: "fetch", Cause: &report.DependencyCodeCause{Kind: "registry_unreachable"}}
}

func readAll(rep *report.Report) {
	rep.DependencyCode = &report.DependencyCode{Source: "fetch"}
}

func depCodeNotes(rep *report.Report) int {
	n := 0
	for _, p := range rep.Partiality {
		if p.Reason == report.PartialReasonDependencyCodeUnavailable {
			n++
		}
	}
	return n
}

// fellBackBaseline is the state a baseline that fell back leaves in store.
func fellBackBaseline(t *testing.T, store *memStore) {
	t.Helper()
	if _, err := RunBaseline(context.Background(), store, BaselineRequest{
		Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
		Advisories:    []assessment.VulnRef{wiringAdvisory},
		AssessOptions: wiringOptions(t, plugin.Complete()),
		Cursor:        wiringAdvisory.ID,
		Disclose:      fellBack,
	}); err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
}

// TestDisclose_StoredReport: the dependency-code disclosure is on the report.json a run writes, so
// a later run that publishes the stored rows carries it. A cve-watch earnest run carries a stored
// note even when it read all the dependency code, since it replaces only the rows it assessed; a
// heartbeat keeps the stored report; a baseline rebuilds every row, so it carries only its own.
// Publishing stamps the run's own disclosure again, and the note still appears once.
func TestDisclose_StoredReport(t *testing.T) {
	baseline := func(disclose Disclosure) func(*testing.T, *memStore) *report.Report {
		return func(t *testing.T, store *memStore) *report.Report {
			rep, err := RunBaseline(context.Background(), store, BaselineRequest{
				Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
				Advisories:    []assessment.VulnRef{wiringAdvisory},
				AssessOptions: wiringOptions(t, plugin.Complete()),
				Disclose:      disclose,
			})
			if err != nil {
				t.Fatalf("RunBaseline: %v", err)
			}
			return rep
		}
	}
	// cveWatch runs with OSV reporting nothing new; listed sends the stored row back to assessment,
	// so the run is earnest, and a run that is not listed is a heartbeat.
	cveWatch := func(disclose Disclosure, listed bool) func(*testing.T, *memStore) *report.Report {
		return func(t *testing.T, store *memStore) *report.Report {
			if listed {
				store.state.DepFetch = &statestore.DepFetch{Reassess: []string{wiringAdvisory.ID}}
			}
			res, err := RunCVEWatch(context.Background(), store, &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: wiringAdvisory.ID, Package: wiringPkg}}}}, CVEWatchRequest{
				Subject:         Subject{Repo: "r", ResolvedCommit: "sha"},
				AssessOptions:   wiringOptions(t, plugin.Complete()),
				DependencyFetch: func(*statestore.DepFetch, DependencyFetchRun) *statestore.DepFetch { return nil },
				Disclose:        disclose,
			})
			if err != nil {
				t.Fatalf("RunCVEWatch: %v", err)
			}
			if res.Heartbeat == listed || len(res.NewAdvisories) != 0 {
				t.Fatalf("heartbeat %v, new %v; the fixture did not set up the case", res.Heartbeat, res.NewAdvisories)
			}
			return res.Report
		}
	}
	for _, tc := range []struct {
		name       string
		storedNote bool
		run        func(*testing.T, *memStore) *report.Report
		disclose   Disclosure
		want       int
	}{
		{name: "baseline that fell back", run: baseline(fellBack), disclose: fellBack, want: 1},
		{name: "baseline that read it all", run: baseline(readAll), disclose: readAll, want: 0},
		{name: "baseline that read it all after one that fell back", storedNote: true, run: baseline(readAll), disclose: readAll, want: 0},
		{name: "cve-watch earnest that fell back", run: cveWatch(fellBack, true), disclose: fellBack, want: 1},
		{name: "cve-watch earnest that read it all after a baseline that fell back", storedNote: true, run: cveWatch(readAll, true), disclose: readAll, want: 1},
		{name: "cve-watch heartbeat after a baseline that fell back", storedNote: true, run: cveWatch(readAll, false), want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := groundedBaseline()
			if tc.storedNote {
				fellBackBaseline(t, store)
			}
			published := tc.run(t, store)
			if got := depCodeNotes(store.state.Report); got != tc.want {
				t.Fatalf("stored report carries %d dependency_code_unavailable notes, want %d: %+v", got, tc.want, store.state.Report.Partiality)
			}
			if published == nil {
				return
			}
			tc.disclose(published)
			if got := depCodeNotes(published); got != tc.want {
				t.Fatalf("published report carries %d dependency_code_unavailable notes, want %d: %+v", got, tc.want, published.Partiality)
			}
		})
	}
}

// TestDisclose_RecordStaysBound: the disclosure changes the report.json bytes, and the depfetch.json
// written beside them is bound to the stamped bytes, so the record reads back with the report.
func TestDisclose_RecordStaysBound(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	cmd := gittest.Command("-C", dir, "init", "--bare", "-q")
	cmd.Env = append(cmd.Env, "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	store := statestore.NewGitRefStore(statestore.Config{GitDir: dir})
	record := &statestore.DepFetch{Registries: map[string]statestore.RegistryFetch{"registry.npmjs.org": {HasServed: true}}}
	if _, err := RunBaseline(context.Background(), store, BaselineRequest{
		Subject:         Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
		Advisories:      []assessment.VulnRef{wiringAdvisory},
		AssessOptions:   wiringOptions(t, plugin.Complete()),
		DependencyFetch: func(*statestore.DepFetch, DependencyFetchRun) *statestore.DepFetch { return record },
		Disclose:        fellBack,
	}); err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
	st, err := store.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if depCodeNotes(st.Report) != 1 || st.Report.DependencyCode == nil || st.Report.DependencyCode.Cause == nil {
		t.Fatalf("stored report: notes %+v, dependency_code %+v", st.Report.Partiality, st.Report.DependencyCode)
	}
	if st.DepFetch == nil || !st.DepFetch.Registries["registry.npmjs.org"].HasServed {
		t.Fatalf("depfetch.json read back %+v: not bound to the stamped report.json", st.DepFetch)
	}
}

// TestDisclose_LostCASKeepsTheNote: a run that loses its CAS keeps the note through the merge,
// whichever side carries it: the run that fell back, merged under a later winner that read all the
// dependency code, and a run that read it all, merged under a later winner, a baseline that fell
// back.
func TestDisclose_LostCASKeepsTheNote(t *testing.T) {
	for _, tc := range []struct {
		name       string
		disclose   Disclosure
		winnerNote bool
	}{
		{name: "the losing run fell back", disclose: fellBack},
		{name: "the winner carries the note", disclose: readAll, winnerNote: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seed, baseline := groundedBaseline()
			inner := statestore.NewMemStore()
			if _, err := inner.Write(context.Background(), seed.state); err != nil {
				t.Fatalf("seed: %v", err)
			}
			store := &racingStore{MemStore: inner, winner: func(cur *statestore.State) *statestore.State {
				later := *baseline
				if tc.winnerNote {
					fell, _ := groundedBaseline()
					fellBackBaseline(t, fell)
					later = *fell.state.Report
				}
				later.Provenance.Timestamp = time.Now().UTC().Add(time.Hour)
				w := *cur
				w.Report = &later
				return &w
			}}
			published, err := RunBaseline(context.Background(), store, BaselineRequest{
				Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
				Advisories:    []assessment.VulnRef{wiringAdvisory},
				AssessOptions: wiringOptions(t, plugin.Complete()),
				Disclose:      tc.disclose,
			})
			if err != nil {
				t.Fatalf("RunBaseline: %v", err)
			}
			if !store.raced {
				t.Fatal("the write did not race")
			}
			stored, err := inner.Read(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if got := depCodeNotes(stored.Report); got != 1 {
				t.Fatalf("merged stored report carries %d dependency_code_unavailable notes, want 1: %+v", got, stored.Report.Partiality)
			}
			tc.disclose(published)
			if got := depCodeNotes(published); got != 1 {
				t.Fatalf("published report carries %d dependency_code_unavailable notes, want 1", got)
			}
		})
	}
}
