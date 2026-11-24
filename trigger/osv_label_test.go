package trigger

import (
	"context"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestCVEWatch_NewOSVAdvisoryGetsARowPerInstance: OSV newly flags GO-S-1, whose example.com/lib
// parent is not reached and whose example.com/lib/v2 sibling is. Whichever of the two packages the
// OSV query reports, and in whichever order, the run gives each instance its own row under its own
// coordinate, as a baseline does. Labelling with the OSV query's package put the parent's
// not_exploitable verdict under the reachable sibling's coordinate and gave the sibling no row.
func TestCVEWatch_NewOSVAdvisoryGetsARowPerInstance(t *testing.T) {
	p := splitVerdictPlugin{refutingGoPlugin{inventory: plugin.Complete()}}
	want := []string{
		"example.com/lib not_exploitable",
		"example.com/lib/v2 reachable_candidate",
	}
	for _, tc := range []struct {
		name     string
		reported []string
	}{
		{"sibling", []string{"example.com/lib/v2"}},
		{"parent", []string{"example.com/lib"}},
		{"both, sibling first", []string{"example.com/lib/v2", "example.com/lib"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &memStore{}
			if _, err := RunBaseline(context.Background(), store, BaselineRequest{
				Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "base-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				Advisories:    passAdvisories("GO-S-1"),
				AssessOptions: siblingAssessOpts(t, p, splitVerdictSource{}),
			}); err != nil {
				t.Fatalf("RunBaseline: %v", err)
			}
			if got := instanceVerdicts(store.state.Report.Advisories, "corpus"); !slices.Equal(got, want) {
				t.Fatalf("baseline rows = %v, want %v", got, want)
			}
			var osvAdvisories []OSVAdvisory
			for _, name := range tc.reported {
				for _, f := range store.state.Report.Advisories {
					if f.Package != nil && f.Package.Name == name {
						osvAdvisories = append(osvAdvisories, OSVAdvisory{ID: "GO-S-1", Package: *f.Package})
					}
				}
			}
			if len(osvAdvisories) != len(tc.reported) {
				t.Fatalf("no baseline package for %v", tc.reported)
			}
			res, err := RunCVEWatch(context.Background(), store, &fakeOSV{result: OSVResult{Advisories: osvAdvisories}}, CVEWatchRequest{
				Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				AssessOptions: siblingAssessOpts(t, p, splitVerdictSource{}),
			})
			if err != nil {
				t.Fatalf("RunCVEWatch: %v", err)
			}
			if res.Report == nil {
				t.Fatal("cve-watch assessed nothing")
			}
			if got := instanceVerdicts(res.Report.Advisories, osvSource); !slices.Equal(got, want) {
				t.Errorf("osv rows = %v, want %v", got, want)
			}
		})
	}
}

// instanceVerdicts lists GO-S-1's rows from source as "package verdict", sorted.
func instanceVerdicts(rows []report.AdvisoryFinding, source string) []string {
	var out []string
	for _, f := range rows {
		if f.Advisory.ID != "GO-S-1" || f.Advisory.Source != source {
			continue
		}
		name := "<none>"
		if f.Package != nil {
			name = f.Package.Name
		}
		out = append(out, strings.TrimSpace(name+" "+string(f.Verdict)))
	}
	slices.Sort(out)
	return out
}

// stopNthReach stops the analysis on its n-th reachability call.
type stopNthReach struct {
	splitVerdictPlugin
	stop  context.CancelFunc
	calls *atomic.Int32
	n     int32
}

func (p stopNthReach) Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	if p.calls.Add(1) == p.n {
		p.stop()
		<-ctx.Done()
		return plugin.ReachabilityResult{}, ctx.Err()
	}
	return p.splitVerdictPlugin.Reachability(ctx, req)
}

// heldOSVRows stores a baseline, then a held-cursor cve-watch on which OSV newly flags GO-S-1 for
// example.com/lib/v2, so GO-S-1's osv rows are stored and the next cve-watch sees it as new again.
func heldOSVRows(t *testing.T, p plugin.LanguagePlugin) (*memStore, []OSVAdvisory) {
	t.Helper()
	store := &memStore{}
	if _, err := RunBaseline(context.Background(), store, BaselineRequest{
		Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "base-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		Advisories:    passAdvisories("GO-S-1"),
		AssessOptions: siblingAssessOpts(t, p, splitVerdictSource{}),
	}); err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
	var osv []OSVAdvisory
	for _, f := range store.state.Report.Advisories {
		if f.Package != nil && f.Package.Name == "example.com/lib/v2" {
			osv = append(osv, OSVAdvisory{ID: "GO-S-1", Package: *f.Package})
		}
	}
	if _, err := RunCVEWatch(context.Background(), store, &fakeOSV{result: OSVResult{Advisories: osv}}, CVEWatchRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		AssessOptions: siblingAssessOpts(t, p, splitVerdictSource{}),
		HoldCursor:    true,
	}); err != nil {
		t.Fatalf("held RunCVEWatch: %v", err)
	}
	if got := instanceVerdicts(store.state.Report.Advisories, osvSource); len(got) != 2 {
		t.Fatalf("held run stored osv rows %v, want one per instance", got)
	}
	return store, osv
}

// TestCVEWatch_NewOSVAdvisoryRerunReplacesEveryInstanceRow: a held cursor stored GO-S-1's osv rows
// when neither instance was reached; OSV flags it again and now example.com/lib/v2 is reached. Each
// instance's fresh row replaces its stored one, so no stale not_exploitable row stands beside it.
func TestCVEWatch_NewOSVAdvisoryRerunReplacesEveryInstanceRow(t *testing.T) {
	store, osv := heldOSVRows(t, refutingGoPlugin{inventory: plugin.Complete()})
	res, err := RunCVEWatch(context.Background(), store, &fakeOSV{result: OSVResult{Advisories: osv}}, CVEWatchRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		AssessOptions: siblingAssessOpts(t, splitVerdictPlugin{refutingGoPlugin{inventory: plugin.Complete()}}, splitVerdictSource{}),
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	want := []string{"example.com/lib not_exploitable", "example.com/lib/v2 reachable_candidate"}
	if got := instanceVerdicts(res.Report.Advisories, osvSource); !slices.Equal(got, want) {
		t.Errorf("osv rows = %v, want %v", got, want)
	}
}

// TestCVEWatch_NewOSVAdvisoryParentStopKeepsSiblingRow: OSV flags stored GO-S-1 again and the run
// stops in the parent's analysis, before the sibling pass. The parent's stored row gives way to a
// cut row (which, like every cut row, records no package), as a retry's does, and the sibling's
// stored row stands: nothing re-assessed it.
func TestCVEWatch_NewOSVAdvisoryParentStopKeepsSiblingRow(t *testing.T) {
	store, osv := heldOSVRows(t, splitVerdictPlugin{refutingGoPlugin{inventory: plugin.Complete()}})
	analysis, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(nil) })
	stop := stopNthReach{splitVerdictPlugin{refutingGoPlugin{inventory: plugin.Complete()}}, func() { cancel(errTestStop) }, &atomic.Int32{}, 1}
	res, err := RunCVEWatch(context.Background(), store, &fakeOSV{result: OSVResult{Advisories: osv}}, CVEWatchRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		AssessOptions: siblingAssessOpts(t, stop, splitVerdictSource{}),
		Analysis:      analysis,
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	want := []string{"<none> undetermined", "example.com/lib/v2 reachable_candidate"}
	if got := instanceVerdicts(res.Report.Advisories, osvSource); !slices.Equal(got, want) {
		t.Errorf("osv rows = %v, want %v", got, want)
	}
	for _, f := range res.Report.Advisories {
		if f.Advisory.Source == osvSource && f.Verdict == report.VerdictUndetermined && f.UndeterminedReason != report.ReasonScanCutShort {
			t.Errorf("undetermined osv row %v has reason %q, want %q", f.Package, f.UndeterminedReason, report.ReasonScanCutShort)
		}
	}
}
