package trigger

import (
	"context"
	"slices"
	"strings"
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
