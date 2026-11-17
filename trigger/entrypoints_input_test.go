package trigger

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// requestEntrypointsPlugin is refutingGoPlugin with the lane recording the entry points it resolved
// from the request it was handed, as the go lane does.
type requestEntrypointsPlugin struct{ refutingGoPlugin }

func (p requestEntrypointsPlugin) Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	res, err := p.refutingGoPlugin.Reachability(ctx, req)
	if le := req.LibraryEntrypoints; le != nil {
		src := plugin.LibraryEntrypointsSourceAuto
		if le.Declared() {
			src = plugin.LibraryEntrypointsSourceDeclared
		}
		res.LibraryEntrypoints = &plugin.ResolvedLibraryEntrypoints{Ecosystem: "golang", Source: src, Input: le.String(), Packages: []string{}}
	}
	return res, err
}

func reportJSON(t *testing.T, r *report.Report) string {
	t.Helper()
	c := *r
	c.Provenance.Timestamp = time.Time{}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestEntrypointsInput_StateStore: a changed entrypoints value is treated as a changed
// library-entrypoints value. A re-analysis records the entry points of the value it ran with in place of
// the stored report's, and an unchanged value records the same set again; where the value is not
// re-resolved (the PR inherit fast path) the stored set stands. Whichever way the value is given, as
// library-entrypoints or as the clauses it stands for, the Report is byte-identical.
func TestEntrypointsInput_StateStore(t *testing.T) {
	stored := []plugin.ResolvedLibraryEntrypoints{{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "none", Packages: []string{}}}
	bumped := func(*report.Report) report.SBOM {
		return report.SBOM{Packages: []report.Package{{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.5"}}}
	}
	type run func(t *testing.T, opts []pipeline.AssessOption) *report.Report
	prReanalysis := func(t *testing.T, opts []pipeline.AssessOption) *report.Report {
		store, baseline := groundedBaseline()
		baseline.LibraryEntrypoints = stored
		res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
			Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
			Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
			PRSBOM:        bumped(baseline),
			Advisories:    []assessment.VulnRef{wiringAdvisory},
			AssessOptions: opts,
		})
		if err != nil {
			t.Fatalf("RunPRInherit: %v", err)
		}
		return res.Report
	}
	fastPath := func(t *testing.T, opts []pipeline.AssessOption) *report.Report {
		store, baseline := groundedBaseline()
		baseline.LibraryEntrypoints = stored
		res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
			Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
			Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
			PRSBOM:        baseline.SBOM,
			Advisories:    []assessment.VulnRef{wiringAdvisory},
			AssessOptions: opts,
		})
		if err != nil {
			t.Fatalf("RunPRInherit: %v", err)
		}
		return res.Report
	}
	cveWatch := func(t *testing.T, opts []pipeline.AssessOption) *report.Report {
		store, _ := seedBaseline(t)
		store.state.Report.LibraryEntrypoints = stored
		store.state.Cursor = ""
		osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: wiringAdvisory.ID, Package: wiringPkg}}}}
		res, err := RunCVEWatch(context.Background(), store, osv, CVEWatchRequest{
			Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
			Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
			AssessOptions: opts,
		})
		if err != nil {
			t.Fatalf("RunCVEWatch: %v", err)
		}
		if res.Report == nil {
			t.Fatal("CVE-watch ran no earnest pass")
		}
		return res.Report
	}
	cases := []struct {
		name  string
		run   run
		value string // library-entrypoints syntax
		want  string // the Input of the one recorded set
	}{
		{"PR re-analysis, value changed", prReanalysis, "pkg/api", "pkg/api"},
		{"PR re-analysis, value changed to auto", prReanalysis, "auto", "auto"},
		{"PR re-analysis, value unchanged", prReanalysis, "none", "none"},
		{"CVE-watch, value changed", cveWatch, "pkg/api,!pkg/api/x", "pkg/api,!pkg/api/x"},
		{"CVE-watch, value unchanged", cveWatch, "none", "none"},
		{"PR inherit fast path keeps the stored set", fastPath, "pkg/api", "none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			le, err := plugin.ParseLibraryEntrypoints(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			overrides, err := plugin.ParseEntryOverrides(plugin.EntryOverrideForLibraryEntrypoints(le).Input)
			if err != nil {
				t.Fatal(err)
			}
			base := func(extra pipeline.AssessOption) []pipeline.AssessOption {
				return []pipeline.AssessOption{
					pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}),
					pipeline.WithPlugin(requestEntrypointsPlugin{refutingGoPlugin{inventory: plugin.Complete()}}),
					extra,
				}
			}
			viaAlias := tc.run(t, base(pipeline.WithLibraryEntrypoints(le)))
			viaClauses := tc.run(t, base(pipeline.WithEntrypoints(overrides)))
			if len(viaAlias.LibraryEntrypoints) != 1 || viaAlias.LibraryEntrypoints[0].Input != tc.want {
				t.Errorf("library_entrypoints = %+v, want one set with input %q", viaAlias.LibraryEntrypoints, tc.want)
			}
			if !reflect.DeepEqual(viaClauses.LibraryEntrypoints, viaAlias.LibraryEntrypoints) {
				t.Errorf("via entrypoints: %+v, via library-entrypoints: %+v", viaClauses.LibraryEntrypoints, viaAlias.LibraryEntrypoints)
			}
			if a, c := reportJSON(t, viaAlias), reportJSON(t, viaClauses); a != c {
				t.Errorf("reports differ:\n via library-entrypoints %s\n via entrypoints         %s", a, c)
			}
		})
	}
}
