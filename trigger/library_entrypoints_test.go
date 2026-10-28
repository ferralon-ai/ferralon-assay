package trigger

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestFinding_RefutationAssumptionsReachEvidence: a not_exploitable grounded on a refutation that
// holds only under a declaration states it on the finding; one that rests on the scan alone states none.
func TestFinding_RefutationAssumptionsReachEvidence(t *testing.T) {
	const assumption = `library-entrypoints "none": no code outside the build imports example.com/m/lib, which reach golang.org/x/net`
	fx := netNotReached()
	if f := fx.finding(t); f.Verdict != report.VerdictNotExploitable || len(f.Evidence.Assumptions) > 0 {
		t.Fatalf("got %s with assumptions %q, want not_exploitable with none", f.Verdict, f.Evidence.Assumptions)
	}
	fx.reach.Refutation.Assumptions = []string{assumption}
	f := fx.finding(t)
	if f.Verdict != report.VerdictNotExploitable {
		t.Fatalf("got %s/%q, want not_exploitable", f.Verdict, f.UndeterminedReason)
	}
	if !slices.Equal(f.Evidence.Assumptions, []string{assumption}) {
		t.Errorf("assumptions = %q, want %q", f.Evidence.Assumptions, []string{assumption})
	}
	if err := report.NewBuilder(report.Subject{ResolvedCommit: "c"}).AddFinding(f).Build().Validate(); err != nil {
		t.Errorf("the finding should validate: %v", err)
	}

	// Arm A grounds first when the lane also searched the symbols; it carries the refutation's
	// assumptions, since its search started from the same entry points.
	armA := yamlSearched()
	armA.reach.Refutation = refutation("pkg:pypi/PyYAML")
	armA.reach.Refutation.Assumptions = []string{assumption}
	if f := armA.finding(t); f.Verdict != report.VerdictNotExploitable || !strings.Contains(f.Evidence.Detail, "no path from any entry point") ||
		!slices.Equal(f.Evidence.Assumptions, []string{assumption}) {
		t.Errorf("arm A: got %s %q with assumptions %q, want not_exploitable on arm A with %q", f.Verdict, f.Evidence.Detail, f.Evidence.Assumptions, []string{assumption})
	}
}

// TestLibraryEntrypoints_ReadsReachabilityRecord: the resolved set comes off the reachability
// artifact, and is empty when the lane resolved none.
func TestLibraryEntrypoints_ReadsReachabilityRecord(t *testing.T) {
	want := &plugin.ResolvedLibraryEntrypoints{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "pkg/api", Packages: []string{"example.com/m/pkg/api"}}
	store := artifact.NewMemStore()
	seedReachArtifact(t, store, "a", plugin.CallGraphResult{Partiality: plugin.Complete()}, plugin.ReachabilityResult{Partiality: plugin.Complete(), LibraryEntrypoints: want})
	if got := libraryEntrypoints(store, "a"); len(got) != 1 || !reflect.DeepEqual(got[0], *want) {
		t.Errorf("libraryEntrypoints = %+v, want [%+v]", got, *want)
	}
	seedReachArtifact(t, store, "b", plugin.CallGraphResult{Partiality: plugin.Complete()}, plugin.ReachabilityResult{Partiality: plugin.Complete()})
	if got := libraryEntrypoints(store, "b"); got != nil {
		t.Errorf("libraryEntrypoints with none resolved = %+v, want nil", got)
	}
	if got := libraryEntrypoints(store, "missing"); got != nil {
		t.Errorf("libraryEntrypoints with no artifact = %+v, want nil", got)
	}
}

// entrypointsGoPlugin is refutingGoPlugin with the lane recording the entry points it resolved.
type entrypointsGoPlugin struct {
	refutingGoPlugin
	resolved *plugin.ResolvedLibraryEntrypoints
}

func (p entrypointsGoPlugin) Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	res, err := p.refutingGoPlugin.Reachability(ctx, req)
	res.LibraryEntrypoints = p.resolved
	return res, err
}

// TestLibraryEntrypoints_EveryRunMode: each run mode records the entry points this pass resolved,
// and where it resolved none, the stored report's, which its inherited rows rest on.
func TestLibraryEntrypoints_EveryRunMode(t *testing.T) {
	head := &plugin.ResolvedLibraryEntrypoints{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "none", Packages: []string{}}
	stored := []plugin.ResolvedLibraryEntrypoints{{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceAuto, Input: "auto", Packages: []string{"example.com/target/lib"}}}
	options := func(t *testing.T, resolved *plugin.ResolvedLibraryEntrypoints) []pipeline.AssessOption {
		return []pipeline.AssessOption{
			pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}),
			pipeline.WithPlugin(entrypointsGoPlugin{refutingGoPlugin: refutingGoPlugin{inventory: plugin.Complete()}, resolved: resolved}),
		}
	}
	pr := func(t *testing.T, sbom func(*report.Report) report.SBOM, resolved *plugin.ResolvedLibraryEntrypoints) *report.Report {
		store, baseline := groundedBaseline()
		baseline.LibraryEntrypoints = stored
		res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
			Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
			Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
			PRSBOM:        sbom(baseline),
			Advisories:    []assessment.VulnRef{wiringAdvisory},
			AssessOptions: options(t, resolved),
		})
		if err != nil {
			t.Fatalf("RunPRInherit: %v", err)
		}
		return res.Report
	}
	bumped := func(*report.Report) report.SBOM {
		return report.SBOM{Packages: []report.Package{{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.5"}}}
	}
	cveWatch := func(t *testing.T, resolved *plugin.ResolvedLibraryEntrypoints) *report.Report {
		store, _ := seedBaseline(t)
		store.state.Report.LibraryEntrypoints = stored
		store.state.Cursor = ""
		osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: wiringAdvisory.ID, Package: wiringPkg}}}}
		res, err := RunCVEWatch(context.Background(), store, osv, CVEWatchRequest{
			Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
			Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
			AssessOptions: options(t, resolved),
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
		name string
		run  func(t *testing.T) *report.Report
		want []plugin.ResolvedLibraryEntrypoints
	}{
		{"baseline", func(t *testing.T) *report.Report {
			rep, err := buildBaselineReport(context.Background(), BaselineRequest{
				Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				Advisories:    []assessment.VulnRef{wiringAdvisory},
				AssessOptions: options(t, head),
			})
			if err != nil {
				t.Fatalf("buildBaselineReport: %v", err)
			}
			return rep
		}, []plugin.ResolvedLibraryEntrypoints{*head}},
		{"PR re-analysis, head resolved", func(t *testing.T) *report.Report { return pr(t, bumped, head) }, []plugin.ResolvedLibraryEntrypoints{*head}},
		{"PR re-analysis, head resolved none", func(t *testing.T) *report.Report { return pr(t, bumped, nil) }, stored},
		{"PR inherit fast path", func(t *testing.T) *report.Report {
			return pr(t, func(b *report.Report) report.SBOM { return b.SBOM }, head)
		}, stored},
		{"CVE-watch, pass resolved", func(t *testing.T) *report.Report { return cveWatch(t, head) }, []plugin.ResolvedLibraryEntrypoints{*head}},
		{"CVE-watch, pass resolved none", func(t *testing.T) *report.Report { return cveWatch(t, nil) }, stored},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.run(t).LibraryEntrypoints; !reflect.DeepEqual(got, tc.want) {
				t.Errorf("library_entrypoints = %+v, want %+v", got, tc.want)
			}
		})
	}
}
