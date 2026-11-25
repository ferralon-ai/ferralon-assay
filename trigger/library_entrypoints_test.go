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

// rootsGoPlugin is entrypointsGoPlugin with the lane also recording the entrypoints[] record.
type rootsGoPlugin struct {
	entrypointsGoPlugin
	roots *plugin.EntryRootRecord
}

func (p rootsGoPlugin) Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	res, err := p.entrypointsGoPlugin.Reachability(ctx, req)
	res.EntryRoots = p.roots
	return res, err
}

// TestEntryRoots_ReadsReachabilityRecord: the lane's entrypoints[] record comes off the reachability
// artifact with its inferred and denied entries, and is empty when the lane recorded none.
func TestEntryRoots_ReadsReachabilityRecord(t *testing.T) {
	want := &plugin.EntryRootRecord{
		Lane: plugin.EntryLaneGo, Source: plugin.LibraryEntrypointsSourceDeclared, Input: "!pkg/lib",
		Effective: map[string][]string{plugin.EntryKindLibrary: {"example.com/m/pkg/api"}},
		Inferred: map[string][]string{
			plugin.EntryKindLibrary: {"example.com/m/pkg/api", "example.com/m/pkg/lib"},
			plugin.EntryKindMain:    {"example.com/m/cmd/tool"},
		},
		Denied: []string{"!pkg/lib"},
	}
	store := artifact.NewMemStore()
	seedReachArtifact(t, store, "a", plugin.CallGraphResult{Partiality: plugin.Complete()}, plugin.ReachabilityResult{Partiality: plugin.Complete(), EntryRoots: want})
	if got := entryRoots(store, "a"); len(got) != 1 || !reflect.DeepEqual(got[0], *want) {
		t.Errorf("entryRoots = %+v, want [%+v]", got, *want)
	}
	seedReachArtifact(t, store, "b", plugin.CallGraphResult{Partiality: plugin.Complete()}, plugin.ReachabilityResult{Partiality: plugin.Complete()})
	if got := entryRoots(store, "b"); got != nil {
		t.Errorf("entryRoots with none recorded = %+v, want nil", got)
	}
}

// TestEntryRoots_EveryRunMode: each run mode states the inferred and denied entry points of the
// pass that resolved them, else the stored report's, and entrypoints[] never drifts from
// library_entrypoints.
func TestEntryRoots_EveryRunMode(t *testing.T) {
	recordOf := func(lib plugin.ResolvedLibraryEntrypoints, denied ...string) plugin.EntryRootRecord {
		rec, _ := plugin.EntryRootRecordOf(lib)
		rec.Inferred = map[string][]string{
			plugin.EntryKindLibrary: {"example.com/target/lib", "example.com/target/other"},
			plugin.EntryKindMain:    {"example.com/target/cmd/tool"},
		}
		rec.Denied = denied
		return rec
	}
	headLib := plugin.ResolvedLibraryEntrypoints{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "!lib", Packages: []string{"example.com/target/other"}}
	storedLib := plugin.ResolvedLibraryEntrypoints{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceAuto, Input: "auto", Packages: []string{"example.com/target/lib", "example.com/target/other"}}
	head, stored := recordOf(headLib, "!lib"), recordOf(storedLib)
	// A head pass over a changed package set that resolved a record and no set.
	movedLib := plugin.ResolvedLibraryEntrypoints{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceAuto, Input: "auto", Packages: []string{"example.com/target/lib", "example.com/target/new"}}
	moved := recordOf(movedLib)
	// Read as an application, every mains set states the same empty library set, so only the stored
	// record names the mains the stored refutations searched from.
	mainsLib := plugin.ResolvedLibraryEntrypoints{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceMains, Input: "auto", Packages: []string{}}
	mainsOf := func(mains ...string) plugin.EntryRootRecord {
		rec := recordOf(mainsLib)
		rec.Effective[plugin.EntryKindMain] = mains
		return rec
	}
	storedMains, headMains := mainsOf("example.com/target/cmd/app"), mainsOf("example.com/target/cmd/app", "example.com/target/cmd/newtool")
	type storedPair struct {
		lib plugin.ResolvedLibraryEntrypoints
		rec plugin.EntryRootRecord
	}
	held := storedPair{storedLib, stored}
	options := func(t *testing.T, lib *plugin.ResolvedLibraryEntrypoints, roots *plugin.EntryRootRecord) []pipeline.AssessOption {
		return []pipeline.AssessOption{
			pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}),
			pipeline.WithPlugin(rootsGoPlugin{
				entrypointsGoPlugin: entrypointsGoPlugin{refutingGoPlugin: refutingGoPlugin{inventory: plugin.Complete()}, resolved: lib},
				roots:               roots,
			}),
		}
	}
	pr := func(t *testing.T, sbom func(*report.Report) report.SBOM, lib *plugin.ResolvedLibraryEntrypoints, roots *plugin.EntryRootRecord) *report.Report {
		store, baseline := groundedBaseline()
		baseline.LibraryEntrypoints = []plugin.ResolvedLibraryEntrypoints{held.lib}
		baseline.Entrypoints = []plugin.EntryRootRecord{held.rec}
		res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
			Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
			Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
			PRSBOM:        sbom(baseline),
			Advisories:    []assessment.VulnRef{wiringAdvisory},
			AssessOptions: options(t, lib, roots),
		})
		if err != nil {
			t.Fatalf("RunPRInherit: %v", err)
		}
		return res.Report
	}
	bumped := func(*report.Report) report.SBOM {
		return report.SBOM{Packages: []report.Package{{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.5"}}}
	}
	cveWatch := func(t *testing.T, lib *plugin.ResolvedLibraryEntrypoints, roots *plugin.EntryRootRecord) *report.Report {
		store, _ := seedBaseline(t)
		store.state.Report.LibraryEntrypoints = []plugin.ResolvedLibraryEntrypoints{held.lib}
		store.state.Report.Entrypoints = []plugin.EntryRootRecord{held.rec}
		store.state.Cursor = ""
		osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: wiringAdvisory.ID, Package: wiringPkg}}}}
		res, err := RunCVEWatch(context.Background(), store, osv, CVEWatchRequest{
			Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
			Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
			AssessOptions: options(t, lib, roots),
		})
		if err != nil {
			t.Fatalf("RunCVEWatch: %v", err)
		}
		if res.Report == nil {
			t.Fatal("CVE-watch ran no earnest pass")
		}
		return res.Report
	}
	mainsHeld := &storedPair{mainsLib, storedMains}
	cases := []struct {
		name   string
		stored *storedPair
		run    func(t *testing.T) *report.Report
		want   plugin.EntryRootRecord
	}{
		{"baseline", nil, func(t *testing.T) *report.Report {
			rep, err := buildBaselineReport(context.Background(), BaselineRequest{
				Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				Advisories:    []assessment.VulnRef{wiringAdvisory},
				AssessOptions: options(t, &headLib, &head),
			})
			if err != nil {
				t.Fatalf("buildBaselineReport: %v", err)
			}
			return rep
		}, head},
		{"PR re-analysis, head resolved", nil, func(t *testing.T) *report.Report { return pr(t, bumped, &headLib, &head) }, head},
		{"PR re-analysis, head resolved none", nil, func(t *testing.T) *report.Report { return pr(t, bumped, nil, nil) }, stored},
		{"PR re-analysis, head resolved a set but no record", nil, func(t *testing.T) *report.Report { return pr(t, bumped, &headLib, nil) },
			func() plugin.EntryRootRecord { r, _ := plugin.EntryRootRecordOf(headLib); return r }()},
		{"PR re-analysis, head resolved a record but no set", nil, func(t *testing.T) *report.Report { return pr(t, bumped, nil, &moved) }, stored},
		{"PR inherit fast path", nil, func(t *testing.T) *report.Report {
			return pr(t, func(b *report.Report) report.SBOM { return b.SBOM }, &headLib, &head)
		}, stored},
		{"CVE-watch, pass resolved", nil, func(t *testing.T) *report.Report { return cveWatch(t, &headLib, &head) }, head},
		{"CVE-watch, pass resolved none", nil, func(t *testing.T) *report.Report { return cveWatch(t, nil, nil) }, stored},
		{"PR re-analysis, application, head resolved a record but no set", mainsHeld,
			func(t *testing.T) *report.Report { return pr(t, bumped, nil, &headMains) }, storedMains},
		{"CVE-watch, application, pass resolved a record but no set", mainsHeld,
			func(t *testing.T) *report.Report { return cveWatch(t, nil, &headMains) }, storedMains},
		{"CVE-watch, application, pass resolved", mainsHeld,
			func(t *testing.T) *report.Report { return cveWatch(t, &mainsLib, &headMains) }, headMains},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			held = storedPair{storedLib, stored}
			if tc.stored != nil {
				held = *tc.stored
			}
			r := tc.run(t)
			if len(r.Entrypoints) != 1 || !reflect.DeepEqual(r.Entrypoints[0], tc.want) {
				t.Errorf("entrypoints = %+v, want [%+v]", r.Entrypoints, tc.want)
			}
		})
	}
}

// TestEntryRoots_JSReadsReachabilityRecord: the js lane's record comes off the reachability artifact
// as recorded, whatever lane wrote it.
func TestEntryRoots_JSReadsReachabilityRecord(t *testing.T) {
	want := &plugin.EntryRootRecord{
		Lane: plugin.EntryLaneJS, Source: plugin.LibraryEntrypointsSourceDeclared, Input: "!js:bin=bin:tool",
		Effective: map[string][]string{plugin.EntryKindBin: {}, plugin.EntryKindScript: {"npm:tool/index.js"}},
		Inferred:  map[string][]string{plugin.EntryKindBin: {"bin:tool"}, plugin.EntryKindScript: {"npm:tool/index.js"}},
		Denied:    []string{"!bin:tool"},
		Unmatched: []string{"!bin:nothing"},
	}
	store := artifact.NewMemStore()
	seedReachArtifact(t, store, "a", plugin.CallGraphResult{Partiality: plugin.Complete()}, plugin.ReachabilityResult{Partiality: plugin.Complete(), EntryRoots: want})
	if got := entryRoots(store, "a"); len(got) != 1 || !reflect.DeepEqual(got[0], *want) {
		t.Errorf("entryRoots = %+v, want [%+v]", got, *want)
	}
}

// TestEntryRoots_JSCarriedWhereTheLaneRecordedNone: a PR inherit or CVE-watch pass that records no
// js record carries the stored report's, which the inherited rows rest on, unchanged.
func TestEntryRoots_JSCarriedWhereTheLaneRecordedNone(t *testing.T) {
	stored := plugin.EntryRootRecord{
		Lane: plugin.EntryLaneJS, Source: plugin.LibraryEntrypointsSourceDeclared, Input: "!js:bin=bin:old",
		Effective: map[string][]string{plugin.EntryKindBin: {}, plugin.EntryKindScript: {"npm:tool/index.js"}},
		Inferred:  map[string][]string{plugin.EntryKindBin: {"bin:old"}, plugin.EntryKindScript: {"npm:tool/index.js"}},
		Denied:    []string{"!bin:old"},
	}
	opts := []pipeline.AssessOption{
		pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}),
		pipeline.WithPlugin(refutingGoPlugin{inventory: plugin.Complete()}),
	}
	t.Run("PR inherit fast path", func(t *testing.T) {
		store, baseline := groundedBaseline()
		baseline.Entrypoints = []plugin.EntryRootRecord{stored}
		res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
			Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
			Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
			PRSBOM:        baseline.SBOM,
			Advisories:    []assessment.VulnRef{wiringAdvisory},
			AssessOptions: opts,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(res.Report.Entrypoints, func(r plugin.EntryRootRecord) bool { return reflect.DeepEqual(r, stored) }) {
			t.Errorf("entrypoints = %+v, want the stored js record", res.Report.Entrypoints)
		}
	})
	t.Run("CVE-watch", func(t *testing.T) {
		store, _ := seedBaseline(t)
		store.state.Report.Entrypoints = []plugin.EntryRootRecord{stored}
		store.state.Cursor = ""
		osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: wiringAdvisory.ID, Package: wiringPkg}}}}
		res, err := RunCVEWatch(context.Background(), store, osv, CVEWatchRequest{
			Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
			Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
			AssessOptions: opts,
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.Report == nil || !slices.ContainsFunc(res.Report.Entrypoints, func(r plugin.EntryRootRecord) bool { return reflect.DeepEqual(r, stored) }) {
			t.Errorf("CVE-watch dropped the stored js record: %+v", res.Report)
		}
	})
}
