package trigger

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/jsanalysis"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// refutingGoPlugin grounds not_exploitable for GO-2021-0113 on arm B, so each run mode's row turns
// on the inventory limit alone. inventory is the head's inventory partiality.
type refutingGoPlugin struct {
	goManifestPlugin
	inventory plugin.Partiality
}

func (p refutingGoPlugin) ResolveInventory(context.Context, plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	return plugin.DependencyInventory{
		Partiality: p.inventory,
		Nodes: []plugin.DependencyNode{{
			ID: "golang.org/x/text@v0.3.6", PURL: "pkg:golang/golang.org/x/text@v0.3.6", Version: "v0.3.6", Direct: true,
		}},
	}, nil
}

func (refutingGoPlugin) Reachability(context.Context, plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	return plugin.ReachabilityResult{
		Partiality: plugin.Complete(),
		Refutation: &plugin.Refutation{
			Basis:   plugin.RefutationAnalyzerSymbolNotReached,
			Package: "pkg:golang/golang.org/x/text",
			Detail:  "govulncheck reached no vulnerable symbol",
		},
	}, nil
}

const wiringGoMod = "module example.com/target\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.6\n"

var (
	wiringAdvisory = assessment.VulnRef{ID: "GO-2021-0113", Source: "corpus"}
	wiringPkg      = report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.6"}
	// A head inventory limit: an ambiguous lockfile may hide a second copy of the package.
	partialInv  = plugin.Partial(plugin.PartialReasonLockfileAmbiguous)
	wiringLimit = inventoryPartialityNotes(partialInv, "Go")[0]
)

func wiringOptions(t *testing.T, inv plugin.Partiality) []pipeline.AssessOption {
	t.Helper()
	return []pipeline.AssessOption{
		pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}),
		pipeline.WithPlugin(refutingGoPlugin{inventory: inv}),
	}
}

// groundedBaseline is a stored baseline whose GO-2021-0113 row is a grounded not_exploitable.
func groundedBaseline() (*memStore, *report.Report) {
	pkg := wiringPkg
	baseline := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
		AddPackage(pkg).
		NotExploitable(report.Advisory{ID: wiringAdvisory.ID, Source: wiringAdvisory.Source}, &pkg,
			"vulnerable_symbol_absent", "golang.org/x/text@v0.3.6: govulncheck reached no vulnerable symbol").
		WithProvenance(report.Provenance{CommitSHA: "base-sha", AdvisoryCursor: wiringAdvisory.ID}).
		Build()
	return &memStore{state: &statestore.State{Report: &baseline, SBOM: baseline.SBOM, Cursor: wiringAdvisory.ID}}, &baseline
}

func wiringVerdict(t *testing.T, rep *report.Report) report.Verdict {
	t.Helper()
	for _, f := range rep.Advisories {
		if f.Advisory.ID == wiringAdvisory.ID {
			return f.Verdict
		}
	}
	t.Fatalf("no %s row in the report", wiringAdvisory.ID)
	return ""
}

// TestInventoryLimits_EveryRunMode: a did_not_run inventory limit on the head turns a grounded
// not_exploitable into undetermined in every run mode, for fresh and inherited rows alike. Each
// row's control (no limit) keeps the not_exploitable, so the limit is what moved it.
func TestInventoryLimits_EveryRunMode(t *testing.T) {
	modes := []struct {
		name string
		run  func(t *testing.T, limited bool) *report.Report
	}{
		{"baseline", func(t *testing.T, limited bool) *report.Report {
			inv := plugin.Complete()
			if limited {
				inv = partialInv
			}
			rep, err := buildBaselineReport(context.Background(), BaselineRequest{
				Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				Advisories:    []assessment.VulnRef{wiringAdvisory},
				AssessOptions: wiringOptions(t, inv),
			})
			if err != nil {
				t.Fatalf("buildBaselineReport: %v", err)
			}
			return rep
		}},
		{"PR re-analysis, fresh row", func(t *testing.T, limited bool) *report.Report {
			store, _ := groundedBaseline()
			return runPR(t, store, report.SBOM{Packages: []report.Package{{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.5"}}}, limited)
		}},
		{"PR re-analysis, carried row", func(t *testing.T, limited bool) *report.Report {
			store, baseline := groundedBaseline()
			head := append([]report.Package{{Ecosystem: "Go", Name: "example.org/other", Version: "v1.0.0"}}, baseline.SBOM.Packages...)
			return runPR(t, store, report.SBOM{Packages: head}, limited)
		}},
		{"PR inherit fast path", func(t *testing.T, limited bool) *report.Report {
			store, baseline := groundedBaseline()
			return runPR(t, store, baseline.SBOM, limited)
		}},
		{"CVE-watch", func(t *testing.T, limited bool) *report.Report {
			store, _ := seedBaseline(t)
			if limited {
				store.state.Report.Partiality = append(store.state.Report.Partiality, wiringLimit)
			}
			osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: wiringAdvisory.ID, Package: wiringPkg}}}}
			store.state.Cursor = ""
			res, err := RunCVEWatch(context.Background(), store, osv, CVEWatchRequest{
				Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				AssessOptions: wiringOptions(t, plugin.Complete()),
			})
			if err != nil {
				t.Fatalf("RunCVEWatch: %v", err)
			}
			if res.Report == nil {
				t.Fatal("CVE-watch ran no earnest pass")
			}
			return res.Report
		}},
	}
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			if got := wiringVerdict(t, m.run(t, false)); got != report.VerdictNotExploitable {
				t.Fatalf("control: verdict = %q, want not_exploitable", got)
			}
			if got := wiringVerdict(t, m.run(t, true)); got != report.VerdictUndetermined {
				t.Fatalf("with a did_not_run inventory limit: verdict = %q, want undetermined", got)
			}
		})
	}
}

func runPR(t *testing.T, store *memStore, head report.SBOM, limited bool) *report.Report {
	t.Helper()
	var limits []report.PartialityNote
	if limited {
		limits = []report.PartialityNote{wiringLimit}
	}
	res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		PRSBOM:        head,
		Advisories:    []assessment.VulnRef{wiringAdvisory},
		DiffLimits:    limits,
		AssessOptions: wiringOptions(t, plugin.Complete()),
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	return res.Report
}

// multiCopyJSPlugin is the real JS version lane, so the version set and its vouching are the
// lane's own. inventory is the head's inventory partiality.
type multiCopyJSPlugin struct {
	plugin.StubPlugin
	inventory plugin.Partiality
}

func (multiCopyJSPlugin) Language() string { return "js" }

func (multiCopyJSPlugin) BuildManifest(context.Context, plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	return plugin.BuildManifestResult{Partiality: plugin.Unsupported()}, nil
}

func (multiCopyJSPlugin) ResolveDependencyVersions(ctx context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	return jsanalysis.ResolveDependencyVersions(ctx, req)
}

func (p multiCopyJSPlugin) ResolveInventory(context.Context, plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	return plugin.DependencyInventory{Partiality: p.inventory}, nil
}

// TestInventoryLimits_MultiCopyDisqualification runs a whole scan over a lockfile that installs
// left-pad at 1.4.0 and, nested, at 1.5.0, both outside FERRALON-JS-DEP-0001's range. The copies
// disagree, so the row is disqualified on the version set with no single version and no Package.
// Under a did_not_run inventory limit the row still becomes undetermined: the limit cannot be
// matched to the row's ecosystem, so it applies.
func TestInventoryLimits_MultiCopyDisqualification(t *testing.T) {
	dir := t.TempDir()
	lock := `{"name": "app", "lockfileVersion": 3, "packages": {
  "": {"name": "app", "version": "1.0.0"},
  "node_modules/left-pad": {"version": "1.4.0"},
  "node_modules/wrapper": {"version": "2.0.0"},
  "node_modules/wrapper/node_modules/left-pad": {"version": "1.5.0"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	advisory := assessment.VulnRef{ID: "FERRALON-JS-DEP-0001", Source: "corpus"}
	run := func(inv plugin.Partiality) report.AdvisoryFinding {
		t.Helper()
		rep, err := buildBaselineReport(context.Background(), BaselineRequest{
			Subject:    Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
			Codebase:   assessment.CodebaseRef{Repo: "r", Revision: "main"},
			Advisories: []assessment.VulnRef{advisory},
			AssessOptions: []pipeline.AssessOption{
				pipeline.WithCheckout(fixedCheckout{dir: dir, lang: "js"}),
				pipeline.WithPlugin(multiCopyJSPlugin{inventory: inv}),
			},
		})
		if err != nil {
			t.Fatalf("buildBaselineReport: %v", err)
		}
		for _, f := range rep.Advisories {
			if f.Advisory.ID == advisory.ID {
				return f
			}
		}
		t.Fatalf("no %s row in the report", advisory.ID)
		return report.AdvisoryFinding{}
	}
	if f := run(plugin.Complete()); f.Verdict != report.VerdictDisqualified || f.Package != nil {
		t.Fatalf("control: verdict = %s (%s), package %+v; want disqualified with no package", f.Verdict, f.Evidence.Detail, f.Package)
	}
	if f := run(plugin.Partial(plugin.PartialReasonLockfileAmbiguous)); f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != report.ReasonAnalysisDidNotRun {
		t.Fatalf("with a did_not_run inventory limit: verdict = %s/%q, want undetermined/%s", f.Verdict, f.UndeterminedReason, report.ReasonAnalysisDidNotRun)
	}
}
