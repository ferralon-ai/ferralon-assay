package trigger

import (
	"context"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// xnetRefutedPlugin is a Go lane over a build of example.com/app and its workspace member
// example.com/a, whose module list is the go mod graph, and which refutes golang.org/x/net.
type xnetRefutedPlugin struct{ goManifestPlugin }

func (xnetRefutedPlugin) ResolveInventory(context.Context, plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	return plugin.DependencyInventory{
		Partiality:       plugin.Complete(),
		Nodes:            []plugin.DependencyNode{{ID: "x/net", PURL: "pkg:golang/golang.org/x/net@v0.15.0", Version: "v0.15.0", Direct: true}},
		BuildList:        plugin.BuildListGoModGraph,
		MainModule:       "example.com/app",
		WorkspaceModules: []string{"example.com/a"},
	}, nil
}

func (xnetRefutedPlugin) Reachability(context.Context, plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	return plugin.ReachabilityResult{Partiality: plugin.Complete(), Refutation: refutation("pkg:golang/golang.org/x/net")}, nil
}

// http2Source serves every advisory as CVE-2023-39325's x/net side: it names x/net and, by import
// path, x/net's http2 package. That path is x/net only by the build's module list.
type http2Source struct{}

func (http2Source) Lookup(string) (pipeline.AdvisoryFacts, bool) {
	return pipeline.AdvisoryFacts{
		Module:         "golang.org/x/net",
		PURL:           "pkg:golang/golang.org/x/net",
		UpperExclusive: "v0.17.0",
		FixedVersion:   "v0.17.0",
		Symbols:        []string{"golang.org/x/net/http2.Server.ServeConn"},
		AffectedPackages: []pipeline.AffectedPackage{{
			Module: "golang.org/x/net", PURL: "pkg:golang/golang.org/x/net", UpperExclusive: "v0.17.0", FixedVersion: "v0.17.0",
		}},
		DroppedPackages: []string{"pkg:golang/golang.org/x/net/http2"},
	}, true
}

// TestCVEWatch_GoModuleListFromStoredState: a CVE-watch re-assessment reads the build's module list
// from the stored Report's SBOM, so an advisory naming a package path of a refuted module is
// not_exploitable there exactly as on a fresh scan of the same build.
func TestCVEWatch_GoModuleListFromStoredState(t *testing.T) {
	ctx := context.Background()
	buildDir := writeGoMod(t, "module example.com/app\n\ngo 1.22\n\nrequire golang.org/x/net v0.15.0\n")
	opts := []pipeline.AssessOption{
		pipeline.WithCheckout(fixedCheckout{dir: buildDir, lang: "go"}),
		pipeline.WithPlugin(xnetRefutedPlugin{}),
		pipeline.WithAdvisorySource(http2Source{}),
	}
	const scanned, disclosed = "GHSA-xnet-0001", "GHSA-xnet-0002"

	store := &memStore{}
	base, err := RunBaseline(ctx, store, BaselineRequest{
		Subject:       Subject{Repo: "example.com/app", Revision: "main", ResolvedCommit: "base-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "example.com/app", Revision: "main"},
		Advisories:    []assessment.VulnRef{{ID: scanned, Source: "corpus"}},
		AssessOptions: opts,
		Cursor:        scanned,
	})
	if err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
	fresh := assertNotExploitable(t, base, scanned)
	for _, sbom := range []report.SBOM{store.state.Report.SBOM, store.state.SBOM} {
		if sbom.GoBuildList != plugin.BuildListGoModGraph || sbom.GoMainModule != "example.com/app" ||
			len(sbom.GoWorkspaceModules) != 1 || sbom.GoWorkspaceModules[0] != "example.com/a" {
			t.Fatalf("stored SBOM Go fields = %q %q %v, want the build list of example.com/app with example.com/a",
				sbom.GoBuildList, sbom.GoMainModule, sbom.GoWorkspaceModules)
		}
	}

	pkg := report.Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.15.0"}
	res, err := RunCVEWatch(ctx, store, &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{
		{ID: scanned, Package: pkg},
		{ID: disclosed, Package: pkg},
	}}}, CVEWatchRequest{
		Subject:       Subject{Repo: "example.com/app", Revision: "main", ResolvedCommit: "base-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "example.com/app", Revision: "main"},
		AssessOptions: opts,
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if res.Heartbeat {
		t.Fatal("want an earnest run: the disclosed advisory is not in the stored cursor")
	}
	if watched := assertNotExploitable(t, res.Report, disclosed); !reflect.DeepEqual(watched.Evidence, fresh.Evidence) {
		t.Errorf("watch evidence = %+v, want the fresh scan's %+v", watched.Evidence, fresh.Evidence)
	}
	if got := res.Report.SBOM.GoBuildList; got != plugin.BuildListGoModGraph {
		t.Errorf("re-assessed SBOM GoBuildList = %q, want it kept for the next watch", got)
	}
}

func assertNotExploitable(t *testing.T, rep *report.Report, id string) report.AdvisoryFinding {
	t.Helper()
	for _, f := range rep.Advisories {
		if f.Advisory.ID != id {
			continue
		}
		if f.Verdict != report.VerdictNotExploitable {
			t.Fatalf("%s = %s/%q (%s), want not_exploitable", id, f.Verdict, f.UndeterminedReason, f.Evidence.Detail)
		}
		return f
	}
	t.Fatalf("%s has no row", id)
	return report.AdvisoryFinding{}
}
