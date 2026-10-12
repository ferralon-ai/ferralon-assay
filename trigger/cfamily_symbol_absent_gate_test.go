package trigger

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/cfamilyanalysis"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// cfamilyGatePlugin is the C/C++ lane as the pipeline sees it. The manifest, version and
// symbol-absent paths are the real cfamilyanalysis ones; the graph ops stand in for the cgx lane
// (which links only into the plugin subprocess) with the shape it returns for a searched C tree:
// edges present, quiet residue only, no path to the advisory's code. A named symbol resolves, as
// the cgx lane resolves one it finds in the graph.
type cfamilyGatePlugin struct{ plugin.StubPlugin }

func (cfamilyGatePlugin) Language() string { return "cfamily" }

func (cfamilyGatePlugin) BuildManifest(ctx context.Context, req plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	return cfamilyanalysis.BuildManifest(ctx, req)
}

func (cfamilyGatePlugin) ResolveDependencyVersions(ctx context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	return cfamilyanalysis.ResolveDependencyVersions(ctx, req)
}

func (cfamilyGatePlugin) ResolveInventory(ctx context.Context, req plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	return cfamilyanalysis.ResolveInventory(ctx, req)
}

func (cfamilyGatePlugin) ResolveDependencySymbols(ctx context.Context, req plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	if !cfamilyanalysis.NamesSymbol(req) {
		return cfamilyanalysis.ResolveDependencySymbols(ctx, req)
	}
	res := plugin.SymbolResolutionResult{Partiality: plugin.Partial(plugin.PartialReasonMacroExpansion)}
	for _, s := range req.AdvisorySymbols {
		res.Resolved = append(res.Resolved, plugin.Symbol{SCIP: s})
	}
	return res, nil
}

func (cfamilyGatePlugin) IndexSymbols(context.Context, plugin.IndexSymbolsRequest) (plugin.SymbolIndexResult, error) {
	return plugin.SymbolIndexResult{Partiality: plugin.Partial(plugin.PartialReasonMacroExpansion)}, nil
}

func (cfamilyGatePlugin) CallGraph(context.Context, plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return plugin.CallGraphResult{
		Algorithm:  "cgx-tree-sitter",
		Partiality: plugin.Partial(plugin.PartialReasonMacroExpansion),
		Edges:      []plugin.CallEdge{{Caller: plugin.Symbol{SCIP: "main"}, Callee: plugin.Symbol{SCIP: "load"}}},
	}, nil
}

func (cfamilyGatePlugin) FindIngresses(context.Context, plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	return plugin.IngressResult{
		Partiality: plugin.Partial(plugin.PartialReasonMacroExpansion),
		Ingresses:  []plugin.Ingress{{Kind: "main", Symbol: plugin.Symbol{SCIP: "main"}}},
	}, nil
}

func (cfamilyGatePlugin) Reachability(context.Context, plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	return plugin.ReachabilityResult{Partiality: plugin.Partial(plugin.PartialReasonMacroExpansion)}, nil
}

func (cfamilyGatePlugin) ComputeTaint(context.Context, plugin.ComputeTaintRequest) (plugin.TaintResult, error) {
	return plugin.TaintResult{Partiality: plugin.Partial(plugin.PartialReasonMacroExpansion)}, nil
}

// cfamilyAdvisories serves one zlib advisory whose affected range contains the tree's pinned
// version, from a first-party source so trust cannot be what withholds the refutation.
type cfamilyAdvisories struct{ symbols []string }

const cfamilyAdvisoryID = "CVE-2022-37434"

func (s cfamilyAdvisories) Lookup(id string) (pipeline.AdvisoryFacts, bool) {
	if id != cfamilyAdvisoryID {
		return pipeline.AdvisoryFacts{}, false
	}
	return pipeline.AdvisoryFacts{
		Coordinate:     "zlib",
		PURL:           "pkg:conan/zlib",
		UpperExclusive: "1.2.13",
		FixedVersion:   "1.2.13",
		AffectedRanges: []pipeline.Range{{Fixed: "1.2.13"}},
		Symbols:        s.symbols,
		Provenance:     pipeline.Provenance{Source: "test", TrustTier: pipeline.TrustFirstParty},
	}, true
}

func runCFamilyBaseline(t *testing.T, src pipeline.AdvisorySource) *report.Report {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"conanfile.txt": "[requires]\nzlib/1.2.11\n",
		"main.c":        "#include <zlib.h>\nint load(const char *p) { return p != 0; }\nint main(int c, char **v) { return load(v[0]); }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := buildBaselineReport(context.Background(), BaselineRequest{
		Subject:    Subject{Repo: "example.com/c-target", Revision: "main", ResolvedCommit: "deadbeef"},
		Codebase:   assessment.CodebaseRef{Repo: "example.com/c-target", Revision: "main"},
		Advisories: []assessment.VulnRef{{ID: cfamilyAdvisoryID, Source: "corpus"}},
		AssessOptions: []pipeline.AssessOption{
			pipeline.WithCheckout(fixedCheckout{dir: dir, lang: "cfamily"}),
			pipeline.WithPlugin(cfamilyGatePlugin{}),
			pipeline.WithAdvisorySource(src),
		},
	})
	if err != nil {
		t.Fatalf("buildBaselineReport: %v", err)
	}
	return rep
}

func cfamilyRow(t *testing.T, rep *report.Report) report.AdvisoryFinding {
	t.Helper()
	for _, f := range rep.Advisories {
		if f.Advisory.ID == cfamilyAdvisoryID {
			return f
		}
	}
	t.Fatalf("report has no row for %s: %+v", cfamilyAdvisoryID, rep.Advisories)
	return report.AdvisoryFinding{}
}

// A C advisory whose range contains the pinned version and which names no vulnerable symbol has
// nothing to search the graph for. The lane declares advisory_symbol_absent, and the verdict is
// undetermined, never not_exploitable, even though the graph has edges and no path was found.
func TestCFamilyBaseline_SymbolAbsentAdvisoryIsUndetermined(t *testing.T) {
	assertUndetermined(t, runCFamilyBaseline(t, cfamilyAdvisories{}), cfamilyAdvisoryID, report.ReasonAnalysisDidNotRun)
}

// The control: the same advisory naming a symbol the graph resolves and does not reach is
// refuted, so the test above is detecting the symbol-absent gate and not some other hold.
func TestCFamilyBaseline_NamedUnreachedSymbolRefutes(t *testing.T) {
	f := cfamilyRow(t, runCFamilyBaseline(t, cfamilyAdvisories{symbols: []string{"inflateGetHeader"}}))
	if f.Verdict != report.VerdictNotExploitable {
		t.Errorf("verdict = %q (undetermined_reason %q), want %q", f.Verdict, f.UndeterminedReason, report.VerdictNotExploitable)
	}
}
