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
// the cgx lane resolves one it finds in the graph. With unresolved set, none does, and the result
// carries what the cgx lane declares for a symbol defined only in the dependency. A symbol in
// unreached resolves, and every op handed it (resolve, and the path ops when the request names it)
// declares what the cgx lane declares for a node no ingress reaches. Ops handed no such symbol
// declare nothing, as the lane's tree-wide ops never do.
type cfamilyGatePlugin struct {
	plugin.StubPlugin
	unresolved bool
	unreached  map[string]bool
}

// The cgx lane's loud codes, spelled here because the lane links only into the plugin
// subprocess: an advisory symbol with no definition in the graph, and a sink that is a node no
// ingress reaches.
const (
	cfamilySinkUnresolved = plugin.PartialReasonToolFailure + ":cgx_sink_unresolved"
	cfamilySinkUnreached  = plugin.PartialReasonToolFailure + ":cgx_sink_unreached"
)

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

func (p cfamilyGatePlugin) ResolveDependencySymbols(ctx context.Context, req plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	if !cfamilyanalysis.NamesSymbol(req) {
		return cfamilyanalysis.ResolveDependencySymbols(ctx, req)
	}
	if p.unresolved {
		return plugin.SymbolResolutionResult{
			Partiality: plugin.Partial(cfamilySinkUnresolved, plugin.PartialReasonNativeLinkBoundary+":uncompress"),
			Resolved:   []plugin.Symbol{},
		}, nil
	}
	res := plugin.SymbolResolutionResult{Partiality: p.symbolPartiality(req.AdvisorySymbols)}
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

func (p cfamilyGatePlugin) Reachability(_ context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	return plugin.ReachabilityResult{Partiality: p.symbolPartiality(req.Symbols)}, nil
}

func (p cfamilyGatePlugin) ComputeTaint(_ context.Context, req plugin.ComputeTaintRequest) (plugin.TaintResult, error) {
	return plugin.TaintResult{Partiality: p.symbolPartiality(req.Sinks)}, nil
}

func (p cfamilyGatePlugin) symbolPartiality(symbols []string) plugin.Partiality {
	reasons := []string{plugin.PartialReasonMacroExpansion}
	if p.unresolved {
		reasons = append(reasons, cfamilySinkUnresolved)
	}
	for _, s := range symbols {
		if p.unreached[s] {
			reasons = append(reasons, cfamilySinkUnreached)
			break
		}
	}
	return plugin.Partial(reasons...)
}

// cfamilyAdvisories serves two zlib advisories whose affected ranges contain the tree's pinned
// version (the first names symbols, the second always names deflate), and one Go module advisory
// whose range contains the go.mod's required version, all from a first-party source so trust
// cannot be what withholds a refutation.
type cfamilyAdvisories struct{ symbols []string }

const (
	cfamilyAdvisoryID       = "CVE-2022-37434"
	cfamilySecondAdvisoryID = "CVE-2018-25032"
	cfamilySecondSymbol     = "deflate"
	goAdvisoryID      = "GO-2099-0001"
	goAdvisoryModule  = "example.com/lib"
	goAdvisorySymbol  = "example.com/lib.Decode"
)

func (s cfamilyAdvisories) Lookup(id string) (pipeline.AdvisoryFacts, bool) {
	switch id {
	case cfamilyAdvisoryID:
		return pipeline.AdvisoryFacts{
			Coordinate:     "zlib",
			PURL:           "pkg:conan/zlib",
			UpperExclusive: "1.2.13",
			FixedVersion:   "1.2.13",
			AffectedRanges: []pipeline.Range{{Fixed: "1.2.13"}},
			Symbols:        s.symbols,
			Provenance:     pipeline.Provenance{Source: "test", TrustTier: pipeline.TrustFirstParty},
		}, true
	case cfamilySecondAdvisoryID:
		return pipeline.AdvisoryFacts{
			Coordinate:     "zlib",
			PURL:           "pkg:conan/zlib",
			UpperExclusive: "1.2.12",
			FixedVersion:   "1.2.12",
			AffectedRanges: []pipeline.Range{{Fixed: "1.2.12"}},
			Symbols:        []string{cfamilySecondSymbol},
			Provenance:     pipeline.Provenance{Source: "test", TrustTier: pipeline.TrustFirstParty},
		}, true
	case goAdvisoryID:
		return pipeline.AdvisoryFacts{
			Module:         goAdvisoryModule,
			PURL:           "pkg:golang/" + goAdvisoryModule,
			UpperExclusive: "v1.2.0",
			FixedVersion:   "v1.2.0",
			AffectedRanges: []pipeline.Range{{Fixed: "v1.2.0"}},
			Symbols:        []string{goAdvisorySymbol},
			Provenance:     pipeline.Provenance{Source: "test", TrustTier: pipeline.TrustFirstParty},
		}, true
	}
	return pipeline.AdvisoryFacts{}, false
}

func runCFamilyBaseline(t *testing.T, lane cfamilyGatePlugin, src pipeline.AdvisorySource, ids ...string) *report.Report {
	t.Helper()
	if len(ids) == 0 {
		ids = []string{cfamilyAdvisoryID}
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"conanfile.txt": "[requires]\nzlib/1.2.11\n",
		"go.mod":        "module example.com/c-target\n\ngo 1.22\n\nrequire " + goAdvisoryModule + " v1.0.0\n",
		"main.c":        "#include <zlib.h>\nint load(const char *p) { return p != 0; }\nint main(int c, char **v) { return load(v[0]); }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	refs := make([]assessment.VulnRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, assessment.VulnRef{ID: id, Source: "corpus"})
	}
	rep, err := buildBaselineReport(context.Background(), BaselineRequest{
		Subject:    Subject{Repo: "example.com/c-target", Revision: "main", ResolvedCommit: "deadbeef"},
		Codebase:   assessment.CodebaseRef{Repo: "example.com/c-target", Revision: "main"},
		Advisories: refs,
		AssessOptions: []pipeline.AssessOption{
			pipeline.WithCheckout(fixedCheckout{dir: dir, lang: "cfamily"}),
			pipeline.WithPlugin(lane),
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
	assertUndetermined(t, runCFamilyBaseline(t, cfamilyGatePlugin{}, cfamilyAdvisories{}), cfamilyAdvisoryID, report.ReasonAnalysisDidNotRun)
}

// A C advisory naming a symbol the graph resolves and does not reach is undetermined, never
// not_exploitable: the lane declares cgx_sink_unreached (did_not_run), because the graph can lose
// the call that reaches it (a parse error inside a body, a call through a macro alias or a
// function pointer). C/C++ does not refute on a missing path.
func TestCFamilyBaseline_NamedUnreachedSymbolIsUndetermined(t *testing.T) {
	const sink = "inflateGetHeader"
	lane := cfamilyGatePlugin{unreached: map[string]bool{sink: true}}
	assertUndetermined(t, runCFamilyBaseline(t, lane, cfamilyAdvisories{symbols: []string{sink}}), cfamilyAdvisoryID, report.ReasonAnalysisDidNotRun)
	if got := report.ClassifyPartialityReason(cfamilySinkUnreached); got != report.PartialityDidNotRun {
		t.Errorf("%s classes as %q, want %q", cfamilySinkUnreached, got, report.PartialityDidNotRun)
	}
}

// cgx_sink_unreached is scoped to the advisory whose sink it is. One scan carries a C advisory
// whose sink is resolved and unreached, a second C advisory whose sink resolves and is not flagged,
// and a Go module advisory. No row here can refute: the fake emits no positive grounds, and the
// cfamily inventory limit holds every not_exploitable in the scan. So the witness is the reason,
// not the verdict. The unreached C row is held by its own did_not_run (analysis_did_not_run); the
// other two land on vulnerable_symbol_unresolved, which a did_not_run on their own ops would
// outrank. A run-wide declaration turns all three into analysis_did_not_run, so the second and
// third rows are what fail if the code ever leaks out of the C advisory's own ops.
func TestCFamilyBaseline_SinkUnreachedScopedToItsAdvisory(t *testing.T) {
	const sink = "inflateGetHeader"
	lane := cfamilyGatePlugin{unreached: map[string]bool{sink: true}}
	rep := runCFamilyBaseline(t, lane, cfamilyAdvisories{symbols: []string{sink}}, cfamilyAdvisoryID, cfamilySecondAdvisoryID, goAdvisoryID)
	assertUndetermined(t, rep, cfamilyAdvisoryID, report.ReasonAnalysisDidNotRun)
	assertUndetermined(t, rep, cfamilySecondAdvisoryID, report.ReasonVulnerableSymbolUnresolved)
	assertUndetermined(t, rep, goAdvisoryID, report.ReasonVulnerableSymbolUnresolved)
}

// A tree that reaches the vulnerable code only through the dependency (it calls uncompress, which
// calls inflate inside zlib) while the advisory names inflate_fast and inflate: neither is defined
// in the tree, so the lane resolves nothing and declares it loud, and the verdict is undetermined,
// never not_exploitable, though the graph has edges and no path was found.
func TestCFamilyBaseline_UnresolvedThroughDependencyIsUndetermined(t *testing.T) {
	rep := runCFamilyBaseline(t, cfamilyGatePlugin{unresolved: true}, cfamilyAdvisories{symbols: []string{"inflate_fast", "inflate"}})
	assertUndetermined(t, rep, cfamilyAdvisoryID, report.ReasonAnalysisDidNotRun)
}
