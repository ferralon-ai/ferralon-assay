package trigger

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/cfamilyanalysis"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/projection"
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
	goAdvisoryID            = "GO-2099-0001"
	goAdvisoryModule        = "example.com/lib"
	goAdvisorySymbol        = "example.com/lib.Decode"
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
	return runCFamilyBaselineTree(t, lane, src, map[string]string{"conanfile.txt": "[requires]\nzlib/1.2.11\n"}, ids...)
}

// runCFamilyBaselineTree scans a C tree whose dependency manifests are manifests.
func runCFamilyBaselineTree(t *testing.T, lane cfamilyGatePlugin, src pipeline.AdvisorySource, manifests map[string]string, ids ...string) *report.Report {
	t.Helper()
	if len(ids) == 0 {
		ids = []string{cfamilyAdvisoryID}
	}
	refs := make([]assessment.VulnRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, assessment.VulnRef{ID: id, Source: "corpus"})
	}
	rep, err := buildBaselineReport(context.Background(), BaselineRequest{
		Subject:       Subject{Repo: "example.com/c-target", Revision: "main", ResolvedCommit: "deadbeef"},
		Codebase:      cfamilyCodebase,
		Advisories:    refs,
		AssessOptions: cfamilyAssessOptions(t, lane, src, manifests),
	})
	if err != nil {
		t.Fatalf("buildBaselineReport: %v", err)
	}
	return rep
}

var cfamilyCodebase = assessment.CodebaseRef{Repo: "example.com/c-target", Revision: "main"}

// cfamilyAssessOptions writes the C tree with manifests into a temp dir and returns the options
// that assess it through lane against src.
func cfamilyAssessOptions(t *testing.T, lane cfamilyGatePlugin, src pipeline.AdvisorySource, manifests map[string]string) []pipeline.AssessOption {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/c-target\n\ngo 1.22\n\nrequire " + goAdvisoryModule + " v1.0.0\n",
		"main.c": "#include <zlib.h>\nint load(const char *p) { return p != 0; }\nint main(int c, char **v) { return load(v[0]); }\n",
	}
	for name, body := range manifests {
		files[name] = body
	}
	for name, body := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return []pipeline.AssessOption{
		pipeline.WithCheckout(fixedCheckout{dir: dir, lang: "cfamily"}),
		pipeline.WithPlugin(lane),
		pipeline.WithAdvisorySource(src),
	}
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
// and a Go module advisory. No row here can refute: the fake emits no positive grounds. So the
// witness is the reason, not the verdict. Both C rows are held by a did_not_run
// (analysis_did_not_run): the first by its own cgx_sink_unreached, the second by its unresolved
// version (sole_source_unproven). The Go row lands on vulnerable_symbol_unresolved, which a
// did_not_run on its own ops would outrank, so it is the row that fails if the code ever leaks out
// of the C advisory's own ops into a run-wide declaration. The second C advisory shares the first's
// package, so its verdict cannot see a leak keyed on that package; its own assessment's footprint
// is the witness for it, read per assessment because report-level notes are scan-wide.
func TestCFamilyBaseline_SinkUnreachedScopedToItsAdvisory(t *testing.T) {
	const sink = "inflateGetHeader"
	lane := cfamilyGatePlugin{unreached: map[string]bool{sink: true}}
	src := cfamilyAdvisories{symbols: []string{sink}}
	rep := runCFamilyBaseline(t, lane, src, cfamilyAdvisoryID, cfamilySecondAdvisoryID, goAdvisoryID)
	assertUndetermined(t, rep, cfamilyAdvisoryID, report.ReasonAnalysisDidNotRun)
	assertUndetermined(t, rep, cfamilySecondAdvisoryID, report.ReasonAnalysisDidNotRun)
	assertUndetermined(t, rep, goAdvisoryID, report.ReasonVulnerableSymbolUnresolved)

	opts := cfamilyAssessOptions(t, lane, src, map[string]string{"conanfile.txt": "[requires]\nzlib/1.2.11\n"})
	for _, tc := range []struct {
		id        string
		unreached bool
	}{
		{cfamilyAdvisoryID, true},
		{cfamilySecondAdvisoryID, false},
	} {
		st, aid, err := assess(context.Background(), assessment.Request{
			Vulnerability: assessment.VulnRef{ID: tc.id, Source: "corpus"},
			Codebase:      cfamilyCodebase,
		}, opts...)
		if err != nil {
			t.Fatalf("assess %s: %v", tc.id, err)
		}
		flags := footprintPartialityFlags(st, aid)
		if got := slices.Contains(flags, cfamilySinkUnreached); got != tc.unreached {
			t.Errorf("%s footprint %v: carries %s = %v, want %v", tc.id, flags, cfamilySinkUnreached, got, tc.unreached)
		}
	}
}

// A tree that reaches the vulnerable code only through the dependency (it calls uncompress, which
// calls inflate inside zlib) while the advisory names inflate_fast and inflate: neither is defined
// in the tree, so the lane resolves nothing and declares it loud, and the verdict is undetermined,
// never not_exploitable, though the graph has edges and no path was found.
func TestCFamilyBaseline_UnresolvedThroughDependencyIsUndetermined(t *testing.T) {
	rep := runCFamilyBaseline(t, cfamilyGatePlugin{unresolved: true}, cfamilyAdvisories{symbols: []string{"inflate_fast", "inflate"}})
	assertUndetermined(t, rep, cfamilyAdvisoryID, report.ReasonAnalysisDidNotRun)
}

// A conan.lock that pins the host graph makes the C/C++ inventory Complete, so the scan carries no
// cfamily inventory limit. No C/C++ row refutes: each lane shape the tests above use lands
// undetermined, on the lane's own declaration.
func TestCFamilyBaseline_LockedInventoryAddsNoRefutation(t *testing.T) {
	const sink = "inflateGetHeader"
	lock := map[string]string{
		"conan.lock":    `{"version":"0.5","requires":["zlib/1.2.11#cac0f6daea041b0ccf42934163defb20%1765284699.337"],"build_requires":[],"python_requires":[]}`,
		"conanfile.txt": "[requires]\nzlib/1.2.11\n",
	}
	for _, tc := range []struct {
		name string
		lane cfamilyGatePlugin
		src  cfamilyAdvisories
	}{
		{"symbol absent", cfamilyGatePlugin{}, cfamilyAdvisories{}},
		{"named and unreached", cfamilyGatePlugin{unreached: map[string]bool{sink: true}}, cfamilyAdvisories{symbols: []string{sink}}},
		{"unresolved through the dependency", cfamilyGatePlugin{unresolved: true}, cfamilyAdvisories{symbols: []string{"inflate_fast", "inflate"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := runCFamilyBaselineTree(t, tc.lane, tc.src, lock, cfamilyAdvisoryID)
			for _, n := range inventoryLimits(rep.Partiality) {
				if n.Ecosystem == "cfamily" {
					t.Errorf("scan still carries a cfamily inventory limit: %+v", n)
				}
			}
			assertUndetermined(t, rep, cfamilyAdvisoryID, report.ReasonAnalysisDidNotRun)
		})
	}
}

// libfooAdvisories serves one first-party advisory against libfoo, fixed at fixed.
type libfooAdvisories struct{ fixed string }

func (s libfooAdvisories) Lookup(id string) (pipeline.AdvisoryFacts, bool) {
	if id != cfamilyAdvisoryID {
		return pipeline.AdvisoryFacts{}, false
	}
	return pipeline.AdvisoryFacts{
		Coordinate:     "libfoo",
		PURL:           "pkg:conan/libfoo",
		UpperExclusive: s.fixed,
		FixedVersion:   s.fixed,
		AffectedRanges: []pipeline.Range{{Fixed: s.fixed}},
		Provenance:     pipeline.Provenance{Source: "test", TrustTier: pipeline.TrustFirstParty},
	}, true
}

// A package manager's pin outside the advisory's range does not disqualify a C/C++ advisory: the
// tree also vendors an affected copy of the library, and no manifest records which copy is linked.
// The row is undetermined. It names the package with the pin as an inventory observation
// (source_unpinned), never as a resolved version, and the pin stays in the SBOM. The rows run with
// and without a v prefix: the version comparison accepts only semver, so a plain C version never
// compares, and the v-prefixed rows are the ones that disqualify if a C/C++ version ever resolves.
// The plain row is held by the package's PartialReason, which a resolved version would not carry.
func TestCFamilyBaseline_PinOutsideRangeBesideVendoredCopyIsUndetermined(t *testing.T) {
	const vendored = "#define FOO_VERSION \"1.0.0\"\nint foo_parse(const char *p) { return p != 0; }\n"
	vcpkgStatus := func(v string) string {
		return "Package: libfoo\nVersion: " + v + "\nArchitecture: x64-linux\nStatus: install ok installed\n"
	}
	for _, tc := range []struct {
		name, fixed, pin string
		manifests        map[string]string
	}{
		{"vcpkg status, v-prefixed", "v1.1.0", "v2.0.0", map[string]string{
			"vcpkg_installed/vcpkg/status": vcpkgStatus("v2.0.0"),
		}},
		{"vcpkg status, plain", "1.1.0", "2.0.0", map[string]string{
			"vcpkg_installed/vcpkg/status": vcpkgStatus("2.0.0"),
		}},
		{"conan.lock, v-prefixed", "v1.1.0", "v2.0.0", map[string]string{
			"conan.lock": `{"version":"0.5","requires":["libfoo/v2.0.0"]}`,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.manifests["third_party/libfoo/foo.c"] = vendored
			rep := runCFamilyBaselineTree(t, cfamilyGatePlugin{}, libfooAdvisories{fixed: tc.fixed}, tc.manifests, cfamilyAdvisoryID)
			assertUndetermined(t, rep, cfamilyAdvisoryID, report.ReasonAnalysisDidNotRun)
			want := report.Package{
				Ecosystem:     "cfamily",
				Name:          "libfoo",
				Version:       tc.pin,
				PURL:          "pkg:conan/libfoo",
				PartialReason: cfamilySoleSourceUnproven,
			}
			if f := cfamilyRow(t, rep); f.Package == nil || *f.Package != want {
				t.Errorf("row package = %+v, want the inventory observation %+v", f.Package, want)
			}
			var inSBOM bool
			for _, p := range rep.SBOM.Packages {
				if p.Name == "libfoo" && p.Version == tc.pin {
					inSBOM = true
				}
			}
			if !inSBOM {
				t.Errorf("SBOM %+v does not carry libfoo at %s", rep.SBOM.Packages, tc.pin)
			}
		})
	}
}

// cfamilySoleSourceUnproven is the code the C/C++ lane declares on every pin, spelled here because
// cfamilyanalysis keeps it unexported.
const cfamilySoleSourceUnproven = plugin.PartialReasonSourceUnpinned + ":sole_source_unproven"

// A C/C++ row names its package in the VEX product ID and in the rendered HTML and SARIF text, and
// shows the pin only as an inventory observation. The product ID is the advisory's versionless PURL,
// the ID every lane emits for a package; it carries no version, so it cannot present the pin as
// resolved.
func TestCFamilyBaseline_RowNamesPackageWithPinAsObservation(t *testing.T) {
	lock := map[string]string{
		"conan.lock":    `{"version":"0.5","requires":["zlib/1.2.11#cac0f6daea041b0ccf42934163defb20%1765284699.337"],"build_requires":[],"python_requires":[]}`,
		"conanfile.txt": "[requires]\nzlib/1.2.11\n",
	}
	rep := runCFamilyBaselineTree(t, cfamilyGatePlugin{}, cfamilyAdvisories{}, lock, cfamilyAdvisoryID)
	assertUndetermined(t, rep, cfamilyAdvisoryID, report.ReasonAnalysisDidNotRun)
	const label = "cfamily:zlib (pinned 1.2.11, not resolved)"

	vex, err := projection.ProjectReportVEX(*rep)
	if err != nil {
		t.Fatalf("ProjectReportVEX: %v", err)
	}
	if got := vex.Statements[0].Products[0].ID; got != "pkg:conan/zlib" {
		t.Errorf("VEX product ID = %q, want the advisory PURL pkg:conan/zlib", got)
	}

	sarif, err := projection.ProjectReportSARIF(*rep)
	if err != nil {
		t.Fatalf("ProjectReportSARIF: %v", err)
	}
	if got := sarif.Runs[0].Results[0].Properties.Scanner["package"]; got != label {
		t.Errorf("SARIF package = %v, want %q", got, label)
	}

	html, err := projection.ProjectReportHTML(*rep)
	if err != nil {
		t.Fatalf("ProjectReportHTML: %v", err)
	}
	if !strings.Contains(string(html), label) {
		t.Errorf("HTML report does not name %q", label)
	}
	if strings.Contains(string(html), "cfamily:zlib@") {
		t.Error("HTML report row presents the pin as a resolved version")
	}
}
