package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// targetConditionalFixture is a Newtonsoft.Json build whose target compiles no async entry and no
// XNode entry: both resolve to nothing in a package the lane read in full, and the advisory
// declares both conditional. Push resolved in the package and was searched.
type targetConditionalFixture struct {
	symbols, conditional []string
	res                  plugin.SymbolResolutionResult
	searched             []string
	flags                []string
}

const (
	tcPush     = "Newtonsoft.Json.JsonReader.Push"
	tcAsync    = "Newtonsoft.Json.JsonTextReader.ReadAsync"
	tcXNode    = "Newtonsoft.Json.JsonConvert.DeserializeXNode"
	tcPushSCIP = "dotnet Newtonsoft.Json JsonReader#Push(int)"
	tcXNodeSym = "dotnet Newtonsoft.Json JsonConvert#DeserializeXNode(string)"
	tcPURL     = "pkg:nuget/newtonsoft.json"
)

func newTargetConditionalFixture() targetConditionalFixture {
	return targetConditionalFixture{
		symbols:     []string{tcPush, tcAsync, tcXNode},
		conditional: []string{tcAsync, tcXNode},
		res: plugin.SymbolResolutionResult{
			Partiality: plugin.Partial(plugin.PartialReasonAdvisorySymbolUnresolved),
			Resolved:   []plugin.Symbol{{SCIP: tcPushSCIP}},
			Origins:    map[string]string{tcPushSCIP: tcPURL},
			Matched:    map[string][]string{tcPush: {tcPushSCIP}},
		},
		searched: []string{tcPushSCIP},
		flags:    []string{plugin.PartialReasonAdvisorySymbolUnresolved},
	}
}

func (fx targetConditionalFixture) finding(t *testing.T) report.AdvisoryFinding {
	t.Helper()
	store := artifact.NewMemStore()
	const aid = "newtonsoft-net20"
	putJSON(t, store, aid, artifact.TypeNormalizedAdvisory, map[string]any{
		"coordinate":                 "Newtonsoft.Json",
		"purl":                       "pkg:nuget/Newtonsoft.Json",
		"advisory_symbols":           fx.symbols,
		"target_conditional_symbols": fx.conditional,
		"symbol_provenance":          "osv-declared",
	})
	putJSON(t, store, aid, artifact.TypeVulnerableSymbol, fx.res)
	seedFootprint(t, store, aid, fx.flags)
	seedReachArtifact(t, store, aid,
		plugin.CallGraphResult{
			Partiality: plugin.Complete(),
			Edges:      []plugin.CallEdge{depEdge("dotnet App Program#Main()", "dotnet App Program#Run()")},
		},
		plugin.ReachabilityResult{Partiality: plugin.Complete(), Searched: fx.searched})
	pkg := &report.Package{Ecosystem: "NuGet", Name: "Newtonsoft.Json", Version: "12.0.3", PURL: "pkg:nuget/Newtonsoft.Json@12.0.3"}
	return finding(store, aid, report.Advisory{ID: "CVE-2024-21907", Source: "corpus"}, pkg)
}

// TestFinding_TargetConditionalSymbols grounds not_exploitable on a target that does not define an
// advisory symbol only when the advisory declares that symbol conditional and the lane read the
// package in full; every other absence still withholds.
func TestFinding_TargetConditionalSymbols(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*targetConditionalFixture)
		detail string // "" = undetermined, for reason
		reason string
	}{
		{"conditional symbols absent from a fully read package", func(*targetConditionalFixture) {},
			"no path from any entry point reaches Newtonsoft.Json.JsonReader.Push in Newtonsoft.Json@12.0.3, " +
				"whose build target does not define Newtonsoft.Json.JsonTextReader.ReadAsync, Newtonsoft.Json.JsonConvert.DeserializeXNode", ""},
		{"every symbol resolved and searched", func(fx *targetConditionalFixture) {
			fx.symbols, fx.flags = []string{tcPush}, nil
			fx.res.Partiality = plugin.Complete()
		}, "no path from any entry point reaches Newtonsoft.Json.JsonReader.Push in Newtonsoft.Json@12.0.3", ""},
		{"a conditional symbol that resolved is searched", func(fx *targetConditionalFixture) {
			fx.res.Matched[tcXNode] = []string{tcXNodeSym}
			fx.res.Origins[tcXNodeSym] = tcPURL
			fx.searched = append(fx.searched, tcXNodeSym)
		}, "no path from any entry point reaches Newtonsoft.Json.JsonReader.Push, Newtonsoft.Json.JsonConvert.DeserializeXNode in Newtonsoft.Json@12.0.3, " +
			"whose build target does not define Newtonsoft.Json.JsonTextReader.ReadAsync", ""},

		{"no symbol declared conditional", func(fx *targetConditionalFixture) { fx.conditional = nil }, "", report.ReasonAnalysisDidNotRun},
		{"an absent symbol not declared conditional", func(fx *targetConditionalFixture) { fx.conditional = []string{tcXNode} }, "", report.ReasonAnalysisDidNotRun},
		{"the package was not read in full", func(fx *targetConditionalFixture) {
			fx.res.Partiality.Reasons = append(fx.res.Partiality.Reasons, plugin.PartialReasonToolFailure+":no_dependency_artifact")
		}, "", report.ReasonAnalysisDidNotRun},
		{"a symbol is ambiguous", func(fx *targetConditionalFixture) {
			fx.res.Partiality.Reasons = append(fx.res.Partiality.Reasons, "advisory_symbol_ambiguous")
		}, "", report.ReasonAnalysisDidNotRun},
		{"the resolution carries a scoped limit", func(fx *targetConditionalFixture) {
			fx.res.Partiality.Scoped = []plugin.ScopedReason{{Reason: plugin.PartialReasonAdvisorySymbolUnresolved, Package: tcPURL, Targets: []string{tcPURL}}}
		}, "", report.ReasonAnalysisDidNotRun},
		{"no symbol resolved", func(fx *targetConditionalFixture) {
			fx.conditional = fx.symbols
			fx.res.Matched, fx.res.Resolved, fx.res.Origins, fx.searched = nil, nil, nil, nil
		}, "", report.ReasonAnalysisDidNotRun},
		{"a complete resolution leaves a conditional symbol unmatched", func(fx *targetConditionalFixture) {
			fx.res.Partiality, fx.flags = plugin.Complete(), nil
		}, "", report.ReasonVulnerableSymbolUnresolved},
		{"the resolved symbol was not searched", func(fx *targetConditionalFixture) { fx.searched = nil }, "", report.ReasonVulnerableSymbolUnresolved},
		{"a conditional symbol resolved outside the package", func(fx *targetConditionalFixture) {
			fx.res.Matched[tcXNode] = []string{tcXNodeSym}
			fx.res.Origins[tcXNodeSym] = "pkg:nuget/other"
			fx.searched = append(fx.searched, tcXNodeSym)
		}, "", report.ReasonVulnerableSymbolUnresolved},
		{"a conditional symbol that resolved is not searched", func(fx *targetConditionalFixture) {
			fx.res.Matched[tcXNode] = []string{tcXNodeSym}
			fx.res.Origins[tcXNodeSym] = tcPURL
		}, "", report.ReasonVulnerableSymbolUnresolved},
		{"another step did not run", func(fx *targetConditionalFixture) {
			fx.flags = append(fx.flags, plugin.PartialReasonToolFailure)
		}, "", report.ReasonAnalysisDidNotRun},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newTargetConditionalFixture()
			tt.mutate(&fx)
			f := fx.finding(t)
			if tt.detail == "" {
				if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != tt.reason {
					t.Fatalf("verdict = %q reason %q (%s), want undetermined for %q", f.Verdict, f.UndeterminedReason, f.Evidence.Detail, tt.reason)
				}
				return
			}
			if f.Verdict != report.VerdictNotExploitable || f.Evidence.Basis != verdict.BasisSymbolUnreachable {
				t.Fatalf("verdict = %q basis %q (reason %q), want not_exploitable on %q",
					f.Verdict, f.Evidence.Basis, f.UndeterminedReason, verdict.BasisSymbolUnreachable)
			}
			if f.Evidence.Detail != tt.detail {
				t.Errorf("detail = %q\nwant     %q", f.Evidence.Detail, tt.detail)
			}
		})
	}
}
