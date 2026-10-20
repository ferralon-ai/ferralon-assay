package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

const (
	spSym  = "Newtonsoft.Json.JsonReader.Push"
	spSCIP = "dotnet Newtonsoft.Json JsonReader#Push(int)"
	spPURL = "pkg:nuget/newtonsoft.json"
)

// symbolProvenanceFinding assesses a corpus-shaped advisory on an admitted, resolved Newtonsoft.Json
// whose one listed symbol resolved inside the package, was searched, and was not reached. Only the
// record's symbol_provenance, trust tier and the lane's refutation vary.
func symbolProvenanceFinding(t *testing.T, provenance, trust string, refutation *plugin.Refutation) report.AdvisoryFinding {
	t.Helper()
	store := artifact.NewMemStore()
	const aid = "symbol-provenance"
	adv := map[string]any{
		"coordinate":       "Newtonsoft.Json",
		"purl":             "pkg:nuget/Newtonsoft.Json",
		"advisory_symbols": []string{spSym},
	}
	if provenance != "" {
		adv["symbol_provenance"] = provenance
	}
	if trust != "" {
		adv["trust_tier"] = trust
	}
	putJSON(t, store, aid, artifact.TypeNormalizedAdvisory, adv)
	putJSON(t, store, aid, artifact.TypeVulnerableSymbol, plugin.SymbolResolutionResult{
		Partiality: plugin.Complete(),
		Resolved:   []plugin.Symbol{{SCIP: spSCIP}},
		Origins:    map[string]string{spSCIP: spPURL},
		Matched:    map[string][]string{spSym: {spSCIP}},
	})
	seedFootprint(t, store, aid, nil)
	seedReachArtifact(t, store, aid,
		plugin.CallGraphResult{
			Partiality: plugin.Complete(),
			Edges:      []plugin.CallEdge{depEdge("dotnet App Program#Main()", "dotnet App Program#Run()")},
		},
		plugin.ReachabilityResult{Partiality: plugin.Complete(), Searched: []string{spSCIP}, Refutation: refutation})
	pkg := &report.Package{Ecosystem: "NuGet", Name: "Newtonsoft.Json", Version: "12.0.3", PURL: "pkg:nuget/Newtonsoft.Json@12.0.3"}
	return finding(store, aid, report.Advisory{ID: "CVE-2024-21907", Source: "corpus"}, pkg)
}

// TestFinding_SymbolProvenanceGate grounds not_exploitable on "no listed symbol reached" only when the
// symbol set is vetted: declared by OSV, curated, or an untagged set in a first-party record. Any other
// set is withheld as advisory_symbols_unvetted, and a lane refutation that does not rest on the listed
// symbols still grounds.
func TestFinding_SymbolProvenanceGate(t *testing.T) {
	const searched = "no path from any entry point reaches " + spSym + " in Newtonsoft.Json@12.0.3"
	analyzer := &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: spPURL, Detail: "the analyzer traced no call"}
	notLoaded := &plugin.Refutation{Basis: plugin.RefutationPackageNotLoaded, Package: spPURL, Detail: "no loaded module imports it"}
	tests := []struct {
		name       string
		provenance string
		trust      string
		refutation *plugin.Refutation
		detail     string // "" = undetermined, for reason
		reason     string
	}{
		{"osv-declared", "osv-declared", "", nil, searched, ""},
		{"curated", "curated", "", nil, searched, ""},
		{"untagged first-party record", "", string(pipeline.TrustFirstParty), nil, searched, ""},

		{"diff-lexed", "diff-lexed", "", nil, "", report.ReasonAdvisorySymbolsUnvetted},
		{"no provenance", "", "", nil, "", report.ReasonAdvisorySymbolsUnvetted},
		{"cna-declared", "cna-declared", "", nil, "", report.ReasonAdvisorySymbolsUnvetted},
		{"unknown provenance", "reasoning", "", nil, "", report.ReasonAdvisorySymbolsUnvetted},
		{"diff-lexed in a first-party record", "diff-lexed", string(pipeline.TrustFirstParty), nil, "", report.ReasonAdvisorySymbolsUnvetted},
		{"untagged third-party record", "", "third_party", nil, "", report.ReasonAdvisorySymbolsUnvetted},

		{"diff-lexed refuted by the analyzer", "diff-lexed", "", analyzer,
			"Newtonsoft.Json@12.0.3: the analyzer traced no call (analyzer_symbol_not_reached)", ""},
		{"diff-lexed with package_not_loaded on a record not listing every package", "diff-lexed", "", notLoaded,
			"", report.ReasonAdvisorySymbolsUnvetted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := symbolProvenanceFinding(t, tt.provenance, tt.trust, tt.refutation)
			if tt.detail == "" {
				if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != tt.reason {
					t.Fatalf("verdict = %q reason %q (%s), want undetermined for %q", f.Verdict, f.UndeterminedReason, f.Evidence.Detail, tt.reason)
				}
				if f.Evidence.Detail != report.UndeterminedDetail(tt.reason) {
					t.Errorf("detail = %q, want the %s detail", f.Evidence.Detail, tt.reason)
				}
				return
			}
			if f.Verdict != report.VerdictNotExploitable || f.Evidence.Basis != verdict.BasisSymbolAbsent {
				t.Fatalf("verdict = %q basis %q (reason %q), want not_exploitable on %q",
					f.Verdict, f.Evidence.Basis, f.UndeterminedReason, verdict.BasisSymbolAbsent)
			}
			if f.Evidence.Detail != tt.detail {
				t.Errorf("detail = %q\nwant     %q", f.Evidence.Detail, tt.detail)
			}
		})
	}
}
