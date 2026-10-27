package trigger

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
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

// spRecord is what varies between rows: the record's symbol provenance, whether S1 marked it as
// answered by the built-in table, the trust tier the record declares about itself, whether it lists
// its affected packages, and the lane's refutation.
type spRecord struct {
	provenance string
	builtIn    bool
	trust      string
	affected   bool
	refutation *plugin.Refutation
}

// symbolProvenanceFinding assesses an advisory on an admitted, resolved Newtonsoft.Json whose one
// listed symbol resolved inside the package, was searched, and was not reached.
func symbolProvenanceFinding(t *testing.T, r spRecord) report.AdvisoryFinding {
	t.Helper()
	store := artifact.NewMemStore()
	const aid = "symbol-provenance"
	adv := map[string]any{
		"coordinate":       "Newtonsoft.Json",
		"purl":             "pkg:nuget/Newtonsoft.Json",
		"advisory_symbols": []string{spSym},
	}
	if r.provenance != "" {
		adv["symbol_provenance"] = r.provenance
	}
	if r.builtIn {
		adv["built_in"] = true
	}
	if r.trust != "" {
		adv["trust_tier"] = r.trust
	}
	if r.affected {
		adv["affected_packages"] = []map[string]string{{"purl": spPURL}}
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
		plugin.ReachabilityResult{Partiality: plugin.Complete(), Searched: []string{spSCIP}, Refutation: r.refutation})
	pkg := &report.Package{Ecosystem: "NuGet", Name: "Newtonsoft.Json", Version: "12.0.3", PURL: "pkg:nuget/Newtonsoft.Json@12.0.3"}
	return finding(store, aid, report.Advisory{ID: "CVE-2024-21907", Source: "corpus"}, pkg)
}

// TestFinding_SymbolProvenanceGate grounds not_exploitable on "no listed symbol reached" only when the
// symbol set is vetted: declared by OSV, curated, or an untagged set the built-in table answered. Any
// other set is withheld as advisory_symbols_unvetted, whatever trust tier the record declares, and a
// lane refutation that does not rest on the listed symbols still grounds.
func TestFinding_SymbolProvenanceGate(t *testing.T) {
	const searched = "no path from any entry point reaches " + spSym + " in Newtonsoft.Json@12.0.3"
	analyzer := &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: spPURL, Detail: "the analyzer traced no call"}
	notLoaded := &plugin.Refutation{Basis: plugin.RefutationPackageNotLoaded, Package: spPURL, Detail: "no loaded module imports it"}
	firstParty := string(pipeline.TrustFirstParty)
	tests := []struct {
		name   string
		record spRecord
		detail string // "" = undetermined, for reason
		reason string
	}{
		{"osv-declared", spRecord{provenance: "osv-declared"}, searched, ""},
		{"curated", spRecord{provenance: "curated"}, searched, ""},
		{"untagged built-in record", spRecord{builtIn: true, trust: firstParty}, searched, ""},

		{"diff-lexed", spRecord{provenance: "diff-lexed"}, "", report.ReasonAdvisorySymbolsUnvetted},
		{"no provenance", spRecord{}, "", report.ReasonAdvisorySymbolsUnvetted},
		{"cna-declared", spRecord{provenance: "cna-declared"}, "", report.ReasonAdvisorySymbolsUnvetted},
		{"unknown provenance", spRecord{provenance: "reasoning"}, "", report.ReasonAdvisorySymbolsUnvetted},
		{"diff-lexed in a built-in record", spRecord{provenance: "diff-lexed", builtIn: true, trust: firstParty},
			"", report.ReasonAdvisorySymbolsUnvetted},
		{"untagged corpus record declaring trust_tier first_party", spRecord{trust: firstParty},
			"", report.ReasonAdvisorySymbolsUnvetted},
		{"untagged third-party record", spRecord{trust: "third_party"}, "", report.ReasonAdvisorySymbolsUnvetted},

		{"diff-lexed refuted by the analyzer", spRecord{provenance: "diff-lexed", refutation: analyzer},
			"Newtonsoft.Json@12.0.3: the analyzer traced no call (analyzer_symbol_not_reached)", ""},
		{"diff-lexed with package_not_loaded on a record listing every package",
			spRecord{provenance: "diff-lexed", affected: true, refutation: notLoaded},
			"Newtonsoft.Json@12.0.3: no loaded module imports it (package_not_loaded)", ""},
		{"diff-lexed with package_not_loaded on a record not listing every package",
			spRecord{provenance: "diff-lexed", refutation: notLoaded}, "", report.ReasonAdvisorySymbolsUnvetted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := symbolProvenanceFinding(t, tt.record)
			if tt.detail == "" {
				if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != tt.reason {
					t.Fatalf("verdict = %q reason %q (%s), want undetermined for %q", f.Verdict, f.UndeterminedReason, f.Evidence.Detail, tt.reason)
				}
				if f.Evidence.Detail != report.UndeterminedDetail(tt.reason) {
					t.Errorf("detail = %q, want the %s detail", f.Evidence.Detail, tt.reason)
				}
				return
			}
			// Every ground leaves the code installed and unreached.
			wantBasis := verdict.BasisSymbolUnreachable
			if f.Verdict != report.VerdictNotExploitable || f.Evidence.Basis != wantBasis {
				t.Fatalf("verdict = %q basis %q (reason %q), want not_exploitable on %q",
					f.Verdict, f.Evidence.Basis, f.UndeterminedReason, wantBasis)
			}
			if f.Evidence.Detail != tt.detail {
				t.Errorf("detail = %q\nwant     %q", f.Evidence.Detail, tt.detail)
			}
		})
	}
}

// TestFinding_BuiltInRecordThroughIntake runs a built-in table id through S1 and into the gate: the
// table's untagged symbol set grounds not_exploitable because S1 marked the record as the table's,
// not because of anything the record says about itself.
func TestFinding_BuiltInRecordThroughIntake(t *testing.T) {
	const (
		id   = "FERRALON-JAVA-SSRF-0002"
		sink = "jvmref com/example/net/App#fetch(Ljava/lang/String;)V"
		purl = "pkg:maven/com.example.net/urlkit"
	)
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "builtin-e2e", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: id, Source: "builtin"},
	}}
	if err := pipeline.NewAdvisoryIntake().Run(context.Background(), c, store); err != nil {
		t.Fatal(err)
	}
	arts, err := store.Query(c.ID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) != 1 {
		t.Fatalf("normalized advisory: %d artifacts, err %v", len(arts), err)
	}
	var rec struct {
		SymbolProvenance string `json:"symbol_provenance"`
		BuiltIn          bool   `json:"built_in"`
	}
	if err := json.Unmarshal(arts[0].Payload, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.SymbolProvenance != "" || !rec.BuiltIn {
		t.Fatalf("intake wrote %s as %+v, want an untagged record marked built_in", id, rec)
	}
	putJSON(t, store, c.ID, artifact.TypeVulnerableSymbol, plugin.SymbolResolutionResult{
		Partiality: plugin.Complete(),
		Resolved:   []plugin.Symbol{{SCIP: sink}},
		Origins:    map[string]string{sink: purl},
		Matched:    map[string][]string{"App.fetch": {sink}},
	})
	seedFootprint(t, store, c.ID, nil)
	seedReachArtifact(t, store, c.ID,
		plugin.CallGraphResult{
			Partiality: plugin.Complete(),
			Edges:      []plugin.CallEdge{depEdge("jvmref com/example/net/App#main()V", "jvmref com/example/net/App#run()V")},
		},
		plugin.ReachabilityResult{Partiality: plugin.Complete(), Searched: []string{sink}})
	pkg := &report.Package{Ecosystem: "Maven", Name: "com.example.net:urlkit", Version: "2.0.0", PURL: purl + "@2.0.0"}
	f := finding(store, c.ID, report.Advisory{ID: id, Source: "builtin"}, pkg)
	if f.Verdict != report.VerdictNotExploitable || f.Evidence.Basis != verdict.BasisSymbolUnreachable {
		t.Fatalf("verdict = %q basis %q (reason %q: %s), want not_exploitable on %q",
			f.Verdict, f.Evidence.Basis, f.UndeterminedReason, f.Evidence.Detail, verdict.BasisSymbolUnreachable)
	}
}
