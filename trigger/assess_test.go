package trigger

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// groundsFixture is one advisory that reached finding()'s default arm: no disqualification, no
// candidate path. Each field is one input the positive-grounds gate reads.
type groundsFixture struct {
	pkg             *report.Package
	advisoryPURL    string
	advisorySymbols []string
	resolution      plugin.SymbolResolutionResult
	reach           plugin.ReachabilityResult
	footprint       []string
}

func (fx groundsFixture) finding(t *testing.T) report.AdvisoryFinding {
	t.Helper()
	store := artifact.NewMemStore()
	const aid = "grounds"
	putJSON(t, store, aid, artifact.TypeNormalizedAdvisory, map[string]any{
		"purl": fx.advisoryPURL, "advisory_symbols": fx.advisorySymbols,
	})
	putJSON(t, store, aid, artifact.TypeVulnerableSymbol, fx.resolution)
	seedReachArtifact(t, store, aid, plugin.CallGraphResult{
		Partiality: plugin.Complete(),
		Edges:      []plugin.CallEdge{depEdge("main", "lib")},
	}, fx.reach)
	if fx.footprint != nil {
		putJSON(t, store, aid, artifact.TypeExposureFootprint, artifact.ExposureFootprintPayload{PartialityFlags: fx.footprint})
	}
	return finding(store, aid, report.Advisory{ID: "GHSA-test", Source: "corpus"}, fx.pkg)
}

const (
	yamlSink  = "scip-python python PyYAML 6.0 yaml/load()."
	yamlSink2 = "scip-python python PyYAML 6.0 yaml/full_load()."
	localSink = "scip-python python app . app/load()."
)

var yamlPkg = &report.Package{Ecosystem: "PyPI", Name: "PyYAML", Version: "5.3", PURL: "pkg:pypi/pyyaml@5.3"}

// yamlSearched is the arm-A shape every row below perturbs: the advisory names yaml.load, the
// lane resolved it to code inside PyYAML (PEP 503 spelling differs from the admitted PURL), and
// the lane searched that sink from its entry points without reaching it.
func yamlSearched() groundsFixture {
	return groundsFixture{
		pkg:             yamlPkg,
		advisoryPURL:    "pkg:pypi/pyyaml",
		advisorySymbols: []string{"yaml.load"},
		resolution: plugin.SymbolResolutionResult{
			Partiality: plugin.Complete(),
			Resolved:   []plugin.Symbol{{SCIP: yamlSink}},
			Origins:    map[string]string{yamlSink: "pkg:pypi/PyYAML"},
			Matched:    map[string][]string{"yaml.load": {yamlSink}},
		},
		reach: plugin.ReachabilityResult{Partiality: plugin.Complete(), Searched: []string{yamlSink}},
	}
}

func refutation(purl string) *plugin.Refutation {
	return &plugin.Refutation{
		Basis:   plugin.RefutationPackageNotLoaded,
		Package: purl,
		Detail:  "no runtime-loaded module imports it",
	}
}

// TestFinding_PositiveGrounds is the NE gate: finding() emits not_exploitable only on named
// grounds — every advisory symbol searched inside the admitted package (arm A), or the lane's
// refutation of that package (arm B) — and otherwise says which ground was missing.
func TestFinding_PositiveGrounds(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(*groundsFixture)
		wantReason string // "" = not_exploitable
		wantDetail string // substring of the NE detail
	}{
		{
			name:       "arm A: every advisory symbol searched inside the package",
			mutate:     func(*groundsFixture) {},
			wantDetail: "yaml.load in PyYAML@5.3",
		},
		{
			name:       "G0 wins: a did_not_run limit keeps undetermined even with grounds",
			mutate:     func(fx *groundsFixture) { fx.footprint = []string{plugin.PartialReasonNoIngress} },
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name:       "G1: no package admitted",
			mutate:     func(fx *groundsFixture) { fx.pkg = nil },
			wantReason: report.ReasonPackageVersionUnresolved,
		},
		{
			name: "G1: version unresolved",
			mutate: func(fx *groundsFixture) {
				fx.pkg = &report.Package{Ecosystem: "PyPI", Name: "PyYAML", PURL: "pkg:pypi/pyyaml"}
			},
			wantReason: report.ReasonPackageVersionUnresolved,
		},
		{
			name: "G1: source unpinned",
			mutate: func(fx *groundsFixture) {
				p := *yamlPkg
				p.PartialReason = plugin.PartialReasonGitRefUnpinned
				fx.pkg = &p
			},
			wantReason: report.ReasonPackageVersionUnresolved,
		},
		{
			name:       "arm A: advisory names no symbol",
			mutate:     func(fx *groundsFixture) { fx.advisorySymbols = nil },
			wantReason: report.ReasonAdvisorySymbolAbsent,
		},
		{
			name:       "arm A: advisory symbol the lane did not match",
			mutate:     func(fx *groundsFixture) { fx.resolution.Matched = nil },
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "arm A: leaf-name hit in first-party code never counts",
			mutate: func(fx *groundsFixture) {
				fx.resolution.Resolved = []plugin.Symbol{{SCIP: localSink}}
				fx.resolution.Origins = nil
				fx.resolution.Matched = map[string][]string{"yaml.load": {localSink}}
				fx.reach.Searched = []string{localSink}
			},
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			// Tracker's required row: an Origin from import→lockfile resolution (a boundary
			// node whose code was not read) is never Searched, so arm A fails.
			name:       "arm A: in-package origin, sink not searched",
			mutate:     func(fx *groundsFixture) { fx.reach.Searched = nil },
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "arm A: one of two in-package sinks not searched",
			mutate: func(fx *groundsFixture) {
				fx.resolution.Resolved = append(fx.resolution.Resolved, plugin.Symbol{SCIP: yamlSink2})
				fx.resolution.Origins[yamlSink2] = "pkg:pypi/pyyaml"
				fx.resolution.Matched["yaml.load"] = []string{yamlSink, yamlSink2}
			},
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "arm A: second advisory symbol unresolved",
			mutate: func(fx *groundsFixture) {
				fx.advisorySymbols = []string{"yaml.load", "yaml.full_load"}
			},
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "arm A: origin in another ecosystem with the same name",
			mutate: func(fx *groundsFixture) {
				fx.resolution.Origins = map[string]string{yamlSink: "pkg:npm/pyyaml"}
			},
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "arm A: origin in a different package of the same ecosystem",
			mutate: func(fx *groundsFixture) {
				fx.resolution.Origins = map[string]string{yamlSink: "pkg:pypi/ruamel.yaml"}
			},
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "arm B: refutation of the admitted package, no symbols needed",
			mutate: func(fx *groundsFixture) {
				fx.advisorySymbols = nil
				fx.reach.Searched = nil
				fx.reach.Refutation = refutation("pkg:pypi/PyYAML")
			},
			wantDetail: "PyYAML@5.3: no runtime-loaded module imports it",
		},
		{
			name: "arm B: refutation of another package",
			mutate: func(fx *groundsFixture) {
				fx.reach.Searched = nil
				fx.reach.Refutation = refutation("pkg:pypi/ruamel.yaml")
			},
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "arm B: refutation does not lift a did_not_run limit",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation = refutation("pkg:pypi/pyyaml")
				fx.footprint = []string{plugin.PartialReasonReachabilityUndetermined}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := yamlSearched()
			tc.mutate(&fx)
			f := fx.finding(t)
			if tc.wantReason != "" {
				if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != tc.wantReason {
					t.Fatalf("got %s/%q, want undetermined/%q", f.Verdict, f.UndeterminedReason, tc.wantReason)
				}
				if f.Evidence.Basis != "" {
					t.Errorf("basis = %q on an undetermined row", f.Evidence.Basis)
				}
				return
			}
			if f.Verdict != report.VerdictNotExploitable {
				t.Fatalf("got %s/%q, want not_exploitable", f.Verdict, f.UndeterminedReason)
			}
			if f.Evidence.Basis != verdict.BasisSymbolAbsent {
				t.Errorf("basis = %q, want %q", f.Evidence.Basis, verdict.BasisSymbolAbsent)
			}
			if !strings.Contains(f.Evidence.Detail, tc.wantDetail) {
				t.Errorf("detail = %q, want it to name %q", f.Evidence.Detail, tc.wantDetail)
			}
		})
	}
}

// TestLimitNoteFor_GroundsReasonsScopeToPackageEcosystem: the gate's reasons are about the
// finding's package, so their scan-level note is scoped to its ecosystem, not to Go.
func TestLimitNoteFor_GroundsReasonsScopeToPackageEcosystem(t *testing.T) {
	for _, reason := range []string{
		report.ReasonPackageVersionUnresolved,
		report.ReasonAdvisorySymbolAbsent,
		report.ReasonVulnerableSymbolUnresolved,
	} {
		note, ok := limitNoteFor(report.AdvisoryFinding{
			Verdict: report.VerdictUndetermined, UndeterminedReason: reason, Package: yamlPkg,
		})
		if !ok || note.Reason != reason || note.Ecosystem != "PyPI" {
			t.Errorf("%s: note = %+v, ok=%v; want reason %q scoped to PyPI", reason, note, ok, reason)
		}
	}
}

func TestPurlKey(t *testing.T) {
	cases := []struct {
		a, b  string
		match bool
	}{
		{"pkg:pypi/PyYAML", "pkg:pypi/pyyaml@6.0", true},
		{"pkg:pypi/zope.interface", "pkg:pypi/zope-interface", true},
		{"pkg:npm/%40babel/core", "pkg:npm/@babel/core@7.0.0", true},
		{"pkg:npm/@babel/core", "pkg:npm/core", false},
		{"pkg:npm/Lodash", "pkg:npm/lodash", false},
		{"pkg:maven/org.yaml/snakeyaml@1.33", "pkg:maven/org.yaml/snakeyaml", true},
		{"pkg:maven/org.yaml/snakeyaml", "pkg:maven/org.other/snakeyaml", false},
		{"pkg:nuget/Newtonsoft.Json", "pkg:nuget/newtonsoft.json@13.0.1", true},
		{"pkg:golang/golang.org/x/net@v0.1.0?type=module#html", "pkg:golang/golang.org/x/net", true},
		{"pkg:golang/golang.org/x/net/html", "pkg:golang/golang.org/x/net", false},
		{"pkg:golang/stdlib", "pkg:npm/stdlib", false},
	}
	for _, tc := range cases {
		ka, oka := purlKey(tc.a)
		kb, okb := purlKey(tc.b)
		if !oka || !okb {
			t.Fatalf("purlKey(%q)=%v, purlKey(%q)=%v: want both parsed", tc.a, oka, tc.b, okb)
		}
		if (ka == kb) != tc.match {
			t.Errorf("%q vs %q: match = %v, want %v", tc.a, tc.b, ka == kb, tc.match)
		}
	}
	for _, bad := range []string{"", "lodash", "pkg:", "pkg:npm", "pkg:npm/"} {
		if _, ok := purlKey(bad); ok {
			t.Errorf("purlKey(%q) parsed; want rejected", bad)
		}
	}
}

// TestWithInventoryLimits: a scan-wide inventory limit of the did_not_run class (stethoscope's
// tool_failure:lockfile_ambiguous) blocks not_exploitable for findings of its ecosystem.
func TestWithInventoryLimits(t *testing.T) {
	ne := report.AdvisoryFinding{
		Package:  &report.Package{Ecosystem: "npm", Name: "qs", Version: "6.5.2"},
		Verdict:  report.VerdictNotExploitable,
		Evidence: report.EvidenceSummary{Basis: verdict.BasisSymbolAbsent, Detail: "grounds"},
	}
	ambiguous := inventoryPartialityNotes(plugin.Partial(plugin.PartialReasonLockfileAmbiguous), "npm")
	cases := []struct {
		name    string
		f       report.AdvisoryFinding
		limits  []report.PartialityNote
		blocked bool
	}{
		{"lockfile ambiguous blocks NE of its ecosystem", ne, ambiguous, true},
		{"no inventory limit", ne, nil, false},
		{"limit of another ecosystem", ne, inventoryPartialityNotes(plugin.Partial(plugin.PartialReasonLockfileAmbiguous), "PyPI"), false},
		{"inherent inventory limit", ne, inventoryPartialityNotes(plugin.Partial(plugin.PartialReasonReflection), "npm"), false},
		{"read back from a prior report's notes", ne, inventoryLimits(append(ambiguous, report.PartialityNote{Reason: plugin.PartialReasonNoIngress, Ecosystem: "npm"})), true},
		{"other scan notes are not inventory limits", ne, inventoryLimits([]report.PartialityNote{{Reason: plugin.PartialReasonNoIngress, Ecosystem: "npm"}}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := withInventoryLimits(tc.f, tc.limits)
			if !tc.blocked {
				if got.Verdict != report.VerdictNotExploitable {
					t.Fatalf("verdict = %s/%q, want not_exploitable", got.Verdict, got.UndeterminedReason)
				}
				return
			}
			if got.Verdict != report.VerdictUndetermined || got.UndeterminedReason != report.ReasonAnalysisDidNotRun || got.Evidence.Basis != "" {
				t.Fatalf("got %s/%q basis %q, want undetermined/%s with no basis", got.Verdict, got.UndeterminedReason, got.Evidence.Basis, report.ReasonAnalysisDidNotRun)
			}
		})
	}
	for _, v := range []report.Verdict{report.VerdictReachableCandidate, report.VerdictDisqualified, report.VerdictUndetermined} {
		f := ne
		f.Verdict = v
		if got := withInventoryLimits(f, ambiguous); got.Verdict != v {
			t.Errorf("%s changed to %s", v, got.Verdict)
		}
	}
}

// TestFinding_AliasedDependencyCallIsNotGrounds pins the shape #79 briefly let through on main:
// `const p = require('json5'); function load(s){ return p.parse(s) }`. The JS lane drew one edge,
// declared only the inherent dynamic_dispatch, and resolved json5.parse to a boundary node whose
// code it never loaded. That defeats analysisDidNotRun's zero-edge arm, so the gate alone must
// refuse not_exploitable: the sink is not Searched and no lane refuted json5.
func TestFinding_AliasedDependencyCallIsNotGrounds(t *testing.T) {
	const boundary = "npm:json5#parse"
	fx := groundsFixture{
		pkg:             &report.Package{Ecosystem: "npm", Name: "json5", Version: "2.2.1", PURL: "pkg:npm/json5@2.2.1"},
		advisoryPURL:    "pkg:npm/json5",
		advisorySymbols: []string{"json5.parse"},
		resolution: plugin.SymbolResolutionResult{
			Partiality: plugin.Complete(),
			Resolved:   []plugin.Symbol{{SCIP: boundary}},
			Origins:    map[string]string{boundary: "pkg:npm/json5"},
			Matched:    map[string][]string{"json5.parse": {boundary}},
		},
		reach:     plugin.ReachabilityResult{Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch)},
		footprint: []string{plugin.PartialReasonDynamicDispatch},
	}
	f := fx.finding(t)
	if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != report.ReasonVulnerableSymbolUnresolved {
		t.Fatalf("got %s/%q, want undetermined/%s", f.Verdict, f.UndeterminedReason, report.ReasonVulnerableSymbolUnresolved)
	}
}
