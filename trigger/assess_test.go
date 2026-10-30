package trigger

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/goanalysis"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
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
	affected        []string // affected_packages[] PURLs
	dropped         []string // dropped_affected_packages: elements that failed validation
	resolution      plugin.SymbolResolutionResult
	reach           plugin.ReachabilityResult
	callGraph       *plugin.CallGraphResult // nil = a complete graph with one edge
	footprint       []string
	mods            goModules // the build's Go modules
	scoped          []artifact.ScopedPartialityFlag
	provenance      string // symbol_provenance; "" = osv-declared
	untagged        bool   // the record carries no symbol_provenance
	builtIn         bool   // S1's marker for a record the built-in table answered
}

func (fx groundsFixture) finding(t *testing.T) report.AdvisoryFinding {
	t.Helper()
	store := artifact.NewMemStore()
	const aid = "grounds"
	affected := make([]map[string]string, 0, len(fx.affected))
	for _, p := range fx.affected {
		affected = append(affected, map[string]string{"purl": p})
	}
	adv := map[string]any{
		"purl": fx.advisoryPURL, "advisory_symbols": fx.advisorySymbols, "affected_packages": affected,
		"dropped_affected_packages": fx.dropped, "symbol_provenance": "osv-declared",
	}
	if fx.provenance != "" {
		adv["symbol_provenance"] = fx.provenance
	}
	if fx.untagged {
		delete(adv, "symbol_provenance")
	}
	if fx.builtIn {
		adv["built_in"] = true
	}
	putJSON(t, store, aid, artifact.TypeNormalizedAdvisory, adv)
	putJSON(t, store, aid, artifact.TypeVulnerableSymbol, fx.resolution)
	cg := plugin.CallGraphResult{Partiality: plugin.Complete(), Edges: []plugin.CallEdge{depEdge("main", "lib")}}
	if fx.callGraph != nil {
		cg = *fx.callGraph
	}
	seedReachArtifact(t, store, aid, cg, fx.reach)
	if fx.footprint != nil || fx.scoped != nil {
		putJSON(t, store, aid, artifact.TypeExposureFootprint, artifact.ExposureFootprintPayload{
			PartialityFlags: fx.footprint, ScopedPartiality: fx.scoped,
		})
	}
	return findingInBuild(store, aid, report.Advisory{ID: "GHSA-test", Source: "corpus"}, fx.pkg, fx.mods)
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
		wantBasis  verdict.NonExploitableBasis
	}{
		{
			name:       "arm A: every advisory symbol searched inside the package",
			mutate:     func(*groundsFixture) {},
			wantDetail: "yaml.load in PyYAML@5.3",
			wantBasis:  verdict.BasisSymbolUnreachable,
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
				fx.affected = []string{"pkg:pypi/pyyaml"}
				fx.reach.Refutation = refutation("pkg:pypi/PyYAML")
			},
			wantDetail: "PyYAML@5.3: no runtime-loaded module imports it (package_not_loaded)",
			wantBasis:  verdict.BasisSymbolUnreachable,
		},
		{
			// A record with only the scalar purl may affect a package it does not name, which
			// could load at runtime beside the refuted one.
			name: "arm B: package_not_loaded on a record without affected_packages does not ground",
			mutate: func(fx *groundsFixture) {
				fx.advisorySymbols = nil
				fx.reach.Searched = nil
				fx.reach.Refutation = refutation("pkg:pypi/PyYAML")
			},
			wantReason: report.ReasonAdvisorySymbolAbsent,
		},
		{
			name: "multi-package: the admitted package listed again grounds as before",
			mutate: func(fx *groundsFixture) {
				fx.affected = []string{"pkg:pypi/PyYAML"}
			},
			wantDetail: "yaml.load in PyYAML@5.3",
			wantBasis:  verdict.BasisSymbolUnreachable,
		},
		{
			// Tracker's probe: symbols in two packages, only the admitted one's were searched.
			name: "multi-package: arm A on the admitted package alone does not ground",
			mutate: func(fx *groundsFixture) {
				fx.affected = []string{"pkg:pypi/pyyaml", "pkg:pypi/ruamel.yaml"}
				fx.advisorySymbols = []string{"yaml.load", "ruamel.yaml.load"}
				fx.resolution.Matched["ruamel.yaml.load"] = nil
			},
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "multi-package: a refutation of the admitted package does not ground",
			mutate: func(fx *groundsFixture) {
				fx.affected = []string{"pkg:pypi/pyyaml", "pkg:pypi/ruamel.yaml"}
				fx.reach.Searched = nil
				fx.reach.Refutation = refutation("pkg:pypi/PyYAML")
			},
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "multi-package: an element without a package URL is another package",
			mutate: func(fx *groundsFixture) {
				fx.affected = []string{"pkg:pypi/pyyaml", ""}
			},
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			// CVE-2023-39325's shape: the second element failed validation and left the
			// multi-package set, but the advisory still names it.
			name: "multi-package: an element dropped at decode is another package",
			mutate: func(fx *groundsFixture) {
				fx.affected = []string{"pkg:pypi/pyyaml"}
				fx.dropped = []string{"pkg:pypi/ruamel.yaml"}
			},
			wantReason: report.ReasonVulnerableSymbolUnresolved,
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
			if f.Evidence.Basis != tc.wantBasis {
				t.Errorf("basis = %q, want %q", f.Evidence.Basis, tc.wantBasis)
			}
			if !strings.Contains(f.Evidence.Detail, tc.wantDetail) {
				t.Errorf("detail = %q, want it to name %q", f.Evidence.Detail, tc.wantDetail)
			}
		})
	}
}

// netNotReached is the Go 1c shape: govulncheck matched the advisory to golang.org/x/net in the
// build and traced no call to its vulnerable functions, which goanalysis states as a refutation.
func netNotReached() groundsFixture {
	return groundsFixture{
		pkg:             &report.Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.1.0", PURL: "pkg:golang/golang.org/x/net@v0.1.0"},
		advisoryPURL:    "pkg:golang/golang.org/x/net",
		advisorySymbols: []string{"html.Parse"},
		resolution:      plugin.SymbolResolutionResult{Partiality: plugin.Complete()},
		reach: plugin.ReachabilityResult{
			Partiality: plugin.Complete(),
			Refutation: &plugin.Refutation{
				Basis:   plugin.RefutationAnalyzerSymbolNotReached,
				Package: "pkg:golang/golang.org/x/net",
				Detail:  "govulncheck matched the advisory to golang.org/x/net v0.1.0 and found no call path to its vulnerable functions",
			},
		},
	}
}

// TestFinding_GoGovulncheckEvidence: Go not_exploitable rests on govulncheck's own evidence for
// the advisory (1c), and govulncheck's silence about it is said as such.
func TestFinding_GoGovulncheckEvidence(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(*groundsFixture)
		wantReason string // "" = not_exploitable
	}{
		{name: "module matched, no symbol reached: not exploitable", mutate: func(*groundsFixture) {}},
		{
			name:   "reflection without a reflective call does not block the refutation",
			mutate: func(fx *groundsFixture) { fx.footprint = []string{plugin.PartialReasonReflection} },
		},
		{
			name: "reflective calls bounded for this advisory, with dynamic dispatch: not exploitable",
			mutate: func(fx *groundsFixture) {
				fx.footprint = []string{plugin.PartialReasonReflection, plugin.PartialReasonDynamicDispatch}
			},
		},
		{
			name: "reflective calls reach the advisory, so the lane withheld its refutation",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation = nil
				fx.footprint = []string{plugin.PartialReasonReflection, plugin.PartialReasonReflectiveCall}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name: "govulncheck has no finding for a program that uses reflection",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation = nil
				fx.footprint = []string{plugin.PartialReasonReflection, plugin.PartialReasonAdvisoryUnknownToAnalyzer}
			},
			wantReason: report.ReasonAdvisoryUnknownToAnalyzer,
		},
		{
			name: "a reflective call blocks the refutation",
			mutate: func(fx *groundsFixture) {
				fx.footprint = []string{plugin.PartialReasonReflection, plugin.PartialReasonReflectiveCall}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name:       "a plugin load blocks the refutation",
			mutate:     func(fx *groundsFixture) { fx.footprint = []string{plugin.PartialReasonPluginLoad} },
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name:       "files the build left out block the refutation",
			mutate:     func(fx *groundsFixture) { fx.footprint = []string{plugin.PartialReasonExcludedFiles} },
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name:       "cgo blind spot keeps undetermined",
			mutate:     func(fx *groundsFixture) { fx.footprint = []string{plugin.PartialReasonCgo} },
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name: "refutation of another module",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation.Package = "pkg:golang/golang.org/x/text"
			},
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "refutation of a package path inside the module does not match the module",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation.Package = "pkg:golang/golang.org/x/net/html"
			},
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "govulncheck has no finding for the advisory",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation = nil
				fx.footprint = []string{plugin.PartialReasonAdvisoryUnknownToAnalyzer}
			},
			wantReason: report.ReasonAdvisoryUnknownToAnalyzer,
		},
		{
			name: "no finding plus another did_not_run limit",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation = nil
				fx.footprint = []string{plugin.PartialReasonAdvisoryUnknownToAnalyzer, plugin.PartialReasonCgo}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := netNotReached()
			tc.mutate(&fx)
			f := fx.finding(t)
			if tc.wantReason != "" {
				if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != tc.wantReason {
					t.Fatalf("got %s/%q, want undetermined/%q", f.Verdict, f.UndeterminedReason, tc.wantReason)
				}
				return
			}
			if f.Verdict != report.VerdictNotExploitable {
				t.Fatalf("got %s/%q, want not_exploitable", f.Verdict, f.UndeterminedReason)
			}
			if want := "golang.org/x/net@v0.1.0: govulncheck matched"; !strings.Contains(f.Evidence.Detail, want) {
				t.Errorf("detail = %q, want it to name %q", f.Evidence.Detail, want)
			}
		})
	}
}

// TestFinding_ScopedLimits: a scoped limit blocks not_exploitable exactly as the same run-wide
// reason would, unless its Targets are bounded and exclude the admitted package (contract §4).
func TestFinding_ScopedLimits(t *testing.T) {
	const (
		xnet  = "pkg:golang/golang.org/x/net"
		xtext = "pkg:golang/golang.org/x/text"
		cgo   = plugin.PartialReasonCgo
	)
	cases := []struct {
		name       string
		base       func() groundsFixture
		mutate     func(*groundsFixture)
		wantReason string // "" = not_exploitable
	}{
		{
			name: "targets exclude the package: refutation stands",
			base: netNotReached,
			mutate: func(fx *groundsFixture) {
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: cgo, Package: "", Path: "example.com/app/native", Targets: []string{"", xtext}}}
			},
		},
		{
			name: "targets include the package",
			base: netNotReached,
			mutate: func(fx *groundsFixture) {
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: cgo, Targets: []string{"", xtext, xnet}}}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name: "the blind spot is inside the package",
			base: netNotReached,
			mutate: func(fx *groundsFixture) {
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: cgo, Package: xnet, Targets: []string{xtext}}}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name: "unbounded targets count against every advisory",
			base: netNotReached,
			mutate: func(fx *groundsFixture) {
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: cgo, Package: xtext}}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name: "empty targets are unbounded, as a JSON round-trip reads them",
			base: netNotReached,
			mutate: func(fx *groundsFixture) {
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: cgo, Package: xtext, Targets: []string{}}}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name: "first-party target does not match a dependency",
			base: netNotReached,
			mutate: func(fx *groundsFixture) {
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: cgo, Targets: []string{""}}}
			},
		},
		{
			name: "target matched by versionless PURL with a version present",
			base: netNotReached,
			mutate: func(fx *groundsFixture) {
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: cgo, Targets: []string{xnet + "@v0.1.0"}}}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name: "a bare module path is not a package URL and counts",
			base: netNotReached,
			mutate: func(fx *groundsFixture) {
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: cgo, Package: "golang.org/x/net", Targets: []string{"golang.org/x/net"}}}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name: "a target that does not parse counts",
			base: netNotReached,
			mutate: func(fx *groundsFixture) {
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: cgo, Package: "golang.org/x/net", Targets: []string{"not a purl"}}}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name: "a package URL with no name counts",
			base: netNotReached,
			mutate: func(fx *groundsFixture) {
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: cgo, Package: "golang.org/x/net", Targets: []string{"pkg:golang/"}}}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name: "a package path inside the module counts",
			base: netNotReached,
			mutate: func(fx *groundsFixture) {
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: cgo, Targets: []string{"", xnet + "/http2"}}}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name: "unresolved package cannot be excluded",
			base: netNotReached,
			mutate: func(fx *groundsFixture) {
				fx.pkg = &report.Package{Ecosystem: "Go", Name: "golang.org/x/net"}
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: cgo, Targets: []string{xtext}}}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name: "an inherent scoped limit does not block",
			base: netNotReached,
			mutate: func(fx *groundsFixture) {
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: plugin.PartialReasonReflection, Targets: []string{xnet}}}
			},
		},
		{
			name: "pypi target matched under PEP 503",
			base: yamlSearched,
			mutate: func(fx *groundsFixture) {
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: plugin.PartialReasonToolFailure, Targets: []string{"pkg:pypi/PyYAML"}}}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name: "pypi target of another package",
			base: yamlSearched,
			mutate: func(fx *groundsFixture) {
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: plugin.PartialReasonToolFailure, Targets: []string{"pkg:pypi/requests"}}}
			},
		},
		{
			name: "a run-wide reason still blocks whatever the scoped ones say",
			base: netNotReached,
			mutate: func(fx *groundsFixture) {
				fx.footprint = []string{cgo}
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: cgo, Targets: []string{xtext}}}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := tc.base()
			tc.mutate(&fx)
			f := fx.finding(t)
			if tc.wantReason != "" {
				if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != tc.wantReason {
					t.Fatalf("got %s/%q, want undetermined/%q", f.Verdict, f.UndeterminedReason, tc.wantReason)
				}
				return
			}
			if f.Verdict != report.VerdictNotExploitable {
				t.Fatalf("got %s/%q, want not_exploitable", f.Verdict, f.UndeterminedReason)
			}
		})
	}
}

// An advisory_unknown_to_analyzer row stands on the lane's own limit, which partialityNotes
// already publishes at scan scope; the row owes no second note.
func TestLimitNoteFor_AdvisoryUnknownToAnalyzerOwesNoNote(t *testing.T) {
	if note, ok := limitNoteFor(report.AdvisoryFinding{
		Verdict: report.VerdictUndetermined, UndeterminedReason: report.ReasonAdvisoryUnknownToAnalyzer,
	}); ok {
		t.Errorf("note = %+v, want none", note)
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
	for _, v := range []report.Verdict{report.VerdictReachableCandidate, report.VerdictUndetermined} {
		f := ne
		f.Verdict = v
		if got := withInventoryLimits(f, ambiguous); got.Verdict != v {
			t.Errorf("%s changed to %s", v, got.Verdict)
		}
	}
}

// TestWithInventoryLimits_Disqualified: a disqualification grounded in the inventory (version out
// of range, package absent from the manifest) does not stand under a did_not_run inventory limit
// of its ecosystem; one grounded elsewhere (symbol axis, ecosystem mismatch) does.
func TestWithInventoryLimits_Disqualified(t *testing.T) {
	disq := func(reason string) report.AdvisoryFinding {
		return report.AdvisoryFinding{
			Package:  &report.Package{Ecosystem: "npm", Name: "qs", Version: "6.5.3"},
			Verdict:  report.VerdictDisqualified,
			Evidence: report.EvidenceSummary{Basis: disqualBasis(reason), Detail: disqualDetail(reason)},
		}
	}
	noPkg := func(f report.AdvisoryFinding) report.AdvisoryFinding {
		f.Package = nil
		return f
	}
	noVersion := func(f report.AdvisoryFinding) report.AdvisoryFinding {
		f.Package = &report.Package{Ecosystem: "npm", Name: "qs"}
		return f
	}
	ambiguous := inventoryPartialityNotes(plugin.Partial(plugin.PartialReasonLockfileAmbiguous), "npm")
	nestedGo := inventoryPartialityNotes(withNestedModules(plugin.Partial(goanalysis.PartialReasonNestedModule), "receiver/a"), "Go")
	cases := []struct {
		name    string
		f       report.AdvisoryFinding
		limits  []report.PartialityNote
		blocked bool
	}{
		{"version out of range", disq(pipeline.ReasonVersionNotInRange), ambiguous, true},
		{"absent from the manifest", disq(pipeline.ReasonNoManifestEntry), ambiguous, true},
		{"version out of range, no limit", disq(pipeline.ReasonVersionNotInRange), nil, false},
		{"version out of range, limit of another ecosystem", disq(pipeline.ReasonVersionNotInRange),
			inventoryPartialityNotes(plugin.Partial(plugin.PartialReasonLockfileAmbiguous), "PyPI"), false},
		{"version out of range, inherent limit", disq(pipeline.ReasonVersionNotInRange),
			inventoryPartialityNotes(plugin.Partial(plugin.PartialReasonReflection), "npm"), false},
		{"symbol axis", disq(pipeline.ReasonSymbolAbsent), ambiguous, false},
		{"ecosystem mismatch", disq(pipeline.ReasonAdvisoryEcosystemMismatch), ambiguous, false},
		{"version set, no single version", noVersion(disq(pipeline.ReasonVersionNotInRange)), ambiguous, true},
		{"version set, limit of another ecosystem", noVersion(disq(pipeline.ReasonVersionNotInRange)),
			inventoryPartialityNotes(plugin.Partial(plugin.PartialReasonLockfileAmbiguous), "PyPI"), false},
		{"toolchain version out of range, no package", noPkg(disq(pipeline.ReasonVersionNotInRange)), ambiguous, false},
		{"absent from the manifest, no package", noPkg(disq(pipeline.ReasonNoManifestEntry)),
			inventoryPartialityNotes(plugin.Partial(plugin.PartialReasonLockfileAmbiguous), "PyPI"), true},
		{"absent from the manifest, no package, no limit", noPkg(disq(pipeline.ReasonNoManifestEntry)), nil, false},
		{"absent from the manifest, no package, inherent limit", noPkg(disq(pipeline.ReasonNoManifestEntry)),
			inventoryPartialityNotes(plugin.Partial(plugin.PartialReasonReflection), "npm"), false},
		{"symbol axis, no package", noPkg(disq(pipeline.ReasonSymbolAbsent)), ambiguous, false},
		{"absent from the manifest, no package, nested Go module", noPkg(disq(pipeline.ReasonNoManifestEntry)), nestedGo, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := withInventoryLimits(tc.f, tc.limits)
			if !tc.blocked {
				if got.Verdict != report.VerdictDisqualified {
					t.Fatalf("verdict = %s/%q, want disqualified", got.Verdict, got.UndeterminedReason)
				}
				return
			}
			if got.Verdict != report.VerdictUndetermined || got.UndeterminedReason != report.ReasonAnalysisDidNotRun || got.Evidence.Basis != "" {
				t.Fatalf("got %s/%q basis %q, want undetermined/%s with no basis", got.Verdict, got.UndeterminedReason, got.Evidence.Basis, report.ReasonAnalysisDidNotRun)
			}
		})
	}
}

// withNestedModules scopes p's nested-module limit to each named module directory, as the Go
// inventory does.
func withNestedModules(p plugin.Partiality, dirs ...string) plugin.Partiality {
	for _, d := range dirs {
		p.Scoped = append(p.Scoped, plugin.ScopedReason{Reason: goanalysis.PartialReasonNestedModule, Path: d})
	}
	return p
}

// TestInventoryPartialityNotes: one note per reason; a reason the inventory scoped names every
// scoped location on that one note, and a scoped reason missing from Reasons is still declared.
func TestInventoryPartialityNotes(t *testing.T) {
	nested := goanalysis.PartialReasonNestedModule
	note := func(reason, path string) report.PartialityNote {
		return report.PartialityNote{Reason: reason, Ecosystem: "Go", Detail: inventoryLimitDetail, Path: path}
	}
	scopedOnly := plugin.Partiality{Scoped: []plugin.ScopedReason{{Reason: nested, Path: "a"}}}
	cases := []struct {
		name string
		p    plugin.Partiality
		want []report.PartialityNote
	}{
		{"complete", plugin.Complete(), nil},
		{"partial with no reason", plugin.Partiality{}, []report.PartialityNote{note(report.ReasonUnspecifiedLimit, "")}},
		{"unscoped reason", plugin.Partial(plugin.PartialReasonToolFailure), []report.PartialityNote{note(plugin.PartialReasonToolFailure, "")}},
		{"nested modules named on one note",
			withNestedModules(plugin.Partial(plugin.PartialReasonToolFailure, nested), "exporter/b", "receiver/a"),
			[]report.PartialityNote{note(plugin.PartialReasonToolFailure, ""), note(nested, "exporter/b, receiver/a")}},
		{"scoped reason missing from Reasons", scopedOnly, []report.PartialityNote{note(nested, "a")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := inventoryPartialityNotes(tc.p, "Go"); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("notes = %+v, want %+v", got, tc.want)
			}
		})
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

// TestScopedLimitCounts pins the failing-wide matches TestFinding_ScopedLimits cannot reach through a
// dependency fixture: the Go toolchain subject, which a limit reaches only by naming it, and a Go
// package-path admission.
func TestScopedLimitCounts(t *testing.T) {
	stdlib := pkgKey{typ: "golang", name: "stdlib"}
	http2 := pkgKey{typ: "golang", name: "golang.org/x/net/http2"}
	cases := []struct {
		name     string
		flag     artifact.ScopedPartialityFlag
		admitted pkgKey
		want     bool
	}{
		{"stdlib: a limit naming the stdlib counts", artifact.ScopedPartialityFlag{Reason: "cgo", Package: "pkg:golang/golang.org/x/text", Targets: []string{"", "pkg:golang/golang.org/x/text", "pkg:golang/stdlib"}}, stdlib, true},
		{"stdlib: a limit held by the stdlib counts", artifact.ScopedPartialityFlag{Reason: "cgo", Package: "pkg:golang/stdlib", Targets: []string{"pkg:golang/golang.org/x/text"}}, stdlib, true},
		{"stdlib: another Go module's target does not count", artifact.ScopedPartialityFlag{Reason: "cgo", Package: "pkg:golang/github.com/mattn/go-sqlite3", Targets: []string{"pkg:golang/github.com/mattn/go-sqlite3", "pkg:golang/golang.org/x/text"}}, stdlib, false},
		{"stdlib: a first-party target does not count", artifact.ScopedPartialityFlag{Reason: "cgo", Targets: []string{""}}, stdlib, false},
		{"stdlib: a first-party package does not count", artifact.ScopedPartialityFlag{Reason: "cgo", Targets: []string{"pkg:npm/lodash"}}, stdlib, false},
		{"stdlib: another ecosystem's targets do not count", artifact.ScopedPartialityFlag{Reason: "tool_failure", Package: "pkg:npm/lodash", Targets: []string{"pkg:npm/lodash"}}, stdlib, false},
		{"stdlib: a malformed target counts", artifact.ScopedPartialityFlag{Reason: "cgo", Package: "pkg:golang/golang.org/x/text", Targets: []string{"golang.org/x/text"}}, stdlib, true},
		{"module admitted, a module nested under it targeted", artifact.ScopedPartialityFlag{Reason: "cgo", Package: "pkg:golang/golang.org/x/tools/gopls", Targets: []string{"pkg:golang/golang.org/x/tools/gopls"}}, pkgKey{typ: "golang", name: "golang.org/x/tools"}, true},
		{"package path admitted, its module targeted", artifact.ScopedPartialityFlag{Reason: "cgo", Package: "pkg:golang/golang.org/x/text", Targets: []string{"pkg:golang/golang.org/x/net"}}, http2, true},
		{"module paths sharing a prefix but not a path boundary", artifact.ScopedPartialityFlag{Reason: "cgo", Package: "pkg:golang/golang.org/x/text", Targets: []string{"pkg:golang/golang.org/x/netx"}}, pkgKey{typ: "golang", name: "golang.org/x/net"}, false},
		{"a module path in another case", artifact.ScopedPartialityFlag{Reason: "cgo", Package: "pkg:golang/golang.org/x/text", Targets: []string{"pkg:golang/github.com/BurntSushi/toml"}}, pkgKey{typ: "golang", name: "github.com/burntsushi/toml"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scopedLimitCounts(tc.flag, tc.admitted, true, false); got != tc.want {
				t.Errorf("scopedLimitCounts(%+v, %v) = %v, want %v", tc.flag, tc.admitted, got, tc.want)
			}
		})
	}
}

const rootSink = "scip-python python apache-airflow 2.9.0 airflow/api/client/trigger_dag()."

// rootSearched is arm A for an advisory against the scanned project itself: the lane resolved the
// advisory symbol to first-party code and searched it without reaching it.
func rootSearched() groundsFixture {
	return groundsFixture{
		pkg:             &report.Package{Ecosystem: "PyPI", Name: "apache-airflow", Version: "2.9.0", PURL: "pkg:pypi/apache-airflow@2.9.0", Root: true},
		advisoryPURL:    "pkg:pypi/apache-airflow",
		advisorySymbols: []string{"airflow.api.client.trigger_dag"},
		resolution: plugin.SymbolResolutionResult{
			Partiality: plugin.Complete(),
			Resolved:   []plugin.Symbol{{SCIP: rootSink}},
			Matched:    map[string][]string{"airflow.api.client.trigger_dag": {rootSink}},
		},
		reach: plugin.ReachabilityResult{Partiality: plugin.Complete(), Searched: []string{rootSink}},
	}
}

// TestFinding_RootPackage: when the advisory's package is the scanned project, first-party code is
// that package, for arm A and for scoped limits alike; for any other package it never is.
func TestFinding_RootPackage(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(*groundsFixture)
		wantReason string // "" = not_exploitable
	}{
		{name: "first-party sink searched", mutate: func(*groundsFixture) {}},
		{
			name:       "the same sink when the package is a dependency",
			mutate:     func(fx *groundsFixture) { fx.pkg.Root = false },
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name:       "first-party sink not searched",
			mutate:     func(fx *groundsFixture) { fx.reach.Searched = nil },
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name:       "the match lives in a dependency",
			mutate:     func(fx *groundsFixture) { fx.resolution.Origins = map[string]string{rootSink: "pkg:pypi/flask"} },
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "a first-party scoped limit counts",
			mutate: func(fx *groundsFixture) {
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: plugin.PartialReasonCgo, Path: "airflow/native", Targets: []string{""}}}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name: "a limit bounded to a dependency does not",
			mutate: func(fx *groundsFixture) {
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: plugin.PartialReasonCgo, Package: "pkg:pypi/flask", Targets: []string{"pkg:pypi/flask"}}}
			},
		},
		{
			name: "a refutation naming no package is not grounds",
			mutate: func(fx *groundsFixture) {
				fx.reach.Searched = nil
				fx.reach.Refutation = &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Detail: "no path reaches it"}
			},
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "package_not_loaded naming the project itself is not grounds",
			mutate: func(fx *groundsFixture) {
				fx.affected = []string{"pkg:pypi/apache-airflow"}
				fx.reach.Searched = nil
				fx.reach.Refutation = refutation("pkg:pypi/apache-airflow")
			},
			wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name:       "no version",
			mutate:     func(fx *groundsFixture) { fx.pkg.Version = "" },
			wantReason: report.ReasonPackageVersionUnresolved,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := rootSearched()
			tc.mutate(&fx)
			f := fx.finding(t)
			if tc.wantReason != "" {
				if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != tc.wantReason {
					t.Fatalf("got %s/%q, want undetermined/%q", f.Verdict, f.UndeterminedReason, tc.wantReason)
				}
				return
			}
			if f.Verdict != report.VerdictNotExploitable {
				t.Fatalf("got %s/%q, want not_exploitable", f.Verdict, f.UndeterminedReason)
			}
		})
	}
}
