package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// gogsOutsideBuild is CVE-2024-55947's shape: a first-party Gogs advisory on gogs.io/gogs/internal/db,
// scanned in a build whose modules none hold it, and whose every module the lane read without
// finding UpdateRepoFile. govulncheck has no finding for a module outside the graph it loads, so
// the Go lane declares advisory_unknown_to_analyzer on reachability, and the pipeline harvests it
// into the footprint.
func gogsOutsideBuild() groundsFixture {
	return groundsFixture{
		advisoryPURL:    "pkg:golang/gogs.io/gogs/internal/db",
		advisorySymbols: []string{"UpdateRepoFile"},
		resolution: plugin.SymbolResolutionResult{
			Partiality: plugin.Complete(),
			ModuleSearch: &plugin.ModuleSearch{
				Searched: []string{"example.com/app", "example.com/fork", "golang.org/x/net", "example.com/a"},
			},
		},
		reach:     plugin.ReachabilityResult{Partiality: plugin.Partial(plugin.PartialReasonAdvisoryUnknownToAnalyzer)},
		footprint: []string{plugin.PartialReasonAdvisoryUnknownToAnalyzer},
		mods:      goModules{"example.com/app": true, "golang.org/x/net": true, "example.com/a": true, "example.com/fork": true},
	}
}

func TestFinding_OutsideBuildGrounds(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(*groundsFixture)
		wantNE     bool
		wantReason string // checked when set
	}{
		{"every module read, none declares the symbol", func(*groundsFixture) {}, true, ""},
		{"a module the lane could not read", func(fx *groundsFixture) {
			fx.resolution.ModuleSearch.Searched = []string{"example.com/app", "example.com/a", "example.com/fork"}
		}, false, ""},
		{"a replacement module the lane could not read", func(fx *groundsFixture) {
			fx.resolution.ModuleSearch.Searched = []string{"example.com/app", "example.com/a", "golang.org/x/net"}
		}, false, ""},
		{"a module declares the symbol", func(fx *groundsFixture) {
			fx.resolution.ModuleSearch.Declaring = []string{"example.com/a"}
		}, false, ""},
		{"no module search", func(fx *groundsFixture) { fx.resolution.ModuleSearch = nil }, false, ""},
		{"no complete module list", func(fx *groundsFixture) { fx.mods = nil }, false, ""},
		{"a module of the build holds the advisory's package", func(fx *groundsFixture) {
			fx.mods["gogs.io/gogs"] = true
			fx.resolution.ModuleSearch.Searched = append(fx.resolution.ModuleSearch.Searched, "gogs.io/gogs")
		}, false, ""},
		{"no advisory symbols", func(fx *groundsFixture) { fx.advisorySymbols = nil }, false, ""},
		{"the advisory names another package", func(fx *groundsFixture) {
			fx.affected = []string{"pkg:golang/gogs.io/gogs/internal/db", "pkg:golang/gogs.io/gogs/internal/route"}
		}, false, ""},
		{"the advisory names the same package again", func(fx *groundsFixture) {
			fx.affected = []string{"pkg:golang/gogs.io/gogs/internal/db@v0.13.0"}
		}, true, ""},
		{"an advisory package that does not parse", func(fx *groundsFixture) { fx.dropped = []string{"gogs.io/gogs"} }, false, ""},
		{"a standard library advisory", func(fx *groundsFixture) { fx.advisoryPURL = "pkg:golang/stdlib" }, false, ""},
		{"another ecosystem", func(fx *groundsFixture) { fx.advisoryPURL = "pkg:npm/gogs" }, false, ""},
		{"the run loads Go code the build never compiled", func(fx *groundsFixture) {
			fx.footprint = append(fx.footprint, plugin.PartialReasonPluginLoad)
		}, false, ""},
		{"another step did not run", func(fx *groundsFixture) {
			fx.footprint = append(fx.footprint, plugin.PartialReasonToolFailure)
		}, false, ""},
		{"a call graph that is empty and not called complete", func(fx *groundsFixture) {
			fx.callGraph = &plugin.CallGraphResult{Partiality: plugin.Partial(plugin.PartialReasonToolFailure)}
		}, false, report.ReasonAnalysisDidNotRun},
		{"a scoped limit on the build", func(fx *groundsFixture) {
			fx.scoped = []artifact.ScopedPartialityFlag{{Reason: plugin.PartialReasonPluginLoad, Package: "pkg:golang/example.com/a"}}
		}, false, ""},
		{"a package was resolved for the advisory", func(fx *groundsFixture) {
			fx.pkg = &report.Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.15.0", PURL: "pkg:golang/golang.org/x/net@v0.15.0"}
		}, false, ""},
		{"a curated symbol set", func(fx *groundsFixture) { fx.provenance = "curated" }, true, ""},
		{"an untagged built-in symbol set", func(fx *groundsFixture) { fx.untagged, fx.builtIn = true, true }, true, ""},
		{"an untagged corpus symbol set", func(fx *groundsFixture) { fx.untagged = true },
			false, report.ReasonAdvisorySymbolsUnvetted},
		{"a diff-lexed symbol set", func(fx *groundsFixture) { fx.provenance = "diff-lexed" },
			false, report.ReasonAdvisorySymbolsUnvetted},
		{"a cna-declared symbol set", func(fx *groundsFixture) { fx.provenance = "cna-declared" },
			false, report.ReasonAdvisorySymbolsUnvetted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := gogsOutsideBuild()
			tc.mutate(&fx)
			f := fx.finding(t)
			if !tc.wantNE {
				if f.Verdict == report.VerdictNotExploitable {
					t.Fatalf("got not_exploitable (%s), want it withheld", f.Evidence.Detail)
				}
				if tc.wantReason != "" && (f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != tc.wantReason) {
					t.Fatalf("got %s/%q, want undetermined/%q", f.Verdict, f.UndeterminedReason, tc.wantReason)
				}
				return
			}
			if f.Verdict != report.VerdictNotExploitable || f.Evidence.Basis != verdict.BasisSymbolAbsent {
				t.Fatalf("got %s/%q basis %q, want not_exploitable/symbol-absent", f.Verdict, f.UndeterminedReason, f.Evidence.Basis)
			}
			if f.Package != nil {
				t.Errorf("Package = %+v, want none", f.Package)
			}
			const want = "no module in the build holds gogs.io/gogs/internal/db, and none of the build's 4 modules declares UpdateRepoFile"
			if f.Evidence.Detail != want {
				t.Errorf("Detail = %q, want %q", f.Evidence.Detail, want)
			}
		})
	}
}

// TestFinding_OutsideBuildLimits pins which did-not-run limits outside-build grounds stand beside: a
// limit of the path search does not touch the module list or the module source reads they rest on,
// and every other limit, one this version does not know included, holds the advisory undetermined.
func TestFinding_OutsideBuildLimits(t *testing.T) {
	cases := []struct {
		name       string
		limits     []string // declared beside the lane's advisory_unknown_to_analyzer
		wantNE     bool
		wantReason string // checked when !wantNE
	}{
		{"the lane's own limit alone", nil, true, ""},
		{"a reflective call", []string{plugin.PartialReasonReflectiveCall}, true, ""},
		{"files the build left out", []string{plugin.PartialReasonExcludedFiles}, true, ""},
		{"every exempt limit", []string{plugin.PartialReasonReflectiveCall, plugin.PartialReasonExcludedFiles}, true, ""},
		{"a plugin load", []string{plugin.PartialReasonPluginLoad}, false, report.ReasonAnalysisDidNotRun},
		{"a tool failure", []string{plugin.PartialReasonToolFailure}, false, report.ReasonAnalysisDidNotRun},
		{"a limit this version does not know", []string{"future_limit"}, false, report.ReasonAnalysisDidNotRun},
		{"an exempt limit beside a blocking one", []string{plugin.PartialReasonReflectiveCall, plugin.PartialReasonToolFailure},
			false, report.ReasonAnalysisDidNotRun},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := gogsOutsideBuild()
			fx.footprint = append(fx.footprint, tc.limits...)
			f := fx.finding(t)
			if !tc.wantNE {
				if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != tc.wantReason {
					t.Fatalf("got %s/%q (%s), want undetermined/%q", f.Verdict, f.UndeterminedReason, f.Evidence.Detail, tc.wantReason)
				}
				return
			}
			if f.Verdict != report.VerdictNotExploitable || f.Evidence.Basis != verdict.BasisSymbolAbsent {
				t.Fatalf("got %s/%q basis %q, want not_exploitable/symbol-absent", f.Verdict, f.UndeterminedReason, f.Evidence.Basis)
			}
		})
	}
}

// TestFinding_OutsideBuildLimitsScoped: the exemption speaks only for outside-build grounds. An
// advisory the build holds, under the same limits, rests on a path search those limits undermine.
func TestFinding_OutsideBuildLimitsScoped(t *testing.T) {
	limits := []string{plugin.PartialReasonAdvisoryUnknownToAnalyzer, plugin.PartialReasonReflectiveCall, plugin.PartialReasonExcludedFiles}
	cases := []struct {
		name    string
		fixture func() groundsFixture
	}{
		{"a module of the build holds the advisory's package", func() groundsFixture {
			fx := gogsOutsideBuild()
			fx.mods["gogs.io/gogs"] = true
			fx.resolution.ModuleSearch.Searched = append(fx.resolution.ModuleSearch.Searched, "gogs.io/gogs")
			return fx
		}},
		{"a package was resolved for the advisory", func() groundsFixture {
			fx := gogsOutsideBuild()
			fx.pkg = &report.Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.15.0", PURL: "pkg:golang/golang.org/x/net@v0.15.0"}
			return fx
		}},
		{"an in-package search that reached nothing", yamlSearched},
	}
	for _, tc := range cases {
		for _, limit := range limits {
			t.Run(tc.name+"/"+limit, func(t *testing.T) {
				fx := tc.fixture()
				fx.footprint = []string{limit}
				f := fx.finding(t)
				if f.Verdict != report.VerdictUndetermined {
					t.Fatalf("got %s (%s), want undetermined", f.Verdict, f.Evidence.Detail)
				}
			})
		}
	}
}
