package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// dockerBesideMoby is the traefik shape of CVE-2026-33997 and CVE-2026-34040: an advisory on
// github.com/docker/docker that also names github.com/moby/moby and github.com/moby/moby/v2, with no
// symbols, in a build that selects docker/docker and neither moby module, and that govulncheck refuted
// at module level. The checkout also holds a test module the build root's graph does not include.
func dockerBesideMoby() groundsFixture {
	return groundsFixture{
		pkg: &report.Package{Ecosystem: "Go", Name: "github.com/docker/docker", Version: "v28.5.2+incompatible",
			PURL: "pkg:golang/github.com/docker/docker@v28.5.2+incompatible"},
		advisoryPURL: "pkg:golang/github.com/docker/docker",
		affected: []string{"pkg:golang/github.com/docker/docker", "pkg:golang/github.com/moby/moby",
			"pkg:golang/github.com/moby/moby/v2"},
		resolution: plugin.SymbolResolutionResult{Partiality: plugin.Complete()},
		reach: plugin.ReachabilityResult{
			Partiality: plugin.Complete(),
			Refutation: &plugin.Refutation{
				Basis:   plugin.RefutationAnalyzerSymbolNotReached,
				Package: "pkg:golang/github.com/docker/docker",
				Detail:  "govulncheck matched the advisory to github.com/docker/docker and a vulnerable package is not imported",
			},
		},
	}
}

// TestFinding_NestedModuleKeepsBuildList pins which nested-module limits leave the build's module
// list whole. A nested module whose limit names it and all it requires is resolved apart from the
// build, so the build root's list still rules a module out; the modules it names join that list, so
// one the nested module requires is never ruled out on the root's behalf. Any other nested-module
// limit, or any other Go limit beside it, leaves the list unknown, as before; an unbounded one also
// withholds every row on its own.
func TestFinding_NestedModuleKeepsBuildList(t *testing.T) {
	const dir = "pkg/plugins/fixtures/withoutsocket"
	bounded := func(requires ...string) plugin.ScopedReason {
		r := plugin.ScopedReason{Reason: plugin.PartialReasonNestedModule, Path: dir, Targets: []string{"pkg:golang/withoutsocket"}}
		for _, p := range requires {
			r.Targets = append(r.Targets, "pkg:golang/"+p)
		}
		return r
	}
	cases := []struct {
		name    string
		reasons []string // run-wide inventory reasons
		scoped  []plugin.ScopedReason
		want    string // the undetermined reason; "" = not_exploitable
	}{
		{"no nested module", nil, nil, ""},
		{"a bounded nested module requiring another module", nil,
			[]plugin.ScopedReason{bounded("github.com/http-wasm/http-wasm-guest-tinygo")}, ""},
		{"a bounded nested module requiring a module the advisory names", nil,
			[]plugin.ScopedReason{bounded("github.com/moby/moby")}, report.ReasonAdvisorySymbolAbsent},
		{"a bounded nested module requiring a package path the advisory names", nil,
			[]plugin.ScopedReason{bounded("github.com/moby/moby/v2")}, report.ReasonAdvisorySymbolAbsent},
		{"a nested module with an older go.mod, so no targets", nil,
			[]plugin.ScopedReason{{Reason: plugin.PartialReasonNestedModule, Path: dir}}, report.ReasonAnalysisDidNotRun},
		{"a walk of the checkout that did not finish", []string{plugin.PartialReasonNestedModule},
			[]plugin.ScopedReason{bounded("github.com/http-wasm/http-wasm-guest-tinygo")}, report.ReasonAdvisorySymbolAbsent},
		{"a bounded nested module beside another Go limit", []string{plugin.PartialReasonToolFailure},
			[]plugin.ScopedReason{bounded("github.com/http-wasm/http-wasm-guest-tinygo")}, report.ReasonAdvisorySymbolAbsent},
		{"a bounded nested module beside an unbounded one", nil,
			[]plugin.ScopedReason{bounded("github.com/http-wasm/http-wasm-guest-tinygo"), {Reason: plugin.PartialReasonNestedModule, Path: "tools"}}, report.ReasonAnalysisDidNotRun},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			part := plugin.Complete()
			if len(tc.reasons) > 0 || len(tc.scoped) > 0 {
				part = plugin.Partial(tc.reasons...)
				part.Scoped = tc.scoped
			}
			inv := plugin.DependencyInventory{
				Partiality: part,
				BuildList:  plugin.BuildListGoModGraph,
				MainModule: "github.com/traefik/traefik/v3",
				Nodes: []plugin.DependencyNode{{ID: "docker", PURL: "pkg:golang/github.com/docker/docker@v28.5.2+incompatible",
					Version: "v28.5.2+incompatible", Partiality: plugin.Complete()}},
			}
			sbom, notes := sbomFromInventory(inv, "Go")
			fx := dockerBesideMoby()
			fx.mods = goModulesOf(sbom, notes)
			for _, s := range tc.scoped {
				fx.scoped = append(fx.scoped, artifact.ScopedPartialityFlag{Reason: s.Reason, Path: s.Path, Targets: s.Targets})
			}
			f := fx.finding(t)
			if tc.want != "" {
				if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != tc.want {
					t.Fatalf("got %s/%q (%s), want undetermined/%q", f.Verdict, f.UndeterminedReason, f.Evidence.Detail, tc.want)
				}
				return
			}
			if f.Verdict != report.VerdictNotExploitable {
				t.Fatalf("got %s/%q, want not_exploitable", f.Verdict, f.UndeterminedReason)
			}
			const want = "github.com/docker/docker@v28.5.2+incompatible: govulncheck matched the advisory to github.com/docker/docker and a vulnerable package is not imported (analyzer_symbol_not_reached)"
			if f.Evidence.Detail != want {
				t.Errorf("detail = %q, want %q", f.Evidence.Detail, want)
			}
		})
	}
}
