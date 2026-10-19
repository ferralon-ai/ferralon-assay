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
// finding UpdateRepoFile.
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
		reach: plugin.ReachabilityResult{Partiality: plugin.Complete()},
		mods:  goModules{"example.com/app": true, "golang.org/x/net": true, "example.com/a": true, "example.com/fork": true},
	}
}

func TestFinding_OutsideBuildGrounds(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*groundsFixture)
		wantNE bool
	}{
		{"every module read, none declares the symbol", func(*groundsFixture) {}, true},
		{"a module the lane could not read", func(fx *groundsFixture) {
			fx.resolution.ModuleSearch.Searched = []string{"example.com/app", "example.com/a", "example.com/fork"}
		}, false},
		{"a replacement module the lane could not read", func(fx *groundsFixture) {
			fx.resolution.ModuleSearch.Searched = []string{"example.com/app", "example.com/a", "golang.org/x/net"}
		}, false},
		{"a module declares the symbol", func(fx *groundsFixture) {
			fx.resolution.ModuleSearch.Declaring = []string{"example.com/a"}
		}, false},
		{"no module search", func(fx *groundsFixture) { fx.resolution.ModuleSearch = nil }, false},
		{"no complete module list", func(fx *groundsFixture) { fx.mods = nil }, false},
		{"a module of the build holds the advisory's package", func(fx *groundsFixture) {
			fx.mods["gogs.io/gogs"] = true
			fx.resolution.ModuleSearch.Searched = append(fx.resolution.ModuleSearch.Searched, "gogs.io/gogs")
		}, false},
		{"no advisory symbols", func(fx *groundsFixture) { fx.advisorySymbols = nil }, false},
		{"the advisory names another package", func(fx *groundsFixture) {
			fx.affected = []string{"pkg:golang/gogs.io/gogs/internal/db", "pkg:golang/gogs.io/gogs/internal/route"}
		}, false},
		{"the advisory names the same package again", func(fx *groundsFixture) {
			fx.affected = []string{"pkg:golang/gogs.io/gogs/internal/db@v0.13.0"}
		}, true},
		{"an advisory package that does not parse", func(fx *groundsFixture) { fx.dropped = []string{"gogs.io/gogs"} }, false},
		{"a standard library advisory", func(fx *groundsFixture) { fx.advisoryPURL = "pkg:golang/stdlib" }, false},
		{"another ecosystem", func(fx *groundsFixture) { fx.advisoryPURL = "pkg:npm/gogs" }, false},
		{"the run loads Go code the build never compiled", func(fx *groundsFixture) {
			fx.footprint = []string{plugin.PartialReasonPluginLoad}
		}, false},
		{"another step did not run", func(fx *groundsFixture) {
			fx.footprint = []string{plugin.PartialReasonToolFailure}
		}, false},
		{"a scoped limit on the build", func(fx *groundsFixture) {
			fx.scoped = []artifact.ScopedPartialityFlag{{Reason: plugin.PartialReasonPluginLoad, Package: "pkg:golang/example.com/a"}}
		}, false},
		{"a package was resolved for the advisory", func(fx *groundsFixture) {
			fx.pkg = &report.Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.15.0", PURL: "pkg:golang/golang.org/x/net@v0.15.0"}
		}, false},
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
