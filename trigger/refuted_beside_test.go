package trigger

import (
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

func unreached(purl, detail string, assumptions ...string) plugin.Refutation {
	return plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: purl, Detail: detail, Assumptions: assumptions}
}

func notImported(purl, detail string, assumptions ...string) plugin.Refutation {
	return plugin.Refutation{Basis: plugin.RefutationAnalyzerPackageNotImported, Package: purl, Detail: detail, Assumptions: assumptions}
}

// TestFinding_RefutedBeside is an advisory that names two packages of the build: the admitted
// package's refutation grounds only when the lane refuted the other package too, on a basis and
// under conditions that hold for that package.
func TestFinding_RefutedBeside(t *testing.T) {
	const (
		xnet   = "pkg:golang/golang.org/x/net"
		stdlib = "pkg:golang/stdlib"
		tools  = "pkg:golang/toolchain"
		v3     = "pkg:golang/github.com/distribution/distribution/v3"
		docker = "pkg:golang/github.com/docker/distribution"
	)
	xnetPkg := &report.Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.15.0", PURL: xnet + "@v0.15.0"}
	dockerPkg := &report.Package{Ecosystem: "Go", Name: "github.com/docker/distribution", Version: "v2.8.1", PURL: docker + "@v2.8.1"}
	exact := pipeline.ToolchainFact{Version: "go1.22.1", Bound: pipeline.ToolchainBoundExact, Source: pipeline.ToolchainSourceCIObserved}
	floor := pipeline.ToolchainFact{Version: "go1.22", Bound: pipeline.ToolchainBoundMinimum, Source: pipeline.ToolchainSourceCIObserved}
	tests := []struct {
		name       string
		pkg        *report.Package
		affected   []string
		mods       goModules
		reach      plugin.ReachabilityResult
		toolchain  pipeline.ToolchainFact
		scanned    bool
		scoped     []artifact.ScopedPartialityFlag
		flags      []string
		wantReason string // "" = not_exploitable
		wantDetail []string
		wantExact  string
		wantAssume []string
	}{
		{
			name: "stdlib refuted beside, subject toolchain scanned", pkg: xnetPkg, affected: []string{xnet, stdlib},
			mods: goModules{"golang.org/x/net": true},
			reach: plugin.ReachabilityResult{
				Refutation:  ptr(unreached(xnet, "x/net imported, no symbol called", "a1")),
				Refutations: []plugin.Refutation{unreached(stdlib, "stdlib imported, no symbol called", "a1", "a2")},
			},
			toolchain: exact, scanned: true,
			wantDetail: []string{"x/net imported, no symbol called", "also stdlib: stdlib imported, no symbol called"},
			wantAssume: []string{"a1", "a2"},
		},
		{
			name: "stdlib refuted beside, scan not under the subject toolchain", pkg: xnetPkg, affected: []string{xnet, stdlib},
			mods: goModules{"golang.org/x/net": true},
			reach: plugin.ReachabilityResult{
				Refutation:  ptr(unreached(xnet, "d")),
				Refutations: []plugin.Refutation{unreached(stdlib, "d")},
			},
			toolchain: exact, scanned: false, wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "stdlib refuted beside, toolchain known only as a floor", pkg: xnetPkg, affected: []string{xnet, stdlib},
			mods: goModules{"golang.org/x/net": true},
			reach: plugin.ReachabilityResult{
				Refutation:  ptr(unreached(xnet, "d")),
				Refutations: []plugin.Refutation{unreached(stdlib, "d")},
			},
			toolchain: floor, scanned: true, wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "other package not refuted", pkg: xnetPkg, affected: []string{xnet, stdlib},
			mods:      goModules{"golang.org/x/net": true},
			reach:     plugin.ReachabilityResult{Refutation: ptr(unreached(xnet, "d"))},
			toolchain: exact, scanned: true, wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "admitted package is the later module", pkg: dockerPkg, affected: []string{v3, docker},
			mods: goModules{"github.com/distribution/distribution/v3": true, "github.com/docker/distribution": true},
			reach: plugin.ReachabilityResult{
				Refutation:  ptr(unreached(v3, "v3 unreached", "a1")),
				Refutations: []plugin.Refutation{unreached(docker, "docker unreached", "a2")},
			},
			toolchain: exact, scanned: true,
			wantExact:  "github.com/docker/distribution@v2.8.1: docker unreached (analyzer_symbol_not_reached); also github.com/distribution/distribution/v3: v3 unreached (analyzer_symbol_not_reached)",
			wantAssume: []string{"a2", "a1"},
		},
		{
			name: "a refutation of a package the advisory does not name", pkg: dockerPkg, affected: []string{v3, docker},
			mods: goModules{"github.com/distribution/distribution/v3": true, "github.com/docker/distribution": true, "golang.org/x/net": true},
			reach: plugin.ReachabilityResult{
				Refutation:  ptr(unreached(v3, "v3 unreached")),
				Refutations: []plugin.Refutation{unreached(docker, "docker unreached"), unreached(xnet, "x/net unreached", "a3")},
			},
			toolchain: exact, scanned: true,
			wantExact:  "github.com/docker/distribution@v2.8.1: docker unreached (analyzer_symbol_not_reached); also github.com/distribution/distribution/v3: v3 unreached (analyzer_symbol_not_reached)",
			wantAssume: []string{},
		},
		{
			name: "toolchain refuted beside, scan not under the subject toolchain", pkg: xnetPkg, affected: []string{xnet, tools},
			mods: goModules{"golang.org/x/net": true},
			reach: plugin.ReachabilityResult{
				Refutation:  ptr(unreached(xnet, "d")),
				Refutations: []plugin.Refutation{unreached(tools, "d")},
			},
			toolchain: exact, scanned: false, wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "toolchain refuted beside, subject toolchain scanned", pkg: xnetPkg, affected: []string{xnet, tools},
			mods: goModules{"golang.org/x/net": true},
			reach: plugin.ReachabilityResult{
				Refutation:  ptr(unreached(xnet, "d")),
				Refutations: []plugin.Refutation{unreached(tools, "d")},
			},
			toolchain: exact, scanned: true,
		},
		{
			name: "other package refuted on a basis this gate does not weigh", pkg: dockerPkg, affected: []string{v3, docker},
			mods: goModules{"github.com/distribution/distribution/v3": true, "github.com/docker/distribution": true},
			reach: plugin.ReachabilityResult{
				Refutation:  &plugin.Refutation{Basis: plugin.RefutationPackageNotLoaded, Package: v3, Detail: "d"},
				Refutations: []plugin.Refutation{unreached(docker, "d")},
			},
			toolchain: exact, scanned: true, wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "other package refuted as not imported", pkg: dockerPkg, affected: []string{v3, docker},
			mods: goModules{"github.com/distribution/distribution/v3": true, "github.com/docker/distribution": true},
			reach: plugin.ReachabilityResult{
				Refutation:  ptr(notImported(v3, "v3 not imported", "a1")),
				Refutations: []plugin.Refutation{unreached(docker, "docker unreached", "a2")},
			},
			toolchain: exact, scanned: true,
			wantExact:  "github.com/docker/distribution@v2.8.1: docker unreached (analyzer_symbol_not_reached); also github.com/distribution/distribution/v3: v3 not imported (analyzer_package_not_imported)",
			wantAssume: []string{"a2", "a1"},
		},
		{
			name: "other package refuted as not imported, beside a file another platform builds", pkg: dockerPkg, affected: []string{v3, docker},
			mods: goModules{"github.com/distribution/distribution/v3": true, "github.com/docker/distribution": true},
			reach: plugin.ReachabilityResult{
				Refutation:  ptr(notImported(v3, "d")),
				Refutations: []plugin.Refutation{unreached(docker, "d")},
			},
			flags:     []string{plugin.PartialReasonExcludedFilesBuildConstraint},
			toolchain: exact, scanned: true, wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "other package unreached, beside a file another platform builds", pkg: dockerPkg, affected: []string{v3, docker},
			mods: goModules{"github.com/distribution/distribution/v3": true, "github.com/docker/distribution": true},
			reach: plugin.ReachabilityResult{
				Refutation:  ptr(unreached(v3, "d")),
				Refutations: []plugin.Refutation{unreached(docker, "d")},
			},
			flags:     []string{plugin.PartialReasonExcludedFilesBuildConstraint},
			toolchain: exact, scanned: true,
		},
		{
			name: "a did-not-run limit scoped to the other package", pkg: dockerPkg, affected: []string{v3, docker},
			mods: goModules{"github.com/distribution/distribution/v3": true, "github.com/docker/distribution": true},
			reach: plugin.ReachabilityResult{
				Refutation:  ptr(unreached(v3, "d")),
				Refutations: []plugin.Refutation{unreached(docker, "d")},
			},
			scoped:    []artifact.ScopedPartialityFlag{{Reason: plugin.PartialReasonExcludedFiles, Package: "pkg:golang/example.com/app", Targets: []string{v3}}},
			toolchain: exact, scanned: true, wantReason: report.ReasonVulnerableSymbolUnresolved,
		},
		{
			name: "a limit inherent to the analysis scoped to the other package", pkg: dockerPkg, affected: []string{v3, docker},
			mods: goModules{"github.com/distribution/distribution/v3": true, "github.com/docker/distribution": true},
			reach: plugin.ReachabilityResult{
				Refutation:  ptr(unreached(v3, "d")),
				Refutations: []plugin.Refutation{unreached(docker, "d")},
			},
			scoped:    []artifact.ScopedPartialityFlag{{Reason: plugin.PartialReasonReflection, Package: "pkg:golang/example.com/app", Targets: []string{v3}}},
			toolchain: exact, scanned: true,
		},
		{
			name: "a did-not-run limit scoped to a third package", pkg: dockerPkg, affected: []string{v3, docker},
			mods: goModules{"github.com/distribution/distribution/v3": true, "github.com/docker/distribution": true},
			reach: plugin.ReachabilityResult{
				Refutation:  ptr(unreached(v3, "d")),
				Refutations: []plugin.Refutation{unreached(docker, "d")},
			},
			scoped:    []artifact.ScopedPartialityFlag{{Reason: plugin.PartialReasonExcludedFiles, Package: "pkg:golang/example.com/app", Targets: []string{"pkg:golang/example.com/other"}}},
			toolchain: exact, scanned: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			const aid = "beside"
			affected := make([]map[string]string, 0, len(tt.affected))
			for _, p := range tt.affected {
				affected = append(affected, map[string]string{"purl": p})
			}
			purl, _, _ := strings.Cut(tt.pkg.PURL, "@")
			putJSON(t, store, aid, artifact.TypeNormalizedAdvisory, map[string]any{
				"purl": purl, "affected_packages": affected, "symbol_provenance": "osv-declared",
				"advisory_symbols": []string{"example.Symbol"},
			})
			putJSON(t, store, aid, artifact.TypeVulnerableSymbol, plugin.SymbolResolutionResult{Partiality: plugin.Complete()})
			tt.reach.Partiality = plugin.Complete()
			putJSON(t, store, aid, artifact.TypeReachability, map[string]any{
				"reachability":   tt.reach,
				"call_graph":     plugin.CallGraphResult{Partiality: plugin.Complete(), Edges: []plugin.CallEdge{depEdge("main", "lib")}},
				"toolchain_scan": pipeline.ToolchainScan{Requested: "go1.22.1", Actual: "go1.22.1", Subject: tt.scanned},
			})
			putJSON(t, store, aid, artifact.TypeInventory, map[string]any{"toolchain": tt.toolchain})
			if tt.scoped != nil || tt.flags != nil {
				putJSON(t, store, aid, artifact.TypeExposureFootprint, artifact.ExposureFootprintPayload{ScopedPartiality: tt.scoped, PartialityFlags: tt.flags})
			}
			f := findingInBuild(store, aid, report.Advisory{ID: "GO-test", Source: "corpus"}, tt.pkg, tt.mods)
			if tt.wantReason != "" {
				if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != tt.wantReason {
					t.Fatalf("got %s/%q, want undetermined/%q", f.Verdict, f.UndeterminedReason, tt.wantReason)
				}
				return
			}
			if f.Verdict != report.VerdictNotExploitable {
				t.Fatalf("got %s/%q, want not_exploitable", f.Verdict, f.UndeterminedReason)
			}
			for _, want := range tt.wantDetail {
				if !strings.Contains(f.Evidence.Detail, want) {
					t.Errorf("detail %q lacks %q", f.Evidence.Detail, want)
				}
			}
			if tt.wantExact != "" && f.Evidence.Detail != tt.wantExact {
				t.Errorf("detail = %q, want %q", f.Evidence.Detail, tt.wantExact)
			}
			if tt.wantAssume != nil && !slices.Equal(f.Evidence.Assumptions, tt.wantAssume) {
				t.Errorf("assumptions = %q, want %q", f.Evidence.Assumptions, tt.wantAssume)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

// TestFinding_SearchedSymbolAssumptions is a symbol search that grounds a package the lane refuted
// beside another: the row rests on that package's assumptions, not the other's.
func TestFinding_SearchedSymbolAssumptions(t *testing.T) {
	fx := yamlSearched()
	fx.reach.Refutation = ptr(unreached("pkg:pypi/first", "d", "first's assumption"))
	fx.reach.Refutations = []plugin.Refutation{unreached(fx.advisoryPURL, "d", "yaml's assumption")}
	f := fx.finding(t)
	if f.Verdict != report.VerdictNotExploitable {
		t.Fatalf("got %s/%q, want not_exploitable", f.Verdict, f.UndeterminedReason)
	}
	if want := []string{"yaml's assumption"}; !slices.Equal(f.Evidence.Assumptions, want) {
		t.Errorf("assumptions = %q, want %q", f.Evidence.Assumptions, want)
	}
}
