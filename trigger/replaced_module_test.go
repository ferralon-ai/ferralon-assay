package trigger

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// replacedFixture is the kubeedge shape of the k8s.io/kubernetes rows: a dependency the build
// compiles from a fork through a replace directive, so its version never resolves and the row has
// no package. Both advisory symbols resolved to the module's compiled code and were searched.
type replacedFixture struct {
	inv        map[string]any
	symbols    []string
	provenance string
	purls      []map[string]string
	res        plugin.SymbolResolutionResult
	searched   []string
	flags      []string
	mods       goModules
}

const (
	rmPURL     = "pkg:golang/k8s.io/kubernetes"
	rmOrigin   = "pkg:golang/k8s.io/kubernetes@v1.32.10"
	rmSymA     = "k8s.io/kubernetes/pkg/kubelet.(*Kubelet).HandlePodAdditions"
	rmSymB     = "k8s.io/kubernetes/pkg/volume.NewSpecFromVolume"
	rmSCIPA    = "scip-go gomod k8s.io/kubernetes v1.32.10 pkg/kubelet/Kubelet#HandlePodAdditions()."
	rmSCIPB    = "scip-go gomod k8s.io/kubernetes v1.32.10 pkg/volume/NewSpecFromVolume()."
	rmForkPath = "github.com/kubeedge/kubernetes"
	rmForkVer  = "v1.32.10-kubeedge1"
)

func newReplacedFixture() replacedFixture {
	return replacedFixture{
		inv: map[string]any{
			"partiality_flags": []string{plugin.PartialReasonSourceUnpinned},
			"replaced_by":      map[string]any{"path": rmForkPath, "version": rmForkVer},
		},
		symbols:    []string{rmSymA, rmSymB},
		provenance: "osv-declared",
		res: plugin.SymbolResolutionResult{
			Partiality: plugin.Complete(),
			Resolved:   []plugin.Symbol{{SCIP: rmSCIPA}, {SCIP: rmSCIPB}},
			Origins:    map[string]string{rmSCIPA: rmOrigin, rmSCIPB: rmOrigin},
			Matched:    map[string][]string{rmSymA: {rmSCIPA}, rmSymB: {rmSCIPB}},
		},
		searched: []string{rmSCIPA, rmSCIPB},
		flags:    []string{plugin.PartialReasonSourceUnpinned},
		mods:     goModules{"k8s.io/kubernetes": true, rmForkPath: true, "github.com/kubeedge/kubeedge": true},
	}
}

func (fx replacedFixture) finding(t *testing.T) report.AdvisoryFinding {
	t.Helper()
	store := artifact.NewMemStore()
	const aid = "kubeedge-k8s"
	putJSON(t, store, aid, artifact.TypeInventory, fx.inv)
	adv := map[string]any{"purl": rmPURL, "advisory_symbols": fx.symbols, "symbol_provenance": fx.provenance}
	if fx.purls != nil {
		adv["affected_packages"] = fx.purls
	}
	putJSON(t, store, aid, artifact.TypeNormalizedAdvisory, adv)
	putJSON(t, store, aid, artifact.TypeVulnerableSymbol, fx.res)
	seedFootprint(t, store, aid, fx.flags)
	part := plugin.Complete()
	if len(fx.flags) > 0 {
		part = plugin.Partial(fx.flags...)
	}
	seedReachArtifact(t, store, aid,
		plugin.CallGraphResult{
			Partiality: plugin.Complete(),
			Edges:      []plugin.CallEdge{depEdge("github.com/kubeedge/kubeedge/cmd.main", "github.com/kubeedge/kubeedge/edge.Run")},
		},
		plugin.ReachabilityResult{Partiality: part, Searched: fx.searched})
	return findingInBuild(store, aid, report.Advisory{ID: "GO-2026-0001", Source: "osv"}, nil, fx.mods)
}

const (
	rmForkHead = "The build compiles k8s.io/kubernetes from " + rmForkPath + " " + rmForkVer +
		", code no release of k8s.io/kubernetes describes, so the advisory's affected versions do not place it. "
	rmForkTail = " It is settled by building k8s.io/kubernetes from a release the advisory's ranges place, " +
		"or by finding the advisory's vulnerable functions in the replacement's code with no path reaching them."
)

// TestFinding_ReplacedModule pins ferralon-ai/tracker#811's fork rows. A dependency the build
// compiles from a fork or a local directory is judged on that compiled code: not_exploitable only
// when every vetted advisory symbol resolved to the module's code and no path reaches any of them.
// The fork's version string is never compared against the advisory's ranges. Every other row stays
// package_version_unresolved, with a detail naming the fork, why it was not judged, and what would
// settle it.
func TestFinding_ReplacedModule(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*replacedFixture)
		detail string // not_exploitable detail; "" = held
		reason string
		why    string // held detail's middle clause
	}{
		{"every symbol defined in the fork and unreached", func(*replacedFixture) {},
			"no path from any entry point reaches " + rmSymA + ", " + rmSymB + " in k8s.io/kubernetes, which the build compiles from " +
				rmForkPath + " " + rmForkVer + "; that code defines each of them", "", ""},
		{"a local directory replacement", func(fx *replacedFixture) {
			fx.inv["replaced_by"] = map[string]any{"path": "../staging/kubernetes", "directory": true}
		}, "no path from any entry point reaches " + rmSymA + ", " + rmSymB + " in k8s.io/kubernetes, which the build compiles from " +
			"the local directory ../staging/kubernetes; that code defines each of them", "", ""},
		// A fork's version string reads like a release inside the advisory's ranges; it is never used.
		{"the fork's version is never compared", func(fx *replacedFixture) {
			fx.inv["replaced_by"] = map[string]any{"path": rmForkPath, "version": "v0.0.1"}
		}, "no path from any entry point reaches " + rmSymA + ", " + rmSymB + " in k8s.io/kubernetes, which the build compiles from " +
			rmForkPath + " v0.0.1; that code defines each of them", "", ""},

		{"a symbol the fork does not define", func(fx *replacedFixture) {
			delete(fx.res.Matched, rmSymB)
			fx.res.Resolved, fx.searched = fx.res.Resolved[:1], fx.searched[:1]
		}, "", report.ReasonPackageVersionUnresolved,
			"The build's code of k8s.io/kubernetes does not define " + rmSymB + ". A replacement can rename or move the vulnerable code, so that is not taken as a fix."},
		{"a symbol defined only outside the module", func(fx *replacedFixture) {
			fx.res.Origins[rmSCIPB] = "pkg:golang/github.com/other/mod@v1.0.0"
		}, "", report.ReasonPackageVersionUnresolved,
			"The build's code of k8s.io/kubernetes does not define " + rmSymB + ". A replacement can rename or move the vulnerable code, so that is not taken as a fix."},
		{"no symbol resolved", func(fx *replacedFixture) {
			fx.res.Matched, fx.res.Resolved, fx.res.Origins, fx.searched = nil, nil, nil, nil
		}, "", report.ReasonPackageVersionUnresolved,
			"The build's code of k8s.io/kubernetes does not define " + rmSymA + ", " + rmSymB + ". A replacement can rename or move the vulnerable code, so that is not taken as a fix."},
		{"a defined symbol not searched", func(fx *replacedFixture) { fx.searched = fx.searched[:1] }, "", report.ReasonPackageVersionUnresolved,
			"The analysis did not search every definition of " + rmSymA + ", " + rmSymB + " from the entry points."},
		{"an unvetted symbol set", func(fx *replacedFixture) { fx.provenance = "diff-lexed" }, "", report.ReasonPackageVersionUnresolved,
			"The advisory's vulnerable symbols are not a vetted set, so their absence from every path is not evidence."},
		{"no advisory symbols", func(fx *replacedFixture) { fx.symbols = nil }, "", report.ReasonPackageVersionUnresolved,
			"The advisory names no vulnerable symbol to look for in that code."},
		{"the advisory names another package in the build", func(fx *replacedFixture) {
			fx.purls = []map[string]string{{"purl": "pkg:golang/k8s.io/apiserver"}}
			fx.mods["k8s.io/apiserver"] = true
		}, "", report.ReasonPackageVersionUnresolved,
			"The advisory also names a package the build may hold, so that code alone does not settle it."},
		{"another step did not run", func(fx *replacedFixture) { fx.flags = append(fx.flags, plugin.PartialReasonToolFailure) },
			"", report.ReasonPackageVersionUnresolved,
			"Steps an analysis of that code rests on did not run, so it was not judged."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newReplacedFixture()
			tt.mutate(&fx)
			f := fx.finding(t)
			if tt.detail == "" {
				if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != tt.reason {
					t.Fatalf("verdict = %q reason %q (%s), want undetermined/%q", f.Verdict, f.UndeterminedReason, f.Evidence.Detail, tt.reason)
				}
				head := rmForkHead
				if !strings.HasPrefix(f.Evidence.Detail, head) || !strings.HasSuffix(f.Evidence.Detail, rmForkTail) {
					t.Fatalf("detail = %q, want the fork head and tail", f.Evidence.Detail)
				}
				if got := strings.TrimSuffix(strings.TrimPrefix(f.Evidence.Detail, head), rmForkTail); got != tt.why {
					t.Errorf("why = %q, want %q", got, tt.why)
				}
				return
			}
			if f.Verdict != report.VerdictNotExploitable || f.Evidence.Basis != verdict.BasisSymbolUnreachable {
				t.Fatalf("verdict = %q basis %q (reason %q: %s), want not_exploitable on %q",
					f.Verdict, f.Evidence.Basis, f.UndeterminedReason, f.Evidence.Detail, verdict.BasisSymbolUnreachable)
			}
			if f.Evidence.Detail != tt.detail {
				t.Errorf("detail = %q, want %q", f.Evidence.Detail, tt.detail)
			}
		})
	}
}

// TestFinding_ReplacedModuleOnlyForForkRows pins that the fork path is taken only for a dependency's
// row with no package and a recorded replacement: the scanned module itself, a row that carries a
// package, and a dependency with no replacement keep today's reasons and details.
func TestFinding_ReplacedModuleOnlyForForkRows(t *testing.T) {
	t.Run("no replacement recorded", func(t *testing.T) {
		fx := newReplacedFixture()
		delete(fx.inv, "replaced_by")
		f := fx.finding(t)
		if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != report.ReasonPackageVersionUnresolved {
			t.Fatalf("got %s/%q, want undetermined/%q", f.Verdict, f.UndeterminedReason, report.ReasonPackageVersionUnresolved)
		}
		if strings.Contains(f.Evidence.Detail, "The build compiles") {
			t.Errorf("detail = %q, want no fork detail", f.Evidence.Detail)
		}
	})
	t.Run("the scanned module itself", func(t *testing.T) {
		fx := newReplacedFixture()
		fx.inv["root"] = true
		f := fx.finding(t)
		if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != report.ReasonOwnReleaseVersionUnknown {
			t.Fatalf("got %s/%q, want undetermined/%q", f.Verdict, f.UndeterminedReason, report.ReasonOwnReleaseVersionUnknown)
		}
	})
	t.Run("the row has a package", func(t *testing.T) {
		store := artifact.NewMemStore()
		pkg := &report.Package{Ecosystem: "Go", Name: "k8s.io/kubernetes", Version: "v1.32.10", PURL: rmOrigin}
		if _, ok := moduleReplacement(store, "x", pkg); ok {
			t.Fatal("moduleReplacement held for a row with a package")
		}
	})
}
