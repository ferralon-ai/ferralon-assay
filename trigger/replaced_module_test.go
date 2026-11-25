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
	refutation *plugin.Refutation
	scoped     []artifact.ScopedPartialityFlag
	graph      *plugin.CallGraphResult
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
	// rmSymV2 is qualified by a package of another major version, as GHSA-w73w-5m7g-f7qc names
	// github.com/dgrijalva/jwt-go/v4 beside github.com/dgrijalva/jwt-go.
	rmSymV2 = "k8s.io/kubernetes/v2/pkg/volume.NewSpecFromVolume"
)

// rmCgo is the Go lane's scoped cgo limit on package path of module mod.
func rmCgo(mod, path string) artifact.ScopedPartialityFlag {
	return artifact.ScopedPartialityFlag{Reason: plugin.PartialReasonCgo, Package: "pkg:golang/" + mod, Path: path, Targets: []string{rmPURL}}
}

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
	store, aid := fx.seed(t)
	return findingInBuild(store, aid, report.Advisory{ID: "GO-2026-0001", Source: "osv"}, nil, fx.mods)
}

func (fx replacedFixture) seed(t *testing.T) (artifact.Store, string) {
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
	if fx.scoped != nil {
		putJSON(t, store, aid, artifact.TypeExposureFootprint, artifact.ExposureFootprintPayload{
			SchemaVersion: artifact.ExposureFootprintSchemaVersion, AssessmentID: aid, PartialityFlags: fx.flags, ScopedPartiality: fx.scoped})
	} else {
		seedFootprint(t, store, aid, fx.flags)
	}
	part := plugin.Complete()
	if len(fx.flags) > 0 {
		part = plugin.Partial(fx.flags...)
	}
	graph := plugin.CallGraphResult{
		Partiality: plugin.Complete(),
		Edges:      []plugin.CallEdge{depEdge("github.com/kubeedge/kubeedge/cmd.main", "github.com/kubeedge/kubeedge/edge.Run")},
	}
	if fx.graph != nil {
		graph = *fx.graph
	}
	seedReachArtifact(t, store, aid, graph,
		plugin.ReachabilityResult{Partiality: part, Searched: fx.searched, Refutation: fx.refutation})
	return store, aid
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
		// The fork's version string is a label in the detail only. That it is never compared against
		// the advisory's ranges is pinned in pipeline's TestGoModuleAxisHonoursReplace E2.
		{"the fork's version string is only a label", func(fx *replacedFixture) {
			fx.inv["replaced_by"] = map[string]any{"path": rmForkPath, "version": "v0.0.1"}
		}, "no path from any entry point reaches " + rmSymA + ", " + rmSymB + " in k8s.io/kubernetes, which the build compiles from " +
			rmForkPath + " v0.0.1; that code defines each of them", "", ""},

		// ferralon-ai/tracker#811: a symbol whose qualifying package is absent from the build's
		// resolved package set (OutsideBuild) is not searched for, and the detail names only the
		// symbols that were.
		{"a symbol qualified by a package outside the build narrows", func(fx *replacedFixture) {
			fx.symbols = append(fx.symbols, rmSymV2)
			fx.res.OutsideBuild = []string{rmSymV2}
		}, "no path from any entry point reaches " + rmSymA + ", " + rmSymB + " in k8s.io/kubernetes, which the build compiles from " +
			rmForkPath + " " + rmForkVer + "; that code defines each of them", "", ""},
		// The refutation side: the same symbol, its package held by the build (compiled, or the source
		// of a replace), is required and unresolved, so the row stays held.
		{"a symbol qualified by a package the build holds stays required", func(fx *replacedFixture) {
			fx.symbols = append(fx.symbols, rmSymV2)
			fx.res.Partiality = plugin.Partial(plugin.PartialReasonAdvisorySymbolUnresolved)
		}, "", report.ReasonPackageVersionUnresolved,
			"The build's code of k8s.io/kubernetes does not define " + rmSymV2 + ". A replacement can rename or move the vulnerable code, so that is not taken as a fix."},
		{"every symbol qualified by a package outside the build", func(fx *replacedFixture) {
			fx.res = plugin.SymbolResolutionResult{Partiality: plugin.Complete(), OutsideBuild: []string{rmSymA, rmSymB}}
			fx.searched = nil
		}, "", report.ReasonPackageVersionUnresolved,
			"The build compiles no package named by " + rmSymA + ", " + rmSymB + ". A replacement can rename or move the vulnerable code, so that is not taken as a fix."},
		// The lane's package-level refutation is never the ground: it carries no searched sink.
		{"a package-level refutation with nothing searched", func(fx *replacedFixture) {
			fx.searched = nil
			fx.refutation = &plugin.Refutation{Basis: plugin.RefutationAnalyzerPackageNotImported, Package: rmPURL, Detail: "not imported"}
		}, "", report.ReasonPackageVersionUnresolved,
			"The analysis did not search every definition of " + rmSymA + ", " + rmSymB + " from the entry points."},
		// plugin_load drops beside a package-level refutation carrying AssumptionPluginsNotAssessed,
		// but only on an admitted package; a fork row has none, so the limit holds the row.
		{"plugin_load beside a refutation assuming plugins not assessed", func(fx *replacedFixture) {
			fx.flags = append(fx.flags, plugin.PartialReasonPluginLoad)
			fx.refutation = &plugin.Refutation{Basis: plugin.RefutationAnalyzerPackageNotImported, Package: rmPURL, Detail: "not imported",
				Assumptions: []string{plugin.AssumptionPluginsNotAssessed}}
		}, "", report.ReasonPackageVersionUnresolved,
			"Steps an analysis of that code rests on did not run, so it was not judged."},

		{"a symbol the fork does not define", func(fx *replacedFixture) {
			delete(fx.res.Matched, rmSymB)
			fx.res.Resolved, fx.searched = fx.res.Resolved[:1], fx.searched[:1]
		}, "", report.ReasonPackageVersionUnresolved,
			"The build's code of k8s.io/kubernetes does not define " + rmSymB + ". A replacement can rename or move the vulnerable code, so that is not taken as a fix."},
		{"a symbol the fork does not define, the resolution short only of it", func(fx *replacedFixture) {
			delete(fx.res.Matched, rmSymB)
			fx.res.Resolved, fx.searched = fx.res.Resolved[:1], fx.searched[:1]
			fx.res.Partiality = plugin.Partial(plugin.PartialReasonAdvisorySymbolUnresolved)
		}, "", report.ReasonPackageVersionUnresolved,
			"The build's code of k8s.io/kubernetes does not define " + rmSymB + ". A replacement can rename or move the vulnerable code, so that is not taken as a fix."},
		// A resolution that did not read all its code has not shown a symbol it missed is undefined.
		{"a symbol unmatched by a resolution that did not finish", func(fx *replacedFixture) {
			delete(fx.res.Matched, rmSymB)
			fx.res.Resolved, fx.searched = fx.res.Resolved[:1], fx.searched[:1]
			fx.res.Partiality = plugin.Partial(plugin.PartialReasonToolFailure)
			fx.flags = append(fx.flags, plugin.PartialReasonToolFailure)
		}, "", report.ReasonPackageVersionUnresolved,
			"Steps an analysis of that code rests on did not run, so it was not judged."},
		{"a symbol defined only outside the module", func(fx *replacedFixture) {
			fx.res.Origins[rmSCIPB] = "pkg:golang/github.com/other/mod@v1.0.0"
		}, "", report.ReasonPackageVersionUnresolved,
			"The build's code of k8s.io/kubernetes does not define " + rmSymB + ". A replacement can rename or move the vulnerable code, so that is not taken as a fix."},
		// The Go lane's ResolveDependencySymbols indexes only the build's own packages: for a dependency
		// it returns its partiality and nothing else. That is no evidence about what the fork defines.
		{"the Go lane's dependency result", func(fx *replacedFixture) {
			fx.res = plugin.SymbolResolutionResult{Partiality: fx.res.Partiality}
			fx.searched = nil
		}, "", report.ReasonPackageVersionUnresolved,
			"The analysis does not locate the advisory's symbols inside the build's code of k8s.io/kubernetes, so whether that code defines " + rmSymA + ", " + rmSymB + " was not determined."},
		// A symbol outside the build is not named as one the analysis failed to locate.
		{"the Go lane's dependency result, one symbol outside the build", func(fx *replacedFixture) {
			fx.symbols = append(fx.symbols, rmSymV2)
			fx.res = plugin.SymbolResolutionResult{Partiality: fx.res.Partiality, OutsideBuild: []string{rmSymV2}}
			fx.searched = nil
		}, "", report.ReasonPackageVersionUnresolved,
			"The analysis does not locate the advisory's symbols inside the build's code of k8s.io/kubernetes, so whether that code defines " + rmSymA + ", " + rmSymB + " was not determined."},
		{"every symbol resolved only outside the module", func(fx *replacedFixture) {
			fx.res.Origins[rmSCIPA] = "pkg:golang/github.com/other/mod@v1.0.0"
			fx.res.Origins[rmSCIPB] = "pkg:golang/github.com/other/mod@v1.0.0"
		}, "", report.ReasonPackageVersionUnresolved,
			"The analysis does not locate the advisory's symbols inside the build's code of k8s.io/kubernetes, so whether that code defines " + rmSymA + ", " + rmSymB + " was not determined."},
		{"a defined symbol not searched", func(fx *replacedFixture) { fx.searched = fx.searched[:1] }, "", report.ReasonPackageVersionUnresolved,
			"The analysis did not search every definition of " + rmSymA + ", " + rmSymB + " from the entry points."},
		// A symbol outside the build is not named as one the analysis did not search for, and does
		// not take the "does not define" statement.
		{"a defined symbol not searched, beside one outside the build", func(fx *replacedFixture) {
			fx.symbols = append(fx.symbols, rmSymV2)
			fx.res.OutsideBuild = []string{rmSymV2}
			fx.searched = fx.searched[:1]
		}, "", report.ReasonPackageVersionUnresolved,
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

		// ferralon-ai/tracker#811: the steps that did not run are named when each is one the detail can
		// state. ignite/cli's GHSA-w73w-5m7g-f7qc row is the first case's shape.
		{"cgo code of more than three packages and an analyzer silent on the advisory", func(fx *replacedFixture) {
			fx.flags = append(fx.flags, plugin.PartialReasonAdvisoryUnknownToAnalyzer)
			fx.scoped = []artifact.ScopedPartialityFlag{
				rmCgo("example.com/a", "example.com/a"), rmCgo("example.com/a", "example.com/a/sub"),
				rmCgo("example.com/b", "example.com/b"), rmCgo("example.com/c", "example.com/c"),
				rmCgo("example.com/d", "example.com/d"), rmCgo("example.com/e", "example.com/e"),
			}
		}, "", report.ReasonPackageVersionUnresolved,
			"Steps an analysis of that code rests on did not run: cgo code of example.com/a, example.com/b, example.com/c and 2 other packages was not analyzed, " +
				"and the vulnerability analyzer emitted no evidence about the advisory, so it was not judged."},
		{"cgo code of four packages", func(fx *replacedFixture) {
			fx.scoped = []artifact.ScopedPartialityFlag{
				rmCgo("example.com/a", "example.com/a"), rmCgo("example.com/b", "example.com/b"),
				rmCgo("example.com/c", "example.com/c"), rmCgo("example.com/d", "example.com/d"),
			}
		}, "", report.ReasonPackageVersionUnresolved,
			"Steps an analysis of that code rests on did not run: cgo code of example.com/a, example.com/b, example.com/c and 1 other package was not analyzed, so it was not judged."},
		{"cgo code of up to three packages", func(fx *replacedFixture) {
			fx.scoped = []artifact.ScopedPartialityFlag{rmCgo("example.com/a", "example.com/a"), rmCgo("example.com/b", "example.com/b")}
		}, "", report.ReasonPackageVersionUnresolved,
			"Steps an analysis of that code rests on did not run: cgo code of example.com/a, example.com/b was not analyzed, so it was not judged."},
		{"an analyzer silent on the advisory", func(fx *replacedFixture) {
			fx.flags = append(fx.flags, plugin.PartialReasonAdvisoryUnknownToAnalyzer)
		}, "", report.ReasonPackageVersionUnresolved,
			"Steps an analysis of that code rests on did not run: the vulnerability analyzer emitted no evidence about the advisory, so it was not judged."},
		// Any limit the detail cannot name keeps the general statement.
		{"a named step beside one it cannot name", func(fx *replacedFixture) {
			fx.flags = append(fx.flags, plugin.PartialReasonAdvisoryUnknownToAnalyzer, plugin.PartialReasonToolFailure)
		}, "", report.ReasonPackageVersionUnresolved,
			"Steps an analysis of that code rests on did not run, so it was not judged."},
		// A symbol outside the build is not named as one the fork does not define.
		{"a symbol the fork does not define, beside one outside the build", func(fx *replacedFixture) {
			fx.symbols = append(fx.symbols, rmSymV2)
			fx.res.OutsideBuild = []string{rmSymV2}
			delete(fx.res.Matched, rmSymB)
			fx.res.Resolved, fx.searched = fx.res.Resolved[:1], fx.searched[:1]
		}, "", report.ReasonPackageVersionUnresolved,
			"The build's code of k8s.io/kubernetes does not define " + rmSymB + ". A replacement can rename or move the vulnerable code, so that is not taken as a fix."},
		// The case order holds: a symbol the fork does not define is stated before any step that did
		// not run.
		{"a symbol the fork does not define, beside steps that did not run", func(fx *replacedFixture) {
			delete(fx.res.Matched, rmSymB)
			fx.res.Resolved, fx.searched = fx.res.Resolved[:1], fx.searched[:1]
			fx.flags = append(fx.flags, plugin.PartialReasonAdvisoryUnknownToAnalyzer)
			fx.scoped = []artifact.ScopedPartialityFlag{rmCgo("example.com/a", "example.com/a")}
		}, "", report.ReasonPackageVersionUnresolved,
			"The build's code of k8s.io/kubernetes does not define " + rmSymB + ". A replacement can rename or move the vulnerable code, so that is not taken as a fix."},
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

// TestReplacedHeldDetail_EmptyGraph: an empty call graph not called complete is a step that did not
// run which the detail cannot name, so a nameable limit beside it keeps the general statement. The
// finding path classifies such a row analysis_did_not_run before the fork detail, so the detail is
// called directly.
func TestReplacedHeldDetail_EmptyGraph(t *testing.T) {
	fx := newReplacedFixture()
	fx.flags = append(fx.flags, plugin.PartialReasonAdvisoryUnknownToAnalyzer)
	fx.graph = &plugin.CallGraphResult{Partiality: plugin.Partial(plugin.PartialReasonCgo)}
	store, aid := fx.seed(t)
	r, ok := moduleReplacement(store, aid, nil)
	if !ok {
		t.Fatal("no replacement recorded")
	}
	const want = rmForkHead + "Steps an analysis of that code rests on did not run, so it was not judged." + rmForkTail
	if got := replacedHeldDetail(store, aid, fx.mods, r); got != want {
		t.Errorf("detail = %q, want %q", got, want)
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
	// The scanned module is never a replacement, even when its own version is known and the row
	// has no package, so it is never judged on replacedGrounds.
	t.Run("the scanned module itself, version known", func(t *testing.T) {
		fx := newReplacedFixture()
		fx.inv["root"], fx.inv["resolved_version"] = true, "v1.9.0"
		if f := fx.finding(t); f.Verdict == report.VerdictNotExploitable {
			t.Fatalf("got not_exploitable (%s), want the scanned module held", f.Evidence.Detail)
		}
	})
	t.Run("the row has a package", func(t *testing.T) {
		store := artifact.NewMemStore()
		putJSON(t, store, "x", artifact.TypeInventory, newReplacedFixture().inv)
		if _, ok := moduleReplacement(store, "x", nil); !ok {
			t.Fatal("moduleReplacement not held for the fork row with no package")
		}
		pkg := &report.Package{Ecosystem: "Go", Name: "k8s.io/kubernetes", Version: "v1.32.10", PURL: rmOrigin}
		if _, ok := moduleReplacement(store, "x", pkg); ok {
			t.Fatal("moduleReplacement held for a row with a package")
		}
	})
	// A fork row held for another reason keeps that reason's detail: the fork detail explains only
	// package_version_unresolved.
	t.Run("held for another reason", func(t *testing.T) {
		fx := newReplacedFixture()
		fx.inv["partiality_flags"] = []string{}
		fx.flags = []string{plugin.PartialReasonToolFailure}
		f := fx.finding(t)
		if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != report.ReasonAnalysisDidNotRun {
			t.Fatalf("got %s/%q, want undetermined/%q", f.Verdict, f.UndeterminedReason, report.ReasonAnalysisDidNotRun)
		}
		if strings.Contains(f.Evidence.Detail, "The build compiles") {
			t.Errorf("detail = %q, want no fork detail", f.Evidence.Detail)
		}
	})
}
