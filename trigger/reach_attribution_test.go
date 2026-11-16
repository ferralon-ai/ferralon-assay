package trigger

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// stdlibPathPlugin is goManifestPlugin with a reachability result holding one path, from an entry
// point into net/http.
type stdlibPathPlugin struct{ goManifestPlugin }

func (stdlibPathPlugin) Reachability(context.Context, plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	return plugin.ReachabilityResult{
		Partiality: plugin.Complete(),
		Paths: []plugin.ReachPath{{
			Ingress: plugin.Symbol{SCIP: "scip-go gomod example.com/target . example.com/target/main()."},
			Sink:    plugin.Symbol{SCIP: "scip-go gomod stdlib v1.26.0 net/http/Client#Get().", Package: "net/http"},
		}},
	}, nil
}

// netAndStdlibSource serves GO-2099-0001, an advisory affecting golang.org/x/net below v0.55.0 and
// the standard library below go1.25.13, with no symbols.
type netAndStdlibSource struct{}

func (netAndStdlibSource) Lookup(id string) (pipeline.AdvisoryFacts, bool) {
	if id != "GO-2099-0001" {
		return pipeline.AdvisoryFacts{}, false
	}
	return pipeline.AdvisoryFacts{
		Module:         "golang.org/x/net",
		PURL:           "pkg:golang/golang.org/x/net",
		AffectedRanges: []pipeline.Range{{Fixed: "v0.55.0"}},
		AffectedPackages: []pipeline.AffectedPackage{
			{Module: "golang.org/x/net", PURL: "pkg:golang/golang.org/x/net", AffectedRanges: []pipeline.Range{{Fixed: "v0.55.0"}}},
			{Coordinate: "stdlib", PURL: "pkg:golang/stdlib", VersionScheme: "go-toolchain", AffectedRanges: []pipeline.Range{{Fixed: "1.25.13"}}},
		},
		Provenance: pipeline.Provenance{Source: "test", TrustTier: pipeline.TrustFirstParty},
	}, true
}

// The only reach path enters the standard library. On a toolchain past the fix that path does not
// count toward the x/net row, and the row is undetermined: no path counts, and none is shown absent.
// On an affected toolchain the path counts.
func TestBaseline_PathIntoAFixedOtherPackageNeverRefutes(t *testing.T) {
	adv := []assessment.VulnRef{{ID: "GO-2099-0001", Source: "corpus"}}
	tests := []struct {
		name    string
		goLine  string
		want    report.Verdict
		wantRsn string
	}{
		{"fixed toolchain", "go 1.26.0", report.VerdictUndetermined, report.ReasonAdvisorySymbolAbsent},
		{"affected toolchain", "go 1.25.0", report.VerdictReachableCandidate, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			goMod := "module example.com/target\n\n" + tt.goLine + "\n\nrequire golang.org/x/net v0.25.0\n"
			rep := runGoBaseline(t, goMod, adv,
				pipeline.WithPlugin(stdlibPathPlugin{}),
				pipeline.WithAdvisorySource(netAndStdlibSource{}))
			if got := verdictByID(rep)["GO-2099-0001"]; got != tt.want {
				t.Fatalf("verdict = %q, want %q", got, tt.want)
			}
			if tt.want == report.VerdictUndetermined {
				assertUndetermined(t, rep, "GO-2099-0001", tt.wantRsn)
			}
		})
	}
}

// jwtPathPlugin is goManifestPlugin whose reachability result, like govulncheck's for one advisory,
// covers every module the advisory names: one path per major version of golang-jwt in calls.
type jwtPathPlugin struct {
	goManifestPlugin
	calls []string
}

func (p jwtPathPlugin) Reachability(context.Context, plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	res := plugin.ReachabilityResult{Partiality: plugin.Complete()}
	for _, major := range p.calls {
		pkg := "github.com/golang-jwt/jwt/" + major
		res.Paths = append(res.Paths, plugin.ReachPath{
			Ingress: plugin.Symbol{SCIP: "scip-go gomod example.com/target . example.com/target/main()."},
			Sink:    plugin.Symbol{SCIP: "scip-go gomod " + pkg + " . " + pkg + "/Parser#ParseUnverified().", Package: pkg},
		})
	}
	return res, nil
}

// jwtSource serves GO-2099-0002, affecting golang-jwt v4 below v4.5.2 and v5 below v5.2.2.
type jwtSource struct{}

func (jwtSource) Lookup(id string) (pipeline.AdvisoryFacts, bool) {
	if id != "GO-2099-0002" {
		return pipeline.AdvisoryFacts{}, false
	}
	pkg := func(major, fixed string) pipeline.AffectedPackage {
		module := "github.com/golang-jwt/jwt/" + major
		return pipeline.AffectedPackage{Module: module, PURL: "pkg:golang/" + module, AffectedRanges: []pipeline.Range{{Fixed: fixed}}}
	}
	return pipeline.AdvisoryFacts{
		Module:           "github.com/golang-jwt/jwt/v4",
		PURL:             "pkg:golang/github.com/golang-jwt/jwt/v4",
		AffectedRanges:   []pipeline.Range{{Fixed: "v4.5.2"}},
		AffectedPackages: []pipeline.AffectedPackage{pkg("v4", "v4.5.2"), pkg("v5", "v5.2.2")},
		Provenance:       pipeline.Provenance{Source: "test", TrustTier: pipeline.TrustFirstParty},
	}, true
}

// A build carrying two major versions of one module gets a finding per instance, and a call path
// belongs to the instance whose code it enters: a path into v5 never makes the v4 row reachable.
func TestBaseline_EachMajorVersionInstanceHasItsOwnVerdictAndPath(t *testing.T) {
	adv := []assessment.VulnRef{{ID: "GO-2099-0002", Source: "corpus"}}
	both := "module example.com/target\n\ngo 1.26.0\n\nrequire (\n\tgithub.com/golang-jwt/jwt/v4 v4.5.1\n\tgithub.com/golang-jwt/jwt/v5 v5.2.1\n)\n"
	onlyV4 := "module example.com/target\n\ngo 1.26.0\n\nrequire github.com/golang-jwt/jwt/v4 v4.5.1\n"
	tests := []struct {
		name  string
		goMod string
		calls []string
		want  map[string]report.Verdict // by package name; absent: no row
	}{
		{"v5 only called", both, []string{"v5"}, map[string]report.Verdict{
			"github.com/golang-jwt/jwt/v5": report.VerdictReachableCandidate,
			"github.com/golang-jwt/jwt/v4": report.VerdictUndetermined,
		}},
		{"both called", both, []string{"v4", "v5"}, map[string]report.Verdict{
			"github.com/golang-jwt/jwt/v5": report.VerdictReachableCandidate,
			"github.com/golang-jwt/jwt/v4": report.VerdictReachableCandidate,
		}},
		{"only v4 present", onlyV4, []string{"v4"}, map[string]report.Verdict{
			"github.com/golang-jwt/jwt/v4": report.VerdictReachableCandidate,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := runGoBaseline(t, tt.goMod, adv,
				pipeline.WithPlugin(jwtPathPlugin{calls: tt.calls}),
				pipeline.WithAdvisorySource(jwtSource{}))
			got := map[string]report.Verdict{}
			for _, f := range rep.Advisories {
				if f.Package == nil {
					t.Fatalf("row without a package: %+v", f)
				}
				got[f.Package.Name] = f.Verdict
			}
			if len(got) != len(tt.want) || len(rep.Advisories) != len(tt.want) {
				t.Fatalf("rows = %v (%d findings), want %v", got, len(rep.Advisories), tt.want)
			}
			for name, v := range tt.want {
				if got[name] != v {
					t.Errorf("%s: verdict %q, want %q", name, got[name], v)
				}
			}
		})
	}
}
