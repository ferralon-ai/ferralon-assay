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
