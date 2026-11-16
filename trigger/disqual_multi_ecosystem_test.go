package trigger

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// multiEcosystemSource serves a cargo-primary advisory that also affects the Go stdlib, the
// CVE-2026-111943 shape.
type multiEcosystemSource struct{}

func (multiEcosystemSource) Lookup(id string) (pipeline.AdvisoryFacts, bool) {
	rng := []pipeline.Range{{Introduced: "0", Fixed: "1.26.10"}}
	return pipeline.AdvisoryFacts{
		Coordinate: "rustls-webpki",
		PURL:       "pkg:cargo/rustls-webpki",
		AffectedPackages: []pipeline.AffectedPackage{
			{Coordinate: "rustls-webpki", PURL: "pkg:cargo/rustls-webpki"},
			{Coordinate: "stdlib", PURL: "pkg:golang/stdlib", VersionScheme: "go-toolchain", AffectedRanges: rng},
		},
	}, true
}

// An advisory with an entry in the codebase's ecosystem is never ruled out as a different ecosystem.
func TestMultiEcosystemAdvisoryIsNeverDifferentEcosystem(t *testing.T) {
	rep := runGoBaseline(t, "module example.com/target\n\ngo 1.20\n",
		[]assessment.VulnRef{{ID: "CVE-2026-111943", Source: "corpus"}},
		pipeline.WithAdvisorySource(multiEcosystemSource{}))
	if len(rep.Advisories) != 1 {
		t.Fatalf("got %d findings, want 1", len(rep.Advisories))
	}
	f := rep.Advisories[0]
	if f.Verdict == report.VerdictDisqualified && strings.Contains(f.Evidence.Detail, "different ecosystem") {
		t.Fatalf("disqualified as a different ecosystem: %s", f.Evidence.Detail)
	}
}
