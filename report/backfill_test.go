package report

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// TestDisqualBasisFromDetail: each fixed intake-disqualification line maps to its basis, with or without
// the source attribution the scanner appends; anything else maps to none.
func TestDisqualBasisFromDetail(t *testing.T) {
	for _, tc := range []struct {
		detail string
		want   verdict.NonExploitableBasis
	}{
		// Version and symbol disqualifications always carried their basis; one without it is refused.
		{"resolved dependency version is outside the advisory's affected range", verdict.BasisNone},
		{"the vulnerable symbol is absent from the built artifact", verdict.BasisNone},
		{"the advisory targets a different ecosystem than this codebase; no version or symbol comparison was performed", verdict.BasisAdvisoryEcosystemMismatch},
		{"the advisory's package is not installed by the build: its dependency manifest or build graph has no entry for it; no version or symbol comparison was performed", verdict.BasisNoManifestEntry},
		{"the advisory's package is absent from this codebase's dependency manifest; no version or symbol comparison was performed", verdict.BasisNoManifestEntry},
		{"the advisory targets a different ecosystem than this codebase; no version or symbol comparison was performed (per advisory GO-1, feed osv)", verdict.BasisAdvisoryEcosystemMismatch},
		{"disqualified on an axis that is neither a version nor a symbol comparison; neither comparison was performed", verdict.BasisNone},
		{"no version or symbol comparison was performed", verdict.BasisNone},
		{"", verdict.BasisNone},
	} {
		if got := DisqualBasisFromDetail(tc.detail); got != tc.want {
			t.Errorf("DisqualBasisFromDetail(%q) = %q, want %q", tc.detail, got, tc.want)
		}
	}
}

// TestUpgradeBackfillsDisqualBasis: at every recognized version, an empty-basis disqualification takes
// the basis its detail names. A basis already set is kept, a not_exploitable is never backfilled, and
// the input is not mutated.
func TestUpgradeBackfillsDisqualBasis(t *testing.T) {
	const intake = "the advisory targets a different ecosystem than this codebase; no version or symbol comparison was performed"
	for _, schema := range []string{SchemaVersion, SchemaVersionV2, SchemaVersionV1} {
		t.Run(schema, func(t *testing.T) {
			in := Report{SchemaVersion: schema, Advisories: []AdvisoryFinding{
				{Advisory: Advisory{ID: "A"}, Verdict: VerdictDisqualified, Evidence: EvidenceSummary{Detail: intake}},
				{Advisory: Advisory{ID: "B"}, Verdict: VerdictDisqualified, Evidence: EvidenceSummary{Basis: verdict.BasisSymbolAbsent, Detail: intake}},
				{Advisory: Advisory{ID: "C"}, Verdict: VerdictNotExploitable, Evidence: EvidenceSummary{Detail: intake}},
			}}
			up, err := Upgrade(in)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]verdict.NonExploitableBasis{
				"A": verdict.BasisAdvisoryEcosystemMismatch,
				"B": verdict.BasisSymbolAbsent,
				"C": verdict.BasisNone,
			}
			for _, f := range up.Advisories {
				if f.Evidence.Basis != want[f.Advisory.ID] {
					t.Errorf("%s basis = %q, want %q", f.Advisory.ID, f.Evidence.Basis, want[f.Advisory.ID])
				}
			}
			if in.Advisories[0].Evidence.Basis != verdict.BasisNone {
				t.Error("Upgrade mutated its input's findings")
			}
		})
	}
}
