package pipeline

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestGoModuleAxisHonoursReplace runs advisory_intake → codebase_inventory →
// disqualification_discovery over a real go.mod with nothing seeded between them, against the
// built-in GO-2021-0113 (golang.org/x/text, fixed v0.3.7). Every go.mod requires v0.3.8, which is
// outside the range; a replace decides what the build actually compiles. E6 swaps in a synthetic
// two-package advisory.
func TestGoModuleAxisHonoursReplace(t *testing.T) {
	const head = "module example.com/app\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.8\n"
	tests := []struct {
		name         string
		replace      string
		src          AdvisorySource
		goMod        string
		wantVersion  string
		wantUnpinned bool
		wantDisqual  bool
		wantReason   string
	}{
		{
			name:        "E1 a version replace of the module is the version the build compiles",
			replace:     "replace golang.org/x/text => golang.org/x/text v0.3.6\n",
			wantVersion: "v0.3.6",
			wantReason:  ReasonInsufficient,
		},
		{
			// The module-wide decoy comes first, so precedence cannot fall out of file order.
			name:        "E1b a replace naming the required version wins over the module-wide one",
			replace:     "replace golang.org/x/text => golang.org/x/text v0.3.8\n\nreplace golang.org/x/text v0.3.8 => golang.org/x/text v0.3.6\n",
			wantVersion: "v0.3.6",
			wantReason:  ReasonInsufficient,
		},
		{
			// The fork's own version sits outside the upstream range, so reading it as the
			// module's version would disqualify.
			name:         "E2 a fork replace is declared with no version",
			replace:      "replace golang.org/x/text => github.com/example/text v0.3.8\n",
			wantUnpinned: true,
			wantReason:   ReasonInsufficient,
		},
		{
			name:         "E3 a local-directory replace is declared with no version",
			replace:      "replace golang.org/x/text => ./third_party/text\n",
			wantUnpinned: true,
			wantReason:   ReasonInsufficient,
		},
		{
			// example.com/a is fork-replaced and example.com/b sits past its fix. Were the replaced
			// package not kept as declared, selection would move on to b and disqualify on b's
			// range alone.
			name:         "E6 a fork-replaced package still ends selection in a two-package advisory",
			src:          multipkgSelectSource{withArray: true},
			goMod:        "module example.com/app\n\ngo 1.22\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/b v1.6.0\n)\n\nreplace example.com/a => github.com/example/a v1.0.0\n",
			wantUnpinned: true,
			wantReason:   ReasonInsufficient,
		},
		{
			name:        "E4 without a replace the require version disqualifies",
			wantVersion: "v0.3.8",
			wantDisqual: true,
			wantReason:  ReasonVersionNotInRange,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			goMod, vulnID := head, "GO-2021-0113"
			if tt.replace != "" {
				goMod += "\n" + tt.replace
			}
			if tt.goMod != "" {
				goMod, vulnID = tt.goMod, "CVE-TEST-MULTIPKG"
			}
			store := artifact.NewMemStore()
			caseID := "case-go-replace"
			c := &assessment.Assessment{ID: caseID, Request: assessment.Request{
				Vulnerability: assessment.VulnRef{ID: vulnID, Source: "corpus"},
				Codebase: assessment.CodebaseRef{
					Repo:        "example.com/app",
					Revision:    "v1",
					Acquisition: assessment.Acquisition{Mode: "git"},
				},
			}}
			if err := (advisoryIntake{src: tt.src}).Run(context.Background(), c, store); err != nil {
				t.Fatalf("advisory_intake: %v", err)
			}
			stage := codebaseInventory{
				checkout: dirCheckout{dir: writeGoModFixture(t, goMod), lang: "go"},
				plugin:   goManifestPlugin{},
				src:      tt.src,
			}
			if err := stage.Run(context.Background(), c, store); err != nil {
				t.Fatalf("codebase_inventory: %v", err)
			}
			arts, err := store.Query(caseID, artifact.TypeInventory)
			if err != nil || len(arts) == 0 {
				t.Fatalf("inventory artifact: %v (n=%d)", err, len(arts))
			}
			var inv struct {
				ResolvedVersion string   `json:"resolved_version"`
				PartialityFlags []string `json:"partiality_flags"`
			}
			if err := json.Unmarshal(arts[len(arts)-1].Payload, &inv); err != nil {
				t.Fatalf("unmarshal inventory: %v", err)
			}
			if inv.ResolvedVersion != tt.wantVersion {
				t.Errorf("resolved_version = %q, want %q", inv.ResolvedVersion, tt.wantVersion)
			}
			if got := slices.Contains(inv.PartialityFlags, plugin.PartialReasonSourceUnpinned); got != tt.wantUnpinned {
				t.Errorf("source_unpinned flagged = %v, want %v (flags %v)", got, tt.wantUnpinned, inv.PartialityFlags)
			}
			res := runDisqual(t, store, caseID)
			if res.Disqualified != tt.wantDisqual || res.Reason != tt.wantReason {
				t.Errorf("discovery = {%v %q}, want {%v %q}", res.Disqualified, res.Reason, tt.wantDisqual, tt.wantReason)
			}
		})
	}
}
