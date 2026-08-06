//go:build eval_live

// The live full-corpus runner for the reachable-candidate eval. It is OPT-IN twice over so
// it never joins the hermetic suite: the `//go:build eval_live` tag keeps it out of
// `go test ./...`, and the TEGRON_EVAL=1 env gate keeps it out of `-tags eval_live` by
// accident. It needs the real Go toolchain + tegron-plugin-go on PATH — do NOT run it inline
// from a /team agent (it stalls the watchdog); hand it to the orchestrator's background bash:
//
//	make install   # put tegron-plugin-go on GOBIN/$PATH first
//	PATH="$(go env GOPATH)/bin:$PATH" TEGRON_EVAL=1 \
//	  go test -tags eval_live ./eval/reachcandidate/ -run TestLiveReachCandidateEval -v
//
// It measures each corpus fixture's reachable-candidate signal against the CURRENT corpus
// symbol lists (pipeline.AdvisoryTable — the pre-populate baseline). RECALL is fully
// measured (no ground truth needed — candidate formed or not). PRECISION is measured only
// for CVEs annotated in testdata/expected_sinks.json (curated, each one verified against the
// upstream fix commit); un-annotated CVEs print sink "-" and are excluded from the
// precision denominator, honestly rather than circularly.
//
// To measure a POPULATE delta (corpus vN → vN+1), the producer's complete symbol lists land
// in AdvisoryTable (or a future artifactSource); re-run and Diff against a saved baseline.

package reachcandidate

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/corpus"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func TestLiveReachCandidateEval(t *testing.T) {
	if os.Getenv("TEGRON_EVAL") != "1" {
		t.Skip("set TEGRON_EVAL=1 to run the live reachable-candidate eval (opt-in)")
	}
	if _, err := exec.LookPath("tegron-plugin-go"); err != nil {
		t.Skip("tegron-plugin-go not on PATH (run `make install` first)")
	}
	goPlugin, err := plugin.NewGoPlugin()
	if err != nil {
		t.Fatalf("go plugin: %v", err)
	}

	fixtures, err := corpus.Load()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	expected := loadExpectedSinks(t)

	var cases []Case
	for _, fix := range fixtures {
		if fix.Codebase.Acquisition.Mode != "vendored_repro" {
			t.Logf("SKIP %s: acquisition mode %q not vendored_repro", fix.Advisory.ID, fix.Codebase.Acquisition.Mode)
			continue
		}
		// Baseline symbols come from the current in-memory corpus (what S1 would read today).
		facts := pipeline.AdvisoryTable[fix.Advisory.ID]
		cases = append(cases, Case{
			VulnID:        fix.Advisory.ID,
			Source:        fix.Advisory.Source,
			Aliases:       facts.Aliases,
			PURL:          facts.PURL,
			Symbols:       facts.Symbols,
			GuardSymbols:  facts.GuardSymbols,
			BuildDir:      corpus.ReproPath(fix.Codebase.Acquisition.Path),
			ExpectedSinks: expected[fix.Advisory.ID], // empty ⇒ precision unmeasured for this CVE
		})
	}
	if len(cases) == 0 {
		t.Fatal("no vendored_repro fixtures found to evaluate")
	}

	rep := Run(context.Background(), goPlugin, "current corpus (baseline)", cases)
	t.Logf("\n%s", rep.Table())

	annotated := 0
	for _, c := range cases {
		if len(c.ExpectedSinks) > 0 {
			annotated++
		}
	}
	t.Logf("recall=%s precision=%s (%d/%d CVEs have curated expected-sink annotations)",
		rep.Recall(), rep.Precision(), annotated, len(cases))
}

// loadExpectedSinks reads the curated, upstream-verified expected-sink annotations. A missing
// file is not fatal — it just means every CVE's precision is unmeasured (recall still runs).
func loadExpectedSinks(t *testing.T) map[string][]string {
	t.Helper()
	data, err := os.ReadFile("testdata/expected_sinks.json")
	if err != nil {
		t.Logf("no testdata/expected_sinks.json (%v) — precision unmeasured, recall only", err)
		return map[string][]string{}
	}
	var doc struct {
		Sinks map[string][]string `json:"expected_sinks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode expected_sinks.json: %v", err)
	}
	return doc.Sinks
}
