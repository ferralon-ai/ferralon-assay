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
	// Go is the floor: its LookPath skip above guarantees the constructor succeeds.
	goPlugin, err := plugin.NewGoPlugin()
	if err != nil {
		t.Fatalf("go plugin: %v", err)
	}
	// Build a MultiPlugin from Go plus every non-Go plugin whose toolchain binary is present.
	// Each non-Go constructor returns an error when its tegron-plugin-<lang> binary is absent
	// from PATH — log-and-omit that language (unmeasured) exactly as the Go path t.Skips. A
	// fixture whose language plugin was omitted then self-routes (by DetectLanguage(BuildDir))
	// to the NoPlugin partiality path — recorded Complete:false, never an error and never a
	// recall miss. Every environment lacks >=1 of the five toolchains, so a missing one must
	// never abort the eval.
	plugins := []plugin.LanguagePlugin{goPlugin}
	for _, opt := range []struct {
		lang string
		ctor func() (plugin.LanguagePlugin, error)
	}{
		{"java", func() (plugin.LanguagePlugin, error) { return plugin.NewJavaPlugin() }},
		{"js", func() (plugin.LanguagePlugin, error) { return plugin.NewJSPlugin() }},
		{"python", func() (plugin.LanguagePlugin, error) { return plugin.NewPythonPlugin() }},
		{"dotnet", func() (plugin.LanguagePlugin, error) { return plugin.NewDotNetPlugin() }},
	} {
		p, err := opt.ctor()
		if err != nil {
			t.Logf("omit %s plugin (toolchain absent): %v", opt.lang, err)
			continue
		}
		plugins = append(plugins, p)
	}
	multi := plugin.NewMultiPlugin(plugins...)

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
			CaseID:        fix.ID, // unique fixture id (advisory id collides across variants)
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

	rep := Run(context.Background(), multi, "current corpus (baseline)", cases)
	t.Logf("\n%s", rep.Table())

	// TEGRON_EVAL_UPDATE=1 regenerates the committed golden from this fresh run (the
	// golden-update idiom). anvil runs this once to fill the empty seed with real numbers.
	if os.Getenv("TEGRON_EVAL_UPDATE") == "1" {
		if err := writeBaselineReport(baselinePath, rep); err != nil {
			t.Fatalf("update baseline %s: %v", baselinePath, err)
		}
		t.Logf("wrote regenerated baseline to %s (%d results)", baselinePath, len(rep.Results))
		return
	}

	// Diff the fresh run against the committed golden and fail the gate on a regression. An
	// empty baseline makes every Go candidate a GainedCandidate (never a LostCandidate), so
	// this is safe until anvil fills the golden with real numbers.
	baseline, err := loadBaselineReport(baselinePath)
	if err != nil {
		t.Fatalf("load baseline %s: %v", baselinePath, err)
	}
	dr := Diff(baseline, rep)
	t.Logf("%s", dr.String())
	if dr.Regressed() {
		t.Fatalf("reach-candidate baseline regressed:\n%s", dr)
	}

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
