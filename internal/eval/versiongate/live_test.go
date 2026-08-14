//go:build eval_live

// The live Phase-1 exit gate (PLAN-190) for the {go} reference lane. OPT-IN twice over so it
// never joins the hermetic suite: the `//go:build eval_live` tag keeps it out of `go test
// ./...`, and the TEGRON_EVAL=1 env gate keeps it out of `-tags eval_live` by accident. It
// calls goanalysis.ResolveInventory IN-PROCESS (no plugin subprocess) but still RESOLVES the
// module graph via `go mod graph` — it needs the real Go toolchain and a warm module cache. Do
// NOT run it inline from a /team agent (the go subprocess stalls the watchdog); hand it to the
// orchestrator's background bash:
//
//	TEGRON_EVAL=1 go test -tags eval_live ./internal/eval/versiongate/ -run TestLiveVersionGate -v
//	TEGRON_EVAL=1 TEGRON_EVAL_UPDATE=1 go test -tags eval_live ./internal/eval/versiongate/ -run TestLiveVersionGate  # regenerate golden
//
// It compares each Go vendored_repro fixture's resolved inventory against the committed native
// oracle (corpus/testdata/oracles/) and diffs the whole per-fixture GateReport against a
// committed golden — a resolver whose graph drifts from the native oracle fails here. The
// oracle is captured content produced out-of-band; this gate never captures it (an oracle the
// gate captured to grade against is not independent).
package versiongate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/corpus"
	"github.com/ferralon-ai/ferralon-assay/internal/eval/versionaccuracy"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/goanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const goldenPath = "testdata/gate_golden.json"

// oracleDir is the committed native-oracle content directory, relative to the corpus package.
func oracleSource(t *testing.T) OracleSource {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "corpus", "testdata", "oracles")
	return func(id string) (*versionaccuracy.Oracle, error) {
		data, err := os.ReadFile(filepath.Join(dir, id+".oracle.json"))
		if os.IsNotExist(err) {
			return nil, nil // honest absence: Measure -> oracle_absent (a C1 gap)
		}
		if err != nil {
			return nil, err
		}
		var o versionaccuracy.Oracle
		if err := json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
		return &o, nil
	}
}

// goRootFixtures selects the {go} lane's in-scope fixtures: vendored_repro fixtures whose repro
// has a go.mod at the build-dir root (the resolver keys on BuildDir/go.mod). GRAFANA's src/-nested
// go.mod is excluded here and recorded as a build-dir-convention coverage finding in the verdict.
func goRootFixtures(t *testing.T) []corpus.Fixture {
	t.Helper()
	all, err := corpus.Load()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	var out []corpus.Fixture
	for _, f := range all {
		if f.Codebase.Acquisition.Mode != "vendored_repro" {
			continue
		}
		bd := corpus.ReproPath(f.Codebase.Acquisition.Path)
		if fi, err := os.Stat(filepath.Join(bd, "go.mod")); err == nil && !fi.IsDir() {
			out = append(out, f)
		}
	}
	return out
}

func TestLiveVersionGate(t *testing.T) {
	if os.Getenv("TEGRON_EVAL") != "1" {
		t.Skip("set TEGRON_EVAL=1 to run the live Phase-1 version gate (opt-in)")
	}
	fixtures := goRootFixtures(t)
	if len(fixtures) == 0 {
		t.Fatal("no go-root vendored_repro fixtures found")
	}

	resolve := func(ctx context.Context, buildDir string) (plugin.DependencyInventory, error) {
		return goanalysis.ResolveInventory(ctx, plugin.ResolveInventoryRequest{BuildDir: buildDir})
	}
	rep, err := Run(context.Background(), "go", fixtures, oracleSource(t), resolve)
	if err != nil {
		t.Fatalf("gate run: %v", err)
	}

	// --- log the per-criterion verdict summary (the human-readable gate result) ---
	measured, unmeas := rep.VersionAxisCoverage()
	t.Logf("go reference lane: %d fixtures | C1 gaps=%v | misses=%v | version-axis measured=%d unmeasurable=%d",
		len(rep.Outcomes), rep.C1OracleComparisonGaps(), rep.Misses(), measured, unmeas)
	for _, cat := range []corpus.Category{
		corpus.CategoryTriviallyExploitable, corpus.CategoryAbsentNotExploitable,
		corpus.CategoryReachableUnconfirmable, corpus.CategoryPatched, corpus.CategoryInstalledUndetermined,
	} {
		t.Logf("  slice %-24s %s", cat, rep.SliceState(cat))
	}
	pwr, ctrl := rep.C5PartialityControl()
	t.Logf("  C5 partiality: partial-with-reason=%v complete-control=%v", pwr, ctrl)

	// --- golden round-trip (BuildDir zeroed: absolute paths are environment-variant) ---
	got := zeroBuildDir(rep)
	if os.Getenv("TEGRON_EVAL_UPDATE") == "1" {
		if err := writeGolden(goldenPath, got); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("golden regenerated at %s", goldenPath)
		return
	}
	want, err := loadGolden(goldenPath)
	if err != nil {
		t.Fatalf("load golden (regenerate with TEGRON_EVAL_UPDATE=1): %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		gj, _ := json.MarshalIndent(got, "", "  ")
		wj, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("gate report drifted from golden.\n--- got ---\n%s\n--- want ---\n%s", gj, wj)
	}

	// --- reference-lane invariant: the Go resolver's graph must not DISAGREE with its native
	// oracle. A measured miss on the reference lane is a real resolver regression. (The version
	// axis being unmeasurable is a preserved-partiality finding, recorded, not a miss.) ---
	if m := rep.Misses(); len(m) != 0 {
		t.Errorf("reference lane has measured oracle disagreements (resolver regression): %v", m)
	}
	if g := rep.C1OracleComparisonGaps(); len(g) != 0 {
		t.Errorf("reference lane has oracle comparison gaps (missing/stale oracle): %v", g)
	}
}

func zeroBuildDir(r GateReport) GateReport {
	out := GateReport{Lane: r.Lane, Outcomes: append([]FixtureOutcome(nil), r.Outcomes...)}
	for i := range out.Outcomes {
		out.Outcomes[i].BuildDir = ""
	}
	return out
}

func loadGolden(path string) (GateReport, error) {
	var r GateReport
	data, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(data, &r)
	return r, err
}

func writeGolden(path string, r GateReport) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
