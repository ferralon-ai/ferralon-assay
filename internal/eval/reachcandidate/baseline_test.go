package reachcandidate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// baselinePath is the committed Go recall golden the eval_live gate diffs against. It holds the
// per-case candidate-formation state of a real live Go run (regenerated with TEGRON_EVAL_UPDATE=1);
// the eval_live gate fails on any case that formed a candidate here but stops forming one (a recall
// regression). The aggregate Recall()/Precision() rates stay n/a until expected_sinks.json is
// populated, but the per-case floor gates regardless.
const baselinePath = "testdata/baseline.json"

// sortResultsByCaseID returns a copy of the report with Results ordered by the unique CaseID.
// Persisting and diffing over a stable order is what makes the golden deterministic (map
// iteration in Run's upstream inputs is not). Ordering on CaseID rather than VulnID also keeps
// the per-variant rows of one advisory distinct instead of collapsing them.
func sortResultsByCaseID(r Report) Report {
	out := Report{Label: r.Label, Results: append([]CaseResult(nil), r.Results...)}
	sort.Slice(out.Results, func(i, j int) bool { return out.Results[i].CaseID < out.Results[j].CaseID })
	return out
}

// zeroRuntime returns a copy of the report with every CaseResult.RuntimeMS zeroed. RuntimeMS is
// environment-variant (§4.7.13), so it is EXCLUDED from golden round-trip equality — a report
// that differs only in wall-clock is the same golden.
func zeroRuntime(r Report) Report {
	out := Report{Label: r.Label, Results: append([]CaseResult(nil), r.Results...)}
	for i := range out.Results {
		out.Results[i].RuntimeMS = 0
	}
	return out
}

// loadBaselineReport reads and decodes a committed golden Report.
func loadBaselineReport(path string) (Report, error) {
	var rep Report
	data, err := os.ReadFile(path)
	if err != nil {
		return rep, err
	}
	err = json.Unmarshal(data, &rep)
	return rep, err
}

// writeBaselineReport marshals a report (results sorted by CaseID) to the golden path. This is
// the TEGRON_EVAL_UPDATE=1 regenerate idiom the live runner calls once anvil has real numbers.
func writeBaselineReport(path string, rep Report) error {
	data, err := json.MarshalIndent(sortResultsByCaseID(rep), "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// TestBaselineGoldenMechanism is the hermetic (no build tag) guardrail for Deliverable B. It
// proves the golden serialization round-trips and that the DiffReport.Regressed() gate fires
// correctly, using ONLY the synthetic fakeProgramPlugin data (no plugin, no toolchain). It
// regression-gates the mechanism even though the live numbers land later.
func TestBaselineGoldenMechanism(t *testing.T) {
	p := program()
	// A run that forms a correct candidate for CVE-CORRECT (recall+precision hit). CaseID is
	// the unique key now — distinct per case, so the diff/sort keys never collide.
	golden := sortResultsByCaseID(Run(context.Background(), p, "golden (synthetic)", []Case{
		{CaseID: "CVE-CORRECT-vulnerable", VulnID: "CVE-CORRECT", Symbols: []string{"language.Parse"}, ExpectedSinks: []string{"language.Parse"}, BuildDir: "/fake"},
		{CaseID: "CVE-WRONGSINK-vulnerable", VulnID: "CVE-WRONGSINK", Symbols: []string{"language.Compose"}, ExpectedSinks: []string{"language.Parse"}, BuildDir: "/fake"},
	}))

	// (1) In-memory round-trip: marshal → unmarshal → DeepEqual. Err is json:"-" so it stays
	// nil on both sides. RuntimeMS is environment-variant, so it is zeroed on both sides before
	// the compare (excluded from golden equality) — a slower run is still the same golden.
	data, err := json.Marshal(golden)
	if err != nil {
		t.Fatalf("marshal golden: %v", err)
	}
	var back Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	if !reflect.DeepEqual(zeroRuntime(golden), zeroRuntime(back)) {
		t.Fatalf("golden did not round-trip:\n got %+v\nwant %+v", back, golden)
	}

	// (2) On-disk round-trip through the persist/reload helpers the live updater uses.
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := writeBaselineReport(path, golden); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	reloaded, err := loadBaselineReport(path)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	if !reflect.DeepEqual(zeroRuntime(golden), zeroRuntime(reloaded)) {
		t.Fatalf("persisted golden did not round-trip:\n got %+v\nwant %+v", reloaded, golden)
	}

	// (3) The gate does NOT fire against itself.
	if Diff(golden, golden).Regressed() {
		t.Errorf("Diff(golden, golden) must not regress:\n%s", Diff(golden, golden))
	}

	// (4) The gate DOES fire on a genuine regression: re-running the same CVEs with empty
	// symbol lists drops both candidates (LostCandidate) — recall went backward.
	regressed := sortResultsByCaseID(Run(context.Background(), p, "regressed (symbols dropped)", []Case{
		{CaseID: "CVE-CORRECT-vulnerable", VulnID: "CVE-CORRECT", Symbols: nil, ExpectedSinks: []string{"language.Parse"}, BuildDir: "/fake"},
		{CaseID: "CVE-WRONGSINK-vulnerable", VulnID: "CVE-WRONGSINK", Symbols: nil, ExpectedSinks: []string{"language.Parse"}, BuildDir: "/fake"},
	}))
	dr := Diff(golden, regressed)
	if !dr.Regressed() {
		t.Errorf("Diff(golden, regressedRun) must regress (lost candidates):\n%s", dr)
	}

	// (5) The committed golden decodes cleanly and does not regress against itself — the durable
	// property the live gate relies on. This holds whether the golden is the empty seed or the
	// real anvil-generated baseline, so filling in real numbers never reddens the hermetic suite.
	committed, err := loadBaselineReport(baselinePath)
	if err != nil {
		t.Fatalf("load committed %s: %v", baselinePath, err)
	}
	if Diff(committed, committed).Regressed() {
		t.Errorf("committed baseline must not regress against itself:\n%s", Diff(committed, committed))
	}
}
