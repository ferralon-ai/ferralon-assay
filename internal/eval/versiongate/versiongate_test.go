package versiongate

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/corpus"
	"github.com/ferralon-ai/ferralon-assay/internal/eval/versionaccuracy"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// --- builders ---------------------------------------------------------------

func fix(id string, cat corpus.Category) corpus.Fixture {
	return corpus.Fixture{
		ID:       id,
		Category: cat,
		Codebase: corpus.Codebase{
			Repo:     "repo/" + id,
			Revision: "rev-" + id,
			Acquisition: corpus.Acquisition{
				Mode: "vendored_repro",
				Path: "testdata/repros/" + id + "/",
			},
		},
	}
}

func onode(purl, ver string, direct bool, proj string) versionaccuracy.OracleNode {
	return versionaccuracy.OracleNode{PURL: purl, Version: ver, Direct: direct, Project: proj}
}

func freshOracle(f corpus.Fixture, nodes []versionaccuracy.OracleNode, edges []versionaccuracy.OracleEdge) *versionaccuracy.Oracle {
	return &versionaccuracy.Oracle{
		FixtureID: f.ID, Category: f.Category, Nodes: nodes, Edges: edges,
		Capture: versionaccuracy.Capture{FixtureDigest: versionaccuracy.FixtureDigest(f)},
	}
}

func rnode(purl, ver string, direct bool, proj string, reasons ...string) plugin.DependencyNode {
	n := plugin.DependencyNode{
		PURL: purl, ID: purl, Version: ver, Direct: direct,
		Membership: plugin.DependencyMembership{Project: proj},
	}
	if len(reasons) > 0 {
		n.Partiality = plugin.Partial(reasons...)
	} else {
		n.Partiality = plugin.Complete()
	}
	return n
}

func inv(complete bool, nodes []plugin.DependencyNode, graphReasons ...string) plugin.DependencyInventory {
	i := plugin.DependencyInventory{Nodes: nodes}
	if complete {
		i.Partiality = plugin.Complete()
	} else {
		i.Partiality = plugin.Partial(graphReasons...)
	}
	return i
}

// runGate wires the injected oracle map + resolved-inventory map (keyed by fixture id) into a
// Run over the given fixtures. A fixture absent from the oracle map has no oracle (honest
// absence). A fixture absent from the inv map resolves to an empty complete inventory.
func runGate(t *testing.T, lane string, fixtures []corpus.Fixture, oracles map[string]*versionaccuracy.Oracle, invs map[string]plugin.DependencyInventory) GateReport {
	t.Helper()
	byDir := map[string]plugin.DependencyInventory{}
	for _, f := range fixtures {
		if iv, ok := invs[f.ID]; ok {
			byDir[corpus.ReproPath(f.Codebase.Acquisition.Path)] = iv
		}
	}
	resolve := func(_ context.Context, buildDir string) (plugin.DependencyInventory, error) {
		if iv, ok := byDir[buildDir]; ok {
			return iv, nil
		}
		return inv(true, nil), nil
	}
	src := func(id string) (*versionaccuracy.Oracle, error) { return oracles[id], nil }
	rep, err := Run(context.Background(), lane, fixtures, src, resolve)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rep
}

// --- C1: an absent or stale oracle is a comparison gap (a gate failure) -------

func TestC1_AbsentAndStaleAreGaps(t *testing.T) {
	const proj = "example.com/m"
	present := fix("has-oracle", corpus.CategoryPatched)
	absent := fix("no-oracle", corpus.CategoryPatched)
	stale := fix("stale-oracle", corpus.CategoryPatched)

	on := []versionaccuracy.OracleNode{onode("pkg:golang/foo@v1.0.0", "v1.0.0", true, proj)}
	staleOracle := freshOracle(stale, on, nil)
	staleOracle.Capture.FixtureDigest = "sha256:deadbeef" // does not match the fixture -> stale

	fixtures := []corpus.Fixture{present, absent, stale}
	oracles := map[string]*versionaccuracy.Oracle{
		present.ID: freshOracle(present, on, nil),
		// absent.ID intentionally missing
		stale.ID: staleOracle,
	}
	invs := map[string]plugin.DependencyInventory{
		present.ID: inv(true, []plugin.DependencyNode{rnode("pkg:golang/foo@v1.0.0", "v1.0.0", true, proj)}),
	}
	rep := runGate(t, "go", fixtures, oracles, invs)

	gaps := rep.C1OracleComparisonGaps()
	if len(gaps) != 2 {
		t.Fatalf("want 2 comparison gaps (absent + stale), got %d: %v", len(gaps), gaps)
	}
	// The gaps must name the reason so the verdict can route them.
	var sawAbsent, sawStale bool
	for _, g := range gaps {
		switch g {
		case "no-oracle:" + versionaccuracy.ReasonOracleAbsent:
			sawAbsent = true
		case "stale-oracle:" + versionaccuracy.ReasonOracleStale:
			sawStale = true
		}
	}
	if !sawAbsent || !sawStale {
		t.Fatalf("gaps must name absent+stale reasons, got %v", gaps)
	}
	// Control: the present, fresh, agreeing fixture is NOT a gap and NOT a miss.
	if len(rep.Misses()) != 0 {
		t.Fatalf("agreeing fixture must not be a miss, got %v", rep.Misses())
	}
}

// --- C2/C3: sub-scores decompose; slices grade separately, empty slice != pass --

func TestC3_SliceStatesAndDecomposition(t *testing.T) {
	const proj = "example.com/m"
	on := []versionaccuracy.OracleNode{
		onode("pkg:golang/a@v1.2.0", "v1.2.0", true, proj),
		onode("pkg:golang/b@v0.1.0", "v0.1.0", false, proj),
	}
	edges := []versionaccuracy.OracleEdge{{
		Parent: onode("pkg:golang/a@v1.2.0", "", false, proj).PURL + "\x1f" + proj + "\x1f\x1f",
		Child:  onode("pkg:golang/b@v0.1.0", "", false, proj).PURL + "\x1f" + proj + "\x1f\x1f",
	}}

	agree := fix("agree", corpus.CategoryTriviallyExploitable)
	wrongEdge := fix("wrong-edge", corpus.CategoryAbsentNotExploitable)

	fixtures := []corpus.Fixture{agree, wrongEdge}
	oracles := map[string]*versionaccuracy.Oracle{
		agree.ID:     freshOracle(agree, on, edges),
		wrongEdge.ID: freshOracle(wrongEdge, on, edges),
	}
	// agree: same nodes + same edge. wrong-edge: correct versions, NO edges -> parent_edge miss,
	// exact_version + transitive still full agreement (C2: axes must decompose).
	agreeNodes := []plugin.DependencyNode{
		rnode("pkg:golang/a@v1.2.0", "v1.2.0", true, proj),
		rnode("pkg:golang/b@v0.1.0", "v0.1.0", false, proj),
	}
	invs := map[string]plugin.DependencyInventory{
		agree.ID: withEdges(inv(true, agreeNodes), proj),
		wrongEdge.ID: inv(true, []plugin.DependencyNode{
			rnode("pkg:golang/a@v1.2.0", "v1.2.0", true, proj),
			rnode("pkg:golang/b@v0.1.0", "v0.1.0", false, proj),
		}),
	}
	rep := runGate(t, "go", fixtures, oracles, invs)

	if !rep.C2Decomposed() {
		t.Fatal("C2: sub-scores must be reported as three separate axes")
	}
	// The agreeing slice passes; the wrong-edge slice fails on a MEASURED edge miss while its
	// version axis still agrees — a blend could not tell these apart.
	if got := rep.SliceState(corpus.CategoryTriviallyExploitable); got != StatePass {
		t.Fatalf("agree slice: want pass, got %s", got)
	}
	if got := rep.SliceState(corpus.CategoryAbsentNotExploitable); got != StateFail {
		t.Fatalf("wrong-edge slice: want fail (measured edge miss), got %s", got)
	}
	// A named slice with no fixtures is a coverage finding, never a default pass (C3).
	if got := rep.SliceState(corpus.CategoryInstalledUndetermined); got != StateUnmeasurableCoverage {
		t.Fatalf("empty slice: want unmeasurable_coverage, got %s", got)
	}
	// Decompose evidence: wrong-edge fixture has version-axis agreement but an edge miss.
	we := outcomeByID(t, rep, "wrong-edge")
	if !we.isMiss() {
		t.Fatal("wrong-edge must be a miss (edge disagreement)")
	}
	if s := we.Result.Scores.ExactVersion; s.State != versionaccuracy.StateMeasured || s.Rate.Num != s.Rate.Denom {
		t.Fatalf("wrong-edge exact_version must be measured full agreement, got %s %v", s.State, s.Rate)
	}
}

// --- §3.6: preserved partiality is not laundered into a version-axis miss -----

func TestVersionAxisUnmeasurablePreserved(t *testing.T) {
	const proj = "example.com/m"
	f := fix("unpinned", corpus.CategoryPatched)
	on := []versionaccuracy.OracleNode{onode("pkg:golang/foo@v1.0.0", "v1.0.0", true, proj)}
	// Resolver reproduces the coordinate but declares source_unpinned on the node (no artifact
	// digest): the version axis must go UNMEASURABLE, not score a miss.
	iv := inv(true, []plugin.DependencyNode{
		rnode("pkg:golang/foo@v1.0.0", "v1.0.0", true, proj, plugin.PartialReasonSourceUnpinned),
	})
	rep := runGate(t, "go", []corpus.Fixture{f},
		map[string]*versionaccuracy.Oracle{f.ID: freshOracle(f, on, nil)},
		map[string]plugin.DependencyInventory{f.ID: iv})

	o := outcomeByID(t, rep, "unpinned")
	if o.isMiss() {
		t.Fatal("source_unpinned must not be a miss (§3.6 preservation)")
	}
	if o.Result.Scores.ExactVersion.State != versionaccuracy.StateUnmeasurable {
		t.Fatalf("exact_version must be unmeasurable, got %s", o.Result.Scores.ExactVersion.State)
	}
	measured, unmeas := rep.VersionAxisCoverage()
	if measured != 0 || unmeas != 1 {
		t.Fatalf("version-axis coverage want measured=0 unmeasurable=1, got %d/%d", measured, unmeas)
	}
}

// --- C5: partiality preserved, with a negative control -----------------------

func TestC5_PartialityControl(t *testing.T) {
	const proj = "example.com/m"
	complete := fix("complete", corpus.CategoryPatched)
	partial := fix("partial", corpus.CategoryReachableUnconfirmable)
	on := []versionaccuracy.OracleNode{onode("pkg:golang/foo@v1.0.0", "v1.0.0", true, proj)}

	fixtures := []corpus.Fixture{complete, partial}
	oracles := map[string]*versionaccuracy.Oracle{
		complete.ID: freshOracle(complete, on, nil),
		partial.ID:  freshOracle(partial, on, nil),
	}
	invs := map[string]plugin.DependencyInventory{
		complete.ID: inv(true, []plugin.DependencyNode{rnode("pkg:golang/foo@v1.0.0", "v1.0.0", true, proj)}),
		partial.ID:  inv(false, []plugin.DependencyNode{rnode("pkg:golang/foo@v1.0.0", "v1.0.0", true, proj)}, plugin.PartialReasonToolFailure),
	}
	rep := runGate(t, "go", fixtures, oracles, invs)

	pwr, ctrl := rep.C5PartialityControl()
	if !pwr {
		t.Fatal("C5: a partial-with-reason resolution must be observed")
	}
	if !ctrl {
		t.Fatal("C5: a complete resolution (negative control) must be observed")
	}
}

// --- helpers ----------------------------------------------------------------

// withEdges adds the a->b parent edge (matching the TestC3 oracle) to an inventory whose nodes
// are keyed by PURL==ID, so the resolved edge maps into the oracle key space.
func withEdges(i plugin.DependencyInventory, _ string) plugin.DependencyInventory {
	i.Edges = []plugin.DependencyEdge{{Parent: "pkg:golang/a@v1.2.0", Child: "pkg:golang/b@v0.1.0"}}
	return i
}

func outcomeByID(t *testing.T, r GateReport, id string) FixtureOutcome {
	t.Helper()
	for _, o := range r.Outcomes {
		if o.FixtureID == id {
			return o
		}
	}
	t.Fatalf("no outcome for %q", id)
	return FixtureOutcome{}
}
