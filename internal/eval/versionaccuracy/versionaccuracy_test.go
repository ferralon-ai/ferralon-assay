package versionaccuracy

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/corpus"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// fully-populated hand-built oracle: ≥2 nodes, ≥1 edge, ≥1 workspace-scoped node, every field
// non-zero (including a declared environment). Nothing populates oracles this cycle, so this
// is hand-built by design (C1).
func fullOracle() Oracle {
	a := OracleNode{PURL: "pkg:golang/example.com/a@1.0.0", Version: "1.0.0", Direct: true, Project: "svc", Workspace: "mono", Target: "runtime"}
	b := OracleNode{PURL: "pkg:golang/example.com/b@2.0.0", Version: "2.0.0", Direct: false, Project: "svc", Workspace: "mono", Target: "runtime"}
	return Oracle{
		FixtureID: "FIX-1",
		Category:  corpus.CategoryReachableUnconfirmable,
		Nodes:     []OracleNode{a, b},
		Edges:     []OracleEdge{{Parent: a.key(), Child: b.key()}},
		Capture: Capture{
			Tool: "go mod", ToolVersion: "go1.26.3", Command: "go mod graph",
			Operator: "eric", CapturedAt: "2026-08-12T00:00:00Z", FixtureDigest: "sha256:deadbeef",
			Environment: map[string]string{"runtime": "go1.26.3", "platform": "linux/amd64"},
		},
	}
}

// obsFor returns the Observed comparability facts that make an oracle fresh + same-environment.
func obsFor(o Oracle) Observed {
	return Observed{FixtureDigest: o.Capture.FixtureDigest, Environment: o.Capture.Environment}
}

// C1 — the oracle records the whole resolved graph and survives a JSON round-trip with every
// field preserved.
func TestOracleJSONRoundTrip(t *testing.T) {
	orig := fullOracle()
	blob, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Oracle
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("round-trip lost a field:\n orig=%+v\n  got=%+v\n json=%s", orig, got, blob)
	}
	// The load-bearing transitive bool must be SERIALIZED as false, not omitted — an
	// accidental omitempty on Direct would drop it from the wire, and a version-only oracle
	// that cannot distinguish direct from transitive nodes is exactly the failure C1 exists to
	// prevent. Assert on the bytes, not just the decoded value (a false bool decodes to false
	// with or without omitempty, so DeepEqual alone would not catch it).
	if !bytes.Contains(blob, []byte(`"direct":false`)) {
		t.Fatalf("transitive node did not serialize \"direct\":false — Direct must not be omitempty; json=%s", blob)
	}
}

func inv(nodes []plugin.DependencyNode, edges []plugin.DependencyEdge) plugin.DependencyInventory {
	return plugin.DependencyInventory{Nodes: nodes, Edges: edges}
}

func node(id, purl, version string, direct bool, proj, ws, target string) plugin.DependencyNode {
	return plugin.DependencyNode{
		ID: id, PURL: purl, Version: version, Direct: direct,
		Membership: plugin.DependencyMembership{Project: proj, Workspace: ws, Target: target},
	}
}

// C2 — a stale, absent, or environment-mismatched oracle yields unmeasurable, never a number;
// and a FRESH oracle with a genuinely low score is distinguishable in the ledger from an
// unmeasurable one (negative control). If one assertion accepted both, the test would be
// measuring nothing.
//
// Mutation control: delete the FixtureDigest comparison in Measure and the "stale" row returns
// StateMeasured, turning this table red.
func TestStaleness_FreshStaleAbsent(t *testing.T) {
	oracle := fullOracle()
	// A resolver that disagrees with everything: wrong version, no matching edges — a fresh
	// but genuinely-low measurement, NOT an unmeasurable one. No partiality, so axes measure.
	badResolved := inv(
		[]plugin.DependencyNode{
			node("n1", "pkg:golang/example.com/a@9.9.9", "9.9.9", true, "svc", "mono", "runtime"),
		}, nil,
	)
	freshEnv := oracle.Capture.Environment

	tests := []struct {
		name         string
		oracle       *Oracle
		obs          Observed
		wantState    State
		wantReason   string
		wantMeasured bool
	}{
		{"fresh-low", &oracle, obsFor(oracle), StateMeasured, "", true},
		{"stale", &oracle, Observed{FixtureDigest: "sha256:changed", Environment: freshEnv}, StateUnmeasurable, ReasonOracleStale, false},
		{"absent", nil, obsFor(oracle), StateUnmeasurable, ReasonOracleAbsent, false},
		{"env-mismatch", &oracle, Observed{FixtureDigest: oracle.Capture.FixtureDigest, Environment: map[string]string{"runtime": "go1.20"}}, StateUnmeasurable, ReasonEnvironmentMismatch, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Measure(tc.oracle, badResolved, tc.obs)
			if got.State != tc.wantState {
				t.Fatalf("State = %q, want %q", got.State, tc.wantState)
			}
			if got.Reason != tc.wantReason {
				t.Fatalf("Reason = %q, want %q", got.Reason, tc.wantReason)
			}
			if tc.wantMeasured {
				if got.Scores.ExactVersion.State != StateMeasured || got.Scores.ExactVersion.Rate.Float() >= 1.0 {
					t.Fatalf("expected a genuinely low measured fresh score, got %+v", got.Scores.ExactVersion)
				}
			} else if got.Scores.ExactVersion.Rate.Denom != 0 {
				t.Fatalf("unmeasurable Result leaked a measured score: %+v", got.Scores.ExactVersion)
			}
		})
	}
}

// C3 — the metric decomposes. A resolver with correct versions and wrong parent edges must
// produce a HIGH version sub-score and a LOW edge sub-score, each measured.
func TestSubScoresDecompose(t *testing.T) {
	oracle := fullOracle() // nodes a@1.0.0 (direct), b@2.0.0 (transitive); edge a->b
	resolved := inv(
		[]plugin.DependencyNode{
			node("na", "pkg:golang/example.com/a@1.0.0", "1.0.0", true, "svc", "mono", "runtime"),
			node("nb", "pkg:golang/example.com/b@2.0.0", "2.0.0", false, "svc", "mono", "runtime"),
			node("nc", "pkg:golang/example.com/c@3.0.0", "3.0.0", true, "svc", "mono", "runtime"),
		},
		[]plugin.DependencyEdge{{Parent: "na", Child: "nc"}}, // wrong: oracle says a->b
	)
	got := Measure(&oracle, resolved, obsFor(oracle))
	if got.State != StateMeasured {
		t.Fatalf("State = %q, want measured", got.State)
	}
	ev, ts, pe := got.Scores.ExactVersion, got.Scores.TransitiveSet, got.Scores.ParentEdge
	if ev.State != StateMeasured || ev.Rate.Float() != 1.0 {
		t.Fatalf("ExactVersion = %+v, want measured 1.0", ev)
	}
	if ts.State != StateMeasured || ts.Rate.Float() != 1.0 {
		t.Fatalf("TransitiveSet = %+v, want measured 1.0", ts)
	}
	if pe.State != StateMeasured || pe.Rate.Float() != 0.0 {
		t.Fatalf("ParentEdge = %+v, want measured 0.0", pe)
	}
	if ev.Rate.Float() == pe.Rate.Float() {
		t.Fatalf("version and edge sub-scores are equal — the metric is blending, not decomposing")
	}
}

// §3.6 boundary (L0 input, folded in before hardening) — a preserved Partiality on the
// resolved set makes the touched axis UNMEASURABLE, never a scored miss. The other axes still
// measure. Laundering preserved Partiality into a measured FAILURE is the failure this guards.
//
// Mutation control: drop the axis() gating and the unmeasurable expectations go red — the axis
// would score the honestly-partial graph as a low agreement rate.
func TestPartialityAxesUnmeasurable(t *testing.T) {
	oracle := fullOracle() // a@1.0.0 direct, b@2.0.0 transitive; edge a->b

	// (1) relationship_unexpressed (lane-suffixed) => ParentEdge unmeasurable, version measured.
	relResolved := plugin.DependencyInventory{
		Partiality: plugin.Partiality{Reasons: []string{plugin.PartialReasonRelationshipUnexpressed + ":python_extras"}},
		Nodes: []plugin.DependencyNode{
			node("na", "pkg:golang/example.com/a@1.0.0", "1.0.0", true, "svc", "mono", "runtime"),
			node("nb", "pkg:golang/example.com/b@2.0.0", "2.0.0", false, "svc", "mono", "runtime"),
		},
	}
	got := Measure(&oracle, relResolved, obsFor(oracle))
	if got.Scores.ParentEdge.State != StateUnmeasurable {
		t.Fatalf("ParentEdge with relationship_unexpressed must be unmeasurable, got %+v", got.Scores.ParentEdge)
	}
	if got.Scores.ParentEdge.Reason != plugin.PartialReasonRelationshipUnexpressed+":python_extras" {
		t.Fatalf("ParentEdge reason lost the lane suffix: %q", got.Scores.ParentEdge.Reason)
	}
	if got.Scores.ParentEdge.Rate.Denom != 0 {
		t.Fatalf("unmeasurable ParentEdge leaked a measured rate: %+v", got.Scores.ParentEdge.Rate)
	}
	if got.Scores.ExactVersion.State != StateMeasured {
		t.Fatalf("ExactVersion must still measure when only edges are unexpressed, got %+v", got.Scores.ExactVersion)
	}

	// (2) source_unpinned on a node (the OUTOFRANGE case) => ExactVersion unmeasurable, edges measured.
	verResolved := plugin.DependencyInventory{
		Nodes: []plugin.DependencyNode{
			node("na", "pkg:golang/example.com/a@1.0.0", "1.0.0", true, "svc", "mono", "runtime"),
			func() plugin.DependencyNode {
				n := node("nb", "pkg:golang/example.com/b@2.0.0", "2.0.0", false, "svc", "mono", "runtime")
				n.Partiality = plugin.Partiality{Reasons: []string{plugin.PartialReasonSourceUnpinned}}
				return n
			}(),
		},
		Edges: []plugin.DependencyEdge{{Parent: "na", Child: "nb"}},
	}
	got = Measure(&oracle, verResolved, obsFor(oracle))
	if got.Scores.ExactVersion.State != StateUnmeasurable || got.Scores.ExactVersion.Reason != plugin.PartialReasonSourceUnpinned {
		t.Fatalf("ExactVersion with source_unpinned must be unmeasurable{source_unpinned}, got %+v", got.Scores.ExactVersion)
	}
	if got.Scores.ParentEdge.State != StateMeasured {
		t.Fatalf("ParentEdge must still measure when only the version is unpinned, got %+v", got.Scores.ParentEdge)
	}
}

// C4 — results slice by corpus category; every category present is individually readable and
// none is silently dropped.
func TestLedgerCategoryCoverage(t *testing.T) {
	present := []corpus.Category{
		corpus.CategoryReachableUnconfirmable,
		corpus.CategoryInstalledUndetermined,
		corpus.CategoryPatched,
	}
	l := NewLedger()
	for i, c := range present {
		l.Add(Result{FixtureID: string(rune('A' + i)), Category: c, State: StateUnmeasurable, Reason: ReasonOracleAbsent})
	}

	if got := l.Categories(); len(got) != len(present) {
		t.Fatalf("breakdown covers %d categories, want %d: %v", len(got), len(present), got)
	}
	for _, c := range present {
		if rows, ok := l.ByCategory[c]; !ok || len(rows) == 0 {
			t.Fatalf("category %q present in corpus but absent from the breakdown", c)
		}
	}
	if got := l.ByCategory[corpus.CategoryInstalledUndetermined]; len(got) != 1 {
		t.Fatalf("installed_undetermined slice = %d rows, want 1 (category-specific visibility)", len(got))
	}
}

// FixtureDigest is deterministic and distinguishes fixtures whose dependency-defining inputs
// differ — the property the staleness anchor (C2) relies on.
func TestFixtureDigest_DeterministicAndDistinguishing(t *testing.T) {
	f1 := corpus.Fixture{ID: "F1", Codebase: corpus.Codebase{Repo: "r", Revision: "abc",
		Acquisition: corpus.Acquisition{Mode: "pinned_ref", Module: "m", Version: "1.0.0"}}}
	f1again := f1
	f2 := f1
	f2.Codebase.Acquisition.Version = "1.0.1"
	if FixtureDigest(f1) != FixtureDigest(f1again) {
		t.Fatalf("FixtureDigest is not deterministic")
	}
	if FixtureDigest(f1) == FixtureDigest(f2) {
		t.Fatalf("FixtureDigest collides across a version change — staleness would go undetected")
	}
}
