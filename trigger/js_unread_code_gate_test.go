package trigger

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/jsanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestUndeterminedReason_JSUnreadCodeNeverRefutes runs JS programs that load code the lane
// does not read through the real producer (jsanalysis CallGraph and Reachability), records
// the result the way the reachability stage does when no vulnerable symbol was resolved, and
// asserts the refutation gate holds the verdict undetermined. Each program has call edges,
// so the gate's zero-edge arm cannot be what holds it.
func TestUndeterminedReason_JSUnreadCodeNeverRefutes(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"binding alias", `
const lib = require('json5'); const p = lib;
function load(s) { return p.parse(s); }
load(process.argv[2]);
`},
		{"inline require", `
function load(s) { return require('json5').parse(s); }
load(process.argv[2]);
`},
		{"aliased require", `
const r = require;
function load(s) { return r('json5').parse(s); }
load(process.argv[2]);
`},
		{"concatenated require", `
function load(s, n) { return require('./plugins/' + n).parse(s); }
load(process.argv[2], 'json5');
`},
		{"interpolated template require", `
function load(s, n) { return require(` + "`./${n}`" + `).parse(s); }
load(process.argv[2], 'json5');
`},
		{"native addon", `
const addon = require('./build/Release/x.node');
function load(s) { return addon.parse(s); }
load(process.argv[2]);
`},
		{"generated module absent from the tree", `
const gen = require('./dist/gen');
function load(s) { return gen.parse(s); }
load(process.argv[2]);
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, edges := gateStoreFromJS(t, tc.src)
			if edges == 0 {
				t.Fatalf("program must have call edges")
			}
			if reason, ok := undeterminedReason(store, "a1"); !ok || reason != report.ReasonAnalysisDidNotRun {
				t.Errorf("undeterminedReason = (%q, %v); want (%q, true): not_exploitable would stand", reason, ok, report.ReasonAnalysisDidNotRun)
			}
		})
	}
}

// TestUndeterminedReason_JSFirstPartyOnlyCanRefute is the control: a program that loads
// nothing outside the tree passes the gate, so the test above detects a refutable result.
func TestUndeterminedReason_JSFirstPartyOnlyCanRefute(t *testing.T) {
	store, _ := gateStoreFromJS(t, `
function parse(s) { return s.trim(); }
function load(s) { return parse(s); }
load(process.argv[2]);
`)
	if reason, ok := undeterminedReason(store, "a1"); ok {
		t.Errorf("undeterminedReason = (%q, true); want refutable", reason)
	}
}

// gateStoreFromJS writes src as index.js, runs the JS producer over it, and stores the call
// graph and reachability partiality as the reachability and exposure-footprint artifacts.
func gateStoreFromJS(t *testing.T, src string) (*artifact.MemStore, int) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"package.json":        `{"name":"fixture","version":"1.0.0","dependencies":{"json5":"2.2.1"}}`,
		"index.js":            src,
		"plugins/index.js":    "function parse(s) { return s; }\nmodule.exports = { parse };\n",
		"node_modules/.keep":  "",
		"build/Release/.keep": "",
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	cg, err := jsanalysis.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	reach, err := jsanalysis.Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	store := artifact.NewMemStore()
	payload, err := json.Marshal(struct {
		Reachability plugin.ReachabilityResult `json:"reachability"`
		CallGraph    plugin.CallGraphResult    `json:"call_graph"`
	}{reach, cg})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(&artifact.Artifact{AssessmentID: "a1", Type: artifact.TypeReachability, ProducedBy: "test", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	seedFootprint(t, store, "a1", reach.Partiality.Reasons)
	return store, len(cg.Edges)
}
