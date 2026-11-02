package pipeline

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const reachReadAID = "01900000-0000-7000-8000-000000000041"

func putReachPayload(t *testing.T, store artifact.Store, payload []byte) {
	t.Helper()
	if _, err := store.Put(&artifact.Artifact{AssessmentID: reachReadAID, Type: artifact.TypeReachability, Payload: payload}); err != nil {
		t.Fatal(err)
	}
}

func resolvedReachPayload(t *testing.T) []byte {
	t.Helper()
	sym := func(s string) plugin.Symbol { return plugin.Symbol{SCIP: s} }
	b, err := json.Marshal(struct {
		Reachability  plugin.ReachabilityResult `json:"reachability"`
		CallGraph     plugin.CallGraphResult    `json:"call_graph"`
		ToolchainScan ToolchainScan             `json:"toolchain_scan"`
	}{
		Reachability: plugin.ReachabilityResult{
			Partiality: plugin.Partiality{Reasons: []string{"r1"}, Scoped: []plugin.ScopedReason{{Reason: "s", Package: "p", Targets: []string{"t"}}}},
			Paths:      []plugin.ReachPath{{Sink: sym("sink"), Ingress: sym("main"), Trace: []plugin.Symbol{sym("main"), sym("sink")}}},
			Searched:   []string{"sink"},
		},
		CallGraph: plugin.CallGraphResult{
			Partiality: plugin.Partiality{Reasons: []string{"c1"}, Scoped: []plugin.ScopedReason{{Reason: "cs", Package: "cp", Targets: []string{"ct1", "ct2"}}}},
			Algorithm:  "vta",
			Edges:      []plugin.CallEdge{{Caller: sym("main"), Callee: sym("foo")}, {Caller: sym("foo"), Callee: sym("sink")}},
			Roots:      []plugin.Symbol{sym("main")},
		},
		ToolchainScan: ToolchainScan{Requested: "go1.22.1", Actual: "go1.22.1", Subject: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestReachabilityRecordMatchesNarrowDecode pins that every leg reads exactly as the per-reader
// narrow decode it replaces: same value, and an error exactly when that decode errs.
func TestReachabilityRecordMatchesNarrowDecode(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"resolved", resolvedReachPayload(t)},
		{"stub", []byte(`{"reachable":true}`)},
		{"stub false", []byte(`{"reachable":false}`)},
		{"empty object", []byte(`{}`)},
		{"null", []byte(`null`)},
		{"null legs", []byte(`{"reachability":null,"call_graph":null,"toolchain_scan":null,"reachable":null}`)},
		{"not an object", []byte(`[1]`)},
		{"invalid", []byte(`{`)},
		{"reachability type error", []byte(`{"reachability":{"paths":"x"},"call_graph":{"edges":[]},"reachable":true}`)},
		{"call graph type error", []byte(`{"reachability":{"paths":[{}]},"call_graph":{"edges":7},"toolchain_scan":{"subject":true}}`)},
		{"toolchain type error", []byte(`{"toolchain_scan":{"subject":"yes"},"reachable":true}`)},
		{"reachable type error", []byte(`{"reachable":"yes"}`)},
		{"keys match case-insensitively", []byte(`{"Reachability":{"paths":[{}]},"CALL_GRAPH":{"algorithm":"cha","edges":[{}]},"Toolchain_Scan":{"subject":true},"Reachable":true}`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			putReachPayload(t, store, tc.payload)
			rec, ok, err := Reachability(store, reachReadAID)
			if err != nil || !ok {
				t.Fatalf("Reachability = %v, %v", ok, err)
			}

			var reachOnly struct {
				Reachability plugin.ReachabilityResult `json:"reachability"`
			}
			wantReachErr := json.Unmarshal(tc.payload, &reachOnly) != nil
			reach, err := rec.Result()
			checkLeg(t, "Result", reach, reachOnly.Reachability, err, wantReachErr)

			var cgOnly struct {
				CallGraph plugin.CallGraphResult `json:"call_graph"`
			}
			wantCGErr := json.Unmarshal(tc.payload, &cgOnly) != nil
			cg, err := rec.CallGraph()
			if (err != nil) != wantCGErr {
				t.Errorf("CallGraph err = %v, want error %v", err, wantCGErr)
			}
			if err == nil {
				var edges []plugin.CallEdge
				for e := range cg.Edges() {
					edges = append(edges, e)
				}
				if !slices.Equal(edges, cgOnly.CallGraph.Edges) || cg.EdgeCount() != len(cgOnly.CallGraph.Edges) {
					t.Errorf("CallGraph edges = %v, want %v", edges, cgOnly.CallGraph.Edges)
				}
				if got := cg.Partiality(); !reflect.DeepEqual(got, cgOnly.CallGraph.Partiality) {
					t.Errorf("CallGraph partiality = %+v, want %+v", got, cgOnly.CallGraph.Partiality)
				}
			}

			// The exposure stage decoded both legs together; its harvest gate is both legs decoding.
			var full struct {
				Reachability plugin.ReachabilityResult `json:"reachability"`
				CallGraph    plugin.CallGraphResult    `json:"call_graph"`
			}
			_, cgErr := rec.CallGraph()
			_, reachErr := rec.Result()
			if got, want := reachErr == nil && cgErr == nil, json.Unmarshal(tc.payload, &full) == nil; got != want {
				t.Errorf("exposure harvest gate = %v, want %v", got, want)
			}

			var tsOnly struct {
				ToolchainScan ToolchainScan `json:"toolchain_scan"`
			}
			wantTSErr := json.Unmarshal(tc.payload, &tsOnly) != nil
			ts, err := rec.ToolchainScan()
			checkLeg(t, "ToolchainScan", ts, tsOnly.ToolchainScan, err, wantTSErr)

			var stub struct {
				Reachable bool `json:"reachable"`
			}
			wantStubErr := json.Unmarshal(tc.payload, &stub) != nil
			reachable, err := rec.StubReachable()
			checkLeg(t, "StubReachable", reachable, stub.Reachable, err, wantStubErr)
		})
	}
}

func checkLeg[T any](t *testing.T, name string, got, want T, err error, wantErr bool) {
	t.Helper()
	if (err != nil) != wantErr {
		t.Errorf("%s err = %v, want error %v", name, err, wantErr)
	}
	if err == nil && !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %+v, want %+v", name, got, want)
	}
}

// TestReachabilityReadersDoNotShare pins that what one reader does to the values it is handed
// never reaches another reader: the small legs are fresh decodes, and the shared call graph is
// reachable only through copies.
func TestReachabilityReadersDoNotShare(t *testing.T) {
	payload := resolvedReachPayload(t)
	tests := []struct {
		name   string
		mutate func(t *testing.T, rec *ReachabilityRecord)
	}{
		{"result paths and searched", func(t *testing.T, rec *ReachabilityRecord) {
			r, _ := rec.Result()
			r.Paths[0].Sink.SCIP = "mutated"
			r.Paths[0].Trace[0].SCIP = "mutated"
			r.Searched[0] = "mutated"
			r.Partiality.Reasons[0] = "mutated"
			r.Partiality.Scoped[0].Targets[0] = "mutated"
		}},
		{"call graph partiality", func(t *testing.T, rec *ReachabilityRecord) {
			cg, _ := rec.CallGraph()
			p := cg.Partiality()
			p.Reasons[0] = "mutated"
			p.Scoped[0].Reason = "mutated"
			p.Scoped[0].Targets[1] = "mutated"
			_ = append(p.Reasons[:0], "appended")
		}},
		{"call graph edges", func(t *testing.T, rec *ReachabilityRecord) {
			cg, _ := rec.CallGraph()
			for e := range cg.Edges() {
				e.Caller.SCIP = "mutated"
				e.Callee.Name = "mutated"
			}
		}},
		{"toolchain scan", func(t *testing.T, rec *ReachabilityRecord) {
			ts, _ := rec.ToolchainScan()
			ts.Subject = false
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			putReachPayload(t, store, payload)
			first, _, _ := Reachability(store, reachReadAID)
			tc.mutate(t, first)

			second, _, err := Reachability(store, reachReadAID)
			if err != nil {
				t.Fatal(err)
			}
			if second != first {
				t.Fatal("a second read of the same store decoded the payload again; the record is meant to be shared")
			}
			fresh := artifact.NewMemStore()
			putReachPayload(t, fresh, payload)
			want, _, _ := Reachability(fresh, reachReadAID)
			if got, w := recordJSON(t, second), recordJSON(t, want); got != w {
				t.Errorf("after a reader's mutation, the next reader sees\n%s\nwant\n%s", got, w)
			}
			arts, err := store.Query(reachReadAID, artifact.TypeReachability)
			if err != nil || len(arts) != 1 || string(arts[0].Payload) != string(payload) {
				t.Errorf("stored payload changed")
			}
		})
	}
}

// recordJSON renders everything a reader can see through rec.
func recordJSON(t *testing.T, rec *ReachabilityRecord) string {
	t.Helper()
	reach, err1 := rec.Result()
	cg, err2 := rec.CallGraph()
	ts, err3 := rec.ToolchainScan()
	stub, err4 := rec.StubReachable()
	for _, err := range []error{err1, err2, err3, err4} {
		if err != nil {
			t.Fatal(err)
		}
	}
	var edges []plugin.CallEdge
	for e := range cg.Edges() {
		edges = append(edges, e)
	}
	return mustMarshal(t, []any{reach, cg.Partiality(), cg.EdgeCount(), edges, ts, stub})
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestFirstPartyReachPathsLeavesGraphUnchanged pins that the BFS over the memoized call graph, which
// every assessment in a run shares, only reads it.
func TestFirstPartyReachPathsLeavesGraphUnchanged(t *testing.T) {
	sym := func(s string) plugin.Symbol { return plugin.Symbol{SCIP: s, Name: s} }
	tests := []struct {
		name string
		cg   plugin.CallGraphResult
		sink string
	}{
		{"path through an ingress", plugin.CallGraphResult{
			Edges: []plugin.CallEdge{{Caller: sym("h"), Callee: sym("a")}, {Caller: sym("a"), Callee: sym("sink")}, {Caller: sym("b"), Callee: sym("sink")}},
			Roots: []plugin.Symbol{sym("main")},
		}, "sink"},
		{"path to a root", plugin.CallGraphResult{
			Edges: []plugin.CallEdge{{Caller: sym("main"), Callee: sym("sink")}},
			Roots: []plugin.Symbol{sym("main")},
		}, "sink"},
		{"no path", plugin.CallGraphResult{
			Edges: []plugin.CallEdge{{Caller: sym("x"), Callee: sym("y")}},
			Roots: []plugin.Symbol{sym("main")},
		}, "sink"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ing := plugin.IngressResult{Ingresses: []plugin.Ingress{{Kind: "http", Symbol: sym("h")}}}
			before := mustMarshal(t, tc.cg)
			paths := firstPartyReachPaths(plugin.NewCallGraphView(tc.cg), ing, tc.sink)
			for i := range paths {
				for j := range paths[i].Trace {
					paths[i].Trace[j].SCIP = "mutated"
				}
				paths[i].Sink.SCIP = "mutated"
			}
			if after := mustMarshal(t, tc.cg); after != before {
				t.Errorf("call graph changed:\n%s\nwant\n%s", after, before)
			}
		})
	}
}

type payloadGraphPlugin struct {
	plugin.StubPlugin
	cg plugin.CallGraphResult
}

func (p payloadGraphPlugin) CallGraph(context.Context, plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return p.cg, nil
}

// TestReachabilityPayloadBytes pins that the reachability artifact's payload is byte for byte what
// json.Marshal makes of the struct it stands for, whether the call graph view holds the memo's
// encoding or encodes the graph itself.
func TestReachabilityPayloadBytes(t *testing.T) {
	sym := func(s string) plugin.Symbol {
		return plugin.Symbol{Kind: plugin.SymbolKindFunction, Package: "example.com/<p>", Name: s, DisplayName: "p." + s + " & \u2028é", SCIP: "scip:p#" + s}
	}
	graphs := map[string]plugin.CallGraphResult{
		"empty":        {},
		"empty slices": {Edges: []plugin.CallEdge{}, Roots: []plugin.Symbol{}},
		"populated": {
			Partiality: plugin.Partiality{Reasons: []string{plugin.PartialReasonReflection}, Scoped: []plugin.ScopedReason{{Reason: plugin.PartialReasonReflection, Targets: []string{"pkg:golang/<y>"}}}},
			Algorithm:  "vta",
			Edges:      []plugin.CallEdge{{Caller: sym("a"), Callee: sym("b")}},
			Roots:      []plugin.Symbol{sym("a")},
			Unresolved: []plugin.UnresolvedCall{{}},
			Escaped:    []plugin.Symbol{sym("b")},
		},
	}
	reaches := map[string]plugin.ReachabilityResult{
		"none":  {},
		"paths": {Partiality: plugin.Complete(), Paths: []plugin.ReachPath{{Sink: sym("b"), Ingress: sym("a"), Trace: []plugin.Symbol{sym("a"), sym("b")}}}},
	}
	scans := []ToolchainScan{{}, {Requested: "go1.22.1", Actual: "go1.22.1", Subject: true}}
	for gname, cg := range graphs {
		memo, err := plugin.SharedCallGraph(context.Background(), plugin.Memoize(payloadGraphPlugin{cg: cg}), plugin.CallGraphRequest{BuildDir: "/src"})
		if err != nil {
			t.Fatal(err)
		}
		views := map[string]plugin.CallGraphView{"memoized": memo, "wrapped": plugin.NewCallGraphView(cg)}
		for vname, v := range views {
			for rname, reach := range reaches {
				for _, ts := range scans {
					t.Run(gname+"/"+vname+"/"+rname, func(t *testing.T) {
						want := mustMarshal(t, struct {
							Reachability  plugin.ReachabilityResult `json:"reachability"`
							CallGraph     plugin.CallGraphResult    `json:"call_graph"`
							ToolchainScan ToolchainScan             `json:"toolchain_scan"`
						}{reach, cg, ts})
						got, err := reachabilityPayload(reach, v, ts)
						if err != nil {
							t.Fatal(err)
						}
						if string(got) != want {
							t.Errorf("payload:\n%s\nwant\n%s", got, want)
						}
					})
				}
			}
		}
	}
}
