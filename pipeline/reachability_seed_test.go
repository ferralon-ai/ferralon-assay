package pipeline

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"sync"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// viewOnlyStore is a MemStore that keeps views but takes no seeds, so its readers decode the
// stored payload.
type viewOnlyStore struct {
	artifact.Store
	artifact.Viewer
}

func newViewOnlyStore() viewOnlyStore {
	m := artifact.NewMemStore()
	return viewOnlyStore{m, m}
}

// reachRead is everything a reader can get from a ReachabilityRecord.
type reachRead struct {
	Result        plugin.ReachabilityResult
	ResultErr     error
	CallGraphErr  error
	Partiality    plugin.Partiality
	EdgeCount     int
	Edges         []plugin.CallEdge
	Roots         []plugin.Symbol
	ToolchainScan ToolchainScan
	ToolchainErr  error
	StubReachable bool
	StubErr       error
}

func readReach(t *testing.T, store artifact.Store) reachRead {
	t.Helper()
	rec, ok, err := Reachability(store, reachReadAID)
	if err != nil || !ok {
		t.Fatalf("Reachability = %v, %v", ok, err)
	}
	return readRecord(rec)
}

func readRecord(rec *ReachabilityRecord) reachRead {
	var got reachRead
	got.Result, got.ResultErr = rec.Result()
	cg, cgErr := rec.CallGraph()
	got.CallGraphErr = cgErr
	got.Partiality = cg.Partiality()
	got.EdgeCount = cg.EdgeCount()
	got.Edges = slices.Collect(cg.Edges())
	got.Roots = slices.Collect(cg.v.Roots())
	got.ToolchainScan, got.ToolchainErr = rec.ToolchainScan()
	got.StubReachable, got.StubErr = rec.StubReachable()
	return got
}

// seededRecord is the record a store holds for the case, and whether it is the seed: a decoded
// record holds its call-graph leg until CallGraph is first read, a seeded one never has it.
func seededRecord(t *testing.T, store artifact.Store) (*ReachabilityRecord, bool) {
	t.Helper()
	rec, ok, err := Reachability(store, reachReadAID)
	if err != nil || !ok {
		t.Fatalf("Reachability = %v, %v", ok, err)
	}
	return rec, rec.legs.CallGraph == nil
}

var reachSeedCase = &assessment.Assessment{ID: reachReadAID}

// TestSeededReachabilityMatchesDecode is the differential proof: over the payload matrix, the record
// the stage seeds reads exactly as the record a non-seeding store decodes from the stored payload.
// The seed is taken only for a memoized graph.
func TestSeededReachabilityMatchesDecode(t *testing.T) {
	for _, tc := range reachPayloadMatrix(t) {
		t.Run(tc.name, func(t *testing.T) {
			seeding, decoding := artifact.NewMemStore(), newViewOnlyStore()
			for _, s := range []artifact.Store{seeding, decoding} {
				if _, err := putReachability(s, reachSeedCase, "reachability_ingress", tc.reach, tc.view, tc.ts); err != nil {
					t.Fatal(err)
				}
			}
			want, err := reachabilityPayload(tc.reach, tc.view, tc.ts)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range []artifact.Store{seeding, decoding} {
				arts, err := s.Query(reachReadAID, artifact.TypeReachability)
				if err != nil || len(arts) != 1 || !bytes.Equal(arts[0].Payload, want) {
					t.Fatalf("stored payload is not reachabilityPayload's (%d artifacts, %v)", len(arts), err)
				}
			}

			seeded, isSeed := seededRecord(t, seeding)
			if wantSeed := tc.view.FromEncoding(); isSeed != wantSeed {
				t.Fatalf("record seeded = %v, want %v", isSeed, wantSeed)
			}
			decoded, isSeed := seededRecord(t, decoding)
			if isSeed {
				t.Fatal("a store without Seed holds a seeded record")
			}
			if seeded.err != nil || decoded.err != nil {
				t.Fatalf("record errors: seeded %v, decoded %v; the payload is valid JSON", seeded.err, decoded.err)
			}
			if !bytes.Equal(seeded.legs.Reachability, decoded.legs.Reachability) ||
				!bytes.Equal(seeded.legs.ToolchainScan, decoded.legs.ToolchainScan) ||
				seeded.legs.Reachable != nil || decoded.legs.Reachable != nil {
				t.Fatalf("legs differ:\nseeded  %s | %s | %s\ndecoded %s | %s | %s",
					seeded.legs.Reachability, seeded.legs.ToolchainScan, seeded.legs.Reachable,
					decoded.legs.Reachability, decoded.legs.ToolchainScan, decoded.legs.Reachable)
			}

			got, wantRead := readReach(t, seeding), readReach(t, decoding)
			if !reflect.DeepEqual(got, wantRead) {
				t.Errorf("seeded record reads\n%+v\ndecoded record reads\n%+v", got, wantRead)
			}
			if got.EdgeCount != len(tc.cg.Edges) || !reflect.DeepEqual(got.Edges, slices.Collect(slices.Values(tc.cg.Edges))) {
				t.Errorf("graph edges = %v, want %v", got.Edges, tc.cg.Edges)
			}
		})
	}
}

// TestEncodeReachabilityLegsOwnMemory pins that the legs the record is seeded with share no memory
// with the payload the store is handed.
func TestEncodeReachabilityLegsOwnMemory(t *testing.T) {
	for _, tc := range reachPayloadMatrix(t) {
		t.Run(tc.name, func(t *testing.T) {
			payload, reach, ts, err := encodeReachability(tc.reach, tc.view, tc.ts)
			if err != nil {
				t.Fatal(err)
			}
			wantReach, wantTS := mustMarshal(t, tc.reach), mustMarshal(t, tc.ts)
			for i := range payload {
				payload[i] = 'x'
			}
			if string(reach) != wantReach || string(ts) != wantTS {
				t.Errorf("legs changed with the payload: %s, %s", reach, ts)
			}
		})
	}
}

// TestSeededReachabilityNoAlias pins that nothing a seeded record returns aliases what later
// readers, or the run's shared graph, see.
func TestSeededReachabilityNoAlias(t *testing.T) {
	sym := func(s string) plugin.Symbol { return plugin.Symbol{SCIP: s} }
	cg := plugin.CallGraphResult{
		Partiality: plugin.Partiality{Reasons: []string{"c1"}, Scoped: []plugin.ScopedReason{{Reason: "cs", Targets: []string{"ct1", "ct2"}}}},
		Edges:      []plugin.CallEdge{{Caller: sym("main"), Callee: sym("sink")}},
		Roots:      []plugin.Symbol{sym("main")},
	}
	reach := plugin.ReachabilityResult{
		Partiality: plugin.Partiality{Reasons: []string{"r1"}, Scoped: []plugin.ScopedReason{{Reason: "s", Targets: []string{"t"}}}},
		Paths:      []plugin.ReachPath{{Sink: sym("sink"), Ingress: sym("main"), Trace: []plugin.Symbol{sym("main"), sym("sink")}}},
		Searched:   []string{"sink"},
	}
	ts := ToolchainScan{Requested: "go1.22.1", Actual: "go1.22.1", Subject: true}
	lp := plugin.Memoize(payloadGraphPlugin{cg: cg})
	view, err := plugin.SharedCallGraph(context.Background(), lp, plugin.CallGraphRequest{BuildDir: "/src"})
	if err != nil {
		t.Fatal(err)
	}
	store, decoding := artifact.NewMemStore(), newViewOnlyStore()
	for _, s := range []artifact.Store{store, decoding} {
		if _, err := putReachability(s, reachSeedCase, "reachability_ingress", reach, view, ts); err != nil {
			t.Fatal(err)
		}
	}
	if _, isSeed := seededRecord(t, store); !isSeed {
		t.Fatal("record was not seeded; the test would not cover the seed")
	}
	want := readReach(t, decoding)

	rec, _, _ := Reachability(store, reachReadAID)
	res, _ := rec.Result()
	res.Partiality.Reasons[0] = "mutated"
	res.Partiality.Scoped[0].Targets[0] = "mutated"
	res.Paths[0].Trace[0].SCIP = "mutated"
	res.Searched[0] = "mutated"
	gv, _ := rec.CallGraph()
	p := gv.Partiality()
	p.Reasons[0] = "mutated"
	p.Scoped[0].Targets[0] = "mutated"
	_ = append(p.Scoped[0].Targets[:1], "mutated")
	for e := range gv.Edges() {
		e.Caller.SCIP = "mutated"
	}
	for r := range gv.v.Roots() {
		r.SCIP = "mutated"
	}
	scan, _ := rec.ToolchainScan()
	scan.Actual = "mutated"
	arts, _ := store.Query(reachReadAID, artifact.TypeReachability)
	for i := range arts[0].Payload {
		arts[0].Payload[i] = 'x'
	}

	if got := readReach(t, store); !reflect.DeepEqual(got, want) {
		t.Errorf("after mutation a later reader reads\n%+v\nwant\n%+v", got, want)
	}
	again, err := plugin.SharedCallGraph(context.Background(), lp, plugin.CallGraphRequest{BuildDir: "/src"})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := again.MarshalJSON(); string(got) != mustMarshal(t, cg) {
		t.Errorf("run's shared graph changed: %s", got)
	}
}

// TestSeededReachabilityConcurrent reads one seeded record from many goroutines. Run it under -race.
func TestSeededReachabilityConcurrent(t *testing.T) {
	var memo reachPayloadCase
	for _, tc := range reachPayloadMatrix(t) {
		if tc.view.FromEncoding() && len(tc.cg.Edges) > 0 && len(tc.reach.Paths) > 0 {
			memo = tc
			break
		}
	}
	if !memo.view.FromEncoding() {
		t.Fatal("no memoized populated case in the matrix")
	}
	store, decoding := artifact.NewMemStore(), newViewOnlyStore()
	for _, s := range []artifact.Store{store, decoding} {
		if _, err := putReachability(s, reachSeedCase, "reachability_ingress", memo.reach, memo.view, memo.ts); err != nil {
			t.Fatal(err)
		}
	}
	want := readReach(t, decoding)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec, ok, err := Reachability(store, reachReadAID)
			if err != nil || !ok {
				t.Errorf("Reachability = %v, %v", ok, err)
				return
			}
			if got := readRecord(rec); !reflect.DeepEqual(got, want) {
				t.Errorf("concurrent reader read\n%+v\nwant\n%+v", got, want)
			}
		}()
	}
	wg.Wait()
}
