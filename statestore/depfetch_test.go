package statestore

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func sampleDepFetch(held int) *DepFetch {
	return &DepFetch{
		Registries: map[string]RegistryFetch{
			"https://registry.npmjs.org/": {HasServed: true, HeldRuns: held, FirstHeldAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)},
		},
		Reassess: []string{"GHSA-bbbb", "GHSA-aaaa"},
	}
}

// TestDepFetchRoundTrip: the record persists across a write → read in both stores, on
// the ordinary CAS update and on the re-create a write falls back to when the ref
// vanished, and the file exists exactly while the record is non-empty.
func TestDepFetchRoundTrip(t *testing.T) {
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	steps := []*DepFetch{
		sampleDepFetch(1),
		sampleDepFetch(2),
		{Registries: map[string]RegistryFetch{"https://registry.npmjs.org/": {}}}, // all-zero: omitted
		nil,
		{Reassess: []string{"GHSA-cccc"}},
	}
	for _, h := range storeHarnesses {
		for _, recreate := range []bool{false, true} {
			name := h.name + "/cas update"
			if recreate {
				name = h.name + "/re-create"
			}
			t.Run(name, func(t *testing.T) {
				hs := h.new(t)
				ctx := context.Background()
				mustWrite(t, hs.store, &State{Report: sampleReport("c0", "cur", ts), Cursor: "cur"})
				for i, in := range steps {
					st, err := hs.store.Read(ctx)
					if err != nil {
						t.Fatalf("step %d read: %v", i, err)
					}
					st.DepFetch = in
					if recreate {
						hs.dropRef(t)
					}
					committed := mustWrite(t, hs.store, st)
					if recreate && hs.parents(t, committed.CommitSHA) != 0 {
						t.Fatalf("step %d: write did not take the re-create path", i)
					}
					got, err := hs.store.Read(ctx)
					if err != nil {
						t.Fatalf("step %d re-read: %v", i, err)
					}
					want := in.normalized()
					if want != nil {
						if got.DepFetch == nil {
							t.Fatalf("step %d: DepFetch lost on round trip", i)
						}
						if got.DepFetch.ReportSHA256 == "" {
							t.Errorf("step %d: record not bound to the report it was written beside", i)
						}
						gotN := got.DepFetch.normalized()
						if !reflect.DeepEqual(gotN, want) {
							t.Errorf("step %d: DepFetch got %+v want %+v", i, gotN, want)
						}
					} else if got.DepFetch != nil {
						t.Errorf("step %d: empty record read back as %+v", i, got.DepFetch)
					}
					if _, has := hs.blobs(t, committed.CommitSHA)[fileDepFetch]; has != (want != nil) {
						t.Errorf("step %d: %s present=%v with record %+v", i, fileDepFetch, has, in)
					}
				}
			})
		}
	}
}

// TestDepFetchHeartbeatZeroNewObjects: a cursor-only heartbeat over a state that carries
// a record re-uses the record's blob, so a heartbeat still writes only the cursor.
func TestDepFetchHeartbeatZeroNewObjects(t *testing.T) {
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	for _, h := range storeHarnesses {
		t.Run(h.name, func(t *testing.T) {
			hs := h.new(t)
			ctx := context.Background()
			first := mustWrite(t, hs.store, &State{Report: sampleReport("c0", "cur", ts), Cursor: "cur", DepFetch: sampleDepFetch(1)})
			before := hs.blobs(t, first.CommitSHA)
			if before[fileDepFetch] == "" {
				t.Fatalf("seed wrote no %s", fileDepFetch)
			}
			st, err := hs.store.Read(ctx)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			st.Cursor = "cur-2"
			second := mustWrite(t, hs.store, st)
			after := hs.blobs(t, second.CommitSHA)
			for name, sha := range before {
				if name == fileCursor {
					continue
				}
				if after[name] != sha {
					t.Errorf("%s blob changed on a cursor-only heartbeat: %s -> %s", name, sha, after[name])
				}
			}
			if len(after) != len(before) {
				t.Errorf("heartbeat tree has %d entries, seed had %d", len(after), len(before))
			}
		})
	}
}

// TestDepFetchIgnoredBesideDifferentReport: a writer that does not model depfetch.json
// carries it unchanged while rewriting report.json. The record then describes a report
// that is gone, so a reader drops it, and the next write omits the file.
func TestDepFetchIgnoredBesideDifferentReport(t *testing.T) {
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	for _, h := range storeHarnesses {
		t.Run(h.name, func(t *testing.T) {
			hs := h.new(t)
			ctx := context.Background()
			mustWrite(t, hs.store, &State{Report: sampleReport("c0", "cur", ts), Cursor: "cur", DepFetch: sampleDepFetch(1)})

			other, err := marshalCanonical(sampleReport("c1", "cur", ts.Add(time.Hour)))
			if err != nil {
				t.Fatal(err)
			}
			hs.plant(t, fileReport, other)

			st, err := hs.store.Read(ctx)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if _, has := hs.blobs(t, st.CommitSHA)[fileDepFetch]; !has {
				t.Fatal("plant dropped the carried record")
			}
			if st.DepFetch != nil {
				t.Fatalf("record written beside another report.json was read: %+v", st.DepFetch)
			}
			committed := mustWrite(t, hs.store, st)
			if _, has := hs.blobs(t, committed.CommitSHA)[fileDepFetch]; has {
				t.Error("a write after the mismatch kept the stale record")
			}
		})
	}
}

// TestDepFetchMergeAfterLostCAS: a race-loser's retry merges its record with the
// winner's rather than replacing it.
func TestDepFetchMergeAfterLostCAS(t *testing.T) {
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	const reg = "https://registry.npmjs.org/"
	early := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	late := early.Add(48 * time.Hour)
	for _, h := range storeHarnesses {
		t.Run(h.name, func(t *testing.T) {
			hs := h.new(t)
			ctx := context.Background()
			mustWrite(t, hs.store, &State{Report: sampleReport("c0", "cur", ts), Cursor: "cur"})
			loser, _ := hs.store.Read(ctx)
			winner, _ := hs.store.Read(ctx)

			winner.DepFetch = &DepFetch{
				Registries: map[string]RegistryFetch{reg: {HeldRuns: 3, FirstHeldAt: early}},
				Reassess:   []string{"GHSA-winner"},
			}
			mustWrite(t, hs.store, winner)

			loser.DepFetch = &DepFetch{
				Registries: map[string]RegistryFetch{reg: {HasServed: true, HeldRuns: 1, FirstHeldAt: late}},
				Reassess:   []string{"GHSA-loser"},
			}
			committed := mustWrite(t, hs.store, loser)
			if hs.parents(t, committed.CommitSHA) != 1 {
				t.Fatal("loser write did not land on top of the winner")
			}

			got, err := hs.store.Read(ctx)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			want := &DepFetch{
				Registries: map[string]RegistryFetch{reg: {HasServed: true, HeldRuns: 3, FirstHeldAt: early}},
				Reassess:   []string{"GHSA-loser", "GHSA-winner"},
			}
			if got.DepFetch == nil || !reflect.DeepEqual(got.DepFetch.normalized(), want) {
				t.Errorf("merged record: got %+v want %+v", got.DepFetch, want)
			}
		})
	}
}

func TestMergeDepFetch(t *testing.T) {
	const a, b = "https://a.example/", "https://b.example/"
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	cases := []struct {
		name       string
		base, mine *DepFetch
		want       *DepFetch
	}{
		{name: "both nil", want: nil},
		{name: "base only", base: &DepFetch{Reassess: []string{"X"}}, want: &DepFetch{Reassess: []string{"X"}}},
		{name: "mine only", mine: &DepFetch{Reassess: []string{"X"}}, want: &DepFetch{Reassess: []string{"X"}}},
		{
			name: "has_served is ORed from either side",
			base: &DepFetch{Registries: map[string]RegistryFetch{a: {HasServed: true}}},
			mine: &DepFetch{Registries: map[string]RegistryFetch{a: {HeldRuns: 1, FirstHeldAt: t0}}},
			want: &DepFetch{Registries: map[string]RegistryFetch{a: {HasServed: true, HeldRuns: 1, FirstHeldAt: t0}}},
		},
		{
			name: "has_served from mine",
			base: &DepFetch{Registries: map[string]RegistryFetch{a: {HeldRuns: 1, FirstHeldAt: t0}}},
			mine: &DepFetch{Registries: map[string]RegistryFetch{a: {HasServed: true}}},
			want: &DepFetch{Registries: map[string]RegistryFetch{a: {HasServed: true, HeldRuns: 1, FirstHeldAt: t0}}},
		},
		{
			name: "larger held count and earliest first-held time, from opposite sides",
			base: &DepFetch{Registries: map[string]RegistryFetch{a: {HeldRuns: 2, FirstHeldAt: t1}}},
			mine: &DepFetch{Registries: map[string]RegistryFetch{a: {HeldRuns: 1, FirstHeldAt: t0}}},
			want: &DepFetch{Registries: map[string]RegistryFetch{a: {HeldRuns: 2, FirstHeldAt: t0}}},
		},
		{
			name: "larger held count from mine, earliest time from base",
			base: &DepFetch{Registries: map[string]RegistryFetch{a: {HeldRuns: 1, FirstHeldAt: t0}}},
			mine: &DepFetch{Registries: map[string]RegistryFetch{a: {HeldRuns: 4, FirstHeldAt: t1}}},
			want: &DepFetch{Registries: map[string]RegistryFetch{a: {HeldRuns: 4, FirstHeldAt: t0}}},
		},
		{
			name: "a zero first-held time never wins",
			base: &DepFetch{Registries: map[string]RegistryFetch{a: {HasServed: true}}},
			mine: &DepFetch{Registries: map[string]RegistryFetch{a: {HeldRuns: 1, FirstHeldAt: t1}}},
			want: &DepFetch{Registries: map[string]RegistryFetch{a: {HasServed: true, HeldRuns: 1, FirstHeldAt: t1}}},
		},
		{
			name: "registries union, reassess union sorted and deduplicated",
			base: &DepFetch{Registries: map[string]RegistryFetch{a: {HasServed: true}}, Reassess: []string{"Y", "X"}},
			mine: &DepFetch{Registries: map[string]RegistryFetch{b: {HeldRuns: 1, FirstHeldAt: t0}}, Reassess: []string{"Z", "X"}},
			want: &DepFetch{
				Registries: map[string]RegistryFetch{a: {HasServed: true}, b: {HeldRuns: 1, FirstHeldAt: t0}},
				Reassess:   []string{"X", "Y", "Z"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeDepFetch(tc.base, tc.mine)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestMergeCarriesDepFetch(t *testing.T) {
	base := &State{CommitSHA: "b", DepFetch: &DepFetch{Reassess: []string{"X"}}}
	mine := &State{DepFetch: &DepFetch{Reassess: []string{"Y"}}}
	got := Merge(base, mine)
	if got.DepFetch == nil || !reflect.DeepEqual(got.DepFetch.Reassess, []string{"X", "Y"}) {
		t.Errorf("Merge DepFetch: got %+v", got.DepFetch)
	}
}

func TestDecodeDepFetch(t *testing.T) {
	report := []byte(`{"a":1}`)
	good, ok, err := encodeDepFetch(&DepFetch{Reassess: []string{"X"}}, report)
	if err != nil || !ok {
		t.Fatalf("encode: ok=%v err=%v", ok, err)
	}
	if d, err := decodeDepFetch(good, report); err != nil || d == nil {
		t.Errorf("matching report: got %+v, %v", d, err)
	}
	if d, err := decodeDepFetch(good, []byte(`{"a":2}`)); err != nil || d != nil {
		t.Errorf("different report: got %+v, %v; want nil, nil", d, err)
	}
	if d, err := decodeDepFetch(good, nil); err != nil || d != nil {
		t.Errorf("no report: got %+v, %v; want nil, nil", d, err)
	}
	noReport, _, _ := encodeDepFetch(&DepFetch{Reassess: []string{"X"}}, nil)
	if d, err := decodeDepFetch(noReport, nil); err != nil || d == nil {
		t.Errorf("written and read with no report: got %+v, %v", d, err)
	}
	if _, err := decodeDepFetch([]byte(`{`), report); err == nil {
		t.Error("malformed record decoded without error")
	}
	foreign := func(digest string) []byte {
		return []byte(`{"report_sha256":"` + digest + `","reassess":5}`)
	}
	if d, err := decodeDepFetch(foreign(reportDigest([]byte(`{"a":2}`))), report); err != nil || d != nil {
		t.Errorf("undecodable record bound to a different report: got %+v, %v; want nil, nil", d, err)
	}
	if _, err := decodeDepFetch(foreign(reportDigest(report)), report); err == nil {
		t.Error("undecodable record bound to this report decoded without error")
	}
	if _, ok, _ := encodeDepFetch(&DepFetch{Registries: map[string]RegistryFetch{"r": {}}}, report); ok {
		t.Error("an all-zero record was encoded rather than omitted")
	}
}
