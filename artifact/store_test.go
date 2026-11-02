package artifact_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

func TestMemStorePutGetRoundTrip(t *testing.T) {
	s := artifact.NewMemStore()
	a := &artifact.Artifact{
		AssessmentID: "01900000-0000-7000-8000-000000000010",
		Type:         artifact.TypeInventory,
		Descriptor:   "test-inventory",
		ProducedBy:   "codebase_inventory",
		Payload:      []byte(`{"packages":[]}`),
	}

	ref, err := s.Put(a)
	if err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	if ref.ID == "" {
		t.Fatal("Put returned empty Ref.ID")
	}
	if ref.Type != artifact.TypeInventory {
		t.Errorf("Ref.Type = %q; want %q", ref.Type, artifact.TypeInventory)
	}
	if !strings.HasPrefix(a.ContentHash, "sha256:") {
		t.Errorf("ContentHash = %q; want sha256: prefix", a.ContentHash)
	}
	// Verify the hash length: "sha256:" + 64 hex chars
	if len(a.ContentHash) != 7+64 {
		t.Errorf("ContentHash length = %d; want 71", len(a.ContentHash))
	}

	got, err := s.Get(ref.ID)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if got.ID != ref.ID {
		t.Errorf("Get returned ID %q; want %q", got.ID, ref.ID)
	}
	if string(got.Payload) != string(a.Payload) {
		t.Errorf("Get Payload = %q; want %q", got.Payload, a.Payload)
	}
	if !strings.HasPrefix(got.ContentHash, "sha256:") {
		t.Errorf("stored ContentHash = %q; want sha256: prefix", got.ContentHash)
	}
	if got.CreatedAt.IsZero() {
		t.Error("stored CreatedAt is zero")
	}
}

func TestMemStoreGetUnknown(t *testing.T) {
	s := artifact.NewMemStore()
	_, err := s.Get("does-not-exist")
	if err == nil {
		t.Fatal("expected error for missing artifact, got nil")
	}
	if !errors.Is(err, artifact.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemStoreQuery(t *testing.T) {
	s := artifact.NewMemStore()
	caseA := "01900000-0000-7000-8000-000000000020"
	caseB := "01900000-0000-7000-8000-000000000021"

	// Put two artifacts for caseA, one for caseB, one different type for caseA.
	put := func(caseID string, typ artifact.Type, payload string) {
		_, err := s.Put(&artifact.Artifact{
			AssessmentID: caseID,
			Type:         typ,
			Payload:      []byte(payload),
		})
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	put(caseA, artifact.TypeInventory, `{"a":1}`)
	put(caseA, artifact.TypeInventory, `{"a":2}`)
	put(caseA, artifact.TypeReachability, `{"a":3}`)
	put(caseB, artifact.TypeInventory, `{"b":1}`)

	results, err := s.Query(caseA, artifact.TypeInventory)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("Query returned %d results; want 2", len(results))
	}
	for _, r := range results {
		if r.AssessmentID != caseA {
			t.Errorf("result has AssessmentID %q; want %q", r.AssessmentID, caseA)
		}
		if r.Type != artifact.TypeInventory {
			t.Errorf("result has Type %q; want %q", r.Type, artifact.TypeInventory)
		}
	}
}

func TestMemStoreIdenticalPayloadSameHash(t *testing.T) {
	s := artifact.NewMemStore()
	payload := []byte(`{"key":"value"}`)
	a1 := &artifact.Artifact{
		AssessmentID: "01900000-0000-7000-8000-000000000030",
		Type:         artifact.TypePublicPoC,
		Payload:      payload,
	}
	a2 := &artifact.Artifact{
		AssessmentID: "01900000-0000-7000-8000-000000000030",
		Type:         artifact.TypePublicPoC,
		Payload:      payload,
	}

	_, err := s.Put(a1)
	if err != nil {
		t.Fatalf("Put a1: %v", err)
	}
	_, err = s.Put(a2)
	if err != nil {
		t.Fatalf("Put a2: %v", err)
	}
	if a1.ContentHash != a2.ContentHash {
		t.Errorf("identical payloads produced different hashes: %q vs %q", a1.ContentHash, a2.ContentHash)
	}
}

func TestMemStorePutAssignsID(t *testing.T) {
	s := artifact.NewMemStore()
	a := &artifact.Artifact{
		AssessmentID: "01900000-0000-7000-8000-000000000040",
		Type:         artifact.TypeDiscovery,
		Payload:      []byte(`{}`),
	}
	if a.ID != "" {
		t.Fatal("precondition: ID should be empty before Put")
	}
	ref, err := s.Put(a)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if a.ID == "" {
		t.Error("Put did not assign ID to artifact")
	}
	if a.ID != ref.ID {
		t.Errorf("a.ID %q != ref.ID %q", a.ID, ref.ID)
	}
}

func TestMemStorePutSetsCreatedAt(t *testing.T) {
	s := artifact.NewMemStore()
	a := &artifact.Artifact{
		AssessmentID: "01900000-0000-7000-8000-000000000050",
		Type:         artifact.TypeDiscovery,
		Payload:      []byte(`{}`),
	}
	before := time.Now()
	_, err := s.Put(a)
	after := time.Now()
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if a.CreatedAt.Before(before) || a.CreatedAt.After(after) {
		t.Errorf("CreatedAt %v not in expected range [%v, %v]", a.CreatedAt, before, after)
	}
}

func TestViewDecodesOncePerArtifactAndKey(t *testing.T) {
	const aid = "01900000-0000-7000-8000-000000000040"
	fs, err := artifact.NewFSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		store artifact.Store
		// wantDecodes is how many times decode runs over the steps below.
		wantDecodes int
	}{
		// Two reads of key a share one decode, key b gets its own, and replacing the artifact's
		// payload under the same id decodes the new payload once more.
		{"mem store shares", artifact.NewMemStore(), 3},
		// A store that keeps no views decodes on every read.
		{"other store decodes each read", fs, 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decodes := 0
			decode := func(p []byte) any { decodes++; return string(p) }
			read := func(key string) (any, bool) {
				t.Helper()
				v, ok, err := artifact.View(tc.store, aid, artifact.TypeReachability, key, decode)
				if err != nil {
					t.Fatalf("View: %v", err)
				}
				return v, ok
			}

			if _, ok := read("a"); ok {
				t.Fatal("View found an artifact in an empty store")
			}
			a := &artifact.Artifact{AssessmentID: aid, Type: artifact.TypeReachability, Payload: []byte(`{"v":1}`)}
			if _, err := tc.store.Put(a); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"a", "a", "b"} {
				if v, ok := read(key); !ok || v != `{"v":1}` {
					t.Fatalf("View(%q) = %v, %v; want the stored payload", key, v, ok)
				}
			}
			if _, err := tc.store.Put(&artifact.Artifact{ID: a.ID, AssessmentID: aid, Type: artifact.TypeReachability, Payload: []byte(`{"v":2}`)}); err != nil {
				t.Fatal(err)
			}
			if v, ok := read("a"); !ok || v != `{"v":2}` {
				t.Fatalf("View after replacing the payload = %v, %v; want the new payload", v, ok)
			}
			if decodes != tc.wantDecodes {
				t.Errorf("decode ran %d times; want %d", decodes, tc.wantDecodes)
			}
		})
	}
}

// TestViewDecodeCannotChangeStoredPayload pins that a decode which writes into or keeps its input
// cannot change what Query returns or desynchronise the payload from its hash.
func TestViewDecodeCannotChangeStoredPayload(t *testing.T) {
	const aid = "01900000-0000-7000-8000-000000000042"
	tests := []struct {
		name   string
		decode func(p []byte) any
	}{
		{"overwrites in place", func(p []byte) any {
			for i := range p {
				p[i] = 'x'
			}
			return nil
		}},
		{"retains and truncates", func(p []byte) any { return p[:0] }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			put := &artifact.Artifact{AssessmentID: aid, Type: artifact.TypeReachability, Payload: []byte(`{"v":1}`)}
			if _, err := store.Put(put); err != nil {
				t.Fatal(err)
			}
			v, _, err := artifact.View(store, aid, artifact.TypeReachability, "k", tc.decode)
			if err != nil {
				t.Fatal(err)
			}
			if kept, ok := v.([]byte); ok {
				_ = append(kept, "mutated"...)
			}
			arts, err := store.Query(aid, artifact.TypeReachability)
			if err != nil || len(arts) != 1 {
				t.Fatalf("Query = %d artifacts, %v", len(arts), err)
			}
			if string(arts[0].Payload) != `{"v":1}` {
				t.Errorf("stored payload = %q, want it unchanged", arts[0].Payload)
			}
			sum := sha256.Sum256(arts[0].Payload)
			if got := "sha256:" + hex.EncodeToString(sum[:]); got != arts[0].ContentHash || got != put.ContentHash {
				t.Errorf("payload hash %s disagrees with stored %s / Put %s", got, arts[0].ContentHash, put.ContentHash)
			}
		})
	}
}

// TestSeed pins Seed's seed-if-absent contract: a seed stands in for the decode only where no view
// exists yet, never replaces one, and does not outlive the payload it was seeded for.
func TestSeed(t *testing.T) {
	const aid = "01900000-0000-7000-8000-000000000043"
	tests := []struct {
		name string
		// before runs between Put and Seed.
		before   func(s *artifact.MemStore, id string, read func(key string) any)
		seedID   func(id string) string
		wantSeed bool
		// wantA and wantB are what readers of keys a and b then get; "decoded" is decode's value.
		wantA, wantB any
		wantDecodes  int
	}{
		{"absent view is seeded", nil, nil, true, "seeded", "decoded", 1},
		{"existing view is kept", func(_ *artifact.MemStore, _ string, read func(string) any) { read("a") }, nil, false, "decoded", "decoded", 2},
		{"unknown id is not seeded", nil, func(string) string { return "no-such-id" }, false, "decoded", "decoded", 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := artifact.NewMemStore()
			decodes := 0
			read := func(key string) any {
				t.Helper()
				v, ok := s.View(aid, artifact.TypeReachability, key, func([]byte) any { decodes++; return "decoded" })
				if !ok {
					t.Fatalf("View(%q) found nothing", key)
				}
				return v
			}
			a := &artifact.Artifact{AssessmentID: aid, Type: artifact.TypeReachability, Payload: []byte(`{}`)}
			if _, err := s.Put(a); err != nil {
				t.Fatal(err)
			}
			if tc.before != nil {
				tc.before(s, a.ID, read)
			}
			id := a.ID
			if tc.seedID != nil {
				id = tc.seedID(id)
			}
			if got := s.Seed(id, "a", "seeded"); got != tc.wantSeed {
				t.Errorf("Seed = %v, want %v", got, tc.wantSeed)
			}
			if got := read("a"); got != tc.wantA {
				t.Errorf("view a = %v, want %v", got, tc.wantA)
			}
			if got := read("b"); got != tc.wantB {
				t.Errorf("view b = %v, want %v", got, tc.wantB)
			}
			if decodes != tc.wantDecodes {
				t.Errorf("decode ran %d times, want %d", decodes, tc.wantDecodes)
			}
		})
	}

	t.Run("replacing the payload drops the seed", func(t *testing.T) {
		s := artifact.NewMemStore()
		a := &artifact.Artifact{AssessmentID: aid, Type: artifact.TypeReachability, Payload: []byte(`{}`)}
		if _, err := s.Put(a); err != nil {
			t.Fatal(err)
		}
		if !s.Seed(a.ID, "a", "seeded") {
			t.Fatal("Seed = false")
		}
		if _, err := s.Put(&artifact.Artifact{ID: a.ID, AssessmentID: aid, Type: artifact.TypeReachability, Payload: []byte(`{"v":2}`)}); err != nil {
			t.Fatal(err)
		}
		v, _ := s.View(aid, artifact.TypeReachability, "a", func(p []byte) any { return string(p) })
		if v != `{"v":2}` {
			t.Errorf("view after replacement = %v, want the new payload decoded", v)
		}
	})

	t.Run("decode in flight is kept", func(t *testing.T) {
		s := artifact.NewMemStore()
		a := &artifact.Artifact{AssessmentID: aid, Type: artifact.TypeReachability, Payload: []byte(`{}`)}
		if _, err := s.Put(a); err != nil {
			t.Fatal(err)
		}
		started, release := make(chan struct{}), make(chan struct{})
		got := make(chan any)
		go func() {
			v, _ := s.View(aid, artifact.TypeReachability, "a", func([]byte) any {
				close(started)
				<-release
				return "decoded"
			})
			got <- v
		}()
		<-started
		if s.Seed(a.ID, "a", "seeded") {
			t.Error("Seed replaced a view whose decode was running")
		}
		close(release)
		if v := <-got; v != "decoded" {
			t.Errorf("in-flight reader got %v, want decoded", v)
		}
		if v, _ := s.View(aid, artifact.TypeReachability, "a", func([]byte) any { return "again" }); v != "decoded" {
			t.Errorf("later reader got %v, want decoded", v)
		}
	})
}

// TestSeedConcurrent races readers against a seed: every reader gets the one value the view
// settles on. Run it under -race.
func TestSeedConcurrent(t *testing.T) {
	const aid = "01900000-0000-7000-8000-000000000044"
	for i := 0; i < 50; i++ {
		s := artifact.NewMemStore()
		a := &artifact.Artifact{AssessmentID: aid, Type: artifact.TypeReachability, Payload: []byte(`{}`)}
		if _, err := s.Put(a); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		got := make([]any, 8)
		for g := range got {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got[g], _ = s.View(aid, artifact.TypeReachability, "a", func([]byte) any { return new(int) })
			}()
		}
		seeded := new(int)
		wg.Add(1)
		var didSeed bool
		go func() {
			defer wg.Done()
			didSeed = s.Seed(a.ID, "a", seeded)
		}()
		wg.Wait()
		for g := range got {
			if got[g] != got[0] {
				t.Fatalf("reader %d got a different value from reader 0", g)
			}
		}
		if (got[0] == seeded) != didSeed {
			t.Fatalf("readers got the seed = %v, Seed reported %v", got[0] == seeded, didSeed)
		}
	}
}
