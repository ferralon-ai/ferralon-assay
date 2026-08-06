package statestore

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestMemStoreReadNotFoundBeforeFirstWrite(t *testing.T) {
	if _, err := NewMemStore().Read(context.Background()); err != ErrNotFound {
		t.Fatalf("want ErrNotFound on a store with no prior write, got %v", err)
	}
}

// TestMemStoreCAS drives the second of two writes with a chosen CAS token and
// checks which advisories survive. A current token is a fast-forward: the write
// REPLACES the stored state. A stale token (including the empty
// create-if-absent token, against a store that already has state) is not an
// error — the caller's intent is re-applied onto the stored state via Merge, so
// both writers' advisories survive.
func TestMemStoreCAS(t *testing.T) {
	t0 := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		// token derives the second write's CAS token from the first write's
		// committed CommitSHA.
		token   func(committed string) string
		wantIDs []string
	}{
		{
			name:    "current token fast-forwards and replaces",
			token:   func(committed string) string { return committed },
			wantIDs: []string{"GO-SECOND"},
		},
		{
			name:    "stale token merges both writers",
			token:   func(string) string { return "mem-stale" },
			wantIDs: []string{"GO-FIRST", "GO-SECOND"},
		},
		{
			name:    "empty token against existing state merges",
			token:   func(string) string { return "" },
			wantIDs: []string{"GO-FIRST", "GO-SECOND"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewMemStore()
			ctx := context.Background()

			first, err := s.Write(ctx, &State{
				Report: sampleReport("c1", "cursor-1", t0, "GO-FIRST"),
				Cursor: "cursor-1",
			})
			if err != nil {
				t.Fatalf("first write: %v", err)
			}
			if first.CommitSHA == "" {
				t.Fatal("first write returned an empty CommitSHA; the CAS token must be set")
			}

			second, err := s.Write(ctx, &State{
				Report:    sampleReport("c2", "cursor-2", t0.Add(time.Hour), "GO-SECOND"),
				Cursor:    "cursor-2",
				CommitSHA: tt.token(first.CommitSHA),
			})
			if err != nil {
				t.Fatalf("second write: %v", err)
			}
			if second.CommitSHA == first.CommitSHA {
				t.Errorf("second write reused CommitSHA %q; every commit needs a fresh token", second.CommitSHA)
			}

			got := advisoryIDs(second)
			for _, want := range tt.wantIDs {
				if !got[want] {
					t.Errorf("committed state is missing advisory %q (have %v)", want, got)
				}
			}
			if len(got) != len(tt.wantIDs) {
				t.Errorf("committed advisories = %v, want exactly %v", got, tt.wantIDs)
			}

			// What Write returned is what a subsequent Read sees.
			read, err := s.Read(ctx)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if read.CommitSHA != second.CommitSHA {
				t.Errorf("Read CommitSHA = %q, want the committed %q", read.CommitSHA, second.CommitSHA)
			}
		})
	}
}

// TestMemStoreReadWriteIsolation: a caller mutating a State it got back must not
// reach into the store's copy. The git-ref store serialises through git objects and
// gets this for free; MemStore has to hand out copies to match.
func TestMemStoreReadWriteIsolation(t *testing.T) {
	t0 := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	s := NewMemStore()
	ctx := context.Background()

	in := &State{Report: sampleReport("c1", "cursor-1", t0, "GO-FIRST"), Cursor: "cursor-1"}
	if _, err := s.Write(ctx, in); err != nil {
		t.Fatalf("write: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*State)
	}{
		{"mutating the State passed to Write", func(st *State) { st.Cursor = "clobbered-by-writer" }},
		{"mutating the State returned by Read", func(st *State) { st.Cursor = "clobbered-by-reader" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "mutating the State passed to Write" {
				tt.mutate(in)
			} else {
				got, err := s.Read(ctx)
				if err != nil {
					t.Fatalf("read: %v", err)
				}
				tt.mutate(got)
			}
			after, err := s.Read(ctx)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if after.Cursor != "cursor-1" {
				t.Errorf("stored cursor = %q, want %q — the store shared a pointer with the caller", after.Cursor, "cursor-1")
			}
		})
	}
}

func TestMemStorePreservesVEXLogAndRevokeCount(t *testing.T) {
	t0 := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	s := NewMemStore()
	ctx := context.Background()

	stmt := json.RawMessage(`{"vulnerability":{"@id":"GO-FIRST"},"status":"not_affected"}`)
	committed, err := s.Write(ctx, &State{
		Report:      sampleReport("c1", "cursor-1", t0, "GO-FIRST"),
		VEXLog:      []json.RawMessage{stmt},
		RevokeCount: 2,
	})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(committed.VEXLog) != 1 || string(committed.VEXLog[0]) != string(stmt) {
		t.Errorf("VEXLog = %v, want the one statement written", committed.VEXLog)
	}
	if committed.RevokeCount != 2 {
		t.Errorf("RevokeCount = %d, want 2", committed.RevokeCount)
	}
}

func TestMemStoreHonoursContextCancellation(t *testing.T) {
	s := NewMemStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.Read(ctx); err != context.Canceled {
		t.Errorf("Read on a cancelled context = %v, want context.Canceled", err)
	}
	if _, err := s.Write(ctx, &State{}); err != context.Canceled {
		t.Errorf("Write on a cancelled context = %v, want context.Canceled", err)
	}
}

func advisoryIDs(s *State) map[string]bool {
	ids := map[string]bool{}
	if s.Report == nil {
		return ids
	}
	for _, f := range s.Report.Advisories {
		ids[f.Advisory.ID] = true
	}
	return ids
}
