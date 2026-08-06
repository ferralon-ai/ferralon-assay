package statestore

import (
	"context"
	"testing"
	"time"
)

// TestCASRejectsNonFastForward simulates a race: writer A reads the state, writer B
// commits a new state, then A tries to Write against its now-stale CommitSHA. The
// merge-retry must re-read B's winner, merge A's intent onto it, and converge — the
// final state must contain BOTH writers' advisories.
func TestCASRejectsNonFastForwardAndMergeConverges(t *testing.T) {
	s := newTempStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)

	// Seed a baseline so both racers read a real CommitSHA.
	base := sampleReport("base", "cursor-0", t0, "GO-0000-0000")
	if _, err := s.Write(ctx, &State{Report: base, Cursor: "cursor-0"}); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	// Writer A reads (captures the baseline CommitSHA).
	aRead, err := s.Read(ctx)
	if err != nil {
		t.Fatalf("A read: %v", err)
	}

	// Writer B reads, then commits a newer state — B wins the ref.
	bRead, err := s.Read(ctx)
	if err != nil {
		t.Fatalf("B read: %v", err)
	}
	bReport := sampleReport("bbb", "cursor-B", t0.Add(time.Hour), "GO-2021-B")
	bRead.Report = bReport
	bRead.Cursor = "cursor-B"
	if _, err := s.Write(ctx, bRead); err != nil {
		t.Fatalf("B write: %v", err)
	}

	// Writer A now writes against its STALE CommitSHA. tryWrite must hit ErrConflict;
	// Write's retry loop must Merge onto B and succeed.
	aReport := sampleReport("aaa", "cursor-A", t0.Add(2*time.Hour), "GO-2021-A")
	aRead.Report = aReport
	aRead.Cursor = "cursor-A"
	committed, err := s.Write(ctx, aRead)
	if err != nil {
		t.Fatalf("A write should converge, got: %v", err)
	}

	// Final state must union both advisories (B's and A's), proving the merge ran.
	final, err := s.Read(ctx)
	if err != nil {
		t.Fatalf("final read: %v", err)
	}
	if final.CommitSHA != committed.CommitSHA {
		t.Errorf("committed SHA %q != final ref %q", committed.CommitSHA, final.CommitSHA)
	}
	ids := map[string]bool{}
	for _, f := range final.Report.Advisories {
		ids[f.Advisory.ID] = true
	}
	// Both B (the winner) and A (the race-loser) replaced the baseline Report with a
	// fresh full scan; the merge unions THEIR advisories. The baseline's advisory is
	// not carried forward (each full scan is the complete current evaluation).
	for _, want := range []string{"GO-2021-A", "GO-2021-B"} {
		if !ids[want] {
			t.Errorf("merged report missing advisory %q (have %v)", want, ids)
		}
	}
	// A's scan is later (t0+2h) so its cursor + provenance win the merge.
	if final.Report.Provenance.AdvisoryCursor != "cursor-A" {
		t.Errorf("later scan's cursor should win: got %q want cursor-A", final.Report.Provenance.AdvisoryCursor)
	}
}

// TestCASConflictExhaustsRetries verifies bounded backoff: with MaxRetries=0 and a
// pre-moved ref, a stale write surfaces ErrConflict rather than looping forever.
func TestCASConflictRespectsRetryBudget(t *testing.T) {
	s := newTempStore(t)
	s.cfg.MaxRetries = 0
	ctx := context.Background()
	t0 := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)

	seed, _ := s.Write(ctx, &State{Report: sampleReport("s", "c0", t0), Cursor: "c0"})
	_ = seed

	stale, _ := s.Read(ctx)
	// Advance the ref so stale's CommitSHA is no longer current.
	if _, err := s.Write(ctx, &State{Report: sampleReport("s2", "c1", t0.Add(time.Hour)), Cursor: "c1", CommitSHA: stale.CommitSHA}); err != nil {
		t.Fatalf("advance: %v", err)
	}

	// stale is now two commits behind; with MaxRetries=0 the single CAS fails and the
	// loop merges once then... actually attempt<=0 means exactly one tryWrite. After
	// that conflict the loop merges and the for-condition (attempt=1 > 0) exits with
	// ErrConflict. Confirm we get a conflict, not a hang or success-on-stale.
	stale.Report = sampleReport("s3", "c2", t0.Add(2*time.Hour))
	_, err := s.Write(ctx, stale)
	if err == nil {
		t.Fatal("expected ErrConflict with zero retry budget against a moved ref")
	}
}

func TestFallbackRefConfig(t *testing.T) {
	s := NewGitRefStore(Config{GitDir: t.TempDir(), Ref: FallbackRef})
	if s.cfg.Ref != FallbackRef {
		t.Errorf("fallback ref not honored: %q", s.cfg.Ref)
	}
	d := NewGitRefStore(Config{GitDir: t.TempDir()})
	if d.cfg.Ref != DefaultRef {
		t.Errorf("default ref wrong: %q", d.cfg.Ref)
	}
}
