package statestore

import (
	"context"
	"testing"
	"time"
)

// TestCapabilityAcceptsCustomRefOnGitHub: the default mock host accepts custom refs
// (per the portability matrix), so the probe passes and the store keeps DefaultRef.
func TestCapabilityAcceptsCustomRefOnGitHub(t *testing.T) {
	m := newMockGitHub("acme", "widget")
	s := newMockStore(t, m)
	ctx := context.Background()
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	committed, err := s.Write(ctx, &State{Report: sampleReport("c0", "cur", ts), Cursor: "cur"})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if s.StateRef() != DefaultRef {
		t.Errorf("custom-ref host: store should keep DefaultRef, got %q", s.StateRef())
	}
	if _, ok := m.refs[DefaultRef]; !ok {
		t.Errorf("expected the custom ref %q to be written, refs=%v", DefaultRef, m.refs)
	}
	// The chosen ref is recorded on the committed Report's BaselineRef.
	if committed.Report == nil || committed.Report.Baseline == nil {
		t.Fatal("committed Report should carry a BaselineRef")
	}
	if committed.Report.Baseline.StateRef != DefaultRef {
		t.Errorf("BaselineRef.StateRef: got %q want %q", committed.Report.Baseline.StateRef, DefaultRef)
	}
}

// TestCapabilityCascadesToFallbackWhenCustomRefRejected: a host that rejects the
// custom namespace (422 on the probe) causes the adapter to cascade to FallbackRef,
// and the fallback (branch) ref is the one actually written + recorded.
func TestCapabilityCascadesToFallbackWhenCustomRefRejected(t *testing.T) {
	m := newMockGitHub("acme", "widget")
	m.rejectCustomRefs = true
	s := newMockStore(t, m)
	ctx := context.Background()
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	committed, err := s.Write(ctx, &State{Report: sampleReport("c0", "cur", ts), Cursor: "cur"})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if s.StateRef() != FallbackRef {
		t.Errorf("rejected-custom host: store should cascade to FallbackRef, got %q", s.StateRef())
	}
	if _, ok := m.refs[FallbackRef]; !ok {
		t.Errorf("expected the fallback ref %q to be written, refs=%v", FallbackRef, m.refs)
	}
	if _, ok := m.refs[DefaultRef]; ok {
		t.Errorf("custom ref %q must NOT be written when rejected", DefaultRef)
	}
	if committed.Report == nil || committed.Report.Baseline == nil || committed.Report.Baseline.StateRef != FallbackRef {
		t.Errorf("BaselineRef.StateRef should record the fallback ref, got %+v", committed.Report.Baseline)
	}

	// Read-back round-trips off the fallback ref.
	got, err := s.Read(ctx)
	if err != nil {
		t.Fatalf("read off fallback: %v", err)
	}
	if got.Cursor != "cur" {
		t.Errorf("fallback round-trip cursor: got %q", got.Cursor)
	}
}

// TestCapabilityProbedOnceCached: the probe runs at most once across many
// operations (R6 — cheap one-time check, not per-write).
func TestCapabilityProbedOnceCached(t *testing.T) {
	m := newMockGitHub("acme", "widget")
	s := newMockStore(t, m)
	ctx := context.Background()
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	var probeCalls int
	s.probedFn = func(ctx context.Context) error {
		probeCalls++
		return s.probeCapability(ctx)
	}

	if _, err := s.Write(ctx, &State{Report: sampleReport("c0", "cur", ts), Cursor: "cur"}); err != nil {
		t.Fatalf("write1: %v", err)
	}
	read, _ := s.Read(ctx)
	read.Cursor = "cur2"
	if _, err := s.Write(ctx, read); err != nil {
		t.Fatalf("write2: %v", err)
	}
	if _, err := s.Read(ctx); err != nil {
		t.Fatalf("read: %v", err)
	}

	if probeCalls != 1 {
		t.Errorf("capability probe ran %d times, want exactly 1 (cached)", probeCalls)
	}
}

// TestCapabilityFallbackRefConfigSkipsProbe: when the caller pre-selects a branch
// ref, no probe round-trip is needed — branch refs are accepted everywhere.
func TestCapabilityFallbackRefConfigSkipsProbe(t *testing.T) {
	m := newMockGitHub("acme", "widget")
	srv := m.server(t)
	s := NewGitHubRefStore(GitHubConfig{
		Owner: "acme", Repo: "widget", BaseURL: srv.URL, HTTPClient: srv.Client(), Ref: FallbackRef,
	})
	ctx := context.Background()

	var probeCalls int
	s.probedFn = func(ctx context.Context) error {
		probeCalls++
		return s.probeCapability(ctx)
	}

	if err := s.ensureRef(ctx); err != nil {
		t.Fatalf("ensureRef: %v", err)
	}
	if s.StateRef() != FallbackRef {
		t.Errorf("store should honor configured FallbackRef, got %q", s.StateRef())
	}
	if probeCalls != 1 {
		t.Errorf("ensureRef should call the resolver once, got %d", probeCalls)
	}
	if !isCustomRef(DefaultRef) || isCustomRef(FallbackRef) {
		t.Error("isCustomRef classification wrong")
	}
}
