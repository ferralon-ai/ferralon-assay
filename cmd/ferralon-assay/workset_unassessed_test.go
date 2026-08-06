// workset_unassessed_test.go
//
// B-4: OSV can report advisories against this repository that no fact source can resolve. Those
// advisories are NOT evaluated by the pass. The count was previously computed, used once in a
// `> 0` guard, and discarded — so a user asking "which advisories did you not assess?" could not be
// answered by the Report, by support, or by anyone, because the number no longer existed.
//
// These tests pin that the identities survive resolveWorkSet and reach a surface.
package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// TestUnassessed_IDsSurviveResolution is the regression test for the discard. It asserts the ids
// themselves, not merely that some note fired: a note that fires without saying what it is about is
// the disclosure this finding rejected.
func TestUnassessed_IDsSurviveResolution(t *testing.T) {
	acq := goFixture(t, fixtureGoMod)
	osv := &fakeOSV{ids: []string{"GHSA-zzzz-zzzz-zzzz", "GHSA-aaaa-aaaa-aaaa", "GHSA-mmmm-mmmm-mmmm"}}

	ws := resolveWorkSet(context.Background(), acq, osv, nil)

	want := []string{"GHSA-aaaa-aaaa-aaaa", "GHSA-mmmm-mmmm-mmmm", "GHSA-zzzz-zzzz-zzzz"}
	if len(ws.unresolved) != len(want) {
		t.Fatalf("unresolved = %v, want %v", ws.unresolved, want)
	}
	for i, id := range want {
		if ws.unresolved[i] != id {
			// Sorted, so a diff here is either a lost id or non-determinism. Both matter: a note
			// whose content reorders between runs churns every downstream artifact that embeds it.
			t.Fatalf("unresolved[%d] = %q, want %q (full: %v)", i, ws.unresolved[i], id, ws.unresolved)
		}
	}
	if !hasNote(ws.partiality, reasonAdvisoryFactsUnavailable) {
		t.Errorf("unassessed advisories emitted no %q note; notes = %+v", reasonAdvisoryFactsUnavailable, ws.partiality)
	}
}

// TestUnassessed_TerminalLineNamesCountAndIDs pins what an operator actually reads. The specifics
// also reach the Report and every sink through PartialityNote.Detail
// (workset_partiality_reach_test.go); the terminal line is a separate surface with its own
// regression, because it is where an operator looks first and it renders from w.unresolved directly.
func TestUnassessed_TerminalLineNamesCountAndIDs(t *testing.T) {
	acq := goFixture(t, fixtureGoMod)
	osv := &fakeOSV{ids: []string{"GHSA-zzzz-zzzz-zzzz", "GHSA-aaaa-aaaa-aaaa"}}

	got := resolveWorkSet(context.Background(), acq, osv, nil).describe()

	for _, want := range []string{"2 advisory id(s)", "NOT assessed", "GHSA-aaaa-aaaa-aaaa", "GHSA-zzzz-zzzz-zzzz"} {
		if !strings.Contains(got, want) {
			t.Errorf("terminal line does not contain %q:\n%s", want, got)
		}
	}
}

// TestUnassessed_SilentWhenEverythingResolved keeps the disclosure meaningful. A line that appears
// on every run is a line operators stop reading, which is how a real gap gets missed.
func TestUnassessed_SilentWhenEverythingResolved(t *testing.T) {
	acq := goFixture(t, fixtureGoMod)
	osv := &fakeOSV{}

	got := resolveWorkSet(context.Background(), acq, osv, nil).describe()

	if strings.Contains(got, "NOT assessed") {
		t.Errorf("a run with nothing unassessed still rendered the disclosure:\n%s", got)
	}
	if unresolvedDetail(nil) != "" {
		t.Errorf("unresolvedDetail(nil) = %q, want empty so a caller can assign it unconditionally", unresolvedDetail(nil))
	}
}

// TestUnassessed_CountIsExactAboveTheCap is the shape the reviewer's 102-id case actually hits. The
// id list is truncated because a note is read by a human; the COUNT never is, because the count is
// what tells that human the list they are looking at is partial.
func TestUnassessed_CountIsExactAboveTheCap(t *testing.T) {
	var ids []string
	for i := 0; i < 102; i++ {
		ids = append(ids, fmt.Sprintf("GHSA-%04d-xxxx-xxxx", i))
	}

	got := unresolvedDetail(ids)

	if !strings.Contains(got, "102 advisory id(s)") {
		t.Errorf("the exact count was elided above the cap:\n%s", got)
	}
	if !strings.Contains(got, fmt.Sprintf("and %d more", 102-unresolvedDetailCap)) {
		t.Errorf("truncation was not disclosed, so the list reads as complete:\n%s", got)
	}
	if n := strings.Count(got, "GHSA-"); n != unresolvedDetailCap {
		t.Errorf("named %d ids, want the cap of %d", n, unresolvedDetailCap)
	}
}
