package selfcleanup

import "testing"

func TestApplyOutcome(t *testing.T) {
	cases := []struct {
		name        string
		prev        int
		o           Outcome
		wantNext    int
		wantChanged bool
	}{
		{"revoke from zero", 0, OutcomeRevoked, 1, true},
		{"revoke advances", 1, OutcomeRevoked, 2, true},
		{"active resets a streak", 1, OutcomeActive, 0, true},
		{"active on zero is no-op", 0, OutcomeActive, 0, false},
		{"transient holds a streak", 1, OutcomeTransient, 1, false},
		{"transient holds zero", 0, OutcomeTransient, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			next, changed := applyOutcome(c.prev, c.o)
			if next != c.wantNext || changed != c.wantChanged {
				t.Fatalf("applyOutcome(%d,%v) = (%d,%v), want (%d,%v)",
					c.prev, c.o, next, changed, c.wantNext, c.wantChanged)
			}
		})
	}
}

func TestThreshold(t *testing.T) {
	if shouldActuate(1) {
		t.Fatal("N=1 must NOT actuate (threshold is 2)")
	}
	if !shouldActuate(2) {
		t.Fatal("N=2 must actuate")
	}
	if !shouldActuate(3) {
		t.Fatal("N>2 must actuate")
	}
}

// TestConsecutiveStreamToThreshold walks the exact sequence that must NOT actuate
// until two consecutive verified revokes: revoke, transient (holds), revoke → fire;
// and a revoke broken by an active response resets.
func TestConsecutiveStreamToThreshold(t *testing.T) {
	n := 0
	step := func(o Outcome) { n, _ = applyOutcome(n, o) }

	step(OutcomeRevoked) // 1
	if shouldActuate(n) {
		t.Fatal("single revoke must not actuate")
	}
	step(OutcomeTransient) // still 1 (transient never counts)
	if n != 1 || shouldActuate(n) {
		t.Fatalf("transient must hold at 1, got %d", n)
	}
	step(OutcomeActive) // reset to 0 (streak broken)
	if n != 0 {
		t.Fatalf("active must reset to 0, got %d", n)
	}
	step(OutcomeRevoked) // 1
	step(OutcomeRevoked) // 2 → actuate
	if !shouldActuate(n) {
		t.Fatalf("two consecutive revokes must actuate, got %d", n)
	}
}
