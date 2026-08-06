package selfcleanup

// RevokeThreshold is N — the number of CONSECUTIVE verified signed revokes that must
// be observed before the actuation ladder fires. N=2 tolerates a single anomalous
// signed revoke (a backend blip that still managed to sign) at the cost of one extra
// scan of latency; on an active repo that is usually the same day. Fully reversible:
// re-installing the App before the second revoke re-enables everything.
const RevokeThreshold = 2

// applyOutcome folds one ingest Outcome into the consecutive-revoke counter and
// reports whether the value changed (a change means the counter must be persisted).
//
//   - OutcomeRevoked  → prev+1 (a signed revoke advances the streak)
//   - OutcomeActive   → 0      (the install is live; the streak breaks)
//   - OutcomeTransient→ prev   (ambiguous; hold — never count, never reset)
func applyOutcome(prev int, o Outcome) (next int, changed bool) {
	switch o {
	case OutcomeRevoked:
		return prev + 1, true
	case OutcomeActive:
		return 0, prev != 0
	default: // OutcomeTransient
		return prev, false
	}
}

// shouldActuate reports whether a counter value has reached the confirmation
// threshold.
func shouldActuate(count int) bool { return count >= RevokeThreshold }
