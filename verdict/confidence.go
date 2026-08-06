package verdict

// ConfidenceFromFlags computes a calibrated score from evidence flags by a fixed,
// versioned function (RFC 0003 — computed, not narrated; auditable by the flag set).
//
// Skeleton scheme (deterministic):
//   - base 0.1 (a bare lean, also the 0-flag result);
//   - +0.3 per non-proof flag;
//   - any proof flag (canary/syscall) sets a floor of 0.9;
//   - cap at 0.99.
//
// Confidence calibrates WITHIN a strength rung; it never promotes a reasoned verdict
// across the proof wall (that gate lives in (PoE).Validate, not here).
func ConfidenceFromFlags(flags []EvidenceFlag) CalibratedConfidence {
	const (
		base     = 0.1
		perFlag  = 0.3
		proofMin = 0.9
		cap      = 0.99
	)

	score := base
	proof := false
	for _, f := range flags {
		if proofFlags[f] {
			proof = true
			continue
		}
		score += perFlag
	}
	if proof && score < proofMin {
		score = proofMin
	}
	if score > cap {
		score = cap
	}

	out := make([]EvidenceFlag, len(flags))
	copy(out, flags)
	return CalibratedConfidence{Score: score, EvidenceFlags: out}
}
