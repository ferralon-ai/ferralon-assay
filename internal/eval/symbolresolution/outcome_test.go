package symbolresolution

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestOutcomeValidate exercises the §2.1 XOR invariant: exactly one shape holds. The malformed
// rows are the real negative controls — a resolved outcome missing its symbol, or an unresolved
// one carrying an empty/unknown reason, must FAIL, else Validate is measuring nothing.
func TestOutcomeValidate(t *testing.T) {
	sym := &ResolvedSymbol{SCIP: "scip:x", DisplayName: "pkg.Fn"}
	tests := []struct {
		name    string
		outcome ResolutionOutcome
		wantErr bool
	}{
		{"resolved shape ok", ResolutionOutcome{Resolved: true, Symbol: sym}, false},
		{"unresolved shape ok", ResolutionOutcome{Resolved: false, Reason: ReasonArtifactNotIndexed}, false},
		{"resolved without symbol malformed", ResolutionOutcome{Resolved: true}, true},
		{"resolved with reason malformed", ResolutionOutcome{Resolved: true, Symbol: sym, Reason: ReasonArtifactNotIndexed}, true},
		{"unresolved with symbol malformed", ResolutionOutcome{Resolved: false, Symbol: sym, Reason: ReasonArtifactNotIndexed}, true},
		{"unresolved empty reason malformed", ResolutionOutcome{Resolved: false}, true},
		{"unresolved unknown reason malformed", ResolutionOutcome{Resolved: false, Reason: "bogus"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.outcome.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("Validate() = nil, want error for %+v", tt.outcome)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil for %+v", err, tt.outcome)
			}
		})
	}
}

// TestResolvedVsNeverReachedDistinguishable is C1's required negative control: a resolved outcome
// and a never-reached outcome must be BYTE-distinguishable, and a single predicate must not
// accept both. The resolved one has resolved:true + a symbol object + no reason; the never-reached
// one has resolved:false + no symbol + a reason. An assertion satisfied by both measures nothing.
func TestResolvedVsNeverReachedDistinguishable(t *testing.T) {
	resolved := ResolutionOutcome{
		RecordID: "GO-2021-0113", Lane: "go", Ecosystem: "golang", Category: "reachable_unconfirmable",
		Resolved: true, Symbol: &ResolvedSymbol{SCIP: "scip:parse", DisplayName: "language.Parse"},
	}
	neverReached := ResolutionOutcome{
		RecordID: "CVE-2024-00000", Lane: "go", Ecosystem: "golang",
		Resolved: false, Reason: ReasonArtifactNotIndexed,
	}
	if err := resolved.Validate(); err != nil {
		t.Fatalf("resolved.Validate(): %v", err)
	}
	if err := neverReached.Validate(); err != nil {
		t.Fatalf("neverReached.Validate(): %v", err)
	}

	rb, err := json.Marshal(resolved)
	if err != nil {
		t.Fatal(err)
	}
	nb, err := json.Marshal(neverReached)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rb, nb) {
		t.Fatalf("resolved and never-reached outcomes serialised identically:\n  %s", rb)
	}

	// A discriminating predicate must SEPARATE them (accept one, reject the other) — not accept
	// both. The resolved shape: Resolved && Symbol != nil && Reason == "".
	discriminates := func(o ResolutionOutcome) bool { return o.Resolved && o.Symbol != nil && o.Reason == "" }
	if !discriminates(resolved) || discriminates(neverReached) {
		t.Fatalf("discriminating predicate failed to separate: resolved=%v neverReached=%v",
			discriminates(resolved), discriminates(neverReached))
	}

	// The resolved JSON carries a symbol and no reason; the never-reached JSON carries a reason
	// and no symbol.
	if !bytes.Contains(rb, []byte(`"symbol"`)) || bytes.Contains(rb, []byte(`"reason"`)) {
		t.Errorf("resolved JSON shape wrong: %s", rb)
	}
	if bytes.Contains(nb, []byte(`"symbol"`)) || !bytes.Contains(nb, []byte(`"reason":"artifact-not-indexed"`)) {
		t.Errorf("never-reached JSON shape wrong: %s", nb)
	}
}
