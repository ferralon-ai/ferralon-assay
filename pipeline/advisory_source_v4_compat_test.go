// advisory_source_v4_compat_test.go
//
// The v3→v4 back-compat GATE (anvil-q18). Before the cve-enrichment producer flips to emitting
// the v4 typed-symbol tag, the v4 reader MUST be proven a strict SUPERSET of v3: every existing
// v2/v3 record still loads, unchanged, with no rejection and no phantom typed symbols. This is the
// one place the "additive" claim can be wrong, and the risk lands OUTSIDE this file's unit surface —
// in the real emitted corpus (garnet's demo feed and every lane's fixtures), all tagged v2/v3 today.
//
// TestSchemaVersionRecognized_Set (advisory_source_v3_test.go) already proves the recognizer is the
// closed set {v2, v3, v4} at the string level. This test discharges the gate the way L0 required it:
// by LOADING actual, digest-pinned v2/v3 records through the full artifactSource path (read → digest
// pin → unmarshal → toFacts) under the v4 reader — not by asserting additivity. The covered set here
// is the in-repo vendored real corpus (the real intel-emitted v2 Log4Shell + v3 HTTP/2 rapid-reset
// records under testdata/ferralon-corpus/); the closed-set recognizer + the omitempty SymbolsTyped
// field are the mechanism that carries the same guarantee to the full feed at scale.
package pipeline

import "testing"

// dedicatedV3CompatRoot is a compat corpus OWNED by this gate — a v2 record and a multi-package v3
// record with go-scheme bare symbols, hand-authored and digest-pinned, that NOTHING in the pipeline
// or the producer ever flips. It decouples the v3→v4 compat proof from the shared cross-repo golden
// (testdata/ferralon-corpus/): when the coordinated v4 flip re-stamps the shared golden's records to
// v4, this fixture stays v3, so the proof "a v3 record still loads under the v4 reader" survives the
// flip instead of being destroyed by it (anvil-q19, Q2 ruling: dedicated fixture, not a retained
// golden record).
const dedicatedV3CompatRoot = "testdata/v3compat"

// TestV4Reader_LoadsDedicatedPreV4Fixture is the durable, flip-proof half of the v3→v4 compat gate.
// It loads the dedicated v2/v3 fixture through the digest-pinned reader and asserts each record loads
// with ok=true, SymbolsTyped nil (declared-awaiting-emit, never asserted-empty), and every pre-v4 axis
// intact. Unlike the shared-golden half below, this fixture is never re-stamped, so this assertion
// keeps proving the superset property after the producer flip lands.
func TestV4Reader_LoadsDedicatedPreV4Fixture(t *testing.T) {
	src := artifactSource{root: dedicatedV3CompatRoot}

	cases := []struct {
		id               string
		wantSymbols      int
		wantAffectedPkgs int
	}{
		{id: "FERRALON-COMPAT-V2-0001", wantSymbols: 0, wantAffectedPkgs: 0}, // v2: no symbols, no v3 block
		{id: "FERRALON-COMPAT-V3-0001", wantSymbols: 2, wantAffectedPkgs: 2}, // v3: 2 go symbols + 2-package block
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			facts, ok := src.Lookup(tc.id)
			if !ok {
				t.Fatalf("v4 reader rejected dedicated pre-v4 record %s — the additive superset claim is BROKEN", tc.id)
			}
			if facts.SymbolsTyped != nil {
				t.Errorf("%s: SymbolsTyped = %v, want nil (a pre-v4 record reads as declared-awaiting-emit, not asserted-empty)", tc.id, facts.SymbolsTyped)
			}
			if len(facts.Symbols) != tc.wantSymbols {
				t.Errorf("%s: bare Symbols count = %d, want %d", tc.id, len(facts.Symbols), tc.wantSymbols)
			}
			if len(facts.AffectedPackages) != tc.wantAffectedPkgs {
				t.Errorf("%s: AffectedPackages count = %d, want %d (the v3 block must project under v4)", tc.id, len(facts.AffectedPackages), tc.wantAffectedPkgs)
			}
		})
	}
}

// TestV4Reader_LoadsRealPreV4RecordsUnchanged is the gate: a v4-era reader loads the real vendored
// v2/v3 records with ok=true, leaves SymbolsTyped nil (declared-awaiting-emit — the v4 axis is absent
// on a pre-v4 record, which is NOT an empty symbol set), and preserves every pre-v4 axis (the bare
// Symbols strings and the v3 affected_packages[] block). If the reader had been made strict-equal to
// the v4 tag, or if the added SymbolsTyped field perturbed decoding, one of these real records would
// fail here — before the producer ever flips.
func TestV4Reader_LoadsRealPreV4RecordsUnchanged(t *testing.T) {
	src := artifactSource{root: ferralonCorpusRoot}

	cases := []struct {
		id               string // manifest identifier
		wantSymbols      int    // bare Symbols[] the pre-v4 record already carries
		wantAffectedPkgs int    // v3 affected_packages[] the record carries (0 for the v2 record)
	}{
		// Real v2 record (Log4Shell): no symbols, no v3 block. Must still load under v4.
		{id: "CVE-2021-44228", wantSymbols: 0, wantAffectedPkgs: 0},
		// Real v3 record (HTTP/2 rapid-reset): 5 go-scheme symbol strings + a 2-package v3 block.
		{id: "CVE-2023-39325", wantSymbols: 5, wantAffectedPkgs: 2},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			facts, ok := src.Lookup(tc.id)
			if !ok {
				t.Fatalf("v4 reader rejected real pre-v4 record %s — the additive superset claim is BROKEN "+
					"(a v3 corpus record stops validating the moment the reader knows v4)", tc.id)
			}
			// The v4 axis MUST be nil on a pre-v4 record: absent, never an asserted-empty symbol set.
			if facts.SymbolsTyped != nil {
				t.Errorf("%s: SymbolsTyped = %v, want nil — a pre-v4 record must read as declared-awaiting-emit, "+
					"not as a phantom empty typed-symbol set", tc.id, facts.SymbolsTyped)
			}
			// Every pre-v4 axis survives the v4 reader untouched.
			if len(facts.Symbols) != tc.wantSymbols {
				t.Errorf("%s: bare Symbols count = %d, want %d — the typed axis must not disturb the bare axis",
					tc.id, len(facts.Symbols), tc.wantSymbols)
			}
			if len(facts.AffectedPackages) != tc.wantAffectedPkgs {
				t.Errorf("%s: AffectedPackages count = %d, want %d — the v3 additive block must still project under v4",
					tc.id, len(facts.AffectedPackages), tc.wantAffectedPkgs)
			}
		})
	}
}
