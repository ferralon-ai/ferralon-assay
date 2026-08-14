package pipeline

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestPresenceProjection proves the §4.4.6 absent-vs-none tri-state projects DISTINCTLY from the wire.
// The three inputs differ only in the `trigger` operand: omitted (nil pointer), empty struct (present
// but value-zero), and populated. toFacts must stamp Presence accordingly, closing the gap where a nil
// and an empty-struct operand both collapsed to one indistinguishable zero.
func TestPresenceProjection(t *testing.T) {
	const envelope = `"schema_version":"ferralon.normalized_advisory.v3","vuln_id":"CVE-PRESENCE","module":"example.com/x","version_scheme":"gomod"`
	cases := []struct {
		name    string
		trigger string // the trigger key fragment, or "" to omit it entirely
		want    Presence
	}{
		{"absent (nil operand)", "", PresenceAbsent},
		{"declared_empty (present, value-zero)", `,"trigger":{}`, PresenceDeclaredEmpty},
		{"declared_values (present, populated)", `,"trigger":{"ingress_kind":"http","route":"/fetch","param":"target"}`, PresenceDeclaredValues},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := "{" + envelope + tc.trigger + "}"
			var doc advisoryDoc
			if err := json.Unmarshal([]byte(raw), &doc); err != nil {
				t.Fatalf("unmarshal: %v (raw=%s)", err, raw)
			}
			facts, ok := doc.toFacts("CVE-PRESENCE")
			if !ok {
				t.Fatalf("toFacts ok=false, want true (raw=%s)", raw)
			}
			if facts.Trigger.Declared != tc.want {
				t.Errorf("Trigger.Declared = %s, want %s", facts.Trigger.Declared, tc.want)
			}
			// Behavior-preserving guard: absent and declared_empty must BOTH still report Zero()==true
			// (no consumer branch flips this cycle — the distinction is representable, not yet acted on).
			if tc.want != PresenceDeclaredValues && !facts.Trigger.Zero() {
				t.Errorf("Trigger.Zero() = false for %s, want true (behavior must be preserved)", tc.want)
			}
		})
	}
}

// TestAttributionStatusRecognized exercises the §4.4.8 fail-open validator: the empty zero plus the
// closed enum are recognized; anything else fails (→ fail open to unreviewed). This keeps the validator
// non-vacuous even though per-symbol wiring is deferred to PLAN-220.
func TestAttributionStatusRecognized(t *testing.T) {
	recognized := []string{"", "unreviewed", "confirmed", "ambiguous", "disputed"}
	for _, s := range recognized {
		if !attributionStatusRecognized(s) {
			t.Errorf("attributionStatusRecognized(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"reviewed", "maybe", "CONFIRMED", "exploitable", "true"} {
		if attributionStatusRecognized(s) {
			t.Errorf("attributionStatusRecognized(%q) = true, want false (must fail open)", s)
		}
	}
	// The named constants must equal their recognized wire strings (guards against a rename drifting
	// the enum away from the wire vocabulary the producer emits).
	if AttributionUnreviewed != "unreviewed" || AttributionConfirmed != "confirmed" ||
		AttributionAmbiguous != "ambiguous" || AttributionDisputed != "disputed" {
		t.Error("AttributionStatus constants drifted from their wire strings")
	}
}

// TestSymbolsTypedDeclaredAwaitingEmit proves the §4.4.2/.3 typed-symbol axis (anvil-q15): a v4 document
// carrying symbols_typed projects the canonical plugin.Symbol identities, while a v3/v2 document (and any
// v4 document the producer has not yet enriched) leaves SymbolsTyped nil. The nil is the
// declared-awaiting-emit state — distinct from an empty symbol set — so no consumer may read it as "no
// symbols" (the bare Symbols axis is unaffected).
func TestSymbolsTypedDeclaredAwaitingEmit(t *testing.T) {
	// (1) v3 document: SymbolsTyped stays nil (producer emits no typed symbols today), bare Symbols intact.
	const v3 = `{"schema_version":"ferralon.normalized_advisory.v3","vuln_id":"CVE-BARE","module":"example.com/x","version_scheme":"gomod","symbols":["x.Vuln"]}`
	var d3 advisoryDoc
	if err := json.Unmarshal([]byte(v3), &d3); err != nil {
		t.Fatalf("unmarshal v3: %v", err)
	}
	f3, ok := d3.toFacts("CVE-BARE")
	if !ok {
		t.Fatal("toFacts(v3) ok=false, want true")
	}
	if f3.SymbolsTyped != nil {
		t.Errorf("v3 SymbolsTyped = %v, want nil (declared-awaiting-emit)", f3.SymbolsTyped)
	}
	if len(f3.Symbols) != 1 || f3.Symbols[0] != "x.Vuln" {
		t.Errorf("v3 bare Symbols = %v, want [x.Vuln] (the typed axis must not disturb the bare axis)", f3.Symbols)
	}

	// (2) v4 document WITH symbols_typed: the canonical identities project through.
	const v4 = `{"schema_version":"ferralon.normalized_advisory.v4","vuln_id":"CVE-TYPED","module":"example.com/x","version_scheme":"gomod",
	  "symbols":["x.Vuln"],
	  "symbols_typed":[{"kind":"function","package":"example.com/x","name":"Vuln","display_name":"x.Vuln","scip":"scip-go . example.com/x Vuln()."}]}`
	var d4 advisoryDoc
	if err := json.Unmarshal([]byte(v4), &d4); err != nil {
		t.Fatalf("unmarshal v4: %v", err)
	}
	f4, ok := d4.toFacts("CVE-TYPED")
	if !ok {
		t.Fatal("toFacts(v4) ok=false, want true — a valid v4 document must decode")
	}
	want := plugin.Symbol{Kind: plugin.SymbolKindFunction, Package: "example.com/x", Name: "Vuln", DisplayName: "x.Vuln", SCIP: "scip-go . example.com/x Vuln()."}
	if len(f4.SymbolsTyped) != 1 || f4.SymbolsTyped[0] != want {
		t.Errorf("v4 SymbolsTyped = %+v, want [%+v]", f4.SymbolsTyped, want)
	}
}

// TestPublishedFeedGoldenBijection is the §4.4.9 enforcement: every record the published-feed manifest
// declares has working, digest-pinned golden coverage (Lookup succeeds), and no golden advisory file is
// an orphan (every *.json under the corpus, except manifest.json, is named by exactly one manifest
// entry). This closes "every published record has regression coverage" over the hash-pinned vendored
// golden without duplicating each record as a separate hand-authored fixture.
//
// SCOPE (documented per the PLAN-024 contract's OQ4 ruling): the covered set is the in-repo vendored
// golden corpus (testdata/ferralon-corpus/ — a small, hash-pinned, byte-for-byte snapshot of the
// producer's emit, currently the Log4Shell + HTTP/2-rapid-reset records), NOT the full 72+ production
// feed. The bijection is asserted over what the vendored manifest DECLARES it covers; extending the
// covered set to the entire production feed (one committed, digest-pinned record per feed entry) is
// PLAN-220's scale-out. This test guarantees no record inside the declared covered set lacks coverage.
func TestPublishedFeedGoldenBijection(t *testing.T) {
	src := artifactSource{root: ferralonCorpusRoot}
	man, ok := src.loadManifest()
	if !ok {
		t.Fatalf("loadManifest(%s) failed — the published-feed manifest must be valid", ferralonCorpusRoot)
	}
	if man.RecordCount == 0 {
		t.Fatal("manifest declares zero records — the published feed must be non-empty")
	}

	// (1) Every declared record round-trips through the digest-pinned golden.
	manifestPaths := make(map[string]bool, len(man.Records))
	for _, r := range man.Records {
		if _, ok := src.Lookup(r.Identifier); !ok {
			t.Errorf("manifest record %q has no working golden coverage (Lookup failed: missing/tampered/malformed)", r.Identifier)
		}
		manifestPaths[filepath.ToSlash(r.Path)] = true
	}

	// (2) No orphan golden: every advisory *.json under the corpus is named by a manifest entry.
	var goldenFiles int
	err := filepath.WalkDir(ferralonCorpusRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") || d.Name() == "manifest.json" {
			return nil
		}
		rel, err := filepath.Rel(ferralonCorpusRoot, path)
		if err != nil {
			return err
		}
		goldenFiles++
		if !manifestPaths[filepath.ToSlash(rel)] {
			t.Errorf("orphan golden advisory %q is not named by any manifest entry", filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk corpus: %v", err)
	}

	// (3) Bijection cardinality: as many golden advisory files as manifest records.
	if goldenFiles != len(man.Records) {
		t.Errorf("golden advisory files (%d) != manifest records (%d) — not a bijection", goldenFiles, len(man.Records))
	}
}
