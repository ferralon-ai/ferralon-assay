// advisory_source_wire_alignment_test.go
//
// Pins the wire shapes the reader must accept for the three fields that have DRIFTED BETWEEN
// PRODUCERS — the built-in AdvisoryTable and the upstream enrichment records on one side, the
// published corpus on the other. The first two drifts share a failure mode
// and a cost: a type mismatch fails json.Unmarshal on the WHOLE document, so one unreadable field
// silently empties an entire corpus.
//
//  1. `poc_signal` — the enrichment records emit the OBJECT {available,...}; the published corpus
//     emits a BARE BOOL, and its own field reference declares it so. Both must decode.
//  2. the advisory narrative — enrichment emits `root_cause`; the published corpus emits `summary` on
//     every record and `root_cause` on none. Both must decode, `root_cause` preferred.
//  3. the Go module path — the built-in table spells it `module`; the published corpus spells it
//     `coordinate` and omits `module`. Costs no decode, but silently costs the Go version axis.
//
// HISTORY — this file previously asserted the OPPOSITE for both fields (object-only, root_cause-only),
// including an explicit "bare-bool must fail the decode" guard. That lock was written from the
// internal record shape, where bool-only decoding was the failure. It was measured wrong against
// the artifact that actually ships: the object-only decoder rejected 67 of the 72 records in the
// published corpus, taking the scan work
// set's overlap with the corpus from a claimed 5-of-16 to a real 0-of-16. The reversal is deliberate:
// the union accepts BOTH producers, so neither direction can regress, and the old one-sided guard
// could only ever be right about one of them.
//
// These tests exercise advisoryDoc.Unmarshal + toFacts directly (no manifest/digest machinery), so a
// regression on either wire shape fails loudly here rather than silently degrading recall.
package pipeline

import (
	"encoding/json"
	"testing"
)

// TestWire_PocSignalObjectDecodes proves poc_signal-as-object round-trips: the object's `available`
// flag lands on AdvisoryFacts.PocSignal, an available:false object yields false, and an absent
// poc_signal yields the zero (false) — never a decode failure.
func TestWire_PocSignalObjectDecodes(t *testing.T) {
	tests := []struct {
		name string
		poc  string // the poc_signal JSON value, or "" to omit the key entirely
		want bool
	}{
		{"available true", `"poc_signal": {"available": true, "references": ["http://example/poc"], "source": "NVD reference tags"},`, true},
		{"available false", `"poc_signal": {"available": false, "source": "OSV"},`, false},
		{"object absent", ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := `{
			  "schema_version": "ferralon.normalized_advisory.v3",
			  "vuln_id": "CVE-TEST-POC",
			  "module": "example.com/x",
			  "version_scheme": "gomod",
			  ` + tt.poc + `
			  "sink_kind": "ssrf"
			}`
			var doc advisoryDoc
			if err := json.Unmarshal([]byte(raw), &doc); err != nil {
				t.Fatalf("unmarshal poc_signal-object doc: %v", err)
			}
			facts, ok := doc.toFacts("CVE-TEST-POC")
			if !ok {
				t.Fatal("toFacts ok=false, want true — a well-formed doc must decode")
			}
			if facts.PocSignal != tt.want {
				t.Errorf("PocSignal = %v, want %v", facts.PocSignal, tt.want)
			}
		})
	}
}

// TestWire_PocSignalBareBoolDecodes is the guard for the published-corpus encoding: a bare-bool
// poc_signal must decode the whole document AND land on AdvisoryFacts.PocSignal. Object-only decoding
// rejected 67 of the 72 published records; this is the test that would have caught that.
func TestWire_PocSignalBareBoolDecodes(t *testing.T) {
	for _, tt := range []struct {
		name string
		poc  string
		want bool
	}{
		{"bare true", `true`, true},
		{"bare false", `false`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw := `{
			  "schema_version": "ferralon.normalized_advisory.v3",
			  "vuln_id": "CVE-TEST-POC",
			  "version_scheme": "gomod",
			  "poc_signal": ` + tt.poc + `
			}`
			var doc advisoryDoc
			if err := json.Unmarshal([]byte(raw), &doc); err != nil {
				t.Fatalf("unmarshal bare-bool poc_signal doc: %v — the published corpus emits this shape", err)
			}
			facts, ok := doc.toFacts("CVE-TEST-POC")
			if !ok {
				t.Fatal("toFacts ok=false, want true — a bare-bool poc_signal must not reject the document")
			}
			if facts.PocSignal != tt.want {
				t.Errorf("PocSignal = %v, want %v", facts.PocSignal, tt.want)
			}
		})
	}
}

// TestWire_PocSignalUnknownEncodingFailsOpenAtTheField proves the third case: an encoding that is
// neither bool nor object narrows poc_signal to its zero WITHOUT rejecting the surrounding advisory.
// Whole-document rejection over one unreadable evidence flag is precisely the failure this file
// documents; poc_signal carries no verdict, so its zero is the honest, conservative reading.
func TestWire_PocSignalUnknownEncodingFailsOpenAtTheField(t *testing.T) {
	const raw = `{
	  "schema_version": "ferralon.normalized_advisory.v3",
	  "vuln_id": "CVE-TEST-POC",
	  "module": "example.com/x",
	  "version_scheme": "gomod",
	  "poc_signal": "yes, definitely"
	}`
	var doc advisoryDoc
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("unmarshal doc with unknown poc_signal encoding: %v — the field must fail open, not the document", err)
	}
	facts, ok := doc.toFacts("CVE-TEST-POC")
	if !ok {
		t.Fatal("toFacts ok=false, want true — an unreadable poc_signal must not discard a digest-verified advisory")
	}
	if facts.PocSignal {
		t.Error("PocSignal = true, want false — an unreadable signal is never a positive signal")
	}
	if facts.Module != "example.com/x" {
		t.Errorf("Module = %q, want the document's module — the rest of the fact must survive", facts.Module)
	}
}

// TestWire_NarrativeDecodesFromEitherKey proves the advisory narrative decodes from BOTH spellings
// onto AdvisoryFacts.Summary, and that `root_cause` wins when a record carries both.
func TestWire_NarrativeDecodesFromEitherKey(t *testing.T) {
	tests := []struct {
		name string
		keys string
		want string
	}{
		{
			name: "root_cause (intel enrichment records)",
			keys: `"root_cause": "server-side request forgery in the fetch handler"`,
			want: "server-side request forgery in the fetch handler",
		},
		{
			name: "summary (published corpus)",
			keys: `"summary": "server-side request forgery in the fetch handler"`,
			want: "server-side request forgery in the fetch handler",
		},
		{
			name: "both present → root_cause wins",
			keys: `"root_cause": "the preferred narrative", "summary": "the compat narrative"`,
			want: "the preferred narrative",
		},
		{
			name: "neither present → empty",
			keys: `"module": "example.com/x"`,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := `{
			  "schema_version": "ferralon.normalized_advisory.v2",
			  "vuln_id": "CVE-TEST-RC",
			  "version_scheme": "gomod",
			  ` + tt.keys + `
			}`
			var doc advisoryDoc
			if err := json.Unmarshal([]byte(raw), &doc); err != nil {
				t.Fatalf("unmarshal narrative doc: %v", err)
			}
			facts, ok := doc.toFacts("CVE-TEST-RC")
			if !ok {
				t.Fatal("toFacts ok=false, want true")
			}
			if facts.Summary != tt.want {
				t.Errorf("Summary = %q, want %q", facts.Summary, tt.want)
			}
		})
	}
}

// TestWire_GoModulePathProjectsCoordinate proves the third producer divergence is reconciled: the
// built-in table spells the Go module path `module`, the published corpus spells it `coordinate` and
// omits `module`. The engine's whole Go version axis is keyed on Module, so without the projection a
// corpus-carried advisory loses its version axis and falls through to reachability — a weaker ground
// for the same non-finding. Scoped to gomod: other ecosystems' coordinates are not module paths.
func TestWire_GoModulePathProjectsCoordinate(t *testing.T) {
	tests := []struct {
		name       string
		module     string
		coordinate string
		scheme     string
		want       string
	}{
		{"gomod, coordinate only (published corpus)", "", "golang.org/x/crypto", "gomod", "golang.org/x/crypto"},
		{"gomod, module only (built-in table)", "golang.org/x/crypto", "", "gomod", "golang.org/x/crypto"},
		{"gomod, both → module wins", "golang.org/x/crypto", "something/else", "gomod", "golang.org/x/crypto"},
		{"maven coordinate is NOT a module path", "", "com.example:widget", "maven", ""},
		{"npm coordinate is NOT a module path", "", "lodash", "npm", ""},
		{"pypi coordinate is NOT a module path", "", "flask", "pypi", ""},
		{"empty scheme (Go semver default) is not gomod-tagged", "", "golang.org/x/crypto", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := goModulePath(tt.module, tt.coordinate, tt.scheme); got != tt.want {
				t.Errorf("goModulePath(%q, %q, %q) = %q, want %q", tt.module, tt.coordinate, tt.scheme, got, tt.want)
			}
		})
	}

	// End-to-end through the decoder, in the exact shape the published corpus emits.
	const raw = `{
	  "schema_version": "ferralon.normalized_advisory.v3",
	  "vuln_id": "CVE-2024-45337",
	  "version_scheme": "gomod",
	  "coordinate": "golang.org/x/crypto",
	  "purl": "pkg:golang/golang.org/x/crypto",
	  "poc_signal": false,
	  "affected_ranges": [{"fixed": "0.31.0", "fixed_version": "0.31.0"}]
	}`
	var doc advisoryDoc
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("unmarshal published-corpus-shaped doc: %v", err)
	}
	facts, ok := doc.toFacts("CVE-2024-45337")
	if !ok {
		t.Fatal("toFacts ok=false — the published corpus's own record shape must decode")
	}
	if facts.Module != "golang.org/x/crypto" {
		t.Errorf("Module = %q, want the coordinate projected onto the module path", facts.Module)
	}
	if facts.Coordinate != "golang.org/x/crypto" {
		t.Errorf("Coordinate = %q, want it preserved alongside Module", facts.Coordinate)
	}
}
