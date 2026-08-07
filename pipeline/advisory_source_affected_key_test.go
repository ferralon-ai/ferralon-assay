// advisory_source_affected_key_test.go
//
// Pins the FOURTH producer divergence (advisory_source_wire_alignment_test.go documents the first
// three): the multi-package affected set arrives under TWO different keys, with two different member
// shapes, and the reader must accept both.
//
//   - the internal enrichment surface — and this package's own testdata/ferralon-corpus fixtures —
//     emit `affected_packages[]`, whose members mirror the reader's scalar block field-for-field;
//   - the published corpus at ferralon-ai/vulnerability-corpus emits `affected[]`, whose members use
//     `ranges` (not `affected_ranges`) and, critically, SWAP the meaning of `fixed` and
//     `upper_exclusive` relative to the flat shape.
//
// Carrying only `affected_packages` was silent, not loud: Go's decoder drops unknown keys, so
// AffectedPackages decoded to nil on EVERY published record and select-by-target — real, wired
// production code at stages.go codebase_inventory — had nothing to iterate. The feature was fully
// built and structurally inert.
//
// FIXTURE PROVENANCE. testdata/public-corpus/ holds three records captured VERBATIM on 2026-08-06
// from https://raw.githubusercontent.com/ferralon-ai/vulnerability-corpus/main/, with a manifest
// generated over their real bytes:
//
//	2021/12/CVE-2021-44228.json  Log4Shell — 3 maven packages; the flat primary is a shaded fork
//	                             whose only range is last_affected-only, and NO flat affected_ranges
//	                             block exists at all
//	2023/10/CVE-2023-39325.json  HTTP/2 rapid reset — 2 gomod packages, both with real bounds
//	2020/07/CVE-2020-8203.json   lodash prototype pollution — 8 npm packages, one of which carries
//	                             the literal version_scheme "honest-absent"
//
// They are read through the real artifactSource (manifest + digest pin + decode), not hand-fed to
// toFacts, so a regression in any part of the production read path fails here.
package pipeline

import (
	"path/filepath"
	"testing"
)

// publicCorpusSource is the real, digest-pinned reader over the captured live records.
func publicCorpusSource() AdvisorySource {
	return NewArtifactSource(filepath.Join("testdata", "public-corpus"))
}

// coordinates lists the decoded set's coordinates in order, for order-independent lookups and for
// readable failure messages.
func coordinates(pkgs []AffectedPackage) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, p.Coordinate)
	}
	return out
}

// findPackage returns the decoded element with the given coordinate. The published corpus does not
// guarantee `affected[]` is coordinate-sorted (CVE-2020-8203 lists lodash-rails before lodash), so
// tests must look elements up by identity, never by index.
func findPackage(pkgs []AffectedPackage, coordinate string) (AffectedPackage, bool) {
	for _, p := range pkgs {
		if p.Coordinate == coordinate {
			return p, true
		}
	}
	return AffectedPackage{}, false
}

// TestAffectedKey_Precedence is the decode-and-precedence table. Both keys populate the SAME
// AffectedPackages field; `affected` wins whole when both are present, and neither present leaves the
// field nil so the scalar flat block stands exactly as it does today.
func TestAffectedKey_Precedence(t *testing.T) {
	const affectedBlock = `"affected": [
	  {"coordinate": "example.com/pub-a", "purl": "pkg:golang/example.com/pub-a", "version_scheme": "gomod",
	   "ranges": [{"introduced": "1.0.0", "upper_exclusive": "1.4.0", "fixed": "1.4.0"}]},
	  {"coordinate": "example.com/pub-b", "purl": "pkg:golang/example.com/pub-b", "version_scheme": "gomod",
	   "ranges": [{"upper_exclusive": "2.2.0", "fixed": "2.2.0"}]}
	]`
	const packagesBlock = `"affected_packages": [
	  {"module": "example.com/int-a", "coordinate": "example.com/int-a", "version_scheme": "gomod",
	   "affected_ranges": [{"fixed": "9.9.9", "fixed_version": "9.9.9"}]}
	]`

	tests := []struct {
		name  string
		block string
		want  []string // coordinates, in any order
	}{
		{
			name:  "affected only (published corpus)",
			block: affectedBlock,
			want:  []string{"example.com/pub-a", "example.com/pub-b"},
		},
		{
			name:  "affected_packages only (internal reader fixture)",
			block: packagesBlock,
			want:  []string{"example.com/int-a"},
		},
		{
			// Precedence is WHOLE-SET, not per-element: the internal-only coordinate must NOT appear
			// alongside the published ones. A merged array is one no producer ever asserted.
			name:  "both present: affected wins whole, no merge",
			block: affectedBlock + ",\n" + packagesBlock,
			want:  []string{"example.com/pub-a", "example.com/pub-b"},
		},
		{
			name:  "neither present: nil, flat block stands",
			block: `"coordinate": "example.com/flat"`,
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := `{
			  "schema_version": "ferralon.normalized_advisory.v3",
			  "vuln_id": "CVE-TEST-KEYS",
			  "version_scheme": "gomod",
			  "affected_ranges": [{"fixed": "1.4.0", "fixed_version": "1.4.0"}],
			  ` + tt.block + `
			}`
			root := writeCorpus(t, map[string]string{"CVE-TEST-KEYS": raw})
			facts, ok := NewArtifactSource(root).Lookup("CVE-TEST-KEYS")
			if !ok {
				t.Fatal("Lookup ok=false, want true — a well-formed document must resolve")
			}
			got := coordinates(facts.AffectedPackages)
			if len(got) != len(tt.want) {
				t.Fatalf("AffectedPackages coordinates = %v, want %v", got, tt.want)
			}
			for _, want := range tt.want {
				if _, found := findPackage(facts.AffectedPackages, want); !found {
					t.Errorf("coordinate %q missing from %v", want, got)
				}
			}
			// Honest-absent contract: whichever key is (or is not) present, the flat block survives
			// untouched. Asserted on populated values, so it cannot pass vacuously.
			if len(facts.AffectedRanges) != 1 || facts.AffectedRanges[0].Fixed != "1.4.0" {
				t.Errorf("flat AffectedRanges = %+v, want one range with Fixed 1.4.0", facts.AffectedRanges)
			}
		})
	}
}

// TestAffectedKey_RangeKeysAreNotAFieldNameMatch is the trap guard. In `affected[].ranges[]` the
// exclusive upper bound is `upper_exclusive` and `fixed` names the FIXING RELEASE; in the flat
// `affected_ranges[]` (and in docRange) those two roles are carried by `fixed` and `fixed_version`
// respectively. The engine's whole version axis reads Range.Fixed AS the upper-exclusive bound
// (buildAffectedRanges), so a name-for-name decode would quietly feed it the wrong value. The two
// coincide on most advisories, which is exactly why the fixture below makes them DIFFER.
func TestAffectedKey_RangeKeysAreNotAFieldNameMatch(t *testing.T) {
	const raw = `{
	  "schema_version": "ferralon.normalized_advisory.v3",
	  "vuln_id": "CVE-TEST-RANGEKEYS",
	  "affected": [
	    {"coordinate": "example.com/x", "version_scheme": "gomod",
	     "ranges": [
	       {"introduced": "1.0.0", "upper_exclusive": "1.9.0", "fixed": "1.9.4"},
	       {"last_affected": "0.9.9"}
	     ]}
	  ]
	}`
	root := writeCorpus(t, map[string]string{"CVE-TEST-RANGEKEYS": raw})
	facts, ok := NewArtifactSource(root).Lookup("CVE-TEST-RANGEKEYS")
	if !ok {
		t.Fatal("Lookup ok=false, want true")
	}
	pkg, found := findPackage(facts.AffectedPackages, "example.com/x")
	if !found {
		t.Fatalf("example.com/x missing; got %v", coordinates(facts.AffectedPackages))
	}
	if len(pkg.AffectedRanges) != 2 {
		t.Fatalf("AffectedRanges = %+v, want 2", pkg.AffectedRanges)
	}
	first := pkg.AffectedRanges[0]
	if first.Introduced != "1.0.0" {
		t.Errorf("Introduced = %q, want 1.0.0", first.Introduced)
	}
	if first.Fixed != "1.9.0" {
		t.Errorf("Fixed = %q, want 1.9.0 — Range.Fixed is the EXCLUSIVE UPPER BOUND, which the corpus spells `upper_exclusive`", first.Fixed)
	}
	if first.FixedVersion != "1.9.4" {
		t.Errorf("FixedVersion = %q, want 1.9.4 — the corpus's `fixed` is the FIXING RELEASE", first.FixedVersion)
	}
	// A last_affected-only range is a real, bounded corpus shape — it must survive the per-element
	// boundless-range check rather than dropping the element.
	if pkg.AffectedRanges[1].LastAffected != "0.9.9" {
		t.Errorf("second range = %+v, want LastAffected 0.9.9", pkg.AffectedRanges[1])
	}
}

// TestAffectedKey_ShapeValidationHoldsForBothKeys proves the per-element guarantees that existed for
// `affected_packages` bind `affected` identically: an unrecognized version_scheme or a boundless range
// DROPS that element and keeps the document (never the reverse, never a whole-corpus outage). Both
// keys run the same table because both normalize onto the one validation loop in toFacts.
func TestAffectedKey_ShapeValidationHoldsForBothKeys(t *testing.T) {
	tests := []struct {
		name string
		// affected / affected_packages spellings of the SAME two-element set: one good element plus
		// one element that must be dropped.
		affected string
		packages string
	}{
		{
			name: "unrecognized version_scheme drops the element",
			// "honest-absent" is not hypothetical: the published corpus emits it literally
			// (CVE-2020-8203's lodash-rails entry), per the corpus field reference.
			affected: `{"coordinate": "example.com/bad", "version_scheme": "honest-absent", "ranges": [{"upper_exclusive": "1.0.0"}]}`,
			packages: `{"coordinate": "example.com/bad", "version_scheme": "honest-absent", "affected_ranges": [{"fixed": "1.0.0"}]}`,
		},
		{
			name:     "boundless range drops the element",
			affected: `{"coordinate": "example.com/bad", "version_scheme": "gomod", "ranges": [{}]}`,
			packages: `{"coordinate": "example.com/bad", "version_scheme": "gomod", "affected_ranges": [{}]}`,
		},
	}
	for _, tt := range tests {
		for _, key := range []struct{ name, jsonKey, bad, good string }{
			{
				name:    "affected",
				jsonKey: "affected",
				bad:     tt.affected,
				good:    `{"coordinate": "example.com/good", "version_scheme": "gomod", "ranges": [{"upper_exclusive": "2.0.0"}]}`,
			},
			{
				name:    "affected_packages",
				jsonKey: "affected_packages",
				bad:     tt.packages,
				good:    `{"coordinate": "example.com/good", "version_scheme": "gomod", "affected_ranges": [{"fixed": "2.0.0"}]}`,
			},
		} {
			t.Run(tt.name+"/"+key.name, func(t *testing.T) {
				raw := `{
				  "schema_version": "ferralon.normalized_advisory.v3",
				  "vuln_id": "CVE-TEST-SHAPE",
				  "` + key.jsonKey + `": [` + key.bad + `, ` + key.good + `]
				}`
				root := writeCorpus(t, map[string]string{"CVE-TEST-SHAPE": raw})
				facts, ok := NewArtifactSource(root).Lookup("CVE-TEST-SHAPE")
				if !ok {
					t.Fatal("Lookup ok=false — a garbled ELEMENT must never reject the document")
				}
				got := coordinates(facts.AffectedPackages)
				if len(got) != 1 || got[0] != "example.com/good" {
					t.Fatalf("AffectedPackages = %v, want only example.com/good", got)
				}
				if len(facts.AffectedPackages[0].AffectedRanges) != 1 ||
					facts.AffectedPackages[0].AffectedRanges[0].Fixed != "2.0.0" {
					t.Errorf("surviving element ranges = %+v, want one upper-exclusive 2.0.0",
						facts.AffectedPackages[0].AffectedRanges)
				}
			})
		}
	}
}

// TestAffectedKey_SymbolsInheritAdvisoryLevel pins the one place normalization is not a pure rename.
// The published corpus states symbols ONCE, at advisory level, and carries no per-entry symbols key;
// the reader models them per-package and — downstream in advisoryPURLAndSymbols — reads the SELECTED
// element's symbols with no fallback to the top-level list. Leaving them empty would take the symbol
// axis dark on every published record the moment select-by-target starts firing. `affected_packages`
// elements state their own and must not inherit.
func TestAffectedKey_SymbolsInheritAdvisoryLevel(t *testing.T) {
	const affectedRaw = `{
	  "schema_version": "ferralon.normalized_advisory.v3",
	  "vuln_id": "CVE-TEST-SYMS",
	  "symbols": ["example.com/x.Sink", "example.com/x.Other"],
	  "affected": [{"coordinate": "example.com/x", "version_scheme": "gomod", "ranges": [{"upper_exclusive": "1.0.0"}]}]
	}`
	root := writeCorpus(t, map[string]string{"CVE-TEST-SYMS": affectedRaw})
	facts, ok := NewArtifactSource(root).Lookup("CVE-TEST-SYMS")
	if !ok {
		t.Fatal("Lookup ok=false, want true")
	}
	pkg, found := findPackage(facts.AffectedPackages, "example.com/x")
	if !found {
		t.Fatalf("example.com/x missing; got %v", coordinates(facts.AffectedPackages))
	}
	if len(pkg.Symbols) != 2 || pkg.Symbols[0] != "example.com/x.Sink" {
		t.Errorf("Symbols = %v, want the advisory-level list inherited", pkg.Symbols)
	}

	const packagesRaw = `{
	  "schema_version": "ferralon.normalized_advisory.v3",
	  "vuln_id": "CVE-TEST-SYMS2",
	  "symbols": ["example.com/x.AdvisoryLevel"],
	  "affected_packages": [{"coordinate": "example.com/x", "version_scheme": "gomod",
	    "affected_ranges": [{"fixed": "1.0.0"}], "symbols": ["example.com/x.PerPackage"]}]
	}`
	root2 := writeCorpus(t, map[string]string{"CVE-TEST-SYMS2": packagesRaw})
	facts2, ok := NewArtifactSource(root2).Lookup("CVE-TEST-SYMS2")
	if !ok {
		t.Fatal("Lookup ok=false, want true")
	}
	pkg2, found := findPackage(facts2.AffectedPackages, "example.com/x")
	if !found {
		t.Fatalf("example.com/x missing; got %v", coordinates(facts2.AffectedPackages))
	}
	if len(pkg2.Symbols) != 1 || pkg2.Symbols[0] != "example.com/x.PerPackage" {
		t.Errorf("Symbols = %v, want the element's own list, not the advisory-level one", pkg2.Symbols)
	}
}

// TestAffectedKey_RealCorpusRecords reads the three captured live records through the real
// artifactSource. Each asserts on POPULATED values — a coordinate that must be present, a bound that
// must have a specific string — so none of them can pass on an empty decode.
func TestAffectedKey_RealCorpusRecords(t *testing.T) {
	src := publicCorpusSource()

	t.Run("CVE-2021-44228 (maven, 3 packages, no flat range block)", func(t *testing.T) {
		facts, ok := src.Lookup("CVE-2021-44228")
		if !ok {
			t.Fatal("Lookup ok=false — the live Log4Shell record must resolve")
		}
		// The record carries NO top-level affected_ranges at all: before this change the reader got a
		// package identity for Log4Shell and zero usable version-range data.
		if len(facts.AffectedRanges) != 0 {
			t.Fatalf("flat AffectedRanges = %+v, want none — this record has no flat range block", facts.AffectedRanges)
		}
		if len(facts.AffectedPackages) != 3 {
			t.Fatalf("AffectedPackages = %v, want 3", coordinates(facts.AffectedPackages))
		}
		// The real fix-relevant package is NOT the flat primary: `com.guicedee.services:log4j-core`
		// sorts first and is a shaded fork whose only range is last_affected-only.
		if facts.Coordinate != "com.guicedee.services:log4j-core" {
			t.Fatalf("flat primary coordinate = %q, want the shaded fork the corpus picks", facts.Coordinate)
		}
		core, found := findPackage(facts.AffectedPackages, "org.apache.logging.log4j:log4j-core")
		if !found {
			t.Fatalf("org.apache.logging.log4j:log4j-core missing; got %v", coordinates(facts.AffectedPackages))
		}
		if core.VersionScheme != "maven" {
			t.Errorf("VersionScheme = %q, want maven", core.VersionScheme)
		}
		wantUppers := map[string]bool{"2.3.1": true, "2.15.0": true, "2.12.2": true}
		if len(core.AffectedRanges) != 3 {
			t.Fatalf("log4j-core ranges = %+v, want 3", core.AffectedRanges)
		}
		for _, r := range core.AffectedRanges {
			if !wantUppers[r.Fixed] {
				t.Errorf("range upper-exclusive %q not in %v", r.Fixed, wantUppers)
			}
			if r.Introduced == "" {
				t.Errorf("range %+v lost its introduced bound", r)
			}
		}
		// Advisory-level symbols reach the element (see TestAffectedKey_SymbolsInheritAdvisoryLevel).
		if len(core.Symbols) != 1 || core.Symbols[0] != "org.apache.logging.log4j.core.lookup.JndiLookup" {
			t.Errorf("Symbols = %v, want the advisory's JndiLookup symbol", core.Symbols)
		}
	})

	t.Run("CVE-2023-39325 (gomod, 2 packages)", func(t *testing.T) {
		facts, ok := src.Lookup("CVE-2023-39325")
		if !ok {
			t.Fatal("Lookup ok=false")
		}
		if len(facts.AffectedPackages) != 2 {
			t.Fatalf("AffectedPackages = %v, want 2", coordinates(facts.AffectedPackages))
		}
		xnet, found := findPackage(facts.AffectedPackages, "golang.org/x/net")
		if !found {
			t.Fatalf("golang.org/x/net missing; got %v", coordinates(facts.AffectedPackages))
		}
		// gomod projection: the corpus states no `module`, so the coordinate becomes the module path —
		// the key the whole Go version axis is resolved on.
		if xnet.Module != "golang.org/x/net" {
			t.Errorf("Module = %q, want the coordinate projected onto the module path", xnet.Module)
		}
		if len(xnet.AffectedRanges) != 1 || xnet.AffectedRanges[0].Fixed != "0.17.0" {
			t.Errorf("x/net ranges = %+v, want one upper-exclusive 0.17.0", xnet.AffectedRanges)
		}
		stdlib, found := findPackage(facts.AffectedPackages, "stdlib")
		if !found {
			t.Fatalf("stdlib missing; got %v", coordinates(facts.AffectedPackages))
		}
		if len(stdlib.AffectedRanges) != 2 {
			t.Errorf("stdlib ranges = %+v, want 2 (the 1.20 and 1.21 branches)", stdlib.AffectedRanges)
		}
	})

	t.Run("CVE-2020-8203 (npm, 8 packages, one honest-absent scheme)", func(t *testing.T) {
		facts, ok := src.Lookup("CVE-2020-8203")
		if !ok {
			t.Fatal("Lookup ok=false")
		}
		// 8 entries in, 7 out: `lodash-rails` declares version_scheme "honest-absent", which is not a
		// comparator this engine has, so per-element fail-open drops it and keeps the document.
		got := coordinates(facts.AffectedPackages)
		if len(got) != 7 {
			t.Fatalf("AffectedPackages = %v, want 7 of the record's 8 entries", got)
		}
		if _, found := findPackage(facts.AffectedPackages, "lodash-rails"); found {
			t.Error("lodash-rails survived; its version_scheme is the literal \"honest-absent\"")
		}
		es, found := findPackage(facts.AffectedPackages, "lodash-es")
		if !found {
			t.Fatalf("lodash-es missing; got %v", got)
		}
		if len(es.AffectedRanges) != 1 || es.AffectedRanges[0].Fixed != "4.17.20" {
			t.Errorf("lodash-es ranges = %+v, want one upper-exclusive 4.17.20", es.AffectedRanges)
		}
		// The flat block names `lodash` and bounds it at 4.17.19 — a DIFFERENT package with a
		// DIFFERENT bound. That divergence is what makes the select-by-target regression real.
		if facts.Coordinate != "lodash" {
			t.Errorf("flat primary = %q, want lodash", facts.Coordinate)
		}
	})
}
