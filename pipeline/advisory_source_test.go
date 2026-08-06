// advisory_source_test.go
//
// Self-contained tests for the AdvisorySource seam. The artifactSource fixtures live under
// testdata/advisory_source/ so these tests do NOT depend on an upstream producer's golden corpus
// being vendored — that reconciliation lives in advisory_source_roundtrip_test.go, which vendors a
// real producer emit and proves the shared cross-repo contract. Every artifactSource failure path
// must fail OPEN — (zero AdvisoryFacts, false) — never a partial or laundered fact (inv.5).
//
// advisory_source.go is the source of truth for the wire shape; where a comment below describes a
// contract rule, that rule is enforced by the code in advisory_source.go and by the test it
// annotates.
package pipeline

import (
	"reflect"
	"testing"
)

const advisoryFixtureRoot = "testdata/advisory_source"

// tableSource is the default AdvisorySource: its Lookup must be the exact AdvisoryTable map read
// the two S1 sites did inline, so wiring the seam preserves behavior byte-for-byte.
func TestTableSource_MatchesAdvisoryTable(t *testing.T) {
	src := tableSource{}
	for id, want := range AdvisoryTable {
		got, ok := src.Lookup(id)
		if !ok {
			t.Errorf("tableSource.Lookup(%q) ok=false, want true", id)
		}
		if got.PURL != want.PURL || got.Module != want.Module || got.UpperExclusive != want.UpperExclusive {
			t.Errorf("tableSource.Lookup(%q) = %+v, want %+v", id, got, want)
		}
	}
	if _, ok := src.Lookup("NOPE-DOES-NOT-EXIST"); ok {
		t.Error("tableSource.Lookup(unknown) ok=true, want false (fail open)")
	}
}

// normalizedAdvisorySchemaVersion is the cross-repo wire tag pinned by literal value. Changing it
// silently would desynchronize this reader from every producer emitting the old tag, so drift here
// must fail this TEST loudly — runtime stays fail-open regardless.
func TestNormalizedAdvisorySchemaVersion_Literal(t *testing.T) {
	const want = "ferralon.normalized_advisory.v2"
	if normalizedAdvisorySchemaVersion != want {
		t.Fatalf("normalizedAdvisorySchemaVersion = %q, want %q — changing the wire tag desynchronizes every producer",
			normalizedAdvisorySchemaVersion, want)
	}
}

// A valid, digest-matching, shape-valid artifact loads with facts fully populated.
func TestArtifactSource_ValidLoads(t *testing.T) {
	src := artifactSource{root: advisoryFixtureRoot}
	facts, ok := src.Lookup("TEGRON-TEST-0001")
	if !ok {
		t.Fatal("Lookup(TEGRON-TEST-0001) ok=false, want true")
	}
	if facts.Coordinate != "com.example.lib:widget" {
		t.Errorf("Coordinate = %q, want com.example.lib:widget", facts.Coordinate)
	}
	if facts.VersionScheme != "maven" || facts.UpperExclusive != "1.4.0" {
		t.Errorf("VersionScheme/UpperExclusive = %q/%q, want maven/1.4.0", facts.VersionScheme, facts.UpperExclusive)
	}
	if len(facts.AffectedRanges) != 1 || facts.AffectedRanges[0].Fixed != "1.4.0" {
		t.Errorf("AffectedRanges = %+v, want one range fixed at 1.4.0", facts.AffectedRanges)
	}
	if facts.Provenance.TrustTier != TrustFirstParty {
		t.Errorf("Provenance.TrustTier = %q, want first_party", facts.Provenance.TrustTier)
	}
}

// A record whose manifest `path` names a date-partitioned subdirectory (the
// "2021/12/CVE-2021-44228.json" shape) loads exactly like a flat-basename record. This is
// the behavior safeRelPath extends beyond the old flat-basename-only safeRelName.
func TestArtifactSource_DatePartitionedPathLoads(t *testing.T) {
	src := artifactSource{root: advisoryFixtureRoot}
	facts, ok := src.Lookup("TEGRON-TEST-DATED")
	if !ok {
		t.Fatal("Lookup(TEGRON-TEST-DATED) ok=false, want true (date-partitioned subpath must resolve)")
	}
	if facts.Coordinate != "com.example.lib:dated" {
		t.Errorf("Coordinate = %q, want com.example.lib:dated", facts.Coordinate)
	}
	if facts.SinkKind != "code_execution" {
		t.Errorf("SinkKind = %q, want code_execution", facts.SinkKind)
	}
}

// A file whose bytes do not match the manifest digest is rejected to Undetermined — a tampered or
// stale-regen artifact can never poison S1.
func TestArtifactSource_DigestMismatchFailsOpen(t *testing.T) {
	src := artifactSource{root: advisoryFixtureRoot}
	facts, ok := src.Lookup("TEGRON-TEST-BADDIGEST")
	if ok {
		t.Fatal("Lookup(TEGRON-TEST-BADDIGEST) ok=true, want false (digest mismatch must fail open)")
	}
	if !reflect.DeepEqual(facts, AdvisoryFacts{}) {
		t.Errorf("digest mismatch returned non-zero facts %+v, want zero (never laundered)", facts)
	}
}

// A digest-matching document declaring the OLD pre-rename "tegron.normalized_advisory.v2" tag fails
// shape-validation: the reader now accepts only "ferralon.normalized_advisory.v2". The
// version-drift loudness lives in TestNormalizedAdvisorySchemaVersion_Literal; here it must be a
// quiet fail-open, never a partial or laundered fact.
func TestArtifactSource_OldSchemaTagFailsOpen(t *testing.T) {
	src := artifactSource{root: advisoryFixtureRoot}
	facts, ok := src.Lookup("TEGRON-TEST-MALFORMED")
	if ok {
		t.Fatal("Lookup(TEGRON-TEST-MALFORMED) ok=true, want false (old tegron.* schema tag must fail open)")
	}
	if !reflect.DeepEqual(facts, AdvisoryFacts{}) {
		t.Errorf("old-tag document returned non-zero facts %+v, want zero", facts)
	}
}

// An id absent from the manifest returns false with zero facts (byte-identical to a map miss).
func TestArtifactSource_UnknownIDFailsOpen(t *testing.T) {
	src := artifactSource{root: advisoryFixtureRoot}
	facts, ok := src.Lookup("TEGRON-TEST-NOPE")
	if ok {
		t.Fatal("Lookup(unknown) ok=true, want false")
	}
	if !reflect.DeepEqual(facts, AdvisoryFacts{}) {
		t.Errorf("unknown id returned non-zero facts %+v, want zero", facts)
	}
}

// A root with no manifest at all fails open on every lookup (unreadable-source path).
func TestArtifactSource_MissingManifestFailsOpen(t *testing.T) {
	src := artifactSource{root: "testdata/advisory_source/does-not-exist"}
	if _, ok := src.Lookup("TEGRON-TEST-0001"); ok {
		t.Error("Lookup against missing manifest ok=true, want false")
	}
}

// Bad `path` variants, all reader-enforced: absolute, ".." traversal, and backslash
// separators must all fail open, even though the manifest entry otherwise names a real, well-formed
// digest. Table-driven since all three share the same "manifest is otherwise fine, only path is bad"
// shape.
func TestArtifactSource_BadPathVariantsFailOpen(t *testing.T) {
	tests := []struct {
		name   string
		vulnID string
	}{
		{"absolute path", "TEGRON-TEST-ABSPATH"},
		{"parent traversal", "TEGRON-TEST-DOTDOT"},
		{"backslash separator", "TEGRON-TEST-BACKSLASH"},
	}
	src := artifactSource{root: advisoryFixtureRoot}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facts, ok := src.Lookup(tt.vulnID)
			if ok {
				t.Fatalf("Lookup(%s) ok=true, want false (bad path must fail open)", tt.vulnID)
			}
			if !reflect.DeepEqual(facts, AdvisoryFacts{}) {
				t.Errorf("bad path returned non-zero facts %+v, want zero", facts)
			}
		})
	}
}

// safeRelPath is exercised directly too, since the manifest-level fixtures above only prove the
// three PRESENT bad-path fixtures; this covers the boundary cases (empty, ".", doubled separators)
// that would be awkward to encode as separate manifest fixtures.
func TestSafeRelPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"CVE-2021-44228.json", true},
		{"2021/12/CVE-2021-44228.json", true},
		{"", false},
		{".", false},
		{"..", false},
		{"/etc/passwd", false},
		{"../escape.json", false},
		{"a/../b.json", false},
		{`sub\file.json`, false},
		{"a//b.json", false},
		{"./a.json", false},
	}
	for _, tt := range tests {
		if got := safeRelPath(tt.path); got != tt.want {
			t.Errorf("safeRelPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// A manifest whose declared record_count disagrees with len(records) is invalid in its entirety —
// every Lookup against it fails open, even for an id whose record entry would otherwise be fine
// — record_count != len(records) means the manifest cannot account for its own record set.
func TestArtifactSource_RecordCountMismatchFailsOpen(t *testing.T) {
	src := artifactSource{root: "testdata/advisory_source/badcount"}
	facts, ok := src.Lookup("TEGRON-TEST-BADCOUNT")
	if ok {
		t.Fatal("Lookup against a record_count-mismatched manifest ok=true, want false")
	}
	if !reflect.DeepEqual(facts, AdvisoryFacts{}) {
		t.Errorf("record_count mismatch returned non-zero facts %+v, want zero", facts)
	}
}

// A manifest with two records sharing the same identifier is invalid in its entirety — an ambiguous
// manifest cannot be trusted to name the right file for that id (or any id), so the whole manifest
// fails open rather than silently picking one of the two records.
func TestArtifactSource_DuplicateIdentifierFailsOpen(t *testing.T) {
	src := artifactSource{root: "testdata/advisory_source/dupid"}
	facts, ok := src.Lookup("TEGRON-TEST-DUP")
	if ok {
		t.Fatal("Lookup against a manifest with a duplicate identifier ok=true, want false")
	}
	if !reflect.DeepEqual(facts, AdvisoryFacts{}) {
		t.Errorf("duplicate identifier returned non-zero facts %+v, want zero", facts)
	}
}
