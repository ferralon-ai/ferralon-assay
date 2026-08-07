package artifact

import (
	"regexp"
	"testing"
)

// allTypes is the canonical list of every artifact.Type constant. The
// completeness test cross-checks it against the Registry in both directions, so
// adding a Type without registering it (or registering an unknown Type) fails.
// TestEveryDeclaredTypeConstIsRegistered (registry_constcoverage_test.go) is the
// backstop: it parses artifact.go and fails if a `Type = "..."` const is declared
// but absent from the Registry — even if it was also forgotten here. That backstop
// exists because two real types (repro_image, exposure_footprint) were once declared
// and emitted while silently missing from both this list and the Registry.
var allTypes = []Type{
	TypeNormalizedAdvisory,
	TypeInventory,
	TypePublicPoC,
	TypeDisqualification,
	TypeDiscovery,
	TypeVulnerableSymbol,
	TypeReachability,
	TypeIngressMap,
	TypeCandidatePair,
	TypePoE,
	TypeTaint,
	TypeHarness,
	TypeExposureFootprint,
	TypeMaliciousPresence,
	// Standard projections.
	TypeProjectionSARIF,
	TypeProjectionVEX,
	TypeProjectionSSVC,
	TypeProjectionRedactedPoE,
}

// TypeNormalizedAdvisory is the designed exception: its SchemaVersion is a cross-repo
// "ferralon.*" wire tag (see the comment on that Registry entry), not an engine-internal shape.
// The regexp already admits the ferralon. prefix, so it lives under the same governed pattern
// without a special case.
var schemaVersionRe = regexp.MustCompile(`^(tegron|ferralon)\.[a-z_]+\.v\d+$`)

func TestRegistryCoversEveryType(t *testing.T) {
	if len(allTypes) != 18 {
		t.Fatalf("expected 18 frozen artifact types, allTypes has %d", len(allTypes))
	}
	for _, ty := range allTypes {
		meta, ok := Lookup(ty)
		if !ok {
			t.Errorf("type %q has no Registry entry", ty)
			continue
		}
		if meta.Owner == "" {
			t.Errorf("type %q has empty Owner", ty)
		}
		if meta.SchemaVersion == "" {
			t.Errorf("type %q has empty SchemaVersion", ty)
		}
		if !schemaVersionRe.MatchString(meta.SchemaVersion) {
			t.Errorf("type %q SchemaVersion %q does not match %s", ty, meta.SchemaVersion, schemaVersionRe)
		}
	}
}

func TestRegistryHasNoOrphanEntries(t *testing.T) {
	known := make(map[Type]bool, len(allTypes))
	for _, ty := range allTypes {
		known[ty] = true
	}
	for _, ty := range Types() {
		if !known[ty] {
			t.Errorf("Registry has orphan entry for unknown type %q", ty)
		}
	}
	if got := len(Types()); got != len(allTypes) {
		t.Fatalf("Registry has %d entries, want %d (one per known Type)", got, len(allTypes))
	}
}

func TestCandidatePairRegistryVersionMatchesConst(t *testing.T) {
	meta, ok := Lookup(TypeCandidatePair)
	if !ok {
		t.Fatal("TypeCandidatePair missing from Registry")
	}
	if meta.SchemaVersion != CandidatePairSchemaVersion {
		t.Fatalf("Registry SchemaVersion = %q, want const %q", meta.SchemaVersion, CandidatePairSchemaVersion)
	}
}
