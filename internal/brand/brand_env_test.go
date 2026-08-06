package brand

import "testing"

// TestEnvOrLegacy_Precedence exercises the resolver's precedence logic with synthetic env-var
// names, independent of which EnvPrefix is compiled in — the whole point of EnvOrLegacy is that
// its behavior doesn't depend on what the names actually are.
func TestEnvOrLegacy_Precedence(t *testing.T) {
	const derived = "FIXTURE_BRAND_DERIVED_X"
	const legacy = "FIXTURE_LEGACY_X"

	t.Run("derived set only → derived", func(t *testing.T) {
		t.Setenv(derived, "from-derived")
		t.Setenv(legacy, "")
		if got := EnvOrLegacy(derived, legacy); got != "from-derived" {
			t.Fatalf("EnvOrLegacy = %q, want %q", got, "from-derived")
		}
	})

	t.Run("legacy set only → legacy is honored", func(t *testing.T) {
		t.Setenv(derived, "")
		t.Setenv(legacy, "from-legacy")
		if got := EnvOrLegacy(derived, legacy); got != "from-legacy" {
			t.Fatalf("EnvOrLegacy = %q, want %q (legacy fallback)", got, "from-legacy")
		}
	})

	t.Run("both set → derived wins", func(t *testing.T) {
		t.Setenv(derived, "from-derived")
		t.Setenv(legacy, "from-legacy")
		if got := EnvOrLegacy(derived, legacy); got != "from-derived" {
			t.Fatalf("EnvOrLegacy = %q, want %q (derived must win over legacy)", got, "from-derived")
		}
	})

	t.Run("neither set → empty (caller applies its own default)", func(t *testing.T) {
		t.Setenv(derived, "")
		t.Setenv(legacy, "")
		if got := EnvOrLegacy(derived, legacy); got != "" {
			t.Fatalf("EnvOrLegacy = %q, want empty", got)
		}
	})

	// Regression guard: if a call site reverts to reading ONLY the legacy name directly
	// (bypassing EnvOrLegacy), a derived-only value silently vanishes. This test fails on that
	// exact regression shape — see the execution note for the negative proof (this assertion
	// was verified to fail when EnvOrLegacy was temporarily rewritten to return
	// os.Getenv(legacyName) unconditionally, i.e. never consulting derivedName).
	t.Run("regression guard: derived-only value must not be lost", func(t *testing.T) {
		t.Setenv(derived, "only-the-derived-name-is-set")
		t.Setenv(legacy, "")
		if got := EnvOrLegacy(derived, legacy); got != "only-the-derived-name-is-set" {
			t.Fatalf("EnvOrLegacy = %q, want %q — a call site reading only the legacy name would silently drop this value", got, "only-the-derived-name-is-set")
		}
	})
}

// TestEnvOrLegacy_LegacyChain covers the multi-legacy form the rebrand introduced: call sites
// pass ASSAY_X, then NUCLEON_X, then TEGRON_X, and the chain must be walked strictly in the
// order given so a newer name always beats an older one an operator forgot to remove.
func TestEnvOrLegacy_LegacyChain(t *testing.T) {
	const (
		derived = "FIXTURE_BRAND_DERIVED_CHAIN"
		mid     = "FIXTURE_LEGACY_CHAIN_MID"
		oldest  = "FIXTURE_LEGACY_CHAIN_OLDEST"
	)

	t.Run("no legacy names at all → derived or empty", func(t *testing.T) {
		t.Setenv(derived, "")
		if got := EnvOrLegacy(derived); got != "" {
			t.Fatalf("EnvOrLegacy = %q, want empty", got)
		}
		t.Setenv(derived, "v")
		if got := EnvOrLegacy(derived); got != "v" {
			t.Fatalf("EnvOrLegacy = %q, want %q", got, "v")
		}
	})

	t.Run("only the oldest legacy set → oldest is reached", func(t *testing.T) {
		t.Setenv(derived, "")
		t.Setenv(mid, "")
		t.Setenv(oldest, "from-oldest")
		if got := EnvOrLegacy(derived, mid, oldest); got != "from-oldest" {
			t.Fatalf("EnvOrLegacy = %q, want %q — the chain must be walked past an unset middle name", got, "from-oldest")
		}
	})

	t.Run("mid and oldest set → chain order wins, not last-set", func(t *testing.T) {
		t.Setenv(derived, "")
		t.Setenv(mid, "from-mid")
		t.Setenv(oldest, "from-oldest")
		if got := EnvOrLegacy(derived, mid, oldest); got != "from-mid" {
			t.Fatalf("EnvOrLegacy = %q, want %q — the newer legacy name must beat the older one", got, "from-mid")
		}
	})

	t.Run("derived beats every legacy name", func(t *testing.T) {
		t.Setenv(derived, "from-derived")
		t.Setenv(mid, "from-mid")
		t.Setenv(oldest, "from-oldest")
		if got := EnvOrLegacy(derived, mid, oldest); got != "from-derived" {
			t.Fatalf("EnvOrLegacy = %q, want %q", got, "from-derived")
		}
	})
}
