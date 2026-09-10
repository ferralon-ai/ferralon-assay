// internal/corpus/vulnclass_kotlin_test.go
package corpus

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadKotlinVulnClass verifies the Kotlin vuln-class corpus loads, validates,
// enforces the schema-version guard, and that every fixture's vulnerable + patched
// repro directories exist on disk with a Dockerfile and the .kt source files (so
// the live trial can compile both JVM images with kotlinc). It is the hermetic
// guard for the embedded Kotlin fixture + repro layout; the expected signal is
// advisory-only (inv.5) and is asserted live by the Kotlin trial, never here.
func TestLoadKotlinVulnClass(t *testing.T) {
	fixtures, err := LoadKotlinVulnClass()
	if err != nil {
		t.Fatalf("LoadKotlinVulnClass: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("LoadKotlinVulnClass: got 0 fixtures, want >= 1 (SSRF)")
	}

	sawSSRF := false
	for _, f := range fixtures {
		if err := f.Validate(); err != nil {
			t.Errorf("fixture %q failed Validate: %v", f.ID, err)
		}
		if f.SchemaVersion != VulnClassSchemaVersion {
			t.Errorf("fixture %q schema_version %q, want %q", f.ID, f.SchemaVersion, VulnClassSchemaVersion)
		}
		if f.VulnClass == "ssrf" {
			sawSSRF = true
		}
		for _, p := range []string{f.VulnerablePath, f.PatchedPath} {
			for _, sub := range []string{
				"Dockerfile",
				"src/com/example/web/Main.kt",
				"src/com/example/web/FetchHandler.kt",
				"src/com/example/web/UrlFetcher.kt",
			} {
				path := filepath.Join(p, sub)
				if _, err := os.Stat(path); err != nil {
					t.Errorf("fixture %q: missing %s (%v)", f.ID, path, err)
				}
			}
		}
	}
	if !sawSSRF {
		t.Error("Kotlin vuln-class corpus missing the \"ssrf\" fixture")
	}
}
