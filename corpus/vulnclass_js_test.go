// internal/corpus/vulnclass_js_test.go
package corpus

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadJSVulnClass verifies the JS vuln-class corpus loads, validates, and that the
// SSRF fixture's vulnerable + patched repro directories exist on disk with a Dockerfile
// and the source files (so the live trial can build both Node images). It is the
// hermetic guard for the embedded JS fixture + repro layout.
func TestLoadJSVulnClass(t *testing.T) {
	fixtures, err := LoadJSVulnClass()
	if err != nil {
		t.Fatalf("LoadJSVulnClass: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("LoadJSVulnClass: got 0 fixtures, want >= 1 (SSRF)")
	}
	sawSSRF := false
	for _, f := range fixtures {
		if err := f.Validate(); err != nil {
			t.Errorf("fixture %q failed Validate: %v", f.ID, err)
		}
		if f.VulnClass == "ssrf" {
			sawSSRF = true
		}
		for _, p := range []string{f.VulnerablePath, f.PatchedPath} {
			for _, sub := range []string{"Dockerfile", "src/app.js", "src/fetcher.js"} {
				path := filepath.Join(p, sub)
				if _, err := os.Stat(path); err != nil {
					t.Errorf("fixture %q: missing %s (%v)", f.ID, path, err)
				}
			}
		}
	}
	if !sawSSRF {
		t.Error("JS vuln-class corpus missing the \"ssrf\" fixture")
	}
}
