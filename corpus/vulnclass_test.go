// internal/corpus/vulnclass_test.go
package corpus

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadVulnClass verifies the vuln-class corpus loads, validates, and that every fixture's
// vulnerable + patched repro directories exist on disk with a Dockerfile and a go.mod (so the live
// trial can build both images).
func TestLoadVulnClass(t *testing.T) {
	fixtures, err := LoadVulnClass()
	if err != nil {
		t.Fatalf("LoadVulnClass: %v", err)
	}
	if len(fixtures) < 2 {
		t.Fatalf("LoadVulnClass: got %d fixtures, want >= 2 (SSRF + DoS)", len(fixtures))
	}

	wantClasses := map[string]bool{"ssrf": false, "dos": false}
	for _, f := range fixtures {
		if err := f.Validate(); err != nil {
			t.Errorf("fixture %q failed Validate: %v", f.ID, err)
		}
		if _, ok := wantClasses[f.VulnClass]; ok {
			wantClasses[f.VulnClass] = true
		}
		for _, p := range []string{f.VulnerablePath, f.PatchedPath} {
			for _, sub := range []string{"Dockerfile", "go.mod", "main.go"} {
				path := filepath.Join(p, sub)
				if _, err := os.Stat(path); err != nil {
					t.Errorf("fixture %q: missing %s (%v)", f.ID, path, err)
				}
			}
		}
	}
	for cls, seen := range wantClasses {
		if !seen {
			t.Errorf("vuln-class corpus missing the %q fixture", cls)
		}
	}
}
