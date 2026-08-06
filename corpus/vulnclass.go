// internal/corpus/vulnclass.go
//
// The vuln-class expansion corpus. It is a SEPARATE fixture set from
// the locked golden-4 (Load/LoadFS): those four are the Phase-1 taxonomy with a hard count guard.
// The vuln-class corpus instead pairs, per NEW vuln class, a (vulnerable, patched) repro and the
// proof signal/strategy the class is proven through, so the live trial can assert both directions:
//   - the vulnerable repro reaches a proven exploitable verdict via the class's intrinsic signal;
//   - detonating the same trigger against the patched repro stays DARK (negative control).
//
// These fixtures are advisory-only metadata: they NEVER decide a verdict (inv.5). The expected
// signal/strategy is what a SOUND end-to-end run must produce, asserted live, never asserted from
// the fixture alone.
package corpus

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
)

//go:embed vulnclass/*.json
var vulnclassEmbedded embed.FS

//go:embed vulnclass_java/*.json
var vulnclassJavaEmbedded embed.FS

//go:embed vulnclass_java_spring/*.json
var vulnclassJavaSpringEmbedded embed.FS

//go:embed vulnclass_js/*.json
var vulnclassJSEmbedded embed.FS

// VulnClassSchemaVersion is the only vuln-class fixture schema version this loader accepts.
const VulnClassSchemaVersion = "tegron.corpus.vulnclass.v1"

// VulnClassFixture pairs a vulnerable + patched repro for one NEW vuln class with the proof route
// the class is confirmed through. The repro paths are relative to internal/corpus (the live trial
// resolves them to absolute, like the golden-4).
type VulnClassFixture struct {
	SchemaVersion  string `json:"schema_version"`
	ID             string `json:"id"`              // advisory id (matches the pipeline advisoryTable entry)
	VulnClass      string `json:"vuln_class"`      // expected proof.Class (e.g. "ssrf", "dos")
	Source         string `json:"source"`          // advisory source: osv|nvd|ghsa
	Summary        string `json:"summary"`         // advisory summary (human + provenance)
	CWE            string `json:"cwe"`             // the driving CWE (e.g. "CWE-918")
	VulnerablePath string `json:"vulnerable_path"` // relative repro dir for the exploitable build
	PatchedPath    string `json:"patched_path"`    // relative repro dir for the negative-control build
	ExpectedSignal string `json:"expected_signal"` // proof.SignalKind a sound proven run must surface
	OwnershipToken string `json:"ownership_token"` // ownership proof for the request
}

// validVulnClassSignals is the closed set of proof signals a vuln-class fixture may name.
var validVulnClassSignals = map[string]bool{
	"canary": true,
	"sink":   true,
	"fault":  true,
}

// Validate enforces the vuln-class fixture invariants.
func (f VulnClassFixture) Validate() error {
	if f.SchemaVersion != VulnClassSchemaVersion {
		return fmt.Errorf("vulnclass: fixture %q has schema_version %q, want %q", f.ID, f.SchemaVersion, VulnClassSchemaVersion)
	}
	if f.ID == "" {
		return errors.New("vulnclass: fixture has empty id")
	}
	if f.VulnClass == "" {
		return fmt.Errorf("vulnclass: fixture %q has empty vuln_class", f.ID)
	}
	if !validSources[f.Source] {
		return fmt.Errorf("vulnclass: fixture %q has unknown source %q", f.ID, f.Source)
	}
	if f.VulnerablePath == "" || f.PatchedPath == "" {
		return fmt.Errorf("vulnclass: fixture %q requires both vulnerable_path and patched_path", f.ID)
	}
	if !validVulnClassSignals[f.ExpectedSignal] {
		return fmt.Errorf("vulnclass: fixture %q has unknown expected_signal %q", f.ID, f.ExpectedSignal)
	}
	if f.OwnershipToken == "" {
		return fmt.Errorf("vulnclass: fixture %q has empty ownership_token", f.ID)
	}
	return nil
}

// LoadVulnClass reads and validates every Go vuln-class fixture from the embedded FS.
func LoadVulnClass() ([]VulnClassFixture, error) {
	return loadVulnClassFrom(vulnclassEmbedded, "vulnclass")
}

// LoadJavaVulnClass reads and validates every Java vuln-class fixture (the
// Increment-1 corpus). It is kept in a SEPARATE embedded dir from the Go fixtures
// so the Go live trial (TestLiveVulnClass, which drives tegron-plugin-go) never
// picks up a Java repro it cannot build, and the Java live trial
// (TestLiveJavaVulnClass, which drives tegron-plugin-java) never picks up a Go one.
func LoadJavaVulnClass() ([]VulnClassFixture, error) {
	return loadVulnClassFrom(vulnclassJavaEmbedded, "vulnclass_java")
}

// LoadJavaSpringVulnClass reads and validates the Java Increment-3 semantic-
// dispatch fixture(s). It is kept in a SEPARATE embedded dir from the Increment-1
// Java fixtures because its ingress→sink path crosses an interface dispatch that
// ONLY the Prove-only scip-java analyzer container resolves: the analyzer-unaware
// Increment-1 live trial (TestLiveJavaVulnClass) would never reach proven on it
// (pure-Go lexical yields Partial(dynamic_dispatch)). The dedicated
// TestLiveJavaSpringSSRF live trial drives this fixture WITH the analyzer image
// set — the control that earns the verdict.
func LoadJavaSpringVulnClass() ([]VulnClassFixture, error) {
	return loadVulnClassFrom(vulnclassJavaSpringEmbedded, "vulnclass_java_spring")
}

// LoadJSVulnClass reads and validates every JS/TS vuln-class fixture (the JS
// Increment-1 corpus). It is kept in a SEPARATE embedded dir from the Go/Java
// fixtures so each language's live trial drives only its own plugin over repros it
// can build: TestLiveJSVulnClass (tegron-plugin-js) never picks up a Go/Java repro,
// and the Go/Java trials never pick up a JS one.
func LoadJSVulnClass() ([]VulnClassFixture, error) {
	return loadVulnClassFrom(vulnclassJSEmbedded, "vulnclass_js")
}

// loadVulnClassFrom reads and validates every fixture under dir in fsys.
func loadVulnClassFrom(fsys embed.FS, dir string) ([]VulnClassFixture, error) {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("vulnclass: sub %s/: %w", dir, err)
	}
	entries, err := fs.Glob(sub, "*.json")
	if err != nil {
		return nil, fmt.Errorf("vulnclass: glob %s/*.json: %w", dir, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("vulnclass: no fixture files found in %s/", dir)
	}
	out := make([]VulnClassFixture, 0, len(entries))
	for _, name := range entries {
		data, err := fs.ReadFile(sub, name)
		if err != nil {
			return nil, fmt.Errorf("vulnclass: read %s: %w", name, err)
		}
		var f VulnClassFixture
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("vulnclass: decode %s: %w", name, err)
		}
		if err := f.Validate(); err != nil {
			return nil, fmt.Errorf("vulnclass: invalid fixture %s: %w", name, err)
		}
		out = append(out, f)
	}
	return out, nil
}
