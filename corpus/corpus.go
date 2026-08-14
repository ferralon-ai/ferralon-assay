// Package corpus provides the C0 golden corpus: checked-in regression fixtures and a
// loader that validates and surfaces them as typed Go values. The fixtures live under
// testdata/ and are embedded via //go:embed so the loader is hermetic and CWD-independent
// (critical for go test ./...).
//
// Corpus imports only stdlib plus assessment (also stdlib-only). It is a leaf package
// with no import-cycle risk.
//
// # No API-stability promise
//
// This package is exported ONLY so a consumer in another module (the backend's honesty
// gate) can import it — Go's internal/ visibility cannot cross a module
// boundary. It is not a supported API and nothing outside this repository should
// depend on it: its shape follows the fixtures, and the fixtures change whenever the
// regression set does. Being importable is a consequence of the module layout, not an
// offer of compatibility.
package corpus

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"

	"github.com/ferralon-ai/ferralon-assay/assessment"
)

//go:embed testdata/*.json
var embedded embed.FS

// packageDir is the absolute directory of this source file, resolved at init via runtime.Caller.
// Fixture repro paths are stored relative to the corpus package (testdata/repros/...); anchoring
// them here makes them resolve correctly regardless of the caller's working directory — the corpus
// moved into its own OSS module, so callers in other packages/modules no longer share its CWD.
var packageDir = func() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Dir(file)
}()

// resolveReproPath makes a fixture's relative vendored-repro path absolute, anchored at the corpus
// package directory. Absolute paths and the empty string pass through unchanged.
func resolveReproPath(p string) string {
	if p == "" || filepath.IsAbs(p) || packageDir == "" {
		return p
	}
	return filepath.Join(packageDir, p)
}

// ReproPath resolves a fixture-relative repro path to an absolute path anchored at the corpus
// package directory, independent of the caller's working directory. Absolute paths and "" pass
// through unchanged. Callers in other packages/modules (e.g. the live corpustest suite) MUST use
// this rather than joining against os.Getwd(), which broke when the corpus was carved into its
// own module (commit 8d38dda).
func ReproPath(p string) string { return resolveReproPath(p) }

// SchemaVersion is the only fixture schema version this loader accepts.
const SchemaVersion = "tegron.corpus.v1"

// Category is the canonical fixture taxonomy (mirrors the ROADMAP categories).
type Category string

const (
	CategoryTriviallyExploitable   Category = "trivially_exploitable"
	CategoryAbsentNotExploitable   Category = "absent_not_exploitable"
	CategoryReachableUnconfirmable Category = "reachable_unconfirmable"
	CategoryPatched                Category = "patched"
	// CategoryInstalledUndetermined: the vulnerable dependency version is present (inside the
	// advisory's affected range) but NO reachability determination was made — the version-only DEP
	// case with no symbols and no call graph. It is neither reachable_unconfirmable (nothing was
	// reached) nor absent_not_exploitable (the version IS present); it pairs with the third Warrant
	// direction "undetermined" (report.VerdictUndetermined: "the advisory applies and the scan
	// established NOTHING about it"). This is the fleet-wide encoding for every lane's version-only
	// DEP-vulnerable fixture (anvil-q12).
	CategoryInstalledUndetermined Category = "installed_undetermined"
)

// validCategories is the closed set of allowed Category values.
var validCategories = map[Category]bool{
	CategoryTriviallyExploitable:   true,
	CategoryAbsentNotExploitable:   true,
	CategoryReachableUnconfirmable: true,
	CategoryPatched:                true,
	CategoryInstalledUndetermined:  true,
}

// validSources is the closed set of allowed advisory source strings.
var validSources = map[string]bool{
	"osv":  true,
	"nvd":  true,
	"ghsa": true,
}

// validDirections is the closed set of allowed verdict directions. It mirrors the three-valued
// Warrant engine: "undetermined" (report.VerdictUndetermined) is the honest label for a case where
// the advisory applies but the scan established nothing — forcing such a case into either binary pole
// would either assert exploitability from mere version-presence (the SCA false positive) or assert
// safety from absent reachability evidence (a §3 violation). See anvil-q12.
var validDirections = map[string]bool{
	"exploitable":     true,
	"not_exploitable": true,
	"undetermined":    true,
}

// validStrengths is the closed set of allowed verdict strengths.
var validStrengths = map[string]bool{
	"proven":   true,
	"reasoned": true,
}

// validAcquisitionModes is the closed set of allowed acquisition modes.
var validAcquisitionModes = map[string]bool{
	"vendored_repro": true,
	"pinned_ref":     true,
}

// validCompletionStatuses is the closed set of allowed completion statuses.
var validCompletionStatuses = map[string]bool{
	"completed":               true,
	"stopped_budget":          true,
	"stopped_capability":      true,
	"environment_unavailable": true,
}

// Advisory carries the vulnerability reference for a fixture.
type Advisory struct {
	ID         string   `json:"id"`
	Source     string   `json:"source"`
	Summary    string   `json:"summary"`
	References []string `json:"references"`
}

// Acquisition describes how the test codebase was obtained.
type Acquisition struct {
	Mode    string `json:"mode"`
	Path    string `json:"path,omitempty"`    // relative to internal/corpus; set when mode=vendored_repro
	Module  string `json:"module,omitempty"`  // set when mode=pinned_ref
	Version string `json:"version,omitempty"` // set when mode=pinned_ref
	Notes   string `json:"notes,omitempty"`
}

// Codebase identifies the codebase under assessment.
type Codebase struct {
	Repo        string      `json:"repo"`
	Revision    string      `json:"revision"`
	Acquisition Acquisition `json:"acquisition"`
}

// Execution describes the execution context.
type Execution struct {
	Kind string `json:"kind"`
}

// ExpectedVerdict carries the known-true verdict for a fixture plus assertability metadata.
type ExpectedVerdict struct {
	Direction        string   `json:"direction"`
	Strength         string   `json:"strength"`
	CompletionStatus string   `json:"completion_status"`
	Label            string   `json:"label"`
	ExpectedFlags    []string `json:"expected_flags"`
	Rationale        string   `json:"rationale"`
	// AssertableNow is false for all v1 fixtures: the stub pipeline emits a uniform
	// reasoned_not_exploitable verdict so direction/strength equality is not yet earned.
	// Flip to true once real stages branch on the fixture's input.
	AssertableNow bool `json:"assertable_now"`
}

// OwnershipProof asserts the requester controls the target codebase.
type OwnershipProof struct {
	Token string `json:"token"`
}

// Fixture is the fully-decoded representation of one corpus fixture (schema tegron.corpus.v1).
type Fixture struct {
	SchemaVersion   string          `json:"schema_version"`
	ID              string          `json:"id"`
	Category        Category        `json:"category"`
	Advisory        Advisory        `json:"advisory"`
	Codebase        Codebase        `json:"codebase"`
	Execution       Execution       `json:"execution"`
	ExpectedVerdict ExpectedVerdict `json:"expected_verdict"`
	OwnershipProof  OwnershipProof  `json:"ownership_proof"`
}

// Validate enforces schema invariants. Returns a non-nil error on the first violation.
func (f Fixture) Validate() error {
	if f.SchemaVersion != SchemaVersion {
		return fmt.Errorf("corpus: fixture %q has schema_version %q, want %q", f.ID, f.SchemaVersion, SchemaVersion)
	}
	if f.ID == "" {
		return errors.New("corpus: fixture has empty id")
	}
	if !validCategories[f.Category] {
		return fmt.Errorf("corpus: fixture %q has unknown category %q", f.ID, f.Category)
	}
	if f.Advisory.ID == "" {
		return fmt.Errorf("corpus: fixture %q has empty advisory.id", f.ID)
	}
	if !validSources[f.Advisory.Source] {
		return fmt.Errorf("corpus: fixture %q has unknown advisory.source %q", f.ID, f.Advisory.Source)
	}
	if !validDirections[f.ExpectedVerdict.Direction] {
		return fmt.Errorf("corpus: fixture %q has unknown expected_verdict.direction %q", f.ID, f.ExpectedVerdict.Direction)
	}
	if !validStrengths[f.ExpectedVerdict.Strength] {
		return fmt.Errorf("corpus: fixture %q has unknown expected_verdict.strength %q", f.ID, f.ExpectedVerdict.Strength)
	}
	if !validCompletionStatuses[f.ExpectedVerdict.CompletionStatus] {
		return fmt.Errorf("corpus: fixture %q has unknown expected_verdict.completion_status %q", f.ID, f.ExpectedVerdict.CompletionStatus)
	}
	wantLabel := expectedLabel(f.ExpectedVerdict.Direction, f.ExpectedVerdict.Strength)
	if f.ExpectedVerdict.Label != wantLabel {
		return fmt.Errorf("corpus: fixture %q label %q is inconsistent with direction+strength (want %q)",
			f.ID, f.ExpectedVerdict.Label, wantLabel)
	}
	if !validAcquisitionModes[f.Codebase.Acquisition.Mode] {
		return fmt.Errorf("corpus: fixture %q has unknown acquisition.mode %q", f.ID, f.Codebase.Acquisition.Mode)
	}
	if f.Codebase.Acquisition.Mode == "vendored_repro" && f.Codebase.Acquisition.Path == "" {
		return fmt.Errorf("corpus: fixture %q acquisition.mode=vendored_repro requires acquisition.path", f.ID)
	}
	if f.OwnershipProof.Token == "" {
		return fmt.Errorf("corpus: fixture %q has empty ownership_proof.token", f.ID)
	}
	return nil
}

// expectedLabel derives the convenience label from direction and strength, matching the
// verdict.PoE.Label() logic. "undetermined" is the absence of a determination, not a graded
// refutation or exploit claim, so it is never strength-prefixed — it labels as itself regardless of
// strength (anvil-q12).
func expectedLabel(direction, strength string) string {
	if direction == "undetermined" {
		return "undetermined"
	}
	if strength == "reasoned" {
		return "reasoned_" + direction
	}
	return direction
}

// ToRequest converts a Fixture into a assessment.Request suitable for submitting to the API.
func (f Fixture) ToRequest() assessment.Request {
	return assessment.Request{
		Vulnerability: assessment.VulnRef{
			ID:     f.Advisory.ID,
			Source: f.Advisory.Source,
		},
		Codebase: assessment.CodebaseRef{
			Repo:     f.Codebase.Repo,
			Revision: f.Codebase.Revision,
			Acquisition: assessment.Acquisition{
				Mode: f.Codebase.Acquisition.Mode,
				Path: resolveReproPath(f.Codebase.Acquisition.Path),
			},
		},
		Execution: assessment.ExecutionContext{
			Kind: f.Execution.Kind,
		},
		OwnershipProof: assessment.OwnershipProof{
			Token: f.OwnershipProof.Token,
		},
	}
}

// Load reads and validates every *.json fixture from the embedded FS. All fixtures must
// pass Validate(); a malformed fixture returns an error rather than silently skewing eval.
func Load() ([]Fixture, error) {
	return LoadFS(embedded)
}

// LoadFS reads and validates every *.json file from an arbitrary fs.FS rooted at the
// fixture directory. The embedded FS wraps the testdata/ dir so callers should pass a
// sub-FS rooted there; Load() does this automatically. External callers that supply their
// own fs.FS (e.g. a runtime eval set) should ensure the FS is rooted at the fixture dir.
func LoadFS(fsys fs.FS) ([]Fixture, error) {
	// When called from Load() we receive the full embedded FS and must descend into testdata/.
	// When called by external callers they may pass any fs.FS; we try testdata/ sub first and
	// fall back to the root so both usages work.
	sub, err := fs.Sub(fsys, "testdata")
	if err == nil {
		fsys = sub
	}

	entries, err := fs.Glob(fsys, "*.json")
	if err != nil {
		return nil, fmt.Errorf("corpus: glob testdata/*.json: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("corpus: no fixture files found in testdata/")
	}

	fixtures := make([]Fixture, 0, len(entries))
	for _, name := range entries {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("corpus: read %s: %w", name, err)
		}
		var f Fixture
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("corpus: decode %s: %w", name, err)
		}
		if err := f.Validate(); err != nil {
			return nil, fmt.Errorf("corpus: invalid fixture %s: %w", name, err)
		}
		fixtures = append(fixtures, f)
	}
	return fixtures, nil
}
