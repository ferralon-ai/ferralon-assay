package trigger

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// goFixtureModule writes a minimal Go module to a temp dir whose go.mod requires
// golang.org/x/text at v0.3.6 (the affected version of GO-2021-0113). S2's offline
// go.mod read resolves the version with no plugin, network, or git — the
// vendored_repro path. It returns the dir as a vendored CodebaseRef.
func goFixtureModule(t *testing.T) assessment.CodebaseRef {
	t.Helper()
	dir := t.TempDir()
	goMod := "module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.6\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	return assessment.CodebaseRef{
		Repo:        "example.com/app",
		Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: dir},
	}
}

// TestResolveSBOM_GoFixture proves ResolveSBOM resolves the advisory-keyed package
// (golang.org/x/text at the go.mod version) from the cheap S1+S2 slice — no analysis
// stages, no StateStore.
func TestResolveSBOM_GoFixture(t *testing.T) {
	codebase := goFixtureModule(t)

	sbom, err := ResolveSBOM(context.Background(), ResolveSBOMRequest{
		Codebase:   codebase,
		Advisories: []assessment.VulnRef{{ID: "GO-2021-0113", Source: "osv"}},
	})
	if err != nil {
		t.Fatalf("ResolveSBOM: %v", err)
	}
	if len(sbom.Packages) != 1 {
		t.Fatalf("want 1 package, got %+v", sbom.Packages)
	}
	pkg := sbom.Packages[0]
	if pkg.Ecosystem != "Go" || pkg.Name != "golang.org/x/text" || pkg.Version != "v0.3.6" {
		t.Fatalf("unexpected package %+v", pkg)
	}
}

// TestResolveSBOM_BaselineParity proves the cheap S1+S2 resolver yields the SAME SBOM
// packages as the full S1–S6 baseline over the same codebase + corpus. This is the
// load-bearing parity: the PR-head SBOM is diffed against a baseline produced by
// RunBaseline, so any divergence would make every PR read deps as changed.
func TestResolveSBOM_BaselineParity(t *testing.T) {
	codebase := goFixtureModule(t)
	corpus := []assessment.VulnRef{
		{ID: "GO-2021-0113", Source: "osv"}, // golang.org/x/text — resolvable
		{ID: "GO-2022-0322", Source: "osv"}, // prometheus/client_golang — absent dep
		{ID: "GO-2021-0264", Source: "osv"}, // stdlib — no module package
	}

	resolved, err := ResolveSBOM(context.Background(), ResolveSBOMRequest{
		Codebase:   codebase,
		Advisories: corpus,
	})
	if err != nil {
		t.Fatalf("ResolveSBOM: %v", err)
	}

	store := &memStore{}
	rep, err := RunBaseline(context.Background(), store, BaselineRequest{
		Subject:    Subject{Repo: "example.com/app", ResolvedCommit: "sha"},
		Codebase:   codebase,
		Advisories: corpus,
	})
	if err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}

	if !equalPackages(resolved.Packages, rep.SBOM.Packages) {
		t.Fatalf("SBOM parity broken:\n  ResolveSBOM = %+v\n  RunBaseline = %+v", resolved.Packages, rep.SBOM.Packages)
	}
}

// TestResolveSBOM_EmptyCorpus proves the advisory-keyed contract: an empty corpus
// resolves an empty SBOM (a dependency nobody has an advisory for is invisible).
func TestResolveSBOM_EmptyCorpus(t *testing.T) {
	sbom, err := ResolveSBOM(context.Background(), ResolveSBOMRequest{
		Codebase:   goFixtureModule(t),
		Advisories: nil,
	})
	if err != nil {
		t.Fatalf("ResolveSBOM: %v", err)
	}
	if len(sbom.Packages) != 0 {
		t.Fatalf("empty corpus must yield empty SBOM, got %+v", sbom.Packages)
	}
}

// equalPackages compares two SBOM package slices order-insensitively (both ResolveSBOM
// and RunBaseline sort, but parity is about the SET).
func equalPackages(a, b []report.Package) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[report.Package]int, len(a))
	for _, p := range a {
		set[p]++
	}
	for _, p := range b {
		set[p]--
		if set[p] < 0 {
			return false
		}
	}
	return true
}

// ensure the statestore import stays meaningful even if RunBaseline internals change.
var _ statestore.StateStore = (*memStore)(nil)
