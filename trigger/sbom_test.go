package trigger

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// goFixtureModule writes a minimal Go module to a temp dir whose go.mod requires
// golang.org/x/text at v0.3.6. ResolveVendored detects the "go" language from it (the
// vendored_repro path — no network, no git). It returns the dir as a vendored CodebaseRef.
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

// TestResolveSBOM_UnsupportedInventoryIsEmpty proves the HONEST Phase-1 state (C3): with no language
// plugin injected, the inventory is not established, so the SBOM is empty. This is the inventory-keyed
// contract, not the old advisory-keyed one — the emptiness comes from an unresolved inventory, not
// from a corpus that names no dependency. (The scan-level partiality note declaring the gap is
// asserted by the baseline producer's tests; ResolveSBOM returns only the package set for the diff.)
func TestResolveSBOM_UnsupportedInventoryIsEmpty(t *testing.T) {
	sbom, _, err := ResolveSBOM(context.Background(), ResolveSBOMRequest{
		Codebase: goFixtureModule(t),
	})
	if err != nil {
		t.Fatalf("ResolveSBOM: %v", err)
	}
	if len(sbom.Packages) != 0 {
		t.Fatalf("no inventory resolver ⇒ empty SBOM, got %+v", sbom.Packages)
	}
}

// TestResolveSBOM_BaselineParity proves the whole-graph resolver yields the SAME SBOM packages as
// the full S1–S6 baseline over the same codebase + inventory. This is the load-bearing parity: the
// PR-head SBOM is diffed against a baseline produced by RunBaseline, so any divergence would make
// every PR read deps as changed. Both now key on the SAME inventory (via WithPlugin), so parity is a
// property of the shared projection, not a coincidence of two advisory loops.
func TestResolveSBOM_BaselineParity(t *testing.T) {
	codebase := goFixtureModule(t)
	inv := twoPackageInventory()
	opts := []pipeline.AssessOption{pipeline.WithPlugin(fakeInventoryPlugin{lang: "go", inv: inv})}
	corpus := []assessment.VulnRef{{ID: "GO-2021-0113", Source: "osv"}}

	resolved, _, err := ResolveSBOM(context.Background(), ResolveSBOMRequest{
		Codebase:      codebase,
		AssessOptions: opts,
	})
	if err != nil {
		t.Fatalf("ResolveSBOM: %v", err)
	}

	store := &memStore{}
	rep, err := RunBaseline(context.Background(), store, BaselineRequest{
		Subject:       Subject{Repo: "example.com/app", ResolvedCommit: "sha"},
		Codebase:      codebase,
		Advisories:    corpus,
		AssessOptions: opts,
	})
	if err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}

	if !equalPackages(resolved.Packages, rep.SBOM.Packages) {
		t.Fatalf("SBOM parity broken:\n  ResolveSBOM = %+v\n  RunBaseline = %+v", resolved.Packages, rep.SBOM.Packages)
	}
	if len(resolved.Packages) == 0 {
		t.Fatal("parity over an empty SBOM proves nothing; the fixture inventory must be non-empty")
	}
}

// TestResolveSBOM_InventoryKeyedNotCorpusKeyed proves the core §4.1 property: the SBOM is keyed on
// the resolved inventory, NOT the advisory corpus. With a fixture inventory and ZERO advisories the
// resolved packages are still present — a dependency reaches the SBOM whether or not any advisory
// names it. (On main this SBOM would be empty: the old producer keyed on the corpus.)
func TestResolveSBOM_InventoryKeyedNotCorpusKeyed(t *testing.T) {
	sbom, _, err := ResolveSBOM(context.Background(), ResolveSBOMRequest{
		Codebase:      goFixtureModule(t),
		AssessOptions: []pipeline.AssessOption{pipeline.WithPlugin(fakeInventoryPlugin{lang: "go", inv: twoPackageInventory()})},
	})
	if err != nil {
		t.Fatalf("ResolveSBOM: %v", err)
	}
	if len(sbom.Packages) != 2 {
		t.Fatalf("inventory-keyed SBOM must carry the resolved deps regardless of corpus, got %+v", sbom.Packages)
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
