// stages_gotoolchain_guard_test.go
//
// Two properties of the "go-toolchain" arm of resolveDependencyVersion, on the v3
// affected_packages[] select path (the CVE-2023-39325 fixture's shape: an unmatched gomod primary
// followed by a stdlib element).
//
//  1. It never reaches the plugin's ResolveDependencyVersions. That is the PR #219 guard (cycle
//     2026-07-23-affected-block-multipkg): before it, module == "" && coordinate == "stdlib" fell into
//     the plugin branch, and a Go plugin that ERRORS on that non-go.mod coordinate propagated the
//     error out of codebase_inventory.Run and aborted the assessment.
//
//  2. It resolves the SUBJECT'S TOOLCHAIN. This file previously asserted the opposite — that
//     resolved_version stayed EMPTY — and justified it with the same false premise the production
//     comment carried: that "its disqualification runs on the separate U7 go-toolchain comparator path
//     off the AdvisoryTable". There is no such path. The AdvisoryTable supplies the affected RANGE and
//     never a version, so the assertion was defending a dead axis, and the guard test's
//     green was part of what kept it dark through two review passes. The emptiness assertion is
//     retired; what replaces it is that the toolchain fact FLOWS — the element resolves and is
//     selected, so the downstream extractors read the toolchain element's go-toolchain ranges rather
//     than the unmatched module primary's semver ones.
//
// Property 1 is unchanged and still load-bearing: taking the toolchain fact returns before the plugin
// branch, so the abort the guard prevents is still prevented, now for a structural reason.
package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// goToolchainErrorPlugin mimics a Go plugin that ERRORS (rather than returning Found:false) when
// asked to resolve the non-go.mod "stdlib" coordinate — the exact shape the reviewer flagged.
type goToolchainErrorPlugin struct {
	plugin.StubPlugin
}

func (goToolchainErrorPlugin) Language() string { return "go" }

func (goToolchainErrorPlugin) ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	if req.Coordinate == "stdlib" {
		return plugin.DependencyVersionResult{}, errors.New("go plugin: stdlib is not a resolvable module coordinate")
	}
	return plugin.DependencyVersionResult{Found: false}, nil
}

// gotoolchainGuardSource returns a synthetic two-element advisory shaped exactly like the
// CVE-2023-39325 fixture's affected_packages[]: element 0 is a gomod primary the target does NOT
// depend on, element 1 is the go-toolchain/stdlib entry (empty module, coordinate "stdlib").
type gotoolchainGuardSource struct{}

func (gotoolchainGuardSource) Lookup(string) (AdvisoryFacts, bool) {
	facts := AdvisoryFacts{
		Module:         "golang.org/x/net",
		VersionScheme:  "gomod",
		PURL:           "pkg:golang/golang.org/x/net",
		AffectedRanges: []Range{{Fixed: "v0.17.0", FixedVersion: "v0.17.0"}},
		Provenance:     Provenance{Source: "synthetic", TrustTier: TrustFirstParty},
		AffectedPackages: []AffectedPackage{
			{
				Module:         "golang.org/x/net",
				Coordinate:     "golang.org/x/net",
				VersionScheme:  "gomod",
				PURL:           "pkg:golang/golang.org/x/net",
				AffectedRanges: []Range{{Fixed: "v0.17.0", FixedVersion: "v0.17.0"}},
			},
			{
				Coordinate:     "stdlib",
				VersionScheme:  "go-toolchain",
				PURL:           "pkg:golang/stdlib",
				AffectedRanges: []Range{{Fixed: "go1.20.10", FixedVersion: "go1.20.10"}},
			},
		},
	}
	return facts, true
}

// writeEmptyGoMod writes a go.mod that requires NEITHER golang.org/x/net nor anything
// stdlib-shaped, so element 0 (gomod primary) is unmatched and select-by-target must walk into
// element 1 (the go-toolchain/stdlib entry) before falling through to the scalar primary.
func writeEmptyGoMod(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	goMod := "module example.com/target\n\ngo 1.21\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	return dir
}

// runGoToolchainGuard drives advisory_intake + the REAL codebase_inventory over the two-element
// fixture with the given plugin, and returns what the stage wrote. Nothing is seeded.
func runGoToolchainGuard(t *testing.T, p plugin.LanguagePlugin, caseID string) selectInventoryFields {
	t.Helper()
	buildDir := writeEmptyGoMod(t)
	store := artifact.NewMemStore()
	src := gotoolchainGuardSource{}
	c := &assessment.Assessment{ID: caseID, Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-2023-39325", Source: "corpus"},
		Codebase: assessment.CodebaseRef{
			Repo:        "example.com/target",
			Revision:    "v1",
			Acquisition: assessment.Acquisition{Mode: "git"},
		},
	}}
	if err := (advisoryIntake{src: src}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}
	stage := codebaseInventory{
		checkout: dirCheckout{dir: buildDir, lang: "go"},
		plugin:   p,
		src:      src,
	}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("codebase_inventory.Run must NOT abort on a go-toolchain element even when the plugin errors on \"stdlib\", got: %v", err)
	}
	arts, err := store.Query(c.ID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		t.Fatalf("no inventory artifact: %v", err)
	}
	var inv selectInventoryFields
	if jerr := json.Unmarshal(arts[0].Payload, &inv); jerr != nil {
		t.Fatalf("decode inventory: %v", jerr)
	}
	return inv
}

// TestCodebaseInventory_GoToolchainElement_NeverAbortsOnPluginError is property 1: even when the
// plugin ERRORS on the "stdlib" coordinate, codebase_inventory.Run must not abort. The go-toolchain
// arm returns before the plugin branch, so the coordinate never reaches the resolver.
//
// This plugin's BuildManifest is StubPlugin's (Unsupported), so no directive is read and the toolchain
// fact resolves nothing — which is why resolved_version is empty HERE. That is a consequence of the
// stub, not the guard: the fact-flows assertion lives in the next test, with a real manifest read.
func TestCodebaseInventory_GoToolchainElement_NeverAbortsOnPluginError(t *testing.T) {
	inv := runGoToolchainGuard(t, goToolchainErrorPlugin{}, "case-gotoolchain-guard")
	if inv.ResolvedVersion != "" {
		t.Errorf("resolved_version = %q, want empty: this plugin reads no manifest, so no toolchain fact resolves", inv.ResolvedVersion)
	}
}

// TestCodebaseInventory_GoToolchainElement_ResolvesTheSubjectToolchain is property 2, and it is what
// replaced the retired emptiness assertion. With a REAL manifest read the go-toolchain element
// resolves the subject's toolchain floor from `go 1.21` and is SELECTED — which is the load-bearing
// half: selection is the join key extractAffectedRange uses, so the axis reasons over the toolchain
// element's go1.20.10/go1.21.3 ranges under the U7 comparator, not over the unmatched module
// primary's v0.17.0 semver bound.
func TestCodebaseInventory_GoToolchainElement_ResolvesTheSubjectToolchain(t *testing.T) {
	inv := runGoToolchainGuard(t, goManifestPlugin{}, "case-gotoolchain-flows")
	if inv.ResolvedVersion != "go1.21.0" {
		t.Errorf("resolved_version = %q, want go1.21.0 — the `go 1.21` floor must flow into the version axis", inv.ResolvedVersion)
	}
	if inv.SelectedModule != "" || inv.SelectedCoordinate != "stdlib" {
		t.Errorf("selection = (%q,%q), want (\"\",\"stdlib\") — the toolchain element must be SELECTED so the axis reads ITS ranges, not the unmatched primary's",
			inv.SelectedModule, inv.SelectedCoordinate)
	}
}
