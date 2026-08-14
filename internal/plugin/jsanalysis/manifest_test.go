package jsanalysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const pkgFixtureDir = "testdata/pkgfixture"

// TestBuildManifest_CleanPackageIsComplete asserts a clean single-package
// package.json (with a lockfile + build script) yields name, Node engine, the
// reproducible install command plus the build step, declared Complete.
func TestBuildManifest_CleanPackageIsComplete(t *testing.T) {
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: pkgFixtureDir})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if res.ProjectRoot != "tegron-fixture-pkg" {
		t.Errorf("ProjectRoot = %q, want tegron-fixture-pkg", res.ProjectRoot)
	}
	if res.Runtime.Name != "node" || res.Runtime.Version != ">=18" {
		t.Errorf("Runtime = %+v, want {Name:node Version:>=18}", res.Runtime)
	}
	if res.Resolver.Command != "npm ci && npm run build" {
		t.Errorf("Resolver.Command = %q, want 'npm ci && npm run build'", res.Resolver.Command)
	}
	if !res.Partiality.Complete {
		t.Errorf("a clean single-package package.json must be Complete; got %+v", res.Partiality)
	}
}

// TestBuildManifest_NoLockfileUsesInstall asserts that without a lockfile the
// install command degrades to `npm install` (not `npm ci`), still Complete.
func TestBuildManifest_NoLockfileUsesInstall(t *testing.T) {
	dir := t.TempDir()
	writePkg(t, dir, `{"name":"solo","engines":{"node":"20"}}`)
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if res.Resolver.Command != "npm install" {
		t.Errorf("Resolver.Command = %q, want 'npm install'", res.Resolver.Command)
	}
	if !res.Partiality.Complete {
		t.Errorf("a clean package with no build script must still be Complete; got %+v", res.Partiality)
	}
}

// TestBuildManifest_NoPackageJSONIsPartial asserts a dir with no package.json
// declares Partial (not a package) — never fabricates a build command.
func TestBuildManifest_NoPackageJSONIsPartial(t *testing.T) {
	dir := t.TempDir()
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("BuildManifest: no package.json is declared partial, not a hard error: %v", err)
	}
	if res.Partiality.Complete {
		t.Error("a dir with no package.json must declare Partial")
	}
	if res.Resolver.Command != "" {
		t.Errorf("must not fabricate a build command without a package.json; got %q", res.Resolver.Command)
	}
	if !hasReason(res.Partiality, plugin.PartialReasonToolFailure) {
		t.Errorf("no package.json must carry tool_failure; got %+v", res.Partiality)
	}
}

// TestBuildManifest_WorkspacesNoLongerDeclines asserts the PLAN-160 C4 change: a
// named workspaces root no longer degrades to Partial merely for being a monorepo.
// It resolves to a Complete, buildable manifest (`npm ci` at the root installs the
// workspace); the whole-graph resolver speaks for per-member subgraphs separately.
func TestBuildManifest_WorkspacesNoLongerDeclines(t *testing.T) {
	dir := t.TempDir()
	writePkg(t, dir, `{"name":"monorepo-root","workspaces":["packages/*"]}`)
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if !res.Partiality.Complete {
		t.Errorf("a named workspaces root must NOT decline post-C4; got %+v", res.Partiality)
	}
	if res.ProjectRoot != "monorepo-root" {
		t.Errorf("ProjectRoot = %q, want monorepo-root", res.ProjectRoot)
	}
	if res.Resolver.Command != "npm install" {
		t.Errorf("Resolver.Command = %q, want 'npm install' (no lockfile in temp dir)", res.Resolver.Command)
	}
}

// TestBuildManifest_MissingNameIsPartial asserts a package.json without a name
// (unidentifiable) degrades to Partial.
func TestBuildManifest_MissingNameIsPartial(t *testing.T) {
	dir := t.TempDir()
	writePkg(t, dir, `{"version":"1.0.0","engines":{"node":"18"}}`)
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if res.Partiality.Complete {
		t.Error("a package.json with no name must declare Partial")
	}
	if res.Resolver.Command != "" {
		t.Errorf("must not fabricate a build command without a name; got %q", res.Resolver.Command)
	}
}

// TestBuildManifest_MalformedJSONIsPartial asserts malformed JSON surfaces as
// Partial(tool_failure), never a silent empty result and never a hard error.
func TestBuildManifest_MalformedJSONIsPartial(t *testing.T) {
	dir := t.TempDir()
	writePkg(t, dir, `{"name": "broken", `)
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("BuildManifest: malformed json is declared partial, not a hard error: %v", err)
	}
	if res.Partiality.Complete {
		t.Error("malformed package.json must declare Partial")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonToolFailure) {
		t.Errorf("malformed package.json must carry tool_failure; got %+v", res.Partiality)
	}
}

// TestBuildManifest_MissingBuildDirIsHardError asserts a nonexistent build dir is a
// hard error (inv.4), not a Partial result.
func TestBuildManifest_MissingBuildDirIsHardError(t *testing.T) {
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: filepath.Join(t.TempDir(), "does-not-exist")})
	if err == nil {
		t.Error("a missing build dir must be a hard error (inv.4)")
	}
	if res.Partiality.Complete {
		t.Error("a missing build dir must not return a Complete result")
	}
}

// TestBuildManifest_C1_NeutralFieldsPopulated is C1's population test: the §4.6
// ecosystem-neutral field groups a JS package.json can actually supply are non-zero.
// Runtime (engines.node), Target (os/cpu), ProjectRoot (name) and Resolver (npm +
// command) are asserted. Configuration is deliberately NOT asserted: package.json has
// no build-profile field and reading the analyzer's own NODE_ENV would fabricate the
// customer's build configuration with wrong provenance — asserting an unpopulated field
// is vacuous (invariant-test-asserting-an-unpopulated-field-is-vacuous).
func TestBuildManifest_C1_NeutralFieldsPopulated(t *testing.T) {
	dir := t.TempDir()
	writePkg(t, dir, `{"name":"targeted","engines":{"node":">=18"},"os":["linux","darwin"],"cpu":["x64","arm64"],"scripts":{"build":"tsc -p ."}}`)
	// A lockfile so the resolver command is the reproducible `npm ci`.
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if res.Runtime.Name != "node" || res.Runtime.Version != ">=18" {
		t.Errorf("runtime group unpopulated: Runtime = %+v", res.Runtime)
	}
	// Target is sorted+comma-joined per side for determinism: os -> "darwin,linux",
	// cpu -> "arm64,x64".
	if res.Target != "darwin,linux/arm64,x64" {
		t.Errorf("target group: Target = %q, want %q", res.Target, "darwin,linux/arm64,x64")
	}
	if res.ProjectRoot != "targeted" {
		t.Errorf("project-root group: ProjectRoot = %q, want targeted", res.ProjectRoot)
	}
	if res.Resolver.Name != "npm" || res.Resolver.Command != "npm ci && npm run build" {
		t.Errorf("resolver group: Resolver = %+v", res.Resolver)
	}
	if !res.Partiality.Complete {
		t.Errorf("a fully-populated package must be Complete; got %+v", res.Partiality)
	}
}

// TestBuildManifest_TargetDeduplicatesRepeatedPlatform asserts a package.json that
// declares a platform value more than once yields a canonical Target with no repeats —
// Target is a deterministic build-context value, so duplicates must collapse.
func TestBuildManifest_TargetDeduplicatesRepeatedPlatform(t *testing.T) {
	dir := t.TempDir()
	writePkg(t, dir, `{"name":"dup","os":["linux","linux","darwin"],"cpu":["x64","x64"]}`)
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if res.Target != "darwin,linux/x64" {
		t.Errorf("repeated platform values must collapse; Target = %q, want %q", res.Target, "darwin,linux/x64")
	}
}

// TestBuildManifest_C1_TargetAbsentWhenNoPlatform asserts Target stays zero when the
// package declares no os/cpu — never inferred from the analyzer's host.
func TestBuildManifest_C1_TargetAbsentWhenNoPlatform(t *testing.T) {
	dir := t.TempDir()
	writePkg(t, dir, `{"name":"portable","engines":{"node":"20"}}`)
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if res.Target != "" {
		t.Errorf("Target must stay zero with no os/cpu; got %q", res.Target)
	}
}

// TestBuildManifest_C2_MultiMemberWorkspaceIsComplete is C2's manifest-level assertion:
// a multi-member workspaces root (packages/a, packages/b on disk) yields a Complete
// manifest with a populated ProjectRoot, not a decline. Per-member subgraphs are served
// by ResolveInventory's DependencyMembership (A2), not by emitting N manifests.
func TestBuildManifest_C2_MultiMemberWorkspaceIsComplete(t *testing.T) {
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: "testdata/manifest-workspace"})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if !res.Partiality.Complete {
		t.Errorf("a multi-member workspaces root must be Complete, not declined; got %+v", res.Partiality)
	}
	if res.ProjectRoot != "ws-root" {
		t.Errorf("ProjectRoot = %q, want ws-root", res.ProjectRoot)
	}
	if res.Resolver.Command != "npm ci" {
		t.Errorf("Resolver.Command = %q, want 'npm ci' (lockfile present, no root build script)", res.Resolver.Command)
	}
}

func writePkg(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
