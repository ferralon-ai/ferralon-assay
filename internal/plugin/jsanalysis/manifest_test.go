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
	if res.Module != "tegron-fixture-pkg" {
		t.Errorf("Module = %q, want tegron-fixture-pkg", res.Module)
	}
	if res.GoVersion != ">=18" {
		t.Errorf("GoVersion (node engine) = %q, want >=18", res.GoVersion)
	}
	if res.BuildCommand != "npm ci && npm run build" {
		t.Errorf("BuildCommand = %q, want 'npm ci && npm run build'", res.BuildCommand)
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
	if res.BuildCommand != "npm install" {
		t.Errorf("BuildCommand = %q, want 'npm install'", res.BuildCommand)
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
	if res.BuildCommand != "" {
		t.Errorf("must not fabricate a build command without a package.json; got %q", res.BuildCommand)
	}
	if !hasReason(res.Partiality, plugin.PartialReasonToolFailure) {
		t.Errorf("no package.json must carry tool_failure; got %+v", res.Partiality)
	}
}

// TestBuildManifest_WorkspacesIsPartial asserts a monorepo (workspaces) degrades to
// Partial while still reporting the module name, with no fabricated command.
func TestBuildManifest_WorkspacesIsPartial(t *testing.T) {
	dir := t.TempDir()
	writePkg(t, dir, `{"name":"monorepo-root","workspaces":["packages/*"]}`)
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if res.Partiality.Complete {
		t.Error("a workspaces/monorepo package must declare Partial")
	}
	if res.Module != "monorepo-root" {
		t.Errorf("Module = %q, want monorepo-root", res.Module)
	}
	if res.BuildCommand != "" {
		t.Errorf("must not fabricate a build command for a monorepo; got %q", res.BuildCommand)
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
	if res.BuildCommand != "" {
		t.Errorf("must not fabricate a build command without a name; got %q", res.BuildCommand)
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

func writePkg(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
