package goanalysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestBuildManifest_SingleModuleIsComplete asserts a clean single-module go.mod
// yields module path + go version + build command, declared Complete.
func TestBuildManifest_SingleModuleIsComplete(t *testing.T) {
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: fixtureDir})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if res.Module != "tegron.test/fixturemod" {
		t.Errorf("Module = %q, want tegron.test/fixturemod", res.Module)
	}
	if res.GoVersion != "1.26" {
		t.Errorf("GoVersion = %q, want 1.26", res.GoVersion)
	}
	if res.BuildCommand != "go build ./..." {
		t.Errorf("BuildCommand = %q, want 'go build ./...'", res.BuildCommand)
	}
	if res.ToolchainVersion != "" {
		t.Errorf("ToolchainVersion = %q, want empty — the fixture declares no toolchain directive", res.ToolchainVersion)
	}
	if !res.Partiality.Complete {
		t.Errorf("a clean single-module go.mod must be Complete; got %+v", res.Partiality)
	}
}

// TestBuildManifest_ToolchainDirective asserts the `toolchain` directive is reported verbatim and
// SEPARATELY from the `go` directive. The two are distinct floors on the subject's toolchain (a
// minimum toolchain vs. a minimum language version); collapsing them would lose the stronger one.
func TestBuildManifest_ToolchainDirective(t *testing.T) {
	dir := t.TempDir()
	gomod := "module example.com/withtoolchain\n\ngo 1.21\n\ntoolchain go1.21.3\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if res.GoVersion != "1.21" {
		t.Errorf("GoVersion = %q, want 1.21 (the `go` directive, unchanged by the toolchain line)", res.GoVersion)
	}
	if res.ToolchainVersion != "go1.21.3" {
		t.Errorf("ToolchainVersion = %q, want go1.21.3", res.ToolchainVersion)
	}
	if !res.Partiality.Complete {
		t.Errorf("a toolchain directive does not complicate the build layout; want Complete, got %+v", res.Partiality)
	}
}

// TestBuildManifest_NoGoModIsPartial asserts a dir with no go.mod declares Partial
// (not a module) — never fabricates a build command.
func TestBuildManifest_NoGoModIsPartial(t *testing.T) {
	dir := t.TempDir()
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("BuildManifest: no go.mod is declared partial, not a hard error: %v", err)
	}
	if res.Partiality.Complete {
		t.Error("a dir with no go.mod must declare Partial")
	}
	if res.BuildCommand != "" {
		t.Errorf("must not fabricate a build command without a go.mod; got %q", res.BuildCommand)
	}
}

// TestBuildManifest_ReplaceDirectiveIsPartial asserts a replace directive degrades
// to Partial (the build layout is complicated) while still reporting module/version.
func TestBuildManifest_ReplaceDirectiveIsPartial(t *testing.T) {
	dir := t.TempDir()
	gomod := "module example.com/withreplace\n\ngo 1.26\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => ./local/dep\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if res.Partiality.Complete {
		t.Error("a replace directive must declare Partial")
	}
	if res.Module != "example.com/withreplace" {
		t.Errorf("Module = %q, want example.com/withreplace", res.Module)
	}
}
