package goanalysis

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	if res.ProjectRoot != "tegron.test/fixturemod" {
		t.Errorf("ProjectRoot = %q, want tegron.test/fixturemod", res.ProjectRoot)
	}
	if runtimeOf(res).Version != "1.26" {
		t.Errorf("Runtime.Version = %q, want 1.26", runtimeOf(res).Version)
	}
	if runtimeOf(res).Name != "go" {
		t.Errorf("Runtime.Name = %q, want go", runtimeOf(res).Name)
	}
	if resolverOf(res).Command != "go build ./..." {
		t.Errorf("Resolver.Command = %q, want 'go build ./...'", resolverOf(res).Command)
	}
	if resolverOf(res).Name != "go" {
		t.Errorf("Resolver.Name = %q, want go", resolverOf(res).Name)
	}
	if runtimeOf(res).Toolchain != "" {
		t.Errorf("Runtime.Toolchain = %q, want empty — the fixture declares no toolchain directive", runtimeOf(res).Toolchain)
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
	if runtimeOf(res).Version != "1.21" {
		t.Errorf("Runtime.Version = %q, want 1.21 (the `go` directive, unchanged by the toolchain line)", runtimeOf(res).Version)
	}
	if runtimeOf(res).Toolchain != "go1.21.3" {
		t.Errorf("Runtime.Toolchain = %q, want go1.21.3", runtimeOf(res).Toolchain)
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
	if resolverOf(res).Command != "" {
		t.Errorf("must not fabricate a build command without a go.mod; got %q", resolverOf(res).Command)
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
	if res.ProjectRoot != "example.com/withreplace" {
		t.Errorf("ProjectRoot = %q, want example.com/withreplace", res.ProjectRoot)
	}
}

// runtimeOf and resolverOf return the manifest's sole runtime/resolver, or the zero value when
// there is not exactly one.
func runtimeOf(res plugin.BuildManifestResult) plugin.RuntimeSpec {
	rt, _ := res.PrimaryRuntime()
	return rt
}

func resolverOf(res plugin.BuildManifestResult) plugin.ResolverSpec {
	rs, _ := res.PrimaryResolver()
	return rs
}

// TestBuildManifest_ResolvedBuildToolchain covers when the manifest carries the toolchain the build's
// environment resolves: only when the go.mod directives do not bound it from below — no `toolchain`
// line and a `go` line below 1.21 or absent — and then exactly what the load records as the build's
// (buildToolchain), or empty when the go command cannot establish it.
func TestBuildManifest_ResolvedBuildToolchain(t *testing.T) {
	var noGoWork []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GOWORK=") && !strings.HasPrefix(kv, "GOTOOLCHAIN=") {
			noGoWork = append(noGoWork, kv)
		}
	}
	// GOTOOLCHAIN=local keeps the probe on the installed go command: no download, a known answer.
	localEnv := append(slices.Clip(noGoWork), "GOTOOLCHAIN=local")
	// A pinned release the go command cannot fetch makes `go env GOVERSION` fail, offline.
	unfetchableEnv := append(slices.Clip(noGoWork), "GOTOOLCHAIN=go1.999.0", "GOPROXY=off")

	tests := []struct {
		name         string
		gomod        string
		env          []string
		wantResolved bool
	}{
		{"go 1.17 alone is advisory: probed", "module example.com/m\n\ngo 1.17\n", localEnv, true},
		{"go 1.20 alone is advisory: probed", "module example.com/m\n\ngo 1.20\n", localEnv, true},
		{"no go line is advisory: probed", "module example.com/m\n", localEnv, true},
		{"go 1.21 two-part is advisory: probed", "module example.com/m\n\ngo 1.21\n", localEnv, true},
		{"go 1.21.0 binds: not probed", "module example.com/m\n\ngo 1.21.0\n", localEnv, false},
		{"go 1.22.3 binds: not probed", "module example.com/m\n\ngo 1.22.3\n", localEnv, false},
		{"a toolchain line binds a pre-1.21 go line: not probed", "module example.com/m\n\ngo 1.17\n\ntoolchain go1.21.3\n", localEnv, false},
		{"the build's toolchain cannot be established: empty", "module example.com/m\n\ngo 1.17\n", unfetchableEnv, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(tc.gomod), 0o644); err != nil {
				t.Fatal(err)
			}
			ctx := WithBuildEnviron(context.Background(), tc.env)
			res, err := BuildManifest(ctx, plugin.BuildManifestRequest{BuildDir: dir})
			if err != nil {
				t.Fatalf("BuildManifest: %v", err)
			}
			got := runtimeOf(res).Resolved
			if !tc.wantResolved {
				if got != "" {
					t.Errorf("Runtime.Resolved = %q, want empty", got)
				}
				return
			}
			want := buildToolchain(ctx, dir)
			if want == "" {
				t.Fatal("the installed go command established no toolchain; the test needs one")
			}
			if got != want {
				t.Errorf("Runtime.Resolved = %q, want %q (the build's toolchain as the load establishes it)", got, want)
			}
		})
	}
}
