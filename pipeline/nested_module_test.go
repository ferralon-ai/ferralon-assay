// nested_module_test.go
//
// Regression: a Go module whose go.mod is not at the repository root (for example
// target/go.mod) must be recognized AND the whole rest of codebase_inventory — BuildManifest,
// the persisted BuildDir every later stage reads back, and dependency-version resolution off
// go.mod — must operate on the discovered MODULE root, not the checkout root. ResolveHead's commit
// pin is the one exception: it must keep using the CHECKOUT root, where .git actually lives.
package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
)

// nestedModuleAdvisorySource seeds one AdvisoryFacts fact so resolveDependencyVersion's Go-module
// branch (moduleVersionFromGoMod) actually runs, proving it reads the discovered module root's
// go.mod rather than the checkout root's (which has none).
type nestedModuleAdvisorySource struct{ module string }

func (s nestedModuleAdvisorySource) Lookup(string) (AdvisoryFacts, bool) {
	return AdvisoryFacts{Module: s.module}, true
}

// writeNestedGoModuleGitTree materializes a git working tree whose go.mod lives under target/
// (a common monorepo shape) rather than at the repo root, and returns the repo root.
func writeNestedGoModuleGitTree(t *testing.T, goMod string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "target"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "target", "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "target", "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "t@example.com"},
		{"config", "user.name", "t"},
		{"add", "."},
		{"commit", "-q", "-m", "seed"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

// TestInventoryThreadsNestedGoModuleRoot is the regression test that fails if any of BuildManifest,
// moduleVersionFromGoMod, or the persisted inv.BuildDir read the checkout root (dir) instead of the
// discovered module root (dir/target).
func TestInventoryThreadsNestedGoModuleRoot(t *testing.T) {
	if !checkout.GitAvailable() {
		t.Skip("git CLI not available")
	}
	dir := writeNestedGoModuleGitTree(t, "module example.com/app/target\n\ngo 1.22\n\nrequire golang.org/x/text v0.14.0\n")

	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-nested-module", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "GO-2021-0113", Source: "corpus"},
		Codebase:      assessment.CodebaseRef{Repo: "example.com/app", Revision: "main"},
	}}
	stage := codebaseInventory{
		checkout: gitTreeCheckout{dir: dir},
		plugin:   goManifestPlugin{},
		src:      nestedModuleAdvisorySource{module: "golang.org/x/text"},
	}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("run: %v", err)
	}

	// ResolveHead must still resolve against the CHECKOUT root's .git (the repo root), not the
	// module root — a nested module has no .git of its own, so reading the wrong dir here would
	// silently drop the T1 reproducibility anchor instead of failing loudly.
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(c.Subject.ResolvedCommit) {
		t.Fatalf("Subject.ResolvedCommit must be pinned off the git checkout root, got %q", c.Subject.ResolvedCommit)
	}

	arts, _ := store.Query(c.ID, artifact.TypeInventory)
	if len(arts) == 0 {
		t.Fatal("no inventory artifact")
	}
	var inv struct {
		BuildDir        string `json:"build_dir"`
		Module          string `json:"module"`
		GoVersion       string `json:"go_version"`
		ResolvedVersion string `json:"resolved_version"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		t.Fatal(err)
	}

	wantRoot := filepath.Join(dir, "target")
	if inv.BuildDir != wantRoot {
		t.Fatalf("inv.BuildDir = %q, want the discovered module root %q (reading the checkout root would record %q)",
			inv.BuildDir, wantRoot, dir)
	}
	// BuildManifest only finds these by reading buildDir/go.mod; at the checkout root that file
	// does not exist and both fields would come back empty.
	if inv.Module != "example.com/app/target" {
		t.Fatalf("inv.Module = %q, want the module declared in target/go.mod — BuildManifest must have read the module root", inv.Module)
	}
	if inv.GoVersion != "1.22" {
		t.Fatalf("inv.GoVersion = %q, want 1.22 from target/go.mod", inv.GoVersion)
	}
	// moduleVersionFromGoMod only finds this by reading buildDir/go.mod; at the checkout root it
	// would come back manifestRead=false and resolvedVersion would stay "".
	if inv.ResolvedVersion != "v0.14.0" {
		t.Fatalf("inv.ResolvedVersion = %q, want v0.14.0 — moduleVersionFromGoMod must have read the module root's go.mod", inv.ResolvedVersion)
	}
}

// TestInventoryGoModuleAtRootUnchanged is the byte-identical-when-unaffected control: a Go module
// already at the checkout root (today's overwhelmingly common case) must see NO behavior change —
// FindGoModuleRoot returns the root itself, so buildDir reassignment is a no-op.
func TestInventoryGoModuleAtRootUnchanged(t *testing.T) {
	if !checkout.GitAvailable() {
		t.Skip("git CLI not available")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/root\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "t@example.com"},
		{"config", "user.name", "t"},
		{"add", "."},
		{"commit", "-q", "-m", "seed"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-root-module", Request: assessment.Request{
		Codebase: assessment.CodebaseRef{Repo: "example.com/root", Revision: "main"},
	}}
	stage := codebaseInventory{checkout: gitTreeCheckout{dir: dir}, plugin: goManifestPlugin{}}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("run: %v", err)
	}
	arts, _ := store.Query(c.ID, artifact.TypeInventory)
	var inv struct {
		BuildDir string `json:"build_dir"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		t.Fatal(err)
	}
	if inv.BuildDir != dir {
		t.Fatalf("inv.BuildDir = %q, want the checkout root %q unchanged", inv.BuildDir, dir)
	}
}
