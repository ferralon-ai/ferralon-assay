// internal/pipeline/checkout_seam_test.go
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

func TestInventoryRecordsResolvedBuildDir(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-1", Request: assessment.Request{
		Codebase: assessment.CodebaseRef{Repo: "example.com/repo", Revision: "v1"},
	}}
	fc := checkout.FakeCheckout{
		FixtureRoot: "../checkout/testdata",
		Map:         map[string]string{"example.com/repo@v1": "gomod-fixture"},
	}
	stage := codebaseInventory{checkout: fc}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("run: %v", err)
	}
	arts, _ := store.Query(c.ID, artifact.TypeInventory)
	if len(arts) == 0 {
		t.Fatal("no inventory artifact")
	}
	var inv struct {
		Repo     string `json:"repo"`
		Revision string `json:"revision"`
		BuildDir string `json:"build_dir"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		t.Fatal(err)
	}
	if inv.BuildDir == "" {
		t.Fatal("inventory must record the resolved BuildDir (closes OQ-2)")
	}
}

// gitTreeCheckout is a test Checkout that returns a real git working tree as the BuildDir so the
// inventory stage's rev-parse pins a concrete SHA (the FakeCheckout fixture is not a git tree).
type gitTreeCheckout struct{ dir string }

func (g gitTreeCheckout) Fetch(context.Context, string, string) (checkout.WorkspacePlan, error) {
	return checkout.WorkspacePlan{Root: g.dir, Projects: []checkout.Project{{Root: g.dir, Language: checkout.LangGo}}}, nil
}

// After a branch-ref assessment whose checkout is a real git tree, the inventory stage must pin the
// concrete commit SHA into Subject.ResolvedCommit (the T1 anchor that firepersist projects into
// proof_verdicts.subject_repo_ref). Regression for the cycle-07 P0-a gap.
func TestInventoryPinsResolvedCommitSHA(t *testing.T) {
	if !checkout.GitAvailable() {
		t.Skip("git CLI not available")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n\ngo 1.23\n"), 0o644); err != nil {
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
	c := &assessment.Assessment{ID: "case-sha", Request: assessment.Request{
		Codebase: assessment.CodebaseRef{Repo: "example.com/repo", Revision: "some-branch"},
	}}
	stage := codebaseInventory{checkout: gitTreeCheckout{dir: dir}}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(c.Subject.ResolvedCommit) {
		t.Fatalf("Subject.ResolvedCommit must be a 40-hex SHA after a branch-ref assessment, got %q", c.Subject.ResolvedCommit)
	}
}

// An explicit ResolvedCommit on the request (the OSS --commit path) must take precedence over the
// rev-parse: the inventory stage never overwrites a caller-pinned SHA.
func TestInventoryDoesNotOverwriteExplicitCommit(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-explicit", Request: assessment.Request{
		Codebase: assessment.CodebaseRef{Repo: "example.com/repo", Revision: "v1"},
	}}
	c.Subject.ResolvedCommit = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	fc := checkout.FakeCheckout{
		FixtureRoot: "../checkout/testdata",
		Map:         map[string]string{"example.com/repo@v1": "gomod-fixture"},
	}
	stage := codebaseInventory{checkout: fc}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("run: %v", err)
	}
	if c.Subject.ResolvedCommit != "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" {
		t.Fatalf("explicit ResolvedCommit must be preserved, got %q", c.Subject.ResolvedCommit)
	}
}

func TestInventoryDefaultsToFakeCheckoutWhenAbsent(t *testing.T) {
	// When no Checkout is injected, the stage must still run hermetically (nil-safe default).
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-2"}
	stage := codebaseInventory{} // checkout == nil → default behavior, no error
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("nil-checkout default must not error: %v", err)
	}
	arts, _ := store.Query(c.ID, artifact.TypeInventory)
	if len(arts) == 0 {
		t.Fatal("inventory artifact must still be written on the default path")
	}
}
