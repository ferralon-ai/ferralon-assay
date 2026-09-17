package main

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/checkout"
)

// The fixture mirrors the real case that motivated analyze.ref: an upstream whose default branch
// (main) is docs-only and whose source lives on another branch (baseline). The scan target is a
// SHALLOW clone of main — what actions/checkout puts in the runner's workspace.

func gitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "init.defaultBranch=main", "-c", "protocol.file.allow=always"}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeT(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

type refFixture struct {
	upstream    string
	clone       string // the "workspace": a shallow clone of main
	mainSHA     string
	baselineSHA string
}

// newRefFixture builds the upstream. mainFiles are committed on main (the default branch), and
// baseline branches off it carrying a Go module. mainHasSource adds a go.mod to main as well, for
// the default-preserving cases where the checked-out tree is itself scannable.
func newRefFixture(t *testing.T, mainFiles map[string]string, mainHasSource bool) refFixture {
	t.Helper()
	if !checkout.GitAvailable() {
		t.Skip("git CLI not available")
	}
	up := t.TempDir()
	gitT(t, up, "init", "-q")
	// GitHub serves any reachable SHA to a fetch; a local upstream must be told to.
	gitT(t, up, "config", "uploadpack.allowAnySHA1InWant", "true")
	writeT(t, filepath.Join(up, "README.md"), "# docs only on main\n")
	for p, body := range mainFiles {
		writeT(t, filepath.Join(up, p), body)
	}
	if mainHasSource {
		writeT(t, filepath.Join(up, "go.mod"), "module example.com/onmain\n\ngo 1.26\n")
	}
	gitT(t, up, "add", "-A")
	gitT(t, up, "commit", "-q", "-m", "main")
	mainSHA := gitT(t, up, "rev-parse", "HEAD")

	gitT(t, up, "checkout", "-q", "-b", "baseline")
	writeT(t, filepath.Join(up, "go.mod"), "module example.com/onbaseline\n\ngo 1.26\n")
	writeT(t, filepath.Join(up, "main.go"), "package main\n\nfunc main() {}\n")
	gitT(t, up, "add", "-A")
	gitT(t, up, "commit", "-q", "-m", "baseline source")
	baselineSHA := gitT(t, up, "rev-parse", "HEAD")
	gitT(t, up, "tag", "v1.0.0")
	gitT(t, up, "checkout", "-q", "main")

	clone := filepath.Join(t.TempDir(), "workspace")
	gitT(t, filepath.Dir(clone), "clone", "-q", "--depth", "1", "--branch", "main", "file://"+up, clone)
	return refFixture{upstream: up, clone: clone, mainSHA: mainSHA, baselineSHA: baselineSHA}
}

func worktreeCount(t *testing.T, repo string) int {
	t.Helper()
	return strings.Count(gitT(t, repo, "worktree", "list", "--porcelain"), "worktree ")
}

func configBody(ref string) map[string]string {
	return map[string]string{".github/ferralon.yml": "version: 1\nanalyze:\n  ref: " + ref + "\n"}
}

// AC2: analyze.ref makes the scan analyze THAT ref's tree, and the Report's subject provenance
// changes WITH it to the requested ref and the commit the analyzed tree really has. The checked-out
// workspace is left exactly as CI left it.
func TestAcquireTarget_AnalyzeRefRedirectsTreeAndProvenance(t *testing.T) {
	for _, tc := range []struct{ name, ref string }{
		{"branch", "baseline"},
		{"tag", "v1.0.0"},
		{"sha", ""}, // filled with the baseline commit below
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newRefFixture(t, configBody("baseline"), false)
			ref := tc.ref
			if ref == "" {
				ref = fx.baselineSHA
			}
			if ref != "baseline" {
				// The workspace's config is what is read; point it at the tag / commit.
				writeT(t, filepath.Join(fx.clone, ".github", "ferralon.yml"), "version: 1\nanalyze:\n  ref: "+ref+"\n")
			}

			// Precondition: the checked-out tree alone is NOT scannable — this is the failure the
			// feature exists to fix.
			if _, err := checkout.ResolveVendored(fx.clone); err == nil {
				t.Fatal("fixture precondition: docs-only main must not be a recognized source tree")
			}

			acq, err := acquireTarget(context.Background(), fx.clone, "main", "", "/fake/analyzer-bin", false)
			if err != nil {
				t.Fatalf("acquireTarget with analyze.ref %q: %v", ref, err)
			}

			// The analyzed content is baseline's.
			if acq.language != checkout.LangGo {
				t.Fatalf("language = %q, want go (baseline's tree)", acq.language)
			}
			mod, err := os.ReadFile(filepath.Join(acq.buildDir, "go.mod"))
			if err != nil || !strings.Contains(string(mod), "example.com/onbaseline") {
				t.Fatalf("buildDir %q must hold baseline's go.mod, got %q (%v)", acq.buildDir, mod, err)
			}

			// ...and the provenance says so, verified against the tree actually analyzed.
			head, err := checkout.ResolveHead(context.Background(), acq.buildDir)
			if err != nil {
				t.Fatal(err)
			}
			if head != fx.baselineSHA {
				t.Fatalf("analyzed tree HEAD = %s, want baseline %s", head, fx.baselineSHA)
			}
			rev, commit := acq.provenance("main", fx.mainSHA)
			if rev != ref || commit != head {
				t.Fatalf("provenance = (%q, %q), want (%q, %q) — the analyzed ref and its real HEAD, not the CI labels", rev, commit, ref, head)
			}
			if commit == fx.mainSHA {
				t.Fatal("report would claim the default-branch commit for an override scan")
			}

			// The workspace is untouched: still main, still docs-only.
			if got := gitT(t, fx.clone, "rev-parse", "HEAD"); got != fx.mainSHA {
				t.Fatalf("workspace HEAD moved to %s, want main %s", got, fx.mainSHA)
			}
			if _, err := os.Stat(filepath.Join(fx.clone, "go.mod")); err == nil {
				t.Fatal("baseline content leaked into the workspace")
			}
			if s := gitT(t, fx.clone, "rev-parse", "--is-shallow-repository"); s != "true" {
				t.Fatalf("workspace shallow = %s", s)
			}

			acq.cleanup()
			if _, err := os.Stat(acq.buildDir); !os.IsNotExist(err) {
				t.Fatalf("cleanup must remove the worktree dir, stat err = %v", err)
			}
			if n := worktreeCount(t, fx.clone); n != 1 {
				t.Fatalf("cleanup must deregister the worktree, %d remain", n)
			}
		})
	}
}

// AC1: no config file, or a config file without analyze.ref, is the pre-change behavior — the
// checked-out tree is inventoried in place, no git is run, and the Report labels pass through
// byte-for-byte.
func TestAcquireTarget_NoAnalyzeRefIsDefaultPreserving(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"no config file":           nil,
		"version only":             {".github/ferralon.yml": "version: 1\n"},
		"analyze without ref":      {".github/ferralon.yml": "version: 1\nanalyze:\n"},
		"unknown keys only":        {".github/ferralon.yml": "version: 1\nanalyze:\n  path: svc\nfuture: true\n"},
		"empty file":               {".github/ferralon.yml": ""},
		"other files under github": {".github/workflows/x.yml": "on: push\n"},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newRefFixture(t, files, true)

			plan, err := checkout.ResolveVendored(fx.clone)
			if err != nil {
				t.Fatal(err)
			}
			wantDir, wantLang := plan.Primary().Root, plan.Primary().Language
			acq, err := acquireTarget(context.Background(), fx.clone, "main", "", "/fake/analyzer-bin", false)
			if err != nil {
				t.Fatalf("acquireTarget: %v", err)
			}
			defer acq.cleanup()

			if acq.buildDir != wantDir || acq.language != wantLang {
				t.Fatalf("got (%q, %q), want in-place (%q, %q)", acq.buildDir, acq.language, wantDir, wantLang)
			}
			if acq.repo != filepath.Base(fx.clone) {
				t.Fatalf("repo = %q", acq.repo)
			}
			if acq.analyzeRef != "" || acq.analyzedCommit != "" {
				t.Fatalf("no redirect expected, got ref=%q commit=%q", acq.analyzeRef, acq.analyzedCommit)
			}
			// Labels pass through exactly, including the empty-label case.
			for _, in := range [][2]string{{"main", fx.mainSHA}, {"", ""}, {"refs/pull/7/merge", "deadbeef"}} {
				if rev, commit := acq.provenance(in[0], in[1]); rev != in[0] || commit != in[1] {
					t.Fatalf("provenance(%q, %q) = (%q, %q), want unchanged", in[0], in[1], rev, commit)
				}
			}
			if n := worktreeCount(t, fx.clone); n != 1 {
				t.Fatalf("default path must not create a worktree, %d present", n)
			}
		})
	}
}

// The default path needs no git at all: a plain vendored directory (not a repository) with no
// config scans in place exactly as before.
func TestAcquireTarget_NoConfigNonGitDirUnchanged(t *testing.T) {
	dir := t.TempDir()
	writeT(t, filepath.Join(dir, "go.mod"), "module example.com/vendored\n\ngo 1.26\n")
	acq, err := acquireTarget(context.Background(), dir, "r", "", "/fake/analyzer-bin", false)
	if err != nil {
		t.Fatalf("acquireTarget: %v", err)
	}
	defer acq.cleanup()
	abs, _ := filepath.Abs(dir)
	if acq.buildDir != abs {
		t.Fatalf("buildDir = %q, want %q", acq.buildDir, abs)
	}
	if rev, commit := acq.provenance("r", "c"); rev != "r" || commit != "c" {
		t.Fatalf("provenance changed on the default path: (%q, %q)", rev, commit)
	}
}

// AC4: an analyze.ref that does not exist fails loud, names the ref and the file, and leaves no
// worktree behind.
func TestAcquireTarget_AnalyzeRefNonexistentFailsLoud(t *testing.T) {
	fx := newRefFixture(t, configBody("no-such-branch"), false)
	_, err := acquireTarget(context.Background(), fx.clone, "main", "", "/fake/analyzer-bin", false)
	if err == nil {
		t.Fatal("a nonexistent analyze.ref must fail")
	}
	for _, want := range []string{`"no-such-branch"`, ".github/ferralon.yml"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error must name %s, got: %v", want, err)
		}
	}
	if n := worktreeCount(t, fx.clone); n != 1 {
		t.Fatalf("failed redirect leaked a worktree (%d present)", n)
	}
}

// A ref that exists but carries no source fails with the analyze.ref named, and cleans up.
func TestAcquireTarget_AnalyzeRefWithoutSourceFailsAndCleansUp(t *testing.T) {
	fx := newRefFixture(t, configBody("main"), false)
	_, err := acquireTarget(context.Background(), fx.clone, "main", "", "/fake/analyzer-bin", false)
	if err == nil || !strings.Contains(err.Error(), `analyze.ref "main"`) || !strings.Contains(err.Error(), "not a recognized source tree") {
		t.Fatalf("want a not-a-source-tree error naming analyze.ref, got %v", err)
	}
	if n := worktreeCount(t, fx.clone); n != 1 {
		t.Fatalf("failed scan leaked a worktree (%d present)", n)
	}
}

// AC3 through the real entry point: a malformed config fails the acquisition closed; it is never
// skipped in favor of scanning the checked-out tree.
func TestAcquireTarget_MalformedConfigFailsClosed(t *testing.T) {
	fx := newRefFixture(t, map[string]string{".github/ferralon.yml": "version: 1\nanalyze: {ref: baseline\n"}, true)
	_, err := acquireTarget(context.Background(), fx.clone, "main", "", "/fake/analyzer-bin", false)
	if err == nil || !strings.Contains(err.Error(), "malformed YAML") {
		t.Fatalf("malformed config must fail closed, got %v", err)
	}
}

// AC6: the state-selection -ref flag keeps its meaning; the new setting is not a flag named ref.
func TestAnalyzeRefDoesNotCollideWithStateRefFlag(t *testing.T) {
	fs := flag.NewFlagSet("analyze-ref-test", flag.ContinueOnError)
	registerRunFlags(fs)
	ref := fs.Lookup("ref")
	if ref == nil || !strings.Contains(strings.ToLower(ref.Usage), "state") {
		t.Fatalf("-ref must remain the StateStore selection flag, got %+v", ref)
	}
	for _, name := range []string{"analyze-ref", "analyze.ref"} {
		if fs.Lookup(name) != nil {
			t.Fatalf("unexpected flag -%s: analyze.ref lives in the repository config file", name)
		}
	}
}
