package github_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"
)

// writeEventFile writes a pull_request webhook payload with the given head/base repo
// full names and PR number, and returns its path.
func writeEventFile(t *testing.T, headRepo, baseRepo string, number int) string {
	t.Helper()
	payload := fmt.Sprintf(`{
      "number": %d,
      "pull_request": {
        "number": %d,
        "head": {"repo": {"full_name": %q}},
        "base": {"repo": {"full_name": %q}}
      }
    }`, number, number, headRepo, baseRepo)
	path := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatalf("write event file: %v", err)
	}
	return path
}

// TestDetectEnv_ForkedPR asserts a PR whose head repo differs from the base repo is
// detected as a fork (HeadRepoFork true) and that Detect refuses Tier 1 there — the
// load-bearing forked-PR safety guarantee. Even with a non-empty token, a fork must
// auto-skip writes.
func TestDetectEnv_ForkedPR(t *testing.T) {
	eventPath := writeEventFile(t, "attacker/repo", "owner/repo", 99)
	t.Setenv(ghsink.EnvActions, "true")
	t.Setenv(ghsink.EnvStepSummary, "/tmp/s.md")
	t.Setenv(ghsink.EnvToken, "ghs_readonly") // forks carry a read-only token (still non-empty)
	t.Setenv(ghsink.EnvRepository, "owner/repo")
	t.Setenv(ghsink.EnvEventName, "pull_request")
	t.Setenv(ghsink.EnvEventPath, eventPath)

	env := ghsink.DetectEnv()
	if !env.HeadRepoFork {
		t.Fatalf("expected HeadRepoFork=true for a forked PR")
	}
	if env.PRNumber != 99 {
		t.Errorf("PRNumber = %d, want 99", env.PRNumber)
	}

	caps := ghsink.Detect(env)
	if caps.CanWrite {
		t.Error("forked PR must NOT be write-capable (Tier 1 must auto-skip)")
	}
	if caps.CanComment {
		t.Error("forked PR must NOT be comment-capable")
	}
	if caps.CanIssue {
		t.Error("forked PR must NOT be issue-capable")
	}
	if caps.MaxTier != ghsink.Tier0 {
		t.Errorf("forked PR MaxTier = %d, want Tier0", caps.MaxTier)
	}
}

// TestDetectEnv_SameRepoPR asserts a same-repo PR (head == base) is NOT a fork and is
// write-capable + comment-capable.
func TestDetectEnv_SameRepoPR(t *testing.T) {
	eventPath := writeEventFile(t, "owner/repo", "owner/repo", 12)
	t.Setenv(ghsink.EnvActions, "true")
	t.Setenv(ghsink.EnvStepSummary, "/tmp/s.md")
	t.Setenv(ghsink.EnvToken, "ghs_write")
	t.Setenv(ghsink.EnvRepository, "owner/repo")
	t.Setenv(ghsink.EnvEventName, "pull_request")
	t.Setenv(ghsink.EnvEventPath, eventPath)

	env := ghsink.DetectEnv()
	if env.HeadRepoFork {
		t.Fatalf("same-repo PR must not be a fork")
	}
	if env.PRNumber != 12 {
		t.Errorf("PRNumber = %d, want 12", env.PRNumber)
	}

	caps := ghsink.Detect(env)
	if !caps.CanWrite {
		t.Error("same-repo PR with a token must be write-capable")
	}
	if !caps.CanComment {
		t.Error("same-repo PR must be comment-capable (has PR context)")
	}
	if !caps.CanIssue {
		t.Error("write-capable run must be issue-capable")
	}
}

// TestDetect_CanIssue_PushWithToken asserts a push build with a write token is
// issue-capable (repo-scoped) but NOT comment-capable (no PR context).
func TestDetect_CanIssue_PushWithToken(t *testing.T) {
	env := ghsink.Env{
		StepSummaryPath:     "/s",
		Token:               "t",
		EventName:           "push",
		CodeScanningEnabled: true,
		PRCommentEnabled:    true,
		IssueEnabled:        true,
	}
	caps := ghsink.Detect(env)
	if !caps.CanIssue {
		t.Error("push with token must be issue-capable")
	}
	if caps.CanComment {
		t.Error("push (no PR) must NOT be comment-capable")
	}
	if !caps.CanWrite {
		t.Error("push with token must be write-capable")
	}
}
