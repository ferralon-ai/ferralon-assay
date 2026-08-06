package selfcleanup

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// ActuatorConfig is the repository context the git/gh-backed Actuator needs. Every
// field is derived from the GitHub Actions run environment (GITHUB_REPOSITORY,
// GITHUB_WORKSPACE, the workflow ref, and the resolved default branch).
type ActuatorConfig struct {
	// Repo is "owner/repo" (GITHUB_REPOSITORY).
	Repo string
	// DefaultBranch is the branch the workflow file lives on and rung 1 pushes to.
	DefaultBranch string
	// WorkflowPath is the repo-relative path of the workflow file to remove
	// (.github/workflows/ferralon-assay.yml).
	WorkflowPath string
	// WorkflowFile is just the basename, used to resolve the workflow id for disable.
	WorkflowFile string
	// GitDir is the checkout root (GITHUB_WORKSPACE) the git commands run in.
	GitDir string
	// StateRef is the durable state ref to delete — the ref the run's own StateStore
	// actually wrote to: statestore.DefaultRef, the host-portability FallbackRef, or a
	// custom ref the operator configured (action.yml's state-ref / the -ref flag).
	// Never assume the default; a caller with a live StateStore should read it back
	// (see statestore's StateRef() accessors) rather than re-deriving it.
	StateRef string
	// Token is the GITHUB_TOKEN used for git push (via the extraheader) and gh calls.
	Token string
	// GitBin / GhBin override the binaries ("" → "git" / "gh" on PATH).
	GitBin string
	GhBin  string
}

// committer identity is the non-identifying github-actions[bot] persona (stealth
// recipe): a self-cleanup commit never carries a personal identity.
const (
	committerName  = "github-actions[bot]"
	committerEmail = "41898282+github-actions[bot]@users.noreply.github.com"
	removalBranch  = "ferralon-assay-removal"
)

// runner runs a subprocess and returns combined stdout, and an error wrapping stderr
// on failure. It is injectable so tests assert command shapes without a live repo.
type runner func(ctx context.Context, name string, args ...string) (string, error)

// gitActuator implements Actuator over git + gh in the customer's Actions runner.
type gitActuator struct {
	cfg ActuatorConfig
	run runner
}

var _ Actuator = (*gitActuator)(nil)

// NewGitActuator builds the git/gh-backed Actuator.
func NewGitActuator(cfg ActuatorConfig) *gitActuator {
	return &gitActuator{cfg: cfg, run: execRunner}
}

func execRunner(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func (g *gitActuator) gitBin() string {
	if g.cfg.GitBin != "" {
		return g.cfg.GitBin
	}
	return "git"
}

func (g *gitActuator) ghBin() string {
	if g.cfg.GhBin != "" {
		return g.cfg.GhBin
	}
	return "gh"
}

// git runs `git -C <GitDir> [-c committer identity] <args>`.
func (g *gitActuator) git(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"-C", g.cfg.GitDir}, args...)
	return g.run(ctx, g.gitBin(), full...)
}

// commitIdentity returns the `-c user.name -c user.email` flags stamping the
// non-identifying committer.
func commitIdentity() []string {
	return []string{"-c", "user.name=" + committerName, "-c", "user.email=" + committerEmail}
}

// DeleteWorkflowFileDirect removes the workflow file and direct-pushes the commit to
// the default branch. A push refused by branch protection is wrapped as
// ErrPushRejected so the caller drops to rung 2; the working tree is restored to the
// pre-attempt HEAD on any failure so rung 2 starts clean.
func (g *gitActuator) DeleteWorkflowFileDirect(ctx context.Context) error {
	orig, _ := g.git(ctx, "rev-parse", "HEAD")
	orig = strings.TrimSpace(orig)

	if _, err := g.git(ctx, "rm", "-q", "--", g.cfg.WorkflowPath); err != nil {
		return err
	}
	commitArgs := append(commitIdentity(), "commit", "-m", removalCommitMsg)
	if _, err := g.git(ctx, commitArgs...); err != nil {
		g.restore(ctx, orig)
		return err
	}
	if _, err := g.git(ctx, "push", "origin", "HEAD:"+g.cfg.DefaultBranch); err != nil {
		g.restore(ctx, orig)
		if isPushRejected(err) {
			return fmt.Errorf("%w: %v", ErrPushRejected, err)
		}
		return err
	}
	return nil
}

func (g *gitActuator) restore(ctx context.Context, orig string) {
	if orig != "" {
		_, _ = g.git(ctx, "reset", "--hard", orig)
	}
}

// OpenRemovalPR branches from origin/<default> with the deletion and opens the PR. It
// branches from the fetched remote tip so it is independent of any partial state a
// failed rung 1 left behind.
func (g *gitActuator) OpenRemovalPR(ctx context.Context) error {
	if _, err := g.git(ctx, "fetch", "origin", g.cfg.DefaultBranch); err != nil {
		return err
	}
	if _, err := g.git(ctx, "checkout", "-B", removalBranch, "origin/"+g.cfg.DefaultBranch); err != nil {
		return err
	}
	if _, err := g.git(ctx, "rm", "-q", "--", g.cfg.WorkflowPath); err != nil {
		return err
	}
	commitArgs := append(commitIdentity(), "commit", "-m", removalCommitMsg)
	if _, err := g.git(ctx, commitArgs...); err != nil {
		return err
	}
	if _, err := g.git(ctx, "push", "-u", "origin", removalBranch); err != nil {
		return err
	}
	_, err := g.run(ctx, g.ghBin(), "pr", "create",
		"--repo", g.cfg.Repo,
		"--base", g.cfg.DefaultBranch,
		"--head", removalBranch,
		"--title", prTitle,
		"--body", g.prBody())
	return err
}

// DisableWorkflow resolves the workflow id from its path and disables it via the
// Actions API.
func (g *gitActuator) DisableWorkflow(ctx context.Context) error {
	id, err := g.run(ctx, g.ghBin(), "api",
		fmt.Sprintf("repos/%s/actions/workflows/%s", g.cfg.Repo, g.cfg.WorkflowFile),
		"--jq", ".id")
	if err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("selfcleanup: could not resolve workflow id for %s", g.cfg.WorkflowFile)
	}
	_, err = g.run(ctx, g.ghBin(), "api", "-X", "PUT",
		fmt.Sprintf("repos/%s/actions/workflows/%s/disable", g.cfg.Repo, id))
	return err
}

// OpenCleanupIssue files the one-manual-step Issue.
func (g *gitActuator) OpenCleanupIssue(ctx context.Context) error {
	_, err := g.run(ctx, g.ghBin(), "issue", "create",
		"--repo", g.cfg.Repo,
		"--title", issueTitle,
		"--body", g.issueBody())
	return err
}

// DeleteStateRef deletes the durable state ref.
func (g *gitActuator) DeleteStateRef(ctx context.Context) error {
	_, err := g.git(ctx, "push", "origin", "--delete", g.cfg.StateRef)
	return err
}

// isPushRejected recognizes a branch-protection refusal in git's stderr. GitHub
// emits GH006 / "protected branch" for a rejected push to a protected ref.
func isPushRejected(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "protected branch") ||
		strings.Contains(s, "gh006") ||
		strings.Contains(s, "[remote rejected]") ||
		strings.Contains(s, "protected-branch")
}
