package checkout

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WorktreeAtRef materializes ref from the `origin` remote of the local git checkout containing
// target into a FRESH, DETACHED worktree, and returns the directory to scan (the worktree path
// that corresponds to target, so a target below the repository root maps to the same subdirectory)
// plus the commit that directory actually has checked out. cleanup removes the worktree; it is
// safe to call once, and it is non-nil only on success.
//
// It is the redirect behind analyze.ref in the repository config file: in the Action flow the
// runner's workspace holds the ref CI checked out (the default branch), and the repository asked
// for another ref to be analyzed. The fetch reuses GitCheckout.Fetch's pattern — fetch the ref
// into FETCH_HEAD and pin the exact fetched commit, which works uniformly for a branch, a tag or
// a SHA — but the result is checked out into a separate worktree rather than by detaching the
// caller's checkout in place, for two reasons:
//
//   - The workspace is shared with the rest of the run. The self-cleanup actuator commits and
//     pushes `HEAD:<default branch>` from that same checkout (internal/selfcleanup), so leaving it
//     detached on another ref could push that ref's history onto the default branch. A local CLI
//     user's working tree is equally not ours to switch.
//   - Honest provenance. A worktree holds exactly the fetched commit's tree: no uncommitted edit
//     and no untracked file from the caller's checkout (the Action creates its out directory
//     inside the workspace) can leak into what is analyzed under that commit's name.
//
// The ref is passed to git as a single argv element, never through a shell. The caller validates
// it (repoconfig.ValidateRef); the checks here are the backstop that keeps a value git would read
// as an option or a ref-writing refspec from reaching `git fetch` whoever the caller is.
//
// No credential is injected: the fetch inherits the environment and the repository's own git
// config, which is how actions/checkout's persisted auth reaches a private repository. A shallow
// repository is fetched with --depth 1 (the Action's default checkout); a full clone is fetched
// without it so this never converts a developer's repository to a shallow one.
func (g *GitCheckout) WorktreeAtRef(ctx context.Context, target, ref string) (dir, commit string, cleanup func(), err error) {
	if ref == "" || strings.HasPrefix(ref, "-") || strings.ContainsAny(ref, ": \t\r\n") {
		return "", "", nil, fmt.Errorf("checkout: refusing ref %q", ref)
	}
	top, err := g.run(ctx, target, Credential{}, "", "rev-parse", "--show-toplevel")
	if err != nil {
		return "", "", nil, fmt.Errorf("checkout: %q is not inside a git checkout (analyzing another ref needs one): %w", target, err)
	}
	rel, err := relUnder(strings.TrimSpace(top), target)
	if err != nil {
		return "", "", nil, err
	}

	shallow, err := g.run(ctx, target, Credential{}, "", "rev-parse", "--is-shallow-repository")
	if err != nil {
		return "", "", nil, fmt.Errorf("checkout: inspect repository: %w", err)
	}
	fetch := []string{"fetch", "--no-tags"}
	if strings.TrimSpace(shallow) == "true" {
		fetch = append(fetch, "--depth", "1")
	}
	fetch = append(fetch, "origin", ref)
	if _, err := g.run(ctx, target, Credential{}, "", fetch...); err != nil {
		return "", "", nil, fmt.Errorf("checkout: git fetch origin %q: %w", ref, err)
	}
	fetched, err := g.run(ctx, target, Credential{}, "", "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil {
		return "", "", nil, fmt.Errorf("checkout: resolve fetched %q: %w", ref, err)
	}
	fetched = strings.TrimSpace(fetched)

	wt, err := os.MkdirTemp("", "assay-analyze-ref-")
	if err != nil {
		return "", "", nil, fmt.Errorf("checkout: mkdtemp: %w", err)
	}
	remove := func() {
		// Background, not ctx: cleanup must still run when the scan's context was cancelled.
		_, _ = g.run(context.Background(), target, Credential{}, "", "worktree", "remove", "--force", wt)
		_ = os.RemoveAll(wt)
		_, _ = g.run(context.Background(), target, Credential{}, "", "worktree", "prune")
	}
	// Hooks are disabled for the checkout: nothing in the analyzed tree, or configured around it,
	// runs as a side effect of materializing it.
	if _, err := g.run(ctx, target, Credential{}, "", "-c", "core.hooksPath="+os.DevNull, "worktree", "add", "--detach", wt, fetched); err != nil {
		remove()
		return "", "", nil, fmt.Errorf("checkout: git worktree add %q (%s): %w", ref, fetched, err)
	}
	head, err := g.run(ctx, wt, Credential{}, "", "rev-parse", "HEAD")
	if err != nil {
		remove()
		return "", "", nil, fmt.Errorf("checkout: rev-parse HEAD in worktree for %q: %w", ref, err)
	}
	head = strings.TrimSpace(head)
	if head != fetched {
		remove()
		return "", "", nil, fmt.Errorf("checkout: worktree for %q is at %s, expected %s", ref, head, fetched)
	}
	return filepath.Join(wt, rel), head, remove, nil
}

// relUnder returns target's path relative to the repository root top, resolving symlinks on both
// (git reports the physical path; a temp dir on macOS is reached through /var → /private/var).
func relUnder(top, target string) (string, error) {
	realTop, err := filepath.EvalSymlinks(top)
	if err != nil {
		return "", fmt.Errorf("checkout: resolve repository root %q: %w", top, err)
	}
	realTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", fmt.Errorf("checkout: resolve %q: %w", target, err)
	}
	rel, err := filepath.Rel(realTop, realTarget)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("checkout: %q is not inside repository root %q", target, top)
	}
	return rel, nil
}
