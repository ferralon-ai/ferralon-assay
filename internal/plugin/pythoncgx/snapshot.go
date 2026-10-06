package pythoncgx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// snapshot commits buildDir's current files into a git repository under cacheDir and returns
// that repository's path and the commit's tree OID.
//
// cgx indexes a git tree and stores its index beside it, in <repo>/.cgx. Opening buildDir
// directly would write into the scanned checkout and would index its HEAD commit rather than
// the files on disk, and a tree extracted from an archive has no repository at all. The
// snapshot repository has a separate git dir with buildDir as its work tree, so buildDir is
// only read; its own .gitignore files apply as they would to a commit of it, while system and
// global git configuration do not. One snapshot repository serves each build directory, so
// the index persists across the one-shot plugin calls of a scan and across scans, and an
// unchanged tree is never re-indexed.
func snapshot(ctx context.Context, cacheDir, buildDir string) (repo, tree string, err error) {
	abs, err := filepath.Abs(buildDir)
	if err != nil {
		return "", "", fmt.Errorf("pythoncgx: build dir %q: %w", buildDir, err)
	}
	if abs, err = filepath.EvalSymlinks(abs); err != nil {
		return "", "", fmt.Errorf("pythoncgx: build dir %q: %w", buildDir, err)
	}
	if info, err := os.Stat(abs); err != nil {
		return "", "", fmt.Errorf("pythoncgx: build dir %q: %w", buildDir, err)
	} else if !info.IsDir() {
		return "", "", fmt.Errorf("pythoncgx: build dir %q is not a directory", buildDir)
	}

	sum := sha256.Sum256([]byte(abs))
	repo = filepath.Join(cacheDir, "repos", hex.EncodeToString(sum[:8]), "repo")
	gitDir := filepath.Join(repo, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		if err := os.MkdirAll(repo, 0o755); err != nil {
			return "", "", fmt.Errorf("pythoncgx: snapshot dir: %w", err)
		}
		if _, err := git(ctx, abs, "init", "-q", repo); err != nil {
			return "", "", err
		}
	} else if err != nil {
		return "", "", fmt.Errorf("pythoncgx: snapshot dir: %w", err)
	}

	gd := "--git-dir=" + gitDir
	if _, err := git(ctx, abs, gd, "--work-tree="+abs, "-c", "advice.addEmbeddedRepo=false", "add", "-A"); err != nil {
		return "", "", err
	}
	if tree, err = git(ctx, abs, gd, "write-tree"); err != nil {
		return "", "", err
	}
	if head, _ := git(ctx, abs, gd, "rev-parse", "-q", "--verify", "HEAD^{tree}"); head == tree {
		return repo, tree, nil
	}
	commit, err := git(ctx, abs, gd, "commit-tree", tree, "-m", "snapshot")
	if err != nil {
		return "", "", err
	}
	if _, err := git(ctx, abs, gd, "update-ref", "HEAD", commit); err != nil {
		return "", "", err
	}
	return repo, tree, nil
}

// git runs one git command in dir with an isolated configuration and returns its trimmed
// stdout. Inherited GIT_* variables are dropped so a caller's GIT_DIR or GIT_INDEX_FILE cannot
// redirect it; author and committer are fixed so a snapshot commit is a function of its tree.
func git(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("pythoncgx: git %s: %w (stderr: %s)", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func gitEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") {
			env = append(env, kv)
		}
	}
	return append(env,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=snapshot",
		"GIT_AUTHOR_EMAIL=snapshot@localhost",
		"GIT_AUTHOR_DATE=1970-01-01T00:00:00Z",
		"GIT_COMMITTER_NAME=snapshot",
		"GIT_COMMITTER_EMAIL=snapshot@localhost",
		"GIT_COMMITTER_DATE=1970-01-01T00:00:00Z",
	)
}
