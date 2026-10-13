package cfamilycgx

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

// snapRepo is the snapshot repository for one build directory.
//
// cgx indexes a git tree and stores its index beside it, in <repo>/.cgx. Opening the build
// directory directly would write into the scanned checkout and would index its HEAD commit
// rather than the files on disk, and a tree extracted from an archive has no repository at all.
// The snapshot repository has a separate git dir with the build directory as its work tree, so
// the build directory is only read; system and global git configuration do not apply. One
// snapshot repository serves each build directory, so the index persists across the one-shot
// plugin calls of a scan and across scans, and an unchanged tree is never re-indexed.
//
// Unlike a whole-tree snapshot, only the files chosen for cgx are committed (selectSources): the
// compilation database's translation units and the headers beside them, so sources the build
// does not compile never enter the graph.
type snapRepo struct {
	work   string // the build directory, absolute with symlinks resolved
	repo   string // the snapshot repository cgx opens
	gitDir string
}

// openSnapshot finds or creates the snapshot repository for buildDir under cacheDir.
func openSnapshot(ctx context.Context, cacheDir, buildDir string) (*snapRepo, error) {
	abs, err := filepath.Abs(buildDir)
	if err != nil {
		return nil, fmt.Errorf("cfamilycgx: build dir %q: %w", buildDir, err)
	}
	if abs, err = filepath.EvalSymlinks(abs); err != nil {
		return nil, fmt.Errorf("cfamilycgx: build dir %q: %w", buildDir, err)
	}
	if info, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("cfamilycgx: build dir %q: %w", buildDir, err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("cfamilycgx: build dir %q is not a directory", buildDir)
	}

	sum := sha256.Sum256([]byte(abs))
	repo := filepath.Join(cacheDir, "repos", hex.EncodeToString(sum[:8]), "repo")
	gitDir := filepath.Join(repo, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		if err := os.MkdirAll(repo, 0o755); err != nil {
			return nil, fmt.Errorf("cfamilycgx: snapshot dir: %w", err)
		}
		if _, err := git(ctx, abs, nil, "init", "-q", repo); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("cfamilycgx: snapshot dir: %w", err)
	}
	return &snapRepo{work: abs, repo: repo, gitDir: gitDir}, nil
}

func (r *snapRepo) args(extra ...string) []string {
	return append([]string{"--git-dir=" + r.gitDir, "--work-tree=" + r.work, "-c", "advice.addEmbeddedRepo=false", "-c", "core.quotePath=false"}, extra...)
}

// candidates lists every file under the build directory that a commit of it would hold (its
// .gitignore files apply), as slash-separated paths relative to it.
func (r *snapRepo) candidates(ctx context.Context) ([]string, error) {
	if _, err := git(ctx, r.work, nil, r.args("read-tree", "--empty")...); err != nil {
		return nil, err
	}
	out, err := git(ctx, r.work, nil, r.args("ls-files", "-z", "-o", "--exclude-standard")...)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range strings.Split(out, "\x00") {
		if f != "" && !strings.HasSuffix(f, "/") {
			files = append(files, f)
		}
	}
	return files, nil
}

// commit stages exactly files (paths relative to the build directory; ignored files are added
// too, since a translation unit can be a generated source) and makes them the snapshot's HEAD.
// It returns the tree OID.
func (r *snapRepo) commit(ctx context.Context, files []string) (string, error) {
	if _, err := git(ctx, r.work, nil, r.args("read-tree", "--empty")...); err != nil {
		return "", err
	}
	if len(files) > 0 {
		var spec bytes.Buffer
		for _, f := range files {
			spec.WriteString(":(literal)" + f)
			spec.WriteByte(0)
		}
		if _, err := git(ctx, r.work, &spec, r.args("add", "-f", "--pathspec-from-file=-", "--pathspec-file-nul")...); err != nil {
			return "", err
		}
	}
	tree, err := git(ctx, r.work, nil, r.args("write-tree")...)
	if err != nil {
		return "", err
	}
	if head, _ := git(ctx, r.work, nil, r.args("rev-parse", "-q", "--verify", "HEAD^{tree}")...); head == tree {
		return tree, nil
	}
	commit, err := git(ctx, r.work, nil, r.args("commit-tree", tree, "-m", "snapshot")...)
	if err != nil {
		return "", err
	}
	if _, err := git(ctx, r.work, nil, r.args("update-ref", "HEAD", commit)...); err != nil {
		return "", err
	}
	return tree, nil
}

// git runs one git command in dir with an isolated configuration and returns its stdout,
// trimmed of surrounding whitespace. Inherited GIT_* variables are dropped so a caller's GIT_DIR
// or GIT_INDEX_FILE cannot redirect it; author and committer are fixed so a snapshot commit is a
// function of its tree.
func git(ctx context.Context, dir string, stdin *bytes.Buffer, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv()
	if stdin != nil {
		cmd.Stdin = stdin
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("cfamilycgx: git %s: %w (stderr: %s)", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
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
