package pythoncgx

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func listTree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		out = append(out, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSnapshot_ReadsBuildDirAndTracksItsContent(t *testing.T) {
	ctx := context.Background()
	build, cache := t.TempDir(), t.TempDir()
	files := map[string]string{"a.py": "def f():\n    pass\n", "pkg/b.py": "x = 1\n", ".gitignore": "venv/\n", "venv/lib.py": "y = 2\n"}
	for name, body := range files {
		p := filepath.Join(build, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	before := listTree(t, build)

	repo, tree1, err := snapshot(ctx, cache, build)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !strings.HasPrefix(repo, cache) {
		t.Errorf("snapshot repo %q is outside the cache dir %q", repo, cache)
	}
	if after := listTree(t, build); !reflect.DeepEqual(before, after) {
		t.Errorf("snapshot wrote into the build dir:\nbefore %v\nafter  %v", before, after)
	}
	ls, err := git(ctx, repo, "ls-tree", "-r", "--name-only", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(ls); !reflect.DeepEqual(got, []string{".gitignore", "a.py", "pkg/b.py"}) {
		t.Errorf("snapshot tree = %v, want the build dir minus its ignored files", got)
	}

	repo2, tree2, err := snapshot(ctx, cache, build)
	if err != nil || repo2 != repo || tree2 != tree1 {
		t.Fatalf("unchanged dir: snapshot = %q %q %v, want %q %q", repo2, tree2, err, repo, tree1)
	}

	if err := os.WriteFile(filepath.Join(build, "a.py"), []byte("def g():\n    pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, tree3, err := snapshot(ctx, cache, build)
	if err != nil || tree3 == tree1 {
		t.Fatalf("edited dir: tree %q (was %q), err %v; want a new tree", tree3, tree1, err)
	}
	if head, err := git(ctx, repo, "rev-parse", "HEAD^{tree}"); err != nil || head != tree3 {
		t.Errorf("HEAD tree = %q (%v), want %q", head, err, tree3)
	}
}

func TestSnapshot_IgnoresInheritedGitDir(t *testing.T) {
	build, cache := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(build, "a.py"), []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_DIR", filepath.Join(t.TempDir(), "elsewhere"))
	if _, _, err := snapshot(context.Background(), cache, build); err != nil {
		t.Fatalf("snapshot with an inherited GIT_DIR: %v", err)
	}
}

func TestSnapshot_MissingDirIsError(t *testing.T) {
	if _, _, err := snapshot(context.Background(), t.TempDir(), filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("snapshot of a missing dir: want error")
	}
}
