package pythonanalysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildTreeWalk_SkipRule pins the walk the install scans share with the other lanes: only
// a directory named node_modules or site-packages is skipped, .git and every build, dot, venv
// and test directory are entered, and a symlink is never followed; one that leaves the root or
// does not resolve is reported as escaping.
func TestBuildTreeWalk_SkipRule(t *testing.T) {
	outside := t.TempDir()
	root := writeTree(t, map[string]string{
		"node_modules/pkg/install.sh":                    "x",
		"lib/python3.12/site-packages/black/__init__.py": "x",
		".git/hooks/post-checkout":                       "x",
		"build/docker/Dockerfile":                        "x",
		"dist/run.sh":                                    "x",
		".docker/Dockerfile":                             "x",
		"env/setup.sh":                                   "x",
		"venv/bin/activate":                              "x",
		"tests/fixtures/deploy.sh":                       "x",
		"app/main.py":                                    "x",
	})
	links := map[string]string{
		"out":      outside,
		"dangling": filepath.Join(root, "missing"),
		"inrepo":   filepath.Join(root, "app"),
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	visited := map[string]buildTreeEntry{}
	if err := buildTreeWalk(root, func(e buildTreeEntry, err error) error {
		if err != nil {
			t.Fatalf("walk error at %s: %v", e.Path, err)
		}
		rel, _ := filepath.Rel(root, e.Path)
		visited[filepath.ToSlash(rel)] = e
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{".git/hooks/post-checkout", "build/docker/Dockerfile", "dist/run.sh", ".docker/Dockerfile", "env/setup.sh", "venv/bin/activate", "tests/fixtures/deploy.sh", "app/main.py"} {
		if _, ok := visited[want]; !ok {
			t.Errorf("%s must be walked", want)
		}
	}
	for rel := range visited {
		if strings.HasPrefix(rel, "node_modules/") || strings.Contains(rel, "site-packages/") {
			t.Errorf("%s is inside a skipped directory and must not be walked", rel)
		}
	}
	for _, dir := range []string{"node_modules", "lib/python3.12/site-packages"} {
		if e, ok := visited[dir]; !ok || !e.Skipped {
			t.Errorf("%s must be visited once as skipped; got %+v", dir, e)
		}
	}
	for name, escapes := range map[string]bool{"out": true, "dangling": true, "inrepo": false} {
		e, ok := visited[name]
		if !ok || !e.Symlink || e.Escapes != escapes {
			t.Errorf("symlink %s: got %+v, want Symlink and Escapes=%v", name, e, escapes)
		}
	}
	if _, ok := visited["inrepo/main.py"]; ok {
		t.Errorf("a symlinked directory must not be followed")
	}
}

// TestLoadSet_EscapingSymlinkVetoes pins that a symlink leaving the repository blocks every
// refutation: the install commands or installed copies behind it are unknown.
func TestLoadSet_EscapingSymlinkVetoes(t *testing.T) {
	outside := writeTree(t, map[string]string{"Dockerfile": "FROM python:3.12\nRUN uv sync --frozen\n"})
	dir := writeTree(t, withLock(nil))
	if err := os.Symlink(outside, filepath.Join(dir, "deploy")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for _, committed := range []bool{false, true} {
		ls := &loadSet{complete: true, reqRuntime: map[string]bool{}, installed: map[string]bool{}, projectNames: map[string]bool{}}
		ls.locks = loadLocks(dir, ls)
		if committed {
			ls.committedInstalls(dir)
		} else {
			ls.scanInstalls(dir)
		}
		found := false
		for _, m := range ls.markerless {
			found = found || strings.Contains(m, "deploy: symlink that leaves the repository")
		}
		if !found {
			t.Errorf("committed=%v: vetoes %v, want the escaping symlink", committed, ls.markerless)
		}
	}
}
