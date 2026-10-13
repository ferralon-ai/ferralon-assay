//go:build unix

package pythonanalysis

// TestBuildTreeCandidates_LinkToPipe is internal/plugin/buildtree/fifo_test.go at commit
// bc0233d, renamed to match the copy and otherwise unchanged.

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestBuildTreeCandidates_LinkToPipe: a symlink to a pipe is a candidate that is not fully read, and the
// walk never opens the pipe, which would block it with no writer. A pipe itself declares nothing.
func TestBuildTreeCandidates_LinkToPipe(t *testing.T) {
	root := t.TempDir()
	pipe := filepath.Join(root, "pipe")
	if err := syscall.Mkfifo(pipe, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	treeSymlink(t, "pipe", filepath.Join(root, "link"))
	done := make(chan []buildTreeCandidate, 1)
	go func() {
		done <- buildTreeCandidates(root, func(string, []byte) (string, bool) { return "match", true }, func(string) bool { return true })
	}()
	select {
	case cs := <-done:
		if len(cs) != 1 || filepath.Base(cs[0].Path) != "link" || cs[0].Why != "symlink to a non-regular file" || cs[0].FullyRead {
			t.Errorf("candidates = %+v, want one at link, a symlink to a non-regular file, not fully read", cs)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("buildTreeCandidates blocked opening the pipe behind link")
	}
}

// TestLoadProgram_BuildScriptLinkToPipe: a symlink to a pipe in the build tree is a file the
// scan can't read, so the build script stays in, and loading never blocks on the pipe.
func TestLoadProgram_BuildScriptLinkToPipe(t *testing.T) {
	dir := writeTree(t, map[string]string{"setup.py": yamlSetupPy, "app.py": runtimePy, "requirements.txt": "setuptools\n"})
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	treeSymlink(t, "pipe", filepath.Join(dir, "link"))
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = loadProgram(dir)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("loadProgram blocked opening the pipe behind link")
	}
	checkBuildScript(t, dir, buildScriptCase{name: "link to a pipe", script: "setup", edge: yamlLoad})
}
