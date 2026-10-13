//go:build unix

package buildtree

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestCandidates_LinkToPipe: a symlink to a pipe is a candidate that is not fully read, and the
// walk never opens the pipe, which would block it with no writer. A pipe itself declares nothing.
func TestCandidates_LinkToPipe(t *testing.T) {
	root := t.TempDir()
	pipe := filepath.Join(root, "pipe")
	if err := syscall.Mkfifo(pipe, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	symlink(t, "pipe", filepath.Join(root, "link"))
	done := make(chan []Candidate, 1)
	go func() {
		done <- Candidates(root, func(string, []byte) (string, bool) { return "match", true }, func(string) bool { return true })
	}()
	select {
	case cs := <-done:
		if len(cs) != 1 || filepath.Base(cs[0].Path) != "link" || cs[0].Why != "symlink to a non-regular file" || cs[0].FullyRead {
			t.Errorf("candidates = %+v, want one at link, a symlink to a non-regular file, not fully read", cs)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Candidates blocked opening the pipe behind link")
	}
}
