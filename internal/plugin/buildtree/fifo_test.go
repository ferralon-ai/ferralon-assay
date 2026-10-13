//go:build unix

package buildtree

import (
	"fmt"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"
)

// candidatesWithin runs Candidates under the 3 s guard, so a walk that opens a pipe fails the
// test instead of hanging the run.
func candidatesWithin(t *testing.T, root string, match func(string, []byte) (string, bool)) []Candidate {
	t.Helper()
	done := make(chan []Candidate, 1)
	go func() {
		done <- Candidates(root, match, func(string) bool { return true })
	}()
	select {
	case cs := <-done:
		return cs
	case <-time.After(3 * time.Second):
		t.Fatal("Candidates blocked opening a pipe")
		return nil
	}
}

func mkfifo(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
}

// TestCandidates_LinkToPipe: a symlink to a pipe is a candidate that is not fully read, and the
// walk never opens the pipe, which would block it with no writer.
func TestCandidates_LinkToPipe(t *testing.T) {
	root := t.TempDir()
	mkfifo(t, filepath.Join(root, "pipe"))
	symlink(t, "pipe", filepath.Join(root, "link"))
	cs := candidatesWithin(t, root, func(path string, _ []byte) (string, bool) { return "match", filepath.Base(path) == "link" })
	if len(cs) != 1 || filepath.Base(cs[0].Path) != "link" || cs[0].Why != "symlink to a non-regular file" || cs[0].FullyRead {
		t.Errorf("candidates = %+v, want one at link, a symlink to a non-regular file, not fully read", cs)
	}
}

// TestCandidates_PipeNamedLikeACandidate: a pipe whose name match accepts is a candidate that
// is not fully read, classified by name alone (match sees a nil head) and never opened. A pipe
// whose name match rejects yields nothing.
func TestCandidates_PipeNamedLikeACandidate(t *testing.T) {
	root := t.TempDir()
	mkfifo(t, filepath.Join(root, "deps.lock"))
	mkfifo(t, filepath.Join(root, "notes"))
	var heads [][]byte
	cs := candidatesWithin(t, root, func(path string, head []byte) (string, bool) {
		heads = append(heads, head)
		return "lock name", filepath.Ext(path) == ".lock"
	})
	if len(cs) != 1 || filepath.Base(cs[0].Path) != "deps.lock" || cs[0].Why != "lock name" || cs[0].FullyRead {
		t.Errorf("candidates = %+v, want one at deps.lock, not fully read", cs)
	}
	if slices.ContainsFunc(heads, func(h []byte) bool { return h != nil }) {
		t.Errorf("match saw content %q for a pipe", heads)
	}
}

// The head readers refuse a pipe without opening it, so a caller handed one (a name-matched entry
// another walk passes on with a nil head) gets an error, never a block, and a content fallback
// takes the pipe as a file it could not read.
func TestHeadReaders_Pipe(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "pylock.toml")
	if err := syscall.Mkfifo(pipe, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	symlink(t, "pylock.toml", filepath.Join(dir, "link"))
	never := func(string, []byte) (string, bool) { return "rule", false }
	for _, p := range []string{pipe, filepath.Join(dir, "link")} {
		calls := map[string]func() string{
			"Head":         func() string { _, err := Head(p); return fmt.Sprint(err != nil) },
			"rawHead":      func() string { _, err := rawHead(p); return fmt.Sprint(err != nil) },
			"NULHeadMatch": func() string { why, ok := NULHeadMatch(p, never); return fmt.Sprint(why, " ", ok) },
		}
		want := map[string]string{"Head": "true", "rawHead": "true", "NULHeadMatch": "unreadable true"}
		for name, call := range calls {
			t.Run(filepath.Base(p)+"/"+name, func(t *testing.T) {
				done := make(chan string, 1)
				go func() { done <- call() }()
				select {
				case got := <-done:
					if got != want[name] {
						t.Errorf("%s(pipe) = %s, want %s", name, got, want[name])
					}
				case <-time.After(3 * time.Second):
					t.Fatalf("%s blocked opening the pipe", name)
				}
			})
		}
	}
}
