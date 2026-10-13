//go:build unix

package buildtree

import (
	"fmt"
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
	marked := append([]byte("\xff\xfe"), make([]byte, HeadSize)...)
	never := func(string, []byte) (string, bool) { return "rule", false }
	for _, p := range []string{pipe, filepath.Join(dir, "link")} {
		calls := map[string]func() string{
			"Head":         func() string { _, err := Head(p); return fmt.Sprint(err != nil) },
			"rawHead":      func() string { _, err := rawHead(p); return fmt.Sprint(err != nil) },
			"NULHeadMatch": func() string { why, ok := NULHeadMatch(p, never); return fmt.Sprint(why, " ", ok) },
			"BOMWide":      func() string { _, bom, err := BOMWide(p, marked); return fmt.Sprint(bom, " ", err != nil) },
		}
		want := map[string]string{"Head": "true", "rawHead": "true", "NULHeadMatch": "unreadable true", "BOMWide": "false true"}
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
