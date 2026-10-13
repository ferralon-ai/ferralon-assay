//go:build unix

package jsanalysis

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestLockClosures_LinkToPipe: a symlink to a pipe leaves every closure unbounded, and the walk
// never opens the pipe, which would block it with no writer. A pipe itself declares nothing.
func TestLockClosures_LinkToPipe(t *testing.T) {
	const lock = `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/qs":{}}}`
	for _, tc := range []struct {
		name    string
		link    bool
		bounded bool
	}{
		{name: "a symlink to a pipe", link: true},
		{name: "a pipe", bounded: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeProgram(t, map[string]string{"package-lock.json": lock})
			if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o644); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			if tc.link {
				treeSymlink(t, "pipe", filepath.Join(dir, "link"))
			}
			done := make(chan []string, 1)
			go func() { done <- newLockClosures(dir).closureOf("", "qs") }()
			select {
			case got := <-done:
				if bounded := got != nil; bounded != tc.bounded {
					t.Errorf("closureOf = %#v; bounded = %v, want %v", got, bounded, tc.bounded)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the walk blocked opening the pipe")
			}
		})
	}
}
