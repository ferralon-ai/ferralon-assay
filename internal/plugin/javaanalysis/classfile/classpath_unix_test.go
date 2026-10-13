//go:build unix

package classfile

import (
	"path/filepath"
	"syscall"
	"testing"
)

// TestClasspathPackages_NonRegularEntry: a FIFO is neither a JAR nor a class directory and
// is never opened, since opening one for reading blocks until a writer appears.
func TestClasspathPackages_NonRegularEntry(t *testing.T) {
	build := t.TempDir()
	fifo := filepath.Join(build, "libs-fifo.jar")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if pkgs, ok := ClasspathPackages(fifo, build); ok {
		t.Fatalf("FIFO entry listed %v, want unlisted", pkgs)
	}

	root := filepath.Join(build, "classes")
	writeEmpty(t, filepath.Join(root, "com", "acme", "A.class"))
	if err := syscall.Mkfifo(filepath.Join(root, "com", "acme", "B.class"), 0o644); err != nil {
		t.Fatal(err)
	}
	if pkgs, ok := ClasspathPackages(root, build); ok {
		t.Fatalf("class directory holding a FIFO listed %v, want unlisted", pkgs)
	}
}
