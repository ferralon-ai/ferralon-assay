package javaanalysis

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// withinDeadline runs fn and fails the test if it has not returned in time. A build file that is
// a FIFO blocks a plain open until something writes to it, so a reader that does not refuse it
// hangs instead of failing.
func withinDeadline(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("did not return within %v: a FIFO was opened for reading", d)
	}
}

func mustFIFO(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Every file the Java lane reads is refused when it is not a regular file: the read fails, the
// reader takes its fail-closed branch, and nothing waits on a writer.
func TestBuildFileReads_RefuseAFIFO(t *testing.T) {
	const deadline = 5 * time.Second
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string)
		check func(t *testing.T, dir string)
	}{
		{"pom.xml, launch model", func(t *testing.T, dir string) {
			mustFIFO(t, filepath.Join(dir, "pom.xml"))
		}, func(t *testing.T, dir string) {
			if _, ok := parseMavenPOM(filepath.Join(dir, "pom.xml")); ok {
				t.Error("parseMavenPOM read a FIFO")
			}
		}},
		{"a graph JAR", func(t *testing.T, dir string) {
			mustFIFO(t, filepath.Join(dir, "netkit-1.0.0.jar"))
		}, func(t *testing.T, dir string) {
			j := RuntimeJar{Coordinate: "com.evil:netkit", Version: "1.0.0", Path: filepath.Join(dir, "netkit-1.0.0.jar"), SHA256: "00"}
			if _, found := readJar(j); found == jarFound {
				t.Error("readJar read a FIFO")
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			withinDeadline(t, deadline, func() { tc.check(t, dir) })
		})
	}
}
