//go:build unix

package pythonanalysis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func mkfifo(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
}

// within runs f and fails the test if it has not returned in 3s: opening a pipe with no
// writer blocks, so a read that reaches one fails here instead of hanging the run.
func within(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("%s blocked opening a pipe", what)
	}
}

// TestLoadSet_LinkToPipe: in both scans a symlink to a pipe blocks every refutation, and the
// pipe behind it is never opened. A pipe itself runs nothing.
func TestLoadSet_LinkToPipe(t *testing.T) {
	tests := []struct {
		name      string
		link      string
		committed bool
		veto      string
	}{
		{"install scan", "deploy/run.sh", false, "deploy/run.sh: symlink to a non-regular file: install commands behind it are unknown"},
		{"committed-install scan", "vendor/black", true, "vendor/black: symlink to a non-regular file: installed copies behind it are unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, withLock(map[string]string{"deploy/README": "x\n", "vendor/README": "x\n"}))
			mkfifo(t, filepath.Join(dir, "pipe"))
			btSymlink(t, "../pipe", filepath.Join(dir, filepath.FromSlash(tt.link)))
			var markerless []string
			within(t, "the scan", func() {
				ls := &loadSet{complete: true, reqRuntime: map[string]bool{}, installed: map[string]bool{}, projectNames: map[string]bool{}}
				ls.locks = loadLocks(dir, ls)
				if tt.committed {
					ls.committedInstalls(dir)
				} else {
					ls.scanInstalls(dir)
				}
				markerless = ls.markerless
			})
			if !strings.Contains(strings.Join(markerless, "\n"), tt.veto) {
				t.Errorf("vetoes %v, want one containing %q", markerless, tt.veto)
			}
			var res plugin.ReachabilityResult
			within(t, "Reachability", func() {
				res, _ = Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Package: "pkg:pypi/black@24.4.2"})
			})
			if res.Refutation != nil {
				t.Errorf("a symlink to a pipe must block refutation; got %+v", res.Refutation)
			}
		})
	}
}

// TestLoadSet_ReadsOpenOnlyRegularFiles: every read outside the install walk (a requirements
// file named by -r, installed metadata, a config file, a nested project, a lockfile, a source
// file) skips a pipe instead of opening it, and the pipe still blocks refutation.
func TestLoadSet_ReadsOpenOnlyRegularFiles(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		pipe  string
	}{
		{"a requirements file named by -r", map[string]string{"deploy/run.sh": "pip install -r reqs.txt\n"}, "reqs.txt"},
		{"a dist-info's METADATA", map[string]string{"lib/README": "x\n"}, "lib/black-24.4.2.dist-info/METADATA"},
		{"a config file", map[string]string{}, "app/settings.yaml"},
		{"a nested project's pyproject.toml", map[string]string{}, "services/worker/pyproject.toml"},
		{"a nested lockfile", map[string]string{}, "services/worker/poetry.lock"},
		{"a source file", map[string]string{}, "app/worker.py"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, withLock(tt.files))
			mkfifo(t, filepath.Join(dir, filepath.FromSlash(tt.pipe)))
			var res plugin.ReachabilityResult
			within(t, "Reachability", func() {
				res, _ = Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Package: "pkg:pypi/black@24.4.2"})
			})
			if res.Refutation != nil {
				t.Errorf("a pipe at %s must block refutation; got %+v", tt.pipe, res.Refutation)
			}
		})
	}
}
