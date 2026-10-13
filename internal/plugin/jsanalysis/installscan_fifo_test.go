//go:build unix

package jsanalysis

import (
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// mustMkfifo makes a named pipe at path, skipping the test where the filesystem refuses one.
func mustMkfifo(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
}

// within runs f and fails the test if it has not returned in 3s: a reader that opens a pipe
// with no writer blocks forever, so a revert fails here instead of hanging the package.
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

// TestTreeWalkLinkToPipe pins walkTree to buildtree as of commit bc0233d: a symlink to a pipe
// fails as a symlink to a non-regular file and is never opened, and a pipe itself runs nothing.
func TestTreeWalkLinkToPipe(t *testing.T) {
	dir, err := filepath.EvalSymlinks(writeTree(t, map[string]string{"c/d.sh": "x"}))
	if err != nil {
		t.Fatal(err)
	}
	mustMkfifo(t, filepath.Join(dir, "pipe"))
	mustSymlink(t, "pipe", filepath.Join(dir, "link"))
	var files, fails []string
	within(t, "walkTree", func() {
		walkTree(dir, func(_, rel string, _ fs.DirEntry) error {
			files = append(files, rel)
			return nil
		}, func(rel, why string) {
			fails = append(fails, rel+": "+why)
		})
	})
	if len(files) != 1 || files[0] != "c/d.sh" {
		t.Errorf("files = %v, want [c/d.sh]", files)
	}
	if len(fails) != 1 || fails[0] != "link: symlink to a non-regular file" {
		t.Errorf("fails = %v, want [link: symlink to a non-regular file]", fails)
	}
}

// TestLoadSetPipes: no reader opens a pipe, whether the walk reaches it through a symlink or a
// reader outside the walk opens it by name. Each pipe withholds every refutation.
func TestLoadSetPipes(t *testing.T) {
	evilLock := npmLockJSON(t, map[string]lockPkg{"node_modules/evil": {Version: "1.0.0", Script: true}})
	cases := []struct {
		name  string
		files map[string]string
		pipe  string // the path made a pipe
		link  string // a symlink to pipe, when set
		all   string // substring of the scan's veto
		gap   string // substring of a load-set gap
	}{
		{name: "a symlink to a pipe in the build dir",
			files: map[string]string{"package.json": `{"name":"app"}`, "package-lock.json": npmLockJSON(t, map[string]lockPkg{})},
			pipe:  "pipe", link: "deploy.sh", all: "deploy.sh: symlink to a non-regular file"},
		{name: "an installed package.json that is a pipe",
			files: map[string]string{"package.json": `{"name":"app"}`, "package-lock.json": evilLock, "node_modules/evil/index.js": ""},
			pipe:  "node_modules/evil/package.json", all: "node_modules/evil/package.json: unreadable"},
		{name: "a lockfile that is a pipe",
			files: map[string]string{"package.json": `{"name":"app"}`},
			pipe:  "package-lock.json", gap: "package-lock.json: unreadable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, tc.files)
			mustMkfifo(t, filepath.Join(dir, filepath.FromSlash(tc.pipe)))
			if tc.link != "" {
				mustSymlink(t, tc.pipe, filepath.Join(dir, tc.link))
			}
			var ls *loadSet
			var sc *installScan
			within(t, "computeLoadSet", func() {
				ls = computeLoadSet(dir)
				if sc = ls.scan; sc == nil && ls.model != nil {
					sc = scanBuild(ls.model.buildReal, ls.model, ls.installed)
				}
			})
			if tc.all != "" && (sc == nil || !strings.Contains(sc.all, tc.all)) {
				t.Fatalf("scan = %+v, want veto %q", sc, tc.all)
			}
			if tc.gap != "" {
				if ls.complete || !strings.Contains(strings.Join(ls.gaps, "\n"), tc.gap) {
					t.Fatalf("complete = %v, gaps = %q, want gap %q", ls.complete, ls.gaps, tc.gap)
				}
			}
		})
	}
}
