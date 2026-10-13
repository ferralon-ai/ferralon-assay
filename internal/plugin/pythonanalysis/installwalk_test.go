package pythonanalysis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// The walk itself is buildtree's, pinned by that package's tests; these rows pin what the
// install scan and the committed-install scan do with what it reports.

func btSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

// TestLoadSet_SymlinkedDirectories pins the rule in both scans: a symlinked directory the walk
// reads at its target vetoes nothing, one into a skipped directory vetoes, and a symlink cycle
// terminates and vetoes as a symlink that does not resolve.
func TestLoadSet_SymlinkedDirectories(t *testing.T) {
	tests := []struct {
		name  string
		links map[string]string
		veto  string // "" for no symlink veto
	}{
		{"lib64 to lib", map[string]string{".venv/lib64": "lib"}, ""},
		{"link to an ancestor", map[string]string{"deploy/up": ".."}, ""},
		{"link into node_modules", map[string]string{"scripts": "node_modules/tool/bin"}, "scripts: symlinked directory whose target the walk does not read"},
		{"symlink cycle", map[string]string{"loop1": "loop2", "loop2": "loop1"}, "loop1: symlink that leaves the repository or does not resolve"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, withLock(map[string]string{
				".venv/lib/python3.12/app.pth":   "x\n",
				"deploy/run.sh":                  "exec gunicorn app:app\n",
				"node_modules/tool/bin/setup.sh": "pip install black\n",
			}))
			for link, target := range tt.links {
				btSymlink(t, target, filepath.Join(dir, filepath.FromSlash(link)))
			}
			for _, committed := range []bool{false, true} {
				ls := &loadSet{complete: true, reqRuntime: map[string]bool{}, installed: map[string]bool{}, projectNames: map[string]bool{}}
				ls.locks = loadLocks(dir, ls)
				if committed {
					ls.committedInstalls(dir)
				} else {
					ls.scanInstalls(dir)
				}
				var symlinkVetoes []string
				for _, m := range ls.markerless {
					if strings.Contains(m, "symlink") {
						symlinkVetoes = append(symlinkVetoes, m)
					}
				}
				switch {
				case tt.veto == "" && len(symlinkVetoes) > 0:
					t.Errorf("committed=%v: symlink vetoes %v, want none", committed, symlinkVetoes)
				case tt.veto != "" && !strings.Contains(strings.Join(symlinkVetoes, "\n"), tt.veto):
					t.Errorf("committed=%v: symlink vetoes %v, want one containing %q", committed, symlinkVetoes, tt.veto)
				}
			}
		})
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

// TestLoadSet_SymlinkedCommittedCopies pins that the committed-install scan reads a symlink by
// the place it links: a vendored package or dist-info linked in from elsewhere in the
// repository is an installed copy, which never refutes.
func TestLoadSet_SymlinkedCommittedCopies(t *testing.T) {
	tests := []struct {
		name   string
		link   string // relative to the repository root; its target is ../third/<base>
		target string
		refute bool
	}{
		{"control: no link", "", "", true},
		{"a vendored package linked in", "vendor/black", "../third/black", false},
		{"a dist-info linked in", "deploy/black-24.4.2.dist-info", "../third/meta", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, withLock(map[string]string{
				"app/main.py":             "import requests\nimport django\n",
				"third/black/__init__.py": "",
				"third/meta/METADATA":     "Metadata-Version: 2.1\nName: black\nVersion: 24.4.2\n",
				"vendor/README":           "x\n",
				"deploy/README":           "x\n",
			}))
			if tt.link != "" {
				btSymlink(t, tt.target, filepath.Join(dir, filepath.FromSlash(tt.link)))
			}
			res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Package: "pkg:pypi/black@24.4.2"})
			if err != nil {
				t.Fatal(err)
			}
			if got := res.Refutation != nil; got != tt.refute {
				t.Fatalf("refuted = %v, want %v (refutation %+v)", got, tt.refute, res.Refutation)
			}
		})
	}
}
