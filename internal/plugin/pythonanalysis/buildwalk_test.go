package pythonanalysis

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// The walk in buildwalk.go is a copy of internal/plugin/buildtree at 444cd8f (buildtree.go blob
// 43f93477755565bdfa3fd0dabf8a313a22deb9b1). TestBuildTreeSkipped, TestBuildTreeWalk_Parity
// and TestBuildTreeLinks_SymlinkedDirs carry that package's own tables (TestSkipped,
// TestWalk_SkipRuleAndSymlinks, TestCandidates_SymlinkedDirs) over unchanged, so a drift from
// it fails here.

// TestBuildTreeSkipped pins the skip rule: exactly node_modules and site-packages,
// case-sensitive, and nothing else.
func TestBuildTreeSkipped(t *testing.T) {
	for name, want := range map[string]bool{
		"node_modules":  true,
		"site-packages": true,
		"Node_Modules":  false,
		"node_modules2": false,
		"dist-packages": false,
		".git":          false,
		".venv":         false,
		"venv":          false,
		"vendor":        false,
		"build":         false,
		"dist":          false,
		"__pycache__":   false,
		".tox":          false,
		"":              false,
	} {
		if got := buildTreeSkipped(name); got != want {
			t.Errorf("buildTreeSkipped(%q) = %v, want %v", name, got, want)
		}
	}
}

func btWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func btSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

// btTree builds a build dir exercising every rule, plus a sibling directory outside it.
func btTree(t *testing.T) (root, outside string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "build")
	outside = filepath.Join(base, "outside")
	btWrite(t, filepath.Join(outside, "dep.txt"), "x")
	btWrite(t, filepath.Join(outside, "pkg", "dep.txt"), "x")
	btWrite(t, filepath.Join(root, "dep.txt"), "x")
	btWrite(t, filepath.Join(root, ".git", "dep.txt"), "x")
	btWrite(t, filepath.Join(root, "build", "dep.txt"), "x")
	btWrite(t, filepath.Join(root, "a", "dep.txt"), "x")
	btWrite(t, filepath.Join(root, "node_modules", "lib", "dep.txt"), "x")
	btWrite(t, filepath.Join(root, "py", "lib", "site-packages", "lib", "dep.txt"), "x")
	btWrite(t, filepath.Join(root, "other.txt"), "x")
	btSymlink(t, filepath.Join(root, "a", "dep.txt"), filepath.Join(root, "in-file.txt"))
	btSymlink(t, "a", filepath.Join(root, "in-dir"))
	btSymlink(t, filepath.Join(outside, "dep.txt"), filepath.Join(root, "out-file.txt"))
	btSymlink(t, filepath.Join(outside, "pkg"), filepath.Join(root, "out-dir"))
	btSymlink(t, filepath.Join(root, "missing"), filepath.Join(root, "dangling.txt"))
	if err := os.MkdirAll(filepath.Join(root, "linked"), 0o755); err != nil {
		t.Fatal(err)
	}
	btSymlink(t, filepath.Join(outside, "pkg"), filepath.Join(root, "linked", "node_modules"))
	return root, outside
}

type btSeen struct {
	Symlink, Escapes, Skipped bool
}

// TestBuildTreeWalk_Parity: the walk enters everything but node_modules and site-packages
// (.git and build included), never follows a symlink, and flags the ones that leave root.
func TestBuildTreeWalk_Parity(t *testing.T) {
	root, _ := btTree(t)
	got := map[string]btSeen{}
	if err := buildTreeWalk(root, func(e buildTreeEntry, err error) error {
		if err != nil {
			t.Fatalf("walk %s: %v", e.Path, err)
		}
		rel, _ := filepath.Rel(root, e.Path)
		got[filepath.ToSlash(rel)] = btSeen{e.Symlink, e.Escapes, e.Skipped}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := map[string]btSeen{
		".":                    {},
		".git":                 {},
		".git/dep.txt":         {},
		"a":                    {},
		"a/dep.txt":            {},
		"build":                {},
		"build/dep.txt":        {},
		"dangling.txt":         {Symlink: true, Escapes: true},
		"dep.txt":              {},
		"in-dir":               {Symlink: true},
		"in-file.txt":          {Symlink: true},
		"linked":               {},
		"linked/node_modules":  {Symlink: true, Escapes: true, Skipped: true},
		"node_modules":         {Skipped: true},
		"other.txt":            {},
		"out-dir":              {Symlink: true, Escapes: true},
		"out-file.txt":         {Symlink: true, Escapes: true},
		"py":                   {},
		"py/lib":               {},
		"py/lib/site-packages": {Skipped: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("visited:\n%v\nwant:\n%v", got, want)
	}
}

// btUnread runs buildTreeWalk with buildTreeLinks over root and reports, as buildtree.Candidates
// does with a matcher that accepts nothing, every escaping symlink and every symlinked
// directory the walk does not read.
func btUnread(root string) []btRow {
	var got []btRow
	links := newBuildTreeLinks(root)
	_ = buildTreeWalk(root, func(e buildTreeEntry, err error) error {
		links.visit(e, err)
		rel, _ := filepath.Rel(root, e.Path)
		switch {
		case err != nil:
			got = append(got, btRow{filepath.ToSlash(rel), "unreadable"})
			if e.D != nil && e.D.IsDir() && e.Path != root {
				return filepath.SkipDir
			}
		case e.Symlink && e.Escapes:
			got = append(got, btRow{filepath.ToSlash(rel), "symlink leaves the build dir"})
		}
		return nil
	})
	for _, link := range links.unread() {
		rel, _ := filepath.Rel(root, link)
		got = append(got, btRow{filepath.ToSlash(rel), "symlinked directory the walk does not read"})
	}
	return got
}

type btRow struct{ Path, Why string }

// TestBuildTreeLinks_SymlinkedDirs: a symlinked directory inside root is read in full only
// through a target the walk itself enters at its real path.
func TestBuildTreeLinks_SymlinkedDirs(t *testing.T) {
	tests := []struct {
		name  string
		links map[string]string // link → target, relative to the link's directory
		want  []btRow
	}{
		{"lib64 to lib", map[string]string{".venv/lib64": "lib"}, nil},
		{"link to root", map[string]string{"self": "."}, nil},
		{"link through a linked directory", map[string]string{"a": ".venv", "b": "a/lib"}, nil},
		{"link into node_modules", map[string]string{"vendor": "node_modules/lib"},
			[]btRow{{"vendor", "symlinked directory the walk does not read"}}},
		{"link to node_modules", map[string]string{"deps": "node_modules"},
			[]btRow{{"deps", "symlinked directory the walk does not read"}}},
		{"link into site-packages", map[string]string{"pkgs": ".venv/lib/site-packages"},
			[]btRow{{"pkgs", "symlinked directory the walk does not read"}}},
		{"symlink cycle", map[string]string{"loop1": "loop2", "loop2": "loop1"},
			[]btRow{{"loop1", "symlink leaves the build dir"}, {"loop2", "symlink leaves the build dir"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			btWrite(t, filepath.Join(root, ".venv", "lib", "dep.txt"), "x")
			btWrite(t, filepath.Join(root, ".venv", "lib", "site-packages", "x", "dep.txt"), "x")
			btWrite(t, filepath.Join(root, "node_modules", "lib", "dep.txt"), "x")
			for link, target := range tt.links {
				btSymlink(t, target, filepath.Join(root, link))
			}
			if got := btUnread(root); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unread:\n%v\nwant:\n%v", got, tt.want)
			}
		})
	}
}

// TestBuildTreeLinks_LinkToUnreadable: a symlinked directory whose target the walk cannot list
// is not read through its target.
func TestBuildTreeLinks_LinkToUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	btWrite(t, filepath.Join(locked, "dep.txt"), "x")
	btSymlink(t, "locked", filepath.Join(root, "via"))
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	want := []btRow{{"locked", "unreadable"}, {"via", "symlinked directory the walk does not read"}}
	if got := btUnread(root); !reflect.DeepEqual(got, want) {
		t.Errorf("unread = %v, want %v", got, want)
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

// TestBuildTreeWalk_SkipRule pins the walk on a Python-shaped tree: only
// a directory named node_modules or site-packages is skipped, .git and every build, dot, venv
// and test directory are entered, and a symlink is never followed; one that leaves the root or
// does not resolve is reported as escaping.
func TestBuildTreeWalk_SkipRule(t *testing.T) {
	outside := t.TempDir()
	root := writeTree(t, map[string]string{
		"node_modules/pkg/install.sh":                    "x",
		"lib/python3.12/site-packages/black/__init__.py": "x",
		".git/hooks/post-checkout":                       "x",
		"build/docker/Dockerfile":                        "x",
		"dist/run.sh":                                    "x",
		".docker/Dockerfile":                             "x",
		"env/setup.sh":                                   "x",
		"venv/bin/activate":                              "x",
		"tests/fixtures/deploy.sh":                       "x",
		"app/main.py":                                    "x",
	})
	links := map[string]string{
		"out":      outside,
		"dangling": filepath.Join(root, "missing"),
		"inrepo":   filepath.Join(root, "app"),
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	visited := map[string]buildTreeEntry{}
	if err := buildTreeWalk(root, func(e buildTreeEntry, err error) error {
		if err != nil {
			t.Fatalf("walk error at %s: %v", e.Path, err)
		}
		rel, _ := filepath.Rel(root, e.Path)
		visited[filepath.ToSlash(rel)] = e
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{".git/hooks/post-checkout", "build/docker/Dockerfile", "dist/run.sh", ".docker/Dockerfile", "env/setup.sh", "venv/bin/activate", "tests/fixtures/deploy.sh", "app/main.py"} {
		if _, ok := visited[want]; !ok {
			t.Errorf("%s must be walked", want)
		}
	}
	for rel := range visited {
		if strings.HasPrefix(rel, "node_modules/") || strings.Contains(rel, "site-packages/") {
			t.Errorf("%s is inside a skipped directory and must not be walked", rel)
		}
	}
	for _, dir := range []string{"node_modules", "lib/python3.12/site-packages"} {
		if e, ok := visited[dir]; !ok || !e.Skipped {
			t.Errorf("%s must be visited once as skipped; got %+v", dir, e)
		}
	}
	for name, escapes := range map[string]bool{"out": true, "dangling": true, "inrepo": false} {
		e, ok := visited[name]
		if !ok || !e.Symlink || e.Escapes != escapes {
			t.Errorf("symlink %s: got %+v, want Symlink and Escapes=%v", name, e, escapes)
		}
	}
	if _, ok := visited["inrepo/main.py"]; ok {
		t.Errorf("a symlinked directory must not be followed")
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
