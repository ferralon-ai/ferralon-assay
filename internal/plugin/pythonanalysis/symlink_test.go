//go:build unix

package pythonanalysis

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// symlinkAt places a symlink to target at rel under dir. A target starting with "/" is taken
// as given; any other is relative to the link.
func symlinkAt(t *testing.T, dir, rel, target string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.FromSlash(target), p); err != nil {
		t.Skipf("symlink: %v", err)
	}
}

// TestInstalledCopies_SymlinkedSitePackages: a symlinked site-packages, or a symlinked entry in
// one, is read at its target when that resolves inside the build dir, whatever the target is
// named, and leaves the copies unread when it leaves the build dir or does not resolve. Each
// directory and metadata entry counts once.
func TestInstalledCopies_SymlinkedSitePackages(t *testing.T) {
	const reqs = "jinja2==3.1.2\n"
	meta := func(v string) string { return "Metadata-Version: 2.1\nName: Jinja2\nVersion: " + v + "\n" }
	cases := []struct {
		name     string
		files    map[string]string
		links    map[string]string // link -> target; "OUTSIDE" stands for a directory outside the build dir
		copies   []string          // the versions installedCopies reads, sorted
		ok       bool
		resolved string // the jinja2 match: a version resolved and complete, or "" for unresolved
	}{
		{name: "a real site-packages", files: map[string]string{"lib/site-packages/jinja2-3.1.2.dist-info/METADATA": meta("3.1.2")},
			copies: []string{"3.1.2"}, ok: true, resolved: "3.1.2"},
		{name: "site-packages linked to an in-tree directory with another name",
			files: map[string]string{"vendor/lib/jinja2-2.10.dist-info/METADATA": meta("2.10")},
			links: map[string]string{"lib/site-packages": "../vendor/lib"}, copies: []string{"2.10"}, ok: true},
		{name: "site-packages linked to another site-packages is read once",
			files: map[string]string{".venv/lib/python3.12/site-packages/jinja2-3.1.2.dist-info/METADATA": meta("3.1.2")},
			links: map[string]string{"lib/site-packages": "../.venv/lib/python3.12/site-packages"}, copies: []string{"3.1.2"}, ok: true, resolved: "3.1.2"},
		{name: "site-packages linked outside the build dir", links: map[string]string{"lib/site-packages": "OUTSIDE"}, ok: false},
		{name: "a dangling site-packages link", links: map[string]string{"lib/site-packages": "../missing"}, ok: false},
		{name: "a dist-info linked to an in-tree directory outside any site-packages",
			files: map[string]string{"lib/site-packages/.keep": "", "vendor/jinja2-2.10.dist-info/METADATA": meta("2.10")},
			links: map[string]string{"lib/site-packages/jinja2-2.10.dist-info": "../../vendor/jinja2-2.10.dist-info"}, copies: []string{"2.10"}, ok: true},
		{name: "a dist-info linked to a sibling is read once",
			files: map[string]string{"lib/site-packages/jinja2-3.1.2.dist-info/METADATA": meta("3.1.2")},
			links: map[string]string{"lib/site-packages/linked.dist-info": "jinja2-3.1.2.dist-info"}, copies: []string{"3.1.2"}, ok: true, resolved: "3.1.2"},
		{name: "a dist-info linked outside the build dir", files: map[string]string{"lib/site-packages/.keep": ""},
			links: map[string]string{"lib/site-packages/jinja2-2.10.dist-info": "OUTSIDE"}, ok: false},
		{name: "a dangling dist-info link", files: map[string]string{"lib/site-packages/.keep": ""},
			links: map[string]string{"lib/site-packages/jinja2-2.10.dist-info": "../missing"}, ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"requirements.txt": reqs}
			for k, v := range tc.files {
				files[k] = v
			}
			dir := writeTree(t, files)
			for link, target := range tc.links {
				if target == "OUTSIDE" {
					target = writeTree(t, map[string]string{"jinja2-2.10.dist-info/METADATA": meta("2.10"), "METADATA": meta("2.10")})
				}
				symlinkAt(t, dir, link, target)
			}
			copies, _, ok := installedCopies(dir)
			var got []string
			for _, c := range copies {
				got = append(got, c.Version)
			}
			slices.Sort(got)
			if ok != tc.ok || !slices.Equal(got, tc.copies) {
				t.Errorf("installedCopies = %v, ok %v; want %v, ok %v", got, ok, tc.copies, tc.ok)
			}
			res := resolveVersion(t, dir, "jinja2")
			if tc.resolved != "" {
				if !res.Match.Resolved || res.Match.Version != tc.resolved || !res.Partiality.Complete {
					t.Errorf("jinja2 = %+v %+v; want %s resolved and complete", res.Match, res.Partiality, tc.resolved)
				}
			} else if res.Match.Resolved {
				t.Errorf("jinja2 = %+v %+v; want unresolved", res.Match, res.Partiality)
			}
		})
	}
}

// TestManifestFiles_SymlinkedDirectories: the manifest walk does not follow a symlinked
// directory, so one counts as read only when its target is a directory the walk itself reads.
// A link leaving the build dir, or to a directory the walk skips, leaves the walk unread and
// the inventory incomplete.
func TestManifestFiles_SymlinkedDirectories(t *testing.T) {
	const svc = "requirements.txt"
	cases := []struct {
		name   string
		files  map[string]string
		links  map[string]string // link -> target; "OUTSIDE" stands for a directory outside the build dir
		listed int
		read   bool
	}{
		{name: "no links", files: map[string]string{"svc/requirements.txt": "flask==3.0.0\n"}, listed: 2, read: true},
		{name: "a link to an in-tree directory the walk reads", files: map[string]string{"services/svc/requirements.txt": "flask==3.0.0\n"},
			links: map[string]string{"svc": "services/svc"}, listed: 2, read: true},
		{name: "a link leaving the build dir", links: map[string]string{"svc": "OUTSIDE"}, listed: 1, read: false},
		{name: "a link to a directory the walk skips", files: map[string]string{"build/svc/requirements.txt": "flask==3.0.0\n"},
			links: map[string]string{"svc": "build/svc"}, listed: 1, read: false},
		{name: "a link to a regular file is a manifest", files: map[string]string{"deps/reqs.txt": "flask==3.0.0\n"},
			links: map[string]string{"svc/requirements.txt": "../deps/reqs.txt"}, listed: 2, read: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{svc: "jinja2==3.1.2\n"}
			for k, v := range tc.files {
				files[k] = v
			}
			dir := writeTree(t, files)
			for link, target := range tc.links {
				if target == "OUTSIDE" {
					target = writeTree(t, map[string]string{"uv.lock": "version = 1\n", "requirements.txt": "flask==3.0.0\n"})
				}
				symlinkAt(t, dir, link, target)
			}
			paths, read := manifestFiles(dir)
			if len(paths) != tc.listed || read != tc.read {
				t.Errorf("manifestFiles = %v, read %v; want %d paths, read %v", paths, read, tc.listed, tc.read)
			}
			inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			if inv.Partiality.Complete != tc.read {
				t.Errorf("inventory partiality = %+v, want complete %v", inv.Partiality, tc.read)
			}
		})
	}
}
