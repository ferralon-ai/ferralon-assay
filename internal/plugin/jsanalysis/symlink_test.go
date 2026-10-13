//go:build unix

package jsanalysis

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestInstalledCopies_SymlinkedEntries: a symlink installedCopies meets (a node_modules, a
// package or @scope entry, a nested node_modules, a .pnpm entry) is read at its target when
// that resolves inside the build dir, whatever the target is named or wherever it lies, and
// leaves the copies unread when it leaves the build dir or does not resolve. Each package and
// node_modules directory counts once, so a pnpm link and a link cycle read each copy once.
func TestInstalledCopies_SymlinkedEntries(t *testing.T) {
	pkg := func(name, v string) string { return `{"name":"` + name + `","version":"` + v + `"}` }
	cases := []struct {
		name     string
		files    map[string]string
		links    map[string]string // link -> target; "OUTSIDE" stands for a directory outside the build dir
		copies   []string          // the name@version copies installedCopies reads, sorted
		ok       bool
		resolved bool // express resolves to 4.18.2 (else unresolved)
	}{
		{name: "real packages", copies: []string{"express@4.18.2", "left-pad@1.3.0"}, ok: true, resolved: true},
		{name: "a package linked into a dot directory under node_modules",
			files: map[string]string{"node_modules/express/package.json": "\x00omit", "node_modules/.store/express/package.json": pkg("express", "4.17.0")},
			links: map[string]string{"node_modules/express": ".store/express"}, copies: []string{"express@4.17.0", "left-pad@1.3.0"}, ok: true},
		{name: "a package linked into a site-packages directory",
			files: map[string]string{"node_modules/express/package.json": "\x00omit", "site-packages/express/package.json": pkg("express", "4.17.0")},
			links: map[string]string{"node_modules/express": "../site-packages/express"}, copies: []string{"express@4.17.0", "left-pad@1.3.0"}, ok: true},
		{name: "a package linked into another package",
			files: map[string]string{"node_modules/express/package.json": "\x00omit", "node_modules/left-pad/dist/express/package.json": pkg("express", "4.17.0")},
			links: map[string]string{"node_modules/express": "left-pad/dist/express"}, copies: []string{"express@4.17.0", "left-pad@1.3.0"}, ok: true},
		{name: "a scoped package linked into a dot directory under node_modules",
			files: map[string]string{"node_modules/.store/core/package.json": pkg("@x/core", "1.0.0")},
			links: map[string]string{"node_modules/@x/core": "../.store/core"}, copies: []string{"@x/core@1.0.0", "express@4.18.2", "left-pad@1.3.0"}, ok: true, resolved: true},
		{name: "a nested node_modules linked out of node_modules",
			files: map[string]string{"vendor/nm/express/package.json": pkg("express", "4.17.0")},
			links: map[string]string{"node_modules/left-pad/node_modules": "../../vendor/nm"}, copies: []string{"express@4.17.0", "express@4.18.2", "left-pad@1.3.0"}, ok: true},
		{name: "node_modules linked to a directory with another name",
			files: map[string]string{"node_modules/express/package.json": "\x00omit", "node_modules/left-pad/package.json": "\x00omit", "deps/express/package.json": pkg("express", "4.17.0")},
			links: map[string]string{"node_modules": "deps"}, copies: []string{"express@4.17.0"}, ok: true},
		{name: "a pnpm link is read once",
			files: map[string]string{"node_modules/express/package.json": "\x00omit", "node_modules/.pnpm/express@4.18.2/node_modules/express/package.json": pkg("express", "4.18.2")},
			links: map[string]string{"node_modules/express": ".pnpm/express@4.18.2/node_modules/express"}, copies: []string{"express@4.18.2", "left-pad@1.3.0"}, ok: true, resolved: true},
		{name: "a link cycle is read once",
			links: map[string]string{"node_modules/left-pad/node_modules": ".."}, copies: []string{"express@4.18.2", "left-pad@1.3.0"}, ok: true, resolved: true},
		{name: "a package linked outside the build dir", files: map[string]string{"node_modules/express/package.json": "\x00omit"},
			links: map[string]string{"node_modules/express": "OUTSIDE"}, copies: []string{"left-pad@1.3.0"}, ok: false},
		{name: "a dangling package link", files: map[string]string{"node_modules/express/package.json": "\x00omit"},
			links: map[string]string{"node_modules/express": "../missing"}, copies: []string{"left-pad@1.3.0"}, ok: false},
		{name: "node_modules linked outside the build dir", files: map[string]string{"node_modules/express/package.json": "\x00omit", "node_modules/left-pad/package.json": "\x00omit"},
			links: map[string]string{"node_modules": "OUTSIDE"}, ok: false},
		{name: "a dangling node_modules link", files: map[string]string{"node_modules/express/package.json": "\x00omit", "node_modules/left-pad/package.json": "\x00omit"},
			links: map[string]string{"node_modules": "missing"}, ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{
				"package.json": exPkgJSON, "package-lock.json": exLockV3,
				"node_modules/express/package.json":  pkg("express", "4.18.2"),
				"node_modules/left-pad/package.json": pkg("left-pad", "1.3.0"),
			}
			for k, v := range tc.files {
				if v == "\x00omit" {
					delete(files, k)
					continue
				}
				files[k] = v
			}
			dir := writeLockTree(t, files)
			for link, target := range tc.links {
				if target == "OUTSIDE" {
					target = filepath.Join(t.TempDir(), "outside")
					if err := os.MkdirAll(filepath.Join(target, "express"), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(target, "package.json"), []byte(pkg("express", "4.17.0")), 0o644); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(target, "express", "package.json"), []byte(pkg("express", "4.17.0")), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				p := filepath.Join(dir, filepath.FromSlash(link))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.FromSlash(target), p); err != nil {
					t.Skipf("symlink: %v", err)
				}
			}
			copies, ok := installedCopies(dir)
			var got []string
			for _, c := range copies {
				got = append(got, c.Coordinate+"@"+c.Version)
			}
			slices.Sort(got)
			if ok != tc.ok || !slices.Equal(got, tc.copies) {
				t.Errorf("installedCopies = %v, ok %v; want %v, ok %v", got, ok, tc.copies, tc.ok)
			}
			res := resolveJS(t, dir, "express")
			if got := res.Match.Resolved && res.Match.Version == "4.18.2" && res.Partiality.Complete; got != tc.resolved {
				t.Errorf("express = %+v %+v; want resolved and complete %v", res.Match, res.Partiality, tc.resolved)
			}
		})
	}
}
