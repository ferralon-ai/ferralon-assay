//go:build unix

package pythonanalysis

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// denied returns a path inside a fresh directory no one but root can search, so a stat of it
// fails with EACCES. The directory is made searchable again before the temp dir is removed.
func denied(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	deny(t, d)
	return filepath.Join(d, "x")
}

// deny strips every permission from the directory at path.
func deny(t *testing.T, path string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o755) })
}

// link places a symlink to target at rel under dir.
func link(t *testing.T, dir, rel, target string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Skipf("symlink: %v", err)
	}
}

// loop makes rel under dir a symlink to itself, so following it fails with ELOOP.
func loop(t *testing.T, dir, rel string) {
	t.Helper()
	link(t, dir, rel, filepath.Base(rel))
}

// notDir makes rel under dir a symlink through a regular file, so following it fails with
// ENOTDIR: a path that is not there.
func notDir(t *testing.T, dir, rel string) {
	t.Helper()
	placeFiles(t, dir, map[string]string{"afile": ""})
	link(t, dir, rel, filepath.Join("afile", "x"))
}

// wantErr fails the row unless following rel under dir fails with want: the fixture must
// produce the error class the row is about. list lists the path as a directory instead of
// stating it.
func wantErr(t *testing.T, dir, rel string, want error, list ...bool) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	var err error
	if len(list) > 0 && list[0] {
		_, err = os.ReadDir(p)
	} else {
		_, err = os.Stat(p)
	}
	if !errors.Is(err, want) {
		t.Fatalf("%s: %v, want %v", rel, err, want)
	}
}

// TestFSErrors_NotAbsent: at every call site that reads a missing path as absent, an error
// other than a missing path (a permission error, a symlink loop) leaves the path unread, and
// the claim absence would support is withheld. A path that is genuinely missing stays absent
// and the claim stands.
func TestFSErrors_NotAbsent(t *testing.T) {
	ctx := context.Background()
	const reqs = "jinja2==3.1.2\n"
	// lockedSub is a subdirectory holding a lockfile, made unreadable by the EACCES rows.
	lockedSub := func(t *testing.T, dir string) {
		placeFiles(t, dir, map[string]string{"sub/uv.lock": "version = 1\n"})
		deny(t, filepath.Join(dir, "sub"))
		wantErr(t, dir, "sub", syscall.EACCES, true)
	}

	// manifestsRead checks manifestFiles' read result.
	manifestsRead := func(want bool) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			if _, read := manifestFiles(dir); read != want {
				t.Errorf("manifestFiles read = %v, want %v", read, want)
			}
		}
	}
	// inventoryFailed checks whether ResolveInventory reports tool_failure.
	inventoryFailed := func(want bool) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			inv, err := ResolveInventory(ctx, plugin.ResolveInventoryRequest{BuildDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			if got := slices.Contains(inv.Partiality.Reasons, plugin.PartialReasonToolFailure); got != want || inv.Partiality.Complete == want {
				t.Errorf("inventory partiality = %+v, want tool_failure %v", inv.Partiality, want)
			}
		}
	}
	// resolver checks detectResolver: unread with no resolver, or read with one.
	resolver := func(wantRead bool) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			spec, read := detectResolver(dir)
			if read != wantRead || (spec.Name != "") != wantRead {
				t.Errorf("detectResolver = %+v, %v; want read %v", spec, read, wantRead)
			}
		}
	}
	// manifestFailed checks whether BuildManifest reports tool_failure, and that it then
	// names no resolver.
	manifestFailed := func(want bool) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			res, err := BuildManifest(ctx, plugin.BuildManifestRequest{BuildDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			if got := hasToolFailure(res.Partiality); got != want || (len(res.Resolvers) == 0) != want {
				t.Errorf("BuildManifest partiality = %+v, resolvers %+v; want tool_failure %v", res.Partiality, res.Resolvers, want)
			}
		}
	}
	// constraintsRead checks constraintFiles' read result for rel under dir.
	constraintsRead := func(rel string, want bool) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			if _, read := constraintFiles(filepath.Join(dir, rel)); read != want {
				t.Errorf("constraintFiles read = %v, want %v", read, want)
			}
		}
	}
	// declaredRead checks a declared-interpreter reader's read result.
	declaredRead := func(read func(string) bool, want bool) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			if got := read(dir); got != want {
				t.Errorf("read = %v, want %v", got, want)
			}
		}
	}
	pyproject := func(dir string) bool { _, r := readPyprojectMeta(dir); return r }
	lockPython := func(dir string) bool { _, r := lockfileRequiresPython(dir); return r }
	pin := func(dir string) bool { _, r := readPythonVersionPin(dir); return r }

	type row struct {
		name  string
		files map[string]string
		fault func(t *testing.T, dir string)
		check func(t *testing.T, dir string)
	}
	// declaredRows are the rows for a reader that follows the declared file at rel.
	declaredRows := func(rel string, read func(string) bool) []row {
		return []row{
			{name: "EACCES", fault: func(t *testing.T, dir string) {
				link(t, dir, rel, denied(t))
				wantErr(t, dir, rel, syscall.EACCES)
			}, check: declaredRead(read, false)},
			{name: "ELOOP", fault: func(t *testing.T, dir string) {
				loop(t, dir, rel)
				wantErr(t, dir, rel, syscall.ELOOP)
			}, check: declaredRead(read, false)},
			{name: "ENOTDIR is absent", fault: func(t *testing.T, dir string) {
				notDir(t, dir, rel)
				wantErr(t, dir, rel, syscall.ENOTDIR)
			}, check: declaredRead(read, true)},
			{name: "missing is absent", check: declaredRead(read, true)},
		}
	}

	sites := []struct {
		site string
		rows []row
	}{
		{"manifestFiles walk", []row{
			{name: "EACCES", files: map[string]string{"requirements.txt": reqs}, fault: lockedSub, check: manifestsRead(false)},
			{name: "missing root is absent", fault: func(t *testing.T, dir string) {
				if err := os.Remove(dir); err != nil {
					t.Fatal(err)
				}
			}, check: manifestsRead(true)},
		}},
		{"ResolveInventory", []row{
			{name: "EACCES", files: map[string]string{"requirements.txt": reqs}, fault: lockedSub, check: inventoryFailed(true)},
			{name: "missing subdirectory", files: map[string]string{"requirements.txt": reqs}, check: inventoryFailed(false)},
		}},
		{"detectResolver", []row{
			{name: "EACCES", files: map[string]string{"requirements.txt": reqs}, fault: lockedSub, check: resolver(false)},
			{name: "missing subdirectory", files: map[string]string{"requirements.txt": reqs}, check: resolver(true)},
		}},
		{"BuildManifest resolver", []row{
			{name: "EACCES", files: map[string]string{"requirements.txt": reqs, ".python-version": "3.12.1\n"}, fault: lockedSub, check: manifestFailed(true)},
			{name: "missing subdirectory", files: map[string]string{"requirements.txt": reqs, ".python-version": "3.12.1\n"}, check: manifestFailed(false)},
		}},
		{"constraintFiles", []row{
			{name: "EACCES", fault: func(t *testing.T, dir string) {
				link(t, dir, "build", denied(t))
				wantErr(t, dir, "build", syscall.EACCES, true)
			}, check: constraintsRead("build", false)},
			{name: "ELOOP", fault: func(t *testing.T, dir string) {
				loop(t, dir, "build")
				wantErr(t, dir, "build", syscall.ELOOP, true)
			}, check: constraintsRead("build", false)},
			{name: "ENOTDIR is absent", fault: func(t *testing.T, dir string) {
				notDir(t, dir, "build")
				wantErr(t, dir, "build", syscall.ENOTDIR, true)
			}, check: constraintsRead("build", true)},
			{name: "missing is absent", check: constraintsRead("build", true)},
		}},
		{"readPyprojectMeta", declaredRows("pyproject.toml", pyproject)},
		{"lockfileRequiresPython uv.lock", declaredRows("uv.lock", lockPython)},
		{"lockfileRequiresPython pdm.lock", declaredRows("pdm.lock", lockPython)},
		{"readPythonVersionPin", declaredRows(".python-version", pin)},
	}
	for _, s := range sites {
		t.Run(s.site, func(t *testing.T) {
			for _, r := range s.rows {
				t.Run(r.name, func(t *testing.T) {
					dir := t.TempDir()
					placeFiles(t, dir, r.files)
					if r.fault != nil {
						r.fault(t, dir)
					}
					r.check(t, dir)
				})
			}
		})
	}
}
