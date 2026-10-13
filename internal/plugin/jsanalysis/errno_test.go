//go:build unix

package jsanalysis

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// denied returns a path inside a fresh directory no one but root can search, so a stat of it
// fails with EACCES. The directory is made searchable again before the temp dir is removed.
func denied(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	d := t.TempDir()
	deny(t, d)
	return filepath.Join(d, "x")
}

// deny strips every permission from the directory at path except, with keepRead, listing it.
func deny(t *testing.T, path string, keepRead ...bool) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	mode := os.FileMode(0)
	if len(keepRead) > 0 && keepRead[0] {
		mode = 0o444
	}
	if err := os.Chmod(path, mode); err != nil {
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

// dangle makes rel under dir a symlink to a path that does not exist.
func dangle(t *testing.T, dir, rel string) {
	t.Helper()
	link(t, dir, rel, "gone")
}

// mkdir creates the directory rel under dir.
func mkdir(t *testing.T, dir, rel string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(rel)), 0o755); err != nil {
		t.Fatal(err)
	}
}

// wantErr fails the row unless stat (os.Stat, or os.Lstat with lstat) of rel under dir fails
// with want: the fixture must produce the error class the row is about.
func wantErr(t *testing.T, dir, rel string, want error, lstat ...bool) {
	t.Helper()
	stat := os.Stat
	if len(lstat) > 0 && lstat[0] {
		stat = os.Lstat
	}
	if _, err := stat(filepath.Join(dir, filepath.FromSlash(rel))); !errors.Is(err, want) {
		t.Fatalf("stat %s: %v, want %v", rel, err, want)
	}
}

// TestFSErrors_NotAbsent: at every call site that reads a missing path as absent, an error
// other than a missing path (a permission error, a symlink loop) leaves the path unread, and
// the claim absence would support is withheld. A path that is genuinely missing (here a
// dangling symlink, which the same call reports as not existing) stays absent and the claim
// stands.
func TestFSErrors_NotAbsent(t *testing.T) {
	const js = "module.exports = function a() {}\n"
	lockTree := map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range lockTree {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	// exhaustive checks that Exhaustive (the refutation of absent-package) is want.
	exhaustive := func(want bool) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			if r := resolveJS(t, dir, "absent-package"); r.Exhaustive != want {
				t.Errorf("Exhaustive = %v, want %v (partiality %+v)", r.Exhaustive, want, r.Partiality)
			}
		}
	}
	const pnpmID = "node_modules/.pnpm/absent-package@1.0.0"
	pnpmCopy := map[string]string{pnpmID + "/node_modules/absent-package/package.json": `{"name":"absent-package","version":"1.0.0"}`}
	express := map[string]string{"node_modules/express/package.json": `{"name":"express"}`}

	tsconfig := func(wantFailed bool) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			prog := mustLoad(t, dir)
			if prog == nil {
				return
			}
			if ts := prog.resolver().governingTsconfig("a.js"); ts != nil || prog.readFailed != wantFailed {
				t.Errorf("tsconfig = %+v, readFailed = %v; want none, readFailed = %v", ts, prog.readFailed, wantFailed)
			}
		}
	}
	members := func(fault func(t *testing.T, dir string), wantFailed bool) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			prog := mustLoad(t, dir)
			if prog == nil {
				return
			}
			fault(t, dir) // after loadProgram, whose own walk fails on an unreadable directory
			if dirs := prog.resolver().workspaceMemberDirs([]string{"packages/*"}); len(dirs) != 0 || prog.readFailed != wantFailed {
				t.Errorf("members = %v, readFailed = %v; want none, readFailed = %v", dirs, prog.readFailed, wantFailed)
			}
		}
	}
	copiesRead := func(sub string, want bool) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			if _, ok := installedCopies(filepath.Join(dir, sub)); ok != want {
				t.Errorf("installedCopies ok = %v, want %v", ok, want)
			}
		}
	}
	rootsRead := func(sub string, want bool) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			if _, read := discoverProjectRoots(filepath.Join(dir, sub)); read != want {
				t.Errorf("discoverProjectRoots read = %v, want %v", read, want)
			}
		}
	}
	inventoryFailed := func(want bool) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
			if err != nil || inv.Partiality.Complete || hasToolFailure(inv.Partiality) != want {
				t.Errorf("inventory partiality = %+v, %v; want partial, tool_failure = %v", inv.Partiality, err, want)
			}
		}
	}
	manifestsRead := func(sub string, want bool) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			if _, complete := manifestsUnder(filepath.Join(dir, sub)); complete != want {
				t.Errorf("manifestsUnder complete = %v, want %v", complete, want)
			}
		}
	}
	buildManifest := func(wantCommand string) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if len(res.Resolvers) == 1 {
				got = res.Resolvers[0].Command
			}
			if wantCommand == "" && (!hasToolFailure(res.Partiality) || len(res.Resolvers) != 0) {
				t.Errorf("BuildManifest = %+v; want tool_failure and no install command", res)
			}
			if wantCommand != "" && (!res.Partiality.Complete || got != wantCommand) {
				t.Errorf("BuildManifest = %+v; want Complete with %q", res, wantCommand)
			}
		}
	}

	type row struct {
		name  string
		files map[string]string
		fault func(t *testing.T, dir string)
		check func(t *testing.T, dir string)
	}
	sites := []struct {
		site string
		rows []row
	}{
		{"installedPackage package dir", []row{
			{"EACCES", with(map[string]string{"node_modules/absent-package/package.json": `{"name":"absent-package"}`}), func(t *testing.T, dir string) {
				deny(t, filepath.Join(dir, "node_modules"), true) // listable, not searchable
				wantErr(t, dir, "node_modules/absent-package", os.ErrPermission)
			}, exhaustive(false)},
			{"ELOOP", lockTree, func(t *testing.T, dir string) {
				loop(t, dir, "node_modules/absent-package")
				wantErr(t, dir, "node_modules/absent-package", syscall.ELOOP)
			}, exhaustive(false)},
			{"missing", lockTree, func(t *testing.T, dir string) {
				dangle(t, dir, "node_modules/absent-package")
			}, exhaustive(true)},
		}},
		{"installedPackages pnpm store entry", []row{
			{"EACCES", with(pnpmCopy), func(t *testing.T, dir string) {
				deny(t, filepath.Join(dir, filepath.FromSlash(pnpmID)))
				wantErr(t, dir, pnpmID+"/node_modules", os.ErrPermission)
			}, exhaustive(false)},
			{"ELOOP", lockTree, func(t *testing.T, dir string) {
				loop(t, dir, pnpmID)
				wantErr(t, dir, pnpmID+"/node_modules", syscall.ELOOP)
			}, exhaustive(false)},
			{"missing", lockTree, func(t *testing.T, dir string) {
				mkdir(t, dir, pnpmID)
			}, exhaustive(true)},
		}},
		{"installedPackage nested node_modules", []row{
			{"EACCES", with(express), func(t *testing.T, dir string) {
				link(t, dir, "node_modules/express/node_modules", denied(t))
				wantErr(t, dir, "node_modules/express/node_modules", os.ErrPermission)
			}, exhaustive(false)},
			{"ELOOP", with(express), func(t *testing.T, dir string) {
				loop(t, dir, "node_modules/express/node_modules")
				wantErr(t, dir, "node_modules/express/node_modules", syscall.ELOOP)
			}, exhaustive(false)},
			{"missing", with(express), func(t *testing.T, dir string) {
				dangle(t, dir, "node_modules/express/node_modules")
			}, exhaustive(true)},
		}},
		{"governingTsconfig", []row{
			{"EACCES", map[string]string{"a.js": js}, func(t *testing.T, dir string) {
				link(t, dir, "tsconfig.json", denied(t))
				wantErr(t, dir, "tsconfig.json", os.ErrPermission)
			}, tsconfig(true)},
			{"ELOOP", map[string]string{"a.js": js}, func(t *testing.T, dir string) {
				loop(t, dir, "tsconfig.json")
				wantErr(t, dir, "tsconfig.json", syscall.ELOOP)
			}, tsconfig(true)},
			{"missing", map[string]string{"a.js": js}, func(t *testing.T, dir string) {
				dangle(t, dir, "tsconfig.json")
			}, tsconfig(false)},
		}},
		{"workspaceMemberDirs", []row{
			{"EACCES", map[string]string{"a.js": js, "packages/b/package.json": `{"name":"b"}`}, nil, members(func(t *testing.T, dir string) {
				deny(t, filepath.Join(dir, "packages"))
				if _, err := os.ReadDir(filepath.Join(dir, "packages")); !errors.Is(err, os.ErrPermission) {
					t.Fatalf("readdir packages: %v, want EACCES", err)
				}
			}, true)},
			{"ELOOP", map[string]string{"a.js": js}, func(t *testing.T, dir string) {
				loop(t, dir, "packages")
				wantErr(t, dir, "packages", syscall.ELOOP)
			}, members(func(*testing.T, string) {}, true)},
			{"missing", map[string]string{"a.js": js}, nil, members(func(*testing.T, string) {}, false)},
		}},
		{"installedCopies walk", []row{
			{"EACCES", map[string]string{"web/node_modules/absent-package/package.json": `{"name":"absent-package","version":"1.0.0"}`}, func(t *testing.T, dir string) {
				deny(t, filepath.Join(dir, "web"))
			}, copiesRead("", false)},
			{"missing", nil, nil, copiesRead("missing", true)},
		}},
		{"installedCopies pnpm store entry", []row{
			{"EACCES", pnpmCopy, func(t *testing.T, dir string) {
				deny(t, filepath.Join(dir, filepath.FromSlash(pnpmID)))
				wantErr(t, dir, pnpmID+"/node_modules", os.ErrPermission, true)
			}, copiesRead("", false)},
			{"missing", nil, func(t *testing.T, dir string) {
				mkdir(t, dir, pnpmID)
			}, copiesRead("", true)},
		}},
		{"discoverProjectRoots walk", []row{
			{"EACCES", map[string]string{"package.json": `{"name":"app"}`, "package-lock.json": `{"lockfileVersion":3,"packages":{"":{"name":"app"}}}`, "web/package-lock.json": `{"lockfileVersion":3,"packages":{"":{}}}`}, func(t *testing.T, dir string) {
				deny(t, filepath.Join(dir, "web"))
			}, rootsRead("", false)},
			{"missing", nil, nil, rootsRead("missing", true)},
		}},
		{"discoverProjectRoots package.json", []row{
			{"EACCES", nil, func(t *testing.T, dir string) {
				link(t, dir, "package.json", denied(t))
				wantErr(t, dir, "package.json", os.ErrPermission)
			}, inventoryFailed(true)},
			{"ELOOP", nil, func(t *testing.T, dir string) {
				loop(t, dir, "package.json")
				wantErr(t, dir, "package.json", syscall.ELOOP)
			}, inventoryFailed(true)},
			{"missing", nil, func(t *testing.T, dir string) {
				dangle(t, dir, "package.json")
			}, inventoryFailed(false)},
		}},
		{"manifestsUnder walk", []row{
			{"EACCES", map[string]string{"package.json": `{"name":"app"}`, "packages/a/package.json": `{"name":"a"}`}, func(t *testing.T, dir string) {
				deny(t, filepath.Join(dir, "packages"))
			}, manifestsRead("", false)},
			{"missing", nil, nil, manifestsRead("missing", true)},
		}},
		{"installCommand lockfile", []row{
			{"EACCES", map[string]string{"package.json": `{"name":"app"}`}, func(t *testing.T, dir string) {
				link(t, dir, "package-lock.json", denied(t))
				wantErr(t, dir, "package-lock.json", os.ErrPermission)
			}, buildManifest("")},
			{"ELOOP", map[string]string{"package.json": `{"name":"app"}`}, func(t *testing.T, dir string) {
				loop(t, dir, "package-lock.json")
				wantErr(t, dir, "package-lock.json", syscall.ELOOP)
			}, buildManifest("")},
			{"missing", map[string]string{"package.json": `{"name":"app"}`}, func(t *testing.T, dir string) {
				dangle(t, dir, "package-lock.json")
			}, buildManifest("npm install")},
		}},
	}
	for _, s := range sites {
		t.Run(s.site, func(t *testing.T) {
			for _, r := range s.rows {
				t.Run(r.name, func(t *testing.T) {
					files := map[string]string{}
					for k, v := range r.files {
						files[k] = v
					}
					dir := writeLockTree(t, files)
					if r.fault != nil {
						r.fault(t, dir)
					}
					r.check(t, dir)
				})
			}
		})
	}
}
