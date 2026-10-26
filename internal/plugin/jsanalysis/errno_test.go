//go:build unix

package jsanalysis

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
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

// pathMax is the longest path the platform's stat accepts.
var pathMax = map[bool]int{true: 1024, false: 4096}[runtime.GOOS == "darwin"]

// deepLink makes rel under dir a symlink to a directory whose real path is realLen bytes long,
// reached through a chain of short links, so the kernel follows paths through it that are far
// shorter than their real paths. It returns a short path to that directory.
func deepLink(t *testing.T, dir, rel string, realLen int) string {
	t.Helper()
	mkdir(t, dir, ".deep")
	at, via := filepath.Join(dir, ".deep"), ".deep"
	real, err := filepath.EvalSymlinks(at)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; len(real) < realLen; i++ {
		name := fmt.Sprintf("%03d", i)
		name += strings.Repeat("d", min(200, realLen-len(real)-1)-len(name))
		if err := os.Mkdir(filepath.Join(at, name), 0o755); err != nil {
			t.Fatal(err)
		}
		s := fmt.Sprintf("s%d", i)
		if err := os.Symlink(name, filepath.Join(at, s)); err != nil {
			t.Skipf("symlink: %v", err)
		}
		at, via, real = filepath.Join(at, s), via+"/"+s, real+"/"+name
	}
	link(t, dir, rel, via)
	return at
}

// noCopyAbove fails the test when an ancestor of dir, logical or real, holds a candidate for
// package name in its node_modules, or a node_modules that cannot be searched: a walk that
// climbs past the build root would find it, and a row expecting no copy would not test that.
func noCopyAbove(t *testing.T, dir, name string) {
	t.Helper()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, start := range []string{dir, real} {
		for d := filepath.Dir(start); ; d = filepath.Dir(d) {
			for _, c := range []string{name, name + ".js", name + ".json", name + ".node"} {
				p := filepath.Join(d, "node_modules", c)
				if _, err := os.Lstat(p); err == nil || !absent(err) {
					t.Fatalf("%s (%v) is above the test's build root: remove it or set TMPDIR elsewhere", p, err)
				}
			}
			if filepath.Dir(d) == d {
				break
			}
		}
	}
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

// physicallyDeep returns a short path under dir to a directory whose real path is longer
// than PATH_MAX: each level is a short symlink to a long sibling directory, so the kernel
// resolves the short path one link at a time, but resolving its real path as a string fails
// with ENAMETOOLONG.
func physicallyDeep(t *testing.T, dir string) string {
	t.Helper()
	comp := strings.Repeat("d", 250)
	logical := ""
	for i := 0; i < 20; i++ {
		mkdir(t, dir, path.Join(logical, comp))
		link(t, dir, path.Join(logical, "l"), comp)
		logical = path.Join(logical, "l")
	}
	return filepath.Join(dir, filepath.FromSlash(logical))
}

// wantListErr fails the row unless listing the directory rel under dir fails with want.
func wantListErr(t *testing.T, dir, rel string, want error) {
	t.Helper()
	if _, err := os.ReadDir(filepath.Join(dir, filepath.FromSlash(rel))); !errors.Is(err, want) {
		t.Fatalf("readdir %s: %v, want %v", rel, err, want)
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
	// memberTree is a workspace whose member foo a.js requires; node_modules exists but holds
	// no copy of foo.
	memberTree := map[string]string{
		"package.json":              `{"name":"app","workspaces":["packages/*"]}`,
		"packages/foo/package.json": `{"name":"foo"}`,
		"packages/foo/index.js":     js,
		"a.js":                      "const foo = require('foo');\n",
		"node_modules/.keep":        "",
	}
	memberShadowed := func(from string, want bool) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			prog := mustLoad(t, dir)
			if prog == nil {
				return
			}
			if !want {
				noCopyAbove(t, dir, "foo")
			}
			if got := prog.resolver().loadsOutOfTree(from, "foo", true); got != want {
				t.Errorf("loadsOutOfTree = %v, want %v", got, want)
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
	// installedExpress is a tree whose lock and installed copy agree on express 4.18.2.
	installedExpress := with(map[string]string{
		"node_modules/express/package.json":  `{"name":"express","version":"4.18.2"}`,
		"node_modules/left-pad/package.json": `{"name":"left-pad","version":"1.3.0"}`,
	})
	// oldExpress returns a directory outside the build dir holding an express 4.17.0 copy at
	// node_modules/express.
	oldExpress := func(t *testing.T) string {
		out := t.TempDir()
		mkdir(t, out, "node_modules/express")
		if err := os.WriteFile(filepath.Join(out, "node_modules", "express", "package.json"), []byte(`{"name":"express","version":"4.17.0"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		return out
	}
	// expressUnread checks that installedCopies reports the tree unread and that express is
	// then not resolved Complete to the lock's 4.18.2.
	expressUnread := func(want bool) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			copiesRead("", !want)(t, dir)
			r := resolveJS(t, dir, "express")
			if got := !r.Partiality.Complete || !r.Match.Resolved; got != want {
				t.Errorf("express = %+v, partiality %+v; want unread %v", r.Match, r.Partiality, want)
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

	// importKeepsLimit checks whether a dynamic import of x keeps dynamic_import_specifier,
	// which follows from the package.json installedManifest finds for x.
	importKeepsLimit := func(want bool) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			if got := hasReason(res.Partiality, plugin.PartialReasonDynamicImportSpecifier); got != want {
				t.Errorf("%s declared = %v, want %v; reasons %v", plugin.PartialReasonDynamicImportSpecifier, got, want, res.Partiality.Reasons)
			}
		}
	}
	const loadX = "async function load(s) { const m = await import('x'); return m.parse(s); }\nload(process.argv);\n"
	const plainX = `{"name":"x","exports":{"import":"./i.js","default":"./i.js"}}`
	importX := func(extra map[string]string) map[string]string {
		m := map[string]string{"package.json": `{"name":"app"}`, "app.js": loadX}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	// shadowKeepsLimit checks uninspectable_package on a require of cfg, a bare specifier a
	// tsconfig paths alias claims, which follows from what nodeModulesHas finds for cfg.
	shadowKeepsLimit := func(want bool) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			if got := hasReason(res.Partiality, plugin.PartialReasonUninspectablePackage); got != want {
				t.Errorf("%s declared = %v, want %v; reasons %v", plugin.PartialReasonUninspectablePackage, got, want, res.Partiality.Reasons)
			}
		}
	}
	shadowedCfg := func(extra map[string]string) map[string]string {
		m := map[string]string{
			"package.json":  `{"name":"app"}`,
			"tsconfig.json": `{"compilerOptions":{"baseUrl":".","paths":{"cfg":["src/cfg.js"]}}}`,
			"src/cfg.js":    "function parse(s) { return s; }\nmodule.exports = { parse };\n",
			"app.js":        "const m = require('cfg');\nfunction load(s) { return m.parse(s); }\nload(process.argv);\n",
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	// longReal, the logical build dir of the ENAMETOOLONG row, is set by its fault.
	var longReal string

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
		{"installedManifest", []row{
			{"EACCES", importX(map[string]string{"node_modules/x/package.json": plainX}), func(t *testing.T, dir string) {
				deny(t, filepath.Join(dir, "node_modules", "x"))
				wantErr(t, dir, "node_modules/x/package.json", os.ErrPermission, true)
			}, importKeepsLimit(true)},
			{"EACCES on a nested copy that shadows a readable one", map[string]string{
				"package.json":                    `{"name":"app"}`,
				"src/app.js":                      loadX,
				"src/node_modules/x/package.json": plainX,
				"node_modules/x/package.json":     plainX,
			}, func(t *testing.T, dir string) {
				deny(t, filepath.Join(dir, "src", "node_modules", "x"))
				wantErr(t, dir, "src/node_modules/x/package.json", os.ErrPermission, true)
			}, importKeepsLimit(true)},
			{"ELOOP", importX(nil), func(t *testing.T, dir string) {
				loop(t, dir, "node_modules/x")
				wantErr(t, dir, "node_modules/x/package.json", syscall.ELOOP, true)
			}, importKeepsLimit(true)},
			{"ENOTDIR", importX(map[string]string{"node_modules/x": "not a directory"}), func(t *testing.T, dir string) {
				wantErr(t, dir, "node_modules/x/package.json", syscall.ENOTDIR, true)
			}, importKeepsLimit(false)},
			{"missing", importX(nil), func(t *testing.T, dir string) {
				dangle(t, dir, "node_modules/x")
			}, importKeepsLimit(false)},
		}},
		{"nodeModulesHas", []row{
			{"EACCES", shadowedCfg(map[string]string{"node_modules/other/package.json": `{"name":"other"}`}), func(t *testing.T, dir string) {
				deny(t, filepath.Join(dir, "node_modules"), true) // listable, not searchable
				wantErr(t, dir, "node_modules/cfg", os.ErrPermission, true)
			}, shadowKeepsLimit(true)},
			{"ELOOP", shadowedCfg(nil), func(t *testing.T, dir string) {
				loop(t, dir, "node_modules")
				wantErr(t, dir, "node_modules/cfg", syscall.ELOOP, true)
			}, shadowKeepsLimit(true)},
			{"missing", shadowedCfg(nil), func(t *testing.T, dir string) {
				dangle(t, dir, "node_modules")
			}, shadowKeepsLimit(false)},
			{"ELOOP above the build root", shadowedCfg(nil), func(t *testing.T, dir string) {
				loop(t, filepath.Dir(dir), "node_modules")
				wantErr(t, filepath.Dir(dir), "node_modules/cfg", syscall.ELOOP, true)
			}, shadowKeepsLimit(true)},
			{"ENAMETOOLONG resolving the real path of the importer", nil, func(t *testing.T, dir string) {
				longReal = filepath.Join(physicallyDeep(t, dir), "app")
				writeFiles(t, longReal, shadowedCfg(nil))
				if _, err := filepath.EvalSymlinks(longReal); !errors.Is(err, syscall.ENAMETOOLONG) {
					t.Fatalf("EvalSymlinks: %v, want %v", err, syscall.ENAMETOOLONG)
				}
			}, func(t *testing.T, _ string) { shadowKeepsLimit(true)(t, longReal) }},
		}},
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
				wantListErr(t, dir, "web", os.ErrPermission)
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
		{"installedCopies symlink leaving the build dir", []row{
			{"nested node_modules", installedExpress, func(t *testing.T, dir string) {
				link(t, dir, "node_modules/left-pad/node_modules", filepath.Join(oldExpress(t), "node_modules"))
			}, expressUnread(true)},
			{"pnpm store entry", installedExpress, func(t *testing.T, dir string) {
				link(t, dir, "node_modules/.pnpm/express@4.17.0", oldExpress(t))
			}, expressUnread(true)},
			{"dangling nested node_modules", installedExpress, func(t *testing.T, dir string) {
				dangle(t, dir, "node_modules/left-pad/node_modules")
			}, expressUnread(true)},
			{"nested node_modules inside root", installedExpress, func(t *testing.T, dir string) {
				mkdir(t, dir, "shared")
				link(t, dir, "node_modules/left-pad/node_modules", filepath.Join(dir, "shared"))
			}, expressUnread(false)},
			{"pnpm store entry inside root", installedExpress, func(t *testing.T, dir string) {
				mkdir(t, dir, "shared")
				link(t, dir, "node_modules/.pnpm/express@4.18.2", filepath.Join(dir, "shared"))
			}, expressUnread(false)},
		}},
		{"discoverProjectRoots walk", []row{
			{"EACCES", map[string]string{"package.json": `{"name":"app"}`, "package-lock.json": `{"lockfileVersion":3,"packages":{"":{"name":"app"}}}`, "web/package-lock.json": `{"lockfileVersion":3,"packages":{"":{}}}`}, func(t *testing.T, dir string) {
				deny(t, filepath.Join(dir, "web"))
				wantListErr(t, dir, "web", os.ErrPermission)
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
				wantListErr(t, dir, "packages", os.ErrPermission)
			}, manifestsRead("", false)},
			{"missing", nil, nil, manifestsRead("missing", true)},
		}},
		{"memberShadowed node_modules candidate", []row{
			{"EACCES", memberTree, func(t *testing.T, dir string) {
				deny(t, filepath.Join(dir, "node_modules"), true) // listable, not searchable
				wantErr(t, dir, "node_modules/foo.js", os.ErrPermission, true)
			}, memberShadowed("a", true)},
			{"ELOOP", memberTree, func(t *testing.T, dir string) {
				loop(t, dir, "node_modules/foo")
				wantErr(t, dir, "node_modules/foo", syscall.ELOOP)
			}, memberShadowed("a", true)},
			{"missing", memberTree, func(t *testing.T, dir string) {
				dangle(t, dir, "node_modules/foo")
			}, memberShadowed("a", false)},
		}},
		{"memberShadowed member real path", []row{
			// The build root is reached through short links, and its real path is long enough that
			// the member's is past PATH_MAX while the importer's still resolves.
			{"ENAMETOOLONG", nil, func(t *testing.T, dir string) {
				member := "packages/" + strings.Repeat("p", 200)
				root := filepath.Join(deepLink(t, dir, "r", pathMax-105), "repo")
				for name, body := range map[string]string{
					"package.json":           memberTree["package.json"],
					member + "/package.json": `{"name":"foo"}`,
					member + "/index.js":     js,
					"a.js":                   memberTree["a.js"],
					"node_modules/.keep":     "",
				} {
					p := filepath.Join(root, filepath.FromSlash(name))
					if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(member))); !errors.Is(err, syscall.ENAMETOOLONG) {
					t.Fatalf("realpath of the member: %v, want %v", err, syscall.ENAMETOOLONG)
				}
				if _, err := filepath.EvalSymlinks(filepath.Join(root, "a.js")); err != nil {
					t.Fatalf("realpath a.js: %v", err)
				}
			}, func(t *testing.T, dir string) {
				memberShadowed("a", true)(t, filepath.Join(dir, "r", "repo"))
			}},
		}},
		{"memberShadowed importer real path", []row{
			{"EACCES", memberTree, func(t *testing.T, dir string) {
				link(t, dir, "src/entry.js", denied(t))
				wantErr(t, dir, "src/entry.js", os.ErrPermission)
			}, memberShadowed("src/entry", true)},
			{"ELOOP", memberTree, func(t *testing.T, dir string) {
				loop(t, dir, "src/entry.js")
				wantErr(t, dir, "src/entry.js", syscall.ELOOP)
			}, memberShadowed("src/entry", true)},
			{"missing", memberTree, func(t *testing.T, dir string) {
				dangle(t, dir, "src/entry.js")
			}, memberShadowed("src/entry", false)},
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
