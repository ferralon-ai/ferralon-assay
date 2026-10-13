//go:build unix

package jsanalysis

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// mkfifo places a named pipe at rel under dir. Opening it for reading blocks until a writer
// appears, and none ever does.
func mkfifo(t *testing.T, dir, rel string) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(p, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	return p
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func hasToolFailure(p plugin.Partiality) bool {
	return !p.Complete && slices.Contains(p.Reasons, plugin.PartialReasonToolFailure)
}

// TestReaders_FIFO places a named pipe where each reader looks for a file. Every reader must
// return without opening it (a reader that blocks fails the 3 s guard rather than hanging the
// run) and treat it as a file it could not read.
func TestReaders_FIFO(t *testing.T) {
	const js = "module.exports = function a() {}\n"
	rows := []struct {
		name  string
		files map[string]string
		fifo  string
		check func(t *testing.T, dir, pipe string)
	}{
		{
			name: "BuildManifest root package.json", fifo: "package.json",
			check: func(t *testing.T, dir, _ string) {
				if _, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir}); err == nil {
					t.Error("BuildManifest read a pipe as package.json without error")
				}
			},
		},
		{
			name: "newBuildContext root package.json", fifo: "package.json",
			check: func(t *testing.T, dir, _ string) {
				if bc := newBuildContext(dir); bc.ModuleMode != moduleModeCJS || len(bc.Roots) != 1 {
					t.Errorf("build context = %+v, want the cjs default", bc)
				}
			},
		},
		{
			name: "readBundlerConfigs bundler config", fifo: "webpack.config.js",
			check: func(t *testing.T, dir, _ string) {
				if _, part := readBundlerConfigs(dir); !hasToolFailure(part) {
					t.Errorf("partiality = %+v, want tool_failure", part)
				}
			},
		},
		{
			name: "loadProgram source file", files: map[string]string{"b.js": js}, fifo: "a.js",
			check: func(t *testing.T, dir, _ string) {
				res, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: dir})
				if err != nil || !hasToolFailure(res.Partiality) {
					t.Errorf("IndexSymbols = %+v, %v; want tool_failure", res.Partiality, err)
				}
			},
		},
		{
			name: "readPackageJSON manifest", fifo: "package.json",
			check: func(t *testing.T, _, pipe string) {
				if _, ok := readPackageJSON(pipe); ok {
					t.Error("readPackageJSON read a pipe")
				}
			},
		},
		{
			name: "yarnWorkspace lock-dir package.json", fifo: "package.json",
			check: func(t *testing.T, dir, _ string) {
				if yarnWorkspace(dir, "packages/a") {
					t.Error("yarnWorkspace named a workspace from a pipe")
				}
			},
		},
		{
			name: "installedPackage installed package.json", fifo: "node_modules/left-pad/package.json",
			check: func(t *testing.T, dir, _ string) {
				pkg := filepath.Join(dir, "node_modules", "left-pad")
				if installedPackage(pkg, "left-pad", dir, map[string]bool{}, map[string]bool{}) {
					t.Error("installedPackage read an installed copy whose package.json is a pipe")
				}
			},
		},
		{
			name: "npm adapter package-lock.json", fifo: "package-lock.json",
			check: func(t *testing.T, dir, pipe string) {
				if _, _, part := (npmAdapter{}).Parse(selectedLock{dialect: "npm", path: pipe, root: dir}, nil); !hasToolFailure(part) {
					t.Errorf("partiality = %+v, want tool_failure", part)
				}
			},
		},
		{
			name: "pnpm adapter pnpm-lock.yaml", fifo: "pnpm-lock.yaml",
			check: func(t *testing.T, dir, pipe string) {
				if _, _, part := (pnpmAdapter{}).Parse(selectedLock{dialect: "pnpm", path: pipe, root: dir}, nil); !hasToolFailure(part) {
					t.Errorf("partiality = %+v, want tool_failure", part)
				}
			},
		},
		{
			name: "yarn adapter yarn.lock", fifo: "yarn.lock",
			check: func(t *testing.T, dir, pipe string) {
				if _, _, part := (yarnAdapter{}).Parse(selectedLock{dialect: "yarn", path: pipe, root: dir}, nil); !hasToolFailure(part) {
					t.Errorf("partiality = %+v, want tool_failure", part)
				}
			},
		},
		{
			name:  "packageManagerDialect root package.json, reached from selectLockfile",
			files: map[string]string{"package-lock.json": `{"lockfileVersion":3,"packages":{"":{}}}`},
			fifo:  "package.json",
			check: func(t *testing.T, dir, _ string) {
				if _, part := selectLockfile(dir); !hasToolFailure(part) {
					t.Errorf("partiality = %+v, want tool_failure: an unread package.json may name another package manager", part)
				}
			},
		},
		{
			name: "selectLockfile lockfile", fifo: "package-lock.json",
			check: func(t *testing.T, dir, _ string) {
				if sel, part := selectLockfile(dir); !hasToolFailure(part) {
					t.Errorf("selected %+v with partiality %+v, want tool_failure", sel, part)
				}
			},
		},
		{
			name: "manifestsUnder nested package.json", files: map[string]string{"package.json": `{"name":"app"}`}, fifo: "packages/a/package.json",
			check: func(t *testing.T, dir, _ string) {
				if _, complete := manifestsUnder(dir); complete {
					t.Error("manifestsUnder reported every package.json read")
				}
			},
		},
		{
			name:  "ResolveInventory with a package.json it cannot read",
			files: map[string]string{"package.json": `{"name":"app","dependencies":{"a":"1.0.0"}}`, "package-lock.json": `{"lockfileVersion":3,"packages":{"":{"name":"app","dependencies":{"a":"1.0.0"}},"node_modules/a":{"version":"1.0.0"}}}`},
			fifo:  "packages/b/package.json",
			check: func(t *testing.T, dir, _ string) {
				inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
				if err != nil || !hasToolFailure(inv.Partiality) {
					t.Errorf("inventory partiality = %+v, %v; want tool_failure", inv.Partiality, err)
				}
			},
		},
		{
			name:  "readBuildPackages with a package.json it cannot read",
			files: map[string]string{"package.json": `{"name":"app","dependencies":{"a":"1.0.0"}}`},
			fifo:  "packages/b/package.json",
			check: func(t *testing.T, dir, _ string) {
				if bp := readBuildPackages(context.Background(), dir); !bp.unread || bp.isDependency("a") {
					t.Errorf("unread = %v, isDependency(a) = %v; want unread and no package taken as a dependency", bp.unread, bp.isDependency("a"))
				}
			},
		},
		{
			name:  "ResolveDependencySymbols with a package.json it cannot read",
			files: map[string]string{"package.json": `{"name":"app","dependencies":{"a":"1.0.0"}}`, "index.js": "function parse() {}\nmodule.exports = { parse }\n"},
			fifo:  "packages/b/package.json",
			check: func(t *testing.T, dir, _ string) {
				res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{BuildDir: dir, PURL: "pkg:npm/a", AdvisorySymbols: []string{"parse"}})
				if err != nil || !hasToolFailure(res.Partiality) || len(res.Resolved) == 0 {
					t.Errorf("resolution = %+v, %v; want tool_failure with the first-party parse kept", res, err)
				}
			},
		},
		{
			name: "resolver governing package.json", files: map[string]string{"sub/a.js": js}, fifo: "sub/package.json",
			check: func(t *testing.T, dir, _ string) {
				prog := mustLoad(t, dir)
				if prog == nil {
					return
				}
				if m, _ := prog.resolver().governingPackageJSON("sub/a.js"); m != nil || !prog.readFailed {
					t.Errorf("manifest = %+v, readFailed = %v; want none and a read failure", m, prog.readFailed)
				}
			},
		},
		{
			name: "resolver root package.json", files: map[string]string{"a.js": js}, fifo: "package.json",
			check: func(t *testing.T, dir, _ string) {
				prog := mustLoad(t, dir)
				if prog == nil {
					return
				}
				if _, ok := prog.resolver().rootManifest(); ok || !prog.readFailed {
					t.Errorf("ok = %v, readFailed = %v; want no manifest and a read failure", ok, prog.readFailed)
				}
			},
		},
		{
			name: "resolver workspace member package.json", files: map[string]string{"a.js": js}, fifo: "packages/b/package.json",
			check: func(t *testing.T, dir, _ string) {
				prog := mustLoad(t, dir)
				if prog == nil {
					return
				}
				if m := prog.resolver().memberManifest("packages/b"); m != nil || !prog.readFailed {
					t.Errorf("manifest = %+v, readFailed = %v; want none and a read failure", m, prog.readFailed)
				}
			},
		},
		{
			name: "resolver tsconfig", files: map[string]string{"a.js": js}, fifo: "tsconfig.json",
			check: func(t *testing.T, dir, _ string) {
				prog := mustLoad(t, dir)
				if prog == nil {
					return
				}
				if ts := prog.resolver().loadTsconfig("", "tsconfig.json", 0); ts != nil || !prog.readFailed {
					t.Errorf("tsconfig = %+v, readFailed = %v; want none and a read failure", ts, prog.readFailed)
				}
			},
		},
		{
			name: "declaredDependencies package.json", files: map[string]string{"package.json": `{"dependencies":{"a":"1.0.0"}}`}, fifo: "packages/b/package.json",
			check: func(t *testing.T, dir, _ string) {
				if got := declaredDependencies(dir); len(got) != 1 || got[0].Coordinate != "a" {
					t.Errorf("declared = %+v, want only a", got)
				}
			},
		},
		{
			name: "parseLockfile lockfile", fifo: "yarn.lock",
			check: func(t *testing.T, _, pipe string) {
				if _, ok := parseLockfile(pipe); ok {
					t.Error("parseLockfile parsed a pipe")
				}
			},
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFiles(t, dir, row.files)
			pipe := mkfifo(t, dir, row.fifo)
			done := make(chan struct{})
			go func() {
				defer close(done)
				row.check(t, dir, pipe)
			}()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatalf("blocked opening the pipe at %s", row.fifo)
			}
		})
	}
}

func mustLoad(t *testing.T, dir string) *program {
	t.Helper()
	prog, err := loadProgram(dir)
	if err != nil {
		t.Errorf("loadProgram: %v", err)
		return nil
	}
	return prog
}
