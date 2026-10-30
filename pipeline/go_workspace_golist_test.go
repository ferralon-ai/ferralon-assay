package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/module"
	"golang.org/x/mod/zip"
)

// TestModuleVersionFromBuild_WorkspaceSelectsAboveEveryRequire runs the real go command over a
// workspace whose members are all go 1.21, tidy and unreplaced, where member a requires
// example.com/m v1.0.0 and member b requires example.com/d, whose own go.mod requires m v1.2.0. The
// workspace build selects m v1.2.0, above every version a member's go.mod lists, and the version axis
// must pin that one; with the module cache empty the go command cannot say, and it stays unpinned.
func TestModuleVersionFromBuild_WorkspaceSelectsAboveEveryRequire(t *testing.T) {
	proxy := offlineProxy(t)
	publish(t, proxy, "example.com/m", "v1.0.0", map[string]string{"go.mod": "module example.com/m\n\ngo 1.21\n", "m.go": "package m\n"})
	publish(t, proxy, "example.com/m", "v1.2.0", map[string]string{"go.mod": "module example.com/m\n\ngo 1.21\n", "m.go": "package m\n"})
	publish(t, proxy, "example.com/d", "v1.0.0", map[string]string{"go.mod": "module example.com/d\n\ngo 1.21\n\nrequire example.com/m v1.2.0\n", "x/x.go": "package x\n"})
	sum := download(t, proxy, "example.com/m@v1.0.0", "example.com/m@v1.2.0", "example.com/d@v1.0.0")

	tree := writeTree(t, map[string]string{
		"go.work":  "go 1.21\n\nuse (\n\t./a\n\t./b\n)\n",
		"a/go.mod": "module example.com/mono/a\n\ngo 1.21\n\nrequire example.com/m v1.0.0\n",
		"a/go.sum": sum,
		"a/a.go":   "package a\n\nimport _ \"example.com/m\"\n",
		"b/go.mod": "module example.com/mono/b\n\ngo 1.21\n\nrequire example.com/d v1.0.0\n",
		"b/go.sum": sum,
		"b/b.go":   "package b\n\nimport _ \"example.com/d/x\"\n",
	})
	ws := GoWorkspace{File: filepath.Join(tree, "go.work")}
	buildDir := filepath.Join(tree, "a")

	if v, pinned, read := moduleVersionFromBuild(context.Background(), buildDir, ws, "example.com/m"); v != "v1.2.0" || !pinned || !read {
		t.Fatalf("under the go.work: moduleVersionFromBuild = %q, %v, %v; want v1.2.0, true, true", v, pinned, read)
	}
	if v, pinned, read := moduleVersionFromBuild(context.Background(), buildDir, GoWorkspace{}, "example.com/m"); v != "v1.0.0" || !pinned || !read {
		t.Fatalf("with GOWORK=off: moduleVersionFromBuild = %q, %v, %v; want v1.0.0, true, true", v, pinned, read)
	}
	coldCache(t)
	if v, pinned, read := moduleVersionFromBuild(context.Background(), buildDir, ws, "example.com/m"); v != "" || pinned || !read {
		t.Fatalf("with a cold module cache: moduleVersionFromBuild = %q, %v, %v; want unpinned", v, pinned, read)
	}
}

// TestGoWorkspace_BuildHoldsAModuleNoGoModLists runs the real go command over a workspace where
// member a requires example.com/d v1.0.0 and member b requires example.com/e, whose own go.mod
// requires d v1.1.0; d v1.1.0 imports example.com/n, which no go.mod in the workspace lists. The
// workspace build selects d v1.1.0 and so compiles n: n is present at the version the build selects,
// never absent; with GOWORK=off it is absent, and with the module cache empty neither is known.
func TestGoWorkspace_BuildHoldsAModuleNoGoModLists(t *testing.T) {
	proxy := offlineProxy(t)
	publish(t, proxy, "example.com/n", "v1.0.0", map[string]string{"go.mod": "module example.com/n\n\ngo 1.21\n", "n.go": "package n\n"})
	publish(t, proxy, "example.com/d", "v1.0.0", map[string]string{"go.mod": "module example.com/d\n\ngo 1.21\n", "d.go": "package d\n"})
	publish(t, proxy, "example.com/d", "v1.1.0", map[string]string{"go.mod": "module example.com/d\n\ngo 1.21\n\nrequire example.com/n v1.0.0\n", "d.go": "package d\n\nimport _ \"example.com/n\"\n"})
	publish(t, proxy, "example.com/e", "v1.0.0", map[string]string{"go.mod": "module example.com/e\n\ngo 1.21\n\nrequire example.com/d v1.1.0\n", "x/x.go": "package x\n"})
	sum := download(t, proxy, "example.com/n@v1.0.0", "example.com/d@v1.0.0", "example.com/d@v1.1.0", "example.com/e@v1.0.0")

	tree := writeTree(t, map[string]string{
		"go.work":  "go 1.21\n\nuse (\n\t./a\n\t./b\n)\n",
		"a/go.mod": "module example.com/mono/a\n\ngo 1.21\n\nrequire example.com/d v1.0.0\n",
		"a/go.sum": sum,
		"a/a.go":   "package a\n\nimport _ \"example.com/d\"\n",
		"b/go.mod": "module example.com/mono/b\n\ngo 1.21\n\nrequire example.com/e v1.0.0\n",
		"b/go.sum": sum,
		"b/b.go":   "package b\n\nimport _ \"example.com/e/x\"\n",
	})
	ws := GoWorkspace{File: filepath.Join(tree, "go.work")}
	buildDir := filepath.Join(tree, "a")
	ctx := context.Background()

	if v, pinned, read := moduleVersionFromBuild(ctx, buildDir, ws, "example.com/n"); v != "v1.0.0" || !pinned || !read {
		t.Fatalf("under the go.work: moduleVersionFromBuild = %q, %v, %v; want v1.0.0, true, true", v, pinned, read)
	}
	if present, known := goModRequires(ctx, buildDir, ws, "example.com/n"); !present || !known {
		t.Fatalf("under the go.work: goModRequires = %v, %v; want true, true", present, known)
	}
	if present, known := goModRequires(ctx, buildDir, ws, "example.com/n/sub"); !present || !known {
		t.Fatalf("under the go.work, a package path: goModRequires = %v, %v; want true, true", present, known)
	}
	if present, known := goModRequires(ctx, buildDir, ws, "example.com/never"); present || !known {
		t.Fatalf("under the go.work, a module outside the build: goModRequires = %v, %v; want false, true", present, known)
	}
	if v, pinned, read := moduleVersionFromBuild(ctx, buildDir, GoWorkspace{}, "example.com/n"); v != "" || !pinned || !read {
		t.Fatalf("with GOWORK=off: moduleVersionFromBuild = %q, %v, %v; want absent", v, pinned, read)
	}
	if present, known := goModRequires(ctx, buildDir, GoWorkspace{}, "example.com/n"); present || !known {
		t.Fatalf("with GOWORK=off: goModRequires = %v, %v; want false, true", present, known)
	}
	coldCache(t)
	if v, pinned, read := moduleVersionFromBuild(ctx, buildDir, ws, "example.com/never"); v != "" || pinned || !read {
		t.Fatalf("with a cold module cache: moduleVersionFromBuild = %q, %v, %v; want unpinned", v, pinned, read)
	}
	if present, known := goModRequires(ctx, buildDir, ws, "example.com/never"); present || known {
		t.Fatalf("with a cold module cache: goModRequires = %v, %v; want false, false", present, known)
	}
}

// offlineProxy returns an empty file:// GOPROXY directory and points the go command at a fresh module
// cache with no go env file, checksum database or toolchain switching.
func offlineProxy(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command")
	}
	root := t.TempDir()
	t.Setenv("GOENV", "off")
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOMODCACHE", filepath.Join(root, "cache"))
	t.Setenv("GOFLAGS", "-modcacherw")
	resetBuildLists(t)
	return filepath.Join(root, "proxy")
}

// download fetches mods from proxy into the module cache and returns their go.sum lines.
func download(t *testing.T, proxy string, mods ...string) string {
	t.Helper()
	dl := exec.Command("go", append([]string{"mod", "download", "-json"}, mods...)...)
	dl.Dir = t.TempDir()
	dl.Env = append(os.Environ(), "GOPROXY=file://"+filepath.ToSlash(proxy), "GOWORK=off")
	out, err := dl.Output()
	if err != nil {
		t.Fatalf("go mod download: %v", err)
	}
	var sum strings.Builder
	for dec := json.NewDecoder(bytes.NewReader(out)); dec.More(); {
		var m struct{ Path, Version, Sum, GoModSum string }
		if err := dec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		sum.WriteString(m.Path + " " + m.Version + " " + m.Sum + "\n" + m.Path + " " + m.Version + "/go.mod " + m.GoModSum + "\n")
	}
	return sum.String()
}

// coldCache empties the module cache and forgets every build list computed so far.
func coldCache(t *testing.T) {
	t.Helper()
	t.Setenv("GOMODCACHE", t.TempDir())
	resetBuildLists(t)
}

// publish writes module path@version, made of files, to the file:// GOPROXY at proxy.
func publish(t *testing.T, proxy, path, version string, files map[string]string) {
	t.Helper()
	src := writeTree(t, files)
	dir := filepath.Join(proxy, filepath.FromSlash(path), "@v")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, version+".zip"))
	if err != nil {
		t.Fatal(err)
	}
	if err := zip.CreateFromDir(f, module.Version{Path: path, Version: version}, src); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	writeProxyFile(t, dir, version+".mod", files["go.mod"])
	writeProxyFile(t, dir, version+".info", `{"Version":"`+version+`"}`)
	list, _ := os.ReadFile(filepath.Join(dir, "list"))
	writeProxyFile(t, dir, "list", string(list)+version+"\n")
}

func writeProxyFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
