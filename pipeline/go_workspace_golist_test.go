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
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command")
	}
	root := t.TempDir()
	proxy, cache := filepath.Join(root, "proxy"), filepath.Join(root, "cache")
	publish(t, proxy, "example.com/m", "v1.0.0", map[string]string{"go.mod": "module example.com/m\n\ngo 1.21\n", "m.go": "package m\n"})
	publish(t, proxy, "example.com/m", "v1.2.0", map[string]string{"go.mod": "module example.com/m\n\ngo 1.21\n", "m.go": "package m\n"})
	publish(t, proxy, "example.com/d", "v1.0.0", map[string]string{"go.mod": "module example.com/d\n\ngo 1.21\n\nrequire example.com/m v1.2.0\n", "x/x.go": "package x\n"})

	t.Setenv("GOENV", "off")
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOMODCACHE", cache)
	t.Setenv("GOFLAGS", "-modcacherw")
	dl := exec.Command("go", "mod", "download", "-json", "example.com/m@v1.0.0", "example.com/m@v1.2.0", "example.com/d@v1.0.0")
	dl.Dir = root
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

	tree := writeTree(t, map[string]string{
		"go.work":  "go 1.21\n\nuse (\n\t./a\n\t./b\n)\n",
		"a/go.mod": "module example.com/mono/a\n\ngo 1.21\n\nrequire example.com/m v1.0.0\n",
		"a/go.sum": sum.String(),
		"a/a.go":   "package a\n\nimport _ \"example.com/m\"\n",
		"b/go.mod": "module example.com/mono/b\n\ngo 1.21\n\nrequire example.com/d v1.0.0\n",
		"b/go.sum": sum.String(),
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
	t.Setenv("GOMODCACHE", t.TempDir())
	if v, pinned, read := moduleVersionFromBuild(context.Background(), buildDir, ws, "example.com/m"); v != "" || pinned || !read {
		t.Fatalf("with a cold module cache: moduleVersionFromBuild = %q, %v, %v; want unpinned", v, pinned, read)
	}
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
