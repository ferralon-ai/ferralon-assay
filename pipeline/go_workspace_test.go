package pipeline

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

// TestResolveGoWorkspace: with nothing declared the build runs under the go.work the go command
// finds from the module, searched no higher than its repository, unless that go.work does not use
// the module; a declared go.work must exist, parse and use the module, and one that cannot be
// established is an error rather than a guess.
func TestResolveGoWorkspace(t *testing.T) {
	const modA = "module example.com/mono/a\n\ngo 1.22\n"
	const modB = "module example.com/mono/b\n\ngo 1.22\n"
	members := "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n"
	cases := []struct {
		name     string
		files    map[string]string
		declared string
		want     string // go.work relative to the tree, "" for off
		wantErr  bool
	}{
		{"no go.work", map[string]string{"a/go.mod": modA}, "", "", false},
		{"a go.work above the module", map[string]string{"go.work": members, "a/go.mod": modA, "b/go.mod": modB}, "", "go.work", false},
		{"a go.work in the module", map[string]string{"a/go.work": "go 1.22\n\nuse .\n", "a/go.mod": modA}, "", "a/go.work", false},
		{"a go.work that does not use the module", map[string]string{"go.work": "go 1.22\n\nuse ./b\n", "a/go.mod": modA, "b/go.mod": modB}, "", "", false},
		{"a go.work that does not parse", map[string]string{"go.work": "go 1.22\n\nuse (\n", "a/go.mod": modA}, "", "", true},
		{"declared off", map[string]string{"go.work": members, "a/go.mod": modA, "b/go.mod": modB}, "off", "", false},
		{"declared relative to the checkout", map[string]string{"ci/ws.work": "go 1.22\n\nuse ../a\n", "a/go.mod": modA}, "ci/ws.work", "ci/ws.work", false},
		{"declared and missing", map[string]string{"a/go.mod": modA}, "ci/ws.work", "", true},
		{"declared and not using the module", map[string]string{"ci/ws.work": "go 1.22\n\nuse ../b\n", "a/go.mod": modA, "b/go.mod": modB}, "ci/ws.work", "", true},
		{"declared and not parsing", map[string]string{"ci/ws.work": "use (\n", "a/go.mod": modA}, "ci/ws.work", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, _ := filepath.EvalSymlinks(writeTree(t, tc.files))
			gitTree(t, tree)
			ws, err := ResolveGoWorkspace(context.Background(), filepath.Join(tree, "a"), tree, tc.declared)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ResolveGoWorkspace error = %v, want error %v", err, tc.wantErr)
			}
			want := GoWorkspace{}
			if tc.want != "" {
				want.File = filepath.Join(tree, filepath.FromSlash(tc.want))
			}
			if err == nil && ws != want {
				t.Fatalf("ResolveGoWorkspace = %+v, want %+v", ws, want)
			}
		})
	}
}

// TestResolveGoWorkspace_StopsAtTheRepository: a go.work above the git work tree holding the
// module is a developer's, so the build does not run under it and its members are not the build's;
// outside a work tree the search stops at the checkout root.
func TestResolveGoWorkspace_StopsAtTheRepository(t *testing.T) {
	outer := writeTree(t, map[string]string{
		"go.work":       "go 1.22\n\nuse (\n\t./repo/a\n\t./lib\n)\n",
		"lib/go.mod":    "module example.com/lib\n\ngo 1.22\n",
		"repo/a/go.mod": "module example.com/mono\n\ngo 1.22\n",
	})
	repo, buildDir := filepath.Join(outer, "repo"), filepath.Join(outer, "repo", "a")
	if ws, err := ResolveGoWorkspace(context.Background(), buildDir, repo, ""); err != nil || ws.File != "" {
		t.Fatalf("outside a work tree: ResolveGoWorkspace = %+v, %v; want off", ws, err)
	}
	gitTree(t, repo)
	ws, err := ResolveGoWorkspace(context.Background(), buildDir, outer, "")
	if err != nil || ws.File != "" {
		t.Fatalf("above the work tree: ResolveGoWorkspace = %+v, %v; want off", ws, err)
	}
	if present, known := goModRequires(context.Background(), buildDir, ws, "example.com/lib"); present || !known {
		t.Fatalf("goModRequires = %v, %v; want false, true", present, known)
	}
}

// TestModuleVersionFromBuild_Workspace: under a go.work the version is pinned only at the one the go
// command selects for the build, and left unpinned when it cannot say or when the module is one the
// workspace builds from source or replaces. The highest version a go.mod there requires is never the
// answer: a dependency's own requirements can select higher.
func TestModuleVersionFromBuild_Workspace(t *testing.T) {
	const work = "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n"
	const modA = "module example.com/mono/a\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.6\n"
	const modB = "module example.com/mono/b\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.8\n"
	type buildList = func(context.Context, string, GoWorkspace) ([]listedModule, error)
	listing := func(mods ...listedModule) buildList {
		return func(context.Context, string, GoWorkspace) ([]listedModule, error) {
			return append([]listedModule{{Path: "example.com/mono/a", Main: true}, {Path: "example.com/mono/b", Main: true}}, mods...), nil
		}
	}
	selected := func(v string) buildList { return listing(listedModule{Path: "golang.org/x/text", Version: v}) }
	failing := func(context.Context, string, GoWorkspace) ([]listedModule, error) {
		return nil, errors.New("go: module lookup disabled by GOPROXY=off")
	}
	replacedBy := listing(listedModule{Path: "golang.org/x/text", Version: "v0.3.8", Replace: &struct{ Path, Version string }{Path: "../text"}})
	main := listing(listedModule{Path: "golang.org/x/text", Main: true})
	cases := []struct {
		name         string
		files        map[string]string
		module       string
		list         buildList
		wantVersion  string
		wantPinned   bool
		wantManifest bool
	}{
		{"the version the go command selects", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": modB}, "golang.org/x/text", selected("v0.3.9"), "v0.3.9", true, true},
		{"the go command cannot say", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": modB}, "golang.org/x/text", failing, "", false, true},
		{"the go command reports a replacement", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": modB}, "golang.org/x/text", replacedBy, "", false, true},
		{"the go command reports a main module", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": modB}, "golang.org/x/text", main, "", false, true},
		{"the go command reports no version", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": modB}, "golang.org/x/text", selected(""), "", false, true},
		{"a module the build list does not hold", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": modB}, "example.com/never", selected("v0.3.9"), "", true, true},
		{"a module no member requires that the build list holds", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": modB}, "example.com/n", listing(listedModule{Path: "example.com/n", Version: "v1.0.0"}), "v1.0.0", true, true},
		{"a module no member requires when the go command cannot say", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": modB}, "example.com/never", failing, "", false, true},
		{"a member module", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": modB}, "example.com/mono/b", selected("v1.0.0"), "", false, true},
		{"a module the go.work replaces", map[string]string{"go.work": work + "\nreplace golang.org/x/text => golang.org/x/text v0.3.0\n", "a/go.mod": modA, "b/go.mod": modB}, "golang.org/x/text", selected("v0.3.8"), "", false, true},
		{"a module a member replaces", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": modB + "\nreplace golang.org/x/text => ../text\n"}, "golang.org/x/text", selected("v0.3.8"), "", false, true},
		{"a member before go 1.17 the go command cannot resolve", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": "module example.com/mono/b\n\ngo 1.16\n\nrequire golang.org/x/text v0.3.8\n"}, "golang.org/x/text", failing, "", false, true},
		{"a member before go 1.17 the go command resolves", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": "module example.com/mono/b\n\ngo 1.16\n\nrequire golang.org/x/text v0.3.8\n"}, "golang.org/x/text", selected("v0.3.10"), "v0.3.10", true, true},
		{"a member with no go.mod", map[string]string{"go.work": work, "a/go.mod": modA}, "golang.org/x/text", selected("v0.3.8"), "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubGoList(t, tc.list)
			tree := writeTree(t, tc.files)
			ws := GoWorkspace{File: filepath.Join(tree, "go.work")}
			v, pinned, read := moduleVersionFromBuild(context.Background(), filepath.Join(tree, "a"), ws, tc.module)
			if v != tc.wantVersion || pinned != tc.wantPinned || read != tc.wantManifest {
				t.Fatalf("moduleVersionFromBuild = %q, %v, %v; want %q, %v, %v", v, pinned, read, tc.wantVersion, tc.wantPinned, tc.wantManifest)
			}
		})
	}

	t.Run("off reads the module's go.mod alone", func(t *testing.T) {
		stubGoList(t, func(context.Context, string, GoWorkspace) ([]listedModule, error) {
			t.Fatal("the go command ran for a build with no go.work")
			return nil, nil
		})
		tree := writeTree(t, map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": modB})
		if v, pinned, read := moduleVersionFromBuild(context.Background(), filepath.Join(tree, "a"), GoWorkspace{}, "golang.org/x/text"); v != "v0.3.6" || !pinned || !read {
			t.Fatalf("moduleVersionFromBuild = %q, %v, %v; want v0.3.6, true, true", v, pinned, read)
		}
	})
}

func stubGoList(t *testing.T, list func(context.Context, string, GoWorkspace) ([]listedModule, error)) {
	t.Helper()
	orig := goListBuild
	goListBuild = list
	t.Cleanup(func() { goListBuild = orig })
	resetBuildLists(t)
}

// resetBuildLists forgets every memoized build list, now and when t ends.
func resetBuildLists(t *testing.T) {
	t.Helper()
	reset := func() { buildLists.Range(func(k, _ any) bool { buildLists.Delete(k); return true }) }
	reset()
	t.Cleanup(reset)
}

// TestGoWorkspaceModules: the build list decides what a workspace build holds and at what version.
// buildDir's own module is not a dependency; a module the workspace uses or replaces is held at no
// required version; and when the go command cannot say, every module the workspace uses or
// requires is held, none at a version.
func TestGoWorkspaceModules(t *testing.T) {
	const work = "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n\nreplace example.com/r1 => example.com/r1 v1.0.1\n"
	files := map[string]string{
		"go.work":  work,
		"a/go.mod": "module example.com/mono/a\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.6\n",
		"b/go.mod": "module example.com/mono/b\n\ngo 1.22\n\nrequire example.com/r2 v1.0.0\n\nreplace example.com/r2 => ../r2\n",
	}
	listed := []listedModule{
		{Path: "example.com/mono/a", Main: true},
		{Path: "example.com/mono/b", Main: true},
		{Path: "golang.org/x/text", Version: "v0.3.9"},
		{Path: "example.com/n", Version: "v1.2.0"},
		{Path: "example.com/r1", Version: "v1.0.0"},
		{Path: "example.com/r2", Version: "v1.0.0"},
		{Path: "example.com/listreplaced", Version: "v1.0.0", Replace: &struct{ Path, Version string }{Path: "../x"}},
		{Path: "example.com/versionless"},
	}

	t.Run("the build list", func(t *testing.T) {
		stubGoList(t, func(context.Context, string, GoWorkspace) ([]listedModule, error) { return listed, nil })
		tree := writeTree(t, files)
		pinned, unpinned, err := GoWorkspaceModules(context.Background(), filepath.Join(tree, "a"), GoWorkspace{File: filepath.Join(tree, "go.work")})
		if err != nil {
			t.Fatal(err)
		}
		if want := map[string]string{"golang.org/x/text": "v0.3.9", "example.com/n": "v1.2.0"}; !reflect.DeepEqual(pinned, want) {
			t.Errorf("pinned = %v, want %v", pinned, want)
		}
		if want := []string{"example.com/listreplaced", "example.com/mono/b", "example.com/r1", "example.com/r2", "example.com/versionless"}; !reflect.DeepEqual(unpinned, want) {
			t.Errorf("unpinned = %v, want %v", unpinned, want)
		}
	})

	t.Run("the go command cannot say", func(t *testing.T) {
		stubGoList(t, func(context.Context, string, GoWorkspace) ([]listedModule, error) {
			return nil, errors.New("go: module lookup disabled by GOPROXY=off")
		})
		tree := writeTree(t, files)
		pinned, unpinned, err := GoWorkspaceModules(context.Background(), filepath.Join(tree, "a"), GoWorkspace{File: filepath.Join(tree, "go.work")})
		if err != nil {
			t.Fatal(err)
		}
		if len(pinned) != 0 {
			t.Errorf("pinned = %v, want none", pinned)
		}
		if want := []string{"example.com/mono/b", "example.com/r1", "example.com/r2", "golang.org/x/text"}; !reflect.DeepEqual(unpinned, want) {
			t.Errorf("unpinned = %v, want %v", unpinned, want)
		}
	})

	t.Run("a member with no go.mod", func(t *testing.T) {
		stubGoList(t, func(context.Context, string, GoWorkspace) ([]listedModule, error) { return listed, nil })
		tree := writeTree(t, map[string]string{"go.work": work, "a/go.mod": files["a/go.mod"]})
		if _, _, err := GoWorkspaceModules(context.Background(), filepath.Join(tree, "a"), GoWorkspace{File: filepath.Join(tree, "go.work")}); err == nil {
			t.Fatal("GoWorkspaceModules read a workspace with a member missing its go.mod")
		}
	})
}
