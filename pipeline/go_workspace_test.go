package pipeline

import (
	"context"
	"path/filepath"
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
	if present, known := goModRequires(buildDir, ws, "example.com/lib"); present || !known {
		t.Fatalf("goModRequires = %v, %v; want false, true", present, known)
	}
}

// TestModuleVersionFromBuild_Workspace: under a go.work the version is the highest any module it
// uses requires, and is left unpinned wherever that bound is not the version the go command
// selects: a module the workspace builds from source or replaces, and a workspace any part of
// which predates module graph pruning (go 1.17), where a transitive requirement may select higher.
func TestModuleVersionFromBuild_Workspace(t *testing.T) {
	const work = "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n"
	const modA = "module example.com/mono/a\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.6\n"
	const modB = "module example.com/mono/b\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.8\n"
	cases := []struct {
		name         string
		files        map[string]string
		module       string
		wantVersion  string
		wantPinned   bool
		wantManifest bool
	}{
		{"the highest require across members", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": modB}, "golang.org/x/text", "v0.3.8", true, true},
		{"a module no member requires", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": modB}, "example.com/never", "", true, true},
		{"a member module", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": modB}, "example.com/mono/b", "", false, true},
		{"a module the go.work replaces", map[string]string{"go.work": work + "\nreplace golang.org/x/text => golang.org/x/text v0.3.0\n", "a/go.mod": modA, "b/go.mod": modB}, "golang.org/x/text", "", false, true},
		{"a module a member replaces", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": modB + "\nreplace golang.org/x/text => ../text\n"}, "golang.org/x/text", "", false, true},
		{"a member before go 1.17", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": "module example.com/mono/b\n\ngo 1.16\n\nrequire golang.org/x/text v0.3.8\n"}, "golang.org/x/text", "", false, true},
		{"a member with no go directive", map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": "module example.com/mono/b\n\nrequire golang.org/x/text v0.3.8\n"}, "golang.org/x/text", "", false, true},
		{"a go.work before go 1.17", map[string]string{"go.work": "go 1.16\n\nuse (\n\t./a\n\t./b\n)\n", "a/go.mod": modA, "b/go.mod": modB}, "golang.org/x/text", "", false, true},
		{"a member with no go.mod", map[string]string{"go.work": work, "a/go.mod": modA}, "golang.org/x/text", "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := writeTree(t, tc.files)
			ws := GoWorkspace{File: filepath.Join(tree, "go.work")}
			v, pinned, read := moduleVersionFromBuild(filepath.Join(tree, "a"), ws, tc.module)
			if v != tc.wantVersion || pinned != tc.wantPinned || read != tc.wantManifest {
				t.Fatalf("moduleVersionFromBuild = %q, %v, %v; want %q, %v, %v", v, pinned, read, tc.wantVersion, tc.wantPinned, tc.wantManifest)
			}
		})
	}

	t.Run("off reads the module's go.mod alone", func(t *testing.T) {
		tree := writeTree(t, map[string]string{"go.work": work, "a/go.mod": modA, "b/go.mod": modB})
		if v, pinned, read := moduleVersionFromBuild(filepath.Join(tree, "a"), GoWorkspace{}, "golang.org/x/text"); v != "v0.3.6" || !pinned || !read {
			t.Fatalf("moduleVersionFromBuild = %q, %v, %v; want v0.3.6, true, true", v, pinned, read)
		}
	})
}
