package scriptsurface

import (
	"os"
	"path/filepath"
	"testing"
)

// A path whose .. parts lead it reaches the directory it names lexically from the nearest
// manifest, so it resolves only while it stays inside root and that manifest is reached
// through no symlink; a .. after a named part, or one that leaves root, fails.
func TestBinder_Climb(t *testing.T) {
	tests := []struct {
		name   string
		files  map[string]string
		link   bool   // app is a symlink to real/app, whose .. is real, not root
		clear  string // the path Clear is asked about, or "" to ask Beside about beside
		beside string
		want   bool // Clear true, or Beside non-nil
	}{
		{"beside, a sibling inside root", map[string]string{"lib/m.toml": "x\n"}, false, "", "../lib/m.toml", true},
		{"beside, a sibling not there", nil, false, "", "../lib/m.toml", false},
		{"beside, leaving root", map[string]string{"lib/m.toml": "x\n"}, false, "", "../../lib/m.toml", false},
		{"beside, a .. after a named part", map[string]string{"lib/m.toml": "x\n"}, false, "", "x/../../lib/m.toml", false},
		{"beside, from a linked manifest", map[string]string{"lib/m.toml": "x\n", "real/lib/m.toml": "x\n"}, true, "", "../lib/m.toml", false},
		{"clear, nothing at a sibling", nil, false, "../plug/sub", "", true},
		{"clear, something at a sibling", map[string]string{"plug/sub/x": "x\n"}, false, "../plug/sub", "", false},
		{"clear, leaving root", nil, false, "../../plug/sub", "", false},
		{"clear, a .. after a named part", nil, false, "x/../../plug/sub", "", false},
		{"clear, from a linked manifest", nil, true, "../plug/sub", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"other/.keep": ""}
			app := "app"
			if tt.link {
				app = "real/app"
			}
			files[app+"/inst.toml"] = "x\n"
			for k, v := range tt.files {
				files[k] = v
			}
			root := writeTree(t, files)
			if tt.link {
				if err := os.Symlink(filepath.Join(root, "real", "app"), filepath.Join(root, "app")); err != nil {
					t.Fatal(err)
				}
			}
			v := New(root, func(string) bool { return true }, testSpec)
			c := &hostCursor{v: v, dirs: []string{filepath.Join(root, "app")}}
			var got bool
			if tt.clear != "" {
				got = c.Clear("inst.toml", tt.clear)
				if got && !v.bound["plug"] {
					t.Fatal("Clear did not bind plug")
				}
			} else {
				got = c.Beside("inst.toml", tt.beside) != nil
			}
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// Enclosing returns the files of a name above the nearest one, up to root, and fails from a
// nearest one reached through a symlink, whose parents are not the ones its path names.
func TestBinder_Enclosing(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		link  bool // app is a symlink to real/app
		cwd   bool // the command runs in a/app/sub, a symlink to real/sub
		want  []string
		ok    bool
	}{
		{"one above, one at root", map[string]string{"a/m.toml": "x\n", "m.toml": "x\n"}, false, false, []string{"a/m.toml", "m.toml"}, true},
		{"none above", nil, false, false, nil, true},
		{"from a linked manifest", map[string]string{"m.toml": "x\n"}, true, false, nil, false},
		{"from a linked directory below the manifest", map[string]string{"real/sub/.keep": ""}, false, true, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := "a/app"
			if tt.link {
				app = "real/app"
			}
			files := map[string]string{app + "/m.toml": "x\n"}
			for k, v := range tt.files {
				files[k] = v
			}
			root := writeTree(t, files)
			if tt.link {
				if err := os.MkdirAll(filepath.Join(root, "a"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, "real", "app"), filepath.Join(root, "a", "app")); err != nil {
					t.Fatal(err)
				}
			}
			dir := filepath.Join(root, "a", "app")
			if tt.cwd {
				dir = filepath.Join(dir, "sub")
				if err := os.Symlink(filepath.Join(root, "real", "sub"), dir); err != nil {
					t.Fatal(err)
				}
			}
			v := New(root, func(string) bool { return true }, testSpec)
			c := &hostCursor{v: v, dirs: []string{dir}}
			got, ok := c.Enclosing("m.toml")
			if ok != tt.ok || len(got) != len(tt.want) {
				t.Fatalf("got %v %v, want %v %v", got, ok, tt.want, tt.ok)
			}
			for i, w := range tt.want {
				if got[i] != filepath.Join(root, w) {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// In an image, Enclosing fails where a mount may cover a place the file is looked for, where a
// command may have written one, or where the directory the command runs in is reached through
// a symlink copied from the build context.
func TestBinder_EnclosingDocker(t *testing.T) {
	spec := testSpec
	var found []string
	spec.Allowed = func(words []string, b Binder) bool {
		if len(words) == 2 && words[0] == "inst" && words[1] == "build" {
			var ok bool
			found, ok = b.Enclosing("inst.toml")
			return ok
		}
		return testSpec.Allowed(words, b)
	}
	const head = "FROM python:3.12\nCOPY . /app\nWORKDIR /app/a\n"
	tests := []struct {
		name       string
		files      map[string]string
		dockerfile string
		link       bool // a/sub is a symlink to real/sub
		want       int  // files found above, or -1 when Enclosing fails
	}{
		{"one above", map[string]string{"inst.toml": "x\n"}, head + "RUN inst build\n", false, 1},
		{"none above", nil, head + "RUN inst build\n", false, 0},
		{"none at all", nil, "FROM python:3.12\nWORKDIR /app\nRUN inst build\n", false, -1},
		{"written above", nil, head + "RUN touch /app/inst.toml\nRUN inst build\n", false, -1},
		{"a file mounted above", nil, head + "RUN --mount=type=bind,source=ci/inst.toml,target=/app/inst.toml inst build\n", false, -1},
		{"a directory mounted above", nil, head + "RUN --mount=type=bind,source=ci,target=/app inst build\n", false, -1},
		{"a mount not known", nil, head + "RUN --mount=type=bind,source=ci inst build\n", false, -1},
		{"a cache mounted elsewhere", nil, head + "RUN --mount=type=cache,target=/root/.cache inst build\n", false, 0},
		{"from a linked directory", map[string]string{"real/sub/.keep": ""}, head + "WORKDIR /app/a/sub\nRUN inst build\n", true, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"a/inst.toml": "x\n", "Dockerfile": tt.dockerfile, "ci/.keep": ""}
			for k, v := range tt.files {
				files[k] = v
			}
			root := writeTree(t, files)
			if tt.link {
				if err := os.Symlink(filepath.Join(root, "real", "sub"), filepath.Join(root, "a", "sub")); err != nil {
					t.Fatal(err)
				}
			}
			found = nil
			w := withheld(root, spec)
			got := len(found)
			if w {
				got = -1
			}
			if got != tt.want {
				t.Fatalf("found %d (%v), want %d", got, found, tt.want)
			}
		})
	}
}
