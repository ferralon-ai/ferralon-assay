package scriptsurface

import (
	"os"
	"path/filepath"
	"testing"
)

// Clear: inst build is allowed only with nothing at plug/sub beside inst.toml, in the tree,
// under a Dockerfile, or named by a command.
func TestVeto_Clear(t *testing.T) {
	spec := testSpec
	spec.Allowed = func(words []string, b Binder) bool {
		if len(words) == 2 && words[0] == "inst" && words[1] == "build" {
			return b.Nearest("inst.toml", "inst.lock") != nil && b.Clear("inst.toml", "plug/sub")
		}
		return testSpec.Allowed(words, b)
	}
	const head = "FROM python:3.12\nWORKDIR /app\nCOPY inst.toml inst.lock ./\n"
	tests := []struct {
		name       string
		files      map[string]string
		dockerfile string
		want       bool // withheld
	}{
		{"nothing there", nil, "", false},
		{"committed", map[string]string{"plug/sub/x": "x\n"}, "", true},
		{"written by a command", map[string]string{"install.sh": "#!/bin/sh\nmkdir -p plug/sub/x\ninst build\n"}, "", true},
		{"written by a command through an absolute path", map[string]string{"install.sh": "#!/bin/sh\nmkdir -p /w/plug/sub\ninst build\n"}, "", true},
		{"a command naming another path's sub", map[string]string{"install.sh": "#!/bin/sh\nls tests/sub\ninst build\n"}, "", false},
		{"whole context copied, nothing there", nil, "FROM python:3.12\nWORKDIR /app\nCOPY . .\nRUN inst build\n", false},
		{"whole context copied", map[string]string{"plug/sub/x": "x\n"}, "FROM python:3.12\nWORKDIR /app\nCOPY . .\nRUN inst build\n", true},
		{"left out of the image", map[string]string{"plug/sub/x": "x\n"}, head + "RUN inst build\n", false},
		{"a stage built on one that copied it", map[string]string{"plug/sub/x": "x\n"},
			"FROM python:3.12 AS src\nWORKDIR /app\nCOPY . .\nFROM src\nWORKDIR /app\nCOPY inst.toml inst.lock ./\nRUN inst build\n", true},
		{"copied to a destination not known", map[string]string{"plug/sub/x": "x\n"}, "FROM python:3.12\nARG D=/app\nWORKDIR /app\nCOPY plug $D/\nCOPY inst.toml inst.lock ./\nRUN inst build\n", true},
		{"a file copied onto a directory above it", map[string]string{"other/sub": "x\n"}, "FROM python:3.12\nWORKDIR /app/plug\nWORKDIR /app\nCOPY other/sub /app/plug\nCOPY inst.toml inst.lock ./\nRUN inst build\n", true},
		{"the context bind-mounted over the workdir", map[string]string{"plug/sub/x": "x\n"}, head + "RUN --mount=type=bind,source=.,target=/app inst build\n", true},
		{"a mount with no target", nil, head + "RUN --mount=type=bind,source=. inst build\n", true},
		{"a cache mounted elsewhere", nil, head + "RUN --mount=type=cache,target=/root/.cache inst build\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"inst.toml": "x\n", "inst.lock": "x\n"}
			switch {
			case tt.dockerfile != "":
				files["Dockerfile"] = tt.dockerfile
			case tt.files["install.sh"] == "":
				files["install.sh"] = "#!/bin/sh\ninst build\n"
			}
			for k, v := range tt.files {
				files[k] = v
			}
			if got := withheld(writeTree(t, files), spec); got != tt.want {
				t.Fatalf("withheld = %v, want %v", got, tt.want)
			}
		})
	}
}

// A dangling symlink at the path is something there: its target may be made before the build
// reads it.
func TestClear_DanglingSymlink(t *testing.T) {
	root := writeTree(t, map[string]string{"inst.toml": "x\n", "plug/.keep": ""})
	if err := os.Symlink(filepath.Join(root, "later"), filepath.Join(root, "plug", "sub")); err != nil {
		t.Fatal(err)
	}
	c := &hostCursor{v: New(root, func(string) bool { return true }, testSpec), dirs: []string{root}}
	if c.Clear("inst.toml", "plug/sub") {
		t.Fatal("Clear = true, want false")
	}
}
