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
		{"written through a variable", map[string]string{"install.sh": "#!/bin/sh\nD=plug\nmkdir -p $D/sub\ninst build\n"}, "", true},
		{"a command naming another path's sub", map[string]string{"install.sh": "#!/bin/sh\nls tests/sub\ninst build\n"}, "", false},
		{"whole context copied, nothing there", nil, "FROM python:3.12\nWORKDIR /app\nCOPY . .\nRUN inst build\n", false},
		{"whole context copied", map[string]string{"plug/sub/x": "x\n"}, "FROM python:3.12\nWORKDIR /app\nCOPY . .\nRUN inst build\n", true},
		{"left out of the image", map[string]string{"plug/sub/x": "x\n"}, head + "RUN inst build\n", false},
		{"a stage built on one that copied it", map[string]string{"plug/sub/x": "x\n"},
			"FROM python:3.12 AS src\nWORKDIR /app\nCOPY . .\nFROM src\nWORKDIR /app\nCOPY inst.toml inst.lock ./\nRUN inst build\n", true},
		{"copied to a destination not known", map[string]string{"plug/sub/x": "x\n"}, "FROM python:3.12\nARG D=/app\nWORKDIR /app\nCOPY plug $D/\nCOPY inst.toml inst.lock ./\nRUN inst build\n", true},
		{"a file copied onto a directory above it", map[string]string{"other/sub": "x\n"}, "FROM python:3.12\nWORKDIR /app\nCOPY other/sub /app/plug\nCOPY inst.toml inst.lock ./\nRUN inst build\n", true},
		{"a stage copied over a directory above it", nil, "FROM python:3.12 AS b\nFROM python:3.12\nWORKDIR /app\nCOPY --from=b /p /app\nCOPY inst.toml inst.lock ./\nRUN inst build\n", true},
		{"the context bind-mounted over the workdir", map[string]string{"plug/sub/x": "x\n"}, head + "RUN --mount=type=bind,source=.,target=/app inst build\n", true},
		{"a quoted mount target", map[string]string{"plug/sub/x": "x\n"}, head + "RUN --mount=type=bind,source=.,target=\"/app\" inst build\n", true},
		{"written through an ENV value", nil, "FROM python:3.12\nENV P /app/plug/sub\nRUN mkdir -p $P\n" + head + "RUN inst build\n", true},
		{"written through an ARG value", nil, "FROM python:3.12\nARG P=/app/plug\nRUN mkdir -p $P/sub\n" + head + "RUN inst build\n", true},
		{"written after a cd", nil, "FROM python:3.12\nWORKDIR /app\nRUN cd plug && mkdir sub\n" + head + "RUN inst build\n", true},
		{"written under a WORKDIR inside it", nil, "FROM python:3.12\nWORKDIR /app/plug\nRUN mkdir sub\n" + head + "RUN inst build\n", true},
		{"made by a WORKDIR", nil, "FROM python:3.12\nWORKDIR /app/plug/sub\n" + head + "RUN inst build\n", true},
		{"a mount with no target", nil, head + "RUN --mount=type=bind,source=. inst build\n", true},
		{"a mount at the root", nil, head + "RUN --mount=type=cache,target=/ inst build\n", true},
		{"a mount under it", nil, head + "RUN --mount=type=cache,target=/app/plug/sub/c inst build\n", true},
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

// A symlink at the path or on the way to it is something there, dangling or not: its target
// may be made before the build reads it.
func TestClear_Symlink(t *testing.T) {
	for _, link := range []string{"plug/sub", "plug"} {
		t.Run(link, func(t *testing.T) {
			root := writeTree(t, map[string]string{"inst.toml": "x\n", "other/.keep": ""})
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root, link)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(root, "later"), filepath.Join(root, link)); err != nil {
				t.Fatal(err)
			}
			c := &hostCursor{v: New(root, func(string) bool { return true }, testSpec), dirs: []string{root}}
			if c.Clear("inst.toml", "plug/sub") {
				t.Fatal("Clear = true, want false")
			}
		})
	}
}
