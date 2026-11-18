package scriptsurface

import (
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
)

// A Dockerfile cursor's Built holds only for a literal relative directory that a plain COPY of
// a build output filled last, that no mount, other write, copy above it or command after it
// beyond one onlyWrites allows reaches, and that sits in no node_modules.
func TestDockerCursorBuilt(t *testing.T) {
	root := writeTree(t, map[string]string{"ctx/api/x.txt": "x\n", "ctx/web/x.txt": "x\n", "img/app/api/x.txt": "x\n", "file": "x\n"})
	spec := testSpec
	spec.Absent = func(err error) bool { return errors.Is(err, fs.ErrNotExist) }
	out := dockerEvent{dst: "/app/api", dir: true, taint: true, built: true}
	tests := []struct {
		name   string
		dir    string
		events []dockerEvent
		mounts []string
		known  bool
		want   bool
	}{
		{"a build output", "api", []dockerEvent{out}, nil, true, true},
		{"before a command that changes only owners", "api", []dockerEvent{out, {all: true, cmd: true, words: []string{"chown", "-R", "api:api", "."}}}, nil, true, true},
		{"after a command whose words were mentioned", "api", []dockerEvent{{all: true, cmd: true}, out}, nil, true, true},
		{"before a command that may write into it", "api", []dockerEvent{out, {all: true, cmd: true, words: []string{"git", "clone", "https://example.test/x.git", "api"}}}, nil, true, false},
		{"before a command whose words are unknown", "api", []dockerEvent{out, {all: true, cmd: true}}, nil, true, false},
		{"before an owner change that redirects", "api", []dockerEvent{out, {all: true, cmd: true, words: []string{"chown", "api", ".", ">api/package.json"}}}, nil, true, false},
		{"before an owner change that expands", "api", []dockerEvent{out, {all: true, cmd: true, words: []string{"chown", "$(cp -r x api)", "."}}}, nil, true, false},
		{"a build output elsewhere", "api", []dockerEvent{{dst: "/app/web", dir: true, taint: true, built: true}}, nil, true, false},
		{"below the root copied from a context that holds it", "api", []dockerEvent{{dst: "/", dir: true, hosts: []string{filepath.Join(root, "img")}}, out}, nil, true, false},
		{"below a tainted root", "api", []dockerEvent{{dst: "/", dir: true, taint: true}, out}, nil, true, false},
		{"below a copy that holds none of it", "api", []dockerEvent{{dst: "/app", dir: true, hosts: []string{filepath.Join(root, "ctx", "web")}}, out}, nil, true, true},
		{"under a mount elsewhere", "api", []dockerEvent{out}, []string{"/root/.npm"}, true, true},
		{"nothing built there", "api", nil, nil, true, false},
		{"under a mount that may be anywhere", "api", []dockerEvent{out}, nil, false, false},
		{"absolute", "/app/api", []dockerEvent{out}, nil, true, false},
		{"brace-expanded", "{api,web}", []dockerEvent{{dst: "/app/{api,web}", dir: true, taint: true, built: true}}, nil, true, false},
		{"holding a backslash", `a\pi`, []dockerEvent{{dst: `/app/a\pi`, dir: true, taint: true, built: true}}, nil, true, false},
		{"through ..", "x/../api", []dockerEvent{out}, nil, true, false},
		{"in node_modules", "node_modules/api", []dockerEvent{{dst: "/app/node_modules/api", dir: true, taint: true, built: true}}, nil, true, false},
		{"under a mount of the root", "api", []dockerEvent{out}, []string{"/"}, true, false},
		{"under a mount of it", "api", []dockerEvent{out}, []string{"/app/api"}, true, false},
		{"under a mount inside it", "api", []dockerEvent{out}, []string{"/app/api/node_modules"}, true, false},
		{"under a mount above it", "x/api", []dockerEvent{{dst: "/app/x/api", dir: true, taint: true, built: true}}, []string{"/app/x"}, true, false},
		{"after a write to everything", "api", []dockerEvent{out, {all: true}}, nil, true, false},
		{"in a stage that wrote everywhere first", "api", []dockerEvent{{all: true}, out}, nil, true, false},
		{"refilled after", "api", []dockerEvent{out, {dst: "/app/api", dir: true, taint: true}}, nil, true, false},
		{"written into after", "api", []dockerEvent{out, {dst: "/app/api/package.json", hosts: []string{filepath.Join(root, "file")}}}, nil, true, false},
		{"below a tainted directory", "api", []dockerEvent{{dst: "/app", dir: true, taint: true}, out}, nil, true, false},
		{"below a copy that holds it", "api", []dockerEvent{{dst: "/app", dir: true, hosts: []string{filepath.Join(root, "ctx")}}, out}, nil, true, false},
		{"below a copy that could not be examined", "api", []dockerEvent{{dst: "/app", dir: true, hosts: []string{filepath.Join(root, "file")}}, out}, nil, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New(root, func(string) bool { return true }, spec)
			c := &dockerCursor{v: v, st: &dockerStage{events: tt.events}, dir: "/app", known: true, mounts: tt.mounts, mountsKnown: tt.known}
			if got := c.Built(tt.dir, "package.json"); got != tt.want {
				t.Fatalf("Built(%q) = %v, want %v", tt.dir, got, tt.want)
			}
			if v.bound["package.json"] != tt.want {
				t.Fatalf("package.json bound = %v, want %v", v.bound["package.json"], tt.want)
			}
		})
	}
}

// Only a plain COPY in a Dockerfile whose every source is a literal path no build context
// holds, or could hold, marks its destination built.
func TestCopyInstrBuilt(t *testing.T) {
	root := writeTree(t, map[string]string{"ci/notes.txt": "x\n", "file": "x\n"})
	spec := testSpec
	spec.Absent = func(err error) bool { return errors.Is(err, fs.ErrNotExist) }
	tests := []struct {
		name  string
		ctx   string
		rest  string
		add   bool
		earth bool
		want  bool
	}{
		{"an absent source", ".", "dist/api api", false, false, true},
		{"beside a source that is there", ".", "dist/api ci/notes.txt api/", false, false, false},
		{"from a glob", ".", "dist/ap* api", false, false, false},
		{"from a context that could not be examined", "file", "dist/api api", false, false, false},
		{"by ADD", ".", "dist/api api", true, false, false},
		{"from another stage", ".", "--from=build dist/api api", false, false, false},
		{"in an Earthfile", ".", "dist/api api", false, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New(root, func(string) bool { return true }, spec)
			st := &dockerStage{wd: "/app", wdKnown: true}
			st.copyInstr(v, []string{filepath.Join(root, tt.ctx)}, tt.rest, tt.add, tt.earth)
			got := false
			for _, e := range st.events {
				got = got || e.built
			}
			if got != tt.want {
				t.Fatalf("built = %v, want %v (events %+v)", got, tt.want, st.events)
			}
		})
	}
}
