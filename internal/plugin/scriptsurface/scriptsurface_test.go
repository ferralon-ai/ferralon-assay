package scriptsurface

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
)

// testSpec is a lane that installs with "inst": inst sync binds inst.toml and inst.lock, inst
// run <name> binds inst.toml, inst install -r <file> binds that file, and instw run <argv> runs
// argv where inst.toml is read.
var testSpec = Spec{
	Token: func(w string) bool { return w == "inst" || w == "instw" },
	Env:   regexp.MustCompile(`(?:^|[^$A-Za-z0-9_{.])INST_[A-Z0-9_]+`),
	Allowed: func(words []string, b Binder) bool {
		head, ok := CommandName(words[0])
		if !ok || head != "inst" || len(words) < 2 {
			return false
		}
		switch words[1] {
		case "sync":
			return FlagsOnly(words[2:], map[string]bool{"-q": true}) && b.Nearest("inst.toml", "inst.lock") != nil
		case "run":
			return len(words) == 3 && b.Nearest("inst.toml") != nil
		case "install":
			return len(words) == 4 && words[2] == "-r" && b.File(words[3])
		}
		return false
	},
	RunWrapper: func(words []string) ([]string, bool) {
		if len(words) >= 2 && words[0] == "instw" && words[1] == "run" {
			return words[2:], true
		}
		return nil, false
	},
	RunBinds:    func(_ []string, b Binder) bool { return b.Nearest("inst.toml") != nil },
	ReadRegular: os.ReadFile,
	Absent: func(err error) bool {
		return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
	},
}

// testRead is the lane's own read check: the files it reads are the regular inst.toml,
// inst.lock and reqs.txt files inside the build root.
func testRead(root string) func(string) bool {
	return func(p string) bool {
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return false
		}
		switch filepath.Base(p) {
		case "inst.toml", "inst.lock", "reqs.txt":
		default:
			return false
		}
		fi, err := os.Stat(p)
		return err == nil && fi.Mode().IsRegular()
	}
}

// withheld runs the veto over root as a lane's version-surface walk does, with a classifier
// that matches nothing else, and reports whether it withholds the build's versions.
func withheld(root string, spec Spec) bool {
	v := New(root, testRead(root), spec)
	none := func(string, []byte) (string, bool) { return "", false }
	for _, c := range buildtree.Candidates(root, v.Classify(none), v.FullyRead) {
		if !c.FullyRead {
			return true
		}
	}
	return v.Rebound()
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// How a surface is read and what binds a command to a file, whatever the lane: rows here use
// testSpec, and each lane's own forms, variables and reads are rowed in that lane.
func TestVeto_LaneNeutral(t *testing.T) {
	const docker = "FROM base\nWORKDIR /app\nCOPY inst.toml inst.lock reqs.txt ./\nRUN "
	tree := func(extra map[string]string) map[string]string {
		files := map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n", "reqs.txt": "x==1\n"}
		for k, v := range extra {
			files[k] = v
		}
		return files
	}
	ci := func(wd, run string) string {
		return "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    defaults:\n      run:\n        working-directory: " +
			wd + "\n    steps:\n      - run: " + run + "\n"
	}
	steps := func(body string) string {
		return "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      " + body
	}
	tests := []struct {
		name  string
		files map[string]string
		want  bool   // withheld
		root  string // the build root, under the tree written
	}{
		// Surfaces and words.
		{"tox.ini commands", tree(map[string]string{"tox.ini": "[testenv]\ncommands_pre =\n    inst add x\ncommands = pytest\n"}), true, ""},
		{"package.json scripts gated whatever the key", tree(map[string]string{"package.json": `{"scripts":{"postinstall":"inst add x"}}`}), true, ""},
		{"script value that is not a string", tree(map[string]string{"package.json": `{"scripts":{"setup":["inst","add"]}}`}), true, ""},
		{"token behind sudo", tree(map[string]string{"install.sh": "sudo inst add x\n"}), true, ""},
		{"token behind xargs", tree(map[string]string{"install.sh": "xargs -a extra.txt inst install\n"}), true, ""},
		{"chained allowed then named", tree(map[string]string{"install.sh": "inst sync && inst add x\n"}), true, ""},
		{"hyphenated action name", tree(map[string]string{".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: org/inst-action@v1\n"}), true, ""},
		{"hyphenated tool name", tree(map[string]string{"install.sh": "inst_wrapper x\n"}), true, ""},
		{"input key naming a token", tree(map[string]string{".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: org/setup@v1\n        with:\n          inst-args: x==2\n"}), true, ""},
		{"installer variable set", tree(map[string]string{"install.sh": "export INST_INDEX=https://x\ninst sync\n"}), true, ""},

		// PowerShell and batch, which are not parsed, and GitLab includes.
		{"PowerShell install", tree(map[string]string{"install.ps1": "Set-Location app\ninst sync\n"}), true, ""},
		{"batch install", tree(map[string]string{"install.bat": "@echo off\r\ninst add x\r\n"}), true, ""},
		{"cmd install", tree(map[string]string{"setup.cmd": "call inst sync\r\n"}), true, ""},
		{"PowerShell install verb after an expansion", tree(map[string]string{"install.ps1": "& $pm install x\n"}), true, ""},
		{"PowerShell sets an installer variable", tree(map[string]string{"install.ps1": "$env:INST_INDEX = 'https://x'\n"}), true, ""},
		{"PowerShell that never installs", tree(map[string]string{"build.ps1": "Write-Host build\ndotnet build\n"}), false, ""},
		{"PowerShell rewrites a file an install binds", tree(map[string]string{"install.sh": "inst sync\n", "fix.ps1": "Copy-Item x inst.lock\n"}), true, ""},
		{"make include file installs", tree(map[string]string{"Makefile": "include deps.make\n", "deps.make": "deps:\n\tinst add x\n"}), true, ""},
		{".gitlab-ci.yaml install", tree(map[string]string{".gitlab-ci.yaml": "build:\n  script:\n    - inst add x\n"}), true, ""},
		{"GitLab local include installs", tree(map[string]string{".gitlab-ci.yml": "include:\n  - local: ci/build.yml\n", "ci/build.yml": "build:\n  script:\n    - inst add x\n"}), true, ""},
		{"GitLab string include installs", tree(map[string]string{".gitlab-ci.yml": "include: '/ci/build.yml'\n", "ci/build.yml": "build:\n  script:\n    - inst add x\n"}), true, ""},
		{"GitLab nested local include installs", tree(map[string]string{".gitlab-ci.yml": "include:\n  - local: ci/a.yml\n", "ci/a.yml": "include: ci/b.yml\n", "ci/b.yml": "build:\n  script:\n    - inst add x\n"}), true, ""},
		{"GitLab include sets an installer variable", tree(map[string]string{".gitlab-ci.yml": "include: ci/vars.yml\n", "ci/vars.yml": "variables:\n  INST_INDEX: https://x\n"}), true, ""},
		{"GitLab remote include", tree(map[string]string{".gitlab-ci.yml": "include:\n  - remote: https://example.com/ci.yml\n"}), true, ""},
		{"GitLab remote include, string form", tree(map[string]string{".gitlab-ci.yml": "include: https://example.com/ci.yml\n"}), true, ""},
		{"GitLab template include", tree(map[string]string{".gitlab-ci.yml": "include:\n  - template: Python.gitlab-ci.yml\n"}), true, ""},
		{"GitLab project include", tree(map[string]string{".gitlab-ci.yml": "include:\n  - project: org/ci\n    file: /build.yml\n"}), true, ""},
		{"GitLab component include", tree(map[string]string{".gitlab-ci.yml": "include:\n  - component: $CI_SERVER_FQDN/org/c@1\n"}), true, ""},
		{"GitLab local include glob", tree(map[string]string{".gitlab-ci.yml": "include: 'ci/*.yml'\n", "ci/build.yml": "build:\n  script:\n    - echo\n"}), true, ""},
		{"GitLab local include with a variable", tree(map[string]string{".gitlab-ci.yml": "include: ci/$ENV.yml\n"}), true, ""},
		{"GitLab local include not there", tree(map[string]string{".gitlab-ci.yml": "include: ci/missing.yml\n"}), true, ""},
		{"GitLab local include outside the tree", tree(map[string]string{".gitlab-ci.yml": "include: ../ci.yml\n"}), true, ""},
		{"GitLab include in a document after a spec header", tree(map[string]string{".gitlab-ci.yml": "include:\n  - local: ci/build.yml\n", "ci/build.yml": "spec:\n  inputs:\n    env:\n      default: prod\n---\ninclude:\n  - local: ci/deep.yml\n", "ci/deep.yml": "build:\n  script:\n    - inst add x\n"}), true, ""},
		{"GitLab remote include in a document after a spec header", tree(map[string]string{".gitlab-ci.yml": "include:\n  - local: ci/build.yml\n", "ci/build.yml": "spec:\n  inputs:\n    env:\n      default: prod\n---\ninclude:\n  - remote: https://example.com/ci.yml\n"}), true, ""},
		{"GitLab spec header then a local include that never installs", tree(map[string]string{".gitlab-ci.yml": "include:\n  - local: ci/build.yml\n", "ci/build.yml": "spec:\n  inputs:\n    env:\n      default: prod\n---\ninclude:\n  - local: ci/test.yml\n", "ci/test.yml": "test:\n  script:\n    - pytest\n"}), false, ""},
		{"GitLab local include that never installs", tree(map[string]string{".gitlab-ci.yml": "include:\n  - local: ci/test.yml\n", "ci/test.yml": "test:\n  script:\n    - pytest\n"}), false, ""},
		{"GitLab local includes in a cycle", tree(map[string]string{".gitlab-ci.yml": "include: ci/a.yml\n", "ci/a.yml": "include: ci/b.yml\n", "ci/b.yml": "include: ci/a.yml\n"}), false, ""},

		// YAML scalars a build folds into one command.
		{"folded block joins its lines", tree(map[string]string{".github/workflows/ci.yml": steps("- run: >\n          inst sync\n          x\n")}), true, ""},
		{"folded block, strip chomping and a comment", tree(map[string]string{".gitlab-ci.yml": "build:\n  script:\n    - >- # install\n      inst sync\n      x\n"}), true, ""},
		{"plain scalar continued on the next line", tree(map[string]string{".github/workflows/ci.yml": steps("- run: inst sync\n          x\n")}), true, ""},
		{"double-quoted scalar continued on the next line", tree(map[string]string{".github/workflows/ci.yml": steps("- run: \"inst sync\n          x\"\n")}), true, ""},

		// Expansions, redirects and lines that do not tokenise.
		{"$VAR argument", tree(map[string]string{"install.sh": "inst install -r $REQS\n"}), true, ""},
		{"$VAR in place of a name an allowed form takes", tree(map[string]string{"install.sh": "inst run $X\n"}), true, ""},
		{"redirect in place of a name an allowed form takes", tree(map[string]string{"install.sh": "inst run >log\n"}), true, ""},
		{"variable installer", tree(map[string]string{"Makefile": "deps:\n\t$(VENV)/bin/inst sync\n"}), true, ""},
		{"variable package manager then an install verb", tree(map[string]string{"install.sh": "\"$PM\" add x\n"}), true, ""},
		{"variable package manager behind sudo", tree(map[string]string{"install.sh": "sudo -E $INSTALLER install x\n"}), true, ""},
		{"make variable installer then an install verb", tree(map[string]string{"Makefile": "deps:\n\t$(PKG) install x\n"}), true, ""},
		{"redirect", tree(map[string]string{"install.sh": "inst sync > /tmp/log\n"}), true, ""},
		{"unterminated quote", tree(map[string]string{"install.sh": "echo 'x && inst sync\n"}), true, ""},
		{"unjoined continuation", tree(map[string]string{"install.sh": "inst sync \\"}), true, ""},

		// Run wrappers.
		{"run wrapper argv gated", tree(map[string]string{"install.sh": "instw run inst add x\n"}), true, ""},
		{"run wrapper with no manifest", map[string]string{"reqs.txt": "x==1\n", "install.sh": "instw run serve\n"}, true, ""},
		{"run wrappers nested past the bound", tree(map[string]string{"install.sh": "instw run instw run instw run instw run instw run inst sync\n"}), true, ""},

		// Binding on the host.
		{"cd outside the tree", tree(map[string]string{"install.sh": "cd /opt/x && inst sync\n"}), true, ""},
		{"CI working-directory outside the tree", tree(map[string]string{".github/workflows/ci.yml": ci("../other", "inst sync")}), true, ""},
		{"upward walk leaves the tree", map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", "tools/run.sh": "inst sync\n"}, true, ""},
		{"upward walk reaches a manifest outside the build root", tree(map[string]string{"app/reqs.txt": "x==1\n", "app/tools/run.sh": "inst run build\n"}), true, "app"},
		{"sources an extensionless file", tree(map[string]string{"install.sh": ". ./scripts/prod\ninst sync\n", "scripts/prod": "inst add x\n"}), true, ""},
		{"sources a file that is not a surface", tree(map[string]string{"install.sh": "source ./scripts/prod.inc\ninst sync\n", "scripts/prod.inc": "inst add x\n"}), true, ""},
		{"sources a file named by a variable", tree(map[string]string{"install.sh": ". ./scripts/$ENV.sh\ninst sync\n", "scripts/prod.sh": "echo\n"}), true, ""},
		{"sources a file in a directory the walk skips", tree(map[string]string{"install.sh": ". node_modules/x/env.sh\ninst sync\n", "node_modules/x/env.sh": "inst add x\n"}), true, ""},
		{"script fetches the file it installs", tree(map[string]string{"install.sh": "curl -fsSL -o inst.toml https://example.com/x\ninst sync\n"}), true, ""},

		// Binding in a Dockerfile.
		{"Dockerfile without WORKDIR", tree(map[string]string{"Dockerfile": "FROM base\nCOPY inst.toml inst.lock ./\nRUN inst sync\n"}), true, ""},
		{"Dockerfile RUN between COPY and install", tree(map[string]string{"Dockerfile": docker + "tool rewrite\nRUN inst sync\n"}), true, ""},
		{"Dockerfile fetches over the file then installs", tree(map[string]string{"Dockerfile": docker + "curl -fsSL https://example.com/x -o inst.toml && inst sync\n"}), true, ""},
		{"Dockerfile installs a file it fetched", tree(map[string]string{"Dockerfile": "FROM base\nWORKDIR /app\nRUN curl -fsSL https://example.com/r.txt -o /tmp/r.txt\nRUN inst install -r /tmp/r.txt\n"}), true, ""},
		{"Dockerfile COPY --from over the file", tree(map[string]string{"Dockerfile": "FROM base AS builder\nRUN true\nFROM base\nWORKDIR /app\nCOPY inst.toml inst.lock ./\nCOPY --from=builder /x/inst.toml ./\nRUN inst sync\n"}), true, ""},
		{"Dockerfile COPY --from naming a context path", tree(map[string]string{"Dockerfile": "FROM base AS builder\nRUN true\nFROM base\nWORKDIR /app\nCOPY inst.toml inst.lock ./\nCOPY --from=builder inst.toml ./\nRUN inst sync\n"}), true, ""},
		{"Dockerfile COPY glob with a wildcard directory", tree(map[string]string{"svc/inst.toml": "[deps]\n", "Dockerfile": "FROM base\nWORKDIR /app\nCOPY inst.toml inst.lock ./\nCOPY */inst.toml ./\nRUN inst sync\n"}), true, ""},

		// Controls.
		{"literal block keeps a command per line", tree(map[string]string{".github/workflows/ci.yml": steps("- run: |\n          inst sync\n          inst run build\n")}), false, ""},
		{"folded block, a blank line between commands", tree(map[string]string{".github/workflows/ci.yml": steps("- run: >\n          inst sync\n\n          inst run build\n        name: deps\n")}), false, ""},
		{"folded block under a key a build never runs", tree(map[string]string{".github/workflows/ci.yml": steps("- name: >\n          inst add x\n        run: inst sync\n")}), false, ""},
		{"plain scalar beside a sibling key", tree(map[string]string{".github/workflows/ci.yml": steps("- run: inst sync\n        name: deps\n")}), false, ""},
		{"job key naming a token opens a block", tree(map[string]string{".gitlab-ci.yml": "inst-build: &job\n  script:\n    - inst sync\n"}), false, ""},
		{"make variable", tree(map[string]string{"Makefile": "all:\n\t$(MAKE) -C sub\n\t$(MAKE) install\n\t${MAKE} build\n\t$(CC) -o x x.c\n"}), false, ""},
		{"expansion not followed by an install verb", tree(map[string]string{"install.sh": "$TOOL build\necho \"$X\" done\n"}), false, ""},
		{"surface with no installer", tree(map[string]string{"install.sh": "#!/bin/sh\nset -e\nserve\n"}), false, ""},
		{"allowed forms", tree(map[string]string{"Makefile": "deps:\n\tinst sync -q\n\tinst install -r reqs.txt\n\tinst run build\n"}), false, ""},
		{"package.json script running an allowed form", tree(map[string]string{"package.json": `{"scripts":{"build":"inst run build"}}`}), false, ""},
		{"run wrapper", tree(map[string]string{"Procfile": "web: instw run serve\n"}), false, ""},
		{"sources an in-tree script", tree(map[string]string{"install.sh": ". ./env.sh\ninst sync\n", "env.sh": "export A=1\n"}), false, ""},
		{"cd to an in-tree directory", map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", "install.sh": "cd app && inst sync\n"}, false, ""},
		{"CI working-directory in the tree", tree(map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", ".github/workflows/ci.yml": ci("app", "inst sync")}), false, ""},
		{"Dockerfile COPY, install, COPY . ., run", tree(map[string]string{"Dockerfile": docker + "inst sync\nCOPY . .\nRUN inst run build\nCMD [\"inst\", \"run\", \"serve\"]\n"}), false, ""},
		{"Dockerfile COPY glob then install", tree(map[string]string{"Dockerfile": "FROM base\nWORKDIR /app\nCOPY inst.* ./\nRUN inst sync\n"}), false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := withheld(filepath.Join(writeTree(t, tt.files), tt.root), testSpec); got != tt.want {
				t.Fatalf("withheld = %v, want %v", got, tt.want)
			}
		})
	}
}

// The shared code keeps nothing by default: a Spec that leaves a decision out withholds where
// that decision would be needed.
func TestVeto_SpecDecidesEveryKeep(t *testing.T) {
	without := func(f func(*Spec)) Spec {
		s := testSpec
		f(&s)
		return s
	}
	files := map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n"}
	tests := []struct {
		name   string
		spec   Spec
		script string
		want   bool // withheld
	}{
		{"empty spec, surface with no installer", Spec{}, "#!/bin/sh\nserve\n", true},
		{"no Token", without(func(s *Spec) { s.Token = nil }), "serve\n", true},
		{"no Env", without(func(s *Spec) { s.Env = nil }), "serve\n", true},
		{"no Allowed", without(func(s *Spec) { s.Allowed = nil }), "serve\n", true},
		{"no ReadRegular", without(func(s *Spec) { s.ReadRegular = nil }), "serve\n", true},
		{"no Absent", without(func(s *Spec) { s.Absent = nil }), "serve\n", true},
		{"no RunBinds", without(func(s *Spec) { s.RunBinds = nil }), "instw run serve\n", true},
		{"no RunWrapper", without(func(s *Spec) { s.RunWrapper = nil }), "instw run serve\n", true},
		{"complete spec", testSpec, "instw run serve\ninst sync\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := map[string]string{"install.sh": tt.script}
			for k, v := range files {
				f[k] = v
			}
			if got := withheld(writeTree(t, f), tt.spec); got != tt.want {
				t.Fatalf("withheld = %v, want %v", got, tt.want)
			}
		})
	}
}
