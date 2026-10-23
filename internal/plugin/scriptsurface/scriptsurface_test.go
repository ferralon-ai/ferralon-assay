package scriptsurface

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
	return v.Withheld()
}

// gitlabChain is a pipeline whose local includes nest n files deep, none of which installs.
func gitlabChain(n int) map[string]string {
	files := map[string]string{".gitlab-ci.yml": "include: ci/c0.yml\n"}
	for i := 0; i < n; i++ {
		body := "test:\n  script:\n    - pytest\n"
		if i+1 < n {
			body = "include: ci/c" + strconv.Itoa(i+1) + ".yml\n"
		}
		files["ci/c"+strconv.Itoa(i)+".yml"] = body
	}
	return files
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
		{"GitLab local include outside the tree, file there", map[string]string{"app/.gitlab-ci.yml": "include: ../x.yml\n", "x.yml": "test:\n  script:\n    - pytest\n"}, true, "app"},
		{"GitLab include item naming a project beside a local", tree(map[string]string{".gitlab-ci.yml": "include:\n  - local: ci/a.yml\n    project: g/p\n", "ci/a.yml": "test:\n  script:\n    - pytest\n"}), true, ""},
		{"GitLab include item naming a template beside a local", tree(map[string]string{".gitlab-ci.yml": "include:\n  - local: ci/a.yml\n    template: Python.gitlab-ci.yml\n", "ci/a.yml": "test:\n  script:\n    - pytest\n"}), true, ""},
		{"GitLab include item naming a component beside a local", tree(map[string]string{".gitlab-ci.yml": "include:\n  - local: ci/a.yml\n    component: org/c@1\n", "ci/a.yml": "test:\n  script:\n    - pytest\n"}), true, ""},
		{"GitLab include item naming a remote beside a local", tree(map[string]string{".gitlab-ci.yml": "include:\n  - local: ci/a.yml\n    remote: https://example.com/ci.yml\n", "ci/a.yml": "test:\n  script:\n    - pytest\n"}), true, ""},
		{"GitLab include through a YAML alias", tree(map[string]string{".gitlab-ci.yml": ".r: &r\n  project: g/p\n  file: f.yml\ninclude:\n  - *r\n"}), true, ""},
		{"GitLab pipeline that does not decode and names include", tree(map[string]string{".gitlab-ci.yml": "include: [ci/a.yml\nbuild: {\n"}), true, ""},
		{"GitLab local includes nested past the bound", tree(gitlabChain(18)), true, ""},
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
		{"pushd outside the tree", tree(map[string]string{"install.sh": "pushd /opt/x && inst sync\n"}), true, ""},
		{"popd leaves the directory unknown", map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", "install.sh": "cd app && popd && inst sync\n"}, true, ""},
		{"cd with two operands", map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", "install.sh": "cd app extra && inst sync\n"}, true, ""},
		{"cd to an absolute path that names a tree directory", map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", "install.sh": "cd /app && inst sync\n"}, true, ""},
		{"CI working-directory outside the tree", tree(map[string]string{".github/workflows/ci.yml": ci("../other", "inst sync")}), true, ""},
		{"upward walk leaves the tree", map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", "tools/run.sh": "inst sync\n"}, true, ""},
		{"upward walk reaches a manifest outside the build root", tree(map[string]string{"app/reqs.txt": "x==1\n", "app/tools/run.sh": "inst run build\n"}), true, "app"},
		{"sources an extensionless file", tree(map[string]string{"install.sh": ". ./scripts/prod\ninst sync\n", "scripts/prod": "inst add x\n"}), true, ""},
		{"sources a file that is not a surface", tree(map[string]string{"install.sh": "source ./scripts/prod.inc\ninst sync\n", "scripts/prod.inc": "inst add x\n"}), true, ""},
		{"source with no operand", tree(map[string]string{"install.sh": "source\ninst sync\n"}), true, ""},
		{"dot with no operand", tree(map[string]string{"install.sh": ".\ninst sync\n"}), true, ""},
		{"sources after a cd the walk cannot follow", tree(map[string]string{"install.sh": "cd /somewhere\n. ./lib.sh\n", "lib.sh": "export A=1\n"}), true, ""},
		{"sources an absolute path that names a tree script", tree(map[string]string{"install.sh": ". /lib.sh\ninst sync\n", "lib.sh": "export A=1\n"}), true, ""},
		{"sources a script above the build root", map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", "app/install.sh": ". ../outside.sh\ninst sync\n", "outside.sh": "export A=1\n"}, true, "app"},
		{"sources a script that is not there", tree(map[string]string{"install.sh": ". ./missing.sh\ninst sync\n"}), true, ""},
		{"sources a file named by a variable", tree(map[string]string{"install.sh": ". ./scripts/$ENV.sh\ninst sync\n", "scripts/prod.sh": "echo\n"}), true, ""},
		{"sources a file in a directory the walk skips", tree(map[string]string{"install.sh": ". node_modules/x/env.sh\ninst sync\n", "node_modules/x/env.sh": "inst add x\n"}), true, ""},
		{"script fetches the file it installs", tree(map[string]string{"install.sh": "curl -fsSL -o inst.toml https://example.com/x\ninst sync\n"}), true, ""},
		{"activates a venv no command created", tree(map[string]string{"install.sh": ". .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv other than the one created", tree(map[string]string{"install.sh": "python -m venv a\n. b/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv before creating it", tree(map[string]string{"install.sh": ". .venv/bin/activate\npython -m venv .venv\ninst sync\n"}), true, ""},
		{"activates a venv another script created", tree(map[string]string{"setup.sh": "python -m venv .venv\n", "install.sh": ". .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv another CI job created", tree(map[string]string{".github/workflows/ci.yml": "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: python -m venv .venv\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: . .venv/bin/activate && inst sync\n"}), true, ""},
		{"activates a venv named by a variable", tree(map[string]string{"install.sh": "python -m venv .venv\n. $VENV/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv created by a variable", tree(map[string]string{"install.sh": "python -m venv $VENV\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv after a cd the walk cannot follow", tree(map[string]string{"install.sh": "python -m venv .venv\ncd /somewhere\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv from another directory than it was created in", map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", "install.sh": "python -m venv .venv\ncd app\n. .venv/bin/activate\ninst sync\n"}, true, ""},
		{"activates a venv after a command that may rewrite it", tree(map[string]string{"install.sh": "python -m venv .venv\ntar xf cache.tgz\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv a flag value names", tree(map[string]string{"install.sh": "uv venv -p venv\n. venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv uv made under another directory", tree(map[string]string{"install.sh": "uv venv --directory sub\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv with two operands", tree(map[string]string{"install.sh": "virtualenv a b\n. a/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv with an extra argument", tree(map[string]string{"install.sh": "python -m venv .venv\n. .venv/bin/activate x\ninst sync\n"}), true, ""},
		{"activates a venv in a Dockerfile RUN after the one that created it", tree(map[string]string{"Dockerfile": "FROM base\nRUN python -m venv /opt/venv\nRUN . /opt/venv/bin/activate\n"}), true, ""},
		{"activates a venv in a Dockerfile without WORKDIR, relative", tree(map[string]string{"Dockerfile": "FROM base\nRUN python -m venv .venv && . .venv/bin/activate\n"}), true, ""},
		{"activates a committed in-tree script that installs", tree(map[string]string{"install.sh": "python -m venv venv\n. venv/bin/activate\ninst sync\n", "venv/bin/activate": "#!/bin/sh\ninst add x\n"}), true, ""},
		{"activates in one CI step a venv the step before created", tree(map[string]string{".github/workflows/ci.yml": steps("- run: python -m venv .venv\n      - run: |\n          . .venv/bin/activate\n          inst sync\n")}), true, ""},
		{"activates in one GitLab job a venv another job created", tree(map[string]string{".gitlab-ci.yml": "a:\n  script:\n    - python -m venv .venv\nb:\n  script:\n    - source .venv/bin/activate\n    - inst sync\n"}), true, ""},
		{"activates in after_script a venv script created", tree(map[string]string{".gitlab-ci.yml": "build:\n  script:\n    - python -m venv .venv\n  after_script:\n    - source .venv/bin/activate\n    - inst sync\n"}), true, ""},
		{"activates a venv in a run block after a command that may rewrite it", tree(map[string]string{".github/workflows/ci.yml": steps("- run: |\n          python -m venv .venv\n          tar xf cache.tgz\n          . .venv/bin/activate\n          inst sync\n")}), true, ""},
		{"activates a venv after a fallback cd, over a committed activate", tree(map[string]string{"install.sh": "python -m venv a/b/.venv\ncd a || cd b\n. .venv/bin/activate\ninst sync\n", "a/b/keep": "", "a/.venv/bin/activate": "# x\ninst add x\n"}), true, ""},
		{"activates a venv in a run block after a fallback cd, over a committed activate", tree(map[string]string{".github/workflows/ci.yml": steps("- run: |\n          python -m venv a/b/.venv\n          cd a || cd b\n          . .venv/bin/activate\n          inst sync\n"), "a/b/keep": "", "a/.venv/bin/activate": "# x\ninst add x\n"}), true, ""},
		{"activates a venv a creation joined to its cd may not have made, over a committed activate", tree(map[string]string{"install.sh": "python -m venv sub/.venv && cd sub\n. .venv/bin/activate\ninst sync\n", "sub/keep": "", ".venv/bin/activate": "# x\ninst add x\n"}), true, ""},
		{"activates a venv a guarded creation may not have made, past a comment", tree(map[string]string{"install.sh": "test -d .venv ||\n# cache miss\npython -m venv .venv\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv a guarded creation may not have made, past a blank line", tree(map[string]string{"install.sh": "test -d .venv ||\n\npython -m venv .venv\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv in a run block a guarded creation may not have made, past a comment", tree(map[string]string{".github/workflows/ci.yml": steps("- run: |\n          test -d .venv ||\n          # cache miss\n          python -m venv .venv\n          . .venv/bin/activate\n          inst sync\n")}), true, ""},
		{"activates a venv a creation in an if body may not have made, after a heredoc holding fi", tree(map[string]string{"install.sh": "cat > notes <<EOF\nfi\nEOF\nif [ ! -d .venv ]; then\npython -m venv .venv\n. .venv/bin/activate\nfi\ninst sync\n"}), true, ""},
		{"activates a venv after a backgrounded cd, over a committed activate", tree(map[string]string{"install.sh": "python -m venv a/.venv\ncd a &\n. .venv/bin/activate\ninst sync\n", "a/keep": "", ".venv/bin/activate": "# x\ninst add x\n"}), true, ""},
		{"activates a venv after a backgrounded cd on the same line, over a committed activate", tree(map[string]string{"install.sh": "python -m venv a/.venv\ncd a & . .venv/bin/activate\ninst sync\n", "a/keep": "", ".venv/bin/activate": "# x\ninst add x\n"}), true, ""},
		{"activates a venv in a run block after a backgrounded cd, over a committed activate", tree(map[string]string{".github/workflows/ci.yml": steps("- run: |\n          python -m venv a/.venv\n          cd a &\n          . .venv/bin/activate\n          inst sync\n"), "a/keep": "", ".venv/bin/activate": "# x\ninst add x\n"}), true, ""},
		{"activates a venv after a backgrounded cd", tree(map[string]string{"install.sh": "python -m venv a/.venv; cd a & . .venv/bin/activate\ninst sync\n", "a/keep": ""}), true, ""},
		{"activates a venv after a piped cd, over a committed activate", tree(map[string]string{"install.sh": "python -m venv a/.venv\ncd a | . .venv/bin/activate\ninst sync\n", "a/keep": "", ".venv/bin/activate": "# x\ninst add x\n"}), true, ""},
		{"activates a venv after a piped cd dangling onto the next line, over a committed activate", tree(map[string]string{"install.sh": "python -m venv a/.venv\ncd a |\n. .venv/bin/activate\ninst sync\n", "a/keep": "", ".venv/bin/activate": "# x\ninst add x\n"}), true, ""},
		{"activates a venv in a run block after a piped cd, over a committed activate", tree(map[string]string{".github/workflows/ci.yml": steps("- run: |\n          python -m venv a/.venv\n          cd a | . .venv/bin/activate\n          inst sync\n"), "a/keep": "", ".venv/bin/activate": "# x\ninst add x\n"}), true, ""},
		{"activates a venv only if a cd failed, over a committed activate", tree(map[string]string{"install.sh": "python -m venv sub/.venv\ncd sub || . .venv/bin/activate\ninst sync\n", "sub/keep": "", ".venv/bin/activate": "# x\ninst add x\n"}), true, ""},
		{"activates a venv a backgrounded creation may not have finished", tree(map[string]string{"install.sh": "python -m venv .venv &\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv uv made with a flag value a variable splits", tree(map[string]string{"install.sh": "uv venv -p $PY\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv uv made under --directory=", tree(map[string]string{"install.sh": "uv venv --directory=sub\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv virtualenv given no directory", tree(map[string]string{"install.sh": "virtualenv -p python3\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv a python-named wrapper made", tree(map[string]string{"install.sh": "python-wrapper -m venv .venv\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv a python module other than venv made", tree(map[string]string{"install.sh": "python -m mytool .venv\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv a creation after && may not have made", tree(map[string]string{"install.sh": "test -f marker && python -m venv .venv\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv a creation continued from a trailing && may not have made", tree(map[string]string{"install.sh": "test -f marker &&\npython -m venv .venv\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv a creation continued from a || ending in a comment may not have made", tree(map[string]string{"install.sh": "test -d .venv || # cache miss\npython -m venv .venv\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv created inside a case arm", tree(map[string]string{"install.sh": "case \"$CI\" in\n  true)\n    python -m venv .venv\n    . .venv/bin/activate\n    ;;\nesac\ninst sync\n"}), true, ""},
		{"activates a venv created inside a while body", tree(map[string]string{"install.sh": "while false; do\n  python -m venv .venv\n  . .venv/bin/activate\ndone\ninst sync\n"}), true, ""},
		{"activates a venv after a cd that runs only if the creation failed, over a committed activate", tree(map[string]string{"install.sh": "python -m venv sub/.venv || cd sub && . .venv/bin/activate\ninst sync\n", "sub/keep": "", ".venv/bin/activate": "# x\ninst add x\n"}), true, ""},
		{"activates a venv created after a cd in an if body, from a cd relative to it", tree(map[string]string{"install.sh": "if [ -n \"$X\" ]; then\ncd sub\nfi\npython -m venv .venv\ncd ..\n. sub/.venv/bin/activate\ninst sync\n", "sub/keep": ""}), true, ""},
		{"activates a venv created after a fallback cd, from a cd relative to it", tree(map[string]string{"install.sh": "cd a || true\npython -m venv .venv\ncd b\n. ../.venv/bin/activate\ninst sync\n", "a/b/keep": ""}), true, ""},
		{"activates a venv named with a tilde in and out of word start", tree(map[string]string{"install.sh": "python -m venv ~/v\ncd sub\n. ../~/v/bin/activate\ninst sync\n", "sub/keep": ""}), true, ""},
		{"activates a venv in a run block after popd with a directory, over a committed activate", tree(map[string]string{".github/workflows/ci.yml": steps("- run: |\n          python -m venv sub/.venv\n          popd sub\n          . .venv/bin/activate\n"), "sub/keep": "", ".venv/bin/activate": "# x\ninst add x\n"}), true, ""},
		{"activates a venv in a run block after cd -", tree(map[string]string{".github/workflows/ci.yml": steps("- run: |\n          python -m venv ./-/.venv\n          cd -\n          . .venv/bin/activate\n"), "-/keep": ""}), true, ""},
		{"activates a venv in a run block after cd ~x", tree(map[string]string{".github/workflows/ci.yml": steps("- run: |\n          cd ./~x\n          python -m venv .venv\n          cd ..\n          cd ~x\n          . .venv/bin/activate\n"), "~x/keep": ""}), true, ""},
		{"activates a venv in a run block after an absolute cd", tree(map[string]string{".github/workflows/ci.yml": steps("- run: |\n          python -m venv opt/.venv\n          cd /opt\n          . .venv/bin/activate\n"), "opt/keep": ""}), true, ""},
		{"activates a venv in a run block after a cd to a directory not there", tree(map[string]string{".github/workflows/ci.yml": steps("- run: |\n          python -m venv .venv\n          cd ghost\n          . ../.venv/bin/activate\n")}), true, ""},
		{"activates a venv in a run block after a cd out of the build root", map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", "app/.github/workflows/ci.yml": steps("- run: |\n          python -m venv .venv\n          cd ..\n          cd y\n          . ../app/.venv/bin/activate\n"), "y/keep": ""}, true, "app"},
		{"activates a venv in a Dockerfile RUN after a fallback cd", tree(map[string]string{"Dockerfile": "FROM base\nWORKDIR /app\nRUN cd sub || cd other; python -m venv .venv; cd x; . ../.venv/bin/activate\n"}), true, ""},
		{"activates a venv in a run block whose working-directory is an expression", tree(map[string]string{".github/workflows/ci.yml": steps("- run: |\n          python -m venv .venv\n          cd b\n          . ../.venv/bin/activate\n        working-directory: ${{ matrix.d }}\n"), "${{ matrix.d }}/b/keep": "", ".venv/bin/activate": "# x\ninst add x\n"}), true, ""},
		{"activates a venv in a run block whose working-directory is absolute", tree(map[string]string{".github/workflows/ci.yml": steps("- run: |\n          python -m venv .venv\n          cd b\n          . ../.venv/bin/activate\n        working-directory: /opt\n"), "opt/b/keep": "", ".venv/bin/activate": "# x\ninst add x\n"}), true, ""},
		{"activates a venv a creation named by the build root's absolute path made, from a relative path", tree(map[string]string{"install.sh": "python -m venv @root@/.venv\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv in a run block whose working-directory leaves the build root", map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", "app/.github/workflows/ci.yml": steps("- run: |\n          python -m venv .venv\n          . .venv/bin/activate\n        working-directory: ../y\n"), "y/keep": ""}, true, "app"},
		{"activates a venv whose activate path cannot be looked up", tree(map[string]string{"install.sh": "python -m venv " + strings.Repeat("v", 300) + "\n. " + strings.Repeat("v", 300) + "/bin/activate\n"}), true, ""},
		{"activates a venv in a Dockerfile RUN over an activate COPY put there", tree(map[string]string{"Dockerfile": "FROM base\nWORKDIR /app\nCOPY . .\nRUN python -m venv .venv && . .venv/bin/activate\n", ".venv/bin/activate": "# x\ninst add x\n"}), true, ""},
		{"activates a venv in a recipe line that may run from either of two directories, over a committed activate", tree(map[string]string{"Makefile": "deps:\n\tcd a\n\tpython -m venv x; . x/bin/activate\n", "a/x/bin/activate": "# x\ninst add x\n"}), true, ""},
		{"venv activated in a hidden job's script that a pipeline above the build root extends", map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", ".gitlab-ci.yml": "include:\n  - local: app/.gitlab-ci.yml\nbuild:\n  extends: .setup\n  before_script:\n    - echo hi\n", "app/.gitlab-ci.yml": ".setup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\n"}, true, "app"},
		{"venv activated in a job's script another job in the file references", tree(map[string]string{".gitlab-ci.yml": "setup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\nbuild:\n  script:\n    - !reference [setup, script]\n"}), true, ""},
		{"venv activated in a job's script another job extends by a list", tree(map[string]string{".gitlab-ci.yml": "setup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\nbuild:\n  extends: [setup]\n  before_script:\n    - echo hi\n"}), true, ""},
		{"a conditional cd in a run block", tree(map[string]string{"sub/inst.toml": "[deps]\n", ".github/workflows/ci.yml": steps("- run: |\n          cd sub\n          test -f marker && cd ..\n          inst sync\n")}), true, ""},
		{"a cd after then in a run block", map[string]string{"inst.toml": "[deps]\n", "sub/inst.toml": "[deps]\n", "sub/inst.lock": "lock\n", ".github/workflows/ci.yml": steps("- run: |\n          cd sub\n          if true; then cd ..; fi\n          inst sync\n")}, true, ""},
		{"builtin cd in a run block", map[string]string{"inst.toml": "[deps]\n", "sub/inst.toml": "[deps]\n", "sub/inst.lock": "lock\n", ".github/workflows/ci.yml": steps("- run: |\n          cd sub\n          builtin cd ..\n          inst sync\n")}, true, ""},
		{"a cd in a heredoc in a run block", map[string]string{"inst.toml": "[deps]\n", "sub/inst.toml": "[deps]\n", "sub/inst.lock": "lock\n", ".github/workflows/ci.yml": steps("- run: |\n          cat > x.sh <<EOF\n          cd sub\n          EOF\n          inst sync\n")}, true, ""},
		{"a cd in an if body in a run block", map[string]string{"inst.toml": "[deps]\n", "sub/inst.toml": "[deps]\n", "sub/inst.lock": "lock\n", ".github/workflows/ci.yml": steps("- run: |\n          if false; then\n          cd sub\n          fi\n          inst sync\n")}, true, ""},
		{"a cd in a subshell in a run block", map[string]string{"inst.toml": "[deps]\n", "sub/inst.toml": "[deps]\n", "sub/inst.lock": "lock\n", ".github/workflows/ci.yml": steps("- run: |\n          (\n          cd sub\n          )\n          inst sync\n")}, true, ""},
		{"Set-Location in a pwsh run block", map[string]string{"inst.toml": "[deps]\n", "sub/inst.toml": "[deps]\n", "sub/inst.lock": "lock\n", ".github/workflows/ci.yml": steps("- shell: pwsh\n        run: |\n          cd sub\n          Set-Location ..\n          inst sync\n")}, true, ""},
		{"chdir in a cmd run block", map[string]string{"inst.toml": "[deps]\n", "sub/inst.toml": "[deps]\n", "sub/inst.lock": "lock\n", ".github/workflows/ci.yml": steps("- shell: cmd\n        run: |\n          cd sub\n          chdir ..\n          inst sync\n")}, true, ""},
		{"a cd after then in a GitLab script", map[string]string{"inst.toml": "[deps]\n", "sub/inst.toml": "[deps]\n", "sub/inst.lock": "lock\n", ".gitlab-ci.yml": "build:\n  script:\n    - cd sub\n    - if true; then cd ..; fi\n    - inst sync\n"}, true, ""},
		{"a cd in a function body in a run block", map[string]string{"inst.toml": "[deps]\n", "sub/inst.toml": "[deps]\n", "sub/inst.lock": "lock\n", ".github/workflows/ci.yml": steps("- run: |\n          f() {\n          cd sub\n          }\n          inst sync\n")}, true, ""},
		{"a cd in a zero-iteration loop in a run block", map[string]string{"inst.toml": "[deps]\n", "sub/inst.toml": "[deps]\n", "sub/inst.lock": "lock\n", ".github/workflows/ci.yml": steps("- run: |\n          for i in; do\n          cd sub\n          done\n          inst sync\n")}, true, ""},
		{"eval cd in a run block", map[string]string{"inst.toml": "[deps]\n", "sub/inst.toml": "[deps]\n", "sub/inst.lock": "lock\n", ".github/workflows/ci.yml": steps("- run: |\n          cd sub\n          eval 'cd ..'\n          inst sync\n")}, true, ""},
		{"activates a venv a guarded creation may not have made, over a committed activate", tree(map[string]string{"install.sh": "test -d .venv || python -m venv .venv\n. .venv/bin/activate\ninst sync\n", ".venv/bin/activate": "# source me\ninst add x\n"}), true, ""},
		{"activates a venv a guarded creation may not have made", tree(map[string]string{"install.sh": "test -d .venv || python -m venv .venv\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv a creation continued from a guarded line may not have made", tree(map[string]string{"install.sh": "test -d .venv ||\n  python -m venv .venv\n. .venv/bin/activate\ninst sync\n"}), true, ""},
		{"activates a venv created inside an if body", tree(map[string]string{"install.sh": "if [ ! -d .venv ]; then\n  python -m venv .venv\n  . .venv/bin/activate\nfi\ninst sync\n"}), true, ""},
		{"activates a venv over a committed activate the walk does not read", tree(map[string]string{"install.sh": "python -m venv .venv\n. .venv/bin/activate\ninst sync\n", ".venv/bin/activate": "# source me\ninst add x\n"}), true, ""},
		{"activates a venv after a function body", tree(map[string]string{"install.sh": "python -m venv .venv\nf() {\n  cd sub\n}\n. ../.venv/bin/activate\ninst sync\n", "sub/x": "x\n"}), true, ""},
		{"sources a file beside nvm.sh", tree(map[string]string{"install.sh": ". ~/.nvm/other.sh\ninst sync\n"}), true, ""},
		{"sources a file above NVM_DIR", tree(map[string]string{"install.sh": ". \"$NVM_DIR/../evil.sh\"\ninst sync\n"}), true, ""},
		{"sources a profile script", tree(map[string]string{"install.sh": ". /etc/profile.d/x.sh\ninst sync\n"}), true, ""},
		{"sources nvm.sh through a brace expansion", tree(map[string]string{"install.sh": ". \"${NVM_DIR}/nvm.sh\"\ninst sync\n"}), true, ""},
		{"sources a single-quoted $NVM_DIR path, which does not expand", tree(map[string]string{"install.sh": ". '$NVM_DIR/nvm.sh'\ninst sync\n"}), true, ""},
		{"sources nvm.sh with an extra argument", tree(map[string]string{"install.sh": ". \"$NVM_DIR/nvm.sh\" --no-use\ninst sync\n"}), true, ""},

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
		{"python -m venv then activate", tree(map[string]string{"install.sh": "python -m venv .venv && . .venv/bin/activate && inst install -r reqs.txt\n"}), false, ""},
		{"virtualenv then source activate", tree(map[string]string{"install.sh": "virtualenv venv\nsource venv/bin/activate\ninst sync\n"}), false, ""},
		{"uv venv then activate the default", tree(map[string]string{"install.sh": "uv venv --seed\n. ./.venv/bin/activate\ninst sync\n"}), false, ""},
		{"python3.12 -m venv with flags around the directory", tree(map[string]string{"install.sh": "python3.12 -m venv --prompt app .venv --upgrade-deps\n. .venv/bin/activate\ninst sync\n"}), false, ""},
		{"absolute venv in a CI run", tree(map[string]string{".github/workflows/ci.yml": steps("- run: python3 -m venv /opt/venv && . /opt/venv/bin/activate && inst sync\n")}), false, ""},
		{"cd away and back between creation and activate", map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n", "sub/inst.toml": "[deps]\n", ".github/workflows/ci.yml": steps("- run: python3 -m venv .venv && cd sub && cd .. && . .venv/bin/activate && inst sync\n")}, false, ""},
		{"venv activated after a cd joined by &&", tree(map[string]string{"install.sh": "python -m venv sub/.venv\ncd sub && . .venv/bin/activate && inst sync\n", "sub/inst.toml": "[deps]\n", "sub/inst.lock": "lock\n", "sub/reqs.txt": "x==1\n"}), false, ""},
		{"venv activated after two cds joined by &&", tree(map[string]string{"install.sh": "python -m venv a/b/.venv\ncd a && cd b && . .venv/bin/activate && inst sync\n", "a/b/inst.toml": "[deps]\n", "a/b/inst.lock": "lock\n"}), false, ""},
		{"venv activated after a cd whose && dangles onto the next line", tree(map[string]string{"install.sh": "python -m venv sub/.venv\ncd sub &&\n. .venv/bin/activate && inst sync\n", "sub/inst.toml": "[deps]\n", "sub/inst.lock": "lock\n", "sub/reqs.txt": "x==1\n"}), false, ""},
		{"activate in a Dockerfile RUN", tree(map[string]string{"Dockerfile": "FROM base\nWORKDIR /app\nRUN python -m venv .venv && . /app/.venv/bin/activate\n"}), false, ""},
		{"venv created and activated in a run block", tree(map[string]string{".github/workflows/ci.yml": steps("- run: |\n          python -m venv .venv\n          . .venv/bin/activate\n          inst install -r reqs.txt\n")}), false, ""},
		{"venv created and activated in a run block with a working-directory", tree(map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", "app/reqs.txt": "x==1\n", ".github/workflows/ci.yml": steps("- run: |\n          python -m venv .venv\n          . .venv/bin/activate\n          inst install -r reqs.txt\n        working-directory: app\n")}), false, ""},
		{"venv created and activated in a GitLab script", tree(map[string]string{".gitlab-ci.yml": "build:\n  script:\n    - python -m venv .venv\n    - source .venv/bin/activate\n    - inst install -r reqs.txt\n"}), false, ""},
		{"venv created in before_script and activated in script", tree(map[string]string{".gitlab-ci.yml": "build:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\n"}), false, ""},
		{"venv activated in a hidden job's script that a job extends with its own before_script", tree(map[string]string{".gitlab-ci.yml": ".base:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\nbuild:\n  extends: .base\n  before_script:\n    - echo hi\n"}), true, ""},
		{"venv activated in a hidden job's script that a job merges with its own before_script", tree(map[string]string{".gitlab-ci.yml": ".base: &base\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\nbuild:\n  <<: *base\n  before_script:\n    - echo hi\n"}), true, ""},
		{"venv activated in a job's script that another job extends with its own before_script", tree(map[string]string{".gitlab-ci.yml": "setup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\nbuild:\n  extends: setup\n  before_script:\n    - echo hi\n"}), true, ""},
		{"venv activated in an anchored script another job aliases", tree(map[string]string{".gitlab-ci.yml": "setup:\n  before_script:\n    - python -m venv .venv\n  script: &s\n    - source .venv/bin/activate\n    - inst sync\nbuild:\n  script: *s\n"}), true, ""},
		{"venv activated in an included job's script that the root file extends with its own before_script", tree(map[string]string{".gitlab-ci.yml": "include: ci/setup.yml\nbuild:\n  extends: setup\n  before_script:\n    - echo hi\n", "ci/setup.yml": "setup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\n"}), true, ""},
		{"venv activated in an included job's script that the root file references", tree(map[string]string{".gitlab-ci.yml": "include: ci/setup.yml\nbuild:\n  script:\n    - !reference [setup, script]\n", "ci/setup.yml": "setup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\n"}), true, ""},
		{"venv activated in a job's script when a top-level << merge brings in an include", tree(map[string]string{".gitlab-ci.yml": ".inc: &inc\n  include:\n    - local: jobs.yml\n<<: *inc\nsetup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\n", "jobs.yml": "build:\n  extends: setup\n  before_script:\n    - echo hi\n"}), true, ""},
		{"venv activated in a job's script when a quoted << merge brings in an include", tree(map[string]string{".gitlab-ci.yml": ".inc: &inc\n  include:\n    - local: jobs.yml\n\"<<\": *inc\nsetup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\n", "jobs.yml": "build:\n  extends: setup\n  before_script:\n    - echo hi\n"}), true, ""},
		{"venv activated in a job's script when an aliased key names include", tree(map[string]string{".gitlab-ci.yml": ".names:\n  - &k include\n*k :\n  - local: jobs.yml\nsetup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\n", "jobs.yml": "build:\n  extends: setup\n  before_script:\n    - echo hi\n"}), true, ""},
		{"venv activated in a job's script whose before_script key is repeated after it", tree(map[string]string{".gitlab-ci.yml": "build:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\n  before_script:\n    - echo hi\n"}), true, ""},
		{"venv activated in a job whose trailing << merge replaces its before_script", tree(map[string]string{".gitlab-ci.yml": ".base: &base\n  before_script:\n    - echo base\nbuild:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\n  <<: *base\n"}), true, ""},
		{"venv activated in a job whose aliased key repeats before_script", tree(map[string]string{".gitlab-ci.yml": ".names:\n  - &k before_script\nbuild:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\n  *k :\n    - echo hi\n"}), true, ""},
		{"venv activated in a job's script that another job extends by an aliased key", tree(map[string]string{".gitlab-ci.yml": ".names:\n  - &e extends\nsetup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\nbuild:\n  *e : setup\n  before_script:\n    - echo hi\n"}), true, ""},
		{"venv activated in a job's script that another job extends through an aliased value", tree(map[string]string{".gitlab-ci.yml": ".names:\n  - &x setup\nsetup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\nbuild:\n  extends: *x\n  before_script:\n    - echo hi\n"}), true, ""},
		{"venv activated in a job's script that another job references through an alias", tree(map[string]string{".gitlab-ci.yml": ".names:\n  - &x setup\nsetup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\nbuild:\n  before_script:\n    - echo hi\n  script:\n    - !reference [*x, script]\n"}), true, ""},
		{"venv activated in a job whose binary key repeats before_script", tree(map[string]string{".gitlab-ci.yml": "build:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\n  !!binary YmVmb3JlX3NjcmlwdA== :\n    - echo hi\n"}), true, ""},
		{"venv activated in a job's script that another job extends through a binary value", tree(map[string]string{".gitlab-ci.yml": "setup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\nbuild:\n  extends: !!binary c2V0dXA=\n  before_script:\n    - echo hi\n"}), true, ""},
		{"venv activated in a job's script that another job references through a binary name", tree(map[string]string{".gitlab-ci.yml": "setup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\nbuild:\n  before_script:\n    - echo hi\n  script:\n    - !reference [!!binary c2V0dXA=, script]\n"}), true, ""},
		{"venv activated in a job's script that another job extends by a binary key", tree(map[string]string{".gitlab-ci.yml": "setup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\nbuild:\n  !!binary ZXh0ZW5kcw== : setup\n  before_script:\n    - echo hi\n"}), true, ""},
		{"venv activated in a job whose binary << merge replaces its before_script", tree(map[string]string{".gitlab-ci.yml": "build:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\n  !!binary PDw= :\n    before_script:\n      - echo hi\n"}), true, ""},
		{"venv activated in a job whose symbol key repeats before_script", tree(map[string]string{".gitlab-ci.yml": "build:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\n  :before_script:\n    - echo hi\n"}), true, ""},
		{"venv activated in a job whose input-interpolated key repeats before_script", tree(map[string]string{".gitlab-ci.yml": "spec:\n  inputs:\n    k:\n      default: before_script\n---\nbuild:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\n  $[[ inputs.k ]]:\n    - echo hi\n"}), true, ""},
		{"venv created in before_script and activated in script, beside a job that references another's script", tree(map[string]string{".gitlab-ci.yml": "setup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\n.x:\n  script:\n    - echo x\nlint:\n  script:\n    - !reference [.x, script]\n"}), false, ""},
		{"venv created in before_script and activated in script, in a file with an anchor", tree(map[string]string{".gitlab-ci.yml": ".names: &n\n  - x\nsetup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\n"}), true, ""},
		{"venv created in before_script and activated in script, beside another job, with no include", tree(map[string]string{".gitlab-ci.yml": "setup:\n  before_script:\n    - python -m venv .venv\n  script:\n    - source .venv/bin/activate\n    - inst sync\nlint:\n  before_script:\n    - echo hi\n  script:\n    - echo lint\n"}), false, ""},
		{"nvm.sh through NVM_DIR", tree(map[string]string{"install.sh": "export NVM_DIR=\"$HOME/.nvm\"\n. \"$NVM_DIR/nvm.sh\" && nvm use && inst sync\n"}), false, ""},
		{"nvm.sh under the home directory", tree(map[string]string{".github/workflows/ci.yml": steps("- run: source ~/.nvm/nvm.sh && inst sync\n")}), false, ""},
		{"cargo env", tree(map[string]string{"install.sh": ". \"$HOME/.cargo/env\"\ninst sync\n"}), false, ""},
		{"cd to an in-tree directory", map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", "install.sh": "cd app && inst sync\n"}, false, ""},
		{"CI working-directory in the tree", tree(map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", ".github/workflows/ci.yml": ci("app", "inst sync")}), false, ""},
		{"Dockerfile COPY, install, COPY . ., run", tree(map[string]string{"Dockerfile": docker + "inst sync\nCOPY . .\nRUN inst run build\nCMD [\"inst\", \"run\", \"serve\"]\n"}), false, ""},
		{"Dockerfile COPY glob then install", tree(map[string]string{"Dockerfile": "FROM base\nWORKDIR /app\nCOPY inst.* ./\nRUN inst sync\n"}), false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, tt.files)
			root := filepath.Join(dir, tt.root)
			// A script that names the build root by its absolute path, as a CI workspace path.
			for rel, content := range tt.files {
				if strings.Contains(content, "@root@") {
					if err := os.WriteFile(filepath.Join(dir, rel), []byte(strings.ReplaceAll(content, "@root@", root)), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			if got := withheld(root, testSpec); got != tt.want {
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

// Git never runs a hook under a .sample name, so the sample hooks in the build root's own
// .git/hooks are not surfaces. Every other hook, path and suffix is, and a build that sources
// or names a sample hook withholds.
func TestVeto_SampleHooks(t *testing.T) {
	const hook = "#!/bin/sh\n. git-sh-setup\n"
	tree := func(extra map[string]string) map[string]string {
		files := map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n"}
		for k, v := range extra {
			files[k] = v
		}
		return files
	}
	tests := []struct {
		name  string
		files map[string]string
		want  bool // withheld
	}{
		{"sample hook sourcing git-sh-setup", tree(map[string]string{".git/hooks/pre-rebase.sample": hook}), false},
		{"sample hook that installs", tree(map[string]string{".git/hooks/pre-commit.sample": "#!/bin/sh\ninst add x\n"}), false},
		{"live hook sourcing git-sh-setup", tree(map[string]string{".git/hooks/pre-rebase": hook}), true},
		{"live hook that installs", tree(map[string]string{".git/hooks/post-checkout": "#!/bin/sh\ninst add x\n"}), true},
		{"suffix after .sample", tree(map[string]string{".git/hooks/pre-rebase.sample.sh": hook}), true},
		{"suffix .sample with no name", tree(map[string]string{".git/hooks/.sample": hook}), true},
		{"suffix .sample in another case", tree(map[string]string{".git/hooks/pre-rebase.SAMPLE": hook}), true},
		{".sample outside .git/hooks", tree(map[string]string{"scripts/pre-rebase.sample": hook}), true},
		{".sample directly under .git", tree(map[string]string{".git/pre-rebase.sample": hook}), true},
		{".sample in a directory under .git/hooks", tree(map[string]string{".git/hooks/old/pre-rebase.sample": hook}), true},
		{".sample in a nested repository's hooks", tree(map[string]string{"vendor/lib/.git/hooks/pre-rebase.sample": hook}), false},
		{"live hook in a nested repository's hooks", tree(map[string]string{"vendor/lib/.git/hooks/pre-rebase": hook}), true},
		{".sample in a submodule's hooks", tree(map[string]string{".git/modules/lib/hooks/pre-rebase.sample": hook}), false},
		{".sample in a nested submodule's hooks", tree(map[string]string{".git/modules/lib/modules/sub/hooks/pre-rebase.sample": hook}), false},
		{"live hook in a submodule's hooks", tree(map[string]string{".git/modules/lib/hooks/pre-rebase": hook}), true},
		{".sample in hooks directly under .git/modules", tree(map[string]string{".git/modules/hooks/pre-rebase.sample": hook}), true},
		{".sample in a hooks directory under .git that is not a repository's", tree(map[string]string{".git/info/hooks/pre-rebase.sample": hook}), true},
		{".sample in a hooks directory outside .git", tree(map[string]string{"tools/hooks/pre-rebase.sample": hook}), true},
		{"script sources a sample hook", tree(map[string]string{".git/hooks/pre-rebase.sample": "#!/bin/sh\necho\n", "build.sh": ". .git/hooks/pre-rebase.sample\n"}), true},
		{"script runs a sample hook", tree(map[string]string{".git/hooks/pre-rebase.sample": "#!/bin/sh\necho\n", "build.sh": "sh .git/hooks/pre-rebase.sample\n"}), true},
		{"script makes a sample hook live", tree(map[string]string{".git/hooks/pre-commit.sample": "#!/bin/sh\necho\n", "build.sh": "cp .git/hooks/pre-commit.sample .git/hooks/pre-commit\n"}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := withheld(writeTree(t, tt.files), testSpec); got != tt.want {
				t.Fatalf("withheld = %v, want %v", got, tt.want)
			}
		})
	}
}

// A variable the lane's EnvKeeps keeps does not withhold, and names no token; every other
// variable Env matches still does, beside a kept one or not. With no EnvKeeps, none is kept.
func TestVeto_EnvKeeps(t *testing.T) {
	keeps := testSpec
	keeps.EnvKeeps = func(name string) bool { return name == "INST_ONLY" || name == "inst_only" }
	tests := []struct {
		name   string
		spec   Spec
		script string
		want   bool // withheld
	}{
		{"kept variable", keeps, "export INST_ONLY=prod\ninst sync\n", false},
		{"kept variable naming the token", keeps, "export inst_only=prod\ninst sync\n", false},
		{"kept beside another", keeps, "export INST_ONLY=prod INST_INDEX=https://x\ninst sync\n", true},
		{"another variable", keeps, "export INST_INDEX=https://x\ninst sync\n", true},
		{"a name extending a kept one", keeps, "export INST_ONLY_X=1\ninst sync\n", true},
		{"no EnvKeeps", testSpec, "export INST_ONLY=prod\ninst sync\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n", "install.sh": tt.script}
			if got := withheld(writeTree(t, files), tt.spec); got != tt.want {
				t.Fatalf("withheld = %v, want %v", got, tt.want)
			}
		})
	}
}
