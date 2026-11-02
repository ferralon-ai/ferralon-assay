package scriptsurface

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
)

// backstopped runs the veto over root as withheld does, and also returns where the backstop
// first withheld.
func backstopped(root string) (bool, string) {
	v := New(root, testRead(root), testSpec)
	none := func(string, []byte) (string, bool) { return "", false }
	out := false
	for _, c := range buildtree.Candidates(root, v.Classify(none), v.FullyRead) {
		if !c.FullyRead {
			out = true
		}
	}
	return out || v.Withheld(), v.Unrecognised()
}

// An installer in a command position of a file surfaceOf does not recognise withholds as the
// same line in install.sh does, and names the file and line; prose, comments, test files and
// what no build runs do not.
func TestVeto_Backstop(t *testing.T) {
	const mcp = `{"mcpServers": {"a": {"command": "inst", "args": ["add", "x"]}}}`
	const localAction = "name: a\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: inst add x\n"
	const modInstall = "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n"
	wf := func(run string) string {
		return "on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: " + run + "\n"
	}
	lock := map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n", "reqs.txt": "x==1\n"}
	tree := func(extra map[string]string) map[string]string {
		files := map[string]string{}
		for k, v := range lock {
			files[k] = v
		}
		for k, v := range extra {
			files[k] = v
		}
		return files
	}
	tests := []struct {
		name  string
		files map[string]string
		want  bool   // withheld
		at    string // Unrecognised(); "-" skips the check
	}{
		// Commands in files no surface rule reads.
		{"Earthfile RUN", tree(map[string]string{"Earthfile": "VERSION 0.8\nbuild:\n    FROM python:3\n    RUN inst add x==1\n"}), true, "-"},
		{"Buildkite command", tree(map[string]string{".buildkite/pipeline.yml": "steps:\n  - label: deps\n    command: inst add x==1\n"}), true, "-"},
		{"Buildkite commands list", tree(map[string]string{".buildkite/pipeline.yaml": "steps:\n  - commands:\n      - echo hi\n      - inst add x\n"}), true, "-"},
		{"root buildkite.yml", tree(map[string]string{"buildkite.yml": "steps:\n  - command: \"inst add x\"\n"}), true, "-"},
		{"Gitea workflow", tree(map[string]string{".gitea/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: inst add x\n"}), true, "-"},
		{"Forgejo workflow", tree(map[string]string{".forgejo/workflows/ci.yaml": "on: push\njobs:\n  t:\n    steps:\n      - run: |\n          echo hi\n          inst add x\n"}), true, "-"},
		{"invoke tasks.py c.run", tree(map[string]string{"tasks.py": "from invoke import task\n\n@task\ndef deps(c):\n    c.run(\"inst add x==1\")\n"}), true, "tasks.py:5"},
		{"tasks.py subprocess argv", tree(map[string]string{"tasks.py": "import subprocess\n\nsubprocess.run([\"inst\", \"add\", \"x\"], check=True)\n"}), true, "tasks.py:3"},
		{"tasks.py argv after an expression", tree(map[string]string{"tasks.py": "import subprocess, sys\nsubprocess.check_call([sys.executable, \"-m\", \"inst\", \"add\", \"x\"])\n"}), true, "tasks.py:2"},
		{"templated installer arguments", tree(map[string]string{"tasks.py": "def deps(c, args):\n    c.run(f\"inst {args}\")\n    c.run(\"inst (x)\")\n"}), true, "tasks.py:2"},
		{"installer named as a key in command text", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: |\n      echo versions\n      inst = 1.0\n      inst : 1.0\n"}), true, "ci/pipeline.yml:4"},
		{"command held in a variable", tree(map[string]string{"tasks.py": "import subprocess\ninstall_cmd = [\"inst\", \"add\", \"x\"]\nsubprocess.run(install_cmd)\n"}), true, "tasks.py:2"},
		{"command held under a cmd key", tree(map[string]string{"scripts/steps.js": "module.exports = [\n  { cmd: 'inst add x' },\n]\n"}), true, "scripts/steps.js:2"},
		{"key that describes a command", tree(map[string]string{"scripts/sandbox.js": "module.exports = {\n  startCommand: 'inst add x',\n}\n"}), false, ""},
		{"list of installer names", tree(map[string]string{"tasks.py": "installer_cmds = [\"inst\", \"instw\"]\n"}), true, "tasks.py:1"},
		{"script under a tool directory", tree(map[string]string{"scripts/fetch_deps.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n"}), true, "scripts/fetch_deps.py:2"},
		{"executable script outside a tool directory", tree(map[string]string{"app/regen.py": "#!/usr/bin/env python3\nimport subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n"}), true, "app/regen.py:3"},
		{"install script named like prose", tree(map[string]string{"install.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n"}), true, "install.py:2"},
		{"install template named like prose", tree(map[string]string{"ci/templates/install.yml": "steps:\n  - script: inst add x\n"}), true, "ci/templates/install.yml:2"},
		{"scripts/*.js execSync", tree(map[string]string{"scripts/setup.js": "const { execSync } = require('child_process')\nexecSync('inst add x')\n"}), true, "scripts/setup.js:2"},
		// surfaceOf reads these names as Dockerfiles, so the Dockerfile rule withholds and
		// the backstop records nothing.
		{"Dockerfile-prod RUN (ferralon-ai/tracker#630)", tree(map[string]string{"Dockerfile-prod": "FROM base\nWORKDIR /app\nRUN inst add x==1\n"}), true, ""},
		{"Containerfile_dev RUN", tree(map[string]string{"Containerfile_dev": "FROM base\nRUN inst add x\n"}), true, ""},
		{"Dockerfile-like name no surface takes", tree(map[string]string{"myDockerfile": "FROM base\nWORKDIR /app\nRUN inst add x==1\n"}), true, "myDockerfile:3"},
		{"arbitrary Dockerfile name (ferralon-ai/tracker#631)", tree(map[string]string{"docker-compose.yml": "services:\n  web:\n    build: {context: ., dockerfile: docker/web.df}\n", "docker/web.df": "FROM base\nRUN inst add x==1\n"}), true, "docker/web.df:2"},
		{"Dockerfile-like ENV sets an installer variable", tree(map[string]string{"myDockerfile": "FROM base\nENV INST_INDEX=http://mirror\n"}), true, "myDockerfile:2"},
		{"poe task (ferralon-ai/tracker#508)", tree(map[string]string{"pyproject.toml": "[project]\nname = \"a\"\n\n[tool.poe.tasks]\nsetup = \"inst add x\"\n"}), true, "pyproject.toml:5"},
		{"pdm script (ferralon-ai/tracker#508)", tree(map[string]string{"pyproject.toml": "[tool.pdm.scripts]\nsetup = {shell = \"inst add x\"}\n"}), true, "pyproject.toml:2"},
		{"hatch env script (ferralon-ai/tracker#508)", tree(map[string]string{"pyproject.toml": "[tool.hatch.envs.default.scripts]\nsetup = [\n  \"echo hi\",\n  \"inst add x\",\n]\n"}), true, "pyproject.toml:4"},
		{"poe subtable sequence of commands (ferralon-ai/tracker#508)", tree(map[string]string{"pyproject.toml": "[tool.poe.tasks.setup]\nhelp = \"set up\"\nsequence = [\n  {cmd = \"echo hi\"},\n  {cmd = \"inst add x\"},\n]\n"}), true, "pyproject.toml:5"},
		{"poe subtable sequence of strings (ferralon-ai/tracker#508)", tree(map[string]string{"pyproject.toml": "[tool.poe.tasks.setup]\ndefault_item_type = \"cmd\"\nsequence = [\"inst add x\"]\n"}), true, "pyproject.toml:3"},
		{"pdm subtable composite", tree(map[string]string{"pyproject.toml": "[tool.pdm.scripts.setup]\ncomposite = [\"inst add x\"]\n"}), true, "pyproject.toml:2"},
		{"sequence outside a task table", tree(map[string]string{"pyproject.toml": "[tool.other.setup]\nsequence = [\"inst add x\"]\n"}), false, ""},
		{"MCP-named JSON that is not an MCP config", tree(map[string]string{"ci/install.json": mcp}), true, "ci/install.json:1"},
		{"Claude Code and VS Code .mcp.json", tree(map[string]string{".mcp.json": mcp}), false, ""},
		{"VS Code .vscode/mcp.json", tree(map[string]string{".vscode/mcp.json": mcp}), false, ""},
		{"Cursor .cursor/mcp.json", tree(map[string]string{".cursor/mcp.json": mcp}), false, ""},
		{"Claude Desktop config", tree(map[string]string{"claude_desktop_config.json": mcp}), false, ""},
		{"mcp.json outside an editor directory", tree(map[string]string{"ci/mcp.json": mcp}), true, "ci/mcp.json:1"},
		{"JSON fixtures under a test directory", tree(map[string]string{"tests/fixtures/mcp_configs/uvx.json": mcp, "testdata/cfg.jsonc": mcp, "__fixtures__/cfg.json5": mcp}), false, ""},
		{"JSON data under a test directory", tree(map[string]string{"tests/fixtures/mcp_configs/uvx.json": mcp}), false, ""},
		{"JSONC data under a test directory", tree(map[string]string{"testdata/cfg.jsonc": mcp}), false, ""},
		{"JSON5 data under a test directory", tree(map[string]string{"__fixtures__/cfg.json5": mcp}), false, ""},
		{"shell continuation in a block scalar", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: |\n      in\\\n      st add x\n"}), true, "ci/pipeline.yml:3"},
		{"shell continuation below a block scalar's first line", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: |\n      make\n      in\\\n      st add x\n"}), true, "ci/pipeline.yml:4"},
		{"YAML under a test directory", tree(map[string]string{"e2e/ci.yml": "steps:\n  - command: inst add x\n"}), true, "e2e/ci.yml:2"},
		{"poe tasks in a pyproject under a test directory", tree(map[string]string{"tests/pyproject.toml": "[tool.poe.tasks]\nsetup = \"inst add x\"\n"}), true, "tests/pyproject.toml:2"},
		{"JSON under a test directory that a pipeline uploads", tree(map[string]string{"ci/tests/steps.json": mcp, ".buildkite/pipeline.yml": "steps:\n  - command: buildkite-agent pipeline upload ci/tests/steps.json\n"}), true, "ci/tests/steps.json:1"},
		{"JSON under src/ a pipeline uploads from its package root", tree(map[string]string{"src/tests/steps.json": mcp, ".buildkite/pipeline.yml": "steps:\n  - command: buildkite-agent pipeline upload tests/steps.json\n"}), true, "src/tests/steps.json:1"},
		{"JSON in a package under a test directory", tree(map[string]string{"tests/app/steps.json": mcp, "tests/app/package.json": "{\"name\": \"app\"}\n"}), true, "tests/app/steps.json:1"},
		{"JSON under a test directory a sub-project names from its own directory", tree(map[string]string{"pkg/tests/steps.json": mcp, "pkg/pyproject.toml": "[tool.ci]\nsteps = \"tests/steps.json\"\n"}), true, "pkg/tests/steps.json:1"},
		{"JSON under a test directory setup.py names", tree(map[string]string{"tests/steps.json": mcp, "setup.py": "from setuptools import setup\nsetup(data_files=[(\"ci\", [\"tests/steps.json\"])])\n"}), true, "tests/steps.json:1"},
		{"JSON in a Python project under a test directory", tree(map[string]string{"tests/app/tasks.json": mcp, "tests/app/pyproject.toml": "[project]\nname = \"app\"\n"}), true, "tests/app/tasks.json:1"},
		{"non-data file under a test directory", tree(map[string]string{"tests/ci.cfg": "[x]\ncommand = inst add x\n"}), true, "tests/ci.cfg:2"},
		{"workflow named for tests", tree(map[string]string{".github/workflows/tests.yml": "on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: inst add x\n"}), true, "-"},
		{"make-like recipe", tree(map[string]string{"tasks.cfg": "deps:\n\tinst add x\n"}), true, "tasks.cfg:2"},
		{"pre-install hook key", tree(map[string]string{"ci/pipeline.yml": "language: python\nbefore_install:\n  - inst add x\n"}), true, "ci/pipeline.yml:3"},
		{"installer variable under env", tree(map[string]string{"ci/pipeline.yml": "env:\n  INST_INDEX: http://mirror\nsteps:\n  - command: make\n"}), true, "ci/pipeline.yml:2"},
		{"published action a workflow here uses", tree(map[string]string{"action.yml": localAction, ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./\n"}), true, "action.yml:6"},
		{"nested action a Gitea workflow uses", tree(map[string]string{"actions/setup/action.yaml": localAction, ".gitea/workflows/ci.yml": "on: push\njobs:\n  t:\n    steps:\n      - uses: './actions/setup'\n"}), true, "actions/setup/action.yaml:6"},
		// Any command naming an installer goes to the rule, wherever in it the name is.
		{"bare installer", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: inst\n"}), true, "ci/pipeline.yml:2"},
		{"shell -c", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: bash -c \"inst add x\"\n"}), true, "ci/pipeline.yml:2"},
		{"eval", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: eval \"inst add x\"\n"}), true, "ci/pipeline.yml:2"},
		{"subshell", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: (inst add x)\n"}), true, "ci/pipeline.yml:2"},
		{"brace group", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: '{ inst add x; }'\n"}), true, "ci/pipeline.yml:2"},
		{"interpreter -c", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: python -c \"import os; os.system('inst add x')\"\n"}), true, "ci/pipeline.yml:2"},
		{"launcher flag value", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: timeout 60 inst add x\n"}), true, "ci/pipeline.yml:2"},
		{"sudo -u value", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: sudo -u ci inst add x\n"}), true, "ci/pipeline.yml:2"},
		{"installer by path", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: ./venv/bin/inst add x\n"}), true, "ci/pipeline.yml:2"},
		{"read-only verb inside shell text", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: bash -c \"inst list; inst add x\"\n"}), true, "ci/pipeline.yml:2"},
		{"installer as an argument", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: retry 3 inst add x\n"}), true, "ci/pipeline.yml:2"},
		// Dockerfile-like files no surface takes by name are read by the Dockerfile rule.
		{"lowercase Dockerfile-like", tree(map[string]string{"myDockerfile": "from base\nrun inst add x\n"}), true, "myDockerfile:2"},
		{"Dockerfile-like heredoc", tree(map[string]string{"myDockerfile": "FROM base\nRUN <<EOF\ninst add x\nEOF\n"}), true, "myDockerfile:2"},
		{"Dockerfile-like CMD", tree(map[string]string{"myDockerfile": "FROM base\nCMD inst add x\nRUN echo\n"}), true, "myDockerfile:2"},
		{"Dockerfile-like continuation line", tree(map[string]string{"myDockerfile": "FROM base\nRUN echo hi && \\\n    inst add x\n"}), true, "myDockerfile:2"},
		{"Dockerfile-like bound install passes", tree(map[string]string{"myDockerfile": "FROM base\nWORKDIR /app\nCOPY inst.toml inst.lock ./\nRUN inst sync\n"}), false, ""},
		// One-line JSON and further CI keys.
		{"one-line Buildkite JSON", tree(map[string]string{".buildkite/pipeline.json": "{\"steps\":[{\"label\":\"deps\",\"command\":\"inst add x\"}]}"}), true, ".buildkite/pipeline.json:1"},
		{"one-line JSON commands array", tree(map[string]string{"ci/steps.json": "{\"steps\":[{\"commands\":[\"echo hi\",\"inst add x\"]}]}\n"}), true, "ci/steps.json:1"},
		{"JSON env map", tree(map[string]string{"ci/steps.json": "{\"env\":{\"INST_INDEX\":\"http://mirror\"}}\n"}), true, "ci/steps.json:1"},
		{"Bitrise script content", tree(map[string]string{"bitrise.yml": "workflows:\n  ci:\n    steps:\n    - script@1:\n        inputs:\n        - content: inst add x\n"}), true, "bitrise.yml:6"},
		{"Cirrus script key", tree(map[string]string{".cirrus.yml": "task:\n  deps_script: inst add x\n"}), true, ".cirrus.yml:2"},
		{"hatch post-install-commands", tree(map[string]string{"pyproject.toml": "[tool.hatch.envs.default]\npost-install-commands = [\"inst add x\"]\n"}), true, "pyproject.toml:2"},
		{"Husky hook without #!", tree(map[string]string{".husky/pre-commit": "echo hi\ninst add x\n"}), true, ".husky/pre-commit:2"},
		{"Buildkite agent hook", tree(map[string]string{".buildkite/hooks/pre-command": "inst add x\n"}), true, ".buildkite/hooks/pre-command:1"},
		{"installer through a variable", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: $INST add x\n"}), true, "ci/pipeline.yml:2"},
		{"bound install in an unknown directory", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: inst sync\n"}), true, "ci/pipeline.yml:2"},
		{"read-only verb with an expansion", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: inst list $PKGS\n"}), true, "ci/pipeline.yml:2"},
		{"read-only verb after another program", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: mytool list inst add x\n"}), true, "ci/pipeline.yml:2"},
		{"audit fix is not read-only", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: inst audit fix\n"}), true, "ci/pipeline.yml:2"},
		{"Dockerfile-like binds the build root", tree(map[string]string{"docker/app.df": "FROM base\nWORKDIR /app\nCOPY inst.toml inst.lock ./\nRUN inst sync\n"}), false, ""},
		{"JSON task table", tree(map[string]string{"ci/tasks.json": "{\"tasks\":{\"deps\":\"inst add x\"}}\n"}), true, "ci/tasks.json:1"},
		{"JSON shell key", tree(map[string]string{"ci/steps.json": "{\"shell\":\"inst add x\"}\n"}), true, "ci/steps.json:1"},
		{"SQL FROM is not a Dockerfile", tree(map[string]string{"sql/q.sql": "SELECT a\nFROM t\nJOIN u ON t.id = u.id\n"}), false, ""},
		{"Dockerfile-like with a lowercase run", tree(map[string]string{"docker/app.df": "from base\nrun inst add x\n"}), true, "docker/app.df:2"},
		{"Dockerfile-like with a continued RUN", tree(map[string]string{"docker/app.df": "FROM base\nRUN\\\n  inst add x\n"}), true, "-"},
		{"URL naming a token is an argument", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: curl -fsSL https://example.com/inst-cache/tool\n"}), false, ""},
		{"URL beside an installer", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: inst add https://example.com/x.tgz\n"}), true, "ci/pipeline.yml:2"},
		{"SQL JOIN naming a token is not a Dockerfile", tree(map[string]string{"sql/q.sql": "SELECT a\nFROM t\nJOIN inst ON t.id = inst.id\n"}), false, ""},
		{"scheme-less word naming a token", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: tool --from=inst://x add y\n"}), true, "ci/pipeline.yml:2"},
		{"quoted URL and installer in one word", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: tool \"https://example.com/x inst add y\"\n"}), true, "ci/pipeline.yml:2"},
		{"content key outside Bitrise is data", tree(map[string]string{"docs/page.yml": "content: inst add x\n"}), false, ""},
		// More build scripts and the ways they run an installer.
		{"zx script", tree(map[string]string{"deps": "#!/usr/bin/env zx\nawait $`inst add x`\n"}), true, "deps:2"},
		{"bundler config execSync", tree(map[string]string{"vite.config.ts": "import { execSync } from 'child_process'\nexecSync('inst add x')\nexport default {}\n"}), true, "vite.config.ts:2"},
		{"installer driven through its API", tree(map[string]string{"tasks.py": "import inst\ninst.main([\"add\", \"x\"])\n"}), true, "tasks.py:2"},
		{"package module named like a build script", tree(map[string]string{"app/utilities/__init__.py": "", "app/utilities/install.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n"}), false, ""},
		{"build-script name outside a package", tree(map[string]string{"app/utilities/install.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n"}), true, "app/utilities/install.py:2"},
		{"package module named in pyproject", tree(map[string]string{"app/utilities/__init__.py": "", "app/utilities/install.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", "pyproject.toml": "[tool.x]\nhook = \"app.utilities.install:main\"\n"}), true, "app/utilities/install.py:2"},
		{"src-layout package module named in setup.cfg", tree(map[string]string{"src/pkg/__init__.py": "", "src/pkg/build.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", "setup.cfg": "[x]\nhook = pkg.build\n"}), true, "src/pkg/build.py:2"},
		{"package module by path in setup.py", tree(map[string]string{"pkg/__init__.py": "", "pkg/build.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", "setup.py": "exec(open(\"pkg/build.py\").read())\n"}), true, "pkg/build.py:2"},
		{"package module a workflow runs by path", tree(map[string]string{"pkg/__init__.py": "", "pkg/build.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: python pkg/build.py\n"}), true, "pkg/build.py:2"},
		{"package module a workflow runs with -m", tree(map[string]string{"pkg/__init__.py": "", "pkg/install.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: python -m pkg.install\n"}), true, "pkg/install.py:2"},
		{"package module a Makefile runs", tree(map[string]string{"pkg/__init__.py": "", "pkg/build.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", "Makefile": "deps:\n\tpython pkg/build.py\n"}), true, "pkg/build.py:2"},
		{"package module tox runs", tree(map[string]string{"pkg/__init__.py": "", "pkg/build.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", "tox.ini": "[testenv]\ncommands =\n    python pkg/build.py\n"}), true, "pkg/build.py:2"},
		{"package module nox runs", tree(map[string]string{"pkg/__init__.py": "", "pkg/build.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", "noxfile.py": "import nox\n@nox.session\ndef deps(session):\n    session.run(\"python\", \"pkg/build.py\")\n"}), true, "pkg/build.py:2"},
		{"package module a Dockerfile runs", tree(map[string]string{"pkg/__init__.py": "", "pkg/build.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", "Dockerfile": "FROM base\nCOPY . .\nRUN python pkg/build.py\n"}), true, "pkg/build.py:2"},
		{"package module a sub-project names from its directory", tree(map[string]string{"packages/foo/foo/__init__.py": "", "packages/foo/foo/build.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", "packages/foo/pyproject.toml": "[tool.hatch.build.hooks.custom]\npath = \"foo/build.py\"\n"}), true, "packages/foo/foo/build.py:2"},
		{"package module setup.py imports from its package", tree(map[string]string{"pkg/__init__.py": "", "pkg/build.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", "setup.py": "from setuptools import setup\nfrom pkg import build\nsetup(cmdclass={\"build_py\": build.BuildPy})\n"}), true, "pkg/build.py:2"},
		{"package module setup.py imports by dotted name", tree(map[string]string{"pkg/__init__.py": "", "pkg/install.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", "setup.py": "from setuptools import setup\nimport pkg.install\nsetup(cmdclass={\"install\": pkg.install.Install})\n"}), true, "pkg/install.py:2"},
		{"build script beside an __init__.py at the root", tree(map[string]string{"__init__.py": "", "tasks.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n"}), true, "tasks.py:2"},
		{"package module the build names only by its package", tree(map[string]string{"src/app/console/commands/__init__.py": "", "src/app/console/commands/build.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", "pyproject.toml": "[project]\nname = \"app\"\n[project.scripts]\napp = \"app.console:main\"\n", ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: python -m build\n"}), false, ""},
		{"package module a workflow runs after cd", tree(map[string]string{"packages/foo/foo/__init__.py": "", "packages/foo/foo/build.py": modInstall, ".github/workflows/ci.yml": wf("cd packages/foo && python -m foo.build")}), true, "packages/foo/foo/build.py:2"},
		{"package module a workflow runs by path from a working-directory", tree(map[string]string{"packages/foo/foo/__init__.py": "", "packages/foo/foo/build.py": modInstall, ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: x\n    defaults:\n      run:\n        working-directory: packages/foo\n    steps:\n      - run: python foo/build.py\n"}), true, "packages/foo/foo/build.py:2"},
		{"package module a workflow runs with -m from a working-directory", tree(map[string]string{"packages/foo/foo/__init__.py": "", "packages/foo/foo/build.py": modInstall, ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: python -m foo.build\n        working-directory: packages/foo\n"}), true, "packages/foo/foo/build.py:2"},
		{"package module tox runs after changedir", tree(map[string]string{"app/mypkg/__init__.py": "", "app/mypkg/build.py": modInstall, "tox.ini": "[testenv]\nchangedir = app\ncommands =\n    python -m mypkg.build\n"}), true, "app/mypkg/build.py:2"},
		{"package module a Dockerfile copies then runs", tree(map[string]string{"app/mypkg/__init__.py": "", "app/mypkg/build.py": modInstall, "Dockerfile": "FROM base\nWORKDIR /srv\nCOPY app/ .\nRUN python -m mypkg.build\n"}), true, "app/mypkg/build.py:2"},
		{"package module a pre-commit hook runs with -m", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, ".pre-commit-config.yaml": "repos:\n  - repo: local\n    hooks:\n      - id: deps\n        entry: python -m mypkg.build\n        language: system\n"}), true, "mypkg/build.py:2"},
		{"package module a pre-commit hook runs by path", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, ".pre-commit-config.yaml": "repos:\n  - repo: local\n    hooks:\n      - id: deps\n        entry: python mypkg/build.py\n        language: system\n"}), true, "mypkg/build.py:2"},
		{"package module a root action runs", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - uses: ./\n", "action.yml": "name: s\nruns:\n  using: composite\n  steps:\n    - run: python -m mypkg.build\n      shell: bash\n"}), true, "mypkg/build.py:2"},
		{"package module a hatch.toml hook names", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "hatch.toml": "[build.hooks.custom]\npath = \"mypkg/build.py\"\n"}), true, "mypkg/build.py:2"},
		{"package module tox.toml runs", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "tox.toml": "[env_run_base]\ncommands = [[\"python\", \"-m\", \"mypkg.build\"]]\n"}), true, "mypkg/build.py:2"},
		{"package module a GitLab local include runs", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, ".gitlab-ci.yml": "include:\n  - local: ci/jobs.yml\n", "ci/jobs.yml": "deps:\n  script:\n    - python -m mypkg.build\n"}), true, "mypkg/build.py:2"},
		{"package module setup.py imports in a parenthesised group", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "setup.py": "from setuptools import setup\nfrom mypkg import (\n    other,\n    build,\n)\nsetup(name=\"app\", cmdclass={\"build_py\": build.BuildPy})\n"}), true, "mypkg/build.py:2"},
		{"package module named only as a longer identifier", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "mypkg/build_utils.py": "", ".github/workflows/ci.yml": wf("python -m mypkg.build_utils")}), false, ""},
		{"package module another package's path ends in", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, ".github/workflows/ci.yml": wf("python other/mypkg/build.py")}), true, "mypkg/build.py:2"},
		{"package module a JS config names", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "package.json": "{\"scripts\": {\"deps\": \"python mypkg/build.py\"}}\n"}), true, "mypkg/build.py:2"},
		{"package module only prose, tests and its own package mention", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "mypkg/run.py": "from mypkg import build\n", "tests/test_build.py": "from mypkg import build\n", "README.md": "Run `python -m mypkg.build`.\n", "docs/notes.txt": "python -m mypkg.build\n"}), false, ""},
		{"package module a tool-directory script runs", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "scripts/all.py": "import subprocess\nsubprocess.run([\"python\", \"-m\", \"mypkg.build\"])\n"}), true, "mypkg/build.py:2"},
		{"package module a setup.py beside an __init__.py imports", tree(map[string]string{"__init__.py": "", "mypkg/__init__.py": "", "mypkg/build.py": modInstall, "setup.py": "from mypkg import build\n"}), true, "mypkg/build.py:2"},
		{"package module setup.py imports from its dotted package", tree(map[string]string{"src/mypkg/__init__.py": "", "src/mypkg/build.py": modInstall, "setup.py": "from src.mypkg import build\n"}), true, "src/mypkg/build.py:2"},
		{"package module whose stem is not one identifier", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.local.py": modInstall}), true, "mypkg/build.local.py:2"},
		{"package module run after cd into its package", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, ".github/workflows/ci.yml": wf("cd mypkg && python build.py")}), true, "mypkg/build.py:2"},
		{"package module run from its package as working-directory", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: python build.py\n        working-directory: mypkg\n"}), true, "mypkg/build.py:2"},
		{"package module tox runs after changedir into its package", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "tox.ini": "[testenv]\nchangedir = mypkg\ncommands =\n    python build.py\n"}), true, "mypkg/build.py:2"},
		{"package module a Dockerfile copies alone then runs", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "Dockerfile": "FROM base\nCOPY mypkg/ /app/\nRUN python /app/build.py\n"}), true, "mypkg/build.py:2"},
		{"package module a PowerShell script runs by backslashed path", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "build.ps1": "python mypkg\\build.py\n"}), true, "mypkg/build.py:2"},
		{"package module a tool-directory module imports", tree(map[string]string{"scripts/__init__.py": "", "scripts/ci_setup.py": "from app import install\ninstall.main()\n", "app/__init__.py": "", "app/install.py": modInstall, ".github/workflows/ci.yml": wf("python -m scripts.ci_setup")}), true, "app/install.py:2"},
		{"package module a mentioned package module runs", tree(map[string]string{"app/__init__.py": "", "app/build.py": "import runpy\nrunpy.run_module(\"app.install\")\n", "app/install.py": modInstall, ".github/workflows/ci.yml": wf("python -m app.build")}), true, "app/install.py:2"},
		{"package module a module with a shebang imports", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "mypkg/run.py": "#!/usr/bin/env python3\nfrom mypkg import build\n"}), true, "mypkg/build.py:2"},
		{"package module only unmentioned modules of its package import", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/__main__.py": "from mypkg.utilities import install\n", "mypkg/api/__init__.py": "", "mypkg/api/handlers.py": "from mypkg.utilities.install import install_deps\n", "mypkg/utilities/__init__.py": "", "mypkg/utilities/install.py": modInstall, "tests/load/tasks.py": "from mypkg.utilities import log\n", ".github/workflows/ci.yml": wf("pytest tests")}), false, ""},
		{"package module a counted module imports relatively from its package", tree(map[string]string{"app/__init__.py": "", "app/build.py": "from . import install\n", "app/install.py": modInstall, ".github/workflows/ci.yml": wf("python -m app.build")}), true, "app/install.py:2"},
		{"package module a counted module imports from relatively", tree(map[string]string{"app/__init__.py": "", "app/build.py": "from .install import main\nmain()\n", "app/install.py": modInstall, ".github/workflows/ci.yml": wf("python -m app.build")}), true, "app/install.py:2"},
		{"package module a counted subpackage module imports from its parent package", tree(map[string]string{"app/__init__.py": "", "app/install.py": modInstall, "app/sub/__init__.py": "", "app/sub/build.py": "from .. import install\n", ".github/workflows/ci.yml": wf("python -m app.sub.build")}), true, "app/install.py:2"},
		{"package module a counted subpackage module imports from a sibling package", tree(map[string]string{"app/__init__.py": "", "app/tools/__init__.py": "", "app/tools/install.py": modInstall, "app/sub/__init__.py": "", "app/sub/build.py": "from ..tools import install\n", ".github/workflows/ci.yml": wf("python -m app.sub.build")}), true, "app/tools/install.py:2"},
		{"package module only unmentioned modules import relatively", tree(map[string]string{"app/__init__.py": "", "app/build.py": "from . import install\nfrom .install import main\n", "app/install.py": modInstall, "app/sub/__init__.py": "", "app/sub/deploy.py": "from .. import install\n"}), false, ""},
		{"package module a counted module imports relatively from another package", tree(map[string]string{"app/__init__.py": "", "app/build.py": "from .other import install\n", "app/install.py": modInstall, ".github/workflows/ci.yml": wf("python -m app.build")}), false, ""},
		{"package module an unmentioned build-stem module imports", tree(map[string]string{"app/__init__.py": "", "app/build.py": "from app import install\n", "app/install.py": modInstall}), false, ""},
		{"package module a batch file runs by backslashed path in capitals", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "make.bat": "@echo off\r\npython MYPKG\\BUILD.PY\r\n"}), true, "mypkg/build.py:2"},
		{"package module AppVeyor runs by backslashed path", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "appveyor.yml": "install:\n  - python mypkg\\build.py\n"}), true, "mypkg/build.py:2"},
		{"package module named by a backslashed tail without extension", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "make.bat": "@echo off\r\ncall run mypkg\\build\r\n"}), true, "mypkg/build.py:2"},
		{"package module nox joins a path to", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "noxfile.py": "import os, nox\n@nox.session\ndef deps(session):\n    session.run(\"python\", os.path.join(\"mypkg\", \"build.py\"))\n"}), true, "mypkg/build.py:2"},
		{"package module setup.py builds a pathlib path to", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "setup.py": "import runpy\nfrom pathlib import Path\nrunpy.run_path(str(Path(\"mypkg\") / \"build.py\"))\n"}), true, "mypkg/build.py:2"},
		{"package module under a hyphenated directory", tree(map[string]string{"build-support/__init__.py": "", "build-support/install.py": modInstall, ".github/workflows/ci.yml": wf("python build-support/install.py")}), true, "build-support/install.py:2"},
		{"package module under a dotted directory", tree(map[string]string{"pkg.v2/__init__.py": "", "pkg.v2/install.py": modInstall, ".github/workflows/ci.yml": wf("python pkg.v2/install.py")}), true, "pkg.v2/install.py:2"},
		{"package module CMake runs with -m", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "CMakeLists.txt": "project(x)\nadd_custom_target(deps ALL COMMAND ${Python3_EXECUTABLE} -m mypkg.build)\n"}), true, "mypkg/build.py:2"},
		{"package module CMake runs by path", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "CMakeLists.txt": "project(x)\nexecute_process(COMMAND python ${CMAKE_SOURCE_DIR}/mypkg/build.py)\n"}), true, "mypkg/build.py:2"},
		{"package module a shebang script named like prose runs", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, "bin/install": "#!/bin/sh\npython -m mypkg.build\n"}), true, "mypkg/build.py:2"},
		{"package module a test fixture's pyproject names by base name", tree(map[string]string{"src/app/commands/__init__.py": "", "src/app/commands/build.py": modInstall, "tests/fixtures/ext/pyproject.toml": "[tool.poetry.build]\nscript = \"build.py\"\n"}), true, "src/app/commands/build.py:2"},
		{"package module without an install a test fixture's pyproject names", tree(map[string]string{"src/app/commands/__init__.py": "", "src/app/commands/build.py": "def handle():\n    return 0\n", "tests/fixtures/ext/pyproject.toml": "[tool.poetry.build]\nscript = \"build.py\"\n"}), false, ""},
		{"package module whose base name ends a longer name", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, ".github/workflows/ci.yml": wf("python prebuild.py && python build.pyc")}), false, ""},
		{"package module named by a slashed tail without extension", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/build.py": modInstall, ".github/workflows/ci.yml": wf("python -c \"import runpy; runpy.run_path('mypkg/build' + '.py')\"")}), true, "mypkg/build.py:2"},
		{"capitalised package module run by its base name", tree(map[string]string{"mypkg/__init__.py": "", "mypkg/Build.py": modInstall, ".github/workflows/ci.yml": wf("cd mypkg && python Build.py")}), true, "mypkg/Build.py:2"},
		{"non-Python build script beside an __init__.py", tree(map[string]string{"pkg/__init__.py": "", "pkg/build.js": "require('child_process').execSync('inst add x')\n"}), true, "pkg/build.js:1"},
		{"bare call named like the installer", tree(map[string]string{"tasks.py": "from helpers import inst\ninst(\"add\", \"x\")\n"}), false, ""},
		{"root build script beside no package", tree(map[string]string{"build.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n"}), true, "build.py:2"},
		{"package module with a shebang", tree(map[string]string{"pkg/__init__.py": "", "pkg/build.py": "#!/usr/bin/env python3\nimport subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n"}), true, "pkg/build.py:3"},
		{"lane token as an attribute, not the module called", tree(map[string]string{"tasks.py": "def f(self):\n    return self.inst.pyproject.data.get(\"build-system\")\n"}), false, ""},
		{"installer API reached through a submodule", tree(map[string]string{"tasks.py": "import inst.console\ninst.console.main([\"add\", \"x\"])\n"}), true, "tasks.py:2"},
		{"nox session helper outside a pip lane", tree(map[string]string{"tools/nox_helpers.py": "def deps(session):\n    session.install(\"x\")\n"}), false, ""},

		// Install.sh parity: what a surface allows only by binding a manifest still withholds,
		// because the backstop does not know the directory it runs in.
		{"interpreter runs the installer module", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: python3 -u -m inst add x\n"}), true, "ci/pipeline.yml:2"},
		{"binding form withholds", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: inst sync\n"}), true, "ci/pipeline.yml:2"},

		// Text that names an installer but no build runs.
		{"README.md", tree(map[string]string{"README.md": "Install:\n\n    inst add x\n\n```\nRUN inst add x\nrun: inst add x\n```\n"}), false, ""},
		{"docs/*.rst", tree(map[string]string{"docs/install.rst": "Install\n=======\n\n.. code-block:: console\n\n   $ inst add x\n\nrun: inst add x\n"}), false, ""},
		{"CHANGELOG", tree(map[string]string{"CHANGELOG": "1.0\n- run: inst add x now works\n", "CHANGELOG.md": "- command: inst add x\n", "HISTORY.rst": "script: inst add x\n", "NEWS": "command: inst add x\n", "INSTALL": "run: inst add x\n"}), false, ""},
		{"prose extension", tree(map[string]string{"notes.txt": "run: inst add x\n", "guide.ipynb": "{\"cells\": [{\"source\": [\"!inst add x\"]}]}\n"}), false, ""},
		{"comment in a build file", tree(map[string]string{".buildkite/pipeline.yml": "# command: inst add x\nsteps:\n  - command: make # inst add x\n"}), false, ""},
		{"comment in a build script", tree(map[string]string{"tasks.py": "# c.run(\"inst add x\")\n\"\"\"Run `inst add x` first.\"\"\"\nprint('inst add x')\n"}), false, ""},
		{"commented-out task-table key", tree(map[string]string{"ci/tasks.cfg": "[tasks]\n//deps = inst add x\n"}), false, ""},
		{"read-only verb past a flag that takes a value", tree(map[string]string{"ci/x.yml": "steps:\n  - run: inst --cache-dir show add x\n"}), true, "ci/x.yml:2"},
		{"read-only verb past a bare flag", tree(map[string]string{"ci/x.yml": "steps:\n  - run: inst -q show x\n  - run: inst --cache-dir=/c show x\n"}), false, ""},
		{"audit that fixes", tree(map[string]string{"ci/x.yml": "steps:\n  - run: inst audit --fix\n"}), true, "ci/x.yml:2"},
		{"audit fix subcommand", tree(map[string]string{"ci/x.yml": "steps:\n  - run: inst audit fix\n"}), true, "ci/x.yml:2"},
		{"plain YAML value continued onto a second line", tree(map[string]string{"ci/x.yml": "steps:\n  - script: echo start &&\n      inst add x\n"}), true, "ci/x.yml:2"},
		{"double-quoted YAML value continued onto a second line", tree(map[string]string{"ci/x.yml": "steps:\n  - script: \"echo start &&\n      inst add x\"\n"}), true, "ci/x.yml:2"},
		{"comment after a plain YAML value", tree(map[string]string{"ci/x.yml": "steps:\n  - script: make\n      # inst add x\n"}), false, ""},
		{"sibling key after a plain YAML value", tree(map[string]string{"ci/x.yml": "steps:\n  - script: make\n    name: inst add x\n"}), false, ""},
		{"URL piped into an interpreter", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sS https://example.com/get-inst | python3 - x\n"}), true, "ci/x.yml:2"},
		{"URL piped into a shell", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sS https://example.com/inst | sh\n"}), true, "ci/x.yml:2"},
		{"URL piped through a filter into a shell", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sS https://example.com/get-inst | sed 's/a/b/' | sh -s x\n"}), true, "ci/x.yml:2"},
		{"URL piped into a shell that pipes on", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sS https://example.com/get-inst | sh -s x | tee log\n"}), true, "ci/x.yml:2"},
		{"URL piped through a filter into nothing that runs it", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sS https://example.com/get-inst | sed 's/a/b/' | tee log\n"}), false, ""},
		{"URL piped through tee into an interpreter", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sS https://example.com/get-inst | tee g.py | python3 - x\n"}), true, "ci/x.yml:2"},
		{"URL in a process substitution an interpreter runs", tree(map[string]string{"ci/x.yml": "steps:\n  - run: python3 <(curl -sS https://example.com/get-inst) x\n"}), true, "ci/x.yml:2"},
		{"URL in a process substitution another command reads", tree(map[string]string{"ci/x.yml": "steps:\n  - run: diff <(curl -sS https://example.com/get-inst) x\n"}), false, ""},
		{"URL piped into an output process substitution an interpreter runs", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sS https://example.com/get-inst | tee >(python3 - x) >/dev/null\n"}), true, "ci/x.yml:2"},
		{"URL redirected into an output process substitution an interpreter runs", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sS https://example.com/get-inst > >(python3 - x)\n"}), true, "ci/x.yml:2"},
		{"URL piped into an output process substitution another command reads", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sS https://example.com/get-inst | tee >(sha256sum) >/dev/null\n"}), false, ""},
		{"URL piped through tee with an output process substitution into an interpreter", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sS https://example.com/get-inst | tee >(sha256sum) | python3 - x\n"}), true, "ci/x.yml:2"},
		{"URL piped into an output process substitution a shell runs", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sS https://example.com/get-inst | tee >(sh) >/dev/null\n"}), true, "ci/x.yml:2"},
		{"URL piped into a spaced output process substitution an interpreter runs", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sS https://example.com/get-inst | tee >( python3 - x ) >/dev/null\n"}), true, "ci/x.yml:2"},
		{"URL piped through tee into a file and a process substitution another command reads", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sS https://example.com/get-inst | tee >(sha256sum) > g.py\n"}), false, ""},
		{"URL piped into a pipeline inside an output process substitution", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sS https://example.com/get-inst | tee >(cat | python3 -) >/dev/null\n"}), true, "ci/x.yml:2"},
		{"URL piped unspaced through tee into an interpreter", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sS https://example.com/get-inst|tee >(sha256sum)|python3 - x\n"}), true, "ci/x.yml:2"},
		{"URL fetched unspaced or else an interpreter reads its own input", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sS https://example.com/get-inst||python3 - x >(cat)\n"}), false, ""},
		{"URL piped with |& through tee into an interpreter", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sS https://example.com/get-inst |& tee >(sha256sum) |& python3 - x\n"}), true, "ci/x.yml:2"},
		{"Nx project under an e2e directory", tree(map[string]string{"e2e/app-e2e/project.json": "{\"name\": \"app-e2e\", \"targets\": {\"setup\": {\"executor\": \"nx:run-commands\", \"options\": {\"command\": \"inst add x\"}}}}\n"}), true, "e2e/app-e2e/project.json:1"},
		{"Nx project under a test directory", tree(map[string]string{"tests/project.json": "{\"name\": \"tests\", \"targets\": {\"setup\": {\"executor\": \"nx:run-commands\", \"options\": {\"commands\": [\"inst add x\"]}}}}\n"}), true, "tests/project.json:1"},
		{"Deno tasks under a test directory", tree(map[string]string{"tests/deno.json": "{\"tasks\": {\"setup\": \"inst add x\"}}\n"}), true, "tests/deno.json:1"},
		{"Deno JSONC tasks under a test directory", tree(map[string]string{"tests/deno.jsonc": "{\"tasks\": {\"setup\": \"inst add x\"}}\n"}), true, "tests/deno.jsonc:1"},
		{"Deno JSONC tasks with comments under a test directory", tree(map[string]string{"tests/deno.jsonc": "{\n  // tasks\n  \"tasks\": {\"setup\": \"inst add x\"}\n}\n"}), true, "tests/deno.jsonc:3"},
		{"Deno JSONC tasks after a block comment", tree(map[string]string{"deno.jsonc": "{\n  /* tasks\n     for CI */\n  \"tasks\": {\n    \"setup\": \"inst add x\"\n  }\n}\n"}), true, "deno.jsonc:5"},
		{"JSONC command with a trailing comment", tree(map[string]string{"ci/tasks.jsonc": "{\"command\": \"inst add x\"} // x\n"}), true, "ci/tasks.jsonc:1"},
		{"comment markers inside a JSONC string", tree(map[string]string{"ci/tasks.jsonc": "{\n  // c\n  \"url\": \"https://x/*\",\n  \"tasks\": {\"setup\": \"inst add x\"}\n}\n"}), true, "ci/tasks.jsonc:4"},
		{"Nx project with trailing commas", tree(map[string]string{"apps/x/project.json": "{\n  \"targets\": {\n    \"setup\": {\n      \"options\": {\"commands\": [\"echo\", \"inst add x\",]},\n    },\n  },\n}\n"}), true, "apps/x/project.json:4"},
		{"Nx JSON5 project under a test directory", tree(map[string]string{"tests/project.json5": "{\n  targets: {setup: {options: {command: 'inst add x'}}},\n}\n"}), true, "tests/project.json5:2"},
		{"JSON5 file that does not decode", tree(map[string]string{"ci/tasks.json5": "{\n  // steps\n  steps: ['inst add x'],\n}\n"}), true, "ci/tasks.json5:3"},
		{"JSONC led by a comment", tree(map[string]string{"ci/runner.jsonc": "// runner\n{\"tasks\": {\"setup\": \"inst add x\"}}\n"}), true, "ci/runner.jsonc:2"},
		{"JSONC block comment outside a task runner file", tree(map[string]string{"ci/runner.jsonc": "{/* c */\n\"tasks\": {\"setup\": \"inst add x\"}}\n"}), true, "ci/runner.jsonc:2"},
		{"JSONC escaped quote before comment markers", tree(map[string]string{"ci/runner.jsonc": "{\"desc\": \"a \\\"b // c\\\"\", // note\n\"tasks\": {\"setup\": \"inst add x\"}}\n"}), true, "ci/runner.jsonc:2"},
		{"JSON trailing comma before a closing brace", tree(map[string]string{"ci/runner.json": "{\"tasks\": {\"setup\": \"inst add x\",},}\n"}), true, "ci/runner.json:1"},
		{"JSON trailing comma before a closing bracket", tree(map[string]string{"ci/runner.json": "{\"tasks\": {\"setup\": [\"inst\", \"add\", \"x\",]}}\n"}), true, "ci/runner.json:1"},
		{"YAML named like a task runner file is not read string by string", tree(map[string]string{"ci/project.yaml": "description: \"run inst add x to set up\"\n"}), false, ""},
		{"Deno tasks that do not decode", tree(map[string]string{"tests/deno.json": "{\n  tasks: {setup: \"inst add x\"}\n"}), true, "tests/deno.json:2"},
		{"turbo tasks under a test directory", tree(map[string]string{"tests/turbo.json": mcp}), true, "tests/turbo.json:1"},
		{"single-quoted YAML continuation", tree(map[string]string{"ci/x.yml": "steps:\n  - command: 'echo start &&\n      inst add x'\n"}), true, "ci/x.yml:2"},
		{"audit that fixes with a value", tree(map[string]string{"ci/x.yml": "steps:\n  - run: inst audit --fix=all\n"}), true, "ci/x.yml:2"},
		{"entry point in project.scripts", tree(map[string]string{"pyproject.toml": "[project.scripts]\nsetup = \"inst add x\"\n"}), false, ""},
		{"sequence in a project table", tree(map[string]string{"pyproject.toml": "[project.scripts.x]\nsequence = [\"inst add x\"]\n"}), false, ""},
		{"CUE fields under a rule-shaped line", tree(map[string]string{"schema/x.cue": "kind: x: {\n\tinst add x\n}\n"}), false, ""},
		{"the same lines read as a make recipe", tree(map[string]string{"schema/x.cfg": "kind: x: {\n\tinst add x\n}\n"}), true, "schema/x.cfg:2"},
		{"CUE command key", tree(map[string]string{"ci/x_tool.cue": "package ci\n\nsetup: {\n\tcmd: \"inst add x\"\n}\n"}), true, "ci/x_tool.cue:4"},
		{"URL fetched to a file", tree(map[string]string{"ci/x.yml": "steps:\n  - run: curl -sSo get.py https://example.com/get-inst | tee log\n"}), false, ""},
		{"tab-indented continuation under no rule", tree(map[string]string{"ci/tool.cfg": "help = run this first\n\tinst add x\n"}), false, ""},
		{"usage example in a docstring", tree(map[string]string{"tasks.py": "def deps(c):\n    \"\"\"Install deps.\n\n    c.run(\"inst add x\")\n    \"\"\"\n"}), false, ""},
		{"test directory under scripts", tree(map[string]string{"scripts/tests/run_setup.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n"}), false, ""},
		{"source that is not a build script", tree(map[string]string{"app/cli.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n"}), false, ""},
		{"test file under scripts", tree(map[string]string{"scripts/tests/test_setup.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", "scripts/setup.test.js": "execSync('inst add x')\n"}), false, ""},
		{"installer named mid-sentence", tree(map[string]string{"config.yml": "description: run inst add x before you start\nhelp: inst add x\n"}), false, ""},
		{"RUN without a FROM", tree(map[string]string{"recipe.cfg": "RUN inst add x\n"}), false, ""},
		{"FROM in a Python import is not a Dockerfile", tree(map[string]string{"ci/notes.cfg": "from os import path\nrun inst add x\n"}), false, ""},
		{"read-only and version queries", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: inst list\n  - command: inst --version\n  - command: inst show x\n  - command: python -m inst freeze\n"}), false, ""},
		{"installer variable under a key that is not env", tree(map[string]string{"ci/pipeline.yml": "labels:\n  INST_INDEX: http://mirror\nsteps:\n  - command: make\n"}), false, ""},
		{"installer variable outside an env map", tree(map[string]string{"data/consts.json": "{\n  \"INST_INDEX\": 1\n}\n"}), false, ""},
		{"lockfile", tree(map[string]string{"deps.lock": "steps:\n  - command: inst add x\n"}), false, ""},
		{"Read the Docs config", tree(map[string]string{".readthedocs.yaml": "build:\n  commands:\n    - inst add x\n"}), false, ""},
		{"published action no workflow here uses", tree(map[string]string{"action.yml": localAction, ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"}), false, ""},
		{"published pre-commit hooks", tree(map[string]string{".pre-commit-hooks.yaml": "- id: x\n  entry: inst add x\n"}), false, ""},
		{"no installer anywhere", tree(map[string]string{".buildkite/pipeline.yml": "steps:\n  - command: make test\n", "Dockerfile-prod": "FROM base\nRUN make\n"}), false, ""},

		// A surface is read by its own rule, never by the backstop as well: the bound install
		// passes there and the backstop records nothing.
		{"recognised surface not double-processed", tree(map[string]string{"install.sh": "inst sync\n", ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: inst sync\n"}), false, ""},
		{"recognised surface withholds by its own rule", tree(map[string]string{"install.sh": "inst add x\n"}), true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTree(t, tt.files)
			got, at := backstopped(root)
			if got != tt.want {
				t.Fatalf("withheld = %v, want %v (at %q)", got, tt.want, at)
			}
			if tt.at != "-" && at != tt.at {
				t.Fatalf("Unrecognised() = %q, want %q", at, tt.at)
			}
		})
	}
}

// Past backstopMax the backstop reads a file's head, and only its head.
func TestVeto_BackstopOversized(t *testing.T) {
	pad := strings.Repeat("// generated\n", backstopMax/13+1)
	tests := []struct {
		name string
		body string
		want bool   // withheld
		at   string // Unrecognised()
	}{
		{"installer in the head", "const { execSync } = require('child_process')\nexecSync('inst add x')\n" + pad, true, "scripts/bundle.js:2"},
		{"installer past the head", pad + "execSync('inst add x')\n", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n", "scripts/bundle.js": tt.body})
			got, at := backstopped(root)
			if got != tt.want || at != tt.at {
				t.Fatalf("withheld = %v at %q, want %v at %q", got, at, tt.want, tt.at)
			}
		})
	}
}

// A nox session's install helper installs with pip, so it withholds in a lane pip installs
// for and nowhere else.
func TestVeto_BackstopNoxLane(t *testing.T) {
	root := writeTree(t, map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n", "tools/nox_helpers.py": "def deps(session):\n    session.install(\"x\")\n"})
	spec := testSpec
	spec.Token = func(w string) bool { return testSpec.Token(w) || w == "pip" }
	v := New(root, testRead(root), spec)
	none := func(string, []byte) (string, bool) { return "", false }
	withheld := false
	for _, c := range buildtree.Candidates(root, v.Classify(none), v.FullyRead) {
		withheld = withheld || !c.FullyRead
	}
	if !withheld || v.Unrecognised() != "tools/nox_helpers.py:2" {
		t.Fatalf("withheld = %v at %q, want true at tools/nox_helpers.py:2", withheld, v.Unrecognised())
	}
}

// A file the backstop would read but cannot is withheld: what it may run is unknown.
func TestVeto_BackstopUnreadable(t *testing.T) {
	root := writeTree(t, map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n"})
	big := make([]byte, buildtree.HeadSize)
	for i := range big {
		big[i] = 'a'
	}
	big[0] = 'x'
	p := filepath.Join(root, "ci.cfg")
	if err := os.WriteFile(p, big, 0o644); err != nil {
		t.Fatal(err)
	}
	spec := testSpec
	spec.ReadRegular = func(string) ([]byte, error) { return nil, errors.New("unreadable") }
	v := New(root, testRead(root), spec)
	why, ok := v.Classify(func(string, []byte) (string, bool) { return "", false })(p, big)
	if !ok || why == "" {
		t.Fatalf("Classify = %q, %v; want a withhold", why, ok)
	}
	if got := v.Unrecognised(); got != "ci.cfg" {
		t.Fatalf("Unrecognised() = %q, want ci.cfg", got)
	}
}

func TestVeto_BackstopPackageModuleFailsClosed(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, root string) func(string) bool // returns which paths fail to read
		want  bool
	}{
		{"every build file readable", func(*testing.T, string) func(string) bool { return func(string) bool { return false } }, false},
		{"a build file unreadable", func(*testing.T, string) func(string) bool {
			return func(p string) bool { return filepath.Base(p) == "Makefile" }
		}, true},
		{"a build file behind a symlink", func(t *testing.T, root string) func(string) bool {
			if err := os.Symlink("Makefile", filepath.Join(root, "GNUmakefile")); err != nil {
				t.Fatal(err)
			}
			return func(string) bool { return false }
		}, true},
		{"a project file behind a symlink", func(t *testing.T, root string) func(string) bool {
			if err := os.Symlink("Makefile", filepath.Join(root, "setup.cfg")); err != nil {
				t.Fatal(err)
			}
			return func(string) bool { return false }
		}, true},
		{"a text file unreadable", func(t *testing.T, root string) func(string) bool {
			if err := os.WriteFile(filepath.Join(root, "ci.cfg"), []byte("[x]\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return func(p string) bool { return filepath.Base(p) == "ci.cfg" }
		}, true},
		{"a file whose head cannot be read", func(t *testing.T, root string) func(string) bool {
			p := filepath.Join(root, "ci.cfg")
			if err := os.WriteFile(p, []byte("[x]\n"), 0o000); err != nil {
				t.Fatal(err)
			}
			if _, err := os.ReadFile(p); err == nil {
				t.Skip("file permissions not enforced")
			}
			return func(string) bool { return false }
		}, true},
		{"a symlinked directory", func(t *testing.T, root string) func(string) bool {
			if err := os.Symlink("pkg", filepath.Join(root, "ci")); err != nil {
				t.Fatal(err)
			}
			return func(string) bool { return false }
		}, true},
		{"a link out of the build", func(t *testing.T, root string) func(string) bool {
			out := filepath.Join(t.TempDir(), "jobs.yml")
			if err := os.WriteFile(out, []byte("deps:\n  script: [make]\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(out, filepath.Join(root, "jobs.yml")); err != nil {
				t.Fatal(err)
			}
			return func(string) bool { return false }
		}, true},
		{"a dangling link", func(t *testing.T, root string) func(string) bool {
			if err := os.Symlink("missing", filepath.Join(root, "ci")); err != nil {
				t.Fatal(err)
			}
			return func(string) bool { return false }
		}, true},
		{"a link to a file in the build", func(t *testing.T, root string) func(string) bool {
			if err := os.Symlink("inst.toml", filepath.Join(root, "notes.toml")); err != nil {
				t.Fatal(err)
			}
			return func(string) bool { return false }
		}, false},
		{"a directory unreadable", func(t *testing.T, root string) func(string) bool {
			d := filepath.Join(root, "ci")
			if err := os.Mkdir(d, 0o000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(d, 0o755) })
			if _, err := os.ReadDir(d); err == nil {
				t.Skip("directory permissions not enforced")
			}
			return func(string) bool { return false }
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"inst.toml":       "[deps]\n",
				"inst.lock":       "lock\n",
				"pkg/__init__.py": "",
				"pkg/build.py":    "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n",
				"Makefile":        "all:\n\techo ok\n",
			})
			fail := tt.setup(t, root)
			spec := testSpec
			read := spec.ReadRegular
			spec.ReadRegular = func(p string) ([]byte, error) {
				if fail(p) {
					return nil, errors.New("unreadable")
				}
				return read(p)
			}
			v := New(root, testRead(root), spec)
			p := filepath.Join(root, "pkg", "build.py")
			head, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			_, ok := v.Classify(func(string, []byte) (string, bool) { return "", false })(p, head)
			if ok != tt.want {
				t.Fatalf("Classify withheld = %v, want %v", ok, tt.want)
			}
		})
	}
}

// A JSON file under a test directory is read when a file the build reads could not be read,
// since that file may name it.
func TestVeto_BackstopFixtureFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		fail string
		want bool
	}{
		{"every build file readable", "", false},
		{"a build file unreadable", "Makefile", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"inst.toml":        "[deps]\n",
				"inst.lock":        "lock\n",
				"Makefile":         "all:\n\techo ok\n",
				"tests/steps.json": `{"mcpServers": {"a": {"command": "inst", "args": ["add", "x"]}}}`,
			})
			spec := testSpec
			read := spec.ReadRegular
			spec.ReadRegular = func(p string) ([]byte, error) {
				if tt.fail != "" && filepath.Base(p) == tt.fail {
					return nil, errors.New("unreadable")
				}
				return read(p)
			}
			v := New(root, testRead(root), spec)
			p := filepath.Join(root, "tests", "steps.json")
			head, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			_, ok := v.Classify(func(string, []byte) (string, bool) { return "", false })(p, head)
			if ok != tt.want {
				t.Fatalf("Classify withheld = %v, want %v", ok, tt.want)
			}
		})
	}
}
