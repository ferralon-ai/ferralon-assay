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
		{"Dockerfile-prod RUN (ferralon-ai/tracker#630)", tree(map[string]string{"Dockerfile-prod": "FROM base\nWORKDIR /app\nRUN inst add x==1\n"}), true, "Dockerfile-prod:3"},
		{"Containerfile_dev RUN", tree(map[string]string{"Containerfile_dev": "FROM base\nRUN inst add x\n"}), true, "Containerfile_dev:2"},
		{"arbitrary Dockerfile name (ferralon-ai/tracker#631)", tree(map[string]string{"docker-compose.yml": "services:\n  web:\n    build: {context: ., dockerfile: docker/web.df}\n", "docker/web.df": "FROM base\nRUN inst add x==1\n"}), true, "docker/web.df:2"},
		{"Dockerfile-like ENV sets an installer variable", tree(map[string]string{"Dockerfile-prod": "FROM base\nENV INST_INDEX=http://mirror\n"}), true, "Dockerfile-prod:2"},
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
		{"MCP fixtures under a test directory", tree(map[string]string{"tests/fixtures/mcp_configs/uvx.json": mcp, "tests/e2e/agent.yaml": "steps:\n  - command: inst add x\n", "testdata/cfg.toml": "[x]\ncommand = \"inst add x\"\n"}), false, ""},
		{"JSON data under a test directory", tree(map[string]string{"tests/fixtures/mcp_configs/uvx.json": mcp}), false, ""},
		{"YAML data under a test directory", tree(map[string]string{"tests/e2e/agent.yaml": "steps:\n  - command: inst add x\n"}), false, ""},
		{"TOML data under a test directory", tree(map[string]string{"testdata/cfg.toml": "[x]\ncommand = \"inst add x\"\n"}), false, ""},
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
		// Dockerfile-like files are read by the Dockerfile rule.
		{"lowercase Dockerfile-like", tree(map[string]string{"Dockerfile-prod": "from base\nrun inst add x\n"}), true, "Dockerfile-prod:2"},
		{"Dockerfile-like heredoc", tree(map[string]string{"Dockerfile-prod": "FROM base\nRUN <<EOF\ninst add x\nEOF\n"}), true, "Dockerfile-prod:2"},
		{"Dockerfile-like CMD", tree(map[string]string{"Dockerfile-prod": "FROM base\nCMD inst add x\nRUN echo\n"}), true, "Dockerfile-prod:2"},
		{"Dockerfile-like continuation line", tree(map[string]string{"Dockerfile-prod": "FROM base\nRUN echo hi && \\\n    inst add x\n"}), true, "Dockerfile-prod:2"},
		{"Dockerfile-like bound install passes", tree(map[string]string{"Dockerfile-prod": "FROM base\nWORKDIR /app\nCOPY inst.toml inst.lock ./\nRUN inst sync\n"}), false, ""},
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
		{"package module named in pyproject", tree(map[string]string{"app/utilities/__init__.py": "", "app/utilities/install.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", "pyproject.toml": "[tool.x]\nhook = \"app.utilities.install:main\"\n"}), true, "app/utilities/install.py:2"},
		{"src-layout package module named in setup.cfg", tree(map[string]string{"src/pkg/__init__.py": "", "src/pkg/build.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", "setup.cfg": "[x]\nhook = pkg.build\n"}), true, "src/pkg/build.py:2"},
		{"package module by path in setup.py", tree(map[string]string{"pkg/__init__.py": "", "pkg/build.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", "setup.py": "exec(open(\"pkg/build.py\").read())\n"}), true, "pkg/build.py:2"},
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
