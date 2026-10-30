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
		{"installer named as a key in command text", tree(map[string]string{"ci/pipeline.yml": "steps:\n  - command: |\n      echo versions\n      inst = 1.0\n      inst : 1.0\n"}), false, ""},
		{"command held in a variable", tree(map[string]string{"tasks.py": "import subprocess\ninstall_cmd = [\"inst\", \"add\", \"x\"]\nsubprocess.run(install_cmd)\n"}), true, "tasks.py:2"},
		{"command held under a cmd key", tree(map[string]string{"scripts/steps.js": "module.exports = [\n  { cmd: 'inst add x' },\n]\n"}), true, "scripts/steps.js:2"},
		{"key that describes a command", tree(map[string]string{"scripts/sandbox.js": "module.exports = {\n  startCommand: 'inst add x',\n}\n"}), false, ""},
		{"list of installer names", tree(map[string]string{"tasks.py": "installer_cmds = [\"inst\", \"instw\"]\n"}), false, ""},
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
		{"make-like recipe", tree(map[string]string{"tasks.cfg": "deps:\n\tinst add x\n"}), true, "tasks.cfg:2"},
		{"pre-install hook key", tree(map[string]string{"ci/pipeline.yml": "language: python\nbefore_install:\n  - inst add x\n"}), true, "ci/pipeline.yml:3"},
		{"installer variable under env", tree(map[string]string{"ci/pipeline.yml": "env:\n  INST_INDEX: http://mirror\nsteps:\n  - command: make\n"}), true, "ci/pipeline.yml:2"},
		{"published action a workflow here uses", tree(map[string]string{"action.yml": localAction, ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./\n"}), true, "action.yml:6"},
		{"nested action a Gitea workflow uses", tree(map[string]string{"actions/setup/action.yaml": localAction, ".gitea/workflows/ci.yml": "on: push\njobs:\n  t:\n    steps:\n      - uses: './actions/setup'\n"}), true, "actions/setup/action.yaml:6"},
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
		{"commented-out command keys", tree(map[string]string{"ci/pipeline.yml": "steps:\n#- command: inst add x\n#command: inst add x\n  - command: make\n", "ci/tasks.jsonc": "{\n  // \"command\": \"inst add x\",\n  \"command\": \"make\"\n}\n", "ci/tool.ini": ";command=inst add x\n", "ci/steps.cfg": "//command: inst add x\n//run = inst add x\n"}), false, ""},
		{"tab-indented continuation under no rule", tree(map[string]string{"ci/tool.cfg": "help = run this first\n\tinst add x\n"}), false, ""},
		{"usage example in a docstring", tree(map[string]string{"tasks.py": "def deps(c):\n    \"\"\"Install deps.\n\n    c.run(\"inst add x\")\n    \"\"\"\n"}), false, ""},
		{"test directory under scripts", tree(map[string]string{"scripts/tests/run_setup.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n"}), false, ""},
		{"source that is not a build script", tree(map[string]string{"app/cli.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n"}), false, ""},
		{"test file under scripts", tree(map[string]string{"scripts/tests/test_setup.py": "import subprocess\nsubprocess.run([\"inst\", \"add\", \"x\"])\n", "scripts/setup.test.js": "execSync('inst add x')\n"}), false, ""},
		{"installer named mid-sentence", tree(map[string]string{"config.yml": "description: run inst add x before you start\nhelp: inst add x\n"}), false, ""},
		{"RUN without a FROM", tree(map[string]string{"recipe.cfg": "RUN inst add x\n"}), false, ""},
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
