package scriptsurface

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readmeWorkflow is the first yaml block of the repository README: the workflow a user copies.
func readmeWorkflow(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(b), "```yaml\n")
	if !ok {
		t.Fatal("README.md has no yaml block")
	}
	block, _, ok := strings.Cut(rest, "```")
	if !ok {
		t.Fatal("README.md yaml block is not closed")
	}
	return block
}

// A data surface's runner runs the values under its command keys; any other value is a
// parameter, which passes every gate a command does except that . or source alone sources
// nothing.
func TestVeto_CommandKeys(t *testing.T) {
	tree := func(extra map[string]string) map[string]string {
		files := map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n"}
		for k, v := range extra {
			files[k] = v
		}
		return files
	}
	const wf = ".github/workflows/ci.yml"
	steps := func(body string) string {
		return "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      " + body
	}
	tests := []struct {
		name  string
		files map[string]string
		want  bool // withheld
	}{
		{"README workflow verbatim", tree(map[string]string{wf: readmeWorkflow(t)}), false},
		{"build-push context: .", tree(map[string]string{wf: steps("- uses: docker/build-push-action@v6\n        with:\n          context: .\n          push: false\n")}), false},
		{"action input source alone", tree(map[string]string{wf: steps("- uses: org/a@v1\n        with:\n          mode: source\n")}), false},
		{"env value .", tree(map[string]string{wf: steps("- run: inst sync\n        env:\n          DIR: .\n")}), false},
		{"compose build context: .", tree(map[string]string{"compose.yaml": "services:\n  app:\n    build:\n      context: .\n    command: serve\n"}), false},
		{"netlify publish", tree(map[string]string{"netlify.toml": "[build]\n  command = \"make\"\n  publish = \".\"\n"}), false},
		{"vercel outputDirectory", tree(map[string]string{"vercel.json": `{"buildCommand": "make", "outputDirectory": "."}`}), false},
		{"devcontainer build context", tree(map[string]string{".devcontainer/devcontainer.json": `{"build": {"context": "."}}`}), false},
		{"JSON exec form . under a parameter", tree(map[string]string{"vercel.json": `{"outputDirectory": ["."]}`}), false},
		{"GitLab variable .", tree(map[string]string{".gitlab-ci.yml": "variables:\n  DIR: .\nbuild:\n  script:\n    - make\n"}), false},
		{"bitbucket step name .", tree(map[string]string{"bitbucket-pipelines.yml": "pipelines:\n  default:\n    - step:\n        name: .\n        script:\n          - make\n"}), false},

		// An action may run its inputs, and an env value may reach a shell, so the install
		// gates still apply to them.
		{"action input . on its own line", tree(map[string]string{wf: steps("- uses: org/a@v1\n        with:\n          script:\n            .\n            ./env.sh\n")}), true},
		{"action input source on its own line", tree(map[string]string{wf: steps("- uses: org/a@v1\n        with:\n          args:\n            source\n            ./env.sh\n")}), true},
		{"compose build arg . on its own line", tree(map[string]string{"compose.yaml": "services:\n  app:\n    build:\n      args:\n        X:\n          .\n          ./env.sh\n"}), true},
		{"action input . continued", tree(map[string]string{wf: steps("- uses: org/a@v1\n        with:\n          script: .\n            ./env.sh\n")}), true},
		{"action input list item . continued", tree(map[string]string{wf: steps("- uses: org/a@v1\n        with:\n          args:\n            - .\n              ./env.sh\n")}), true},
		{"action input literal block of .", tree(map[string]string{wf: steps("- uses: org/a@v1\n        with:\n          script: |\n            .\n            ./env.sh\n")}), true},
		{"tox parameter . continued", tree(map[string]string{"tox.ini": "[testenv]\nsetenv = .\n    ./env.sh\n"}), true},
		{"tox parameter . continued by a tab", tree(map[string]string{"tox.ini": "[testenv]\nsetenv = .\n\t./env.sh\n"}), true},
		{"tox parameter continuation .", tree(map[string]string{"tox.ini": "[testenv]\nsetenv =\n    .\n"}), true},
		{"JSON parameter . on its own line", tree(map[string]string{"vercel.json": `{"outputDirectory": ".\n./env.sh"}`}), true},
		{"command key in an item under a parameter", tree(map[string]string{".travis.yml": "jobs:\n  include:\n    - install: .\n"}), true},
		{"action input list item .", tree(map[string]string{wf: steps("- uses: org/a@v1\n        with:\n          args:\n            - .\n")}), false},
		{"netlify publish before a sibling key", tree(map[string]string{"netlify.toml": "[build]\npublish = \".\"\ncommand = \"make\"\n"}), false},
		{"netlify publish before a table", tree(map[string]string{"netlify.toml": "[build]\n  publish = \".\"\n[context.production]\n  command = \"make\"\n"}), false},
		{"action input names an installer", tree(map[string]string{wf: steps("- uses: org/a@v1\n        with:\n          args: inst add x\n")}), true},
		{"action input sources a file", tree(map[string]string{wf: steps("- uses: org/a@v1\n        with:\n          script: . ./env.sh\n")}), true},
		{"env value names an installer", tree(map[string]string{wf: steps("- run: make\n        env:\n          CMD: inst add x\n")}), true},
		{"env sets a lane variable", tree(map[string]string{wf: steps("- run: make\n        env:\n          INST_INDEX: https://example.test\n")}), true},
		{"compose build arg names an installer", tree(map[string]string{"compose.yaml": "services:\n  app:\n    build:\n      args:\n        X: inst add x\n"}), true},

		{"run: . ./env.sh", tree(map[string]string{wf: steps("- run: . ./env.sh\n")}), true},
		{"run: source ./env.sh", tree(map[string]string{wf: steps("- run: source ./env.sh\n")}), true},
		{"run: inst add x", tree(map[string]string{wf: steps("- run: inst add x\n")}), true},
		{"run block", tree(map[string]string{wf: steps("- run: |\n          make\n          inst add x\n")}), true},
		{"GitLab script item", tree(map[string]string{".gitlab-ci.yml": "build:\n  script:\n    - . ./env.sh\n"}), true},
		{"Procfile line", tree(map[string]string{"Procfile": "web: source ./env.sh\n"}), true},
		{"Procfile .", tree(map[string]string{"Procfile": "web: .\n"}), true},
		{"package.json script", tree(map[string]string{"package.json": `{"scripts": {"build": ". ./env.sh"}}`}), true},
		{"package.json script .", tree(map[string]string{"package.json": `{"scripts": {"build": "."}}`}), true},
		{"compose command", tree(map[string]string{"compose.yaml": "services:\n  app:\n    command: inst add x\n"}), true},
		{"compose command list", tree(map[string]string{"compose.yaml": "services:\n  app:\n    command:\n      - .\n"}), true},
		{"bitbucket script in a step item", tree(map[string]string{"bitbucket-pipelines.yml": "pipelines:\n  default:\n    - step:\n        name: b\n        script:\n          - .\n"}), true},
		{"travis install list", tree(map[string]string{".travis.yml": "install:\n  - .\n"}), true},
		{"key nested under a command key", tree(map[string]string{"Taskfile.yml": "tasks:\n  b:\n    cmds:\n      - cmd: .\n"}), true},
		{"JSON object under a command key", tree(map[string]string{".devcontainer/devcontainer.json": `{"postCreateCommand": {"a": "."}}`}), true},
		{"JSON exec form under a command key", tree(map[string]string{"vercel.json": `{"installCommand": "inst add x"}`}), true},
		{"tox continuation under commands", tree(map[string]string{"tox.ini": "[testenv]\ncommands =\n    .\n"}), true},
		{"quoted command key", tree(map[string]string{"compose.yaml": "services:\n  app:\n    \"command\": .\n"}), true},
		{"upper-case command key", tree(map[string]string{"vercel.json": `{"BUILDCOMMAND": "."}`}), true},
		{"compose command list at the key's column", tree(map[string]string{"compose.yaml": "services:\n  app:\n    command:\n    - .\n"}), true},
		{"compose command literal block", tree(map[string]string{"compose.yaml": "services:\n  app:\n    command: |\n      .\n"}), true},
		{"compose map under command", tree(map[string]string{"compose.yaml": "services:\n  app:\n    command:\n      a: .\n"}), true},
		{"JSON exec form . under a command key", tree(map[string]string{"vercel.json": `{"installCommand": ["."]}`}), true},
		{"JSON objects in an array under a command key", tree(map[string]string{".devcontainer/devcontainer.json": `{"postCreateCommand": [{"a": "."}]}`}), true},
		{"TOML line before any key", tree(map[string]string{"netlify.toml": ".\n"}), true},
		{"bare item under no key", tree(map[string]string{".travis.yml": "- .\n"}), true},
		{"bare line under no key", tree(map[string]string{".travis.yml": ".\n"}), true},

		// Surfaces with no command keys listed run every value.
		{"appveyor value", tree(map[string]string{"appveyor.yml": "dir: .\n"}), true},
		{"noxfile value", tree(map[string]string{"noxfile.py": "x = \".\"\n"}), true},
		{"Jenkinsfile value", tree(map[string]string{"Jenkinsfile": "dir: .\n"}), true},
		{"undecodable vercel.json", tree(map[string]string{"vercel.json": "{\n\"outputDirectory\": \".\"\n"}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTree(t, tt.files)
			if got := withheld(root, testSpec); got != tt.want {
				t.Fatalf("withheld = %v, want %v", got, tt.want)
			}
		})
	}
}

// Each surface's command keys, stated here apart from commandKeys: a value of . alone under
// one withholds, and under any other key (dir) passes.
func TestVeto_CommandKeysBySurface(t *testing.T) {
	yaml := func(key string) string { return key + ": .\n" }
	toml := func(key string) string { return key + " = \".\"\n" }
	ini := func(key string) string { return "[testenv]\n" + key + " = .\n" }
	jsonDoc := func(key string) string { return `{"` + key + `": "."}` }
	surfaces := []struct {
		path string
		doc  func(key string) string
		keys []string
	}{
		{".github/workflows/ci.yml", yaml, []string{"run", "command", "entrypoint"}},
		{".github/actions/a/action.yml", yaml, []string{"run", "entrypoint", "pre-entrypoint", "post-entrypoint", "args"}},
		{"compose.yaml", yaml, []string{"command", "entrypoint", "test"}},
		{"docker-compose.yml", yaml, []string{"command", "entrypoint", "test"}},
		{".circleci/config.yml", yaml, []string{"run", "command"}},
		{".drone.yml", yaml, []string{"commands", "command", "entrypoint"}},
		{".woodpecker.yml", yaml, []string{"commands", "command", "entrypoint"}},
		{".woodpecker/build.yml", yaml, []string{"commands", "command", "entrypoint"}},
		{"azure-pipelines.yml", yaml, []string{"script", "bash", "pwsh", "powershell"}},
		{"buildspec.yml", yaml, []string{"commands", "finally"}},
		{"cloudbuild.yaml", yaml, []string{"args", "entrypoint", "script"}},
		{"Taskfile.yml", yaml, []string{"cmds", "cmd", "sh", "status", "preconditions", "defer"}},
		{".gitlab-ci.yml", yaml, []string{"script", "before_script", "after_script", "pre_get_sources_script", "command", "entrypoint", "run"}},
		{"bitbucket-pipelines.yml", yaml, []string{"script", "after-script"}},
		{".travis.yml", yaml, []string{"before_install", "install", "before_script", "script", "after_script", "after_success", "after_failure", "before_cache", "before_deploy", "after_deploy"}},
		{".gitpod.yml", yaml, []string{"before", "init", "command"}},
		{"render.yaml", yaml, []string{"buildCommand", "startCommand", "preDeployCommand", "dockerCommand", "initialDeployHook"}},
		{"netlify.toml", toml, []string{"command", "ignore"}},
		{"nixpacks.toml", toml, []string{"cmds", "cmd"}},
		{"tox.ini", ini, []string{"commands", "commands_pre", "commands_post", "install_command", "list_dependencies_command"}},
		{"vercel.json", jsonDoc, []string{"buildCommand", "installCommand", "devCommand", "ignoreCommand"}},
		{"app.json", jsonDoc, []string{"scripts"}},
		{"devcontainer.json", jsonDoc, []string{"initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"}},
		{".devcontainer.json", jsonDoc, []string{"initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"}},
	}
	for _, s := range surfaces {
		for _, key := range append(s.keys, "dir") {
			want := key != "dir"
			t.Run(s.path+"/"+key, func(t *testing.T) {
				root := writeTree(t, map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n", s.path: s.doc(key)})
				if got := withheld(root, testSpec); got != want {
					t.Fatalf("withheld = %v, want %v", got, want)
				}
			})
		}
	}
}
