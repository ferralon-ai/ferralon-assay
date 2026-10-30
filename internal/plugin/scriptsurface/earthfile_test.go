package scriptsurface

import (
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
)

// An Earthfile, a Buildkite pipeline and a Gitea or Forgejo workflow are surfaces: their
// installs are read by the Dockerfile and CI rules, so an allowed one is recorded where it
// binds and the backstop never reads them.
func TestVeto_RecognisedCI(t *testing.T) {
	lock := map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n"}
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
	const earth = "VERSION 0.8\nbuild:\n    FROM python:3\n    WORKDIR /app\n    COPY inst.toml inst.lock ./\n"
	actions := func(wd, run string) string {
		return "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    defaults:\n      run:\n        working-directory: " +
			wd + "\n    steps:\n      - run: " + run + "\n"
	}
	const unit = "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          python -m venv .venv\n          . .venv/bin/activate\n          inst install -r reqs.txt\n"
	tests := []struct {
		name   string
		files  map[string]string
		want   bool   // withheld
		record string // an allowed command the walk must record, or ""
	}{
		{"Earthfile allowed install", tree(map[string]string{"Earthfile": earth + "    RUN inst sync\n"}), false, "inst sync"},
		{"Earthfile install off the lock", tree(map[string]string{"Earthfile": earth + "    RUN inst add x==1\n"}), true, ""},
		{"Earthfile continuation", tree(map[string]string{"Earthfile": earth + "    RUN echo hi && \\\n        inst add x\n"}), true, ""},
		{"Earthfile target built on another target", tree(map[string]string{"Earthfile": earth + "    SAVE ARTIFACT /app\ntest:\n    FROM +build\n    RUN inst sync\n"}), true, ""},
		{"Earthfile new target inherits no stage", tree(map[string]string{"Earthfile": earth + "deps:\n    RUN inst sync\n"}), true, ""},
		{"Earthfile function call before install", tree(map[string]string{"Earthfile": earth + "    DO +SETUP\n    RUN inst sync\n"}), true, ""},
		{"Earthfile artifact naming an installer is inert", tree(map[string]string{"Earthfile": earth + "    RUN inst sync\n    SAVE ARTIFACT /root/.cache/inst AS LOCAL inst-cache\n"}), false, "inst sync"},
		{"Earthfile LOCALLY", tree(map[string]string{"Earthfile": "VERSION 0.8\ndev:\n    LOCALLY\n    RUN inst sync\n"}), true, ""},
		{"Earthfile artifact copied from a target", tree(map[string]string{"Earthfile": earth + "    COPY +deps/inst.lock ./\n    RUN inst sync\n"}), true, ""},
		{"Earthfile DO naming an installer", tree(map[string]string{"Earthfile": earth + "    DO --pass-args ./lib+INST --cmd=\"inst add x\"\n"}), true, ""},
		{"Buildkite allowed install", tree(map[string]string{".buildkite/pipeline.yml": "steps:\n  - command: inst sync\n"}), false, "inst sync"},
		{"Buildkite install off the lock", tree(map[string]string{".buildkite/pipeline.yml": "steps:\n  - command: inst add x\n"}), true, ""},
		{"root buildkite.yml allowed install", tree(map[string]string{"buildkite.yml": "steps:\n  - command: inst sync\n"}), false, "inst sync"},
		{"root buildkite.yaml", tree(map[string]string{"buildkite.yaml": "steps:\n  - commands:\n      - inst add x\n"}), true, ""},
		{"Gitea working-directory", tree(map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", ".gitea/workflows/ci.yml": actions("app", "inst sync")}), false, "inst sync"},
		{"Forgejo working-directory", tree(map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", ".forgejo/workflows/ci.yml": actions("app", "inst sync")}), false, "inst sync"},
		{"GitHub working-directory", tree(map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", ".github/workflows/ci.yml": actions("app", "inst sync")}), false, "inst sync"},
		{"GitHub step is one shell", tree(map[string]string{"reqs.txt": "x==1\n", ".github/workflows/ci.yml": unit}), false, "inst install -r reqs.txt"},
		{"Gitea step is one shell", tree(map[string]string{"reqs.txt": "x==1\n", ".gitea/workflows/ci.yml": unit}), false, "inst install -r reqs.txt"},
		{"Forgejo step is one shell", tree(map[string]string{"reqs.txt": "x==1\n", ".forgejo/workflows/ci.yaml": unit}), false, "inst install -r reqs.txt"},
		{"Gitea install off the lock", tree(map[string]string{".gitea/workflows/ci.yml": actions(".", "inst add x")}), true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTree(t, tt.files)
			var recorded []string
			spec := testSpec
			spec.Allowed = func(words []string, b Binder) bool {
				ok := testSpec.Allowed(words, b)
				if ok {
					recorded = append(recorded, strings.Join(words, " "))
				}
				return ok
			}
			v := New(root, testRead(root), spec)
			none := func(string, []byte) (string, bool) { return "", false }
			got := false
			for _, c := range buildtree.Candidates(root, v.Classify(none), v.FullyRead) {
				if !c.FullyRead {
					got = true
				}
			}
			got = got || v.Withheld()
			if got != tt.want {
				t.Fatalf("withheld = %v, want %v (recorded %q)", got, tt.want, recorded)
			}
			if at := v.Unrecognised(); at != "" {
				t.Fatalf("Unrecognised() = %q: a surface reached the backstop", at)
			}
			if tt.record != "" && !slices.Contains(recorded, tt.record) {
				t.Fatalf("recorded %q, want %q among them", recorded, tt.record)
			}
		})
	}
}
