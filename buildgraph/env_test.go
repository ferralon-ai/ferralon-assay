package buildgraph

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestStripCredentials(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"every credential goes", []string{"GITHUB_TOKEN=a", "GH_TOKEN=b", "ACTIONS_ID_TOKEN_REQUEST_TOKEN=c", "ACTIONS_ID_TOKEN_REQUEST_URL=d", "ACTIONS_RUNTIME_TOKEN=e", "ACTIONS_CACHE_URL=f"}, []string{}},
		{"every runner file goes", []string{"GITHUB_ENV=/r/env", "GITHUB_PATH=/r/path", "GITHUB_OUTPUT=/r/out", "GITHUB_STATE=/r/state", "GITHUB_STEP_SUMMARY=/r/sum"}, []string{}},
		{"names match in any case", []string{"Github_Token=a", "gh_token=b", "github_env=c", "Github_Path=d"}, []string{}},
		{"the rest stays in order", []string{"PATH=/bin", "GITHUB_TOKEN=a", "NPM_TOKEN=n", "MAVEN_OPTS=-Xmx1g"}, []string{"PATH=/bin", "NPM_TOKEN=n", "MAVEN_OPTS=-Xmx1g"}},
		{"a longer name is kept", []string{"GITHUB_TOKEN_FILE=x", "MY_GH_TOKEN=y"}, []string{"GITHUB_TOKEN_FILE=x", "MY_GH_TOKEN=y"}},
		{"empty value still removed", []string{"GH_TOKEN="}, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := append([]string(nil), tt.in...)
			if got := StripCredentials(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			if !reflect.DeepEqual(in, tt.in) {
				t.Fatalf("input modified: %q", tt.in)
			}
		})
	}
}

// TestCredentialEnvIsACopy guards the exported list: a caller that edits its copy must not shrink
// what StripCredentials removes.
func TestCredentialEnvIsACopy(t *testing.T) {
	names := CredentialEnv()
	for i := range names {
		names[i] = "x"
	}
	if got := StripCredentials([]string{"GITHUB_TOKEN=a"}); len(got) != 0 {
		t.Fatalf("editing CredentialEnv's result changed the strip: %q", got)
	}
}

// dumpEnvTool writes a script that dumps its environment to out and exits 0.
func dumpEnvTool(t *testing.T, path, out string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n/usr/bin/env > "+out+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func credentialEnvSet() []string {
	env := []string{"PATH=/usr/bin:/bin", "KEEP_ME=1"}
	for _, k := range CredentialEnv() {
		env = append(env, k+"=secret")
	}
	return env
}

func requireStripped(t *testing.T, dump string) {
	t.Helper()
	b, err := os.ReadFile(dump)
	if err != nil {
		t.Fatalf("tool did not run: %v", err)
	}
	for _, k := range CredentialEnv() {
		if strings.Contains(string(b), k+"=") {
			t.Errorf("%s reached the tool", k)
		}
	}
	if !strings.Contains(string(b), "KEEP_ME=1") {
		t.Errorf("other variables were dropped: %q", b)
	}
}

func TestRunnerStripsCredentials(t *testing.T) {
	root := t.TempDir()
	dump := filepath.Join(root, "env.txt")
	tool := filepath.Join(root, "tool")
	dumpEnvTool(t, tool, dump)
	r := &runner{dir: root, tool: tool, shown: "tool", env: credentialEnvSet(), work: filepath.Join(root, "work")}
	if _, err := r.run(context.Background(), "step"); err != nil {
		t.Fatal(err)
	}
	requireStripped(t, dump)
}

func TestCompileStripsCredentials(t *testing.T) {
	root := t.TempDir()
	dump := filepath.Join(root, "env.txt")
	dumpEnvTool(t, filepath.Join(root, "repo", "mvnw"), dump)
	if _, f := Compile(context.Background(), CompileRequest{Dir: filepath.Join(root, "repo"), Tool: ToolMaven, Env: credentialEnvSet()}); f != nil {
		t.Fatal(f)
	}
	requireStripped(t, dump)
}
