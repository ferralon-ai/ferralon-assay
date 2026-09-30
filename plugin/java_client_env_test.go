package plugin

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeEnvEchoPlugin writes a stand-in plugin binary that answers every request with a hard error
// naming the two analyzer env vars it saw, so a test can read the child's environment back out of
// the client's returned error.
func fakeEnvEchoPlugin(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell script as the stand-in plugin binary")
	}
	bin := filepath.Join(t.TempDir(), "fake-plugin")
	script := "#!/bin/sh\ncat >/dev/null\n" +
		`printf '{"protocol":"%s","error":"image=%s docker=%s"}\n' "` + ProtocolVersion + `" ` +
		`"$` + javaAnalyzerImageEnv + `" "$` + javaAnalyzerDockerEnv + `"` + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// TestJavaAnalyzerOptions_ReachChildEnv asserts the analyzer options travel to the subprocess on
// its environment, win over an inherited value, and add nothing when empty.
func TestJavaAnalyzerOptions_ReachChildEnv(t *testing.T) {
	bin := fakeEnvEchoPlugin(t)
	t.Setenv(javaAnalyzerImageEnv, "inherited-image")
	t.Setenv(javaAnalyzerDockerEnv, "")

	cases := []struct {
		name string
		opts []JavaOption
		want string
	}{
		{"no options inherit the parent env", nil, "image=inherited-image docker="},
		{"options override", []JavaOption{
			WithJavaAnalyzerImage("example.invalid/scip-java@sha256:abc"),
			WithJavaAnalyzerDocker("/opt/bin/docker"),
		}, "image=example.invalid/scip-java@sha256:abc docker=/opt/bin/docker"},
		{"empty options add nothing", []JavaOption{
			WithJavaAnalyzerImage(""),
			WithJavaAnalyzerDocker(""),
		}, "image=inherited-image docker="},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := NewJavaPlugin(append([]JavaOption{WithJavaBinaryPath(bin)}, c.opts...)...)
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.CallGraph(context.Background(), CallGraphRequest{BuildDir: t.TempDir()})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to carry %q", err, c.want)
			}
		})
	}
}
