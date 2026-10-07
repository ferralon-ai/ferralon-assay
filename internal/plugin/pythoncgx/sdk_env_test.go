package pythoncgx

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeCgxEnvFile is where the fake `cgx session` (this test binary, run with the session
// arguments) writes its environment: beside the repository it is given, because no variable of
// the test's reaches it to say where.
const fakeCgxEnvFile = "fake-cgx-env.json"

func TestMain(m *testing.M) {
	if len(os.Args) == 4 && os.Args[1] == "session" && os.Args[2] == "--repo" {
		data, _ := json.Marshal(os.Environ())
		_ = os.WriteFile(filepath.Join(filepath.Dir(os.Args[3]), fakeCgxEnvFile), data, 0o644)
		os.Exit(3)
	}
	os.Exit(m.Run())
}

// The native cgx process parses the scanned code, so the runner's credentials must not reach
// it: it gets the SDK's minimal environment and nothing the lane adds.
func TestOpenSDK_NativeEngineGetsNoCredentials(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(t.TempDir(), "repo")
	for _, args := range [][]string{
		{"init", "-q", repo},
		{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "--allow-empty", "-m", "c"},
	} {
		if out, err := exec.Command(git, args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	secrets := []string{"IN_STATE_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "GITHUB_TOKEN"}
	for _, k := range secrets {
		t.Setenv(k, "sentinel-"+k)
	}
	cfg := Config{Transport: TransportNative, CgxBin: bin, CgxBinSHA256: sum(t, bin), CacheDir: t.TempDir()}
	if g, err := OpenSDK(context.Background(), repo, cfg); err == nil {
		g.Close()
		t.Fatal("OpenSDK on the fake engine succeeded; want its handshake to fail")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(repo), fakeCgxEnvFile))
	if err != nil {
		t.Fatalf("the fake engine did not run: %v", err)
	}
	var env []string
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if slices.Contains(secrets, k) || strings.HasPrefix(v, "sentinel-") {
			t.Errorf("%s reached the native engine", k)
		}
	}
	if !slices.Contains(env, "GIT_NO_LAZY_FETCH=1") {
		// Names only: values may be credentials.
		names := make([]string, len(env))
		for i, kv := range env {
			names[i], _, _ = strings.Cut(kv, "=")
		}
		t.Errorf("engine environment %q lacks the SDK's minimal set", names)
	}
}
