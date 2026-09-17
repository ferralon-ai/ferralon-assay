package checkout

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

// allLanguageMarkers is the marker enumeration every "not a recognized source tree" error must
// carry: one entry per language DetectLanguage actually classifies (Go / Java / Kotlin / JS /
// Python / .NET). A copy that lists fewer sends a user of the missing language hunting for a
// go.mod they never needed.
var allLanguageMarkers = []string{"go.mod", ".java", ".kt/.kts", ".js/.ts", ".py", ".cs/.csproj"}

func assertAllMarkers(t *testing.T, msg string) {
	t.Helper()
	for _, m := range allLanguageMarkers {
		if !strings.Contains(msg, m) {
			t.Errorf("error copy is missing the %q marker:\n%s", m, msg)
		}
	}
	if !strings.Contains(msg, "not a recognized source tree") {
		t.Errorf("error copy lost its stable prefix:\n%s", msg)
	}
}

// The vendored path is the one the GitHub-Action flow hits, so it is the one that also names the
// repo config file a user can set to scan the branch their source actually lives on.
func TestResolveVendored_UnrecognizedCopy(t *testing.T) {
	_, err := ResolveVendored(t.TempDir())
	if err == nil {
		t.Fatal("an empty tree must not resolve")
	}
	assertAllMarkers(t, err.Error())
	if !strings.Contains(err.Error(), "analyze.ref in .github/ferralon.yml") {
		t.Errorf("vendored error must point at analyze.ref in .github/ferralon.yml:\n%s", err)
	}
}

func TestFakeCheckout_UnrecognizedCopy(t *testing.T) {
	root := t.TempDir()
	_, err := FakeCheckout{FixtureRoot: root, Map: map[string]string{"r@v": "."}}.Fetch(context.Background(), "r", "v")
	if err == nil {
		t.Fatal("an empty fixture must not resolve")
	}
	assertAllMarkers(t, err.Error())
}

func TestGitCheckout_UnrecognizedCopy(t *testing.T) {
	if !GitAvailable() {
		t.Skip("git CLI not available")
	}
	src := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "--allow-empty", "-q", "-m", "seed"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = src
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	_, err := NewGitCheckout().Fetch(context.Background(), "file://"+src, "")
	if err == nil {
		t.Fatal("a clone with no sources must not resolve")
	}
	assertAllMarkers(t, err.Error())
}
