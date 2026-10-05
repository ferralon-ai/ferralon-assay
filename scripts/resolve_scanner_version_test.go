// Hermetic self-test for resolve-scanner-version.sh, the Action's scanner-version resolver. It builds
// a fake scanner repository on the local filesystem (a bare git repository carrying release tags
// and a minor alias), points the script at it through a file:// base URL, and checks each outcome.
// No network.
package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/gittest"
)

const resolverRepo = "acme/scanner"

// resolverTag is one tag in the fake repository: name, the commit (by index) it points at, and
// whether it is annotated. Release tags are annotated on the real repository; the alias is not.
type resolverTag struct {
	name      string
	commit    int
	annotated bool
}

func resolverGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := gittest.Command(args...)
	cmd.Dir = dir
	cmd.Env = append(cmd.Env, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// writeResolverRepo creates `commits` commits, applies tags, and returns the SCANNER_GITHUB base.
func writeResolverRepo(t *testing.T, root string, commits int, tags []resolverTag) string {
	t.Helper()
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	resolverGit(t, src, "init", "-q")
	var shas []string
	for i := 0; i < commits; i++ {
		resolverGit(t, src, "-c", "user.name=t", "-c", "user.email=t@example.com",
			"commit", "-q", "--allow-empty", "-m", "c")
		shas = append(shas, resolverGit(t, src, "rev-parse", "HEAD"))
	}
	for _, tg := range tags {
		args := []string{"-c", "user.name=t", "-c", "user.email=t@example.com", "tag"}
		if tg.annotated {
			args = append(args, "-a", "-m", tg.name)
		}
		resolverGit(t, src, append(args, tg.name, shas[tg.commit])...)
	}
	gh := filepath.Join(root, "gh")
	if err := os.MkdirAll(filepath.Join(gh, "acme"), 0o755); err != nil {
		t.Fatal(err)
	}
	resolverGit(t, root, "clone", "-q", "--bare", src, filepath.Join(gh, "acme", "scanner.git"))
	return "file://" + gh
}

// releasedMinor is the real repository's shape: three annotated patch releases, each on its own
// minted leaf, a lightweight minor alias on the newest leaf, and a neighbouring minor whose name
// shares the alias's prefix.
func releasedMinor() []resolverTag {
	return []resolverTag{
		{"v0.3.0", 0, true},
		{"v0.3.1", 1, true},
		{"v0.3.2", 2, true},
		{"v0.3", 2, false},
		{"v0.30.0", 2, true},
		{"v0.30", 2, false},
	}
}

func TestResolveScannerVersion(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	script, err := filepath.Abs("resolve-scanner-version.sh")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		version string
		sha256  string
		repo    string        // default resolverRepo
		commits int           // default 3
		tags    []resolverTag // default releasedMinor()
		offline bool          // point the script at a base URL that does not exist
		want    string        // "" = the script must fail
		wantErr string
	}{
		{name: "lightweight alias resolves to the patch on its commit", version: "v0.3", want: "v0.3.2"},
		{name: "annotated alias resolves through its peeled commit", version: "v0.3",
			tags: []resolverTag{{"v0.3.0", 0, true}, {"v0.3.1", 1, true}, {"v0.3", 1, true}}, want: "v0.3.1"},
		{name: "a newer patch tag the alias has not reached is not picked", version: "v0.3", commits: 4,
			tags: append(releasedMinor(), resolverTag{"v0.3.3", 3, true}), want: "v0.3.2"},
		{name: "exact version passes through without the network", version: "v0.3.1", offline: true, want: "v0.3.1"},
		{name: "exact version keeps its checksum pin", version: "v0.3.1", sha256: strings.Repeat("a", 64),
			offline: true, want: "v0.3.1"},
		{name: "alias with no tag", version: "v0.9", wantErr: "has no tag v0.9"},
		{name: "alias on a commit no release names", version: "v0.3", commits: 4,
			tags: append(releasedMinor()[:3], resolverTag{"v0.3", 3, false}), wantErr: "names no release"},
		{name: "alias matching two releases", version: "v0.3",
			tags: append(releasedMinor(), resolverTag{"v0.3.9", 2, true}), wantErr: "more than one release"},
		{name: "unreachable repository", version: "v0.3", offline: true, wantErr: "could not list tags"},
		{name: "checksum with an alias is rejected before any lookup", version: "v0.3",
			sha256: strings.Repeat("a", 64), offline: true, wantErr: "scanner-sha256 is set"},
		{name: "placeholder checksum with an alias is not a pin", version: "v0.3",
			sha256: "REPLACE_WITH_RELEASE_SHA256", want: "v0.3.2"},
		{name: "empty version", version: "", offline: true, wantErr: "scanner-version is unset"},
		{name: "placeholder version", version: "REPLACE_WITH_RELEASE_TAG", offline: true, wantErr: "scanner-version is unset"},
		{name: "version without the v", version: "0.3", offline: true, wantErr: "neither a release tag"},
		{name: "four-field version", version: "v0.3.2.1", offline: true, wantErr: "neither a release tag"},
		{name: "wildcard version", version: "v0.3.*", offline: true, wantErr: "neither a release tag"},
		{name: "ref-like version", version: "v0.3/../../x", offline: true, wantErr: "neither a release tag"},
		{name: "repo with a traversal", version: "v0.3", repo: "acme/..", offline: true, wantErr: "is not an owner/repo"},
		{name: "repo with three segments", version: "v0.3", repo: "a/b/c", offline: true, wantErr: "is not an owner/repo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			base := "file://" + filepath.Join(root, "absent")
			if !tc.offline {
				commits, tags := tc.commits, tc.tags
				if commits == 0 {
					commits = 3
				}
				if tags == nil {
					tags = releasedMinor()
				}
				base = writeResolverRepo(t, root, commits, tags)
			}
			repo := tc.repo
			if repo == "" {
				repo = resolverRepo
			}

			cmd := exec.Command("bash", script)
			cmd.Env = append(os.Environ(),
				"SCANNER_REPO="+repo, "SCANNER_VERSION="+tc.version, "SCANNER_SHA256="+tc.sha256,
				"SCANNER_GITHUB="+base, "GH_TOKEN=must-not-be-used",
				"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
			var stdout, stderr strings.Builder
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()

			if tc.want == "" {
				if err == nil {
					t.Fatalf("script succeeded with %q, want failure containing %q\n%s", stdout.String(), tc.wantErr, stderr.String())
				}
				if !strings.Contains(stderr.String(), tc.wantErr) {
					t.Fatalf("stderr lacks %q:\n%s", tc.wantErr, stderr.String())
				}
				if stdout.Len() != 0 {
					t.Fatalf("a failed resolution printed %q to stdout, which the Action would read as a version", stdout.String())
				}
				return
			}
			if err != nil {
				t.Fatalf("script failed: %v\n%s", err, stderr.String())
			}
			if got := stdout.String(); got != tc.want+"\n" {
				t.Fatalf("stdout = %q, want %q\n%s", got, tc.want+"\n", stderr.String())
			}
		})
	}
}
