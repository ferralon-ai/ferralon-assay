// Offline test for pr-dup-check.sh. The PR and branch listings are fixture files named by env
// vars, or the live lookups run against a fake gh and either a directory with no git remote or a
// local bare origin, so no network is involved.
package scripts

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/gittest"
)

const (
	dupRS = "\x1e"
	dupUS = "\x1f"
)

// dupPR renders one fixture PR record: number, title, head branch, body.
func dupPR(num, title, head, body string) string {
	return strings.Join([]string{num, title, head, body}, dupUS) + dupRS
}

type dupCase struct {
	name     string
	id       string
	prs      string
	branches string
	want     int
	contains string // in stdout when want == 1
}

var (
	dupPRs = dupPR("11", "docs: tidy readme", "docs/readme", "no order here") +
		dupPR("12", "scanner: ASY-099 duplicate check", "feature/x", "body\nsecond line") +
		dupPR("13", "unrelated", "chore/y", "Fixes order asy-077.\nSee also (ASY-123).")
	dupBranches = "origin/main\nrefs/heads/asy-050-other\nabc123\trefs/heads/asy-0990-longer\n"
)

// runDupCases drives the script over a table, with env appended after the defaults (a later value
// wins). Each top-level test below holds only a few rows so every test stays well under the
// per-test time limit (each row spawns bash and awk).
func runDupCases(t *testing.T, cases []dupCase, env ...string) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name, content string) string {
				p := filepath.Join(dir, name)
				if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
				return p
			}
			cmd := exec.Command("bash", "pr-dup-check.sh", tc.id)
			cmd.Env = append(os.Environ(),
				"PR_DUP_PRS_FILE="+write("prs", tc.prs),
				"PR_DUP_BRANCHES_FILE="+write("branches", tc.branches),
				"PR_DUP_SELF_BRANCH=",
			)
			cmd.Env = append(cmd.Env, env...)
			out, err := cmd.Output()
			code := 0
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tc.want {
				t.Fatalf("exit = %d, want %d; stdout:\n%s", code, tc.want, out)
			}
			if tc.want == 1 && !strings.Contains(string(out), tc.contains) {
				t.Fatalf("stdout does not name %q:\n%s", tc.contains, out)
			}
		})
	}
}

func TestPRDupCheckMatchByBranch(t *testing.T) {
	runDupCases(t, []dupCase{
		{"remote branch", "ASY-050", "", dupBranches, 1, "asy-050-other"},
		{"case-insensitive", "asy-050", "", dupBranches, 1, "asy-050-other"},
	})
}

func TestPRDupCheckMatchByPR(t *testing.T) {
	runDupCases(t, []dupCase{
		{"title", "ASY-099", dupPRs, "", 1, "PR #12"},
		{"body", "ASY-077", dupPRs, "", 1, "PR #13"},
		{"head branch", "docs/readme", dupPRs, "", 1, "PR #11"},
	})
}

func TestPRDupCheckNoMatch(t *testing.T) {
	runDupCases(t, []dupCase{
		{"absent id", "ASY-555", dupPRs, dupBranches, 0, ""},
		{"empty listings", "ASY-099", "", "", 0, ""},
	})
}

func TestPRDupCheckPrefixDoesNotMatch(t *testing.T) {
	runDupCases(t, []dupCase{
		{"prefix of id in title", "ASY-09", dupPRs, "", 0, ""},
		{"prefix of id in branch", "ASY-099", "", dupBranches, 0, ""},
		{"suffix of longer token", "SY-099", dupPRs, "", 0, ""},
	})
}

func TestPRDupCheckUsage(t *testing.T) {
	err := exec.Command("bash", "pr-dup-check.sh").Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 2 {
		t.Fatalf("no-arg run = %v, want exit 2", err)
	}
}

// dupSelfBranches lists one branch in both accepted shapes, so the self-branch exclusion has to see
// through either prefix.
const dupSelfBranches = "origin/main\norigin/asy-050-other\nabc123\trefs/heads/asy-050-other\n"

func TestPRDupCheckSelfBranch(t *testing.T) {
	runDupCases(t, []dupCase{
		{"own branch left out", "ASY-050", "", dupSelfBranches, 0, ""},
	}, "PR_DUP_SELF_BRANCH=asy-050-other")
	runDupCases(t, []dupCase{
		{"other branch still found", "ASY-050", "", dupSelfBranches, 1, "asy-050-other"},
	}, "PR_DUP_SELF_BRANCH=other")
}

// An unexpected failure (here mktemp, with TMPDIR unusable) exits 2, never 1: the branch listing
// matches, so a set -e failure that kept its own status would read as "found".
func TestPRDupCheckUnexpectedFailure(t *testing.T) {
	runDupCases(t, []dupCase{
		{"mktemp fails", "ASY-050", "", dupBranches, 2, ""},
	}, "TMPDIR="+filepath.Join(t.TempDir(), "missing"))
}

// dupLiveTools are the tools the script runs, linked into a PATH of their own so the runner's gh,
// if any, is out of reach.
var dupLiveTools = []string{"awk", "cat", "cp", "git", "mktemp", "rm", "sed"}

type dupLiveCase struct {
	name     string
	gh       string   // fake gh's script body; empty means no gh on PATH
	branches string   // a branch listing file; empty means the live git ls-remote
	origin   []string // when set, run from a repository on asy-099-mine whose bare origin holds these
	want     int
	stdout   string // in stdout; empty means stdout must be empty
	stderr   []string
}

const (
	dupGhRateLimited = "echo 'HTTP 403: API rate limit exceeded' >&2; exit 1"
	dupGhMatch       = `printf '12\037scanner: ASY-099 duplicate check\037feature/x\037body\036'`
)

// With no branch listing there is nothing to stand on, whatever gh does.
func TestPRDupCheckLiveNoRemote(t *testing.T) {
	runDupLive(t, []dupLiveCase{
		{"no gh, no remote", "", "", nil, 2, "",
			[]string{"gh not installed", "git ls-remote --heads origin failed", "  fatal:"}},
		{"gh fails, no remote", dupGhRateLimited, "", nil, 2, "",
			[]string{"gh pr list failed", "git ls-remote --heads origin failed"}},
		{"PR match still named", dupGhMatch, "", nil, 2, "open PR #12",
			[]string{"git ls-remote --heads origin failed"}},
	})
}

// A PR listing that fails or is cut short leaves the branches checked, and stderr says why.
func TestPRDupCheckLiveGhFallback(t *testing.T) {
	runDupLive(t, []dupLiveCase{
		{"gh fails, branches read", dupGhRateLimited, "origin/main\n", nil, 0, "",
			[]string{"gh pr list failed", "  HTTP 403: API rate limit exceeded"}},
		{"gh at its listing limit", "cat \"$PR_DUP_TEST_PRS\"", "origin/main\n", nil, 0, "",
			[]string{"gh returned 200 open PRs, its listing limit"}},
	})
}

// The path every real run takes: no self-branch override, so the checked-out asy-099-mine is left
// out while asy-099-old is found, through a live git ls-remote against a reachable origin.
func TestPRDupCheckLiveOrigin(t *testing.T) {
	runDupLive(t, []dupLiveCase{
		{"own branch left out by default", "", "", []string{"asy-099-mine", "asy-099-old"}, 1,
			"remote branch already carries ASY-099: asy-099-old", []string{"gh not installed"}},
	})
}

// runDupLive runs the script with no PR listing file and no self-branch override, a PATH holding
// only dupLiveTools plus an optional fake gh, from a directory with no git repository and so no
// remote, or from a repository with a local bare origin. The fake gh can print PR_DUP_TEST_PRS, a
// full page of 200 unrelated PRs.
func runDupLive(t *testing.T, cases []dupLiveCase) {
	t.Helper()
	var full strings.Builder
	for i := 1; i <= 200; i++ {
		full.WriteString(dupPR(strconv.Itoa(i), "unrelated", "chore/y", "no order here"))
	}
	script, err := filepath.Abs("pr-dup-check.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin, dir := t.TempDir(), t.TempDir()
			for _, tool := range dupLiveTools {
				p, err := exec.LookPath(tool)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
					t.Fatal(err)
				}
			}
			if tc.gh != "" {
				if err := os.WriteFile(filepath.Join(bin, "gh"), []byte("#!/bin/sh\n"+tc.gh+"\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			prsFile := filepath.Join(dir, "prs")
			if err := os.WriteFile(prsFile, []byte(full.String()), 0o644); err != nil {
				t.Fatal(err)
			}
			env := []string{"PATH=" + bin, "PR_DUP_TEST_PRS=" + prsFile, "GIT_CEILING_DIRECTORIES=" + filepath.Dir(dir)}
			for _, kv := range gittest.Scrub(os.Environ()) {
				if !strings.HasPrefix(kv, "PR_DUP_") && !strings.HasPrefix(kv, "PATH=") {
					env = append(env, kv)
				}
			}
			if tc.origin != nil {
				dupOrigin(t, dir, tc.origin)
			}
			if tc.branches != "" {
				p := filepath.Join(dir, "branches")
				if err := os.WriteFile(p, []byte(tc.branches), 0o644); err != nil {
					t.Fatal(err)
				}
				env = append(env, "PR_DUP_BRANCHES_FILE="+p)
			}
			cmd := exec.Command("bash", script, "ASY-099")
			cmd.Dir = dir
			cmd.Env = env
			var stdout, stderr strings.Builder
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			code := 0
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tc.want {
				t.Fatalf("exit = %d, want %d; stdout:\n%s\nstderr:\n%s", code, tc.want, stdout.String(), stderr.String())
			}
			if tc.stdout == "" && stdout.Len() != 0 {
				t.Fatalf("stdout names a match where none exists:\n%s", stdout.String())
			}
			if !strings.Contains(stdout.String(), tc.stdout) {
				t.Fatalf("stdout does not name %q:\n%s", tc.stdout, stdout.String())
			}
			if tc.origin != nil && strings.Contains(stdout.String(), "asy-099-mine") {
				t.Fatalf("stdout names the checked-out branch:\n%s", stdout.String())
			}
			for _, w := range tc.stderr {
				if !strings.Contains(stderr.String(), w) {
					t.Fatalf("stderr does not say %q:\n%s", w, stderr.String())
				}
			}
		})
	}
}

// dupOrigin makes dir a repository checked out on asy-099-mine, with one commit, and gives it a
// bare origin holding the named branches. The origin borrows dir's objects through an alternates
// file and gets its refs written directly, which costs far less than a push.
func dupOrigin(t *testing.T, dir string, branches []string) {
	t.Helper()
	origin := filepath.Join(t.TempDir(), "origin.git")
	git := func(args ...string) string {
		cmd := gittest.Command(append([]string{"-c", "maintenance.auto=false"}, args...)...)
		cmd.Env = append(cmd.Env, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q", "--bare", origin)
	git("init", "-q", "-b", "asy-099-mine", dir)
	git("-C", dir, "commit", "-q", "--allow-empty", "-m", "fixture")
	git("-C", dir, "config", "remote.origin.url", origin)
	head := git("-C", dir, "rev-parse", "HEAD")
	files := map[string]string{"objects/info/alternates": filepath.Join(dir, ".git", "objects")}
	for _, b := range branches {
		files["refs/heads/"+b] = head
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(origin, name), []byte(content+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
