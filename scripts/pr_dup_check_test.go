// Offline test for pr-dup-check.sh. The PR and branch listings are fixture files named by env
// vars, or the live lookups run against a fake gh and a directory with no git remote, so no
// network is involved.
package scripts

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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

// dupLiveTools are the tools the script runs, linked into a PATH of their own so the runner's gh,
// if any, is out of reach.
var dupLiveTools = []string{"awk", "cat", "cp", "git", "mktemp", "rm", "sed"}

// TestPRDupCheckLiveLookups runs the script with neither listing file set, a PATH holding only
// dupLiveTools plus an optional fake gh, from a directory with no git repository and so no remote.
func TestPRDupCheckLiveLookups(t *testing.T) {
	var full strings.Builder
	for i := 1; i <= 200; i++ {
		full.WriteString(dupPR(strconv.Itoa(i), "unrelated", "chore/y", "no order here"))
	}
	cases := []struct {
		name     string
		gh       string // fake gh's script body; empty means no gh on PATH
		branches string // a branch listing file; empty means the live git ls-remote
		want     int
		stderr   []string
	}{
		{"no gh, no remote", "", "", 2,
			[]string{"gh not installed", "git ls-remote --heads origin failed", "  fatal:"}},
		{"gh fails, branches read", "echo 'HTTP 403: API rate limit exceeded' >&2; exit 1", "origin/main\n", 0,
			[]string{"gh pr list failed", "  HTTP 403: API rate limit exceeded"}},
		{"gh fails, no remote", "echo 'HTTP 403: API rate limit exceeded' >&2; exit 1", "", 2,
			[]string{"gh pr list failed", "git ls-remote --heads origin failed"}},
		{"gh at its listing limit", "cat \"$PR_DUP_TEST_PRS\"", "origin/main\n", 0,
			[]string{"gh returned 200 open PRs, its listing limit"}},
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
			for _, kv := range os.Environ() {
				if !strings.HasPrefix(kv, "PR_DUP_") && !strings.HasPrefix(kv, "GIT_") && !strings.HasPrefix(kv, "PATH=") {
					env = append(env, kv)
				}
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
			if stdout.Len() != 0 {
				t.Fatalf("stdout names a match where none exists:\n%s", stdout.String())
			}
			for _, w := range tc.stderr {
				if !strings.Contains(stderr.String(), w) {
					t.Fatalf("stderr does not say %q:\n%s", w, stderr.String())
				}
			}
		})
	}
}
