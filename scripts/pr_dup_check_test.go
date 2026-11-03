// Offline test for pr-dup-check.sh. The PR and branch listings are fixture files named by env
// vars, so no network, gh or git remote is involved.
package scripts

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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

// runDupCases drives the script over a table. Each top-level test below holds only a few rows so
// every test stays well under the per-test time limit (each row spawns bash and awk).
func runDupCases(t *testing.T, cases []dupCase) {
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
