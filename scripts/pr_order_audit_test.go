// Offline tests for pr-order-audit.sh (open-PR duplicate report) and githooks/pre-push (refuse a
// second remote branch for an order id), plus install-githooks.sh. The hook runs against throwaway
// git repositories with a local bare "origin". No network.
package scripts

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/gittest"
)

// runScript runs a script and returns its stdout+stderr and exit code.
func runScript(t *testing.T, dir string, env []string, stdin string, name string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(gittest.Env(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	cmd.Env = append(cmd.Env, env...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return out.String(), 0
	case errors.As(err, &ee):
		return out.String(), ee.ExitCode()
	}
	t.Fatalf("%s: %v", name, err)
	return "", -1
}

type auditCase struct {
	name     string
	listing  string // "MISSING" = a path that does not exist
	wantCode int
	want     []string // substrings of the output
	notWant  []string
}

func auditPR(n, head, title string) string {
	return `{"number":` + n + `,"headRefName":"` + head + `","title":"` + title + `"}`
}

func auditList(prs ...string) string { return "[" + strings.Join(prs, ",") + "]" }

func runAuditCases(t *testing.T, cases []auditCase) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not on PATH")
	}
	script, err := filepath.Abs("pr-order-audit.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "prs"+string(rune('a'+i))+".json")
			if tc.listing != "MISSING" {
				if err := os.WriteFile(path, []byte(tc.listing), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			out, code := runScript(t, ".", []string{"PR_ORDER_AUDIT_JSON=" + path}, "", script)
			if code != tc.wantCode {
				t.Fatalf("exit %d, want %d:\n%s", code, tc.wantCode, out)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(out, w) {
					t.Errorf("output has %q:\n%s", w, out)
				}
			}
		})
	}
}

func TestPROrderAuditDuplicates(t *testing.T) {
	runAuditCases(t, []auditCase{
		{name: "by branch", wantCode: 1, want: []string{"ASY-104", "#1", "#2"},
			listing: auditList(auditPR("1", "asy-104-a", "one"), auditPR("2", "asy-104-b", "two"))},
		{name: "by title", wantCode: 1, want: []string{"ASY-7"},
			listing: auditList(auditPR("1", "fix/x", "ASY-7: first"), auditPR("2", "other", "Again for ASY-7"))},
		{name: "branch of one and title of another", wantCode: 1, want: []string{"ASY-5"},
			listing: auditList(auditPR("1", "asy-5-x", "t"), auditPR("2", "y", "[ASY-5] t"))},
		{name: "eric-req slug", wantCode: 1, want: []string{"eric-req-fix-184-docs"},
			listing: auditList(auditPR("1", "eric-req-fix-184-docs", "a"), auditPR("2", "z", "eric-req-fix-184-docs docs"))},
	})
}

func TestPROrderAuditNoDuplicates(t *testing.T) {
	runAuditCases(t, []auditCase{
		{name: "distinct ids", wantCode: 0, notWant: []string{"ASY"},
			listing: auditList(auditPR("1", "asy-1-a", "t"), auditPR("2", "asy-2-a", "t"))},
		{name: "empty listing", listing: "[]", wantCode: 0},
		{name: "same id twice in one PR is one PR", wantCode: 0,
			listing: auditList(auditPR("1", "asy-104-asy-104", "ASY-104 ASY-104"))},
		{name: "prefix id does not match", wantCode: 0,
			listing: auditList(auditPR("1", "asy-09-a", "t"), auditPR("2", "asy-099-a", "t"))},
		{name: "embedded id does not match", wantCode: 0,
			listing: auditList(auditPR("1", "xasy-9", "t"), auditPR("2", "asy-9", "t"))},
		{name: "eric-req prefix slug does not match", wantCode: 0,
			listing: auditList(auditPR("1", "eric-req-fix-184", "t"), auditPR("2", "eric-req-fix-184-docs", "t"))},
	})
}

func TestPROrderAuditUnreadable(t *testing.T) {
	runAuditCases(t, []auditCase{
		{name: "missing file", listing: "MISSING", wantCode: 2},
		{name: "not json", listing: "<html>", wantCode: 2},
		{name: "json but not a list", listing: `{"message":"bad credentials"}`, wantCode: 2},
	})
}

func TestPROrderAuditFailingGh(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not on PATH")
	}
	script, err := filepath.Abs("pr-order-audit.sh")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, code := runScript(t, ".", []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "PR_ORDER_AUDIT_JSON="}, "", script)
	if code != 2 {
		t.Fatalf("exit %d, want 2 (a failed read is never safe):\n%s", code, out)
	}
}

const zeroSHA = "0000000000000000000000000000000000000000"

// bareOrigin is a bare repository whose heads are the named branches. The refs are written
// straight into the directory (git ls-remote lists them without their objects), so building one
// costs a single `git init`.
func bareOrigin(t *testing.T, branches ...string) string {
	t.Helper()
	origin := filepath.Join(t.TempDir(), "origin.git")
	cmd := gittest.Command("init", "-q", "--bare", origin)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	for _, b := range branches {
		ref := filepath.Join(origin, "refs", "heads", filepath.FromSlash(b))
		if err := os.MkdirAll(filepath.Dir(ref), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ref, []byte(fakeSHA+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return origin
}

const fakeSHA = "1111111111111111111111111111111111111111"

type hookCase struct {
	name      string
	remote    []string // branches already on origin
	line      string   // the push line on stdin
	env       []string
	badRemote bool
	wantCode  int
	want      string
}

func runHookCases(t *testing.T, cases []hookCase) {
	t.Helper()
	hook, err := filepath.Abs("githooks/pre-push")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			origin := bareOrigin(t, tc.remote...)
			if tc.badRemote {
				origin = filepath.Join(filepath.Dir(origin), "absent.git")
			}
			out, code := runScript(t, t.TempDir(), tc.env, tc.line+"\n", hook, origin)
			if code != tc.wantCode {
				t.Fatalf("exit %d, want %d:\n%s", code, tc.wantCode, out)
			}
			if tc.want != "" && !strings.Contains(out, tc.want) {
				t.Errorf("output lacks %q:\n%s", tc.want, out)
			}
		})
	}
}

func TestPrePushRefusesSecondBranch(t *testing.T) {
	runHookCases(t, []hookCase{
		{name: "taken id", remote: []string{"asy-104-first"},
			line: newBranch("asy-104-second"), wantCode: 1, want: "asy-104-first"},
		{name: "taken id matches case-insensitively", remote: []string{"ASY-104-first"},
			line: newBranch("asy-104-second"), wantCode: 1, want: "ASY-104-first"},
	})
}

func TestPrePushRefusesSecondEricReqBranch(t *testing.T) {
	runHookCases(t, []hookCase{
		{name: "taken eric-req id", remote: []string{"eric-req-fix-184-docs"},
			line: newBranch("work/eric-req-fix-184-docs"), wantCode: 1, want: "eric-req-fix-184-docs"},
	})
}

func TestPrePushAllows(t *testing.T) {
	runHookCases(t, []hookCase{
		{name: "revision to an existing branch", remote: []string{"asy-104-first"},
			line: "refs/heads/asy-104-first " + fakeSHA + " refs/heads/asy-104-first " + fakeSHA},
		{name: "bypass", remote: []string{"asy-104-first"}, env: []string{"PR_ORDER_ALLOW=1"},
			line: newBranch("asy-104-second")},
	})
}

func TestPrePushAllowsUnrelatedBranches(t *testing.T) {
	runHookCases(t, []hookCase{
		{name: "no id", remote: []string{"asy-104-first"}, line: newBranch("cleanup")},
		{name: "different id", remote: []string{"asy-104-first"}, line: newBranch("asy-105-first")},
	})
}

func TestPrePushIdBoundaries(t *testing.T) {
	runHookCases(t, []hookCase{
		{name: "prefix id", remote: []string{"asy-099-first"}, line: newBranch("asy-09-second")},
	})
}

func TestPrePushLongerIdIsAnotherOrder(t *testing.T) {
	runHookCases(t, []hookCase{
		{name: "longer id", remote: []string{"asy-09-first"}, line: newBranch("asy-099-second")},
		{name: "longer eric-req slug", remote: []string{"eric-req-fix-184-docs"},
			line: newBranch("eric-req-fix-184-docs-take2")},
	})
}

func TestPrePushIgnoresDeletesAndTags(t *testing.T) {
	runHookCases(t, []hookCase{
		{name: "deleting a branch", remote: []string{"asy-104-first", "asy-104-second"},
			line: "(delete) " + zeroSHA + " refs/heads/asy-104-second " + fakeSHA},
		{name: "tag push", remote: []string{"asy-104-first"},
			line: "refs/tags/asy-104-t " + fakeSHA + " refs/tags/asy-104-t " + zeroSHA},
	})
}

func TestPrePushFailsClosed(t *testing.T) {
	runHookCases(t, []hookCase{
		{name: "unlistable remote", badRemote: true, line: newBranch("asy-104-second"), wantCode: 2},
		{name: "unlistable remote without an id", badRemote: true, line: newBranch("cleanup")},
	})
}

// newBranch is a push line creating branch name on the remote.
func newBranch(name string) string {
	return "refs/heads/" + name + " " + fakeSHA + " refs/heads/" + name + " " + zeroSHA
}

func TestInstallGithooksIsIdempotent(t *testing.T) {
	install, err := filepath.Abs("install-githooks.sh")
	if err != nil {
		t.Fatal(err)
	}
	// Stand in for the checkout: the script finds its repository from its own location.
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(install)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "scripts", "install-githooks.sh"), b, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, code := runScript(t, work, nil, "", "git", "init", "-q"); code != 0 {
		t.Fatalf("git init: exit %d:\n%s", code, out)
	}
	for i := 0; i < 2; i++ {
		if out, code := runScript(t, work, nil, "", "bash", "scripts/install-githooks.sh"); code != 0 {
			t.Fatalf("install run %d: exit %d:\n%s", i+1, code, out)
		}
	}
	if out, code := runScript(t, work, nil, "", "git", "config", "--get-all", "core.hooksPath"); code != 0 || out != "scripts/githooks\n" {
		t.Fatalf("core.hooksPath = %q (exit %d), want exactly one scripts/githooks", out, code)
	}
}

// TestPrePushHookFiresOnRealPush is the one end-to-end check: with core.hooksPath on the tracked
// hook directory, a real `git push` of a second branch for a taken id is refused by the hook.
func TestPrePushHookFiresOnRealPush(t *testing.T) {
	hooks, err := filepath.Abs("githooks")
	if err != nil {
		t.Fatal(err)
	}
	origin := bareOrigin(t, "asy-104-first")
	work := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"}, {"commit", "-q", "--allow-empty", "-m", "c"},
		{"config", "core.hooksPath", hooks}, {"remote", "add", "origin", origin},
	} {
		if out, code := runScript(t, work, nil, "", "git", args...); code != 0 {
			t.Fatalf("git %v: exit %d:\n%s", args, code, out)
		}
	}
	out, code := runScript(t, work, nil, "", "git", "push", "-q", "origin", "HEAD:refs/heads/asy-104-second")
	if code == 0 || !strings.Contains(out, "pre-push: refusing") || !strings.Contains(out, "asy-104-first") {
		t.Fatalf("second branch push: exit %d, want a hook refusal naming asy-104-first:\n%s", code, out)
	}
}
