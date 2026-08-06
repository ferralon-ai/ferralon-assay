package selfcleanup

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func testActuatorCfg() ActuatorConfig {
	return ActuatorConfig{
		Repo:          "acme/widget",
		DefaultBranch: "main",
		WorkflowPath:  ".github/workflows/ferralon-assay.yml",
		WorkflowFile:  "ferralon-assay.yml",
		GitDir:        "/ws",
		StateRef:      "refs/tegron/state",
		Token:         "ghs_x",
	}
}

// recordingRunner captures every command and returns a programmed error keyed by a
// substring match on the joined command line.
type recordingRunner struct {
	cmds    []string
	failSub map[string]error
}

func (r *recordingRunner) run(ctx context.Context, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	r.cmds = append(r.cmds, line)
	for sub, err := range r.failSub {
		if strings.Contains(line, sub) {
			return "", err
		}
	}
	// Resolve-id path returns a fake id.
	if strings.Contains(line, "actions/workflows/ferralon-assay.yml ") && strings.Contains(line, ".id") {
		return "310137034\n", nil
	}
	if strings.Contains(line, "rev-parse HEAD") {
		return "deadbeefcafe\n", nil
	}
	return "", nil
}

func withRunner(cfg ActuatorConfig, r *recordingRunner) *gitActuator {
	return &gitActuator{cfg: cfg, run: r.run}
}

func joined(cmds []string) string { return strings.Join(cmds, "\n") }

func TestActuatorDirectPushHappyPath(t *testing.T) {
	r := &recordingRunner{failSub: map[string]error{}}
	a := withRunner(testActuatorCfg(), r)
	if err := a.DeleteWorkflowFileDirect(context.Background()); err != nil {
		t.Fatalf("direct push: %v", err)
	}
	all := joined(r.cmds)
	for _, want := range []string{
		"git -C /ws rm -q -- .github/workflows/ferralon-assay.yml",
		"user.name=github-actions[bot]",
		"commit -m Remove Ferralon Assay workflow",
		"git -C /ws push origin HEAD:main",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing command fragment %q in:\n%s", want, all)
		}
	}
}

func TestActuatorDirectPushRejectionClassified(t *testing.T) {
	r := &recordingRunner{failSub: map[string]error{
		"push origin HEAD:main": errors.New("! [remote rejected] HEAD -> main (protected branch hook declined)"),
	}}
	a := withRunner(testActuatorCfg(), r)
	err := a.DeleteWorkflowFileDirect(context.Background())
	if !errors.Is(err, ErrPushRejected) {
		t.Fatalf("protected-branch push must map to ErrPushRejected, got %v", err)
	}
	// The working tree is restored after the failed push.
	if !strings.Contains(joined(r.cmds), "reset --hard") {
		t.Errorf("expected a reset --hard to restore the tree, got:\n%s", joined(r.cmds))
	}
}

func TestActuatorOpenRemovalPR(t *testing.T) {
	r := &recordingRunner{failSub: map[string]error{}}
	a := withRunner(testActuatorCfg(), r)
	if err := a.OpenRemovalPR(context.Background()); err != nil {
		t.Fatalf("open PR: %v", err)
	}
	all := joined(r.cmds)
	for _, want := range []string{
		"git -C /ws fetch origin main",
		"checkout -B ferralon-assay-removal origin/main",
		"push -u origin ferralon-assay-removal",
		"gh pr create --repo acme/widget --base main --head ferralon-assay-removal --title Ferralon removed — merge to finish cleanup",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing PR-flow fragment %q in:\n%s", want, all)
		}
	}
}

func TestActuatorDisableWorkflowResolvesID(t *testing.T) {
	r := &recordingRunner{failSub: map[string]error{}}
	a := withRunner(testActuatorCfg(), r)
	if err := a.DisableWorkflow(context.Background()); err != nil {
		t.Fatalf("disable: %v", err)
	}
	all := joined(r.cmds)
	if !strings.Contains(all, "gh api repos/acme/widget/actions/workflows/ferralon-assay.yml --jq .id") {
		t.Errorf("expected workflow-id resolve call, got:\n%s", all)
	}
	if !strings.Contains(all, "gh api -X PUT repos/acme/widget/actions/workflows/310137034/disable") {
		t.Errorf("expected disable-by-id call, got:\n%s", all)
	}
}

func TestActuatorCleanupIssueAndStateRef(t *testing.T) {
	r := &recordingRunner{failSub: map[string]error{}}
	a := withRunner(testActuatorCfg(), r)
	if err := a.OpenCleanupIssue(context.Background()); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := a.DeleteStateRef(context.Background()); err != nil {
		t.Fatalf("delete ref: %v", err)
	}
	all := joined(r.cmds)
	if !strings.Contains(all, "gh issue create --repo acme/widget --title Ferralon removed — one manual step to finish cleanup") {
		t.Errorf("issue-create shape wrong:\n%s", all)
	}
	if !strings.Contains(all, "git -C /ws push origin --delete refs/tegron/state") {
		t.Errorf("state-ref delete shape wrong:\n%s", all)
	}
}

// The Issue body must carry the manual git rm command and the clinical, no-alarm
// re-install note, and must never use alarming language.
func TestIssueBodyClinicalRegister(t *testing.T) {
	a := withRunner(testActuatorCfg(), &recordingRunner{failSub: map[string]error{}})
	body := a.issueBody()
	if !strings.Contains(body, "git rm .github/workflows/ferralon-assay.yml") {
		t.Errorf("issue body missing the manual git rm command:\n%s", body)
	}
	if !strings.Contains(strings.ToLower(body), "re-install") {
		t.Errorf("issue body missing the reversibility note:\n%s", body)
	}
	for _, banned := range []string{"exploit", "attack", "malicious", "danger"} {
		if strings.Contains(strings.ToLower(body), banned) {
			t.Errorf("issue body uses alarming/non-clinical word %q:\n%s", banned, body)
		}
	}
}
