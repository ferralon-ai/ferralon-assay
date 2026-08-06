package selfcleanup

import (
	"context"
	"errors"
)

// Rung identifies which rung of the actuation ladder ultimately succeeded.
type Rung int

const (
	RungNone Rung = iota // no rung reached (should not happen — rung 3 always progresses)
	Rung1DirectPush
	Rung2RemovalPR
	Rung3DisableIssue
)

func (r Rung) String() string {
	switch r {
	case Rung1DirectPush:
		return "rung1-direct-push"
	case Rung2RemovalPR:
		return "rung2-removal-pr"
	case Rung3DisableIssue:
		return "rung3-disable-issue"
	default:
		return "none"
	}
}

// ErrPushRejected is what an Actuator returns from DeleteWorkflowFileDirect /
// OpenRemovalPR when the push was refused by branch protection (the specific
// condition that drops to the next rung). Any OTHER error also falls through, but
// this one is the designed trigger and is surfaced for logging.
var ErrPushRejected = errors.New("selfcleanup: push rejected (branch protection)")

// Actuator performs the concrete repository operations of the cleanup ladder. Each
// method is one platform action; the git/gh-backed implementation is gitActuator,
// and tests use a mock to assert the ladder's decision logic.
type Actuator interface {
	// DeleteWorkflowFileDirect direct-pushes a commit to the default branch removing
	// .github/workflows/ferralon-assay.yml. Returns ErrPushRejected (or any error) to
	// fall through to rung 2.
	DeleteWorkflowFileDirect(ctx context.Context) error
	// OpenRemovalPR pushes the ferralon-assay-removal branch with the deletion and
	// opens the "merge to finish cleanup" PR.
	OpenRemovalPR(ctx context.Context) error
	// DisableWorkflow disables the running workflow via the Actions API so it never
	// fires again (rung 3, the guaranteed-progress fallback).
	DisableWorkflow(ctx context.Context) error
	// OpenCleanupIssue files the "one manual step to finish cleanup" Issue.
	OpenCleanupIssue(ctx context.Context) error
	// DeleteStateRef removes refs/assay/state (statestore.DefaultRef).
	DeleteStateRef(ctx context.Context) error
}

// Actuate runs the three-rung cleanup ladder, stopping at the first rung that
// succeeds. The invariant is "make progress and leave no live footprint":
//
//	Rung 1  direct-push delete the workflow file → delete state ref (LAST). Zero
//	        residual, zero human steps.
//	Rung 2  (rung 1 push refused) push removal branch + open PR → delete state ref.
//	Rung 3  (PR could not be opened) delete state ref FIRST (a disabled workflow can
//	        never run again, so the counter is moot), then self-disable, then file the
//	        one-manual-step Issue. Best-effort: it collects errors but always returns
//	        Rung3DisableIssue so the run does not fail the customer's build.
//
// State-ref deletion is LAST in rungs 1 and 2 so the consecutive-revoke count
// survives a retry if the file deletion itself is retried; it is FIRST in rung 3
// because there the workflow is being disabled anyway.
func Actuate(ctx context.Context, a Actuator) (Rung, error) {
	// Rung 1: direct push.
	if err := a.DeleteWorkflowFileDirect(ctx); err == nil {
		if derr := a.DeleteStateRef(ctx); derr != nil {
			return Rung1DirectPush, derr
		}
		return Rung1DirectPush, nil
	}

	// Rung 2: removal branch + PR.
	if err := a.OpenRemovalPR(ctx); err == nil {
		if derr := a.DeleteStateRef(ctx); derr != nil {
			return Rung2RemovalPR, derr
		}
		return Rung2RemovalPR, nil
	}

	// Rung 3: guaranteed progress. Delete the state ref FIRST, then disable + Issue.
	var errs []error
	if err := a.DeleteStateRef(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := a.DisableWorkflow(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := a.OpenCleanupIssue(ctx); err != nil {
		errs = append(errs, err)
	}
	return Rung3DisableIssue, errors.Join(errs...)
}
