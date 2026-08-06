package selfcleanup

import (
	"context"
	"errors"
	"testing"
)

// mockActuator records the order of calls and returns programmed errors per method.
type mockActuator struct {
	calls []string
	errs  map[string]error
}

func newMock() *mockActuator { return &mockActuator{errs: map[string]error{}} }

func (m *mockActuator) do(name string) error {
	m.calls = append(m.calls, name)
	return m.errs[name]
}
func (m *mockActuator) DeleteWorkflowFileDirect(context.Context) error { return m.do("direct") }
func (m *mockActuator) OpenRemovalPR(context.Context) error            { return m.do("pr") }
func (m *mockActuator) DisableWorkflow(context.Context) error          { return m.do("disable") }
func (m *mockActuator) OpenCleanupIssue(context.Context) error         { return m.do("issue") }
func (m *mockActuator) DeleteStateRef(context.Context) error           { return m.do("deleteRef") }

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("call order:\n got %v\nwant %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("call order:\n got %v\nwant %v", got, want)
		}
	}
}

func TestRung1Success(t *testing.T) {
	m := newMock()
	rung, err := Actuate(context.Background(), m)
	if err != nil || rung != Rung1DirectPush {
		t.Fatalf("rung1: got %v err=%v", rung, err)
	}
	// Direct push succeeds, then the state ref is deleted LAST.
	eq(t, m.calls, []string{"direct", "deleteRef"})
}

func TestRung2OnPushRejected(t *testing.T) {
	m := newMock()
	m.errs["direct"] = ErrPushRejected
	rung, err := Actuate(context.Background(), m)
	if err != nil || rung != Rung2RemovalPR {
		t.Fatalf("rung2: got %v err=%v", rung, err)
	}
	// Direct rejected → PR → delete ref LAST. No disable/issue.
	eq(t, m.calls, []string{"direct", "pr", "deleteRef"})
}

func TestRung3OnPRFailure(t *testing.T) {
	m := newMock()
	m.errs["direct"] = ErrPushRejected
	m.errs["pr"] = errors.New("no permission to open PR")
	rung, err := Actuate(context.Background(), m)
	if err != nil || rung != Rung3DisableIssue {
		t.Fatalf("rung3: got %v err=%v", rung, err)
	}
	// Rung 3 deletes the ref FIRST, then disables, then files the Issue.
	eq(t, m.calls, []string{"direct", "pr", "deleteRef", "disable", "issue"})
}

func TestRung3AlwaysProgressesDespiteErrors(t *testing.T) {
	m := newMock()
	m.errs["direct"] = errors.New("network")
	m.errs["pr"] = errors.New("network")
	m.errs["disable"] = errors.New("api down")
	m.errs["issue"] = errors.New("api down")
	rung, err := Actuate(context.Background(), m)
	if rung != Rung3DisableIssue {
		t.Fatalf("must land on rung3, got %v", rung)
	}
	if err == nil {
		t.Fatal("rung3 must surface the joined errors for logging")
	}
	// All rung-3 steps are attempted even when each fails.
	eq(t, m.calls, []string{"direct", "pr", "deleteRef", "disable", "issue"})
}

func TestRung1AnyErrorFallsThrough(t *testing.T) {
	// A non-ErrPushRejected error on rung 1 also drops to rung 2 (make progress).
	m := newMock()
	m.errs["direct"] = errors.New("some transient git error")
	rung, err := Actuate(context.Background(), m)
	if err != nil || rung != Rung2RemovalPR {
		t.Fatalf("any rung1 error → rung2: got %v err=%v", rung, err)
	}
	eq(t, m.calls, []string{"direct", "pr", "deleteRef"})
}
