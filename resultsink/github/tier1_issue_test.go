package github_test

import (
	"context"
	"strings"
	"testing"

	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"
)

func issueWriteEnv(serverURL string) ghsink.Env {
	return ghsink.Env{
		InActions:  true,
		Token:      "ghs_write",
		Repository: "owner/repo",
		EventName:  "push",
		ServerURL:  serverURL,
	}
}

// TestTier1Issue_CreatesThenOverwritesSameIssue asserts the first run opens one
// dashboard issue and a second run overwrites the SAME issue body (Renovate pattern).
func TestTier1Issue_CreatesThenOverwritesSameIssue(t *testing.T) {
	mock := newMockGitHub()
	// Seed an unrelated issue WITHOUT the marker; the sink must not hijack it.
	mock.issues = append(mock.issues, mockIssue{Number: 7, Title: "unrelated", Body: "nothing here", State: "open"})
	srv := mock.server(t)
	env := issueWriteEnv(srv.URL)

	sink := ghsink.NewTier1Issue(env, srv.Client())

	if err := sink.Publish(context.Background(), newResult()); err != nil {
		t.Fatalf("first Publish: %v", err)
	}
	if mock.createdIss != 1 {
		t.Fatalf("want exactly 1 issue created, got %d", mock.createdIss)
	}
	// Locate the dashboard issue by marker.
	var dash *mockIssue
	for i := range mock.issues {
		if strings.Contains(mock.issues[i].Body, ghsink.IssueMarker) {
			dash = &mock.issues[i]
		}
	}
	if dash == nil {
		t.Fatalf("dashboard issue not found by marker")
	}
	if dash.Title != ghsink.IssueTitle {
		t.Errorf("dashboard title = %q, want %q", dash.Title, ghsink.IssueTitle)
	}
	dashNum := dash.Number

	// Second run overwrites the same issue body; no new issue.
	if err := sink.Publish(context.Background(), newResult()); err != nil {
		t.Fatalf("second Publish: %v", err)
	}
	if mock.createdIss != 1 {
		t.Fatalf("want still 1 issue created (overwrite-in-place), got %d", mock.createdIss)
	}
	// The same issue number still carries the marker.
	found := false
	for i := range mock.issues {
		if mock.issues[i].Number == dashNum && strings.Contains(mock.issues[i].Body, ghsink.IssueMarker) {
			found = true
		}
	}
	if !found {
		t.Errorf("dashboard issue %d lost its marker after overwrite", dashNum)
	}

	// inv. 5.
	for _, forbidden := range []string{"affected", "::error"} {
		if strings.Contains(mock.issues[len(mock.issues)-1].Body, forbidden) {
			t.Errorf("inv.5 violation: dashboard body contains %q", forbidden)
		}
	}
}

// TestTier1Issue_AutoSkip_NoToken asserts the sink no-ops without a write token.
func TestTier1Issue_AutoSkip_NoToken(t *testing.T) {
	mock := newMockGitHub()
	srv := mock.server(t)
	env := issueWriteEnv(srv.URL)
	env.Token = ""

	sink := ghsink.NewTier1Issue(env, srv.Client())
	if err := sink.Publish(context.Background(), newResult()); err != nil {
		t.Fatalf("Publish should auto-skip cleanly, got: %v", err)
	}
	if mock.createdIss != 0 {
		t.Errorf("no-token run must not create an issue; createdIss=%d", mock.createdIss)
	}
}
