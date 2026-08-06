package github_test

import (
	"context"
	"strings"
	"testing"

	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"
)

// writeEnv builds a write-capable PR Env pointed at the mock server.
func prWriteEnv(serverURL string, prNumber int) ghsink.Env {
	return ghsink.Env{
		InActions:  true,
		Token:      "ghs_write",
		Repository: "owner/repo",
		EventName:  "pull_request",
		ServerURL:  serverURL,
		PRNumber:   prNumber,
	}
}

// TestTier1PRComment_CreatesThenUpdatesInPlace asserts the first run creates one sticky
// comment and a second run UPDATES the same comment in place (no spam) — the marker is
// the durable handle.
func TestTier1PRComment_CreatesThenUpdatesInPlace(t *testing.T) {
	mock := newMockGitHub()
	srv := mock.server(t)
	env := prWriteEnv(srv.URL, 42)

	sink := ghsink.NewTier1PRComment(env, srv.Client())

	if err := sink.Publish(context.Background(), newResult()); err != nil {
		t.Fatalf("first Publish: %v", err)
	}
	if got := len(mock.commentsByIssue[42]); got != 1 {
		t.Fatalf("after first run want 1 comment, got %d", got)
	}
	firstID := mock.commentsByIssue[42][0].ID
	if !strings.Contains(mock.commentsByIssue[42][0].Body, ghsink.PRCommentMarker) {
		t.Errorf("sticky comment missing marker")
	}

	// Second run must update in place, not create a new comment.
	if err := sink.Publish(context.Background(), newResult()); err != nil {
		t.Fatalf("second Publish: %v", err)
	}
	if got := len(mock.commentsByIssue[42]); got != 1 {
		t.Fatalf("after second run want still 1 comment (update-in-place), got %d", got)
	}
	if mock.commentsByIssue[42][0].ID != firstID {
		t.Errorf("comment ID changed (new comment created): %d != %d", mock.commentsByIssue[42][0].ID, firstID)
	}
	if mock.createdCmt != 1 {
		t.Errorf("want exactly 1 POST comment (no spam), got %d", mock.createdCmt)
	}

	// inv. 5: the rendered body never surfaces affected/error/exploitable.
	body := mock.commentsByIssue[42][0].Body
	for _, forbidden := range []string{"affected", "::error"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("inv.5 violation: comment body contains %q", forbidden)
		}
	}
}

// TestTier1PRComment_AutoSkip_NoToken asserts the sink no-ops (no API call) without a
// token — the forked-PR read-only condition.
func TestTier1PRComment_AutoSkip_NoToken(t *testing.T) {
	mock := newMockGitHub()
	srv := mock.server(t)
	env := prWriteEnv(srv.URL, 42)
	env.Token = "" // forked-PR / no-token

	sink := ghsink.NewTier1PRComment(env, srv.Client())
	if err := sink.Publish(context.Background(), newResult()); err != nil {
		t.Fatalf("Publish should auto-skip cleanly, got: %v", err)
	}
	if mock.createdCmt != 0 || len(mock.commentsByIssue[42]) != 0 {
		t.Errorf("no-token run must make no write call; createdCmt=%d comments=%d", mock.createdCmt, len(mock.commentsByIssue[42]))
	}
}

// TestTier1PRComment_AutoSkip_NoPRContext asserts the sink no-ops when there is no PR
// to comment on (PRNumber == 0), e.g. a push build.
func TestTier1PRComment_AutoSkip_NoPRContext(t *testing.T) {
	mock := newMockGitHub()
	srv := mock.server(t)
	env := prWriteEnv(srv.URL, 0) // no PR number
	env.EventName = "push"

	sink := ghsink.NewTier1PRComment(env, srv.Client())
	if err := sink.Publish(context.Background(), newResult()); err != nil {
		t.Fatalf("Publish should auto-skip cleanly, got: %v", err)
	}
	if mock.createdCmt != 0 {
		t.Errorf("push build (no PR) must not comment; createdCmt=%d", mock.createdCmt)
	}
}
