package github_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"
)

// TestTier1Issue_TitleAndCodenameConfinedToMarker asserts the pinned dashboard Issue
// title reads brand.Tier1IssueTitle and that, once the invisible HTML marker is
// stripped, the rendered Issue body carries zero occurrences of a prior codename
// ("nucleon" / "open-tegron" / "tegron") — i.e. the only place a codename survives is
// inside the marker comment, which tier1_issue.go's find-or-create depends on staying
// stable (see brand/brand_identity_test.go).
func TestTier1Issue_TitleAndCodenameConfinedToMarker(t *testing.T) {
	if ghsink.IssueTitle != brand.Tier1IssueTitle {
		t.Errorf("IssueTitle = %q, want %q", ghsink.IssueTitle, brand.Tier1IssueTitle)
	}

	mock := newMockGitHub()
	srv := mock.server(t)
	sink := ghsink.NewTier1Issue(issueWriteEnv(srv.URL), srv.Client())
	if err := sink.Publish(context.Background(), newResult()); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	var body string
	for i := range mock.issues {
		if strings.Contains(mock.issues[i].Body, ghsink.IssueMarker) {
			body = mock.issues[i].Body
			break
		}
	}
	if body == "" {
		t.Fatalf("dashboard issue not found by marker")
	}

	withoutMarker := strings.Replace(body, ghsink.IssueMarker, "", 1)
	low := strings.ToLower(withoutMarker)
	for _, bad := range []string{"nucleon", "open-tegron", "tegron"} {
		if strings.Contains(low, bad) {
			t.Errorf("Tier-1 Issue render leaks codename %q outside the marker\n---\n%s", bad, withoutMarker)
		}
	}
}
