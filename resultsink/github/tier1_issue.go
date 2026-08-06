// tier1_issue.go — the Tier 1 pinned-Issue dashboard surface: a single, repo-scoped
// GitHub Issue whose body is rewritten on every run to show the latest scan. It is the
// durable between-PRs human surface — the "where do things stand on main" view — and
// follows the Renovate dashboard pattern of overwriting one issue rather than opening a
// new one each run.
//
// # Overwrite-one-issue
//
// The issue is identified by an invisible HTML-comment marker (IssueMarker) in its body
// (the title is also stable). On each run the sink lists the repo's issues, finds the
// one carrying the marker, and PATCHes its body; only when none exists does it open a
// new issue. The marker is the durable handle, so no state is stored by the tool.
//
// # Auto-skip
//
// The sink no-ops cleanly (returns nil, makes no write call) when it has no usable
// write client (missing owner/repo/token). Issues are repo-scoped, not PR-scoped, so —
// unlike the sticky comment — it needs no PR context; the selector (Item 5) composes it
// whenever caps.CanIssue (i.e. any write-capable run). It renders only deterministic
// verdicts (inv. 5) via renderTier1Body.
package github

import (
	"context"
	"fmt"
	"net/http"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
)

var (
	// IssueMarker is the invisible HTML-comment tag the dashboard issue carries so a
	// re-run finds and overwrites the single issue rather than opening a new one.
	IssueMarker = brand.IssueMarker()
	// IssueTitle is the stable title of the dashboard issue.
	IssueTitle = brand.Tier1IssueTitle
)

// Tier1Issue is a resultsink.ResultSink that maintains one pinned dashboard Issue for
// the repository, overwriting its body each run.
type Tier1Issue struct {
	client *apiClient
	marker string
	title  string
}

var _ resultsink.ResultSink = (*Tier1Issue)(nil)

// NewTier1Issue builds the pinned-issue sink from a detected Env snapshot. The
// *http.Client is injectable for hermetic tests; a nil client uses the default.
func NewTier1Issue(env Env, httpClient *http.Client) *Tier1Issue {
	return &Tier1Issue{
		client: newAPIClient(env, httpClient),
		marker: IssueMarker,
		title:  IssueTitle,
	}
}

// Publish creates or overwrites the dashboard issue. It auto-skips (returns nil) when
// the client is not write-usable. The body is the shared deterministic Markdown wrapped
// with the marker.
func (s *Tier1Issue) Publish(ctx context.Context, res Result) error {
	if s == nil || s.client == nil || !s.client.usable() {
		return nil
	}

	body := withMarker(s.marker, renderTier1Body(res.Report))

	existing, err := s.findMarkedIssue(ctx)
	if err != nil {
		return err
	}

	if existing != 0 {
		status, err := s.client.updateIssue(ctx, existing, s.title, body)
		if err != nil {
			return err
		}
		if status < 200 || status >= 300 {
			return fmt.Errorf("resultsink/github: update dashboard issue: unexpected status %d", status)
		}
		return nil
	}

	_, status, err := s.client.createIssue(ctx, s.title, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("resultsink/github: create dashboard issue: unexpected status %d", status)
	}
	return nil
}

// findMarkedIssue scans the repo's issues (paged, all states) for the sink's marker and
// returns the matching issue number, or 0 when none carries the marker. The Issues
// listing also returns pull requests; the marker match filters those out. A non-2xx
// list status degrades to "not found" so the sink creates rather than erroring.
func (s *Tier1Issue) findMarkedIssue(ctx context.Context) (int, error) {
	for page := 1; ; page++ {
		issues, status, err := s.client.listIssues(ctx, page)
		if err != nil {
			return 0, err
		}
		if status < 200 || status >= 300 {
			return 0, nil
		}
		for i := range issues {
			if hasMarker(issues[i].Body, s.marker) {
				return issues[i].Number, nil
			}
		}
		if len(issues) < 100 {
			return 0, nil
		}
	}
}
