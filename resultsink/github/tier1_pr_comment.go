// tier1_pr_comment.go — the Tier 1 sticky PR-comment surface: a single marker-tagged
// comment on the pull request that is created once and then updated in place on every
// re-run, so a busy PR gets one living scan comment instead of a new one per push.
//
// # Find-or-update (no spam)
//
// The body is wrapped with an invisible HTML-comment marker (PRCommentMarker). On each
// run the sink lists the PR's comments, finds the one carrying the marker, and PATCHes
// it; only when none exists does it POST a new comment. The marker is the durable
// handle — it survives across runs without the sink storing any state.
//
// # Auto-skip (forked-PR safety)
//
// The sink no-ops cleanly (returns nil, makes no write call) when it has no usable
// write client (missing owner/repo/token) or no pull-request context (PRNumber == 0).
// A forked pull_request carries a read-only token; the selector (Item 5) only composes
// this sink when caps.CanComment, but the sink self-guards too so it is safe to call
// directly. It renders only deterministic verdicts (inv. 5) via renderTier1Body.
package github

import (
	"context"
	"fmt"
	"net/http"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
)

// PRCommentMarker is the invisible HTML-comment tag the sticky comment carries so a
// re-run can find and overwrite its single comment rather than posting a new one.
var PRCommentMarker = brand.PRCommentMarker()

// Tier1PRComment is a resultsink.ResultSink that maintains one sticky scan comment on
// the current pull request. It holds the shared REST client and the PR number resolved
// from the Env snapshot.
type Tier1PRComment struct {
	client   *apiClient
	prNumber int
	marker   string
}

var _ resultsink.ResultSink = (*Tier1PRComment)(nil)

// NewTier1PRComment builds the sticky-comment sink from a detected Env snapshot. The
// *http.Client is injectable so tests drive it against httptest; a nil client uses the
// default. PRNumber comes from the parsed event payload (DetectEnv); when it is 0 (not
// a PR run) the sink auto-skips.
func NewTier1PRComment(env Env, httpClient *http.Client) *Tier1PRComment {
	return &Tier1PRComment{
		client:   newAPIClient(env, httpClient),
		prNumber: env.PRNumber,
		marker:   PRCommentMarker,
	}
}

// Publish creates or updates the sticky comment on the PR. It auto-skips (returns nil)
// when the client is not write-usable or there is no PR context. The body is the shared
// deterministic Markdown wrapped with the marker.
func (s *Tier1PRComment) Publish(ctx context.Context, res Result) error {
	if s == nil || s.client == nil || !s.client.usable() || s.prNumber <= 0 {
		return nil
	}

	body := withMarker(s.marker, renderTier1Body(res.Report))

	existingID, err := s.findMarkedComment(ctx)
	if err != nil {
		return err
	}

	if existingID != 0 {
		status, err := s.client.updateIssueComment(ctx, existingID, body)
		if err != nil {
			return err
		}
		if status < 200 || status >= 300 {
			return fmt.Errorf("resultsink/github: update sticky comment: unexpected status %d", status)
		}
		return nil
	}

	status, err := s.client.createIssueComment(ctx, s.prNumber, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("resultsink/github: create sticky comment: unexpected status %d", status)
	}
	return nil
}

// findMarkedComment scans the PR's comments (paged) for the sink's marker and returns
// the matching comment ID, or 0 when none carries the marker. A non-2xx list status is
// treated as "no comment found" so the sink degrades to a create rather than erroring.
func (s *Tier1PRComment) findMarkedComment(ctx context.Context) (int64, error) {
	for page := 1; ; page++ {
		comments, status, err := s.client.listIssueComments(ctx, s.prNumber, page)
		if err != nil {
			return 0, err
		}
		if status < 200 || status >= 300 {
			return 0, nil
		}
		for i := range comments {
			if hasMarker(comments[i].Body, s.marker) {
				return comments[i].ID, nil
			}
		}
		if len(comments) < 100 {
			return 0, nil
		}
	}
}
