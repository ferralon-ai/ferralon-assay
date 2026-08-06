// client.go — the minimal GitHub REST client shared by the Tier 1 sinks (sticky PR
// comment, pinned-Issue dashboard). It is the resultsink counterpart of the
// statestore GitHubRefStore client: a stdlib net/http + encoding/json wrapper with an
// injectable base URL and *http.Client so tests drive it against httptest with no
// live network (the depguard allowlist forbids a third-party GitHub client).
//
// It exposes only the Issues / Issue-comments endpoints the Tier 1 surfaces need.
// SARIF (tier1_sarif.go) makes no REST call — the upload is delegated to the
// codeql-action workflow step — so it does not use this client.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// apiClient issues authenticated requests to {BaseURL}/repos/{Owner}/{Repo}/...
// It holds no per-surface state; the sticky-comment and pinned-issue sinks share one
// instance constructed from the Env snapshot.
type apiClient struct {
	baseURL string
	owner   string
	repo    string
	token   string
	http    *http.Client
}

const defaultAPIBaseURL = "https://api.github.com"

// newAPIClient builds an apiClient from the detected Env. owner/repo come from
// GITHUB_REPOSITORY ("owner/repo"); an unparseable value yields empty fields and the
// caller's sink auto-skips. The base URL is derived from GITHUB_SERVER_URL when it is
// a GitHub Enterprise host, else the public api.github.com. The *http.Client is
// injectable via the sink constructors for hermetic tests.
func newAPIClient(env Env, httpClient *http.Client) *apiClient {
	owner, repo := splitRepository(env.Repository)
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &apiClient{
		baseURL: apiBaseURL(env.ServerURL),
		owner:   owner,
		repo:    repo,
		token:   env.Token,
		http:    httpClient,
	}
}

// usable reports whether the client has the minimum coordinates + token to make an
// authenticated write. A sink with !usable auto-skips (no error).
func (c *apiClient) usable() bool {
	return c.owner != "" && c.repo != "" && c.token != ""
}

// splitRepository splits "owner/repo" into its parts; returns ("","") when malformed.
func splitRepository(full string) (owner, repo string) {
	parts := strings.SplitN(full, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", ""
	}
	return parts[0], parts[1]
}

// apiBaseURL maps GITHUB_SERVER_URL to its REST API root. github.com → api.github.com;
// a GHES host https://ghe.example.com → https://ghe.example.com/api/v3. An empty
// server URL defaults to public GitHub.
func apiBaseURL(serverURL string) string {
	s := strings.TrimRight(serverURL, "/")
	switch s {
	case "", "https://github.com", "http://github.com":
		return defaultAPIBaseURL
	default:
		return s + "/api/v3"
	}
}

// do issues one request against {baseURL}/repos/{owner}/{repo}{path}, JSON-encoding
// body when non-nil and decoding the 2xx response into out when non-nil. It returns
// the HTTP status so callers branch on it without a non-2xx being a transport error.
func (c *apiClient) do(ctx context.Context, method, path string, body, out any) (int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("resultsink/github: marshal request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	url := c.baseURL + "/repos/" + c.owner + "/" + c.repo + path
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return 0, fmt.Errorf("resultsink/github: build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("resultsink/github: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("resultsink/github: read response %s %s: %w", method, path, err)
	}
	if out != nil && len(raw) > 0 && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("resultsink/github: decode response %s %s: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

// --- Issue / comment API shapes (only the fields the sinks use) ---

type ghIssueComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

type ghIssue struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	State  string `json:"state"`
}

// listIssueComments returns the comments on an issue/PR (paged 100 at a time). The
// sticky-comment sink scans them for its marker. issues/{n}/comments serves both
// issues and PRs (a PR is an issue for the comments API).
func (c *apiClient) listIssueComments(ctx context.Context, issueNumber, page int) ([]ghIssueComment, int, error) {
	var out []ghIssueComment
	path := "/issues/" + strconv.Itoa(issueNumber) + "/comments?per_page=100&page=" + strconv.Itoa(page)
	status, err := c.do(ctx, http.MethodGet, path, nil, &out)
	return out, status, err
}

func (c *apiClient) createIssueComment(ctx context.Context, issueNumber int, bodyMD string) (int, error) {
	path := "/issues/" + strconv.Itoa(issueNumber) + "/comments"
	return c.do(ctx, http.MethodPost, path, map[string]string{"body": bodyMD}, nil)
}

func (c *apiClient) updateIssueComment(ctx context.Context, commentID int64, bodyMD string) (int, error) {
	path := "/issues/comments/" + strconv.FormatInt(commentID, 10)
	return c.do(ctx, http.MethodPatch, path, map[string]string{"body": bodyMD}, nil)
}

// listIssues returns one page of the repo's issues (open and closed) so the
// pinned-issue sink can locate its single dashboard issue by marker. The Issues
// listing also returns pull requests, which the caller filters out by marker match.
func (c *apiClient) listIssues(ctx context.Context, page int) ([]ghIssue, int, error) {
	var out []ghIssue
	path := "/issues?per_page=100&state=all&page=" + strconv.Itoa(page)
	status, err := c.do(ctx, http.MethodGet, path, nil, &out)
	return out, status, err
}

func (c *apiClient) createIssue(ctx context.Context, title, bodyMD string) (ghIssue, int, error) {
	var out ghIssue
	status, err := c.do(ctx, http.MethodPost, "/issues", map[string]string{"title": title, "body": bodyMD}, &out)
	return out, status, err
}

func (c *apiClient) updateIssue(ctx context.Context, number int, title, bodyMD string) (int, error) {
	path := "/issues/" + strconv.Itoa(number)
	return c.do(ctx, http.MethodPatch, path, map[string]string{"title": title, "body": bodyMD}, nil)
}
